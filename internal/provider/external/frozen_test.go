package external_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// The frozen identity is recorded with the work: its JSON is stable and
// carries identities, versions and object names only.
func TestFrozenEncoding(t *testing.T) {
	f := external.Expected(externaltest.Registration("reporting", func(ap *v1alpha1.AssessmentProvider) {
		ap.Generation = 3
		ap.Spec.Capabilities = []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate, v1alpha1.ProviderCapabilityCollect}
		ap.Spec.Endpoint.ServerTrust.Key = ""
	}))
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"registration":"reporting","uid":"uid-reporting","revision":3,"provider":"example-reporting","contractVersion":1,` +
		`"releaseDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","protocol":"konstapel.provider.v1",` +
		`"protocolRevision":2,"evaluatorVersion":1,"payloadVersion":1,"capabilities":["Collect","Evaluate"],` +
		`"endpoint":{"namespace":"providers","service":"example-reporting","port":8443,"serverName":"example-reporting.providers.svc",` +
		`"trustConfigMap":"example-reporting-ca","trustKey":"ca.crt"}}`
	if string(b) != want {
		t.Fatalf("encoding\n%s\nwant\n%s", b, want)
	}
	var back external.Frozen
	if err := json.Unmarshal(b, &back); err != nil || !equalFrozen(back, f) {
		t.Fatalf("round trip %+v %v", back, err)
	}
	if f.Endpoint.Address() != "example-reporting.providers.svc:8443" || f.Contract() != "example-reporting/v1" {
		t.Fatalf("address %s contract %s", f.Endpoint.Address(), f.Contract())
	}
}

func frozenReason(t *testing.T, err error) external.FrozenReason {
	t.Helper()
	var fe *external.FrozenError
	if !errors.As(err, &fe) {
		t.Fatalf("%v is not a frozen-work error", err)
	}
	return fe.Reason
}

// Work frozen to a revision keeps it across later revisions, including
// newRequests Disabled and a changed endpoint, and ends explicitly when
// the registration is removed or replaced or the capability was never
// frozen.
func TestFrozenWorkContinuesOnlyOnItsRegistration(t *testing.T) {
	ap := externaltest.Registration("reporting")
	f := external.Expected(ap)
	if err := f.Continue(ap, v1alpha1.ProviderCapabilityCollect); err != nil {
		t.Fatal(err)
	}
	// Revision 2 moves the endpoint, revision 3 drains new work.
	changed := ap.DeepCopy()
	changed.Generation = 3
	changed.Spec.Endpoint.Service.Port = 9443
	changed.Spec.Endpoint.ServerTrust.Name = "rotated-ca"
	changed.Spec.Capabilities = []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate}
	changed.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled
	if err := f.Continue(changed, v1alpha1.ProviderCapabilityCollect); err != nil {
		t.Fatalf("frozen work stopped on a later revision: %v", err)
	}
	if f.Endpoint.Port != 8443 || f.Endpoint.TrustConfigMap != externaltest.TrustConfig || f.Revision != 1 {
		t.Fatalf("the frozen configuration changed: %+v", f.Endpoint)
	}
	if next := external.Expected(changed); next.Revision != 3 || next.Endpoint.Port != 9443 {
		t.Fatalf("new work does not use the new revision: %+v", next)
	}
	if got := frozenReason(t, f.Continue(nil, v1alpha1.ProviderCapabilityCollect)); got != external.FrozenRegistrationRemoved {
		t.Fatal(got)
	}
	replaced := ap.DeepCopy()
	replaced.UID = "uid-recreated"
	if got := frozenReason(t, f.Continue(replaced, v1alpha1.ProviderCapabilityCollect)); got != external.FrozenRegistrationReplaced {
		t.Fatal(got)
	}
	rewritten := ap.DeepCopy()
	rewritten.Spec.Provider.ReleaseDigest = externaltest.OtherRelease
	if got := frozenReason(t, f.Continue(rewritten, v1alpha1.ProviderCapabilityCollect)); got != external.FrozenRegistrationChanged {
		t.Fatal(got)
	}
	if got := frozenReason(t, f.Continue(changed, v1alpha1.ProviderCapabilityScan)); got != external.FrozenCapabilityNotFrozen {
		t.Fatal(got)
	}
}

// Old work is rejected, not reinterpreted, when its endpoint now reports
// another implementation or compatibility.
func TestFrozenWorkChecksTheDescribedImplementation(t *testing.T) {
	f := external.Expected(externaltest.Registration("reporting"))
	if err := f.CheckDescription(externaltest.Description()); err != nil {
		t.Fatal(err)
	}
	d := externaltest.Description()
	d.Implementation = externaltest.OtherRelease
	if got := frozenReason(t, f.CheckDescription(d)); got != external.FrozenImplementationChanged {
		t.Fatal(got)
	}
	d = externaltest.Description()
	d.EvaluatorVersion = 2
	if err := f.CheckDescription(d); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_EVALUATOR_VERSION") {
		t.Fatalf("evaluator: %v", err)
	}
	d = externaltest.Description()
	d.Capabilities = []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE}
	if err := f.CheckDescription(d); err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("capability: %v", err)
	}
}
