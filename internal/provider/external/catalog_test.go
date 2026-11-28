package external_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

var catalogNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

// ready gives a registration the status a successful probe of its current
// revision writes.
func ready(ap *v1alpha1.AssessmentProvider) *v1alpha1.AssessmentProvider {
	ap.Status = external.Status(ap, external.Observation{Generation: ap.Generation, At: catalogNow.Add(-time.Minute)}, nil)
	return ap
}

func catalog(t *testing.T, regs ...*v1alpha1.AssessmentProvider) *external.Catalog {
	t.Helper()
	list := make([]v1alpha1.AssessmentProvider, 0, len(regs))
	for _, r := range regs {
		list = append(list, *r)
	}
	c, err := external.NewCatalog(external.CatalogOptions{BuiltIn: installed.Registry(), External: true, Registrations: list, Now: catalogNow})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wantSelection(t *testing.T, c *external.Catalog, contract string, reason provider.SelectionReason, need ...v1alpha1.AssessmentProviderCapability) {
	t.Helper()
	sel, err := c.Resolve(contract, need...)
	if err == nil || err.Reason != reason {
		t.Fatalf("resolve %s: %+v, %v; want %s", contract, sel, err, reason)
	}
	if sel.BuiltIn != nil || sel.External != nil {
		t.Fatalf("a rejected selection returned %+v", sel)
	}
	if reason.BindingReason() != v1alpha1.ReasonContentUnavailable && reason != provider.ReasonInvalidSelection {
		t.Fatalf("%s is reported as %s", reason, reason.BindingReason())
	}
}

const contract = externaltest.Provider + "/v1"

func withName(name string) func(*v1alpha1.AssessmentProvider) {
	return func(ap *v1alpha1.AssessmentProvider) { ap.Name, ap.UID = name, types.UID("uid-"+name) }
}

func disabled(ap *v1alpha1.AssessmentProvider) {
	ap.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled
}

// Built-in providers resolve exactly as the compiled-in registry resolves
// them, whatever is registered: a registration never shadows one.
func TestCatalogResolvesBuiltInsFirst(t *testing.T) {
	shadow := ready(externaltest.Registration("shadow", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "konstapel-kyverno" }))
	c := catalog(t, shadow)
	for _, contract := range []string{"", kyverno.Contract} {
		sel, err := c.Resolve(contract)
		if err != nil || sel.BuiltIn == nil || sel.External != nil || sel.Contract != kyverno.Contract {
			t.Fatalf("resolve %q: %+v %v", contract, sel, err)
		}
	}
	wantSelection(t, c, "konstapel-kyverno/v2", provider.ReasonIncompatibleVersion)
	wantSelection(t, c, "./konstapel-provider", provider.ReasonInvalidSelection)
	if !c.BuiltIn("konstapel-kyverno") || c.BuiltIn(externaltest.Provider) {
		t.Fatal("built-in names")
	}
	if _, err := external.NewCatalog(external.CatalogOptions{}); err == nil {
		t.Fatal("a catalog without a built-in registry")
	}
}

// Without external providers enabled, registrations are ignored and an
// external contract is unknown, exactly as before registration support.
func TestCatalogWithoutExternalProvidersIsTheInstalledRegistry(t *testing.T) {
	c, err := external.NewCatalog(external.CatalogOptions{BuiltIn: installed.Registry(),
		Registrations: []v1alpha1.AssessmentProvider{*ready(externaltest.Registration("reporting"))}, Now: catalogNow})
	if err != nil {
		t.Fatal(err)
	}
	wantSelection(t, c, contract, provider.ReasonUnknownProvider)
	if sel, err := c.Resolve(kyverno.Contract); err != nil || sel.BuiltIn == nil {
		t.Fatalf("built-in: %+v %v", sel, err)
	}
	if c.Registration("reporting") != nil {
		t.Fatal("a disabled catalog holds registrations")
	}
}

// A contract no registration names is unknown; one registered only at
// other contract versions is incompatible.
func TestCatalogUnknownAndIncompatibleContracts(t *testing.T) {
	v2 := ready(externaltest.Registration("reporting-v2", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Compatibility.ContractVersion = 2 }))
	c := catalog(t, v2)
	wantSelection(t, c, "other-provider/v1", provider.ReasonUnknownProvider)
	wantSelection(t, c, contract, provider.ReasonIncompatibleVersion)
	_, err := c.Resolve(contract)
	if !strings.Contains(err.Message, externaltest.Provider+"/v2") {
		t.Fatalf("message %q does not name the registered contract", err.Message)
	}
	if sel, err := c.Resolve(externaltest.Provider + "/v2"); err != nil || sel.External == nil || sel.External.Registration != "reporting-v2" {
		t.Fatalf("v2: %+v %v", sel, err)
	}
}

// A Disabled registration is never selected by new work.
func TestCatalogDisabledRegistrationsBlockNewStarts(t *testing.T) {
	c := catalog(t, ready(externaltest.Registration("reporting", disabled)))
	wantSelection(t, c, contract, provider.ReasonProviderDisabled)
	if got := c.Conflicts(c.Registration("reporting")); len(got) != 0 {
		t.Fatalf("a disabled registration conflicts with %v", got)
	}
}

// Two Enabled registrations of one contract are ambiguous: neither is
// chosen, whatever their order, age or health, until all but one are
// Disabled. A Disabled old release beside an Enabled new one is the
// upgrade procedure and selects the new one.
func TestCatalogRejectsAmbiguousRegistrations(t *testing.T) {
	old := ready(externaltest.Registration("reporting-a"))
	next := externaltest.Registration("reporting-b", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.ReleaseDigest = externaltest.OtherRelease })
	unhealthy := next.DeepCopy()
	unhealthy.Status = external.Status(unhealthy, external.Observation{Generation: 1, At: catalogNow,
		Problem: &external.Problem{Condition: v1alpha1.ProviderConditionAvailable, Reason: v1alpha1.ProviderReasonEndpointUnavailable, Message: "down"}}, nil)
	for _, regs := range [][]*v1alpha1.AssessmentProvider{{old, ready(next.DeepCopy())}, {ready(next.DeepCopy()), old}, {old, unhealthy}} {
		c := catalog(t, regs...)
		wantSelection(t, c, contract, provider.ReasonAmbiguousProvider)
		_, err := c.Resolve(contract)
		if !strings.Contains(err.Message, "reporting-a, reporting-b") {
			t.Fatalf("message %q", err.Message)
		}
		if got := c.Conflicts(old); !slices.Equal(got, []string{"reporting-b"}) {
			t.Fatalf("conflicts %v", got)
		}
	}
	oldDisabled := old.DeepCopy()
	disabled(oldDisabled)
	oldDisabled.Generation = 2
	c := catalog(t, oldDisabled, ready(next.DeepCopy()))
	sel, err := c.Resolve(contract)
	if err != nil || sel.External == nil || sel.External.Registration != "reporting-b" || sel.External.ReleaseDigest != externaltest.OtherRelease {
		t.Fatalf("after draining the old release: %+v %v", sel, err)
	}
	// Another provider's registrations never make a contract ambiguous.
	other := ready(externaltest.Registration("other", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "other-reporting" }))
	if got := catalog(t, old, other).Conflicts(old); len(got) != 0 {
		t.Fatalf("conflicts across providers %v", got)
	}
}

// The one Enabled registration is selected only while its status shows it
// Ready, compatible and fresh for its current revision, and only for
// capabilities it allows and was observed serving.
func TestCatalogSelectsOnlyReadyRegistrations(t *testing.T) {
	sel, err := catalog(t, ready(externaltest.Registration("reporting"))).Resolve(contract, v1alpha1.ProviderCapabilityCollect)
	if err != nil || sel.External == nil {
		t.Fatalf("ready: %+v %v", sel, err)
	}
	if want := external.Expected(externaltest.Registration("reporting")); !equalFrozen(*sel.External, want) || sel.Contract != contract {
		t.Fatalf("frozen %+v, want %+v", *sel.External, want)
	}
	for _, tc := range []struct {
		name   string
		ap     *v1alpha1.AssessmentProvider
		need   v1alpha1.AssessmentProviderCapability
		reason provider.SelectionReason
	}{
		{name: "never probed", ap: externaltest.Registration("reporting"), reason: provider.ReasonProviderUnavailable},
		{name: "status of an older revision", ap: func() *v1alpha1.AssessmentProvider {
			ap := ready(externaltest.Registration("reporting"))
			ap.Generation = 2
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "unavailable", ap: func() *v1alpha1.AssessmentProvider {
			ap := externaltest.Registration("reporting")
			ap.Status = external.Status(ap, external.Observation{Generation: 1, At: catalogNow,
				Problem: &external.Problem{Condition: v1alpha1.ProviderConditionAvailable, Reason: v1alpha1.ProviderReasonAuthenticationFailed, Message: "x"}}, nil)
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "incompatible", ap: func() *v1alpha1.AssessmentProvider {
			ap := externaltest.Registration("reporting")
			ap.Status = external.Status(ap, external.Observation{Generation: 1, At: catalogNow,
				Problem: &external.Problem{Condition: v1alpha1.ProviderConditionCompatible, Reason: v1alpha1.ProviderReasonReleaseMismatch, Message: "x"}}, nil)
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "stale observation", ap: func() *v1alpha1.AssessmentProvider {
			ap := externaltest.Registration("reporting")
			ap.Status = external.Status(ap, external.Observation{Generation: 1, At: catalogNow.Add(-time.Hour)}, nil)
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "identity of another release", ap: func() *v1alpha1.AssessmentProvider {
			ap := ready(externaltest.Registration("reporting"))
			ap.Status.Identity.ReleaseDigest = externaltest.OtherRelease
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "Ready of an older revision", ap: func() *v1alpha1.AssessmentProvider {
			ap := ready(externaltest.Registration("reporting"))
			meta.FindStatusCondition(ap.Status.Conditions, v1alpha1.ProviderConditionReady).ObservedGeneration = 0
			return ap
		}(), reason: provider.ReasonProviderUnavailable},
		{name: "a capability the registration does not allow", ap: ready(externaltest.Registration("reporting")), need: v1alpha1.ProviderCapabilityScan,
			reason: provider.ReasonUnsupportedCapability},
		{name: "a capability not observed", ap: func() *v1alpha1.AssessmentProvider {
			ap := ready(externaltest.Registration("reporting"))
			ap.Status.Identity.Capabilities = []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate}
			return ap
		}(), need: v1alpha1.ProviderCapabilityCollect, reason: provider.ReasonProviderUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var need []v1alpha1.AssessmentProviderCapability
			if tc.need != "" {
				need = append(need, tc.need)
			}
			wantSelection(t, catalog(t, tc.ap), contract, tc.reason, need...)
		})
	}
}

// One unhealthy, disabled or ambiguous provider never affects the
// selection of another provider or of a built-in one.
func TestCatalogProvidersAreIndependent(t *testing.T) {
	down := externaltest.Registration("down", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "down-reporting" })
	down.Status = external.Status(down, external.Observation{Generation: 1, At: catalogNow,
		Problem: &external.Problem{Condition: v1alpha1.ProviderConditionAvailable, Reason: v1alpha1.ProviderReasonEndpointUnavailable, Message: "down"}}, nil)
	off := ready(externaltest.Registration("off", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "off-reporting" }, disabled))
	dupA := ready(externaltest.Registration("dup-a", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "dup-reporting" }))
	dupB := ready(externaltest.Registration("dup-b", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "dup-reporting" }))
	healthy := ready(externaltest.Registration("reporting"))
	c := catalog(t, down, off, dupA, dupB, healthy)
	if sel, err := c.Resolve(contract); err != nil || sel.External == nil || sel.External.Registration != "reporting" {
		t.Fatalf("healthy: %+v %v", sel, err)
	}
	if sel, err := c.Resolve(kyverno.Contract); err != nil || sel.BuiltIn == nil {
		t.Fatalf("built-in: %+v %v", sel, err)
	}
	wantSelection(t, c, "down-reporting/v1", provider.ReasonProviderUnavailable)
	wantSelection(t, c, "off-reporting/v1", provider.ReasonProviderDisabled)
	wantSelection(t, c, "dup-reporting/v1", provider.ReasonAmbiguousProvider)
}

func equalFrozen(a, b external.Frozen) bool {
	return a.Registration == b.Registration && a.UID == b.UID && a.Revision == b.Revision && a.Contract() == b.Contract() &&
		a.ReleaseDigest == b.ReleaseDigest && equalEndpoint(a.Endpoint, b.Endpoint) && equalEndpoint(a.EvaluatorEndpoint, b.EvaluatorEndpoint) &&
		slices.Equal(a.Capabilities, b.Capabilities) &&
		a.EvaluatorVersion == b.EvaluatorVersion && a.PayloadVersion == b.PayloadVersion && a.Protocol == b.Protocol && a.ProtocolRevision == b.ProtocolRevision
}

func equalEndpoint(a, b *external.Endpoint) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// A registration being deleted is not selected for new work.
func TestCatalogIgnoresDeletingRegistrations(t *testing.T) {
	ap := ready(externaltest.Registration("reporting"))
	now := metav1.NewTime(catalogNow)
	ap.DeletionTimestamp = &now
	wantSelection(t, catalog(t, ap), contract, provider.ReasonProviderDisabled)
}
