package external_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
)

// validStatus checks a status write against the generated CRD as the API
// server would: schema, list types and the CEL rule that ties the observed
// identity to the registration.
func validStatus(t *testing.T, ap *v1alpha1.AssessmentProvider) {
	t.Helper()
	v := crdtest.Load(t, "../../../config/crd/bases")["AssessmentProvider"]
	if v == nil {
		t.Fatal("no AssessmentProvider CRD")
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ap.DeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	old := ap.DeepCopy()
	old.Status = v1alpha1.AssessmentProviderStatus{}
	prev, err := runtime.DefaultUnstructuredConverter.ToUnstructured(old)
	if err != nil {
		t.Fatal(err)
	}
	if errs := v.ValidateUpdate(obj, prev); len(errs) > 0 {
		t.Fatalf("status rejected by the CRD: %v", errs.ToAggregate())
	}
}

type wantCondition struct {
	status metav1.ConditionStatus
	reason string
}

func checkConditions(t *testing.T, st v1alpha1.AssessmentProviderStatus, gen int64, want map[string]wantCondition) {
	t.Helper()
	if len(st.Conditions) != len(want) || st.ObservedGeneration != gen {
		t.Fatalf("conditions %+v at generation %d", st.Conditions, st.ObservedGeneration)
	}
	for typ, w := range want {
		c := meta.FindStatusCondition(st.Conditions, typ)
		if c == nil || c.Status != w.status || c.Reason != w.reason || c.ObservedGeneration != gen {
			t.Fatalf("%s: %+v, want %+v", typ, c, w)
		}
		if len(c.Message) > 1100 || strings.Contains(c.Message, "BEGIN") {
			t.Fatalf("%s message is unbounded or carries PEM: %q", typ, c.Message)
		}
	}
}

// Each probe outcome is reported on its own condition, with Ready the
// summary new work selects on, and the identity only while compatible.
func TestStatusReportsAvailabilityCompatibilityAndReadiness(t *testing.T) {
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", 5000)
	for _, tc := range []struct {
		name      string
		ap        *v1alpha1.AssessmentProvider
		problem   *external.Problem
		conflicts []string
		want      map[string]wantCondition
		identity  bool
	}{
		{name: "ready", ap: externaltest.Registration("reporting"), identity: true, want: map[string]wantCondition{
			v1alpha1.ProviderConditionAvailable:  {metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable},
			v1alpha1.ProviderConditionCompatible: {metav1.ConditionTrue, v1alpha1.ProviderReasonCompatible},
			v1alpha1.ProviderConditionReady:      {metav1.ConditionTrue, v1alpha1.ProviderReasonReady}}},
		{name: "draining", ap: externaltest.Registration("reporting", disabled), identity: true, want: map[string]wantCondition{
			v1alpha1.ProviderConditionAvailable:  {metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable},
			v1alpha1.ProviderConditionCompatible: {metav1.ConditionTrue, v1alpha1.ProviderReasonCompatible},
			v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonNewRequestsDisabled}}},
		{name: "ambiguous", ap: externaltest.Registration("reporting"), conflicts: []string{"reporting-b"}, identity: true, want: map[string]wantCondition{
			v1alpha1.ProviderConditionAvailable:  {metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable},
			v1alpha1.ProviderConditionCompatible: {metav1.ConditionTrue, v1alpha1.ProviderReasonCompatible},
			v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonAmbiguousRegistration}}},
		{name: "unauthenticated", ap: externaltest.Registration("reporting"),
			problem: &external.Problem{Condition: v1alpha1.ProviderConditionAvailable, Reason: v1alpha1.ProviderReasonAuthenticationFailed, Message: long},
			want: map[string]wantCondition{
				v1alpha1.ProviderConditionAvailable:  {metav1.ConditionFalse, v1alpha1.ProviderReasonAuthenticationFailed},
				v1alpha1.ProviderConditionCompatible: {metav1.ConditionUnknown, v1alpha1.ProviderReasonNotChecked},
				v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonUnavailable}}},
		{name: "another release", ap: externaltest.Registration("reporting"),
			problem: &external.Problem{Condition: v1alpha1.ProviderConditionCompatible, Reason: v1alpha1.ProviderReasonReleaseMismatch, Message: "other"},
			want: map[string]wantCondition{
				v1alpha1.ProviderConditionAvailable:  {metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable},
				v1alpha1.ProviderConditionCompatible: {metav1.ConditionFalse, v1alpha1.ProviderReasonReleaseMismatch},
				v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonIncompatible}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := tc.ap
			ap.Status = external.Status(ap, external.Observation{Generation: ap.Generation, At: at, Problem: tc.problem}, tc.conflicts)
			checkConditions(t, ap.Status, ap.Generation, tc.want)
			if id := ap.Status.Identity; tc.identity != (id != nil) {
				t.Fatalf("identity %+v", id)
			} else if id != nil && (id.ReleaseDigest != externaltest.Release || id.ProtocolRevision != 1 || !id.ObservedAt.Time.Equal(at) ||
				len(id.Capabilities) != 2) {
				t.Fatalf("identity %+v", id)
			}
			validStatus(t, ap)
		})
	}
	builtIn := externaltest.Registration("shadow", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "konstapel-kyverno" })
	builtIn.Status = external.Status(builtIn, external.BuiltInObservation(builtIn, at), nil)
	checkConditions(t, builtIn.Status, 1, map[string]wantCondition{
		v1alpha1.ProviderConditionAvailable:  {metav1.ConditionUnknown, v1alpha1.ProviderReasonNotChecked},
		v1alpha1.ProviderConditionCompatible: {metav1.ConditionFalse, v1alpha1.ProviderReasonBuiltInProvider},
		v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonIncompatible}})
	if builtIn.Status.Identity != nil {
		t.Fatal("a built-in name has an observed identity")
	}
}

// Repeated probes keep transition times, a new revision is reported for
// itself, and conditions this controller does not own are dropped.
func TestStatusKeepsTransitionsAndRevisions(t *testing.T) {
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ap := externaltest.Registration("reporting")
	ap.Status.Conditions = []metav1.Condition{{Type: "Foreign", Status: metav1.ConditionTrue, Reason: "X", LastTransitionTime: metav1.NewTime(at)}}
	ap.Status = external.Status(ap, external.Observation{Generation: 1, At: at}, nil)
	first := meta.FindStatusCondition(ap.Status.Conditions, v1alpha1.ProviderConditionReady).LastTransitionTime
	if meta.FindStatusCondition(ap.Status.Conditions, "Foreign") != nil {
		t.Fatal("a foreign condition was kept")
	}
	time.Sleep(1100 * time.Millisecond)
	ap.Status = external.Status(ap, external.Observation{Generation: 1, At: at.Add(time.Minute)}, nil)
	if got := meta.FindStatusCondition(ap.Status.Conditions, v1alpha1.ProviderConditionReady).LastTransitionTime; !got.Equal(&first) {
		t.Fatalf("transition time moved from %s to %s", first, got)
	}
	if !ap.Status.Identity.ObservedAt.Time.Equal(at.Add(time.Minute)) {
		t.Fatalf("observedAt %s", ap.Status.Identity.ObservedAt)
	}
	ap.Generation = 2
	ap.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled
	ap.Status = external.Status(ap, external.Observation{Generation: 2, At: at.Add(2 * time.Minute)}, nil)
	checkConditions(t, ap.Status, 2, map[string]wantCondition{
		v1alpha1.ProviderConditionAvailable:  {metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable},
		v1alpha1.ProviderConditionCompatible: {metav1.ConditionTrue, v1alpha1.ProviderReasonCompatible},
		v1alpha1.ProviderConditionReady:      {metav1.ConditionFalse, v1alpha1.ProviderReasonNewRequestsDisabled}})
	validStatus(t, ap)
}

// The protocol reference documents every condition and reason the
// controller writes or returns for registrations.
func TestRegistrationReasonsAreDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/integration/external-provider-protocol.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "## Registration, selection and status")
	j := strings.Index(doc, "## What is not specified here")
	if i < 0 || j < i {
		t.Fatal("no registration section")
	}
	section := doc[i:j]
	for _, name := range []string{
		v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderConditionCompatible, v1alpha1.ProviderConditionReady,
		v1alpha1.ProviderReasonAvailable, v1alpha1.ProviderReasonTrustUnavailable, v1alpha1.ProviderReasonClientCredentialsUnavailable,
		v1alpha1.ProviderReasonEndpointUnavailable, v1alpha1.ProviderReasonAuthenticationFailed, v1alpha1.ProviderReasonInvalidDescription,
		v1alpha1.ProviderReasonNotChecked, v1alpha1.ProviderReasonCompatible, v1alpha1.ProviderReasonProviderMismatch,
		v1alpha1.ProviderReasonReleaseMismatch, v1alpha1.ProviderReasonUnsupportedProtocolVersion, v1alpha1.ProviderReasonUnsupportedContractVersion,
		v1alpha1.ProviderReasonUnsupportedEvaluatorVersion, v1alpha1.ProviderReasonUnsupportedPayloadVersion, v1alpha1.ProviderReasonUnsupportedCapability,
		v1alpha1.ProviderReasonBuiltInProvider, v1alpha1.ProviderReasonReady, v1alpha1.ProviderReasonUnavailable, v1alpha1.ProviderReasonIncompatible,
		v1alpha1.ProviderReasonNewRequestsDisabled, v1alpha1.ProviderReasonAmbiguousRegistration,
		string(provider.ReasonInvalidSelection), string(provider.ReasonUnknownProvider), string(provider.ReasonIncompatibleVersion),
		string(provider.ReasonProviderDisabled), string(provider.ReasonAmbiguousProvider), string(provider.ReasonUnsupportedCapability),
		string(provider.ReasonProviderUnavailable),
		string(external.FrozenRegistrationRemoved), string(external.FrozenRegistrationReplaced), string(external.FrozenRegistrationChanged),
		string(external.FrozenCapabilityNotFrozen),
		string(external.FrozenImplementationChanged),
	} {
		if !strings.Contains(section, "`"+name+"`") {
			t.Errorf("the registration section does not document %s", name)
		}
	}
}
