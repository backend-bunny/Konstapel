package exception

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	cluster = "kube-system:cluster-a"
	digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	policy  = "disallow-privileged-containers"
)

var (
	t0    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	alice = authenticationv1.UserInfo{Username: "alice", UID: "u-alice", Groups: []string{"team-a-editors", "system:authenticated"}}
	dave  = authenticationv1.UserInfo{Username: "dave", UID: "u-dave", Groups: []string{"team-a-editors", "system:authenticated"}}
	argo  = authenticationv1.UserInfo{Username: "system:serviceaccount:argocd:argocd-application-controller", UID: "u-argo", Groups: []string{"system:serviceaccounts", "system:authenticated"}}
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

type content struct{}

func (content) Content(_ context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	if ref.Digest != digest {
		return nil, targeting.ErrContentUnavailable
	}
	return &targeting.Content{Bundle: targeting.Bundle{Name: ref.Name, Digest: digest,
		Policies: []targeting.BundlePolicy{{Name: policy, Scope: targeting.ScopeNamespaced}}}}, nil
}

func profile(name string, el v1alpha1.ExceptionEligibility, lifetime time.Duration) *v1alpha1.ComplianceProfile {
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("p-" + name), Generation: 1}}
	p.Spec.Bundle = v1alpha1.BundleReference{Name: "example", Digest: digest}
	ex := v1alpha1.ExceptionSettings{Eligibility: el}
	if lifetime > 0 {
		ex.MaxLifetime = &metav1.Duration{Duration: lifetime}
	}
	p.Spec.Policies = []v1alpha1.ProfilePolicy{{Name: policy, Exceptions: ex}}
	return p
}

func binding(name, prof string, labels map[string]v1alpha1.LabelValue) *v1alpha1.ComplianceBinding {
	b := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("b-" + name), Generation: 1}}
	b.Spec.ProfileRef.Name = prof
	b.Spec.NamespaceSelector = &v1alpha1.NamespaceSelector{MatchLabels: labels}
	b.Spec.Mode = v1alpha1.ModeDeny
	b.Spec.EnforcementEpoch = 1
	return b
}

// world is a cluster where team-a may self-serve and team-prod also has a
// Forbidden contribution.
func world(t *testing.T) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", UID: "ns-a-1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-prod", UID: "ns-p-1", Labels: map[string]string{"env": "prod"}}},
		profile("self-service", v1alpha1.ExceptionsSelfService, 720*time.Hour),
		profile("no-exceptions", v1alpha1.ExceptionsForbidden, 0),
		binding("baseline", "self-service", nil),
		binding("pci", "no-exceptions", map[string]v1alpha1.LabelValue{"env": "prod"}),
	).Build()
}

func newHandlers(t *testing.T, c client.Client, now time.Time) (*Mutator, *Validator) {
	t.Helper()
	m, v := NewHandlers(scheme(t), c, content{}, cluster)
	m.Now = func() time.Time { return now }
	v.Now = m.Now
	return m, v
}

func exceptionObj(ns string, rev int64, annotations map[string]string) *v1alpha1.ComplianceException {
	return &v1alpha1.ComplianceException{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "ComplianceException"},
		ObjectMeta: metav1.ObjectMeta{Name: "priv", Namespace: ns, Annotations: annotations},
		Spec: v1alpha1.ComplianceExceptionSpec{Policy: policy, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
			Reason: "debugging", ExpiresAt: metav1.NewTime(t0.Add(48 * time.Hour)), AcceptanceRevision: rev},
	}
}

func request(t *testing.T, op admissionv1.Operation, user authenticationv1.UserInfo, obj, old *v1alpha1.ComplianceException) admission.Request {
	t.Helper()
	raw := func(o *v1alpha1.ComplianceException) runtime.RawExtension {
		if o == nil {
			return runtime.RawExtension{}
		}
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		return runtime.RawExtension{Raw: b}
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, Namespace: obj.Namespace, Name: obj.Name, UserInfo: user,
		Object: raw(obj), OldObject: raw(old), DryRun: ptr.To(false),
	}}
}

// admit runs the mutating then validating webhook, as the API server does,
// and returns the stored object or the validating denial.
func admit(t *testing.T, m *Mutator, v *Validator, req admission.Request) (*v1alpha1.ComplianceException, error) {
	t.Helper()
	if resp := m.Handle(context.Background(), req); !resp.Allowed {
		return nil, errors.New(resp.Result.Message)
	}
	updated, err := m.record(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if updated != nil {
		raw, _ := json.Marshal(updated)
		req.Object.Raw = raw
	}
	if resp := v.Handle(context.Background(), req); !resp.Allowed {
		return nil, errors.New(resp.Result.Message)
	}
	out := &v1alpha1.ComplianceException{}
	if err := json.Unmarshal(req.Object.Raw, out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func acceptanceOf(t *testing.T, ex *v1alpha1.ComplianceException) Acceptance {
	t.Helper()
	var a Acceptance
	if err := json.Unmarshal([]byte(ex.Annotations[AcceptanceAnnotation]), &a); err != nil {
		t.Fatalf("acceptance annotation: %v", err)
	}
	return a
}

func revisions(a Acceptance) []string {
	if a.Eligibility == nil {
		return nil
	}
	var out []string
	for _, c := range a.Eligibility.Contributors {
		out = append(out, c.Binding.Name+"@"+c.Revision)
	}
	return out
}

func TestCreateRecordsAuthenticatedAcceptance(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	forged, _ := json.Marshal(Acceptance{Revision: 1, Actor: Actor{Username: "platform-admin"}, Cluster: cluster,
		Namespace: targeting.NamespaceRef{Name: "team-a"}, Policy: policy})
	got, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, map[string]string{AcceptanceAnnotation: string(forged)}), nil))
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceOf(t, got)
	if a.Actor.Username != "alice" || a.Actor.UID != "u-alice" || !slices.Equal(a.Actor.Groups, alice.Groups) {
		t.Errorf("forged actor survived admission: %+v", a.Actor)
	}
	if a.Revision != 1 || !a.AcceptedAt.Time.Equal(t0) || a.Cluster != cluster || a.Policy != policy {
		t.Errorf("acceptance = %+v", a)
	}
	if a.Namespace != (targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}) {
		t.Errorf("namespace identity = %+v", a.Namespace)
	}
	if a.Eligibility == nil || a.Eligibility.Effective != v1alpha1.ExceptionsSelfService || len(revisions(a)) != 1 || !strings.HasPrefix(revisions(a)[0], "baseline@") {
		t.Errorf("resolved set = %+v", a.Eligibility)
	}
}

// Capture records the full resolved set, including restrictive contributions;
// rejecting them is task 2.3.
func TestCreateCapturesEveryContribution(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	got, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-prod", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceOf(t, got)
	if a.Eligibility.Effective != v1alpha1.ExceptionsForbidden || len(revisions(a)) != 2 {
		t.Errorf("resolved set = %+v", a.Eligibility)
	}
}

func TestDryRunMatchesAndWritesNothing(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	req := request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil)
	req.DryRun = ptr.To(true)
	before := snapshot(t, c)
	got, err := admit(t, m, v, req)
	if err != nil {
		t.Fatal(err)
	}
	if acceptanceOf(t, got).Actor.Username != "alice" {
		t.Error("dry run should show the acceptance that would be recorded")
	}
	if after := snapshot(t, c); after != before {
		t.Error("admission changed cluster state")
	}
}

func snapshot(t *testing.T, c client.Client) string {
	t.Helper()
	var out []any
	for _, l := range []client.ObjectList{&corev1.NamespaceList{}, &v1alpha1.ComplianceBindingList{}, &v1alpha1.ComplianceProfileList{}, &v1alpha1.ComplianceExceptionList{}} {
		if err := c.List(context.Background(), l); err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func TestMetadataEditsKeepTheAcceptance(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	created, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	accepted := created.Annotations[AcceptanceAnnotation]

	// Later configuration must not replace the accepted set.
	if err := c.Delete(context.Background(), binding("baseline", "self-service", nil)); err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return t0.Add(time.Hour) }

	edited := created.DeepCopy()
	edited.Labels = map[string]string{"team": "a"}
	got, err := admit(t, m, v, request(t, admissionv1.Update, dave, edited, created))
	if err != nil {
		t.Fatalf("metadata edit rejected: %v", err)
	}
	if got.Annotations[AcceptanceAnnotation] != accepted {
		t.Error("a metadata edit re-recorded the acceptance")
	}

	forged := created.DeepCopy()
	a := acceptanceOf(t, created)
	a.Actor = Actor{Username: "platform-admin"}
	raw, _ := json.Marshal(a)
	forged.Annotations[AcceptanceAnnotation] = string(raw)
	if _, err := admit(t, m, v, request(t, admissionv1.Update, alice, forged, created)); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Errorf("forged acceptance edit: %v", err)
	}

	removed := created.DeepCopy()
	delete(removed.Annotations, AcceptanceAnnotation)
	if _, err := admit(t, m, v, request(t, admissionv1.Update, alice, removed, created)); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Errorf("removed acceptance: %v", err)
	}
}

func TestRenewalRecordsANewAcceptance(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	created, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	// An extra contribution appears after the first acceptance.
	if err := c.Create(context.Background(), binding("extra", "self-service", nil)); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(24 * time.Hour)
	m.Now = func() time.Time { return later }
	v.Now = m.Now
	renewed := created.DeepCopy()
	renewed.Spec.AcceptanceRevision = 2
	renewed.Spec.Reason = "still needed"
	renewed.Spec.ExpiresAt = metav1.NewTime(later.Add(48 * time.Hour))
	got, err := admit(t, m, v, request(t, admissionv1.Update, dave, renewed, created))
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceOf(t, got)
	if a.Revision != 2 || a.Actor.Username != "dave" || !a.AcceptedAt.Time.Equal(later) || len(revisions(a)) != 2 {
		t.Errorf("renewal = %+v contributors %v", a, revisions(a))
	}
	if first := acceptanceOf(t, created); first.Revision != 1 || first.Actor.Username != "alice" || len(revisions(first)) != 1 {
		t.Errorf("first acceptance changed: %+v", first)
	}
}

// Without the mutating webhook, a caller-written record must still match the
// operation: another identity, revision, cluster or time is rejected.
func TestValidatorRejectsRecordsOfOtherOperations(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	good, err := m.record(context.Background(), request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	base := acceptanceOf(t, good)
	cases := map[string]func(a *Acceptance, ex *v1alpha1.ComplianceException){
		"other actor": func(a *Acceptance, _ *v1alpha1.ComplianceException) { a.Actor.Username = "platform-admin" },
		"other uid":   func(a *Acceptance, _ *v1alpha1.ComplianceException) { a.Actor.UID = "u-admin" },
		"extra group": func(a *Acceptance, _ *v1alpha1.ComplianceException) {
			a.Actor.Groups = append(a.Actor.Groups, "system:masters")
		},
		"other revision": func(a *Acceptance, _ *v1alpha1.ComplianceException) { a.Revision = 2 },
		"other cluster":  func(a *Acceptance, _ *v1alpha1.ComplianceException) { a.Cluster = "kube-system:other" },
		"backdated": func(a *Acceptance, _ *v1alpha1.ComplianceException) {
			a.AcceptedAt = metav1.NewTime(t0.Add(-time.Hour))
		},
		"other policy":   func(a *Acceptance, _ *v1alpha1.ComplianceException) { a.Policy = "other" },
		"claim mismatch": func(_ *Acceptance, ex *v1alpha1.ComplianceException) { ex.Annotations[ClaimAnnotation] = "ticket" },
		"missing":        nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ex := exceptionObj("team-a", 1, map[string]string{})
			if mutate != nil {
				a := base
				a.Actor.Groups = slices.Clone(base.Actor.Groups)
				mutate(&a, ex)
				raw, _ := json.Marshal(a)
				ex.Annotations[AcceptanceAnnotation] = string(raw)
			}
			if resp := v.Handle(context.Background(), request(t, admissionv1.Create, alice, ex, nil)); resp.Allowed {
				t.Error("allowed")
			}
		})
	}
	ex := exceptionObj("team-a", 1, map[string]string{})
	raw, _ := json.Marshal(base)
	ex.Annotations[AcceptanceAnnotation] = string(raw)
	if resp := v.Handle(context.Background(), request(t, admissionv1.Create, alice, ex, nil)); !resp.Allowed {
		t.Errorf("matching record rejected: %s", resp.Result.Message)
	}
}

func TestGitOpsActorIsDistinctFromClaim(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	claim := "commit author carol <carol@example.com>, ticket SEC-7"
	got, err := admit(t, m, v, request(t, admissionv1.Create, argo, exceptionObj("team-a", 1, map[string]string{ClaimAnnotation: claim}), nil))
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceOf(t, got)
	if a.Actor.Username != argo.Username || a.Claim != claim {
		t.Errorf("actor %q claim %q", a.Actor.Username, a.Claim)
	}
}

func TestAdmissionFailsClosed(t *testing.T) {
	// The namespace is unknown to the controller: no acceptance is recorded.
	m, _ := newHandlers(t, world(t), t0)
	if resp := m.Handle(context.Background(), request(t, admissionv1.Create, alice, exceptionObj("missing", 1, nil), nil)); resp.Allowed {
		t.Error("acceptance in an unreadable namespace was allowed")
	}
	m.Resolver = failing{}
	if resp := m.Handle(context.Background(), request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil)); resp.Allowed {
		t.Error("acceptance without a resolved set was allowed")
	}
}

type failing struct{}

func (failing) Eligibility(context.Context, targeting.NamespaceRef, string) (*targeting.Eligibility, error) {
	return nil, errors.New("api unavailable")
}

func TestRecreatedNamespaceIsNotResolved(t *testing.T) {
	r := &ClusterResolver{Reader: world(t), Content: content{}, Cluster: cluster}
	if _, err := r.Eligibility(context.Background(), targeting.NamespaceRef{Name: "team-a", UID: "ns-a-0"}, policy); err == nil {
		t.Error("a stale namespace identity resolved")
	}
	el, err := r.Eligibility(context.Background(), targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}, "not-applied")
	if err != nil || el != nil {
		t.Errorf("unapplied policy: %v %v", el, err)
	}
}
