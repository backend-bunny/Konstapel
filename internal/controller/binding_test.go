package controller

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var content = targeting.LocalContent{Root: "../../content", Name: "konstapel-vendored",
	Policies: map[string]string{assessment.PolicyName: assessment.SourcePolicy}}

func digest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	c, err := content.Content(context.Background(), v1alpha1.BundleReference{Name: content.Name, Digest: "sha256:" + sha256Bytes(b)})
	if err != nil {
		t.Fatal(err)
	}
	return c.Bundle.Digest
}

func sha256Bytes(b []byte) string { return sha256Hex(string(b)) }

type env struct {
	t      *testing.T
	c      client.Client
	ready  map[string]bool
	engine bool
	r      *BindingReconciler
}

func newEnv(t *testing.T, objs ...client.Object) *env {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(targeting.ValidatingPolicyGVK, meta.RESTScopeRoot)
	for _, k := range []string{"ComplianceBinding", "ComplianceProfile"} {
		mapper.Add(v1alpha1.GroupVersion.WithKind(k), meta.RESTScopeRoot)
	}
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithRESTMapper(mapper).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.ComplianceBinding{}, &v1alpha1.ComplianceProfile{}).
		WithIndex(&v1alpha1.ComplianceBinding{}, ProfileRefIndex, func(o client.Object) []string {
			return []string{o.(*v1alpha1.ComplianceBinding).Spec.ProfileRef.Name}
		}).Build()
	e := &env{t: t, c: c, ready: map[string]bool{}, engine: true}
	e.r = &BindingReconciler{Client: c, Content: content, Cluster: "kube-system:test",
		Engine: func(context.Context) (bool, error) { return e.engine, nil },
		Ready:  func(o *unstructured.Unstructured) bool { return e.ready[o.GetName()] }}
	return e
}

func nsObj(name string, kv ...string) *corev1.Namespace {
	l := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Labels: l}}
}

func profileObj(t *testing.T, name string, policies ...string) *v1alpha1.ComplianceProfile {
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Generation: 1},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}}}
	for _, pol := range policies {
		p.Spec.Policies = append(p.Spec.Policies, v1alpha1.ProfilePolicy{Name: pol})
	}
	return p
}

func bindingObj(name, profile string, mode v1alpha1.EnforcementMode, sel map[string]v1alpha1.LabelValue) *v1alpha1.ComplianceBinding {
	return &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Generation: 1},
		Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: profile}, Mode: mode,
			NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: sel}}}
}

func (e *env) reconcile(name string) ctrl.Result {
	e.t.Helper()
	res, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *env) binding(name string) *v1alpha1.ComplianceBinding {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, b); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) policies() []unstructured.Unstructured {
	e.t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := e.c.List(context.Background(), list); err != nil {
		e.t.Fatal(err)
	}
	slices.SortFunc(list.Items, func(a, b unstructured.Unstructured) int { return strings.Compare(a.GetName(), b.GetName()) })
	return list.Items
}

func (e *env) markAllReady() {
	for _, p := range e.policies() {
		e.ready[p.GetName()] = true
	}
}

func cond(b *v1alpha1.ComplianceBinding, typ string) metav1.Condition {
	c := meta.FindStatusCondition(b.Status.Conditions, typ)
	if c == nil {
		return metav1.Condition{}
	}
	return *c
}

// requireNotCurrent asserts a binding cannot be read as current, ready enforcement.
func requireNotCurrent(t *testing.T, b *v1alpha1.ComplianceBinding, reason string) {
	t.Helper()
	if c := cond(b, v1alpha1.ConditionEngineReady); c.Status != metav1.ConditionFalse || c.Reason != reason {
		t.Fatalf("EngineReady = %s/%s (%s), want False/%s", c.Status, c.Reason, c.Message, reason)
	}
}

func requireObserved(t *testing.T, b *v1alpha1.ComplianceBinding) {
	t.Helper()
	if b.Status.ObservedGeneration != b.Generation {
		t.Fatalf("observedGeneration %d, generation %d", b.Status.ObservedGeneration, b.Generation)
	}
	for _, c := range b.Status.Conditions {
		if c.ObservedGeneration != b.Generation {
			t.Fatalf("condition %s observedGeneration %d, generation %d", c.Type, c.ObservedGeneration, b.Generation)
		}
	}
}

const pol = assessment.PolicyName

func TestBindingBecomesReadyOnlyWhenEngineAccepts(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"), nsObj("dev"),
		profileObj(t, "baseline", pol), bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))

	if res := e.reconcile("deny-prod"); res.RequeueAfter != TransitionRequeue {
		t.Fatalf("not-ready policy must requeue, got %+v", res)
	}
	b := e.binding("deny-prod")
	requireObserved(t, b)
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionTrue {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonReplacementPending)

	e.markAllReady()
	if res := e.reconcile("deny-prod"); res.RequeueAfter != 0 {
		t.Fatalf("ready binding requeued: %+v", res)
	}
	b = e.binding("deny-prod")
	requireObserved(t, b)
	ready := cond(b, v1alpha1.ConditionEngineReady)
	if ready.Status != metav1.ConditionTrue || !strings.Contains(ready.Message, "not a compliance result") {
		t.Fatalf("EngineReady %+v", ready)
	}
	if *b.Status.TargetCount != 1 || b.Status.Profile == nil || b.Status.Profile.Generation != 1 || b.Status.Profile.BundleDigest != digest(t) || !strings.HasPrefix(b.Status.ConfigurationRevision, "sha256:") {
		t.Fatalf("status %+v", b.Status)
	}
	if p := e.policies(); len(p) != 1 || p[0].GetAnnotations()[targeting.AnnotationRevision] != b.Status.ConfigurationRevision {
		t.Fatalf("policies %v", p)
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"),
		profileObj(t, "baseline", pol), bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	bindingRV := e.binding("deny-prod").ResourceVersion
	policyRV := e.policies()[0].GetResourceVersion()
	for range 3 {
		e.reconcile("deny-prod")
	}
	if e.binding("deny-prod").ResourceVersion != bindingRV {
		t.Error("an unchanged reconcile rewrote binding status")
	}
	if e.policies()[0].GetResourceVersion() != policyRV {
		t.Error("an unchanged reconcile rewrote the engine policy")
	}
}

func TestNamespaceChangesUpdateStatusWithoutPolicyWrites(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"), nsObj("dev"),
		profileObj(t, "baseline", pol), bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	policyRV := e.policies()[0].GetResourceVersion()

	dev := &corev1.Namespace{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "dev"}, dev)
	dev.Labels = map[string]string{"environment": "production"}
	if err := e.c.Update(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	e.reconcile("deny-prod")
	b := e.binding("deny-prod")
	if *b.Status.TargetCount != 2 || cond(b, v1alpha1.ConditionEngineReady).Status != metav1.ConditionTrue {
		t.Fatalf("status after relabel %+v", b.Status)
	}
	if e.policies()[0].GetResourceVersion() != policyRV {
		t.Fatal("a namespace relabel rewrote the engine policy")
	}
}

func TestZeroTargetsIsReadyButExplicitlyZero(t *testing.T) {
	e := newEnv(t, nsObj("dev"), profileObj(t, "baseline", pol),
		bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	b := e.binding("deny-prod")
	if b.Status.TargetCount == nil || *b.Status.TargetCount != 0 {
		t.Fatalf("targetCount must be an explicit 0: %v", b.Status.TargetCount)
	}
	if m := cond(b, v1alpha1.ConditionEngineReady).Message; !strings.Contains(m, "0 namespaces") || !strings.Contains(m, "not a compliance result") {
		t.Fatalf("message %q", m)
	}
}

func TestMissingProfileKeepsAppliedPoliciesAndIsNotCurrent(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	e := newEnv(t, nsObj("prod", "environment", "production"), p,
		bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	applied := e.policies()[0].GetName()

	if err := e.c.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.reconcile("deny-prod")
	b := e.binding("deny-prod")
	requireObserved(t, b)
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonProfileNotFound {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
	if !strings.Contains(cond(b, v1alpha1.ConditionEngineReady).Message, applied) {
		t.Fatal("status must name the retained last-applied policy")
	}
	if p := e.policies(); len(p) != 1 || p[0].GetName() != applied {
		t.Fatalf("working enforcement withdrawn: %v", p)
	}
}

func TestMissingProfileWithNothingAppliedCreatesNothing(t *testing.T) {
	e := newEnv(t, nsObj("prod"), bindingObj("orphan", "absent", v1alpha1.ModeDeny, nil))
	e.reconcile("orphan")
	b := e.binding("orphan")
	requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
	if len(e.policies()) != 0 {
		t.Fatal("policies created without a profile")
	}
}

func TestUnavailableContentKeepsAppliedPolicies(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(p), p)
	p.Spec.Bundle.Digest = "sha256:" + strings.Repeat("0", 64)
	p.Generation = 2
	if err := e.c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.reconcile("all")
	b := e.binding("all")
	if c := cond(b, v1alpha1.ConditionResolved); c.Reason != v1alpha1.ReasonContentUnavailable {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
	if len(e.policies()) != 1 {
		t.Fatal("unavailable content withdrew applied enforcement")
	}
}

func TestFailedReplacementIsNotCurrent(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	old := e.policies()[0].GetName()

	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	p.Generation = 2
	if err := e.c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	for range 3 { // the engine never accepts the replacement
		if res := e.reconcile("all"); res.RequeueAfter == 0 {
			t.Fatal("pending replacement must requeue")
		}
	}
	b := e.binding("all")
	requireNotCurrent(t, b, v1alpha1.ReasonReplacementPending)
	if b.Status.Profile.Generation != 2 {
		t.Fatal("status must report the profile generation being applied")
	}
	names := []string{}
	for _, p := range e.policies() {
		names = append(names, p.GetName())
	}
	if len(names) != 2 || !slices.Contains(names, old) {
		t.Fatalf("old revision must stay until the replacement is ready: %v", names)
	}
}

func TestEngineUnavailableIsReportedAndNothingIsWritten(t *testing.T) {
	e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	e.engine = false
	if res := e.reconcile("all"); res.RequeueAfter == 0 {
		t.Fatal("an unavailable engine must be retried")
	}
	requireNotCurrent(t, e.binding("all"), ReasonEngineUnavailable)
	if len(e.policies()) != 0 {
		t.Fatal("policies written while the engine is unavailable")
	}
	e.engine = true
	e.reconcile("all")
	if len(e.policies()) != 1 {
		t.Fatal("delivery did not resume when the engine returned")
	}
}

func TestOwnershipConflictIsReported(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	b := bindingObj("all", "baseline", v1alpha1.ModeAudit, nil)
	e := newEnv(t, nsObj("prod"), p, b)
	e.reconcile("all")
	name := e.policies()[0].GetName()
	// Replace the owned policy with an unmanaged one of the same name.
	for _, o := range e.policies() {
		_ = e.c.Delete(context.Background(), &o)
	}
	squatter := &unstructured.Unstructured{}
	squatter.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	squatter.SetName(name)
	if err := e.c.Create(context.Background(), squatter); err != nil {
		t.Fatal(err)
	}
	// Unmanaged policies are not watched, so the conflict must be re-checked.
	if res := e.reconcile("all"); res.RequeueAfter != ConflictRequeue {
		t.Fatalf("conflict not re-checked: %+v", res)
	}
	requireNotCurrent(t, e.binding("all"), v1alpha1.ReasonOwnershipConflict)
	// Once the unmanaged resource is gone, the next check delivers again.
	if err := e.c.Delete(context.Background(), squatter); err != nil {
		t.Fatal(err)
	}
	e.reconcile("all")
	if len(e.policies()) != 1 || e.policies()[0].GetLabels()[targeting.LabelManagedBy] != targeting.ManagedByValue {
		t.Fatal("delivery did not resume after the conflict was removed")
	}
}

func TestStatusIsBounded(t *testing.T) {
	var policies []string
	for i := range 40 {
		policies = append(policies, strings.Repeat("x", 200)+string(rune('a'+i%26))+strings.Repeat("y", i))
	}
	e := newEnv(t, nsObj("prod"), profileObj(t, "big", policies...), bindingObj("all", "big", v1alpha1.ModeAudit, nil))
	e.reconcile("all")
	for _, c := range e.binding("all").Status.Conditions {
		if len(c.Message) > maxMessage {
			t.Fatalf("condition %s message is %d bytes", c.Type, len(c.Message))
		}
	}
}

func TestProfileReconciler(t *testing.T) {
	good := profileObj(t, "good", pol)
	unknown := profileObj(t, "unknown", "does-not-exist")
	missing := profileObj(t, "missing", pol)
	missing.Spec.Bundle.Digest = "sha256:" + strings.Repeat("1", 64)
	e := newEnv(t, good, unknown, missing)
	pr := &ProfileReconciler{Client: e.c, Content: content}
	for name, want := range map[string]string{"good": v1alpha1.ReasonResolutionSucceeded, "unknown": v1alpha1.ReasonUnknownPolicy, "missing": v1alpha1.ReasonContentUnavailable} {
		if _, err := pr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatal(err)
		}
		p := &v1alpha1.ComplianceProfile{}
		_ = e.c.Get(context.Background(), client.ObjectKey{Name: name}, p)
		c := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionResolved)
		if c == nil || c.Reason != want || c.ObservedGeneration != p.Generation || p.Status.ObservedGeneration != p.Generation {
			t.Errorf("%s: %+v", name, p.Status)
		}
	}
}

func TestNamespaceEventsEnqueueOnlyMatchingBindings(t *testing.T) {
	e := newEnv(t, profileObj(t, "baseline", pol),
		bindingObj("prod-only", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}),
		bindingObj("dev-only", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "development"}),
		bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	h := namespaceHandler(e.c)
	queued := func(f func(workqueue.TypedRateLimitingInterface[reconcile.Request])) []string {
		q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
		defer q.ShutDown()
		f(q)
		var out []string
		for q.Len() > 0 {
			r, _ := q.Get()
			out = append(out, r.Name)
			q.Done(r)
		}
		slices.Sort(out)
		return out
	}
	ctx := context.Background()
	got := queued(func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		h.Create(ctx, event.CreateEvent{Object: nsObj("x", "environment", "production")}, q)
	})
	if !slices.Equal(got, []string{"all", "prod-only"}) {
		t.Errorf("create: %v", got)
	}
	got = queued(func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		h.Update(ctx, event.UpdateEvent{ObjectOld: nsObj("x", "environment", "production"), ObjectNew: nsObj("x", "environment", "development")}, q)
	})
	if !slices.Equal(got, []string{"all", "dev-only", "prod-only"}) {
		t.Errorf("relabel must reach bindings matching old or new labels: %v", got)
	}
	unchanged := nsObj("x", "environment", "production")
	annotated := unchanged.DeepCopy()
	annotated.Annotations = map[string]string{"a": "b"}
	got = queued(func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		h.Update(ctx, event.UpdateEvent{ObjectOld: unchanged, ObjectNew: annotated}, q)
	})
	if len(got) != 0 {
		t.Errorf("non-label updates must not enqueue: %v", got)
	}
}

func TestBindingsForProfileUsesIndex(t *testing.T) {
	e := newEnv(t, profileObj(t, "a", pol), profileObj(t, "b", pol),
		bindingObj("x", "a", v1alpha1.ModeAudit, nil), bindingObj("y", "b", v1alpha1.ModeAudit, nil), bindingObj("z", "a", v1alpha1.ModeDeny, nil))
	reqs := bindingsForProfile(e.c)(context.Background(), profileObj(t, "a", pol))
	var names []string
	for _, r := range reqs {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"x", "z"}) {
		t.Fatalf("profile a maps to %v", names)
	}
}

// A reporting-only edit (spec.assessment) advances the binding generation but
// not its enforcement epoch. It must not write to engine policies at all.
func TestReportingOnlyEditWritesNoEnginePolicy(t *testing.T) {
	b := bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"})
	b.Spec.EnforcementEpoch = 1
	e := newEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b)
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	before := e.policies()[0]

	live := e.binding("deny-prod")
	live.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "12h"}
	live.Generation = 2 // the fake client does not advance generation
	if err := e.c.Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	e.reconcile("deny-prod")
	after := e.policies()
	if len(after) != 1 || after[0].GetName() != before.GetName() || after[0].GetResourceVersion() != before.GetResourceVersion() {
		t.Fatalf("reporting-only edit wrote engine policies: %s@%s -> %v", before.GetName(), before.GetResourceVersion(), after)
	}
	if got := e.binding("deny-prod"); got.Status.ObservedGeneration != 2 || cond(got, v1alpha1.ConditionEngineReady).Status != metav1.ConditionTrue {
		t.Fatalf("status after reporting-only edit: %+v", got.Status)
	}
}

// statusJSON encodes a value for byte-identical comparison.
func statusJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func assessmentStatus() *v1alpha1.BindingAssessmentStatus {
	at := metav1.NewTime(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC))
	return &v1alpha1.BindingAssessmentStatus{
		Schedule: &v1alpha1.AssessmentSchedule{Anchor: at, Interval: "24h", LastScheduled: &at, MissedTotal: 2,
			Gaps: []v1alpha1.MissedInterval{{From: at, To: at, Missed: 2}}},
		Current: &v1alpha1.CurrentEvidence{Evidence: v1alpha1.EvidenceSummary{Completeness: "Incomplete", Expected: 1, Missing: 1},
			EvaluatedAt: at, Limitations: []string{"no attributable report yet"}},
		LatestRun: &v1alpha1.RunReference{Name: "run", UID: "run-uid"},
	}
}

// The assessment controller owns status.assessment; this reconciler carries it
// forward byte-identical, including when its own fields change.
func TestReconcileCarriesAssessmentStatusForward(t *testing.T) {
	b := bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"})
	e := newEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b)
	got := e.binding("deny-prod")
	got.Status.Assessment = assessmentStatus()
	if err := e.c.Status().Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	want := statusJSON(got.Status.Assessment)

	e.reconcile("deny-prod") // policies not ready yet
	if b := e.binding("deny-prod"); statusJSON(b.Status.Assessment) != want || cond(b, v1alpha1.ConditionEngineReady).Status != metav1.ConditionFalse {
		t.Fatalf("assessment status changed on first reconcile: %s", statusJSON(b.Status.Assessment))
	}
	e.markAllReady()
	e.reconcile("deny-prod") // EngineReady False -> True: this reconciler writes
	b = e.binding("deny-prod")
	if cond(b, v1alpha1.ConditionEngineReady).Status != metav1.ConditionTrue {
		t.Fatal("own status did not change; the carry-forward was not exercised")
	}
	if statusJSON(b.Status.Assessment) != want {
		t.Fatalf("assessment status not carried forward:\nwant %s\ngot  %s", want, statusJSON(b.Status.Assessment))
	}
}

// staleReader returns a binding as it was before a concurrent status write.
type staleReader struct {
	client.Client
	stale *v1alpha1.ComplianceBinding
}

func (s staleReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if b, ok := obj.(*v1alpha1.ComplianceBinding); ok && key.Name == s.stale.Name {
		s.stale.DeepCopyInto(b)
		return nil
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

// A reconcile from a stale read after the assessment controller wrote status
// gets a Conflict and returns it for a retry; it never clobbers the write.
func TestStaleStatusWriteConflictsInsteadOfClobbering(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	stale := e.binding("deny-prod")
	fresh := stale.DeepCopy()
	fresh.Status.Assessment = assessmentStatus()
	if err := e.c.Status().Update(context.Background(), fresh); err != nil { // the concurrent assessment write
		t.Fatal(err)
	}
	e.r.Client = staleReader{Client: e.c, stale: stale}
	_, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "deny-prod"}})
	if !apierrors.IsConflict(err) {
		t.Fatalf("stale status write must return a conflict for retry, got %v", err)
	}
	if b := e.binding("deny-prod"); b.Status.Assessment == nil || statusJSON(b.Status.Assessment) != statusJSON(fresh.Status.Assessment) {
		t.Fatal("stale reconcile clobbered status.assessment")
	}
}
