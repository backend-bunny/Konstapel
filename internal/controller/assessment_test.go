package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var a0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type assessEnv struct {
	t   *testing.T
	c   client.Client
	tr  *BindingReconciler
	ar  *AssessmentReconciler
	now time.Time
}

// newAssessEnv runs the targeting reconciler (to deliver real engine
// policies) and the assessment reconciler against one fake cluster.
func newAssessEnv(t *testing.T, objs ...client.Object) *assessEnv {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(targeting.ValidatingPolicyGVK, meta.RESTScopeRoot)
	mapper.Add(PolicyReportGVK, meta.RESTScopeNamespace)
	for _, k := range []string{"ComplianceBinding", "ComplianceProfile", "AssessmentRun"} {
		mapper.Add(v1alpha1.GroupVersion.WithKind(k), meta.RESTScopeRoot)
	}
	mapper.Add(v1alpha1.GroupVersion.WithKind("AssessmentRequest"), meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	for _, gvk := range []schema.GroupVersionKind{{Version: "v1", Kind: "Pod"}, {Version: "v1", Kind: "ReplicationController"},
		{Group: "apps", Version: "v1", Kind: "Deployment"}, {Group: "apps", Version: "v1", Kind: "DaemonSet"}, {Group: "apps", Version: "v1", Kind: "StatefulSet"},
		{Group: "apps", Version: "v1", Kind: "ReplicaSet"}, {Group: "batch", Version: "v1", Kind: "Job"}, {Group: "batch", Version: "v1", Kind: "CronJob"}} {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithRESTMapper(mapper).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.ComplianceBinding{}, &v1alpha1.ComplianceProfile{}, &v1alpha1.AssessmentRun{}).
		// The API server assigns UIDs on create; the fake client does not.
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("uid-" + obj.GetName()))
			}
			return c.Create(ctx, obj, opts...)
		}}).Build()
	e := &assessEnv{t: t, c: c, now: a0}
	e.tr = &BindingReconciler{Client: c, Content: content, Cluster: "kube-system:test",
		Engine: func(context.Context) (bool, error) { return true, nil },
		Ready:  func(*unstructured.Unstructured) bool { return true }}
	e.ar = &AssessmentReconciler{Client: c, Content: content, Cluster: "kube-system:test", Boundaries: NewBoundaryTracker(),
		Engine: func(context.Context) (bool, error) { return true, nil }, Now: func() time.Time { return e.now }}
	return e
}

func (e *assessEnv) deliver(name string) {
	e.t.Helper()
	for range 2 {
		if _, err := e.tr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *assessEnv) assess(name string) ctrl.Result {
	e.t.Helper()
	res, err := e.ar.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *assessEnv) current(name string) *v1alpha1.CurrentEvidence {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, b); err != nil {
		e.t.Fatal(err)
	}
	if b.Status.Assessment == nil || b.Status.Assessment.Current == nil {
		e.t.Fatalf("no current evidence on %s", name)
	}
	return b.Status.Assessment.Current
}

func (e *assessEnv) enginePolicy() string {
	e.t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := e.c.List(context.Background(), list); err != nil || len(list.Items) != 1 {
		e.t.Fatalf("want one engine policy: %v %d", err, len(list.Items))
	}
	return list.Items[0].GetName()
}

// report writes a PolicyReport for pod with one result evaluated at at.
func (e *assessEnv) report(ns, podUID, policy, outcome string, at time.Time) {
	e.t.Helper()
	r := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "r-" + podUID, "namespace": ns},
		"scope":    map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": ns, "name": "web", "uid": podUID},
		"results": []any{map[string]any{"policy": policy, "result": outcome, "source": "KyvernoValidatingPolicy",
			"properties": map[string]any{"cel.validationIndex": "0"},
			"timestamp":  map[string]any{"seconds": at.Unix(), "nanos": int64(0)}}},
	}}
	r.SetGroupVersionKind(PolicyReportGVK)
	r.SetUID(types.UID("report-" + podUID))
	if err := e.c.Create(context.Background(), r); err != nil {
		e.t.Fatal(err)
	}
}

func privilegedPod(ns, name, uid string) *corev1.Pod {
	yes := true
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), Labels: map[string]string{"app": name}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
}

func epochBinding(name string, sel map[string]v1alpha1.LabelValue) *v1alpha1.ComplianceBinding {
	b := bindingObj(name, "baseline", v1alpha1.ModeAudit, sel)
	b.Spec.EnforcementEpoch = 1
	return b
}

func TestCurrentEvidenceRequiresEvaluationAfterObservation(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}), privilegedPod("prod", "web", "pod-1"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()

	// A report evaluated before the controller observed the pod's state is
	// not proof about that state.
	e.report("prod", "pod-1", policy, "fail", a0.Add(-10*time.Minute))
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	if cur.Evidence.Completeness != "Incomplete" || cur.Evidence.Rejected != 1 || cur.Outcomes.Fail != 0 {
		t.Fatalf("pre-observation report counted: %+v", cur.Evidence)
	}

	// A re-evaluation after observation is attributable; failures are kept.
	_ = e.c.DeleteAllOf(context.Background(), reportList(), client.InNamespace("prod"))
	e.report("prod", "pod-1", policy, "fail", a0.Add(5*time.Minute))
	e.now = a0.Add(6 * time.Minute)
	res := e.assess("audit-prod")
	cur = e.current("audit-prod")
	if cur.Evidence.Completeness != "Complete" || cur.Evidence.Expected != 1 || cur.Outcomes.Fail != 1 || cur.NextExpiry == nil {
		t.Fatalf("attributable evidence not reported: %+v %+v", cur.Evidence, cur.Outcomes)
	}
	// Requeue at expiry: 2h after evaluation, not at a 24h snapshot tick.
	if want := a0.Add(5*time.Minute + 2*time.Hour).Sub(e.now); res.RequeueAfter < want || res.RequeueAfter > want+2*time.Second {
		t.Fatalf("requeue %v, want ~%v", res.RequeueAfter, want)
	}
	e.now = a0.Add(5*time.Minute + 2*time.Hour + time.Second)
	e.assess("audit-prod")
	if cur = e.current("audit-prod"); cur.Evidence.Completeness != "Incomplete" || cur.Evidence.Rejected != 1 {
		t.Fatalf("expired evidence still current: %+v", cur.Evidence)
	}
}

func reportList() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(PolicyReportGVK)
	return u
}

func TestUndeliveredEnginePolicyIsStaleScope(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}), privilegedPod("prod", "web", "pod-1"))
	e.assess("audit-prod") // targeting has not delivered anything
	cur := e.current("audit-prod")
	if cur.Evidence.Completeness != "Incomplete" || cur.Evidence.StaleScopes != 1 || cur.Evidence.Expected != 0 {
		t.Fatalf("undelivered policy hidden: %+v", cur.Evidence)
	}
	if !strings.Contains(strings.Join(cur.Limitations, ";"), "is not delivered") {
		t.Fatal(cur.Limitations)
	}
}

func TestZeroTargetsAndMissingEpoch(t *testing.T) {
	b := bindingObj("nobody", "baseline", v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{"environment": "none"})
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b)
	e.assess("nobody")
	cur := e.current("nobody")
	if cur.Evidence.Completeness != "NoTargets" || cur.Outcomes != (v1alpha1.OutcomeCounts{}) {
		t.Fatalf("zero targets: %+v %+v", cur.Evidence, cur.Outcomes)
	}
	if !strings.Contains(strings.Join(cur.Limitations, ";"), "no enforcementEpoch") {
		t.Fatalf("missing epoch not surfaced: %v", cur.Limitations)
	}
}

func TestUnchangedEvidenceWritesNothingAndTargetingKeepsIt(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}), privilegedPod("prod", "web", "pod-1"))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	get := func() *v1alpha1.ComplianceBinding {
		b := &v1alpha1.ComplianceBinding{}
		_ = e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b)
		return b
	}
	rv, want := get().ResourceVersion, statusJSON(get().Status.Assessment)
	e.now = a0.Add(time.Minute) // only evaluatedAt would change
	e.assess("audit-prod")
	if get().ResourceVersion != rv {
		t.Fatal("unchanged evidence rewrote binding status")
	}
	e.deliver("audit-prod") // the targeting reconciler writes its own status
	if statusJSON(get().Status.Assessment) != want {
		t.Fatal("targeting reconcile dropped status.assessment")
	}
}

func TestWorkloadPredicateIgnoresStatusChurn(t *testing.T) {
	p := privilegedPod("prod", "web", "pod-1")
	statusOnly := p.DeepCopy()
	statusOnly.Status.Phase = corev1.PodRunning
	statusOnly.ResourceVersion = "9"
	relabeled := p.DeepCopy()
	relabeled.Labels["team"] = "a"
	pred := workloadStateChanged()
	if pred.Update(event.UpdateEvent{ObjectOld: p, ObjectNew: statusOnly}) {
		t.Fatal("status-only update enqueued")
	}
	if !pred.Update(event.UpdateEvent{ObjectOld: p, ObjectNew: relabeled}) {
		t.Fatal("label change ignored")
	}
}

func TestBoundaryTrackerRestartsOnStateChange(t *testing.T) {
	tr := NewBoundaryTracker()
	w := func(state string) []collector.Workload { return []collector.Workload{{UID: "u1", StateSHA256: state}} }
	first := tr.Observe(a0, w("s1"))[0]
	again := tr.Observe(a0.Add(time.Hour), w("s1"))[0]
	changed := tr.Observe(a0.Add(2*time.Hour), w("s2"))[0]
	if !first.Since.Equal(a0) || !again.Since.Equal(a0) || !changed.Since.Equal(a0.Add(2*time.Hour)) {
		t.Fatalf("%v %v %v", first.Since, again.Since, changed.Since)
	}
	// Another binding's observations do not erase u1; long absence does.
	tr.Observe(a0.Add(3*time.Hour), []collector.Workload{{UID: "u2", StateSHA256: "x"}})
	if b := tr.Observe(a0.Add(4*time.Hour), w("s2"))[0]; !b.Since.Equal(a0.Add(2 * time.Hour)) {
		t.Fatal("unrelated observation erased history")
	}
	tr.Observe(a0.Add(4*time.Hour+PruneAfter+time.Second), nil)
	if b := tr.Observe(a0.Add(5*time.Hour+PruneAfter), w("s2"))[0]; !b.Since.Equal(a0.Add(5*time.Hour + PruneAfter)) {
		t.Fatal("pruned workload kept history")
	}
}
