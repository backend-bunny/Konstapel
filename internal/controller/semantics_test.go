package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// These cases back the "Reading status" table in
// docs/integration/targeting-api.md. Resolved scope, engine readiness and
// assessment completeness are three separate answers, and none implies another.
// Each case reconciles a binding, then freezes and evaluates an assessment
// scope from the same configuration with add-continuous-assessments' collector,
// with no engine reports.

type answers struct {
	resolved, engineReady metav1.ConditionStatus
	targets               int32
	completeness          publication.Completeness
	evidence              publication.EvidenceSummary
}

func (e *env) answers(binding string, pods ...*corev1.Pod) answers {
	e.t.Helper()
	ctx := context.Background()
	b := e.binding(binding)
	in, _, err := e.r.input(ctx, b)
	if err != nil {
		e.t.Fatal(err)
	}
	result := targeting.Resolve(in)
	contents := map[string]*targeting.Content{}
	for _, bundle := range in.Bundles {
		c, err := content.Content(ctx, v1alpha1.BundleReference{Name: bundle.Name, Digest: bundle.Digest})
		if err != nil {
			e.t.Fatal(err)
		}
		contents[bundle.Digest] = c
	}
	subjects, stale, err := targeting.ExpectedEvidence(result, contents)
	if err != nil {
		e.t.Fatal(err)
	}
	var rendered []assessment.Object
	for _, p := range e.policies() {
		rendered = append(rendered, assessment.Object(p.Object))
	}
	var listed []collector.ListedObject
	for _, pod := range pods {
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
		if err != nil {
			e.t.Fatal(err)
		}
		listed = append(listed, collector.ListedObject{Resource: "/v1/pods", NamespaceUID: "uid-" + pod.Namespace, Object: obj})
	}
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	capture, err := collector.FreezeScope(e.r.Cluster, start, "sha256:mapping", subjects, stale, rendered, listed)
	if err != nil {
		e.t.Fatal(err)
	}
	capture.Window.Closed = start.Add(time.Minute)
	eval, err := capture.Evaluate(nil, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	b = e.binding(binding)
	var targets int32 = -1
	if b.Status.TargetCount != nil {
		targets = *b.Status.TargetCount
	}
	return answers{
		resolved:     cond(b, v1alpha1.ConditionResolved).Status,
		engineReady:  cond(b, v1alpha1.ConditionEngineReady).Status,
		targets:      targets,
		completeness: eval.Evidence.Completeness,
		evidence:     eval.Evidence,
	}
}

func pod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID("uid-pod-" + name)},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.example/app:1"}}},
	}
}

func TestReadyEnforcementIsNotCompleteEvidence(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	a := e.answers("deny-prod", pod("prod", "web"))
	if a.resolved != metav1.ConditionTrue || a.engineReady != metav1.ConditionTrue || a.targets != 1 {
		t.Fatalf("binding should be resolved and ready: %+v", a)
	}
	if a.completeness != publication.Incomplete || a.evidence.Missing == 0 || a.evidence.Attributable != 0 {
		t.Fatalf("ready enforcement without reports must be Incomplete evidence: %+v", a.evidence)
	}
}

func TestStaleScopeIsNeverCompleteOrNoTargets(t *testing.T) {
	e := newEnv(t, nsObj("prod", "environment", "production"),
		bindingObj("orphan", "absent", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("orphan")
	a := e.answers("orphan", pod("prod", "web"))
	if a.resolved != metav1.ConditionFalse || a.engineReady != metav1.ConditionFalse {
		t.Fatalf("missing profile must be unresolved and not ready: %+v", a)
	}
	if a.evidence.Expected != 0 || a.evidence.StaleScopes != 1 || a.completeness != publication.Incomplete {
		t.Fatalf("stale scope with nothing expected must be Incomplete, not NoTargets: %+v", a.evidence)
	}
}

func TestZeroTargetsIsReadyAndNoTargetsNotComplete(t *testing.T) {
	e := newEnv(t, nsObj("dev", "environment", "development"), profileObj(t, "baseline", pol),
		bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.reconcile("deny-prod")
	e.markAllReady()
	e.reconcile("deny-prod")
	a := e.answers("deny-prod", pod("dev", "web"))
	if a.resolved != metav1.ConditionTrue || a.engineReady != metav1.ConditionTrue || a.targets != 0 {
		t.Fatalf("zero-target binding is resolved and ready: %+v", a)
	}
	if a.completeness != publication.NoTargets || a.evidence.Expected != 0 {
		t.Fatalf("zero targets must be NoTargets, never Complete: %+v", a.evidence)
	}
}
