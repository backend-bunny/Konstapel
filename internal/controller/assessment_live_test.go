//go:build live

package controller

// Live current-evidence acceptance (add-continuous-assessments task 3.4):
// the manager's assessment reconciler reads real Kyverno PolicyReports and
// applies status.assessment.current. Run through scripts/targeting-live.sh.

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveAssessmentStatus(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("assess-prod", "assess-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "assess-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	audit := bindingObj("assess-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "assess-production"})
	empty := bindingObj("assess-empty", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "assess-nowhere"})
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "assess-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, pod)
		for _, n := range []string{audit.Name, empty.Name} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
		_ = l.c.Delete(l.ctx, p)
		l.eventually("assessment test policies removed", func() (bool, string) {
			got := l.policiesFor(audit.Name, empty.Name)
			return len(got) == 0, toJSON(got)
		})
	})
	for _, o := range []client.Object{p, audit, empty, pod} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer stop()
	l.waitReady(audit.Name, 1)

	current := func(name string) *v1alpha1.CurrentEvidence {
		b := l.binding(name)
		if b.Status.Assessment == nil {
			return nil
		}
		return b.Status.Assessment.Current
	}
	l.eventually("no-target binding reports NoTargets", func() (bool, string) {
		c := current(empty.Name)
		return c != nil && c.Evidence.Completeness == "NoTargets" && c.Outcomes == (v1alpha1.OutcomeCounts{}), toJSON(c)
	})
	// The privileged pod existed before the manager observed it, so evidence
	// becomes attributable only after Kyverno's next background evaluation.
	l.eventually("attributable failing evidence", func() (bool, string) {
		c := current(audit.Name)
		return c != nil && c.Evidence.Completeness == "Complete" && c.Evidence.Expected == 1 && c.Outcomes.Fail == 1 && c.NextExpiry != nil, toJSON(c)
	})
	c := current(audit.Name)
	l.record("assessment-complete", map[string]any{"evidence": c.Evidence, "outcomes": c.Outcomes, "nextExpiry": c.NextExpiry})

	// Engine readiness and evidence stay separate: EngineReady never claims a
	// result, and the assessment status lives only under status.assessment.
	b := l.binding(audit.Name)
	for _, cond := range b.Status.Conditions {
		if strings.Contains(strings.ToLower(cond.Message), "complete") {
			t.Fatalf("condition %s mentions assessment completeness: %s", cond.Type, cond.Message)
		}
	}
	// A spec change to the pod's labels invalidates the observed state until
	// Kyverno re-evaluates it.
	got := &corev1.Pod{}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(pod), got); err != nil {
		t.Fatal(err)
	}
	got.Labels = map[string]string{"changed": "true"}
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	before := c.NextExpiry.Time
	l.eventually("state change re-established by a newer evaluation", func() (bool, string) {
		c := current(audit.Name)
		return c != nil && c.Evidence.Completeness == "Complete" && c.NextExpiry != nil && c.NextExpiry.After(before), toJSON(c)
	})
	l.record("assessment-passed", map[string]any{"binding": audit.Name, "detail": fmt.Sprint(current(audit.Name).Evidence)})
}
