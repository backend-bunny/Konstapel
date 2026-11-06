//go:build live

package controller

// Live engine correlation study (add-continuous-assessments task 4.3). It
// records what the pinned Kyverno release reports for a workload before and
// after an in-place update, and checks that the assessment controller never
// counts a result evaluated before the update as current evidence for the
// updated state. The raw observations are written to
// $KONSTAPEL_LIVE_OUTPUT/engine-correlation.json.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
)

type reportSample struct {
	At           time.Time         `json:"at"`
	SinceUpdate  string            `json:"sinceUpdate,omitempty"`
	ReportRV     string            `json:"reportResourceVersion"`
	Labels       map[string]string `json:"reportLabels,omitempty"`
	Annotations  map[string]string `json:"reportAnnotations,omitempty"`
	Scope        any               `json:"scope"`
	Results      any               `json:"results"`
	PodRV        string            `json:"podResourceVersion"`
	PodGen       int64             `json:"podGeneration"`
	PodStateHash string            `json:"podStateSha256"`
}

type statusSample struct {
	At           time.Time `json:"at"`
	SinceUpdate  string    `json:"sinceUpdate"`
	Completeness string    `json:"completeness"`
	Evaluated    *string   `json:"evaluatedFromNextExpiry,omitempty"`
}

func TestLiveEngineCorrelation(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("corr-prod", "corr-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "corr-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("corr-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "corr-production"})
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "subject", Namespace: "corr-prod", Labels: map[string]string{"state": "a"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, pod)
		_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}})
		_ = l.c.Delete(l.ctx, p)
		l.eventually("correlation policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer stop()
	l.waitReady(b.Name, 1)

	podNow := func() *corev1.Pod {
		got := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(pod), got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	report := func() *unstructured.Unstructured {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(PolicyReportGVK.GroupVersion().WithKind("PolicyReportList"))
		if err := l.c.List(l.ctx, list, client.InNamespace("corr-prod")); err != nil {
			return nil
		}
		uid := string(podNow().UID)
		for i := range list.Items {
			if assessment.Str(assessment.At(list.Items[i].Object, "scope", "uid")) == uid {
				return &list.Items[i]
			}
		}
		return nil
	}
	var updated time.Time
	sample := func(r *unstructured.Unstructured) reportSample {
		pd := podNow()
		o, _ := toUnstructuredMap(pd)
		s := reportSample{At: time.Now().UTC(), ReportRV: r.GetResourceVersion(), Labels: r.GetLabels(), Annotations: r.GetAnnotations(),
			Scope: r.Object["scope"], Results: r.Object["results"], PodRV: pd.ResourceVersion, PodGen: pd.Generation, PodStateHash: collector.WorkloadState(o)}
		if !updated.IsZero() {
			s.SinceUpdate = s.At.Sub(updated).Round(time.Second).String()
		}
		return s
	}

	var reports []reportSample
	l.eventually("initial report", func() (bool, string) {
		r := report()
		if r == nil {
			return false, "no report"
		}
		reports = append(reports, sample(r))
		return true, ""
	})

	// Update the workload in place: a new state for policies and selectors.
	got := podNow()
	got.Labels["state"] = "b"
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	updated = time.Now().UTC().Truncate(time.Second)

	// Observe the report and the controller's current evidence for a minute.
	var statuses []statusSample
	lastRV := reports[0].ReportRV
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if r := report(); r != nil && r.GetResourceVersion() != lastRV {
			lastRV = r.GetResourceVersion()
			reports = append(reports, sample(r))
		}
		bd := l.binding(b.Name)
		if bd.Status.Assessment != nil && bd.Status.Assessment.Current != nil {
			cur := bd.Status.Assessment.Current
			s := statusSample{At: time.Now().UTC(), SinceUpdate: time.Since(updated).Round(time.Second).String(), Completeness: string(cur.Evidence.Completeness)}
			if cur.NextExpiry != nil {
				ev := cur.NextExpiry.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
				s.Evaluated = &ev
			}
			if len(statuses) == 0 || statuses[len(statuses)-1].Completeness != s.Completeness || !samePtr(statuses[len(statuses)-1].Evaluated, s.Evaluated) {
				statuses = append(statuses, s)
			}
			// The rule under test: Complete evidence after the update must
			// rest on an evaluation after the controller observed the new
			// state, never on an earlier (merely recent) result.
			// Allow 10s for the controller to observe the update.
			if time.Since(updated) > 10*time.Second && cur.Evidence.Completeness == "Complete" && cur.NextExpiry != nil && cur.NextExpiry.Add(-2*time.Hour).Before(updated) {
				t.Errorf("pre-update evaluation counted as current after the update: %s", toJSON(cur))
			}
		}
		time.Sleep(time.Second)
	}

	evidence := map[string]any{
		"date":                      time.Now().UTC().Format("2006-01-02"),
		"versions":                  "versions.json",
		"purpose":                   "add-continuous-assessments task 4.3: evaluation-to-resource-state correlation in the pinned Kyverno release",
		"workloadUpdate":            map[string]any{"at": updated, "change": "metadata.labels.state a→b (in place, same UID)"},
		"reports":                   reports,
		"controllerCurrentEvidence": statuses,
	}
	raw, _ := json.MarshalIndent(evidence, "", "  ")
	if err := os.WriteFile(filepath.Join(l.out, "engine-correlation.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	l.record("engine-correlation", map[string]any{"reportVersions": len(reports), "statusChanges": len(statuses)})
	if len(reports) < 2 {
		t.Fatalf("Kyverno did not re-report the updated workload within 60s: %s", raw)
	}
}

func samePtr(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func toUnstructuredMap(o any) (map[string]any, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}
