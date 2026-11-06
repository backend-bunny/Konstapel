//go:build live

package controller

// Live run lifecycle acceptance (add-continuous-assessments tasks 3.1–3.3,
// 3.5): scheduled and manual runs execute against real Kyverno reports and
// publish through the publication contract. add-s3-evidence-publishing has
// no backend yet, so the in-memory fake publisher stands in for storage.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

func TestLiveAssessmentRuns(t *testing.T) {
	// Route controller logs into the test log so reconcile errors are visible.
	ctrllog.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := fake.New(time.Now)
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })

	l.setNamespace("runs-prod", "runs-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "runs-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("runs-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "runs-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "40s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "runs-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	t.Cleanup(func() {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if runs.Items[i].Spec.BindingRef.Name == b.Name {
				_ = l.c.Delete(l.ctx, &runs.Items[i])
			}
		}
		_ = l.c.Delete(l.ctx, pod)
		_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}})
		_ = l.c.Delete(l.ctx, p)
		l.eventually("run test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
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

	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	var scheduled string
	l.eventually("initial scheduled run admitted", func() (bool, string) {
		got := l.binding(b.Name)
		if got.Status.Assessment == nil || got.Status.Assessment.Schedule == nil || got.Status.Assessment.Schedule.ActiveRun == nil {
			return false, toJSON(got.Status.Assessment)
		}
		scheduled = got.Status.Assessment.Schedule.ActiveRun.Name
		return true, ""
	})
	l.eventually("scheduled run published", func() (bool, string) {
		r := run(scheduled)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.Phase == "Committed", toJSON(r.Status)
	})
	r := run(scheduled)
	if r.Spec.Trigger == nil || r.Spec.Trigger.Type != v1alpha1.TriggerScheduled || r.Status.Summary == nil || r.Status.Summary.Evidence.Expected != 1 {
		t.Fatalf("scheduled run %s: %s", scheduled, toJSON(r))
	}
	l.record("scheduled-run", map[string]any{"run": scheduled, "evidence": r.Status.Summary.Evidence, "outcomes": r.Status.Summary.Outcomes, "publication": r.Status.Publication.PublicationID})

	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "runs-audit-manual"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, manual); err != nil {
		t.Fatal(err)
	}
	l.eventually("manual run published", func() (bool, string) {
		r := run(manual.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil, toJSON(r)
	})
	l.eventually("slot released, cadence unchanged", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment.Schedule
		return s.ActiveRun == nil && s.LastScheduled != nil && s.NextDue != nil && s.NextDue.Sub(s.LastScheduled.Time) == 24*time.Hour, toJSON(s)
	})
	if pub.Commits() != 2 {
		t.Fatalf("want 2 commits, got %d", pub.Commits())
	}
	l.record("manual-run", map[string]any{"run": manual.Name, "evidence": run(manual.Name).Status.Summary.Evidence})

	// A team request in a second selected namespace runs as a namespace run
	// and assesses only that namespace.
	l.setNamespace("runs-team", "runs-production")
	teamPod := pod.DeepCopy()
	teamPod.ResourceVersion, teamPod.UID, teamPod.Namespace = "", "", "runs-team"
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "runs-team"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	for _, o := range []client.Object{teamPod, req} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, req); _ = l.c.Delete(l.ctx, teamPod) })
	var st v1alpha1.AssessmentRequestStatus
	l.eventually("team request completed", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got); err != nil {
			return false, err.Error()
		}
		st = got.Status
		detail := toJSON(st) + " schedule: " + toJSON(l.binding(b.Name).Status.Assessment.Schedule)
		if st.Run != nil {
			if r := run(st.Run.Name); r != nil {
				detail += " run: " + toJSON(r.Status)
			}
		}
		return st.Phase == v1alpha1.RequestCompleted && st.ArtifactRef != "", detail
	})
	nsRun := run(st.Run.Name)
	ns := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "runs-team"}, ns); err != nil {
		t.Fatal(err)
	}
	if nsRun.Spec.Scope != v1alpha1.RunScopeNamespace || nsRun.Status.Scope.NamespaceUID != string(ns.UID) || nsRun.Status.Scope.NamespaceCount != 1 ||
		st.NamespaceUID != string(ns.UID) || st.Summary == nil || st.Summary.Evidence.Expected != 1 || st.ArtifactRef != nsRun.Status.Publication.PublicationID {
		t.Fatalf("team run %s / request %s", toJSON(nsRun.Status), toJSON(st))
	}
	l.record("team-request", map[string]any{"run": nsRun.Name, "namespaceUID": st.NamespaceUID, "evidence": st.Summary.Evidence, "artifactRef": st.ArtifactRef})
}
