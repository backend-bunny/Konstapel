//go:build live

package controller

// Recovery on leadership acquisition (add-controller-high-availability 4.1):
// a leader stages a run's package durably in S3 and loses leadership before
// the commit. Its successor has its own, empty staging directory (a
// different pod). While S3 is unreachable the run stays Publishing and is
// never CaptureLost; once S3 returns, the successor commits the original
// staged bytes under the original run identity. There is only one run.

import (
	"context"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// stalledPublisher stages through to the real backend, records what it
// staged, and never completes a commit: its leader is lost mid-publish.
type stalledPublisher struct {
	publication.Publisher
	mu     sync.Mutex
	staged *publication.Staged
}

func (p *stalledPublisher) Stage(ctx context.Context, req publication.StageRequest) (publication.Staged, error) {
	s, err := p.Publisher.Stage(ctx, req)
	if err == nil {
		p.mu.Lock()
		p.staged = &s
		p.mu.Unlock()
	}
	return s, err
}

func (p *stalledPublisher) Publish(ctx context.Context, _ publication.PublishRequest) (publication.Receipt, error) {
	<-ctx.Done()
	return publication.Receipt{}, ctx.Err()
}

func (p *stalledPublisher) stagedPackage() *publication.Staged {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.staged
}

func TestLiveLeaderHandoverRecovery(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	const ns = "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	l.setNamespace("hr-prod", "hr-production")
	p := profileObj(t, "hr-baseline", pol)
	b := bindingObj("hr-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "hr-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "hr-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "unpause", l.s3Container).Run()
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		for _, o := range []client.Object{pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("handover test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
		ConfigureAssessments(AssessmentRuntime{})
	})
	runtime := func(p publication.Publisher) AssessmentRuntime {
		return AssessmentRuntime{Publisher: p, StagingDir: t.TempDir(), ContentRoot: root, Poll: 2 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
			Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }, ReadyInterval: time.Second}
	}
	runs := func() []v1alpha1.AssessmentRun {
		var list v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &list)
		var out []v1alpha1.AssessmentRun
		for _, r := range list.Items {
			if r.Spec.BindingRef.Name == b.Name {
				out = append(out, r)
			}
		}
		return out
	}

	// 1. Leader A collects and stages durably, then stalls before commit.
	stalled := &stalledPublisher{Publisher: pub}
	ConfigureAssessments(runtime(stalled))
	a := l.candidateAs("", "hr-candidate-a")
	l.eventually("A elected", func() (bool, string) { return a.elected(), "" })
	var name string
	l.eventually("A staged the run's package", func() (bool, string) {
		rs := runs()
		if len(rs) != 1 || stalled.stagedPackage() == nil {
			return false, toJSON(rs)
		}
		name = rs[0].Name
		return rs[0].Status.Phase == v1alpha1.RunPublishing, string(rs[0].Status.Phase)
	})
	staged := *stalled.stagedPackage()
	l.record("staged", map[string]any{"run": name, "publicationID": staged.PublicationID, "packageSha256": staged.PackageSHA256})

	// 2. The backend becomes unreachable and A loses leadership; B (its own
	// empty staging directory) takes over once the Lease expires.
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	ConfigureAssessments(runtime(pub))
	bb := l.candidateAs("", "hr-candidate-b")
	defer bb.stop()
	a.stop()
	l.eventually("B elected", func() (bool, string) { return bb.elected(), "" })

	// 3. Uncertain backend access is not CaptureLost: the run stays
	// Publishing under its identity while S3 is unreachable.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		rs := runs()
		if len(rs) != 1 || rs[0].Name != name {
			t.Fatalf("runs during the outage: %s", toJSON(rs))
		}
		r := rs[0]
		if r.Status.Phase != v1alpha1.RunPublishing || (r.Status.Summary != nil && r.Status.Summary.Export == v1alpha1.ExportState(v1alpha1.ReasonCaptureLost)) {
			t.Fatalf("run during the outage: %s", toJSON(r.Status))
		}
		time.Sleep(3 * time.Second)
	}
	l.record("outage", map[string]any{"run": name, "phase": "Publishing", "seconds": 30})

	// 4. S3 returns: B commits A's staged bytes under the original identity.
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	var done v1alpha1.AssessmentRun
	l.eventually("successor commits the staged package", func() (bool, string) {
		rs := runs()
		if len(rs) != 1 {
			return false, toJSON(rs)
		}
		done = rs[0]
		return done.Status.Phase == v1alpha1.RunCompleted && done.Status.Publication != nil, toJSON(done.Status)
	})
	if done.Name != name || done.Status.Publication.PublicationID != staged.PublicationID || done.Status.Publication.PackageSHA256 != staged.PackageSHA256 {
		t.Fatalf("successor published %s %s/%s, staged %s %s/%s", done.Name, done.Status.Publication.PublicationID, done.Status.Publication.PackageSHA256,
			name, staged.PublicationID, staged.PackageSHA256)
	}
	l.record("recovered", map[string]any{"run": done.Name, "publicationID": done.Status.Publication.PublicationID, "packageSha256": done.Status.Publication.PackageSHA256, "runs": 1})
}
