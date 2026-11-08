//go:build live

package controller

// Recovery on leadership acquisition (add-controller-high-availability 4.1,
// 4.2):
// a leader stages a run's package durably in S3 and loses leadership before
// the commit. Its successor has its own, empty staging directory (a
// different pod). While S3 is unreachable the run stays Publishing and is
// never CaptureLost; once S3 returns, the successor commits the original
// staged bytes under the original run identity. There is only one run.

import (
	"context"
	"errors"
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

// committedPublisher commits through to the real backend, records the
// receipt, and never returns it: the leader is lost after the commit and
// before the Kubernetes receipt is written.
type committedPublisher struct {
	publication.Publisher
	mu      sync.Mutex
	receipt *publication.Receipt
}

func (p *committedPublisher) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	r, err := p.Publisher.Publish(ctx, req)
	if err != nil {
		return r, err
	}
	p.mu.Lock()
	p.receipt = &r
	p.mu.Unlock()
	<-ctx.Done()
	return publication.Receipt{}, ctx.Err()
}

func (p *committedPublisher) committed() *publication.Receipt {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.receipt
}

// lostPublisher never stages: the leader is lost after freezing the capture
// in its own staging directory and before durable staging.
type lostPublisher struct {
	publication.Publisher
	mu     sync.Mutex
	called bool
}

func (p *lostPublisher) Stage(ctx context.Context, _ publication.StageRequest) (publication.Staged, error) {
	p.mu.Lock()
	p.called = true
	p.mu.Unlock()
	<-ctx.Done()
	return publication.Staged{}, ctx.Err()
}

func (p *lostPublisher) staging() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.called
}

// Loss boundaries across leaders (add-controller-high-availability 4.2):
//   - after the commit and before the receipt: the successor records the
//     original commit, publication time and expiry, with the retention the
//     run committed under even though the binding's retention changed since;
//   - before durable staging: the successor cannot recover the capture from
//     another pod's directory, so the run fails as a diagnostic CaptureLost
//     with nothing committed, and the next run is a new identity that
//     publishes normally.
func TestLiveLeaderHandoverLoss(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	const ns = "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	l.setNamespace("hl-prod", "hl-production")
	p := profileObj(t, "hl-baseline", pol)
	b := bindingObj("hl-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "hl-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: "600s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "hl-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
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
		l.eventually("loss test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
		ConfigureAssessments(AssessmentRuntime{})
	})
	runtime := func(p publication.Publisher) AssessmentRuntime {
		return AssessmentRuntime{Publisher: p, StagingDir: t.TempDir(), ContentRoot: root, Poll: 2 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
			Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }, ReadyInterval: time.Second}
	}
	get := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	scheduled := func() []v1alpha1.AssessmentRun {
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
	handover := func(from *candidate, to publication.Publisher, agent string) *candidate {
		ConfigureAssessments(runtime(to))
		next := l.candidateAs("", agent)
		from.stop()
		l.eventually(agent+" elected", func() (bool, string) { return next.elected(), "" })
		return next
	}

	// 1. Commit lands, receipt is lost with the leader.
	committing := &committedPublisher{Publisher: pub}
	ConfigureAssessments(runtime(committing))
	a := l.candidateAs("", "hl-candidate-a")
	l.eventually("A elected", func() (bool, string) { return a.elected(), "" })
	var name string
	l.eventually("A committed without recording the receipt", func() (bool, string) {
		rs := scheduled()
		if len(rs) != 1 || committing.committed() == nil {
			return false, toJSON(rs)
		}
		name = rs[0].Name
		return rs[0].Status.Phase == v1alpha1.RunPublishing && (rs[0].Status.Publication == nil || rs[0].Status.Publication.PublishedAt == nil), toJSON(rs[0].Status)
	})
	receipt := *committing.committed()
	// The binding's retention changes before the successor takes over; the
	// commit keeps the retention it was made with.
	got := l.binding(b.Name)
	got.Spec.Assessment.Retention = "120s"
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	bb := handover(a, pub, "hl-candidate-b")
	var r *v1alpha1.AssessmentRun
	l.eventually("successor records the original commit", func() (bool, string) {
		r = get(name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.ExpiresAt != nil, toJSON(r)
	})
	pubSt := r.Status.Publication
	if pubSt.PublicationID != receipt.PublicationID || pubSt.PackageSHA256 != receipt.PackageSHA256 ||
		!pubSt.PublishedAt.Time.Equal(receipt.PublishedAt) || !pubSt.ExpiresAt.Time.Equal(receipt.ExpiresAt) ||
		pubSt.Commit == nil || pubSt.Commit.ArchiveKey != receipt.Commit.ArchiveKey || pubSt.Commit.ManifestVersionID != receipt.Commit.ManifestVersionID {
		t.Fatalf("recorded %s, committed %s", toJSON(pubSt), toJSON(receipt))
	}
	if d := receipt.ExpiresAt.Sub(receipt.PublishedAt); d != 600*time.Second {
		t.Fatalf("committed retention %s", d)
	}
	if rs := scheduled(); len(rs) != 1 {
		t.Fatalf("runs after recovery: %s", toJSON(rs))
	}
	l.record("receipt-lost", map[string]any{"run": name, "publicationID": receipt.PublicationID, "publishedAt": receipt.PublishedAt, "expiresAt": receipt.ExpiresAt,
		"retention": "600s (binding now 120s)"})

	// 2. The capture is frozen on the leader's pod and lost before durable
	// staging.
	losing := &lostPublisher{Publisher: pub}
	c := handover(bb, losing, "hl-candidate-c")
	lost := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "hl-audit-lost"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, lost); err != nil {
		t.Fatal(err)
	}
	l.eventually("C froze the capture and is staging", func() (bool, string) {
		r := get(lost.Name)
		return losing.staging() && r != nil && r.Status.Phase == v1alpha1.RunPublishing, toJSON(r)
	})
	d := handover(c, pub, "hl-candidate-d")
	defer d.stop()
	l.eventually("successor reports the lost capture", func() (bool, string) {
		r := get(lost.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunFailed && r.Status.Summary != nil &&
			r.Status.Summary.Export == v1alpha1.ExportState(v1alpha1.ReasonCaptureLost), toJSON(r)
	})
	if r := get(lost.Name); r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil {
		t.Fatalf("lost capture was published: %s", toJSON(r.Status.Publication))
	}
	if lr := get(lost.Name); lr.Status.Scope == nil || lr.Status.Binding == nil {
		t.Fatalf("lost run lacks its frozen identity: %s", toJSON(lr.Status))
	} else if _, err := pub.Recover(l.ctx, publication.RunRef{ClusterID: lr.Status.Scope.ClusterID, BindingUID: lr.Status.Binding.UID, RunUID: string(lr.UID)}); !errors.Is(err, publication.ErrCaptureLost) {
		t.Fatalf("lost run's durable staging: %v", err)
	}
	next := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "hl-audit-next"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, next); err != nil {
		t.Fatal(err)
	}
	l.eventually("the next run publishes under a new identity", func() (bool, string) {
		r := get(next.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil, toJSON(r)
	})
	if got := get(next.Name).Status.Publication.PublicationID; got == "" || got == receipt.PublicationID {
		t.Fatalf("next run publication %q", got)
	}
	if r := get(lost.Name); r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("lost run changed after the next run: %s", toJSON(r.Status))
	}
	l.record("capture-lost", map[string]any{"lostRun": lost.Name, "export": "CaptureLost", "nextRun": next.Name})
}
