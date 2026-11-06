package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// restart replaces the controller process: a new instance ID and an empty
// boundary tracker, with the same staging directory and publisher.
func (e *runEnv) restart() {
	e.ar.Boundaries = NewBoundaryTracker()
	e.rr = &AssessmentRunReconciler{Client: e.c, Assess: e.ar, Runtime: e.rr.Runtime, Now: e.rr.Now, Instance: e.rr.Instance + "-restarted"}
}

func (e *runEnv) staged(run *v1alpha1.AssessmentRun) collector.CaptureV2 {
	e.t.Helper()
	var c collector.CaptureV2
	if err := assessment.Read(filepath.Join(e.rr.staging(run), "capture.json"), &c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func startedRun(t *testing.T) (*runEnv, string) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.rr.Instance = "process-1"
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	return e, name
}

// A restart during collection resumes the same frozen capture, but evidence
// evaluated before the restart no longer counts: continuity is not proven.
func TestRestartResumesSameCaptureWithoutContinuity(t *testing.T) {
	e, name := startedRun(t)
	before := e.staged(e.run(name))
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(2 * time.Minute)
	e.restart()
	e.step(name)
	r := e.run(name)
	after := e.staged(r)
	if r.Status.Phase != v1alpha1.RunCollecting || !after.Window.Started.Equal(before.Window.Started) || len(after.Expected) != len(before.Expected) {
		t.Fatalf("restart changed the frozen capture: %s %v", r.Status.Phase, after.Window)
	}
	if after.Observer != "process-1-restarted" || !strings.Contains(statusJSON(after.ScopeChanges), string(collector.WatchDiscontinuity)) {
		t.Fatalf("restart not recorded: observer %q changes %s", after.Observer, statusJSON(after.ScopeChanges))
	}
	// Close at the timeout: the pre-restart evaluation is rejected.
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r = e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary.Evidence.Completeness != "Incomplete" || r.Status.Summary.Evidence.Rejected != 1 {
		t.Fatalf("pre-restart evidence counted: %+v", r.Status.Summary)
	}
}

// A crash after closure but before the status update re-exports the same
// frozen snapshot; it does not collect newer observations.
func TestCrashAfterClosureFinishesSameSnapshot(t *testing.T) {
	e, name := startedRun(t)
	for range 10 {
		e.pub.Fail(fake.OpStage, publication.ErrUnavailable) // keep it Publishing
	}
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunPublishing {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	closedAt, summary := r.Status.Window.Closed.Time, statusJSON(r.Status.Summary)
	// Simulate the lost status update: the cluster still says Collecting.
	r.Status.Phase, r.Status.Summary, r.Status.DescriptorSHA256, r.Status.Window.Closed = v1alpha1.RunCollecting, nil, "", nil
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Newer evidence appears; it must not enter the closed snapshot.
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(6*time.Minute))
	e.now = a0.Add(7 * time.Minute)
	e.restart()
	e.step(name)
	r = e.run(name)
	if !r.Status.Window.Closed.Time.Equal(closedAt) || statusJSON(r.Status.Summary) != summary {
		t.Fatalf("retry changed the closed snapshot: closed %v→%v summary %s→%s", closedAt, r.Status.Window.Closed, summary, statusJSON(r.Status.Summary))
	}
}

// A lost publish response is retried against the same frozen package and
// converges on the original receipt; nothing is committed twice.
func TestLostPublishResponseKeepsOriginalReceipt(t *testing.T) {
	e, name := startedRun(t)
	e.pub.LoseResponse(fake.OpPublish)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunPublishing {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	digest := r.Status.DescriptorSHA256
	e.now = a0.Add(6 * time.Minute)
	e.step(name)
	r = e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.PublishedAt == nil || !r.Status.Publication.PublishedAt.Time.Equal(a0.Add(5*time.Minute+time.Second)) {
		t.Fatalf("receipt not the original commit: %+v", r.Status.Publication)
	}
	if r.Status.DescriptorSHA256 != digest || e.pub.Commits() != 1 {
		t.Fatal("retry published different bytes or committed twice")
	}
}

// Once the descriptor digest is recorded, a changed staged package is never
// published under the run's identity.
func TestChangedStagedPackageIsCaptureLost(t *testing.T) {
	e, name := startedRun(t)
	for range 10 {
		e.pub.Fail(fake.OpStage, publication.ErrUnavailable)
	}
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	pkg := filepath.Join(e.rr.staging(r), "package")
	d, err := publication.LoadDescriptor(pkg)
	if err != nil {
		t.Fatal(err)
	}
	d.Window.Closed = d.Window.Closed.Add(time.Hour) // a different snapshot
	if err := assessment.Write(filepath.Join(pkg, publication.DescriptorFile), d); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(6 * time.Minute)
	e.step(name)
	r = e.run(name)
	c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
	if r.Status.Phase != v1alpha1.RunFailed || c == nil || c.Reason != v1alpha1.ReasonCaptureLost || e.pub.Commits() != 0 {
		t.Fatalf("changed package published or not failed: %s %+v", r.Status.Phase, c)
	}
}

// Without the local package, a durably staged publication is recovered and
// committed; without any recoverable data the run is CaptureLost.
func TestPublisherRecoveryAndCaptureLost(t *testing.T) {
	for _, durable := range []bool{true, false} {
		e, name := startedRun(t)
		e.pub.DurableStaging = durable
		e.pub.LoseResponse(fake.OpStage) // staged, but the response was lost
		e.now = a0.Add(5*time.Minute + time.Second)
		e.step(name)
		r := e.run(name)
		if r.Status.Phase != v1alpha1.RunPublishing {
			t.Fatalf("durable=%v phase %s", durable, r.Status.Phase)
		}
		_ = os.RemoveAll(e.rr.staging(r)) // controller restart without a persistent staging volume
		e.pub.Restart()
		e.restart()
		e.now = a0.Add(6 * time.Minute)
		e.step(name)
		r = e.run(name)
		switch {
		case durable && (r.Status.Phase != v1alpha1.RunCompleted || e.pub.Commits() != 1):
			t.Fatalf("durable staging not recovered: %s", r.Status.Phase)
		case !durable && (r.Status.Phase != v1alpha1.RunFailed || r.Status.Summary.Export != "CaptureLost" || e.pub.Commits() != 0):
			t.Fatalf("lost capture not explicit: %s %+v", r.Status.Phase, r.Status.Summary)
		}
	}
}
