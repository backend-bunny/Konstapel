package controller

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// A terminal run's uncommitted attempts are cleaned up; a storage failure is
// recorded and retried, including after a restart, and the committed package
// is never touched.
func TestTerminalRunCleansAttemptsWithRetry(t *testing.T) {
	e, name := startedRun(t)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name) // closes and publishes
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	e.pub.Fail(fake.OpCleanup, publication.ErrUnavailable)
	if res := e.step(name); res.RequeueAfter != AttemptCleanupRetry {
		t.Fatalf("failed cleanup not retried: %+v", res)
	}
	c := meta.FindStatusCondition(e.run(name).Status.Conditions, v1alpha1.ConditionAttemptsCleaned)
	if c == nil || c.Status != "False" || c.Reason != v1alpha1.ReasonCleanupPending {
		t.Fatalf("pending cleanup not visible: %+v", c)
	}
	e.restart()
	if res := e.step(name); res.RequeueAfter != 0 {
		t.Fatalf("cleanup still pending: %+v", res)
	}
	r := e.run(name)
	if !meta.IsStatusConditionTrue(r.Status.Conditions, v1alpha1.ConditionAttemptsCleaned) || e.pub.Commits() != 1 || r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("cleanup: %+v commits %d", r.Status.Conditions, e.pub.Commits())
	}
	calls := e.pub.Calls(fake.OpCleanup)
	e.step(name)
	if e.pub.Calls(fake.OpCleanup) != calls {
		t.Fatal("cleaned run cleaned again")
	}
}

// A failed publication's staged attempt is removed too.
func TestFailedRunCleansAttempts(t *testing.T) {
	e, name := startedRun(t)
	for range 100 {
		e.pub.Fail(fake.OpPublish, publication.ErrUnavailable)
	}
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	e.now = a0.Add(11 * time.Minute)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	ref := publication.RunRef{ClusterID: r.Status.Scope.ClusterID, BindingUID: r.Status.Binding.UID, RunUID: string(r.UID)}
	if _, err := e.pub.Recover(context.Background(), ref); err != nil {
		t.Fatalf("setup: nothing staged: %v", err)
	}
	e.step(name)
	if _, err := e.pub.Recover(context.Background(), ref); err == nil {
		t.Fatal("failed run's attempt survived cleanup")
	}
	if !meta.IsStatusConditionTrue(e.run(name).Status.Conditions, v1alpha1.ConditionAttemptsCleaned) {
		t.Fatal("cleanup not recorded")
	}
}
