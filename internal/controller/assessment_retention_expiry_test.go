package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// completedRun publishes one scheduled run under the given binding retention.
func completedRun(t *testing.T, retention string) (*runEnv, string) {
	b := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "5m", Retention: v1alpha1.Duration(retention)}
	e := newRunEnv(t, b)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if !controllerutil.ContainsFinalizer(e.run(name), RetentionFinalizer) {
		t.Fatal("retention finalizer not added before staging")
	}
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	return e, name
}

func (e *runEnv) ref(r *v1alpha1.AssessmentRun) publication.RunRef {
	return publication.RunRef{ClusterID: r.Status.Scope.ClusterID, BindingUID: r.Status.Binding.UID, RunUID: string(r.UID)}
}

// The default retention is 2160h from the commit; the run waits for it and
// a binding retention edit after publication does not move it.
func TestDefaultRetentionSchedulesExpiryFromReceipt(t *testing.T) {
	e, name := completedRun(t, "")
	r := e.run(name)
	want := r.Status.Publication.PublishedAt.Add(2160 * time.Hour)
	if !r.Status.Publication.ExpiresAt.Time.Equal(want) {
		t.Fatalf("expiry %v, want publishedAt+2160h %v", r.Status.Publication.ExpiresAt, want)
	}
	b := &v1alpha1.ComplianceBinding{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b)
	b.Spec.Assessment.Retention = "1h"
	_ = e.c.Update(context.Background(), b)
	e.now = r.Status.Publication.PublishedAt.Add(2 * time.Hour)
	if res := e.step(name); res.RequeueAfter != MaxRetentionRequeue {
		t.Fatalf("not waiting for the recorded expiry: %+v", res)
	}
	if r := e.run(name); !r.Status.Publication.ExpiresAt.Time.Equal(want) || e.pub.Calls(fake.OpDelete) != 0 {
		t.Fatal("retention edit changed or ended an existing publication's retention")
	}
}

// A short retention expires, storage is deleted, and the record is released.
// Deleting the binding, its request, and the run itself before expiry ends
// neither the record nor the cleanup.
func TestExpiryDeletesStorageIndependentOfOwners(t *testing.T) {
	e, name := completedRun(t, "10m")
	ctx := context.Background()
	_ = e.c.Delete(ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "audit-prod"}})
	if err := e.c.Delete(ctx, e.run(name)); err != nil {
		t.Fatal(err)
	}
	r := e.run(name) // still present: the finalizer holds the cleanup record
	if r.DeletionTimestamp.IsZero() {
		t.Fatal("run not marked for deletion")
	}
	expires := r.Status.Publication.ExpiresAt.Time
	e.restart()
	e.now = expires.Add(-time.Minute)
	if res := e.step(name); res.RequeueAfter != time.Minute || e.pub.Calls(fake.OpDelete) != 0 {
		t.Fatalf("deleted before expiry: %+v", res)
	}
	// Storage refuses deletion: the record keeps its ownership metadata.
	e.pub.Fail(fake.OpDelete, publication.ErrRetentionBlocked)
	e.now = expires.Add(time.Second)
	if res := e.step(name); res.RequeueAfter == 0 {
		t.Fatal("blocked deletion not retried")
	}
	r = e.run(name)
	if r.Status.Publication.Cleanup.State != "RetentionBlocked" || r.Status.Publication.Phase != "Deleting" || r.Status.Publication.Commit == nil ||
		!controllerutil.ContainsFinalizer(r, RetentionFinalizer) {
		t.Fatalf("blocked deletion reported as %+v", r.Status.Publication)
	}
	e.pub.Fail(fake.OpDelete, publication.ErrUnavailable)
	e.step(name)
	if r = e.run(name); r.Status.Publication.Cleanup.State != "DeletionFailed" || r.Status.Publication.Cleanup.Attempts != 2 {
		t.Fatalf("failed deletion reported as %+v", r.Status.Publication.Cleanup)
	}
	e.step(name)
	if err := e.c.Get(ctx, client.ObjectKey{Name: name}, &v1alpha1.AssessmentRun{}); err == nil {
		t.Fatal("cleaned-up run record not released")
	}
	if _, _, err := e.pub.Open(ctx, e.ref(r)); err == nil {
		t.Fatal("expired package still served")
	}
}

// A run that is not deleted keeps a small tombstone after cleanup.
func TestExpiredRunKeepsTombstone(t *testing.T) {
	e, name := completedRun(t, "10m")
	e.now = e.run(name).Status.Publication.ExpiresAt.Add(time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Publication.Phase != "Deleted" || r.Status.Publication.Cleanup.State != "Deleted" || r.Status.Publication.Availability != "Expired" ||
		controllerutil.ContainsFinalizer(r, RetentionFinalizer) {
		t.Fatalf("tombstone %+v", r.Status.Publication)
	}
	calls := e.pub.Calls(fake.OpDelete)
	e.step(name)
	if e.pub.Calls(fake.OpDelete) != calls {
		t.Fatal("deleted package deleted again")
	}
}

// A run deleted while still collecting has nothing in storage and goes away.
func TestRunDeletedDuringCollectionIsReleased(t *testing.T) {
	e, name := startedRun(t)
	if err := e.c.Delete(context.Background(), e.run(name)); err != nil {
		t.Fatal(err)
	}
	e.step(name)
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, &v1alpha1.AssessmentRun{}); err == nil {
		t.Fatal("collecting run kept after deletion")
	}
}
