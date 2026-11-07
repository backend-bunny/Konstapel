package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func (e *pinEnv) gone(name string) bool {
	err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, &v1alpha1.AssessmentRun{})
	return apierrors.IsNotFound(err)
}

// Runs are held until the inventory is saved; then completed runs keep
// their original receipt as Orphaned, a verified Deleted record stays
// Deleted, records pending deletion are released only after the inventory
// recorded them, and the destination's finalizer is released last — all
// without a storage operation.
func TestOrphanedDispositionKeepsReceipts(t *testing.T) {
	e, names := orphanedEnv(t)
	completed := names[0]
	receipt := e.run(completed).Status.Publication.DeepCopy()
	deleted := e.pinnedCopy(t, completed, "deleted")
	r := e.run(deleted)
	r.Status.Phase, r.Status.Publication = v1alpha1.RunCompleted, receipt.DeepCopy()
	r.Status.Publication.Phase = v1alpha1.PublicationPhase(publication.PhaseDeleted)
	r.Status.Publication.Availability = v1alpha1.Availability(publication.AvailabilityExpired)
	r.Status.Publication.Cleanup.State = v1alpha1.CleanupState(publication.CleanupDeleted)
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	pending := e.pinnedCopy(t, completed, "pending-deletion")
	if err := e.c.Delete(context.Background(), e.run(pending)); err != nil {
		t.Fatal(err)
	}
	before := e.storageCalls()

	// Accepted and fenced, but the inventory can't be saved yet: every run
	// is held unchanged.
	fc := &failingCreates{Client: e.c, fail: true}
	reconcileDestination(t, e.destinationReconciler(fc), "primary")
	if res := e.step(completed); res.RequeueAfter != OrphanHoldRequeue || e.run(completed).Status.Destination.OrphanedAt != nil {
		t.Fatalf("run disposed before the inventory: %+v", res)
	}
	dr := e.destinationReconciler(e.c)
	reconcileDestination(t, dr, "primary")
	if inv := e.destination("primary").Status.OrphanHandoff.Inventory; inv == nil || inv.Runs != 3 {
		t.Fatalf("inventory %+v", inv)
	}
	if !controllerutil.ContainsFinalizer(e.destination("primary"), DestinationFinalizer) {
		t.Fatal("destination released before its runs were disposed")
	}

	for _, n := range []string{completed, deleted, pending} {
		e.step(n)
	}
	got := e.run(completed)
	pub := got.Status.Publication
	if got.Status.Phase != v1alpha1.RunCompleted || got.Status.Destination.OrphanedAt == nil ||
		pub.Phase != v1alpha1.PublicationPhase(publication.PhaseOrphaned) || pub.Availability != v1alpha1.Availability(publication.AvailabilityUnavailable) ||
		pub.Cleanup.State != v1alpha1.CleanupState(publication.CleanupOrphaned) {
		t.Fatalf("completed run: %s", mustJSON(got.Status))
	}
	if pub.PublicationID != receipt.PublicationID || pub.PackageSHA256 != receipt.PackageSHA256 || !pub.ExpiresAt.Equal(receipt.ExpiresAt) ||
		*pub.Commit != *receipt.Commit || !pub.PublishedAt.Equal(receipt.PublishedAt) {
		t.Fatalf("receipt changed: %s vs %s", mustJSON(pub), mustJSON(receipt))
	}
	if controllerutil.ContainsFinalizer(got, RetentionFinalizer) {
		t.Fatal("retention finalizer kept for an operator-owned package")
	}
	if d := e.run(deleted).Status.Publication; d.Phase != v1alpha1.PublicationPhase(publication.PhaseDeleted) || d.Cleanup.State != v1alpha1.CleanupState(publication.CleanupDeleted) {
		t.Fatalf("Deleted record rewritten: %s", mustJSON(d))
	}
	if !e.gone(pending) {
		t.Fatal("run pending deletion not released after the inventory")
	}

	// With every run handed off, the destination's finalizer is released.
	reconcileDestination(t, dr, "primary")
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, &v1alpha1.EvidenceDestination{}); !apierrors.IsNotFound(err) {
		t.Fatalf("destination not finalized: %v", err)
	}

	// Past the original expiry and with the destination gone, nothing
	// resumes: no cleanup, no lookup error loop, no storage.
	e.now = receipt.ExpiresAt.Add(time.Hour)
	if res := e.step(completed); res.RequeueAfter != 0 {
		t.Fatalf("orphaned run requeued: %+v", res)
	}
	if p := e.run(completed).Status.Publication; p.Phase != v1alpha1.PublicationPhase(publication.PhaseOrphaned) {
		t.Fatalf("orphaned disposition cleared: %s", p.Phase)
	}
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), e.run(completed).Status.Destination); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("orphaned run served a publisher: %v", err)
	}
	if e.storageCalls() != before {
		t.Fatalf("disposition touched storage: %d calls", e.storageCalls()-before)
	}
}

// An interrupted run ends Failed (never Published) once the inventory is
// saved, and its binding's active run slot is released.
func TestOrphanedDispositionEndsInterruptedRun(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name) // pinned, collecting
	ed := e.destination("primary")
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "handed off", Actor: "platform-admin"}
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	before := e.storageCalls()
	reconcileDestination(t, e.destinationReconciler(e.c), "primary")
	e.step(name)
	r := e.run(name)
	c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
	if r.Status.Phase != v1alpha1.RunFailed || c == nil || c.Reason != v1alpha1.ReasonDestinationOrphaned || r.Status.Destination.OrphanedAt == nil {
		t.Fatalf("interrupted run: %s", mustJSON(r.Status))
	}
	if p := r.Status.Publication; p != nil && p.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted) {
		t.Fatal("interrupted run claims a committed publication")
	}
	e.assess("audit-prod")
	if a := e.schedule("audit-prod").ActiveRun; a != nil && a.Name == name {
		t.Fatalf("binding slot not released: %s", mustJSON(e.schedule("audit-prod")))
	}
	if e.storageCalls() != before {
		t.Fatal("disposition touched storage")
	}
}
