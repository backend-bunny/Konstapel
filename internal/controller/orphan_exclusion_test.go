package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

func (e *pinEnv) inventoryConfigMaps(t *testing.T, uid string) int {
	t.Helper()
	var cms corev1.ConfigMapList
	if err := e.c.List(context.Background(), &cms, client.InNamespace("konstapel-system"), client.MatchingLabels{LabelOrphanHandoff: uid}); err != nil {
		t.Fatal(err)
	}
	return len(cms.Items)
}

// replacement recreates a destination under the same name and location
// (a new UID) and makes it the default.
func (e *pinEnv) replacement(t *testing.T, name, uid string) {
	t.Helper()
	ed := evidenceDestination(name, true)
	ed.UID = types.UID(uid)
	status := ed.Status
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	if err := e.c.Create(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	ed.Status = status
	if err := e.c.Status().Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	e.stores[uid] = fake.New(func() time.Time { return e.now })
	e.setDefault(name)
}

// Orphaned ownership is never adopted: a destination recreated under the
// same name at the same bucket/prefix, a restart, and the original expiry
// leave the handed-off run and its storage untouched, the replacement owes
// nothing for it, and the inventory is never collected.
func TestOrphanedOwnershipIsNeverAdopted(t *testing.T) {
	e, names := orphanedEnv(t)
	old := names[0]
	dr := e.destinationReconciler(e.c)
	reconcileDestination(t, dr, "primary")
	e.step(old)
	reconcileDestination(t, dr, "primary")
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, &v1alpha1.EvidenceDestination{}); err == nil {
		t.Fatal("setup: destination not finalized")
	}
	inventory := e.inventoryConfigMaps(t, "uid-primary")

	e.replacement(t, "primary", "uid-primary-2")
	reconcileDestination(t, dr, "primary")
	repl := e.destination("primary")
	if repl.Status.OutstandingRuns != 0 || repl.Status.OutstandingPackages != 0 || !meta.IsStatusConditionTrue(repl.Status.Conditions, v1alpha1.ConditionDestinationReady) {
		t.Fatalf("replacement adopted orphaned ownership: %s", mustJSON(repl.Status))
	}
	before := e.storageCalls()
	expires := e.run(old).Status.Publication.ExpiresAt.Time
	for _, at := range []time.Time{expires.Add(-time.Hour), expires.Add(time.Hour), expires.Add(400 * 24 * time.Hour)} {
		e.now = at
		e.restart()
		if res := e.step(old); res.RequeueAfter != 0 {
			t.Fatalf("orphaned run scheduled more work: %+v", res)
		}
		reconcileDestination(t, dr, "primary")
	}
	got := e.run(old)
	if got.Status.Publication.Phase != v1alpha1.PublicationPhase(publication.PhaseOrphaned) || got.Status.Destination.UID != "uid-primary" {
		t.Fatalf("orphaned run re-adopted: %s", mustJSON(got.Status))
	}
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), got.Status.Destination); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("orphaned pin resolved through the replacement: %v", err)
	}
	if e.storageCalls() != before {
		t.Fatalf("orphaned storage touched: %d calls", e.storageCalls()-before)
	}
	if n := e.inventoryConfigMaps(t, "uid-primary"); n != inventory || n == 0 {
		t.Fatalf("inventory collected: %d of %d ConfigMaps", n, inventory)
	}
}

// A destination removed by force (finalizer stripped) after its inventory
// was saved but before its runs were handed off: the inventory still owns
// them, so they take the Orphaned disposition instead of recovering, and
// nothing is served or touched. Without an inventory a lost destination is
// only unavailable.
func TestForcedFinalizationKeepsOrphanedOwnership(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	ed := e.destination("primary")
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "handed off", Actor: "platform-admin"}
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	reconcileDestination(t, e.destinationReconciler(e.c), "primary")
	ed = e.destination("primary")
	controllerutil.RemoveFinalizer(ed, DestinationFinalizer)
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, &v1alpha1.EvidenceDestination{}); err == nil {
		t.Fatal("setup: destination not removed")
	}
	pin := e.run(name).Status.Destination
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), pin); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("lost destination with an inventory served: %v", err)
	}
	before := e.storageCalls()
	e.restart()
	e.step(name)
	r := e.run(name)
	c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
	if r.Status.Phase != v1alpha1.RunFailed || c == nil || c.Reason != v1alpha1.ReasonDestinationOrphaned || r.Status.Destination.OrphanedAt == nil {
		t.Fatalf("run recovered instead of handed off: %s", mustJSON(r.Status))
	}
	if e.storageCalls() != before {
		t.Fatal("storage touched")
	}

	// A lost destination without an inventory is only unavailable.
	lost := &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "gone", UID: "uid-gone"}}
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), lost); errors.Is(err, publication.ErrOrphaned) || !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("lost destination without inventory: %v", err)
	}
}
