package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// Selecting Orphan changes nothing; deletion with an admission-recorded
// actor accepts the handoff exactly once; without a recorded actor nothing
// is accepted.
func TestOrphanIntentIsAcceptedOnceOnDeletion(t *testing.T) {
	e := newPinEnv(t)
	at := time.Date(2026, 11, 7, 3, 0, 0, 0, time.UTC)
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Now: func() time.Time { return at },
		Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}
	reconcile := func() {
		t.Helper()
		if _, err := dr.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	// A pinned, collecting run holds the destination through deletion.
	e.deliver("audit-prod")
	e.assess("audit-prod")
	e.step(e.schedule("audit-prod").ActiveRun.Name)
	ed := e.destination("primary")
	if !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatal("setup: destination not pinned")
	}
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "bucket handed to the archive team"}
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	// Selecting the policy alone: nothing accepted, no storage touched.
	reconcile()
	if got := e.destination("primary"); got.Status.OrphanIntent != nil {
		t.Fatal("orphan accepted before deletion")
	}
	for _, s := range e.stores {
		if s.Calls(fake.OpDelete) != 0 || s.Calls(fake.OpCleanup) != 0 {
			t.Fatal("selecting Orphan touched storage")
		}
	}
	// Deleted without an admission-recorded actor: not accepted, and the
	// condition says why.
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	reconcile()
	got := e.destination("primary")
	c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
	if got.Status.OrphanIntent != nil || c == nil || !strings.Contains(c.Message, "no admission-recorded actor") {
		t.Fatalf("unattributed orphan: %+v %+v", got.Status.OrphanIntent, c)
	}
	// Admission recorded the actor (escalation of a terminating destination).
	got.Spec.Orphan.Actor, got.Spec.Orphan.ActorUID = "platform-admin", "uid-admin"
	if err := e.c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	got = e.destination("primary")
	want := v1alpha1.OrphanIntent{Reason: "bucket handed to the archive team", Actor: "platform-admin", ActorUID: "uid-admin"}
	if oi := got.Status.OrphanIntent; oi == nil || oi.Reason != want.Reason || oi.Actor != want.Actor || oi.ActorUID != want.ActorUID || !oi.AcceptedAt.Time.Equal(at) {
		t.Fatalf("accepted intent %+v", got.Status.OrphanIntent)
	}
	// Accepted once: later reconciles never change it.
	at = at.Add(time.Hour)
	got.Spec.Orphan.Reason = "changed after acceptance (admission rejects this in a cluster)"
	_ = e.c.Update(context.Background(), got)
	reconcile()
	if oi := e.destination("primary").Status.OrphanIntent; oi.Reason != want.Reason || !oi.AcceptedAt.Time.Equal(at.Add(-time.Hour)) {
		t.Fatalf("accepted intent changed: %+v", oi)
	}
}
