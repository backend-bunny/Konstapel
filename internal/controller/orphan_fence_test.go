package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func (e *pinEnv) acceptOrphan(t *testing.T, name string) {
	t.Helper()
	ed := e.destination(name)
	ed.Status.OrphanIntent = &v1alpha1.OrphanIntent{Reason: "handed to archive team", Actor: "platform-admin", AcceptedAt: metav1.NewTime(e.now)}
	if err := e.c.Status().Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
}

func (e *pinEnv) storageCalls() int {
	n := 0
	for _, s := range e.stores {
		for _, op := range []fake.Op{fake.OpStage, fake.OpPublish, fake.OpInspect, fake.OpDelete, fake.OpCleanup, fake.OpOpen} {
			n += s.Calls(op)
		}
	}
	return n
}

// After an accepted handoff a pinned run issues no storage operation of any
// kind — not at collection timeout, publication, retries, or retention —
// including after a restart with an empty in-process fence.
func TestOrphanFenceStopsAllStorageWork(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name) // pinned, collecting
	e.acceptOrphan(t, "primary")
	before := e.storageCalls()
	for _, at := range []time.Duration{6 * time.Minute, 12 * time.Minute, 48 * time.Hour} {
		e.now = a0.Add(at)
		if res := e.step(name); res.RequeueAfter != OrphanHoldRequeue {
			t.Fatalf("fenced run not held: %+v", res)
		}
	}
	// A restarted process has no in-memory fence; the durable intent holds.
	e.rr.Runtime.Destinations = &DestinationPublishers{Reader: e.c, New: e.rr.Runtime.Destinations.New}
	e.restart()
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCollecting || e.storageCalls() != before {
		t.Fatalf("fenced run progressed or touched storage: %s, %d calls", r.Status.Phase, e.storageCalls()-before)
	}
}

// A completed package on an orphaned destination is never deleted or
// checked by Konstapel, even after its expiry; a late success does not
// resume cleanup.
func TestOrphanFenceStopsRetention(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name) // published (the late response arrived before the fence)
	if e.run(name).Status.Phase != v1alpha1.RunCompleted {
		t.Fatal("setup")
	}
	e.acceptOrphan(t, "primary")
	before := e.storageCalls()
	e.now = e.run(name).Status.Publication.ExpiresAt.Add(time.Hour)
	e.step(name)
	if e.storageCalls() != before || e.run(name).Status.Publication.Cleanup.State == "Deleted" {
		t.Fatal("retention ran against an orphaned destination")
	}
}

// Fencing cancels and drains in-process work with a bounded wait; work that
// does not stop in time is reported as uncertain, and no new work begins.
func TestFenceCancelsAndDrainsInflightWork(t *testing.T) {
	p := &DestinationPublishers{}
	ctx, done, err := p.Begin(context.Background(), "uid-a", "run a Publishing")
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-ctx.Done(); done() }()                                   // honours cancellation
	_, _, err = p.Begin(context.Background(), "uid-a", "run b Publishing") // ignores it
	if err != nil {
		t.Fatal(err)
	}
	other, otherDone, _ := p.Begin(context.Background(), "uid-b", "run c Publishing")
	defer otherDone()
	uncertain := p.Fence("uid-a", 200*time.Millisecond)
	if len(uncertain) != 1 || uncertain[0] != "run b Publishing" {
		t.Fatalf("uncertain %v", uncertain)
	}
	if _, _, err := p.Begin(context.Background(), "uid-a", "late"); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("work began after the fence: %v", err)
	}
	if other.Err() != nil {
		t.Fatal("another destination's work was cancelled")
	}
}

// The destination reconciler records the fence, stops probing, and refuses
// the destination to publisher lookups.
func TestDestinationReconcilerFencesOrphanedDestination(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	e.step(e.schedule("audit-prod").ActiveRun.Name)
	ed := e.destination("primary")
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "handed off", Actor: "platform-admin"}
	_ = e.c.Update(context.Background(), ed)
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	probes := 0
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Destinations: e.rr.Runtime.Destinations, DrainTimeout: 10 * time.Millisecond,
		Probe: func(context.Context, s3store.Destination, client.Reader, string) error { probes++; return nil }}
	if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
		t.Fatal(err)
	}
	got := e.destination("primary")
	if got.Status.OrphanIntent == nil || got.Status.OrphanHandoff == nil || !got.Status.OrphanHandoff.Drained || probes != 0 {
		t.Fatalf("handoff %+v probes %d", got.Status.OrphanHandoff, probes)
	}
	pin := &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "primary", UID: string(got.UID)}}
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), pin); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("orphaned destination served a publisher: %v", err)
	}
}

// A hanging backend cannot stall the destination reconciler: the probe is
// bounded and the destination is reported not ready.
func TestDestinationProbeIsBounded(t *testing.T) {
	e := newPinEnv(t)
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, ProbeTimeout: 50 * time.Millisecond,
		Probe: func(ctx context.Context, _ s3store.Destination, _ client.Reader, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		}}
	start := time.Now()
	if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("probe not bounded")
	}
	if c := e.destination("primary").Status.Conditions; len(c) == 0 || c[0].Status != metav1.ConditionFalse {
		t.Fatalf("hanging backend reported ready: %+v", c)
	}
}
