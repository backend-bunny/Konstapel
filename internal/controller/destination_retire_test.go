package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// Deleting a destination retires it: pinned work finishes, retained packages
// stay downloadable until expiry and are cleaned up, blockers are visible and
// retried, unknown expiry is never "empty", and only then is it released.
func TestDestinationRetirementHoldsUntilObligationsEnd(t *testing.T) {
	e := newPinEnv(t)
	b := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(b), b)
	b.Spec.Assessment.Retention = "1h"
	if err := e.c.Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	reconcileDest := func() *v1alpha1.EvidenceDestination {
		t.Helper()
		if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
			t.Fatal(err)
		}
		ed := &v1alpha1.EvidenceDestination{}
		if err := e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, ed); apierrors.IsNotFound(err) {
			return nil
		} else if err != nil {
			t.Fatal(err)
		}
		return ed
	}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name) // pinned to primary, collecting

	// 1. Delete while the run collects: held, outstanding with unknown expiry.
	if err := e.c.Delete(context.Background(), e.destination("primary")); err != nil {
		t.Fatal(err)
	}
	ed := reconcileDest()
	c := meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
	if ed == nil || !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) || ed.Status.OutstandingRuns != 1 || ed.Status.UnknownExpiryRuns != 1 || c == nil || c.Reason != "Retiring" {
		t.Fatalf("collecting run: %+v", ed.Status)
	}
	// New work cannot select it.
	if sel := selectDestination(context.Background(), e.c, "", e.binding(t)); sel.Ready || sel.Reason != v1alpha1.ReasonDestinationRetiring {
		t.Fatalf("retiring destination selected: %+v", sel)
	}

	// 2. The pinned run still publishes there; its package is retained.
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || e.stores["uid-primary"].Commits() != 1 {
		t.Fatalf("pinned run did not finish at its retiring destination: %s", r.Status.Phase)
	}
	e.step(name) // attempt cleanup
	ed = reconcileDest()
	if ed.Status.OutstandingRuns != 0 || ed.Status.OutstandingPackages != 1 || ed.Status.UnknownExpiryRuns != 0 || ed.Status.LatestRetainedExpiry == nil ||
		!ed.Status.LatestRetainedExpiry.Equal(r.Status.Publication.ExpiresAt) || !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatalf("retained package: %+v", ed.Status)
	}
	// Downloads keep working from the pinned destination while it retires.
	if _, err := e.rr.publisherFor(context.Background(), r); err != nil {
		t.Fatalf("retiring destination unreachable for its pinned run: %v", err)
	}

	// 3. Expiry deletion is blocked: the blocker is visible and retried.
	e.stores["uid-primary"].Fail(fake.OpDelete, publication.ErrRetentionBlocked)
	e.now = r.Status.Publication.ExpiresAt.Add(time.Second)
	e.step(name)
	ed = reconcileDest()
	c = meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
	if ed.Status.OutstandingPackages != 1 || len(ed.Status.CleanupBlockers) != 1 || !strings.Contains(ed.Status.CleanupBlockers[0], "RetentionBlocked") ||
		c.Reason != "RetirementBlocked" || !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatalf("blocked cleanup: %+v", ed.Status)
	}

	// 4. The retry succeeds, the run record is released, and so is the destination.
	e.now = e.now.Add(2 * time.Minute)
	e.step(name)
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, &v1alpha1.AssessmentRun{}); err != nil {
		// A run that was not deleted keeps a tombstone; either way it owes nothing.
		if !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
	if ed = reconcileDest(); ed != nil {
		t.Fatalf("destination kept after its obligations ended: %+v %v", ed.Status, ed.Finalizers)
	}
}

// A run still starting (labelled, not yet pinned) holds a retiring
// destination with unknown expiry; once it fails without storage writes it
// owes nothing.
func TestStartingRunHoldsRetiringDestination(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	r := e.run(name)
	r.Labels = map[string]string{LabelRunDestination: "uid-primary"}
	if err := e.c.Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ed := e.destination("primary")
	controllerutil.AddFinalizer(ed, DestinationFinalizer)
	_ = e.c.Update(context.Background(), ed)
	_ = e.c.Delete(context.Background(), ed)
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}
	if _, err := dr.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if ed = e.destination("primary"); ed.Status.OutstandingRuns != 1 || ed.Status.UnknownExpiryRuns != 1 || !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatalf("starting run not counted: %+v", ed.Status)
	}
	// The start resumes, confirmation sees the deletion, the run fails
	// without storage writes, and the destination is released.
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	e.step(name)
	if _, err := dr.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, &v1alpha1.EvidenceDestination{}); !apierrors.IsNotFound(err) {
		t.Fatalf("destination not released after the losing start: %v", err)
	}
	for _, s := range e.stores {
		if s.Calls(fake.OpStage) != 0 {
			t.Fatal("storage written by a losing start")
		}
	}
}
