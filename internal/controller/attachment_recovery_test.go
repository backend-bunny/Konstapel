package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// add-supporting-evidence-attachments 4.2: crash and restart at every
// durable step of an attachment's life. The controller process stops right
// before its n-th API write (so every earlier write, and every storage
// operation before it, has happened); a fresh process with empty memory
// (a restart or a new leader) continues. For every n the record ends the
// same way: withdrawn, retained until its fixed expiry, released only
// after its owned source is removed, and nothing else touched.

var errCrashed = errors.New("test: the controller process stopped before this write")

// crashingClient allows a budget of writes, then fails every write. It
// logs the writes it allowed.
type crashingClient struct {
	client.Client
	budget *int
	log    *[]string
}

func (c crashingClient) spend(op string, o client.Object) error {
	if *c.budget <= 0 {
		return errCrashed
	}
	*c.budget--
	*c.log = append(*c.log, fmt.Sprintf("%s %s/%s", op, strings.TrimPrefix(fmt.Sprintf("%T", o), "*v1alpha1."), o.GetName()))
	return nil
}

func (c crashingClient) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	if err := c.spend("create", o); err != nil {
		return err
	}
	return c.Client.Create(ctx, o, opts...)
}

func (c crashingClient) Update(ctx context.Context, o client.Object, opts ...client.UpdateOption) error {
	if err := c.spend("update", o); err != nil {
		return err
	}
	return c.Client.Update(ctx, o, opts...)
}

func (c crashingClient) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.PatchOption) error {
	if err := c.spend("patch", o); err != nil {
		return err
	}
	return c.Client.Patch(ctx, o, p, opts...)
}

func (c crashingClient) Delete(ctx context.Context, o client.Object, opts ...client.DeleteOption) error {
	if err := c.spend("delete", o); err != nil {
		return err
	}
	return c.Client.Delete(ctx, o, opts...)
}

func (c crashingClient) Status() client.SubResourceWriter {
	return crashingStatus{SubResourceWriter: c.Client.Status(), c: c}
}

type crashingStatus struct {
	client.SubResourceWriter
	c crashingClient
}

func (s crashingStatus) Update(ctx context.Context, o client.Object, opts ...client.SubResourceUpdateOption) error {
	if err := s.c.spend("status update", o); err != nil {
		return err
	}
	return s.SubResourceWriter.Update(ctx, o, opts...)
}

func (s crashingStatus) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
	if err := s.c.spend("status patch", o); err != nil {
		return err
	}
	return s.SubResourceWriter.Patch(ctx, o, p, opts...)
}

// lifecycleRun drives one record through registration, commitment,
// withdrawal, a refused deletion and cleanup, with the first controller
// process crashing before write number budget+1.
type lifecycleRun struct {
	*storageFixture
	budget  int
	crashed bool
	// writes are the first process's writes, in order.
	writes []string
}

func (l *lifecycleRun) process(c client.Client) *AttachmentReconciler {
	return &AttachmentReconciler{Client: c, Baselines: l.r.Baselines, Storage: &AttachmentStorage{Reader: l.c, Namespace: "konstapel-system",
		Cluster: "kube-system:cluster", Stores: l.stores, ContentInterval: time.Hour, Now: func() time.Time { return l.now }}}
}

// converge reconciles until the record is released or a pass writes
// nothing. A crash replaces the process.
func (l *lifecycleRun) converge(name string) {
	l.t.Helper()
	for range 30 {
		before := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(context.Background(), client.ObjectKey{Name: name}, before); apierrors.IsNotFound(err) {
			return
		}
		_, err := l.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
		switch {
		case errors.Is(err, errCrashed):
			l.crashed = true
			l.r = l.process(l.c) // restart with no memory of the old process
			continue
		case apierrors.IsConflict(err):
			continue
		case err != nil:
			l.t.Fatal(err)
		}
		after := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(context.Background(), client.ObjectKey{Name: name}, after); apierrors.IsNotFound(err) || after.ResourceVersion == before.ResourceVersion {
			return
		}
	}
	l.t.Fatalf("%s did not converge", name)
}

func (l *lifecycleRun) run() {
	t := l.t
	ctx := context.Background()
	budget := l.budget
	first := crashingClient{Client: l.c, budget: &budget, log: &l.writes}
	l.r = l.process(first)
	l.create("dc", l.association("a", "uid-a"))
	l.converge("dc")
	if a := l.get("dc"); a.Status.Storage == nil || a.Status.Storage.Destination == nil || a.Labels[v1alpha1.LabelAttachmentDestination] != "dest-1" {
		t.Fatalf("not pinned: %+v %v", a.Status.Storage, a.Labels)
	}
	r := l.commit("dc", "dest-1", nil)
	l.converge("dc")
	if a := l.get("dc"); a.Status.Storage.Commitment == nil || !a.Status.Storage.Commitment.ExpiresAt.Time.Equal(r.ExpiresAt) || contentOf(a) != "Available/Verified" {
		t.Fatalf("commitment not recorded: %+v", a.Status)
	}
	if err := l.c.Delete(ctx, l.get("dc")); err != nil {
		t.Fatal(err)
	}
	l.converge("dc")
	a := l.get("dc")
	if a.Status.Withdrawal == nil || a.Status.Storage.Cleanup == nil || a.Status.Storage.Cleanup.State != "NotDue" || a.Status.Storage.Commitment == nil {
		t.Fatalf("withdrawn record not retained: %+v", a.Status)
	}
	// An hour before the expiry, a pass (from any process) deletes nothing.
	l.now = r.ExpiresAt.Add(-time.Hour)
	l.converge("dc")
	if len(l.store().deleted) != 0 {
		t.Fatal("deleted before the fixed expiry")
	}
	// At the expiry storage first refuses, then allows, the deletion.
	l.now = r.ExpiresAt
	l.store().deleteErr = errors.New("AccessDenied")
	l.converge("dc")
	if a := l.get("dc"); a.Status.Storage.Cleanup.State != string(attachments.CleanupRetentionBlocked) || a.Status.Storage.Commitment == nil {
		t.Fatalf("refused deletion: %+v", a.Status.Storage)
	}
	l.store().deleteErr = nil
	l.now = l.now.Add(time.Minute)
	l.converge("dc")
	if err := l.c.Get(ctx, client.ObjectKey{Name: "dc"}, &v1alpha1.EvidenceAttachment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("record not released: %v", err)
	}
	for _, at := range l.store().deletedAt {
		if at.Before(r.ExpiresAt) {
			t.Fatalf("source deleted at %s, before its expiry %s", at, r.ExpiresAt)
		}
	}
	if len(l.store().deleted) == 0 || l.store().deleted[0].UID != "dc-uid" {
		t.Fatalf("deletions %v", l.store().deleted)
	}
	// The neighbor keeps its storage, pin and destination protection.
	if _, err := l.store().Committed(ctx, attachments.Ref{ClusterID: "kube-system:cluster", UID: "neighbor-uid"}); err != nil {
		t.Fatalf("another record's source was touched: %v", err)
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKey{Name: "primary"}, ed); err != nil || !containsString(ed.Finalizers, DestinationFinalizer) {
		t.Fatalf("destination protection lost: %v", err)
	}
}

func TestAttachmentRecoversFromACrashAtEveryDurableStep(t *testing.T) {
	newRun := func(t *testing.T, budget int) *lifecycleRun {
		f := newLifecycleFixture(t)
		f.create("neighbor", f.association("a", "uid-a"))
		f.settle("neighbor")
		f.commit("neighbor", "dest-1", nil)
		f.settle("neighbor")
		return &lifecycleRun{storageFixture: f, budget: budget}
	}
	// Without a crash: count the writes, each a durable step.
	full := newRun(t, 1<<30)
	full.run()
	if full.crashed || len(full.writes) < 8 {
		t.Fatalf("uninterrupted run made %d writes (crashed %v)", len(full.writes), full.crashed)
	}
	for n, w := range full.writes {
		t.Run(fmt.Sprintf("crash before write %d %s", n+1, w), func(t *testing.T) {
			l := newRun(t, n)
			l.run()
			if !l.crashed {
				t.Fatal("the process did not crash")
			}
		})
	}
}
