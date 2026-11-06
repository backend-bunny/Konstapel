package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// receiptLoss fails the first status update that records a completed run,
// as when the API server is unreachable right after the storage commit.
type receiptLoss struct {
	client.Client
	failed bool
}

func (c *receiptLoss) Status() client.SubResourceWriter {
	return &receiptLossWriter{c.Client.Status(), c}
}

type receiptLossWriter struct {
	client.SubResourceWriter
	c *receiptLoss
}

func (w *receiptLossWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if r, ok := obj.(*v1alpha1.AssessmentRun); ok && r.Status.Phase == v1alpha1.RunCompleted && !w.c.failed {
		w.c.failed = true
		return errors.New("connection refused")
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// A committed publication whose receipt never reached Kubernetes is
// reconciled from storage: the original digest, publication time, expiry and
// namespace scope are recorded and nothing is committed twice.
func TestReceiptUpdateFailureReconcilesOriginalCommit(t *testing.T) {
	e := newTeamEnv(t)
	e.request("dev", "nightly")
	e.assess("audit-all")
	name := e.requestStatus("dev", "nightly").Run.Name
	e.step(name)
	frozen := e.run(name).Status.Scope.DeepCopy()
	commitsBefore := e.pub.Commits()

	lossy := &receiptLoss{Client: e.c}
	e.rr.Client = lossy
	e.now = e.now.Add(5*time.Minute + time.Second)
	if _, err := e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err == nil || !lossy.failed {
		t.Fatal("receipt update did not fail")
	}
	run := e.run(name)
	if run.Status.Phase == v1alpha1.RunCompleted || e.pub.Commits() != commitsBefore+1 {
		t.Fatalf("setup: phase %s commits %d", run.Status.Phase, e.pub.Commits())
	}
	ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
	stored, err := e.pub.Inspect(context.Background(), ref)
	if err != nil || stored.Phase != publication.PhaseCommitted {
		t.Fatalf("storage commit: %+v %v", stored, err)
	}

	// A new leader, later, with a different retention on the binding.
	e.rr.Client = e.c
	e.restart()
	e.now = e.now.Add(3 * time.Minute)
	e.step(name)
	run = e.run(name)
	p := run.Status.Publication
	if run.Status.Phase != v1alpha1.RunCompleted || p == nil || p.PublishedAt == nil || p.ExpiresAt == nil ||
		!p.PublishedAt.Time.Equal(*stored.PublishedAt) || !p.ExpiresAt.Time.Equal(*stored.ExpiresAt) || run.Status.DescriptorSHA256 != stored.DescriptorSHA256 {
		t.Fatalf("receipt not reconciled from the original commit:\nstored %+v\nrun    %+v", stored, p)
	}
	if e.pub.Commits() != commitsBefore+1 {
		t.Fatalf("committed twice: %d", e.pub.Commits()-commitsBefore)
	}
	if run.Status.Scope.NamespaceUID != frozen.NamespaceUID || run.Status.Scope.NamespaceUID != "uid-dev" || statusJSON(run.Status.Scope) != statusJSON(frozen) {
		t.Fatalf("namespace scope changed: %+v → %+v", frozen, run.Status.Scope)
	}
	if st := e.requestStatus("dev", "nightly"); st.Phase != v1alpha1.RequestCompleted || st.ArtifactRef != stored.PublicationID {
		t.Fatalf("request not completed with the original publication: %+v", st)
	}
}
