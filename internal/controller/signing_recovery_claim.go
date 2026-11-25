package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// The per-run recovery claim (add-evidence-signing-recovery task 2.3,
// design section 5).
//
// At most one EvidenceSigningRequest holds a run: it records itself in
// status.signingRecovery.active with a resourceVersion-conditional status
// update of the run, so of two concurrent claimants exactly one wins and
// the other re-reads the run. Every other request for the run waits
// (Pending/Waiting). The claim is durable in the run's status, so it
// survives restarts and leader changes and the successor resumes the
// holder's request. A claim whose request is gone, was recreated, or is
// already terminal is stale and is cleared after a fresh read; a holder that
// ends terminally releases its own claim after recording its outcome, so a
// crash between the two writes is repaired by its next reconcile. The
// recovered record (task 2.6) is set, and the claim cleared, in the single
// run update that commits the recovered publication; any request evaluated
// after that ends from the recovered run without a storage write.

func (r *SigningRecoveryReconciler) poll() time.Duration {
	if p := r.Runtime.Poll; p > 0 {
		return p
	}
	return 15 * time.Second
}

func (r *SigningRecoveryReconciler) publishTimeout() time.Duration {
	if p := r.Runtime.PublishTimeout; p > 0 {
		return p
	}
	return 5 * time.Minute
}

// claimOf returns the run's current recovery claim, or nil.
func claimOf(run *v1alpha1.AssessmentRun) *v1alpha1.SigningRecoveryClaim {
	if sr := run.Status.SigningRecovery; sr != nil {
		return sr.Active
	}
	return nil
}

// holdsClaim reports whether the claim names this request (name and UID: a
// recreated request with the same name never inherits a claim).
func holdsClaim(c *v1alpha1.SigningRecoveryClaim, esr *v1alpha1.EvidenceSigningRequest) bool {
	return c != nil && c.Name == esr.Name && c.UID == string(esr.UID)
}

// staleClaim reports, from an uncached read, whether the request named by a
// claim is gone, was recreated, or has already ended.
func (r *SigningRecoveryReconciler) staleClaim(ctx context.Context, c *v1alpha1.SigningRecoveryClaim) (bool, error) {
	holder := &v1alpha1.EvidenceSigningRequest{}
	switch err := r.reader().Get(ctx, client.ObjectKey{Name: c.Name}, holder); {
	case apierrors.IsNotFound(err):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("read the EvidenceSigningRequest %s holding the recovery claim: %w", c.Name, err)
	}
	return string(holder.UID) != c.UID || holder.Status.Phase.Terminal(), nil
}

// claim records esr as the run's recovery holder. The update carries the
// resourceVersion of the uncached read the decision was made from, so a
// concurrent claim, release, or any other run status write since then makes
// it fail with a conflict and the request is evaluated again from a fresh
// read. The attempt's deadline is the claim time plus PublishTimeout.
func (r *SigningRecoveryReconciler) claim(ctx context.Context, run *v1alpha1.AssessmentRun, esr *v1alpha1.EvidenceSigningRequest) error {
	now := r.now().UTC().Truncate(time.Second)
	c := &v1alpha1.SigningRecoveryClaim{Name: esr.Name, UID: string(esr.UID),
		ClaimedAt: metav1.NewTime(now), Deadline: metav1.NewTime(now.Add(max(r.publishTimeout(), time.Second)))}
	before := run.Status.SigningRecovery
	sr := &v1alpha1.SigningRecoveryStatus{}
	if before != nil {
		sr = before.DeepCopy()
	}
	sr.Active = c
	run.Status.SigningRecovery = sr
	if err := r.Client.Status().Update(ctx, run); err != nil {
		run.Status.SigningRecovery = before
		return err
	}
	return nil
}

// clearClaim removes the claim c from the run with a
// resourceVersion-conditional update; a concurrent change makes it fail
// with a conflict instead of clearing a newer claim.
func (r *SigningRecoveryReconciler) clearClaim(ctx context.Context, run *v1alpha1.AssessmentRun, c *v1alpha1.SigningRecoveryClaim) error {
	cur := claimOf(run)
	if cur == nil || cur.UID != c.UID || cur.Name != c.Name {
		return nil
	}
	before := run.Status.SigningRecovery
	if before.Recovered == nil {
		// Nothing else is recorded: the run keeps no empty recovery state.
		run.Status.SigningRecovery = nil
	} else {
		sr := before.DeepCopy()
		sr.Active = nil
		run.Status.SigningRecovery = sr
	}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		run.Status.SigningRecovery = before
		return err
	}
	return nil
}

// release clears a claim esr still holds on its run, from an uncached read.
// It never writes the request, and writes the run only when the request
// holds it.
func (r *SigningRecoveryReconciler) release(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest) error {
	run := &v1alpha1.AssessmentRun{}
	switch err := r.reader().Get(ctx, client.ObjectKey{Name: esr.Spec.Run.Name}, run); {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("read AssessmentRun %s to release its recovery claim: %w", esr.Spec.Run.Name, err)
	}
	if c := claimOf(run); holdsClaim(c, esr) {
		return r.clearClaim(ctx, run, c)
	}
	return nil
}

// end records a terminal Failed outcome, then releases any claim the request
// holds so that a waiting request can try. The outcome is written first: a
// crash in between leaves a stale claim of a terminal request, which its next
// reconcile (or any waiting request) clears.
func (r *SigningRecoveryReconciler) end(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, reason v1alpha1.SigningRecoveryReason, msg string) error {
	if err := r.fail(ctx, esr, reason, msg); err != nil {
		return err
	}
	return r.release(ctx, esr)
}

// pending records a non-terminal Pending reason and message, writing only on
// a change. The resourceVersion precondition makes a concurrent writer
// retry from a fresh read.
func (r *SigningRecoveryReconciler) pending(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, reason v1alpha1.SigningRecoveryReason, msg string) error {
	st := &esr.Status
	msg = truncateRecoveryMessage(msg)
	if st.Phase == v1alpha1.SigningRequestPending && st.Reason == reason && st.Message == msg && st.AcceptedAt != nil {
		return nil
	}
	now := metav1.NewTime(r.now())
	r.record(esr, now)
	st.Phase, st.Reason, st.Message = v1alpha1.SigningRequestPending, reason, msg
	meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionFalse,
		Reason: string(reason), Message: msg, ObservedGeneration: esr.Generation, LastTransitionTime: now})
	return r.Client.Status().Update(ctx, esr)
}

// wait records that another request holds the run and polls: the holder's
// release or recovery also wakes waiting requests through the run watch.
func (r *SigningRecoveryReconciler) wait(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, c *v1alpha1.SigningRecoveryClaim) (reconcile.Result, error) {
	msg := fmt.Sprintf("waiting: EvidenceSigningRequest %s holds the signing recovery of AssessmentRun %s", c.Name, esr.Spec.Run.Name)
	if err := r.pending(ctx, esr, v1alpha1.RecoveryWaiting, msg); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: r.poll()}, nil
}

// finishRecovered ends a request evaluated after its run records a
// successful recovery. It issues no storage write: the run is the durable
// record. The namespace AssessmentRequest projection is reconciled from the
// recovered run first (never recreating or overwriting a missing or
// recreated request); only then does the request succeed, as Recovered when
// it is the recorded request (the holder resuming after its run update) and
// AlreadyRecovered otherwise, referencing the same commit and signature.
func (r *SigningRecoveryReconciler) finishRecovered(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun) error {
	rec := run.Status.SigningRecovery.Recovered
	pub := run.Status.Publication
	if run.Status.Phase != v1alpha1.RunCompleted || pub == nil || pub.Commit == nil || pub.Signature == nil || pub.PublishedAt == nil || pub.ExpiresAt == nil {
		// The recovered record is written with the committed publication in
		// one update, so this is never a state recovery produced.
		return fmt.Errorf("AssessmentRun %s records a signing recovery without a committed signed publication", run.Name)
	}
	if err := finishRequestStatus(ctx, r.Client, run, ""); err != nil {
		return err
	}
	reason, msg := v1alpha1.RecoveryAlreadyRecovered, fmt.Sprintf("AssessmentRun %s was already recovered by EvidenceSigningRequest %s", run.Name, rec.Name)
	if rec.Name == esr.Name && rec.UID == string(esr.UID) {
		reason, msg = v1alpha1.RecoveryRecovered, fmt.Sprintf("AssessmentRun %s was published with its recovered signature", run.Name)
	}
	now := metav1.NewTime(r.now())
	r.record(esr, now)
	st := &esr.Status
	msg = truncateRecoveryMessage(msg)
	st.Phase, st.Reason, st.Message, st.CompletedAt = v1alpha1.SigningRequestSucceeded, reason, msg, &now
	st.KeyFingerprint = pub.Signature.KeyFingerprint
	st.Publication = &v1alpha1.SigningRecoveryPublication{PublicationID: pub.PublicationID, PackageSHA256: pub.PackageSHA256,
		SignatureSHA256: pub.Signature.SHA256, PublishedAt: *pub.PublishedAt, ExpiresAt: *pub.ExpiresAt}
	meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionTrue,
		Reason: string(reason), Message: msg, ObservedGeneration: esr.Generation, LastTransitionTime: now})
	return r.Client.Status().Update(ctx, esr)
}

// signingRequestsForRun enqueues the requests that name a run, so that a
// released claim, a recorded recovery, or the run's deletion is seen without
// waiting for the poll.
func signingRequestsForRun(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var list v1alpha1.EvidenceSigningRequestList
		if err := c.List(ctx, &list); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, esr := range list.Items {
			if esr.Spec.Run.Name == o.GetName() {
				out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: esr.Name}})
			}
		}
		return out
	})
}

// signingRecoveryChanged passes run updates that change the run's recovery
// state or start its deletion; creations and deletions always pass.
func signingRecoveryChanged() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		o, ok1 := e.ObjectOld.(*v1alpha1.AssessmentRun)
		n, ok2 := e.ObjectNew.(*v1alpha1.AssessmentRun)
		if !ok1 || !ok2 {
			return false
		}
		return !equalJSON(o.Status.SigningRecovery, n.Status.SigningRecovery) || o.DeletionTimestamp.IsZero() != n.DeletionTimestamp.IsZero()
	}}
}
