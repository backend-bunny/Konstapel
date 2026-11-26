package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// The recovery attempt (add-evidence-signing-recovery task 2.4, design
// section 4, decision 7).
//
// The claim holder finishes the run's signed publication through the run
// path's own signingRequirement and the publisher's commit gate, under the
// destination fence it holds as "run <name> signature recovery":
//
//   - A matching commit already in storage (one whose response was lost) is
//     adopted unchanged, with no storage write.
//   - An intent that never pinned a key pins one only as the request
//     confirms it: without spec.expectedKeyFingerprint the request ends
//     KeyConfirmationRequired before any Secret is read; a Secret holding
//     another key ends it KeyMismatch and nothing is pinned.
//   - signingRequirement then uses a stored signature that verifies under the
//     pinned key without reading any private key, and otherwise signs with
//     the pinned key only (any other key is KeyMismatch) and stores the
//     signature once (the first durable writer wins). A stored signature that
//     does not verify is never replaced: Conflict.
//   - The commit carries the run's recorded retention, bounded by its
//     recorded expiry (retention.notAfter), never a retention selected now.
//
// The destination's current signing policy, other Secrets, and key rotation
// are never consulted, so nothing commits unsigned or under another key.
// Retried, overlapping, and successor attempts converge on one stored
// signature and one commit: the claim admits one request, the signature
// store and the commit are first-writer-wins, and an existing commit is
// adopted. Recording the committed publication on the run (task 2.6) and the
// attempt deadline (task 2.5) build on this; until then the holder reports
// the commit and keeps its claim.

// signing is the run path's publication signing (publication_signing.go)
// over this reconciler's API client, runtime, and clock.
func (r *SigningRecoveryReconciler) signing() *AssessmentRunReconciler {
	return &AssessmentRunReconciler{Client: r.Client, Runtime: r.Runtime, Now: r.Now}
}

// running records the holder's Running reason and message.
func (r *SigningRecoveryReconciler) running(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, reason v1alpha1.SigningRecoveryReason, msg string) error {
	return r.progress(ctx, esr, v1alpha1.SigningRequestRunning, reason, msg)
}

// advance records that the holder entered reason, only moving forward
// (Accepted, then Signing, then Committing): a retried attempt keeps the
// outcome its last attempt recorded instead of rewriting the request on every
// poll.
func (r *SigningRecoveryReconciler) advance(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, reason v1alpha1.SigningRecoveryReason, msg string) error {
	if st := esr.Status; st.Phase == v1alpha1.SigningRequestRunning && (st.Reason == reason || st.Reason == v1alpha1.RecoveryCommitting) {
		return nil
	}
	return r.running(ctx, esr, reason, msg)
}

// attempt runs the claim holder's recovery within fenced work of the run's
// pinned destination. el is the storage eligibility read in the same work.
func (r *SigningRecoveryReconciler) attempt(ctx, fenced context.Context, store publication.Publisher, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun, el recoveryEligibility) (reconcile.Result, error) {
	if el.committed != nil {
		// Adopted unchanged with its own publication time and expiry.
		return r.committed(ctx, esr, run, *el.committed)
	}
	in := run.Status.SigningIntent
	if in.Key == nil {
		if res, stop, err := r.confirmKey(ctx, fenced, esr, run); stop || err != nil {
			return res, err
		}
	}
	if err := r.advance(ctx, esr, v1alpha1.RecoverySigning, fmt.Sprintf("signing the retained archive of AssessmentRun %s under its intent key %s, or reusing its stored signature", run.Name, in.Key.Fingerprint)); err != nil {
		return reconcile.Result{}, err
	}
	signing, err := r.signing().signingRequirement(fenced, run, store, el.staged, in)
	if err != nil {
		return r.attemptFailed(ctx, esr, run, v1alpha1.RecoverySigning, err)
	}
	if signing.Mode != publication.SigningRequired || signing.KeyFingerprint != in.Key.Fingerprint {
		// signingRequirement satisfies a Required intent only; never commit
		// anything else.
		return reconcile.Result{}, fmt.Errorf("AssessmentRun %s: signing requirement %s/%s is not the intent's", run.Name, signing.Mode, signing.KeyFingerprint)
	}
	if err := r.advance(ctx, esr, v1alpha1.RecoveryCommitting, fmt.Sprintf("committing AssessmentRun %s with its signature under %s", run.Name, in.Key.Fingerprint)); err != nil {
		return reconcile.Result{}, err
	}
	receipt, err := store.Publish(fenced, publication.PublishRequest{Staged: el.staged, Retention: recordedRetention(run, r.now()), Signing: signing})
	if err != nil {
		return r.attemptFailed(ctx, esr, run, v1alpha1.RecoveryCommitting, err)
	}
	if receipt.ExpiredAt(r.now()) {
		// Committed at or after the recorded expiry: never served, and
		// deleted by the run's retention.
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryExpired, fmt.Sprintf("the recovered commit of AssessmentRun %s landed at %s, at or after its recorded expiry %s; it is never served",
			run.Name, receipt.PublishedAt.UTC().Format(time.RFC3339), receipt.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	return r.committed(ctx, esr, run, publication.Committed(receipt))
}

// confirmKey pins the key of an intent that never pinned one, only as the
// request confirms it. It reports stop when the request ended.
func (r *SigningRecoveryReconciler) confirmKey(ctx, fenced context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun) (reconcile.Result, bool, error) {
	in := run.Status.SigningIntent
	want := esr.Spec.ExpectedKeyFingerprint
	if want == "" {
		// Decided before any Secret is read.
		return reconcile.Result{}, true, r.end(ctx, esr, v1alpha1.RecoveryKeyConfirmationRequired,
			fmt.Sprintf("the signing intent of AssessmentRun %s never pinned a key; state spec.expectedKeyFingerprint to confirm the key in its recorded Secret", run.Name))
	}
	if err := r.advance(ctx, esr, v1alpha1.RecoverySigning, fmt.Sprintf("confirming the key %s for the signing intent of AssessmentRun %s", want, run.Name)); err != nil {
		return reconcile.Result{}, true, err
	}
	// Only the intent's recorded Secret, never the destination's current one.
	signer, secret, err := r.signing().loadSigningKey(fenced, in)
	if err != nil {
		res, err := r.attemptFailed(ctx, esr, run, v1alpha1.RecoverySigning, err)
		return res, true, err
	}
	if got := signer.PublicKey().Fingerprint; got != want {
		return reconcile.Result{}, true, r.end(ctx, esr, v1alpha1.RecoveryKeyMismatch,
			fmt.Sprintf("the recorded key Secret of AssessmentRun %s holds key %s, not the confirmed %s; nothing was pinned or signed", run.Name, got, want))
	}
	// The existing write-once pin: a resourceVersion-conditional update that
	// a concurrent pin or claim change makes fail with a conflict.
	in.Key = pinnedKey(signer.PublicKey(), secret, r.now())
	if err := r.Client.Status().Update(ctx, run); err != nil {
		in.Key = nil
		return reconcile.Result{}, true, err
	}
	return reconcile.Result{}, false, nil
}

// attemptFailed ends the request on a failure that retrying cannot change,
// and otherwise records the transient cause under reason and polls. Key and
// Secret bytes never reach the message; the Secret's name is not repeated.
func (r *SigningRecoveryReconciler) attemptFailed(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun, reason v1alpha1.SigningRecoveryReason, cause error) (reconcile.Result, error) {
	msg := recoveryCause(run, cause)
	var mismatch signingKeyMismatch
	var invalid storedSignatureInvalid
	switch {
	case errors.As(cause, &mismatch):
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryKeyMismatch, fmt.Sprintf("AssessmentRun %s: %s; nothing was signed or committed", run.Name, msg))
	case errors.As(cause, &invalid):
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryConflict, fmt.Sprintf("AssessmentRun %s: %s; the stored signature is never replaced", run.Name, msg))
	case errors.Is(cause, publication.ErrOrphaned):
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryOrphaned, fmt.Sprintf("the destination of AssessmentRun %s was handed off during recovery", run.Name))
	case errors.Is(cause, publication.ErrExpired):
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryExpired, fmt.Sprintf("AssessmentRun %s reached its recorded expiry before the commit; nothing was committed", run.Name))
	case errors.Is(cause, publication.ErrConflict), errors.Is(cause, publication.ErrUnsupportedRecord):
		// Includes a bounded commit that storage would hold as invalid (its
		// clock behind the controller's): fail closed, never overwrite.
		return reconcile.Result{}, r.end(ctx, esr, v1alpha1.RecoveryConflict, fmt.Sprintf("the commit of AssessmentRun %s cannot be made and is never overwritten: %s", run.Name, msg))
	case ctx.Err() != nil:
		return reconcile.Result{}, ctx.Err()
	}
	if err := r.running(ctx, esr, reason, fmt.Sprintf("retrying the signing recovery of AssessmentRun %s: %s", run.Name, msg)); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: r.poll()}, nil
}

// recoveryCause is a bounded cause for a request message that does not
// repeat the intent's Secret name.
func recoveryCause(run *v1alpha1.AssessmentRun, cause error) string {
	msg := cause.Error()
	if in := run.Status.SigningIntent; in != nil && in.SecretName != "" {
		msg = strings.ReplaceAll(msg, "signing Secret "+in.SecretName, "the recorded key Secret")
	}
	return truncateStatus(msg)
}

// recordedRetention is the retention of a recovered commit: the duration
// recorded on the run at closure, the one its retained failure's expiry was
// computed from (retainAfterSigningFailure), never a retention selected from
// the binding now; bounded by that recorded expiry so a late commit never
// extends retention (decision 7).
func recordedRetention(run *v1alpha1.AssessmentRun, now time.Time) publication.Retention {
	d := string(run.Status.Retention)
	if v, err := time.ParseDuration(d); err != nil || v <= 0 {
		d = DefaultRetention.String()
	}
	notAfter := run.Status.Publication.ExpiresAt.UTC()
	return publication.Retention{Duration: d, BindingConfiguration: run.Status.BindingConfiguration + " (signing recovery; retention and expiry recorded at the signing failure)",
		SelectedAt: now.UTC().Truncate(time.Second), NotAfter: &notAfter}
}

// committed is reached with the run's signed commit in storage, made by this
// attempt or adopted unchanged. Recording it on the run, which ends the
// request and releases the claim, is task 2.6. Until then the holder keeps
// its claim and reports the commit; every later attempt adopts it without a
// storage write.
func (r *SigningRecoveryReconciler) committed(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun, st publication.Status) (reconcile.Result, error) {
	msg := fmt.Sprintf("AssessmentRun %s is committed as %s with the signature under %s", run.Name, st.PublicationID, signatureKey(st))
	if st.PublishedAt != nil && st.ExpiresAt != nil {
		msg += fmt.Sprintf(" (published %s, expires %s)", st.PublishedAt.UTC().Format(time.RFC3339), st.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if err := r.running(ctx, esr, v1alpha1.RecoveryCommitting, msg); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: r.poll()}, nil
}

func signatureKey(st publication.Status) string {
	if st.Signature == nil {
		return "no key"
	}
	return st.Signature.KeyFingerprint
}
