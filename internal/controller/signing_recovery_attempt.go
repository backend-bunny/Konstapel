package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// adopted.
//
// The attempt is bounded (task 2.5, design section 6): the holder retries at
// the existing poll interval until its claim's deadline (claimedAt plus
// PublishTimeout). At the deadline it ends SigningFailed, decided before any
// storage access, unless its run already records the successful recovery;
// the run keeps its retained failure and a new request can try again.
//
// Success (task 2.6, design section 8) is one resourceVersion-conditional
// run status update: the committed publication, the run Completed with
// Published True, and signingRecovery.recovered, which also clears the
// claim. That run record is the durable source: finishRecovered then
// projects it onto the namespace AssessmentRequest and only after that ends
// the request Succeeded. Every reconcile after the run update, by the holder
// or any other request and even past the deadline, repairs whatever of those
// two writes is missing and never signs, commits, or rewrites the run.

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
	if requester(esr) == nil {
		// Admission always records the requester; a recovery is never
		// recorded unattributed, so nothing is signed or committed for it.
		return reconcile.Result{}, fmt.Errorf("EvidenceSigningRequest %s records no admission-recorded requester; nothing is signed or committed for it", esr.Name)
	}
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
	return reconcile.Result{RequeueAfter: r.retryAfter(claimOf(run))}, nil
}

// retryAfter is the holder's next poll: the existing interval, or sooner
// when its claim's deadline comes first, so the attempt ends on time.
func (r *SigningRecoveryReconciler) retryAfter(c *v1alpha1.SigningRecoveryClaim) time.Duration {
	p := r.poll()
	if c == nil {
		return p
	}
	return min(p, max(c.Deadline.Sub(r.now()), time.Second))
}

// pastDeadline reports whether the bounded attempt of claim c is over.
func (r *SigningRecoveryReconciler) pastDeadline(c *v1alpha1.SigningRecoveryClaim) bool {
	return !r.now().Before(c.Deadline.Time)
}

// deadlineExceeded ends a holder whose attempt passed its claim's deadline
// with SigningFailed and releases the claim (task 2.5). It is decided from
// the run and the claim alone, before any storage access, so an unavailable
// store or key never extends the attempt. The run keeps its retained
// failure record, expiry, and destination accounting byte for byte; a commit
// already in storage without the run's record is adopted unchanged by a new
// request. The last progress the attempt recorded is kept in the message.
func (r *SigningRecoveryReconciler) deadlineExceeded(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun, c *v1alpha1.SigningRecoveryClaim) error {
	msg := fmt.Sprintf("the signing recovery of AssessmentRun %s did not succeed by its attempt deadline %s (claimed %s, plus PublishTimeout); the run keeps its retained signing failure and expiry, and a new request can try again",
		run.Name, c.Deadline.UTC().Format(time.RFC3339), c.ClaimedAt.UTC().Format(time.RFC3339))
	if st := esr.Status; st.Phase == v1alpha1.SigningRequestRunning && st.Message != "" {
		msg += "; last: " + st.Message
	}
	return r.end(ctx, esr, v1alpha1.RecoverySigningFailed, msg)
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

// committed records the run's signed commit in storage, made by this attempt
// or adopted unchanged, as the recovered publication (task 2.6). It is one
// resourceVersion-conditional run status update: the committed
// status.publication with its signature reference (its own publishedAt and
// expiry), the run Completed with Published True naming the request, and
// signingRecovery.recovered, which clears the claim. The evidence summary,
// completeness, outcomes, export kind, window, retention, and signing intent
// are not touched. A conflicting or failed update leaves the run as it was
// and is retried from a fresh read, adopting the same commit. The namespace
// projection and the request's success follow from the recorded run
// (finishRecovered).
func (r *SigningRecoveryReconciler) committed(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, run *v1alpha1.AssessmentRun, st publication.Status) (reconcile.Result, error) {
	in, who := run.Status.SigningIntent, requester(esr)
	switch {
	case who == nil:
		return reconcile.Result{}, fmt.Errorf("EvidenceSigningRequest %s records no admission-recorded requester; the recovery is never recorded unattributed", esr.Name)
	case st.Phase != publication.PhaseCommitted || st.Commit == nil || st.PublishedAt == nil || st.ExpiresAt == nil || st.Signature == nil ||
		in.Key == nil || st.Signature.KeyFingerprint != in.Key.Fingerprint || st.PackageSHA256 != in.ArchiveSHA256:
		// The commit gate and the storage eligibility only reach here with
		// the intent's signed commit; anything else is never recorded.
		return reconcile.Result{}, fmt.Errorf("AssessmentRun %s: commit %s is not the signing intent's signed commit of its archive; it is not recorded", run.Name, st.PublicationID)
	}
	now := metav1.NewTime(r.now().UTC().Truncate(time.Second))
	before := run.Status.DeepCopy()
	pub := publication.ToAPI(st)
	run.Status.Publication = &pub
	run.Status.Phase = v1alpha1.RunCompleted
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionTrue, Reason: "Committed",
		Message: truncateMsg(fmt.Sprintf("published as %s by signing recovery: EvidenceSigningRequest %s", st.PublicationID, esr.Name)), LastTransitionTime: now})
	run.Status.SigningRecovery = &v1alpha1.SigningRecoveryStatus{Recovered: &v1alpha1.SigningRecoveryRecord{
		Name: esr.Name, UID: string(esr.UID), RequestedBy: *who, At: now}}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		run.Status = *before
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, r.finishRecovered(ctx, esr, run)
}

// requester is the admission-recorded identity that created esr (the
// recorded status copy must equal it).
func requester(esr *v1alpha1.EvidenceSigningRequest) *v1alpha1.Requester {
	return esr.Spec.RequestedBy
}
