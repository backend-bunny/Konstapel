package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Signing recovery (add-evidence-signing-recovery group 2, design sections
// 4 and 6). An EvidenceSigningRequest asks the controller to finish the
// signed publication of one retained SigningFailed run with its staged
// archive and original intent.
//
// This file holds eligibility and the terminal outcomes that end a request
// before any storage write (task 2.2). Eligibility is decided from an
// uncached read of the run and its destination, then from read-only
// storage checks under the destination fence. A terminal request is never
// re-evaluated. An eligible request then takes the run's recovery claim or
// waits for it (task 2.3, signing_recovery_claim.go). The holder then runs
// the recovery attempt under the same destination fence until its claim's
// deadline and records the recovered publication (tasks 2.4 to 2.6,
// signing_recovery_attempt.go).

// recoveryEligibility is the outcome of evaluating a request against its
// run. A terminal reason ends the request; otherwise the run is eligible
// (or already recovered) and the claim decides what happens next.
type recoveryEligibility struct {
	// reason is a Failed reason, or "" when the request may proceed.
	reason  v1alpha1.SigningRecoveryReason
	message string
	// recovered is set when the run already records a successful recovery
	// (AlreadyRecovered, task 2.3).
	recovered bool
	// run is the run as read without the cache, when it exists.
	run *v1alpha1.AssessmentRun
	// committed is the matching existing signed commit a recovery adopts
	// unchanged (a commit whose response was lost before SigningFailed).
	committed *publication.Status
	// staged is the durable staging of the intent's archive.
	staged publication.Staged
}

func terminal(reason v1alpha1.SigningRecoveryReason, format string, a ...any) recoveryEligibility {
	return recoveryEligibility{reason: reason, message: fmt.Sprintf(format, a...)}
}

// SigningRecoveryReconciler processes EvidenceSigningRequests.
type SigningRecoveryReconciler struct {
	// Client reads requests and writes their status.
	Client client.Client
	// Reader is uncached: runs, destinations, and orphan inventories are
	// read fresh for every decision.
	Reader  client.Reader
	Runtime AssessmentRuntime
	Now     func() time.Time
}

func (r *SigningRecoveryReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *SigningRecoveryReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// Reconcile evaluates one request. A terminal request is never evaluated
// again; it only releases a recovery claim it still holds. A returned error
// is transient (API or storage unavailable, or a conflicting write): the
// request is retried and nothing is decided.
func (r *SigningRecoveryReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	esr := &v1alpha1.EvidenceSigningRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, esr); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if esr.Status.Phase.Terminal() {
		return reconcile.Result{}, r.release(ctx, esr)
	}
	el, err := r.runEligibility(ctx, esr)
	switch {
	case err != nil:
		return reconcile.Result{}, err
	case el.recovered:
		return reconcile.Result{}, r.finishRecovered(ctx, esr, el.run)
	case el.reason != "":
		return reconcile.Result{}, r.end(ctx, esr, el.reason, el.message)
	}
	run := el.run
	held := claimOf(run)
	if held != nil && !holdsClaim(held, esr) {
		stale, err := r.staleClaim(ctx, held)
		if err != nil {
			return reconcile.Result{}, err
		}
		if !stale {
			return r.wait(ctx, esr, held)
		}
		// Cleared against the read that found it stale; the run's new
		// resourceVersion carries the claim below.
		if err := r.clearClaim(ctx, run, held); err != nil {
			return reconcile.Result{}, err
		}
		held = nil
	}
	if held != nil && r.pastDeadline(held) {
		// The holder's bounded attempt is over (task 2.5); a run that
		// records its recovery ended above, from the recovered run.
		return reconcile.Result{}, r.deadlineExceeded(ctx, esr, run, held)
	}
	// Storage eligibility, the claim, and the attempt are one unit of fenced
	// work of the pinned destination, as "run <name> signature recovery".
	fenced, store, done, el, err := r.openStorage(ctx, run)
	if err != nil {
		return reconcile.Result{}, err
	} else if el.reason != "" {
		return reconcile.Result{}, r.end(ctx, esr, el.reason, el.message)
	}
	defer done()
	if el, err = r.checkStorage(fenced, store, run); err != nil {
		return reconcile.Result{}, err
	} else if el.reason != "" {
		return reconcile.Result{}, r.end(ctx, esr, el.reason, el.message)
	}
	if held == nil {
		if err := r.claim(ctx, run, esr); err != nil {
			return reconcile.Result{}, err
		}
		held = claimOf(run)
		// The claim is recorded before anything is signed or committed;
		// the claim's run update and this status update both enqueue the
		// holder, which then runs the attempt.
		return reconcile.Result{}, r.pending(ctx, esr, v1alpha1.RecoveryAccepted,
			fmt.Sprintf("accepted; holds the signing recovery of AssessmentRun %s until %s", run.Name, held.Deadline.UTC().Format(time.RFC3339)))
	}
	return r.attempt(ctx, fenced, store, esr, run, el)
}

// eligibility decides whether a request may proceed. It issues no write to
// the run, the destination, or storage. A returned error is transient.
func (r *SigningRecoveryReconciler) eligibility(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest) (recoveryEligibility, error) {
	el, err := r.runEligibility(ctx, esr)
	if err != nil || el.reason != "" || el.recovered {
		return el, err
	}
	return r.storageEligibility(ctx, el.run)
}

// runEligibility checks the run, its retained failure, and its destination
// from uncached reads.
func (r *SigningRecoveryReconciler) runEligibility(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest) (recoveryEligibility, error) {
	ref := esr.Spec.Run
	run := &v1alpha1.AssessmentRun{}
	if err := r.reader().Get(ctx, client.ObjectKey{Name: ref.Name}, run); apierrors.IsNotFound(err) {
		return terminal(v1alpha1.RecoveryRunNotFound, "AssessmentRun %s does not exist", ref.Name), nil
	} else if err != nil {
		return recoveryEligibility{}, fmt.Errorf("read AssessmentRun %s: %w", ref.Name, err)
	}
	if string(run.UID) != ref.UID {
		return terminal(v1alpha1.RecoveryRunNotFound, "AssessmentRun %s has UID %s, not the requested %s; a recreated run never matches", ref.Name, run.UID, ref.UID), nil
	}
	if !run.DeletionTimestamp.IsZero() {
		return terminal(v1alpha1.RecoveryRunDeleting, "AssessmentRun %s is being deleted", ref.Name), nil
	}
	if sr := run.Status.SigningRecovery; sr != nil && sr.Recovered != nil {
		return recoveryEligibility{recovered: true, run: run}, nil
	}
	pub, in, pin := run.Status.Publication, run.Status.SigningIntent, run.Status.Destination
	switch {
	case !retainedSigningFailure(run):
		return terminal(v1alpha1.RecoveryNotRecoverable, "AssessmentRun %s is not a retained SigningFailed run (phase %s, publication %s)", ref.Name, run.Status.Phase, publicationPhase(pub)), nil
	case in == nil || in.Mode != v1alpha1.SigningRequired:
		return terminal(v1alpha1.RecoveryNotRecoverable, "AssessmentRun %s has no Required signing intent", ref.Name), nil
	case pin == nil || pin.UID != in.DestinationUID:
		return terminal(v1alpha1.RecoveryNotRecoverable, "AssessmentRun %s is not pinned to its signing intent's destination", ref.Name), nil
	case pub.PackageSHA256 != in.ArchiveSHA256:
		return terminal(v1alpha1.RecoveryNotRecoverable, "AssessmentRun %s retains archive %s, but its signing intent covers %s", ref.Name, pub.PackageSHA256, in.ArchiveSHA256), nil
	case pin.OrphanedAt != nil || pub.Phase == v1alpha1.PublicationPhase(publication.PhaseOrphaned) || pub.Cleanup.State == v1alpha1.CleanupState(publication.CleanupOrphaned):
		return terminal(v1alpha1.RecoveryOrphaned, "the storage of AssessmentRun %s was handed to an operator by an orphan handoff", ref.Name), nil
	case pub.ExpiresAt == nil:
		return terminal(v1alpha1.RecoveryNotRecoverable, "AssessmentRun %s records no retention expiry for its retained evidence", ref.Name), nil
	case pub.Cleanup.State != v1alpha1.CleanupState(publication.CleanupNotDue):
		return terminal(v1alpha1.RecoveryExpired, "the retained evidence of AssessmentRun %s is past retention (cleanup %s)", ref.Name, pub.Cleanup.State), nil
	case !r.now().Before(pub.ExpiresAt.Time):
		return terminal(v1alpha1.RecoveryExpired, "the retained evidence of AssessmentRun %s expired at %s", ref.Name, pub.ExpiresAt.UTC().Format(time.RFC3339)), nil
	}
	h, held, err := orphanHandoff(ctx, r.reader(), r.namespace(), pin)
	switch {
	case err != nil:
		return recoveryEligibility{}, fmt.Errorf("read the orphan state of destination %s: %w", pin.Name, err)
	case h != nil || held:
		return terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s has an accepted orphan handoff", pin.Name, ref.Name), nil
	}
	ed, err := destinationByUID(ctx, r.reader(), pin.UID)
	switch {
	case errors.Is(err, errDestinationLost):
		return terminal(v1alpha1.RecoveryNotRecoverable, "the pinned destination %s of AssessmentRun %s no longer exists", pin.Name, ref.Name), nil
	case err != nil:
		return recoveryEligibility{}, fmt.Errorf("read destination %s: %w", pin.Name, err)
	case ed.Status.OrphanIntent != nil:
		return terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s has an accepted orphan handoff", pin.Name, ref.Name), nil
	}
	return recoveryEligibility{run: run}, nil
}

// storageEligibility reads, never writes, the run's storage under the
// destination fence: the staged archive must be the intent's, and an
// existing commit must be the intent's signed commit of it.
func (r *SigningRecoveryReconciler) storageEligibility(ctx context.Context, run *v1alpha1.AssessmentRun) (recoveryEligibility, error) {
	fenced, store, done, el, err := r.openStorage(ctx, run)
	if err != nil || el.reason != "" {
		return el, err
	}
	defer done()
	return r.checkStorage(fenced, store, run)
}

// openStorage begins fenced work of the run's pinned destination as
// "run <name> signature recovery" and returns its context and publisher;
// done must be called when the work ends. After an orphan handoff no work
// begins (Orphaned), and work in flight is cancelled.
func (r *SigningRecoveryReconciler) openStorage(ctx context.Context, run *v1alpha1.AssessmentRun) (context.Context, publication.Publisher, func(), recoveryEligibility, error) {
	pin := run.Status.Destination
	dp := r.Runtime.Destinations
	if dp == nil {
		return nil, nil, nil, recoveryEligibility{}, fmt.Errorf("%w: pinned destinations are not configured", publication.ErrUnavailable)
	}
	fenced, done, err := dp.Begin(ctx, pin.UID, "run "+run.Name+" signature recovery")
	if errors.Is(err, publication.ErrOrphaned) {
		return nil, nil, nil, terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s is fenced by an orphan handoff", pin.Name, run.Name), nil
	} else if err != nil {
		return nil, nil, nil, recoveryEligibility{}, err
	}
	store, err := dp.For(fenced, pin)
	if errors.Is(err, publication.ErrOrphaned) {
		done()
		return nil, nil, nil, terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s is handed off", pin.Name, run.Name), nil
	} else if err != nil {
		done()
		return nil, nil, nil, recoveryEligibility{}, err
	}
	return fenced, store, done, recoveryEligibility{}, nil
}

// checkStorage is storageEligibility within fenced work.
func (r *SigningRecoveryReconciler) checkStorage(fenced context.Context, store publication.Publisher, run *v1alpha1.AssessmentRun) (recoveryEligibility, error) {
	pin, in := run.Status.Destination, run.Status.SigningIntent
	ref := publication.RunRef{ClusterID: scopeCluster(run), BindingUID: bindingUID(run), RunUID: string(run.UID)}

	st, err := store.Inspect(fenced, ref)
	switch {
	case errors.Is(err, publication.ErrOrphaned):
		return terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s is handed off", pin.Name, run.Name), nil
	case errors.Is(err, publication.ErrNotFound):
		return terminal(v1alpha1.RecoveryEvidenceLost, "the staged archive of AssessmentRun %s is missing from storage", run.Name), nil
	case errors.Is(err, publication.ErrConflict), errors.Is(err, publication.ErrUnsupportedRecord):
		return terminal(v1alpha1.RecoveryConflict, "the commit of AssessmentRun %s cannot be used and is never overwritten: %s", run.Name, truncateStatus(err.Error())), nil
	case err != nil:
		return recoveryEligibility{}, err
	}
	var committed *publication.Status
	if st.Commit != nil {
		if c := commitConflict(st, in); c != "" {
			return terminal(v1alpha1.RecoveryConflict, "AssessmentRun %s already has a commit that %s; it is never overwritten", run.Name, c), nil
		}
		if st.Phase == publication.PhaseExpired {
			return terminal(v1alpha1.RecoveryExpired, "the existing commit of AssessmentRun %s expired at %s", run.Name, st.ExpiresAt.UTC().Format(time.RFC3339)), nil
		}
		if st.Failure != nil {
			return terminal(v1alpha1.RecoveryEvidenceLost, "the committed package of AssessmentRun %s is not intact: %s", run.Name, st.Failure.Reason), nil
		}
		committed = &st
	}

	staged, err := store.Recover(fenced, ref)
	switch {
	case errors.Is(err, publication.ErrCaptureLost), errors.Is(err, publication.ErrNotFound):
		return terminal(v1alpha1.RecoveryEvidenceLost, "the staged archive of AssessmentRun %s is missing or no longer verifies", run.Name), nil
	case errors.Is(err, publication.ErrOrphaned):
		return terminal(v1alpha1.RecoveryOrphaned, "destination %s of AssessmentRun %s is handed off", pin.Name, run.Name), nil
	case err != nil:
		return recoveryEligibility{}, err
	}
	if staged.PackageSHA256 != in.ArchiveSHA256 || (run.Status.DescriptorSHA256 != "" && staged.DescriptorSHA256 != run.Status.DescriptorSHA256) {
		return terminal(v1alpha1.RecoveryEvidenceLost, "the staged archive of AssessmentRun %s is %s, not the intent's %s", run.Name, staged.PackageSHA256, in.ArchiveSHA256), nil
	}
	return recoveryEligibility{run: run, committed: committed, staged: staged}, nil
}

// commitConflict explains why an existing commit is not the intent's
// signed commit of its archive, or returns "".
func commitConflict(st publication.Status, in *v1alpha1.SigningIntent) string {
	switch {
	case st.PackageSHA256 != in.ArchiveSHA256:
		return "covers another archive"
	case st.Signature == nil:
		return "is unsigned under a Required signing intent"
	case in.Key == nil:
		return "is signed although the signing intent never pinned a key"
	case st.Signature.KeyFingerprint != in.Key.Fingerprint:
		return fmt.Sprintf("is signed by %s, not the pinned %s", st.Signature.KeyFingerprint, in.Key.Fingerprint)
	}
	return ""
}

func publicationPhase(pub *v1alpha1.PublicationStatus) string {
	if pub == nil {
		return "none"
	}
	return string(pub.Phase)
}

func (r *SigningRecoveryReconciler) namespace() string {
	if d := r.Runtime.Destinations; d != nil && d.Namespace != "" {
		return controllerNamespace(d.Namespace)
	}
	return controllerNamespace(r.Runtime.ControllerNamespace)
}

// record fills the attribution a request's status keeps once set.
func (r *SigningRecoveryReconciler) record(esr *v1alpha1.EvidenceSigningRequest, now metav1.Time) {
	st := &esr.Status
	if st.RequestedBy == nil && esr.Spec.RequestedBy != nil {
		st.RequestedBy = esr.Spec.RequestedBy.DeepCopy()
	}
	if st.Run == nil {
		run := esr.Spec.Run
		st.Run = &run
	}
	if st.AcceptedAt == nil {
		st.AcceptedAt = &now
	}
}

// fail ends a request with a terminal Failed reason. The resourceVersion
// precondition makes a concurrent writer retry from a fresh read.
func (r *SigningRecoveryReconciler) fail(ctx context.Context, esr *v1alpha1.EvidenceSigningRequest, reason v1alpha1.SigningRecoveryReason, msg string) error {
	now := metav1.NewTime(r.now())
	r.record(esr, now)
	msg = truncateRecoveryMessage(msg)
	esr.Status.Phase, esr.Status.Reason, esr.Status.Message, esr.Status.CompletedAt = v1alpha1.SigningRequestFailed, reason, msg, &now
	meta.SetStatusCondition(&esr.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionTrue,
		Reason: string(reason), Message: msg, ObservedGeneration: esr.Generation, LastTransitionTime: now})
	return r.Client.Status().Update(ctx, esr)
}

// maxRecoveryMessage is the request status message bound (CRD MaxLength).
const maxRecoveryMessage = 1024

func truncateRecoveryMessage(s string) string {
	if len(s) > maxRecoveryMessage {
		return s[:maxRecoveryMessage-3] + "..."
	}
	return s
}
