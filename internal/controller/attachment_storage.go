package controller

// EvidenceAttachment storage ownership (add-supporting-evidence-attachments
// 2.1-2.4): the destination pin, the recorded commitment, owned attempt
// cleanup, and the retention finalizer's release.
//
// Pin protocol, as for assessment runs: record intent (the
// LabelAttachmentDestination label) before confirming, re-read the selected
// destination uncached, require its UID and no deletion, add the destination
// finalizer with an update conditioned on its resourceVersion, then record
// status.storage.destination. A pin never changes; a later default
// destination never relocates a document. The transfer service stages and
// commits only against the pinned destination.
//
// The commitment is read from storage, not reported by a writer, so a lost
// upload response or a status write lost across a restart or leader change
// is recovered by reading the one commit manifest again. It is recorded only
// when it matches this record's spec digest and registered document; the
// API keeps it immutable once recorded.
//
// Content (add-supporting-evidence-attachments 4.1) is checked separately
// from the commitment record: a committed version that is missing, damaged,
// unreachable or handed off is Unavailable, and so is every source at or
// after its fixed expiry, while the commitment itself never changes. The
// check reads object metadata only, at most once per ContentInterval while
// the content was last Available, and every reconcile otherwise.
//
// Deleting a record withdraws it immediately. The finalizer stays until:
//   - nothing was pinned (no bytes can exist), or
//   - nothing was committed and every owned attempt is removed, or
//   - the commitment expired and every owned version is removed.
//
// Before the expiry nothing is deleted and storage is contacted only to
// check the retained content. Failures keep the finalizer, the pin and the
// commitment, and are retried after a backoff of one minute doubling to an
// hour (status.storage.cleanup.attempts); they are never treated as
// deletion, and a pass that waits for its backoff writes nothing.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// Requeue intervals for attachment storage.
const (
	// attachmentStorageRequeue re-reads storage while a commitment is
	// awaited or a destination is unavailable.
	attachmentStorageRequeue = time.Minute
	// attachmentCleanupRetry re-checks a pinned, withdrawn record while
	// this controller has no attachment storage configured. Failed cleanups
	// back off with cleanupBackoff instead.
	attachmentCleanupRetry = 5 * time.Minute
)

// AttachmentStores builds the store for a pinned destination.
type AttachmentStores interface {
	Store(ctx context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error)
}

// AttachmentStorage configures storage ownership. A nil configuration (no
// controller namespace) pins nothing, so no record can own stored bytes.
type AttachmentStorage struct {
	// Reader is uncached: destinations and the default ConfigMap.
	Reader    client.Reader
	Namespace string
	// Cluster is the cluster identity ("kube-system:<uid>").
	Cluster string
	Stores  AttachmentStores
	// Fences registers storage work so an orphan handoff can fence it; nil
	// registers nothing.
	Fences *DestinationPublishers
	// AttemptRetention is how long uncommitted attempts are kept (default
	// attachments.DefaultAttemptRetention).
	AttemptRetention time.Duration
	// ContentInterval is how often available committed content is
	// re-checked (default MaxRetentionRequeue). Unavailable content is
	// re-checked on every reconcile, at least every minute.
	ContentInterval time.Duration
	Now             func() time.Time

	// checked is when this process last checked each record's content; a
	// restart or a new leader checks again at once.
	checkedMu sync.Mutex
	checked   map[types.UID]time.Time
}

func (s *AttachmentStorage) contentInterval() time.Duration {
	if s.ContentInterval > 0 {
		return s.ContentInterval
	}
	return MaxRetentionRequeue
}

// contentDue reports whether a committed record's content must be checked
// now, and otherwise how long until it must.
func (s *AttachmentStorage) contentDue(uid types.UID, now time.Time, prev *v1alpha1.AttachmentContentStatus) (bool, time.Duration) {
	if prev == nil || prev.State != v1alpha1.ContentAvailable {
		return true, 0
	}
	s.checkedMu.Lock()
	last, ok := s.checked[uid]
	s.checkedMu.Unlock()
	if !ok {
		return true, 0
	}
	if next := last.Add(s.contentInterval()); now.Before(next) {
		return false, next.Sub(now)
	}
	return true, 0
}

func (s *AttachmentStorage) markChecked(uid types.UID, now time.Time) {
	s.checkedMu.Lock()
	defer s.checkedMu.Unlock()
	if s.checked == nil {
		s.checked = map[types.UID]time.Time{}
	}
	s.checked[uid] = now
}

// forget drops a released record's schedule.
func (s *AttachmentStorage) forget(uid types.UID) {
	s.checkedMu.Lock()
	defer s.checkedMu.Unlock()
	delete(s.checked, uid)
}

// setContent records the content state. Its transition time changes only
// when the state or reason does; messages are fixed per reason, so an
// unchanged state writes nothing.
func setContent(status *v1alpha1.EvidenceAttachmentStatus, state v1alpha1.ContentState, reason, msg string, now time.Time) {
	t := metav1.NewTime(now)
	if c := status.Content; c != nil && c.State == state && c.Reason == reason && c.LastTransitionTime != nil {
		t = *c.LastTransitionTime
	}
	status.Content = &v1alpha1.AttachmentContentStatus{State: state, Reason: reason, Message: truncateMsg(msg), LastTransitionTime: &t}
}

// storageReason classifies a failure to open the pinned destination.
func storageReason(err error) (string, string) {
	if errors.Is(err, publication.ErrOrphaned) {
		return v1alpha1.ReasonDestinationHandedOff, "the pinned destination was handed off to an operator and is no longer contacted"
	}
	return v1alpha1.ReasonStorageUnavailable, "the pinned destination cannot be reached; see DocumentCommitted"
}

// sourceExpired marks content whose fixed source expiry has passed.
func sourceExpired(status *v1alpha1.EvidenceAttachmentStatus, c *v1alpha1.AttachmentCommitment, now time.Time) {
	setContent(status, v1alpha1.ContentUnavailable, v1alpha1.ReasonSourceExpired,
		"the source retention ended at "+c.ExpiresAt.UTC().Format(time.RFC3339)+"; the document is no longer served", now)
}

// checkContent checks a recorded, unexpired commitment's bytes (metadata
// only) and returns when to check again.
func (s *AttachmentStorage) checkContent(ctx context.Context, st attachments.Store, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus, now time.Time) time.Duration {
	c := status.Storage.Commitment
	p, err := st.Health(ctx, s.receipt(a, c, st))
	switch {
	case err != nil:
		setContent(status, v1alpha1.ContentUnavailable, v1alpha1.ReasonStorageUnavailable, "the committed document could not be checked: storage did not answer", now)
	case p != nil:
		setContent(status, v1alpha1.ContentUnavailable, p.Reason, p.Message, now)
	default:
		setContent(status, v1alpha1.ContentAvailable, v1alpha1.ReasonContentVerified,
			"the committed version is present with its registered size; this attests storage and integrity only", now)
	}
	s.markChecked(a.UID, now)
	untilExpiry := c.ExpiresAt.Sub(now)
	if status.Content.State != v1alpha1.ContentAvailable {
		return min(untilExpiry, attachmentStorageRequeue)
	}
	return min(untilExpiry, s.contentInterval())
}

func (s *AttachmentStorage) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *AttachmentStorage) attemptRetention() time.Duration {
	if s.AttemptRetention > 0 {
		return s.AttemptRetention
	}
	return attachments.DefaultAttemptRetention
}

func (s *AttachmentStorage) ref(a *v1alpha1.EvidenceAttachment) attachments.Ref {
	return attachments.Ref{ClusterID: s.Cluster, UID: string(a.UID)}
}

// begin opens a store for the pinned destination, registered against the
// destination's fence.
func (s *AttachmentStorage) begin(ctx context.Context, a *v1alpha1.EvidenceAttachment) (context.Context, attachments.Store, func(), error) {
	pin := a.Status.Storage.Destination
	done := func() {}
	if s.Fences != nil {
		var err error
		ctx, done, err = s.Fences.Begin(ctx, pin.UID, "attachment "+a.Name)
		if err != nil {
			return ctx, nil, done, fmt.Errorf("%w: destination %s is fenced: %w", attachments.ErrUnavailable, pin.Name, err)
		}
	}
	st, err := s.Stores.Store(ctx, *pin)
	if err != nil {
		done()
		return ctx, nil, func() {}, err
	}
	return ctx, st, done, nil
}

func setCommitted(status *v1alpha1.EvidenceAttachmentStatus, gen int64, s metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: v1alpha1.ConditionDocumentCommitted, Status: s, Reason: reason,
		Message: truncateMsg(msg), ObservedGeneration: gen})
}

// pin selects and confirms the destination, recording it in status. It
// returns false when no destination can be pinned yet.
func (s *AttachmentStorage) pin(ctx context.Context, c client.Client, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus) (bool, error) {
	var ref v1alpha1.DestinationReference
	if uid := a.Labels[v1alpha1.LabelAttachmentDestination]; uid != "" {
		ed, err := destinationByUID(ctx, s.Reader, uid)
		if err != nil {
			setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonNoDestination, err.Error())
			return false, nil
		}
		ref = v1alpha1.DestinationReference{Name: ed.Name, UID: uid}
	} else {
		sel := selectDestination(ctx, s.Reader, s.Namespace, &v1alpha1.ComplianceBinding{})
		if sel.Source == v1alpha1.DestinationNone || !sel.Ready || sel.Ref == nil {
			setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonNoDestination, "no destination can be pinned: "+sel.Message)
			return false, nil
		}
		ref = *sel.Ref
		base := a.DeepCopy()
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		a.Labels[v1alpha1.LabelAttachmentDestination] = ref.UID
		if err := c.Patch(ctx, a, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return false, err
		}
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: ref.Name}, ed); err != nil {
		if apierrors.IsNotFound(err) {
			setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonNoDestination, "EvidenceDestination "+ref.Name+" no longer exists")
			return false, nil
		}
		return false, err
	}
	switch {
	case string(ed.UID) != ref.UID:
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonNoDestination, "EvidenceDestination "+ref.Name+" was replaced")
		return false, nil
	case !ed.DeletionTimestamp.IsZero():
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonNoDestination, "EvidenceDestination "+ref.Name+" is retiring")
		return false, nil
	}
	controllerutil.AddFinalizer(ed, DestinationFinalizer)
	// Always update: the resourceVersion precondition is the confirmation.
	if err := c.Update(ctx, ed); err != nil {
		return false, err
	}
	now := metav1.NewTime(s.now())
	if status.Storage == nil {
		status.Storage = &v1alpha1.AttachmentStorage{}
	}
	status.Storage.Destination, status.Storage.PinnedAt = &ref, &now
	return true, nil
}

// commitment reads and checks the stored commitment. It returns nil with a
// condition set when there is none (or it cannot be recorded).
func (s *AttachmentStorage) commitment(ctx context.Context, st attachments.Store, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus) (*v1alpha1.AttachmentCommitment, error) {
	r, err := st.Committed(ctx, s.ref(a))
	switch {
	case errors.Is(err, attachments.ErrNotFound):
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonAwaitingUpload, "no committed upload yet")
		return nil, nil
	case errors.Is(err, attachments.ErrConflict), errors.Is(err, attachments.ErrUnsupportedRecord):
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageConflict, err.Error())
		return nil, nil
	case err != nil:
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageUnavailable, err.Error())
		return nil, err
	}
	switch want := attachments.Expected(a.Spec); {
	case r.Document != want:
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageConflict, "storage committed "+r.Document.SHA256+", not the registered document")
		return nil, nil
	case r.SpecDigest != attachments.SpecDigest(a.Spec):
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageConflict, "storage committed another registration (spec digest "+r.SpecDigest+")")
		return nil, nil
	case !r.ValidUntil.Equal(a.Spec.Validity.ValidUntil.UTC()):
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageConflict, "storage committed another validity period")
		return nil, nil
	}
	return &v1alpha1.AttachmentCommitment{ManifestKey: r.ManifestKey, ManifestVersionID: r.ManifestVersionID, DocumentKey: r.DocumentKey,
		DocumentVersionID: r.DocumentVersionID, SHA256: r.Document.SHA256, Size: r.Document.Size, SpecDigest: r.SpecDigest,
		Uploader: v1alpha1.Requester{Username: r.Uploader.Username, UID: r.Uploader.UID}, CommittedAt: metav1.NewTime(r.CommittedAt),
		Retention: metav1.Duration{Duration: r.Retention}, ExpiresAt: metav1.NewTime(r.ExpiresAt)}, nil
}

func recordCommitment(status *v1alpha1.EvidenceAttachmentStatus, gen int64, c *v1alpha1.AttachmentCommitment) {
	status.Storage.Commitment = c
	setCommitted(status, gen, metav1.ConditionTrue, v1alpha1.ReasonCommitted,
		fmt.Sprintf("committed by %s at %s; source retained until %s. This attests storage and integrity only.",
			c.Uploader.Username, c.CommittedAt.UTC().Format(time.RFC3339), c.ExpiresAt.UTC().Format(time.RFC3339)))
}

// receipt converts a recorded commitment back to the storage form.
func (s *AttachmentStorage) receipt(a *v1alpha1.EvidenceAttachment, c *v1alpha1.AttachmentCommitment, st attachments.Store) attachments.Receipt {
	return attachments.Receipt{Ref: s.ref(a), Destination: st.Destination(), ManifestKey: c.ManifestKey, ManifestVersionID: c.ManifestVersionID,
		DocumentKey: c.DocumentKey, DocumentVersionID: c.DocumentVersionID, Document: attachments.Document{SHA256: c.SHA256, Size: c.Size},
		SpecDigest: c.SpecDigest, Uploader: attachments.Principal{Username: c.Uploader.Username, UID: c.Uploader.UID},
		CommittedAt: c.CommittedAt.UTC(), ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: c.Retention.Duration, ExpiresAt: c.ExpiresAt.UTC()}
}

// reconcile pins a destination, records the commitment of a live record,
// and checks its content.
func (s *AttachmentStorage) reconcile(ctx context.Context, c client.Client, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus, now time.Time) (time.Duration, error) {
	if status.Storage == nil || status.Storage.Destination == nil {
		ok, err := s.pin(ctx, c, a, status)
		if err != nil {
			return attachmentStorageRequeue, err
		}
		if !ok {
			setContent(status, v1alpha1.ContentPending, v1alpha1.ReasonNoDestination, "no destination is pinned; nothing can be stored yet", now)
			return attachmentStorageRequeue, nil
		}
		setContent(status, v1alpha1.ContentPending, v1alpha1.ReasonAwaitingUpload, "no committed upload yet", now)
		// Persist the pin before any storage read.
		return time.Second, nil
	}
	if cm := status.Storage.Commitment; cm != nil {
		recordCommitment(status, a.Generation, cm)
		if !now.Before(cm.ExpiresAt.Time) {
			// Downloads stop at the fixed expiry; a live record's bytes stay
			// until it is withdrawn.
			sourceExpired(status, cm, now)
			return 0, nil
		}
		if due, wait := s.contentDue(a.UID, now, status.Content); !due {
			return min(wait, cm.ExpiresAt.Sub(now)), nil
		}
	}
	ctx, st, done, err := s.begin(ctx, a)
	defer done()
	if err != nil {
		reason, msg := storageReason(err)
		if cm := status.Storage.Commitment; cm != nil {
			setContent(status, v1alpha1.ContentUnavailable, reason, msg, now)
			s.markChecked(a.UID, now)
			return min(attachmentStorageRequeue, cm.ExpiresAt.Sub(now)), nil
		}
		setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageUnavailable, err.Error())
		setContent(status, v1alpha1.ContentPending, reason, msg, now)
		return attachmentStorageRequeue, nil
	}
	if status.Storage.DestinationID == "" {
		status.Storage.DestinationID = st.Destination().ID
	}
	if status.Storage.Commitment == nil {
		cm, err := s.commitment(ctx, st, a, status)
		if err != nil {
			setContent(status, v1alpha1.ContentPending, v1alpha1.ReasonStorageUnavailable, "storage could not be read for a commitment", now)
			return attachmentStorageRequeue, nil
		}
		if cm == nil {
			if c := meta.FindStatusCondition(status.Conditions, v1alpha1.ConditionDocumentCommitted); c != nil && c.Reason == v1alpha1.ReasonStorageConflict {
				setContent(status, v1alpha1.ContentUnavailable, v1alpha1.ReasonStorageConflict,
					"storage holds a commitment for this UID that does not match the record; it is never used", now)
			} else {
				setContent(status, v1alpha1.ContentPending, v1alpha1.ReasonAwaitingUpload, "no committed upload yet", now)
			}
			s.cleanupAttempts(ctx, st, a, now)
			return attachmentStorageRequeue, nil
		}
		recordCommitment(status, a.Generation, cm)
		if !now.Before(cm.ExpiresAt.Time) {
			sourceExpired(status, cm, now)
			return 0, nil
		}
	}
	wait := s.checkContent(ctx, st, a, status, now)
	// Abandoned attempts (a concurrent writer that lost, an interrupted
	// upload) are removed once they are old enough, on the content schedule.
	s.cleanupAttempts(ctx, st, a, now)
	return wait, nil
}

func (s *AttachmentStorage) cleanupAttempts(ctx context.Context, st attachments.Store, a *v1alpha1.EvidenceAttachment, now time.Time) {
	if err := st.CleanupAttempts(ctx, s.ref(a), now.Add(-s.attemptRetention())); err != nil {
		log.FromContext(ctx).Info("attachment attempt cleanup incomplete; retried later", "attachment", a.Name, "reason", err.Error())
	}
}

// finalize decides whether a withdrawn record may be released. It returns
// release=true only when no owned storage remains.
func (s *AttachmentStorage) finalize(ctx context.Context, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus, now time.Time) (release bool, requeue time.Duration, err error) {
	if status.Storage == nil || status.Storage.Destination == nil {
		// Never pinned: the transfer service accepts bytes only for a
		// pinned record, so nothing can be stored.
		return true, 0, nil
	}
	// The store is opened at most once per pass, and only when storage
	// must be contacted.
	var st attachments.Store
	closeStore := func() {}
	defer func() { closeStore() }()
	open := func() error {
		if st != nil {
			return nil
		}
		var err error
		ctx, st, closeStore, err = s.begin(ctx, a)
		if err != nil {
			st = nil
		}
		return err
	}
	cm := status.Storage.Commitment
	if cm == nil {
		// Undecided: a commitment that landed while its status write was
		// lost governs retention exactly like a recorded one.
		if wait := cleanupWait(status.Storage.Cleanup, now); wait > 0 {
			return false, wait, nil
		}
		if err := open(); err != nil {
			return s.cleanupFailed(a, status, attachments.Cleanup{}, err, now)
		}
		found, err := s.commitment(ctx, st, a, status)
		if err != nil {
			return s.cleanupFailed(a, status, attachments.Cleanup{}, err, now)
		}
		if found == nil {
			if c := meta.FindStatusCondition(status.Conditions, v1alpha1.ConditionDocumentCommitted); c != nil && c.Reason == v1alpha1.ReasonStorageConflict {
				// A foreign commitment under this record's UID is never
				// deleted as ours; an administrator must resolve it.
				return s.cleanupFailed(a, status, attachments.Cleanup{State: attachments.CleanupRetentionBlocked,
					Message: "storage holds a commitment that does not match this record; it is not deleted: " + c.Message}, attachments.ErrRetentionBlocked, now)
			}
			res, err := st.DeleteUncommitted(ctx, s.ref(a))
			if errors.Is(err, attachments.ErrConflict) {
				return false, time.Second, nil // committed meanwhile: record it first
			}
			if err != nil {
				return s.cleanupFailed(a, status, res, err, now)
			}
			return true, 0, nil
		}
		recordCommitment(status, a.Generation, found)
		cm = status.Storage.Commitment
	}
	if now.Before(cm.ExpiresAt.Time) {
		// Retention active: withdrawal never shortens the commitment, and
		// nothing is deleted. The retained source stays downloadable, so its
		// content is still checked.
		until := cm.ExpiresAt.UTC().Format(time.RFC3339)
		status.Storage.Cleanup = &v1alpha1.AttachmentCleanup{State: "NotDue", Message: "withdrawn; the committed source is retained until " + until}
		s.retained(a, status, metav1.ConditionTrue, v1alpha1.ReasonRetentionActive, "withdrawn from new current evidence; the committed source is retained until "+until)
		wait := min(cm.ExpiresAt.Sub(now), MaxRetentionRequeue)
		if due, untilDue := s.contentDue(a.UID, now, status.Content); !due {
			return false, min(wait, untilDue), nil
		}
		if err := open(); err != nil {
			reason, msg := storageReason(err)
			setContent(status, v1alpha1.ContentUnavailable, reason, msg, now)
			s.markChecked(a.UID, now)
			return false, min(wait, attachmentStorageRequeue), nil
		}
		return false, min(wait, s.checkContent(ctx, st, a, status, now)), nil
	}
	sourceExpired(status, cm, now)
	if wait := cleanupWait(status.Storage.Cleanup, now); wait > 0 {
		return false, wait, nil
	}
	if err := open(); err != nil {
		return s.cleanupFailed(a, status, attachments.Cleanup{}, err, now)
	}
	res, err := st.Delete(ctx, s.receipt(a, cm, st), now)
	if err != nil {
		return s.cleanupFailed(a, status, res, err, now)
	}
	return true, 0, nil
}

func (s *AttachmentStorage) retained(a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus, st metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: v1alpha1.ConditionSourceRetained, Status: st, Reason: reason,
		Message: truncateMsg(msg), ObservedGeneration: a.Generation})
}

// cleanupWait is the remaining backoff after a failed or refused cleanup.
func cleanupWait(c *v1alpha1.AttachmentCleanup, now time.Time) time.Duration {
	if c == nil || c.LastAttempt == nil || (c.State != string(attachments.CleanupDeletionFailed) && c.State != string(attachments.CleanupRetentionBlocked)) {
		return 0
	}
	if next := c.LastAttempt.Add(cleanupBackoff(c.Attempts)); now.Before(next) {
		return next.Sub(now)
	}
	return 0
}

// cleanupFailed records a failed or refused cleanup attempt: ownership, the
// pin and any commitment are kept, and the attempt is retried after its
// backoff.
func (s *AttachmentStorage) cleanupFailed(a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus, res attachments.Cleanup, err error, now time.Time) (bool, time.Duration, error) {
	state, reason := string(attachments.CleanupDeletionFailed), v1alpha1.ReasonCleanupFailed
	if res.State == attachments.CleanupRetentionBlocked || errors.Is(err, attachments.ErrRetentionBlocked) {
		state, reason = string(attachments.CleanupRetentionBlocked), v1alpha1.ReasonCleanupBlocked
	}
	msg := res.Message
	if msg == "" {
		msg = err.Error()
	}
	if errors.Is(err, publication.ErrOrphaned) {
		msg = "the pinned destination was handed off to an operator and is not contacted; take over the attachment's storage and release the record (docs/supporting-evidence.md)"
	}
	attempts := int32(1)
	if prev := status.Storage.Cleanup; prev != nil && (prev.State == string(attachments.CleanupDeletionFailed) || prev.State == string(attachments.CleanupRetentionBlocked)) {
		attempts = prev.Attempts + 1
	}
	t := metav1.NewTime(now)
	status.Storage.Cleanup = &v1alpha1.AttachmentCleanup{State: state, Attempts: attempts, LastAttempt: &t, Message: truncateMsg(msg)}
	wait := cleanupBackoff(attempts)
	s.retained(a, status, metav1.ConditionTrue, reason, fmt.Sprintf("owned storage could not be removed; ownership is kept and cleanup is retried after %s: %s", wait, msg))
	return false, wait, nil
}

// destinationStores builds attachment stores for pinned destinations. The
// location comes from the destination, which is immutable; credentials and
// trust are resolved through it on every build (credential Secrets are
// re-read at least every s3store.CredentialRefresh), so rotation applies to
// existing documents.
type destinationStores struct {
	Reader    client.Reader
	Namespace string

	mu    sync.Mutex
	cache map[string]cachedStore
}

type cachedStore struct {
	generation int64
	store      attachments.Store
}

func (d *destinationStores) Store(ctx context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error) {
	ed := &v1alpha1.EvidenceDestination{}
	if err := d.Reader.Get(ctx, client.ObjectKey{Name: ref.Name}, ed); err != nil {
		return nil, fmt.Errorf("%w: EvidenceDestination %s: %v", attachments.ErrUnavailable, ref.Name, err)
	}
	switch {
	case string(ed.UID) != ref.UID:
		return nil, fmt.Errorf("%w: EvidenceDestination %s was replaced; the pinned destination is never substituted", attachments.ErrUnavailable, ref.Name)
	case ed.Status.OrphanIntent != nil:
		return nil, fmt.Errorf("%w: %w: EvidenceDestination %s was handed off to an operator and is no longer contacted", attachments.ErrUnavailable, publication.ErrOrphaned, ref.Name)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.cache[ref.UID]; ok && c.generation == ed.Generation {
		return c.store, nil
	}
	dest, err := DestinationFromAPI(ctx, d.Reader, d.Namespace, ed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", attachments.ErrUnavailable, err)
	}
	pub, err := s3store.NewPublisher(ctx, dest, d.Reader, controllerNamespace(d.Namespace))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", attachments.ErrUnavailable, err)
	}
	st := &s3store.AttachmentStore{Client: pub.Client, Dest: dest}
	if d.cache == nil {
		d.cache = map[string]cachedStore{}
	}
	d.cache[ref.UID] = cachedStore{generation: ed.Generation, store: st}
	return st, nil
}

// NewAttachmentStores builds attachment stores for pinned destinations for
// the transfer service (konstapel download-server), with the same adapter,
// credential resolution and orphan refusal as the controller. A destination
// handed off to an operator yields an error matching publication.ErrOrphaned.
func NewAttachmentStores(r client.Reader, namespace string) AttachmentStores {
	return &destinationStores{Reader: r, Namespace: namespace}
}

// attachmentStorage configures storage ownership from the assessment
// runtime; without a controller namespace nothing is pinned.
func attachmentStorage(mgr manager.Manager, rt AssessmentRuntime, cluster string) *AttachmentStorage {
	if rt.ControllerNamespace == "" {
		return nil
	}
	return &AttachmentStorage{Reader: mgr.GetAPIReader(), Namespace: rt.ControllerNamespace, Cluster: cluster,
		Stores: &destinationStores{Reader: mgr.GetAPIReader(), Namespace: rt.ControllerNamespace}, Fences: rt.Destinations}
}
