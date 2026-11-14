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
// Deleting a record withdraws it immediately. The finalizer stays until:
//   - nothing was pinned (no bytes can exist), or
//   - nothing was committed and every owned attempt is removed, or
//   - the commitment expired and every owned version is removed.
//
// Failures keep the finalizer and the pin and are retried; they are never
// treated as deletion.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// Requeue intervals for attachment storage.
const (
	// attachmentStorageRequeue re-reads storage while a commitment is
	// awaited or a destination is unavailable.
	attachmentStorageRequeue = time.Minute
	// attachmentCleanupRetry retries a failed or blocked cleanup.
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
	Now              func() time.Time
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
			return ctx, nil, done, fmt.Errorf("%w: destination %s is fenced: %v", attachments.ErrUnavailable, pin.Name, err)
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

// reconcile pins a destination and records the commitment of a live record.
func (s *AttachmentStorage) reconcile(ctx context.Context, c client.Client, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus) (time.Duration, error) {
	if status.Storage == nil || status.Storage.Destination == nil {
		ok, err := s.pin(ctx, c, a, status)
		if err != nil || !ok {
			return attachmentStorageRequeue, err
		}
		// Persist the pin before any storage read.
		return time.Second, nil
	}
	if status.Storage.Commitment != nil {
		recordCommitment(status, a.Generation, status.Storage.Commitment)
	}
	ctx, st, done, err := s.begin(ctx, a)
	defer done()
	if err != nil {
		if status.Storage.Commitment == nil {
			setCommitted(status, a.Generation, metav1.ConditionFalse, v1alpha1.ReasonStorageUnavailable, err.Error())
		}
		return attachmentStorageRequeue, nil
	}
	if status.Storage.DestinationID == "" {
		status.Storage.DestinationID = st.Destination().ID
	}
	if status.Storage.Commitment == nil {
		cm, err := s.commitment(ctx, st, a, status)
		if err != nil {
			return attachmentStorageRequeue, nil
		}
		if cm == nil {
			s.cleanupAttempts(ctx, st, a)
			return attachmentStorageRequeue, nil
		}
		recordCommitment(status, a.Generation, cm)
	}
	// Abandoned attempts (a concurrent writer that lost, an interrupted
	// upload) are removed once they are old enough.
	s.cleanupAttempts(ctx, st, a)
	return 0, nil
}

func (s *AttachmentStorage) cleanupAttempts(ctx context.Context, st attachments.Store, a *v1alpha1.EvidenceAttachment) {
	if err := st.CleanupAttempts(ctx, s.ref(a), s.now().Add(-s.attemptRetention())); err != nil {
		log.FromContext(ctx).Info("attachment attempt cleanup incomplete; retried later", "attachment", a.Name, "reason", err.Error())
	}
}

// finalize decides whether a withdrawn record may be released. It returns
// release=true only when no owned storage remains.
func (s *AttachmentStorage) finalize(ctx context.Context, a *v1alpha1.EvidenceAttachment, status *v1alpha1.EvidenceAttachmentStatus) (release bool, requeue time.Duration, err error) {
	if status.Storage == nil || status.Storage.Destination == nil {
		// Never pinned: the transfer service accepts bytes only for a
		// pinned record, so nothing can be stored.
		return true, 0, nil
	}
	now := s.now()
	setCleanup := func(state, msg string) {
		t := metav1.NewTime(now)
		status.Storage.Cleanup = &v1alpha1.AttachmentCleanup{State: state, LastAttempt: &t, Message: truncateMsg(msg)}
	}
	retained := func(st metav1.ConditionStatus, reason, msg string) {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: v1alpha1.ConditionSourceRetained, Status: st, Reason: reason,
			Message: truncateMsg(msg), ObservedGeneration: a.Generation})
	}
	ctx, st, done, err := s.begin(ctx, a)
	defer done()
	if err != nil {
		setCleanup(string(attachments.CleanupDeletionFailed), err.Error())
		retained(metav1.ConditionTrue, v1alpha1.ReasonCleanupFailed, "owned storage cannot be reached; ownership is kept and cleanup retried: "+err.Error())
		return false, attachmentCleanupRetry, nil
	}
	if status.Storage.Commitment == nil {
		// A commitment that landed while its status write was lost governs
		// retention exactly like a recorded one.
		cm, err := s.commitment(ctx, st, a, status)
		if err != nil {
			setCleanup(string(attachments.CleanupDeletionFailed), err.Error())
			retained(metav1.ConditionTrue, v1alpha1.ReasonCleanupFailed, err.Error())
			return false, attachmentCleanupRetry, nil
		}
		if cm != nil {
			recordCommitment(status, a.Generation, cm)
		} else if c := meta.FindStatusCondition(status.Conditions, v1alpha1.ConditionDocumentCommitted); c != nil && c.Reason == v1alpha1.ReasonStorageConflict {
			// A foreign commitment under this record's UID is never deleted
			// as ours; an administrator must resolve it.
			setCleanup(string(attachments.CleanupDeletionFailed), c.Message)
			retained(metav1.ConditionTrue, v1alpha1.ReasonCleanupBlocked, "storage holds a commitment that does not match this record; it is not deleted: "+c.Message)
			return false, attachmentCleanupRetry, nil
		} else {
			res, err := st.DeleteUncommitted(ctx, s.ref(a))
			if errors.Is(err, attachments.ErrConflict) {
				return false, time.Second, nil // committed meanwhile: record it first
			}
			if err != nil {
				return s.cleanupFailed(res, err, setCleanup, retained)
			}
			setCleanup(string(attachments.CleanupDeleted), "no commitment; owned upload attempts removed")
			return true, 0, nil
		}
	}
	r := s.receipt(a, status.Storage.Commitment, st)
	if now.Before(r.ExpiresAt) {
		setCleanup("NotDue", "withdrawn; the committed source is retained until "+r.ExpiresAt.Format(time.RFC3339))
		retained(metav1.ConditionTrue, v1alpha1.ReasonRetentionActive, "withdrawn from new current evidence; the committed source is retained until "+r.ExpiresAt.Format(time.RFC3339))
		wait := r.ExpiresAt.Sub(now)
		if wait > MaxRetentionRequeue {
			wait = MaxRetentionRequeue
		}
		return false, wait, nil
	}
	res, err := st.Delete(ctx, r, now)
	if err != nil {
		return s.cleanupFailed(res, err, setCleanup, retained)
	}
	setCleanup(string(attachments.CleanupDeleted), "expired source and every owned version removed")
	return true, 0, nil
}

func (s *AttachmentStorage) cleanupFailed(res attachments.Cleanup, err error, setCleanup func(string, string), retained func(metav1.ConditionStatus, string, string)) (bool, time.Duration, error) {
	state, reason := string(attachments.CleanupDeletionFailed), v1alpha1.ReasonCleanupFailed
	if res.State == attachments.CleanupRetentionBlocked || errors.Is(err, attachments.ErrRetentionBlocked) {
		state, reason = string(attachments.CleanupRetentionBlocked), v1alpha1.ReasonCleanupBlocked
	}
	msg := res.Message
	if msg == "" {
		msg = err.Error()
	}
	setCleanup(state, msg)
	retained(metav1.ConditionTrue, reason, "owned storage could not be removed; ownership is kept and cleanup retried: "+msg)
	return false, attachmentCleanupRetry, nil
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
		return nil, fmt.Errorf("%w: EvidenceDestination %s was handed off to an operator and is no longer contacted", attachments.ErrUnavailable, ref.Name)
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

// attachmentStorage configures storage ownership from the assessment
// runtime; without a controller namespace nothing is pinned.
func attachmentStorage(mgr manager.Manager, rt AssessmentRuntime, cluster string) *AttachmentStorage {
	if rt.ControllerNamespace == "" {
		return nil
	}
	return &AttachmentStorage{Reader: mgr.GetAPIReader(), Namespace: rt.ControllerNamespace, Cluster: cluster,
		Stores: &destinationStores{Reader: mgr.GetAPIReader(), Namespace: rt.ControllerNamespace}, Fences: rt.Destinations}
}
