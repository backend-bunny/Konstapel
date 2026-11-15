package download

// Supporting-evidence document transfer (add-supporting-evidence-attachments
// 3.1-3.2). The same TLS service and the same authentication as package
// downloads: a bearer token checked by TokenReview for the service's
// audience, then SubjectAccessReview on a dedicated service attribute and
// read access to the resolved record, by its current name:
//
//	PUT /v1/evidenceattachments/<uid>/upload    create evidenceattachments/upload + get evidenceattachments
//	GET /v1/evidenceattachments/<uid>/download  get evidenceattachments/download + get evidenceattachments
//
// Records are addressed by UID only; a recreated record is a different
// address. An unknown UID gets the same 403 as a denial.
//
// An upload is accepted only for a live (not withdrawn) record whose
// destination the controller has pinned, within the configured size,
// deadline and concurrency. The bytes are received into bounded temporary
// storage and hashed against the registered size and SHA-256 before
// anything is stored; authorization and the record are checked again before
// staging and the record once more before the commit, so a revoked uploader
// or a withdrawn record never commits. Staging and the commit go through the
// attachment storage contract (attachments.Store) of the pinned destination
// only, which verifies the stored version and creates the one commitment;
// a retry, a concurrent upload on another replica, or a call after a lost
// response returns that commitment. The authenticated caller is the
// recorded uploader. Every ready replica serves; no leader is involved.
//
// A download serves only the commitment the controller recorded in the
// record's status, after the stored commit manifest confirms it, before its
// fixed expiry, and after the bytes are verified against the registered
// size and SHA-256. A withdrawn record's retained document stays readable
// until that expiry. Responses are passive attachments that are never
// rendered, sniffed or cached.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Attachment routes, addressed by EvidenceAttachment UID.
const (
	AttachmentUploadRoute   = "PUT /v1/evidenceattachments/{uid}/upload"
	AttachmentDownloadRoute = "GET /v1/evidenceattachments/{uid}/download"
)

// Attachment transfer defaults and the bounds of their overrides.
const (
	DefaultAttachmentMaxBytes      int64 = 32 << 20
	DefaultAttachmentTimeout             = 5 * time.Minute
	DefaultAttachmentMaxConcurrent       = 2
	// MaxAttachmentBytes is the API's absolute document ceiling
	// (EvidenceAttachment spec.document.size).
	MaxAttachmentBytes int64 = 1 << 30
	// MaxAttachmentTimeout bounds how long one transfer can hold a slot.
	MaxAttachmentTimeout       = time.Hour
	MaxAttachmentMaxConcurrent = 64
)

// AttachmentLimits bound attachment transfers on one replica.
type AttachmentLimits struct {
	// MaxBytes is the largest registered document this service accepts for
	// upload. Downloads of committed documents are not limited by it.
	MaxBytes int64
	// Timeout bounds one transfer, receiving and storing included.
	Timeout time.Duration
	// MaxConcurrent bounds simultaneous uploads and downloads together.
	MaxConcurrent int
	// Retention is the central source retention frozen into a new
	// commitment: expiresAt = max(committedAt, validUntil) + Retention.
	Retention time.Duration
}

// DefaultAttachmentLimits returns the documented defaults: 32 MiB, five
// minutes, two transfers per replica, and 2160h retention.
func DefaultAttachmentLimits() AttachmentLimits {
	return AttachmentLimits{MaxBytes: DefaultAttachmentMaxBytes, Timeout: DefaultAttachmentTimeout,
		MaxConcurrent: DefaultAttachmentMaxConcurrent, Retention: attachments.DefaultRetention}
}

// Validate checks operator overrides. maxTempBytes is the temporary storage
// budget every staged upload must fit in.
func (l AttachmentLimits) Validate(maxTempBytes int64) error {
	var errs []error
	if l.MaxBytes < 1 || l.MaxBytes > MaxAttachmentBytes {
		errs = append(errs, fmt.Errorf("attachment upload limit %d must be between 1 and %d bytes", l.MaxBytes, MaxAttachmentBytes))
	} else if maxTempBytes > 0 && l.MaxBytes > maxTempBytes {
		errs = append(errs, fmt.Errorf("attachment upload limit %d exceeds the temporary storage budget %d", l.MaxBytes, maxTempBytes))
	}
	if l.Timeout < time.Second || l.Timeout > MaxAttachmentTimeout {
		errs = append(errs, fmt.Errorf("attachment transfer timeout %s must be between 1s and %s", l.Timeout, MaxAttachmentTimeout))
	}
	if l.MaxConcurrent < 1 || l.MaxConcurrent > MaxAttachmentMaxConcurrent {
		errs = append(errs, fmt.Errorf("concurrent attachment transfers %d must be between 1 and %d", l.MaxConcurrent, MaxAttachmentMaxConcurrent))
	}
	if err := attachments.ValidateRetention(l.Retention); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// UploadReceipt is the upload response: the commitment that holds the
// document, which may predate this request (a retry, or another uploader).
type UploadReceipt struct {
	Name        string                `json:"name"`
	UID         string                `json:"uid"`
	SHA256      string                `json:"sha256"`
	Size        int64                 `json:"size"`
	Uploader    attachments.Principal `json:"uploader"`
	CommittedAt time.Time             `json:"committedAt"`
	Retention   string                `json:"retention"`
	ExpiresAt   time.Time             `json:"expiresAt"`
}

var (
	errNotUploadable = problem{http.StatusConflict, "the uploaded bytes do not match the registered size and SHA-256; nothing was stored"}
	errWithdrawn     = problem{http.StatusConflict, "the attachment is withdrawn (being deleted) and accepts no upload; register a new record"}
	errHandedOff     = problem{http.StatusGone, "the attachment's storage was handed off to an operator and is no longer served"}
	errAttUnavail    = problem{http.StatusServiceUnavailable, "attachment storage is unavailable; try again later"}
)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func attachmentAttrs(name, verb, subresource string) []authzv1.ResourceAttributes {
	base := authzv1.ResourceAttributes{Verb: "get", Group: v1alpha1.GroupVersion.Group, Version: v1alpha1.GroupVersion.Version, Resource: "evidenceattachments", Name: name}
	transfer := base
	transfer.Verb, transfer.Subresource = verb, subresource
	return []authzv1.ResourceAttributes{transfer, base}
}

func uploadAttrs(name string) []authzv1.ResourceAttributes {
	return attachmentAttrs(name, "create", "upload")
}

func downloadAttrs(name string) []authzv1.ResourceAttributes {
	return attachmentAttrs(name, "get", "download")
}

// attachmentByUID resolves a record by UID. A missing record answers like a
// denial, so UIDs are not an existence oracle.
func (s *Server) attachmentByUID(ctx context.Context, uid string) (*v1alpha1.EvidenceAttachment, error) {
	var list v1alpha1.EvidenceAttachmentList
	if err := s.Reader.List(ctx, &list); err != nil {
		log.FromContext(ctx).Info("listing attachments failed", "error", err.Error())
		return nil, errReview
	}
	for i := range list.Items {
		if string(list.Items[i].UID) == uid {
			return &list.Items[i], nil
		}
	}
	return nil, errForbidden
}

// current re-reads the record uncached and requires the same identity, no
// withdrawal and the same destination pin.
func (s *Server) current(ctx context.Context, a *v1alpha1.EvidenceAttachment) (*v1alpha1.EvidenceAttachment, error) {
	cur := &v1alpha1.EvidenceAttachment{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: a.Name}, cur); err != nil || cur.UID != a.UID {
		return nil, errForbidden
	}
	if !cur.DeletionTimestamp.IsZero() {
		return nil, errWithdrawn
	}
	if pin, was := pinOf(cur), pinOf(a); pin == nil || was == nil || *pin != *was {
		return nil, problem{http.StatusConflict, "the attachment's storage pin changed during the upload; nothing was committed"}
	}
	return cur, nil
}

func pinOf(a *v1alpha1.EvidenceAttachment) *v1alpha1.DestinationReference {
	if a.Status.Storage == nil {
		return nil
	}
	return a.Status.Storage.Destination
}

// store opens the pinned destination's store and checks it is that
// destination. A destination handed off to an operator is never contacted.
func (s *Server) store(ctx context.Context, a *v1alpha1.EvidenceAttachment) (attachments.Store, error) {
	pin := pinOf(a)
	st, err := s.AttachmentStores(ctx, *pin)
	switch {
	case errors.Is(err, publication.ErrOrphaned):
		return nil, errHandedOff
	case err != nil:
		log.FromContext(ctx).Info("pinned attachment destination unavailable", "attachment", a.Name, "error", err.Error())
		return nil, errAttUnavail
	}
	if id := st.Destination().ID; id != pin.UID || (a.Status.Storage.DestinationID != "" && id != a.Status.Storage.DestinationID) {
		log.FromContext(ctx).Info("attachment store is not the pinned destination", "attachment", a.Name)
		return nil, errAttUnavail
	}
	return st, nil
}

func (s *Server) ref(a *v1alpha1.EvidenceAttachment) attachments.Ref {
	return attachments.Ref{ClusterID: s.Cluster, UID: string(a.UID)}
}

// responseGrace lets an upload's error or receipt be written after its
// receive deadline.
const responseGrace = 10 * time.Second

// acquire takes a transfer slot and bounds the transfer: the request
// context and the connection's read deadline expire after the configured
// timeout, and its write deadline grace later.
func (s *Server) acquire(w http.ResponseWriter, r *http.Request, grace time.Duration) (context.Context, func(), error) {
	select {
	case s.attSem <- struct{}{}:
	default:
		return nil, nil, problem{http.StatusTooManyRequests, "too many concurrent attachment transfers; try again later"}
	}
	deadline := time.Now().Add(s.AttachmentLimits.Timeout)
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline.Add(grace))
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	return ctx, func() { cancel(); <-s.attSem }, nil
}

// spool receives exactly size bytes from body into a temporary file,
// hashing them. It returns the file, rewound, only when the bytes match the
// registered document.
func (s *Server) spool(ctx context.Context, body io.Reader, doc attachments.Document) (*os.File, func(), error) {
	want, err := doc.Sum()
	if err != nil {
		return nil, nil, errNotUploadable
	}
	if !s.reserve(doc.Size) {
		return nil, nil, problem{http.StatusServiceUnavailable, "upload staging is full; try again later"}
	}
	f, err := os.CreateTemp(s.TempDir, "attachment-*")
	if err != nil {
		s.release(doc.Size)
		return nil, nil, err
	}
	done := func() { f.Close(); os.Remove(f.Name()); s.release(doc.Size) }
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, doc.Size+1))
	if err != nil {
		done()
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			return nil, nil, errNotUploadable
		case errors.Is(err, os.ErrDeadlineExceeded) || ctx.Err() != nil:
			return nil, nil, problem{http.StatusRequestTimeout, "the upload did not complete within the transfer deadline; nothing was stored"}
		}
		return nil, nil, problem{http.StatusBadRequest, "the upload was interrupted; nothing was stored"}
	}
	if n != doc.Size || [32]byte(h.Sum(nil)) != want {
		done()
		return nil, nil, errNotUploadable
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		done()
		return nil, nil, err
	}
	return f, done, nil
}

// storageProblem maps a storage contract error to a response.
func storageProblem(ctx context.Context, a *v1alpha1.EvidenceAttachment, err error) error {
	switch {
	case errors.Is(err, attachments.ErrConflict), errors.Is(err, attachments.ErrUnsupportedRecord):
		log.FromContext(ctx).Info("attachment storage conflict", "attachment", a.Name, "error", err.Error())
		return problem{http.StatusConflict, "storage holds a different commitment for this attachment; it is preserved and nothing was replaced"}
	case errors.Is(err, attachments.ErrIntegrity):
		log.FromContext(ctx).Info("stored attachment failed verification", "attachment", a.Name, "error", err.Error())
		return problem{http.StatusBadGateway, "storage did not verify the uploaded document; nothing was committed"}
	}
	log.FromContext(ctx).Info("attachment storage unavailable", "attachment", a.Name, "error", err.Error())
	return errAttUnavail
}

// uploadAttachment receives, verifies, stages and commits a document.
func (s *Server) uploadAttachment(w http.ResponseWriter, r *http.Request) {
	u, err := s.authenticate(r)
	if err != nil {
		fail(w, err)
		return
	}
	a, err := s.attachmentByUID(r.Context(), r.PathValue("uid"))
	if err == nil {
		err = s.authorize(r.Context(), u, uploadAttrs(a.Name)...)
	}
	if err == nil {
		err = s.uploadable(r, a)
	}
	if err != nil {
		fail(w, err)
		return
	}
	ctx, release, err := s.acquire(w, r, responseGrace)
	if err != nil {
		fail(w, err)
		return
	}
	defer release()
	doc := attachments.Expected(a.Spec)
	f, done, err := s.spool(ctx, http.MaxBytesReader(w, r.Body, doc.Size), doc)
	if err != nil {
		fail(w, err)
		return
	}
	defer done()
	receipt, err := s.stageAndCommit(ctx, u, a, f)
	if err != nil {
		fail(w, err)
		return
	}
	b, _ := json.Marshal(UploadReceipt{Name: a.Name, UID: string(a.UID), SHA256: receipt.Document.SHA256, Size: receipt.Document.Size,
		Uploader: receipt.Uploader, CommittedAt: receipt.CommittedAt, Retention: receipt.Retention.String(), ExpiresAt: receipt.ExpiresAt})
	hd := w.Header()
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(b, '\n'))
}

// uploadable checks the record and the declared request before any byte is
// read: a live record with a pinned destination, a registered size within
// the limit, and no declared length other than the registered size.
func (s *Server) uploadable(r *http.Request, a *v1alpha1.EvidenceAttachment) error {
	switch {
	case !a.DeletionTimestamp.IsZero():
		return errWithdrawn
	case pinOf(a) == nil:
		return problem{http.StatusConflict, "the attachment has no pinned storage destination yet; see its DocumentCommitted condition and retry"}
	case a.Spec.Document.Size > s.AttachmentLimits.MaxBytes:
		return problem{http.StatusRequestEntityTooLarge, fmt.Sprintf("the registered document size %d exceeds this service's upload limit of %d bytes", a.Spec.Document.Size, s.AttachmentLimits.MaxBytes)}
	case r.ContentLength >= 0 && r.ContentLength != a.Spec.Document.Size:
		return errNotUploadable
	}
	return nil
}

// stageAndCommit checks the caller's authorization and the record again
// after receiving the bytes, then stages and commits through the pinned
// destination's store.
func (s *Server) stageAndCommit(ctx context.Context, u authnv1.UserInfo, a *v1alpha1.EvidenceAttachment, body io.ReadSeeker) (attachments.Receipt, error) {
	if err := s.authorize(ctx, u, uploadAttrs(a.Name)...); err != nil {
		return attachments.Receipt{}, err
	}
	a, err := s.current(ctx, a)
	if err != nil {
		return attachments.Receipt{}, err
	}
	st, err := s.store(ctx, a)
	if err != nil {
		return attachments.Receipt{}, err
	}
	ref := s.ref(a)
	req := attachments.CommitRequest{Ref: ref, SpecDigest: attachments.SpecDigest(a.Spec), Document: attachments.Expected(a.Spec),
		ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: s.AttachmentLimits.Retention}
	// A retry (for example after a lost response) gets the commitment
	// that already holds these verified bytes, without a new attempt.
	if r, err := st.Committed(ctx, ref); err == nil {
		if r.Document != req.Document || r.SpecDigest != req.SpecDigest {
			return attachments.Receipt{}, storageProblem(ctx, a, attachments.ErrConflict)
		}
		return r, nil
	} else if !errors.Is(err, attachments.ErrNotFound) {
		return attachments.Receipt{}, storageProblem(ctx, a, err)
	}
	if _, err := st.Stage(ctx, attachments.StageRequest{Ref: ref, Document: req.Document,
		Uploader: attachments.Principal{Username: u.Username, UID: u.UID}, Body: body}); err != nil {
		return attachments.Receipt{}, storageProblem(ctx, a, err)
	}
	// Withdrawal removes uncommitted attempts; an upload accepted before
	// it must not commit afterwards. A destination handed off to an
	// operator meanwhile is not written to again either: the controller
	// fences only its own in-process work, so this service re-reads the
	// destination (uncached) right before its one write that matters.
	if _, err := s.current(ctx, a); err != nil {
		return attachments.Receipt{}, err
	}
	if _, err := s.store(ctx, a); err != nil {
		return attachments.Receipt{}, err
	}
	r, err := st.Commit(ctx, req)
	if err != nil {
		return attachments.Receipt{}, storageProblem(ctx, a, err)
	}
	if _, err := s.current(ctx, a); err != nil {
		// Withdrawn while committing: the controller retains whatever was
		// committed until its expiry; it is not current evidence.
		log.FromContext(ctx).Info("attachment withdrawn while its upload committed", "attachment", a.Name)
		return attachments.Receipt{}, errWithdrawn
	}
	return r, nil
}

// downloadAttachment serves a committed document as a passive attachment.
func (s *Server) downloadAttachment(w http.ResponseWriter, r *http.Request) {
	u, err := s.authenticate(r)
	if err != nil {
		fail(w, err)
		return
	}
	a, err := s.attachmentByUID(r.Context(), r.PathValue("uid"))
	if err == nil {
		err = s.authorize(r.Context(), u, downloadAttrs(a.Name)...)
	}
	var c *v1alpha1.AttachmentCommitment
	if err == nil {
		c, err = s.downloadable(a)
	}
	if err != nil {
		fail(w, err)
		return
	}
	ctx, release, err := s.acquire(w, r, 0)
	if err != nil {
		fail(w, err)
		return
	}
	defer release()
	st, err := s.store(ctx, a)
	if err != nil {
		fail(w, err)
		return
	}
	// The stored manifest must confirm the recorded commitment: the same
	// keys, versions, document, spec and times, for this record's UID.
	rec, err := st.Committed(ctx, s.ref(a))
	switch {
	case errors.Is(err, attachments.ErrNotFound):
		fail(w, problem{http.StatusServiceUnavailable, "the committed document is missing before its expiry"})
		return
	case err != nil:
		fail(w, storageProblem(ctx, a, err))
		return
	case !sameRecorded(rec, c, a):
		log.FromContext(ctx).Info("stored commitment does not match the recorded one", "attachment", a.Name)
		fail(w, problem{http.StatusBadGateway, "the stored commitment does not match the record's receipt"})
		return
	}
	body, err := st.Open(ctx, rec)
	switch {
	case errors.Is(err, attachments.ErrNotFound):
		fail(w, problem{http.StatusGone, "the source document expired and is no longer served"})
		return
	case err != nil:
		fail(w, storageProblem(ctx, a, err))
		return
	}
	defer body.Close()
	doc := attachments.Expected(a.Spec)
	want, _ := doc.Sum()
	if !s.reserve(doc.Size) {
		fail(w, problem{http.StatusServiceUnavailable, "download staging is full; try again later"})
		return
	}
	defer s.release(doc.Size)
	f, err := os.CreateTemp(s.TempDir, "attachment-*")
	if err != nil {
		fail(w, err)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, doc.Size+1))
	if err != nil {
		fail(w, errAttUnavail)
		return
	}
	sum := h.Sum(nil)
	if n != doc.Size || [32]byte(sum) != want {
		log.FromContext(ctx).Info("attachment failed integrity verification", "attachment", a.Name, "size", n)
		fail(w, problem{http.StatusBadGateway, "the stored document failed integrity verification"})
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fail(w, err)
		return
	}
	hd := w.Header()
	// Passive: never rendered, sniffed, executed or cached. The declared
	// media type is descriptive only and is reported, not served.
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("Content-Type", "application/octet-stream")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hd.Set("Content-Disposition", `attachment; filename="`+a.Name+`"`)
	hd.Set("Content-Length", strconv.FormatInt(n, 10))
	hd.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":")
	hd.Set("X-Konstapel-Attachment-UID", string(a.UID))
	hd.Set("X-Konstapel-Document-SHA256", "sha256:"+hex.EncodeToString(sum))
	hd.Set("X-Konstapel-Declared-Media-Type", a.Spec.Document.MediaType)
	hd.Set("X-Konstapel-Valid-From", a.Spec.Validity.ValidFrom.UTC().Format(time.RFC3339))
	hd.Set("X-Konstapel-Valid-Until", a.Spec.Validity.ValidUntil.UTC().Format(time.RFC3339))
	hd.Set("X-Konstapel-Committed-At", rec.CommittedAt.UTC().Format(time.RFC3339))
	hd.Set("X-Konstapel-Expires-At", rec.ExpiresAt.UTC().Format(time.RFC3339))
	if !a.DeletionTimestamp.IsZero() {
		hd.Set("X-Konstapel-Withdrawn", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// downloadable returns the record's recorded commitment when it can be
// served: recorded by the controller, consistent with the immutable spec,
// pinned, and not expired.
func (s *Server) downloadable(a *v1alpha1.EvidenceAttachment) (*v1alpha1.AttachmentCommitment, error) {
	st := a.Status.Storage
	if st == nil || st.Commitment == nil {
		return nil, problem{http.StatusConflict, "the document is not committed yet; see the record's DocumentCommitted condition"}
	}
	c := st.Commitment
	if st.Destination == nil || c.SHA256 != a.Spec.Document.SHA256 || c.Size != a.Spec.Document.Size || c.SpecDigest != attachments.SpecDigest(a.Spec) {
		return nil, problem{http.StatusBadGateway, "the recorded commitment does not match the record"}
	}
	if !s.now().Before(c.ExpiresAt.Time) {
		return nil, problem{http.StatusGone, "the source document expired at " + c.ExpiresAt.UTC().Format(time.RFC3339) + " and is no longer served"}
	}
	return c, nil
}

// sameRecorded compares a stored commitment with the recorded one.
func sameRecorded(r attachments.Receipt, c *v1alpha1.AttachmentCommitment, a *v1alpha1.EvidenceAttachment) bool {
	return r.Ref.UID == string(a.UID) && r.ManifestKey == c.ManifestKey && r.ManifestVersionID == c.ManifestVersionID &&
		r.DocumentKey == c.DocumentKey && r.DocumentVersionID == c.DocumentVersionID && r.Document.SHA256 == c.SHA256 &&
		r.Document.Size == c.Size && r.SpecDigest == c.SpecDigest && r.Uploader.Username == c.Uploader.Username &&
		r.CommittedAt.Equal(c.CommittedAt.Time) && r.ExpiresAt.Equal(c.ExpiresAt.Time)
}
