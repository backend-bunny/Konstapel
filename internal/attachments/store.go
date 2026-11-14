package attachments

// Source-document storage contract (add-supporting-evidence-attachments
// 2.1-2.4). It is deliberately separate from publication.Publisher: a
// supporting document is keyed by cluster and attachment UID, not by an
// assessment run, and no run is invented to store one.
//
// Commit protocol: the transfer service stages the bytes under a fresh
// attempt (an ownership intent first, then the document, verified by
// checksum or read-back, then the attempt record naming the uploader), and
// commits by conditionally creating the attachment's one fixed commit
// manifest (If-None-Match: *). The manifest binds the document digest and
// size, the immutable spec digest, the uploader, the destination, the stored
// version, and the retention inputs; its server LastModified time is the
// commitment time. Every later commit for the attachment, a retry, a
// concurrent writer, or a call after a lost response, returns that first
// commitment, or a conflict if its content differs. Expiry is fixed then:
// max(committedAt, validUntil) + retention.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// DefaultRetention is the central source-document retention tail added after
// a document's validity (or its commitment, if later).
const DefaultRetention = 2160 * time.Hour

// DefaultAttemptRetention is how long an uncommitted upload attempt is kept
// before it is cleaned up.
const DefaultAttemptRetention = 24 * time.Hour

// Errors of the storage contract.
var (
	// ErrNotFound: no commitment (or no staged attempt to commit) exists.
	ErrNotFound = errors.New("attachment document not found")
	// ErrConflict: storage holds a different commitment for this attachment.
	ErrConflict = errors.New("attachment commitment conflict")
	// ErrIntegrity: bytes do not match the registered size and SHA-256.
	ErrIntegrity = errors.New("attachment document does not match its registration")
	// ErrUnavailable: storage could not be reached or did not confirm.
	ErrUnavailable = errors.New("attachment storage unavailable")
	// ErrRetentionActive: the commitment has not expired; nothing is deleted.
	ErrRetentionActive = errors.New("attachment retention is still active")
	// ErrRetentionBlocked: storage refused deletion (object lock, legal
	// hold, missing permission); an administrator must resolve it.
	ErrRetentionBlocked = errors.New("attachment deletion is blocked by storage")
	// ErrUnsupportedRecord: a stored record has an unknown version or shape.
	ErrUnsupportedRecord = errors.New("unsupported attachment storage record")
)

// Ref identifies an attachment's storage: the cluster identity and the
// EvidenceAttachment UID. Names never appear in storage keys.
type Ref struct {
	ClusterID string `json:"clusterID"`
	UID       string `json:"uid"`
}

var refPattern = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,128}$`)

// Validate checks that the identity is complete and key-safe.
func (r Ref) Validate() error {
	if !refPattern.MatchString(r.ClusterID) || !refPattern.MatchString(r.UID) {
		return fmt.Errorf("attachment storage identity %q/%q is invalid", r.ClusterID, r.UID)
	}
	return nil
}

// Principal is an authenticated Kubernetes identity.
type Principal struct {
	Username string `json:"username"`
	UID      string `json:"uid,omitempty"`
}

// Document is the registered identity of the bytes: "sha256:<hex>" and size.
type Document struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Sum returns the raw digest.
func (d Document) Sum() ([32]byte, error) {
	if !digestPattern.MatchString(d.SHA256) || d.Size < 1 {
		return [32]byte{}, fmt.Errorf("%w: document identity %q (%d bytes) is invalid", ErrIntegrity, d.SHA256, d.Size)
	}
	b, _ := hex.DecodeString(d.SHA256[len("sha256:"):])
	return [32]byte(b), nil
}

// StageRequest uploads one attempt. Body must hold exactly Document.Size
// bytes; it is read once to verify, rewound, and uploaded.
type StageRequest struct {
	Ref      Ref
	Document Document
	Uploader Principal
	Body     io.ReadSeeker
}

// Staged identifies a verified, uncommitted attempt.
type Staged struct {
	Ref       Ref
	AttemptID string
	Document  Document
	Uploader  Principal
}

// CommitRequest commits the newest verified attempt holding Document.
// SpecDigest, ValidUntil and Retention are recorded only by the first
// commitment; a retry with other values returns the original commitment.
type CommitRequest struct {
	Ref        Ref
	SpecDigest string
	Document   Document
	ValidUntil time.Time
	Retention  time.Duration
}

// Destination identifies where a commitment is stored.
type Destination struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix,omitempty"`
}

// Receipt is a durable commitment, derived from the stored manifest.
type Receipt struct {
	Ref               Ref
	Destination       Destination
	ManifestKey       string
	ManifestVersionID string
	DocumentKey       string
	DocumentVersionID string
	Document          Document
	SpecDigest        string
	Uploader          Principal
	CommittedAt       time.Time
	ValidUntil        time.Time
	Retention         time.Duration
	ExpiresAt         time.Time
}

// ExpiresAt is the fixed source expiry: max(committedAt, validUntil) +
// retention.
func ExpiresAt(committedAt, validUntil time.Time, retention time.Duration) time.Time {
	start := committedAt
	if validUntil.After(start) {
		start = validUntil
	}
	return start.Add(retention).UTC()
}

// ValidateRetention requires a positive whole-second retention.
func ValidateRetention(d time.Duration) error {
	if d <= 0 || d%time.Second != 0 {
		return fmt.Errorf("attachment retention %s must be a positive whole number of seconds", d)
	}
	return nil
}

// Validate checks a receipt's internal consistency.
func (r Receipt) Validate() error {
	var errs []error
	if err := r.Ref.Validate(); err != nil {
		errs = append(errs, err)
	}
	if _, err := r.Document.Sum(); err != nil {
		errs = append(errs, err)
	}
	if !digestPattern.MatchString(r.SpecDigest) {
		errs = append(errs, fmt.Errorf("spec digest %q is invalid", r.SpecDigest))
	}
	if r.Uploader.Username == "" {
		errs = append(errs, errors.New("uploader is missing"))
	}
	if r.ManifestKey == "" || r.DocumentKey == "" || r.Destination.ID == "" {
		errs = append(errs, errors.New("storage location is incomplete"))
	}
	if err := ValidateRetention(r.Retention); err != nil {
		errs = append(errs, err)
	}
	if r.CommittedAt.IsZero() || r.ValidUntil.IsZero() || !r.ExpiresAt.Equal(ExpiresAt(r.CommittedAt, r.ValidUntil, r.Retention)) {
		errs = append(errs, errors.New("commitment times are inconsistent"))
	}
	return errors.Join(errs...)
}

// CleanupState is the outcome of a cleanup attempt.
type CleanupState string

const (
	CleanupDeleted          CleanupState = "Deleted"
	CleanupDeletionFailed   CleanupState = "DeletionFailed"
	CleanupRetentionBlocked CleanupState = "RetentionBlocked"
)

// Cleanup reports a deletion of owned storage.
type Cleanup struct {
	State   CleanupState
	Message string
}

// Problem is a committed document's health failure.
type Problem struct {
	Reason  string
	Message string
}

// Health problem reasons.
const (
	ProblemMissing   = "ObjectMissing"
	ProblemIntegrity = "IntegrityFailed"
)

// Store is the attachment storage contract. Implementations never read
// caller-chosen keys: every key derives from the Ref and the destination.
type Store interface {
	// Destination identifies the store's destination.
	Destination() Destination
	// Stage verifies and uploads one attempt.
	Stage(ctx context.Context, req StageRequest) (Staged, error)
	// Commit creates the attachment's commitment once (see the package
	// comment); ErrNotFound means no verified attempt holds the document.
	Commit(ctx context.Context, req CommitRequest) (Receipt, error)
	// Committed returns the existing commitment, or ErrNotFound.
	Committed(ctx context.Context, ref Ref) (Receipt, error)
	// Open returns the committed document version. The caller verifies
	// size and digest while streaming.
	Open(ctx context.Context, r Receipt) (io.ReadCloser, error)
	// Health checks the committed document's presence, size and digest.
	Health(ctx context.Context, r Receipt) (*Problem, error)
	// CleanupAttempts removes owned, uncommitted attempts created before
	// olderThan, and incomplete multipart uploads under the attachment's
	// prefix initiated before it. The committed attempt is kept.
	CleanupAttempts(ctx context.Context, ref Ref, olderThan time.Time) error
	// DeleteUncommitted removes every owned attempt of an attachment that
	// has no commitment; it returns ErrConflict if one exists.
	DeleteUncommitted(ctx context.Context, ref Ref) (Cleanup, error)
	// Delete removes every owned object version of an expired commitment;
	// before ExpiresAt it returns ErrRetentionActive and deletes nothing.
	Delete(ctx context.Context, r Receipt, now time.Time) (Cleanup, error)
}

// SpecDigest is the "sha256:<hex>" of an attachment's immutable spec
// (including the admission-recorded registrant), as canonical JSON.
func SpecDigest(spec v1alpha1.EvidenceAttachmentSpec) string {
	b, _ := json.Marshal(spec)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Expected returns the registered document identity of a spec.
func Expected(spec v1alpha1.EvidenceAttachmentSpec) Document {
	return Document{SHA256: spec.Document.SHA256, Size: spec.Document.Size}
}
