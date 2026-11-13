package publication

import (
	"context"
	"errors"
	"io"
)

// Errors returned by publishers. Storage errors never change evaluation
// outcomes; they are publication state only.
var (
	// ErrConflict means different bytes or a different commit already exist
	// under this run's identity. It is never permission to overwrite.
	ErrConflict = errors.New("publication conflict")
	// ErrCaptureLost means frozen package bytes were not durably staged and
	// cannot be recovered. The producer records CaptureLost on the run; a newer
	// assessment needs a new run identity.
	ErrCaptureLost = errors.New("capture lost before durable staging")
	// ErrUnavailable is a retryable backend failure or uncertain response.
	ErrUnavailable = errors.New("publication backend unavailable")
	// ErrNotFound means the publisher has no record of the run.
	ErrNotFound = errors.New("publication not found")
	// ErrRetentionActive means deletion was requested before recorded expiry.
	ErrRetentionActive = errors.New("publication retention has not expired")
	// ErrExpired reports that a publication's retention ended; it is no
	// longer served.
	ErrExpired = errors.New("publication expired")
	// ErrRetentionBlocked reports that storage refused deletion, for example
	// an object lock or a missing delete permission. Konstapel never bypasses
	// it; an administrator must resolve it.
	ErrRetentionBlocked = errors.New("storage refused deletion")
	// ErrOrphaned reports that the destination's storage responsibility was
	// handed to an operator: Konstapel issues no further remote operations
	// there and serves no downloads.
	ErrOrphaned = errors.New("evidence destination handed off to an operator")
	// ErrSignatureRequired means a Required signing intent has no stored,
	// verified signature for the staged archive, so nothing is committed.
	// It is never permission to commit unsigned.
	ErrSignatureRequired = errors.New("a verified signature is required before commit")
	// ErrUnsupportedRecord means a durable publication record has an
	// unknown kind, version, format, or field. It is never read as an
	// older (for example unsigned) record.
	ErrUnsupportedRecord = errors.New("unsupported publication record")
)

// SigningMode is a publication's frozen signing mode.
type SigningMode string

const (
	SigningDisabled SigningMode = "Disabled"
	SigningRequired SigningMode = "Required"
)

// Signing is the frozen signing intent a publication must satisfy. A nil
// *Signing is a Disabled intent.
type Signing struct {
	Mode SigningMode
	// PublicKeyPEM is the intent's pinned public key (Required). The
	// publisher verifies the stored signature with it before committing.
	PublicKeyPEM []byte
	// KeyFingerprint is the pinned key's fingerprint (Required).
	KeyFingerprint string
}

// StageRequest hands a frozen, validated package directory to the publisher.
type StageRequest struct {
	Run RunRef
	Dir string
}

// Staged identifies durably staged package bytes.
type Staged struct {
	Run              RunRef `json:"run"`
	PublicationID    string `json:"publicationID"`
	DescriptorSHA256 string `json:"descriptorSha256"`
	PackageSHA256    string `json:"packageSha256"`
	PackageSize      int64  `json:"packageSize"`
}

// PublishRequest commits staged bytes with the retention read from a
// consistent view of the binding.
type PublishRequest struct {
	Staged    Staged
	Retention Retention
	// Signing is the run's frozen signing intent; nil is Disabled. Under a
	// Required intent the publisher commits only a stored signature that
	// verifies with the pinned key, and never accepts an unsigned commit.
	Signing *Signing
}

// Publisher is the storage boundary. Every method is idempotent for a run:
// retries and new leaders converge on the same publication identity.
type Publisher interface {
	// Stage verifies the package directory against its descriptor and stages
	// its bytes durably. Restaging identical bytes returns the existing
	// staging; different bytes for the same run return ErrConflict.
	Stage(ctx context.Context, req StageRequest) (Staged, error)
	// Recover returns the run's durable staging without new bytes, or
	// ErrCaptureLost when bytes were lost before durable staging.
	Recover(ctx context.Context, run RunRef) (Staged, error)
	// Publish commits staged bytes once. If a matching commit exists, it
	// returns that receipt, including its originally selected retention.
	Publish(ctx context.Context, req PublishRequest) (Receipt, error)
	// Inspect reports current publication state.
	Inspect(ctx context.Context, run RunRef) (Status, error)
	// Delete removes owned objects after expiry and reports cleanup state.
	Delete(ctx context.Context, run RunRef) (Cleanup, error)
	// CleanupAttempts removes the run's uncommitted attempt data once the run
	// is terminal: every staged attempt except the committed one, and any
	// incomplete uploads. It never touches the commit or the committed
	// archive, and leaves anything whose ownership by this run cannot be
	// established. It is idempotent and safe to retry.
	CleanupAttempts(ctx context.Context, run RunRef) error
	// StoreSignature stores a run's signature bundle for the staged archive
	// once. The first durable bundle wins: if one exists, it is returned
	// unchanged and bundle is discarded. The caller verifies the returned
	// bytes before relying on them.
	StoreSignature(ctx context.Context, run RunRef, bundle []byte) ([]byte, Signature, error)
	// ReadSignature returns the run's stored signature bundle, or
	// ErrNotFound. It never needs a private key.
	ReadSignature(ctx context.Context, run RunRef) ([]byte, Signature, error)
	// Open returns the committed archive of a run with its committed status,
	// for a verified download. An uncommitted run is ErrNotFound, an expired
	// one ErrExpired, and a committed archive that cannot be read before
	// expiry ErrUnavailable. The caller verifies size and SHA-256 against the
	// returned status before serving any byte.
	Open(ctx context.Context, run RunRef) (io.ReadCloser, Status, error)
}
