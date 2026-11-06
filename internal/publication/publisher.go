package publication

import (
	"context"
	"errors"
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
)

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
}
