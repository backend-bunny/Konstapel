package publication

import (
	"errors"
	"fmt"
	"time"
)

// Phase is the publication lifecycle, independent of evidence completeness
// and check outcomes. Only Committed denotes durable published output.
type Phase string

const (
	PhasePending   Phase = "Pending"
	PhaseUploading Phase = "Uploading"
	PhaseCommitted Phase = "Committed"
	PhaseFailed    Phase = "Failed"
	PhaseExpired   Phase = "Expired"
	PhaseDeleting  Phase = "Deleting"
	PhaseDeleted   Phase = "Deleted"
)

// Availability reports whether new authorized downloads can be served.
type Availability string

const (
	AvailabilityUnknown     Availability = "Unknown"
	AvailabilityAvailable   Availability = "Available"
	AvailabilityUnavailable Availability = "Unavailable"
	AvailabilityExpired     Availability = "Expired"
)

// CleanupState reports retention cleanup, which outlives bindings and requests.
type CleanupState string

const (
	CleanupNotDue           CleanupState = "NotDue"
	CleanupPending          CleanupState = "Pending"
	CleanupDeleted          CleanupState = "Deleted"
	CleanupDeletionFailed   CleanupState = "DeletionFailed"
	CleanupRetentionBlocked CleanupState = "RetentionBlocked"
)

// ObjectRole identifies an owned storage object's purpose.
type ObjectRole string

const (
	ObjectArchive  ObjectRole = "archive"
	ObjectManifest ObjectRole = "manifest"
	ObjectStaging  ObjectRole = "staging"
)

// Bounds keep status small; bulk data belongs in packages.
const (
	MaxOwnedObjects  = 32
	MaxMessageLength = 512
)

// SecretRef names a credential Secret. Status never holds credential values.
type SecretRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Destination snapshots where a publication was written so old publications
// remain addressable after the default destination changes.
type Destination struct {
	ID            string     `json:"id"`
	Endpoint      string     `json:"endpoint"`
	Bucket        string     `json:"bucket"`
	Prefix        string     `json:"prefix,omitempty"`
	CredentialRef *SecretRef `json:"credentialRef,omitempty"`
}

// OwnedObject is a storage object this publication owns and must clean up.
type OwnedObject struct {
	Role      ObjectRole `json:"role"`
	AttemptID string     `json:"attemptID,omitempty"`
	Key       string     `json:"key"`
	VersionID string     `json:"versionID,omitempty"`
	UploadID  string     `json:"uploadID,omitempty"`
}

// Commit is the fixed commit-manifest reference and the archive it selects.
type Commit struct {
	ManifestKey       string `json:"manifestKey"`
	ManifestVersionID string `json:"manifestVersionID,omitempty"`
	ArchiveKey        string `json:"archiveKey"`
	ArchiveVersionID  string `json:"archiveVersionID,omitempty"`
}

// Retention is the effective retention frozen at the first commit.
type Retention struct {
	// Duration is a positive Go/Kubernetes duration string such as "2160h".
	Duration string `json:"duration"`
	// BindingConfiguration is the binding revision the duration was read from.
	BindingConfiguration string    `json:"bindingConfiguration"`
	SelectedAt           time.Time `json:"selectedAt"`
}

// ParseDuration returns the positive retention duration.
func (r Retention) ParseDuration() (time.Duration, error) {
	d, err := time.ParseDuration(r.Duration)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("retention %q must be a positive duration", r.Duration)
	}
	return d, nil
}

// Cleanup is the retention cleanup record.
type Cleanup struct {
	State       CleanupState `json:"state"`
	Attempts    int          `json:"attempts,omitempty"`
	LastAttempt *time.Time   `json:"lastAttempt,omitempty"`
	Message     string       `json:"message,omitempty"`
}

// Failure is a sanitized publication failure. Messages must not contain
// credentials, tokens, or another scope's data.
type Failure struct {
	Reason    string    `json:"reason"`
	Message   string    `json:"message,omitempty"`
	Retryable bool      `json:"retryable"`
	At        time.Time `json:"at"`
}

// Receipt is a verified commit. Recovery after a lost response returns the
// same receipt, with dates derived from the commit rather than the retry clock.
type Receipt struct {
	PublicationID    string      `json:"publicationID"`
	Destination      Destination `json:"destination"`
	Commit           Commit      `json:"commit"`
	DescriptorSHA256 string      `json:"descriptorSha256"`
	PackageSHA256    string      `json:"packageSha256"`
	PackageSize      int64       `json:"packageSize"`
	PublishedAt      time.Time   `json:"publishedAt"`
	Retention        Retention   `json:"retention"`
	ExpiresAt        time.Time   `json:"expiresAt"`
}

// Validate checks receipt consistency, including expiresAt = publishedAt + retention.
func (r Receipt) Validate() error {
	d, err := r.Retention.ParseDuration()
	if err != nil {
		return err
	}
	if r.PublicationID == "" || r.Destination.ID == "" || r.Commit.ManifestKey == "" || r.Commit.ArchiveKey == "" {
		return errors.New("receipt requires publication, destination, and commit identities")
	}
	if !sha256Hex.MatchString(r.PackageSHA256) || !sha256Hex.MatchString(r.DescriptorSHA256) || r.PackageSize <= 0 {
		return errors.New("receipt requires package and descriptor SHA-256 and size")
	}
	if r.PublishedAt.IsZero() || !r.ExpiresAt.Equal(r.PublishedAt.Add(d)) {
		return errors.New("receipt expiry must equal publication time plus retention")
	}
	return nil
}

// Status is the run's publication status. It holds references and bounded
// state only, never package bytes, reports, or credential values.
type Status struct {
	Phase            Phase         `json:"phase"`
	PublicationID    string        `json:"publicationID"`
	Destination      *Destination  `json:"destination,omitempty"`
	OwnedObjects     []OwnedObject `json:"ownedObjects,omitempty"`
	DescriptorSHA256 string        `json:"descriptorSha256,omitempty"`
	PackageSHA256    string        `json:"packageSha256,omitempty"`
	PackageSize      int64         `json:"packageSize,omitempty"`
	Commit           *Commit       `json:"commit,omitempty"`
	PublishedAt      *time.Time    `json:"publishedAt,omitempty"`
	Retention        *Retention    `json:"retention,omitempty"`
	ExpiresAt        *time.Time    `json:"expiresAt,omitempty"`
	Availability     Availability  `json:"availability"`
	Cleanup          Cleanup       `json:"cleanup"`
	Failure          *Failure      `json:"failure,omitempty"`
}

// Failure reasons for a committed package that is not intact before its
// expiry. The assessment result is never rewritten; only availability is.
const (
	FailureObjectMissing   = "ObjectMissing"
	FailureIntegrityFailed = "IntegrityFailed"
)

// Committed returns the status for a verified receipt.
func Committed(r Receipt) Status {
	return Status{
		Phase: PhaseCommitted, PublicationID: r.PublicationID, Destination: &r.Destination,
		DescriptorSHA256: r.DescriptorSHA256, PackageSHA256: r.PackageSHA256, PackageSize: r.PackageSize,
		Commit: &r.Commit, PublishedAt: &r.PublishedAt, Retention: &r.Retention, ExpiresAt: &r.ExpiresAt,
		Availability: AvailabilityAvailable, Cleanup: Cleanup{State: CleanupNotDue},
	}
}

// Validate checks status bounds and phase invariants.
func (s Status) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.PublicationID == "" {
		fail("status requires publicationID")
	}
	if len(s.OwnedObjects) > MaxOwnedObjects {
		fail("status lists %d owned objects; limit is %d", len(s.OwnedObjects), MaxOwnedObjects)
	}
	if len(s.Cleanup.Message) > MaxMessageLength || (s.Failure != nil && len(s.Failure.Message) > MaxMessageLength) {
		fail("status messages are limited to %d bytes", MaxMessageLength)
	}
	switch s.Phase {
	case PhaseCommitted, PhaseExpired, PhaseDeleting, PhaseDeleted:
		if s.Commit == nil || s.PublishedAt == nil || s.Retention == nil || s.ExpiresAt == nil || s.Destination == nil {
			fail("%s publication requires its commit receipt", s.Phase)
			break
		}
		r := Receipt{PublicationID: s.PublicationID, Destination: *s.Destination, Commit: *s.Commit, DescriptorSHA256: s.DescriptorSHA256, PackageSHA256: s.PackageSHA256, PackageSize: s.PackageSize, PublishedAt: *s.PublishedAt, Retention: *s.Retention, ExpiresAt: *s.ExpiresAt}
		if err := r.Validate(); err != nil {
			errs = append(errs, err)
		}
	case PhasePending, PhaseUploading:
		if s.Commit != nil || s.PublishedAt != nil {
			fail("%s publication cannot record a commit", s.Phase)
		}
	case PhaseFailed:
		if s.Failure == nil || s.Commit != nil {
			fail("failed publication requires a failure and no commit")
		}
	default:
		fail("unknown publication phase %q", s.Phase)
	}
	if s.Availability == AvailabilityAvailable && s.Phase != PhaseCommitted {
		fail("only committed publications can be available")
	}
	return errors.Join(errs...)
}
