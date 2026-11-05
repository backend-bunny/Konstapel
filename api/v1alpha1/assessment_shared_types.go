package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types reported on AssessmentRequest and AssessmentRun status.
const (
	// ConditionScoped is True when a request's namespace is selected by the
	// referenced binding at execution time.
	ConditionScoped = "Scoped"
	// ConditionEvidenceComplete is True only when every expected check is
	// attributable. It never asserts compliance.
	ConditionEvidenceComplete = "EvidenceComplete"
	// ConditionPublished is True only after a verified storage commit.
	ConditionPublished = "Published"

	ReasonBindingNotFound     = "BindingNotFound"
	ReasonNamespaceNotInScope = "NamespaceNotInScope"
	ReasonCaptureLost         = "CaptureLost"
	ReasonPublicationFailed   = "PublicationFailed"
)

// BindingReference names a cluster-scoped ComplianceBinding.
type BindingReference struct {
	// name of the ComplianceBinding.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ResolvedBinding records the binding identity a request or run resolved.
// A binding recreated under the same name has a different UID and is never
// adopted.
type ResolvedBinding struct {
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// RunReference identifies an AssessmentRun.
type RunReference struct {
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// EvidenceCompleteness describes evidence coverage only, never outcomes.
// +kubebuilder:validation:Enum=Complete;Incomplete;NoTargets
type EvidenceCompleteness string

// ExportState records whether a run produced assessment OSCAL.
// +kubebuilder:validation:Enum=Assessment;Diagnostic;CaptureLost
type ExportState string

// EvidenceSummary counts expected checks by evidence state.
type EvidenceSummary struct {
	Completeness EvidenceCompleteness `json:"completeness"`
	// +kubebuilder:validation:Minimum=0
	Expected int32 `json:"expected"`
	// +kubebuilder:validation:Minimum=0
	Attributable int32 `json:"attributable"`
	// +kubebuilder:validation:Minimum=0
	Missing int32 `json:"missing"`
	// +kubebuilder:validation:Minimum=0
	Rejected int32 `json:"rejected"`
	// +kubebuilder:validation:Minimum=0
	Unresolved int32 `json:"unresolved"`
}

// OutcomeCounts preserves check dispositions separately from completeness.
// It deliberately has no aggregate pass field.
type OutcomeCounts struct {
	// +kubebuilder:validation:Minimum=0
	Pass int32 `json:"pass"`
	// +kubebuilder:validation:Minimum=0
	Fail int32 `json:"fail"`
	// +kubebuilder:validation:Minimum=0
	Error int32 `json:"error"`
	// +kubebuilder:validation:Minimum=0
	Skip int32 `json:"skip"`
	// +kubebuilder:validation:Minimum=0
	AcceptedRisk int32 `json:"acceptedRisk"`
	// +kubebuilder:validation:Minimum=0
	NotApplicable int32 `json:"notApplicable"`
	// +kubebuilder:validation:Minimum=0
	Unknown int32 `json:"unknown"`
}

// AssessmentSummary is the sanitized result summary exposed in status. It
// contains no inventory, storage location, credential, or sibling data.
type AssessmentSummary struct {
	Evidence EvidenceSummary `json:"evidence"`
	Outcomes OutcomeCounts   `json:"outcomes"`
	Export   ExportState     `json:"export"`
}

// PublicationPhase is the publication lifecycle. Only Committed denotes
// durable published output.
// +kubebuilder:validation:Enum=Pending;Uploading;Committed;Failed;Expired;Deleting;Deleted
type PublicationPhase string

// Availability reports whether new authorized downloads can be served.
// +kubebuilder:validation:Enum=Unknown;Available;Unavailable;Expired
type Availability string

// CleanupState reports retention cleanup.
// +kubebuilder:validation:Enum=NotDue;Pending;Deleted;DeletionFailed;RetentionBlocked
type CleanupState string

// ObjectRole identifies an owned storage object's purpose.
// +kubebuilder:validation:Enum=archive;manifest;staging
type ObjectRole string

// SecretReference names a credential Secret; status never holds its value.
type SecretReference struct {
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// PublicationDestination snapshots where a publication was written.
type PublicationDestination struct {
	// +kubebuilder:validation:MaxLength=253
	ID string `json:"id"`
	// +kubebuilder:validation:MaxLength=2048
	Endpoint string `json:"endpoint"`
	// +kubebuilder:validation:MaxLength=255
	Bucket string `json:"bucket"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Prefix string `json:"prefix,omitempty"`
	// +optional
	CredentialRef *SecretReference `json:"credentialRef,omitempty"`
}

// OwnedObject is a storage object a publication owns and must clean up.
type OwnedObject struct {
	Role ObjectRole `json:"role"`
	// +optional
	// +kubebuilder:validation:MaxLength=128
	AttemptID string `json:"attemptID,omitempty"`
	// +kubebuilder:validation:MaxLength=1024
	Key string `json:"key"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	VersionID string `json:"versionID,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	UploadID string `json:"uploadID,omitempty"`
}

// PublicationCommit is the fixed commit-manifest reference and its archive.
type PublicationCommit struct {
	// +kubebuilder:validation:MaxLength=1024
	ManifestKey string `json:"manifestKey"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	ManifestVersionID string `json:"manifestVersionID,omitempty"`
	// +kubebuilder:validation:MaxLength=1024
	ArchiveKey string `json:"archiveKey"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	ArchiveVersionID string `json:"archiveVersionID,omitempty"`
}

// PublicationRetention is the effective retention frozen at first commit.
type PublicationRetention struct {
	// duration is a positive duration string such as "2160h".
	// +kubebuilder:validation:MaxLength=64
	Duration string `json:"duration"`
	// bindingConfiguration is the binding revision the duration was read from.
	// +kubebuilder:validation:MaxLength=128
	BindingConfiguration string      `json:"bindingConfiguration"`
	SelectedAt           metav1.Time `json:"selectedAt"`
}

// PublicationCleanup is the retention cleanup record.
type PublicationCleanup struct {
	State CleanupState `json:"state"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	Attempts int32 `json:"attempts,omitempty"`
	// +optional
	LastAttempt *metav1.Time `json:"lastAttempt,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Message string `json:"message,omitempty"`
}

// PublicationFailure is a sanitized publication failure.
type PublicationFailure struct {
	// +kubebuilder:validation:MaxLength=128
	Reason string `json:"reason"`
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Message   string      `json:"message,omitempty"`
	Retryable bool        `json:"retryable"`
	At        metav1.Time `json:"at"`
}

// PublicationStatus is the run's publication record. It mirrors
// internal/publication.Status; publication.ToAPI/FromAPI convert between them.
type PublicationStatus struct {
	Phase PublicationPhase `json:"phase"`
	// +kubebuilder:validation:MaxLength=64
	PublicationID string `json:"publicationID"`
	// +optional
	Destination *PublicationDestination `json:"destination,omitempty"`
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	OwnedObjects []OwnedObject `json:"ownedObjects,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	DescriptorSHA256 string `json:"descriptorSha256,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	PackageSHA256 string `json:"packageSha256,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	PackageSize int64 `json:"packageSize,omitempty"`
	// +optional
	Commit *PublicationCommit `json:"commit,omitempty"`
	// +optional
	PublishedAt *metav1.Time `json:"publishedAt,omitempty"`
	// +optional
	Retention *PublicationRetention `json:"retention,omitempty"`
	// +optional
	ExpiresAt    *metav1.Time       `json:"expiresAt,omitempty"`
	Availability Availability       `json:"availability"`
	Cleanup      PublicationCleanup `json:"cleanup"`
	// +optional
	Failure *PublicationFailure `json:"failure,omitempty"`
}
