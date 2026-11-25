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
	// ConditionAttemptsCleaned is True once a terminal run's uncommitted
	// storage attempts have been removed. The committed package is kept.
	ConditionAttemptsCleaned = "AttemptsCleaned"

	ReasonBindingNotFound     = "BindingNotFound"
	ReasonNamespaceNotInScope = "NamespaceNotInScope"
	ReasonCaptureLost         = "CaptureLost"
	ReasonPublicationFailed   = "PublicationFailed"
	// ReasonPublicationRetrying marks a Published=False run whose current
	// publication attempt failed and is retried within the publish timeout.
	ReasonPublicationRetrying = "Retrying"
	ReasonCleanupPending      = "CleanupPending"
	ReasonCleaned             = "Cleaned"
	// ReasonDestinationOrphaned ends a run whose destination was handed off
	// to an operator before its publication committed.
	ReasonDestinationOrphaned = "DestinationOrphaned"
	// ReasonSigningPending: the run's Required signing intent is not yet
	// satisfied (key unavailable or signature not yet stored); publication
	// retries within the publish timeout and never commits unsigned.
	ReasonSigningPending = "SigningPending"
	// ReasonSigningFailed ends a run whose Required signing intent could not
	// be satisfied within the publish timeout. Evidence and outcomes are
	// unchanged; nothing unsigned was committed.
	ReasonSigningFailed = "SigningFailed"
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
	// staleScopes counts bindings or policies whose configuration did not
	// resolve; any stale scope makes evidence Incomplete.
	// +optional
	// +kubebuilder:validation:Minimum=0
	StaleScopes int32 `json:"staleScopes,omitempty"`
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
	// oldestEvaluation is the source evaluation time of the oldest
	// attributable observation: when the engine evaluated it, never a
	// collection, upload or report-update time. Absent when no observation
	// is attributable, and on summaries recorded before this field existed.
	// +optional
	OldestEvaluation *metav1.Time `json:"oldestEvaluation,omitempty"`
	// coverage summarizes the control coverage report (coverage.json) the
	// run's package carries. Absent when the package carries none (a run
	// exported before coverage existed, or whose coverage was left out),
	// and never a substitute for the evidence and outcomes above.
	// +optional
	Coverage *CoverageSummary `json:"coverage,omitempty"`
}

// CoverageEvidenceState is a coverage report's technical-evidence state.
// +kubebuilder:validation:Enum=resolved;unresolved;notProvided
type CoverageEvidenceState string

// CoverageSummary is the bounded status summary of one control coverage
// report (docs/control-coverage.md). It counts the selected baseline's
// controls by automation state; no count is a satisfaction or pass count,
// and the per-control rows, findings and observations stay in the package.
// It mirrors internal/publication.CoverageSummary.
type CoverageSummary struct {
	// asOf is the report's closure time: the capture's, never a read time.
	AsOf metav1.Time `json:"asOf"`
	// sha256 is the lowercase hex sha256 of the package's
	// coverage.json, as its descriptor inventories it.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	SHA256 string `json:"sha256"`
	// inputsSha256 identifies what the report assessed: the binding UID,
	// the scope's namespace UIDs and the profile selection (bundle,
	// policies, parameters) frozen when the run started. Absent when that
	// selection was not recorded.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	InputsSHA256 string `json:"inputsSha256,omitempty"`
	// bundle is the content the baseline was read from; absent when the
	// scope selected no profile.
	// +optional
	Bundle *BundleReference `json:"bundle,omitempty"`
	// inventoryResolved is true only when the selected baseline resolved.
	// An unresolved inventory lists no controls (never a guessed list).
	InventoryResolved bool `json:"inventoryResolved"`
	// mappingsResolved is true only when the authored mappings resolved.
	MappingsResolved bool `json:"mappingsResolved"`
	// controls counts the selected controls including enhancements.
	// +kubebuilder:validation:Minimum=0
	Controls int32 `json:"controls"`
	// +kubebuilder:validation:Minimum=0
	Enhancements int32 `json:"enhancements"`
	// automation counts controls by technical coverage state.
	Automation CoverageAutomationCounts `json:"automation"`
	// technicalEvidence is whether the run's evaluated capture was joined
	// to the controls; the evidence counts are the run's own.
	TechnicalEvidence CoverageEvidenceState `json:"technicalEvidence"`
	// validUntil is when the oldest attributable observation the report
	// counts exceeds the binding's maxEvidenceAge, as the run evaluated it
	// at closure. Absent when no observation is attributable. It never
	// changes the report, which stays evaluated at asOf.
	// +optional
	ValidUntil *metav1.Time `json:"validUntil,omitempty"`
	// limitations counts every report and control-row limitation.
	// +kubebuilder:validation:Minimum=0
	Limitations int32 `json:"limitations"`
	// blockingCodes are the distinct codes of blocking limitations, in
	// code order; at most eight are listed, the report has them all.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=64
	BlockingCodes []string `json:"blockingCodes,omitempty"`
}

// CoverageAutomationCounts counts controls by automation state. There is
// deliberately no "full" or satisfied state.
type CoverageAutomationCounts struct {
	// +kubebuilder:validation:Minimum=0
	None int32 `json:"none"`
	// +kubebuilder:validation:Minimum=0
	Unselected int32 `json:"unselected"`
	// +kubebuilder:validation:Minimum=0
	Partial int32 `json:"partial"`
	// +kubebuilder:validation:Minimum=0
	Unknown int32 `json:"unknown"`
}

// PublicationPhase is the publication lifecycle. Only Committed denotes
// durable published output.
// +kubebuilder:validation:Enum=Pending;Uploading;Committed;Failed;Expired;Deleting;Deleted;Orphaned
type PublicationPhase string

// Availability reports whether new authorized downloads can be served.
// +kubebuilder:validation:Enum=Unknown;Available;Unavailable;Expired
type Availability string

// CleanupState reports retention cleanup.
// +kubebuilder:validation:Enum=NotDue;Pending;Deleted;DeletionFailed;RetentionBlocked;Orphaned
type CleanupState string

// ObjectRole identifies an owned storage object's purpose.
// +kubebuilder:validation:Enum=archive;manifest;staging;signature
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
	// notAfter bounds the expiry of a signed publication committed by
	// signing recovery: it is the expiry recorded when signing failed, so a
	// late commit never extends retention. expiresAt is then notAfter, never
	// after publishedAt + duration. It is absent on every other publication.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
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
	// signature is the committed detached signature; set only for a
	// publication committed under a Required signing intent.
	// +optional
	Signature *PublicationSignature `json:"signature,omitempty"`
}

// PublicationSignature references a committed publication's signature
// bundle (package.sigstore.json) and the key that made it.
type PublicationSignature struct {
	// +kubebuilder:validation:MaxLength=1024
	Key string `json:"key"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	VersionID string `json:"versionID,omitempty"`
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	SHA256 string `json:"sha256"`
	// +kubebuilder:validation:Minimum=1
	Size int64 `json:"size"`
	// +kubebuilder:validation:MaxLength=128
	MediaType string `json:"mediaType"`
	// +kubebuilder:validation:MaxLength=64
	Algorithm string `json:"algorithm"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	KeyFingerprint string `json:"keyFingerprint"`
}
