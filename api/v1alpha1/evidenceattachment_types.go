package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EvidenceAttachmentFinalizer keeps a deleted EvidenceAttachment, and the
// ownership metadata of its stored document, until owned source cleanup is
// confirmed. Deletion withdraws the record from new current evidence at
// once; it never shortens a recorded storage commitment.
const EvidenceAttachmentFinalizer = "compliance.erenius.io/evidence-attachment-retention"

// Condition types and reasons on EvidenceAttachment.
const (
	// ConditionAssociationsValid is True when every association references
	// the current identity of an existing binding whose resolved catalog and
	// selected baseline contain the referenced controls and statements. It
	// never asserts that a control is satisfied.
	ConditionAssociationsValid = "AssociationsValid"

	ReasonAssociationsValid   = "Valid"
	ReasonAssociationMismatch = "AssociationMismatch"
	ReasonAssociationPending  = "AssociationPending"
	// ReasonWithdrawn: the record is being deleted and no longer
	// contributes to new current evidence.
	ReasonWithdrawn = "Withdrawn"
)

// Per-association reasons (ReasonBindingNotFound is shared with assessments).
const (
	ReasonBindingReplaced       = "BindingReplaced"
	ReasonBindingUnresolved     = "BindingUnresolved"
	ReasonBaselineUnavailable   = "BaselineUnavailable"
	ReasonCatalogMismatch       = "CatalogMismatch"
	ReasonControlNotInBaseline  = "ControlNotInBaseline"
	ReasonStatementNotInControl = "StatementNotInControl"
)

// EvidenceAttachmentSpec registers one immutable supporting document. Every
// field is evidence-defining and fixed at creation: a corrected document,
// period, catalog mapping, or added binding is a new EvidenceAttachment
// (and a new upload); the old record can be withdrawn by deleting it.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable; register a new EvidenceAttachment"
// +kubebuilder:validation:XValidation:rule="self.associations.all(a, self.associations.exists_one(b, b.binding.uid == a.binding.uid))",message="each binding UID may be associated only once"
type EvidenceAttachmentSpec struct {
	// document identifies the bytes the platform will upload: its declared
	// title and media type, and the exact size and SHA-256 the transfer
	// service verifies before the document becomes available.
	// +required
	Document AttachmentDocument `json:"document"`

	// source declares where the document came from. It is a platform claim,
	// not an identity Konstapel authenticates; its url is informational and
	// is never fetched.
	// +required
	Source AttachmentSource `json:"source"`

	// validity is the declared documentary coverage period,
	// validFrom <= T < validUntil. Upload or copy time never changes it.
	// +required
	Validity AttachmentValidity `json:"validity"`

	// associations name the exact local bindings, the catalog each was
	// registered against, and the controls (and optionally statements) the
	// document supports. The controller validates them against each
	// binding's current resolved catalog and selected baseline before they
	// apply; a recreated binding or changed catalog never inherits them.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Associations []AttachmentAssociation `json:"associations"`

	// scope is the platform's description of the facility or system the
	// document covers. It is a declaration; Konstapel does not verify it.
	// +required
	Scope AttachmentScope `json:"scope"`

	// registeredBy is the authenticated identity that created the record.
	// The konstapel-evidence-attachment-registrant admission policy sets it
	// from the API server's user info on create; user-supplied values are
	// overwritten and mismatches are rejected. The actual uploader is
	// recorded separately by the transfer service.
	// +optional
	RegisteredBy *Requester `json:"registeredBy,omitempty"`
}

// AttachmentDocument is the declared identity of the document bytes.
type AttachmentDocument struct {
	// title is a human-readable name for the document.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="title must not be blank"
	Title string `json:"title"`

	// mediaType is descriptive only (lowercase type/subtype, no
	// parameters); downloads are always served as passive attachments.
	// +required
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`
	MediaType string `json:"mediaType"`

	// size is the exact byte length of the document. The transfer
	// service's configured limit (32 MiB by default) applies on upload;
	// 1 GiB is the API's absolute ceiling.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1073741824
	Size int64 `json:"size"`

	// sha256 is the document's content digest, "sha256:<64 hex>".
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SHA256 string `json:"sha256"`
}

// AttachmentSource is the declared provenance of a document.
type AttachmentSource struct {
	// issuer describes who issued the document, for example an audit firm
	// or datacenter operator. It is not an authenticated identity.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="issuer must not be blank"
	Issuer string `json:"issuer"`

	// url is optional informational provenance. Konstapel never fetches it
	// and never treats it as a storage location.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^\s]+$`
	URL string `json:"url,omitempty"`
}

// AttachmentValidity is a half-open declared validity window.
// +kubebuilder:validation:XValidation:rule="timestamp(self.validFrom) < timestamp(self.validUntil)",message="validFrom must be before validUntil"
type AttachmentValidity struct {
	// validFrom is the first instant the document declares coverage for
	// (RFC 3339).
	// +required
	ValidFrom metav1.Time `json:"validFrom"`
	// validUntil is the first instant the document no longer covers
	// (RFC 3339).
	// +required
	ValidUntil metav1.Time `json:"validUntil"`
}

// AttachmentAssociation links the document to controls of one exact local
// binding.
type AttachmentAssociation struct {
	// binding is the exact binding identity, name and UID.
	// +required
	Binding ExactBindingReference `json:"binding"`

	// catalogDigest is the sha256 of the OSCAL catalog file the binding
	// resolved when the association was registered, "sha256:<64 hex>". A
	// catalog revision change stops the association.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	CatalogDigest string `json:"catalogDigest"`

	// controls are the selected-baseline controls the document supports.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=id
	Controls []AttachmentControl `json:"controls"`
}

// ExactBindingReference names a ComplianceBinding and the UID it must have.
type ExactBindingReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// AttachmentControl is one catalog control and optional statement parts.
type AttachmentControl struct {
	// id is the catalog control identifier, for example "pe-3" or "ac-2.1".
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_.-]*$`
	ID string `json:"id"`

	// statements optionally narrow the support to statement parts of this
	// control, for example "pe-3_smt.a".
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=128
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z_][A-Za-z0-9_.-]*$`
	Statements []string `json:"statements,omitempty"`
}

// AttachmentScope is the platform's declared document scope.
type AttachmentScope struct {
	// description explains the facility or system covered.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="description must not be blank"
	Description string `json:"description"`
}

// AssociationState is the controller's current view of one association.
// +kubebuilder:validation:Enum=Pending;Valid;Mismatched
type AssociationState string

const (
	// AssociationPending: the binding or its baseline cannot be resolved
	// yet; the association does not apply.
	AssociationPending AssociationState = "Pending"
	// AssociationValid: the association applies to the binding's current
	// identity, catalog and selected baseline.
	AssociationValid AssociationState = "Valid"
	// AssociationMismatched: the binding was replaced, its catalog changed,
	// or a control/statement is not part of its selected baseline.
	AssociationMismatched AssociationState = "Mismatched"
)

// AttachmentAssociationStatus is the resolution of one spec association.
type AttachmentAssociationStatus struct {
	// binding is the association's binding reference, as registered.
	// +required
	Binding ExactBindingReference `json:"binding"`
	// +required
	State AssociationState `json:"state"`
	// +required
	// +kubebuilder:validation:MaxLength=64
	Reason string `json:"reason"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
	// observedCatalogDigest is the catalog digest the binding currently
	// resolves, when known.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ObservedCatalogDigest string `json:"observedCatalogDigest,omitempty"`
}

// Storage conditions and reasons on EvidenceAttachment.
const (
	// ConditionDocumentCommitted is True once the document's storage
	// commitment is recorded in status.storage.commitment. It attests
	// storage and integrity only, never the truth of the document.
	ConditionDocumentCommitted = "DocumentCommitted"

	ReasonCommitted = "Committed"
	// ReasonAwaitingUpload: a destination is pinned and no commitment exists.
	ReasonAwaitingUpload = "AwaitingUpload"
	// ReasonNoDestination: no destination could be pinned (none configured,
	// replaced, retiring or not ready); nothing is stored elsewhere.
	ReasonNoDestination = "NoDestination"
	// ReasonStorageUnavailable: the pinned destination could not be read.
	ReasonStorageUnavailable = "StorageUnavailable"
	// ReasonStorageConflict: storage holds a commitment that does not match
	// this record's spec; it is never recorded.
	ReasonStorageConflict = "StorageConflict"

	// ConditionSourceRetained reports a withdrawn record's retention: True
	// while its committed source is retained until expiry, then False with
	// the cleanup outcome.
	ConditionSourceRetained = "SourceRetained"
	ReasonRetentionActive   = "RetentionActive"
	ReasonCleanupFailed     = "CleanupFailed"
	ReasonCleanupBlocked    = "CleanupBlocked"
)

// LabelAttachmentDestination records an attachment's pinned destination UID.
// The controller writes it before confirming the pin, so the destination's
// obligations never miss an attachment; it is never changed afterwards.
const LabelAttachmentDestination = "compliance.erenius.io/attachment-destination-uid"

// AttachmentStorage is the attachment's durable storage ownership: where its
// document is (or will be) stored, the first storage commitment, and the
// cleanup of withdrawn storage. The pin and the commitment never change once
// recorded.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.destination) || (has(self.destination) && self.destination == oldSelf.destination)",message="the pinned destination never changes"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.commitment) || (has(self.commitment) && self.commitment == oldSelf.commitment)",message="a recorded commitment never changes"
type AttachmentStorage struct {
	// destination is the EvidenceDestination pinned for this document,
	// selected once from the central default. A later default never
	// relocates it; credentials and trust rotate through the destination.
	// +optional
	Destination *DestinationReference `json:"destination,omitempty"`
	// destinationID is the storage destination identity recorded with the
	// commitment.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	DestinationID string `json:"destinationID,omitempty"`
	// +optional
	PinnedAt *metav1.Time `json:"pinnedAt,omitempty"`
	// +optional
	Commitment *AttachmentCommitment `json:"commitment,omitempty"`
	// +optional
	Cleanup *AttachmentCleanup `json:"cleanup,omitempty"`
}

// AttachmentCommitment is the first storage commitment of the document. It
// is read from the stored commit manifest and never changes.
type AttachmentCommitment struct {
	// +required
	// +kubebuilder:validation:MaxLength=1024
	ManifestKey string `json:"manifestKey"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	ManifestVersionID string `json:"manifestVersionID,omitempty"`
	// +required
	// +kubebuilder:validation:MaxLength=1024
	DocumentKey string `json:"documentKey"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	DocumentVersionID string `json:"documentVersionID,omitempty"`
	// sha256 and size are the committed document's, equal to spec.document.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SHA256 string `json:"sha256"`
	// +required
	// +kubebuilder:validation:Minimum=1
	Size int64 `json:"size"`
	// specDigest is the sha256 of the immutable spec the commitment binds.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	SpecDigest string `json:"specDigest"`
	// uploader is the authenticated principal whose verified upload was
	// committed, as recorded by the transfer service. It may differ from
	// spec.registeredBy and from the declared spec.source.
	// +required
	Uploader Requester `json:"uploader"`
	// committedAt is the storage server's time of the commit manifest.
	// +required
	CommittedAt metav1.Time `json:"committedAt"`
	// retention is the central retention frozen at commitment.
	// +required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=duration
	Retention metav1.Duration `json:"retention"`
	// expiresAt is max(committedAt, spec.validity.validUntil) + retention,
	// fixed at commitment. Source cleanup never happens before it.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// AttachmentCleanup reports cleanup of a withdrawn record's owned storage.
type AttachmentCleanup struct {
	// +required
	// +kubebuilder:validation:Enum=NotDue;Deleted;DeletionFailed;RetentionBlocked
	State string `json:"state"`
	// +optional
	LastAttempt *metav1.Time `json:"lastAttempt,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
}

// EvidenceAttachmentStatus is written only by the Konstapel controller. It
// never holds document bytes or credentials; storage keys are owned,
// UID-derived and opaque.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.storage) || has(self.storage)",message="storage ownership is never removed"
type EvidenceAttachmentStatus struct {
	// observedGeneration is the generation last processed.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// associations report each spec association, in spec order.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	Associations []AttachmentAssociationStatus `json:"associations,omitempty"`
	// storage is the document's durable storage ownership.
	// +optional
	Storage *AttachmentStorage `json:"storage,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EvidenceAttachment is a platform-managed supporting document for selected
// controls of explicitly named bindings. It is supporting material only: it
// records no control verdict and never changes technical outcomes.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=eattach
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Title",type=string,JSONPath=`.spec.document.title`
// +kubebuilder:printcolumn:name="Valid From",type=string,JSONPath=`.spec.validity.validFrom`
// +kubebuilder:printcolumn:name="Valid Until",type=string,JSONPath=`.spec.validity.validUntil`
// +kubebuilder:printcolumn:name="Associations",type=string,JSONPath=`.status.conditions[?(@.type=="AssociationsValid")].status`
// +kubebuilder:printcolumn:name="Committed",type=string,JSONPath=`.status.conditions[?(@.type=="DocumentCommitted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EvidenceAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EvidenceAttachmentSpec `json:"spec"`
	// +optional
	Status EvidenceAttachmentStatus `json:"status,omitzero"`
}

// EvidenceAttachmentList contains a list of EvidenceAttachment.
// +kubebuilder:object:root=true
type EvidenceAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidenceAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EvidenceAttachment{}, &EvidenceAttachmentList{})
}
