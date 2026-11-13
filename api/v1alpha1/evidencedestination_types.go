package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeletionPolicy selects what deleting an EvidenceDestination does.
// +kubebuilder:validation:Enum=Retire;Orphan
type DeletionPolicy string

const (
	// DeletionRetire keeps the destination, terminating, until every
	// accepted run, upload, retained package, and cleanup that needs it is
	// complete. It is the default.
	DeletionRetire DeletionPolicy = "Retire"
	// DeletionOrphan is the explicit administrative handoff of remaining
	// storage responsibility (audited; see the orphan handoff contract).
	DeletionOrphan DeletionPolicy = "Orphan"
)

// S3Addressing selects S3 request addressing.
// +kubebuilder:validation:Enum=path;virtual
type S3Addressing string

// ControllerNamespaceReference names an object in the controller's own
// namespace. It has no usable namespace: credentials and trust are never
// read from another namespace.
// +kubebuilder:validation:XValidation:rule="!has(self.__namespace__)",message="references resolve in the controller namespace only; namespace must not be set"
type ControllerNamespaceReference struct {
	// name of the object in the controller namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`

	// namespace is rejected when set; it exists so that a cross-namespace
	// reference is an explicit API error rather than a silently dropped field.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// S3CredentialSecret names a Secret in the controller namespace and its keys.
type S3CredentialSecret struct {
	ControllerNamespaceReference `json:",inline"`

	// accessKeyIDKey is the Secret data key of the access key ID.
	// +optional
	// +kubebuilder:default=accessKeyID
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	AccessKeyIDKey string `json:"accessKeyIDKey,omitempty"`

	// secretAccessKeyKey is the Secret data key of the secret access key.
	// +optional
	// +kubebuilder:default=secretAccessKey
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
}

// CATrust names a ConfigMap in the controller namespace holding PEM roots.
type CATrust struct {
	ControllerNamespaceReference `json:",inline"`

	// key is the ConfigMap data key holding PEM certificates.
	// +optional
	// +kubebuilder:default=ca.crt
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`
}

// S3Location is where evidence is stored. It is immutable: a new location
// needs a new EvidenceDestination and an explicit reference switch, so no
// edit ever moves existing evidence. Credentials and trust can rotate.
// +kubebuilder:validation:XValidation:rule="self.endpoint == oldSelf.endpoint && self.bucket == oldSelf.bucket && self.region == oldSelf.region && has(self.prefix) == has(oldSelf.prefix) && (!has(self.prefix) || self.prefix == oldSelf.prefix)",message="endpoint, bucket, region, and prefix are immutable; create a new EvidenceDestination for a new location"
// +kubebuilder:validation:XValidation:rule="(has(self.workloadIdentity) && self.workloadIdentity) != has(self.credentialSecret)",message="set exactly one credential source: workloadIdentity or credentialSecret"
// +kubebuilder:validation:XValidation:rule="self.endpoint.startsWith('https://') || (has(self.developmentFixture) && self.developmentFixture && self.endpoint.startsWith('http://'))",message="endpoint must be https; plain http is allowed only for an isolated developmentFixture"
type S3Location struct {
	// endpoint is the S3 service URL. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=8
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^\s/?#@]+(:[0-9]+)?/?$`
	Endpoint string `json:"endpoint"`

	// bucket must already exist; Konstapel never creates or reconfigures it.
	// Immutable.
	// +required
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`
	Bucket string `json:"bucket"`

	// region of the bucket. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+$`
	Region string `json:"region"`

	// prefix is a clean relative key prefix; Konstapel writes only below it.
	// Immutable.
	// +optional
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!_.*'()-]+(/[A-Za-z0-9!_.*'()-]+)*$`
	// +kubebuilder:validation:XValidation:rule="!self.matches('(^|/)[.]{1,2}(/|$)')",message="prefix must not contain . or .. segments"
	Prefix string `json:"prefix,omitempty"`

	// addressing selects path-style or virtual-hosted requests.
	// +optional
	// +kubebuilder:default=path
	Addressing S3Addressing `json:"addressing,omitempty"`

	// workloadIdentity uses the SDK's standard credential chain.
	// +optional
	WorkloadIdentity bool `json:"workloadIdentity,omitempty"`

	// credentialSecret names the credential Secret in the controller
	// namespace. Rotatable, including while the destination is retiring.
	// +optional
	CredentialSecret *S3CredentialSecret `json:"credentialSecret,omitempty"`

	// caTrust names extra trusted PEM roots in the controller namespace.
	// TLS verification is never disabled. Rotatable.
	// +optional
	CATrust *CATrust `json:"caTrust,omitempty"`

	// developmentFixture permits a plain-http endpoint for an explicitly
	// isolated local test service.
	// +optional
	DevelopmentFixture bool `json:"developmentFixture,omitempty"`
}

// OrphanRequest is an administrator's explicit request to hand the
// destination's remaining storage responsibility to an operator instead of
// retiring it. The reason is supplied by the administrator; actor and
// actorUID are recorded by admission from the authenticated request and
// cannot be forged.
type OrphanRequest struct {
	// reason explains the handoff. It must not be blank.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="reason must not be blank"
	Reason string `json:"reason"`
	// actor is the authenticated user who set or changed the request,
	// written by the konstapel-destination-orphan admission policy.
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Actor string `json:"actor,omitempty"`
	// actorUID is that user's UID when the authenticator provides one.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	ActorUID string `json:"actorUID,omitempty"`
}

// EvidenceDestinationSpec is platform-managed storage for evidence packages.
// +kubebuilder:validation:XValidation:rule="self.deletionPolicy != 'Orphan' || has(self.orphan)",message="deletionPolicy Orphan requires orphan.reason"
// +kubebuilder:validation:XValidation:rule="!has(self.orphan) || self.deletionPolicy == 'Orphan'",message="orphan is set only with deletionPolicy Orphan"
// +kubebuilder:validation:XValidation:rule="has(self.legacy) == has(oldSelf.legacy) && (!has(self.legacy) || self.legacy == oldSelf.legacy)",message="legacy is set only when the destination is created and is immutable"
type EvidenceDestinationSpec struct {
	// s3 is the S3-compatible location and its access.
	// +required
	S3 S3Location `json:"s3"`

	// deletionPolicy is what deleting this destination does. Retire (the
	// default) keeps it until its outstanding obligations finish; Orphan is
	// the explicit, audited handoff. Setting it alone deletes nothing.
	// +optional
	// +kubebuilder:default=Retire
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// orphan is required with deletionPolicy Orphan. Selecting Orphan
	// changes nothing until the destination is deleted; once that handoff is
	// accepted (status.orphanIntent) it cannot be changed or reversed.
	// +optional
	Orphan *OrphanRequest `json:"orphan,omitempty"`

	// legacy declares that this destination continues a legacy
	// file-configured destination (the removed --evidence-destination file).
	// Runs published there before destinations existed are attached to this
	// destination only after their recorded location is verified against
	// it and against the preserved legacy configuration. It is set only when
	// the destination is created and never changes.
	// +optional
	Legacy *LegacyDestination `json:"legacy,omitempty"`

	// signing governs signatures of evidence published to this destination.
	// Absent means Disabled. Bindings and requests inherit it and cannot
	// override it. It can change at any time; a change applies to
	// publication intents prepared afterwards.
	// +optional
	Signing *EvidenceSigning `json:"signing,omitempty"`
}

// SigningMode selects whether evidence published to a destination is signed.
// +kubebuilder:validation:Enum=Disabled;Required
type SigningMode string

const (
	// SigningDisabled publishes unsigned evidence. It is the default.
	SigningDisabled SigningMode = "Disabled"
	// SigningRequired publishes evidence only with a verified signature from
	// the referenced key; there is no unsigned fallback.
	SigningRequired SigningMode = "Required"
)

// EvidenceSigning is a destination's signing policy. Only operator-provided
// Kubernetes Secret keys are supported: secretRef names a Secret in the
// controller namespace with cosign.key, cosign.pub, and cosign.password
// (docs/integration/evidence-signing.md).
// +kubebuilder:validation:XValidation:rule="self.mode != 'Required' || has(self.secretRef)",message="signing mode Required needs secretRef naming the signing key Secret in the controller namespace"
// +kubebuilder:validation:XValidation:rule="self.mode == 'Required' || !has(self.secretRef)",message="secretRef is set only with signing mode Required"
// +kubebuilder:validation:XValidation:rule="!has(self.kms)",message="KMS signing keys are not supported; use secretRef"
// +kubebuilder:validation:XValidation:rule="!has(self.keyless)",message="keyless signing is not supported; use secretRef"
type EvidenceSigning struct {
	// mode is Disabled (the default) or Required.
	// +optional
	// +kubebuilder:default=Disabled
	Mode SigningMode `json:"mode,omitempty"`

	// secretRef names the signing key Secret in the controller namespace.
	// Required only with mode Required. Rotate by referencing a new Secret.
	// +optional
	SecretRef *ControllerNamespaceReference `json:"secretRef,omitempty"`

	// kms is rejected when set: remote signing keys are not supported yet.
	// It exists so that the request is an explicit API error rather than a
	// silently dropped field.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=object
	KMS *runtime.RawExtension `json:"kms,omitempty"`

	// keyless is rejected when set: keyless (Fulcio) signing is not
	// supported. It exists for the same reason as kms.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=object
	Keyless *runtime.RawExtension `json:"keyless,omitempty"`
}

// LegacyDestination identifies the legacy file-configured destination a
// destination continues, and where its preserved configuration is kept.
type LegacyDestination struct {
	// destinationID is the legacy destination's id, as recorded in the
	// receipts of runs it published.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	DestinationID string `json:"destinationID"`
	// configuration is a ConfigMap in the controller namespace holding the
	// preserved legacy destination file under key. Fields that receipts do
	// not record (the region) are verified against it; nothing is taken
	// from current defaults.
	// +required
	Configuration LegacyConfiguration `json:"configuration"`
}

// LegacyConfiguration references the preserved legacy destination file.
type LegacyConfiguration struct {
	ControllerNamespaceReference `json:",inline"`
	// key is the ConfigMap data key holding the destination YAML.
	// +optional
	// +kubebuilder:default=destination.yaml
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`
}

// OrphanIntent is the accepted orphan handoff, recorded by the controller
// when a destination with deletionPolicy Orphan is deleted. It is protected:
// only the controller writes status, and admission then freezes the spec.
type OrphanIntent struct {
	// reason, actor, and actorUID are copied from the accepted spec.orphan.
	// +required
	// +kubebuilder:validation:MaxLength=1024
	Reason string `json:"reason"`
	// +required
	// +kubebuilder:validation:MaxLength=512
	Actor string `json:"actor"`
	// +optional
	// +kubebuilder:validation:MaxLength=128
	ActorUID string `json:"actorUID,omitempty"`
	// acceptedAt is when the controller accepted the handoff.
	// +required
	AcceptedAt metav1.Time `json:"acceptedAt"`
}

// Condition types and reasons reported on EvidenceDestination status.
const (
	// ConditionDestinationReady is True when the backend passed the
	// compatibility probe with the current credentials and trust.
	ConditionDestinationReady = "Ready"
	// ConditionDestinationRetiring is True while a deleted destination
	// finishes its outstanding obligations.
	ConditionDestinationRetiring = "Retiring"
	// ConditionDestinationSigningReady reports whether the signing policy can
	// be satisfied for new publication intents. It is advisory and set only
	// when spec.signing is present: True for Disabled, or for Required when
	// the referenced key loads and matches; False otherwise. It never
	// affects Ready, historical downloads, retention, or retirement.
	ConditionDestinationSigningReady = "SigningReady"
)

// SigningReady reasons. The set is fixed; messages never contain key
// material.
const (
	SigningReasonDisabled         = "SigningDisabled"
	SigningReasonKeyLoaded        = "KeyLoaded"
	SigningReasonSecretNotFound   = "SecretNotFound"
	SigningReasonSecretUnreadable = "SecretUnreadable"
	SigningReasonKeyUnavailable   = "KeyUnavailable"
	SigningReasonKeyMalformed     = "KeyMalformed"
	SigningReasonKeyPassword      = "KeyPasswordInvalid"
	SigningReasonKeyMismatch      = "KeyMismatch"
	SigningReasonUnsupportedKey   = "UnsupportedKey"
)

// SigningStatus is the controller's latest observation of a destination's
// signing policy and key. It is advisory: publication rereads the policy
// and the Secret when it records a signing intent.
type SigningStatus struct {
	// mode is the observed spec.signing.mode.
	// +required
	Mode SigningMode `json:"mode"`
	// secretName is the referenced Secret (Required only).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	SecretName string `json:"secretName,omitempty"`
	// keyFingerprint identifies the loaded public key: "sha256:" and the hex
	// SHA-256 of its DER SubjectPublicKeyInfo. Set only while the key loads.
	// +optional
	// +kubebuilder:validation:MaxLength=71
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
	// algorithm of the loaded key (ecdsa-sha2-256-nistp256).
	// +optional
	// +kubebuilder:validation:MaxLength=64
	Algorithm string `json:"algorithm,omitempty"`
}

// OrphanHandoff reports how storage work was fenced for an accepted orphan
// handoff. Cancelling local work never reverses a remote write or deletion;
// operations that were already dispatched have unknown remote outcomes.
type OrphanHandoff struct {
	// fencedAt is when the controller stopped issuing storage operations.
	// +required
	FencedAt metav1.Time `json:"fencedAt"`
	// drained is true when no local operation was still in flight after the
	// bounded wait.
	// +required
	Drained bool `json:"drained"`
	// uncertainOperations are local operations still in flight when the
	// wait ended; their remote outcome is unknown.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=256
	UncertainOperations []string `json:"uncertainOperations,omitempty"`
	// inventory is the durable ownership inventory, once fully saved.
	// +optional
	Inventory *OrphanInventoryRef `json:"inventory,omitempty"`
}

// OrphanInventoryRef locates a saved orphan inventory: immutable ConfigMaps
// in the controller namespace, independent of any destination, run, binding,
// or request, kept until a platform administrator removes them.
type OrphanInventoryRef struct {
	// header is the ConfigMap holding the handoff identity and chunk digests;
	// it is written last, so its presence means the inventory is complete.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Header string `json:"header"`
	// chunks is the number of run-list ConfigMaps.
	// +required
	// +kubebuilder:validation:Minimum=0
	Chunks int32 `json:"chunks"`
	// runs is the number of runs recorded.
	// +required
	// +kubebuilder:validation:Minimum=0
	Runs int32 `json:"runs"`
	// savedAt is when the header was saved.
	// +required
	SavedAt metav1.Time `json:"savedAt"`
}

// EvidenceDestinationStatus is written by the controller only.
type EvidenceDestinationStatus struct {
	// observedGeneration is the spec generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// outstandingRuns counts accepted runs pinned to this destination that
	// have not finished publication.
	// +optional
	// +kubebuilder:validation:Minimum=0
	OutstandingRuns int32 `json:"outstandingRuns,omitempty"`

	// outstandingPackages counts retained packages not yet deleted.
	// +optional
	// +kubebuilder:validation:Minimum=0
	OutstandingPackages int32 `json:"outstandingPackages,omitempty"`

	// unknownExpiryRuns counts outstanding runs whose expiry is not yet
	// known because they have not committed. It is not zero outstanding work.
	// +optional
	// +kubebuilder:validation:Minimum=0
	UnknownExpiryRuns int32 `json:"unknownExpiryRuns,omitempty"`

	// latestRetainedExpiry is the latest known expiry of a retained package.
	// +optional
	LatestRetainedExpiry *metav1.Time `json:"latestRetainedExpiry,omitempty"`

	// cleanupBlockers are bounded descriptions of what blocks retirement.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=512
	CleanupBlockers []string `json:"cleanupBlockers,omitempty"`

	// orphanIntent is the accepted, irreversible orphan handoff.
	// +optional
	OrphanIntent *OrphanIntent `json:"orphanIntent,omitempty"`

	// orphanHandoff reports the work fence after an accepted handoff.
	// +optional
	OrphanHandoff *OrphanHandoff `json:"orphanHandoff,omitempty"`

	// signing is the observed signing policy and key identity; absent when
	// spec.signing is absent.
	// +optional
	Signing *SigningStatus `json:"signing,omitempty"`

	// conditions report readiness, signing readiness, and retirement.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DestinationReference identifies an EvidenceDestination by name and UID. A
// destination recreated with the same name has a new UID and is never
// resolved through an old reference.
type DestinationReference struct {
	// name of the EvidenceDestination.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
	// uid of the EvidenceDestination.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	UID string `json:"uid"`
}

// DestinationSource says where a binding's destination selection came from.
// +kubebuilder:validation:Enum=Binding;Default;None;Migrated
type DestinationSource string

const (
	DestinationFromBinding DestinationSource = "Binding"
	DestinationFromDefault DestinationSource = "Default"
	DestinationNone        DestinationSource = "None"
	// DestinationMigrated marks a run published by a legacy file-configured
	// destination and attached to an EvidenceDestination by verified
	// migration.
	DestinationMigrated DestinationSource = "Migrated"
)

// Destination selection reasons on a binding's status.assessment.destination.
const (
	ReasonDestinationSelected    = "Selected"
	ReasonNoDefaultDestination   = "NoDefaultDestination"
	ReasonInvalidDefault         = "InvalidDefaultDestination"
	ReasonDestinationNotFound    = "DestinationNotFound"
	ReasonDestinationUIDMismatch = "DestinationUIDMismatch"
	ReasonDestinationRetiring    = "DestinationRetiring"
	ReasonDestinationNotReady    = "DestinationNotReady"
)

// DestinationSelection is the binding's resolved evidence destination. It is
// evidence readiness only and never affects enforcement (EngineReady).
type DestinationSelection struct {
	// source is Binding (spec.assessment.destinationRef), Default (the central
	// default), or None (no selection configured).
	// +required
	Source DestinationSource `json:"source"`
	// ref is the selected destination.
	// +optional
	Ref *DestinationReference `json:"ref,omitempty"`
	// ready is true only when the referenced destination exists with the
	// same UID, is not retiring, and its backend is Ready.
	// +required
	Ready bool `json:"ready"`
	// reason is Selected or why the selection cannot be used. There is never
	// a fallback to another destination.
	// +required
	// +kubebuilder:validation:MaxLength=64
	Reason string `json:"reason"`
	// message explains the reason.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
}

// DestinationPin is the destination a run accepted when it started. The run
// stages, publishes, retries, serves downloads, and cleans up there for its
// whole life, whatever later selection edits say. It holds no credentials.
type DestinationPin struct {
	DestinationReference `json:",inline"`
	// endpoint, bucket, region, and prefix snapshot the pinned location.
	// +required
	// +kubebuilder:validation:MaxLength=2048
	Endpoint string `json:"endpoint"`
	// +required
	// +kubebuilder:validation:MaxLength=63
	Bucket string `json:"bucket"`
	// +required
	// +kubebuilder:validation:MaxLength=64
	Region string `json:"region"`
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Prefix string `json:"prefix,omitempty"`
	// source is where the selection came from (Binding or Default), or
	// Migrated for a verified legacy run.
	// +required
	Source DestinationSource `json:"source"`
	// pinnedAt is when the pin was accepted.
	// +required
	PinnedAt metav1.Time `json:"pinnedAt"`
	// legacy is the verified association of a migrated run: its legacy
	// destination ID. With the location above it governs every later
	// storage operation; the destination's spec only expressed intent.
	// +optional
	Legacy *LegacyPin `json:"legacy,omitempty"`
	// orphanedAt is when the run's storage responsibility passed to an
	// operator with its destination's orphan handoff. Konstapel issues no
	// storage operation for the run afterwards.
	// +optional
	OrphanedAt *metav1.Time `json:"orphanedAt,omitempty"`
}

// LegacyPin records a verified legacy migration.
type LegacyPin struct {
	// destinationID is the legacy destination ID from the run's receipt.
	// +required
	// +kubebuilder:validation:MaxLength=63
	DestinationID string `json:"destinationID"`
	// verifiedAt is when the receipt, the preserved legacy configuration,
	// and the destination were found to name the same location.
	// +required
	VerifiedAt metav1.Time `json:"verifiedAt"`
}

// EvidenceDestination is a cluster-scoped, platform-managed evidence storage
// location. Runs pin it by name and UID when they start; later edits to the
// default or a binding's selection affect only subsequent runs.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=evdest
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Bucket",type=string,JSONPath=`.spec.s3.bucket`
// +kubebuilder:printcolumn:name="Prefix",type=string,JSONPath=`.spec.s3.prefix`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Signing",type=string,JSONPath=`.spec.signing.mode`,priority=1
// +kubebuilder:printcolumn:name="Deletion",type=string,JSONPath=`.spec.deletionPolicy`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EvidenceDestination struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EvidenceDestinationSpec `json:"spec"`
	// +optional
	Status EvidenceDestinationStatus `json:"status,omitempty,omitzero"`
}

// EvidenceDestinationList contains a list of EvidenceDestination.
// +kubebuilder:object:root=true
type EvidenceDestinationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidenceDestination `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EvidenceDestination{}, &EvidenceDestinationList{})
}
