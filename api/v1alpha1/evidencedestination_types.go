package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// EvidenceDestinationSpec is platform-managed storage for evidence packages.
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
}

// Condition types and reasons reported on EvidenceDestination status.
const (
	// ConditionDestinationReady is True when the backend passed the
	// compatibility probe with the current credentials and trust.
	ConditionDestinationReady = "Ready"
	// ConditionDestinationRetiring is True while a deleted destination
	// finishes its outstanding obligations.
	ConditionDestinationRetiring = "Retiring"
)

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

	// conditions report readiness and retirement.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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
