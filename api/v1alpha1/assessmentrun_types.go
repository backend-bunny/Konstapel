package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RunScope distinguishes platform full-binding runs from namespace runs.
// +kubebuilder:validation:Enum=Binding;Namespace
type RunScope string

const (
	// RunScopeBinding assesses every namespace the binding selects. It stays
	// platform-scoped even if the binding selects a single namespace.
	RunScopeBinding RunScope = "Binding"
	// RunScopeNamespace assesses one AssessmentRequest's namespace. Only the
	// controller creates these runs.
	RunScopeNamespace RunScope = "Namespace"
)

// TriggerType records what caused a run.
// +kubebuilder:validation:Enum=Scheduled;Manual;Request
type TriggerType string

const (
	TriggerScheduled TriggerType = "Scheduled"
	TriggerManual    TriggerType = "Manual"
	TriggerRequest   TriggerType = "Request"
)

// RequestReference identifies the AssessmentRequest a namespace run serves.
// It is not an owner reference: a cluster-scoped run cannot be owned by a
// namespaced request, and request deletion does not cancel retained cleanup.
type RequestReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// RunTrigger is the trigger identity. Scheduled triggers are identified by
// their due time, so retries and leader changes cannot duplicate them.
// +kubebuilder:validation:XValidation:rule="self.type == 'Scheduled' ? has(self.scheduledTime) : !has(self.scheduledTime)",message="scheduledTime is required for and only allowed on Scheduled triggers"
type RunTrigger struct {
	// +required
	Type TriggerType `json:"type"`
	// scheduledTime is the due time this scheduled run serves.
	// +optional
	ScheduledTime *metav1.Time `json:"scheduledTime,omitempty"`
}

// AssessmentRunSpec is immutable. Platform operators may create Binding-scope
// runs; Namespace-scope runs, request references, and Scheduled/Request
// triggers are controller-owned and enforced by admission policy.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
// +kubebuilder:validation:XValidation:rule="self.scope == 'Namespace' ? has(self.request) : !has(self.request)",message="request is required for and only allowed on Namespace scope"
// +kubebuilder:validation:XValidation:rule="(self.scope == 'Namespace') == (has(self.trigger) && self.trigger.type == 'Request')",message="Namespace scope requires a Request trigger, and Request triggers require Namespace scope"
type AssessmentRunSpec struct {
	// bindingRef names the ComplianceBinding to assess.
	// +required
	BindingRef BindingReference `json:"bindingRef"`
	// scope is Binding or Namespace. It has no default.
	// +required
	Scope RunScope `json:"scope"`
	// request identifies the AssessmentRequest a Namespace run serves.
	// +optional
	Request *RequestReference `json:"request,omitempty"`
	// trigger records what caused the run; absent means Manual.
	// +optional
	Trigger *RunTrigger `json:"trigger,omitempty"`
}

// RunPhase is an AssessmentRun's lifecycle. Evidence completeness, outcomes,
// and publication state are reported separately.
// +kubebuilder:validation:Enum=Pending;Collecting;Exporting;Publishing;Completed;Failed
type RunPhase string

const (
	RunPending    RunPhase = "Pending"
	RunCollecting RunPhase = "Collecting"
	RunExporting  RunPhase = "Exporting"
	RunPublishing RunPhase = "Publishing"
	RunCompleted  RunPhase = "Completed"
	RunFailed     RunPhase = "Failed"
)

// FrozenScope summarizes the scope frozen at run start. The full inventory
// lives in the package, not in status.
type FrozenScope struct {
	// +kubebuilder:validation:MaxLength=253
	ClusterID string `json:"clusterID"`
	// namespaceUID is set for Namespace scope only.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	NamespaceUID string `json:"namespaceUID,omitempty"`
	// +kubebuilder:validation:Minimum=0
	NamespaceCount int32 `json:"namespaceCount"`
	// +kubebuilder:validation:MaxLength=128
	Revision string `json:"revision"`
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	SHA256 string `json:"sha256"`
}

// CaptureWindow is the bounded observation window.
type CaptureWindow struct {
	Started metav1.Time `json:"started"`
	// +optional
	Closed *metav1.Time `json:"closed,omitempty"`
}

// AssessmentRunStatus holds controller-resolved fields. Only the controller
// can write status; users cannot set resolved scope, captured data, or
// publication state.
type AssessmentRunStatus struct {
	// +optional
	Phase RunPhase `json:"phase,omitempty"`
	// +optional
	Binding *ResolvedBinding `json:"binding,omitempty"`
	// bindingConfiguration is the binding configuration revision captured.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	BindingConfiguration string `json:"bindingConfiguration,omitempty"`
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=128
	EnforcementRevisions []string `json:"enforcementRevisions,omitempty"`
	// +optional
	Scope *FrozenScope `json:"scope,omitempty"`
	// +optional
	Window *CaptureWindow `json:"window,omitempty"`
	// +optional
	Summary *AssessmentSummary `json:"summary,omitempty"`
	// retention is the binding's retention resolved when collection closed.
	// Publication uses the binding's current retention while it is the same
	// binding, and this recorded value if the binding was deleted or replaced.
	// +optional
	Retention Duration `json:"retention,omitempty"`
	// descriptorSha256 is the digest of the frozen package descriptor.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	DescriptorSHA256 string `json:"descriptorSha256,omitempty"`
	// +optional
	Publication *PublicationStatus `json:"publication,omitempty"`
	// destination is the evidence destination pinned when the run started.
	// Absent for runs that use the controller's legacy file destination.
	// +optional
	Destination *DestinationPin `json:"destination,omitempty"`
	// signingIntent is the signing policy frozen when publication was first
	// prepared. It is written once and never removed; publication commits
	// only what it requires. Absent for runs prepared before evidence
	// signing existed (unsigned).
	// +optional
	SigningIntent *SigningIntent `json:"signingIntent,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AssessmentRun is a durable assessment record. It is protected and
// cluster-scoped: application teams can neither create nor read runs.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=arun
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Binding",type=string,JSONPath=`.spec.bindingRef.name`
// +kubebuilder:printcolumn:name="Scope",type=string,JSONPath=`.spec.scope`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Evidence",type=string,JSONPath=`.status.summary.evidence.completeness`
// +kubebuilder:printcolumn:name="Publication",type=string,JSONPath=`.status.publication.phase`
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.status) || !has(oldSelf.status.signingIntent) || (has(self.status) && has(self.status.signingIntent))",message="status.signingIntent is never removed"
type AssessmentRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec AssessmentRunSpec `json:"spec"`
	// +optional
	Status AssessmentRunStatus `json:"status,omitzero"`
}

// AssessmentRunList contains a list of AssessmentRun.
// +kubebuilder:object:root=true
type AssessmentRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AssessmentRun `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AssessmentRun{}, &AssessmentRunList{})
}

// SigningIntent is a run's frozen publication signing policy (see
// docs/integration/evidence-signing.md). The controller records it once from
// an authoritative read of the pinned destination, after the archive is
// staged and before any commit attempt. Later destination edits and key
// rotation never change it.
// +kubebuilder:validation:XValidation:rule="self.mode == oldSelf.mode && self.destinationUID == oldSelf.destinationUID && self.destinationGeneration == oldSelf.destinationGeneration && self.archiveSha256 == oldSelf.archiveSha256 && self.preparedAt == oldSelf.preparedAt",message="a signing intent is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.secretName) == has(oldSelf.secretName) && (!has(self.secretName) || self.secretName == oldSelf.secretName)",message="a signing intent's key Secret is immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.key) || (has(self.key) && self.key == oldSelf.key)",message="a signing intent's pinned key is set once and never changes"
// +kubebuilder:validation:XValidation:rule="self.mode == 'Required' ? has(self.secretName) : (!has(self.secretName) && !has(self.key))",message="Required intents name their key Secret; Disabled intents have no key"
type SigningIntent struct {
	// mode is Disabled or Required, from the destination's spec.signing
	// (absent is Disabled).
	// +required
	Mode SigningMode `json:"mode"`
	// destinationUID and destinationGeneration identify the destination
	// configuration the policy was read from.
	// +required
	// +kubebuilder:validation:MaxLength=64
	DestinationUID string `json:"destinationUID"`
	// +required
	// +kubebuilder:validation:Minimum=0
	DestinationGeneration int64 `json:"destinationGeneration"`
	// secretName is the signing key Secret in the controller namespace
	// (Required only).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	SecretName string `json:"secretName,omitempty"`
	// key is the public identity pinned at the first successful key load.
	// A Required intent prepared while its key was unavailable has none
	// until then; any later load must yield this same key.
	// +optional
	Key *SigningKey `json:"key,omitempty"`
	// archiveSha256 is the digest of the staged archive the intent covers.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	ArchiveSHA256 string `json:"archiveSha256"`
	// preparedAt is when the intent was recorded.
	// +required
	PreparedAt metav1.Time `json:"preparedAt"`
}

// SigningKey is public signing key material and its provenance. It never
// holds private key bytes or the key password.
type SigningKey struct {
	// fingerprint is "sha256:" and the hex SHA-256 of the DER
	// SubjectPublicKeyInfo.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Fingerprint string `json:"fingerprint"`
	// algorithm is the key's signing algorithm (ecdsa-sha2-256-nistp256).
	// +required
	// +kubebuilder:validation:MaxLength=64
	Algorithm string `json:"algorithm"`
	// publicKey is the PEM public key, retained to verify the signature.
	// +required
	// +kubebuilder:validation:MaxLength=4096
	PublicKey string `json:"publicKey"`
	// secretUID and secretResourceVersion record which Secret object the key
	// was first read from (provenance only).
	// +optional
	// +kubebuilder:validation:MaxLength=64
	SecretUID string `json:"secretUID,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=64
	SecretResourceVersion string `json:"secretResourceVersion,omitempty"`
	// pinnedAt is when the key was pinned.
	// +required
	PinnedAt metav1.Time `json:"pinnedAt"`
}
