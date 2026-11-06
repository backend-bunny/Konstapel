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
