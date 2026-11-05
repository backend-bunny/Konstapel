package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AssessmentRequestSpec asks for an assessment of the request's own namespace
// against a binding. The namespace is the request's maximum scope; the request
// cannot change binding settings, enforcement, eligibility, or cadence.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable; create a new AssessmentRequest"
type AssessmentRequestSpec struct {
	// bindingRef names the ComplianceBinding to assess this namespace against.
	// +required
	BindingRef BindingReference `json:"bindingRef"`

	// requester is the authenticated identity that created the request. The
	// konstapel-assessment-requester admission policy sets it from the API
	// server's user info on create; user-supplied values are overwritten and
	// mismatches are rejected.
	// +optional
	Requester *Requester `json:"requester,omitempty"`
}

// Requester is an authenticated Kubernetes user identity.
type Requester struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Username string `json:"username"`
	// +optional
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid,omitempty"`
}

// RequestPhase is an AssessmentRequest's lifecycle.
// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed;Rejected
type RequestPhase string

const (
	RequestPending   RequestPhase = "Pending"
	RequestRunning   RequestPhase = "Running"
	RequestCompleted RequestPhase = "Completed"
	RequestFailed    RequestPhase = "Failed"
	// RequestRejected means the binding did not select the namespace at
	// execution; no broader assessment is substituted.
	RequestRejected RequestPhase = "Rejected"
)

// AssessmentRequestStatus is controller-owned and team-visible. It holds a
// sanitized summary and an opaque artifact reference only: no full-binding
// inventory, storage location, credential, or reusable download token.
type AssessmentRequestStatus struct {
	// +optional
	Phase RequestPhase `json:"phase,omitempty"`
	// binding is the binding identity resolved for this request.
	// +optional
	Binding *ResolvedBinding `json:"binding,omitempty"`
	// namespaceUID is the request namespace's UID at resolution. Downloads
	// are bound to it, so a recreated namespace cannot read prior evidence.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	NamespaceUID string `json:"namespaceUID,omitempty"`
	// run identifies the internal scoped run executing this request.
	// +optional
	Run *RunReference `json:"run,omitempty"`
	// +optional
	Summary *AssessmentSummary `json:"summary,omitempty"`
	// artifactRef is an opaque handle to the committed package. It is not a
	// download capability; downloads authorize against this request.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	ArtifactRef string `json:"artifactRef,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AssessmentRequest is an application team's on-demand assessment of its
// namespace against a ComplianceBinding.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=areq
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Binding",type=string,JSONPath=`.spec.bindingRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Evidence",type=string,JSONPath=`.status.summary.evidence.completeness`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AssessmentRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec AssessmentRequestSpec `json:"spec"`
	// +optional
	Status AssessmentRequestStatus `json:"status,omitzero"`
}

// AssessmentRequestList contains a list of AssessmentRequest.
// +kubebuilder:object:root=true
type AssessmentRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AssessmentRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AssessmentRequest{}, &AssessmentRequestList{})
}
