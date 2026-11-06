package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceExceptionSpec is an application team's time-limited acceptance of
// risk for one logical policy and a workload scope in its own namespace.
//
// The policy and workload selector are fixed at creation; wider scope needs a
// new resource. Creation is acceptance revision 1. An explicit renewal
// increments acceptanceRevision by one and may change only the reason and
// expiry with it; any other change to the reason or expiry is rejected, so
// metadata edits and reconciliation cannot renew. Admission (identity, time,
// eligibility and lifetime checks) and the controller do the rest.
// +kubebuilder:validation:XValidation:rule="oldSelf.hasValue() || self.acceptanceRevision == 1",optionalOldSelf=true,message="a new exception starts at acceptanceRevision 1"
// +kubebuilder:validation:XValidation:rule="!oldSelf.hasValue() || self.acceptanceRevision == oldSelf.value().acceptanceRevision || self.acceptanceRevision == oldSelf.value().acceptanceRevision + 1",optionalOldSelf=true,message="a renewal increments acceptanceRevision by exactly one"
// +kubebuilder:validation:XValidation:rule="!oldSelf.hasValue() || self.acceptanceRevision != oldSelf.value().acceptanceRevision || (self.reason == oldSelf.value().reason && self.expiresAt == oldSelf.value().expiresAt)",optionalOldSelf=true,message="reason and expiresAt change only with an explicit renewal (acceptanceRevision + 1)"
type ComplianceExceptionSpec struct {
	// policy is the logical policy identity within the bundle, as used by
	// ComplianceProfile spec.policies[].name. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="policy is immutable; create a new ComplianceException"
	Policy string `json:"policy"`

	// workloadSelector selects the evaluated objects, in this namespace only,
	// by their own labels. It is required; an explicit {} selects every
	// applicable workload in the namespace. Controllers and their Pods are
	// distinct objects: label both when both need the exception. Immutable.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="workloadSelector is immutable; create a new ComplianceException"
	WorkloadSelector *metav1.LabelSelector `json:"workloadSelector"`

	// reason explains the accepted risk. It must not be blank.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="reason must not be blank"
	Reason string `json:"reason"`

	// expiresAt ends the acceptance. It must be in the future and within the
	// shortest applicable maxLifetime, checked at admission.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`

	// acceptanceRevision counts explicit acceptances: 1 at creation, plus one
	// for each renewal.
	// +required
	// +kubebuilder:validation:Minimum=1
	AcceptanceRevision int64 `json:"acceptanceRevision"`
}

// ComplianceExceptionStatus is written only by the Konstapel controller.
type ComplianceExceptionStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ComplianceException is a namespace team's self-service, time-limited
// exception from one eligible logical policy for selected workloads in its
// namespace.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=cexc
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.policy`
// +kubebuilder:printcolumn:name="Revision",type=integer,JSONPath=`.spec.acceptanceRevision`
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.spec.expiresAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ComplianceException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ComplianceExceptionSpec `json:"spec"`
	// +optional
	Status ComplianceExceptionStatus `json:"status,omitzero"`
}

// ComplianceExceptionList contains a list of ComplianceException.
// +kubebuilder:object:root=true
type ComplianceExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceException `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceException{}, &ComplianceExceptionList{})
}
