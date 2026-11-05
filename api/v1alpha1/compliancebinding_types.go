package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EnforcementMode is the admission behaviour of a binding's contributions.
// +kubebuilder:validation:Enum=Audit;Deny
type EnforcementMode string

const (
	// ModeAudit reports violations without rejecting admission.
	ModeAudit EnforcementMode = "Audit"
	// ModeDeny rejects admission of violating resources.
	ModeDeny EnforcementMode = "Deny"
)

// Condition types and reasons reported on ComplianceBinding status.
const (
	// ConditionResolved is True when the profile, content, and selector resolved.
	ConditionResolved = "Resolved"
	// ConditionEngineReady is True when every owned engine policy is ready at
	// the current configuration revision. It never asserts workload compliance.
	ConditionEngineReady = "EngineReady"

	ReasonProfileNotFound      = "ProfileNotFound"
	ReasonContentUnavailable   = "ContentUnavailable"
	ReasonUnknownPolicy        = "UnknownPolicy"
	ReasonUnsupportedScope     = "UnsupportedScope"
	ReasonInvalidSelector      = "InvalidSelector"
	ReasonInvalidConfiguration = "InvalidConfiguration"
	ReasonOwnershipConflict    = "OwnershipConflict"
	ReasonStaleRevision        = "StaleRevision"
	ReasonReplacementPending   = "ReplacementPending"
	ReasonResolutionSucceeded  = "Resolved"
)

// ProfileReference names a cluster-scoped ComplianceProfile.
type ProfileReference struct {
	// name of the ComplianceProfile.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ComplianceBindingSpec applies a profile to selected namespaces in one mode.
type ComplianceBindingSpec struct {
	// profileRef references the profile whose policies this binding contributes.
	// +required
	ProfileRef ProfileReference `json:"profileRef"`

	// namespaceSelector selects Namespaces by their labels with standard
	// Kubernetes LabelSelector semantics. It is required; an explicit empty
	// selector ({}) selects every namespace.
	// +required
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector"`

	// mode is Audit or Deny. It has no default.
	// +required
	Mode EnforcementMode `json:"mode"`
}

// ResolvedProfile records the profile revision a binding last resolved.
type ResolvedProfile struct {
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
	// bundleDigest is the pinned content digest of that profile revision.
	BundleDigest string `json:"bundleDigest"`
}

// ComplianceBindingStatus reports resolution and engine readiness separately.
// It does not report assessment outcomes.
type ComplianceBindingStatus struct {
	// observedGeneration is the binding generation last processed.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// profile is the profile revision last resolved.
	// +optional
	Profile *ResolvedProfile `json:"profile,omitempty"`

	// configurationRevision identifies the resolved enforcement configuration.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	ConfigurationRevision string `json:"configurationRevision,omitempty"`

	// targetCount is the number of matched namespaces. Absent means unknown;
	// zero is a valid resolved scope and never implies a compliance pass.
	// +optional
	TargetCount *int32 `json:"targetCount,omitempty"`

	// conditions report Resolved and EngineReady separately.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ComplianceBinding applies a ComplianceProfile to namespaces in Audit or Deny mode.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=cbinding
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profileRef.name`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Targets",type=integer,JSONPath=`.status.targetCount`
// +kubebuilder:printcolumn:name="Resolved",type=string,JSONPath=`.status.conditions[?(@.type=="Resolved")].status`
// +kubebuilder:printcolumn:name="EngineReady",type=string,JSONPath=`.status.conditions[?(@.type=="EngineReady")].status`
type ComplianceBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ComplianceBindingSpec `json:"spec"`
	// +optional
	Status ComplianceBindingStatus `json:"status,omitzero"`
}

// ComplianceBindingList contains a list of ComplianceBinding.
// +kubebuilder:object:root=true
type ComplianceBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceBinding{}, &ComplianceBindingList{})
}
