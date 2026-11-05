package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExceptionEligibility states whether namespace teams may request exceptions
// for a policy contribution.
// +kubebuilder:validation:Enum=Forbidden;SelfService
type ExceptionEligibility string

const (
	// ExceptionsForbidden never allows self-service exceptions. It is the default.
	ExceptionsForbidden ExceptionEligibility = "Forbidden"
	// ExceptionsSelfService allows time-bounded self-service exceptions.
	ExceptionsSelfService ExceptionEligibility = "SelfService"
)

// BundleReference pins immutable bundle content by digest.
type BundleReference struct {
	// name identifies the bundle, for example "linux-workload-hardening".
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`

	// digest is the sha256 digest of the bundle content.
	// +required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	Digest string `json:"digest"`
}

// ExceptionSettings configures exception eligibility for one logical policy.
// +kubebuilder:validation:XValidation:rule="self.eligibility == 'SelfService' ? has(self.maxLifetime) && self.maxLifetime > duration('0s') : !has(self.maxLifetime)",message="SelfService requires a positive maxLifetime; Forbidden must not set maxLifetime"
type ExceptionSettings struct {
	// eligibility defaults to Forbidden.
	// +optional
	// +kubebuilder:default=Forbidden
	Eligibility ExceptionEligibility `json:"eligibility,omitempty"`

	// maxLifetime bounds a self-service exception, for example "720h".
	// +optional
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=duration
	MaxLifetime *metav1.Duration `json:"maxLifetime,omitempty"`
}

// ProfilePolicy selects one logical policy from the bundle and configures it.
type ProfilePolicy struct {
	// name is the logical policy identity within the bundle.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`

	// parameters are policy-specific settings validated against the bundle
	// once its content resolves.
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	Parameters *apiextensionsv1.JSON `json:"parameters,omitempty"`

	// exceptions configures exception eligibility; it defaults to Forbidden.
	// +optional
	// +kubebuilder:default={eligibility: Forbidden}
	Exceptions ExceptionSettings `json:"exceptions,omitzero"`
}

// ComplianceProfileSpec is reusable, centrally administered content configuration.
type ComplianceProfileSpec struct {
	// bundle pins the content this profile selects policies from.
	// +required
	Bundle BundleReference `json:"bundle"`

	// policies lists the selected logical policies.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Policies []ProfilePolicy `json:"policies"`
}

// ComplianceProfileStatus reports resolution of the pinned content.
type ComplianceProfileStatus struct {
	// observedGeneration is the generation last processed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions report content resolution. They never assert compliance.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ComplianceProfile identifies pinned bundle content and logical policy settings.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=cprofile
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Bundle",type=string,JSONPath=`.spec.bundle.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ComplianceProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ComplianceProfileSpec `json:"spec"`
	// +optional
	Status ComplianceProfileStatus `json:"status,omitzero"`
}

// ComplianceProfileList contains a list of ComplianceProfile.
// +kubebuilder:object:root=true
type ComplianceProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceProfile{}, &ComplianceProfileList{})
}
