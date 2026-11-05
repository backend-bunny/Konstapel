package v1alpha1

// Duration is a positive Kubernetes/Go duration string such as "24h" or
// "2160h". Days ("90d"), cron expressions, zero, negative, and values that
// overflow a duration are rejected.
// +kubebuilder:validation:MinLength=2
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+(\\\\.[0-9]+)?(ns|us|ms|s|m|h))+$')",message="must be a duration such as 24h, 90m or 2160h; days, cron expressions and signs are not supported"
// +kubebuilder:validation:XValidation:rule="!self.matches('^([0-9]+(\\\\.[0-9]+)?(ns|us|ms|s|m|h))+$') || duration(self) > duration('0s')",message="must be a positive duration"
type Duration string

// BindingAssessment configures continuous assessment of a binding. Changing
// it is a reporting-only edit: it never changes the enforcement epoch, engine
// policy identities, or accepted exceptions. An explicit null is equivalent to
// omitting a setting: the API server prunes it and applies the default (CEL
// cannot distinguish null from an absent field), so null is never stored.
type BindingAssessment struct {
	// interval between scheduled snapshots, measured from a persisted anchor.
	// +optional
	// +kubebuilder:default="24h"
	Interval Duration `json:"interval,omitempty"`
	// maxEvidenceAge is the oldest source evaluation accepted as current
	// evidence at snapshot closure.
	// +optional
	// +kubebuilder:default="2h"
	MaxEvidenceAge Duration `json:"maxEvidenceAge,omitempty"`
	// collectionTimeout bounds how long a run waits for evidence.
	// +optional
	// +kubebuilder:default="5m"
	CollectionTimeout Duration `json:"collectionTimeout,omitempty"`
	// retention is how long published packages are kept, fixed at
	// publication. 90 days is 2160h.
	// +optional
	// +kubebuilder:default="2160h"
	Retention Duration `json:"retention,omitempty"`
}
