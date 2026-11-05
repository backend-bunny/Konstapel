// Package targeting resolves ComplianceProfiles and ComplianceBindings into
// namespace-scoped policy contributions and exception eligibility.
//
// The types in this file are the shared contract. add-self-service-policy-exceptions
// consumes Eligibility and Contribution revisions. add-continuous-assessments
// consumes Contribution identities and supplies the binding enforcement epoch
// through EnforcementInput.BindingEpoch. Dependent changes may read these types,
// but must not redefine them.
package targeting

import (
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// ContractVersion versions the serialized contract and the revision algorithm.
const ContractVersion = 1

// ObjectRevision identifies one observed revision of a Kubernetes object.
type ObjectRevision struct {
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
}

// NamespaceRef identifies a namespace instance. A recreated namespace has a new UID.
type NamespaceRef struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid"`
}

// Contribution is one binding's enforcement of one logical policy. Overlapping
// contributions are never merged: each is delivered and evaluated under its
// own configuration and mode.
type Contribution struct {
	// Cluster is the assessment-loop cluster identity ("kube-system:<uid>").
	Cluster string         `json:"cluster"`
	Binding ObjectRevision `json:"binding"`
	Profile ObjectRevision `json:"profile"`
	// Policy is the logical policy identity within the bundle.
	Policy       string `json:"policy"`
	BundleName   string `json:"bundleName"`
	BundleDigest string `json:"bundleDigest"`
	// ConfigurationDigest covers the policy parameters and exception settings.
	ConfigurationDigest string                     `json:"configurationDigest"`
	Mode                v1alpha1.EnforcementMode   `json:"mode"`
	NamespaceSelector   v1alpha1.NamespaceSelector `json:"namespaceSelector"`
	Exceptions          v1alpha1.ExceptionSettings `json:"exceptions"`
	// Revision is EnforcementRevision for this contribution. Engine policy
	// names and exception acceptances are scoped to it.
	Revision string `json:"revision"`
}

// ContributionRef identifies the contribution revision behind a decision.
type ContributionRef struct {
	Binding  ObjectRevision           `json:"binding"`
	Profile  ObjectRevision           `json:"profile"`
	Mode     v1alpha1.EnforcementMode `json:"mode"`
	Revision string                   `json:"revision"`
}

// Eligibility is the effective self-service exception eligibility for one
// logical policy in one namespace, across every applicable contribution.
type Eligibility struct {
	Namespace NamespaceRef                  `json:"namespace"`
	Policy    string                        `json:"policy"`
	Effective v1alpha1.ExceptionEligibility `json:"effective"`
	// MaxLifetime is the shortest applicable limit; set only when Effective is SelfService.
	MaxLifetime *Duration `json:"maxLifetime,omitempty"`
	// Contributors are every contribution considered, sorted by Revision.
	Contributors []ContributionRef `json:"contributors"`
	// Errors make eligibility Forbidden; unresolved configuration is not permission.
	Errors []ResolutionError `json:"errors,omitempty"`
}

// Reason values match the ComplianceBinding condition reasons.
type Reason string

const (
	ReasonProfileNotFound    Reason = v1alpha1.ReasonProfileNotFound
	ReasonContentUnavailable Reason = v1alpha1.ReasonContentUnavailable
	ReasonUnknownPolicy      Reason = v1alpha1.ReasonUnknownPolicy
	ReasonUnsupportedScope   Reason = v1alpha1.ReasonUnsupportedScope
	ReasonInvalidSelector    Reason = v1alpha1.ReasonInvalidSelector
)

// ResolutionError is an explicit, attributable failure to resolve configuration.
type ResolutionError struct {
	Reason  Reason `json:"reason"`
	Binding string `json:"binding,omitempty"`
	Profile string `json:"profile,omitempty"`
	Policy  string `json:"policy,omitempty"`
	Message string `json:"message"`
}

// BindingResult is the resolved scope of one binding. TargetCount of zero is
// a valid resolved scope and never a compliance pass.
type BindingResult struct {
	Binding       ObjectRevision    `json:"binding"`
	Targets       []NamespaceRef    `json:"targets"`
	TargetCount   int               `json:"targetCount"`
	Contributions []Contribution    `json:"contributions"`
	Errors        []ResolutionError `json:"errors,omitempty"`
}

// Result is the resolver output, sorted deterministically.
type Result struct {
	ContractVersion int             `json:"contractVersion"`
	Cluster         string          `json:"cluster"`
	Bindings        []BindingResult `json:"bindings"`
	Eligibility     []Eligibility   `json:"eligibility"`
}

// Duration serializes as a Go duration string, for example "168h0m0s".
type Duration struct{ time.Duration }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) (err error) {
	d.Duration, err = time.ParseDuration(string(b))
	return err
}
