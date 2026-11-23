package provider

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// SelectionReason is a bounded explanation of a rejected selection.
type SelectionReason string

const (
	// ReasonInvalidSelection: the selection itself is malformed (no checks,
	// a repeated check, an unparseable provider contract).
	ReasonInvalidSelection SelectionReason = "InvalidSelection"
	// ReasonUnknownProvider: no installed provider has the requested name.
	ReasonUnknownProvider SelectionReason = "UnknownProvider"
	// ReasonIncompatibleVersion: the provider is installed at another
	// contract version, or cannot read the capture version.
	ReasonIncompatibleVersion SelectionReason = "IncompatibleVersion"
	// ReasonMixedProviders: the checks belong to more than one provider, or
	// to a provider other than the selected one. A binding uses one provider.
	ReasonMixedProviders SelectionReason = "MixedProviders"
	// ReasonUnsupportedCheck: no installed provider evaluates the check kind.
	ReasonUnsupportedCheck SelectionReason = "UnsupportedCheck"
	// ReasonUnsupportedMode: the check kind does not accept the binding mode
	// (Deny for a reporting-only kind).
	ReasonUnsupportedMode SelectionReason = "UnsupportedMode"
	// ReasonInvalidParameters: the parameters violate the check's contract.
	ReasonInvalidParameters SelectionReason = "InvalidParameters"
)

// BindingReason maps a selection reason to the existing ComplianceBinding
// condition reason that reports it, so surfacing selection errors needs no
// new API reason: provider contracts are already reported as unavailable
// (Incompatible) content, unsupported policy types as UnsupportedScope, and
// configuration the provider cannot honour as InvalidConfiguration.
func (r SelectionReason) BindingReason() string {
	switch r {
	case ReasonUnknownProvider, ReasonIncompatibleVersion:
		return v1alpha1.ReasonContentUnavailable
	case ReasonUnsupportedCheck:
		return v1alpha1.ReasonUnsupportedScope
	default:
		return v1alpha1.ReasonInvalidConfiguration
	}
}

// SelectionError is one attributable reason a selection was rejected.
type SelectionError struct {
	Reason SelectionReason `json:"reason"`
	// Check is the check the error concerns; empty for the whole selection.
	Check   string `json:"check,omitempty"`
	Message string `json:"message"`
}

func (e *SelectionError) Error() string {
	if e.Check == "" {
		return fmt.Sprintf("%s: %s", e.Reason, e.Message)
	}
	return fmt.Sprintf("%s: check %s: %s", e.Reason, e.Check, e.Message)
}

// Selection is one binding's request: one provider, one mode, and the
// checks its profile selects from verified content.
type Selection struct {
	// Provider is the content's provider contract ("name/vN"); empty means
	// the registry default, which is the Kyverno provider in production, so
	// existing bindings keep resolving as before.
	Provider string
	Mode     v1alpha1.EnforcementMode
	Checks   []CheckSelection
}

// CheckSelection is one selected check.
type CheckSelection struct {
	// Name is the logical check (policy) name within the content.
	Name string
	// Kind is the check definition's "<group>/<version>/<Kind>".
	Kind string
	// Parameters are the profile's parameters for the check; nil, null and
	// {} mean none, as in targeting.HasParameters.
	Parameters *apiextensionsv1.JSON
	// Content is the verified content's parameter contract for the check,
	// used by kinds whose parameters come from content.
	Content ContentParameters
}

// ContentParameters is what verified content and delivery state about a
// check's parameters, for ParametersFromContent kinds.
type ContentParameters struct {
	// Declared is true when the content declares a parameter contract
	// (targeting.PolicySource.ParametersValidated); Schema is then the
	// policy's schema, nil meaning it accepts none.
	Declared bool
	Schema   []byte
	// Rendered is true when delivery renders the parameters
	// (targeting.BundlePolicy.Parameters). Unrendered parameters are
	// rejected, never dropped.
	Rendered bool
}

// Plan is an accepted selection. It exists only when every check is
// supported; a rejected selection yields no plan, so nothing is partially
// applied.
type Plan struct {
	Provider         string                   `json:"provider"`
	EvaluatorVersion int                      `json:"evaluatorVersion"`
	CaptureVersion   int                      `json:"captureVersion"`
	Mode             v1alpha1.EnforcementMode `json:"mode"`
	// Delivery is true when every check is delivered as an engine policy by
	// the delivery owner; false for reporting-only selections, which must
	// not claim engine readiness or produce engine resources.
	Delivery bool           `json:"delivery"`
	Checks   []PlannedCheck `json:"checks"`
}

// PlannedCheck is one accepted check.
type PlannedCheck struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Select validates a selection against the installed providers. It returns
// a plan, or every reason the selection is rejected and no plan. It is pure:
// it reads no cluster, registry or file, and never executes anything.
func (r *Registry) Select(sel Selection) (*Plan, []SelectionError) {
	var errs []SelectionError
	fail := func(reason SelectionReason, check, format string, a ...any) {
		errs = append(errs, SelectionError{Reason: reason, Check: check, Message: fmt.Sprintf(format, a...)})
	}
	if sel.Mode != v1alpha1.ModeAudit && sel.Mode != v1alpha1.ModeDeny {
		fail(ReasonInvalidSelection, "", "mode %q is not Audit or Deny", sel.Mode)
	}
	if len(sel.Checks) == 0 {
		fail(ReasonInvalidSelection, "", "selects no checks")
	}
	d, lerr := r.Lookup(sel.Provider)
	if lerr != nil {
		errs = append(errs, *lerr)
	}

	// Which providers own the selected kinds, independent of the request.
	owners := map[string]bool{}
	for _, c := range sel.Checks {
		if o, ok := r.byKind[c.Kind]; ok {
			owners[o] = true
		}
	}
	if len(owners) > 1 {
		fail(ReasonMixedProviders, "", "checks belong to providers %s; a binding uses one provider", strings.Join(slices.Sorted(maps.Keys(owners)), ", "))
	}

	plan := &Plan{Provider: d.Contract(), EvaluatorVersion: d.EvaluatorVersion, CaptureVersion: d.Capture.Write, Mode: sel.Mode, Delivery: true, Checks: []PlannedCheck{}}
	seen := map[string]bool{}
	for _, c := range sel.Checks {
		if c.Name == "" || seen[c.Name] {
			fail(ReasonInvalidSelection, c.Name, "check names must be non-empty and unique")
			continue
		}
		seen[c.Name] = true
		owner, owned := r.byKind[c.Kind]
		switch {
		case !owned:
			fail(ReasonUnsupportedCheck, c.Name, "no installed provider evaluates %q", c.Kind)
			continue
		case lerr != nil:
			continue // the provider itself is the error
		case owner != d.Name:
			if len(owners) == 1 {
				fail(ReasonMixedProviders, c.Name, "kind %s belongs to %s, not the selected %s", c.Kind, owner, d.Contract())
			}
			continue
		}
		k := kindOf(d, c.Kind)
		if !slices.Contains(k.Modes, sel.Mode) && (sel.Mode == v1alpha1.ModeAudit || sel.Mode == v1alpha1.ModeDeny) {
			fail(ReasonUnsupportedMode, c.Name, "%s accepts %s, not %s", c.Kind, modes(k.Modes), sel.Mode)
		}
		if msg := parameterProblem(k, c); msg != "" {
			fail(ReasonInvalidParameters, c.Name, "%s", msg)
		}
		plan.Delivery = plan.Delivery && k.Delivery
		plan.Checks = append(plan.Checks, PlannedCheck{Name: c.Name, Kind: c.Kind})
	}
	if len(errs) > 0 {
		slices.SortStableFunc(errs, func(a, b SelectionError) int {
			return cmp.Or(cmp.Compare(a.Check, b.Check), cmp.Compare(a.Reason, b.Reason))
		})
		return nil, errs
	}
	slices.SortFunc(plan.Checks, func(a, b PlannedCheck) int { return cmp.Compare(a.Name, b.Name) })
	return plan, nil
}

// parameterProblem applies the kind's parameter contract. Content-defined
// contracts keep the existing Kyverno semantics exactly: parameters must
// satisfy the content's declared schema when there is one, and are rejected
// unless delivery renders them.
func parameterProblem(k CheckKind, c CheckSelection) string {
	if !targeting.HasParameters(v1alpha1.ProfilePolicy{Parameters: c.Parameters}) {
		return ""
	}
	raw := c.Parameters.Raw
	switch k.Parameters.Source {
	case ParametersFromContent:
		if c.Content.Declared {
			if err := bundle.ValidatePolicyParameters(c.Name, c.Content.Schema, raw); err != nil {
				return err.Error()
			}
		}
		if !c.Content.Rendered {
			return fmt.Sprintf("policy %q does not accept parameters", c.Name)
		}
		return ""
	case ParametersFromDescriptor:
		if err := bundle.ValidatePolicyParameters(c.Name, k.Parameters.Schema, raw); err != nil {
			return err.Error()
		}
		return ""
	default:
		return fmt.Sprintf("%s accepts no parameters", k.Kind)
	}
}

func kindOf(d Descriptor, kind string) CheckKind {
	for _, k := range d.Checks {
		if k.Kind == kind {
			return k
		}
	}
	return CheckKind{}
}

func modes(ms []v1alpha1.EnforcementMode) string {
	s := make([]string, len(ms))
	for i, m := range ms {
		s[i] = string(m)
	}
	return strings.Join(s, ", ")
}
