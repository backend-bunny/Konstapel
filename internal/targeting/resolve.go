package targeting

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// PolicyScope is the resource scope a bundle policy evaluates.
type PolicyScope string

const (
	// ScopeNamespaced policies match only namespaced workload resources.
	ScopeNamespaced PolicyScope = "Namespaced"
	// ScopeCluster policies match cluster-scoped resources. Namespace targeting
	// cannot constrain them, so they are rejected.
	ScopeCluster PolicyScope = "Cluster"
)

// BundlePolicy is the resolver's view of one logical policy in pinned content.
type BundlePolicy struct {
	Name  string      `json:"name"`
	Scope PolicyScope `json:"scope"`
	// Parameters is true when the content defines how profile parameters are
	// rendered. Parameters for any other policy are rejected, never dropped.
	Parameters bool `json:"parameters,omitempty"`
}

// Bundle is the metadata of one available, pinned bundle.
type Bundle struct {
	Name     string         `json:"name"`
	Digest   string         `json:"digest"`
	Policies []BundlePolicy `json:"policies"`
}

// Namespace is the resolver's view of a Namespace.
type Namespace struct {
	Name   string            `json:"name"`
	UID    types.UID         `json:"uid"`
	Labels map[string]string `json:"labels"`
}

// Input is a complete snapshot of the configuration to resolve. The resolver
// is pure: the same snapshot in any order produces the same Result.
type Input struct {
	Cluster    string
	Bundles    []Bundle
	Profiles   []v1alpha1.ComplianceProfile
	Bindings   []v1alpha1.ComplianceBinding
	Namespaces []Namespace
}

// BindingEpoch returns the binding-side input to EnforcementRevision. It is
// the binding's metadata.generation today. add-continuous-assessments replaces
// this with an admission-maintained enforcement epoch.
func BindingEpoch(b *v1alpha1.ComplianceBinding) int64 { return b.Generation }

// Resolve computes every binding's targets and contributions and the
// effective exception eligibility per namespace and policy.
func Resolve(in Input) Result {
	profiles := make(map[string]*v1alpha1.ComplianceProfile, len(in.Profiles))
	for i := range in.Profiles {
		profiles[in.Profiles[i].Name] = &in.Profiles[i]
	}
	bundles := make(map[string]*Bundle, len(in.Bundles))
	for i := range in.Bundles {
		bundles[in.Bundles[i].Digest] = &in.Bundles[i]
	}
	namespaces := slices.SortedFunc(slices.Values(in.Namespaces), func(a, b Namespace) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID))
	})

	res := Result{ContractVersion: ContractVersion, Cluster: in.Cluster, Bindings: []BindingResult{}, Eligibility: []Eligibility{}}
	// Per namespace UID: contributions that apply, and binding-level errors that
	// make every policy there ineligible for exceptions.
	type nsState struct {
		ns            Namespace
		contributions []Contribution
		blocking      []ResolutionError
		policyErrors  map[string][]ResolutionError
	}
	states := map[types.UID]*nsState{}
	state := func(ns Namespace) *nsState {
		s := states[ns.UID]
		if s == nil {
			s = &nsState{ns: ns, policyErrors: map[string][]ResolutionError{}}
			states[ns.UID] = s
		}
		return s
	}

	for i := range in.Bindings {
		b := &in.Bindings[i]
		br := resolveBinding(in.Cluster, b, profiles, bundles, namespaces)
		for _, t := range br.Targets {
			s := state(Namespace{Name: t.Name, UID: t.UID})
			s.contributions = append(s.contributions, br.Contributions...)
			for _, e := range br.Errors {
				if e.Policy == "" {
					s.blocking = append(s.blocking, e)
				} else {
					s.policyErrors[e.Policy] = append(s.policyErrors[e.Policy], e)
				}
			}
		}
		res.Bindings = append(res.Bindings, br)
	}
	slices.SortFunc(res.Bindings, func(a, b BindingResult) int {
		return cmp.Or(cmp.Compare(a.Binding.Name, b.Binding.Name), cmp.Compare(a.Binding.UID, b.Binding.UID))
	})

	for _, s := range states {
		byPolicy := map[string][]Contribution{}
		for _, c := range s.contributions {
			byPolicy[c.Policy] = append(byPolicy[c.Policy], c)
		}
		for policy, cs := range byPolicy {
			errs := append(slices.Clone(s.blocking), s.policyErrors[policy]...)
			res.Eligibility = append(res.Eligibility, eligibility(NamespaceRef{Name: s.ns.Name, UID: s.ns.UID}, policy, cs, errs))
		}
	}
	slices.SortFunc(res.Eligibility, func(a, b Eligibility) int {
		return cmp.Or(cmp.Compare(a.Namespace.Name, b.Namespace.Name), cmp.Compare(a.Namespace.UID, b.Namespace.UID), cmp.Compare(a.Policy, b.Policy))
	})
	return res
}

func resolveBinding(cluster string, b *v1alpha1.ComplianceBinding, profiles map[string]*v1alpha1.ComplianceProfile, bundles map[string]*Bundle, namespaces []Namespace) (br BindingResult) {
	br = BindingResult{
		Binding:       ObjectRevision{Name: b.Name, UID: b.UID, Generation: b.Generation},
		Targets:       []NamespaceRef{},
		Contributions: []Contribution{},
	}
	fail := func(reason Reason, profile, policy, format string, args ...any) {
		br.Errors = append(br.Errors, ResolutionError{Reason: reason, Binding: b.Name, Profile: profile, Policy: policy, Message: fmt.Sprintf(format, args...)})
	}
	defer func() {
		br.TargetCount = len(br.Targets)
		slices.SortFunc(br.Contributions, func(x, y Contribution) int {
			return cmp.Or(cmp.Compare(x.Policy, y.Policy), cmp.Compare(x.Revision, y.Revision))
		})
		slices.SortFunc(br.Errors, func(x, y ResolutionError) int {
			return cmp.Or(cmp.Compare(x.Reason, y.Reason), cmp.Compare(x.Policy, y.Policy), cmp.Compare(x.Message, y.Message))
		})
	}()

	// Targets resolve from the selector alone, so status reports scope even
	// when the profile or content does not resolve.
	selector, err := b.Spec.NamespaceSelector.AsSelector()
	if err != nil {
		fail(ReasonInvalidSelector, "", "", "namespaceSelector: %v", err)
		return br
	}
	for _, ns := range namespaces {
		if selector.Matches(labels.Set(ns.Labels)) {
			br.Targets = append(br.Targets, NamespaceRef{Name: ns.Name, UID: ns.UID})
		}
	}

	if b.Spec.Mode != v1alpha1.ModeAudit && b.Spec.Mode != v1alpha1.ModeDeny {
		fail(ReasonInvalidConfiguration, "", "", "mode %q is not Audit or Deny", b.Spec.Mode)
		return br
	}
	p := profiles[b.Spec.ProfileRef.Name]
	if p == nil {
		fail(ReasonProfileNotFound, b.Spec.ProfileRef.Name, "", "ComplianceProfile %q not found", b.Spec.ProfileRef.Name)
		return br
	}
	bundle := bundles[p.Spec.Bundle.Digest]
	if bundle == nil || bundle.Name != p.Spec.Bundle.Name {
		fail(ReasonContentUnavailable, p.Name, "", "bundle %s@%s is not available", p.Spec.Bundle.Name, p.Spec.Bundle.Digest)
		return br
	}
	meta := make(map[string]BundlePolicy, len(bundle.Policies))
	for _, bp := range bundle.Policies {
		meta[bp.Name] = bp
	}

	profileRev := ObjectRevision{Name: p.Name, UID: p.UID, Generation: p.Generation}
	selectorCopy := *b.Spec.NamespaceSelector
	for _, pol := range p.Spec.Policies {
		bp, known := meta[pol.Name]
		scope := bp.Scope
		switch {
		case !known:
			fail(ReasonUnknownPolicy, p.Name, pol.Name, "policy %q is not in bundle %s@%s", pol.Name, bundle.Name, bundle.Digest)
			continue
		case scope != ScopeNamespaced:
			fail(ReasonUnsupportedScope, p.Name, pol.Name, "policy %q has %s scope; namespace targeting supports only namespaced workload resources", pol.Name, scope)
			continue
		case hasParameters(pol) && !bp.Parameters:
			fail(ReasonInvalidConfiguration, p.Name, pol.Name, "policy %q does not accept parameters", pol.Name)
			continue
		}
		ex, err := normalizeExceptions(pol.Exceptions)
		if err != nil {
			fail(ReasonInvalidConfiguration, p.Name, pol.Name, "policy %q: %v", pol.Name, err)
			continue
		}
		pol.Exceptions = ex
		cfg, err := ConfigurationDigest(pol)
		if err != nil {
			fail(ReasonInvalidConfiguration, p.Name, pol.Name, "%v", err)
			continue
		}
		br.Contributions = append(br.Contributions, Contribution{
			Cluster:             cluster,
			Binding:             br.Binding,
			Profile:             profileRev,
			Policy:              pol.Name,
			BundleName:          bundle.Name,
			BundleDigest:        bundle.Digest,
			ConfigurationDigest: cfg,
			Mode:                b.Spec.Mode,
			NamespaceSelector:   selectorCopy,
			Exceptions:          ex,
			Revision: EnforcementRevision(EnforcementInput{
				Cluster:             cluster,
				BindingUID:          b.UID,
				BindingEpoch:        BindingEpoch(b),
				ProfileUID:          p.UID,
				ProfileGeneration:   p.Generation,
				Policy:              pol.Name,
				BundleDigest:        bundle.Digest,
				ConfigurationDigest: cfg,
				Mode:                b.Spec.Mode,
				NamespaceSelector:   selectorCopy,
			}),
		})
	}
	return br
}

// normalizeExceptions applies the Forbidden default and re-checks what
// admission enforces, so stored objects that bypassed validation cannot
// grant eligibility.
func normalizeExceptions(ex v1alpha1.ExceptionSettings) (v1alpha1.ExceptionSettings, error) {
	switch ex.Eligibility {
	case "", v1alpha1.ExceptionsForbidden:
		return v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsForbidden}, nil
	case v1alpha1.ExceptionsSelfService:
		if ex.MaxLifetime == nil || ex.MaxLifetime.Duration <= 0 {
			return ex, fmt.Errorf("SelfService requires a positive maxLifetime")
		}
		return ex, nil
	default:
		return ex, fmt.Errorf("unknown exception eligibility %q", ex.Eligibility)
	}
}

// eligibility applies Forbidden precedence and the shortest lifetime across
// every contribution for one policy in one namespace. Mode does not matter:
// a Forbidden Audit contribution still forbids. Any error forbids.
func eligibility(ns NamespaceRef, policy string, cs []Contribution, errs []ResolutionError) Eligibility {
	e := Eligibility{Namespace: ns, Policy: policy, Effective: v1alpha1.ExceptionsSelfService, Contributors: []ContributionRef{}}
	var shortest time.Duration
	for _, c := range cs {
		e.Contributors = append(e.Contributors, ContributionRef{Binding: c.Binding, Profile: c.Profile, Mode: c.Mode, Revision: c.Revision})
		if c.Exceptions.Eligibility != v1alpha1.ExceptionsSelfService || c.Exceptions.MaxLifetime == nil {
			e.Effective = v1alpha1.ExceptionsForbidden
			continue
		}
		if d := c.Exceptions.MaxLifetime.Duration; shortest == 0 || d < shortest {
			shortest = d
		}
	}
	if len(errs) > 0 || len(cs) == 0 {
		e.Effective = v1alpha1.ExceptionsForbidden
	}
	if e.Effective == v1alpha1.ExceptionsSelfService {
		e.MaxLifetime = &Duration{shortest}
	}
	slices.SortFunc(e.Contributors, func(a, b ContributionRef) int {
		return cmp.Or(cmp.Compare(a.Binding.Name, b.Binding.Name), cmp.Compare(a.Revision, b.Revision))
	})
	if len(errs) > 0 {
		e.Errors = slices.Clone(errs)
		slices.SortFunc(e.Errors, func(a, b ResolutionError) int {
			return cmp.Or(cmp.Compare(a.Reason, b.Reason), cmp.Compare(a.Binding, b.Binding), cmp.Compare(a.Policy, b.Policy), cmp.Compare(a.Message, b.Message))
		})
	}
	return e
}

func hasParameters(p v1alpha1.ProfilePolicy) bool {
	if p.Parameters == nil {
		return false
	}
	raw := strings.TrimSpace(string(p.Parameters.Raw))
	return raw != "" && raw != "null" && raw != "{}"
}
