package targeting

import (
	"cmp"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// EvidenceSubject is one expected-evidence subject: one contribution applied
// to one namespace instance. add-continuous-assessments' collector consumes
// these and owns everything inside internal/assessment. It records them
// verbatim for provenance, so changes to this type or its derivation require a
// ContractVersion bump and an updated golden file.
//
// Subjects are keyed by namespace UID, never name: a recreated namespace is a
// new subject. Overlapping bindings yield separate subjects with distinct
// revisions; collectors must not count them as independent control coverage.
type EvidenceSubject struct {
	Cluster      string    `json:"cluster"`
	Namespace    string    `json:"namespace"`
	NamespaceUID types.UID `json:"namespaceUID"`
	BindingName  string    `json:"bindingName"`
	BindingUID   types.UID `json:"bindingUID"`
	// Revision is the contribution's EnforcementRevision. Use it, never a
	// binding generation, to identify the configuration evaluated.
	Revision      string                   `json:"revision"`
	EnginePolicy  string                   `json:"enginePolicy"`
	LogicalPolicy string                   `json:"logicalPolicy"`
	Mode          v1alpha1.EnforcementMode `json:"mode"`
	// Checks lists named sub-validations when the content names them. It is
	// empty for the vendored policy, whose validations are unnamed;
	// collectors enumerate checks from the rendered policy.
	Checks []string `json:"checks"`
	// Resources are the matched "group/version/resource" entries, sorted,
	// with "" for the core group (for example "/v1/pods").
	Resources           []string  `json:"resources"`
	ProfileName         string    `json:"profileName"`
	ProfileUID          types.UID `json:"profileUID"`
	ProfileGeneration   int64     `json:"profileGeneration"`
	BundleName          string    `json:"bundleName"`
	BundleDigest        string    `json:"bundleDigest"`
	ConfigurationDigest string    `json:"configurationDigest"`
	SourceDigest        string    `json:"sourceDigest"`
}

// StaleScope marks a binding, or one of its policies, whose current
// configuration did not resolve. No subjects are produced for it, although its
// last applied engine policies may still be enforcing. Collectors record a
// limitation instead of a silent gap.
type StaleScope struct {
	Binding ObjectRevision `json:"binding"`
	// Policy is empty when the whole binding is stale.
	Policy  string `json:"policy,omitempty"`
	Reason  Reason `json:"reason"`
	Message string `json:"message"`
}

// ExpectedEvidence lists the expected-evidence subjects for a resolver Result.
// content maps bundle digests to the verified content each contribution was
// resolved against; a contribution without content is an error, never a guess.
// Subjects are sorted by namespace UID, binding UID, logical policy and
// revision; stale scopes by binding UID, policy and reason.
func ExpectedEvidence(r Result, content map[string]*Content) ([]EvidenceSubject, []StaleScope, error) {
	subjects := []EvidenceSubject{}
	stale := []StaleScope{}
	for _, b := range r.Bindings {
		for _, e := range b.Errors {
			stale = append(stale, StaleScope{Binding: b.Binding, Policy: e.Policy, Reason: e.Reason, Message: e.Message})
		}
		for _, c := range b.Contributions {
			bundle := content[c.BundleDigest]
			if bundle == nil {
				return nil, nil, fmt.Errorf("binding %s: no content for bundle %s@%s", b.Binding.Name, c.BundleName, c.BundleDigest)
			}
			src, ok := bundle.Policies[c.Policy]
			if !ok {
				return nil, nil, fmt.Errorf("binding %s: bundle %s@%s has no policy %q", b.Binding.Name, c.BundleName, c.BundleDigest, c.Policy)
			}
			resources, err := matchedResources(src.Manifest)
			if err != nil {
				return nil, nil, fmt.Errorf("binding %s: policy %s: %w", b.Binding.Name, c.Policy, err)
			}
			for _, ns := range b.Targets {
				subjects = append(subjects, EvidenceSubject{
					Cluster:             c.Cluster,
					Namespace:           ns.Name,
					NamespaceUID:        ns.UID,
					BindingName:         c.Binding.Name,
					BindingUID:          c.Binding.UID,
					Revision:            c.Revision,
					EnginePolicy:        PolicyName(c),
					LogicalPolicy:       c.Policy,
					Mode:                c.Mode,
					Checks:              []string{},
					Resources:           slices.Clone(resources),
					ProfileName:         c.Profile.Name,
					ProfileUID:          c.Profile.UID,
					ProfileGeneration:   c.Profile.Generation,
					BundleName:          c.BundleName,
					BundleDigest:        c.BundleDigest,
					ConfigurationDigest: c.ConfigurationDigest,
					SourceDigest:        src.SourceDigest,
				})
			}
		}
	}
	slices.SortFunc(subjects, func(a, b EvidenceSubject) int {
		return cmp.Or(cmp.Compare(a.NamespaceUID, b.NamespaceUID), cmp.Compare(a.BindingUID, b.BindingUID),
			cmp.Compare(a.LogicalPolicy, b.LogicalPolicy), cmp.Compare(a.Revision, b.Revision))
	})
	slices.SortFunc(stale, func(a, b StaleScope) int {
		return cmp.Or(cmp.Compare(a.Binding.UID, b.Binding.UID), cmp.Compare(a.Policy, b.Policy), cmp.Compare(a.Reason, b.Reason), cmp.Compare(a.Message, b.Message))
	})
	return subjects, stale, nil
}

// matchedResources lists a ValidatingPolicy's resourceRules as sorted, unique
// "group/version/resource" strings.
func matchedResources(m map[string]any) ([]string, error) {
	mc, _ := nested(m, "spec", "matchConstraints").(map[string]any)
	rules, _ := mc["resourceRules"].([]any)
	seen := map[string]bool{}
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		for _, g := range stringList(rule["apiGroups"]) {
			for _, v := range stringList(rule["apiVersions"]) {
				for _, res := range stringList(rule["resources"]) {
					if g == "*" || v == "*" || res == "*" {
						return nil, fmt.Errorf("wildcard resource rule %s/%s/%s", g, v, res)
					}
					seen[g+"/"+v+"/"+res] = true
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no resource rules")
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}

func stringList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
