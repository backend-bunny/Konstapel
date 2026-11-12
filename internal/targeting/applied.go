package targeting

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// AppliedContribution is the inverse of Render's provenance: the
// contribution a delivered engine policy was rendered for, read from its
// labels, annotations and namespace selector. It identifies what is applied
// (for example a previous revision still enforcing while an update rolls
// out); it is not proof that the policy matches its content. Callers verify
// that by rendering the result again from the content the policy names
// (collector.VerifyEnginePolicy). Engine policies do not record the binding
// generation or the exception settings, so they are zero.
func AppliedContribution(obj map[string]any) (Contribution, error) {
	meta, _ := obj["metadata"].(map[string]any)
	ann := stringMap(meta["annotations"])
	lbl := stringMap(meta["labels"])
	name, _ := meta["name"].(string)
	c := Contribution{
		Cluster:             ann[AnnotationCluster],
		Binding:             ObjectRevision{Name: ann[AnnotationBinding], UID: types.UID(lbl[LabelBindingUID])},
		Profile:             ObjectRevision{Name: ann[AnnotationProfile], UID: types.UID(ann[AnnotationProfileUID])},
		Policy:              ann[AnnotationPolicy],
		BundleName:          ann[AnnotationBundle],
		BundleDigest:        ann[AnnotationBundleDigest],
		ConfigurationDigest: ann[AnnotationConfiguration],
		Mode:                v1alpha1.EnforcementMode(ann[AnnotationMode]),
		Revision:            ann[AnnotationRevision],
	}
	var missing []string
	for k, v := range map[string]string{"cluster": c.Cluster, "binding": c.Binding.Name, "binding UID": string(c.Binding.UID), "policy": c.Policy,
		"bundle": c.BundleName, "bundle digest": c.BundleDigest, "revision": c.Revision, "mode": string(c.Mode), "source digest": ann[AnnotationSourceDigest]} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return c, fmt.Errorf("engine policy %s does not record its applied contribution (%v)", name, missing)
	}
	if g := ann[AnnotationProfileGen]; g != "" {
		gen, err := strconv.ParseInt(g, 10, 64)
		if err != nil {
			return c, fmt.Errorf("engine policy %s: profile generation %q", name, g)
		}
		c.Profile.Generation = gen
	}
	if name != PolicyName(c) {
		return c, fmt.Errorf("engine policy %s is not named for its recorded revision", name)
	}
	sel, err := appliedSelector(obj)
	if err != nil {
		return c, fmt.Errorf("engine policy %s: namespaceSelector: %w", name, err)
	}
	c.NamespaceSelector = sel
	return c, nil
}

// AppliedEvidence lists the expected-evidence subjects of one applied
// engine policy: its contribution (AppliedContribution) in every namespace
// its own namespace selector matches now, for the resources its own rules
// match. The policy's source digest annotation names the source it must
// re-render from.
func AppliedEvidence(obj map[string]any, namespaces []Namespace) (Contribution, []EvidenceSubject, error) {
	c, err := AppliedContribution(obj)
	if err != nil {
		return c, nil, err
	}
	resources, err := matchedResources(obj)
	if err != nil {
		return c, nil, fmt.Errorf("engine policy %s: %w", PolicyName(c), err)
	}
	selector, err := c.NamespaceSelector.AsSelector()
	if err != nil {
		return c, nil, err
	}
	meta, _ := obj["metadata"].(map[string]any)
	source := stringMap(meta["annotations"])[AnnotationSourceDigest]
	var out []EvidenceSubject
	for _, ns := range slices.SortedFunc(slices.Values(namespaces), func(a, b Namespace) int { return cmp.Compare(a.UID, b.UID) }) {
		if !selector.Matches(labels.Set(ns.Labels)) {
			continue
		}
		out = append(out, EvidenceSubject{
			Cluster: c.Cluster, Namespace: ns.Name, NamespaceUID: ns.UID, BindingName: c.Binding.Name, BindingUID: c.Binding.UID,
			Revision: c.Revision, EnginePolicy: PolicyName(c), LogicalPolicy: c.Policy, Mode: c.Mode, Checks: []string{},
			Resources: slices.Clone(resources), ProfileName: c.Profile.Name, ProfileUID: c.Profile.UID, ProfileGeneration: c.Profile.Generation,
			BundleName: c.BundleName, BundleDigest: c.BundleDigest, ConfigurationDigest: c.ConfigurationDigest, SourceDigest: source,
		})
	}
	return c, out, nil
}

// SortSubjects orders subjects as ExpectedEvidence does.
func SortSubjects(subjects []EvidenceSubject) {
	slices.SortFunc(subjects, func(a, b EvidenceSubject) int {
		return cmp.Or(cmp.Compare(a.NamespaceUID, b.NamespaceUID), cmp.Compare(a.BindingUID, b.BindingUID),
			cmp.Compare(a.LogicalPolicy, b.LogicalPolicy), cmp.Compare(a.Revision, b.Revision))
	})
}

func appliedSelector(obj map[string]any) (v1alpha1.NamespaceSelector, error) {
	raw, found := nested(obj, "spec", "matchConstraints", "namespaceSelector").(map[string]any)
	if !found || raw == nil {
		return v1alpha1.NamespaceSelector{}, errors.New("not set")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return v1alpha1.NamespaceSelector{}, err
	}
	var ls metav1.LabelSelector
	if err := json.Unmarshal(b, &ls); err != nil {
		return v1alpha1.NamespaceSelector{}, err
	}
	var s v1alpha1.NamespaceSelector
	if ls.MatchLabels != nil {
		s.MatchLabels = make(map[string]v1alpha1.LabelValue, len(ls.MatchLabels))
		for k, v := range ls.MatchLabels {
			s.MatchLabels[k] = v1alpha1.LabelValue(v)
		}
	}
	for _, r := range ls.MatchExpressions {
		s.MatchExpressions = append(s.MatchExpressions, v1alpha1.NamespaceSelectorRequirement{Key: r.Key, Operator: r.Operator, Values: r.Values})
	}
	return s, nil
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := make(map[string]string, len(m))
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}
