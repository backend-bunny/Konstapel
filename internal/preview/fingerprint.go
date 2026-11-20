package preview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Fingerprint identifies the normalized configuration of a profile or binding
// (exactly one non-nil). Two specs that differ only in defaults being written
// out, list order of set-like lists, key order, equivalent duration spellings,
// metadata, status, or the admission-maintained enforcementEpoch have the same
// fingerprint. It is a semantic-equivalence aid only: it is not an
// enforcement revision and not an acceptance token. The API server and the
// controller's EnforcementRevision see list order and spellings as written,
// so equal fingerprints do not mean that revisions stay the same
// (StoredSpecChange, RevisionEffect).
func Fingerprint(p *v1alpha1.ComplianceProfile, b *v1alpha1.ComplianceBinding) string {
	var v any
	switch {
	case p != nil:
		v = canonicalProfile(p)
	case b != nil:
		v = canonicalBinding(b)
	default:
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		// Only fixed structs and decoded JSON values reach here.
		panic("preview: fingerprint: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type canonPolicy struct {
	Name        string `json:"name"`
	Parameters  any    `json:"parameters"`
	Eligibility string `json:"eligibility"`
	MaxLifetime string `json:"maxLifetime,omitempty"`
}

func canonicalProfile(p *v1alpha1.ComplianceProfile) any {
	c := p.DeepCopy()
	DefaultProfile(c)
	pols := make([]canonPolicy, 0, len(c.Spec.Policies))
	for _, pol := range c.Spec.Policies {
		cp := canonPolicy{Name: pol.Name, Eligibility: string(pol.Exceptions.Eligibility)}
		if pol.Parameters != nil && len(pol.Parameters.Raw) > 0 {
			// Decoded JSON re-encodes with sorted keys.
			_ = json.Unmarshal(pol.Parameters.Raw, &cp.Parameters)
		}
		if d := pol.Exceptions.MaxLifetime; d != nil {
			cp.MaxLifetime = d.Duration.String()
		}
		pols = append(pols, cp)
	}
	sort.SliceStable(pols, func(i, j int) bool { return pols[i].Name < pols[j].Name })
	return struct {
		Kind     string                   `json:"kind"`
		Bundle   v1alpha1.BundleReference `json:"bundle"`
		Policies []canonPolicy            `json:"policies"`
	}{KindProfile, c.Spec.Bundle, pols}
}

type canonRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// canonicalSelector is the order-independent form of a selector: expression
// order and value order and duplicates do not matter to which namespaces it
// selects. A nil selector stays distinguishable from {}. It is a semantic
// comparison aid only: the API server, the enforcement epoch and
// EnforcementRevision all see the selector as written.
func canonicalSelector(s *v1alpha1.NamespaceSelector) any {
	if s == nil {
		return nil
	}
	labels := map[string]string{}
	for k, v := range s.MatchLabels {
		labels[k] = string(v)
	}
	exprs := make([]canonRequirement, 0, len(s.MatchExpressions))
	for _, r := range s.MatchExpressions {
		vals := slices.Clone(r.Values)
		if vals == nil {
			vals = []string{}
		}
		slices.Sort(vals)
		vals = slices.Compact(vals)
		exprs = append(exprs, canonRequirement{r.Key, string(r.Operator), vals})
	}
	sort.SliceStable(exprs, func(i, j int) bool {
		if exprs[i].Key != exprs[j].Key {
			return exprs[i].Key < exprs[j].Key
		}
		if exprs[i].Operator != exprs[j].Operator {
			return exprs[i].Operator < exprs[j].Operator
		}
		return slices.Compare(exprs[i].Values, exprs[j].Values) < 0
	})
	return struct {
		MatchLabels      map[string]string  `json:"matchLabels"`
		MatchExpressions []canonRequirement `json:"matchExpressions"`
	}{labels, exprs}
}

func canonicalBinding(b *v1alpha1.ComplianceBinding) any {
	c := b.DeepCopy()
	DefaultBinding(c)
	sel := canonicalSelector(c.Spec.NamespaceSelector)
	dur := func(d v1alpha1.Duration) string {
		if v, err := time.ParseDuration(string(d)); err == nil {
			return v.String()
		}
		return string(d)
	}
	a := c.Spec.Assessment
	var dest *v1alpha1.DestinationReference
	if a.DestinationRef != nil {
		d := *a.DestinationRef
		dest = &d
	}
	return struct {
		Kind       string `json:"kind"`
		ProfileRef string `json:"profileRef"`
		Selector   any    `json:"namespaceSelector"`
		Mode       string `json:"mode"`
		Assessment struct {
			Interval          string                         `json:"interval"`
			MaxEvidenceAge    string                         `json:"maxEvidenceAge"`
			CollectionTimeout string                         `json:"collectionTimeout"`
			Retention         string                         `json:"retention"`
			DestinationRef    *v1alpha1.DestinationReference `json:"destinationRef"`
		} `json:"assessment"`
	}{
		Kind: KindBinding, ProfileRef: c.Spec.ProfileRef.Name, Selector: sel, Mode: string(c.Spec.Mode),
		Assessment: struct {
			Interval          string                         `json:"interval"`
			MaxEvidenceAge    string                         `json:"maxEvidenceAge"`
			CollectionTimeout string                         `json:"collectionTimeout"`
			Retention         string                         `json:"retention"`
			DestinationRef    *v1alpha1.DestinationReference `json:"destinationRef"`
		}{dur(a.Interval), dur(a.MaxEvidenceAge), dur(a.CollectionTimeout), dur(a.Retention), dest},
	}
}
