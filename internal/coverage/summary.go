package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Summarize is the bounded status summary of r, whose canonical JSON
// (coverage.json) has the lowercase hex sha256 reportSHA256. It counts the
// selected controls by automation state and the limitations, and lists at
// most publication.MaxBlockingCodes distinct blocking codes. Its size does
// not depend on the size of the baseline: no control, statement, check,
// observation or limitation text is copied.
//
// The caller adds what the report does not record: the inputs digest
// (InputsDigest) and the owner's evidence expiry at closure.
func Summarize(r *Report, reportSHA256 string) publication.CoverageSummary {
	s := publication.CoverageSummary{AsOf: r.AsOf.UTC(), SHA256: reportSHA256,
		InventoryResolved: r.Inventory.Resolved, MappingsResolved: r.Mappings.Resolved,
		Controls: r.Inventory.Controls, Enhancements: r.Inventory.Enhancements, TechnicalEvidence: r.TechnicalEvidence.State}
	if b := r.Inputs.Bundle; b.Name != "" || b.Digest != "" {
		s.Bundle = &publication.CoverageBundle{Name: b.Name, Digest: b.Digest}
	}
	codes := map[string]bool{}
	count := func(ls []Limitation) {
		s.Limitations += len(ls)
		for _, l := range ls {
			if l.Blocking {
				codes[l.Code] = true
			}
		}
	}
	count(r.Limitations)
	for _, c := range r.Controls {
		count(c.Limitations)
		switch c.Automation {
		case AutomationNone:
			s.Automation.None++
		case AutomationUnselected:
			s.Automation.Unselected++
		case AutomationPartial:
			s.Automation.Partial++
		default:
			s.Automation.Unknown++
		}
	}
	for _, c := range slices.Sorted(maps.Keys(codes)) {
		if len(s.BlockingCodes) == publication.MaxBlockingCodes {
			break
		}
		s.BlockingCodes = append(s.BlockingCodes, c)
	}
	return s
}

// InputsDigest identifies what a coverage report assesses: the binding
// UID, the scope's namespace UIDs and the profile selection (nil when the
// binding selects no profile). Namespace and policy order carry no
// meaning; policy parameters are compared compacted. It is the lowercase
// hex sha256 of a canonical JSON form, so a report's recorded inputs and a
// binding's current ones compare by value. It is "" when the selection's
// parameters are not JSON: such inputs never compare equal.
func InputsDigest(bindingUID string, namespaceUIDs []string, sel *Selection) string {
	ns := slices.Clone(namespaceUIDs)
	if ns == nil {
		ns = []string{}
	}
	slices.Sort(ns)
	ns = slices.Compact(ns)
	v := struct {
		Version    int        `json:"version"`
		Binding    string     `json:"binding"`
		Namespaces []string   `json:"namespaces"`
		Selection  *Selection `json:"selection"`
	}{Version: 1, Binding: bindingUID, Namespaces: ns}
	if sel != nil {
		s := sortedSelection(*sel)
		v.Selection = &s
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
