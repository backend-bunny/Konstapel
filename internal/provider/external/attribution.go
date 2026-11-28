package external

import (
	"fmt"
	"time"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// MaxDiagnostics bounds the diagnostics of one collection. Further
// withheld items are counted in Attribution.DiagnosticsOmitted.
const MaxDiagnostics = 64

// DiagnosticReason is why the host withheld an item of a result.
type DiagnosticReason string

const (
	// DiagnosticOutOfScope: an attribution or limitation names a subject
	// that is neither an inventory subject nor an accepted supplement.
	DiagnosticOutOfScope DiagnosticReason = "OutOfScope"
	// DiagnosticUnexpectedCheck: an attribution or limitation names a check
	// that is not expected for its subject (for a supplement, its parent).
	DiagnosticUnexpectedCheck DiagnosticReason = "UnexpectedCheck"
	// DiagnosticSupplementNotAllowed: a supplement of an inventory that
	// allows none.
	DiagnosticSupplementNotAllowed DiagnosticReason = "SupplementNotAllowed"
	// DiagnosticOrphanSupplement: a supplement whose parent is not an
	// inventory workload subject.
	DiagnosticOrphanSupplement DiagnosticReason = "OrphanSupplement"
	// DiagnosticSupplementCollision: a supplement whose id is an inventory
	// subject's UID.
	DiagnosticSupplementCollision DiagnosticReason = "SupplementCollision"
)

// Diagnostic is one withheld item. Item locates it in the result, for
// example "evidence[3]"; the message says why. Neither repeats a
// provider-supplied identifier or detail, because diagnostics reach
// operator status.
type Diagnostic struct {
	Reason  DiagnosticReason `json:"reason"`
	Item    string           `json:"item"`
	Message string           `json:"message"`
}

// Evidence is an accepted evidence item: every attribution names an
// inventory subject or accepted supplement and a check expected for it.
// Its details stay in the payload, uninterpreted.
type Evidence struct {
	ID           string        `json:"id"`
	Attributions []Expectation `json:"attributions"`
	Observed     time.Time     `json:"observed"`
}

// Supplement is an accepted supplement of an inventory workload.
type Supplement struct {
	ID     string `json:"id"`
	Parent string `json:"parent"`
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
}

// Missing is an expectation without accepted evidence, with the provider's
// limitation for it when it gave one. Missing evidence is never a pass.
type Missing struct {
	Expectation
	Limitation string `json:"limitation,omitempty"`
}

// Attribution is a result attributed against its frozen inventory (design
// Decision 9).
type Attribution struct {
	// Evidence are the accepted items, in result order.
	Evidence []Evidence `json:"evidence"`
	// Supplements are the accepted supplements, in result order.
	Supplements []Supplement `json:"supplements,omitempty"`
	// Missing are the inventory's expectations without accepted evidence
	// attributed to the inventory subject itself, sorted. Evidence
	// attributed only to a supplement never removes one.
	Missing []Missing `json:"missing"`
	// SupplementalMissing are the accepted supplements' expectations
	// (their parent's checks) without accepted evidence, sorted.
	SupplementalMissing []Missing `json:"supplementalMissing,omitempty"`
	// Withheld counts the evidence items that were not accepted.
	Withheld int `json:"withheld"`
	// Diagnostics are the first MaxDiagnostics withheld items;
	// DiagnosticsOmitted counts the rest.
	Diagnostics        []Diagnostic `json:"diagnostics,omitempty"`
	DiagnosticsOmitted int          `json:"diagnosticsOmitted,omitempty"`
}

func (a *Attribution) diagnose(reason DiagnosticReason, item, format string, args ...any) {
	if len(a.Diagnostics) >= MaxDiagnostics {
		a.DiagnosticsOmitted++
		return
	}
	a.Diagnostics = append(a.Diagnostics, Diagnostic{Reason: reason, Item: item, Message: fmt.Sprintf(format, args...)})
}

// Attribute validates a structurally checked result
// (providerkit.ParseCollectionResult) against the frozen inventory it was
// collected for:
//
//   - a supplement is accepted only when the inventory allows supplements,
//     its parent is an inventory workload subject, and its id is no
//     inventory UID;
//   - an evidence item is accepted only when every one of its attributions
//     names an inventory subject or an accepted supplement and a check
//     expected for it (for a supplement, for its parent). An item with any
//     other attribution is withheld whole, because its details may carry
//     the other subject's data;
//   - a limitation is kept only for a known subject and expected check;
//   - every inventory expectation without an accepted item attributed to
//     that subject itself is missing.
//
// Withheld items and limitations are diagnostics, never evidence.
func Attribute(inv Inventory, res *providerv1.CollectionResult) Attribution {
	a := Attribution{Evidence: []Evidence{}, Missing: []Missing{}}
	expected := map[string]map[string]bool{}
	workload := map[string]bool{}
	for _, s := range inv.Subjects {
		checks := map[string]bool{}
		for _, c := range s.Checks {
			checks[c] = true
		}
		expected[s.UID] = checks
		workload[s.UID] = s.Resource != providerkit.NamespaceResource
	}
	parent := map[string]string{}
	for i, s := range res.GetSupplements() {
		item := fmt.Sprintf("supplements[%d]", i)
		switch {
		case !inv.Supplements:
			a.diagnose(DiagnosticSupplementNotAllowed, item, "withheld: the inventory allows no supplements")
		case expected[s.GetId()] != nil:
			a.diagnose(DiagnosticSupplementCollision, item, "withheld: its id is an inventory subject's uid")
		case !workload[s.GetParent()]:
			a.diagnose(DiagnosticOrphanSupplement, item, "withheld: its parent is not a workload subject of the inventory")
		default:
			parent[s.GetId()] = s.GetParent()
			a.Supplements = append(a.Supplements, Supplement{ID: s.GetId(), Parent: s.GetParent(), Kind: s.GetKind(), Name: s.GetName()})
		}
	}
	// checksOf is the expected checks of a known subject, nil otherwise.
	checksOf := func(subject string) map[string]bool {
		if c, ok := expected[subject]; ok {
			return c
		}
		if p, ok := parent[subject]; ok {
			return expected[p]
		}
		return nil
	}
	covered := map[Expectation]bool{}
	for i, e := range res.GetEvidence() {
		ok := true
		for j, at := range e.GetAttributions() {
			checks := checksOf(at.GetSubject())
			switch {
			case checks == nil:
				a.diagnose(DiagnosticOutOfScope, fmt.Sprintf("evidence[%d]", i), "withheld: attribution %d names a subject outside the inventory", j)
			case !checks[at.GetCheck()]:
				a.diagnose(DiagnosticUnexpectedCheck, fmt.Sprintf("evidence[%d]", i), "withheld: attribution %d names a check not expected for its subject", j)
			default:
				continue
			}
			ok = false
			break
		}
		if !ok {
			a.Withheld++
			continue
		}
		ev := Evidence{ID: e.GetId(), Observed: e.GetObserved().AsTime().UTC()}
		for _, at := range e.GetAttributions() {
			x := Expectation{Subject: at.GetSubject(), Check: at.GetCheck()}
			ev.Attributions = append(ev.Attributions, x)
			covered[x] = true
		}
		a.Evidence = append(a.Evidence, ev)
	}
	limited := map[Expectation]string{}
	for i, l := range res.GetLimitations() {
		checks := checksOf(l.GetSubject())
		switch {
		case checks == nil:
			a.diagnose(DiagnosticOutOfScope, fmt.Sprintf("limitations[%d]", i), "ignored: it names a subject outside the inventory")
			continue
		case l.GetCheck() != "" && !checks[l.GetCheck()]:
			a.diagnose(DiagnosticUnexpectedCheck, fmt.Sprintf("limitations[%d]", i), "ignored: it names a check not expected for its subject")
			continue
		}
		key := Expectation{Subject: l.GetSubject(), Check: l.GetCheck()}
		if _, seen := limited[key]; !seen {
			limited[key] = bound(l.GetMessage(), 256)
		}
	}
	missing := func(x Expectation) Missing {
		m := Missing{Expectation: x, Limitation: limited[x]}
		if m.Limitation == "" {
			m.Limitation = limited[Expectation{Subject: x.Subject}]
		}
		return m
	}
	for _, s := range inv.Subjects {
		for _, c := range s.Checks {
			if x := (Expectation{Subject: s.UID, Check: c}); !covered[x] {
				a.Missing = append(a.Missing, missing(x))
			}
		}
	}
	for _, s := range a.Supplements {
		for c := range expected[s.Parent] {
			if x := (Expectation{Subject: s.ID, Check: c}); !covered[x] {
				a.SupplementalMissing = append(a.SupplementalMissing, missing(x))
			}
		}
	}
	sortExpectations(a.Missing)
	sortExpectations(a.SupplementalMissing)
	return a
}
