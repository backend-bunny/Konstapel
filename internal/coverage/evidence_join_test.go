package coverage

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// A check shared by two controls is one set of observations referenced by
// both rows, never two evaluations; the report's total is the owner's.
func TestSharedCheckIsReferencedNotRecounted(t *testing.T) {
	c := official(t, hardening)
	cap := capture(t, []contrib{{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}}, pod("p1"), pod("p2"))
	reportAll(&cap, evStarted.Add(time.Minute), "pass")
	// Repeated reports of the same results: the owner attributes each
	// expected observation once.
	cap.Reports = append(cap.Reports, cap.Reports...)
	ev := evaluated(t, cap, evMaxAge)
	r := Build(Input{Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: ev})
	if ev.Evaluation.Evidence.Expected != 2 || *r.TechnicalEvidence.Evidence != ev.Evaluation.Evidence {
		t.Fatalf("owner %+v report %+v", ev.Evaluation.Evidence, *r.TechnicalEvidence.Evidence)
	}
	ac6, cm6 := row(t, r, "ac-6"), row(t, r, "cm-6")
	a, b := observationsOf(checkOf(t, ac6, pEsc)), observationsOf(checkOf(t, cm6, pEsc))
	if len(a) != 2 || !slices.Equal(a, b) {
		t.Fatalf("ac-6 %q cm-6 %q", a, b)
	}
	for _, o := range r.TechnicalEvidence.Observations {
		if !slices.Equal(o.Controls, []string{"ac-6", "cm-6"}) {
			t.Errorf("%q referenced by %v", o.Observation.Key, o.Controls)
		}
	}
	// Each row counts the shared observations; the rows are not additive
	// and never add up to the report's unique count.
	for _, x := range []ControlCoverage{ac6, cm6} {
		if e, o := counts(t, x.ID, *x.Evidence); e.Expected != 2 || o.Pass != 2 {
			t.Errorf("%s %+v %+v", x.ID, e, o)
		}
	}
	// Statement joins: ac-6_smt and cm-6's mapped statement reference the
	// same rule and the same two observations.
	for _, x := range []ControlCoverage{ac6, cm6} {
		if len(x.StatementEvidence) == 0 {
			t.Fatalf("%s has no statement evidence", x.ID)
		}
		for _, s := range x.StatementEvidence {
			if e, _ := counts(t, s.ID, s.EvidenceView); !slices.Equal(s.Rules, []string{pEsc}) || e.Expected != 2 {
				t.Errorf("%s statement %+v", x.ID, s)
			}
		}
	}
	// An identical repeated evaluation entry is counted once, with a notice.
	dup := &Evidence{Capture: ev.Capture, Evaluation: clone(ev.Evaluation)}
	dup.Evaluation.Observations = append(dup.Evaluation.Observations, dup.Evaluation.Observations[0])
	r = Build(Input{Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: dup})
	if r.TechnicalEvidence.State != EvidenceResolved || !hasCode(r.Limitations, CodeDuplicateObservation) || len(r.TechnicalEvidence.Observations) != 2 {
		t.Fatalf("state %s limitations %v records %d", r.TechnicalEvidence.State, r.Limitations, len(r.TechnicalEvidence.Observations))
	}
	if e, _ := counts(t, "esc", checkOf(t, row(t, r, "ac-6"), pEsc).Evidence.EvidenceView); e.Expected != 2 {
		t.Errorf("repeated observation counted twice: %+v", e)
	}
}

// Overlapping bindings and distinct configurations (revisions) of one
// check stay distinct contributions with their own observations.
func TestOverlappingContributionsStayDistinct(t *testing.T) {
	c := official(t, hardening)
	a1 := contrib{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}
	a2 := contrib{binding: "bind-a", revision: "r2", policy: pEsc, bundle: c.Bundle} // another configuration
	b1 := contrib{binding: "bind-b", revision: "r1", policy: pEsc, bundle: c.Bundle} // an overlapping binding
	cap := capture(t, []contrib{a1, a2, b1}, pod("p1"), pod("p2"))
	at := evStarted.Add(time.Minute)
	for _, w := range []collector.Workload{pod("p1"), pod("p2")} {
		cap.Reports = append(cap.Reports, result(a1.enginePolicy(), 0, w, "pass", at), result(b1.enginePolicy(), 0, w, "fail", at))
	}
	// a2 has no results yet: its observations are missing, not a's passes.
	ev := evaluated(t, cap, evMaxAge)
	r := Build(Input{Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: ev})
	ch := checkOf(t, row(t, r, "ac-6"), pEsc)
	if len(ch.Evidence.Contributions) != 3 {
		t.Fatalf("contributions %+v", ch.Evidence.Contributions)
	}
	want := map[[2]string]publication.EvidenceSummary{
		{"bind-a", "r1"}: {Completeness: publication.Complete, Expected: 2, Attributable: 2},
		{"bind-a", "r2"}: {Completeness: publication.Incomplete, Expected: 2, Missing: 2},
		{"bind-b", "r1"}: {Completeness: publication.Complete, Expected: 2, Attributable: 2},
	}
	seen := map[string]bool{}
	for _, x := range ch.Evidence.Contributions {
		if x.Evidence != want[[2]string{x.BindingUID, x.Revision}] || len(x.Observations) != 2 {
			t.Errorf("%s/%s %+v %v", x.BindingUID, x.Revision, x.Evidence, x.Observations)
		}
		for _, k := range x.Observations {
			if seen[k] {
				t.Errorf("observation %q shared by two contributions", k)
			}
			seen[k] = true
		}
	}
	e, o := counts(t, "esc", ch.Evidence.EvidenceView)
	if e.Expected != 6 || e != ev.Evaluation.Evidence || o.Pass != 2 || o.Fail != 2 {
		t.Errorf("check %+v %+v; owner %+v", e, o, ev.Evaluation.Evidence)
	}
	// A binding-scoped report refuses a capture holding another binding.
	r = Build(Input{Scope: Scope{Binding: &ObjectRef{Name: "bind-a", UID: "bind-a"}}, Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: ev})
	if r.TechnicalEvidence.State != EvidenceUnresolved || !hasCode(r.Limitations, CodeEvidenceScopeMismatch) {
		t.Errorf("binding scope: %s %v", r.TechnicalEvidence.State, r.Limitations)
	}
}

// Observations of another bundle, an unselected policy or an unmapped
// policy are retained in the report but attributed to no control, even
// when the identifiers coincide.
func TestEvidenceAttributionBoundaries(t *testing.T) {
	hard, priv := official(t, hardening), official(t, privileged)
	// priv's policy has the same name as one of hard's, from other content.
	other := contrib{binding: "bind-a", revision: "r1", policy: privPolicy, bundle: priv.Bundle}
	unsel := contrib{binding: "bind-a", revision: "r1", policy: pNonroot, bundle: hard.Bundle}
	own := contrib{binding: "bind-a", revision: "r1", policy: pEsc, bundle: hard.Bundle}
	cap := capture(t, []contrib{other, unsel, own}, pod("p1"))
	reportAll(&cap, evStarted.Add(time.Minute), "pass")
	r := Build(Input{Content: hard, Selection: selecting(hard, pEsc, privPolicy), Options: opts(t), Evidence: evaluated(t, cap, evMaxAge)})
	if r.TechnicalEvidence.State != EvidenceResolved {
		t.Fatalf("state %s %v", r.TechnicalEvidence.State, r.Limitations)
	}
	attr := map[string]string{}
	for _, x := range r.TechnicalEvidence.Contributions {
		attr[x.LogicalPolicy] = x.Attribution
	}
	if attr[privPolicy] != AttributionOtherContent || attr[pNonroot] != AttributionNotSelected || attr[pEsc] != AttributionAttributed {
		t.Fatalf("attribution %v", attr)
	}
	for _, code := range []string{CodeEvidenceOtherContent, CodeEvidenceNotSelected} {
		if !hasCode(r.Limitations, code) {
			t.Errorf("no %s notice in %v", code, r.Limitations)
		}
	}
	// hard's own privileged check is selected but had no contribution from
	// hard: zero targets, not priv's pass.
	e, o := counts(t, privPolicy, checkOf(t, row(t, r, "ac-6"), privPolicy).Evidence.EvidenceView)
	if e.Completeness != publication.NoTargets || o.Pass != 0 {
		t.Errorf("other content's observation attributed: %+v %+v", e, o)
	}
	for _, rec := range r.TechnicalEvidence.Observations {
		attributed := rec.Expected.Contribution.LogicalPolicy == pEsc
		if attributed != (len(rec.Controls) > 0) {
			t.Errorf("%s referenced by %v", rec.Expected.Contribution.LogicalPolicy, rec.Controls)
		}
	}
	if *r.TechnicalEvidence.Evidence != (publication.EvidenceSummary{Completeness: publication.Complete, Expected: 3, Attributable: 3}) {
		t.Errorf("owner summary changed: %+v", *r.TechnicalEvidence.Evidence)
	}
}

// The alternate catalog: logical policy, rule and engine sub-validation are
// different identifiers, joined through the descriptor. A policy declaring
// several checks cannot attribute its sub-validations to one rule.
func TestAlternateCatalogEvidence(t *testing.T) {
	a := newAlt()
	c := a.content(t)
	rot := contrib{binding: "bind-a", revision: "r1", policy: "rotate-keys-policy", bundle: c.Bundle, validations: 2}
	cap := capture(t, []contrib{rot}, pod("p1"))
	at := evStarted.Add(time.Minute)
	cap.Reports = append(cap.Reports, result(rot.enginePolicy(), 0, pod("p1"), "pass", at), result(rot.enginePolicy(), 1, pod("p1"), "fail", at))
	ev := evaluated(t, cap, evMaxAge)
	r := Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t), Evidence: ev})
	noNIST(t, r)
	op1 := row(t, r, "op1")
	ch := checkOf(t, op1, "rotate-keys")
	e, o := counts(t, "rotate-keys", ch.Evidence.EvidenceView)
	if ch.Policy != "rotate-keys-policy" || e.Expected != 2 || o.Pass != 1 || o.Fail != 1 {
		t.Fatalf("rotate-keys %+v %+v %+v", ch, e, o)
	}
	if len(op1.StatementEvidence) != 1 || op1.StatementEvidence[0].ID != "op1-req-a" {
		t.Errorf("statement evidence %+v", op1.StatementEvidence)
	}
	if x := row(t, r, "fa1"); x.Automation != AutomationNone || x.Evidence != nil {
		t.Errorf("fa1 %+v", x)
	}

	// One policy providing both rules: unresolved, never split by guess.
	b := newAlt()
	b.policies = []bundle.Policy{{Name: "rotate-keys-policy", Path: altDir + "policies/rotate.yaml",
		Checks: []bundle.Check{{RuleID: "rotate-keys", CheckID: "rotate-keys"}, {RuleID: "no-root", CheckID: "no-root"}}}}
	c = b.content(t)
	rot.bundle = c.Bundle
	cap = capture(t, []contrib{rot}, pod("p1"))
	reportAll(&cap, at, "pass")
	r = Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t), Evidence: evaluated(t, cap, evMaxAge)})
	for _, id := range []string{"op1", "op2"} {
		x := row(t, r, id)
		if x.Evidence == nil || x.Evidence.Resolved || x.Evidence.Evidence != nil || !hasCode(x.Limitations, CodeEvidenceCheckAmbiguous) {
			t.Errorf("%s %+v %v", id, x.Evidence, x.Limitations)
		}
	}
	for _, rec := range r.TechnicalEvidence.Observations {
		if len(rec.Controls) > 0 {
			t.Errorf("ambiguous observation attributed to %v", rec.Controls)
		}
	}
	if r.TechnicalEvidence.Contributions[0].Attribution != AttributionUnresolved || !hasCode(r.Limitations, CodeEvidenceUnattributed) {
		t.Errorf("contributions %+v limitations %v", r.TechnicalEvidence.Contributions, r.Limitations)
	}
}

// When the baseline cannot be resolved, technical evidence is retained as
// recorded and attributed to no guessed control.
func TestUnresolvedInventoryRetainsEvidence(t *testing.T) {
	a := newAlt()
	a.altImport(0)["href"] = "missing-profile.json"
	c := a.content(t)
	rot := contrib{binding: "bind-a", revision: "r1", policy: "rotate-keys-policy", bundle: c.Bundle}
	cap := capture(t, []contrib{rot}, pod("p1"))
	reportAll(&cap, evStarted.Add(time.Minute), "fail")
	ev := evaluated(t, cap, evMaxAge)
	r := Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t), Evidence: ev})
	if r.Inventory.Resolved || len(r.Controls) != 0 {
		t.Fatalf("inventory %+v", r.Inventory)
	}
	te := r.TechnicalEvidence
	if te.State != EvidenceResolved || *te.Outcomes != ev.Evaluation.Outcomes || len(te.Observations) != 1 || te.Observations[0].Observation.Outcome != "fail" {
		t.Fatalf("evidence not retained: %+v", te)
	}
	if len(te.Observations[0].Controls) != 0 || te.Contributions[0].Attribution != AttributionUnresolved {
		t.Errorf("guessed attribution: %+v %+v", te.Observations[0], te.Contributions)
	}
	if !strings.Contains(strings.Join(limitationCodes(r.Limitations), " "), CodeEvidenceUnattributed) {
		t.Errorf("limitations %v", r.Limitations)
	}
}
