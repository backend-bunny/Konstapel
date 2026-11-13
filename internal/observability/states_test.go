package observability

import (
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// One summary can meet several conditions; the projected status follows a
// fixed precedence, most conservative first:
//
//	current view expired > inventory lost > stale scope > inconsistent counts > no targets > known
//
// Only no_targets and known expose counts.
func TestStatePrecedence(t *testing.T) {
	noTargets := publication.EvidenceSummary{Completeness: publication.NoTargets}
	expired := ptr(t0)
	cases := []struct {
		name string
		v    CurrentView
		want AssessmentStatus
	}{
		{"expired beats no targets", CurrentView{Summary: Summary{Evidence: noTargets}, ValidUntil: expired}, AssessmentUnknown},
		{"expired beats complete", CurrentView{Summary: completeSummary(3, 0), ValidUntil: expired}, AssessmentUnknown},
		{"lost inventory beats no targets", CurrentView{Summary: Summary{Evidence: noTargets, InventoryUnknown: true}}, AssessmentUnknown},
		{"lost inventory beats complete", CurrentView{Summary: Summary{Evidence: completeSummary(1, 0).Evidence, Outcomes: completeSummary(1, 0).Outcomes, InventoryUnknown: true}}, AssessmentUnknown},
		{"stale scope beats known checks", CurrentView{Summary: Summary{
			Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 1, Attributable: 1, StaleScopes: 1},
			Outcomes: publication.OutcomeCounts{Pass: 1}}}, AssessmentUnknown},
		{"inconsistent no targets", CurrentView{Summary: Summary{Evidence: noTargets, Outcomes: publication.OutcomeCounts{Pass: 1}}}, AssessmentUnknown},
		{"no targets", CurrentView{Summary: Summary{Evidence: noTargets}, ValidUntil: ptr(t0.Add(time.Hour))}, AssessmentNoTargets},
		{"known", CurrentView{Summary: completeSummary(3, 0), ValidUntil: ptr(t0.Add(time.Hour))}, AssessmentKnown},
	}
	for _, c := range cases {
		p := projectCurrent(&c.v, t0)
		if p.status != c.want {
			t.Errorf("%s: %s, want %s", c.name, p.status, c.want)
		}
		if (p.counts != nil) != (c.want == AssessmentKnown || c.want == AssessmentNoTargets) {
			t.Errorf("%s: counts exposed=%v for %s", c.name, p.counts != nil, p.status)
		}
		if p.complete != nil && c.want != AssessmentKnown {
			t.Errorf("%s: completeness asserted for %s", c.name, p.status)
		}
	}
}

// An accepted risk is counted once, as accepted_risk, whatever the engine
// reported; a summary that would also count its raw outcome does not add up
// and is withheld rather than double counted.
func TestAcceptedRiskVersusRawOutcome(t *testing.T) {
	accepted := Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 2, Attributable: 2},
		Outcomes: publication.OutcomeCounts{AcceptedRisk: 1, Fail: 1},
	}
	p := projectSummary(accepted)
	if p.status != AssessmentKnown || p.counts["accepted_risk"] != 1 || p.counts["fail"] != 1 || p.counts["pass"] != 0 {
		t.Errorf("accepted risk next to a failure: %+v", p)
	}
	double := accepted
	double.Outcomes.Fail = 2 // the accepted check also counted as its raw fail
	if p := projectSummary(double); p.status != AssessmentUnknown || p.counts != nil {
		t.Errorf("a double-counted acceptance was exposed: %+v", p)
	}
	passAccepted := Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 1, Attributable: 1},
		Outcomes: publication.OutcomeCounts{AcceptedRisk: 1},
	}
	if p := projectSummary(passAccepted); p.counts["pass"] != 0 || p.counts["accepted_risk"] != 1 {
		t.Errorf("an acceptance counted as pass: %+v", p)
	}
}

// Missing, rejected and unresolved evidence stay distinct and never pass.
func TestMissingRejectedUnresolvedStayDistinct(t *testing.T) {
	p := projectSummary(Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 7, Attributable: 1, Missing: 1, Rejected: 2, Unresolved: 3},
		Outcomes: publication.OutcomeCounts{Pass: 1},
	})
	if p.status != AssessmentKnown || p.counts["missing"] != 1 || p.counts["rejected"] != 2 || p.counts["unresolved"] != 3 || p.counts["pass"] != 1 || *p.complete {
		t.Errorf("evidence gaps: %+v", p)
	}
}

// The current evidence expiry is the bounded freshness signal: exposed
// before and after it passes, never extended by refreshes, and absent when
// the owner records none.
func TestCurrentEvidenceExpirySignal(t *testing.T) {
	h, clk := newHub(t, DomainAssessment)
	term := h.Acquire()
	s := assessmentOf(alpha, beta)
	s.Bindings[0].Current.ValidUntil = ptr(t0.Add(time.Minute))
	s.Bindings[1].Current.ValidUntil = nil
	mustOK(t, h.PublishAssessment(term, t0, s))
	key := `konstapel_binding_current_evidence_expiry_timestamp_seconds{binding="alpha"}`
	if got := scrape(t, h)[key]; got != float64(t0.Add(time.Minute).Unix()) {
		t.Fatalf("expiry before it passes: %v", got)
	}
	clk.SetTime(t0.Add(time.Minute))
	mustOK(t, h.PublishAssessment(term, clk.Now(), s))
	got := scrape(t, h)
	if got[key] != float64(t0.Add(time.Minute).Unix()) || got[`konstapel_binding_assessment_status{binding="alpha",status="unknown",view="current"}`] != 1 {
		t.Errorf("after expiry: expiry %v, status unknown %v", got[key], got[`konstapel_binding_assessment_status{binding="alpha",status="unknown",view="current"}`])
	}
	if _, ok := got[`konstapel_binding_current_evidence_expiry_timestamp_seconds{binding="beta"}`]; ok {
		t.Error("an expiry the owner did not record is exposed")
	}
}
