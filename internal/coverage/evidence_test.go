package coverage

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	pEsc     = "disallow-privilege-escalation"
	pNonroot = "require-run-as-nonroot"
	pCaps    = "disallow-capabilities-strict"
	pSeccomp = "restrict-seccomp-strict"
)

// statesFixture is one binding of the hardening bundle with current,
// missing, rejected, conflicting, warn and changed-scope observations.
func statesFixture(t *testing.T) (Content, *Evidence) {
	t.Helper()
	c := official(t, hardening)
	p1, p2, p3 := pod("p1"), pod("p2"), pod("p3")
	esc := contrib{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}
	nonroot := contrib{binding: "bind-a", revision: "r1", policy: pNonroot, bundle: c.Bundle}
	caps := contrib{binding: "bind-a", revision: "r1", policy: pCaps, bundle: c.Bundle, validations: 2}
	cap := capture(t, []contrib{esc, nonroot, caps}, p1, p2, p3)
	at := evStarted.Add(time.Minute)
	cap.Reports = append(cap.Reports,
		result(esc.enginePolicy(), 0, p1, "pass", at), // current pass
		result(esc.enginePolicy(), 0, p2, "fail", at), // current fail
		// nonroot p1: no result (missing)
		result(nonroot.enginePolicy(), 0, p2, "pass", evStarted.Add(-time.Minute)), // before the continuity boundary: rejected
		result(caps.enginePolicy(), 0, p1, "pass", at), result(caps.enginePolicy(), 0, p1, "fail", at), // conflicting
		result(caps.enginePolicy(), 1, p1, "warn", at), // Kyverno warn: unknown
		result(caps.enginePolicy(), 0, p2, "pass", at), result(caps.enginePolicy(), 1, p2, "pass", at),
	)
	// p3 changed during collection: all its observations are unresolved,
	// whatever its results say.
	cap.Reports = append(cap.Reports, result(esc.enginePolicy(), 0, p3, "pass", at), result(nonroot.enginePolicy(), 0, p3, "pass", at),
		result(caps.enginePolicy(), 0, p3, "pass", at), result(caps.enginePolicy(), 1, p3, "pass", at))
	changed := p3
	changed.StateSHA256 = "state-p3-updated"
	cap.ScopeChanges = []collector.ScopeChange{{Kind: collector.WorkloadUpdated, Observed: evStarted.Add(2 * time.Minute), Namespace: evNS, NamespaceUID: evNSUID, Previous: &p3, Current: &changed}}
	return c, evaluated(t, cap, evMaxAge)
}

func allHardening(c Content) Selection {
	return selecting(c, privPolicy, pEsc, pNonroot, pCaps, pSeccomp)
}

func counts(t *testing.T, what string, v EvidenceView) (publication.EvidenceSummary, publication.OutcomeCounts) {
	t.Helper()
	if !v.Resolved || v.Evidence == nil || v.Outcomes == nil {
		t.Fatalf("%s: unresolved view %+v", what, v)
	}
	return *v.Evidence, *v.Outcomes
}

// The collector's frozen states, outcomes and reasons reach the report
// unchanged, and each selected check counts exactly its observations.
func TestEvidencePreservesCollectorResults(t *testing.T) {
	c, ev := statesFixture(t)
	r := Build(Input{Content: c, Selection: allHardening(c), Options: opts(t), Evidence: ev})
	te := r.TechnicalEvidence
	if te.State != EvidenceResolved || anyBlocking(r.Limitations) {
		t.Fatalf("state %s limitations %v", te.State, r.Limitations)
	}
	if *te.Evidence != ev.Evaluation.Evidence || *te.Outcomes != ev.Evaluation.Outcomes || !r.AsOf.Equal(evClosed) {
		t.Fatalf("summary %+v %+v asOf %s; owner %+v %+v", *te.Evidence, *te.Outcomes, r.AsOf, ev.Evaluation.Evidence, ev.Evaluation.Outcomes)
	}
	// Every observation is retained verbatim, joined by its exact key.
	if len(te.Observations) != len(ev.Capture.Expected) {
		t.Fatalf("%d records for %d expected observations", len(te.Observations), len(ev.Capture.Expected))
	}
	byKey := map[string]collector.Observation{}
	for _, o := range ev.Evaluation.Observations {
		byKey[o.Key] = o
	}
	for _, e := range ev.Capture.Expected {
		rec := record(t, r, e.Key())
		if !reflect.DeepEqual(rec.Expected, e) || !reflect.DeepEqual(rec.Observation, byKey[e.Key()]) {
			t.Errorf("record %+v is not the owner's %+v %+v", rec, e, byKey[e.Key()])
		}
	}
	states := map[collector.ObservationState]int{}
	reasons := ""
	for _, o := range te.Observations {
		states[o.Observation.State]++
		reasons += strings.Join(o.Observation.Reasons, ";") + ";"
		if o.Observation.Outcome == "warn" && o.Observation.State != collector.Attributable {
			t.Errorf("warn observation %+v", o.Observation)
		}
	}
	if states[collector.Attributable] != 5 || states[collector.Missing] != 1 || states[collector.Rejected] != 1 || states[collector.Unresolved] != 5 {
		t.Fatalf("states %v", states)
	}
	for _, want := range []string{"conflicting results evaluated at the same time", "WorkloadUpdated during collection", "not after the observed-state boundary"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("reason %q is not retained", want)
		}
	}

	ac6 := row(t, r, "ac-6")
	cases := []struct {
		rule string
		ev   publication.EvidenceSummary
		out  publication.OutcomeCounts
	}{
		{pEsc, publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 3, Attributable: 2, Unresolved: 1}, publication.OutcomeCounts{Pass: 1, Fail: 1}},
		{pNonroot, publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 3, Missing: 1, Rejected: 1, Unresolved: 1}, publication.OutcomeCounts{}},
		// The warn is counted once, as unknown: never a pass or a failure.
		{pCaps, publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 6, Attributable: 3, Unresolved: 3}, publication.OutcomeCounts{Pass: 2, Unknown: 1}},
		// Selected with zero targets: neither covered nor missing.
		{privPolicy, publication.EvidenceSummary{Completeness: publication.NoTargets}, publication.OutcomeCounts{}},
	}
	for _, tc := range cases {
		ch := checkOf(t, ac6, tc.rule)
		e, o := counts(t, tc.rule, ch.Evidence.EvidenceView)
		if e != tc.ev || o != tc.out {
			t.Errorf("%s: %+v %+v, want %+v %+v", tc.rule, e, o, tc.ev, tc.out)
		}
	}
	// The owner's failure and the incomplete evidence stay visible together
	// on the control; nothing is a control verdict.
	e, o := counts(t, "ac-6", *ac6.Evidence)
	if e.Completeness != publication.Incomplete || e.Expected != 12 || e.Missing != 1 || o.Fail != 1 || o.Pass != 3 || ac6.Automation != AutomationPartial {
		t.Errorf("ac-6 %s %+v %+v", ac6.Automation, e, o)
	}
}

// Coverage takes the owner's frozen evaluation as recorded: the same
// capture evaluated with a different evidence-age limit gives a different
// report, and a reader's later clock never renews or expires evidence.
func TestEvidenceFreshnessIsTheOwners(t *testing.T) {
	c := official(t, hardening)
	cap := capture(t, []contrib{{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}}, pod("p1"), pod("p2"))
	reportAll(&cap, evStarted.Add(time.Minute), "pass") // nine minutes old at closure
	for _, tc := range []struct {
		age   time.Duration
		state collector.ObservationState
		pass  int
	}{{evMaxAge, collector.Attributable, 2}, {time.Minute, collector.Rejected, 0}} {
		ev := evaluated(t, cap, tc.age)
		r := Build(Input{Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: ev})
		for _, o := range r.TechnicalEvidence.Observations {
			if o.Observation.State != tc.state {
				t.Errorf("age %s: %s, owner recorded %s", tc.age, o.Observation.State, tc.state)
			}
		}
		e, out := counts(t, "esc", checkOf(t, row(t, r, "ac-6"), pEsc).Evidence.EvidenceView)
		if out.Pass != tc.pass || e != ev.Evaluation.Evidence {
			t.Errorf("age %s: %+v %+v, owner %+v", tc.age, e, out, ev.Evaluation.Evidence)
		}
	}
	// A report claiming a time other than the capture's closure is refused.
	ev := evaluated(t, cap, evMaxAge)
	r := Build(Input{AsOf: evClosed.Add(30 * 24 * time.Hour), Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: ev})
	if r.TechnicalEvidence.State != EvidenceUnresolved || !hasCode(r.Limitations, CodeEvidenceScopeMismatch) {
		t.Fatalf("later reader time accepted: %s %v", r.TechnicalEvidence.State, r.Limitations)
	}
	if ch := checkOf(t, row(t, r, "ac-6"), pEsc); ch.Evidence.Resolved || ch.Evidence.Evidence != nil {
		t.Errorf("unresolved evidence still counted: %+v", ch.Evidence)
	}
}

// An evaluation that does not match its capture is retained as recorded but
// attributed to nothing; it is never repaired or recounted into a result.
func TestInconsistentEvidenceIsNotAttributed(t *testing.T) {
	c, ev := statesFixture(t)
	for name, mutate := range map[string]func(*Evidence){
		"state changed": func(e *Evidence) {
			for i, o := range e.Evaluation.Observations {
				if o.State == collector.Missing {
					e.Evaluation.Observations[i].State, e.Evaluation.Observations[i].Outcome = collector.Attributable, "pass"
				}
			}
		},
		"observation dropped": func(e *Evidence) { e.Evaluation.Observations = e.Evaluation.Observations[1:] },
		"unknown key": func(e *Evidence) {
			e.Evaluation.Observations[0].Key += "x"
		},
		"capture narrowed": func(e *Evidence) { e.Capture.Expected = e.Capture.Expected[1:] },
		"repeated with another result": func(e *Evidence) {
			o := e.Evaluation.Observations[0]
			o.Outcome = "fail"
			e.Evaluation.Observations = append(e.Evaluation.Observations, o)
		},
		"other cluster": func(e *Evidence) {},
	} {
		t.Run(name, func(t *testing.T) {
			e := &Evidence{Capture: clone(ev.Capture), Evaluation: clone(ev.Evaluation)}
			mutate(e)
			in := Input{Content: c, Selection: allHardening(c), Options: opts(t), Evidence: e}
			if name == "other cluster" {
				in.Scope.Cluster = "cluster-2"
			}
			r := Build(in)
			te := r.TechnicalEvidence
			if te.State != EvidenceUnresolved || !anyBlocking(r.Limitations) {
				t.Fatalf("state %s limitations %v", te.State, r.Limitations)
			}
			if *te.Evidence != e.Evaluation.Evidence {
				t.Errorf("owner summary not retained verbatim")
			}
			for _, o := range te.Observations {
				if len(o.Controls) > 0 {
					t.Errorf("%q attributed to %v", o.Observation.Key, o.Controls)
				}
			}
			for _, x := range te.Contributions {
				if x.Attribution != AttributionUnresolved {
					t.Errorf("contribution %+v", x)
				}
			}
			ac6 := row(t, r, "ac-6")
			if ac6.Evidence == nil || ac6.Evidence.Resolved || ac6.Evidence.Evidence != nil || ac6.Automation != AutomationPartial {
				t.Errorf("ac-6 %s %+v", ac6.Automation, ac6.Evidence)
			}
		})
	}
}

// A selected check with zero targets, a stale scope and a control without
// mappings stay distinct: none of them is a pass or invents observations.
func TestZeroTargetsStaleScopeAndNoMapping(t *testing.T) {
	c := official(t, hardening)
	cap := capture(t, []contrib{{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}}, pod("p1"))
	reportAll(&cap, evStarted.Add(time.Minute), "pass")
	sel := selecting(c, pEsc, pSeccomp, pNonroot)
	r := Build(Input{Content: c, Selection: sel, Options: opts(t), Evidence: evaluated(t, cap, evMaxAge)})

	cm7 := row(t, r, "cm-7") // capabilities (unselected) and seccomp (selected, no targets)
	if cm7.Automation != AutomationPartial || checkOf(t, cm7, pCaps).Evidence != nil {
		t.Fatalf("cm-7 %s %+v", cm7.Automation, cm7.Checks)
	}
	e, o := counts(t, "seccomp", checkOf(t, cm7, pSeccomp).Evidence.EvidenceView)
	if e != (publication.EvidenceSummary{Completeness: publication.NoTargets}) || o != (publication.OutcomeCounts{}) {
		t.Errorf("zero targets: %+v %+v", e, o)
	}
	if e, _ := counts(t, "cm-7", *cm7.Evidence); e.Completeness != publication.NoTargets {
		t.Errorf("cm-7 evidence %+v", e)
	}
	for _, id := range []string{"pe-3", "ac-2", "sc-7"} {
		x := row(t, r, id)
		if x.Automation != AutomationNone || x.Evidence != nil || len(x.Checks) != 0 || x.StatementEvidence != nil {
			t.Errorf("%s: %s %+v; no automation must not gain evidence", id, x.Automation, x.Evidence)
		}
	}

	// A stale scope makes its policy's expected checks unknown: incomplete,
	// never no-targets, and the binding-wide one affects every check.
	cap.Stale = []targeting.StaleScope{{Binding: targeting.ObjectRevision{Name: "bind-a", UID: "bind-a"}, Policy: pSeccomp, Reason: "BundleUnavailable"}}
	r = Build(Input{Content: c, Selection: sel, Options: opts(t), Evidence: evaluated(t, cap, evMaxAge)})
	e, _ = counts(t, "seccomp", checkOf(t, row(t, r, "cm-7"), pSeccomp).Evidence.EvidenceView)
	if e.Completeness != publication.Incomplete || e.StaleScopes != 1 || e.Expected != 0 {
		t.Errorf("stale seccomp: %+v", e)
	}
	if e, _ := counts(t, "esc", checkOf(t, row(t, r, "ac-6"), pEsc).Evidence.EvidenceView); e.Completeness != publication.Complete {
		t.Errorf("a policy-scoped stale scope affected another check: %+v", e)
	}
	if e, _ := counts(t, "ac-6", *row(t, r, "cm-6").Evidence); e.StaleScopes != 1 || e.Completeness != publication.Incomplete {
		t.Errorf("cm-6 hides its stale seccomp check: %+v", e)
	}
	cap.Stale[0].Policy = ""
	r = Build(Input{Content: c, Selection: sel, Options: opts(t), Evidence: evaluated(t, cap, evMaxAge)})
	if e, _ := counts(t, "esc", checkOf(t, row(t, r, "ac-6"), pEsc).Evidence.EvidenceView); e.Completeness != publication.Incomplete || e.StaleScopes != 1 {
		t.Errorf("binding-wide stale scope: %+v", e)
	}
}

// Without evidence the report says so; it is not an empty result.
func TestEvidenceNotProvided(t *testing.T) {
	c := official(t, hardening)
	r := Build(Input{Content: c, Selection: allHardening(c), Options: opts(t)})
	if r.TechnicalEvidence.State != EvidenceNotProvided || r.TechnicalEvidence.Evidence != nil || len(r.TechnicalEvidence.Observations) != 0 {
		t.Fatalf("%+v", r.TechnicalEvidence)
	}
	for _, x := range r.Controls {
		if x.Evidence != nil || x.StatementEvidence != nil {
			t.Errorf("%s has evidence without input", x.ID)
		}
		for _, ch := range x.Checks {
			if ch.Evidence != nil {
				t.Errorf("%s/%s has evidence without input", x.ID, ch.RuleID)
			}
		}
	}
}
