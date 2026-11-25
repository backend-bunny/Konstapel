package reporttest_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const postureCheck = "baseline"

var evaluatedAt = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

func subject(workload, image string) reporttest.Subject {
	return reporttest.Subject{NamespaceUID: "ns-shop", WorkloadUID: workload, Container: "app", Image: image}
}

func pinned(c byte) string { return "registry.example/shop@" + digest(c) }

func postureReport(id string, d string, at *time.Time, verdict string) reporttest.Report {
	return reporttest.Report{ID: id, Digest: d, EvaluatedAt: at, Verdicts: map[string]string{postureCheck: verdict}}
}

func input(subjects []reporttest.Subject, reports ...reporttest.Report) reporttest.Input {
	return reporttest.Input{PayloadVersion: reporttest.PayloadVersion, MaxEvidenceAge: "1h", Subjects: subjects, Checks: []string{postureCheck}, Reports: reports}
}

func evaluateAt(t *testing.T, in reporttest.Input, at time.Time) conformance.Evaluation {
	t.Helper()
	ev, err := reporttest.Evaluate(in, at)
	if err != nil {
		t.Fatal(err)
	}
	// The adapter is the same evaluator behind a strict decode.
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	via, err := reporttest.Adapter{}.Evaluate(raw, at)
	if err != nil || !sameEvaluation(ev, via) {
		t.Fatalf("adapter differs from the pure evaluator: %v", err)
	}
	return ev
}

func sameEvaluation(a, b conformance.Evaluation) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func one(t *testing.T, ev conformance.Evaluation) conformance.Observation {
	t.Helper()
	if len(ev.Observations) != 1 {
		t.Fatalf("observations %+v", ev.Observations)
	}
	return ev.Observations[0]
}

// Freshness is decided at the explicit time only: evidence exactly
// maxEvidenceAge old is current, a nanosecond more is rejected, evidence
// after the time is rejected, and a fresh update time renews nothing.
func TestReportingEvaluateFreshnessBoundaries(t *testing.T) {
	subs := []reporttest.Subject{subject("w-1", pinned('a'))}
	in := input(subs, postureReport("r", digest('a'), &evaluatedAt, "Passed"))
	for name, tc := range map[string]struct {
		at    time.Time
		state conformance.State
	}{
		"evaluated at the boundary":    {evaluatedAt, conformance.Attributable},
		"at exact expiry":              {evaluatedAt.Add(time.Hour), conformance.Attributable},
		"one nanosecond past expiry":   {evaluatedAt.Add(time.Hour + time.Nanosecond), conformance.Rejected},
		"evaluated after the boundary": {evaluatedAt.Add(-time.Nanosecond), conformance.Rejected},
	} {
		if o := one(t, evaluateAt(t, in, tc.at)); o.State != tc.state {
			t.Errorf("%s: %+v, want %s", name, o, tc.state)
		}
	}

	updated := evaluatedAt.Add(2 * time.Hour)
	old := postureReport("r", digest('a'), &evaluatedAt, "Passed")
	old.UpdatedAt = &updated
	if o := one(t, evaluateAt(t, input(subs, old), updated)); o.State != conformance.Rejected {
		t.Errorf("an updated report with an old evaluation: %+v", o)
	}
	if o := one(t, evaluateAt(t, input(subs, postureReport("r", digest('a'), nil, "Passed")), evaluatedAt)); o.State != conformance.Rejected {
		t.Errorf("an untimed report: %+v", o)
	}
	if _, err := reporttest.Evaluate(in, time.Time{}); err == nil {
		t.Error("zero evaluation time accepted")
	}
}

// Evidence that cannot be attributed establishes nothing: a subject that
// runs a tag, not a digest, and equally new conflicting verdicts.
func TestReportingEvaluateAmbiguousProvenance(t *testing.T) {
	tagged := input([]reporttest.Subject{subject("w-1", "registry.example/shop:latest")}, postureReport("r", digest('a'), &evaluatedAt, "Passed"))
	conflict := input([]reporttest.Subject{subject("w-1", pinned('a'))},
		postureReport("r1", digest('a'), &evaluatedAt, "Passed"), postureReport("r2", digest('a'), &evaluatedAt, "Violated"))
	for name, in := range map[string]reporttest.Input{"tagged image": tagged, "conflicting verdicts": conflict} {
		ev := evaluateAt(t, in, evaluatedAt)
		if o := one(t, ev); o.State != conformance.Unresolved || o.Outcome != "" || o.Raw != "" {
			t.Errorf("%s: %+v", name, o)
		}
		if _, out := conformance.Summarize(ev); out != (publication.OutcomeCounts{}) {
			t.Errorf("%s: outcomes %+v", name, out)
		}
	}
}

// Shared evidence keeps each association's own identity without duplicate
// credit: one report shared by two workloads attributes each once, a
// repeated report counts once, and a subject or check listed twice is an
// invalid payload, not a second observation.
func TestReportingEvaluateDuplicateAssociations(t *testing.T) {
	subs := []reporttest.Subject{subject("w-1", pinned('a')), subject("w-2", pinned('a'))}
	r := postureReport("r", digest('a'), &evaluatedAt, "Passed")
	ev := evaluateAt(t, input(subs, r, r), evaluatedAt)
	if len(ev.Observations) != 2 || ev.Observations[0].Subject == ev.Observations[1].Subject {
		t.Fatalf("observations %+v", ev.Observations)
	}
	if e, o := conformance.Summarize(ev); e.Expected != 2 || e.Attributable != 2 || o.Pass != 2 {
		t.Fatalf("summary %+v %+v", e, o)
	}
	for name, in := range map[string]reporttest.Input{
		"subject twice": input([]reporttest.Subject{subs[0], subs[0]}, r),
		"check twice":   {PayloadVersion: reporttest.PayloadVersion, MaxEvidenceAge: "1h", Subjects: subs, Checks: []string{postureCheck, postureCheck}},
	} {
		if _, err := reporttest.Evaluate(in, evaluatedAt); err == nil {
			t.Errorf("%s accepted by Evaluate", name)
		}
		raw, _ := json.Marshal(in)
		if _, err := (reporttest.Adapter{}).Inventory(raw); err == nil {
			t.Errorf("%s accepted by Inventory", name)
		}
	}
}

// A not-applicable verdict is attributable, kept raw and never a pass; an
// unrecognized warning verdict is kept raw and counted once as unknown.
func TestReportingEvaluateApplicabilityAndWarnings(t *testing.T) {
	subs := []reporttest.Subject{subject("w-1", pinned('a'))}
	for raw, want := range map[string]publication.OutcomeCounts{
		"NotApplicable": {NotApplicable: 1},
		"Warned":        {Unknown: 1},
	} {
		ev := evaluateAt(t, input(subs, postureReport("r", digest('a'), &evaluatedAt, raw), postureReport("r2", digest('a'), &evaluatedAt, raw)), evaluatedAt)
		o := one(t, ev)
		if o.State != conformance.Attributable || o.Raw != raw || o.Outcome != conformance.Unknown || o.NotApplicable != (raw == "NotApplicable") {
			t.Errorf("%s: %+v", raw, o)
		}
		if _, out := conformance.Summarize(ev); out != want {
			t.Errorf("%s: outcomes %+v, want %+v", raw, out, want)
		}
	}
}
