package collector

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const maxAge = 2 * time.Hour

// freshCapture is captureV2 with stale scopes cleared, closed 5 minutes after
// it started. Its expected observations are pod-dev x audit-all, and pod-prod
// x audit-all and deny-production.
func freshCapture(t *testing.T) CaptureV2 {
	c := captureV2(t)
	c.Stale = nil
	return c
}

func result(policyName string, index int, uid, outcome string, at time.Time) assessment.Object {
	r := assessment.Object{"policy": policyName, "result": outcome, "source": "KyvernoValidatingPolicy",
		"properties": assessment.Object{"cel.validationIndex": strconv.Itoa(index)}}
	if !at.IsZero() {
		r["timestamp"] = assessment.Object{"seconds": float64(at.Unix()), "nanos": float64(at.Nanosecond())}
	}
	return r
}

func report(uid string, ns string, workloadUID string, results ...assessment.Object) assessment.Object {
	rs := make([]any, len(results))
	for i, r := range results {
		rs[i] = r
	}
	return assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
		"metadata": assessment.Object{"uid": uid, "namespace": ns}, "scope": assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": ns, "uid": workloadUID}, "results": rs}
}

// reportsAt reports every expected observation as evaluated at time at.
func reportsAt(c CaptureV2, at time.Time, outcome func(Expected) string) []assessment.Object {
	var out []assessment.Object
	for i, e := range c.Expected {
		out = append(out, report("r"+strconv.Itoa(i), "ns", e.Workload.UID, result(e.Check.EnginePolicy, e.Check.Index, e.Workload.UID, outcome(e), at)))
	}
	return out
}

func evaluate(t *testing.T, c CaptureV2, bs []Boundary, age time.Duration) Evaluation {
	t.Helper()
	ev, err := c.Evaluate(bs, age)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func states(ev Evaluation) map[ObservationState]int {
	m := map[ObservationState]int{}
	for _, o := range ev.Observations {
		m[o.State]++
	}
	return m
}

func failProd(e Expected) string {
	if e.Workload.UID == "pod-prod" {
		return "fail"
	}
	return "pass"
}

func TestFreshEvidenceIsCompleteAndKeepsFailures(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	ev, err := c.Evaluate(nil, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Evidence.Completeness != publication.Complete || ev.Outcomes.Fail != 2 || ev.Outcomes.Pass != 1 {
		t.Fatalf("%+v %+v", ev.Evidence, ev.Outcomes)
	}
	// Overlapping bindings are two observations, not one doubled pass.
	if ev.Evidence.Expected != 3 {
		t.Fatal("overlapping contributions must stay distinct")
	}
	want := c.Window.Started.Add(time.Minute + maxAge)
	if ev.NextExpiry == nil || !ev.NextExpiry.Equal(want) {
		t.Fatalf("next expiry %v, want %v", ev.NextExpiry, want)
	}
	if err = ev.Evidence.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOldStateResultsAreNotCurrentEvidence(t *testing.T) {
	c := freshCapture(t)
	// Evaluated recently (30 min before the run), but before the collector
	// had observed the current state: no proof it evaluated that state.
	c.Reports = reportsAt(c, c.Window.Started.Add(-30*time.Minute), func(Expected) string { return "pass" })
	ev := evaluate(t, c, nil, maxAge)
	if ev.Evidence.Completeness != publication.Incomplete || states(ev)[Rejected] != 3 || ev.Outcomes.Pass != 0 {
		t.Fatalf("old-state results counted: %+v", ev.Evidence)
	}
	if !strings.Contains(strings.Join(ev.Observations[0].Reasons, ";"), "not after the observed-state boundary") {
		t.Fatal(ev.Observations[0].Reasons)
	}
	// With continuous observation of the same state since before the
	// evaluation, the same results are attributable.
	var bs []Boundary
	for _, w := range c.Workloads {
		bs = append(bs, Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: c.Window.Started.Add(-time.Hour)})
	}
	if ev = evaluate(t, c, bs, maxAge); ev.Evidence.Completeness != publication.Complete {
		t.Fatalf("continuously observed state rejected: %+v", ev.Evidence)
	}
	// A boundary for a different state proves nothing about the frozen state.
	for i := range bs {
		bs[i].StateSHA256 = "other-state"
	}
	if ev = evaluate(t, c, bs, maxAge); states(ev)[Rejected] != 3 {
		t.Fatal("boundary for another state accepted")
	}
}

func TestTimestampsMustBeValidAndNotInTheFuture(t *testing.T) {
	c := freshCapture(t)
	e0, e1 := c.Expected[0], c.Expected[1]
	c.Reports = []assessment.Object{
		report("missing-ts", "ns", e0.Workload.UID, result(e0.Check.EnginePolicy, e0.Check.Index, e0.Workload.UID, "pass", time.Time{})),
		report("future", "ns", e1.Workload.UID, result(e1.Check.EnginePolicy, e1.Check.Index, e1.Workload.UID, "pass", c.Window.Closed.Add(time.Minute))),
	}
	ev := evaluate(t, c, nil, maxAge)
	if s := states(ev); s[Rejected] != 2 || s[Missing] != 1 || ev.Outcomes.Pass != 0 {
		t.Fatalf("invalid timestamps accepted: %v", s)
	}
	joined := ""
	for _, o := range ev.Observations {
		joined += strings.Join(o.Reasons, ";")
	}
	if !strings.Contains(joined, "missing source evaluation timestamp") || !strings.Contains(joined, "after closure") {
		t.Fatal(joined)
	}
}

func TestAgeAtClosureExpiresEvidence(t *testing.T) {
	c := freshCapture(t)
	var bs []Boundary
	for _, w := range c.Workloads {
		bs = append(bs, Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: c.Window.Started.Add(-24 * time.Hour)})
	}
	evaluated := c.Window.Closed.Add(-maxAge + time.Minute)
	c.Reports = reportsAt(c, evaluated, func(Expected) string { return "pass" })
	if ev := evaluate(t, c, bs, maxAge); ev.Evidence.Completeness != publication.Complete {
		t.Fatalf("fresh evidence rejected: %+v", ev.Evidence)
	}
	// The same results evaluated for current status two minutes later have
	// aged past maxEvidenceAge: stale before any 24h snapshot tick.
	later := c
	later.Window.Closed = c.Window.Closed.Add(2 * time.Minute)
	ev := evaluate(t, later, bs, maxAge)
	if ev.Evidence.Completeness != publication.Incomplete || states(ev)[Rejected] != 3 || ev.NextExpiry != nil {
		t.Fatalf("expired evidence counted: %+v", ev.Evidence)
	}
	if !strings.Contains(strings.Join(ev.Observations[0].Reasons, ";"), "exceeds maxEvidenceAge") {
		t.Fatal(ev.Observations[0].Reasons)
	}
}

func TestWatchDiscontinuityDiscardsContinuity(t *testing.T) {
	c := freshCapture(t)
	var bs []Boundary
	for _, w := range c.Workloads {
		bs = append(bs, Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: c.Window.Started.Add(-time.Hour)})
	}
	restart := c.Window.Started.Add(2 * time.Minute)
	NewTracker(&c).Discontinuity(restart, "controller restart; relisted")
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return "pass" })
	ev, err := c.Evaluate(bs, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if states(ev)[Rejected] != 3 {
		t.Fatalf("pre-restart evaluation accepted after relist: %+v", ev.Evidence)
	}
	// An evaluation after the restart re-establishes attributable evidence.
	c.Reports = reportsAt(c, restart.Add(time.Minute), func(Expected) string { return "pass" })
	if ev = evaluate(t, c, bs, maxAge); ev.Evidence.Completeness != publication.Complete {
		t.Fatalf("post-restart evaluation rejected: %+v", ev.Evidence)
	}
}

func TestChangedOrConflictingEvidenceIsUnresolved(t *testing.T) {
	c := freshCapture(t)
	at := c.Window.Started.Add(time.Minute)
	updated := c.Workloads[0]
	updated.StateSHA256 = "in-place-update"
	NewTracker(&c).Workload(at, updated, false)
	c.Reports = reportsAt(c, at.Add(time.Minute), func(Expected) string { return "pass" })
	// A second, conflicting result for pod-prod/deny-production at the same time.
	for _, e := range c.Expected {
		if e.Workload.UID == "pod-prod" && strings.HasSuffix(e.Check.EnginePolicy, "835a035b40c0af8f") {
			c.Reports = append(c.Reports, report("conflict", "ns", e.Workload.UID, result(e.Check.EnginePolicy, e.Check.Index, e.Workload.UID, "fail", at.Add(time.Minute))))
		}
	}
	ev := evaluate(t, c, nil, maxAge)
	if s := states(ev); s[Unresolved] != 2 || s[Attributable] != 1 || ev.Evidence.Completeness != publication.Incomplete {
		t.Fatalf("changed/conflicting evidence: %v", s)
	}
}

func TestWrongRevisionOrCheckDoesNotSatisfy(t *testing.T) {
	c := freshCapture(t)
	at := c.Window.Started.Add(time.Minute)
	for _, e := range c.Expected {
		// Results from another revision's engine policy and another
		// sub-validation index.
		c.Reports = append(c.Reports,
			report("old-rev", "ns", e.Workload.UID, result("konstapel-disallow-privileged-containers-0000000000000000", e.Check.Index, e.Workload.UID, "pass", at)),
			report("other-check", "ns", e.Workload.UID, result(e.Check.EnginePolicy, e.Check.Index+1, e.Workload.UID, "pass", at)))
	}
	ev := evaluate(t, c, nil, maxAge)
	if states(ev)[Missing] != 3 || ev.Outcomes.Pass != 0 {
		t.Fatalf("unrelated results satisfied expectations: %+v", ev.Evidence)
	}
}

func TestStaleScopeAndZeroTargets(t *testing.T) {
	c := captureV2(t) // keeps the golden stale "dangling" binding
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return "pass" })
	ev := evaluate(t, c, nil, maxAge)
	if ev.Evidence.Attributable != 3 || ev.Evidence.StaleScopes != 1 || ev.Evidence.Completeness != publication.Incomplete || ev.Evidence.Validate() != nil {
		t.Fatalf("stale scope hidden: %+v", ev.Evidence)
	}
	empty := freshCapture(t)
	empty.Workloads, empty.Expected = []Workload{}, []Expected{}
	ev, err := empty.Evaluate(nil, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Evidence.Completeness != publication.NoTargets || ev.Outcomes != (publication.OutcomeCounts{}) {
		t.Fatalf("zero targets: %+v", ev.Evidence)
	}
	if err = ev.Evidence.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Reports read through the Kubernetes client decode integers as int64;
// reports read with encoding/json decode them as float64. Both are valid.
func TestEvaluationTimeAcceptsDecoderIntegerForms(t *testing.T) {
	want := time.Date(2026, 11, 5, 10, 1, 0, 5, time.UTC)
	for name, stamp := range map[string]assessment.Object{
		"int64":       {"seconds": want.Unix(), "nanos": int64(5)},
		"float64":     {"seconds": float64(want.Unix()), "nanos": float64(5)},
		"json.Number": {"seconds": json.Number(strconv.FormatInt(want.Unix(), 10)), "nanos": json.Number("5")},
	} {
		got, err := evaluationTime(assessment.Object{"timestamp": stamp})
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	for name, stamp := range map[string]assessment.Object{
		"fractional": {"seconds": 1.5},
		"string":     {"seconds": "1793836860"},
		"negative":   {"seconds": int64(-1)},
		"bad nanos":  {"seconds": int64(1), "nanos": int64(1e9)},
	} {
		if _, err := evaluationTime(assessment.Object{"timestamp": stamp}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := evaluationTime(assessment.Object{}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal("missing timestamp not reported as missing")
	}
}
