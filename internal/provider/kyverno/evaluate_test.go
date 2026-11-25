package kyverno_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Workloads and engine policies of the saved live capture.
const (
	savedCapture = "testdata/assessments/kyverno-1.19.2-background/capture.json"
	compliant    = "c449a7fd-5403-4ab0-bc14-61d9045c7260"
	runViolator  = "39ee35a7-d253-4129-bc2e-13870a64f18f"
	// nonroot has a single validation; capabilities has two.
	nonroot      = "konstapel-require-run-as-nonroot-1e869ab60b470d58"
	capabilities = "konstapel-disallow-capabilities-strict-1eaf6d77d78a3f58"
)

// saved is the saved capture with its reports replaced by reports.
func saved(t *testing.T, reports ...assessment.Object) collector.CaptureV2 {
	t.Helper()
	var c collector.CaptureV2
	if err := assessment.Read(filepath.Join(repoRoot(t), savedCapture), &c); err != nil {
		t.Fatal(err)
	}
	c.Reports = append([]assessment.Object{}, reports...)
	return c
}

// result is one PolicyReport result; index < 0 omits cel.validationIndex.
func evResult(policy, outcome string, index int, at time.Time, uids ...string) map[string]any {
	props := map[string]any{}
	if index >= 0 {
		props["cel.validationIndex"] = strconv.Itoa(index)
	}
	refs := []any{}
	for _, u := range uids {
		refs = append(refs, map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "hz-bg", "uid": u})
	}
	return map[string]any{"policy": policy, "result": outcome, "source": "KyvernoValidatingPolicy", "properties": props,
		"resources": refs, "timestamp": map[string]any{"seconds": at.Unix(), "nanos": int64(at.Nanosecond())}}
}

func evReport(uid string, results ...map[string]any) assessment.Object {
	rs := make([]any, len(results))
	for i, r := range results {
		rs[i] = r
	}
	return assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
		"metadata": map[string]any{"uid": uid, "namespace": "hz-bg"}, "results": rs}
}

// observation is the evaluated observation of (workload, policy, index).
func observation(t *testing.T, c collector.CaptureV2, ev collector.Evaluation, uid, policy string, index int) collector.Observation {
	t.Helper()
	for _, e := range c.Expected {
		if e.Workload.UID == uid && e.Check.EnginePolicy == policy && e.Check.Index == index {
			for _, o := range ev.Observations {
				if o.Key == e.Key() {
					return o
				}
			}
		}
	}
	t.Fatalf("no observation for %s %s#%d", uid, policy, index)
	return collector.Observation{}
}

func evalAt(t *testing.T, c collector.CaptureV2, age time.Duration, at time.Time) collector.Evaluation {
	t.Helper()
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: age}, at)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// Freshness is decided at the explicit time: evidence exactly
// maxEvidenceAge old is current, a nanosecond more is rejected; evidence
// evaluated at the boundary itself counts, a nanosecond after it does not;
// evidence evaluated at the observed-state boundary predates the state.
func TestEvaluateFreshnessBoundaries(t *testing.T) {
	base := saved(t)
	started := base.Window.Started
	evaluated := started.Add(30 * time.Second)
	const age = 2 * time.Hour
	c := saved(t, evReport("r", evResult(nonroot, "pass", -1, evaluated, compliant)))
	for name, tc := range map[string]struct {
		at     time.Time
		state  collector.ObservationState
		reason string
	}{
		"evaluated at the boundary":    {evaluated, collector.Attributable, ""},
		"at exact expiry":              {evaluated.Add(age), collector.Attributable, ""},
		"one nanosecond past expiry":   {evaluated.Add(age + time.Nanosecond), collector.Rejected, "exceeds maxEvidenceAge"},
		"evaluated after the boundary": {evaluated.Add(-time.Nanosecond), collector.Rejected, "is after closure"},
		"replay at the frozen closure": {base.Window.Closed, collector.Attributable, ""},
		"current state a day later":    {base.Window.Closed.Add(24 * time.Hour), collector.Rejected, "exceeds maxEvidenceAge"},
	} {
		t.Run(name, func(t *testing.T) {
			ev := evalAt(t, c, age, tc.at)
			o := observation(t, c, ev, compliant, nonroot, 0)
			if o.State != tc.state || (tc.reason != "" && !strings.Contains(strings.Join(o.Reasons, ";"), tc.reason)) {
				t.Fatalf("at %s: %s %v, want %s (%q)", tc.at, o.State, o.Reasons, tc.state, tc.reason)
			}
			if o.State == collector.Attributable {
				if o.Outcome != "pass" || !o.Evaluated.Equal(evaluated) || ev.NextExpiry == nil || !ev.NextExpiry.Equal(evaluated.Add(age)) {
					t.Fatalf("attributable %+v, next expiry %v", o, ev.NextExpiry)
				}
			}
		})
	}

	// Evaluated exactly at the observed-state boundary: not after it.
	at := saved(t, evReport("r", evResult(nonroot, "pass", -1, started, compliant)))
	if o := observation(t, at, evalAt(t, at, age, base.Window.Closed), compliant, nonroot, 0); o.State != collector.Rejected ||
		!strings.Contains(strings.Join(o.Reasons, ";"), "not after the observed-state boundary") {
		t.Fatalf("evaluated at the state boundary: %+v", o)
	}
	after := saved(t, evReport("r", evResult(nonroot, "pass", -1, started.Add(time.Nanosecond), compliant)))
	if o := observation(t, after, evalAt(t, after, age, base.Window.Closed), compliant, nonroot, 0); o.State != collector.Attributable {
		t.Fatalf("evaluated just after the state boundary: %+v", o)
	}
}

// The time is an input, never defaulted: zero, before the window or before
// a recorded scope change is refused, and the caller's capture is not
// modified.
func TestEvaluateRequiresAnExplicitConsistentTime(t *testing.T) {
	c := saved(t)
	closed := c.Window.Closed
	if _, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: time.Hour}, time.Time{}); err == nil || !strings.Contains(err.Error(), "explicit evaluation time") {
		t.Errorf("zero evaluation time: %v, want an explicit-time refusal", err)
	}
	if _, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: time.Hour}, c.Window.Started.Add(-time.Nanosecond)); err == nil {
		t.Error("evaluation before the window started accepted")
	}
	changed := saved(t)
	changed.ScopeChanges = []collector.ScopeChange{{Kind: collector.WatchDiscontinuity, Observed: closed, Detail: "restart"}}
	if _, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: changed, MaxEvidenceAge: time.Hour}, closed.Add(-time.Second)); err == nil {
		t.Error("evaluation before a recorded scope change accepted")
	}
	if _, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: time.Hour}, closed.Add(time.Hour)); err != nil || !c.Window.Closed.Equal(closed) {
		t.Fatalf("later evaluation: %v, closure %s", err, c.Window.Closed)
	}
}

// Evidence whose provenance cannot be attributed establishes nothing:
// conflicting same-time results and a scope change are unresolved, an
// unindexed non-pass of a multi-validation policy names no validation, a
// result about a replaced workload's UID is someone else's, and an untimed
// result is rejected.
func TestEvaluateAmbiguousProvenance(t *testing.T) {
	c := saved(t)
	at := c.Window.Closed
	e := c.Window.Started.Add(time.Minute)
	replaced := "00000000-0000-4000-8000-000000000000"
	untimed := evResult(nonroot, "pass", -1, e, runViolator)
	delete(untimed, "timestamp")
	c = saved(t, evReport("r",
		evResult(nonroot, "pass", -1, e, compliant), evResult(nonroot, "fail", -1, e, compliant),
		evResult(capabilities, "fail", -1, e, compliant),
		evResult(capabilities, "pass", -1, e, replaced),
		untimed))
	ev := evalAt(t, c, time.Hour, at)
	for _, tc := range []struct {
		uid, policy string
		index       int
		state       collector.ObservationState
	}{
		{compliant, nonroot, 0, collector.Unresolved},
		{compliant, capabilities, 0, collector.Missing},
		{compliant, capabilities, 1, collector.Missing},
		{runViolator, nonroot, 0, collector.Rejected},
		{runViolator, capabilities, 0, collector.Missing},
	} {
		if o := observation(t, c, ev, tc.uid, tc.policy, tc.index); o.State != tc.state || o.Outcome != "" {
			t.Errorf("%s %s#%d: %s %q %v, want %s without an outcome", tc.uid, tc.policy, tc.index, o.State, o.Outcome, o.Reasons, tc.state)
		}
	}
	if ev.Outcomes != (publication.OutcomeCounts{}) {
		t.Errorf("ambiguous evidence counted outcomes %+v", ev.Outcomes)
	}

	// A fresh pass for a workload replaced during collection is unresolved.
	var w collector.Workload
	for _, x := range c.Expected {
		if x.Workload.UID == compliant {
			w = x.Workload
		}
	}
	cur := w
	cur.UID = replaced
	scoped := saved(t, evReport("r", evResult(nonroot, "pass", -1, e, compliant)))
	scoped.ScopeChanges = []collector.ScopeChange{{Kind: collector.WorkloadReplaced, Observed: e, Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, Previous: &w, Current: &cur}}
	if o := observation(t, scoped, evalAt(t, scoped, time.Hour, at), compliant, nonroot, 0); o.State != collector.Unresolved || o.Outcome != "" {
		t.Errorf("replaced during collection: %+v", o)
	}
}

// Shared or repeated evidence keeps each association's own identity and
// earns no duplicate credit: one result about two workloads attributes
// each once, the same result repeated across reports or resource lists is
// one observation, and an unindexed pass attests every validation of its
// policy for that workload, once each.
func TestEvaluateDuplicateAssociations(t *testing.T) {
	c := saved(t)
	e := c.Window.Started.Add(time.Minute)
	shared := evResult(nonroot, "pass", -1, e, compliant, runViolator, compliant)
	c = saved(t,
		evReport("r1", shared, evResult(capabilities, "pass", -1, e, compliant)),
		evReport("r2", shared))
	ev := evalAt(t, c, time.Hour, c.Window.Closed)
	for _, tc := range []struct {
		uid, policy string
		index       int
		report      string
	}{{compliant, nonroot, 0, ""}, {runViolator, nonroot, 0, ""}, {compliant, capabilities, 0, "r1"}, {compliant, capabilities, 1, "r1"}} {
		o := observation(t, c, ev, tc.uid, tc.policy, tc.index)
		if o.State != collector.Attributable || o.Outcome != "pass" || (tc.report != "" && o.Report != tc.report) {
			t.Errorf("%s %s#%d: %+v", tc.uid, tc.policy, tc.index, o)
		}
	}
	if ev.Evidence.Expected != len(c.Expected) || ev.Evidence.Attributable != 4 || ev.Outcomes.Pass != 4 {
		t.Errorf("summary %+v %+v, want 4 attributable passes of %d", ev.Evidence, ev.Outcomes, len(c.Expected))
	}
}

// A Linux-only check on a workload that declares Windows is not
// applicable: its raw result is kept and never counted as a pass.
func TestEvaluateApplicability(t *testing.T) {
	c := saved(t)
	e := c.Window.Started.Add(time.Minute)
	c = saved(t, evReport("r", evResult(nonroot, "pass", -1, e, compliant), evResult(capabilities, "fail", 0, e, compliant)))
	for i := range c.Expected {
		if c.Expected[i].Workload.UID == compliant {
			c.Expected[i].Workload.OS = "windows"
		}
	}
	for i := range c.Workloads {
		if c.Workloads[i].UID == compliant {
			c.Workloads[i].OS = "windows"
		}
	}
	ev := evalAt(t, c, time.Hour, c.Window.Closed)
	for policy, raw := range map[string]string{nonroot: "pass", capabilities: "fail"} {
		o := observation(t, c, ev, compliant, policy, 0)
		if o.State != collector.Attributable || o.Applicability != collector.NotApplicable || o.Outcome != raw {
			t.Errorf("%s: %+v", policy, o)
		}
	}
	if o := ev.Outcomes; o.NotApplicable != 2 || o.Pass != 0 || o.Fail != 0 {
		t.Errorf("outcomes %+v, want two not applicable", o)
	}
}

// A raw warn stays warn on the observation and counts once as unknown in
// the summary: never pass, fail or accepted risk.
func TestEvaluateWarnMapsToUnknownOnce(t *testing.T) {
	c := saved(t)
	e := c.Window.Started.Add(time.Minute)
	c = saved(t, evReport("r", evResult(nonroot, "warn", -1, e, compliant)), evReport("r2", evResult(nonroot, "warn", -1, e, compliant)))
	ev := evalAt(t, c, time.Hour, c.Window.Closed)
	if o := observation(t, c, ev, compliant, nonroot, 0); o.State != collector.Attributable || o.Outcome != "warn" {
		t.Fatalf("warn observation %+v", o)
	}
	if ev.Outcomes != (publication.OutcomeCounts{Unknown: 1}) {
		t.Fatalf("outcomes %+v, want exactly one unknown", ev.Outcomes)
	}
}

// Behavior equivalence: the provider evaluator at time t is exactly what
// the controller computed before it took an explicit time (the capture
// closed at t, then Evaluate), for the saved live evidence and the
// synthetic unknowns, across closure, expiry boundaries and later times.
func TestEvaluateMatchesCaptureClosedAtTheSameTime(t *testing.T) {
	root := repoRoot(t)
	inputs := map[string]collector.CaptureV2{"saved": saved(t)}
	var live collector.CaptureV2
	if err := assessment.Read(filepath.Join(root, savedCapture), &live); err != nil {
		t.Fatal(err)
	}
	inputs["live"] = live
	for name, c := range inputs {
		times := []time.Time{c.Window.Closed, c.Window.Started, c.Window.Closed.Add(time.Hour)}
		closure, err := c.Evaluate(nil, 2*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range closure.Observations {
			if o.Evaluated != nil {
				exp := o.Evaluated.Add(2 * time.Hour)
				times = append(times, *o.Evaluated, exp, exp.Add(time.Nanosecond))
			}
		}
		if name == "live" && len(times) < 10 {
			t.Fatalf("live capture yields only %d times", len(times))
		}
		for _, at := range times {
			closed := c
			closed.Window.Closed = at
			want, wantErr := closed.Evaluate(nil, 2*time.Hour)
			got, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: 2 * time.Hour}, at)
			if (err == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s at %s: %v %v", name, at, err, wantErr)
			}
		}
	}
}

// The evaluators read no clock: freshness depends only on the explicit
// time. Production callers reach the Kyverno evaluator only through
// kyverno.Evaluate, so they cannot evaluate at an implicit boundary.
func TestEvaluatorsReadNoClockAndCallersPassTime(t *testing.T) {
	root := repoRoot(t)
	clock := []string{"Now", "Since", "Until", "After", "AfterFunc", "Tick", "NewTimer", "NewTicker", "Sleep"}
	for _, f := range []string{"internal/collector/freshness.go", "internal/provider/kyverno/evaluate.go", "internal/provider/reporttest/reporttest.go"} {
		for _, call := range selectors(t, filepath.Join(root, f)) {
			if pkg, name, _ := strings.Cut(call, "."); pkg == "time" && slices.Contains(clock, name) {
				t.Errorf("%s reads the clock: %s", f, call)
			}
		}
	}
	// Outside the evaluator itself and test-only packages, no non-test code
	// calls Evaluate or EvaluateAt except as kyverno.Evaluate.
	skip := []string{"internal/collector", "internal/provider/kyverno", "internal/provider/conformance", "internal/provider/reporttest"}
	found := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() && (slices.Contains(skip, rel) || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			for _, call := range selectors(t, p) {
				pkg, name, _ := strings.Cut(call, ".")
				if name != "Evaluate" && name != "EvaluateAt" {
					continue
				}
				if pkg != "kyverno" || name != "Evaluate" {
					t.Errorf("%s calls %s; route Kyverno evaluation through kyverno.Evaluate with an explicit time", rel, call)
				}
				found++
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found < 2 {
		t.Fatalf("found %d kyverno.Evaluate callers, want the current projection and the closing run", found)
	}
}

// selectors lists the X.Sel call expressions of a Go file, X rendered only
// when it is an identifier ("?" otherwise).
func selectors(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			x := "?"
			if id, ok := sel.X.(*ast.Ident); ok {
				x = id.Name
			}
			out = append(out, x+"."+sel.Sel.Name)
		}
		return true
	})
	return out
}
