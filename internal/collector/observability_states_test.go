package collector

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/observability"
)

// The owner's normalized evaluations reach the metric contract through the
// observability Hub unchanged: these tests pin the catalog's state mapping
// to the real normalizer.

func currentSeries(t *testing.T, ev Evaluation, scrapeAt time.Time) map[string]float64 {
	t.Helper()
	clk := clocktesting.NewFakePassiveClock(scrapeAt)
	hub, err := observability.NewHub(observability.Options{Enabled: []observability.Domain{observability.DomainAssessment}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	term := hub.Acquire()
	cur := &observability.CurrentView{Summary: observability.Summary{Evidence: ev.Evidence, Outcomes: ev.Outcomes}, ValidUntil: ev.NextExpiry}
	if err := hub.PublishAssessment(term, scrapeAt, observability.AssessmentSnapshot{Bindings: []observability.BindingAssessment{
		{Binding: observability.BindingRef{Name: "b", UID: "uid-b"}, Current: cur}}}); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(hub)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			var ls []string
			for _, l := range m.Label {
				if l.GetName() != "binding" {
					ls = append(ls, fmt.Sprintf("%s=%s", l.GetName(), l.GetValue()))
				}
			}
			if m.Gauge != nil {
				out[f.GetName()+"{"+strings.Join(ls, ",")+"}"] = m.Gauge.GetValue()
			}
		}
	}
	return out
}

func checks(s map[string]float64, state string) (float64, bool) {
	v, ok := s["konstapel_binding_assessment_checks{state="+state+",view=current}"]
	return v, ok
}

// Previously passing evidence that ages past maxEvidenceAge is never a
// current pass: the current view turns unknown at the owner's next expiry
// (exposed as the freshness signal), and the owner's re-evaluation counts
// it as rejected.
func TestStalePassNeverCountsAsCurrentPass(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return "pass" })
	ev := evaluate(t, c, nil, maxAge)
	if ev.Outcomes.Pass != 3 || ev.NextExpiry == nil {
		t.Fatalf("fresh: %+v next expiry %v", ev.Outcomes, ev.NextExpiry)
	}
	if s := currentSeries(t, ev, c.Window.Closed); s["konstapel_binding_assessment_checks{state=pass,view=current}"] != 3 {
		t.Fatalf("fresh passes not exposed: %v", s)
	}

	// The same summary, scraped at its expiry, is no longer a pass.
	s := currentSeries(t, ev, *ev.NextExpiry)
	if s["konstapel_binding_assessment_status{status=unknown,view=current}"] != 1 {
		t.Error("expired evidence is not unknown")
	}
	if _, ok := checks(s, "pass"); ok {
		t.Error("expired passes are still exposed")
	}
	if s["konstapel_binding_current_evidence_expiry_timestamp_seconds{}"] != float64(ev.NextExpiry.Unix()) {
		t.Error("freshness signal missing")
	}

	// Re-evaluated after expiry, the owner rejects the old results.
	c.Window.Closed = ev.NextExpiry.Add(time.Second)
	later := evaluate(t, c, nil, maxAge)
	s = currentSeries(t, later, c.Window.Closed)
	if n, _ := checks(s, "pass"); n != 0 {
		t.Errorf("stale evidence counted as %v passes", n)
	}
	if n, _ := checks(s, "rejected"); n != 3 || s["konstapel_binding_assessment_complete{view=current}"] != 0 {
		t.Errorf("stale evidence: rejected %v, complete %v", n, s["konstapel_binding_assessment_complete{view=current}"])
	}
	if _, ok := s["konstapel_binding_current_evidence_expiry_timestamp_seconds{}"]; ok {
		t.Error("an expiry is exposed without attributable evidence")
	}
}

// warnCapture reports Kyverno warn for one expected check and pass for the
// others. Kyverno reports warn for a failing policy annotated
// policies.kyverno.io/scored: "false".
func warnCapture(t *testing.T) (CaptureV2, string) {
	c := freshCapture(t)
	warned := c.Expected[0].Key()
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(e Expected) string {
		if e.Key() == warned {
			return "warn"
		}
		return "pass"
	})
	return c, warned
}

// A warning stays a distinct warning in the retained evaluation and in the
// OSCAL output: never a pass, a failure or an accepted risk.
func TestWarnSurvivesRetainedEvidenceAndOSCAL(t *testing.T) {
	c, warned := warnCapture(t)
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if o := d.Outcomes; o.Unknown != 1 || o.Pass != 2 || o.Fail != 0 || o.AcceptedRisk != 0 || o.Error != 0 || o.Skip != 0 {
		t.Fatalf("descriptor outcomes %+v", o)
	}

	// Retained evaluation: the raw outcome is kept on its observation.
	var retained Evaluation
	if err := assessment.Read(filepath.Join(req.Out, "evaluation.json"), &retained); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, o := range retained.Observations {
		if o.Key == warned {
			found++
			if o.State != Attributable || o.Outcome != "warn" {
				t.Errorf("retained observation %+v", o)
			}
		}
	}
	if found != 1 {
		t.Fatalf("warned observation retained %d times", found)
	}

	// OSCAL: a warning result with its source outcome, and no
	// not-satisfied finding.
	r := firstResult(t, req.Out)
	results := map[string]int{}
	for _, s := range subjects(r) {
		res, _ := prop(s, "result")
		results[res]++
		if res == "warning" {
			if src, _ := prop(s, "source-outcome"); src != "warn" {
				t.Errorf("warning subject lacks source-outcome warn: %v", s)
			}
		}
	}
	if results["warning"] != 1 || results["pass"] != 2 || results["fail"] != 0 || len(results) != 2 {
		t.Errorf("OSCAL subject results %v", results)
	}
	findings, _ := r["findings"].([]any)
	for _, f := range findings {
		if st := assessment.Str(assessment.At(assessment.Map(f), "target", "status", "state")); st == "not-satisfied" {
			t.Errorf("a warning produced a not-satisfied finding: %v", f)
		}
	}
}

// In summaries and metrics a warning is counted exactly once, as unknown,
// in both the current and the latest closed view.
func TestWarnCountsOnceAsUnknown(t *testing.T) {
	c, _ := warnCapture(t)
	ev := evaluate(t, c, nil, maxAge)
	if o := ev.Outcomes; o.Unknown != 1 || o.Pass != 2 || o.Fail != 0 || o.AcceptedRisk != 0 {
		t.Fatalf("owner outcomes %+v", o)
	}
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	closed, ok := observability.ClosedFromDescriptor(d)
	if !ok {
		t.Fatal("binding package is not a closed run")
	}
	clk := clocktesting.NewFakePassiveClock(c.Window.Closed)
	hub, err := observability.NewHub(observability.Options{Enabled: []observability.Domain{observability.DomainAssessment}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	term := hub.Acquire()
	cur := &observability.CurrentView{Summary: observability.Summary{Evidence: ev.Evidence, Outcomes: ev.Outcomes}, ValidUntil: ev.NextExpiry}
	if err := hub.PublishAssessment(term, c.Window.Closed, observability.AssessmentSnapshot{Bindings: []observability.BindingAssessment{
		{Binding: observability.BindingRef{Name: "b", UID: "uid-b"}, Current: cur, LatestClosed: closed}}}); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(hub)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	enc := expfmt.NewEncoder(&text, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
	}
	// Every exposed checks sample, parsed from the exposition text.
	type key struct{ view, state string }
	samples := map[key]float64{}
	lines := map[key]int{}
	sample := regexp.MustCompile(`^konstapel_binding_assessment_checks\{binding="b",state="([a-z_]+)",view="([a-z_]+)"\} (\S+)$`)
	for _, line := range strings.Split(text.String(), "\n") {
		if m := sample.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseFloat(m[3], 64)
			if err != nil {
				t.Fatal(err)
			}
			k := key{m[2], m[1]}
			samples[k] += v
			lines[k]++
		}
	}
	for _, view := range []string{"current", "latest_closed"} {
		total := 0.0
		for _, state := range observability.CheckStates {
			k := key{view, state}
			if lines[k] != 1 {
				t.Errorf("%s/%s exposed %d times", view, state, lines[k])
			}
			total += samples[k]
		}
		want := map[string]float64{"unknown": 1, "pass": 2, "fail": 0, "accepted_risk": 0, "error": 0, "skip": 0}
		for state, n := range want {
			if samples[key{view, state}] != n {
				t.Errorf("%s/%s = %v, want %v", view, state, samples[key{view, state}], n)
			}
		}
		if total != float64(len(c.Expected)) {
			t.Errorf("%s: checks total %v, want the %d expected checks counted once", view, total, len(c.Expected))
		}
	}
}

// Missing, rejected and unresolved observations stay distinct.
func TestMissingRejectedUnresolvedFromOwner(t *testing.T) {
	c := freshCapture(t)
	at := c.Window.Started.Add(time.Minute)
	old, none, conflict := c.Expected[0], c.Expected[1], c.Expected[2]
	c.Reports = nil
	// Evaluated before the observed-state boundary: rejected.
	c.Reports = append(c.Reports, report("r-old", "ns", old.Workload.UID, result(old.Check.EnginePolicy, old.Check.Index, old.Workload.UID, "pass", c.Window.Started.Add(-time.Minute))))
	// Two different outcomes at the same time: unresolved.
	c.Reports = append(c.Reports,
		report("r-a", "ns", conflict.Workload.UID, result(conflict.Check.EnginePolicy, conflict.Check.Index, conflict.Workload.UID, "pass", at)),
		report("r-b", "ns", conflict.Workload.UID, result(conflict.Check.EnginePolicy, conflict.Check.Index, conflict.Workload.UID, "fail", at)))
	_ = none // no result at all: missing
	ev := evaluate(t, c, nil, maxAge)
	s := currentSeries(t, ev, c.Window.Closed)
	for state, want := range map[string]float64{"missing": 1, "rejected": 1, "unresolved": 1, "pass": 0, "fail": 0} {
		if n, _ := checks(s, state); n != want {
			t.Errorf("%s = %v, want %v (evidence %+v)", state, n, want, ev.Evidence)
		}
	}
	if s["konstapel_binding_assessment_status{status=known,view=current}"] != 1 || s["konstapel_binding_assessment_complete{view=current}"] != 0 {
		t.Error("an inventory with gaps must be known and incomplete")
	}
}
