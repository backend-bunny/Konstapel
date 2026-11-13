package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clocktesting "k8s.io/utils/clock/testing"

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

// Kyverno reports warn for a failing policy annotated
// policies.kyverno.io/scored: "false". The owner keeps the raw outcome on
// the observation and counts it as unknown: never pass, never fail.
func TestWarnOutcomeIsUnknown(t *testing.T) {
	c := freshCapture(t)
	warned := c.Expected[0].Key()
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(e Expected) string {
		if e.Key() == warned {
			return "warn"
		}
		return "pass"
	})
	ev := evaluate(t, c, nil, maxAge)
	for _, o := range ev.Observations {
		if o.Key == warned && (o.State != Attributable || o.Outcome != "warn") {
			t.Fatalf("raw warn not retained: %+v", o)
		}
	}
	s := currentSeries(t, ev, c.Window.Closed)
	if n, _ := checks(s, "unknown"); n != 1 {
		t.Errorf("warn counted as %v unknown", n)
	}
	if p, _ := checks(s, "pass"); p != 2 {
		t.Errorf("passes %v, want 2", p)
	}
	if f, _ := checks(s, "fail"); f != 0 {
		t.Errorf("warn counted as %v failures", f)
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
