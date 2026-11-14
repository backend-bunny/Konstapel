package observability

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// queryCase is one documented query and its expected result.
type queryCase struct {
	Name       string `json:"name"`
	Expr       string `json:"expr"`
	EvalTime   string `json:"eval_time"`
	ExpSamples []struct {
		Labels string  `json:"labels"`
		Value  float64 `json:"value"`
	} `json:"exp_samples"`
}

// queryFixture builds the leader and follower Hubs of the query fixture
// (see testdata/observability/queries.cases.yaml) at 60s after the epoch,
// so promtool's evaluation clock and the exposed timestamps agree.
func queryFixture(t *testing.T) map[string]*Hub {
	t.Helper()
	at := time.Unix(60, 0).UTC()
	clk := clocktesting.NewFakePassiveClock(at)
	newHub := func() *Hub {
		h, err := NewHub(Options{Enabled: Domains, Clock: clk})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	leader, follower := newHub(), newHub()
	term := leader.Acquire()
	payments, legacy := BindingRef{Name: "payments", UID: "uid-payments"}, BindingRef{Name: "legacy", UID: "uid-legacy"}
	three := 3
	mustOK(t, leader.PublishTargeting(term, at, TargetingSnapshot{
		Bindings: []BindingTargeting{
			{Binding: payments, Created: time.Unix(0, 0), Resolved: StatusTrue, EngineReady: StatusTrue, TargetNamespaces: &three},
			{Binding: legacy, Created: time.Unix(0, 0), Resolved: StatusFalse, EngineReady: StatusFalse},
		},
		Capabilities: map[Capability]Status{CapabilityPolicyDelivery: StatusTrue, CapabilityAssessment: StatusTrue},
	}))
	expiry, due, oldest := time.Unix(7200, 0), time.Unix(120, 0), time.Unix(0, 0)
	mustOK(t, leader.PublishAssessment(term, at, AssessmentSnapshot{Bindings: []BindingAssessment{
		{Binding: payments,
			Current: &CurrentView{Summary: Summary{
				Evidence:        publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 46, Attributable: 44, Missing: 2},
				Outcomes:        publication.OutcomeCounts{Pass: 40, Fail: 2, AcceptedRisk: 1, Unknown: 1},
				OldestEvaluated: &oldest}, ValidUntil: &expiry},
			LatestClosed: &ClosedRun{Summary: completeSummary(40, 2), CollectionStarted: time.Unix(10, 0), Closed: time.Unix(20, 0)},
			Interval:     time.Hour, MaxEvidenceAge: 2 * time.Hour, CollectionTimeout: 5 * time.Minute, Due: &due},
		{Binding: legacy, Interval: 24 * time.Hour, MaxEvidenceAge: 2 * time.Hour, CollectionTimeout: 5 * time.Minute},
	}}))
	mustOK(t, leader.PublishBundleResolution(term, at))
	blocked := time.Unix(0, 0)
	mustOK(t, leader.PublishStorage(term, at, StorageSnapshot{PublicationFailed: 1, CleanupBlocked: 1, OldestCleanupExpiry: &blocked}))
	for range 3 {
		leader.ObserveOperation(OperationEvidencePublication, ResultFailure, time.Second)
	}
	for range 5 {
		leader.ObserveOperation(OperationEvidencePublication, ResultSuccess, time.Second)
	}
	for range 2 {
		follower.ObserveOperation(OperationEvidencePublication, ResultSuccess, time.Second)
	}
	return map[string]*Hub{"konstapel-0": leader, "konstapel-1": follower}
}

// inputSeries renders the fixture Hubs' exposition as promtool input
// series of the "konstapel" job: gauges constant, counters (and histogram
// counts) increasing by their exposed value every minute.
func inputSeries(t *testing.T, hubs map[string]*Hub) []string {
	t.Helper()
	var out []string
	for _, instance := range slices.Sorted(func(yield func(string) bool) {
		for k := range hubs {
			if !yield(k) {
				return
			}
		}
	}) {
		reg := prometheus.NewPedanticRegistry()
		reg.MustRegister(hubs[instance])
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range families {
			for _, m := range f.Metric {
				labels := []string{fmt.Sprintf(`instance=%q`, instance), `job="konstapel"`}
				for _, l := range m.Label {
					labels = append(labels, fmt.Sprintf(`%s=%q`, l.GetName(), l.GetValue()))
				}
				slices.Sort(labels)
				series := func(name, values string) {
					out = append(out, fmt.Sprintf("      - series: '%s{%s}'\n        values: '%s'", name, strings.Join(labels, ","), values))
				}
				switch {
				case m.Gauge != nil:
					series(f.GetName(), fmt.Sprintf("%gx150", m.Gauge.GetValue()))
				case m.Counter != nil:
					series(f.GetName(), fmt.Sprintf("0+%gx150", m.Counter.GetValue()))
				case m.Histogram != nil:
					series(f.GetName()+"_count", fmt.Sprintf("0+%dx150", m.Histogram.GetSampleCount()))
				}
			}
		}
	}
	return out
}

// The documented query examples are evaluated by promtool against series
// the Hub actually exposes; the test file is generated so a catalog or
// projection change cannot leave the examples on stale series.
func TestQueryExamplesFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "testdata/observability/queries.cases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []queryCase `json:"cases"`
	}
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no query cases")
	}
	var b strings.Builder
	b.WriteString("# Generated by `go test ./internal/observability -update` from\n# queries.cases.yaml and the Hub fixture; run with promtool test rules.\n")
	b.WriteString("rule_files: []\nevaluation_interval: 1m\ntests:\n  - interval: 1m\n    input_series:\n")
	b.WriteString(strings.Join(inputSeries(t, queryFixture(t)), "\n") + "\n")
	b.WriteString("    promql_expr_test:\n")
	for _, c := range doc.Cases {
		fmt.Fprintf(&b, "      # %s\n      - expr: |\n", c.Name)
		for _, line := range strings.Split(strings.TrimRight(c.Expr, "\n"), "\n") {
			fmt.Fprintf(&b, "          %s\n", line)
		}
		fmt.Fprintf(&b, "        eval_time: %s\n", c.EvalTime)
		if len(c.ExpSamples) == 0 {
			b.WriteString("        exp_samples: []\n")
			continue
		}
		b.WriteString("        exp_samples:\n")
		for _, s := range c.ExpSamples {
			fmt.Fprintf(&b, "          - labels: '%s'\n            value: %g\n", s.Labels, s.Value)
		}
	}
	golden(t, "testdata/observability/queries.test.yml", []byte(b.String()))

	// Every documented query is one of the evaluated cases.
	md, err := os.ReadFile(filepath.Join(repoRoot, "docs/integration/metrics.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```promql\n(.*?)```").FindAllStringSubmatch(string(md), -1)
	if len(blocks) == 0 {
		t.Fatal("docs/integration/metrics.md has no promql examples")
	}
	exprs := map[string]bool{}
	for _, c := range doc.Cases {
		exprs[strings.TrimSpace(c.Expr)] = true
	}
	for _, blk := range blocks {
		if !exprs[strings.TrimSpace(blk[1])] {
			t.Errorf("documented query is not an evaluated case:\n%s", blk[1])
		}
	}
	if len(blocks) != len(doc.Cases) {
		t.Errorf("%d documented queries, %d cases", len(blocks), len(doc.Cases))
	}
}
