package conformance_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

const module = "github.com/backend-bunny/Konstapel"

// Kyverno-specific packages: engine policy names, CEL validation indexes,
// PolicyReport layouts and the bundle/targeting content model live there.
var kyvernoPackages = []string{
	module + "/internal/assessment", module + "/internal/collector", module + "/internal/targeting",
	module + "/internal/bundle", module + "/internal/provider/kyverno", module + "/internal/capability",
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-mod=readonly"}, args...)...)
	cmd.Dir = "../../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	return strings.Fields(string(out))
}

// The shared harness imports no Kyverno package, not even transitively;
// the synthetic reporting adapter imports none directly.
func TestHarnessHasNoKyvernoDependencies(t *testing.T) {
	self := module + "/internal/provider/conformance"
	deps := goList(t, "-deps", self)
	if !slices.Contains(deps, module+"/internal/publication") {
		t.Fatalf("deps %v lack internal/publication; the check is not working", deps)
	}
	for _, p := range kyvernoPackages {
		if slices.Contains(deps, p) {
			t.Errorf("the shared harness depends on %s", p)
		}
	}
	imports := goList(t, "-f", `{{join .Imports "\n"}}`, module+"/internal/provider/reporttest")
	for _, p := range kyvernoPackages {
		if slices.Contains(imports, p) {
			t.Errorf("the synthetic reporting adapter imports %s", p)
		}
	}
	// The shared namespace projection seam is provider-neutral too.
	projection := goList(t, "-deps", module+"/internal/provider/projection")
	if !slices.Contains(projection, module+"/internal/provider/projection") {
		t.Fatalf("deps %v lack the projection package itself; the check is not working", projection)
	}
	for _, p := range kyvernoPackages {
		if slices.Contains(projection, p) {
			t.Errorf("the shared projection seam depends on %s", p)
		}
	}
}

func reportingCase(t *testing.T) (conformance.Case, conformance.Expected) {
	t.Helper()
	c, want, err := conformance.Load(filepath.Join("../../../testdata/providers/conformance/v1/konstapel-reporttest/shared-image-evidence"))
	if err != nil || want == nil {
		t.Fatalf("load: %v", err)
	}
	return c, *want
}

// mutant wraps the reporting adapter with a deliberate semantic regression.
type mutant struct {
	reporttest.Adapter
	inventory func([]conformance.Expectation, json.RawMessage) []conformance.Expectation
	evaluate  func(conformance.Evaluation) conformance.Evaluation
}

func (m mutant) Inventory(raw json.RawMessage) ([]conformance.Expectation, error) {
	inv, err := m.Adapter.Inventory(raw)
	if m.inventory != nil {
		inv = m.inventory(inv, raw)
	}
	return inv, err
}

func (m mutant) Evaluate(raw json.RawMessage, at time.Time) (conformance.Evaluation, error) {
	ev, err := m.Adapter.Evaluate(raw, at)
	if m.evaluate != nil {
		ev = m.evaluate(ev)
	}
	return ev, err
}

func each(f func(*conformance.Observation)) func(conformance.Evaluation) conformance.Evaluation {
	return func(ev conformance.Evaluation) conformance.Evaluation {
		ev.Observations = slices.Clone(ev.Observations)
		for i := range ev.Observations {
			f(&ev.Observations[i])
		}
		return ev
	}
}

func TestHarnessCatchesSemanticRegressions(t *testing.T) {
	c, want := reportingCase(t)
	if errs := conformance.Verify(reporttest.Adapter{}, c, want); len(errs) > 0 {
		t.Fatalf("the unmodified adapter fails: %v", errs)
	}
	at := c.EvaluationTime
	calls := 0
	for name, m := range map[string]mutant{
		"drops missing observations": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation {
			ev.Observations = slices.DeleteFunc(slices.Clone(ev.Observations), func(o conformance.Observation) bool { return o.State == conformance.Missing })
			return ev
		}},
		"missing evidence passes": {evaluate: each(func(o *conformance.Observation) {
			if o.State == conformance.Missing {
				t := at.Add(-time.Minute)
				o.State, o.Raw, o.Outcome, o.Evaluated = conformance.Attributable, "Passed", conformance.Pass, &t
			}
		})},
		"inventory from evidence": {inventory: func(inv []conformance.Expectation, raw json.RawMessage) []conformance.Expectation {
			if strings.Contains(string(raw), `"reports":[]`) {
				return nil
			}
			return inv
		}},
		"warning counted as pass": {evaluate: each(func(o *conformance.Observation) {
			if o.Raw == "Warning" {
				o.Outcome = conformance.Pass
			}
		})},
		"not applicable counted as pass": {evaluate: each(func(o *conformance.Observation) { o.NotApplicable = false })},
		"rejected evidence carries an outcome": {evaluate: each(func(o *conformance.Observation) {
			if o.State == conformance.Rejected {
				o.Outcome = conformance.Fail
			}
		})},
		"unresolved treated as attributable": {evaluate: each(func(o *conformance.Observation) {
			if o.State == conformance.Unresolved {
				t := at
				o.State, o.Raw, o.Outcome, o.Evaluated = conformance.Attributable, "Passed", conformance.Pass, &t
			}
		})},
		"raw outcome dropped": {evaluate: each(func(o *conformance.Observation) { o.Raw = "" })},
		"report update time as freshness": {evaluate: each(func(o *conformance.Observation) {
			if o.Evaluated != nil {
				t := at.Add(time.Second)
				o.Evaluated = &t
			}
		})},
		"duplicate credit": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation {
			ev.Observations = append(slices.Clone(ev.Observations), ev.Observations[0])
			return ev
		}},
		"invented observation": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation {
			ev.Observations = append(slices.Clone(ev.Observations), conformance.Observation{Subject: "ns-x/w-x/app", Check: "no-critical", State: conformance.Missing})
			return ev
		}},
		"inconsistent normalization": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation {
			ev.Observations = slices.Clone(ev.Observations)
			for i := range ev.Observations {
				if ev.Observations[i].Raw == "Warning" {
					ev.Observations[i].Outcome = conformance.Fail
					break
				}
			}
			return ev
		}},
		"unknown state": {evaluate: each(func(o *conformance.Observation) {
			if o.State == conformance.Missing {
				o.State = "Pending"
			}
		})},
		"nondeterministic": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation {
			calls++
			if calls%2 == 0 {
				ev.Observations = slices.Clone(ev.Observations)
				ev.Observations[0].State = conformance.Missing
				ev.Observations[0].Raw, ev.Observations[0].Outcome, ev.Observations[0].Evaluated, ev.Observations[0].NotApplicable = "", "", nil, false
			}
			return ev
		}},
		"stale scope hidden": {evaluate: func(ev conformance.Evaluation) conformance.Evaluation { ev.StaleScopes = 1; return ev }},
	} {
		t.Run(name, func(t *testing.T) {
			if errs := conformance.Verify(m, c, want); len(errs) == 0 {
				t.Fatal("the harness accepted a semantic regression")
			}
		})
	}
}

func TestHarnessRejectsMalformedCases(t *testing.T) {
	c, want := reportingCase(t)
	for name, mutate := range map[string]func(*conformance.Case, *conformance.Expected){
		"case version":     func(c *conformance.Case, _ *conformance.Expected) { c.Version = "konstapel.provider-conformance/v2" },
		"expected version": func(_ *conformance.Case, e *conformance.Expected) { e.Version = "" },
		"other provider":   func(c *conformance.Case, _ *conformance.Expected) { c.Provider = "konstapel-kyverno/v1" },
		"implicit time":    func(c *conformance.Case, _ *conformance.Expected) { c.EvaluationTime = time.Time{} },
		"no input":         func(c *conformance.Case, _ *conformance.Expected) { c.Input = nil },
		"payload version": func(c *conformance.Case, _ *conformance.Expected) {
			c.Input = json.RawMessage(strings.Replace(string(c.Input), `"payloadVersion": 1`, `"payloadVersion": 2`, 1))
		},
		"later time renews nothing": func(c *conformance.Case, _ *conformance.Expected) {
			c.EvaluationTime = c.EvaluationTime.Add(2 * time.Hour)
		},
		"golden edited": func(_ *conformance.Case, e *conformance.Expected) { e.Outcomes.Pass++ },
	} {
		t.Run(name, func(t *testing.T) {
			c2, w2 := c, want
			mutate(&c2, &w2)
			if errs := conformance.Verify(reporttest.Adapter{}, c2, w2); len(errs) == 0 {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, conformance.CaseFile), `{"version":"konstapel.provider-conformance/v1","provider":"x/v1","evaluationTime":"2026-11-20T12:00:00Z","input":{},"executable":"/bin/sh"}`)
	if _, _, err := conformance.Load(dir); err == nil {
		t.Fatal("unknown case field accepted")
	}
}

func TestSummarizeFollowsTheSummaryContract(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	obs := func(state conformance.State, outcome conformance.Outcome, na bool) conformance.Observation {
		o := conformance.Observation{Subject: "s", Check: "c", State: state, Outcome: outcome, NotApplicable: na}
		if state == conformance.Attributable {
			o.Evaluated, o.Raw = &at, "raw"
		}
		return o
	}
	e, o := conformance.Summarize(conformance.Evaluation{})
	if e.Completeness != "NoTargets" || o.Pass != 0 {
		t.Fatalf("empty %+v %+v", e, o)
	}
	e, _ = conformance.Summarize(conformance.Evaluation{StaleScopes: 1})
	if e.Completeness != "Incomplete" {
		t.Fatalf("stale scope only: %+v", e)
	}
	e, o = conformance.Summarize(conformance.Evaluation{Observations: []conformance.Observation{
		obs(conformance.Attributable, conformance.Pass, false), obs(conformance.Attributable, conformance.Fail, false),
		obs(conformance.Attributable, conformance.Unknown, false), obs(conformance.Attributable, conformance.Pass, true),
		obs(conformance.Attributable, conformance.Skip, false), obs(conformance.Attributable, conformance.Error, false),
	}})
	if e.Completeness != "Complete" || o.Pass != 1 || o.Fail != 1 || o.Unknown != 1 || o.NotApplicable != 1 || o.Skip != 1 || o.Error != 1 || o.AcceptedRisk != 0 {
		t.Fatalf("complete %+v %+v", e, o)
	}
	e, _ = conformance.Summarize(conformance.Evaluation{Observations: []conformance.Observation{
		obs(conformance.Attributable, conformance.Pass, false), obs(conformance.Missing, "", false), obs(conformance.Rejected, "", false), obs(conformance.Unresolved, "", false),
	}})
	if e.Completeness != "Incomplete" || e.Missing != 1 || e.Rejected != 1 || e.Unresolved != 1 || e.Attributable != 1 {
		t.Fatalf("incomplete %+v", e)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
