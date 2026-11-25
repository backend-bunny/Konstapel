package kyverno_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

var update = flag.Bool("update", false, "rewrite the Kyverno conformance golden results")

const cases = "testdata/providers/conformance/v1/konstapel-kyverno"

// input is the Kyverno conformance payload: a saved CaptureV2 (repository
// relative), the evidence-age limit, and optionally reports that replace
// the capture's own, over the same frozen scope.
type input struct {
	Capture        string               `json:"capture"`
	MaxEvidenceAge string               `json:"maxEvidenceAge"`
	Reports        *[]assessment.Object `json:"reports,omitempty"`
}

// adapter drives the existing, unchanged Kyverno evaluator
// (kyverno.Evaluate over collector.CaptureV2.EvaluateAt) through the
// shared harness.
type adapter struct{ root string }

func (adapter) Contract() string { return kyverno.Contract }

func (a adapter) load(raw json.RawMessage) (collector.CaptureV2, time.Duration, error) {
	var in input
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return collector.CaptureV2{}, 0, err
	}
	if in.Capture == "" || filepath.IsAbs(in.Capture) || strings.Contains(in.Capture, "..") {
		return collector.CaptureV2{}, 0, fmt.Errorf("capture %q must be a repository-relative path", in.Capture)
	}
	age, err := time.ParseDuration(in.MaxEvidenceAge)
	if err != nil {
		return collector.CaptureV2{}, 0, err
	}
	var c collector.CaptureV2
	if err := assessment.Read(filepath.Join(a.root, in.Capture), &c); err != nil {
		return c, 0, err
	}
	if in.Reports != nil {
		c.Reports = *in.Reports
	}
	return c, age, c.Validate()
}

func key(e collector.Expected) conformance.Expectation {
	w := e.Workload
	return conformance.Expectation{
		Subject: fmt.Sprintf("%s %s/%s uid=%s", w.Resource, w.Namespace, w.Name, w.UID),
		Check:   fmt.Sprintf("%s#%d", e.Check.EnginePolicy, e.Check.Index),
	}
}

func (a adapter) Inventory(raw json.RawMessage) ([]conformance.Expectation, error) {
	c, _, err := a.load(raw)
	if err != nil {
		return nil, err
	}
	out := make([]conformance.Expectation, len(c.Expected))
	for i, e := range c.Expected {
		out[i] = key(e)
	}
	return out, nil
}

// normalized is collector.Tally's outcome mapping.
func normalized(raw string) conformance.Outcome {
	switch raw {
	case "pass", "fail", "error", "skip":
		return conformance.Outcome(raw)
	}
	return conformance.Unknown
}

func (a adapter) evaluate(raw json.RawMessage, at time.Time) (collector.Evaluation, collector.CaptureV2, error) {
	c, age, err := a.load(raw)
	if err != nil {
		return collector.Evaluation{}, c, err
	}
	// The case's explicit time is the evaluation boundary; the capture's
	// own closure is never substituted for it.
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: age}, at)
	return ev, c, err
}

func (a adapter) Evaluate(raw json.RawMessage, at time.Time) (conformance.Evaluation, error) {
	ev, c, err := a.evaluate(raw, at)
	if err != nil {
		return conformance.Evaluation{}, err
	}
	byKey := map[string]collector.Expected{}
	for _, e := range c.Expected {
		byKey[e.Key()] = e
	}
	out := conformance.Evaluation{StaleScopes: len(c.Stale)}
	for _, o := range ev.Observations {
		e, ok := byKey[o.Key]
		if !ok {
			return out, errors.New("observation for an unexpected key")
		}
		k := key(e)
		obs := conformance.Observation{Subject: k.Subject, Check: k.Check, State: conformance.State(o.State)}
		if o.State == collector.Attributable {
			obs.Raw, obs.Outcome, obs.NotApplicable, obs.Evaluated = o.Outcome, normalized(o.Outcome), o.Applicability == collector.NotApplicable, o.Evaluated
		}
		out.Observations = append(out.Observations, obs)
	}
	return out, nil
}

func (a adapter) WithoutEvidence(raw json.RawMessage) (json.RawMessage, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	none := []assessment.Object{}
	in.Reports = &none
	return json.Marshal(in)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestKyvernoConformance(t *testing.T) {
	root := repoRoot(t)
	conformance.Run(t, adapter{root: root}, filepath.Join(root, cases), *update)
}

// The harness's provider-neutral summary is exactly the controller's
// summary (collector.Tally) for the same frozen inputs, so the shared
// contract cannot drift from what assessments publish.
func TestKyvernoHarnessSummaryMatchesCollector(t *testing.T) {
	root := repoRoot(t)
	a := adapter{root: root}
	dirs, err := conformance.Dirs(filepath.Join(root, cases))
	if err != nil || len(dirs) < 2 {
		t.Fatalf("cases %v: %v", dirs, err)
	}
	for _, dir := range dirs {
		c, _, err := conformance.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		ev, _, err := a.evaluate(c.Input, c.EvaluationTime)
		if err != nil {
			t.Fatal(err)
		}
		shared, err := a.Evaluate(c.Input, c.EvaluationTime)
		if err != nil {
			t.Fatal(err)
		}
		evidence, outcomes := conformance.Summarize(shared)
		if evidence != ev.Evidence || outcomes != ev.Outcomes {
			t.Errorf("%s: harness %+v %+v, collector %+v %+v", filepath.Base(dir), evidence, outcomes, ev.Evidence, ev.Outcomes)
		}
	}
}

// The saved live evidence keeps its documented interpretation
// (internal/collector TestSavedPolicyLevelPassEvidence) through the harness.
func TestKyvernoSavedEvidenceInterpretation(t *testing.T) {
	root := repoRoot(t)
	c, want, err := conformance.Load(filepath.Join(root, cases, "background-1.19.2"))
	if err != nil || want == nil {
		t.Fatal(err)
	}
	e, o := want.Evidence, want.Outcomes
	if e.Expected != 30 || e.Attributable != 28 || e.Missing != 2 || e.Completeness != "Incomplete" || o.Pass != 24 || o.Fail != 4 {
		t.Fatalf("golden summary %+v %+v", e, o)
	}
	if c.Provider != kyverno.Contract {
		t.Fatal(c.Provider)
	}
}

// The case's evaluation time is used, never replaced by the capture's
// closure: evaluated past every result's evidence-age limit, the saved
// evidence no longer matches its golden result and is all rejected, and a
// zero time is refused.
func TestKyvernoHonorsTheExplicitEvaluationTime(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, cases, "background-1.19.2")
	c, want, err := conformance.Load(dir)
	if err != nil || want == nil {
		t.Fatal(err)
	}
	later := c
	later.EvaluationTime = c.EvaluationTime.Add(3 * time.Hour)
	if errs := conformance.Verify(adapter{root: root}, later, *want); len(errs) == 0 {
		t.Fatal("a later evaluation time reproduced the closure result")
	}
	got, errs := conformance.Check(adapter{root: root}, later)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if e := got.Evidence; e.Attributable != 0 || e.Rejected != want.Evidence.Attributable || got.Outcomes.Pass != 0 || got.Outcomes.Fail != 0 {
		t.Fatalf("three hours later: %+v %+v", e, got.Outcomes)
	}
	zero := c
	zero.EvaluationTime = time.Time{}
	if _, err := (adapter{root: root}).Evaluate(zero.Input, zero.EvaluationTime); err == nil {
		t.Fatal("a zero evaluation time was accepted")
	}
}
