package collector

import (
	"context"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"github.com/oscal-compass/oscal-sdk-go/models/components"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// snapshotCases are frozen snapshots covering the conversion's outcomes:
// attributable passes and failures, warnings, missing evidence, stale
// scopes and zero targets.
func snapshotCases(t *testing.T) map[string]Snapshot {
	t.Helper()
	out := map[string]Snapshot{}
	add := func(name string, c CaptureV2) {
		out[name] = Snapshot{Capture: c, Evaluation: evaluate(t, c, nil, maxAge)}
	}
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	add("failures", c)
	c = freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return "warn" })
	add("warnings", c)
	add("missing", freshCapture(t))
	c = captureV2(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return "pass" })
	add("stale-scopes", c)
	c = freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(-time.Minute), func(Expected) string { return "pass" })
	add("rejected", c)
	c = freshCapture(t)
	c.Workloads, c.Expected = []Workload{}, []Expected{}
	add("zero-targets", c)
	return out
}

// inputFor is the C2P input continuous export converts a vendored
// snapshot for.
func inputFor(t *testing.T, c CaptureV2) *actions.InputContext {
	t.Helper()
	cov, err := coverageFor(repo(t), assessment.Shipped, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	input, _, err := assessment.InputFromSet(repo(t), assessment.Shipped, cov.rules)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// Dispatching through the C2P framework adds nothing to the conversion:
// its one result is exactly the snapshot's direct conversion, and it
// claims a violation exactly when that does.
func TestDispatchedConversionEqualsTheDirectOne(t *testing.T) {
	for name, s := range snapshotCases(t) {
		t.Run(name, func(t *testing.T) {
			got, err := convert(context.Background(), inputFor(t, s.Capture), s)
			if err != nil {
				t.Fatal(err)
			}
			want, fail := pvpResults(s.Capture, s.Evaluation)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("dispatched results differ from the direct conversion:\n%+v\n%+v", got, want)
			}
			if attributableFailure(got) != fail {
				t.Fatalf("attributable failure %v, direct %v", attributableFailure(got), fail)
			}
		})
	}
}

// A package's evaluation is exactly the evaluation of its capture: an
// evaluation that drops, repeats or invents an observation, names a report
// the capture does not hold, or miscounts its observations is refused
// before anything is written, and never converted.
func TestExportRefusesAnEvaluationThatIsNotOfItsCapture(t *testing.T) {
	base := snapshotCases(t)["failures"]
	mutations := map[string]func(*Evaluation){
		"dropped": func(ev *Evaluation) { ev.Observations = ev.Observations[1:] },
		"dropped and recounted": func(ev *Evaluation) {
			ev.Observations = ev.Observations[1:]
			ev.Evidence, ev.Outcomes = Tally(ev.Observations, 0)
		},
		"repeated": func(ev *Evaluation) {
			ev.Observations = append(ev.Observations, ev.Observations[0])
		},
		"invented": func(ev *Evaluation) { ev.Observations[0].Key = "another observation" },
		"report":   func(ev *Evaluation) { ev.Observations[0].Report = "not-captured" },
		"summary":  func(ev *Evaluation) { ev.Outcomes.Fail, ev.Outcomes.Pass = ev.Outcomes.Fail-1, ev.Outcomes.Pass+1 },
		"outcome": func(ev *Evaluation) {
			for i, o := range ev.Observations {
				if o.Outcome == "fail" {
					ev.Observations[i].Outcome = "pass"
				}
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Evaluation.Observations = slices.Clone(base.Evaluation.Observations)
			mutate(&s.Evaluation)
			if err := s.Validate(); err == nil {
				t.Fatal("an evaluation that is not of its capture was accepted")
			}
			p := &SnapshotProvider{Snapshot: s}
			if err := p.Configure(context.Background(), nil); err == nil {
				t.Fatal("the provider accepted the snapshot")
			}
			if _, err := p.GetResults(context.Background(), nil); err == nil {
				t.Fatal("an unconfigured provider converted")
			}
			req := exportReq(t, s.Capture, s.Evaluation, repo(t))
			if _, err := Export(context.Background(), req); err == nil || !strings.Contains(err.Error(), "evaluation") {
				t.Fatalf("exported: %v", err)
			}
			if entries, _ := os.ReadDir(req.Out); len(entries) != 0 {
				t.Fatalf("a refused export wrote %d files", len(entries))
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The snapshot provider converts, and only for a policy that names its
// checks; it never regenerates engine policies.
func TestSnapshotProviderConvertsOnlyForItsChecks(t *testing.T) {
	s := snapshotCases(t)["failures"]
	p := &SnapshotProvider{Snapshot: s}
	if err := p.Configure(context.Background(), map[string]string{"root": "/nonexistent"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Generate(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "never regenerated") {
		t.Fatalf("a frozen snapshot regenerated: %v", err)
	}
	check := s.Capture.Expected[0].Contribution.LogicalPolicy
	named := policy.Policy{{Rule: extensions.Rule{ID: check}, Checks: []extensions.Check{{ID: check}}}}
	got, err := p.GetResults(context.Background(), named)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := pvpResults(s.Capture, s.Evaluation); !reflect.DeepEqual([]policy.PVPResult{got}, want) {
		t.Fatalf("%+v", got)
	}
	other := policy.Policy{{Rule: extensions.Rule{ID: "another-policy"}, Checks: []extensions.Check{{ID: "another-policy"}}}}
	if _, err := p.GetResults(context.Background(), other); err == nil || !strings.Contains(err.Error(), check) {
		t.Fatalf("converted for a policy that does not name its check: %v", err)
	}
}

// An input without the provider's validation component is no conversion:
// the framework would skip the provider, and convert refuses the empty
// result rather than export an assessment without observations.
func TestConvertRefusesASkippedProvider(t *testing.T) {
	s := snapshotCases(t)["failures"]
	def, _, err := assessment.ValidateDefinition(repo(t), assessment.ComponentDefinitions[0], assessment.ShippedPolicies)
	if err != nil {
		t.Fatal(err)
	}
	var comps []components.Component
	for _, c := range *def.Components {
		if c.Type != "validation" {
			comps = append(comps, components.NewDefinedComponentAdapter(c))
		}
	}
	input, err := actions.NewContextFromComponents(comps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := convert(context.Background(), input, s); err == nil || !strings.Contains(err.Error(), "want one") {
		t.Fatalf("a skipped provider converted: %v", err)
	}
}
