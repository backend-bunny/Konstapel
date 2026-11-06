package collector

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// Saved live evidence (Kyverno 1.19.2, hardening checks, five Pods).
// Background reports carry one unindexed pass per policy and resource when
// every validation passes, and only the failing validation (indexed) when
// one fails, with nothing for that policy's other validations on that
// resource. So every passing policy is attributable through its unindexed
// pass, each failure through its index, and the sibling validations of a
// failing multi-validation policy stay Missing: the engine never reported
// them and the collector does not assume they passed.
// evaluation-before-fix.json records the earlier result (26 of 30 missing).
func TestSavedPolicyLevelPassEvidence(t *testing.T) {
	var c CaptureV2
	if err := assessment.Read(filepath.Join(repo(t), "testdata/assessments/kyverno-1.19.2-background/capture.json"), &c); err != nil {
		t.Fatal(err)
	}
	var before Evaluation
	if err := assessment.Read(filepath.Join(repo(t), "testdata/assessments/kyverno-1.19.2-background/evaluation-before-fix.json"), &before); err != nil {
		t.Fatal(err)
	}
	ev, err := c.Evaluate(nil, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if before.Evidence.Missing != 26 || ev.Evidence.Expected != 30 || ev.Evidence.Attributable != 28 || ev.Evidence.Missing != 2 || ev.Evidence.Completeness != "Incomplete" {
		t.Fatalf("evidence before %+v after %+v", before.Evidence, ev.Evidence)
	}
	if ev.Outcomes.Fail != before.Outcomes.Fail || ev.Outcomes.Fail != 4 || ev.Outcomes.Pass != 24 {
		t.Fatalf("outcomes before %+v after %+v", before.Outcomes, ev.Outcomes)
	}
	var missing []string
	for i, o := range ev.Observations {
		if o.State == Missing {
			e := c.Expected[i]
			missing = append(missing, fmt.Sprintf("%s/%d", e.Workload.Name, e.Check.Index))
		}
	}
	slices.Sort(missing)
	if !slices.Equal(missing, []string{"hz-bg-violates-capabilities/1", "hz-bg-violates-seccomp/0"}) {
		t.Fatalf("missing checks %v: only unreported siblings of a failing validation may be missing", missing)
	}
}

// For a single-validation policy any unindexed result names its only
// validation; an unindexed non-pass result stays unattributable only for
// multi-validation policies (covered by the saved evidence above).
func TestUnindexedResultsForSingleValidationPolicy(t *testing.T) {
	for _, outcome := range []string{"pass", "fail"} {
		c := freshCapture(t)
		c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), func(Expected) string { return outcome })
		for _, rep := range c.Reports {
			for _, r := range rep["results"].([]any) {
				delete(assessment.Map(assessment.Map(r)["properties"]), "cel.validationIndex")
			}
		}
		ev := evaluate(t, c, nil, maxAge)
		if ev.Evidence.Attributable != ev.Evidence.Expected || ev.Evidence.Expected == 0 {
			t.Fatalf("%s: unindexed results for a single-validation policy not attributed: %+v", outcome, ev.Evidence)
		}
	}
}
