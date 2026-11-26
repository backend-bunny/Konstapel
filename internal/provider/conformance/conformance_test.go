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

// A malformed case, golden or payload fails for its own reason.
func TestHarnessRejectsMalformedCases(t *testing.T) {
	c, want := reportingCase(t)
	if errs := conformance.Verify(reporttest.Adapter{}, c, want); len(errs) > 0 {
		t.Fatalf("the unmodified case fails: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*conformance.Case, *conformance.Expected)
		want   conformance.Kind
	}{
		"case version":     {func(c *conformance.Case, _ *conformance.Expected) { c.Version = "konstapel.provider-conformance/v2" }, conformance.KindCase},
		"expected version": {func(_ *conformance.Case, e *conformance.Expected) { e.Version = "" }, conformance.KindCase},
		"other provider":   {func(c *conformance.Case, _ *conformance.Expected) { c.Provider = "konstapel-kyverno/v1" }, conformance.KindCase},
		"implicit time":    {func(c *conformance.Case, _ *conformance.Expected) { c.EvaluationTime = time.Time{} }, conformance.KindCase},
		"no input":         {func(c *conformance.Case, _ *conformance.Expected) { c.Input = nil }, conformance.KindCase},
		"payload version": {func(c *conformance.Case, _ *conformance.Expected) {
			c.Input = json.RawMessage(strings.Replace(string(c.Input), `"payloadVersion": 1`, `"payloadVersion": 2`, 1))
		}, conformance.KindInventory},
		"later time renews nothing": {func(c *conformance.Case, _ *conformance.Expected) {
			c.EvaluationTime = c.EvaluationTime.Add(2 * time.Hour)
		}, conformance.KindGolden},
		"golden edited": {func(_ *conformance.Case, e *conformance.Expected) { e.Outcomes.Pass++ }, conformance.KindGolden},
	} {
		t.Run(name, func(t *testing.T) {
			c2, w2 := c, want
			mutate := tc.mutate
			mutate(&c2, &w2)
			errs := conformance.Verify(reporttest.Adapter{}, c2, w2)
			if kinds := conformance.Kinds(errs); !slices.Contains(kinds, tc.want) {
				t.Fatalf("reported %q, want %q: %v", kinds, tc.want, errs)
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
