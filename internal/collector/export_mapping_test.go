package collector

import (
	"context"
	"encoding/json"
	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// The mapping layer of the export names exactly the assessed checks'
// controls: for restrict-seccomp-strict the context SSP and the scoped plan
// carry CM-6 and CM-7 and never AC-6, and the description is that check's
// own partial-coverage rationale. (A full export of a hardening capture
// needs the variant served and rendered; the privileged export tests cover
// the end-to-end path.)
func TestExportMappingNamesAssessedChecksOnly(t *testing.T) {
	c := freshCapture(t)
	const lp = "restrict-seccomp-strict"
	for i := range c.Expected {
		c.Expected[i].Contribution.LogicalPolicy = lp
	}
	for i := range c.Subjects {
		c.Subjects[i].LogicalPolicy = lp
	}
	cov, err := coverageFor(repo(t), c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cov.rules, []string{lp}) || strings.Contains(cov.summary, assessment.Coverage) || !strings.Contains(cov.summary, lp) {
		t.Fatalf("coverage %+v", cov)
	}
	if !slices.Equal(cov.definitions, []string{"content/linux-hardening/component-definition.json"}) {
		t.Fatalf("mapping definitions to link: %v", cov.definitions)
	}
	ssp, _ := json.Marshal(contextSSP(c.Cluster, time.Now(), cov))
	if s := string(ssp); !strings.Contains(s, `"cm-6"`) || !strings.Contains(s, "cm-7_smt.b") || strings.Contains(s, `"ac-6"`) {
		t.Fatalf("context SSP control implementation: %s", s)
	}
	_, plan, err := assessment.InputFrom(repo(t), assessment.ComponentDefinitions, cov.rules)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := json.Marshal(plan); strings.Contains(string(p), `"ac-6"`) || !strings.Contains(string(p), `"cm-7"`) {
		t.Fatal("plan is not scoped to the assessed check")
	}
	// Nothing in scope falls back to the first-loop coverage statement.
	empty := c
	empty.Subjects, empty.Expected = nil, nil
	if cov, _ := coverageFor(repo(t), empty); cov.summary != assessment.Coverage || !slices.Equal(cov.rules, []string{assessment.PolicyName}) ||
		!slices.Equal(cov.definitions, []string{"content/component-definition.json"}) {
		t.Fatalf("no-targets coverage %+v", cov)
	}
}

// The results reference every mapping definition the package relies on.
func TestExportLinksContributingMappings(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	if _, err := Export(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(req.Out, "assessment-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AR struct {
			Metadata struct {
				Links []struct{ Href, Text string } `json:"links"`
			} `json:"metadata"`
		} `json:"assessment-results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var mappings []string
	for _, l := range doc.AR.Metadata.Links {
		if l.Text == "Authored partial mapping" {
			mappings = append(mappings, l.Href)
			if _, err := os.Stat(filepath.Join(req.Out, l.Href)); err != nil {
				t.Errorf("linked mapping %s is not in the package: %v", l.Href, err)
			}
		}
	}
	if !slices.Equal(mappings, []string{"content/component-definition.json"}) {
		t.Fatalf("privileged package mapping links: %v", mappings)
	}
}

// A finding targets exactly the mapped statement, not the whole control.
func TestFindingsTargetMappedStatements(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	if _, err := Export(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	r := firstResult(t, req.Out)
	findings, _ := r["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("no findings for an attributable failure")
	}
	for _, f := range findings {
		if id := assessment.Str(assessment.At(assessment.Map(f), "target", "target-id")); id != "ac-6_smt" {
			// The privileged check maps ac-6_smt itself; a part mapping would differ.
			t.Fatalf("finding target %q", id)
		}
	}
}

func TestRetargetFindingsToMappedStatement(t *testing.T) {
	cov := coverage{controls: map[string]map[string][]string{
		"ac-6": {"ac-6_smt": {"x"}}, "cm-6": {"cm-6_smt.b": {"y"}}, "cm-7": {"cm-7_smt.a": {"z"}, "cm-7_smt.b": {"z"}},
	}}
	fs := []oscal.Finding{{Target: oscal.FindingTarget{TargetId: "ac-6_smt"}}, {Target: oscal.FindingTarget{TargetId: "cm-6_smt"}}, {Target: oscal.FindingTarget{TargetId: "cm-7_smt"}}}
	retargetFindings(&fs, cov)
	got := []string{fs[0].Target.TargetId, fs[1].Target.TargetId, fs[2].Target.TargetId}
	if !slices.Equal(got, []string{"ac-6_smt", "cm-6_smt.b", "cm-7_smt"}) {
		t.Fatalf("targets %v", got)
	}
}
