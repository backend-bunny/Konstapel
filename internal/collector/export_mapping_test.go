package collector

import (
	"encoding/json"
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
	if cov, _ := coverageFor(repo(t), empty); cov.summary != assessment.Coverage || !slices.Equal(cov.rules, []string{assessment.PolicyName}) {
		t.Fatalf("no-targets coverage %+v", cov)
	}
}
