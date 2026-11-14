package observability

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// guides maps each owner domain to its owning integration guide.
var guides = map[Domain]string{
	DomainTargeting:        "docs/integration/targeting-api.md",
	DomainAssessment:       "docs/integration/assessment-contract.md",
	DomainEvidenceStorage:  "docs/integration/s3-evidence.md",
	DomainBundleResolution: "docs/policy-bundles.md",
}

// processFamilies are per-replica families documented by the guides of the
// domains whose operations they count.
var processFamilies = map[Domain][]string{
	DomainEvidenceStorage:  {"konstapel_operation_attempts_total", "konstapel_operation_duration_seconds"},
	DomainBundleResolution: {"konstapel_operation_attempts_total", "konstapel_operation_duration_seconds", "konstapel_observation_ready"},
}

// Each owning guide documents every signal its domain emits, links the
// metric contract, and names producer tests that exist.
func TestOwningGuidesDocumentSignals(t *testing.T) {
	tests := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".devbox" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			tests[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for domain, guide := range guides {
		raw, err := os.ReadFile(filepath.Join(repoRoot, guide))
		if err != nil {
			t.Fatal(err)
		}
		_, after, ok := strings.Cut(string(raw), "\n## Metrics\n")
		if !ok {
			t.Errorf("%s has no Metrics section", guide)
			continue
		}
		section, _, _ := strings.Cut(after, "\n## ")
		if !strings.Contains(section, "metrics.md") {
			t.Errorf("%s: Metrics section does not link the metric contract", guide)
		}
		if !strings.Contains(section, `domain="`+string(domain)+`"`) {
			t.Errorf("%s: Metrics section does not name its domain %s", guide, domain)
		}
		want := processFamilies[domain]
		for _, m := range Catalog {
			if m.Domain == domain {
				want = append(want, m.Name)
			}
		}
		for _, name := range want {
			if !strings.Contains(section, name) {
				t.Errorf("%s: Metrics section does not document %s", guide, name)
			}
		}
		named := regexp.MustCompile("`(Test\\w+)`").FindAllStringSubmatch(section, -1)
		if len(named) == 0 {
			t.Errorf("%s: Metrics section names no producer tests", guide)
		}
		for _, m := range named {
			if !tests[m[1]] {
				t.Errorf("%s: producer test %s does not exist", guide, m[1])
			}
		}
	}
}
