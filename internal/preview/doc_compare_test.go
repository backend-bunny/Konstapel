package preview

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func exampleSet(t *testing.T, name string) *Set {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/preview/examples/valid/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return mustSet(t, string(raw))
}

// The worked examples in docs/policy-preview.md say what the comparison
// reports for their fixtures; these are those statements.
func TestDocumentedComparisonExamples(t *testing.T) {
	t.Run("selector change keeps the remaining overlap", func(t *testing.T) {
		c := overlapWorld(t).compare(exampleSet(t, "selector-change.yaml"), nil)
		if !c.Complete || c.ImpactCount != 2 || len(c.Contributions) != 2 || len(c.Namespaces) != 4 {
			t.Fatalf("%+v", c)
		}
		for _, r := range c.Contributions {
			if r.Key.Binding != "deny-prod" || !slices.Equal(categories(r), []string{"selector-changed", "namespace-added", "namespace-removed", "revision-replaced"}) ||
				r.Impacts[0].Before != "env=production" || r.Impacts[0].After != "env=staging" ||
				r.Impacts[1].After != "staging (staging-uid)" || r.Impacts[2].Before != "prod (prod-uid)" {
				t.Fatalf("%+v", r)
			}
		}
		for _, n := range c.Namespaces {
			moved := n.Removed
			if n.Namespace.Name == "staging" {
				moved = n.Added
			}
			if len(moved) != 1 || moved[0].Binding != "deny-prod" || len(n.Impacts) != 0 ||
				len(n.Remaining) != 1 || n.Remaining[0].Binding != "audit-all" || n.Remaining[0].RevisionEffect != RevisionUnchanged ||
				n.Before.Effective != "Forbidden" || n.After.Effective != "Forbidden" {
				t.Fatalf("%+v", n)
			}
		}
	})
	t.Run("reordered selector replaces revisions", func(t *testing.T) {
		c := revisionWorld(t).compare(exampleSet(t, "reordered-selector.yaml"), nil)
		if !c.Complete || len(c.Objects) != 1 || len(c.Contributions) != 2 {
			t.Fatalf("%+v", c)
		}
		if o := c.Objects[0]; o.Disposition != Unchanged || o.ConfigurationChanged || o.LiveFingerprint != o.CandidateFingerprint || o.StoredSpec != StoredSpecDifferent {
			t.Fatalf("%+v", o)
		}
		for _, r := range c.Contributions {
			if r.Key.Binding != "deny" || r.RevisionEffect != RevisionReplacement || !r.SemanticallyEquivalent || !slices.Equal(categories(r), []string{"revision-replaced"}) {
				t.Fatalf("%+v", r)
			}
		}
	})
}

// Every impact category the comparison can raise is documented with its area.
func TestImpactCategoriesAreDocumented(t *testing.T) {
	src, err := os.ReadFile("compare.go")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/policy-preview.md")
	if err != nil {
		t.Fatal(err)
	}
	consts := regexp.MustCompile(`(?m)^\s+(Category\w+)\s+Category = "([a-z-]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(consts) < 12 {
		t.Fatalf("found only %d categories", len(consts))
	}
	for _, m := range consts {
		row := "| `" + m[2] + "` | " + string(AreaOf(Category(m[2]))) + " |"
		if !strings.Contains(string(doc), row) {
			t.Errorf("%s is not documented as %q", m[1], row)
		}
	}
}
