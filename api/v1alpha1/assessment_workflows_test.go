package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The workflow guide publishes only validated example files, verbatim.
func TestWorkflowExamplesArePublishedFiles(t *testing.T) {
	raw, err := os.ReadFile("../../docs/integration/assessment-workflows.md")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("../../testdata/assessments/examples/valid/*.yaml")
	examples := map[string]bool{}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		examples[strings.TrimSpace(string(b))] = true
	}
	blocks := 0
	rest := string(raw)
	for {
		_, after, ok := strings.Cut(rest, "```yaml\n")
		if !ok {
			break
		}
		block, tail, _ := strings.Cut(after, "```")
		rest = tail
		blocks++
		if !examples[strings.TrimSpace(block)] {
			t.Errorf("yaml block %d is not a validated example file:\n%s", blocks, block)
		}
	}
	if blocks < 3 {
		t.Fatalf("expected the binding, run and request examples, found %d yaml blocks", blocks)
	}
}
