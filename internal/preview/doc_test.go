package preview

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var docBlock = regexp.MustCompile("(?s)<!-- fixture: (\\S+) -->\n```yaml\n(.*?)```\n")

// Every YAML example in docs/policy-preview.md must be exactly a fixture, and
// every fixture must behave as the documentation says.
func TestDocumentedExamplesAreFixtures(t *testing.T) {
	doc, err := os.ReadFile("../../docs/policy-preview.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	blocks := docBlock.FindAllStringSubmatch(text, -1)
	if fences := strings.Count(text, "```yaml\n"); fences != len(blocks) || len(blocks) == 0 {
		t.Fatalf("%d yaml fences but %d fixture-backed blocks", fences, len(blocks))
	}
	used := map[string]bool{}
	for _, b := range blocks {
		path := "../../" + b[1]
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != b[2] {
			t.Errorf("%s differs from its documented example", b[1])
		}
		used[b[1]] = true
		objs, errs := Parse(b[1], raw, Limits{})
		if strings.Contains(b[1], "/invalid/") {
			first, _, _ := strings.Cut(string(raw), "\n")
			want := strings.TrimPrefix(first, "# expect: ")
			if len(errs) == 0 || string(errs[0].Code) != want {
				t.Errorf("%s: want error %q, got %v (%d objects)", b[1], want, errs, len(objs))
			}
		} else if len(errs) != 0 {
			t.Errorf("%s: %v", b[1], errs)
		}
	}
	for _, dir := range []string{"valid", "invalid"} {
		entries, _ := os.ReadDir("../../testdata/preview/examples/" + dir)
		for _, e := range entries {
			if p := "testdata/preview/examples/" + dir + "/" + e.Name(); !used[p] {
				t.Errorf("fixture %s is not documented", p)
			}
		}
	}
	// The statements the page makes about the exported example hold.
	raw, _ := os.ReadFile("../../testdata/preview/examples/valid/exported.yaml")
	objs, _ := Parse("exported.yaml", raw, Limits{})
	if len(objs) != 1 || len(objs[0].Ignored) == 0 || objs[0].Binding.UID != "" {
		t.Errorf("exported example: %+v", objs)
	}
}
