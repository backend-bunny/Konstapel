package installed_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

var verifiedBlock = regexp.MustCompile("(?s)<!-- verified: ([a-z-]+) -->\n```json\n(.*?)\n```")

// documentedExamples computes every example docs/assessment-providers.md
// shows, from the installed registry.
func documentedExamples() map[string]any {
	r := installed.Registry()
	_, rejected := r.Select(provider.Selection{Provider: "konstapel-kyverno/v1", Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{
		{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"allowPrivileged":true}`)}},
		{Name: "image-vulnerabilities", Kind: "scanner.example.io/v1/ImageReport"},
	}})
	_, unknown := r.Select(provider.Selection{Provider: "example-scanner/v1", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{
		{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind}}})
	return map[string]any{
		"kyverno-descriptor":  kyverno.Descriptor(),
		"installed-contracts": r.Contracts(),
		"rejected-selection":  rejected,
		"unknown-provider":    unknown,
	}
}

func TestDocumentedExamples(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/assessment-providers.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := documentedExamples()
	seen := map[string]bool{}
	for _, m := range verifiedBlock.FindAllSubmatch(doc, -1) {
		name := string(m[1])
		seen[name] = true
		actual, ok := want[name]
		if !ok {
			t.Errorf("documented example %q is not verified by this test", name)
			continue
		}
		var documented, computed any
		if err := json.Unmarshal(m[2], &documented); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		b, _ := json.Marshal(actual)
		_ = json.Unmarshal(b, &computed)
		if !reflect.DeepEqual(documented, computed) {
			pretty, _ := json.MarshalIndent(actual, "", "  ")
			t.Errorf("documented %s differs from the implementation; it is:\n%s", name, pretty)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("example %s is not in the guide", name)
		}
	}
}

// Every test the guide cites as a guarantee exists.
func TestDocumentedTestsExist(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "docs/assessment-providers.md"))
	if err != nil {
		t.Fatal(err)
	}
	cited := regexp.MustCompile("`(Test[A-Za-z]+)`").FindAllStringSubmatch(string(doc), -1)
	if len(cited) == 0 {
		t.Fatal("the guide cites no tests; the check is not working")
	}
	var sources strings.Builder
	files, _ := filepath.Glob(filepath.Join(root, "internal/provider/*/*_test.go"))
	more, _ := filepath.Glob(filepath.Join(root, "internal/provider/*_test.go"))
	for _, f := range slices.Concat(files, more) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sources.Write(b)
	}
	for _, c := range cited {
		if !strings.Contains(sources.String(), "func "+c[1]+"(") {
			t.Errorf("the guide cites %s, which does not exist", c[1])
		}
	}
}
