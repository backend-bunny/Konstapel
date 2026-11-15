package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// crdSchema is the subset of an OpenAPI v3 schema the path check walks.
type crdSchema struct {
	Properties map[string]crdSchema `json:"properties"`
	Items      *crdSchema           `json:"items"`
}

func loadCRDStatusSchema(t *testing.T, plural string) crdSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "config/crd/bases/compliance.erenius.io_"+plural+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema crdSchema `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	return crd.Spec.Versions[0].Schema.OpenAPIV3Schema
}

var (
	kubectlGetRE = regexp.MustCompile(`kubectl get (compliancebindings?|assessmentruns?) .*`)
	fieldPathRE  = regexp.MustCompile(`\.(status|spec)((?:\.[A-Za-z]+|\[[^\]]*\])*)`)
	segmentRE    = regexp.MustCompile(`\.[A-Za-z]+|\[[^\]]*\]`)
)

// Every kubectl command in the runbooks reads status and spec fields that
// the owning CRDs define, and every starter-alert runbook explains its
// meaning, diagnosis and recovery check (task 5.3).
func TestRunbookCommandsMatchStatusContracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs/integration/alert-runbooks.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(raw), "\\\n", " ")
	schemas := map[string]crdSchema{
		"compliancebinding": loadCRDStatusSchema(t, "compliancebindings"),
		"assessmentrun":     loadCRDStatusSchema(t, "assessmentruns"),
	}
	checked := 0
	for _, cmd := range kubectlGetRE.FindAllStringSubmatch(doc, -1) {
		schema := schemas[strings.TrimSuffix(cmd[1], "s")]
		for _, m := range fieldPathRE.FindAllStringSubmatch(cmd[0], -1) {
			node, ok := schema.Properties[m[1]]
			for _, seg := range segmentRE.FindAllString(m[2], -1) {
				if !ok {
					break
				}
				if strings.HasPrefix(seg, "[") {
					ok = node.Items != nil
					if ok {
						node = *node.Items
					}
					continue
				}
				node, ok = node.Properties[seg[1:]]
			}
			if !ok {
				t.Errorf("%s has no field %s (in %q)", cmd[1], m[0], cmd[0])
			}
			checked++
		}
	}
	if checked < 20 {
		t.Errorf("only %d status paths checked", checked)
	}

	sections := strings.Split(doc, "\n## ")
	runbooks := 0
	for _, s := range sections[1:] {
		title, body, _ := strings.Cut(s, "\n")
		if !strings.HasPrefix(title, "Konstapel") {
			continue
		}
		runbooks++
		for _, part := range []string{"**Meaning.**", "**Impact.**", "**Diagnose.**", "**Recovery check.**", "```sh"} {
			if !strings.Contains(body, part) {
				t.Errorf("runbook %s has no %s", title, part)
			}
		}
	}
	if runbooks != 7 {
		t.Errorf("%d starter-alert runbooks, want 7", runbooks)
	}
}
