package charttest

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// renderFiles renders the runtime chart with values files, as the docs
// instruct, plus a pinned digest (a published chart carries one).
func renderFiles(t *testing.T, files ...string) []map[string]any {
	t.Helper()
	args := []string{"template", "konstapel", "../../charts/konstapel", "--namespace", "konstapel-system", "--set", "image.digest=" + digest}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("render %v: %v\n%s", files, err, out)
	}
	return documents(t, out)
}

// The values examples in docs/examples/charts render to what docs/charts.md
// says they do, and the docs reference every one of them.
func TestDocumentedExamples(t *testing.T) {
	examples, _ := filepath.Glob("../../docs/examples/charts/*.yaml")
	docs, err := os.ReadFile("../../docs/charts.md")
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]func(t *testing.T, docs []map[string]any){
		"operator-tls.yaml": func(t *testing.T, docs []map[string]any) {
			d := find(docs, "Deployment", "konstapel-download")
			if at(d, "spec", "template", "spec", "volumes", 0, "secret", "secretName") != "operator-download-tls" {
				t.Error("download does not mount the operator Secret")
			}
			for _, kind := range []string{"Certificate", "Issuer", "Secret"} {
				for _, o := range docs {
					if o["kind"] == kind {
						t.Errorf("operator TLS renders a %s %v", kind, metadata(o)["name"])
					}
				}
			}
		},
		"platform-issuer.yaml": func(t *testing.T, docs []map[string]any) {
			c := find(docs, "Certificate", "konstapel-download")
			if at(c, "spec", "issuerRef", "name") != "platform-ca" || at(c, "spec", "issuerRef", "kind") != "ClusterIssuer" {
				t.Errorf("download Certificate issuer %v", at(c, "spec", "issuerRef"))
			}
			if find(docs, "Issuer", "konstapel-ca") != nil || find(docs, "Certificate", "konstapel-ca") != nil {
				t.Error("platform issuer still renders the chart CA")
			}
		},
		"oci-bundles.yaml": func(t *testing.T, docs []map[string]any) {
			role := find(docs, "Role", "konstapel-controller-bundles")
			if want := bundleRules([]string{"acme-registry-ca"}, []string{"acme-registry", "acme-bundle-signing-key"}); role == nil || !reflect.DeepEqual(role["rules"], any(want)) {
				t.Errorf("bundle Role %v", role)
			}
			args := at(find(docs, "Deployment", "konstapel-controller"), "spec", "template", "spec", "containers", 0, "args").([]any)
			if !slices.Contains(args, any("--bundle-sources-configmap="+sourcesCM)) {
				t.Errorf("bundles not enabled: %v", args)
			}
		},
		"development.yaml": func(t *testing.T, docs []map[string]any) {
			for _, name := range []string{"konstapel-controller", "konstapel-download"} {
				if r := at(find(docs, "Deployment", name), "spec", "replicas"); r != float64(1) && r != 1 {
					t.Errorf("%s replicas %v", name, r)
				}
			}
			for _, o := range docs {
				if o["kind"] == "PodDisruptionBudget" {
					t.Errorf("development renders PodDisruptionBudget %v", metadata(o)["name"])
				}
			}
			args := at(find(docs, "Deployment", "konstapel-controller"), "spec", "template", "spec", "containers", 0, "args").([]any)
			found := false
			for _, a := range args {
				found = found || a == "--leader-elect=true"
			}
			if !found {
				t.Error("development turns leader election off")
			}
		},
	}
	if len(examples) != len(checks) {
		t.Fatalf("examples %v, checked %d", examples, len(checks))
	}
	for _, f := range examples {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			check, ok := checks[name]
			if !ok {
				t.Fatalf("no check for %s", name)
			}
			if !strings.Contains(string(docs), "docs/examples/charts/"+name) {
				t.Errorf("docs/charts.md does not reference %s", name)
			}
			check(t, renderFiles(t, f))
		})
	}
}
