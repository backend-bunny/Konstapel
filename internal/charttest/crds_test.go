// Package charttest checks the Helm charts against the generated API
// outputs without a cluster (add-helm-oci-distribution 2.1, 2.2).
package charttest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func documents(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, doc := range bytes.Split(raw, []byte("\n---")) {
		var m map[string]any
		if err := yaml.Unmarshal(doc, &m); err != nil {
			t.Fatal(err)
		}
		if len(m) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func metadata(o map[string]any) map[string]any {
	m, _ := o["metadata"].(map[string]any)
	return m
}

// The CRD chart renders exactly the generated definitions: the same set,
// identical specs, and only the reviewed packaging metadata added — the
// keep policy and chart labels. Nothing in it can delete, recreate, or
// strip a CRD or its instances.
func TestCRDChartMatchesGeneratedDefinitions(t *testing.T) {
	out, err := exec.Command("helm", "template", "konstapel-crds", "../../charts/konstapel-crds").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rendered := map[string]map[string]any{}
	for _, o := range documents(t, out) {
		if o["kind"] != "CustomResourceDefinition" || o["apiVersion"] != "apiextensions.k8s.io/v1" {
			t.Fatalf("the CRD chart renders a %v %v", o["apiVersion"], o["kind"])
		}
		rendered[metadata(o)["name"].(string)] = o
	}
	files, _ := filepath.Glob("../../config/crd/bases/*.yaml")
	if len(files) == 0 {
		t.Fatal("no generated CRDs")
	}
	var want []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		base := documents(t, raw)[0]
		name := metadata(base)["name"].(string)
		want = append(want, name)
		got, ok := rendered[name]
		if !ok {
			t.Errorf("%s: generated CRD missing from the chart", name)
			continue
		}
		if !strings.HasSuffix(name, ".compliance.erenius.io") {
			t.Errorf("%s: outside the compliance.erenius.io API group", name)
		}
		if !reflect.DeepEqual(got["spec"], base["spec"]) {
			t.Errorf("%s: chart schema differs from the generated definition", name)
		}
		m := metadata(got)
		for k := range m {
			if k != "name" && k != "annotations" && k != "labels" {
				t.Errorf("%s: unexpected metadata.%s (owner references, finalizers, etc. are never packaged)", name, k)
			}
		}
		ann, _ := m["annotations"].(map[string]any)
		if ann["helm.sh/resource-policy"] != "keep" {
			t.Errorf("%s: not retained on uninstall", name)
		}
		for k := range ann {
			if strings.HasPrefix(k, "helm.sh/hook") {
				t.Errorf("%s: carries hook annotation %s", name, k)
			}
		}
		baseAnn, _ := metadata(base)["annotations"].(map[string]any)
		delete(ann, "helm.sh/resource-policy")
		if !reflect.DeepEqual(ann, baseAnn) {
			t.Errorf("%s: annotations %v differ from generated %v beyond the keep policy", name, ann, baseAnn)
		}
		if labels, _ := m["labels"].(map[string]any); labels["app.kubernetes.io/name"] != "konstapel-crds" || labels["app.kubernetes.io/part-of"] != "konstapel" {
			t.Errorf("%s: chart labels %v", name, labels)
		}
	}
	got := make([]string, 0, len(rendered))
	for name := range rendered {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chart CRDs %v, generated %v (placeholder or obsolete definitions?)", got, want)
	}
}

// Neither chart can run cleanup on install, upgrade, or uninstall.
func TestChartsHaveNoHooksOrCleanupJobs(t *testing.T) {
	for _, chart := range []string{"konstapel-crds", "konstapel"} {
		out, err := exec.Command("helm", "template", chart, "../../charts/"+chart, "--include-crds").CombinedOutput()
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", chart, err, out)
		}
		for _, o := range documents(t, out) {
			ann, _ := metadata(o)["annotations"].(map[string]any)
			for k := range ann {
				if strings.HasPrefix(k, "helm.sh/hook") {
					t.Errorf("%s renders a hook (%s) on %v %v", chart, k, o["kind"], metadata(o)["name"])
				}
			}
			if k := o["kind"]; k == "Job" || k == "CronJob" {
				t.Errorf("%s renders a %v", chart, k)
			}
		}
	}
}
