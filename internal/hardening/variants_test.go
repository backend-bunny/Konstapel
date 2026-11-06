package hardening

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type variantsManifest struct {
	Convention struct {
		Windows   string `json:"windows"`
		OmittedOS string `json:"omittedOs"`
		Templates string `json:"templates"`
	} `json:"convention"`
	ProvenanceAnnotations []string `json:"provenanceAnnotations"`
	Variants              []struct {
		Check        string `json:"check"`
		File         string `json:"file"`
		SHA256       string `json:"sha256"`
		Source       string `json:"source"`
		SourceSHA256 string `json:"sourceSha256"`
		Changes      []struct {
			ID     string   `json:"id"`
			Paths  []string `json:"paths"`
			Detail string   `json:"detail"`
		} `json:"changes"`
	} `json:"variants"`
}

func loadVariants(t *testing.T) variantsManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "content/linux-hardening/variants.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m variantsManifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func yamlMap(t *testing.T, rel string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// diffPaths lists the leaf paths where a and b differ, in the dotted/indexed
// form used by variants.json. Annotation keys are kept whole.
func diffPaths(prefix string, a, b any) []string {
	if reflect.DeepEqual(a, b) {
		return nil
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		var out []string
		for k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if strings.HasSuffix(prefix, "annotations") {
				if !reflect.DeepEqual(am[k], bm[k]) {
					out = append(out, p)
				}
				continue
			}
			out = append(out, diffPaths(p, am[k], bm[k])...)
		}
		return out
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok && blok && len(al) == len(bl) {
		var out []string
		for i := range al {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			// List elements that are objects with a name are compared whole.
			if m, ok := al[i].(map[string]any); ok && m["name"] != nil {
				if !reflect.DeepEqual(al[i], bl[i]) {
					out = append(out, p)
				}
				continue
			}
			out = append(out, diffPaths(p, al[i], bl[i])...)
		}
		return out
	}
	return []string{prefix}
}

// Each variant differs from its vendored source only where variants.json
// says so, plus the provenance annotations; the source stays untouched.
func TestVariantsDifferOnlyAsDeclared(t *testing.T) {
	m := loadVariants(t)
	listed := listedSums(t)
	var checks []string
	for _, v := range m.Variants {
		checks = append(checks, v.Check)
		t.Run(v.Check, func(t *testing.T) {
			if fileSum(t, v.File) != v.SHA256 || listed[v.File] != v.SHA256 {
				t.Errorf("variant %s checksum: file %s, recorded %s, SHA256SUMS %s", v.File, fileSum(t, v.File), v.SHA256, listed[v.File])
			}
			if fileSum(t, v.Source) != v.SourceSHA256 || listed[v.Source] != v.SourceSHA256 {
				t.Errorf("source %s checksum mismatch", v.Source)
			}
			src, variant := yamlMap(t, v.Source), yamlMap(t, v.File)
			ann := variant["metadata"].(map[string]any)["annotations"].(map[string]any)
			if ann["compliance.erenius.io/source-sha256"] != v.SourceSHA256 || !strings.HasSuffix(fmt.Sprint(ann["compliance.erenius.io/variant-of"]), "/"+v.Check) {
				t.Errorf("provenance annotations = %v", ann)
			}
			for _, a := range m.ProvenanceAnnotations {
				delete(ann, a)
			}
			want := map[string]bool{}
			for _, c := range v.Changes {
				if c.Detail == "" || len(c.Paths) == 0 {
					t.Errorf("change %s is undocumented", c.ID)
				}
				for _, p := range c.Paths {
					want[p] = true
				}
			}
			got := diffPaths("", src, variant)
			sort.Strings(got)
			var declared []string
			for p := range want {
				declared = append(declared, p)
			}
			sort.Strings(declared)
			if !slices.Equal(got, declared) {
				t.Errorf("variant differs at %v, declared %v", got, declared)
			}
			// The logical check identity is unchanged.
			if variant["metadata"].(map[string]any)["name"] != v.Check {
				t.Errorf("variant name %v", variant["metadata"].(map[string]any)["name"])
			}
		})
	}
	slices.Sort(checks)
	if !slices.Equal(checks, []string{"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot", "restrict-seccomp-strict"}) {
		t.Errorf("variants for %v", checks)
	}
	if listed["content/linux-hardening/variants.json"] != fileSum(t, "content/linux-hardening/variants.json") {
		t.Error("variants.json is not covered by SHA256SUMS")
	}
}

// Every variant applies the same OS convention: explicit Windows
// short-circuits every validation; nothing else consults the OS.
func TestVariantsShareTheOSConvention(t *testing.T) {
	const guard = "variables.podSpec.?os.?name.orValue('') == 'windows'"
	for _, v := range loadVariants(t).Variants {
		p := yamlMap(t, v.File)
		spec := p["spec"].(map[string]any)
		found := false
		for _, x := range spec["variables"].([]any) {
			vr := x.(map[string]any)
			if vr["name"] == "isWindowsPod" {
				found = vr["expression"] == guard
			}
			if vr["name"] == "podSpec" && !strings.Contains(fmt.Sprint(vr["expression"]), "jobTemplate") {
				t.Errorf("%s: podSpec does not extract CronJob templates", v.Check)
			}
		}
		if !found {
			t.Errorf("%s: no isWindowsPod = %s", v.Check, guard)
		}
		for i, x := range spec["validations"].([]any) {
			expr := strings.TrimSpace(fmt.Sprint(x.(map[string]any)["expression"]))
			if !strings.HasPrefix(expr, "variables.isWindowsPod ||") {
				t.Errorf("%s validation %d does not start with the Windows guard", v.Check, i)
			}
			if strings.Contains(expr, "hostUsers") || strings.Contains(expr, "userNamespace") {
				t.Errorf("%s validation %d has a user-namespace bypass", v.Check, i)
			}
		}
	}
}

// The recorded CLI evidence names the exact variant digests it tested; a
// changed variant makes it stale until the suites are re-run and re-recorded.
func TestVariantCLIEvidenceIsCurrent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "docs/integration/hardening-variant-cli.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev struct {
		Variants []struct {
			Check  string `json:"check"`
			SHA256 string `json:"sha256"`
		} `json:"variants"`
		Suites []struct {
			Fixture  string   `json:"fixture"`
			Policies []string `json:"policies"`
			Passed   int      `json:"passed"`
			Failed   int      `json:"failed"`
		} `json:"suites"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	current := map[string]string{}
	for _, v := range loadVariants(t).Variants {
		current[v.Check] = v.SHA256
	}
	if len(ev.Variants) != len(current) {
		t.Fatalf("evidence covers %d variants, have %d", len(ev.Variants), len(current))
	}
	for _, v := range ev.Variants {
		if current[v.Check] != v.SHA256 {
			t.Errorf("%s: evidence tested %s, current variant is %s; re-run and re-record the CLI suites", v.Check, v.SHA256, current[v.Check])
		}
	}
	tested := map[string]bool{}
	for _, s := range ev.Suites {
		if s.Failed != 0 || s.Passed == 0 {
			t.Errorf("%s: %d passed, %d failed", s.Fixture, s.Passed, s.Failed)
		}
		if _, err := os.Stat(filepath.Join(root, s.Fixture, "kyverno-test.yaml")); err != nil {
			t.Errorf("%s: %v", s.Fixture, err)
		}
		for _, p := range s.Policies {
			tested[p] = true
		}
	}
	for check := range current {
		if !tested["content/linux-hardening/variants/"+check+".yaml"] {
			t.Errorf("no recorded suite tests the %s variant", check)
		}
	}
}
