package hardening

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// split-hardening-policy-validations 1.1-1.2: the single-validation
// revision of the two multi-validation hardening checks. Each new policy is
// its original local variant with only one validation kept, byte-for-byte;
// the generated CLI suites under testdata/linux-hardening/split evaluate the
// original and both replacements on every resource, so the engine itself
// shows that the original outcome is the conjunction of the two new ones.

const splitInventory = "content/linux-hardening/split/variants.json"

type splitRef struct {
	Check      string `json:"check"`
	File       string `json:"file"`
	Validation int    `json:"validation"`
}

type splitManifest struct {
	Change     string `json:"change"`
	Purpose    string `json:"purpose"`
	Supersedes struct {
		Bundle              string `json:"bundle"`
		Version             string `json:"version"`
		ComponentDefinition string `json:"componentDefinition"`
		Variants            string `json:"variants"`
	} `json:"supersedes"`
	// Bundle is the OCI definition that ships this revision; the vendored
	// bundle keeps the superseded revision (owner decision 2026-11-27).
	Bundle struct {
		Definition string `json:"definition"`
		Version    string `json:"version"`
		Detail     string `json:"detail"`
	} `json:"bundle"`
	Sources             string `json:"sources"`
	ComponentDefinition string `json:"componentDefinition"`
	Checksums           struct {
		File   string `json:"file"`
		Detail string `json:"detail"`
	} `json:"checksums"`
	ProvenanceAnnotations []string `json:"provenanceAnnotations"`
	Denominator           struct {
		Original struct{ Policies, Validations int } `json:"original"`
		Revision struct{ Policies, Validations int } `json:"revision"`
	} `json:"denominator"`
	Identities []struct {
		From splitRef `json:"from"`
		To   splitRef `json:"to"`
	} `json:"identities"`
	Variants []struct {
		Check        string `json:"check"`
		File         string `json:"file"`
		SHA256       string `json:"sha256"`
		Source       string `json:"source"`
		SourceSHA256 string `json:"sourceSha256"`
		SplitFrom    struct {
			Check         string `json:"check"`
			File          string `json:"file"`
			SHA256        string `json:"sha256"`
			Validation    int    `json:"validation"`
			SubValidation string `json:"subValidation"`
			Sibling       string `json:"sibling"`
		} `json:"splitFrom"`
		Changes []struct {
			ID     string   `json:"id"`
			Paths  []string `json:"paths"`
			Detail string   `json:"detail"`
		} `json:"changes"`
	} `json:"variants"`
	Exceptions string `json:"exceptions"`
}

func loadSplit(t *testing.T) splitManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, splitInventory))
	if err != nil {
		t.Fatal(err)
	}
	var m splitManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The accepted identities of design decision 1, written out so that a
// renamed or dropped check fails here rather than against the inventory.
var (
	originalChecks = []string{"disallow-capabilities-strict", "disallow-privilege-escalation", "disallow-privileged-containers", "require-run-as-nonroot", "restrict-seccomp-strict"}
	splitChecks    = map[string][2]string{
		"disallow-capabilities-strict": {"require-drop-all-capabilities", "restrict-added-capabilities"},
		"restrict-seccomp-strict":      {"restrict-pod-seccomp-profile", "require-container-seccomp-profile"},
	}
)

// sumsFile reads a sha256sum list with repository-relative paths.
func sumsFile(t *testing.T, rel string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		sum, path, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("%s: malformed line %q", rel, line)
		}
		out[path] = sum
	}
	return out
}

func specValidations(t *testing.T, doc map[string]any) []any {
	t.Helper()
	v, _ := doc["spec"].(map[string]any)["validations"].([]any)
	return v
}

// 1.1: each new policy is its original local variant with exactly one
// validation kept unchanged and engine index 0; every other spec field is
// the original's, and the pair together is the original's validation list.
func TestSplitVariantsKeepTheOriginalValidations(t *testing.T) {
	m := loadSplit(t)
	var got []string
	kept := map[string][]any{}
	for _, v := range m.Variants {
		got = append(got, v.Check)
		t.Run(v.Check, func(t *testing.T) {
			pair, ok := splitChecks[v.SplitFrom.Check]
			if !ok || pair[v.SplitFrom.Validation] != v.Check || pair[1-v.SplitFrom.Validation] != v.SplitFrom.Sibling {
				t.Fatalf("%s is not validation %d of %s (pair %v)", v.Check, v.SplitFrom.Validation, v.SplitFrom.Check, pair)
			}
			if v.File != "content/linux-hardening/variants/"+v.Check+".yaml" || v.SplitFrom.File != "content/linux-hardening/variants/"+v.SplitFrom.Check+".yaml" {
				t.Errorf("paths %s from %s", v.File, v.SplitFrom.File)
			}
			orig, split := yamlMap(t, v.SplitFrom.File), yamlMap(t, v.File)
			if orig["apiVersion"] != "policies.kyverno.io/v1" || split["apiVersion"] != orig["apiVersion"] || split["kind"] != "ValidatingPolicy" || split["kind"] != orig["kind"] {
				t.Errorf("resource type %v %v", split["apiVersion"], split["kind"])
			}
			ov, sv := specValidations(t, orig), specValidations(t, split)
			if len(ov) != 2 || len(sv) != 1 {
				t.Fatalf("validations: original %d, split %d", len(ov), len(sv))
			}
			if !reflect.DeepEqual(sv[0], ov[v.SplitFrom.Validation]) {
				t.Errorf("validation differs from original validation %d:\n got  %v\n want %v", v.SplitFrom.Validation, sv[0], ov[v.SplitFrom.Validation])
			}
			kept[v.SplitFrom.Check] = append(kept[v.SplitFrom.Check], sv[0])
			// Everything else in spec is identical: actions, evaluation,
			// matching and operations (including the ephemeral-container
			// subresource) and every variable, used or not.
			oSpec, sSpec := maps.Clone(orig["spec"].(map[string]any)), maps.Clone(split["spec"].(map[string]any))
			delete(oSpec, "validations")
			delete(sSpec, "validations")
			if !reflect.DeepEqual(oSpec, sSpec) {
				t.Errorf("spec outside validations differs: %v", diffPaths("spec", oSpec, sSpec))
			}
			// Metadata: the new identity, the same upstream provenance, and
			// only the declared documentation annotations rewritten.
			om, sm := orig["metadata"].(map[string]any), split["metadata"].(map[string]any)
			if sm["name"] != v.Check {
				t.Errorf("metadata.name %v", sm["name"])
			}
			oa, sa := om["annotations"].(map[string]any), sm["annotations"].(map[string]any)
			for _, a := range m.ProvenanceAnnotations {
				if sa[a] == nil || sa[a] != oa[a] {
					t.Errorf("provenance annotation %s = %v, original %v", a, sa[a], oa[a])
				}
			}
			if sa["compliance.erenius.io/source-sha256"] != v.SourceSHA256 || !strings.HasSuffix(fmt.Sprint(sa["compliance.erenius.io/variant-of"]), "/"+v.SplitFrom.Check) {
				t.Errorf("provenance annotations = %v", sa)
			}
			// Declared changes are exactly the differences from the
			// unchanged upstream source (provenance annotations aside), as
			// for the original variants.
			src := yamlMap(t, v.Source)
			for _, a := range m.ProvenanceAnnotations {
				delete(sa, a)
			}
			var declared []string
			for _, c := range v.Changes {
				if c.Detail == "" || len(c.Paths) == 0 {
					t.Errorf("change %s is undocumented", c.ID)
				}
				declared = append(declared, c.Paths...)
			}
			diff := diffPaths("", src, split)
			sort.Strings(diff)
			sort.Strings(declared)
			if !slices.Equal(diff, declared) {
				t.Errorf("split variant differs from its source at %v, declared %v", diff, declared)
			}
		})
	}
	sort.Strings(got)
	if !slices.Equal(got, []string{"require-container-seccomp-profile", "require-drop-all-capabilities", "restrict-added-capabilities", "restrict-pod-seccomp-profile"}) {
		t.Fatalf("split variants %v", got)
	}
	// Each pair, in index order, is the original's whole validation list.
	for old := range splitChecks {
		ov := specValidations(t, yamlMap(t, "content/linux-hardening/variants/"+old+".yaml"))
		k := kept[old]
		if len(k) == 2 && !reflect.DeepEqual(ov, k) && !reflect.DeepEqual(ov, []any{k[1], k[0]}) {
			t.Errorf("%s: the pair does not reassemble the original validations", old)
		}
	}
}

// 1.2: checksums, source and license records, and the old-to-new identity
// mapping with an unchanged seven-check denominator.
func TestSplitInventory(t *testing.T) {
	m := loadSplit(t)
	listed := listedSums(t)
	if m.Change != "split-hardening-policy-validations" || m.Purpose == "" || !strings.Contains(m.Exceptions, "do not transfer") {
		t.Errorf("inventory header %q %q %q", m.Change, m.Purpose, m.Exceptions)
	}
	// The revision's own checksum list covers exactly its new files. They
	// stay out of content/SHA256SUMS, whose digest is the vendored bundle's
	// identity: saved vendored captures replay only against that content,
	// so adding unselected files there would change it for nothing.
	revision := sumsFile(t, m.Checksums.File)
	want := []string{splitInventory, m.ComponentDefinition}
	for _, v := range m.Variants {
		want = append(want, v.File)
	}
	if got := slices.Sorted(maps.Keys(revision)); !slices.Equal(got, slices.Sorted(slices.Values(want))) || m.Checksums.Detail == "" {
		t.Errorf("%s lists %v, want %v", m.Checksums.File, got, want)
	}
	for _, f := range want {
		if revision[f] != fileSum(t, f) {
			t.Errorf("%s does not match %s", f, m.Checksums.File)
		}
		if listed[f] != "" {
			t.Errorf("%s is listed in content/SHA256SUMS, changing the vendored bundle digest", f)
		}
	}
	// Source and license records: the split adds no upstream source; each
	// variant derives from an unchanged vendored file sources.json records,
	// and from the original local variant at its recorded digest.
	s := load(t)
	if m.Sources != "content/linux-hardening/sources.json" || s.License.SPDX != "Apache-2.0" || fileSum(t, s.License.File) != s.License.SHA256 || listed[s.License.File] != s.License.SHA256 {
		t.Errorf("license record %+v", s.License)
	}
	orig := loadVariants(t)
	for _, v := range m.Variants {
		if fileSum(t, v.File) != v.SHA256 || revision[v.File] != v.SHA256 {
			t.Errorf("%s checksum: file %s, recorded %s, %s %s", v.File, fileSum(t, v.File), v.SHA256, m.Checksums.File, revision[v.File])
		}
		if listed[v.SplitFrom.File] != v.SplitFrom.SHA256 {
			t.Errorf("%s: original %s is not the vendored variant", v.Check, v.SplitFrom.File)
		}
		if fileSum(t, v.SplitFrom.File) != v.SplitFrom.SHA256 {
			t.Errorf("%s: original %s changed", v.Check, v.SplitFrom.File)
		}
		var rec bool
		for _, c := range s.Checks {
			if c.Check != v.SplitFrom.Check {
				continue
			}
			rec = c.PolicyFile == v.Source && c.PolicySHA256 == v.SourceSHA256 && listed[v.Source] == v.SourceSHA256 && fileSum(t, v.Source) == v.SourceSHA256
			if v.SplitFrom.Validation >= len(c.SubValidations) || c.SubValidations[v.SplitFrom.Validation].Index != v.SplitFrom.Validation || c.SubValidations[v.SplitFrom.Validation].ID != v.SplitFrom.SubValidation {
				t.Errorf("%s: sub-validation %s is not %s index %d in sources.json", v.Check, v.SplitFrom.SubValidation, c.Check, v.SplitFrom.Validation)
			}
		}
		if !rec {
			t.Errorf("%s: source %s is not the recorded upstream file", v.Check, v.Source)
		}
		for _, ov := range orig.Variants {
			if ov.Check == v.SplitFrom.Check && (ov.File != v.SplitFrom.File || ov.SHA256 != v.SplitFrom.SHA256 || ov.SourceSHA256 != v.SourceSHA256) {
				t.Errorf("%s: original variant record %+v", v.Check, ov)
			}
		}
	}
	// Identities: every validation of every original policy maps to exactly
	// one single-validation policy at index 0, and nothing else is added.
	countValidations := func(file string) int { return len(specValidations(t, yamlMap(t, file))) }
	fromFiles, from, to := map[string]string{}, map[string]bool{}, map[string]bool{}
	origValidations, revValidations := 0, 0
	for _, id := range m.Identities {
		key := fmt.Sprintf("%s/%d", id.From.Check, id.From.Validation)
		if from[key] || to[id.To.Check] {
			t.Errorf("duplicate identity %s -> %s", key, id.To.Check)
		}
		from[key], to[id.To.Check] = true, true
		if f, ok := fromFiles[id.From.Check]; ok && f != id.From.File {
			t.Errorf("%s has two files", id.From.Check)
		}
		if _, ok := fromFiles[id.From.Check]; !ok {
			origValidations += countValidations(id.From.File)
		}
		fromFiles[id.From.Check] = id.From.File
		if n := countValidations(id.To.File); n != 1 || id.To.Validation != 0 {
			t.Errorf("%s has %d validations, index %d", id.To.Check, n, id.To.Validation)
		}
		revValidations++
		if pair, ok := splitChecks[id.From.Check]; ok {
			if pair[id.From.Validation] != id.To.Check {
				t.Errorf("%s maps to %s, want %s", key, id.To.Check, pair[id.From.Validation])
			}
		} else if id.To.Check != id.From.Check || id.To.File != id.From.File || id.From.Validation != 0 {
			t.Errorf("unsplit check %s changed identity to %s", key, id.To.Check)
		}
		if yamlMap(t, id.To.File)["metadata"].(map[string]any)["name"] != id.To.Check {
			t.Errorf("%s: metadata.name does not match", id.To.File)
		}
	}
	for c, f := range fromFiles {
		for i := 0; i < countValidations(f); i++ {
			if !from[fmt.Sprintf("%s/%d", c, i)] {
				t.Errorf("validation %d of %s has no new identity", i, c)
			}
		}
	}
	if got := slices.Sorted(maps.Keys(fromFiles)); !slices.Equal(got, originalChecks) {
		t.Errorf("original checks %v, want %v", got, originalChecks)
	}
	d := m.Denominator
	if d.Original.Policies != len(fromFiles) || d.Original.Validations != origValidations || d.Revision.Policies != len(to) || d.Revision.Validations != revValidations {
		t.Errorf("denominator %+v; counted %d/%d -> %d/%d", d, len(fromFiles), origValidations, len(to), revValidations)
	}
	if origValidations != 7 || revValidations != 7 || len(fromFiles) != 5 || len(to) != 7 {
		t.Errorf("the full-bundle check denominator changed: %d policies/%d validations -> %d/%d", len(fromFiles), origValidations, len(to), revValidations)
	}
	// The released superseded definition ships exactly the identity map's
	// original side, and the OCI definition that ships this revision exactly
	// its new side, in identity order.
	type definition struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Policies []struct{ Name, Path string }
	}
	readDef := func(p string) definition {
		raw, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		var d definition
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	old := readDef(m.Supersedes.Bundle)
	if old.Name != "konstapel-linux-hardening" || old.Version != m.Supersedes.Version || len(old.Policies) != len(fromFiles) {
		t.Errorf("superseded bundle %s@%s has %d policies, identity map %d", old.Name, old.Version, len(old.Policies), len(fromFiles))
	}
	for _, p := range old.Policies {
		if fromFiles[p.Name] != p.Path {
			t.Errorf("superseded bundle policy %s at %s, identity map %s", p.Name, p.Path, fromFiles[p.Name])
		}
	}
	rev := readDef(m.Bundle.Definition)
	if m.Bundle.Definition != "bundles/konstapel-linux-hardening/definition.json" || rev.Name != old.Name || rev.Version != m.Bundle.Version ||
		rev.Version == old.Version || !strings.Contains(m.Bundle.Detail, "vendored") {
		t.Errorf("revision bundle %+v: %s@%s", m.Bundle, rev.Name, rev.Version)
	}
	if len(rev.Policies) != len(m.Identities) {
		t.Fatalf("revision bundle has %d policies, identity map %d", len(rev.Policies), len(m.Identities))
	}
	for i, id := range m.Identities {
		if p := rev.Policies[i]; p.Name != id.To.Check || p.Path != id.To.File {
			t.Errorf("revision bundle policy %d is %s at %s, identity map %s at %s", i, p.Name, p.Path, id.To.Check, id.To.File)
		}
	}
}

// 1.2: the revision's component definition validates on its own content set
// (catalog, Moderate membership, Check_Id, policies) composed with the
// privileged check, maps seven distinct checks, keeps every original check's
// statements for each replacement and leaves the unsplit checks unchanged.
func TestSplitMappings(t *testing.T) {
	m := loadSplit(t)
	set := func(def string, side func(i int) splitRef) assessment.ContentSet {
		cs := assessment.ContentSet{Definitions: []string{assessment.ComponentDefinitions[0], def}, Policies: map[string]string{}}
		for i := range m.Identities {
			r := side(i)
			cs.Policies[r.Check] = r.File
		}
		return cs
	}
	if assessment.ComponentDefinitions[0] != "content/component-definition.json" {
		t.Fatalf("privileged definition %s", assessment.ComponentDefinitions[0])
	}
	old, err := assessment.MappingsOf(root, set(m.Supersedes.ComponentDefinition, func(i int) splitRef { return m.Identities[i].From }))
	if err != nil {
		t.Fatal(err)
	}
	rev, err := assessment.MappingsOf(root, set(m.ComponentDefinition, func(i int) splitRef { return m.Identities[i].To }))
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 5 || len(rev) != 7 {
		t.Fatalf("mapped checks: original %d, revision %d", len(old), len(rev))
	}
	statements := func(ms []assessment.Mapping) []string {
		var out []string
		for _, x := range ms {
			out = append(out, x.ControlID+"/"+x.StatementID)
		}
		sort.Strings(out)
		return out
	}
	for _, id := range m.Identities {
		o, n := old[id.From.Check], rev[id.To.Check]
		if len(n) == 0 || !slices.Equal(statements(o), statements(n)) {
			t.Errorf("%s maps %v, its original %s maps %v", id.To.Check, statements(n), id.From.Check, statements(o))
		}
		for _, x := range n {
			if id.To.Check == id.From.Check {
				if x.Rationale != o[0].Rationale {
					t.Errorf("%s: unsplit rationale changed", id.To.Check)
				}
				continue
			}
			if !strings.HasPrefix(x.Rationale, "Partial ") || !strings.Contains(x.Rationale, "does not establish full") ||
				!strings.Contains(x.Rationale, fmt.Sprintf("Split from %s validation %d", id.From.Check, id.From.Validation)) {
				t.Errorf("%s: rationale %q", id.To.Check, x.Rationale)
			}
		}
	}
	// No old identity survives in the revision's mappings, and the
	// revision definition never claims more than partial evidence.
	for old := range splitChecks {
		if rev[old] != nil {
			t.Errorf("revision still maps %s", old)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, m.ComponentDefinition))
	if err != nil {
		t.Fatal(err)
	}
	for old := range splitChecks {
		if bytes.Contains(raw, []byte(`"value": "`+old+`"`)) {
			t.Errorf("%s names %s as a rule or check", m.ComponentDefinition, old)
		}
	}
	var doc struct {
		CD struct {
			Components []struct {
				ControlImplementations []struct {
					ImplementedRequirements []struct {
						Description string `json:"description"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.CD.Components {
		for _, ci := range c.ControlImplementations {
			for _, r := range ci.ImplementedRequirements {
				if !strings.HasPrefix(r.Description, "Partial technical evidence only") {
					t.Errorf("implemented requirement claims more than partial evidence: %q", r.Description)
				}
			}
		}
	}
}

// --- 1.1 outcome matrices. A case is one subject container of a class in a
// workload form; extra adds a second regular container. Expected outcomes
// come from per-validation Go models; the original's expectation is the
// independent combined model from matrices_test.go, and the test requires it
// to equal the conjunction of the two split models on every case.

type splitCase struct {
	name, form, class string
	windows           bool
	podSC, subjectSC  map[string]any
	extraSC           map[string]any // nil: no extra container
	first, second     bool           // split models
	original          bool           // combined model
}

type splitPair struct {
	dir, original string
	checks        [2]string
	otherSC       func() map[string]any
	cases         []splitCase
}

// fullForms get the complete value cross-product; the remaining template
// forms get every outcome combination.
var fullForms = []string{"Pod", "Deployment", "CronJob"}

func splitFormsFor(class string) []string {
	if class == "ephemeral" {
		return []string{"Pod"}
	}
	var out []string
	for _, f := range forms {
		out = append(out, f.kind)
	}
	return out
}

func (p splitPair) object(c splitCase) map[string]any {
	ctr := func(name string, sc map[string]any) map[string]any {
		o := map[string]any{"name": name, "image": "busybox:1.38.0"}
		if sc != nil {
			o["securityContext"] = sc
		}
		return o
	}
	spec := map[string]any{}
	switch c.class {
	case "regular":
		spec["containers"] = []any{ctr("subject", c.subjectSC)}
	case "init":
		spec["containers"] = []any{ctr("app", p.otherSC())}
		spec["initContainers"] = []any{ctr("subject", c.subjectSC)}
	case "ephemeral":
		spec["containers"] = []any{ctr("app", p.otherSC())}
		spec["ephemeralContainers"] = []any{ctr("subject", c.subjectSC)}
	}
	if c.extraSC != nil {
		spec["containers"] = append(spec["containers"].([]any), ctr("extra", c.extraSC))
	}
	if c.podSC != nil {
		spec["securityContext"] = c.podSC
	}
	if c.windows {
		spec["os"] = map[string]any{"name": "windows"}
	}
	for _, f := range forms {
		if f.kind == c.form {
			return map[string]any{"apiVersion": f.apiVersion, "kind": f.kind,
				"metadata": map[string]any{"name": c.name, "namespace": "default"}, "spec": f.wrap(spec)}
		}
	}
	panic("unknown form " + c.form)
}

func (p splitPair) generate() (resources, test []byte) {
	header := []byte(fmt.Sprintf("# Generated by internal/hardening (go test ./internal/hardening -run TestSplitMatrices -update). Do not edit.\n# %s split into %s and %s: expected results come from the Go models in split_test.go.\n", p.original, p.checks[0], p.checks[1]))
	var docs [][]byte
	type key struct{ kind, policy, result string }
	grouped := map[key][]string{}
	var keys []key
	add := func(kind, policy string, pass bool, name string) {
		k := key{kind, policy, map[bool]string{true: "pass", false: "fail"}[pass]}
		if _, ok := grouped[k]; !ok {
			keys = append(keys, k)
		}
		grouped[k] = append(grouped[k], name)
	}
	for _, c := range p.cases {
		b, _ := yaml.Marshal(p.object(c))
		docs = append(docs, b)
		add(c.form, p.original, c.original, c.name)
		add(c.form, p.checks[0], c.first, c.name)
		add(c.form, p.checks[1], c.second, c.name)
	}
	var results []any
	for _, k := range keys {
		results = append(results, map[string]any{"isValidatingPolicy": true, "kind": k.kind, "policy": k.policy, "result": k.result, "resources": grouped[k]})
	}
	var policies []any
	for _, c := range []string{p.original, p.checks[0], p.checks[1]} {
		policies = append(policies, "../../../../content/linux-hardening/variants/"+c+".yaml")
	}
	t, _ := yaml.Marshal(map[string]any{"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Test", "metadata": map[string]any{"name": "linux-hardening-split-" + p.dir},
		"policies": policies, "resources": []any{"resources.yaml"}, "results": results})
	return append(header, bytes.Join(docs, []byte("---\n"))...), append(header, t...)
}

// formLabel keeps generated names within the 63-character DNS label limit.
func formLabel(form string) string {
	if form == "ReplicationController" {
		return "rc"
	}
	return form
}

func toAny(v []string) []any {
	out := []any{}
	for _, s := range v {
		out = append(out, s)
	}
	return out
}

// Capabilities: validation 0 requires the exact string ALL in drop;
// validation 1 allows only the exact string NET_BIND_SERVICE in add.
func capDropModel(drop []string) bool { return slices.Contains(drop, "ALL") }
func capAddModel(add []string) bool {
	return !slices.ContainsFunc(add, func(c string) bool { return c != "NET_BIND_SERVICE" })
}

func capsSC(drop, add []string) map[string]any {
	caps := map[string]any{}
	if drop != nil {
		caps["drop"] = toAny(drop)
	}
	if add != nil {
		caps["add"] = toAny(add)
	}
	return map[string]any{"capabilities": caps}
}

func capabilitiesSplit() splitPair {
	p := splitPair{dir: "capabilities", original: "disallow-capabilities-strict", checks: splitChecks["disallow-capabilities-strict"],
		otherSC: func() map[string]any { return capsSC([]string{"ALL"}, nil) }}
	type val struct {
		label string
		v     []string
	}
	drops := []val{{"all", []string{"ALL"}}, {"lower", []string{"all"}}, {"netraw", []string{"NET_RAW"}}, {"all-and-netraw", []string{"NET_RAW", "ALL"}}, {"empty", []string{}}, {"none", nil}}
	adds := []val{{"none", nil}, {"empty", []string{}}, {"nbs", []string{"NET_BIND_SERVICE"}}, {"nbs-lower", []string{"net_bind_service"}}, {"sysadmin", []string{"SYS_ADMIN"}}, {"nbs-sysadmin", []string{"NET_BIND_SERVICE", "SYS_ADMIN"}}}
	reduced := map[string]bool{"all/none": true, "none/none": true, "all/sysadmin": true, "none/sysadmin": true}
	for _, class := range classes {
		for _, form := range splitFormsFor(class) {
			full := slices.Contains(fullForms, form)
			for _, d := range drops {
				for _, a := range adds {
					if !full && !reduced[d.label+"/"+a.label] {
						continue
					}
					p.cases = append(p.cases, splitCase{name: name("cap", formLabel(form), class, "drop", d.label, "add", a.label), form: form, class: class,
						subjectSC: capsSC(d.v, a.v), first: capDropModel(d.v), second: capAddModel(a.v), original: capabilitiesModel(d.v, a.v)})
				}
			}
			p.cases = append(p.cases, splitCase{name: name("cap", formLabel(form), class, "nocontext"), form: form, class: class, first: false, second: true, original: false})
			// Each check fails on a different container: both fail, and
			// neither failure hides the other.
			p.cases = append(p.cases, splitCase{name: name("cap", formLabel(form), class, "split-containers"), form: form, class: class,
				subjectSC: capsSC(nil, nil), extraSC: capsSC([]string{"ALL"}, []string{"SYS_ADMIN"}),
				first: false, second: false, original: capabilitiesModel(nil, nil) && capabilitiesModel([]string{"ALL"}, []string{"SYS_ADMIN"})})
			// Explicit Windows short-circuits both checks.
			p.cases = append(p.cases, splitCase{name: name("cap", formLabel(form), class, "windows-both"), form: form, class: class, windows: true,
				subjectSC: capsSC(nil, []string{"SYS_ADMIN"}), first: true, second: true, original: true})
		}
	}
	return p
}

// Seccomp: validation 0 requires a set Pod-level type to be allowed;
// validation 1 requires each container's own allowed type or, when it sets
// none, an allowed Pod-level type.
func secPodModel(pod string) bool { return pod == "" || seccompAllowed(pod) }
func secCtrModel(pod, ctr string) bool {
	return seccompAllowed(map[bool]string{true: ctr, false: pod}[ctr != ""])
}

func seccompSplit() splitPair {
	p := splitPair{dir: "seccomp", original: "restrict-seccomp-strict", checks: splitChecks["restrict-seccomp-strict"],
		otherSC: func() map[string]any { return map[string]any{"seccompProfile": seccompProfile("RuntimeDefault")} }}
	label := func(t string) string {
		if t == "" {
			return "unset"
		}
		return t
	}
	reduced := map[string]bool{"RuntimeDefault/": true, "Unconfined/RuntimeDefault": true, "/": true, "Unconfined/": true, "Localhost/Unconfined": true}
	for _, class := range classes {
		for _, form := range splitFormsFor(class) {
			full := slices.Contains(fullForms, form)
			for _, pod := range seccompTypes {
				for _, ctr := range seccompTypes {
					if !full && !reduced[pod+"/"+ctr] {
						continue
					}
					c := splitCase{name: name("sec", formLabel(form), class, "pod", label(pod), "ctr", label(ctr)), form: form, class: class,
						first: secPodModel(pod), second: secCtrModel(pod, ctr), original: seccompModel(pod, ctr)}
					if pod != "" {
						c.podSC = map[string]any{"seccompProfile": seccompProfile(pod)}
					}
					if ctr != "" {
						c.subjectSC = map[string]any{"seccompProfile": seccompProfile(ctr)}
					}
					p.cases = append(p.cases, c)
				}
			}
			p.cases = append(p.cases, splitCase{name: name("sec", formLabel(form), class, "windows-both"), form: form, class: class, windows: true,
				podSC: map[string]any{"seccompProfile": seccompProfile("Unconfined")}, first: true, second: true, original: true})
		}
	}
	return p
}

func TestSplitMatrices(t *testing.T) {
	for _, p := range []splitPair{capabilitiesSplit(), seccompSplit()} {
		t.Run(p.dir, func(t *testing.T) {
			resources, test := p.generate()
			dir := filepath.Join(root, "testdata/linux-hardening/split", p.dir)
			for file, want := range map[string][]byte{"resources.yaml": resources, "kyverno-test.yaml": test} {
				path := filepath.Join(dir, file)
				if *update {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, want, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
					t.Errorf("%s is stale; run go test ./internal/hardening -run TestSplitMatrices -update", path)
				}
			}
			// The original's independent model is the conjunction of the
			// split models on every case, so the CLI suite, which requires
			// all three policies to match, checks engine equivalence.
			seen := map[string]bool{}
			combos := map[string]map[[2]bool]bool{}
			for _, c := range p.cases {
				if c.original != (c.first && c.second) {
					t.Errorf("%s: original %v, split %v && %v", c.name, c.original, c.first, c.second)
				}
				if seen[c.name] || len(c.name) > 63 || strings.ContainsAny(c.name, "_ ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
					t.Errorf("bad or duplicate name %q", c.name)
				}
				seen[c.name] = true
				if c.windows {
					if !c.first || !c.second {
						t.Errorf("%s: a Windows workload fails a Linux check", c.name)
					}
					continue
				}
				k := c.form + "/" + c.class
				if combos[k] == nil {
					combos[k] = map[[2]bool]bool{}
				}
				combos[k][[2]bool{c.first, c.second}] = true
			}
			// Every outcome combination occurs on every form and container
			// class, including init containers, ephemeral containers and
			// each pod-template controller.
			want := 0
			for _, class := range classes {
				want += len(splitFormsFor(class))
			}
			if len(combos) != want || want != 2*len(forms)+1 {
				t.Errorf("%d form/class combinations, want %d", len(combos), want)
			}
			for k, c := range combos {
				for _, w := range [][2]bool{{true, true}, {false, true}, {true, false}, {false, false}} {
					if !c[w] {
						t.Errorf("%s: no case with %s=%v, %s=%v", k, p.checks[0], w[0], p.checks[1], w[1])
					}
				}
			}
		})
	}
}

// The split models encode the spec's sibling cases.
func TestSplitModelsMatchTheSpec(t *testing.T) {
	// Missing drop ALL fails only the drop check; a disallowed addition only
	// the additions check; case matters for both.
	if capDropModel(nil) || !capAddModel(nil) || !capDropModel([]string{"ALL"}) || capAddModel([]string{"SYS_ADMIN"}) || capDropModel([]string{"all"}) || capAddModel([]string{"net_bind_service"}) {
		t.Error("capabilities split models")
	}
	// An invalid Pod type fails the Pod check even when every container
	// overrides it; an unset Pod type passes the Pod check but leaves
	// containers without a profile failing.
	if secPodModel("Unconfined") || !secCtrModel("Unconfined", "RuntimeDefault") || !secPodModel("") || secCtrModel("", "") || !secCtrModel("Localhost", "") || secCtrModel("RuntimeDefault", "Unconfined") {
		t.Error("seccomp split models")
	}
}
