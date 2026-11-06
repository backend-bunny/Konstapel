package assessment

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The design's mapping table (add-linux-workload-hardening-bundle §4).
var wantHardening = map[string][]string{
	"disallow-privilege-escalation": {"ac-6_smt", "cm-6_smt.b"},
	"disallow-capabilities-strict":  {"ac-6_smt", "cm-6_smt.b", "cm-7_smt.b"},
	"require-run-as-nonroot":        {"ac-6_smt", "cm-6_smt.b"},
	"restrict-seccomp-strict":       {"cm-6_smt.b", "cm-7_smt.b"},
}

func TestShippedMappingsMatchTheDesign(t *testing.T) {
	ms, err := Mappings(repo(t))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for rule, list := range ms {
		for _, m := range list {
			got[rule] = append(got[rule], m.StatementID)
			if !strings.Contains(m.Rationale, "Partial") || !strings.Contains(m.Rationale, "full") || !strings.Contains(m.Rationale, "Moderate") {
				t.Errorf("%s: rationale does not state its partial-coverage limit: %q", rule, m.Rationale)
			}
		}
	}
	want := map[string][]string{PolicyName: {"ac-6_smt"}}
	for k, v := range wantHardening {
		want[k] = v
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mappings = %v\nwant %v", got, want)
	}
	// Each rule comes from exactly one definition: the hardening bundle
	// composes the privileged check by reference instead of copying it.
	for _, m := range ms[PolicyName] {
		if m.Definition != "content/component-definition.json" {
			t.Errorf("privileged check mapped in %s", m.Definition)
		}
	}
	for rule := range wantHardening {
		for _, m := range ms[rule] {
			if m.Definition != "content/linux-hardening/component-definition.json" {
				t.Errorf("%s mapped in %s", rule, m.Definition)
			}
		}
	}
}

// mappingRoot is a scratch repository whose shipped content links to the
// real content except for the edited hardening component definition.
func mappingRoot(t *testing.T, edit func(string) string) string {
	t.Helper()
	root := repo(t)
	temp := t.TempDir()
	for _, dir := range []string{"upstream", "schemas"} {
		if err := os.MkdirAll(filepath.Join(temp, "content"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "content", dir), filepath.Join(temp, "content", dir)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"content/component-definition.json", "content/linux-hardening/component-definition.json"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if strings.HasPrefix(f, "content/linux-hardening") {
			s = edit(s)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(temp, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(temp, f), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "content/linux-hardening/variants"), filepath.Join(temp, "content/linux-hardening/variants")); err != nil {
		t.Fatal(err)
	}
	return temp
}

func TestInvalidMappingsAreRejected(t *testing.T) {
	if _, err := Mappings(mappingRoot(t, func(s string) string { return s })); err != nil {
		t.Fatalf("unchanged copy rejected: %v", err)
	}
	cases := map[string]struct{ from, to, want string }{
		"unknown statement":          {`"statement-id": "cm-7_smt.b"`, `"statement-id": "cm-7_smt.z"`, "invalid statement"},
		"statement of other control": {`"statement-id": "cm-7_smt.b"`, `"statement-id": "cm-6_smt.b"`, "invalid statement"},
		"unknown control":            {`"control-id": "cm-7"`, `"control-id": "cm-999"`, "unsupported control"},
		"control outside Moderate":   {`"control-id": "cm-7"`, `"control-id": "cm-7.6"`, "not in the Moderate baseline"},
		"undeclared rule":            {"\"value\": \"restrict-seccomp-strict\"\n                      }", "\"value\": \"restrict-seccomp-strictx\"\n                      }", "undeclared rule"},
		"no provider check": {`"name": "Check_Id",
            "ns": "https://oscal-compass.github.io/compliance-trestle/schemas/oscal/cd/kyverno",
            "value": "restrict-seccomp-strict"`, `"name": "Check_Description_X",
            "ns": "https://oscal-compass.github.io/compliance-trestle/schemas/oscal/cd/kyverno",
            "value": "restrict-seccomp-strict"`, "no Check_Id"},
		"wrong catalog source":  {`"source": "../upstream/nist`, `"source": "../../upstream/nist`, "catalog source unresolved"},
		"not a vendored policy": {`"restrict-seccomp-strict"`, `"restrict-seccomp-unknown"`, "not a vendored policy"},
		"duplicate check":       {`"value": "require-run-as-nonroot"`, `"value": "disallow-privileged-containers"`, "mapped by both"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := mappingRoot(t, func(s string) string {
				if !strings.Contains(s, c.from) {
					t.Fatalf("fixture text %q not found", c.from)
				}
				return strings.ReplaceAll(s, c.from, c.to)
			})
			_, err := Mappings(root)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}
