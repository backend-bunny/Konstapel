package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const hardeningDef = "bundles/konstapel-linux-hardening/definition.json"

// The accepted inputs of add-linux-workload-hardening-bundle (design
// decisions 1, 3 and 4) plus the privileged check the first loop owns. They
// are written out here on purpose: a policy dropped from or added to the
// definition must fail against this list, not against the definition itself.
var (
	hardeningChecks = []string{
		"disallow-capabilities-strict",
		"disallow-privilege-escalation",
		"disallow-privileged-containers",
		"require-run-as-nonroot",
		"restrict-seccomp-strict",
	}
	// Local variants shipped for the four new checks; the privileged check
	// ships its vendored upstream policy by reference, not a variant.
	hardeningVariants = []string{
		"disallow-capabilities-strict",
		"disallow-privilege-escalation",
		"require-run-as-nonroot",
		"restrict-seccomp-strict",
	}
	// Bounded Moderate mappings: control -> statement -> rules.
	hardeningMappings = map[string]map[string][]string{
		"ac-6": {"ac-6_smt": {"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot"}},
		"cm-6": {"cm-6_smt.b": {"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot", "restrict-seccomp-strict"}},
		"cm-7": {"cm-7_smt.b": {"disallow-capabilities-strict", "restrict-seccomp-strict"}},
	}
)

var (
	hardeningOnce  sync.Once
	hardeningArch  *Archive
	hardeningFiles fstest.MapFS
)

func hardeningDefinition(t *testing.T) Definition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", hardeningDef))
	if err != nil {
		t.Fatal(err)
	}
	def, err := LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = strings.Repeat("c", 40)
	return def
}

func buildHardeningFrom(t *testing.T, def Definition) (*Archive, fstest.MapFS, error) {
	t.Helper()
	a, err := Build(def, os.DirFS("../.."), time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		return nil, nil, err
	}
	_, files, err := Unpack(a.Layer)
	return a, files, err
}

func buildHardening(t *testing.T) (*Archive, fstest.MapFS) {
	t.Helper()
	hardeningOnce.Do(func() {
		a, f, err := buildHardeningFrom(t, hardeningDefinition(t))
		if err != nil {
			t.Fatal(err)
		}
		hardeningArch, hardeningFiles = a, f
	})
	return hardeningArch, hardeningFiles
}

// mappingsOf reads control -> statement -> sorted rules from an authored
// component definition in the payload.
func mappingsOf(t *testing.T, data []byte) map[string]map[string][]string {
	t.Helper()
	var cd struct {
		CD struct {
			Components []struct {
				CI []struct {
					IR []struct {
						ControlID  string `json:"control-id"`
						Statements []struct {
							ID    string                         `json:"statement-id"`
							Props []struct{ Name, Value string } `json:"props"`
						} `json:"statements"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(data, &cd); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]string{}
	for _, c := range cd.CD.Components {
		for _, ci := range c.CI {
			for _, ir := range ci.IR {
				for _, st := range ir.Statements {
					for _, p := range st.Props {
						if p.Name != "Rule_Id" {
							continue
						}
						if out[ir.ControlID] == nil {
							out[ir.ControlID] = map[string][]string{}
						}
						out[ir.ControlID][st.ID] = append(out[ir.ControlID][st.ID], p.Value)
					}
				}
			}
		}
	}
	for _, m := range out {
		for _, r := range m {
			sort.Strings(r)
		}
	}
	return out
}

func TestHardeningBundleIsReproducible(t *testing.T) {
	a, _ := buildHardening(t)
	b, _, err := buildHardeningFrom(t, hardeningDefinition(t))
	if err != nil {
		t.Fatal(err)
	}
	if a.LayerDigest != b.LayerDigest || a.ManifestDigest != b.ManifestDigest {
		t.Fatal("the hardening bundle is not reproducible")
	}
	if a.Descriptor.Name != "konstapel-linux-hardening" || a.Descriptor.Version != "0.1.0" {
		t.Fatalf("identity %s@%s", a.Descriptor.Name, a.Descriptor.Version)
	}
}

// The packaged payload is accepted by the same content validation the
// controller and release verification run, and by payload verification.
func TestHardeningBundleRoundTrip(t *testing.T) {
	a, files := buildHardening(t)
	d, payload, err := Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyPayload(payload); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContent(d, files); err != nil {
		t.Fatal(err)
	}
}

// Every shipped policy, rule and check ID matches the accepted inputs exactly;
// a dropped or extra policy fails here.
func TestHardeningBundleInventory(t *testing.T) {
	a, files := buildHardening(t)
	var got []string
	for _, p := range a.Descriptor.Policies {
		got = append(got, p.Name)
		if len(p.Checks) != 1 || p.Checks[0].RuleID != p.Name || p.Checks[0].CheckID != p.Name {
			t.Errorf("policy %s: checks %+v, want one check with rule and check ID equal to the name", p.Name, p.Checks)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(hardeningChecks, ",") {
		t.Fatalf("shipped policies %v, accepted inputs %v", got, hardeningChecks)
	}
	// Policy-role files are exactly the five policies: no unlisted policy
	// can ride along in the payload.
	var policyFiles []string
	for _, f := range a.Descriptor.Files {
		if f.Role == RolePolicy {
			policyFiles = append(policyFiles, f.Path)
		}
	}
	var want []string
	for _, p := range a.Descriptor.Policies {
		want = append(want, p.Path)
	}
	sort.Strings(policyFiles)
	sort.Strings(want)
	if strings.Join(policyFiles, ",") != strings.Join(want, ",") {
		t.Fatalf("policy files %v, listed policies %v", policyFiles, want)
	}

	// Policy sources: owned variants for the four new checks, the first
	// loop's vendored policy for the privileged check; byte-identical to the
	// owned sources, so nothing is copied or edited here.
	for _, p := range a.Descriptor.Policies {
		src := "content/upstream/kyverno/" + p.Name + "/" + p.Name + ".yaml"
		for _, v := range hardeningVariants {
			if v == p.Name {
				src = "content/linux-hardening/variants/" + p.Name + ".yaml"
			}
		}
		if p.Path != src {
			t.Errorf("policy %s ships %s, want %s", p.Name, p.Path, src)
		}
		owned, err := os.ReadFile(filepath.Join("../..", src))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(owned, files[p.Path].Data) {
			t.Errorf("%s differs from its owned source", p.Path)
		}
	}

	// The variant manifest the hardening change owns agrees with the
	// shipped variants and their recorded digests, and the unmodified
	// upstream originals ship as provenance.
	var vm struct {
		Variants []struct{ Check, File, SHA256, Source, SourceSha256 string } `json:"variants"`
	}
	if err := json.Unmarshal(files["content/linux-hardening/variants.json"].Data, &vm); err != nil {
		t.Fatal(err)
	}
	if len(vm.Variants) != len(hardeningVariants) {
		t.Fatalf("variants.json lists %d variants, want %d", len(vm.Variants), len(hardeningVariants))
	}
	for _, v := range vm.Variants {
		if !contains(hardeningVariants, v.Check) {
			t.Errorf("unexpected variant %s", v.Check)
		}
		if f := files[v.File]; f == nil || sha(f.Data) != v.SHA256 {
			t.Errorf("variant %s: packaged bytes do not match the recorded digest", v.Check)
		}
		if f := files[v.Source]; f == nil || sha(f.Data) != v.SourceSha256 {
			t.Errorf("variant %s: upstream original missing or changed", v.Check)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sha(b []byte) string { return strings.TrimPrefix(digestOf(b), "sha256:") }

// Scope: Linux only (the exact [linux] rule); Windows is never listed.
func TestHardeningBundleScope(t *testing.T) {
	a, _ := buildHardening(t)
	if got := a.Descriptor.Scope.OS; len(got) != 1 || got[0] != "linux" {
		t.Fatalf("scope.os %v, want exactly [linux]", got)
	}
	want := []string{"CronJob", "DaemonSet", "Deployment", "Job", "Pod", "ReplicaSet", "ReplicationController", "StatefulSet"}
	got := append([]string(nil), a.Descriptor.Scope.Workloads...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("workloads %v, want %v", got, want)
	}
	if a.Descriptor.Compatibility.Provider != "konstapel-kyverno/v1" {
		t.Fatalf("compatibility %+v", a.Descriptor.Compatibility)
	}
}

// Windows exclusion and missing-OS handling travel in the shipped variants:
// each of the four guards on spec.os.name, and non-root no longer bypasses
// through hostUsers.
func TestHardeningBundleOSConvention(t *testing.T) {
	_, files := buildHardening(t)
	for _, v := range hardeningVariants {
		body := string(files["content/linux-hardening/variants/"+v+".yaml"].Data)
		if !strings.Contains(body, "isWindowsPod") || !strings.Contains(body, "windows") {
			t.Errorf("variant %s has no explicit Windows exclusion", v)
		}
	}
	nr := string(files["content/linux-hardening/variants/require-run-as-nonroot.yaml"].Data)
	if strings.Contains(nr, "userNamespacePod") {
		t.Error("require-run-as-nonroot still carries the hostUsers bypass")
	}
}

// Bounded mappings: exactly the design's table, plus the first loop's AC-6
// mapping of the privileged check; nothing broader is shipped.
func TestHardeningBundleMappings(t *testing.T) {
	_, files := buildHardening(t)
	got := mappingsOf(t, files["content/linux-hardening/component-definition.json"].Data)
	if fmt.Sprint(got) != fmt.Sprint(hardeningMappings) {
		t.Fatalf("hardening mappings\n got  %v\n want %v", got, hardeningMappings)
	}
	priv := mappingsOf(t, files["content/component-definition.json"].Data)
	if fmt.Sprint(priv) != fmt.Sprint(map[string]map[string][]string{"ac-6": {"ac-6_smt": {"disallow-privileged-containers"}}}) {
		t.Fatalf("privileged mapping %v", priv)
	}
	for _, p := range []string{
		"content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
	} {
		for c := range hardeningMappings {
			if !bytes.Contains(files[p].Data, []byte(`"`+c+`"`)) {
				t.Errorf("Moderate profile does not include %s", c)
			}
		}
	}
}

// Shipped tests: the retained upstream CLI suites of all five checks and the
// local variant suites, at the paths their relative policy references need.
func TestHardeningBundleTests(t *testing.T) {
	a, files := buildHardening(t)
	suites := map[string]bool{}
	for _, f := range a.Descriptor.Files {
		if f.Role == RoleTest && strings.HasSuffix(f.Path, "/kyverno-test.yaml") && !strings.Contains(f.Path, "chainsaw") {
			suites[filepath.Dir(f.Path)] = true
		}
	}
	for _, c := range hardeningChecks {
		found := false
		for s := range suites {
			if strings.HasPrefix(s, "content/upstream/kyverno/"+c+"/") {
				found = true
			}
		}
		if !found {
			t.Errorf("no upstream CLI suite shipped for %s", c)
		}
	}
	for _, s := range []string{"capabilities", "escalation", "forms", "nonroot/upstream", "nonroot/variant", "seccomp"} {
		if !suites["tests/linux-hardening/"+s] {
			t.Errorf("local variant suite %s not shipped", s)
		}
	}
	// Every policy a shipped suite references is itself in the payload.
	for s := range suites {
		raw := files[s+"/kyverno-test.yaml"].Data
		for _, line := range strings.Split(string(raw), "\n") {
			l := strings.Trim(strings.TrimSpace(line), `-",: `)
			if strings.Contains(l, "content/") && strings.HasSuffix(l, ".yaml") || strings.HasPrefix(l, "../") && strings.HasSuffix(l, ".yaml") {
				target := filepath.ToSlash(filepath.Join(s, l))
				if _, ok := files[target]; !ok {
					t.Errorf("%s references %s, which is not in the payload", s, target)
				}
			}
		}
	}
}

// Licenses and notices of every vendored source ride along.
func TestHardeningBundleLicenses(t *testing.T) {
	a, _ := buildHardening(t)
	have := map[string]bool{}
	for _, f := range a.Descriptor.Files {
		if f.Role == RoleLicense {
			have[f.Path] = true
		}
	}
	for _, p := range []string{"LICENSE", "NOTICE", "content/upstream/kyverno/LICENSE", "content/upstream/nist/LICENSE.md", "licenses/kyverno-LICENSE", "licenses/nist-LICENSE.md"} {
		if !have[p] {
			t.Errorf("license file %s missing", p)
		}
	}
}

// Hand-breaks: every accidental change to the definition fails a build,
// validation or the accepted-input assertions.
func TestHardeningBundleHandBreaks(t *testing.T) {
	policyIdx := func(d *Definition, n string) int {
		for i, p := range d.Policies {
			if p.Name == n {
				return i
			}
		}
		t.Fatalf("no policy %s", n)
		return -1
	}
	cases := map[string]func(d *Definition){
		"dropped policy": func(d *Definition) {
			i := policyIdx(d, "restrict-seccomp-strict")
			d.Policies = append(d.Policies[:i], d.Policies[i+1:]...)
		},
		"windows scope": func(d *Definition) { d.Scope.OS = append(d.Scope.OS, "windows") },
		"rule typo": func(d *Definition) {
			d.Policies[policyIdx(d, "require-run-as-nonroot")].Checks[0].CheckID = "require-run-as-nonrot"
		},
		"upstream original in place of the variant": func(d *Definition) {
			d.Policies[policyIdx(d, "require-run-as-nonroot")].Path = "content/upstream/kyverno/require-run-as-nonroot/require-run-as-nonroot.yaml"
		},
		"unlisted policy": func(d *Definition) {
			d.Policies = append(d.Policies, Policy{Name: "extra", Path: "content/upstream/kyverno/restrict-seccomp-strict/restrict-seccomp-strict.yaml", Checks: []Check{{RuleID: "extra", CheckID: "extra"}}})
		},
		"missing mapping": func(d *Definition) {
			var keep []OSCALDocument
			for _, o := range d.OSCAL {
				if o.Path != "content/linux-hardening/component-definition.json" {
					keep = append(keep, o)
				}
			}
			d.OSCAL = keep
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			def := hardeningDefinition(t)
			mutate(&def)
			a, files, err := buildHardeningFrom(t, def)
			if err == nil {
				err = ValidateContent(a.Descriptor, files)
			}
			if err == nil {
				err = assertHardeningInputs(a)
			}
			if err == nil {
				t.Fatal("the broken definition was accepted")
			}
		})
	}
}

// assertHardeningInputs is the inventory comparison as a plain error, for the
// hand-break cases that content validation alone does not reject.
func assertHardeningInputs(a *Archive) error {
	var got []string
	for _, p := range a.Descriptor.Policies {
		src := "content/upstream/kyverno/" + p.Name + "/" + p.Name + ".yaml"
		if contains(hardeningVariants, p.Name) {
			src = "content/linux-hardening/variants/" + p.Name + ".yaml"
		}
		if p.Path != src {
			return fmt.Errorf("policy %s ships %s, want %s", p.Name, p.Path, src)
		}
		got = append(got, p.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(hardeningChecks, ",") {
		return fmt.Errorf("policies %v", got)
	}
	if len(a.Descriptor.Scope.OS) != 1 || a.Descriptor.Scope.OS[0] != "linux" {
		return fmt.Errorf("scope %v", a.Descriptor.Scope.OS)
	}
	return nil
}

// The pinned Kyverno CLI passes every shipped suite against the unpacked
// release payload, not the working tree.
func TestHardeningBundleKyvernoFixtures(t *testing.T) {
	kyverno, err := exec.LookPath("kyverno")
	if err != nil {
		t.Skip("kyverno CLI not on PATH; run through devbox (task test)")
	}
	_, files := buildHardening(t)
	dir := t.TempDir()
	for p, f := range files {
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"content/upstream/kyverno", "tests/linux-hardening"} {
		out, err := exec.Command(kyverno, "test", filepath.Join(dir, d), "--require-tests", "--remove-color").CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("0 tests failed")) {
			t.Fatalf("kyverno test %s on the unpacked payload failed: %v\n%s", d, err, out)
		}
	}
}
