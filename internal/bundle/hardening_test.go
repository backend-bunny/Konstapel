package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

	"sigs.k8s.io/yaml"
)

const (
	// hardeningDef is the next version of the hardening bundle: the
	// single-validation split revision (split-hardening-policy-validations).
	hardeningDef = "bundles/konstapel-linux-hardening/definition.json"
	// hardeningReleasedDef is the released 0.1.0 definition, kept
	// byte-identical to the bundle/konstapel-linux-hardening/v0.1.0 tag.
	hardeningReleasedDef = "bundles/konstapel-linux-hardening/released/0.1.0.json"
	// hardeningReleasedContent is the content digest of the published 0.1.0
	// release (docs/policy-bundles.md). The content digest covers only the
	// file inventory, so rebuilding the retained definition from this tree
	// must reproduce it: the old pinned content is still fully present.
	hardeningReleasedContent = "sha256:fa46e726523e4625a065519da71c6211876cdb860044d4841514aa76657d2542"
	// vendoredDigest is the vendored bundle's identity, the sha256 of
	// content/SHA256SUMS. Owner decision 2026-11-27: the split ships only in
	// the OCI bundle, and the vendored content stays byte-unchanged.
	vendoredDigest = "sha256:39dcd9f643a36ab2302f1959c8fa5089e91c11977f427359aa315606354bba71"
	splitSums      = "content/linux-hardening/split/SHA256SUMS"
)

// A hardening edition is one version of the hardening bundle and its
// accepted inputs. They are written out here on purpose: a policy dropped
// from or added to a definition must fail against these lists, not against
// the definition itself.
type hardeningEdition struct {
	name, def, version string
	// checks are the shipped policies, sorted; each has one rule and check
	// ID equal to its name.
	checks []string
	// variants are the checks shipped from content/linux-hardening/variants/;
	// every other check ships its vendored upstream policy.
	variants []string
	// cd is the hardening component definition and mappings its bounded
	// Moderate mappings: control -> statement -> rules.
	cd       string
	mappings map[string]map[string][]string
	// inventories are the variant manifests that record the shipped variants.
	inventories []string
	// suites are the local suites shipped under tests/linux-hardening/.
	suites []string
}

var (
	// The accepted inputs of add-linux-workload-hardening-bundle (design
	// decisions 1, 3 and 4) plus the privileged check the first loop owns.
	hardening010 = hardeningEdition{
		name: "0.1.0", def: hardeningReleasedDef, version: "0.1.0",
		checks: []string{
			"disallow-capabilities-strict",
			"disallow-privilege-escalation",
			"disallow-privileged-containers",
			"require-run-as-nonroot",
			"restrict-seccomp-strict",
		},
		variants: []string{
			"disallow-capabilities-strict",
			"disallow-privilege-escalation",
			"require-run-as-nonroot",
			"restrict-seccomp-strict",
		},
		cd: "content/linux-hardening/component-definition.json",
		mappings: map[string]map[string][]string{
			"ac-6": {"ac-6_smt": {"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot"}},
			"cm-6": {"cm-6_smt.b": {"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot", "restrict-seccomp-strict"}},
			"cm-7": {"cm-7_smt.b": {"disallow-capabilities-strict", "restrict-seccomp-strict"}},
		},
		inventories: []string{"content/linux-hardening/variants.json"},
		suites:      []string{"capabilities", "escalation", "forms", "nonroot/upstream", "nonroot/variant", "seccomp"},
	}
	// The split revision (split-hardening-policy-validations design
	// decision 1): each two-validation check becomes two single-validation
	// policies, keeping every original check's statements.
	hardening020 = hardeningEdition{
		name: "0.2.0", def: hardeningDef, version: "0.2.0",
		checks: []string{
			"disallow-privilege-escalation",
			"disallow-privileged-containers",
			"require-container-seccomp-profile",
			"require-drop-all-capabilities",
			"require-run-as-nonroot",
			"restrict-added-capabilities",
			"restrict-pod-seccomp-profile",
		},
		variants: []string{
			"disallow-privilege-escalation",
			"require-container-seccomp-profile",
			"require-drop-all-capabilities",
			"require-run-as-nonroot",
			"restrict-added-capabilities",
			"restrict-pod-seccomp-profile",
		},
		cd: "content/linux-hardening/split/component-definition.json",
		mappings: map[string]map[string][]string{
			"ac-6": {"ac-6_smt": {"disallow-privilege-escalation", "require-drop-all-capabilities", "require-run-as-nonroot", "restrict-added-capabilities"}},
			"cm-6": {"cm-6_smt.b": {"disallow-privilege-escalation", "require-container-seccomp-profile", "require-drop-all-capabilities", "require-run-as-nonroot", "restrict-added-capabilities", "restrict-pod-seccomp-profile"}},
			"cm-7": {"cm-7_smt.b": {"require-container-seccomp-profile", "require-drop-all-capabilities", "restrict-added-capabilities", "restrict-pod-seccomp-profile"}},
		},
		inventories: []string{"content/linux-hardening/variants.json", "content/linux-hardening/split/variants.json"},
		suites:      []string{"capabilities", "escalation", "forms", "nonroot/upstream", "nonroot/variant", "seccomp", "split/capabilities", "split/seccomp"},
	}
	hardeningEditions = []hardeningEdition{hardening010, hardening020}
	// upstreamChecks have retained upstream CLI suites in both editions.
	upstreamChecks = []string{"disallow-capabilities-strict", "disallow-privilege-escalation", "disallow-privileged-containers", "require-run-as-nonroot", "restrict-seccomp-strict"}
	// supersededVariants are the 0.1.0 combined variants. 0.2.0 ships them
	// only as derivation sources of the split (role upstream), never as policy.
	supersededVariants = []string{"content/linux-hardening/variants/disallow-capabilities-strict.yaml", "content/linux-hardening/variants/restrict-seccomp-strict.yaml"}
)

type hardeningBuild struct {
	arch  *Archive
	files fstest.MapFS
}

var (
	hardeningMu    sync.Mutex
	hardeningBuilt = map[string]hardeningBuild{}
)

func forEachEdition(t *testing.T, f func(t *testing.T, e hardeningEdition)) {
	for _, e := range hardeningEditions {
		t.Run(e.name, func(t *testing.T) { f(t, e) })
	}
}

func hardeningDefinition(t *testing.T, e hardeningEdition) Definition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", e.def))
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

func buildHardening(t *testing.T, e hardeningEdition) (*Archive, fstest.MapFS) {
	t.Helper()
	hardeningMu.Lock()
	defer hardeningMu.Unlock()
	if b, ok := hardeningBuilt[e.name]; ok {
		return b.arch, b.files
	}
	a, f, err := buildHardeningFrom(t, hardeningDefinition(t, e))
	if err != nil {
		t.Fatal(err)
	}
	hardeningBuilt[e.name] = hardeningBuild{a, f}
	return a, f
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
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, _ := buildHardening(t, e)
		b, _, err := buildHardeningFrom(t, hardeningDefinition(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if a.LayerDigest != b.LayerDigest || a.ManifestDigest != b.ManifestDigest {
			t.Fatal("the hardening bundle is not reproducible")
		}
		if a.Descriptor.Name != "konstapel-linux-hardening" || a.Descriptor.Version != e.version {
			t.Fatalf("identity %s@%s", a.Descriptor.Name, a.Descriptor.Version)
		}
	})
}

// The released 0.1.0 stays readable: its retained definition still builds
// from this tree to the published content digest, and the next version is a
// different revision rather than a rewrite of it.
func TestHardeningReleasedContentIsUnchanged(t *testing.T) {
	old, _ := buildHardening(t, hardening010)
	if got := old.Descriptor.ContentDigest(); got != hardeningReleasedContent {
		t.Fatalf("released 0.1.0 rebuilds to content %s, published %s: a file it pins changed", got, hardeningReleasedContent)
	}
	next, _ := buildHardening(t, hardening020)
	if next.Descriptor.ContentDigest() == hardeningReleasedContent || next.Descriptor.Version == old.Descriptor.Version {
		t.Fatal("the split revision reuses the released version or content")
	}
}

// The vendored bundle is byte-unchanged by the split revision: its digest is
// still the one saved captures and rendered fixtures pin, it lists none of
// the revision's files, and the revision's own checksums cover those.
func TestHardeningRevisionLeavesVendoredContentUnchanged(t *testing.T) {
	raw, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != vendoredDigest {
		t.Fatalf("vendored digest %s, want %s: vendored content must not change for the split revision", got, vendoredDigest)
	}
	vendored, split := sumsOf(t, raw), sumsOf(t, readRepo(t, splitSums))
	for f := range split {
		if _, ok := vendored[f]; ok {
			t.Errorf("%s is listed in content/SHA256SUMS", f)
		}
	}
	// Saved historical fixtures still name the vendored digest they were
	// recorded against, so they keep replaying against this content.
	fixtures := []string{
		"testdata/assessments/kyverno-1.19.2-background/capture.json",
		"testdata/providers/conformance/v1/konstapel-kyverno/windows-not-applicable/capture.json",
		"testdata/targeting/contract/evidence.json",
		"testdata/targeting/rendered/audit-all.yaml",
		"testdata/targeting/rendered/deny-production.yaml",
	}
	rendered, err := filepath.Glob("../../testdata/linux-hardening/rendered/*-*-*.yaml")
	if err != nil || len(rendered) != 8 {
		t.Fatalf("rendered hardening fixtures %v %v", rendered, err)
	}
	for _, r := range rendered {
		fixtures = append(fixtures, strings.TrimPrefix(filepath.ToSlash(r), "../../"))
	}
	hexDigest := strings.TrimPrefix(vendoredDigest, "sha256:")
	for _, f := range fixtures {
		if !bytes.Contains(readRepo(t, f), []byte(hexDigest)) {
			t.Errorf("%s no longer names the vendored digest", f)
		}
	}
	// Every content file the split revision packages verifies against the
	// vendored checksums, the revision's own SHA256SUMS, or (for files
	// neither lists, such as the provenance record) is byte-identical to
	// what the released 0.1.0 ships.
	_, files := buildHardening(t, hardening020)
	_, released := buildHardening(t, hardening010)
	for p, f := range files {
		if !strings.HasPrefix(p, "content/") || p == "content/SHA256SUMS" {
			continue
		}
		want, ok := vendored[p]
		if !ok {
			want, ok = split[p]
		}
		if !ok {
			if r := released[p]; r != nil {
				want, ok = sha(r.Data), true
			}
		}
		if !ok || want != sha(f.Data) {
			t.Errorf("%s: packaged bytes are not the checksummed repository file", p)
		}
	}
	for p := range split {
		if p != splitSums && files[p] == nil && !strings.HasSuffix(p, "SHA256SUMS") {
			t.Errorf("revision file %s is not packaged", p)
		}
	}
}

func readRepo(t *testing.T, p string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", p))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sumsOf(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		h, f, ok := strings.Cut(l, "  ")
		if !ok {
			t.Fatalf("checksum line %q", l)
		}
		out[f] = h
	}
	return out
}

// The packaged payload is accepted by the same content validation the
// controller and release verification run, and by payload verification.
func TestHardeningBundleRoundTrip(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, files := buildHardening(t, e)
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
	})
}

// Every shipped policy, rule and check ID matches the accepted inputs exactly;
// a dropped or extra policy fails here.
func TestHardeningBundleInventory(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, files := buildHardening(t, e)
		var got []string
		for _, p := range a.Descriptor.Policies {
			got = append(got, p.Name)
			if len(p.Checks) != 1 || p.Checks[0].RuleID != p.Name || p.Checks[0].CheckID != p.Name {
				t.Errorf("policy %s: checks %+v, want one check with rule and check ID equal to the name", p.Name, p.Checks)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(e.checks, ",") {
			t.Fatalf("shipped policies %v, accepted inputs %v", got, e.checks)
		}
		// Policy-role files are exactly the listed policies: no unlisted
		// policy can ride along in the payload.
		var policyFiles []string
		roles := map[string]string{}
		for _, f := range a.Descriptor.Files {
			roles[f.Path] = f.Role
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

		// Policy sources: owned variants, and the first loop's vendored
		// policy for the privileged check; byte-identical to the owned
		// sources, so nothing is copied or edited here.
		for _, p := range a.Descriptor.Policies {
			src := hardeningSource(e, p.Name)
			if p.Path != src {
				t.Errorf("policy %s ships %s, want %s", p.Name, p.Path, src)
			}
			if !bytes.Equal(readRepo(t, src), files[p.Path].Data) {
				t.Errorf("%s differs from its owned source", p.Path)
			}
		}

		// The variant manifests agree with the shipped variants and their
		// recorded digests, and every original they derive from (upstream
		// file, or the superseded combined variant) ships as provenance.
		recorded := map[string]bool{}
		for _, inv := range e.inventories {
			if roles[inv] != RoleUpstream {
				t.Errorf("variant manifest %s has role %q", inv, roles[inv])
			}
			var vm struct {
				Variants []struct {
					Check, File, SHA256, Source, SourceSha256 string
					SplitFrom                                 *struct{ File, SHA256 string }
				} `json:"variants"`
			}
			if err := json.Unmarshal(files[inv].Data, &vm); err != nil {
				t.Fatal(err)
			}
			for _, v := range vm.Variants {
				recorded[v.Check] = true
				if f := files[v.File]; f == nil || sha(f.Data) != v.SHA256 {
					t.Errorf("variant %s: packaged bytes do not match the recorded digest", v.Check)
				}
				if f := files[v.Source]; f == nil || sha(f.Data) != v.SourceSha256 || roles[v.Source] != RoleUpstream {
					t.Errorf("variant %s: upstream original missing or changed", v.Check)
				}
				if v.SplitFrom != nil {
					if f := files[v.SplitFrom.File]; f == nil || sha(f.Data) != v.SplitFrom.SHA256 || roles[v.SplitFrom.File] != RoleUpstream {
						t.Errorf("variant %s: superseded original %s missing, changed or not provenance", v.Check, v.SplitFrom.File)
					}
				}
				if !contains(e.variants, v.Check) && roles[v.File] == RolePolicy {
					t.Errorf("variant %s is recorded but not an accepted policy of %s", v.Check, e.version)
				}
			}
		}
		for _, v := range e.variants {
			if !recorded[v] {
				t.Errorf("shipped variant %s is in no variant manifest", v)
			}
		}
		if e.version != "0.1.0" {
			for _, f := range supersededVariants {
				if roles[f] != RoleUpstream {
					t.Errorf("superseded variant %s has role %q, want %q", f, roles[f], RoleUpstream)
				}
			}
		}
	})
}

func hardeningSource(e hardeningEdition, name string) string {
	if contains(e.variants, name) {
		return "content/linux-hardening/variants/" + name + ".yaml"
	}
	return "content/upstream/kyverno/" + name + "/" + name + ".yaml"
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
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, _ := buildHardening(t, e)
		if got := a.Descriptor.Scope.OS; len(got) != 1 || got[0] != "linux" {
			t.Fatalf("scope.os %v, want exactly [linux]", got)
		}
		want := []string{"CronJob", "DaemonSet", "Deployment", "Job", "Pod", "ReplicaSet", "ReplicationController", "StatefulSet"}
		got := append([]string(nil), a.Descriptor.Scope.Workloads...)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("workloads %v, want %v", got, want)
		}
		// 0.2.0 is the first controller release that consumes OCI bundles at
		// all (docs/policy-bundles.md, "Second bundle"); an earlier minimum
		// would claim a compatibility no released controller has. The split
		// needs nothing newer: its policies use the same engine features.
		if a.Descriptor.Compatibility.Provider != "konstapel-kyverno/v1" || a.Descriptor.Compatibility.Konstapel != "0.2.0" {
			t.Fatalf("compatibility %+v, want konstapel-kyverno/v1 and minimum Konstapel 0.2.0", a.Descriptor.Compatibility)
		}
	})
}

// Windows exclusion and missing-OS handling travel in the shipped variants:
// each guards on spec.os.name, and non-root no longer bypasses through
// hostUsers.
func TestHardeningBundleOSConvention(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		_, files := buildHardening(t, e)
		for _, v := range e.variants {
			body := string(files["content/linux-hardening/variants/"+v+".yaml"].Data)
			if !strings.Contains(body, "isWindowsPod") || !strings.Contains(body, "windows") {
				t.Errorf("variant %s has no explicit Windows exclusion", v)
			}
		}
		nr := string(files["content/linux-hardening/variants/require-run-as-nonroot.yaml"].Data)
		if strings.Contains(nr, "userNamespacePod") {
			t.Error("require-run-as-nonroot still carries the hostUsers bypass")
		}
	})
}

// Bounded mappings: exactly the design's table, plus the first loop's AC-6
// mapping of the privileged check; nothing broader is shipped.
func TestHardeningBundleMappings(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, files := buildHardening(t, e)
		var cds []string
		for _, o := range a.Descriptor.OSCAL {
			if strings.Contains(o.Path, "component-definition") {
				cds = append(cds, o.Path)
			}
		}
		if strings.Join(cds, ",") != "content/component-definition.json,"+e.cd {
			t.Fatalf("component definitions %v, want the privileged one and %s", cds, e.cd)
		}
		got := mappingsOf(t, files[e.cd].Data)
		if fmt.Sprint(got) != fmt.Sprint(e.mappings) {
			t.Fatalf("hardening mappings\n got  %v\n want %v", got, e.mappings)
		}
		priv := mappingsOf(t, files["content/component-definition.json"].Data)
		if fmt.Sprint(priv) != fmt.Sprint(map[string]map[string][]string{"ac-6": {"ac-6_smt": {"disallow-privileged-containers"}}}) {
			t.Fatalf("privileged mapping %v", priv)
		}
		profile := files["content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"].Data
		for c := range e.mappings {
			if !bytes.Contains(profile, []byte(`"`+c+`"`)) {
				t.Errorf("Moderate profile does not include %s", c)
			}
		}
	})
}

// Shipped tests: the retained upstream CLI suites of every upstream check and
// the local variant suites, at the paths their relative policy references need.
func TestHardeningBundleTests(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, files := buildHardening(t, e)
		suites := map[string]bool{}
		for _, f := range a.Descriptor.Files {
			if f.Role == RoleTest && strings.HasSuffix(f.Path, "/kyverno-test.yaml") && !strings.Contains(f.Path, "chainsaw") {
				suites[filepath.Dir(f.Path)] = true
			}
		}
		for _, c := range upstreamChecks {
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
		for _, s := range e.suites {
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
	})
}

// Licenses and notices of every vendored source ride along.
func TestHardeningBundleLicenses(t *testing.T) {
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		a, _ := buildHardening(t, e)
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
	})
}

// Hand-breaks: every accidental change to a definition fails a build,
// validation or the accepted-input assertions.
func TestHardeningBundleHandBreaks(t *testing.T) {
	policyIdx := func(t *testing.T, d *Definition, n string) int {
		for i, p := range d.Policies {
			if p.Name == n {
				return i
			}
		}
		t.Fatalf("no policy %s", n)
		return -1
	}
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		cases := map[string]func(t *testing.T, d *Definition){
			"dropped policy": func(t *testing.T, d *Definition) {
				d.Policies = d.Policies[:len(d.Policies)-1]
			},
			"windows scope": func(t *testing.T, d *Definition) { d.Scope.OS = append(d.Scope.OS, "windows") },
			"rule typo": func(t *testing.T, d *Definition) {
				d.Policies[policyIdx(t, d, "require-run-as-nonroot")].Checks[0].CheckID = "require-run-as-nonrot"
			},
			"upstream original in place of the variant": func(t *testing.T, d *Definition) {
				d.Policies[policyIdx(t, d, "require-run-as-nonroot")].Path = "content/upstream/kyverno/require-run-as-nonroot/require-run-as-nonroot.yaml"
			},
			"unlisted policy": func(t *testing.T, d *Definition) {
				d.Policies = append(d.Policies, Policy{Name: "extra", Path: "content/upstream/kyverno/restrict-seccomp-strict/restrict-seccomp-strict.yaml", Checks: []Check{{RuleID: "extra", CheckID: "extra"}}})
			},
			"missing mapping": func(t *testing.T, d *Definition) {
				var keep []OSCALDocument
				for _, o := range d.OSCAL {
					if o.Path != e.cd {
						keep = append(keep, o)
					}
				}
				d.OSCAL = keep
			},
		}
		if e.version != "0.1.0" {
			// The superseded combined check shipped as a policy again,
			// with its include promoted to policy so validation accepts it.
			cases["superseded combined policy"] = func(t *testing.T, d *Definition) {
				f := "content/linux-hardening/variants/disallow-capabilities-strict.yaml"
				d.Policies = append(d.Policies, Policy{Name: "disallow-capabilities-strict", Path: f, Checks: []Check{{RuleID: "disallow-capabilities-strict", CheckID: "disallow-capabilities-strict"}}})
				for i := range d.Include {
					if d.Include[i].From == f {
						d.Include[i].Role = RolePolicy
					}
				}
			}
			cases["combined variant in place of a split check"] = func(t *testing.T, d *Definition) {
				d.Policies[policyIdx(t, d, "restrict-added-capabilities")].Path = "content/linux-hardening/variants/disallow-capabilities-strict.yaml"
			}
			cases["superseded mapping"] = func(t *testing.T, d *Definition) {
				for i := range d.OSCAL {
					if d.OSCAL[i].Path == e.cd {
						d.OSCAL[i].Path = hardening010.cd
					}
				}
				d.Include = append(d.Include, Include{From: hardening010.cd, To: hardening010.cd, Role: RoleComponentDefinition})
			}
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				def := hardeningDefinition(t, e)
				mutate(t, &def)
				a, files, err := buildHardeningFrom(t, def)
				if err == nil {
					err = ValidateContent(a.Descriptor, files)
				}
				if err == nil {
					err = assertHardeningInputs(t, e, a, files)
				}
				if err == nil {
					t.Fatal("the broken definition was accepted")
				}
			})
		}
	})
}

// assertHardeningInputs is the inventory comparison as a plain error, for the
// hand-break cases that content validation alone does not reject.
func assertHardeningInputs(t *testing.T, e hardeningEdition, a *Archive, files fstest.MapFS) error {
	var got []string
	for _, p := range a.Descriptor.Policies {
		if src := hardeningSource(e, p.Name); p.Path != src {
			return fmt.Errorf("policy %s ships %s, want %s", p.Name, p.Path, src)
		}
		got = append(got, p.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(e.checks, ",") {
		return fmt.Errorf("policies %v", got)
	}
	if len(a.Descriptor.Scope.OS) != 1 || a.Descriptor.Scope.OS[0] != "linux" {
		return fmt.Errorf("scope %v", a.Descriptor.Scope.OS)
	}
	for _, o := range a.Descriptor.OSCAL {
		if strings.HasPrefix(o.Path, "content/linux-hardening/") && o.Path != e.cd {
			return fmt.Errorf("component definition %s, want %s", o.Path, e.cd)
		}
	}
	if f := files[e.cd]; f == nil || fmt.Sprint(mappingsOf(t, f.Data)) != fmt.Sprint(e.mappings) {
		return fmt.Errorf("mappings of %s", e.cd)
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
	forEachEdition(t, func(t *testing.T, e hardeningEdition) {
		_, files := buildHardening(t, e)
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
	})
}

// The documented 0.2.0 example selects exactly the split revision's checks
// from this bundle; no superseded identity survives in it.
func TestHardeningRevisionExample(t *testing.T) {
	raw := readRepo(t, "docs/examples/bundles/linux-hardening-0.2.0.yaml")
	profile, _, _ := strings.Cut(string(raw), "\n---\n")
	var p struct {
		Kind string `json:"kind"`
		Spec struct {
			Bundle   struct{ Name, Digest string } `json:"bundle"`
			Policies []struct{ Name string }       `json:"policies"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(profile), &p); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range p.Spec.Policies {
		got = append(got, x.Name)
	}
	sort.Strings(got)
	if p.Kind != "ComplianceProfile" || p.Spec.Bundle.Name != "konstapel-linux-hardening" || strings.Join(got, ",") != strings.Join(hardening020.checks, ",") {
		t.Fatalf("example selects %s %v, want the 0.2.0 checks %v", p.Spec.Bundle.Name, got, hardening020.checks)
	}
	if p.Spec.Bundle.Digest == vendoredDigest || !strings.Contains(string(raw), "placeholder") {
		t.Fatal("the example must pin the OCI 0.2.0 digest, marked as a placeholder until it is published")
	}
}

// The identity mapping is documented: every row of the machine-readable
// identity map appears in the hardening guide's table.
func TestHardeningIdentityMappingIsDocumented(t *testing.T) {
	var m struct {
		Identities []struct {
			From, To struct {
				Check      string `json:"check"`
				Validation int    `json:"validation"`
			}
		} `json:"identities"`
	}
	if err := json.Unmarshal(readRepo(t, "content/linux-hardening/split/variants.json"), &m); err != nil {
		t.Fatal(err)
	}
	doc := string(readRepo(t, "docs/integration/linux-hardening.md"))
	if len(m.Identities) != 7 {
		t.Fatalf("%d identities", len(m.Identities))
	}
	for _, id := range m.Identities {
		row := fmt.Sprintf("| `%s` | %d", id.From.Check, id.From.Validation)
		found := false
		for _, line := range strings.Split(doc, "\n") {
			if strings.HasPrefix(line, row) && strings.Contains(line, "| `"+id.To.Check+"`") {
				found = true
			}
		}
		if !found {
			t.Errorf("docs/integration/linux-hardening.md has no mapping row %s -> %s", row, id.To.Check)
		}
	}
}
