package hardening

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const root = "../.."

type sources struct {
	Bundle           string `json:"bundle"`
	SourceRepository string `json:"sourceRepository"`
	SourceRevision   string `json:"sourceRevision"`
	Research         string `json:"research"`
	License          struct {
		SPDX   string `json:"spdx"`
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
		URL    string `json:"url"`
	} `json:"license"`
	Notices             string `json:"notices"`
	ComposesByReference []struct {
		Check string `json:"check"`
		Note  string `json:"note"`
	} `json:"composesByReference"`
	Checks []struct {
		Check                string `json:"check"`
		Title                string `json:"title"`
		SourceURL            string `json:"sourceUrl"`
		SourcePath           string `json:"sourcePath"`
		VendoredPath         string `json:"vendoredPath"`
		PolicyFile           string `json:"policyFile"`
		PolicySHA256         string `json:"policySha256"`
		ResearchPolicySHA256 string `json:"researchPolicySha256"`
		APIVersion           string `json:"apiVersion"`
		Kind                 string `json:"kind"`
		SubValidations       []struct {
			Index   int    `json:"index"`
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"subValidations"`
		FixtureAids []struct {
			Path   string `json:"path"`
			Role   string `json:"role"`
			SHA256 string `json:"sha256"`
		} `json:"fixtureAids"`
		Modifications string `json:"modifications"`
	} `json:"checks"`
}

func load(t *testing.T) sources {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "content/linux-hardening/sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s sources
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func fileSum(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func listedSums(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, "content/SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, path, _ := strings.Cut(sc.Text(), "  ")
		out[path] = sum
	}
	return out
}

// The research table is the independent record of the source checksums.
func researchSums(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile("\\| \\[([a-z-]+)\\]\\(https://github.com/kyverno/policies/tree/[0-9a-f]{40}/[^)]+\\) \\| `([0-9a-f]{64})` \\|").FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = m[2]
	}
	return out
}

func TestSourcesMatchTheVendoredFiles(t *testing.T) {
	s := load(t)
	listed := listedSums(t)
	research := researchSums(t, s.Research)
	if s.SourceRevision != "fac1ccda72ab53594921ca1c040ac90b80afadcd" || s.License.SPDX != "Apache-2.0" {
		t.Errorf("source pin %s / license %s", s.SourceRevision, s.License.SPDX)
	}
	if fileSum(t, s.License.File) != s.License.SHA256 || listed[s.License.File] != s.License.SHA256 {
		t.Error("license checksum mismatch")
	}
	want := []string{"disallow-capabilities-strict", "disallow-privilege-escalation", "require-run-as-nonroot", "restrict-seccomp-strict"}
	var got []string
	for _, c := range s.Checks {
		got = append(got, c.Check)
		t.Run(c.Check, func(t *testing.T) {
			if c.Check == "disallow-privileged-containers" {
				t.Fatal("the first loop's check must be composed by reference, not vendored again")
			}
			sum := fileSum(t, c.PolicyFile)
			if sum != c.PolicySHA256 || sum != c.ResearchPolicySHA256 || sum != research[c.Check] || listed[c.PolicyFile] != sum {
				t.Errorf("policy %s: file %s, recorded %s, research %s, SHA256SUMS %s", c.PolicyFile, sum, c.PolicySHA256, research[c.Check], listed[c.PolicyFile])
			}
			if !strings.HasSuffix(c.SourceURL, "/tree/"+s.SourceRevision+"/"+c.SourcePath) || !strings.HasSuffix(c.SourcePath, "/"+c.Check) {
				t.Errorf("source URL %s does not resolve to the pinned path", c.SourceURL)
			}
			// Every vendored file, including hidden CLI/Chainsaw fixtures, is checksummed.
			files := 0
			err := filepath.WalkDir(filepath.Join(root, c.VendoredPath), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(root, p)
				files++
				if listed[rel] != fileSum(t, rel) {
					t.Errorf("%s is not covered by SHA256SUMS", rel)
				}
				return nil
			})
			if err != nil || files == 0 {
				t.Fatalf("vendored files: %d, %v", files, err)
			}
			for _, aid := range c.FixtureAids {
				if fileSum(t, filepath.Join(c.VendoredPath, aid.Path)) != aid.SHA256 {
					t.Errorf("fixture aid %s checksum mismatch", aid.Path)
				}
			}
			// The shipped policy is a new-group v1 ValidatingPolicy whose
			// validations each have exactly one stable identity.
			raw, _ := os.ReadFile(filepath.Join(root, c.PolicyFile))
			var policy struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Metadata   struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					Validations []map[string]any `json:"validations"`
				} `json:"spec"`
			}
			if err := yaml.Unmarshal(raw, &policy); err != nil {
				t.Fatal(err)
			}
			if policy.APIVersion != "policies.kyverno.io/v1" || policy.Kind != "ValidatingPolicy" || policy.APIVersion != c.APIVersion || policy.Metadata.Name != c.Check {
				t.Errorf("policy is %s %s %s", policy.APIVersion, policy.Kind, policy.Metadata.Name)
			}
			if len(c.SubValidations) != len(policy.Spec.Validations) {
				t.Fatalf("%d sub-validation identities for %d validations", len(c.SubValidations), len(policy.Spec.Validations))
			}
			for i, sv := range c.SubValidations {
				if sv.Index != i || !strings.HasPrefix(sv.ID, c.Check+".") || sv.Summary == "" {
					t.Errorf("sub-validation %d: %+v", i, sv)
				}
			}
		})
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("checks = %v, want %v", got, want)
	}
	if len(s.ComposesByReference) != 1 || s.ComposesByReference[0].Check != "disallow-privileged-containers" {
		t.Errorf("composes by reference: %+v", s.ComposesByReference)
	}
	if listed["content/linux-hardening/sources.json"] != fileSum(t, "content/linux-hardening/sources.json") {
		t.Error("sources.json is not covered by SHA256SUMS")
	}
}

// Only new-group v1 policy resources may ship; fixture exceptions and the
// test helper are v1 as well.
func TestVendoredPolicyResourcesAreNewGroupV1(t *testing.T) {
	for _, c := range load(t).Checks {
		err := filepath.WalkDir(filepath.Join(root, c.VendoredPath), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
				return err
			}
			raw, _ := os.ReadFile(p)
			for _, doc := range strings.Split(string(raw), "\n---") {
				var m struct{ APIVersion, Kind string }
				if yaml.Unmarshal([]byte(doc), &m) != nil {
					continue
				}
				if strings.Contains(m.APIVersion, "kyverno.io") && strings.HasSuffix(m.Kind, "Policy") || m.Kind == "PolicyException" {
					if m.APIVersion != "policies.kyverno.io/v1" {
						t.Errorf("%s: %s %s", p, m.APIVersion, m.Kind)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpstreamCLIEvidenceCoversEveryCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "docs/integration/hardening-upstream-cli.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev struct {
		CLI struct {
			Version string `json:"version"`
		} `json:"cli"`
		Checks map[string]struct {
			Matched  int            `json:"matched"`
			Failed   int            `json:"failed"`
			ByPolicy map[string]int `json:"byPolicy"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.CLI.Version != "v1.19.2" {
		t.Errorf("CLI %s", ev.CLI.Version)
	}
	for _, c := range load(t).Checks {
		r, ok := ev.Checks[c.Check]
		if !ok || r.Failed != 0 || r.Matched == 0 || r.ByPolicy[c.Check] == 0 {
			t.Errorf("%s: %+v", c.Check, r)
		}
		total := 0
		for policy, n := range r.ByPolicy {
			total += n
			if policy != c.Check && !slices.ContainsFunc(c.FixtureAids, func(a struct {
				Path   string `json:"path"`
				Role   string `json:"role"`
				SHA256 string `json:"sha256"`
			}) bool {
				return strings.HasSuffix(a.Path, "/"+policy+".yaml")
			}) {
				t.Errorf("%s: results for %s, which is neither the check nor a declared fixture aid", c.Check, policy)
			}
		}
		if total != r.Matched {
			t.Errorf("%s: byPolicy sums to %d, not %d", c.Check, total, r.Matched)
		}
	}
}
