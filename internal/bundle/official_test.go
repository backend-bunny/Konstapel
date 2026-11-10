package bundle

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const officialDef = "bundles/konstapel-privileged-containers/definition.json"

// buildOfficial builds the checked-in privileged-container bundle from this
// repository's real content, as the release workflow will.
var (
	officialOnce  sync.Once
	officialArch  *Archive
	officialFiles fstest.MapFS
)

// buildOfficial builds once per test binary; callers must not modify the
// returned payload (officialPayload hands out private copies).
func buildOfficial(t *testing.T) (*Archive, fstest.MapFS) {
	t.Helper()
	officialOnce.Do(func() { officialArch, officialFiles = buildOfficialFresh(t) })
	return officialArch, officialFiles
}

func buildOfficialFresh(t *testing.T) (*Archive, fstest.MapFS) {
	t.Helper()
	root := os.DirFS("../..")
	raw, err := os.ReadFile(filepath.Join("../..", officialDef))
	if err != nil {
		t.Fatal(err)
	}
	def, err := LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = strings.Repeat("c", 40)
	a, err := Build(def, root, time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	return a, files
}

func TestOfficialBundleIsReproducible(t *testing.T) {
	a, _ := buildOfficial(t)
	b, _ := buildOfficialFresh(t)
	if a.LayerDigest != b.LayerDigest || a.ManifestDigest != b.ManifestDigest {
		t.Fatal("the official bundle is not reproducible")
	}
}

// sums parses a sha256sum-format file.
func sums(t *testing.T, data []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		sum, p, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("malformed checksum line %q", sc.Text())
		}
		out[p] = sum
	}
	return out
}

// The packaged checksums verify against the payload, and agree with the
// repository's existing content checksums for every shared file.
func TestOfficialBundleChecksums(t *testing.T) {
	_, files := buildOfficial(t)
	packaged := sums(t, files["content/SHA256SUMS"].Data)
	if len(packaged) < 20 {
		t.Fatalf("only %d packaged checksums", len(packaged))
	}
	for p, want := range packaged {
		f, ok := files[p]
		if !ok {
			t.Fatalf("%s is checksummed but absent", p)
		}
		sum := sha256.Sum256(f.Data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: payload digest %s != packaged checksum %s", p, got, want)
		}
	}
	repo, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	shared := 0
	for p, want := range sums(t, repo) {
		if got, ok := packaged[p]; ok {
			shared++
			if got != want {
				t.Errorf("%s: packaged %s differs from the repository's content/SHA256SUMS %s", p, got, want)
			}
		}
	}
	if shared < 15 {
		t.Errorf("only %d files overlap the repository checksums; the existing provenance is not being retained", shared)
	}
}

// The existing bounded AC-6 mapping survives packaging unchanged and agrees
// with the descriptor's logical inventory.
func TestOfficialBundleAC6Mapping(t *testing.T) {
	a, files := buildOfficial(t)
	var cd struct {
		CD struct {
			Components []struct {
				Title string                         `json:"title"`
				Props []struct{ Name, Value string } `json:"props"`
				CI    []struct {
					Source string `json:"source"`
					IR     []struct {
						ControlID  string `json:"control-id"`
						Statements []struct {
							Props []struct{ Name, Value string } `json:"props"`
						} `json:"statements"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(files["content/component-definition.json"].Data, &cd); err != nil {
		t.Fatal(err)
	}
	want := a.Descriptor.Policies[0].Checks[0]
	var ac6, check bool
	for _, c := range cd.CD.Components {
		for _, ci := range c.CI {
			if _, ok := files["content/"+ci.Source]; !ok {
				t.Errorf("control source %q does not resolve inside the archive", ci.Source)
			}
			for _, ir := range ci.IR {
				if ir.ControlID != "ac-6" {
					t.Errorf("unexpected control %q: the mapping must stay bounded to AC-6", ir.ControlID)
					continue
				}
				for _, st := range ir.Statements {
					for _, p := range st.Props {
						ac6 = ac6 || (p.Name == "Rule_Id" && p.Value == want.RuleID)
					}
				}
			}
		}
		for _, p := range c.Props {
			check = check || (p.Name == "Check_Id" && p.Value == want.CheckID)
		}
	}
	if !ac6 || !check {
		t.Fatalf("AC-6 statement maps rule %q: %v; check %q declared: %v", want.RuleID, ac6, want.CheckID, check)
	}
	if !bytes.Contains(files["content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"].Data, []byte(`"ac-6"`)) {
		t.Error("the Moderate profile does not include ac-6")
	}
}

// The upstream Kyverno fixtures pass when run against the unpacked release
// payload rather than the working tree.
func TestOfficialBundleKyvernoFixtures(t *testing.T) {
	kyverno, err := exec.LookPath("kyverno")
	if err != nil {
		t.Skip("kyverno CLI not on PATH; run through devbox (task test)")
	}
	_, files := buildOfficial(t)
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
	out, err := exec.Command(kyverno, "test", filepath.Join(dir, "content/upstream/kyverno"), "--require-tests", "--remove-color").CombinedOutput()
	if err != nil {
		t.Fatalf("kyverno test on the unpacked payload failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("0 tests failed")) {
		t.Fatalf("unexpected kyverno output:\n%s", out)
	}
}

func TestGeneratedChecksumsValidation(t *testing.T) {
	def, root := buildInputs(t)
	def.Include = append(def.Include, Include{Generate: "md5", To: "content/MD5SUMS", Role: RoleChecksums})
	if _, err := Build(def, root, epoch); err == nil || !strings.Contains(err.Error(), "unsupported generator") {
		t.Fatalf("got %v", err)
	}
	if _, err := LoadDefinition([]byte(`{"name":"x","bogus":1}`)); err == nil {
		t.Error("LoadDefinition accepted an unknown field")
	}
}
