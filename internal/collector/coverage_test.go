package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type covSource struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// stubCoverage is a minimal coverage producer: a report envelope whose
// sources are the packaged capture and evaluation, edited by mutate, and a
// text bound to it. The package owner verifies only the envelope.
func stubCoverage(t *testing.T, seen *CoveragePackage, mutate func(version *string, sources *[]covSource)) CoverageProducer {
	return func(p CoveragePackage) (CoverageFiles, error) {
		if seen != nil {
			*seen = p
		}
		version := CoverageSchemaVersions[0]
		sources := []covSource{
			{Path: "capture.json", Kind: "capture", SHA256: fileSHA(t, filepath.Join(p.Dir, "capture.json"))},
			{Path: "evaluation.json", Kind: "evaluation", SHA256: fileSHA(t, filepath.Join(p.Dir, "evaluation.json"))},
		}
		if mutate != nil {
			mutate(&version, &sources)
		}
		j, err := json.Marshal(map[string]any{"schemaVersion": version, "sources": sources})
		if err != nil {
			return CoverageFiles{}, err
		}
		h := sha256.Sum256(j)
		return CoverageFiles{JSON: j, Text: []byte("Konstapel control coverage report\n" + publication.CoverageTextReportPrefix + hex.EncodeToString(h[:]) + "\n")}, nil
	}
}

func coverageExport(t *testing.T) (ExportRequest, CaptureV2, Evaluation) {
	t.Helper()
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	ev := evaluate(t, c, nil, maxAge)
	return exportReq(t, c, ev, repo(t)), c, ev
}

func roleOf(d publication.Descriptor, p string) publication.FileRole {
	for _, f := range d.Files {
		if f.Path == p {
			return f.Role
		}
	}
	return ""
}

// Without a producer the package is exactly the pre-coverage package; with
// one it gains the two summary files, their roles and a validation check,
// and nothing else changes.
func TestExportCoverageIsAdditive(t *testing.T) {
	req, _, _ := coverageExport(t)
	plain, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if roleOf(plain, publication.CoverageFile) != "" || slices.Contains(plain.Producer.Checks, "coverage-references") {
		t.Fatalf("a package without a producer has coverage: %+v", plain.Producer)
	}
	var seen CoveragePackage
	req2 := req
	req2.Out = filepath.Join(t.TempDir(), "pkg")
	req2.Coverage = stubCoverage(t, &seen, nil)
	req2.CoverageOmitted = func(err error) { t.Fatalf("omitted: %v", err) }
	d, err := Export(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if roleOf(d, publication.CoverageFile) != publication.RoleCoverage || roleOf(d, publication.CoverageTextFile) != publication.RoleCoverageText ||
		!slices.Equal(d.Producer.Checks, append(slices.Clone(plain.Producer.Checks), "coverage-references")) {
		t.Fatalf("descriptor %+v", d)
	}
	if d.Evidence != plain.Evidence || d.Outcomes != plain.Outcomes || d.PackageKind != plain.PackageKind || len(d.Files) != len(plain.Files)+2 {
		t.Fatalf("coverage changed the package: %+v vs %+v", d, plain)
	}
	for i, f := range slices.DeleteFunc(slices.Clone(d.Files), func(f publication.File) bool {
		return f.Role == publication.RoleCoverage || f.Role == publication.RoleCoverageText
	}) {
		if f.Path != plain.Files[i].Path || f.Role != plain.Files[i].Role {
			t.Fatalf("file %d: %+v vs %+v", i, f, plain.Files[i])
		}
	}
	// The producer saw the vendored content at the package root.
	if seen.Kind != publication.KindAssessment || len(seen.Content) != 1 || seen.Content[0].Path != "" || !seen.Content[0].Vendored ||
		!strings.HasPrefix(seen.Content[0].Ref.Digest, "sha256:") {
		t.Fatalf("producer view %+v", seen)
	}
	if err := VerifyCoverage(req2.Out, d); err != nil {
		t.Fatal(err)
	}
}

// Hand-break guards (coverage failure blocking publication; invalid
// reference accepted): a failing, panicking or invalid producer leaves
// the package exactly as without coverage, and says why.
func TestExportCoverageFailureNeverBlocksEvidence(t *testing.T) {
	req, _, _ := coverageExport(t)
	plain, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]CoverageProducer{
		"error": func(CoveragePackage) (CoverageFiles, error) { return CoverageFiles{}, errors.New("boom") },
		"panic": func(CoveragePackage) (CoverageFiles, error) { panic("boom") },
		"empty": func(CoveragePackage) (CoverageFiles, error) { return CoverageFiles{}, nil },
		"escaping reference": stubCoverage(t, nil, func(_ *string, s *[]covSource) {
			*s = append(*s, covSource{Path: "../etc/passwd", SHA256: strings.Repeat("0", 64)})
		}),
		"absolute reference": stubCoverage(t, nil, func(_ *string, s *[]covSource) { (*s)[0].Path = "/capture.json" }),
		"missing file": stubCoverage(t, nil, func(_ *string, s *[]covSource) {
			*s = append(*s, covSource{Path: "content/nope.json", SHA256: strings.Repeat("0", 64)})
		}),
		"checksum mismatch": stubCoverage(t, nil, func(_ *string, s *[]covSource) { (*s)[1].SHA256 = strings.Repeat("0", 64) }),
		"self reference": stubCoverage(t, nil, func(_ *string, s *[]covSource) {
			*s = append(*s, covSource{Path: publication.CoverageTextFile, SHA256: strings.Repeat("0", 64)})
		}),
		"no capture reference": stubCoverage(t, nil, func(_ *string, s *[]covSource) { *s = (*s)[1:] }),
		"unknown version":      stubCoverage(t, nil, func(v *string, _ *[]covSource) { *v = "konstapel.io/coverage/v2" }),
		"unbound text": func(p CoveragePackage) (CoverageFiles, error) {
			f, err := stubCoverage(t, nil, nil)(p)
			f.Text = []byte("Konstapel control coverage report\n")
			return f, err
		},
	}
	for name, prod := range cases {
		r := req
		r.Out = filepath.Join(t.TempDir(), "pkg")
		r.Coverage = prod
		var omitted error
		r.CoverageOmitted = func(err error) { omitted = err }
		d, err := Export(context.Background(), r)
		if err != nil {
			t.Fatalf("%s: coverage blocked the export: %v", name, err)
		}
		if omitted == nil {
			t.Errorf("%s: not reported", name)
		}
		if roleOf(d, publication.CoverageFile) != "" || d.Evidence != plain.Evidence || d.Outcomes != plain.Outcomes ||
			d.PackageKind != plain.PackageKind || !slices.Equal(d.Producer.Checks, plain.Producer.Checks) {
			t.Errorf("%s: package changed: %+v", name, d)
		}
		for _, f := range []string{publication.CoverageFile, publication.CoverageTextFile} {
			if _, err := os.Stat(filepath.Join(r.Out, f)); !os.IsNotExist(err) {
				t.Errorf("%s: %s left behind", name, f)
			}
		}
	}
}

// A diagnostic package still gets coverage (as a diagnostic), with no
// packaged content offered to the producer.
func TestExportCoverageOfDiagnosticPackage(t *testing.T) {
	req, _, _ := coverageExport(t)
	req.Content = &RunContent{Failure: &ContentFailure{Reason: ReasonContentLost, Message: "lost"}}
	var seen CoveragePackage
	req.Coverage = stubCoverage(t, &seen, nil)
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindDiagnostic || seen.Kind != publication.KindDiagnostic || seen.Diagnostic == nil ||
		seen.Diagnostic.Reason != ReasonContentLost || len(seen.Content) != 0 || roleOf(d, publication.CoverageFile) != publication.RoleCoverage {
		t.Fatalf("diagnostic %+v producer view %+v", d, seen)
	}
}

// Hand-break guards (checksum mismatch accepted; invalid reference
// accepted): verification of a stored package fails closed, including
// after the descriptor is regenerated to match tampered bytes.
func TestVerifyCoverageFailsClosed(t *testing.T) {
	req, _, _ := coverageExport(t)
	req.Coverage = stubCoverage(t, nil, nil)
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	reinventory := func(dir string, d publication.Descriptor) publication.Descriptor {
		files, err := publication.Inventory(dir, exportRole)
		if err != nil {
			t.Fatal(err)
		}
		d.Files = files
		if err := assessment.Write(filepath.Join(dir, publication.DescriptorFile), d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	copyPkg := func() string {
		dir := filepath.Join(t.TempDir(), "pkg")
		if err := os.CopyFS(dir, os.DirFS(req.Out)); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// The capture changed after coverage referenced it: the descriptor
	// matches the new bytes, but the coverage reference does not.
	dir := copyPkg()
	raw, _ := os.ReadFile(filepath.Join(dir, "capture.json"))
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), append(raw, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCoverage(dir, reinventory(dir, d)); err == nil {
		t.Error("a stale coverage reference was accepted")
	}
	// coverage.json edited with its descriptor entry: the text no longer
	// names it.
	dir = copyPkg()
	j, _ := os.ReadFile(filepath.Join(dir, publication.CoverageFile))
	if err := os.WriteFile(filepath.Join(dir, publication.CoverageFile), append(j, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCoverage(dir, reinventory(dir, d)); err == nil {
		t.Error("a text bound to another JSON was accepted")
	}
	// Only one of the pair, or a coverage role on another path, is not a
	// valid descriptor.
	one := d
	one.Files = slices.DeleteFunc(slices.Clone(d.Files), func(f publication.File) bool { return f.Path == publication.CoverageTextFile })
	if err := one.Validate(); err == nil {
		t.Error("coverage.json without coverage.txt validated")
	}
	moved := d
	moved.Files = slices.Clone(d.Files)
	for i := range moved.Files {
		if moved.Files[i].Path == "summary.json" {
			moved.Files[i].Role = publication.RoleCoverage
		}
	}
	if err := moved.Validate(); err == nil {
		t.Error("a coverage role on another path validated")
	}
	unknown := d
	unknown.Files = slices.Clone(d.Files)
	for i := range unknown.Files {
		if unknown.Files[i].Path == publication.CoverageFile {
			unknown.Files[i].Role = "coverage-summary-v2"
		}
	}
	if err := unknown.Validate(); err == nil {
		t.Error("an unknown role validated")
	}
}
