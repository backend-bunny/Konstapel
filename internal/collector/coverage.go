package collector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Control coverage summary files (add-control-coverage-reporting).
//
// The package owner places them and verifies their references; it does not
// build them. internal/coverage imports this package, so Export receives
// a CoverageProducer (the assessment controller's) and calls it once the
// package's kind and packaged content are known. Coverage is a summary:
// it never changes the OSCAL documents, the evidence and outcome counts,
// or whether the package is an Assessment or a Diagnostic, and a coverage
// failure never fails the export.

// CoverageSchemaVersions are the coverage report versions a package may
// carry. Any other version fails verification (fail closed).
var CoverageSchemaVersions = []string{"konstapel.io/coverage/v1"}

// CoveragePackage is what a CoverageProducer is given: the package
// directory with its capture, evaluation and content written, its kind,
// and the content it packages.
type CoveragePackage struct {
	// Dir is the package directory. Producers read it; they never write.
	Dir        string
	Kind       publication.PackageKind
	Diagnostic *publication.Diagnostic
	// Content are the packaged content roots; empty for a Diagnostic,
	// which packages no content.
	Content []PackagedContent
}

// PackagedContent is one content root of a package.
type PackagedContent struct {
	// Ref is the bundle. For a vendored run's content/ tree at the package
	// root, Name is empty (the package does not name it) and Digest is the
	// sha256 of its content/SHA256SUMS.
	Ref v1alpha1.BundleReference
	// Path is the root's package directory: "" for the package root, or
	// bundles/<hex> for a member of a content set.
	Path     string
	Vendored bool
	// Applied: contributions the run assesses were applied from it.
	Applied bool
}

// CoverageFiles are a rendered coverage report (coverage.json and
// coverage.txt).
type CoverageFiles struct {
	JSON, Text []byte
}

// CoverageProducer builds a package's coverage files. It should turn its
// own input problems into a coverage diagnostic report rather than an
// error; an error, or files whose references do not verify, leave the
// package without coverage (reported through ExportRequest.CoverageOmitted).
type CoverageProducer func(CoveragePackage) (CoverageFiles, error)

// coveragePackage is the producer's view of a package being exported.
func coveragePackage(req ExportRequest, kind publication.PackageKind, diag *publication.Diagnostic) (CoveragePackage, error) {
	p := CoveragePackage{Dir: req.Out, Kind: kind, Diagnostic: diag, Content: []PackagedContent{}}
	if kind != publication.KindAssessment {
		return p, nil
	}
	if req.Content == nil {
		sums, err := os.ReadFile(filepath.Join(req.Out, "content", "SHA256SUMS"))
		if err != nil {
			return p, err
		}
		h := sha256.Sum256(sums)
		p.Content = append(p.Content, PackagedContent{Ref: v1alpha1.BundleReference{Digest: "sha256:" + hex.EncodeToString(h[:])}, Vendored: true, Applied: true})
		return p, nil
	}
	for _, m := range req.Content.Members {
		if _, err := os.Lstat(filepath.Join(req.Out, filepath.FromSlash(m.Path()))); err != nil {
			continue // not packaged (an unapplied member beside applied ones)
		}
		p.Content = append(p.Content, PackagedContent{Ref: m.Ref, Path: m.Path(), Vendored: m.Vendored, Applied: m.Applied})
	}
	return p, nil
}

// writeCoverage asks the producer for the package's coverage and writes
// it, verified against the files already in the package. On any failure
// nothing is left behind and the error is returned for CoverageOmitted.
func writeCoverage(req ExportRequest, kind publication.PackageKind, diag *publication.Diagnostic) (err error) {
	jp, tp := filepath.Join(req.Out, publication.CoverageFile), filepath.Join(req.Out, publication.CoverageTextFile)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("coverage producer panicked: %v", r)
		}
		if err != nil {
			_ = os.Remove(jp)
			_ = os.Remove(tp)
		}
	}()
	p, err := coveragePackage(req, kind, diag)
	if err != nil {
		return err
	}
	f, err := req.Coverage(p)
	if err != nil {
		return err
	}
	if len(f.JSON) == 0 || len(f.Text) == 0 {
		return errors.New("the coverage producer returned no report")
	}
	if err := os.WriteFile(jp, f.JSON, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(tp, f.Text, 0o644); err != nil {
		return err
	}
	return verifyCoverage(f, func(rel string) (string, publication.FileRole, bool) {
		if safeRel(rel) != nil {
			return "", "", false
		}
		b, err := os.ReadFile(filepath.Join(req.Out, filepath.FromSlash(rel)))
		if err != nil {
			return "", "", false
		}
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:]), exportRole(rel), true
	})
}

// VerifyCoverage checks a package's coverage summary files against its
// descriptor: a known report version, a text bound to the JSON's digest,
// and every source reference a safe relative path to an inventoried,
// non-coverage file with the same sha256 (VerifyDir checks the bytes).
// The capture and evaluation must be among the sources. A package without
// coverage files passes; one with only one of them fails
// (Descriptor.Validate). Equivalence of the text to the JSON is
// coverage.VerifyFiles.
func VerifyCoverage(dir string, d publication.Descriptor) error {
	files := map[string]publication.File{}
	for _, f := range d.Files {
		files[f.Path] = f
	}
	jf, hasJSON := files[publication.CoverageFile]
	tf, hasText := files[publication.CoverageTextFile]
	switch {
	case !hasJSON && !hasText:
		return nil
	case jf.Role != publication.RoleCoverage || tf.Role != publication.RoleCoverageText:
		return errors.New("coverage: the coverage files do not have their coverage roles")
	}
	var f CoverageFiles
	var err error
	if f.JSON, err = os.ReadFile(filepath.Join(dir, publication.CoverageFile)); err != nil {
		return err
	}
	if f.Text, err = os.ReadFile(filepath.Join(dir, publication.CoverageTextFile)); err != nil {
		return err
	}
	return verifyCoverage(f, func(rel string) (string, publication.FileRole, bool) {
		x, ok := files[rel]
		return x.SHA256, x.Role, ok
	})
}

// verifyCoverage checks the files with lookup, which returns a package
// file's sha256 and role.
func verifyCoverage(f CoverageFiles, lookup func(string) (string, publication.FileRole, bool)) error {
	var env struct {
		SchemaVersion string `json:"schemaVersion"`
		Sources       []struct {
			Path   string `json:"path"`
			Kind   string `json:"kind"`
			SHA256 string `json:"sha256"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(f.JSON, &env); err != nil {
		return fmt.Errorf("coverage: %s: %w", publication.CoverageFile, err)
	}
	if !slices.Contains(CoverageSchemaVersions, env.SchemaVersion) {
		return fmt.Errorf("coverage: unsupported report version %q", env.SchemaVersion)
	}
	sum := sha256.Sum256(f.JSON)
	if !textBinds(f.Text, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("coverage: %s does not name the sha256 of %s", publication.CoverageTextFile, publication.CoverageFile)
	}
	var errs []error
	seen := map[string]bool{}
	for _, s := range env.Sources {
		if err := safeRel(s.Path); err != nil {
			errs = append(errs, fmt.Errorf("coverage: source %w", err))
			continue
		}
		if seen[s.Path] {
			errs = append(errs, fmt.Errorf("coverage: source %q is listed twice", s.Path))
		}
		seen[s.Path] = true
		sha, role, ok := lookup(s.Path)
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("coverage: source %q is not a file of the package", s.Path))
		case role == publication.RoleCoverage || role == publication.RoleCoverageText:
			errs = append(errs, fmt.Errorf("coverage: source %q is a coverage file", s.Path))
		case sha != s.SHA256:
			errs = append(errs, fmt.Errorf("coverage: source %q does not match its packaged sha256", s.Path))
		}
	}
	for _, p := range []string{"capture.json", "evaluation.json"} {
		if !seen[p] {
			errs = append(errs, fmt.Errorf("coverage: the report does not reference the packaged %s", p))
		}
	}
	return errors.Join(errs...)
}

// textBinds reports whether text has the report line naming sum within its
// header (the first lines).
func textBinds(text []byte, sum string) bool {
	sc := bufio.NewScanner(bytes.NewReader(text))
	for i := 0; i < 8 && sc.Scan(); i++ {
		if sc.Text() == publication.CoverageTextReportPrefix+sum {
			return true
		}
	}
	return false
}

// safeRel accepts clean, relative, slash-separated package paths.
func safeRel(p string) error {
	if p == "" || strings.Contains(p, "\\") || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") || p == publication.DescriptorFile {
		return fmt.Errorf("%q is not a package-relative path", p)
	}
	return nil
}
