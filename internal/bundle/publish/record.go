package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const (
	// RecordFormat is the publication record's format identifier.
	RecordFormat = "konstapel.policy.bundle.publication/v1"
	// RecordArtifactType is the artifact type of the OCI referrer that
	// carries the record in the registry, and the media type of its layer.
	RecordArtifactType = "application/vnd.konstapel.policy.bundle.publication.v1+json"
	// RecordFile is the record's file name inside a frozen layout directory.
	RecordFile = "publication-record.json"
	// MaxRecordBytes bounds a record, locally and in the registry.
	MaxRecordBytes = 64 << 10
	// TestsPassed is the only test result a record may carry.
	TestsPassed = "passed"
)

var (
	sha256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitHex  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ociDigest  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	printable  = regexp.MustCompile(`^[\x21-\x7e]([\x20-\x7e]{0,254}[\x21-\x7e])?$`)
	errNoBytes = errors.New("empty")
)

// Record is the publication record: the facts a later run needs to publish,
// recover or attest exactly these bytes without rebuilding them. It contains
// only frozen facts (no run identifiers), so the same frozen inputs always
// produce byte-identical records and therefore the same record referrer.
type Record struct {
	Format  string `json:"format"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"source"`
	// Definition is bundles/<name>/definition.json at Source.Commit.
	Definition     FileDigest `json:"definition"`
	ManifestDigest string     `json:"manifestDigest"`
	LayerDigest    string     `json:"layerDigest"`
	// ContentDigest is Descriptor.ContentDigest(): the canonical payload
	// inventory, the provenance contract's bundle-content material.
	ContentDigest string `json:"contentDigest"`
	// Tools built and tested the bytes, sorted by name.
	Tools []Tool `json:"tools"`
	Tests Tests  `json:"tests"`
}

// FileDigest names a file and its SHA-256 (hex).
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Tool is one build or test tool and its version.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tests records the declarative policy fixtures that passed against the
// unpacked frozen layer. Files are payload files with role "test", sorted.
type Tests struct {
	Runner string       `json:"runner"`
	Result string       `json:"result"`
	Files  []FileDigest `json:"files"`
}

// Canonical returns the record's only accepted serialization.
func (r Record) Canonical() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err) // a struct of strings and slices always marshals
	}
	return b
}

// ParseRecord parses a record strictly: bounded, no unknown fields, no
// trailing data, and exactly its canonical serialization (so its digest is
// stable). It checks the record's own syntax; Frozen binds it to bytes.
func ParseRecord(raw []byte) (Record, error) {
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return Record{}, fmt.Errorf("record is %d bytes; want 1 to %d", len(raw), MaxRecordBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("record: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Record{}, errors.New("record has trailing data")
	}
	if !bytes.Equal(r.Canonical(), raw) {
		return Record{}, errors.New("record is not in canonical form")
	}
	if err := r.validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

func (r Record) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if r.Format != RecordFormat {
		fail("format %q: want %q", r.Format, RecordFormat)
	}
	if r.Name == "" || r.Version == "" {
		fail("name and version are required")
	}
	if !strings.HasPrefix(r.Source.Repository, "https://") || !printable.MatchString(r.Source.Repository) {
		fail("source repository %q must be an https URL", r.Source.Repository)
	}
	if !commitHex.MatchString(r.Source.Commit) {
		fail("source commit %q must be a full 40-character SHA", r.Source.Commit)
	}
	if r.Definition.Path != "bundles/"+r.Name+"/definition.json" || !sha256Hex.MatchString(r.Definition.SHA256) {
		fail("definition %+v must be bundles/%s/definition.json with a sha256", r.Definition, r.Name)
	}
	for what, d := range map[string]string{"manifest": r.ManifestDigest, "layer": r.LayerDigest, "content": r.ContentDigest} {
		if !ociDigest.MatchString(d) {
			fail("%s digest %q must be sha256:<64 hex>", what, d)
		}
	}
	if len(r.Tools) == 0 {
		fail("at least one tool is required")
	}
	for i, t := range r.Tools {
		if !printable.MatchString(t.Name) || !printable.MatchString(t.Version) {
			fail("tool %d (%q %q) needs a printable name and version", i, t.Name, t.Version)
		}
		if i > 0 && r.Tools[i-1].Name >= t.Name {
			fail("tools must be sorted by name without duplicates")
		}
	}
	if r.Tests.Runner == "" || !printable.MatchString(r.Tests.Runner) {
		fail("tests need a runner")
	}
	if r.Tests.Result != TestsPassed {
		fail("tests result %q: only %q bundles are frozen", r.Tests.Result, TestsPassed)
	}
	if len(r.Tests.Files) == 0 {
		fail("tests must name the fixtures that ran")
	}
	for i, f := range r.Tests.Files {
		if !sha256Hex.MatchString(f.SHA256) || f.Path == "" {
			fail("test file %d (%q) needs a path and a sha256", i, f.Path)
		}
		if i > 0 && r.Tests.Files[i-1].Path >= f.Path {
			fail("test files must be sorted by path without duplicates")
		}
	}
	return errors.Join(errs...)
}

// Frozen is a verified bundle and the record bound to it: exactly the bytes
// Publish pushes or recovers.
type Frozen struct {
	Descriptor     *bundle.Descriptor
	Manifest       []byte
	ManifestDigest string
	Layer          []byte
	LayerDigest    string
	Record         Record
	RecordJSON     []byte
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// verifyBundle checks manifest and layer bytes the way the consumer does:
// the bundle manifest shape, the layer digest and size it names, and the
// unpacked payload against its descriptor.
func verifyBundle(manifest, layer []byte) (*bundle.Descriptor, error) {
	layerDigest, layerSize, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, err
	}
	if digestOf(layer) != layerDigest || int64(len(layer)) != layerSize {
		return nil, fmt.Errorf("layer does not match the manifest's %s (%d bytes)", layerDigest, layerSize)
	}
	d, payload, err := bundle.Unpack(layer)
	if err != nil {
		return nil, err
	}
	if err := d.VerifyPayload(payload); err != nil {
		return nil, err
	}
	return d, nil
}

// newFrozen verifies manifest and layer and binds rec to them.
func newFrozen(manifest, layer []byte, rec Record) (*Frozen, error) {
	d, err := verifyBundle(manifest, layer)
	if err != nil {
		return nil, err
	}
	f := &Frozen{
		Descriptor: d, Manifest: manifest, ManifestDigest: digestOf(manifest),
		Layer: layer, LayerDigest: digestOf(layer),
	}
	if err := f.bind(rec); err != nil {
		return nil, err
	}
	return f, nil
}

// CheckRecord verifies manifest and layer the way the consumer does and that
// rec is a valid record describing exactly those bytes.
func CheckRecord(manifest, layer []byte, rec Record) error {
	_, err := newFrozen(manifest, layer, rec)
	return err
}

// bind checks that rec describes exactly f's bytes and sets it.
func (f *Frozen) bind(rec Record) error {
	if err := rec.validate(); err != nil {
		return err
	}
	d := f.Descriptor
	var errs []error
	check := func(what, got, want string) {
		if got != want {
			errs = append(errs, fmt.Errorf("record %s %q does not match the bundle's %q", what, got, want))
		}
	}
	check("name", rec.Name, d.Name)
	check("version", rec.Version, d.Version)
	check("source repository", rec.Source.Repository, d.Source.Repository)
	check("source commit", rec.Source.Commit, d.Source.Revision)
	check("manifest digest", rec.ManifestDigest, f.ManifestDigest)
	check("layer digest", rec.LayerDigest, f.LayerDigest)
	check("content digest", rec.ContentDigest, d.ContentDigest())
	for _, t := range rec.Tests.Files {
		i := slices.IndexFunc(d.Files, func(x bundle.File) bool { return x.Path == t.Path })
		switch {
		case i < 0:
			errs = append(errs, fmt.Errorf("record test %s is not in the payload", t.Path))
		case d.Files[i].Role != bundle.RoleTest:
			errs = append(errs, fmt.Errorf("record test %s has role %q, not %q", t.Path, d.Files[i].Role, bundle.RoleTest))
		case d.Files[i].SHA256 != t.SHA256:
			errs = append(errs, fmt.Errorf("record test %s sha256 differs from the payload", t.Path))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	f.Record, f.RecordJSON = rec, rec.Canonical()
	return nil
}

// Load reads a frozen layout directory written by bundlepack and Freeze: it
// verifies the OCI layout end to end (bundle.VerifyLayout) and requires a
// publication record bound to exactly those bytes. Every failure is
// ErrFrozenInputs.
func Load(dir string) (*Frozen, error) {
	f, err := load(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFrozenInputs, dir, err)
	}
	return f, nil
}

func load(dir string) (*Frozen, error) {
	_, manifestDigest, err := bundle.VerifyLayout(dir)
	if err != nil {
		return nil, err
	}
	manifest, err := readBlob(dir, manifestDigest)
	if err != nil {
		return nil, err
	}
	layerDigest, _, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, err
	}
	layer, err := readBlob(dir, layerDigest)
	if err != nil {
		return nil, err
	}
	raw, err := readBounded(filepath.Join(dir, RecordFile))
	if err != nil {
		return nil, fmt.Errorf("publication record: %w (run Freeze first)", err)
	}
	rec, err := ParseRecord(raw)
	if err != nil {
		return nil, err
	}
	return newFrozen(manifest, layer, rec)
}

func readBlob(dir, digest string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")))
	if err != nil {
		return nil, err
	}
	if digestOf(b) != digest {
		return nil, fmt.Errorf("blob %s does not match its digest", digest)
	}
	return b, nil
}

// readBounded reads a regular file of at most MaxRecordBytes.
func readBounded(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, MaxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errNoBytes
	}
	if len(b) > MaxRecordBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, MaxRecordBytes)
	}
	return b, nil
}
