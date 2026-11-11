package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const repoRoot = "../../.."

var (
	officialOnce sync.Once
	officialArch *bundle.Archive
	officialErr  error
)

// official builds the checked-in privileged-container bundle once.
func official(t testing.TB) *bundle.Archive {
	t.Helper()
	officialOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join(repoRoot, "bundles/konstapel-privileged-containers/definition.json"))
		if err != nil {
			officialErr = err
			return
		}
		def, err := bundle.LoadDefinition(raw)
		if err != nil {
			officialErr = err
			return
		}
		def.Source.Revision = strings.Repeat("c", 40)
		officialArch, officialErr = bundle.Build(def, os.DirFS(repoRoot), time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	})
	if officialErr != nil {
		t.Fatal(officialErr)
	}
	return officialArch
}

// ent is one crafted tar entry. typ defaults to a regular file; size < 0
// means len(body).
type ent struct {
	name string
	typ  byte
	body []byte
	link string
	mode int64
}

func mktar(t testing.TB, format tar.Format, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Typeflag: typ, Name: e.name, Linkname: e.link, Mode: mode, Format: format, ModTime: time.Unix(0, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gz compresses b as one gzip member; modTime varies the layer digest.
func gz(t testing.TB, b []byte, modTime int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Header = gzip.Header{OS: 255}
	if modTime != 0 {
		zw.ModTime = time.Unix(modTime, 0)
	}
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// manifestFor is the bundle manifest for layer, as bundle.Build writes it;
// annotations give distinct manifests for the same layer.
func manifestFor(t testing.TB, layer []byte, annotations map[string]string) []byte {
	t.Helper()
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"artifactType":  bundle.ArtifactType,
		"config":        map[string]any{"mediaType": bundle.EmptyConfigMediaType, "digest": bundle.EmptyConfigDigest, "size": 2},
		"layers":        []any{map[string]any{"mediaType": bundle.LayerMediaType, "digest": digest(layer), "size": len(layer)}},
	}
	if annotations != nil {
		m["annotations"] = annotations
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// variant is the small bundle 0 under a different layer and manifest
// digest (same tar, different gzip header time).
func variant(t testing.TB, i int) (manifest, layer []byte) {
	t.Helper()
	layer = gz(t, mktar(t, tar.FormatPAX, filesOf(t, small(t, 0))...), int64(1000+i))
	return manifestFor(t, layer, nil), layer
}

// small builds a minimal valid bundle (descriptor validation only; it is
// not meant to pass the content check) whose version, and so every digest,
// depends on i. Storage tests use it to stay fast; the official bundle
// covers the real content.
func small(t testing.TB, i int) *bundle.Archive {
	t.Helper()
	src := fstest.MapFS{
		"policy.yaml": {Data: []byte(fmt.Sprintf("kind: ValidatingPolicy # %d\n", i))},
		"cd.json":     {Data: []byte(`{"component-definition":{}}`)},
		"prov.json":   {Data: []byte(`{}`)},
		"LICENSE":     {Data: []byte("license\n")},
		"deep.txt":    {Data: bytes.Repeat([]byte("payload "), 512)},
	}
	def := bundle.Definition{
		Name: "small", Version: fmt.Sprintf("1.0.%d", i),
		Source:        bundle.Source{Repository: "https://example.invalid/repo", Revision: strings.Repeat("a", 40)},
		Policies:      []bundle.Policy{{Name: "p", Path: "content/policies/p.yaml", Checks: []bundle.Check{{RuleID: "r", CheckID: "c"}}}},
		Scope:         bundle.Scope{Workloads: []string{"Pod"}, OS: []string{"linux"}},
		Compatibility: bundle.Compatibility{Provider: "kyverno/v1", Konstapel: "0.1.0"},
		OSCAL:         []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"}},
		Include: []bundle.Include{
			{From: "policy.yaml", To: "content/policies/p.yaml", Role: bundle.RolePolicy},
			{From: "cd.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "prov.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{From: "deep.txt", To: "content/upstream/a/b/c/deep.txt", Role: bundle.RoleUpstream},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
		},
	}
	a, err := bundle.Build(def, src, time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// filesOf returns an archive's payload in archive order.
func filesOf(t testing.TB, a *bundle.Archive) []ent {
	t.Helper()
	_, files, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	var out []ent
	for name, f := range files {
		out = append(out, ent{name: name, body: append([]byte(nil), f.Data...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// noCheck skips the content check where a test is about storage only.
func noCheck(*bundle.Descriptor, string) error { return nil }

// env is a cache root beside unrelated files that must never change.
type env struct {
	parent, root, unrelated string
}

func newEnv(t testing.TB) env {
	t.Helper()
	parent := t.TempDir()
	e := env{parent: parent, root: filepath.Join(parent, "cache"), unrelated: filepath.Join(parent, "unrelated")}
	must(t, os.MkdirAll(filepath.Join(e.unrelated, "dir"), 0o755))
	must(t, os.WriteFile(filepath.Join(e.unrelated, "file"), []byte("unrelated"), 0o644))
	must(t, os.WriteFile(filepath.Join(e.unrelated, "dir", "x"), []byte("x"), 0o600))
	must(t, os.Symlink("../unrelated/file", filepath.Join(parent, "link")))
	return e
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e env) open(t testing.TB, cfg Config) *Cache {
	t.Helper()
	c, err := Open(e.root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// snapshot records every name under the parent directory (the cache root,
// unrelated files and a symlink) with type, mode, size and content hash.
// Directory modification times are excluded: creating and removing a
// staging directory is allowed to touch staging/'s mtime.
func (e env) snapshot(t testing.TB) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(e.parent, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(e.parent, p)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		desc := info.Mode().String()
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			desc += " -> " + l
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			desc += fmt.Sprintf(" %d %s %d", len(b), digest(b), info.ModTime().UnixNano())
		}
		out[rel] = desc
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(t testing.TB, before, after map[string]string) {
	t.Helper()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("changed: %s: %q -> %q", k, v, after[k])
		}
	}
	for k, v := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("added: %s (%s)", k, v)
		}
	}
}

// assertIdle checks that no reservation leaked and staging is empty.
func assertIdle(t testing.TB, c *Cache) {
	t.Helper()
	if s := c.Stats(); s.ReservedBytes != 0 {
		t.Errorf("reservation leaked: %d", s.ReservedBytes)
	}
	left, err := os.ReadDir(filepath.Join(c.dir, stagingDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("staging not cleaned: %v", left)
	}
}

// faultFS wraps the real filesystem, logging every operation and injecting
// failures: a hook before each operation, a byte quota that yields ENOSPC,
// and a crash after which every operation fails (cleanup included), as if
// the process had died.
type faultFS struct {
	fileSystem
	mu      sync.Mutex
	ops     []string
	hook    func(op, name string) error
	quota   int64 // < 0: unlimited
	written int64
	crashAt int // mutating operation number that "kills" the process; 0: never
	mutates int
	crashed bool
}

var errCrashed = fmt.Errorf("simulated crash")

func newFaultFS(inner fileSystem) *faultFS { return &faultFS{fileSystem: inner, quota: -1} }

func (f *faultFS) before(op, name string, mutating bool) error {
	f.mu.Lock()
	f.ops = append(f.ops, op+" "+name)
	if f.crashed {
		f.mu.Unlock()
		return errCrashed
	}
	if mutating {
		f.mutates++
		if f.crashAt > 0 && f.mutates >= f.crashAt {
			f.crashed = true
			f.mu.Unlock()
			return errCrashed
		}
	}
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		return hook(op, name)
	}
	return nil
}

func (f *faultFS) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func (f *faultFS) Mkdir(name string, perm fs.FileMode) error {
	if err := f.before("mkdir", name, true); err != nil {
		return err
	}
	return f.fileSystem.Mkdir(name, perm)
}

func (f *faultFS) Create(name string, perm fs.FileMode) (writer, error) {
	if err := f.before("create", name, true); err != nil {
		return nil, err
	}
	w, err := f.fileSystem.Create(name, perm)
	if err != nil {
		return nil, err
	}
	return &faultWriter{w: w, f: f, name: name}, nil
}

func (f *faultFS) Open(name string) (fs.File, error) {
	if err := f.before("open", name, false); err != nil {
		return nil, err
	}
	return f.fileSystem.Open(name)
}

func (f *faultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := f.before("readdir", name, false); err != nil {
		return nil, err
	}
	return f.fileSystem.ReadDir(name)
}

func (f *faultFS) Lstat(name string) (fs.FileInfo, error) {
	if err := f.before("lstat", name, false); err != nil {
		return nil, err
	}
	return f.fileSystem.Lstat(name)
}

func (f *faultFS) Rename(oldname, newname string) error {
	if err := f.before("rename", oldname+" -> "+newname, true); err != nil {
		return err
	}
	return f.fileSystem.Rename(oldname, newname)
}

func (f *faultFS) RemoveAll(name string) error {
	if err := f.before("removeall", name, true); err != nil {
		return err
	}
	return f.fileSystem.RemoveAll(name)
}

func (f *faultFS) SyncDir(name string) error {
	if err := f.before("syncdir", name, true); err != nil {
		return err
	}
	return f.fileSystem.SyncDir(name)
}

type faultWriter struct {
	w    writer
	f    *faultFS
	name string
}

func (w *faultWriter) Write(p []byte) (int, error) {
	if err := w.f.before("write", w.name, true); err != nil {
		return 0, err
	}
	w.f.mu.Lock()
	n := int64(len(p))
	full := false
	if w.f.quota >= 0 && w.f.written+n > w.f.quota {
		n, full = w.f.quota-w.f.written, true
	}
	w.f.written += n
	w.f.mu.Unlock()
	k, err := w.w.Write(p[:n])
	if err == nil && full {
		err = &fs.PathError{Op: "write", Path: w.name, Err: syscall.ENOSPC}
	}
	return k, err
}

func (w *faultWriter) Sync() error {
	if err := w.f.before("sync", w.name, true); err != nil {
		return err
	}
	return w.w.Sync()
}

func (w *faultWriter) Close() error {
	err := w.f.before("close", w.name, false)
	if cerr := w.w.Close(); err == nil {
		err = cerr
	}
	return err
}

func withFault(f **faultFS) func(fileSystem) fileSystem {
	return func(inner fileSystem) fileSystem {
		*f = newFaultFS(inner)
		return *f
	}
}

func bg() context.Context { return context.Background() }

// readTree reads every regular file under dir.
func readTree(t testing.TB, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	must(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = b
		return err
	}))
	return out
}

var _ = io.EOF
