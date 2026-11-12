package content

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const repoRoot = "../../.."

var (
	t0      = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fixOnce sync.Once
	fix     *provfixture.Fixtures
	fixErr  error
)

func fixtures(t testing.TB) *provfixture.Fixtures {
	t.Helper()
	fixOnce.Do(func() { fix, fixErr = provfixture.Load() })
	if fixErr != nil {
		t.Fatal(fixErr)
	}
	return fix
}

// revs is a settable resolver configuration; changes follow the
// invalidation protocol (update, then invalidate).
type revs struct {
	mu     sync.Mutex
	src    map[string]bundle.BundleSource
	trust  map[string]string
	compat Compatibility
}

func (r *revs) Source(name string) (bundle.BundleSource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.src[name]
	if !ok {
		return bundle.BundleSource{}, fmt.Errorf("%w: %q", bundle.ErrUnconfigured, name)
	}
	return s, nil
}

func (r *revs) Trust(src bundle.BundleSource) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.trust[src.Name], nil
}

func (r *revs) Compatibility() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.compat.Revision()
}

func (r *revs) check(d *bundle.Descriptor) bundle.ContentCompatibility {
	r.mu.Lock()
	c := r.compat
	r.mu.Unlock()
	return c.Check(d)
}

func (r *revs) edit(f func(r *revs)) { r.mu.Lock(); f(r); r.mu.Unlock() }

// fetcher is a fake registry that can be taken down. failWith, when set,
// is returned instead of the content (to plant error text).
type fetcher struct {
	res      *registry.Result
	down     atomic.Bool
	calls    atomic.Int64
	mu       sync.Mutex
	failWith error
	onFetch  func()
	repos    []string
}

func (f *fetcher) Fetch(_ context.Context, src bundle.BundleSource, digest string) (*registry.Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.repos = append(f.repos, src.Repository)
	fail, hook := f.failWith, f.onFetch
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if fail != nil {
		return nil, fail
	}
	if f.down.Load() {
		return nil, fmt.Errorf("%w: connection refused", registry.ErrUnavailable)
	}
	if f.res == nil || f.res.Digest != digest {
		return nil, registry.ErrNotFound
	}
	return f.res, nil
}

// world is the real resolver over the real cache with the Cosign-signed
// official bundle fixtures and a fake registry.
type world struct {
	t      *testing.T
	f      *provfixture.Fixtures
	dir    string
	cache  *cache.Cache
	reader *kubeaccess.MemoryReader
	revs   *revs
	fetch  *fetcher
	acc    *resolve.Acceptances
	r      *resolve.Resolver
	oci    *OCIContent
	scope  targeting.ScopeFunc
}

// newWorld starts with a cold process over a cache that already holds the
// official bundle and its retained evidence (no acceptance, no lease): the
// first resolution rechecks the evidence offline. Copying one populated
// cache keeps the tests fast under -race; newEmptyWorld starts empty.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := baseWorld(t, t.TempDir())
	copyTree(t, populated(t), w.dir)
	w.open()
	return w
}

// copyTree copies a closed cache directory, keeping every permission (the
// cache checks them; read-only files are written before they are chmodded).
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
			return os.Chmod(dst, 0o700|info.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
		return os.Chmod(dst, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	// Directory permissions last, deepest first, once their files exist.
	for i := len(dirs) - 1; i >= 0; i-- {
		info, err := os.Stat(filepath.Join(from, dirs[i]))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(to, dirs[i]), info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
}

// newEmptyWorld starts with an empty cache.
func newEmptyWorld(t *testing.T) *world {
	t.Helper()
	w := baseWorld(t, t.TempDir())
	w.open()
	return w
}

func baseWorld(t *testing.T, dir string) *world {
	f := fixtures(t)
	return &world{t: t, f: f, dir: dir, reader: f.Reader(), fetch: &fetcher{res: f.Result("sign-org", "prov-valid")},
		revs: &revs{src: map[string]bundle.BundleSource{provfixture.Name: f.Source()}, trust: map[string]string{provfixture.Name: "trust-1"},
			compat: Compatibility{Controller: "0.1.0"}}}
}

var (
	populatedOnce sync.Once
	populatedDir  string
	populatedErr  error
)

// populated is a closed cache directory into which the official bundle was
// retrieved, verified and stored through the real resolver.
func populated(t *testing.T) string {
	t.Helper()
	populatedOnce.Do(func() {
		populatedDir, populatedErr = os.MkdirTemp("", "konstapel-content-cache-")
		if populatedErr != nil {
			return
		}
		w := baseWorld(t, populatedDir)
		w.open()
		if _, populatedErr = w.content(); populatedErr == nil {
			populatedErr = w.cache.Close()
		}
	})
	if populatedErr != nil {
		t.Fatal(populatedErr)
	}
	return populatedDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if populatedDir != "" {
		os.RemoveAll(populatedDir)
	}
	os.Exit(code)
}

// open (re)starts the process: a cache over the same directory with the
// production content check, a new acceptance store and a new OCIContent.
func (w *world) open() {
	w.t.Helper()
	w.acc = resolve.NewAcceptances()
	c, err := cache.Open(w.dir, cache.Config{OnRemove: func(d string) { w.acc.InvalidateDigest(d) }})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	w.cache = c
	v, err := verify.New(w.reader, verify.WithClock(func() time.Time { return t0 }))
	if err != nil {
		w.t.Fatal(err)
	}
	w.r, err = resolve.New(resolve.Config{Cache: c, Fetcher: w.fetch, Verifier: v, Acceptances: w.acc, Revisions: w.revs,
		Compatible: w.revs.check, Now: func() time.Time { return t0 }})
	if err != nil {
		w.t.Fatal(err)
	}
	w.oci, err = New(Config{Resolver: w.r, Entries: c, Scope: w.scope})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) restart() {
	w.t.Helper()
	if err := w.cache.Close(); err != nil {
		w.t.Fatal(err)
	}
	w.open()
}

func (w *world) ref() v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: provfixture.Name, Digest: w.f.Subject}
}

func (w *world) content() (*targeting.Content, error) {
	return w.oci.Content(context.Background(), w.ref())
}

func (w *world) mustContent() *targeting.Content {
	w.t.Helper()
	c, err := w.content()
	if err != nil {
		w.t.Fatal(err)
	}
	noLeases(w.t, w.cache)
	return c
}

func noLeases(t testing.TB, c *cache.Cache) {
	t.Helper()
	if n := c.Stats().Leases; n != 0 {
		t.Fatalf("%d leases held", n)
	}
}

// wantClass checks a classified content error.
func wantClass(t testing.TB, err error, class targeting.ContentErrorClass) *targeting.ContentError {
	t.Helper()
	if err == nil {
		t.Fatalf("succeeded, want %s", class)
	}
	if !errors.Is(err, targeting.ErrContentUnavailable) {
		t.Fatalf("%v is not ErrContentUnavailable", err)
	}
	var ce *targeting.ContentError
	if !errors.As(err, &ce) || ce.Class != class {
		t.Fatalf("%v: class %q, want %q", err, targeting.ContentErrorClassOf(err), class)
	}
	if len(ce.Detail) > maxDetail {
		t.Fatalf("detail of %d bytes", len(ce.Detail))
	}
	return ce
}

// fakeResolver resolves bundles stored in a real cache without
// verification: it stands in for resolve.Resolver for crafted bundles that
// cannot carry real signatures. Leases are real cache leases.
type fakeResolver struct {
	c *cache.Cache
	// substitute, when set, is the digest handed out instead of the request.
	substitute string
	err        error
}

func (r *fakeResolver) Resolve(ctx context.Context, req resolve.Request) (bundle.ResolvedContent, error) {
	if r.err != nil {
		return bundle.ResolvedContent{}, r.err
	}
	digest := req.Digest
	if r.substitute != "" {
		digest = r.substitute
	}
	l, err := r.c.Acquire(digest, req.Holder, req.Owner)
	if err != nil {
		return bundle.ResolvedContent{}, fmt.Errorf("%w: %w", resolve.ErrContentUnavailable, err)
	}
	e, err := r.c.Get(ctx, digest)
	if err != nil {
		_ = r.c.Release(l)
		return bundle.ResolvedContent{}, err
	}
	return bundle.ResolvedContent{Name: e.Descriptor.Name, Digests: bundle.Digests{OCI: digest}, Lease: l}, nil
}

func (r *fakeResolver) Release(h bundle.ResolvedContent) error { return r.c.Release(h.Lease) }

// crafted is a small bundle around the official policy file (with its real
// path and bytes): the given policies extend its policy list and files are
// added. It skips the large NIST documents, so it passes descriptor
// validation but not the content check; crafted bundles are stored without
// it. Version distinguishes digests.
type crafted struct {
	version  string
	policies []bundle.Policy
	files    map[string]string // archive path -> body
	roles    map[string]string // archive path -> role
}

func build(t testing.TB, c crafted) *bundle.Archive {
	t.Helper()
	official, err := os.ReadFile(filepath.Join(repoRoot, assessment.SourcePolicy))
	if err != nil {
		t.Fatal(err)
	}
	src := fstest.MapFS{
		"policy.yaml": {Data: official},
		"cd.json":     {Data: []byte(`{"component-definition":{}}`)},
		"prov.json":   {Data: []byte(`{}`)},
		"LICENSE":     {Data: []byte("license\n")},
	}
	version := c.version
	if version == "" {
		version = "0.1.0"
	}
	def := bundle.Definition{
		Name: provfixture.Name, Version: version,
		Source:        bundle.Source{Repository: provfixture.SourceRepository, Revision: strings.Repeat("c", 40)},
		Policies:      append([]bundle.Policy{pol(assessment.PolicyName, assessment.SourcePolicy)}, c.policies...),
		Scope:         bundle.Scope{Workloads: []string{"Pod"}, OS: []string{"linux"}},
		Compatibility: bundle.Compatibility{Provider: DefaultProvider, Konstapel: "0.1.0"},
		OSCAL:         []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"}},
		Include: []bundle.Include{
			{From: "policy.yaml", To: assessment.SourcePolicy, Role: bundle.RolePolicy},
			{From: "cd.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "prov.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
		},
	}
	for to, body := range c.files {
		from := "crafted/" + to
		src[from] = &fstest.MapFile{Data: []byte(body)}
		def.Include = append(def.Include, bundle.Include{From: from, To: to, Role: c.roles[to]})
	}
	a, err := bundle.Build(def, src, time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// craftedWorld stores crafted archives in a real cache (storage checks
// only) behind a fakeResolver.
type craftedWorld struct {
	cache *cache.Cache
	r     *fakeResolver
	oci   *OCIContent
}

func newCraftedWorld(t *testing.T, scope targeting.ScopeFunc, archives ...*bundle.Archive) *craftedWorld {
	t.Helper()
	c, err := cache.Open(t.TempDir(), cache.Config{CheckContent: func(*bundle.Descriptor, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	for _, a := range archives {
		if _, err := c.Put(context.Background(), a.Manifest, a.Layer); err != nil {
			t.Fatal(err)
		}
	}
	w := &craftedWorld{cache: c, r: &fakeResolver{c: c}}
	w.oci, err = New(Config{Resolver: w.r, Entries: c, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func refOf(a *bundle.Archive) v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: a.Descriptor.Name, Digest: a.ManifestDigest}
}
