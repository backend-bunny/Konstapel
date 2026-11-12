package stack

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func TestOptionsValidate(t *testing.T) {
	ok := Options{SourcesConfigMap: "konstapel-bundle-sources", Namespace: "konstapel-system", CacheDir: "/var/cache/konstapel/bundles"}
	for _, tc := range []struct {
		name string
		edit func(*Options)
		want string // "" valid
	}{
		{"disabled zero value", func(o *Options) { *o = Options{} }, ""},
		{"disabled with a namespace and version only", func(o *Options) { *o = Options{Namespace: "x", ControllerVersion: "dev"} }, ""},
		{"disabled with a cache dir", func(o *Options) { *o = Options{CacheDir: "/x"} }, "require the bundle sources ConfigMap"},
		{"disabled with a capacity", func(o *Options) { *o = Options{CacheCapacity: 1 << 30} }, "require the bundle sources ConfigMap"},
		{"disabled with a refresh", func(o *Options) { *o = Options{RefreshInterval: time.Minute} }, "require the bundle sources ConfigMap"},
		{"enabled", func(*Options) {}, ""},
		{"namespace required", func(o *Options) { o.Namespace = "" }, "controller namespace (POD_NAMESPACE)"},
		{"namespace invalid", func(o *Options) { o.Namespace = "Bad_NS" }, "controller namespace"},
		{"cache dir required", func(o *Options) { o.CacheDir = "" }, "cache directory"},
		{"cache dir absolute", func(o *Options) { o.CacheDir = "relative/dir" }, "must be absolute"},
		{"configmap name invalid", func(o *Options) { o.SourcesConfigMap = "Not/A/Name" }, "ConfigMap name"},
		{"capacity too small", func(o *Options) { o.CacheCapacity = 1 << 20 }, "cannot hold one maximal entry"},
		{"capacity negative", func(o *Options) { o.CacheCapacity = -1 }, "must not be negative"},
		{"capacity large", func(o *Options) { o.CacheCapacity = 4 << 30 }, ""},
		{"refresh at max", func(o *Options) { o.RefreshInterval = MaxRefreshInterval }, ""},
		{"refresh above max", func(o *Options) { o.RefreshInterval = MaxRefreshInterval + time.Second }, "refresh interval"},
		{"refresh negative", func(o *Options) { o.RefreshInterval = -time.Second }, "refresh interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := ok
			tc.edit(&o)
			err := o.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A disabled or invalid configuration constructs nothing: no cache
// directory appears.
func TestNewCreatesNothingWhenDisabledOrInvalid(t *testing.T) {
	base := t.TempDir()
	c := NewWorld(t).Client
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"disabled", Options{CacheDir: filepath.Join(base, "disabled")}},
		{"no namespace", Options{SourcesConfigMap: TestConfigMap, CacheDir: filepath.Join(base, "no-namespace")}},
		{"bad refresh", Options{SourcesConfigMap: TestConfigMap, Namespace: TestNamespace, CacheDir: filepath.Join(base, "bad-refresh"), RefreshInterval: time.Hour}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := New(tc.opts, Deps{APIReader: c, Config: c}); err == nil {
				s.Close()
				t.Fatal("constructed")
			}
			if _, err := os.Stat(tc.opts.CacheDir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("cache directory created: %v", err)
			}
		})
	}
	if _, err := New(Options{SourcesConfigMap: TestConfigMap, Namespace: TestNamespace, CacheDir: filepath.Join(base, "deps")}, Deps{}); err == nil {
		t.Fatal("constructed without readers")
	}
	if _, err := os.Stat(filepath.Join(base, "deps")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cache directory created without readers")
	}
}

// Startup fails fast, with the reason, when the cache cannot be opened.
func TestNewFailsWhenTheCacheCannotBeOpened(t *testing.T) {
	w := NewWorld(t)
	t.Run("held by another owner", func(t *testing.T) {
		_, err := New(w.Opts, w.Deps)
		if err == nil || !strings.Contains(err.Error(), "bundle cache "+w.Opts.CacheDir) {
			t.Fatalf("second owner of the cache: %v", err)
		}
	})
	t.Run("unwritable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0o700) })
		o := w.Opts
		o.CacheDir = filepath.Join(parent, "cache")
		if _, err := New(o, w.Deps); err == nil || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("unwritable cache directory: %v", err)
		}
	})
}

// The wired stack resolves the signed fixture through the Watcher, the
// real verifier and the cache, and holds no lease afterwards.
func TestStackResolvesThroughTheWatcher(t *testing.T) {
	w := NewWorld(t)
	r := w.Stack.Router(LocalContent(), VendoredName)
	c, err := r.Content(context.Background(), w.Ref())
	if err != nil {
		t.Fatal(err)
	}
	if c.Bundle.Name != FixtureName || c.Bundle.Digest != w.Fix.Subject || len(c.Policies) == 0 {
		t.Fatalf("content %+v", c.Bundle)
	}
	if w.Leases() != 0 || w.Stack.Acceptances.Len() != 1 {
		t.Fatalf("%d leases, %d acceptances", w.Leases(), w.Stack.Acceptances.Len())
	}
	if err := r.Confirm(context.Background(), w.Ref()); err != nil {
		t.Fatalf("confirm after resolution: %v", err)
	}
}

// The cache's OnRemove is wired to the acceptance store: an entry removed
// because it is found corrupt drops its acceptance.
func TestCacheRemovalInvalidatesAcceptances(t *testing.T) {
	w := NewWorld(t)
	if _, err := w.Stack.Content.Content(context.Background(), w.Ref()); err != nil {
		t.Fatal(err)
	}
	if w.Stack.Acceptances.Len() != 1 {
		t.Fatal("no acceptance")
	}
	corruptEntry(t, w.Opts.CacheDir)
	if _, err := w.Stack.Cache.Get(context.Background(), w.Fix.Subject); err == nil {
		t.Fatal("corrupt entry served")
	}
	if n := w.Stack.Acceptances.Len(); n != 0 {
		t.Fatalf("%d acceptances survive the removal of their entry", n)
	}
}

// corruptEntry changes one extracted payload file of the cached entry.
func corruptEntry(t testing.TB, dir string) {
	t.Helper()
	done := false
	err := filepath.WalkDir(filepath.Join(dir, "content"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || done || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		if err := os.Chmod(p, 0o600); err != nil {
			return err
		}
		done = true
		return os.WriteFile(p, []byte("tampered: true\n"), 0o600)
	})
	if err != nil || !done {
		t.Fatalf("corrupting the entry: %v (found %v)", err, done)
	}
}

// A development build (version not SemVer) starts; OCI bundles are a
// configuration error and the vendored bundle is unaffected.
func TestDevelopmentVersionDoesNotFailStartup(t *testing.T) {
	w := NewWorld(t)
	o := w.Opts
	o.CacheDir = filepath.Join(t.TempDir(), "dev")
	o.ControllerVersion = "dev"
	s, err := New(o, w.Deps)
	if err != nil {
		t.Fatalf("startup with a development version: %v", err)
	}
	defer s.Close()
	if s.CompatibilityProblem() == nil {
		t.Fatal("no compatibility problem reported for a non-SemVer version")
	}
	if _, err := s.Watcher.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := s.Router(LocalContent(), VendoredName)
	_, err = r.Content(context.Background(), w.Ref())
	if targeting.ContentErrorClassOf(err) != targeting.ContentErrorConfig {
		t.Fatalf("OCI content with a development version: %v", err)
	}
	if _, err := r.Content(context.Background(), vendoredRef(t)); err != nil {
		t.Fatalf("vendored content with a development version: %v", err)
	}
}

func vendoredRef(t testing.TB) v1alpha1.BundleReference {
	t.Helper()
	sums, err := os.ReadFile(filepath.Join(RepoRoot, "content", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	return v1alpha1.BundleReference{Name: VendoredName, Digest: "sha256:" + hexSum(sums)}
}

// fakeSource counts calls and serves fixed content.
type fakeSource struct {
	calls int
	err   error
}

func (f *fakeSource) Content(_ context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &targeting.Content{Bundle: targeting.Bundle{Name: ref.Name, Digest: ref.Digest, Policies: []targeting.BundlePolicy{{Name: "p"}}},
		Policies: map[string]targeting.PolicySource{"p": {Manifest: map[string]any{"spec": map[string]any{"rules": []any{"a"}}}, SourceDigest: "sha256:x"}}}, nil
}

func TestRouter(t *testing.T) {
	ctx := context.Background()
	local := LocalContent()
	vref := vendoredRef(t)
	oref := v1alpha1.BundleReference{Name: "org-bundle", Digest: "sha256:" + strings.Repeat("a", 64)}

	t.Run("vendored bundle is served by LocalContent unchanged", func(t *testing.T) {
		want, err := local.Content(ctx, vref)
		if err != nil {
			t.Fatal(err)
		}
		oci := &fakeSource{}
		for _, r := range []*Router{NewRouter(local, VendoredName), newRouter(local, VendoredName, oci, func(string, string) error { return nil })} {
			got, err := r.Content(ctx, vref)
			if err == nil {
				// LocalContent lists policies in map order.
				sortPolicies(got)
				sortPolicies(want)
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("vendored content differs: %v", err)
			}
			wrong := vref
			wrong.Digest = oref.Digest
			_, gotErr := r.Content(ctx, wrong)
			_, wantErr := local.Content(ctx, wrong)
			if gotErr == nil || gotErr.Error() != wantErr.Error() {
				t.Fatalf("vendored error %v, LocalContent's %v", gotErr, wantErr)
			}
			if err := r.Confirm(ctx, vref); err != nil {
				t.Fatalf("vendored confirm: %v", err)
			}
		}
		if oci.calls != 0 {
			t.Fatal("the vendored name reached the OCI source")
		}
	})

	t.Run("disabled: other names are a Config error", func(t *testing.T) {
		r := NewRouter(local, VendoredName)
		if r.Enabled() {
			t.Fatal("enabled")
		}
		for _, err := range []error{func() error { _, err := r.Content(ctx, oref); return err }(), r.Confirm(ctx, oref)} {
			var ce *targeting.ContentError
			if !errors.As(err, &ce) || ce.Class != targeting.ContentErrorConfig || !errors.Is(err, targeting.ErrContentUnavailable) ||
				!errors.Is(err, resolve.ErrConfig) || !strings.Contains(ce.Detail, "no source is configured") {
				t.Fatalf("disabled: %v", err)
			}
		}
	})

	t.Run("enabled: other names go to OCI content", func(t *testing.T) {
		oci := &fakeSource{}
		r := newRouter(local, VendoredName, oci, func(string, string) error { return nil })
		c, err := r.Content(ctx, oref)
		if err != nil || c.Bundle.Name != oref.Name || oci.calls != 1 {
			t.Fatalf("routed: %v, %d calls", err, oci.calls)
		}
	})

	t.Run("memo is served only while confirmed", func(t *testing.T) {
		oci := &fakeSource{}
		var confirmErr error
		r := newRouter(local, VendoredName, oci, func(string, string) error { return confirmErr })
		first, _ := r.Content(ctx, oref)
		first.Policies["p"].Manifest["spec"].(map[string]any)["rules"].([]any)[0] = "mutated"
		second, err := r.Content(ctx, oref)
		if err != nil || oci.calls != 1 {
			t.Fatalf("memo not used: %v, %d calls", err, oci.calls)
		}
		if second.Policies["p"].Manifest["spec"].(map[string]any)["rules"].([]any)[0] != "a" {
			t.Fatal("a caller's change reached the memo")
		}
		second.Policies["p"].Manifest["spec"].(map[string]any)["rules"].([]any)[0] = "mutated"
		if third, _ := r.Content(ctx, oref); third.Policies["p"].Manifest["spec"].(map[string]any)["rules"].([]any)[0] != "a" {
			t.Fatal("a memo hit shares state with its caller")
		}
		confirmErr = resolve.ErrStale
		oci.err = &targeting.ContentError{Class: targeting.ContentErrorUntrusted}
		if _, err := r.Content(ctx, oref); targeting.ContentErrorClassOf(err) != targeting.ContentErrorUntrusted || oci.calls != 2 {
			t.Fatalf("memo served past an invalidation: %v", err)
		}
		if r.MemoLen() != 0 {
			t.Fatal("failed resolution kept its memo entry")
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		confirmErr, oci.err = nil, nil
		if _, err := r.Content(ctx, oref); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Content(cctx, oref); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled context served from the memo: %v", err)
		}
	})

	t.Run("memo is bounded", func(t *testing.T) {
		r := newRouter(local, VendoredName, &fakeSource{}, func(string, string) error { return nil })
		for i := 0; i < memoSize+5; i++ {
			ref := oref
			ref.Digest = "sha256:" + strings.Repeat(string(rune('a'+i%26)), 63) + string(rune('a'+i/26))
			if _, err := r.Content(ctx, ref); err != nil {
				t.Fatal(err)
			}
		}
		if r.MemoLen() != memoSize {
			t.Fatalf("%d memo entries", r.MemoLen())
		}
	})
}

// With the real stack: trust revocation, configuration loss and a removed
// cache entry are seen at once despite the memo.
func TestRouterMemoFollowsInvalidations(t *testing.T) {
	ctx := context.Background()
	w := NewWorld(t)
	r := w.Stack.Router(LocalContent(), VendoredName)
	mustResolve := func(step string) {
		t.Helper()
		if _, err := r.Content(ctx, w.Ref()); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if r.MemoLen() != 1 {
			t.Fatalf("%s: not memoized", step)
		}
	}
	mustResolve("first")
	calls := w.Fetch.Calls.Load()
	mustResolve("memo hit")
	if w.Fetch.Calls.Load() != calls {
		t.Fatal("memo hit fetched")
	}

	w.SetSources(w.OtherSource())
	w.Sync()
	if _, err := r.Content(ctx, w.Ref()); targeting.ContentErrorClassOf(err) != targeting.ContentErrorUntrusted {
		t.Fatalf("revoked trust: %v", err)
	}
	if err := r.Confirm(ctx, w.Ref()); err == nil {
		t.Fatal("confirmed revoked content")
	}

	w.SetSources(w.OrgSource())
	w.Sync()
	mustResolve("restored")
	w.DeleteSources()
	w.Sync()
	if _, err := r.Content(ctx, w.Ref()); targeting.ContentErrorClassOf(err) != targeting.ContentErrorConfig {
		t.Fatalf("configuration deleted: %v", err)
	}

	w.SetSources(w.OrgSource())
	w.Sync()
	mustResolve("restored again")
	w.Fetch.Down.Store(true)
	corruptEntry(t, w.Opts.CacheDir)
	if _, err := w.Stack.Cache.Get(ctx, w.Fix.Subject); err == nil {
		t.Fatal("corrupt entry served")
	}
	if _, err := r.Content(ctx, w.Ref()); targeting.ContentErrorClassOf(err) != targeting.ContentErrorContentUnavailable {
		t.Fatalf("removed entry with the registry down: %v", err)
	}
}

func sortPolicies(c *targeting.Content) {
	slices.SortFunc(c.Bundle.Policies, func(a, b targeting.BundlePolicy) int { return strings.Compare(a.Name, b.Name) })
}
