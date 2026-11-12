package controller

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const bundleNS = "konstapel-system"

// fakeHost records what the bundle wiring adds to the manager.
type fakeHost struct {
	c     client.Client
	added []manager.Runnable
}

func (h *fakeHost) Add(r manager.Runnable) error { h.added = append(h.added, r); return nil }
func (h *fakeHost) GetAPIReader() client.Reader  { return h.c }
func (h *fakeHost) GetClient() client.Client     { return h.c }
func (h *fakeHost) GetCache() crcache.Cache      { return nil }
func (h *fakeHost) leader(r manager.Runnable) bool {
	return r.(manager.LeaderElectionRunnable).NeedLeaderElection()
}
func (h *fakeHost) count() int                      { return len(h.added) }
func (h *fakeHost) runnable(i int) manager.Runnable { return h.added[i] }

// readerCache is an unstarted informer cache (for the informer the
// handler is registered on) whose reads come from a fake API server, with a
// hook that observes each read.
type readerCache struct {
	crcache.Cache
	r      client.Reader
	onRead func()
}

func (c *readerCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.onRead != nil {
		c.onRead()
	}
	return c.r.Get(ctx, key, obj, opts...)
}

func (c *readerCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.r.List(ctx, list, opts...)
}

// configCacheFactory builds a real, never started controller-runtime cache
// (no API server is contacted) that reads from c.
func configCacheFactory(t *testing.T, c client.Reader, calls *int, onRead func()) func(crcache.Options) (crcache.Cache, error) {
	return func(o crcache.Options) (crcache.Cache, error) {
		*calls++
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
		o.Scheme, o.Mapper = Scheme(), mapper
		if len(o.ByObject) != 1 {
			t.Fatalf("config cache holds %d types", len(o.ByObject))
		}
		for obj, by := range o.ByObject {
			if _, ok := obj.(*corev1.ConfigMap); !ok || by.Field == nil || by.Field.String() != "metadata.name=konstapel-bundle-sources" {
				t.Fatalf("config cache selects %T %v", obj, by.Field)
			}
		}
		real, err := crcache.New(&rest.Config{Host: "https://127.0.0.1:1"}, o)
		if err != nil {
			return nil, err
		}
		return &readerCache{Cache: real, r: c, onRead: onRead}, nil
	}
}

func enabledOptions(dir string) Options {
	return Options{Content: content, LocalBundle: content.Name, Bundles: stack.Options{SourcesConfigMap: "konstapel-bundle-sources",
		Namespace: bundleNS, CacheDir: filepath.Join(dir, "cache"), ControllerVersion: "0.1.0"}}
}

// Default off: the vendored bundle keeps LocalContent, other names are a
// Config error, and nothing is constructed or added.
func TestBundlesDisabledConstructsNothing(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(Scheme()).Build()
	dir := t.TempDir()
	calls := 0
	for _, tc := range []struct {
		name    string
		opts    Options
		wantErr string
		router  bool
	}{
		{"no local bundle: content as is", Options{Content: content}, "", false},
		{"vendored router", Options{Content: content, LocalBundle: content.Name}, "", true},
		{"half configured", Options{Content: content, LocalBundle: content.Name, Bundles: stack.Options{CacheDir: filepath.Join(dir, "half")}}, "require the bundle sources ConfigMap", false},
		{"enabled without a local bundle", Options{Content: content, Bundles: enabledOptions(dir).Bundles}, "vendored bundle name", false},
		{"enabled without a namespace", func() Options { o := enabledOptions(dir); o.Bundles.Namespace = ""; return o }(), "POD_NAMESPACE", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHost{c: c}
			got, w, err := setupBundles(h, tc.opts, configCacheFactory(t, c, &calls, nil))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if w != nil || h.count() != 0 || calls != 0 {
				t.Fatalf("constructed: wiring %v, %d runnables, %d caches", w != nil, h.count(), calls)
			}
			if tc.wantErr != "" {
				return
			}
			r, isRouter := got.(*stack.Router)
			if isRouter != tc.router {
				t.Fatalf("content %T", got)
			}
			if !tc.router {
				if _, ok := got.(targeting.LocalContent); !ok || !reflect.DeepEqual(got, targeting.ContentSource(content)) {
					t.Fatal("content was replaced")
				}
				return
			}
			if r.Enabled() {
				t.Fatal("router enabled")
			}
			_, err = got.Content(context.Background(), v1alpha1.BundleReference{Name: "org", Digest: "sha256:" + strings.Repeat("a", 64)})
			if targeting.ContentErrorClassOf(err) != targeting.ContentErrorConfig || !errors.Is(err, targeting.ErrContentUnavailable) {
				t.Fatalf("disabled OCI name: %v", err)
			}
			if _, err := got.Content(context.Background(), v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}); err != nil {
				t.Fatalf("vendored: %v", err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("created %v (%v)", entries, err)
	}
}

func sourcesDoc(t *testing.T, names ...string) string {
	var srcs []bundle.BundleSource
	for _, n := range names {
		srcs = append(srcs, bundle.BundleSource{Name: n, Repository: "registry.example.test/bundles/" + n,
			Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "key"},
				KeyFingerprint: strings.Repeat("ab", 32),
				Provenance:     bundle.ProvenanceRule{SourceRepository: "https://github.com/example/bundles", Builder: "https://ci.example.test/build@refs/heads/main"}}})
	}
	b, err := yaml.Marshal(bundle.Sources{Version: bundle.SourcesVersion, Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Enabled: the stack, the dedicated ConfigMap cache, the Watcher (every
// replica), its Trigger (leader) and the Pinner (every replica) are added;
// the Trigger feeds both controller channels; the router is the stack's.
func TestBundlesEnabledWiring(t *testing.T) {
	profile := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "uses-org"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: "org", Digest: "sha256:" + strings.Repeat("a", 64)}}}
	other := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "uses-vendored"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: "sha256:" + strings.Repeat("b", 64)}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: bundleNS, Name: "konstapel-bundle-sources"},
		Data: map[string]string{bundle.SourcesConfigKey: sourcesDoc(t, "org")}}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(profile, other, cm).Build()
	h := &fakeHost{c: c}
	calls := 0
	opts := enabledOptions(t.TempDir())
	got, w, err := setupBundles(h, opts, configCacheFactory(t, c, &calls, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer w.stack.Close()
	if w == nil || calls != 1 || got != targeting.ContentSource(w.router) || !w.router.Enabled() || w.router.LocalName() != content.Name {
		t.Fatalf("wiring %+v, content %T", w, got)
	}
	if _, err := os.Stat(opts.Bundles.CacheDir); err != nil {
		t.Fatalf("cache directory: %v", err)
	}
	want := []struct {
		r      manager.Runnable
		leader bool
	}{{w.configCache, false}, {w.watcher, false}, {w.trigger, true}, {w.pinner, false}}
	if h.count() != len(want) {
		t.Fatalf("%d runnables added", h.count())
	}
	for i, x := range want {
		if h.runnable(i) != x.r || h.leader(x.r) != x.leader {
			t.Fatalf("runnable %d: %T leader=%v, want %T leader=%v", i, h.runnable(i), h.leader(h.runnable(i)), x.r, x.leader)
		}
	}

	// The Trigger turns a configuration change into one event per affected
	// profile on each controller channel.
	if _, err := w.stack.Watcher.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- w.trigger.Start(ctx) }()
	for _, ch := range []chan event.GenericEvent{w.profileEvents, w.bindingEvents} {
		if e := <-ch; e.Object.GetName() != "uses-org" {
			t.Fatalf("event for %s", e.Object.GetName())
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A second process on the same cache directory fails at startup.
	h2 := &fakeHost{c: c}
	if _, _, err := setupBundles(h2, opts, configCacheFactory(t, c, &calls, nil)); err == nil || h2.count() != 0 {
		t.Fatalf("second owner: %v, %d runnables", err, h2.count())
	}
	if _, err := os.Stat(filepath.Join(opts.Bundles.CacheDir, ".lock")); errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no cache lock")
	}
}

// The Watcher starts only after its ConfigMap cache synced; until then it
// reads nothing and serves "not loaded yet".
func TestSyncedWatcherWaitsForTheCache(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: bundleNS, Name: "konstapel-bundle-sources"},
		Data: map[string]string{bundle.SourcesConfigKey: sourcesDoc(t, "org")}}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(cm).Build()
	var mu sync.Mutex
	reads := 0
	read := make(chan struct{}, 1)
	calls := 0
	_, w, err := setupBundles(&fakeHost{c: c}, enabledOptions(t.TempDir()), configCacheFactory(t, c, &calls, func() {
		mu.Lock()
		reads++
		mu.Unlock()
		select {
		case read <- struct{}{}:
		default:
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.stack.Close()

	ctx, cancel := context.WithCancel(context.Background())
	unsynced := &syncedWatcher{w: w.stack.Watcher, synced: func(ctx context.Context) bool { <-ctx.Done(); return false }}
	done := make(chan error)
	go func() { done <- unsynced.Start(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := reads
	mu.Unlock()
	if n != 0 || w.stack.Watcher.State().Revision != 0 {
		t.Fatalf("unsynced watcher read %d times, revision %d", n, w.stack.Watcher.State().Revision)
	}

	ctx, cancel = context.WithCancel(context.Background())
	synced := &syncedWatcher{w: w.stack.Watcher, synced: func(context.Context) bool { return true }}
	go func() { done <- synced.Start(ctx) }()
	<-read
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if synced.NeedLeaderElection() {
		t.Fatal("the watcher must run on every replica")
	}
}

// Both reconcilers get the parameter validator.
func TestTargetingReconcilersValidateParameters(t *testing.T) {
	br, pr := targetingReconcilers(nil, nil, content, nil, "c")
	contract := targeting.PolicySource{ParametersValidated: true}
	for name, v := range map[string]ParameterValidator{"binding": br.ValidateParameters, "profile": pr.ValidateParameters} {
		if v == nil {
			t.Fatalf("%s reconciler has no parameter validator", name)
		}
		if err := v(contract, "p", []byte(`{"x":1}`)); err == nil {
			t.Fatalf("%s: parameters for a policy without a schema accepted", name)
		}
		if err := v(targeting.PolicySource{}, "p", []byte(`{"x":1}`)); err != nil {
			t.Fatalf("%s: content without a contract checked: %v", name, err)
		}
	}
	if !reflect.DeepEqual(br.Content, targeting.ContentSource(content)) || !reflect.DeepEqual(pr.Content, targeting.ContentSource(content)) {
		t.Fatal("reconcilers do not share the content source")
	}
}

// confirming adds an adoption guard to the vendored content.
type confirming struct {
	targeting.ContentSource
	err  error
	refs []v1alpha1.BundleReference
}

func (c *confirming) Confirm(_ context.Context, ref v1alpha1.BundleReference) error {
	c.refs = append(c.refs, ref)
	return c.err
}

// The binding applies only content its source still confirms right before
// the write; a refusal resolves again and writes nothing.
func TestBindingConfirmsContentBeforeApplying(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		applied bool
	}{
		{"confirmed", nil, true},
		{"withdrawn", errors.New("stale: no acceptance under the current revisions"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nsObj("prod", "environment", "production"),
				profileObj(t, "baseline", pol), bindingObj("deny-prod", "baseline", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{"environment": "production"}))
			src := &confirming{ContentSource: content, err: tc.err}
			e.r.Content = src
			res := e.reconcile("deny-prod")
			if got := len(e.policies()) > 0; got != tc.applied {
				t.Fatalf("applied %v", got)
			}
			if len(src.refs) == 0 || src.refs[0] != (v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}) {
				t.Fatalf("confirmed %v", src.refs)
			}
			if !tc.applied && res.RequeueAfter == 0 {
				t.Fatal("a refused apply must resolve again")
			}
		})
	}
}
