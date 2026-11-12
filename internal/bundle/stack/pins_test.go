package stack

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// fakePins records pins and releases.
type fakePins struct {
	mu       sync.Mutex
	held     map[string]int
	fail     map[string]error
	released []string
}

func newFakePins() *fakePins { return &fakePins{held: map[string]int{}, fail: map[string]error{}} }

func (f *fakePins) pin(_ context.Context, ref v1alpha1.BundleReference, holder, owner string) (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := PinKey{holder, owner, ref.Name, ref.Digest}.String()
	if err := f.fail[k]; err != nil {
		return nil, err
	}
	f.held[k]++
	once := sync.Once{}
	return func() error {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.held[k]--
			if f.held[k] == 0 {
				delete(f.held, k)
			}
			f.released = append(f.released, k)
		})
		return nil
	}, nil
}

func (f *fakePins) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k, n := range f.held {
		if n != 1 {
			out = append(out, fmt.Sprintf("%s x%d", k, n))
			continue
		}
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func key(holder, owner, name string) PinKey {
	return PinKey{Holder: holder, Owner: owner, Name: name, Digest: "sha256:" + fmt.Sprintf("%064x", len(name))}
}

func desiredOf(keys ...PinKey) Desired {
	d := Desired{Keys: map[PinKey]bool{}, Unknown: map[string]bool{}}
	for _, k := range keys {
		d.Keys[k] = true
	}
	return d
}

func strs(keys ...PinKey) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, k.String())
	}
	slices.Sort(out)
	return out
}

// Set semantics: missing pins are acquired, stale ones released, holders
// whose state is unknown keep theirs, failures are retried, and a new
// Pinner (a restart: leases are in memory) re-pins everything.
func TestPinnerSetSemantics(t *testing.T) {
	ctx := context.Background()
	a := key(bundle.HolderProfile, "profile/a", "bundle-a")
	b := key(bundle.HolderApplied, "binding/b", "bundle-b")
	c := key(bundle.HolderAssessment, "run/c", "bundle-c")
	b2 := key(bundle.HolderProfile, "profile/b", "bundle-b")
	f := newFakePins()
	var want Desired
	p := &Pinner{Pin: f.pin, Desired: func(context.Context) (Desired, error) { return want, nil }}

	steps := []struct {
		name    string
		desired Desired
		fail    map[string]error
		held    []string
		wantErr bool
	}{
		{"initial", desiredOf(a, b), nil, strs(a, b), false},
		{"idempotent", desiredOf(a, b), nil, strs(a, b), false},
		{"replace a by c, same bundle for two owners", desiredOf(b, c, b2), nil, strs(b, b2, c), false},
		{"applied unknown keeps its pins", Desired{Keys: map[PinKey]bool{c: true}, Unknown: map[string]bool{bundle.HolderApplied: true}}, nil, strs(b, c), false},
		{"failure is retried", desiredOf(a, c), map[string]error{a.String(): errors.New("registry down")}, strs(c), true},
		{"recovered", desiredOf(a, c), nil, strs(a, c), false},
		{"empty releases everything", desiredOf(), nil, []string{}, false},
	}
	for _, s := range steps {
		want = s.desired
		f.fail = s.fail
		if f.fail == nil {
			f.fail = map[string]error{}
		}
		err := p.Reconcile(ctx)
		if (err != nil) != s.wantErr {
			t.Fatalf("%s: error %v", s.name, err)
		}
		got := f.keys()
		if got == nil {
			got = []string{}
		}
		if !slices.Equal(got, s.held) {
			t.Fatalf("%s: cache holds %v, want %v", s.name, got, s.held)
		}
		if held := strs(p.Held()...); !slices.Equal(held, s.held) {
			t.Fatalf("%s: pinner holds %v, want %v", s.name, held, s.held)
		}
	}

	// A failed desired-state read changes nothing.
	want = desiredOf(a)
	if err := p.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	p.Desired = func(context.Context) (Desired, error) { return Desired{}, errors.New("cache not synced") }
	if err := p.Reconcile(ctx); err == nil || !slices.Equal(f.keys(), strs(a)) {
		t.Fatalf("read failure: %v, holds %v", err, f.keys())
	}

	// Restart: the old process's leases are gone; a new Pinner re-pins.
	f2 := newFakePins()
	p2 := &Pinner{Pin: f2.pin, Desired: func(context.Context) (Desired, error) { return desiredOf(a, b), nil }}
	if err := p2.Reconcile(ctx); err != nil || !slices.Equal(f2.keys(), strs(a, b)) {
		t.Fatalf("re-pin after restart: %v, %v", err, f2.keys())
	}
}

// Start: subscribes to events, runs a pass at once and on each kick, and
// releases everything when it stops. Ordering uses the pass hook, never
// sleeps.
func TestPinnerRun(t *testing.T) {
	a := key(bundle.HolderProfile, "profile/a", "bundle-a")
	b := key(bundle.HolderProfile, "profile/b", "bundle-b")
	f := newFakePins()
	var mu sync.Mutex
	want := desiredOf(a)
	var kick func()
	p := &Pinner{Pin: f.pin, Resync: time.Hour,
		Desired: func(context.Context) (Desired, error) { mu.Lock(); defer mu.Unlock(); return want, nil },
		Events:  func(_ context.Context, k func()) error { kick = k; return nil }}
	if p.NeedLeaderElection() {
		t.Fatal("the pinner must run on every replica")
	}
	passes := make(chan struct{})
	p.SetPassHook(passes)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- p.Start(ctx) }()
	<-passes
	if !slices.Equal(f.keys(), strs(a)) {
		t.Fatalf("startup pass holds %v", f.keys())
	}
	mu.Lock()
	want = desiredOf(b)
	mu.Unlock()
	kick()
	<-passes
	if !slices.Equal(f.keys(), strs(b)) {
		t.Fatalf("after a kick holds %v", f.keys())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(f.keys()) != 0 {
		t.Fatalf("stopping kept %v", f.keys())
	}
	// A failed subscription fails Start.
	p2 := &Pinner{Pin: f.pin, Desired: p.Desired, Events: func(context.Context, func()) error { return errors.New("no informer") }}
	if err := p2.Start(context.Background()); err == nil {
		t.Fatal("started without its event subscription")
	}
}

// craftedArchive builds a small bundle with an incompressible data file of
// size n, so a few entries put a small cache under capacity pressure.
func craftedArchive(t testing.TB, version string, n int) *bundle.Archive {
	t.Helper()
	official, err := os.ReadFile(filepath.Join(RepoRoot, assessment.SourcePolicy))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	src := fstest.MapFS{
		"policy.yaml": {Data: official},
		"cd.json":     {Data: []byte(`{"component-definition":{}}`)},
		"prov.json":   {Data: []byte(`{}`)},
		"LICENSE":     {Data: []byte("license\n")},
		"data.bin":    {Data: data},
	}
	def := bundle.Definition{
		Name: "crafted", Version: version,
		Source:        bundle.Source{Repository: "https://github.com/backend-bunny/Konstapel", Revision: string(bytes.Repeat([]byte("c"), 40))},
		Policies:      []bundle.Policy{{Name: assessment.PolicyName, Path: assessment.SourcePolicy, Checks: []bundle.Check{{RuleID: "r", CheckID: "c"}}}},
		Scope:         bundle.Scope{Workloads: []string{"Pod"}, OS: []string{"linux"}},
		Compatibility: bundle.Compatibility{Provider: "konstapel-kyverno/v1", Konstapel: "0.1.0"},
		OSCAL:         []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"}},
		Include: []bundle.Include{
			{From: "policy.yaml", To: assessment.SourcePolicy, Role: bundle.RolePolicy},
			{From: "cd.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "prov.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
			{From: "data.bin", To: "content/data.bin", Role: bundle.RoleUpstream},
		},
	}
	a, err := bundle.Build(def, src, time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The Pinner's leases interact with eviction in a real cache: a pinned
// entry survives capacity pressure, the least recently used unpinned entry
// is evicted, and releasing a pin makes its entry evictable.
func TestPinsProtectContentFromEviction(t *testing.T) {
	ctx := context.Background()
	const size = 1 << 20
	lim := cache.Limits{MaxManifestBytes: 64 << 10, MaxCompressedBytes: 2 << 20, MaxUnpackedBytes: 4 << 20, MaxFiles: 64,
		MaxDescriptorBytes: 64 << 10, MaxPathBytes: 1024, MaxNameBytes: 255, MaxDepth: 32, MaxProofBytes: 64 << 10}
	lim.CapacityBytes = 7 << 20 // room for three entries (~2 MiB each), not four
	removed := map[string]bool{}
	var mu sync.Mutex
	c, err := cache.Open(t.TempDir(), cache.Config{Limits: lim, CheckContent: func(*bundle.Descriptor, string) error { return nil },
		OnRemove: func(d string) { mu.Lock(); removed[d] = true; mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	archives := map[string]*bundle.Archive{}
	put := func(v string) string {
		t.Helper()
		a := craftedArchive(t, v, size)
		if _, err := c.Put(ctx, a.Manifest, a.Layer); err != nil {
			t.Fatalf("put %s: %v", v, err)
		}
		archives[v] = a
		return a.ManifestDigest
	}
	pinFn := func(_ context.Context, ref v1alpha1.BundleReference, holder, owner string) (func() error, error) {
		l, err := c.Acquire(ref.Digest, holder, owner)
		if err != nil {
			return nil, err
		}
		return func() error { return c.Release(l) }, nil
	}
	var want Desired
	p := &Pinner{Pin: pinFn, Desired: func(context.Context) (Desired, error) { return want, nil }}
	present := func(d string) bool {
		_, err := c.Get(ctx, d)
		return err == nil
	}

	dA, dB := put("1.0.0"), put("1.0.1")
	pinA := PinKey{bundle.HolderProfile, "profile/a", "crafted", dA}
	want = desiredOf(pinA)
	if err := p.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	present(dB) // B is now more recently used than A: LRU would pick A
	dC := put("1.0.2")
	dD := put("1.0.3") // over capacity: the unpinned LRU (B) goes, pinned A stays
	mu.Lock()
	gotRemoved := removed[dB] && !removed[dA]
	mu.Unlock()
	if !gotRemoved || !present(dA) || present(dB) || !present(dC) || !present(dD) {
		t.Fatalf("pinned A present %v, B evicted %v (removed %v)", present(dA), !present(dB), removed)
	}

	want = desiredOf()
	if err := p.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Stats().Leases != 0 {
		t.Fatal("release left a lease")
	}
	present(dC)
	present(dD)
	put("1.0.4") // A, now released and least recently used, is evicted
	if present(dA) {
		t.Fatal("released entry survived capacity pressure")
	}
}

// ClusterState derives the pin set from profiles, applied engine policies
// and active assessment runs, skipping the vendored bundle.
func TestClusterStateDesired(t *testing.T) {
	d1, d2, d3 := "sha256:"+fmt.Sprintf("%064x", 1), "sha256:"+fmt.Sprintf("%064x", 2), "sha256:"+fmt.Sprintf("%064x", 3)
	vp := func(name, binding, bundleName, digest string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
		u.SetName(name)
		u.SetLabels(map[string]string{targeting.LabelManagedBy: targeting.ManagedByValue})
		u.SetAnnotations(map[string]string{targeting.AnnotationBinding: binding, targeting.AnnotationBundle: bundleName, targeting.AnnotationBundleDigest: digest})
		return u
	}
	unmanaged := vp("foreign", "x", "org", d3)
	unmanaged.SetLabels(nil)
	run := func(name, binding string, phase v1alpha1.RunPhase) *v1alpha1.AssessmentRun {
		return &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: binding}}, Status: v1alpha1.AssessmentRunStatus{Phase: phase}}
	}
	objs := []client.Object{
		&v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "p-org"}, Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: "org", Digest: d2}}},
		&v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "p-vendored"}, Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: VendoredName, Digest: d1}}},
		&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "b-org"}, Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "p-org"}}},
		&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "b-vendored"}, Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "p-vendored"}}},
		vp("applied-old", "b-org", "org", d1), vp("applied-old-2", "b-org", "org", d1), vp("applied-vendored", "b-vendored", VendoredName, d1), unmanaged,
		run("r-collecting", "b-org", v1alpha1.RunCollecting), run("r-new", "b-org", ""), run("r-done", "b-org", v1alpha1.RunCompleted),
		run("r-publishing", "b-org", v1alpha1.RunPublishing), run("r-vendored", "b-vendored", v1alpha1.RunPending),
	}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(targeting.ValidatingPolicyGVK, meta.RESTScopeRoot)
	for _, k := range []string{"ComplianceBinding", "ComplianceProfile", "AssessmentRun"} {
		mapper.Add(v1alpha1.GroupVersion.WithKind(k), meta.RESTScopeRoot)
	}
	c := fake.NewClientBuilder().WithScheme(SchemeForTests()).WithRESTMapper(mapper).WithObjects(objs...).Build()
	got, err := ClusterState{Client: c, Engine: c, Local: VendoredName}.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := strs(
		PinKey{bundle.HolderProfile, "profile/p-org", "org", d2},
		PinKey{bundle.HolderApplied, "binding/b-org", "org", d1},
		PinKey{bundle.HolderAssessment, "run/r-collecting", "org", d2},
		PinKey{bundle.HolderAssessment, "run/r-new", "org", d2},
	)
	if g := strs(slices.Collect(mapsKeys(got.Keys))...); !slices.Equal(g, want) || len(got.Unknown) != 0 {
		t.Fatalf("desired %v (unknown %v), want %v", g, got.Unknown, want)
	}

	for _, tc := range []struct {
		name    string
		err     error
		unknown bool
	}{
		{"engine API not served", &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "policies.kyverno.io", Kind: "ValidatingPolicy"}}, false},
		{"engine read failed", errors.New("forbidden"), true},
	} {
		engine := interceptor.NewClient(fake.NewClientBuilder().WithScheme(SchemeForTests()).Build().(client.WithWatch), interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error { return tc.err }})
		got, err := ClusterState{Client: c, Engine: engine, Local: VendoredName}.Desired(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.Unknown[bundle.HolderApplied] != tc.unknown {
			t.Fatalf("%s: unknown %v", tc.name, got.Unknown)
		}
		for k := range got.Keys {
			if k.Holder == bundle.HolderApplied {
				t.Fatalf("%s: applied pin %v", tc.name, k)
			}
		}
	}
	broken := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, l client.ObjectList, o ...client.ListOption) error {
			if _, ok := l.(*v1alpha1.ComplianceProfileList); ok {
				return errors.New("cache not synced")
			}
			return cl.List(ctx, l, o...)
		}})
	got, _ = ClusterState{Client: broken, Engine: c, Local: VendoredName}.Desired(context.Background())
	if !got.Unknown[bundle.HolderProfile] || !got.Unknown[bundle.HolderAssessment] || got.Unknown[bundle.HolderApplied] {
		t.Fatalf("profile read failure: unknown %v", got.Unknown)
	}
}

func mapsKeys(m map[PinKey]bool) func(func(PinKey) bool) {
	return func(yield func(PinKey) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
