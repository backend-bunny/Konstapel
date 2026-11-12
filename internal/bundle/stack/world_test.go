package stack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/sources"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Shared fixtures for this package's tests and the stack_test end-to-end
// tests (exported so the external test package can use them).

const (
	// TestNamespace is the controller namespace of the test worlds.
	TestNamespace = "konstapel-system"
	// TestConfigMap is the sources ConfigMap name.
	TestConfigMap = "konstapel-bundle-sources"
	// VendoredName is the vendored bundle's name in tests.
	VendoredName = "konstapel-vendored"
)

// RepoRoot is the repository root, relative to this package.
var RepoRoot = filepath.Join("..", "..", "..")

// TestT0 is the fixed clock of the test worlds.
var TestT0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

var (
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

// LocalContent is the vendored content source the controller uses.
func LocalContent() targeting.LocalContent {
	return targeting.LocalContent{Root: filepath.Join(RepoRoot, "content"), Name: VendoredName, Policies: assessment.ShippedPolicies}
}

// FakeFetcher serves the Cosign-signed fixture bundle; it can be taken down.
type FakeFetcher struct {
	Res   *registry.Result
	Down  atomic.Bool
	Calls atomic.Int64
}

// Fetch implements resolve.Fetcher.
func (f *FakeFetcher) Fetch(_ context.Context, _ bundle.BundleSource, digest string) (*registry.Result, error) {
	f.Calls.Add(1)
	if f.Down.Load() {
		return nil, fmt.Errorf("%w: connection refused", registry.ErrUnavailable)
	}
	if f.Res.Digest != digest {
		return nil, registry.ErrNotFound
	}
	return f.Res, nil
}

// SchemeForTests has the core and Konstapel types.
func SchemeForTests() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		panic(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		panic(err)
	}
	return s
}

// World is the real stack (cache, verifier, acceptances, Watcher, resolver
// and OCI content) over a fake API server holding the sources ConfigMap and
// the fixture's public keys, with the signed fixture bundle behind a fake
// registry.
type World struct {
	T      testing.TB
	Fix    *provfixture.Fixtures
	Client client.Client
	Fetch  *FakeFetcher
	Stack  *Stack
	Opts   Options
	Deps   Deps
}

// NewWorld builds a World with the organization-key rule configured and
// synced. The cache lives in a fresh temporary directory.
func NewWorld(t testing.TB) *World {
	t.Helper()
	f := fixtures(t)
	c := fake.NewClientBuilder().WithScheme(SchemeForTests()).WithObjects(
		keySecret("org", f.PubOrg), keySecret("other", f.PubOther)).Build()
	w := &World{T: t, Fix: f, Client: c, Fetch: &FakeFetcher{Res: f.Result("sign-org", "prov-valid")},
		Opts: Options{SourcesConfigMap: TestConfigMap, Namespace: TestNamespace, CacheDir: filepath.Join(t.TempDir(), "cache"),
			ControllerVersion: "0.1.0"}}
	w.Deps = WithTestClock(WithTestFetcher(Deps{APIReader: c, Config: c}, w.Fetch), func() time.Time { return TestT0 })
	w.SetSources(w.OrgSource())
	w.Open()
	return w
}

// Open builds the stack (again, as after a restart) and syncs it.
func (w *World) Open() {
	w.T.Helper()
	s, err := New(w.Opts, w.Deps)
	if err != nil {
		w.T.Fatal(err)
	}
	w.T.Cleanup(func() { _ = s.Close() })
	w.Stack = s
	w.Sync()
}

// Restart closes the stack and opens a new one over the same directory.
func (w *World) Restart() {
	w.T.Helper()
	if err := w.Stack.Close(); err != nil {
		w.T.Fatal(err)
	}
	w.Open()
}

func keySecret(name string, pub []byte) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: TestNamespace, Name: name},
		Data: map[string][]byte{bundle.DefaultPublicKey: pub}}
}

// OrgSource is the rule trusting the organization key the fixture is signed with.
func (w *World) OrgSource() bundle.BundleSource { return w.Fix.Source() }

// OtherSource is the same rule naming another key: trust revoked.
func (w *World) OtherSource() bundle.BundleSource {
	s := w.Fix.Source()
	s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "other"}
	s.Publisher.KeyFingerprint = w.Fix.FPOther
	return s
}

// SetSources writes the sources ConfigMap (call Sync to apply it).
func (w *World) SetSources(srcs ...bundle.BundleSource) {
	w.T.Helper()
	doc, err := yaml.Marshal(bundle.Sources{Version: bundle.SourcesVersion, Sources: srcs})
	if err != nil {
		w.T.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: TestNamespace, Name: TestConfigMap},
		Data: map[string]string{bundle.SourcesConfigKey: string(doc)}}
	ctx := context.Background()
	if err := w.Client.Update(ctx, cm); err != nil {
		if err := w.Client.Create(ctx, cm); err != nil {
			w.T.Fatal(err)
		}
	}
}

// DeleteSources deletes the sources ConfigMap.
func (w *World) DeleteSources() {
	w.T.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: TestNamespace, Name: TestConfigMap}}
	if err := w.Client.Delete(context.Background(), cm); err != nil {
		w.T.Fatal(err)
	}
}

// Sync applies the current cluster state to the Watcher.
func (w *World) Sync() sources.Change {
	w.T.Helper()
	ch, err := w.Stack.Watcher.Sync(context.Background())
	if err != nil {
		w.T.Fatal(err)
	}
	return ch
}

// Ref is the fixture bundle's reference.
func (w *World) Ref() v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: provfixture.Name, Digest: w.Fix.Subject}
}

// Leases reports the cache's leases.
func (w *World) Leases() int { return w.Stack.Cache.Stats().Leases }

// FixtureName is the fixture bundle's name.
const FixtureName = provfixture.Name

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
