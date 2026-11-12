package sources

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

const (
	ns      = "konstapel-system"
	planted = "PLANTED-SECRET-hunter2"
	digestA = "sha256:" + "aa" + "00000000000000000000000000000000000000000000000000000000000000"
)

// key is a throwaway ECDSA P-256 public key in PEM and its fingerprint.
type key struct {
	pem []byte
	fp  string
}

func newKey(t testing.TB) key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return key{pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), fp: hex.EncodeToString(sum[:])}
}

func pkSource(name, keySecret, fp string) bundle.BundleSource {
	return bundle.BundleSource{
		Name: name, Repository: "registry.example.test/bundles/" + name,
		Publisher: bundle.Publisher{
			Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: keySecret}, KeyFingerprint: fp,
			Provenance: bundle.ProvenanceRule{SourceRepository: "https://github.com/example/bundles", Builder: "https://ci.example.test/build@refs/heads/main"},
		},
	}
}

func keylessSource(name string, root *bundle.ObjectRef) bundle.BundleSource {
	return bundle.BundleSource{
		Name: name, Repository: "registry.example.test/bundles/" + name,
		Publisher: bundle.Publisher{
			Type: bundle.SignerKeyless, Issuer: "https://token.actions.githubusercontent.com",
			Identity:  "https://github.com/example/bundles/.github/workflows/release.yml@refs/heads/main",
			TrustRoot: root,
			Provenance: bundle.ProvenanceRule{SourceRepository: "https://github.com/example/bundles",
				Builder: "https://github.com/example/bundles/.github/workflows/release.yml@refs/heads/main"},
		},
	}
}

func doc(t testing.TB, srcs ...bundle.BundleSource) string {
	t.Helper()
	b, err := yaml.Marshal(bundle.Sources{Version: bundle.SourcesVersion, Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// recorder is an Invalidator that records calls.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) Invalidate(kind, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, kind+"/"+name)
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := slices.Clone(r.calls)
	slices.Sort(out)
	r.calls = nil
	return out
}

type fixture struct {
	t     testing.TB
	cfg   client.Client
	objs  *kubeaccess.MemoryReader
	acc   *resolve.Acceptances
	trans *recorder
	w     *Watcher
	keyA  key
	keyB  key
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{t: t, cfg: fake.NewClientBuilder().Build(), objs: kubeaccess.NewMemoryReader(),
		acc: resolve.NewAcceptances(), trans: &recorder{}, keyA: newKey(t), keyB: newKey(t)}
	f.putKey("key-a", f.keyA.pem)
	f.putKey("key-b", f.keyB.pem)
	w, err := New(Options{Namespace: ns, Config: f.cfg, Objects: f.objs, Acceptances: f.acc, Transport: f.trans,
		Compatibility: func() (string, error) { return "compat-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.w = w
	return f
}

func (f *fixture) putKey(name string, pem []byte) {
	f.objs.Put(bundle.KindSecret, name, kubeaccess.NewObject("Opaque", map[string][]byte{bundle.DefaultPublicKey: pem}))
}

func (f *fixture) putCreds(name, password string) {
	cfg := `{"auths":{"registry.example.test":{"username":"reader","password":"` + password + `"}}}`
	f.objs.Put(bundle.KindSecret, name, kubeaccess.NewObject(string(corev1.SecretTypeDockerConfigJson), map[string][]byte{bundle.DefaultCredentialKey: []byte(cfg)}))
}

// setData creates, updates or (data == nil) deletes the sources ConfigMap.
func (f *fixture) setData(data map[string]string) {
	f.t.Helper()
	ctx := context.Background()
	cm := &corev1.ConfigMap{}
	err := f.cfg.Get(ctx, client.ObjectKey{Namespace: ns, Name: DefaultConfigMapName}, cm)
	exists := err == nil
	switch {
	case data == nil && exists:
		err = f.cfg.Delete(ctx, cm)
	case data == nil:
		err = nil
	case exists:
		cm.Data = data
		err = f.cfg.Update(ctx, cm)
	default:
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultConfigMapName}, Data: data}
		err = f.cfg.Create(ctx, cm)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) set(srcs ...bundle.BundleSource) {
	f.t.Helper()
	f.setData(map[string]string{bundle.SourcesConfigKey: doc(f.t, srcs...)})
}

func (f *fixture) sync() Change {
	f.t.Helper()
	ch, err := f.w.Sync(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return ch
}

// accept records an acceptance for name under the current revisions, as
// the resolver would.
func (f *fixture) accept(name, digest string) resolve.Key {
	f.t.Helper()
	tk := f.acc.Begin(name, digest)
	k := f.key(name, digest)
	tk.Key = k
	if err := f.acc.Record(tk, resolve.Acceptance{Key: k}); err != nil {
		f.t.Fatal(err)
	}
	return k
}

// key computes the acceptance key from the current revisions.
func (f *fixture) key(name, digest string) resolve.Key {
	f.t.Helper()
	k, err := f.tryKey(name, digest)
	if err != nil {
		f.t.Fatal(err)
	}
	return k
}

func (f *fixture) tryKey(name, digest string) (resolve.Key, error) {
	src, err := f.w.Source(name)
	if err != nil {
		return resolve.Key{}, err
	}
	rule, err := verify.RuleRevision(src)
	if err != nil {
		return resolve.Key{}, err
	}
	trust, err := f.w.Trust(src)
	if err != nil {
		return resolve.Key{}, err
	}
	compat, err := f.w.Compatibility()
	if err != nil {
		return resolve.Key{}, err
	}
	return resolve.Key{Name: name, Digest: digest, Rule: rule, Trust: trust, Compat: compat}, nil
}

func TestNewValidates(t *testing.T) {
	f := newFixture(t)
	good := Options{Namespace: ns, Config: f.cfg, Objects: f.objs, Acceptances: f.acc, Compatibility: func() (string, error) { return "", nil }}
	for name, mut := range map[string]func(o *Options){
		"namespace":     func(o *Options) { o.Namespace = "" },
		"config":        func(o *Options) { o.Config = nil },
		"objects":       func(o *Options) { o.Objects = nil },
		"acceptances":   func(o *Options) { o.Acceptances = nil },
		"compatibility": func(o *Options) { o.Compatibility = nil },
		"interval":      func(o *Options) { o.Interval = kubeaccess.MaxCacheFor + 1 },
		"negative":      func(o *Options) { o.Interval = -1 },
	} {
		o := good
		mut(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	w, err := New(good)
	if err != nil {
		t.Fatal(err)
	}
	if w.opts.Interval != kubeaccess.DefaultCacheFor || w.opts.Name != DefaultConfigMapName {
		t.Fatalf("defaults %+v", w.opts)
	}
	// Before the first Sync nothing is served.
	if _, err := w.Source("a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("before the first Sync: %v", err)
	}
}

// An invalid, incomplete or removed configuration makes everything
// unavailable as a whole; the previous revision is never served in its
// place, and fixing it recovers.
func TestConfigurationIsAtomic(t *testing.T) {
	f := newFixture(t)
	good := doc(t, pkSource("a", "key-a", f.keyA.fp), pkSource("b", "key-b", f.keyB.fp))
	invalid := doc(t, pkSource("a", "key-a", f.keyA.fp), pkSource("bad", "key-b", "not-a-fingerprint"))
	v2 := strings.Replace(good, "version: 1", "version: 2", 1)

	type step struct {
		name      string
		data      map[string]string // nil: delete
		binary    bool
		available bool
		revision  uint64
		reason    string
	}
	steps := []step{
		{name: "missing", data: nil, revision: 1, reason: "not found"},
		{name: "good", data: map[string]string{bundle.SourcesConfigKey: good}, available: true, revision: 2},
		{name: "unchanged resync", data: map[string]string{bundle.SourcesConfigKey: good}, available: true, revision: 2},
		{name: "invalid entry", data: map[string]string{bundle.SourcesConfigKey: invalid}, revision: 3, reason: "keyFingerprint"},
		{name: "fixed", data: map[string]string{bundle.SourcesConfigKey: good}, available: true, revision: 4},
		{name: "extra key", data: map[string]string{bundle.SourcesConfigKey: good, "other.yaml": "x"}, revision: 5, reason: "unexpected key"},
		{name: "fixed again", data: map[string]string{bundle.SourcesConfigKey: good}, available: true, revision: 6},
		{name: "missing key", data: map[string]string{"sources.yml": good}, revision: 7, reason: "has no"},
		{name: "version 2", data: map[string]string{bundle.SourcesConfigKey: v2}, revision: 8, reason: "version 2"},
		{name: "binaryData", data: map[string]string{bundle.SourcesConfigKey: good}, binary: true, revision: 9, reason: "binaryData"},
		{name: "recovered", data: map[string]string{bundle.SourcesConfigKey: good}, available: true, revision: 10},
		{name: "deleted", data: nil, revision: 11, reason: "not found"},
	}
	// Some steps start from "the ConfigMap does not exist yet"; the first
	// step's state is "not loaded", so it already counts as a change.
	for _, s := range steps {
		f.setData(s.data)
		if s.binary {
			cm := &corev1.ConfigMap{}
			if err := f.cfg.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: DefaultConfigMapName}, cm); err != nil {
				t.Fatal(err)
			}
			cm.BinaryData = map[string][]byte{"x": {1}}
			if err := f.cfg.Update(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
		}
		if s.name == "recovered" {
			cm := &corev1.ConfigMap{}
			_ = f.cfg.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: DefaultConfigMapName}, cm)
			cm.BinaryData = nil
			if err := f.cfg.Update(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
		}
		f.sync()
		st := f.w.State()
		if st.Available != s.available || st.Revision != s.revision || !strings.Contains(st.Reason, s.reason) || len(st.Reason) > maxReason {
			t.Fatalf("%s: state %+v, want available=%v revision=%d reason~%q", s.name, st, s.available, s.revision, s.reason)
		}
		_, srcErr := f.w.Source("a")
		_, trustErr := f.w.Trust(pkSource("a", "key-a", f.keyA.fp))
		if s.available {
			if srcErr != nil || trustErr != nil {
				t.Fatalf("%s: %v / %v", s.name, srcErr, trustErr)
			}
			if st.LastGoodRevision != st.Revision || len(st.Sources.Sources) != 2 {
				t.Fatalf("%s: %+v", s.name, st)
			}
		} else {
			if !errors.Is(srcErr, ErrUnavailable) || !errors.Is(trustErr, ErrUnavailable) {
				t.Fatalf("%s: the previous revision is still served: %v / %v", s.name, srcErr, trustErr)
			}
			if len(st.Sources.Sources) != 0 {
				t.Fatalf("%s: unavailable state carries sources", s.name)
			}
		}
	}
	if st := f.w.State(); st.LastGoodRevision != 10 {
		t.Fatalf("last good revision %d", st.LastGoodRevision)
	}
	// An unconfigured name is ErrUnconfigured, never another source.
	f.set(pkSource("a", "key-a", f.keyA.fp))
	f.sync()
	if _, err := f.w.Source("ab"); !errors.Is(err, bundle.ErrUnconfigured) {
		t.Fatalf("unconfigured: %v", err)
	}
}

// Becoming unavailable drops every acceptance and fails verifications in
// flight; recovering does too.
func TestUnavailabilityInvalidatesEverything(t *testing.T) {
	f := newFixture(t)
	f.set(pkSource("a", "key-a", f.keyA.fp), pkSource("b", "key-b", f.keyB.fp))
	f.sync()
	f.accept("a", digestA)
	f.accept("b", digestA)
	inflight := f.acc.Begin("a", digestA)
	inflight.Key = f.key("a", digestA)

	f.setData(map[string]string{bundle.SourcesConfigKey: "version: 1\nsources: [{name: a}]\n"})
	ch := f.sync()
	if !ch.InvalidatedAll || !slices.Equal(ch.Affected, []string{"a", "b"}) || f.acc.Len() != 0 {
		t.Fatalf("invalid config: %+v, %d acceptances", ch, f.acc.Len())
	}
	if err := f.acc.Record(inflight, resolve.Acceptance{Key: inflight.Key}); !errors.Is(err, resolve.ErrStale) {
		t.Fatalf("in-flight verification recorded under the old configuration: %v", err)
	}
	// Unavailable -> unavailable for another reason: nothing to do.
	f.setData(nil)
	if ch := f.sync(); !ch.Empty() {
		t.Fatalf("unavailable to unavailable: %+v", ch)
	}
	f.set(pkSource("a", "key-a", f.keyA.fp))
	inflight = f.acc.Begin("a", digestA)
	if ch := f.sync(); !ch.InvalidatedAll || !slices.Equal(ch.Affected, []string{"a"}) {
		t.Fatalf("recovery: %+v", ch)
	}
	if err := f.acc.Record(inflight, resolve.Acceptance{Key: f.key("a", digestA)}); !errors.Is(err, resolve.ErrStale) {
		t.Fatalf("verification begun while unavailable was recorded: %v", err)
	}
}

// The trust token is derived from the referenced key or root content only.
func TestTrustToken(t *testing.T) {
	root, err := os.ReadFile("../verify/publicgood/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, root); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	f.putCreds("creds", planted)
	f.objs.Put(bundle.KindConfigMap, "ca", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultCAKey: []byte("not even a certificate")}))
	f.objs.Put(bundle.KindConfigMap, "root", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultTrustRootKey: root}))
	rootRef := &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "root"}

	pk := pkSource("a", "key-a", f.keyA.fp)
	pk.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
	pk.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "ca"}
	f.set(pk, keylessSource("default-root", nil), keylessSource("own-root", rootRef))
	f.sync()
	trust := func(src bundle.BundleSource) (string, error) {
		s, err := f.w.Source(src.Name)
		if err != nil {
			return "", err
		}
		return f.w.Trust(s)
	}
	must := func(src bundle.BundleSource) string {
		t.Helper()
		tok, err := trust(src)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if got := must(pk); got != "public-key:sha256:"+f.keyA.fp {
		t.Fatalf("public-key token %q", got)
	}
	if got := must(keylessSource("default-root", nil)); got != "keyless:sha256:"+verify.PublicGoodTrustRootSHA256 {
		t.Fatalf("default root token %q", got)
	}
	sum := sha256.Sum256(root)
	if got := must(keylessSource("own-root", rootRef)); got != "keyless:sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("own root token %q", got)
	}
	base := must(pk)

	// Credentials, CA and repository do not contribute.
	f.putCreds("creds", "rotated-"+planted)
	f.objs.Put(bundle.KindConfigMap, "ca", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultCAKey: []byte("another CA")}))
	mirror := pk
	mirror.Repository = "mirror.example.test/bundles/a"
	f.set(mirror, keylessSource("default-root", nil), keylessSource("own-root", rootRef))
	f.sync()
	if got := must(mirror); got != base {
		t.Fatalf("credential/CA/mirror changed the trust token: %q -> %q", base, got)
	}
	// Re-encoding the same key (surrounding whitespace) keeps it: the
	// token is the key's fingerprint, like the receipt's TrustRevision.
	f.putKey("key-a", append([]byte("\n\n"), f.keyA.pem...))
	f.sync()
	if got := must(mirror); got != base {
		t.Fatalf("re-encoded key changed the token")
	}
	// Other root bytes change it.
	f.objs.Put(bundle.KindConfigMap, "root", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultTrustRootKey: compact.Bytes()}))
	f.sync()
	csum := sha256.Sum256(compact.Bytes())
	if got := must(keylessSource("own-root", rootRef)); got != "keyless:sha256:"+hex.EncodeToString(csum[:]) {
		t.Fatalf("root bytes changed, token %q", got)
	}

	// Unusable material makes Trust fail; there is no stale token.
	for name, breakIt := range map[string]func(){
		"wrong key": func() { f.putKey("key-a", f.keyB.pem) },
		"missing":   func() { f.objs.Delete(bundle.KindSecret, "key-a") },
		"malformed": func() { f.putKey("key-a", []byte(planted)) },
		"private": func() {
			f.putKey("key-a", []byte("-----BEGIN PRIVATE KEY-----\n"+planted+"\n-----END PRIVATE KEY-----\n"))
		},
		"missing data": func() { f.objs.Put(bundle.KindSecret, "key-a", kubeaccess.NewObject("Opaque", nil)) },
		"unreadable":   func() { f.objs.FailWith(errors.New("apiserver unavailable")) },
	} {
		breakIt()
		ch := f.sync()
		_, err := trust(mirror)
		if !errors.Is(err, ErrTrustUnavailable) {
			t.Fatalf("%s: trust %v", name, err)
		}
		if !slices.Contains(ch.Invalidated, "a") {
			t.Fatalf("%s: the source was not invalidated: %+v", name, ch)
		}
		if strings.Contains(err.Error(), planted) || strings.Contains(f.w.State().Reason, planted) {
			t.Fatalf("%s: secret material in %q", name, err)
		}
		f.objs.FailWith(nil)
		f.putKey("key-a", f.keyA.pem)
		f.sync()
		if got := must(mirror); got != base {
			t.Fatalf("%s: not recovered", name)
		}
	}
	// A source that is not the configured one gets no token.
	other := mirror
	other.Publisher.Provenance.Builder = "https://ci.example.test/other@refs/heads/main"
	if _, err := f.w.Trust(other); !errors.Is(err, ErrTrustUnavailable) {
		t.Fatalf("trust for a source that is not configured now: %v", err)
	}
}

// Each kind of change invalidates exactly what depends on it and reports
// the affected names; transport state is refreshed for changed objects.
func TestInvalidationMatrix(t *testing.T) {
	type world struct {
		f    *fixture
		srcs map[string]bundle.BundleSource
	}
	base := func(f *fixture) map[string]bundle.BundleSource {
		a := pkSource("a", "key-a", f.keyA.fp)
		a.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
		a.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "ca"}
		return map[string]bundle.BundleSource{"a": a, "b": pkSource("b", "key-b", f.keyB.fp)}
	}
	cases := []struct {
		name        string
		change      func(w *world)
		affected    []string
		invalidated []string
		all         bool
		objects     []string
	}{
		{name: "nothing", change: func(*world) {}},
		{name: "unrelated secret", change: func(w *world) { w.f.putCreds("unrelated", "x") }},
		{name: "source added", change: func(w *world) { w.srcs["c"] = pkSource("c", "key-a", w.f.keyA.fp) },
			affected: []string{"c"}, invalidated: []string{"c"}},
		{name: "source removed", change: func(w *world) { delete(w.srcs, "b") },
			affected: []string{"b"}, invalidated: []string{"b"}, objects: []string{"Secret/key-b"}},
		{name: "rule changed", change: func(w *world) {
			s := w.srcs["b"]
			s.Publisher.Provenance.Builder = "https://ci.example.test/other@refs/heads/main"
			w.srcs["b"] = s
		}, affected: []string{"b"}, invalidated: []string{"b"}},
		{name: "trust reference changed", change: func(w *world) {
			w.f.putKey("key-b2", w.f.keyB.pem) // same key, other object
			s := w.srcs["b"]
			s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "key-b2"}
			w.srcs["b"] = s
		}, affected: []string{"b"}, invalidated: []string{"b"}, objects: []string{"Secret/key-b", "Secret/key-b2"}},
		{name: "key rotated (revocation)", change: func(w *world) {
			k := newKey(w.f.t)
			w.f.putKey("key-b", k.pem)
			s := w.srcs["b"]
			s.Publisher.KeyFingerprint = k.fp
			w.srcs["b"] = s
		}, affected: []string{"b"}, invalidated: []string{"b"}, objects: []string{"Secret/key-b"}},
		{name: "key object replaced, rule unchanged", change: func(w *world) { w.f.putKey("key-b", w.f.keyA.pem) },
			affected: []string{"b"}, invalidated: []string{"b"}, objects: []string{"Secret/key-b"}},
		{name: "key re-encoded", change: func(w *world) { w.f.putKey("key-b", append(w.f.keyB.pem, '\n')) },
			affected: []string{"b"}, objects: []string{"Secret/key-b"}},
		{name: "repository only (mirror)", change: func(w *world) {
			s := w.srcs["a"]
			s.Repository = "mirror.example.test/bundles/a"
			w.srcs["a"] = s
		}, affected: []string{"a"}},
		{name: "credential reference changed", change: func(w *world) {
			w.f.putCreds("creds2", "y")
			s := w.srcs["a"]
			s.CredentialSecret = &bundle.ObjectRef{Name: "creds2"}
			w.srcs["a"] = s
		}, affected: []string{"a"}, objects: []string{"Secret/creds", "Secret/creds2"}},
		{name: "credential rotated", change: func(w *world) { w.f.putCreds("creds", "rotated") },
			affected: []string{"a"}, objects: []string{"Secret/creds"}},
		{name: "credential deleted", change: func(w *world) { w.f.objs.Delete(bundle.KindSecret, "creds") },
			affected: []string{"a"}, objects: []string{"Secret/creds"}},
		{name: "CA changed", change: func(w *world) {
			w.f.objs.Put(bundle.KindConfigMap, "ca", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultCAKey: []byte("new CA")}))
		}, affected: []string{"a"}, objects: []string{"ConfigMap/ca"}},
		{name: "CA deleted", change: func(w *world) { w.f.objs.Delete(bundle.KindConfigMap, "ca") },
			affected: []string{"a"}, objects: []string{"ConfigMap/ca"}},
		{name: "configuration deleted", change: func(w *world) { w.srcs = nil },
			affected: []string{"a", "b"}, all: true, objects: []string{"ConfigMap/ca", "Secret/creds", "Secret/key-a", "Secret/key-b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.putCreds("creds", planted)
			f.objs.Put(bundle.KindConfigMap, "ca", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultCAKey: []byte("CA")}))
			w := &world{f: f, srcs: base(f)}
			apply := func() {
				if w.srcs == nil {
					f.setData(nil)
					return
				}
				var list []bundle.BundleSource
				for _, s := range w.srcs {
					list = append(list, s)
				}
				f.set(list...)
			}
			apply()
			f.sync()
			f.trans.take()
			_ = f.w.takePending()
			keys := map[string]resolve.Key{"a": f.accept("a", digestA), "b": f.accept("b", digestA)}

			tc.change(w)
			apply()
			ch := f.sync()
			if !slices.Equal(ch.Affected, tc.affected) || !slices.Equal(ch.Invalidated, tc.invalidated) || ch.InvalidatedAll != tc.all || !slices.Equal(ch.Objects, tc.objects) {
				t.Fatalf("change %+v\nwant affected=%v invalidated=%v all=%v objects=%v", ch, tc.affected, tc.invalidated, tc.all, tc.objects)
			}
			if got := f.trans.take(); !slices.Equal(got, tc.objects) {
				t.Fatalf("transport invalidations %v, want %v", got, tc.objects)
			}
			if got := f.w.takePending(); !slices.Equal(got, tc.affected) {
				t.Fatalf("pending %v, want %v", got, tc.affected)
			}
			for name, k := range keys {
				_, kept := f.acc.Lookup(k)
				dropped := tc.all || slices.Contains(tc.invalidated, name)
				if kept == dropped {
					t.Fatalf("acceptance of %s kept=%v, want dropped=%v", name, kept, dropped)
				}
				// A kept acceptance is still found under the current revisions.
				if kept {
					if cur, err := f.tryKey(name, digestA); err != nil || cur != k {
						t.Fatalf("kept acceptance of %s is not reachable: %v", name, err)
					}
				}
			}
			if strings.Contains(strings.Join(append(ch.Affected, ch.Objects...), ","), planted) || strings.Contains(f.w.State().Reason, planted) {
				t.Fatal("secret material reported")
			}
		})
	}
}

// The protocol: the new state is published before anything is invalidated,
// so a verification never records an acceptance under the old configuration.
func TestPublishBeforeInvalidate(t *testing.T) {
	f := newFixture(t)
	f.set(pkSource("a", "key-a", f.keyA.fp))
	f.sync()
	oldKey := f.key("a", digestA)

	// A verification that read the old revisions before the change.
	early := f.acc.Begin("a", digestA)
	early.Key = oldKey

	// One that begins exactly between publication and invalidation, reads
	// the revisions current then and records.
	var during resolve.Key
	f.w.afterPublish = func() {
		tk := f.acc.Begin("a", digestA)
		k, err := f.tryKey("a", digestA)
		if err != nil {
			t.Error(err)
			return
		}
		tk.Key = k
		during = k
		_ = f.acc.Record(tk, resolve.Acceptance{Key: k})
	}
	k := newKey(t)
	f.putKey("key-c", k.pem)
	f.set(pkSource("a", "key-c", k.fp))
	f.sync()
	f.w.afterPublish = nil

	if during == oldKey {
		t.Fatal("between publication and invalidation the old revisions were still served")
	}
	if _, ok := f.acc.Lookup(oldKey); ok {
		t.Fatal("an acceptance under the old configuration exists")
	}
	if err := f.acc.Record(early, resolve.Acceptance{Key: oldKey}); !errors.Is(err, resolve.ErrStale) {
		t.Fatalf("early verification recorded under the old configuration: %v", err)
	}
}
