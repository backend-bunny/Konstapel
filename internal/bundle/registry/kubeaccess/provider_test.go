package kubeaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

type harness struct {
	objs  *MemoryReader
	clock *fakeClock
	reset *recordingResetter
	p     *Provider
	src   bundle.BundleSource
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{objs: NewMemoryReader(), clock: &fakeClock{now: time.Unix(1_800_000_000, 0)}, reset: &recordingResetter{}}
	p, err := New(Options{Reader: h.objs, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	p.Bind(h.reset)
	h.p = p
	h.src = bundle.BundleSource{Name: sourceName, Repository: host + "/" + repoPath, CredentialSecret: &bundle.ObjectRef{Name: secretName}}
	return h
}

func (h *harness) put(doc []byte) { h.objs.Put(bundle.KindSecret, secretName, dockerSecret(doc)) }

func (h *harness) cred(t *testing.T) (registry.Credential, error) {
	t.Helper()
	c, err := h.p.Credential(context.Background(), h.src, host)
	assertNoSecrets(t, err)
	return c, err
}

func TestProviderAnonymousSource(t *testing.T) {
	h := newHarness(t)
	h.src.CredentialSecret = nil
	c, err := h.cred(t)
	if err != nil || c != (registry.Credential{}) {
		t.Fatalf("want the zero credential, got %v", err)
	}
	if h.objs.Reads(bundle.KindSecret, secretName) != 0 {
		t.Fatal("an anonymous source read a Secret")
	}
}

func TestProviderFailures(t *testing.T) {
	good := dockerConfig(host, user, password)
	for _, tc := range []struct {
		name  string
		setup func(h *harness)
		host  string
		want  error
	}{
		{"missing Secret", func(h *harness) {}, host, ErrObjectNotFound},
		{"missing key", func(h *harness) {
			h.objs.Put(bundle.KindSecret, secretName, NewObject(string(corev1.SecretTypeDockerConfigJson), map[string][]byte{"other": good}))
		}, host, registry.ErrCredentials},
		{"custom key missing", func(h *harness) {
			h.put(good)
			h.src.CredentialSecret.Key = "config.json"
		}, host, registry.ErrCredentials},
		{"wrong Secret type", func(h *harness) {
			h.objs.Put(bundle.KindSecret, secretName, NewObject(string(corev1.SecretTypeOpaque), map[string][]byte{corev1.DockerConfigJsonKey: good}))
		}, host, registry.ErrCredentials},
		{"empty value", func(h *harness) { h.put(nil) }, host, ErrMalformedCredentials},
		{"no entry for the host", func(h *harness) { h.put(dockerConfig("other.example", user, password)) }, host, ErrNoCredentialForHost},
		{"helper document", func(h *harness) { h.put([]byte(`{"auths":{},"credsStore":"desktop"}`)) }, host, ErrMalformedCredentials},
		{"asked for another host", func(h *harness) { h.put(dockerConfig("other.example", user, password)) }, "other.example", registry.ErrCredentials},
		{"API error", func(h *harness) { h.objs.FailWith(errors.New("etcdserver: request timed out")) }, host, registry.ErrCredentials},
		{"not a Secret", func(h *harness) {
			h.put(good)
			h.src.CredentialSecret.Kind = bundle.KindConfigMap
		}, host, registry.ErrCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h)
			c, err := h.p.Credential(context.Background(), h.src, tc.host)
			if !errors.Is(err, tc.want) || !errors.Is(err, registry.ErrCredentials) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if c != (registry.Credential{}) {
				t.Fatal("a credential was returned with an error")
			}
			assertNoSecrets(t, err)
		})
	}
}

func TestProviderRequiresBinding(t *testing.T) {
	objs := NewMemoryReader()
	objs.Put(bundle.KindSecret, secretName, dockerSecret(dockerConfig(host, user, password)))
	p, err := New(Options{Reader: objs})
	if err != nil {
		t.Fatal(err)
	}
	src := bundle.BundleSource{Name: sourceName, Repository: host + "/" + repoPath, CredentialSecret: &bundle.ObjectRef{Name: secretName}}
	if _, err := p.Credential(context.Background(), src, host); !errors.Is(err, registry.ErrCredentials) {
		t.Fatalf("an unbound provider released a credential: %v", err)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("no reader accepted")
	}
	if _, err := New(Options{Reader: objs, CacheFor: time.Hour}); err == nil {
		t.Fatal("unbounded cache accepted")
	}
}

func TestProviderRotation(t *testing.T) {
	h := newHarness(t)
	h.put(dockerConfig(host, user, password))
	c, err := h.cred(t)
	if err != nil || c.Password != password {
		t.Fatalf("first read: %v", err)
	}
	if h.reset.n() != 0 {
		t.Fatal("tokens reset on the first credential")
	}

	// Rotated, but the change is not observed yet: the cached read is used.
	h.put(dockerConfig(host, user, "rotated-"+password))
	if c, _ := h.cred(t); c.Password != password {
		t.Fatal("a cached read was not reused within CacheFor")
	}
	// An unchanged re-read does not reset tokens.
	h.p.Invalidate(bundle.KindSecret, "unrelated")
	if h.reset.n() != 0 {
		t.Fatal("unexpected reset")
	}

	// Invalidate: the new credential is used and tokens are reset once.
	h.p.Invalidate(bundle.KindSecret, secretName)
	if c, _ := h.cred(t); c.Password != "rotated-"+password {
		t.Fatal("the rotated credential was not used after Invalidate")
	}
	if h.reset.n() != 1 {
		t.Fatalf("resets %d, want 1", h.reset.n())
	}
	// Same content again (re-read after expiry): no reset.
	h.clock.advance(DefaultCacheFor)
	if c, _ := h.cred(t); c.Password != "rotated-"+password || h.reset.n() != 1 {
		t.Fatalf("resets %d after an unchanged re-read", h.reset.n())
	}
	if got := h.objs.Reads(bundle.KindSecret, secretName); got != 3 {
		t.Fatalf("reads %d, want 3", got)
	}

	// Rotation observed by expiry alone.
	h.put(dockerConfig(host, user, "third-"+password))
	h.clock.advance(DefaultCacheFor - time.Second)
	if c, _ := h.cred(t); c.Password != "rotated-"+password {
		t.Fatal("expired early")
	}
	h.clock.advance(time.Second)
	if c, _ := h.cred(t); c.Password != "third-"+password || h.reset.n() != 2 {
		t.Fatalf("expiry: resets %d", h.reset.n())
	}

	// Removal: an error (never the old credential, never anonymous) and a
	// reset; repeated failures do not reset again.
	h.objs.Delete(bundle.KindSecret, secretName)
	h.p.Invalidate(bundle.KindSecret, secretName)
	if c, err := h.cred(t); !errors.Is(err, ErrObjectNotFound) || c != (registry.Credential{}) {
		t.Fatalf("removed Secret: %v", err)
	}
	if h.reset.n() != 3 {
		t.Fatalf("resets %d after removal, want 3", h.reset.n())
	}
	if _, err := h.cred(t); err == nil || h.reset.n() != 3 {
		t.Fatalf("second failure: %v, resets %d", err, h.reset.n())
	}
	// Emptied rather than deleted behaves the same.
	h.put(dockerConfig(host, user, password))
	if _, err := h.cred(t); err != nil {
		t.Fatal(err)
	}
	h.put([]byte(`{"auths":{}}`))
	h.p.InvalidateAll()
	if _, err := h.cred(t); !errors.Is(err, ErrNoCredentialForHost) || h.reset.n() != 4 {
		t.Fatalf("emptied Secret: %v, resets %d", err, h.reset.n())
	}
}

func TestProviderNoCaching(t *testing.T) {
	objs := NewMemoryReader()
	objs.Put(bundle.KindSecret, secretName, dockerSecret(dockerConfig(host, user, password)))
	p, err := New(Options{Reader: objs, CacheFor: -1})
	if err != nil {
		t.Fatal(err)
	}
	p.Bind(&recordingResetter{})
	src := bundle.BundleSource{Name: sourceName, Repository: host + "/" + repoPath, CredentialSecret: &bundle.ObjectRef{Name: secretName}}
	for range 3 {
		if _, err := p.Credential(context.Background(), src, host); err != nil {
			t.Fatal(err)
		}
	}
	if objs.Reads(bundle.KindSecret, secretName) != 3 {
		t.Fatal("reads were cached with CacheFor < 0")
	}
}

// TestInvalidateDuringRead: an invalidation that races with a read forces the
// next use to read again.
func TestInvalidateDuringRead(t *testing.T) {
	h := newHarness(t)
	h.put(dockerConfig(host, user, password))
	blocking := &blockingReader{MemoryReader: h.objs, entered: make(chan struct{}), release: make(chan struct{})}
	h.p.reader = blocking
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.p.Credential(context.Background(), h.src, host)
	}()
	<-blocking.entered
	h.put(dockerConfig(host, user, "rotated-"+password))
	h.p.Invalidate(bundle.KindSecret, secretName)
	close(blocking.release)
	<-done
	blocking.disable()
	if c, _ := h.cred(t); c.Password != "rotated-"+password {
		t.Fatal("a read that raced with Invalidate was reused")
	}
}

type blockingReader struct {
	*MemoryReader
	entered, release chan struct{}
	once             sync.Once
	mu               sync.Mutex
	off              bool
}

func (b *blockingReader) disable() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.off = true
}

func (b *blockingReader) Get(ctx context.Context, kind, name string) (Object, error) {
	o, err := b.MemoryReader.Get(ctx, kind, name)
	b.mu.Lock()
	off := b.off
	b.mu.Unlock()
	if !off {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return o, err
}

func TestProviderConcurrentRotation(t *testing.T) {
	h := newHarness(t)
	h.put(dockerConfig(host, user, "p-0-"+password))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				if i == 0 && j%5 == 0 {
					h.put(dockerConfig(host, user, fmt.Sprintf("p-%d-%s", j, password)))
					h.p.Invalidate(bundle.KindSecret, secretName)
				}
				c, err := h.p.Credential(context.Background(), h.src, host)
				if err != nil || !strings.HasSuffix(c.Password, password) {
					t.Errorf("credential: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	h.p.Invalidate(bundle.KindSecret, secretName)
	if c, _ := h.cred(t); c.Password != "p-45-"+password {
		t.Fatal("the last rotation is not current")
	}
	// Every observed change reset tokens; there were at most 9 rotations.
	if n := h.reset.n(); n < 1 || n > 9 {
		t.Fatalf("resets %d", n)
	}
}

func TestRedaction(t *testing.T) {
	cred := registry.Credential{Username: user, Password: password, IdentityToken: idToken, RegistryToken: regToken}
	obj := dockerSecret(dockerConfig(host, user, password))
	type holder struct {
		C registry.Credential
		O Object
	}
	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "cred", cred, "obj", obj)
	js, _ := json.Marshal(holder{cred, obj})
	outputs := []string{logs.String(), string(js)}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		outputs = append(outputs, fmt.Sprintf(verb, cred), fmt.Sprintf(verb, obj),
			fmt.Sprintf(verb, holder{cred, obj}), fmt.Sprintf(verb, &holder{cred, obj}), fmt.Sprintf(verb, []any{cred, obj}))
	}
	for _, out := range outputs {
		for _, v := range append([]string{user}, secretValues...) {
			if strings.Contains(out, v) || strings.Contains(out, fmt.Sprintf("%x", v)) || strings.Contains(out, fmt.Sprintf("%X", v)) {
				t.Fatalf("formatted output discloses a credential value: %s", out)
			}
		}
	}
}

func TestClientReader(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: secretName},
			Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte("doc")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "stolen"}, Data: map[string][]byte{"k": []byte("v")}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: caName},
			Data: map[string]string{"ca.crt": "pem"}, BinaryData: map[string][]byte{"bin": {1}}},
	).Build()
	r, err := NewClientReader(c, "konstapel-system")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := r.Get(ctx, bundle.KindSecret, secretName)
	if v, _ := s.Value(corev1.DockerConfigJsonKey); err != nil || s.Type() != string(corev1.SecretTypeDockerConfigJson) || string(v) != "doc" {
		t.Fatalf("secret: %v", err)
	}
	cm, err := r.Get(ctx, bundle.KindConfigMap, caName)
	if v, _ := cm.Value("ca.crt"); err != nil || string(v) != "pem" {
		t.Fatalf("configmap: %v", err)
	}
	if v, ok := cm.Value("bin"); !ok || len(v) != 1 {
		t.Fatal("binaryData missing")
	}
	// Another namespace is unreachable: references carry no namespace.
	if _, err := r.Get(ctx, bundle.KindSecret, "stolen"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("another namespace was read: %v", err)
	}
	if _, err := r.Get(ctx, "Pod", "x"); err == nil {
		t.Fatal("unsupported kind accepted")
	}
	if _, err := NewClientReader(nil, "konstapel-system"); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := NewClientReader(c, ""); err == nil {
		t.Fatal("empty namespace accepted")
	}
}
