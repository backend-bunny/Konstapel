package kubeaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// env is a provider and client against one TLS fake registry whose CA is
// held in a ConfigMap and whose credential is held in a Secret.
type env struct {
	ca     testCA
	f      *fakeRegistry
	objs   *MemoryReader
	p      *Provider
	c      *registry.Client
	src    bundle.BundleSource
	pinned string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca := newTestCA(t, "registry")
	e := &env{ca: ca, f: newFakeRegistry(t, ca), objs: NewMemoryReader()}
	var err error
	// A long cache: rotations here are observed through Invalidate only.
	e.p, err = New(Options{Reader: e.objs, CacheFor: MaxCacheFor, SystemRoots: poolWith()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.p.Close)
	e.c, err = NewClient(e.p, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.objs.Put(bundle.KindConfigMap, caName, caObject(ca.pem))
	e.src = e.f.source()
	e.src.CredentialSecret = &bundle.ObjectRef{Name: secretName}
	e.src.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: caName}
	e.pinned = e.f.digest.String()
	return e
}

func (e *env) putCred(user, pass string) {
	e.objs.Put(bundle.KindSecret, secretName, dockerSecret(dockerConfig(e.f.host(), user, pass)))
}

func (e *env) rotate(user, pass string) {
	e.putCred(user, pass)
	e.p.Invalidate(bundle.KindSecret, secretName)
}

func (e *env) fetch(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := e.c.Fetch(ctx, e.src, e.pinned)
	if err == nil && res.Digest != e.pinned {
		t.Fatal("wrong content")
	}
	return err
}

// assertNoLeak checks every rendering of err for the given values.
func assertNoLeak(t *testing.T, err error, values ...string) {
	t.Helper()
	if err == nil {
		return
	}
	out := fmt.Sprintf("%s %v %+v %#v %q", err, err, err, err, err)
	for _, v := range values {
		if strings.Contains(out, v) || strings.Contains(out, b64(user+":"+v)) {
			t.Fatalf("error discloses a credential: %s", out)
		}
	}
}

func TestFetchWithSecretCredentials(t *testing.T) {
	e := newEnv(t)
	e.f.setValid(map[string]string{user: password})
	e.putCred(user, password)
	if err := e.fetch(t); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.f.seen() {
		if r.authz != "" && r.authz != "Basic "+b64(user+":"+password) {
			t.Fatalf("unexpected Authorization on %s", r.path)
		}
	}
}

func TestFetchMissingConfiguredCredential(t *testing.T) {
	for name, setup := range map[string]func(e *env){
		"missing Secret": func(*env) {},
		"missing key": func(e *env) {
			e.objs.Put(bundle.KindSecret, secretName, NewObject("kubernetes.io/dockerconfigjson", map[string][]byte{"x": nil}))
		},
		"no entry for the host": func(e *env) {
			e.objs.Put(bundle.KindSecret, secretName, dockerSecret(dockerConfig("evil-"+e.f.host(), user, password)))
		},
		"credential helper only": func(e *env) {
			e.objs.Put(bundle.KindSecret, secretName, dockerSecret([]byte(`{"auths":{},"credsStore":"desktop"}`)))
		},
		"malformed": func(e *env) {
			e.objs.Put(bundle.KindSecret, secretName, dockerSecret([]byte(`{"auths":{"`+e.f.host()+`":{"auth":"`+b64(user+password)+`"}}}`)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t) // anonymous registry: a fallback would succeed
			setup(e)
			err := e.fetch(t)
			if !errors.Is(err, registry.ErrCredentials) {
				t.Fatalf("want ErrCredentials, got %v", err)
			}
			if n := len(e.f.seen()); n != 0 {
				t.Fatalf("%d requests reached the registry", n)
			}
			assertNoLeak(t, err, password)
		})
	}
}

func TestFetchInvalidCA(t *testing.T) {
	e := newEnv(t)
	e.putCred(user, password)
	e.objs.Put(bundle.KindConfigMap, caName, caObject([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")))
	if err := e.fetch(t); !errors.Is(err, registry.ErrTrustConfig) || !errors.Is(err, ErrMalformedCA) {
		t.Fatalf("want ErrTrustConfig, got %v", err)
	}
	if len(e.f.seen()) != 0 {
		t.Fatal("a request was sent without the configured trust")
	}
}

func TestFetchRotationAfterWrongPassword(t *testing.T) {
	e := newEnv(t)
	e.f.setValid(map[string]string{user: password})
	e.putCred(user, "wrong-"+password)
	err := e.fetch(t)
	if !errors.Is(err, registry.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	assertNoLeak(t, err, "wrong-"+password, password)
	// Same client, rotated Secret.
	e.rotate(user, password)
	if err := e.fetch(t); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	// Removal: an error, no request, never the old credential.
	before := len(e.f.seen())
	e.objs.Delete(bundle.KindSecret, secretName)
	e.p.Invalidate(bundle.KindSecret, secretName)
	if err := e.fetch(t); !errors.Is(err, registry.ErrCredentials) {
		t.Fatalf("removed Secret: %v", err)
	}
	if len(e.f.seen()) != before {
		t.Fatal("a request was sent after the Secret was removed")
	}
}

// TestBearerTokenDroppedOnRotation: a token obtained with the old credential
// is reused while the credential is unchanged and discarded once the
// rotation is observed, although the registry would still accept it.
func TestBearerTokenDroppedOnRotation(t *testing.T) {
	e := newEnv(t)
	e.f.mu.Lock()
	e.f.bearer = true
	e.f.mu.Unlock()
	e.f.setValid(map[string]string{"old-user": password, "new-user": "new-" + password})
	e.putCred("old-user", password)

	if err := e.fetch(t); err != nil {
		t.Fatal(err)
	}
	if got := e.f.issuedTo(); len(got) != 1 || got[0] != "old-user" {
		t.Fatalf("tokens issued to %v", got)
	}
	if err := e.fetch(t); err != nil {
		t.Fatal(err)
	}
	if got := e.f.issuedTo(); len(got) != 1 {
		t.Fatalf("the cached token was not reused: issued to %v", got)
	}

	// Rotated but not yet observed: the old token is still used.
	e.putCred("new-user", "new-"+password)
	if err := e.fetch(t); err != nil || len(e.f.issuedTo()) != 1 {
		t.Fatalf("before observation: %v, issued %v", err, e.f.issuedTo())
	}

	e.p.Invalidate(bundle.KindSecret, secretName)
	mark := len(e.f.seen())
	if err := e.fetch(t); err != nil {
		t.Fatal(err)
	}
	if got := e.f.issuedTo(); len(got) != 2 || got[1] != "new-user" {
		t.Fatalf("no new token after rotation: issued to %v", got)
	}
	for _, r := range e.f.seen()[mark:] {
		if strings.HasPrefix(r.authz, "Bearer tok-old-user") {
			t.Fatalf("the old token was used after rotation on %s", r.path)
		}
	}
}

// TestCredentialsStayWithTheRegistry: no Authorization header and no
// credential reaches another origin or another repository.
func TestCredentialsStayWithTheRegistry(t *testing.T) {
	basic := "Basic " + b64(user+":"+password)

	t.Run("token realm on another origin", func(t *testing.T) {
		e := newEnv(t)
		// Same hostname and CA, another port: ORAS accepts this realm (it
		// compares hostnames only), so only the adapter's origin check stops
		// the credential. TLS to it would succeed.
		other := newFakeRegistry(t, e.ca)
		e.f.mu.Lock()
		e.f.bearer, e.f.realm = true, other.srv.URL+"/token"
		e.f.mu.Unlock()
		e.f.setValid(map[string]string{user: password})
		other.setValid(map[string]string{user: password})
		e.putCred(user, password)
		err := e.fetch(t)
		if !errors.Is(err, registry.ErrCredentialScope) {
			t.Fatalf("want ErrCredentialScope, got %v", err)
		}
		for _, r := range other.seen() {
			t.Fatalf("the other origin received %s %s", r.method, r.path)
		}
		assertNoLeak(t, err, password)
	})

	t.Run("redirect to another host", func(t *testing.T) {
		e := newEnv(t)
		e.f.setValid(map[string]string{user: password})
		e.putCred(user, password)
		storage := newFakeRegistry(t, e.ca) // anonymous, serves the same blob
		layer := e.f.layerDigest()
		// localhost is another host name for the same address.
		target := strings.Replace(storage.srv.URL, "127.0.0.1", "localhost", 1) + "/v2/" + repoPath + "/blobs/" + layer
		e.f.mu.Lock()
		e.f.redirect = func(r *http.Request) string {
			if strings.HasSuffix(r.URL.Path, "/blobs/"+layer) {
				return target
			}
			return ""
		}
		e.f.mu.Unlock()
		if err := e.fetch(t); err != nil {
			t.Fatal(err)
		}
		got := storage.seen()
		if len(got) == 0 {
			t.Fatal("the redirect was not followed")
		}
		for _, r := range got {
			if r.authz != "" {
				t.Fatalf("another host received Authorization %q", r.authz)
			}
		}
		_ = basic
	})

	t.Run("redirect to another repository on the same registry", func(t *testing.T) {
		e := newEnv(t)
		e.f.setValid(map[string]string{user: password})
		e.putCred(user, password)
		layer := e.f.layerDigest()
		e.f.mu.Lock()
		e.f.redirect = func(r *http.Request) string {
			if strings.HasPrefix(r.URL.Path, "/v2/"+repoPath+"/blobs/") {
				return "/v2/other/repository/blobs/" + layer
			}
			return ""
		}
		e.f.mu.Unlock()
		if err := e.fetch(t); err != nil {
			t.Fatal(err)
		}
		reached := false
		for _, r := range e.f.seen() {
			if strings.HasPrefix(r.path, "/v2/other/") {
				reached = true
				if r.authz != "" {
					t.Fatalf("another repository received Authorization %q", r.authz)
				}
			}
		}
		if !reached {
			t.Fatal("the redirect was not followed")
		}
	})
}

func TestTrustIsPerSource(t *testing.T) {
	// Two registries with different CAs, one provider and one client: each
	// source trusts only its own CA (plus system roots).
	caA, caB := newTestCA(t, "a"), newTestCA(t, "b")
	fa, fb := newFakeRegistry(t, caA), newFakeRegistry(t, caB)
	objs := NewMemoryReader()
	p, err := New(Options{Reader: objs, SystemRoots: poolWith()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(p, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	objs.Put(bundle.KindConfigMap, "a-ca", caObject(caA.pem))
	objs.Put(bundle.KindConfigMap, "b-ca", caObject(caB.pem))
	ctx := context.Background()
	srcA := caSource("a", fa.host())
	if _, err := c.Fetch(ctx, srcA, fa.digest.String()); err != nil {
		t.Fatal(err)
	}
	// B's repository configured with A's CA object fails verification.
	wrong := caSource("b", fb.host())
	wrong.CA.Name = "a-ca"
	if _, err := c.Fetch(ctx, wrong, fb.digest.String()); !isUnknownAuthority(err) {
		t.Fatalf("A's CA trusted B's registry: %v", err)
	}
	if len(fb.seen()) != 0 {
		t.Fatal("B served a request over an unverified connection")
	}
	if _, err := c.Fetch(ctx, caSource("b", fb.host()), fb.digest.String()); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentFetchesDuringRotation(t *testing.T) {
	e := newEnv(t)
	e.f.mu.Lock()
	e.f.bearer = true
	e.f.mu.Unlock()
	users := map[string]string{}
	for i := range 4 {
		users[fmt.Sprintf("u%d", i)] = fmt.Sprintf("p%d-%s", i, password)
	}
	e.f.setValid(users)
	e.putCred("u0", users["u0"])
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 6 {
				if i == 0 && j%2 == 1 {
					u := fmt.Sprintf("u%d", (j/2+1)%4)
					e.rotate(u, users[u])
				}
				if err := e.fetch(t); err != nil {
					t.Errorf("fetch: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	mark := len(e.f.seen())
	if err := e.fetch(t); err != nil {
		t.Fatal(err)
	}
	// After the last rotation only tokens issued for the current credential
	// are used.
	for _, r := range e.f.seen()[mark:] {
		if r.path != "/token" && r.authz != "" && !strings.HasPrefix(r.authz, "Bearer tok-u3-") {
			t.Fatalf("stale token %q after the last rotation", r.authz)
		}
	}
}
