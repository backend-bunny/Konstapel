package kubeaccess

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

func TestParseCABundle(t *testing.T) {
	a, b := newTestCA(t, "a"), newTestCA(t, "b")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	certs, err := ParseCABundle(append(append([]byte("\n"), a.pem...), append([]byte("\r\n\t"), b.pem...)...))
	if err != nil || len(certs) != 2 {
		t.Fatalf("two certificates: %v", err)
	}
	many := []byte{}
	for range MaxCACerts + 1 {
		many = append(many, a.pem...)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"whitespace", []byte(" \n")},
		{"no PEM", []byte("not a certificate")},
		{"oversized", make([]byte, MaxCABytes+1)},
		{"private key", append(append([]byte{}, a.pem...), keyPEM...)},
		{"private key only", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		{"public key block", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})},
		{"headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a.cert.Raw})},
		{"text before", append([]byte("subject=CN=a\n"), a.pem...)},
		{"text after", append(append([]byte{}, a.pem...), []byte("trailer")...)},
		{"garbage certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})},
		{"malformed block then a valid one", append([]byte("-----BEGIN CERTIFICATE-----\n!!!\n"), a.pem...)},
		{"too many", many},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCABundle(tc.data); !errors.Is(err, ErrMalformedCA) || !errors.Is(err, registry.ErrTrustConfig) {
				t.Fatalf("want ErrMalformedCA, got %v", err)
			}
		})
	}
	if len(many) <= MaxCABytes {
		// the count limit, not the size limit, rejected it
		if _, err := ParseCABundle(many); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Fatalf("count limit: %v", err)
		}
	}
}

// caSource is a source whose CA is the ConfigMap name.
func caSource(name, repoHost string) bundle.BundleSource {
	return bundle.BundleSource{Name: name, Repository: repoHost + "/" + repoPath,
		CA: &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: name + "-ca"}}
}

func get(t *testing.T, rt http.RoundTripper, url string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func isUnknownAuthority(err error) bool {
	var ua x509.UnknownAuthorityError
	return errors.As(err, &ua) || (err != nil && strings.Contains(err.Error(), "certificate signed by unknown authority"))
}

func TestTransportTrust(t *testing.T) {
	sys, caA, caB := newTestCA(t, "system"), newTestCA(t, "a"), newTestCA(t, "b")
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	srvSys, srvA, srvB := startTLS(t, sys, ok), startTLS(t, caA, ok), startTLS(t, caB, ok)
	objs := NewMemoryReader()
	p, err := New(Options{Reader: objs, SystemRoots: poolWith(sys)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	objs.Put(bundle.KindConfigMap, "a-ca", caObject(caA.pem))
	objs.Put(bundle.KindConfigMap, "b-ca", caObject(caB.pem))
	ctx := context.Background()
	srcA, srcB := caSource("a", hostOf(srvA)), caSource("b", hostOf(srvB))

	tA, err := p.Transport(ctx, srcA)
	if err != nil {
		t.Fatal(err)
	}
	tB, err := p.Transport(ctx, srcB)
	if err != nil {
		t.Fatal(err)
	}
	ht := tA.(*http.Transport)
	if ht.TLSClientConfig.InsecureSkipVerify || ht.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("transport must verify TLS 1.2+")
	}
	// The extra roots are added to the system roots, not substituted.
	if err := get(t, tA, srvA.URL); err != nil {
		t.Fatalf("A's CA not trusted for A: %v", err)
	}
	if err := get(t, tA, srvSys.URL); err != nil {
		t.Fatalf("system roots dropped: %v", err)
	}
	// Per-source isolation: A's extra CA does not vouch for B, nor B's for A.
	if err := get(t, tA, srvB.URL); !isUnknownAuthority(err) {
		t.Fatalf("A's transport trusts B's registry: %v", err)
	}
	if err := get(t, tB, srvA.URL); !isUnknownAuthority(err) {
		t.Fatalf("B's transport trusts A's registry: %v", err)
	}
	// Unchanged content reuses the transport.
	if again, _ := p.Transport(ctx, srcA); again != tA {
		t.Fatal("transport rebuilt without a change")
	}
	// A source without a CA uses the shared system-roots transport.
	plain := bundle.BundleSource{Name: "plain", Repository: hostOf(srvA) + "/" + repoPath}
	tp, err := p.Transport(ctx, plain)
	if err != nil || tp == tA || tp == tB {
		t.Fatalf("plain source: %v", err)
	}
}

func TestTransportFailures(t *testing.T) {
	ca := newTestCA(t, "a")
	for _, tc := range []struct {
		name  string
		setup func(objs *MemoryReader, src *bundle.BundleSource)
		roots func() (*x509.CertPool, error)
	}{
		{"missing object", func(*MemoryReader, *bundle.BundleSource) {}, nil},
		{"missing key", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", NewObject("", map[string][]byte{"other.crt": ca.pem}))
		}, nil},
		{"invalid PEM", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", caObject([]byte("nope")))
		}, nil},
		{"private key", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", caObject(ca.pem, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})))
		}, nil},
		{"wrong kind", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", caObject(ca.pem))
			s.CA.Kind = "Pod"
		}, nil},
		{"Secret kind is read as a Secret", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", caObject(ca.pem))
			s.CA.Kind = bundle.KindSecret
		}, nil},
		{"system roots unavailable", func(o *MemoryReader, s *bundle.BundleSource) {
			o.Put(bundle.KindConfigMap, "a-ca", caObject(ca.pem))
		}, func() (*x509.CertPool, error) { return nil, errors.New("no system roots") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := NewMemoryReader()
			p, err := New(Options{Reader: objs, SystemRoots: tc.roots})
			if err != nil {
				t.Fatal(err)
			}
			src := caSource("a", "registry.example")
			tc.setup(objs, &src)
			if rt, err := p.Transport(context.Background(), src); !errors.Is(err, registry.ErrTrustConfig) || rt != nil {
				t.Fatalf("want ErrTrustConfig and no transport, got %v", err)
			}
		})
	}
	// A Secret-held CA works.
	objs := NewMemoryReader()
	p, _ := New(Options{Reader: objs, SystemRoots: poolWith()})
	objs.Put(bundle.KindSecret, "a-ca", NewObject("Opaque", map[string][]byte{"tls-ca": ca.pem}))
	src := caSource("a", "registry.example")
	src.CA.Kind, src.CA.Key = bundle.KindSecret, "tls-ca"
	if _, err := p.Transport(context.Background(), src); err != nil {
		t.Fatal(err)
	}
}

// connTracker records server-side connection closes.
type connTracker struct {
	mu     sync.Mutex
	closed int
}

func (c *connTracker) state(_ net.Conn, s http.ConnState) {
	if s == http.StateClosed {
		c.mu.Lock()
		c.closed++
		c.mu.Unlock()
	}
}

func (c *connTracker) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestTransportRotation(t *testing.T) {
	caA, caB := newTestCA(t, "a"), newTestCA(t, "b")
	f := newFakeRegistry(t, caA)
	tracker := &connTracker{}
	f.mu.Lock()
	f.connState = tracker.state
	f.mu.Unlock()
	objs := NewMemoryReader()
	p, err := New(Options{Reader: objs, SystemRoots: poolWith()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	src := caSource("a", f.host())
	objs.Put(bundle.KindConfigMap, "a-ca", caObject(caA.pem))
	old, err := p.Transport(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, old, f.srv.URL+"/v2/"); err != nil {
		t.Fatal(err)
	}
	if tracker.n() != 0 {
		t.Fatal("connection closed early")
	}

	// Rotation to a bundle that still trusts the registry: a new transport,
	// and the old transport's idle connection is closed.
	objs.Put(bundle.KindConfigMap, "a-ca", caObject(caB.pem, caA.pem))
	p.Invalidate(bundle.KindConfigMap, "a-ca")
	rotated, err := p.Transport(ctx, src)
	if err != nil || rotated == old {
		t.Fatalf("transport not rebuilt: %v", err)
	}
	waitUntil(t, "old idle connection closed", func() bool { return tracker.n() == 1 })
	if err := get(t, rotated, f.srv.URL+"/v2/"); err != nil {
		t.Fatal(err)
	}

	// Rotation to a CA that no longer trusts the registry takes effect.
	objs.Put(bundle.KindConfigMap, "a-ca", caObject(caB.pem))
	p.Invalidate(bundle.KindConfigMap, "a-ca")
	untrusting, err := p.Transport(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "second idle connection closed", func() bool { return tracker.n() == 2 })
	if err := get(t, untrusting, f.srv.URL+"/v2/"); !isUnknownAuthority(err) {
		t.Fatalf("rotated-out CA still trusted: %v", err)
	}

	// An invalid replacement makes the source unavailable; it does not keep
	// the previous trust.
	objs.Put(bundle.KindConfigMap, "a-ca", caObject([]byte("broken")))
	p.Invalidate(bundle.KindConfigMap, "a-ca")
	if _, err := p.Transport(ctx, src); !errors.Is(err, ErrMalformedCA) {
		t.Fatalf("invalid CA: %v", err)
	}
	objs.Delete(bundle.KindConfigMap, "a-ca")
	p.Invalidate(bundle.KindConfigMap, "a-ca")
	if _, err := p.Transport(ctx, src); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("removed CA: %v", err)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
