package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/rest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const metricsName = "konstapel-controller-metrics.konstapel-system.svc"

type testIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newIssuer(t *testing.T) testIssuer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testIssuer{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serving writes tls.crt, tls.key and ca.crt for names into a new directory.
func (ca testIssuer) serving(t *testing.T, serial int64, names ...string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		"ca.crt":  ca.pem,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// No plaintext and no self-signed fallback: serving requires a verified
// certificate for the metrics Service name.
func TestMetricsOptionsRequireVerifiedTLS(t *testing.T) {
	if o, certs, err := metricsOptions("0", nil); err != nil || o.BindAddress != "0" || certs != nil {
		t.Fatalf("disabled: %+v %v %v", o, certs, err)
	}
	if _, _, err := metricsOptions(":8443", nil); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("serving without TLS: %v", err)
	}
	ca := newIssuer(t)
	if _, _, err := metricsOptions(":8443", &MetricsTLS{CertDir: ca.serving(t, 2, "other.example"), ServerName: metricsName}); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	wrong := ca.serving(t, 3, metricsName)
	other := newIssuer(t)
	if err := os.WriteFile(filepath.Join(wrong, "ca.crt"), other.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := metricsOptions(":8443", &MetricsTLS{CertDir: wrong, ServerName: metricsName}); err == nil {
		t.Fatal("a certificate that does not chain to ca.crt was accepted")
	}
	if _, _, err := metricsOptions(":8443", &MetricsTLS{CertDir: t.TempDir(), ServerName: metricsName}); err == nil {
		t.Fatal("missing certificate files were accepted (no self-signed fallback)")
	}
	o, certs, err := metricsOptions(":8443", &MetricsTLS{CertDir: ca.serving(t, 4, metricsName), ServerName: metricsName})
	if err != nil || !o.SecureServing || o.FilterProvider == nil || certs == nil || len(o.TLSOpts) == 0 {
		t.Fatalf("valid: %+v %v", o, err)
	}
}

// fakeAPIServer answers TokenReview and SubjectAccessReview the way the
// kube-apiserver does: known tokens authenticate; only readers may get
// /metrics. It counts reviews and can be switched off.
type fakeAPIServer struct {
	mu      sync.Mutex
	readers map[string]bool // users allowed to get /metrics
	down    atomic.Bool
	sars    []authzv1.SubjectAccessReviewSpec
	reviews atomic.Int64
}

var tokens = map[string]string{
	"reader-token":    "system:serviceaccount:monitoring:prometheus",
	"namespace-token": "system:serviceaccount:team-a:exceptions",
}

func (f *fakeAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.reviews.Add(1)
	if f.down.Load() {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/tokenreviews"):
		var tr authnv1.TokenReview
		_ = json.Unmarshal(body, &tr)
		if user, ok := tokens[tr.Spec.Token]; ok {
			tr.Status = authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: user}}
		}
		tr.APIVersion, tr.Kind = "authentication.k8s.io/v1", "TokenReview"
		_ = json.NewEncoder(w).Encode(tr)
	case strings.HasSuffix(r.URL.Path, "/subjectaccessreviews"):
		var sar authzv1.SubjectAccessReview
		_ = json.Unmarshal(body, &sar)
		f.mu.Lock()
		f.sars = append(f.sars, sar.Spec)
		allowed := f.readers[sar.Spec.User]
		f.mu.Unlock()
		na := sar.Spec.NonResourceAttributes
		sar.Status.Allowed = allowed && na != nil && na.Path == "/metrics" && na.Verb == "get"
		sar.APIVersion, sar.Kind = "authorization.k8s.io/v1", "SubjectAccessReview"
		_ = json.NewEncoder(w).Encode(sar)
	default:
		http.NotFound(w, r)
	}
}

// The real metrics server, with the options the manager uses: verified
// TLS for the Service name, authentication and authorization through the
// API server, and fail-closed behavior when the API server is unavailable.
func TestMetricsServerAuthenticatesAndAuthorizes(t *testing.T) {
	api := &fakeAPIServer{readers: map[string]bool{"system:serviceaccount:monitoring:prometheus": true}}
	apiSrv := httptest.NewServer(api)
	t.Cleanup(apiSrv.Close)
	cfg := &rest.Config{Host: apiSrv.URL}
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ca := newIssuer(t)
	o, _, err := metricsOptions("127.0.0.1:0", &MetricsTLS{CertDir: ca.serving(t, 5, metricsName), ServerName: metricsName})
	if err != nil {
		t.Fatal(err)
	}
	o.ExtraHandlers = nil
	srv, err := metricsserver.NewServer(o, cfg, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Start(ctx) }()
	var addr string
	for deadline := time.Now().Add(10 * time.Second); addr == ""; {
		if a := srvAddr(srv); a != "" {
			addr = a
		} else if time.Now().After(deadline) {
			t.Fatal("metrics server did not listen")
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	scrape := func(roots *x509.CertPool, serverName, token string) (int, error) {
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK && !strings.Contains(string(b), "# TYPE") {
			return 0, fmt.Errorf("200 without an exposition: %q", b)
		}
		return resp.StatusCode, nil
	}

	if code, err := scrape(roots, metricsName, "reader-token"); err != nil || code != http.StatusOK {
		t.Fatalf("authorized monitoring identity: %d %v", code, err)
	}
	if code, err := scrape(roots, metricsName, "namespace-token"); err != nil || code != http.StatusForbidden {
		t.Errorf("namespace identity without the reader role: %d %v", code, err)
	}
	if code, err := scrape(roots, metricsName, ""); err != nil || code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d %v", code, err)
	}
	// The pinned filter reports a token the API server does not
	// authenticate as an error (500 "invalid bearer token"), not 401; either
	// way nothing is served.
	if code, err := scrape(roots, metricsName, "forged-token"); err != nil || code == http.StatusOK || code < 400 {
		t.Errorf("unknown token: %d %v", code, err)
	}
	// The client verifies the server: another CA or another name fails the
	// handshake; nothing falls back to plaintext.
	if _, err := scrape(newIssuerPool(t), metricsName, "reader-token"); err == nil {
		t.Error("an untrusted CA was accepted")
	}
	if _, err := scrape(roots, "konstapel-download.konstapel-system.svc", "reader-token"); err == nil {
		t.Error("the certificate verified for another service name")
	}
	if resp, err := http.Get("http://" + addr + "/metrics"); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), "# TYPE") {
			t.Error("metrics served over plaintext")
		}
	}

	// The authorization question is exactly get on /metrics.
	api.mu.Lock()
	for _, s := range api.sars {
		if s.NonResourceAttributes == nil || s.NonResourceAttributes.Path != "/metrics" || s.NonResourceAttributes.Verb != "get" || s.ResourceAttributes != nil {
			t.Errorf("unexpected SubjectAccessReview %+v", s)
		}
	}
	api.mu.Unlock()

	// With the API server unavailable, an identity without a cached answer
	// is refused (fail closed); scraping never bypasses review.
	api.down.Store(true)
	if code, err := scrape(roots, metricsName, "other-reader-token"); err != nil || code == http.StatusOK {
		t.Errorf("API server down: %d %v", code, err)
	}
}

func newIssuerPool(t *testing.T) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(newIssuer(t).cert)
	return p
}

// srvAddr reads the listening address of a started controller-runtime
// metrics server.
func srvAddr(s metricsserver.Server) string {
	type addressed interface{ GetBindAddr() string }
	if a, ok := s.(addressed); ok {
		addr := a.GetBindAddr()
		if _, port, err := net.SplitHostPort(addr); err == nil && port != "0" {
			return addr
		}
	}
	return ""
}
