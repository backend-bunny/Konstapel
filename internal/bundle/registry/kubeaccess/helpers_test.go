package kubeaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	corev1 "k8s.io/api/core/v1"
)

const (
	repoPath   = "bundles/konstapel-privileged-containers"
	sourceName = "konstapel-privileged-containers"
	secretName = "registry-creds"
	caName     = "registry-ca"
)

// testCA is a throwaway certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serverCert issues a certificate for 127.0.0.1 and localhost.
func (ca testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "registry"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLS serves h over TLS with a certificate from ca.
func startTLS(t *testing.T, ca testCA, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

var (
	archOnce sync.Once
	arch     *bundle.Archive
	archErr  error
)

// official builds the checked-in bundle once so tests serve real bytes.
func official(t *testing.T) *bundle.Archive {
	t.Helper()
	archOnce.Do(func() {
		root := "../../../.."
		raw, err := os.ReadFile(filepath.Join(root, "bundles/konstapel-privileged-containers/definition.json"))
		if err != nil {
			archErr = err
			return
		}
		def, err := bundle.LoadDefinition(raw)
		if err != nil {
			archErr = err
			return
		}
		def.Source.Revision = strings.Repeat("c", 40)
		arch, archErr = bundle.Build(def, os.DirFS(root), time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	})
	if archErr != nil {
		t.Fatal(archErr)
	}
	return arch
}

type seenRequest struct {
	method, path, authz string
}

// fakeRegistry serves one bundle (no referrers) and authenticates with
// Basic or with a bearer token service, in-process over TLS.
type fakeRegistry struct {
	srv    *httptest.Server
	digest digest.Digest

	mu        sync.Mutex
	manifest  []byte
	blobs     map[string][]byte
	valid     map[string]string // user -> password
	bearer    bool
	realm     string            // token realm; default this server's /token
	tokens    map[string]string // token -> user
	issued    []string          // users tokens were issued to
	requests  []seenRequest
	redirect  func(r *http.Request) string // non-empty: redirect there
	connState func(net.Conn, http.ConnState)
}

func newFakeRegistry(t *testing.T, ca testCA) *fakeRegistry {
	t.Helper()
	a := official(t)
	f := &fakeRegistry{
		manifest: a.Manifest,
		digest:   digest.FromBytes(a.Manifest),
		blobs:    map[string][]byte{digest.FromBytes(a.Layer).String(): a.Layer},
		valid:    map[string]string{},
		tokens:   map[string]string{},
	}
	f.srv = httptest.NewUnstartedServer(f)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	f.srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		f.mu.Lock()
		h := f.connState
		f.mu.Unlock()
		if h != nil {
			h(c, s)
		}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string { return hostOf(f.srv) }

func (f *fakeRegistry) layerDigest() string {
	for d := range f.blobs {
		return d
	}
	return ""
}

func (f *fakeRegistry) setValid(users map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.valid = users
}

func (f *fakeRegistry) seen() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.requests...)
}

func (f *fakeRegistry) issuedTo() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.issued...)
}

func (f *fakeRegistry) source() bundle.BundleSource {
	return bundle.BundleSource{Name: sourceName, Repository: f.host() + "/" + repoPath}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": code}}})
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, seenRequest{r.Method, r.URL.Path, r.Header.Get("Authorization")})
	redirect := f.redirect
	f.mu.Unlock()

	if r.URL.Path == "/token" {
		f.serveToken(w, r)
		return
	}
	prefix := "/v2/" + repoPath + "/"
	inRepo := r.URL.Path == "/v2/" || strings.HasPrefix(r.URL.Path, prefix)
	// Only the configured repository is protected; other paths stand for
	// another repository and are served to anyone, so tests can observe
	// exactly what arrives there.
	if inRepo && !f.authorized(r) {
		f.challenge(w)
		return
	}
	if redirect != nil {
		if to := redirect(r); to != "" {
			http.Redirect(w, r, to, http.StatusTemporaryRedirect)
			return
		}
	}
	if r.URL.Path == "/v2/" {
		return
	}
	path := r.URL.Path
	if !inRepo {
		// /v2/<other repo>/blobs/<digest>
		if i := strings.Index(path, "/blobs/"); i >= 0 {
			path = prefix + path[i+1:]
		}
	}
	kind, ref, _ := strings.Cut(strings.TrimPrefix(path, prefix), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case kind == "manifests" && ref == f.digest.String():
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", fmt.Sprint(len(f.manifest)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(f.manifest)
		}
	case kind == "blobs" && f.blobs[ref] != nil:
		w.Header().Set("Content-Length", fmt.Sprint(len(f.blobs[ref])))
		_, _ = w.Write(f.blobs[ref])
	case kind == "referrers":
		w.WriteHeader(http.StatusNotFound)
	default:
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN")
	}
}

func (f *fakeRegistry) authorized(r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.valid) == 0 {
		return true
	}
	h := r.Header.Get("Authorization")
	if f.bearer {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		_, known := f.tokens[tok]
		return ok && known
	}
	u, p, ok := r.BasicAuth()
	return ok && f.valid[u] == p && p != ""
}

func (f *fakeRegistry) challenge(w http.ResponseWriter) {
	f.mu.Lock()
	bearer, realm := f.bearer, f.realm
	f.mu.Unlock()
	if bearer {
		if realm == "" {
			realm = f.srv.URL + "/token"
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fake",scope="repository:%s:pull"`, realm, repoPath))
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
	}
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
}

func (f *fakeRegistry) serveToken(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ok || p == "" || f.valid[u] != p {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	tok := fmt.Sprintf("tok-%s-%d", u, len(f.issued))
	f.tokens[tok] = u
	f.issued = append(f.issued, u)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// dockerConfig builds a dockerconfigjson document with one Basic entry.
func dockerConfig(host, user, pass string) []byte {
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{
		host: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))},
	}})
	return b
}

func dockerSecret(doc []byte) Object {
	return NewObject(string(corev1.SecretTypeDockerConfigJson), map[string][]byte{corev1.DockerConfigJsonKey: doc})
}

func caObject(pemData ...[]byte) Object {
	var all []byte
	for _, p := range pemData {
		all = append(all, p...)
	}
	return NewObject("", map[string][]byte{bundle.DefaultCAKey: all})
}

// recordingResetter counts token resets per source name.
type recordingResetter struct {
	mu    sync.Mutex
	count int
}

func (r *recordingResetter) ResetTokens(bundle.BundleSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
}

func (r *recordingResetter) n() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// poolWith returns a "system" pool holding the given CAs.
func poolWith(cas ...testCA) func() (*x509.CertPool, error) {
	return func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		for _, ca := range cas {
			p.AddCert(ca.cert)
		}
		return p, nil
	}
}
