package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Bearer challenges observed on 2026-11-12 with an unauthenticated, read-only
// GET (no credentials) of each registry's /v2/ and of one public repository's
// manifest. They fix the token realm origins documented in
// docs/policy-bundles.md ("Token realms on another origin"). Nothing was
// validated with credentials: none were available.
const (
	observedDockerHubV2       = `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`
	observedDockerHubManifest = `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`
	observedGitLabV2          = `Bearer realm="https://gitlab.com/jwt/auth",service="container_registry"`
	observedGitLabManifest    = `Bearer realm="https://gitlab.com/jwt/auth",service="container_registry",scope="repository:gitlab-org/gitlab-runner:pull"`
)

const (
	realmRegistry = "registry.test"
	realmAuth     = "auth.test"
	realmEvil     = "evil.test"
	issuedToken   = "issued-registry-token-0123456789"
	refreshSecret = "r3fresh-identity-token-secret"
)

// sent is one request as the network received it.
type sent struct {
	host, method, uri, authz, body string
}

// realmNet is a small TLS network of named hosts served by one in-process
// server: the registry (the fake registry behind a bearer challenge), a token
// service and other hosts. The client's transport dials every name to it, so
// tests use real host names, real TLS and real redirects, and every request
// that reaches any host is recorded.
type realmNet struct {
	t        *testing.T
	srv      *httptest.Server
	pool     *x509.CertPool
	reg      *fakeRegistry
	registry string // registry host name
	auth     string // token service host name

	mu         sync.Mutex
	reqs       []sent
	challenges []string // WWW-Authenticate headers sent by the registry
	// tokenHook runs first on a token service request; true means handled.
	tokenHook func(w http.ResponseWriter, r *http.Request) bool
	// registryHook runs first on an authorized registry request.
	registryHook func(w http.ResponseWriter, r *http.Request) bool
}

func selfSignedPool(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel token-realm test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		DNSNames: names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

func newRealmNet(t *testing.T, registryHost, authHost string) *realmNet {
	t.Helper()
	n := &realmNet{t: t, reg: newFakeRegistry(t), registry: registryHost, auth: authHost}
	n.challenges = []string{fmt.Sprintf(`Bearer realm="https://%s/token",service="%s",scope="repository:%s:pull"`, authHost, registryHost, repoPath)}
	cert, pool := selfSignedPool(t, registryHost, authHost, realmEvil, "storage.test", "x."+authHost)
	n.pool = pool
	n.srv = httptest.NewUnstartedServer(n)
	n.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	return n
}

func (n *realmNet) transport() http.RoundTripper {
	addr := n.srv.Listener.Addr().String()
	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: n.pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func (n *realmNet) client(t *testing.T, creds CredentialProvider, limits Limits) *Client {
	t.Helper()
	c, err := NewClient(Options{Transport: n.transport(), Credentials: creds, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (n *realmNet) source(realms ...string) bundle.BundleSource {
	return bundle.BundleSource{
		Name: "konstapel-privileged-containers", Repository: n.registry + "/" + repoPath,
		CredentialSecret: &bundle.ObjectRef{Name: "registry-creds"}, TokenRealms: realms,
	}
}

// challenge replaces the registry's WWW-Authenticate headers.
func (n *realmNet) challenge(headers ...string) {
	n.set(func(n *realmNet) { n.challenges = headers })
}

func (n *realmNet) set(f func(n *realmNet)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(n)
}

func (n *realmNet) sent() []sent {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]sent(nil), n.reqs...)
}

func (n *realmNet) to(host string) []sent {
	var out []sent
	for _, r := range n.sent() {
		if r.host == host {
			out = append(out, r)
		}
	}
	return out
}

func (n *realmNet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	n.mu.Lock()
	n.reqs = append(n.reqs, sent{host: host, method: r.Method, uri: r.URL.RequestURI(), authz: r.Header.Get("Authorization"), body: string(body)})
	challenges, tokenHook, registryHook := n.challenges, n.tokenHook, n.registryHook
	n.mu.Unlock()

	switch host {
	case n.registry:
		if r.Header.Get("Authorization") != "Bearer "+issuedToken {
			for _, c := range challenges {
				w.Header().Add("WWW-Authenticate", c)
			}
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return
		}
		if registryHook != nil && registryHook(w, r) {
			return
		}
		n.reg.ServeHTTP(w, r)
	case n.auth, realmEvil, "x." + n.auth:
		if tokenHook != nil && tokenHook(w, r) {
			return
		}
		serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveToken is a token service that issues a token for the test
// credential: Basic on GET (distribution token), a password or refresh token
// form on POST (OAuth2).
func serveToken(w http.ResponseWriter, r *http.Request) {
	ok := false
	switch r.Method {
	case http.MethodGet:
		u, p, basic := r.BasicAuth()
		ok = basic && u == "robot" && p == secretPassword
	case http.MethodPost:
		_ = r.ParseForm()
		ok = (r.PostForm.Get("grant_type") == "refresh_token" && r.PostForm.Get("refresh_token") == refreshSecret) ||
			(r.PostForm.Get("grant_type") == "password" && r.PostForm.Get("password") == secretPassword)
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "bad credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": issuedToken, "access_token": issuedToken})
}

var (
	basicCred   = Credential{Username: "robot", Password: secretPassword}
	refreshCred = Credential{IdentityToken: refreshSecret}
	basicHeader = base64.StdEncoding.EncodeToString([]byte("robot:" + secretPassword))
)

// assertConfined checks every recorded request: the credential (password,
// its Basic encoding, the refresh token) reaches only the hosts in
// credHosts, and the issued registry token only the registry.
func (n *realmNet) assertConfined(t *testing.T, credHosts ...string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, h := range credHosts {
		allowed[h] = true
	}
	for _, r := range n.sent() {
		all := r.authz + " " + r.body + " " + r.uri
		if (strings.Contains(all, secretPassword) || strings.Contains(all, basicHeader) || strings.Contains(all, refreshSecret)) && !allowed[r.host] {
			t.Fatalf("credential reached %s: %s %s", r.host, r.method, r.uri)
		}
		if strings.Contains(all, issuedToken) && r.host != n.registry {
			t.Fatalf("registry token reached %s: %s %s", r.host, r.method, r.uri)
		}
	}
}

func assertNoSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, v := range []string{secretPassword, basicHeader, refreshSecret, issuedToken} {
		if strings.Contains(err.Error(), v) {
			t.Fatalf("error contains a secret: %v", err)
		}
	}
}

func TestTokenRealmAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		cred Credential
		// method the token service must see, every time with the credential
		method string
	}{
		{"distribution token with Basic credentials", basicCred, http.MethodGet},
		{"OAuth2 refresh token", refreshCred, http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newRealmNet(t, realmRegistry, realmAuth)
			d := n.reg.publishSigned(t)
			creds := &recordingCreds{cred: tc.cred}
			res, err := n.client(t, creds, Limits{}).Fetch(context.Background(), n.source("https://"+realmAuth), d.String())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Proofs) != 2 {
				t.Fatalf("want 2 proofs, got %d", len(res.Proofs))
			}
			tokenReqs := n.to(realmAuth)
			if len(tokenReqs) == 0 {
				t.Fatal("the token realm was never asked")
			}
			for _, r := range tokenReqs {
				if r.method != tc.method || (r.authz == "" && r.body == "") {
					t.Fatalf("token request %s %s without the credential", r.method, r.uri)
				}
			}
			for _, h := range creds.hosts {
				if h != realmRegistry {
					t.Fatalf("credential provider asked for %q", h)
				}
			}
			n.assertConfined(t, realmAuth)
		})
	}

	t.Run("publisher session may request push for its own repository", func(t *testing.T) {
		n := newRealmNet(t, realmRegistry, realmAuth)
		n.challenge(fmt.Sprintf(`Bearer realm="https://%s/token",service="x",scope="repository:%s:pull,push"`, realmAuth, repoPath))
		d := n.reg.publishSigned(t)
		s, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{}).Open(context.Background(), n.source("https://"+realmAuth))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Repository.Resolve(context.Background(), d.String()); err != nil {
			t.Fatal(s.Err("resolve", err))
		}
		n.assertConfined(t, realmAuth)
	})
}

// TestObservedChallenges replays the Docker Hub and GitLab.com challenges
// recorded above against local stand-ins named like the real hosts (the
// transport dials every name to the in-process server; nothing leaves the
// machine). It shows that the documented tokenRealms entry is exactly what
// those challenges need, and that without it the credential stays home.
var realmParam = regexp.MustCompile(`realm="([^"]*)"`)

func TestObservedChallenges(t *testing.T) {
	for _, tc := range []struct {
		name, registry, repo, realm, challenge string
	}{
		{"Docker Hub", "registry-1.docker.io", "library/alpine", "https://auth.docker.io", observedDockerHubManifest},
		{"GitLab.com", "registry.gitlab.com", "gitlab-org/gitlab-runner", "https://gitlab.com", observedGitLabManifest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := realmParam.FindStringSubmatch(tc.challenge)
			if m == nil {
				t.Fatalf("no realm in %q", tc.challenge)
			}
			u, err := url.Parse(m[1])
			if err != nil {
				t.Fatal(err)
			}
			origin, err := bundle.ParseTokenRealm(u.Scheme + "://" + u.Host)
			if err != nil || origin != tc.realm {
				t.Fatalf("observed realm origin %q: %v", origin, err)
			}
			s := newCredentialScope("https", tc.registry, tc.repo, []string{tc.realm}, "pull")
			token := func() *http.Request {
				// The token request ORAS builds from the challenge.
				q := url.Values{"service": {"x"}, "scope": {"repository:" + tc.repo + ":pull"}}
				req, _ := http.NewRequest(http.MethodGet, u.String()+"?"+q.Encode(), nil)
				req.SetBasicAuth("robot", secretPassword)
				return req
			}
			if _, err := s.guard(token()); err != nil {
				t.Fatalf("configured realm refused: %v", err)
			}
			none := newCredentialScope("https", tc.registry, tc.repo, nil, "pull")
			if _, err := none.guard(token()); !errors.Is(err, ErrCredentialScope) {
				t.Fatalf("unconfigured realm accepted: %v", err)
			}
		})
	}
	for _, c := range []string{observedDockerHubV2, observedGitLabV2} {
		if !strings.HasPrefix(c, `Bearer realm="https://`) {
			t.Fatalf("unexpected observed challenge %q", c)
		}
	}

	// End to end with the real host names and challenge text.
	n := newRealmNet(t, "registry-1.docker.io", "auth.docker.io")
	n.challenge(strings.ReplaceAll(observedDockerHubManifest, "library/alpine", repoPath))
	d := n.reg.publishSigned(t)
	c := n.client(t, &recordingCreds{cred: basicCred}, Limits{})
	if _, err := c.Fetch(context.Background(), n.source(), d.String()); !errors.Is(err, ErrCredentialScope) {
		t.Fatalf("Docker Hub without tokenRealms: want ErrCredentialScope, got %v", err)
	}
	if len(n.to("auth.docker.io")) != 0 {
		t.Fatal("unconfigured realm contacted with a credential")
	}
	if _, err := c.Fetch(context.Background(), n.source("https://auth.docker.io"), d.String()); err != nil {
		t.Fatalf("Docker Hub with tokenRealms: %v", err)
	}
	n.assertConfined(t, "auth.docker.io")
}

func TestTokenRealmDenied(t *testing.T) {
	scoped := func(realm, scope string) string {
		return fmt.Sprintf(`Bearer realm=%q,service="registry.test",scope=%q`, realm, scope)
	}
	own := "repository:" + repoPath + ":pull"
	for _, tc := range []struct {
		name, challenge string
		realms          []string
		cred            Credential
		// scopeErr: our guard (ErrCredentialScope) must refuse; otherwise any
		// error is acceptable (ORAS refuses first), as long as nothing leaks.
		scopeErr bool
	}{
		{"unconfigured host", scoped("https://evil.test/token", own), []string{"https://auth.test"}, basicCred, true},
		{"no realms configured", scoped("https://auth.test/token", own), nil, basicCred, true},
		{"subdomain of a configured realm", scoped("https://x.auth.test/token", own), []string{"https://auth.test"}, basicCred, true},
		{"other port", scoped("https://auth.test:8443/token", own), []string{"https://auth.test"}, basicCred, true},
		{"trailing dot", scoped("https://auth.test./token", own), []string{"https://auth.test"}, basicCred, true},
		{"userinfo in the realm", scoped("https://user:pw@auth.test/token", own), []string{"https://auth.test"}, basicCred, true},
		{"OAuth2 POST to an unconfigured host", scoped("https://evil.test/token", own), []string{"https://auth.test"}, refreshCred, true},
		{"http realm", scoped("http://auth.test/token", own), []string{"https://auth.test"}, basicCred, false},
		{"loopback IP realm", scoped("https://127.0.0.1/token", own), []string{"https://auth.test"}, basicCred, false},
		{"localhost realm", scoped("https://localhost/token", own), []string{"https://auth.test"}, basicCred, false},
		{"missing realm", `Bearer service="registry.test",scope="` + own + `"`, []string{"https://auth.test"}, basicCred, false},
		{"empty challenge parameters", `Bearer`, []string{"https://auth.test"}, basicCred, false},
		{"scope for another repository", scoped("https://auth.test/token", "repository:other/repo:pull"), []string{"https://auth.test"}, basicCred, true},
		{"scope for a repository prefix", scoped("https://auth.test/token", "repository:"+repoPath+"x:pull"), []string{"https://auth.test"}, basicCred, true},
		{"scope for a parent repository", scoped("https://auth.test/token", "repository:bundles:pull"), []string{"https://auth.test"}, basicCred, true},
		{"push scope for a reader", scoped("https://auth.test/token", "repository:"+repoPath+":pull,push"), []string{"https://auth.test"}, basicCred, true},
		{"wildcard actions", scoped("https://auth.test/token", "repository:"+repoPath+":*"), []string{"https://auth.test"}, basicCred, true},
		{"catalog scope", scoped("https://auth.test/token", "registry:catalog:*"), []string{"https://auth.test"}, basicCred, true},
		{"extra scope next to the own one", scoped("https://auth.test/token", own+" repository:other/repo:pull"), []string{"https://auth.test"}, refreshCred, true},
		{"scope in the realm query", scoped("https://auth.test/token?scope=repository:other/repo:pull", own), []string{"https://auth.test"}, basicCred, true},
		{"scope in the realm query of an OAuth2 POST", scoped("https://auth.test/token?scope=repository:other/repo:push", own), []string{"https://auth.test"}, refreshCred, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newRealmNet(t, realmRegistry, realmAuth)
			n.challenge(tc.challenge)
			d := n.reg.publishSigned(t)
			_, err := n.client(t, &recordingCreds{cred: tc.cred}, Limits{}).Fetch(context.Background(), n.source(tc.realms...), d.String())
			if err == nil {
				t.Fatal("fetch succeeded")
			}
			if tc.scopeErr && !errors.Is(err, ErrCredentialScope) {
				t.Fatalf("want ErrCredentialScope, got %v", err)
			}
			assertNoSecret(t, err)
			for _, r := range n.sent() {
				if r.host != realmRegistry {
					t.Fatalf("request reached %s: %s %s", r.host, r.method, r.uri)
				}
			}
			n.assertConfined(t)
		})
	}
}

func TestTokenRealmMultipleChallenges(t *testing.T) {
	own := "repository:" + repoPath + ":pull"
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"unconfigured Bearer first, configured second", []string{
			`Bearer realm="https://evil.test/token",scope="` + own + `"`,
			`Bearer realm="https://auth.test/token",scope="` + own + `"`,
		}},
		{"Basic and Bearer in one header", []string{
			`Basic realm="registry", Bearer realm="https://evil.test/token",scope="` + own + `"`,
		}},
		{"repeated realm parameter", []string{
			`Bearer realm="https://auth.test/token",realm="https://evil.test/token",scope="` + own + `"`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newRealmNet(t, realmRegistry, realmAuth)
			d := n.reg.publishSigned(t)
			n.challenge(tc.headers...)
			_, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{}).Fetch(context.Background(), n.source("https://auth.test"), d.String())
			assertNoSecret(t, err)
			if len(n.to(realmEvil)) != 0 {
				t.Fatalf("unconfigured realm contacted: %v", n.to(realmEvil))
			}
			// Basic credentials may go to the registry itself (a Basic
			// challenge), never elsewhere.
			n.assertConfined(t, realmAuth, realmRegistry)
		})
	}
}

// chainlessTransport drops Request from redirect responses, so a redirect hop
// does not record where its chain started (redirect targets here are absolute).
type chainlessTransport struct{ base http.RoundTripper }

func (c chainlessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Request = nil // the next hop's Response.Request
	}
	return resp, err
}

func TestTokenRealmRedirects(t *testing.T) {
	redirectTo := func(target string, code int) func(w http.ResponseWriter, r *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/token") {
				http.Redirect(w, r, target+"?"+r.URL.RawQuery, code)
				return true
			}
			return false
		}
	}
	for _, tc := range []struct {
		name string
		cred Credential
		hook func(w http.ResponseWriter, r *http.Request) bool
		// orasFirst: ORAS's own redirect check (no token request body to
		// another origin) refuses before ours runs, with an unclassified
		// error; the request must still not be followed.
		orasFirst bool
	}{
		{"token GET redirected to another host", basicCred, redirectTo("https://evil.test/token", http.StatusFound), false},
		{"token GET redirected within the realm", basicCred, redirectTo("https://auth.test/token2", http.StatusFound), false},
		{"token POST redirected with 307", refreshCred, redirectTo("https://evil.test/token", http.StatusTemporaryRedirect), true},
		{"token POST redirected within the realm with 308", refreshCred, redirectTo("https://auth.test/token2", http.StatusPermanentRedirect), false},
		{"token GET redirected to the registry", basicCred, redirectTo("https://registry.test/token", http.StatusFound), false},
	} {
		// chainless: the base transport does not record Response.Request, so
		// only CheckRedirect can see where the chain started.
		for _, chainless := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s chainless=%v", tc.name, chainless), func(t *testing.T) {
				n := newRealmNet(t, realmRegistry, realmAuth)
				n.set(func(n *realmNet) { n.tokenHook = tc.hook })
				d := n.reg.publishSigned(t)
				var rt http.RoundTripper = n.transport()
				if chainless {
					rt = chainlessTransport{rt}
				}
				c, err := NewClient(Options{Transport: rt, Credentials: &recordingCreds{cred: tc.cred}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.Fetch(context.Background(), n.source("https://auth.test"), d.String())
				if err == nil || (!tc.orasFirst && !errors.Is(err, ErrCredentialScope)) {
					t.Fatalf("want ErrCredentialScope, got %v", err)
				}
				assertNoSecret(t, err)
				for _, r := range n.sent() {
					if r.host == realmEvil || strings.HasPrefix(r.uri, "/token2") || (r.host == realmRegistry && strings.HasPrefix(r.uri, "/token")) {
						t.Fatalf("redirect followed to %s %s", r.host, r.uri)
					}
				}
				n.assertConfined(t, realmAuth)
			})
		}
	}

	t.Run("registry redirects keep the registry token at the registry", func(t *testing.T) {
		for _, target := range []string{"https://auth.test/blob", "https://evil.test/blob", "https://storage.test/blob"} {
			n := newRealmNet(t, realmRegistry, realmAuth)
			d := n.reg.publishSigned(t)
			n.set(func(n *realmNet) {
				n.registryHook = func(w http.ResponseWriter, r *http.Request) bool {
					if strings.Contains(r.URL.Path, "/blobs/") {
						http.Redirect(w, r, target, http.StatusTemporaryRedirect)
						return true
					}
					return false
				}
			})
			_, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{}).Fetch(context.Background(), n.source("https://auth.test"), d.String())
			if err == nil {
				t.Fatalf("%s: fetch succeeded through a redirect to a host without the blob", target)
			}
			assertNoSecret(t, err)
			u, _ := url.Parse(target)
			for _, r := range n.to(u.Hostname()) {
				if r.uri == "/blob" && r.authz != "" {
					t.Fatalf("%s: redirect carried Authorization", target)
				}
			}
			n.assertConfined(t, realmAuth)
		}
	})
}

func TestTokenRealmFailuresDoNotWeakenAuth(t *testing.T) {
	t.Run("refused credential", func(t *testing.T) {
		n := newRealmNet(t, realmRegistry, realmAuth)
		d := n.reg.publishSigned(t)
		// A hostile token service echoes what it received.
		n.set(func(n *realmNet) {
			n.tokenHook = func(w http.ResponseWriter, r *http.Request) bool {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", fmt.Sprintf("rejected %q %s", r.Header.Get("Authorization"), secretPassword))
				return true
			}
		})
		_, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{}).Fetch(context.Background(), n.source("https://auth.test"), d.String())
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("want ErrUnauthorized, got %v", err)
		}
		assertNoSecret(t, err)
		for _, r := range n.to(realmAuth) {
			if r.authz == "" {
				t.Fatal("anonymous token request after a refused credential")
			}
		}
		for _, r := range n.to(realmRegistry) {
			if r.authz != "" {
				t.Fatalf("registry request with %q after a refused credential", r.authz)
			}
		}
		n.assertConfined(t, realmAuth)
	})

	t.Run("token service timeout", func(t *testing.T) {
		n := newRealmNet(t, realmRegistry, realmAuth)
		d := n.reg.publishSigned(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		n.set(func(n *realmNet) {
			n.tokenHook = func(w http.ResponseWriter, r *http.Request) bool {
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return true
			}
		})
		_, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{RequestTimeout: 200 * time.Millisecond}).Fetch(context.Background(), n.source("https://auth.test"), d.String())
		if err == nil {
			t.Fatal("fetch succeeded")
		}
		assertNoSecret(t, err)
		for _, r := range n.to(realmAuth) {
			if r.authz == "" {
				t.Fatal("anonymous token request after a timeout")
			}
		}
		for _, r := range n.to(realmRegistry) {
			if r.authz != "" {
				t.Fatal("registry request with a token after a timeout")
			}
		}
	})

	t.Run("configured credential missing", func(t *testing.T) {
		n := newRealmNet(t, realmRegistry, realmAuth)
		d := n.reg.publishSigned(t)
		_, err := n.client(t, &recordingCreds{err: errors.New("secret not found")}, Limits{}).Fetch(context.Background(), n.source("https://auth.test"), d.String())
		if !errors.Is(err, ErrCredentials) || len(n.sent()) != 0 {
			t.Fatalf("want ErrCredentials before any request, got %v after %d requests", err, len(n.sent()))
		}
	})

	t.Run("invalid tokenRealms fail before any request", func(t *testing.T) {
		n := newRealmNet(t, realmRegistry, realmAuth)
		d := n.reg.publishSigned(t)
		for _, realms := range [][]string{
			{"http://auth.test"}, {"https://auth.test/token"}, {"https://*.test"}, {"https://127.0.0.1"},
			{"https://registry.test"}, {"https://registry.test:443"},
		} {
			_, err := n.client(t, &recordingCreds{cred: basicCred}, Limits{}).Fetch(context.Background(), n.source(realms...), d.String())
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("%v: want ErrInvalidRequest, got %v", realms, err)
			}
		}
		if len(n.sent()) != 0 {
			t.Fatalf("requests sent: %v", n.sent())
		}
	})
}

func TestTokenRequestGuard(t *testing.T) {
	own := "repository:" + repoPath + ":pull"
	reader := newCredentialScope("https", "registry.test", repoPath, []string{"https://auth.test", "https://auth.test:8443"}, "pull")
	writer := newCredentialScope("https", "registry.test", repoPath, []string{"https://auth.test"}, "pull", "push")
	get := func(rawURL string, scopes ...string) *http.Request {
		q := url.Values{"service": {"registry.test"}}
		for _, s := range scopes {
			q.Add("scope", s)
		}
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req, err := http.NewRequest(http.MethodGet, rawURL+sep+q.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("robot", secretPassword)
		return req
	}
	post := func(rawURL, contentType string, form url.Values) *http.Request {
		req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		return req
	}
	oauth := func(scope string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshSecret}, "scope": {scope}}
	}
	form := "application/x-www-form-urlencoded"
	for _, tc := range []struct {
		name  string
		s     credentialScope
		req   *http.Request
		allow bool
	}{
		{"GET own repository", reader, get("https://auth.test/token", own), true},
		{"GET realm with explicit default port", reader, get("https://auth.test:443/token", own), true},
		{"GET realm with configured port", reader, get("https://auth.test:8443/token", own), true},
		{"GET uppercase host", reader, get("https://AUTH.test/token", own), true},
		{"GET without scope", reader, get("https://auth.test/token"), false},
		{"GET other repository", reader, get("https://auth.test/token", "repository:other:pull"), false},
		{"GET push for a reader", reader, get("https://auth.test/token", "repository:"+repoPath+":push"), false},
		{"GET empty actions", reader, get("https://auth.test/token", "repository:"+repoPath+":"), false},
		{"GET over http", reader, get("http://auth.test/token", own), false},
		{"GET with userinfo", reader, get("https://u@auth.test/token", own), false},
		{"GET with a body", reader, func() *http.Request {
			r := get("https://auth.test/token", own)
			r.Body = io.NopCloser(strings.NewReader("x"))
			return r
		}(), false},
		{"GET unconfigured realm", reader, get("https://evil.test/token", own), false},
		{"GET IP realm", reader, get("https://127.0.0.1/token", own), false},
		{"GET realm query adds a scope", reader, get("https://auth.test/token?scope=repository:other:pull", own), false},
		{"POST own repository", reader, post("https://auth.test/token", form, oauth(own)), true},
		{"POST form with charset", reader, post("https://auth.test/token", form+"; charset=utf-8", oauth(own)), true},
		{"POST push for a writer", writer, post("https://auth.test/token", form, oauth("repository:"+repoPath+":pull,push")), true},
		{"POST delete for a writer", writer, post("https://auth.test/token", form, oauth("repository:"+repoPath+":delete")), false},
		{"POST other repository among own", reader, post("https://auth.test/token", form, oauth(own+" repository:other:pull")), false},
		{"POST JSON body", reader, post("https://auth.test/token", "application/json", oauth(own)), false},
		{"POST oversized form", reader, post("https://auth.test/token", form, url.Values{"scope": {own}, "zpad": {strings.Repeat("a", maxTokenForm)}}), false},
		{"POST body not rewindable", reader, func() *http.Request {
			r := post("https://auth.test/token", form, oauth(own))
			r.GetBody = nil
			return r
		}(), false},
		{"PUT to the realm", reader, func() *http.Request {
			r := post("https://auth.test/token", form, oauth(own))
			r.Method = http.MethodPut
			return r
		}(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.s.guard(tc.req)
			if tc.allow {
				if err != nil || out == nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrCredentialScope) || out != nil {
				t.Fatalf("want ErrCredentialScope, got %v", err)
			}
			assertNoSecret(t, err)
		})
	}

	t.Run("redirects of credentialed realm requests are refused", func(t *testing.T) {
		first := get("https://auth.test/token", own)
		if err := reader.redirectScope([]*http.Request{first}); !errors.Is(err, ErrCredentialScope) {
			t.Fatalf("want ErrCredentialScope, got %v", err)
		}
		anon, _ := http.NewRequest(http.MethodGet, "https://auth.test/token", nil)
		if err := reader.redirectScope([]*http.Request{anon}); err != nil {
			t.Fatalf("anonymous token redirect refused: %v", err)
		}
		reg, _ := http.NewRequest(http.MethodGet, "https://registry.test/v2/"+repoPath+"/blobs/sha256:1", nil)
		reg.Header.Set("Authorization", "Bearer x")
		if err := reader.redirectScope([]*http.Request{reg}); err != nil {
			t.Fatalf("registry redirect refused: %v", err)
		}

		// The transport refuses the hop on its own, whatever CheckRedirect did.
		for _, target := range []string{"https://evil.test/token", "https://auth.test/token2"} {
			hop, _ := http.NewRequest(http.MethodGet, target, nil)
			hop.Response = &http.Response{Request: first}
			if out, err := reader.guard(hop); !errors.Is(err, ErrCredentialScope) || out != nil {
				t.Fatalf("%s: transport followed a realm redirect: %v", target, err)
			}
		}
		hop, _ := http.NewRequest(http.MethodGet, "https://storage.test/blob", nil)
		hop.Header.Set("Authorization", "Bearer x")
		hop.Response = &http.Response{Request: reg}
		if out, err := reader.guard(hop); err != nil || out.Header.Get("Authorization") != "" {
			t.Fatalf("registry redirect: %v", err)
		}
	})
}
