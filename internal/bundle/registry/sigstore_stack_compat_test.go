//go:build registrycompat

package registry_test

// A disposable, test-owned Sigstore instance for real Cosign keyless signing
// (KONSTAPEL_SIGSTORE_STACK, run by scripts/registry-compat.sh). Every
// component is a pinned image from scripts/runtime.env; every key, CA and
// token is generated for this run and never leaves the test's temporary
// directories and containers:
//
//   - two test OIDC issuers, https://issuer-a.test and https://issuer-b.test:
//     an nginx container serving only their discovery documents and JWKS over
//     TLS from a throwaway CA. The test signs ID tokens itself with keys it
//     generated; the private keys never enter a container.
//   - Fulcio (ephemeral in-memory CA, no CT log) trusting exactly those two
//     issuers for email identities.
//   - Rekor v1 (in-memory signer) on Trillian (log server and signer) with a
//     PostgreSQL backend on tmpfs; the Trillian schema is the one the go.sum
//     pinned Trillian module ships (scripts/check-dependencies.sh requires the
//     image tags to match it).
//   - a timestamp authority (in-memory signer, NTP monitoring off).
//
// All containers share one labelled bridge network; only Fulcio, Rekor and
// the timestamp authority publish a loopback port, for Cosign. From the
// services' keys the test builds a trusted root and a signing configuration
// with the pinned Cosign CLI (cosign trusted-root create, cosign
// signing-config create). Cosign's outbound HTTP(S) goes to a closed port
// except for loopback, so nothing reaches the public Sigstore instance.
// Containers are removed with their anonymous volumes and the network is
// removed at cleanup; the script removes anything still carrying the run
// label and fails if a container, network or new volume remains.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test issuers. They are reserved .test names that resolve only inside the
// stack's network.
const (
	issuerA = "https://issuer-a.test"
	issuerB = "https://issuer-b.test"
)

// stackImages are the pinned images, from scripts/runtime.env.
type stackImages struct {
	Fulcio, Rekor, TrillianServer, TrillianSigner, DB, TSA, OIDC string
}

func stackImagesFromEnv(t *testing.T) stackImages {
	t.Helper()
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is required (run through scripts/registry-compat.sh with KONSTAPEL_SIGSTORE_STACK=1)", name)
		}
		return v
	}
	return stackImages{
		Fulcio: get("KONSTAPEL_SIGSTORE_FULCIO_IMAGE"), Rekor: get("KONSTAPEL_SIGSTORE_REKOR_IMAGE"),
		TrillianServer: get("KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE"), TrillianSigner: get("KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE"),
		DB: get("KONSTAPEL_SIGSTORE_DB_IMAGE"), TSA: get("KONSTAPEL_SIGSTORE_TSA_IMAGE"), OIDC: get("KONSTAPEL_SIGSTORE_OIDC_IMAGE"),
	}
}

// testIssuer is one test OIDC issuer: its URL and the signing key the test
// keeps.
type testIssuer struct {
	url string
	key *ecdsa.PrivateKey
}

// token returns an ES256 ID token for an email identity, audience sigstore,
// valid for validity.
func (i *testIssuer) token(t *testing.T, email string, validity time.Duration) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now()
	signed := enc(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "test"}) + "." + enc(map[string]any{
		"iss": i.url, "sub": email, "aud": "sigstore", "email": email, "email_verified": true,
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(validity).Unix(),
	})
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// sigstoreStack is a running disposable Sigstore instance.
type sigstoreStack struct {
	images stackImages
	// Loopback base URLs (http://127.0.0.1:port).
	fulcioURL, rekorURL, tsaURL string
	issuers                     map[string]*testIssuer
	// Verification material fetched from the services.
	fulcioChain, rekorKey, tsaChain []byte
	// rootJSON is the trusted root Cosign and the verifier use; rootFile and
	// signingConfig are the files Cosign reads.
	rootJSON                []byte
	rootFile, signingConfig string
	startTime               time.Time
	dir                     string
}

func stackDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func stackHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

// writeFiles writes world-readable files (the services run as non-root
// users) into a new world-readable directory.
func writeFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// tlsLeaf issues a server certificate for names from a fresh CA and returns
// the CA PEM, the certificate PEM and the key PEM.
func tlsLeaf(t *testing.T, names ...string) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel sigstore-stack test OIDC CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// startSigstoreStack starts the stack for run and registers its teardown.
func startSigstoreStack(t *testing.T, run, cosignBin string) *sigstoreStack {
	t.Helper()
	s := &sigstoreStack{images: stackImagesFromEnv(t), dir: t.TempDir(), issuers: map[string]*testIssuer{}}
	if err := os.Chmod(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := stackHex(t, 4)
	network := "konstapel-sigstore-" + id
	stackDocker(t, "network", "create", "--label", "konstapel.test="+run, network)
	var containers []string
	t.Cleanup(func() {
		for _, c := range containers {
			_ = exec.Command("docker", "rm", "-fv", c).Run()
		}
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	subnet := stackDocker(t, "network", "inspect", network, "--format", "{{(index .IPAM.Config 0).Subnet}}")
	start := func(role string, args ...string) string {
		name := "konstapel-sigstore-" + role + "-" + id
		full := append([]string{"run", "-d", "--name", name, "--label", "konstapel.test=" + run, "--network", network}, args...)
		containers = append(containers, name)
		stackDocker(t, full...)
		return name
	}
	port := func(name, p string) string {
		out := stackDocker(t, "port", name, p)
		out = strings.Split(out, "\n")[0]
		return "http://127.0.0.1:" + out[strings.LastIndex(out, ":")+1:]
	}

	// OIDC issuers: discovery and JWKS only, over TLS.
	caPEM, certPEM, keyPEM := tlsLeaf(t, "issuer-a.test", "issuer-b.test")
	oidcFiles := map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}
	nginx := "events {}\nhttp {\n  access_log off;\n  default_type application/json;\n"
	for _, n := range []struct{ name, url string }{{"a", issuerA}, {"b", issuerB}} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s.issuers[n.url] = &testIssuer{url: n.url, key: key}
		jwk := map[string]string{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "test",
			"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		}
		jwks, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
		disc, _ := json.Marshal(map[string]any{
			"issuer": n.url, "jwks_uri": n.url + "/jwks", "response_types_supported": []string{"id_token"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"},
		})
		oidcFiles[n.name+"/jwks"] = jwks
		oidcFiles[n.name+"/.well-known/openid-configuration"] = disc
		host := strings.TrimPrefix(n.url, "https://")
		nginx += fmt.Sprintf("  server {\n    listen 443 ssl;\n    server_name %s;\n    ssl_certificate /srv/tls.crt;\n    ssl_certificate_key /srv/tls.key;\n    root /srv/%s;\n  }\n", host, n.name)
	}
	nginx += "}\n"
	oidcFiles["nginx.conf"] = []byte(nginx)
	writeFiles(t, filepath.Join(s.dir, "oidc"), oidcFiles)
	start("oidc", "--network-alias", "issuer-a.test", "--network-alias", "issuer-b.test",
		"-v", filepath.Join(s.dir, "oidc")+":/srv:ro", "-v", filepath.Join(s.dir, "oidc", "nginx.conf")+":/etc/nginx/nginx.conf:ro", s.images.OIDC)

	// Trillian on PostgreSQL (tmpfs), with the go.sum-pinned module's schema.
	schema := trillianSchema(t)
	writeFiles(t, filepath.Join(s.dir, "db"), map[string][]byte{"storage.sql": schema})
	dbPass := stackHex(t, 16)
	db := start("db", "--network-alias", "db", "--tmpfs", "/var/lib/postgresql/data",
		"-e", "POSTGRES_USER=trillian", "-e", "POSTGRES_PASSWORD="+dbPass, "-e", "POSTGRES_DB=trillian",
		"-v", filepath.Join(s.dir, "db")+":/docker-entrypoint-initdb.d:ro", s.images.DB)
	waitFor(t, "database", 90*time.Second, func() error {
		return exec.Command("docker", "exec", db, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "trillian", "-d", "trillian").Run()
	}, db)
	uri := "--postgresql_uri=postgresql:///trillian?host=db&user=trillian&password=" + dbPass
	trillianFlags := []string{"--storage_system=postgresql", "--quota_system=noop", uri, "--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091", "--alsologtostderr"}
	tls := start("trillian-server", append([]string{"--network-alias", "trillian", "--restart", "on-failure:5", s.images.TrillianServer}, trillianFlags...)...)
	tsig := start("trillian-signer", append([]string{"--restart", "on-failure:5", s.images.TrillianSigner}, append(trillianFlags, "--force_master", "--sequencer_interval=100ms", "--batch_size=100")...)...)

	// Rekor v1 creates its tree on first start; it is restarted until
	// Trillian answers.
	rekor := start("rekor", "--restart", "on-failure:10", "-p", "127.0.0.1::3000", s.images.Rekor, "serve",
		"--trillian_log_server.address=trillian", "--trillian_log_server.port=8090", "--rekor_server.address=0.0.0.0",
		"--rekor_server.hostname=rekor.test", "--rekor_server.signer=memory", "--enable_retrieve_api=false")

	// Fulcio trusts exactly the two test issuers (email identities) and may
	// reach them only on the stack's subnet.
	fulcioCfg := fmt.Sprintf("oidc-issuers:\n  %[1]s:\n    issuer-url: %[1]s\n    client-id: sigstore\n    type: email\n  %[2]s:\n    issuer-url: %[2]s\n    client-id: sigstore\n    type: email\n", issuerA, issuerB)
	writeFiles(t, filepath.Join(s.dir, "fulcio"), map[string][]byte{"config.yaml": []byte(fulcioCfg), "oidc-ca.pem": caPEM})
	fulcio := start("fulcio", "-p", "127.0.0.1::8080", "-e", "SSL_CERT_FILE=/etc/fulcio-config/oidc-ca.pem",
		"-v", filepath.Join(s.dir, "fulcio")+":/etc/fulcio-config:ro", s.images.Fulcio, "serve",
		"--ca=ephemeralca", "--ct-log-url=", "--port=8080", "--oidc-allowed-cidrs="+subnet)
	tsa := start("tsa", "-p", "127.0.0.1::3000", s.images.TSA, "timestamp-server", "serve",
		"--host=0.0.0.0", "--port=3000", "--timestamp-signer=memory", "--disable-ntp-monitoring")

	s.fulcioURL, s.rekorURL, s.tsaURL = port(fulcio, "8080/tcp"), port(rekor, "3000/tcp"), port(tsa, "3000/tcp")
	all := []string{db, tls, tsig, rekor, fulcio, tsa}
	hc := &http.Client{Timeout: 5 * time.Second}
	get := func(url string) ([]byte, error) {
		resp, err := hc.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s: %d %s", url, resp.StatusCode, b)
		}
		return b, err
	}
	var trustBundle []byte
	waitFor(t, "fulcio", 90*time.Second, func() (err error) { trustBundle, err = get(s.fulcioURL + "/api/v2/trustBundle"); return }, all...)
	waitFor(t, "rekor", 120*time.Second, func() (err error) { s.rekorKey, err = get(s.rekorURL + "/api/v1/log/publicKey"); return }, all...)
	waitFor(t, "timestamp authority", 60*time.Second, func() (err error) { s.tsaChain, err = get(s.tsaURL + "/api/v1/timestamp/certchain"); return }, all...)
	var tb struct {
		Chains []struct{ Certificates []string } `json:"chains"`
	}
	if err := json.Unmarshal(trustBundle, &tb); err != nil || len(tb.Chains) != 1 {
		t.Fatalf("fulcio trust bundle: %v (%d chains)", err, len(tb.Chains))
	}
	s.fulcioChain = []byte(strings.Join(tb.Chains[0].Certificates, ""))

	// The trusted root and signing configuration, built by the pinned Cosign
	// from the material just fetched; no defaults from the public instance.
	s.startTime = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	writeFiles(t, filepath.Join(s.dir, "material"), map[string][]byte{"fulcio.pem": s.fulcioChain, "rekor.pub": s.rekorKey, "tsa.pem": s.tsaChain})
	s.rootFile = filepath.Join(s.dir, "material", "trusted_root.json")
	s.signingConfig = filepath.Join(s.dir, "material", "signing_config.json")
	s.rootJSON = s.trustedRoot(t, cosignBin, s.rootFile, filepath.Join(s.dir, "material", "rekor.pub"), filepath.Join(s.dir, "material", "tsa.pem"))
	st := s.startTime.Format(time.RFC3339)
	s.cosign(t, cosignBin, "signing-config", "create",
		"--fulcio=url="+s.fulcioURL+",api-version=1,start-time="+st+",operator=konstapel-test",
		"--rekor=url="+s.rekorURL+",api-version=1,start-time="+st+",operator=konstapel-test", "--rekor-config=ANY",
		"--tsa=url="+s.tsaURL+"/api/v1/timestamp,api-version=1,start-time="+st+",operator=konstapel-test", "--tsa-config=ANY",
		"--out", s.signingConfig)
	return s
}

// trustedRoot builds a trusted root for this stack's Fulcio with the given
// Rekor key and TSA chain (an empty tsaChain path omits the TSA), writes it
// to out and returns its bytes.
func (s *sigstoreStack) trustedRoot(t *testing.T, cosignBin, out, rekorKey, tsaChain string) []byte {
	t.Helper()
	st := s.startTime.Format(time.RFC3339)
	args := []string{"trusted-root", "create",
		"--fulcio=url=" + s.fulcioURL + ",certificate-chain=" + filepath.Join(s.dir, "material", "fulcio.pem") + ",start-time=" + st,
		"--rekor=url=" + s.rekorURL + ",public-key=" + rekorKey + ",start-time=" + st}
	if tsaChain != "" {
		args = append(args, "--tsa=url="+s.tsaURL+"/api/v1/timestamp,certificate-chain="+tsaChain+",start-time="+st)
	}
	s.cosign(t, cosignBin, append(args, "--out", out)...)
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cosignEnv is Cosign's environment for the stack: a private HOME and TUF
// cache, and every non-loopback HTTP(S) request sent to a closed port.
func (s *sigstoreStack) cosignEnv() []string {
	home := filepath.Join(s.dir, "cosign-home")
	_ = os.MkdirAll(home, 0o700)
	return []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TUF_ROOT=" + filepath.Join(s.dir, "tuf-unused"),
		"HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost",
	}
}

func (s *sigstoreStack) cosign(t *testing.T, cosignBin string, args ...string) {
	t.Helper()
	cmd := exec.Command(cosignBin, args...)
	cmd.Dir, cmd.Env = s.dir, s.cosignEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign %s: %v\n%s", args[0], err, out)
	}
}

// cosignWrapper writes an executable that runs the pinned Cosign with this
// stack's signing configuration and trusted root for sign and attest, and
// passes any other command through unchanged. sign.Cosign runs it as its
// Cosign binary, so the release signer's own argv, environment allowlist and
// credential handling are what is exercised; only the instance differs.
func (s *sigstoreStack) cosignWrapper(t *testing.T, cosignBin string) string {
	t.Helper()
	for _, p := range []string{cosignBin, s.signingConfig, s.rootFile} {
		if strings.ContainsAny(p, "'\n") {
			t.Fatalf("unexpected path %q", p)
		}
	}
	script := fmt.Sprintf("#!/bin/sh\ncmd=$1\nshift\ncase $cmd in\nsign|attest) exec '%s' \"$cmd\" --signing-config='%s' --trusted-root='%s' \"$@\" ;;\n*) exec '%s' \"$cmd\" \"$@\" ;;\nesac\n",
		cosignBin, s.signingConfig, s.rootFile, cosignBin)
	p := filepath.Join(s.dir, "cosign-stack")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// timestamp asks the stack's timestamp authority for an RFC 3161 timestamp
// over signature, with the request sigstore-go's client (and so Cosign)
// sends: a SHA-256 message imprint, no nonce, no certificate request. It
// returns the DER response a bundle carries.
func (s *sigstoreStack) timestamp(t *testing.T, signature []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(signature)
	type imprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	req, err := asn1.Marshal(struct {
		Version        int
		MessageImprint imprint
	}{1, imprint{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.NullRawValue}, sum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(s.tsaURL+"/api/v1/timestamp", "application/timestamp-query", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("timestamp authority: %d %s", resp.StatusCode, body)
	}
	return body
}

// trillianSchema reads the PostgreSQL schema of the Trillian module version
// go.sum pins (the script downloads it first).
func trillianSchema(t *testing.T) []byte {
	t.Helper()
	out, err := exec.Command("go", "list", "-mod=readonly", "-m", "-f", "{{.Version}} {{.Dir}}", "github.com/google/trillian").Output()
	if err != nil {
		t.Fatalf("go list github.com/google/trillian: %v", err)
	}
	version, dir, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if dir == "" {
		t.Fatalf("github.com/google/trillian %s is not downloaded (go mod download github.com/google/trillian)", version)
	}
	for _, img := range []string{os.Getenv("KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE"), os.Getenv("KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE")} {
		if !strings.Contains(img, ":"+version+"@") {
			t.Fatalf("Trillian image %s does not match the schema of github.com/google/trillian %s", img, version)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "storage", "postgresql", "schema", "storage.sql"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitFor polls ready until it succeeds or timeout passes, then fails with
// the logs of the named containers.
func waitFor(t *testing.T, what string, timeout time.Duration, ready func() error, containers ...string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := ready()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			var logs strings.Builder
			for _, c := range containers {
				out, _ := exec.Command("docker", "logs", "--tail", "30", c).CombinedOutput()
				fmt.Fprintf(&logs, "--- %s\n%s\n", c, out)
			}
			t.Fatalf("%s not ready after %s: %v\n%s", what, timeout, err, logs.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// stackVersions reports each component's image and the version it reports.
func (s *sigstoreStack) versions(t *testing.T) map[string]string {
	t.Helper()
	v := func(image string, args ...string) string {
		out, err := exec.Command("docker", append([]string{"run", "--rm", "--network", "none"}, append([]string{"--entrypoint", args[0], image}, args[1:]...)...)...).CombinedOutput()
		if err != nil {
			return "unknown"
		}
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "GitVersion:") {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "GitVersion:"))
			}
		}
		return strings.TrimSpace(strings.Split(string(out), "\n")[0])
	}
	return map[string]string{
		"fulcio":            s.images.Fulcio + " " + v(s.images.Fulcio, "/usr/local/bin/fulcio-server", "version"),
		"rekor":             s.images.Rekor + " " + v(s.images.Rekor, "/usr/local/bin/rekor-server", "version"),
		"tsa":               s.images.TSA + " " + v(s.images.TSA, "timestamp-server", "version"),
		"trillianLogServer": s.images.TrillianServer, "trillianLogSigner": s.images.TrillianSigner,
		"database": s.images.DB, "oidcIssuer": s.images.OIDC + " (static discovery and JWKS; tokens signed by the test)",
	}
}
