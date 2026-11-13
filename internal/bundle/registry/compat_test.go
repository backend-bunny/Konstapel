//go:build registrycompat

package registry

// Compatibility suite against a real registry: disposable, test-owned
// instances of the pinned image (KONSTAPEL_REGISTRY_IMAGE) over TLS with a
// throwaway CA, one anonymous and one htpasswd-authenticated. Run it with
// scripts/registry-compat.sh. The fake registry in the other tests cannot show
// real TLS, real custom-CA trust or a real authentication challenge; this can.
//
// The pinned registry does not serve the OCI referrers API
// (GET /v2/<name>/referrers/<digest> answers 404), so this suite exercises the
// referrers tag schema fallback: ORAS Go, when pushing a manifest that has a
// subject to such a registry, also maintains the image index tagged
// sha256-<subject hex>, and pushSigned relies on that deliberately (it checks
// the API is absent and the tag index lists what was pushed).
//
// Not covered: bearer-token (token service) authentication, which this
// registry image only offers through a separate token server, and a registry
// that serves the referrers API (covered by the in-process fake only).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/crypto/bcrypt"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// pki is a throwaway CA and a server certificate for loopback.
type pki struct {
	caPEM, certPEM, keyPEM []byte
	pool                   *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel registry-compat test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "registry-compat"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pki{
		caPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pool:    pool,
	}
}

func randHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type regInstance struct {
	host string // 127.0.0.1:port
	name string
}

// startRegistry runs one registry container over TLS, optionally requiring
// htpasswd authentication, and registers its removal.
const zotConfig = `{"distSpecVersion":"1.1.0","storage":{"rootDirectory":"/var/lib/zot"},"http":{"address":"0.0.0.0","port":"5000","tls":{"cert":"/certs/server.crt","key":"/certs/server.key"}},"log":{"level":"error"}}`

// startZot runs a registry that serves the OCI 1.1 referrers API (anonymous, TLS).
func startZot(t *testing.T, image, run string, p pki) regInstance {
	return startRegistryWith(t, image, run, p, "", zotConfig)
}

// startZotPublisher runs a Zot that requires htpasswd authentication for
// writes but lets anyone read, the access model of a public ghcr.io package
// written by a workflow token. user may read and create; nobody may delete.
func startZotPublisher(t *testing.T, image, run string, p pki, user, htpasswd string) regInstance {
	cfg := `{"distSpecVersion":"1.1.0","storage":{"rootDirectory":"/var/lib/zot"},"http":{"address":"0.0.0.0","port":"5000",` +
		`"tls":{"cert":"/certs/server.crt","key":"/certs/server.key"},"auth":{"htpasswd":{"path":"/certs/htpasswd"}},` +
		`"accessControl":{"repositories":{"**":{"anonymousPolicy":["read"],"policies":[{"users":["` + user + `"],"actions":["read","create","update"]}]}}}},` +
		`"log":{"level":"error"}}`
	return startRegistryWith(t, image, run, p, htpasswd, cfg)
}

func startRegistry(t *testing.T, image, run string, p pki, htpasswd string) regInstance {
	return startRegistryWith(t, image, run, p, htpasswd, "")
}

func startRegistryWith(t *testing.T, image, run string, p pki, htpasswd string, zotCfg string) regInstance {
	zot := zotCfg != ""
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"server.crt": p.certPEM, "server.key": p.keyPEM}
	if htpasswd != "" {
		files["htpasswd"] = []byte(htpasswd)
	}
	if zot {
		files["config.json"] = []byte(zotCfg)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	name := "konstapel-registry-compat-" + randHex(t, 4)
	args := []string{"run", "-d", "--name", name, "--label", "konstapel.test=" + run, "-p", "127.0.0.1::5000",
		"-v", dir + ":/certs:ro"}
	if !zot {
		args = append(args, "-e", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt", "-e", "REGISTRY_HTTP_TLS_KEY=/certs/server.key")
	}
	if htpasswd != "" && !zot {
		args = append(args, "-e", "REGISTRY_AUTH=htpasswd", "-e", "REGISTRY_AUTH_HTPASSWD_REALM=konstapel-test",
			"-e", "REGISTRY_AUTH_HTPASSWD_PATH=/certs/htpasswd")
	}
	args = append(args, image)
	if zot {
		args = append(args, "serve", "/certs/config.json")
	}
	docker(t, args...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-fv", name).Run() })
	port := docker(t, "port", name, "5000/tcp")
	port = port[strings.LastIndex(port, ":")+1:]
	r := regInstance{host: "127.0.0.1:" + port, name: name}

	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool}}}
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := hc.Get("https://" + r.host + "/v2/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry %s not ready: %v\n%s", name, err, docker(t, "logs", name))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type hostCreds map[string]Credential

func (s hostCreds) Credential(_ context.Context, _ bundle.BundleSource, host string) (Credential, error) {
	return s[host], nil
}

func transportFor(pool *x509.CertPool) http.RoundTripper {
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}

// pushSigned publishes the official bundle, a signature, a provenance
// attestation and an unrelated referrer into repo, plus a moved tag pointing at
// a different bundle. It returns the published manifest digest.
func pushSigned(t *testing.T, r regInstance, p pki, cred auth.Credential, tagSchema bool) digest.Digest {
	t.Helper()
	ctx := context.Background()
	repo, err := remote.NewRepository(r.host + "/" + repoPath)
	if err != nil {
		t.Fatal(err)
	}
	repo.Client = &auth.Client{
		Client:     &http.Client{Transport: transportFor(p.pool)},
		Credential: auth.StaticCredential(r.host, cred),
	}
	push := func(mediaType string, body []byte) ocispec.Descriptor {
		d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(body), Size: int64(len(body))}
		if err := repo.Push(ctx, d, bytes.NewReader(body)); err != nil {
			t.Fatalf("push %s: %v", d.Digest, err)
		}
		return d
	}
	a := official(t)
	push(ocispec.MediaTypeEmptyJSON, []byte("{}"))
	push(bundle.LayerMediaType, a.Layer)
	subject := push(ocispec.MediaTypeImageManifest, a.Manifest)

	for _, pt := range []string{CosignSignPredicateType, SLSAProvenanceV1PredicateType} {
		b := sigstoreBundle(pt)
		push(SigstoreBundleArtifactType, b)
		push(ocispec.MediaTypeImageManifest, cosignReferrer(subject.Digest, subject.Size, pt, b))
	}
	// An unrelated referrer on the same subject: listed, never used.
	other := map[string]any{
		"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "artifactType": "application/vnd.example.sbom",
		"config":  map[string]any{"mediaType": ocispec.MediaTypeEmptyJSON, "digest": bundle.EmptyConfigDigest, "size": 2},
		"layers":  []any{map[string]any{"mediaType": ocispec.MediaTypeEmptyJSON, "digest": bundle.EmptyConfigDigest, "size": 2}},
		"subject": map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": subject.Digest.String(), "size": subject.Size},
	}
	raw, _ := json.Marshal(other)
	push(ocispec.MediaTypeImageManifest, raw)
	if tagSchema {
		checkTagSchema(t, r, p, cred, subject.Digest, 3)
	} else {
		checkReferrersAPI(t, r, p, subject.Digest, 3)
	}

	// A moved tag: "stable" points at a different manifest than the pin.
	decoy := push(ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.example.decoy","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"`+bundle.EmptyConfigDigest+`","size":2},"layers":[]}`))
	if err := repo.Tag(ctx, decoy, "stable"); err != nil {
		t.Fatal(err)
	}
	return subject.Digest
}

// checkReferrersAPI confirms the registry really serves the OCI 1.1 referrers
// API for the subject (a 200 image index listing want referrers), reading with
// plain HTTP requests, not the code under test.
func checkReferrersAPI(t *testing.T, r regInstance, p pki, subject digest.Digest, want int) {
	t.Helper()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: transportFor(p.pool)}
	resp, err := hc.Get("https://" + r.host + "/v2/" + repoPath + "/referrers/" + subject.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var idx struct {
		MediaType string               `json:"mediaType"`
		Manifests []ocispec.Descriptor `json:"manifests"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&idx) != nil ||
		idx.MediaType != ocispec.MediaTypeImageIndex || len(idx.Manifests) != want {
		t.Fatalf("referrers API: status %d, index %+v: want an image index listing %d referrers", resp.StatusCode, idx, want)
	}
}

// checkTagSchema confirms what the suite relies on: this registry does not
// serve the referrers API, and the pushes above left a referrers tag schema
// index listing want referrers. It reads with plain HTTP requests, not the
// code under test.
func checkTagSchema(t *testing.T, r regInstance, p pki, cred auth.Credential, subject digest.Digest, want int) {
	t.Helper()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: transportFor(p.pool)}
	get := func(path, accept string) (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodGet, "https://"+r.host+"/v2/"+repoPath+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", accept)
		if cred.Username != "" {
			req.SetBasicAuth(cred.Username, cred.Password)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			t.Fatal(err)
		}
		return resp, buf.Bytes()
	}
	if resp, _ := get("/referrers/"+subject.String(), ocispec.MediaTypeImageIndex); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("registry answers the referrers API with %d; this suite expects a registry without it", resp.StatusCode)
	}
	resp, body := get("/manifests/sha256-"+subject.Encoded(), ocispec.MediaTypeImageIndex)
	var index ocispec.Index
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ocispec.MediaTypeImageIndex ||
		json.Unmarshal(body, &index) != nil || len(index.Manifests) != want {
		t.Fatalf("referrers tag index: status %d, type %q, body %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

// CompatEnv exposes the running registries to compatibility cases that live
// in the external test package registry_test, which may import packages that
// import this one (kubeaccess's Secret-backed credentials and CAs).
type CompatEnv struct {
	Ctx    context.Context
	Pinned string // the published bundle manifest digest
	// Hosts (127.0.0.1:port): anonymous and htpasswd-protected registries
	// with CA CAPEM, and an anonymous registry with an unrelated CA
	// OtherCAPEM.
	Anon, Authd, Other string
	// API is the anonymous Zot (referrers API); APIAuthd a Zot that requires
	// User/Pass for writes and allows anonymous reads. Both use CAPEM.
	API, APIAuthd     string
	CAPEM, OtherCAPEM []byte
	User, Pass        string
	// Record adds a case to the evidence; Skip records a case that did not
	// run, with the reason; CheckFetched asserts a complete tag-schema
	// retrieval of the published bundle.
	Record       func(name string, err error, detail string)
	Skip         func(name, reason string)
	CheckFetched func(t *testing.T, res *Result)
}

// CompatCases are run by TestRegistryCompat after its own cases.
var CompatCases []func(t *testing.T, env CompatEnv)

type compatRecord struct {
	Case   string `json:"case"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

func TestRegistryCompat(t *testing.T) {
	image := os.Getenv("KONSTAPEL_REGISTRY_IMAGE")
	run := os.Getenv("KONSTAPEL_REGISTRY_RUN")
	if image == "" || run == "" {
		t.Skip("run through scripts/registry-compat.sh (KONSTAPEL_REGISTRY_IMAGE, KONSTAPEL_REGISTRY_RUN)")
	}
	p := newPKI(t)
	user, pass := "konstapel-"+randHex(t, 3), randHex(t, 16)
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	anon := startRegistry(t, image, run, p, "")
	authd := startRegistry(t, image, run, p, user+":"+string(hash)+"\n")

	apiImage := os.Getenv("KONSTAPEL_REGISTRY_API_IMAGE")
	if apiImage == "" {
		t.Fatal("KONSTAPEL_REGISTRY_API_IMAGE is required (run through scripts/registry-compat.sh)")
	}
	api := startZot(t, apiImage, run, p)
	apiAuthd := startZotPublisher(t, apiImage, run, p, user, user+":"+string(hash)+"\n")
	// A registry with its own, unrelated CA: trust configured for one
	// registry must not extend to it.
	otherPKI := newPKI(t)
	other := startRegistry(t, image, run, otherPKI, "")
	subjectAnon := pushSigned(t, anon, p, auth.Credential{}, true)
	if s := pushSigned(t, other, otherPKI, auth.Credential{}, true); s != subjectAnon {
		t.Fatalf("the same bundle has different digests: %s, %s", s, subjectAnon)
	}
	subjectAuth := pushSigned(t, authd, p, auth.Credential{Username: user, Password: pass}, true)
	subjectAPI := pushSigned(t, api, p, auth.Credential{}, false)
	if subjectAnon != subjectAuth || subjectAnon != subjectAPI {
		t.Fatalf("the same bundle has different digests: %s, %s, %s", subjectAnon, subjectAuth, subjectAPI)
	}
	pinned := subjectAnon.String()

	var records []compatRecord
	record := func(name string, err error, detail string) {
		r := compatRecord{Case: name, Result: "pass", Detail: detail}
		if err != nil {
			r.Result, r.Detail = "fail", err.Error()
		}
		records = append(records, r)
	}
	skip := func(name, reason string) {
		records = append(records, compatRecord{Case: name, Result: "skip", Detail: reason})
	}
	src := func(r regInstance, withSecret bool) bundle.BundleSource {
		s := bundle.BundleSource{Name: "konstapel-privileged-containers", Repository: r.host + "/" + repoPath}
		if withSecret {
			s.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
		}
		return s
	}
	newClient := func(pool *x509.CertPool, creds CredentialProvider) *Client {
		c, err := NewClient(Options{Transport: transportFor(pool), Credentials: creds})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a := official(t)

	checkFetchedVia := func(t *testing.T, res *Result, via ReferrersSource) {
		t.Helper()
		if res.Digest != pinned || !bytes.Equal(res.Manifest, a.Manifest) || !bytes.Equal(res.Layer, a.Layer) {
			t.Fatalf("retrieved bytes differ from what was published")
		}
		if err := res.RequireProofs(RequiredProofs...); err != nil {
			t.Fatal(err)
		}
		if res.ReferrersSource != via || res.ReferrerCount != 3 || len(res.Proofs) != 2 ||
			len(res.Skipped) != 1 || res.Skipped[0].ArtifactType != "application/vnd.example.sbom" {
			t.Fatalf("referrers: source %q, listed %d, proofs %d, skipped %+v", res.ReferrersSource, res.ReferrerCount, len(res.Proofs), res.Skipped)
		}
		kinds := res.Found()
		if kinds[ProofSignature] != 1 || kinds[ProofProvenance] != 1 {
			t.Fatalf("proof kinds %v", kinds)
		}
	}

	checkFetched := func(t *testing.T, res *Result) {
		t.Helper()
		checkFetchedVia(t, res, ReferrersFromTagSchema)
	}

	t.Run("referrers API registry: anonymous retrieval through the API", func(t *testing.T) {
		res, err := newClient(p.pool, nil).Fetch(ctx, src(api, false), pinned)
		record(t.Name(), err, fmt.Sprintf("referrers via %s, %d proofs, %d skipped", res.sourceOrNone(), len(res.proofsOrNil()), len(res.skippedOrNil())))
		if err != nil {
			t.Fatal(err)
		}
		checkFetchedVia(t, res, ReferrersFromAPI)
	})

	t.Run("anonymous retrieval with the custom CA", func(t *testing.T) {
		res, err := newClient(p.pool, nil).Fetch(ctx, src(anon, false), pinned)
		record(t.Name(), err, fmt.Sprintf("manifest %s, referrers via %s, %d proofs, %d skipped",
			pinned, res.sourceOrNone(), len(res.proofsOrNil()), len(res.skippedOrNil())))
		if err != nil {
			t.Fatal(err)
		}
		checkFetched(t, res)
	})

	t.Run("authenticated retrieval with credentials", func(t *testing.T) {
		creds := hostCreds{authd.host: {Username: user, Password: pass}}
		res, err := newClient(p.pool, creds).Fetch(ctx, src(authd, true), pinned)
		record(t.Name(), err, "")
		if err != nil {
			t.Fatal(err)
		}
		checkFetched(t, res)
	})

	t.Run("wrong password is refused and never echoed", func(t *testing.T) {
		creds := hostCreds{authd.host: {Username: user, Password: "wrong-" + pass}}
		_, err := newClient(p.pool, creds).Fetch(ctx, src(authd, true), pinned)
		ok := errors.Is(err, ErrUnauthorized) && !strings.Contains(err.Error(), pass) && !strings.Contains(err.Error(), "wrong-")
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v", err)}[ok], "")
		if !ok {
			t.Fatalf("want ErrUnauthorized without the password, got %v", err)
		}
	})

	t.Run("no credentials against a protected registry fails", func(t *testing.T) {
		_, err := newClient(p.pool, nil).Fetch(ctx, src(authd, false), pinned)
		ok := errors.Is(err, ErrUnauthorized)
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v", err)}[ok], "")
		if !ok {
			t.Fatalf("want ErrUnauthorized, got %v", err)
		}
	})

	t.Run("a configured credential Secret never falls back to anonymous", func(t *testing.T) {
		// The anonymous registry would serve this request; the configured
		// Secret has no credential, so retrieval must not even try.
		_, err := newClient(p.pool, hostCreds{}).Fetch(ctx, src(anon, true), pinned)
		ok := errors.Is(err, ErrCredentials)
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v", err)}[ok], "")
		if !ok {
			t.Fatalf("want ErrCredentials, got %v", err)
		}
	})

	t.Run("an untrusted CA fails TLS verification", func(t *testing.T) {
		_, err := newClient(x509.NewCertPool(), nil).Fetch(ctx, src(anon, false), pinned)
		var unknown x509.UnknownAuthorityError
		ok := err != nil && (errors.As(err, &unknown) || strings.Contains(err.Error(), "certificate signed by unknown authority"))
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v", err)}[ok], "")
		if !ok {
			t.Fatalf("want a TLS verification failure, got %v", err)
		}
	})

	t.Run("a moved tag does not change what a digest returns", func(t *testing.T) {
		res, err := newClient(p.pool, nil).Fetch(ctx, src(anon, false), pinned)
		record(t.Name(), err, `tag "stable" points at a different manifest`)
		if err != nil {
			t.Fatal(err)
		}
		checkFetched(t, res)
	})

	t.Run("a bundle without referrers has no proofs", func(t *testing.T) {
		// Same bundle, another revision: a new subject nothing refers to, so
		// the registry has no referrers tag for it.
		def := officialDefinition(t)
		def.Source.Revision = strings.Repeat("d", 40)
		bare, err := bundle.Build(def, os.DirFS("../../.."), time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		repo, err := remote.NewRepository(anon.host + "/" + repoPath)
		if err != nil {
			t.Fatal(err)
		}
		repo.Client = &auth.Client{Client: &http.Client{Transport: transportFor(p.pool)}}
		for _, b := range []struct {
			mt   string
			body []byte
		}{{bundle.LayerMediaType, bare.Layer}, {ocispec.MediaTypeImageManifest, bare.Manifest}} {
			d := ocispec.Descriptor{MediaType: b.mt, Digest: digest.FromBytes(b.body), Size: int64(len(b.body))}
			if err := repo.Push(ctx, d, bytes.NewReader(b.body)); err != nil {
				t.Fatal(err)
			}
		}
		res, err := newClient(p.pool, nil).Fetch(ctx, src(anon, false), digest.FromBytes(bare.Manifest).String())
		var missing error
		if err == nil {
			missing = res.RequireProofs(RequiredProofs...)
		}
		ok := err == nil && res.ReferrersSource == ReferrersNone && len(res.Proofs) == 0 && errors.Is(missing, ErrMissingProofs)
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v / %v", err, missing)}[ok], fmt.Sprintf("referrers via %s; %v", res.sourceOrNone(), missing))
		if !ok {
			t.Fatalf("want zero proofs from source none and ErrMissingProofs, got err %v, missing %v", err, missing)
		}
	})

	t.Run("an unknown digest is not found", func(t *testing.T) {
		missing := digest.FromString("not published").String()
		_, err := newClient(p.pool, nil).Fetch(ctx, src(anon, false), missing)
		ok := errors.Is(err, ErrNotFound)
		record(t.Name(), map[bool]error{true: nil, false: fmt.Errorf("got %v", err)}[ok], "")
		if !ok {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	env := CompatEnv{
		Ctx: ctx, Pinned: pinned, Anon: anon.host, Authd: authd.host, Other: other.host,
		API: api.host, APIAuthd: apiAuthd.host,
		CAPEM: p.caPEM, OtherCAPEM: otherPKI.caPEM, User: user, Pass: pass,
		Record: record, Skip: skip, CheckFetched: checkFetched,
	}
	// Each case gets its own deadline: the keyless Sigstore stack case waits
	// for real certificate expiry, which must not eat into later cases.
	for _, c := range CompatCases {
		caseCtx, caseCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		env.Ctx = caseCtx
		c(t, env)
		caseCancel()
	}

	writeCompatEvidence(t, image, apiImage, run, records)
}

func (r *Result) proofsOrNil() []Proof {
	if r == nil {
		return nil
	}
	return r.Proofs
}

func (r *Result) sourceOrNone() ReferrersSource {
	if r == nil {
		return ""
	}
	return r.ReferrersSource
}

func (r *Result) skippedOrNil() []Skipped {
	if r == nil {
		return nil
	}
	return r.Skipped
}

// writeCompatEvidence records the versions the suite ran against and each case.
func writeCompatEvidence(t *testing.T, image, apiImage, run string, records []compatRecord) {
	t.Helper()
	out := os.Getenv("KONSTAPEL_REGISTRY_OUTPUT")
	if out == "" {
		return
	}
	orasVersion := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "oras.land/oras-go/v2" {
				orasVersion = d.Version
			}
		}
	}
	registryVersion := docker(t, "run", "--rm", "--entrypoint", "registry", image, "--version")
	ev := map[string]any{
		"run": run, "recordedAt": time.Now().UTC().Format(time.RFC3339),
		"registryImage": image, "registryVersion": registryVersion,
		"apiRegistryImage": apiImage, "apiRegistryVersion": docker(t, "run", "--rm", "--entrypoint", "/usr/local/bin/zot-linux-amd64", apiImage, "--version"),
		"docker": docker(t, "version", "--format", "client {{.Client.Version}} server {{.Server.Version}}"),
		"orasGo": orasVersion, "go": runtime.Version(),
		"layout":         "Sigstore bundle v0.3 referrers (see docs/policy-bundles.md): listed through the OCI referrers tag schema on registryImage (no referrers API) and through the referrers API on apiRegistryImage",
		"authentication": "anonymous and htpasswd (basic), directly and through kubeaccess (dockerconfigjson Secret, rotation, CA ConfigMap); bearer-token service not covered",
		"publication":    "internal/bundle/publish write-once publication: anonymous-write distribution registry (tag schema) and Zot with htpasswd writes and anonymous reads (referrers API); recovery through a fault-injecting TLS proxy; anonymous read-back failure against the htpasswd distribution registry",
		"signing":        "internal/bundle/sign (pinned Cosign CLI, key mode, no transparency log, outbound HTTP(S) to a closed port) through publish.Completer: digest-only signatures and SLSA provenance for missing kinds only, recovery, refusal of another subject; release.VerifyRelease anonymously under a test public-key rule; keyless signing through a disposable Sigstore instance with KONSTAPEL_SIGSTORE_STACK (sigstore-stack.json), otherwise recorded as skip",
		"official":       "with KONSTAPEL_NETWORK_INTEROP=1: the official keyless release read anonymously from ghcr.io, verified directly, mirrored with mirror.Mirror and bundlerelease mirror into the htpasswd Zot and distribution registries and verified there through the production verifier (and Cosign) under bundles/official-sources.yaml with only the location changed; otherwise recorded as skip",
		"tls":            "throwaway CAs (a second, unrelated one for the per-source trust case), verification always on", "cases": records,
	}
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "registry-compat.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
