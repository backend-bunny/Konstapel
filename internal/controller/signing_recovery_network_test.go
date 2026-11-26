package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/s3store/s3fake"
)

// add-evidence-signing-recovery 5.4: the network boundary of signing
// recovery, in the normal cluster-free checks and without a Sigstore stack.
//
// The process's default HTTP transport is replaced by one whose dialer
// records every outbound connection and refuses, at once and before any
// name resolution, every destination but the S3 fixture's listener. The S3
// adapter clones that transport for its client (s3store.tlsClient), as does
// any library using the default client, so a recovery that reached Fulcio,
// Rekor, a timestamp authority, a TUF mirror, or an OIDC issuer would be
// recorded and refused deterministically: no DNS failure or timeout is
// involved. The Kubernetes API is the in-memory fake client, which opens no
// connection, so the only allowed traffic is the S3 fixture's.

// errOutbound is the boundary's refusal.
var errOutbound = errors.New("network boundary: outbound connection refused")

// netBoundary is a deny-by-default dialer that records every attempt.
type netBoundary struct {
	mu       sync.Mutex
	allowed  map[string]bool
	attempts []string // host:port of every dial, in order
}

// installNetworkBoundary replaces http.DefaultTransport with a clone that
// dials only through the boundary and uses no proxy, for the test's
// duration. The test must not run in parallel.
func installNetworkBoundary(t *testing.T) *netBoundary {
	t.Helper()
	b := &netBoundary{allowed: map[string]bool{}}
	saved := http.DefaultTransport
	base, ok := saved.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is a %T, not an *http.Transport", saved)
	}
	guarded := base.Clone()
	guarded.Proxy = nil // a proxy would hide the destination behind one address
	guarded.DialContext = b.dial
	guarded.DialTLSContext = nil
	http.DefaultTransport = guarded
	t.Cleanup(func() {
		http.DefaultTransport = saved
		guarded.CloseIdleConnections()
	})
	return b
}

func (b *netBoundary) allow(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowed[addr] = true
}

func (b *netBoundary) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	b.mu.Lock()
	b.attempts = append(b.attempts, addr)
	ok := b.allowed[addr]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s %s", errOutbound, network, addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// take returns and clears the attempts: the allowed count and every
// refused destination.
func (b *netBoundary) take() (allowed int, refused []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.attempts {
		if b.allowed[a] {
			allowed++
		} else {
			refused = append(refused, a)
		}
	}
	b.attempts = nil
	return allowed, refused
}

// keylessEndpoints are the services keyless signing and verification would
// contact: the public-good Sigstore instance and the identity providers its
// clients use for ambient credentials.
var keylessEndpoints = map[string]string{
	"Fulcio":             "https://fulcio.sigstore.dev/api/v2/signingCert",
	"Rekor":              "https://rekor.sigstore.dev/api/v1/log/entries",
	"Rekor v2":           "https://log2025-1.rekor.sigstore.dev/api/v2/log/entries",
	"timestamp":          "https://timestamp.sigstore.dev/api/v1/timestamp",
	"TUF":                "https://tuf-repo-cdn.sigstore.dev/root.json",
	"Sigstore OIDC":      "https://oauth2.sigstore.dev/auth/.well-known/openid-configuration",
	"GitHub OIDC":        "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
	"cloud metadata":     "http://169.254.169.254/latest/api/token",
	"plain-HTTP example": "http://example.com/",
}

// The boundary is not vacuous: requests to every keyless service, through
// the default client and through a clone of the default transport (the S3
// adapter's construction), fail with the boundary's refusal, without name
// resolution or a timeout, and each destination is recorded. An allowed
// listener is reached.
func TestNetworkBoundaryRefusesKeylessServices(t *testing.T) {
	b := installNetworkBoundary(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(srv.Close)
	b.allow(srv.Listener.Addr().String())

	clients := map[string]*http.Client{
		"default client":   http.DefaultClient,
		"cloned transport": {Transport: http.DefaultTransport.(*http.Transport).Clone()},
	}
	var want []string
	for cname, c := range clients {
		for service, url := range keylessEndpoints {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s reached %s (%s)", cname, service, url)
			}
			if !errors.Is(err, errOutbound) {
				t.Fatalf("%s to %s failed for another reason than the boundary: %v", cname, service, err)
			}
			want = append(want, req.URL.Host+map[string]string{"https": ":443", "http": ":80"}[req.URL.Scheme])
		}
		resp, err := c.Get(srv.URL)
		if err != nil || resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s did not reach the allowed listener: %v", cname, err)
		}
		_ = resp.Body.Close()
	}
	allowed, refused := b.take()
	slices.Sort(want)
	slices.Sort(refused)
	if !slices.Equal(refused, want) || allowed == 0 {
		t.Fatalf("recorded refusals %v (allowed %d), want %v", refused, allowed, want)
	}
}

// s3Log records the S3 fixture's requests as "METHOD key".
type s3Log struct {
	mu   sync.Mutex
	reqs []string
}

func (l *s3Log) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.reqs = append(l.reqs, r.Method+" "+r.URL.Path)
		l.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func (l *s3Log) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.reqs
	l.reqs = nil
	return out
}

func countSuffix(reqs []string, prefix, suffix string) int {
	n := 0
	for _, r := range reqs {
		if strings.HasPrefix(r, prefix) && strings.HasSuffix(r, suffix) {
			n++
		}
	}
	return n
}

// realS3Destination points the "primary" destination at the TLS S3 fixture
// (trusted through its caTrust ConfigMap, not as a development fixture),
// installs its credential Secret, and makes the run path build production
// S3 publishers on the fake clock.
func realS3Destination(srv *httptest.Server) func(e *pinEnv) {
	return func(e *pinEnv) {
		ctx := context.Background()
		ns := "konstapel-system"
		ca := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "s3-fixture-ca"},
			Data: map[string]string{"ca.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))}}
		creds := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "s3"},
			Data: map[string][]byte{"accessKeyID": []byte("AKIAFIXTURE"), "secretAccessKey": []byte("fixture-secret")}}
		for _, o := range []client.Object{ca, creds} {
			if err := e.c.Create(ctx, o); err != nil {
				e.t.Fatal(err)
			}
		}
		ed := e.destination("primary")
		ed.Spec.S3.Endpoint = srv.URL
		ed.Spec.S3.CATrust = &v1alpha1.CATrust{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: ca.Name}}
		ed.Generation++
		if err := e.c.Update(ctx, ed); err != nil {
			e.t.Fatal(err)
		}
		requiredWithoutKey(recordedSecret)(e)
		e.rr.Runtime.Destinations.New = s3Publishers(e)
	}
}

// s3Publishers builds the production S3 publisher; only its expiry clock is
// the test's.
func s3Publishers(e *pinEnv) func(context.Context, s3store.Destination, client.Reader, string) (publication.Publisher, error) {
	return func(ctx context.Context, d s3store.Destination, r client.Reader, ns string) (publication.Publisher, error) {
		p, err := s3store.NewPublisher(ctx, d, r, controllerNamespace(ns))
		if err != nil {
			return nil, err
		}
		p.Now = func() time.Time { return e.now }
		return p, nil
	}
}

// A run's Required signing fails for a missing key and its archive is
// retained in a real S3 publisher's storage; a new leader recovers it.
// Every outbound connection of the run and of the recovery is recorded:
// both reach only the S3 fixture, and nothing else is attempted. The
// recovery stores exactly one signature and one commit, and the stored
// bundle is a key-based Sigstore bundle v0.3 with no certificate, no
// transparency-log entry and no timestamp, which verifies offline under the
// pinned key. Ambient Sigstore and GitHub identity tokens are set and never
// used.
func TestSigningRecoveryNetworkBoundary(t *testing.T) {
	for _, v := range []string{"SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(v, "ambient-sentinel-"+v)
	}
	b := installNetworkBoundary(t)
	fixture, log := s3fake.New(), &s3Log{}
	fixture.Versioning = "Enabled"
	srv := httptest.NewTLSServer(log.wrap(fixture))
	t.Cleanup(srv.Close)
	b.allow(srv.Listener.Addr().String())

	var pe *pinEnv
	e := newSignEnv(t, func(p *pinEnv) {
		pe = p
		fixture.Now = func() time.Time { return pe.now }
		realS3Destination(srv)(p)
	})
	e.step(e.name)
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	if !retainedSigningFailure(e.run_()) {
		t.Fatalf("fixture is not a retained SigningFailed run: %s", js(e.run_().Status))
	}
	if allowed, refused := b.take(); len(refused) != 0 || allowed == 0 {
		t.Fatalf("the run attempted outbound connections %v (S3 fixture %d)", refused, allowed)
	}
	if reqs := log.take(); countSuffix(reqs, "PUT ", "/package.tar.gz") == 0 || countSuffix(reqs, "PUT ", "/commit.json") != 0 {
		t.Fatalf("the failed run did not stage its archive uncommitted: %v", reqs)
	}

	// A new leader: nothing in memory, its own S3 client under the boundary.
	runtime := e.rr.Runtime
	runtime.Destinations = &DestinationPublishers{Reader: e.c, New: s3Publishers(e.pinEnv)}
	re := &recoveryEnv{signEnv: e, failed: e.run_().Status.DeepCopy(),
		rec: &SigningRecoveryReconciler{Client: e.c, Reader: e.c, Runtime: runtime, Now: func() time.Time { return e.now }}}
	_, fp := re.installKey("pw-network")
	e.now = e.now.Add(time.Minute)
	re.requestKey("network-boundary", e.name, re.uid(), fp)
	for i := 0; i < 4 && re.esr("network-boundary").Status.CompletedAt == nil; i++ {
		re.reconcile("network-boundary")
	}
	re.wantSucceeded("network-boundary", v1alpha1.RecoveryRecovered)
	allowed, refused := b.take()
	if len(refused) != 0 {
		t.Fatalf("recovery attempted outbound connections beyond the S3 fixture: %v", refused)
	}
	if allowed == 0 {
		t.Fatal("recovery opened no S3 connection through the boundary; the boundary did not observe its client")
	}
	reqs := log.take()
	if countSuffix(reqs, "PUT ", "/package.sigstore.json") != 1 || countSuffix(reqs, "PUT ", "/commit.json") != 1 || countSuffix(reqs, "PUT ", "/package.tar.gz") != 0 {
		t.Fatalf("recovery did not store exactly one signature and one commit over the retained archive: %v", reqs)
	}

	run := e.run_()
	pub := run.Status.Publication
	if run.Status.Phase != v1alpha1.RunCompleted || !meta.IsStatusConditionTrue(run.Status.Conditions, v1alpha1.ConditionPublished) ||
		pub == nil || pub.Commit == nil || pub.Signature == nil || pub.Signature.KeyFingerprint != fp || evidenceOf(&run.Status) != evidenceOf(re.failed) {
		t.Fatalf("want the run Completed and published, signed under %s, with its evidence unchanged: %s", fp, js(run.Status))
	}

	raw := storedSignature(t, fixture, string(run.UID))
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != pub.Signature.SHA256 {
		t.Fatalf("the stored bundle is not the run's recorded signature %s", pub.Signature.SHA256)
	}
	key, err := evidencesign.ParsePublicKey([]byte(run.Status.SigningIntent.Key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	d, err := evidencesign.ParseArchiveDigest(pub.PackageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyOnlyBundle(raw, d, key); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if bytes.Contains(raw, []byte("ambient-sentinel")) {
		t.Fatalf("the bundle carries an ambient identity token: %s", raw)
	}
}

// storedSignature returns the run's only stored signature object, which
// must have one version.
func storedSignature(t *testing.T, f *s3fake.Server, runUID string) []byte {
	t.Helper()
	f.Lock()
	defer f.Unlock()
	var found [][]byte
	for k, vs := range f.Objects {
		if strings.Contains(k, "/"+runUID+"/") && strings.HasSuffix(k, "/"+evidencesign.BundleFileName) {
			for _, v := range vs {
				if !v.Deleted {
					found = append(found, v.Body)
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("storage holds %d signature versions for run %s, want 1", len(found), runUID)
	}
	return found[0]
}

// keyOnlyBundle checks a recovered bundle against the pinned Cosign's
// key-based format: a Sigstore bundle v0.3 whose verification material is
// only the signing key's hint, with a message signature over the archive
// digest, and no certificate or chain, transparency-log entry, inclusion
// promise or proof, RFC 3161 timestamp, or DSSE envelope. It must verify
// offline under the pinned key.
func keyOnlyBundle(raw []byte, archive evidencesign.ArchiveDigest, key evidencesign.PublicKey) error {
	// The exact JSON members, so that no field the protobuf mapping would
	// ignore or a later bundle version adds can carry keyless material.
	members := func(raw json.RawMessage, what string, want ...string) (map[string]json.RawMessage, error) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%s is not a JSON object: %v", what, err)
		}
		got := make([]string, 0, len(m))
		for k := range m {
			got = append(got, k)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return nil, fmt.Errorf("%s has members %v, want exactly %v", what, got, want)
		}
		return m, nil
	}
	top, err := members(raw, "the bundle", "mediaType", "verificationMaterial", "messageSignature")
	if err != nil {
		return err
	}
	vm, err := members(top["verificationMaterial"], "verificationMaterial", "publicKey")
	if err != nil {
		return err
	}
	if _, err := members(vm["publicKey"], "verificationMaterial.publicKey", "hint"); err != nil {
		return err
	}
	if _, err := members(top["messageSignature"], "messageSignature", "messageDigest", "signature"); err != nil {
		return err
	}

	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return fmt.Errorf("the bundle does not parse as a Sigstore bundle: %v", err)
	}
	pb := b.Bundle
	m := pb.GetVerificationMaterial()
	der, _ := pem.Decode(key.PEM)
	hint := sha256.Sum256(der.Bytes)
	switch {
	case pb.GetMediaType() != evidencesign.BundleMediaType:
		return fmt.Errorf("media type %q, want %s", pb.GetMediaType(), evidencesign.BundleMediaType)
	case m.GetCertificate() != nil || m.GetX509CertificateChain() != nil:
		return errors.New("the bundle carries a certificate")
	case m.GetPublicKey() == nil || m.GetPublicKey().GetHint() != base64.StdEncoding.EncodeToString(hint[:]):
		return fmt.Errorf("the verification material is not the pinned key's hint: %v", m.GetPublicKey())
	case len(m.GetTlogEntries()) != 0 || b.HasInclusionPromise() || b.HasInclusionProof():
		return errors.New("the bundle carries a transparency-log entry")
	case m.GetTimestampVerificationData() != nil || len(m.GetTimestampVerificationData().GetRfc3161Timestamps()) != 0:
		return errors.New("the bundle carries timestamp verification data")
	case pb.GetDsseEnvelope() != nil || pb.GetMessageSignature() == nil:
		return errors.New("the bundle content is not a message signature")
	case !bytes.Equal(pb.GetMessageSignature().GetMessageDigest().GetDigest(), archive[:]):
		return errors.New("the message signature does not sign the archive digest")
	}
	if vc, err := b.VerificationContent(); err != nil || vc.Certificate() != nil || vc.PublicKey() == nil {
		return fmt.Errorf("the verification content is not a bare public key: %v", err)
	}
	if v, err := evidencesign.Verify(raw, archive, key); err != nil || v.KeyFingerprint != key.Fingerprint {
		return fmt.Errorf("the bundle does not verify offline under the pinned key: %v", err)
	}
	return nil
}

// The bundle check is not vacuous: a signer's key-based bundle passes, and
// the same bundle with a certificate, a certificate chain, a
// transparency-log entry, an RFC 3161 timestamp, a DSSE envelope, another
// key's hint, or another media type is refused, each for its own reason.
func TestKeyOnlyBundleCheckRefusesKeylessMaterial(t *testing.T) {
	sec, _ := signingKeySecret(t, "bundle-check", "pw")
	s, err := evidencesign.NewSecretSigner(sec.Data)
	if err != nil {
		t.Fatal(err)
	}
	d := evidencesign.DigestArchive([]byte("archive"))
	sig, err := s.Sign(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyOnlyBundle(sig.Bundle, d, s.PublicKey()); err != nil {
		t.Fatalf("a key-based bundle was refused: %v", err)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(sig.Bundle, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	vm := func(m map[string]any) map[string]any { return m["verificationMaterial"].(map[string]any) }
	for name, c := range map[string]struct {
		edit func(m map[string]any)
		want string
	}{
		"certificate": {func(m map[string]any) { vm(m)["certificate"] = map[string]any{"rawBytes": "AA=="} }, "members"},
		"certificate chain": {func(m map[string]any) {
			vm(m)["x509CertificateChain"] = map[string]any{"certificates": []any{map[string]any{"rawBytes": "AA=="}}}
		}, "members"},
		"tlog entry": {func(m map[string]any) {
			vm(m)["tlogEntries"] = []any{map[string]any{"logIndex": "1", "integratedTime": "1"}}
		}, "members"},
		"RFC 3161 timestamp": {func(m map[string]any) {
			vm(m)["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{map[string]any{"signedTimestamp": "AA=="}}}
		}, "members"},
		"DSSE envelope":  {func(m map[string]any) { m["dsseEnvelope"] = map[string]any{"payload": "AA=="} }, "members"},
		"other key hint": {func(m map[string]any) { vm(m)["publicKey"] = map[string]any{"hint": "b3RoZXI="} }, "hint"},
		"v0.2 media type": {func(m map[string]any) {
			m["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
		}, "media type"},
	} {
		if err := keyOnlyBundle(edit(c.edit), d, s.PublicKey()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want refusal mentioning %q, got %v", name, c.want, err)
		}
	}
}
