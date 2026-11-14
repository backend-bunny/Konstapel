package download

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const (
	teamSigPath   = "/v1/namespaces/dev/assessmentrequests/nightly/signature?uid=req-uid"
	signingSecret = "konstapel-evidence-signing-2026-11"
)

// testSigner is a disposable Cosign-format key generated per test.
func testSigner(t *testing.T) *evidencesign.SecretSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	enc, err := encrypted.Encrypt(der, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	s, err := evidencesign.NewSecretSigner(map[string][]byte{
		evidencesign.SecretPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: enc}),
		evidencesign.SecretPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		evidencesign.SecretPassword:   []byte("pw"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signedEnv is an env whose packages were published signed.
type signedEnv struct {
	*env
	signer *evidencesign.SecretSigner
}

func newSignedEnv(t *testing.T) *signedEnv {
	s := testSigner(t)
	return &signedEnv{env: newEnvSigned(t, s), signer: s}
}

func refByID(t *testing.T, e *env, id string) publication.RunRef {
	for _, name := range []string{"nightly-run", "scheduled-run"} {
		run := &v1alpha1.AssessmentRun{}
		_ = e.c.Get(context.Background(), client.ObjectKey{Name: name}, run)
		ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
		if ref.PublicationID() == id {
			return ref
		}
	}
	t.Fatalf("no run for %s", id)
	return publication.RunRef{}
}

func (e *signedEnv) run(name string) *v1alpha1.AssessmentRun {
	r := &v1alpha1.AssessmentRun{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

// A team downloads both artifacts of its signed package; they verify
// together under the retained key, the response names the key but never
// the key's Secret, and nothing is left in temporary storage.
func TestSignedPackageAndSignatureDownload(t *testing.T) {
	e := newSignedEnv(t)
	run := e.run("nightly-run")
	archive := e.get(teamPath, "team-token")
	sig := e.get(teamSigPath, "team-token")
	if archive.Code != http.StatusOK || sig.Code != http.StatusOK {
		t.Fatalf("archive %d %s, signature %d %s", archive.Code, archive.Body, sig.Code, sig.Body)
	}
	d := evidencesign.DigestArchive(archive.Body.Bytes())
	if d.String() != run.Status.Publication.PackageSHA256 {
		t.Fatal("served archive is not the committed package")
	}
	if _, err := evidencesign.Verify(sig.Body.Bytes(), d, e.signer.PublicKey()); err != nil {
		t.Fatalf("the served pair does not verify: %v", err)
	}
	for _, w := range []http.Header{archive.Header(), sig.Header()} {
		if w.Get("X-Konstapel-Signing") != "signed" || w.Get("X-Konstapel-Signing-Key") != e.signer.PublicKey().Fingerprint ||
			w.Get("X-Konstapel-Signature-SHA256") != run.Status.Publication.Signature.SHA256 || w.Get("Cache-Control") != "private, no-store" {
			t.Fatalf("headers %v", w)
		}
		for k, vs := range w {
			for _, v := range vs {
				if strings.Contains(v, signingSecret) || strings.Contains(k+v, "PRIVATE") {
					t.Fatalf("response exposes key-source details: %s: %s", k, v)
				}
			}
		}
	}
	if !strings.HasSuffix(sig.Header().Get("Content-Disposition"), `.sigstore.json"`) || sig.Header().Get("X-Konstapel-Package-SHA256") != d.String() {
		t.Fatalf("signature headers %v", sig.Header())
	}
	if entries, _ := os.ReadDir(e.srv.TempDir); len(entries) != 0 {
		t.Fatal("temporary download data left behind")
	}
	// The platform route serves the full-binding run's signature too.
	plat := e.run("scheduled-run")
	if w := e.get("/v1/assessmentruns/"+string(plat.UID)+"/signature", "admin-token"); w.Code != http.StatusOK {
		t.Fatalf("platform signature: %d %s", w.Code, w.Body)
	}
}

// The signature route has exactly the archive route's authorization: every
// identity, scope and review failure is answered the same way on both.
func TestSignatureRouteAuthorizationMatchesArchiveRoute(t *testing.T) {
	e := newSignedEnv(t)
	plat := e.run("scheduled-run")
	cases := []struct {
		name, path, token string
		hdr               []string
	}{
		{"team own", "/v1/namespaces/dev/assessmentrequests/nightly/%s?uid=req-uid", "team-token", nil},
		{"no token", "/v1/namespaces/dev/assessmentrequests/nightly/%s?uid=req-uid", "", nil},
		{"forwarded identity only", "/v1/namespaces/dev/assessmentrequests/nightly/%s?uid=req-uid", "", []string{"X-Remote-User", "alice", "Impersonate-User", "alice"}},
		{"unknown token", "/v1/namespaces/dev/assessmentrequests/nightly/%s?uid=req-uid", "other-service-token", nil},
		{"sibling namespace", "/v1/namespaces/prod/assessmentrequests/nightly/%s?uid=req-prod", "team-token", nil},
		{"wrong request UID", "/v1/namespaces/dev/assessmentrequests/nightly/%s?uid=req-old", "team-token", nil},
		{"missing UID", "/v1/namespaces/dev/assessmentrequests/nightly/%s", "team-token", nil},
		{"team to full-binding run", "/v1/assessmentruns/" + string(plat.UID) + "/%s", "team-token", nil},
		{"team to own run, platform route", "/v1/assessmentruns/" + e.nsRun.RunUID + "/%s", "team-token", nil},
		{"guessed run UID", "/v1/assessmentruns/guessed/%s", "admin-token", nil},
		{"platform", "/v1/assessmentruns/" + string(plat.UID) + "/%s", "admin-token", nil},
	}
	for _, c := range cases {
		a := e.get(strings.Replace(c.path, "%s", "download", 1), c.token, c.hdr...)
		s := e.get(strings.Replace(c.path, "%s", "signature", 1), c.token, c.hdr...)
		if a.Code != s.Code {
			t.Errorf("%s: archive %d, signature %d", c.name, a.Code, s.Code)
		}
		noLeak(t, s)
	}
	// The signature route asks for exactly the same SubjectAccessReviews.
	e.rev.asked = nil
	e.get(teamPath, "team-token")
	archiveAsked := strings.Join(e.rev.asked, ";")
	e.rev.asked = nil
	e.get(teamSigPath, "team-token")
	if got := strings.Join(e.rev.asked, ";"); got != archiveAsked || got == "" {
		t.Fatalf("signature reviews %q, archive reviews %q", got, archiveAsked)
	}
	// Revocation and review outages deny both.
	e.rev.grants["alice get dev/assessmentrequests/download/nightly"] = false
	if w := e.get(teamSigPath, "team-token"); w.Code != http.StatusForbidden {
		t.Fatalf("revoked: %d", w.Code)
	}
	e.rev.down = true
	if w := e.get(teamSigPath, "team-token"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("review outage: %d", w.Code)
	}
}

// A damaged, swapped, or inconsistently recorded pair is never served,
// neither the archive nor the signature; missing signature material is
// unavailable, never an unsigned replacement.
func TestDamagedSignedPairIsNotServed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *signedEnv)
		code  int
	}{
		{"signature missing", func(e *signedEnv) { e.pub.SetSignature(e.nsRun, nil) }, http.StatusServiceUnavailable},
		{"signature by another key", func(e *signedEnv) {
			d, _ := evidencesign.ParseArchiveDigest(e.run("nightly-run").Status.Publication.PackageSHA256)
			other, _ := testSigner(t).Sign(context.Background(), d)
			e.pub.SetSignature(e.nsRun, other.Bundle)
		}, http.StatusBadGateway},
		{"signature for another archive (swapped)", func(e *signedEnv) {
			b, _, _ := e.pub.ReadSignature(context.Background(), refByID(t, e.env, e.run("scheduled-run").Status.Publication.PublicationID))
			e.pub.SetSignature(e.nsRun, b)
		}, http.StatusBadGateway},
		{"tampered signature bytes", func(e *signedEnv) {
			b, _, _ := e.pub.ReadSignature(context.Background(), e.nsRun)
			e.pub.SetSignature(e.nsRun, bytes.Replace(b, []byte(`"signature":"M`), []byte(`"signature":"N`), 1))
		}, http.StatusBadGateway},
		{"tampered archive", func(e *signedEnv) { e.pub.Corrupt(e.nsRun, []byte("tampered")) }, http.StatusBadGateway},
		{"receipt names another signature digest", func(e *signedEnv) {
			r := e.run("nightly-run")
			r.Status.Publication.Signature.SHA256 = strings.Repeat("0", 64)
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusBadGateway},
		{"intent pinned another key", func(e *signedEnv) {
			r := e.run("nightly-run")
			o := testSigner(t).PublicKey()
			r.Status.SigningIntent.Key.Fingerprint, r.Status.SigningIntent.Key.PublicKey = o.Fingerprint, string(o.PEM)
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusBadGateway},
		{"retained public key replaced (fingerprint kept)", func(e *signedEnv) {
			r := e.run("nightly-run")
			r.Status.SigningIntent.Key.PublicKey = string(testSigner(t).PublicKey().PEM)
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusBadGateway},
		{"no signing intent", func(e *signedEnv) {
			r := e.run("nightly-run")
			r.Status.SigningIntent = nil
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusBadGateway},
		{"recorded unsigned, stored signed", func(e *signedEnv) {
			r := e.run("nightly-run")
			r.Status.Publication.Signature = nil
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusBadGateway},
		{"expired", func(e *signedEnv) { e.now = e.now.Add(25 * time.Hour) }, http.StatusGone},
		{"orphaned publication", func(e *signedEnv) {
			r := e.run("nightly-run")
			r.Status.Publication.Phase = v1alpha1.PublicationPhase(publication.PhaseOrphaned)
			r.Status.Publication.Availability = v1alpha1.Availability(publication.AvailabilityUnavailable)
			r.Status.Publication.Cleanup.State = v1alpha1.CleanupState(publication.CleanupOrphaned)
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusGone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSignedEnv(t)
			c.setup(e)
			for _, path := range []string{teamPath, teamSigPath} {
				w := e.get(path, "team-token")
				if w.Code != c.code {
					t.Errorf("%s: %d %s", path, w.Code, w.Body)
				}
				noLeak(t, w)
			}
			if entries, _ := os.ReadDir(e.srv.TempDir); len(entries) != 0 {
				t.Error("temporary data left behind")
			}
		})
	}
}

// Unsigned publications keep their archive response, and their signature
// route answers explicitly that there is no signature.
func TestUnsignedPublicationHasNoSignature(t *testing.T) {
	e := newEnv(t)
	a := e.get(teamPath, "team-token")
	if a.Code != http.StatusOK || a.Header().Get("X-Konstapel-Signing") != "unsigned" {
		t.Fatalf("unsigned archive: %d %v", a.Code, a.Header())
	}
	w := e.get(teamSigPath, "team-token")
	if w.Code != http.StatusNotFound || w.Header().Get("X-Konstapel-Signing") != "unsigned" || !strings.Contains(w.Body.String(), "unsigned") {
		t.Fatalf("unsigned signature route: %d %v %s", w.Code, w.Header(), w.Body)
	}
	// An unauthorized caller learns nothing about signing.
	if w := e.get("/v1/namespaces/prod/assessmentrequests/nightly/signature?uid=req-prod", "team-token"); w.Code != http.StatusForbidden || w.Header().Get("X-Konstapel-Signing") != "" {
		t.Fatalf("sibling: %d %v", w.Code, w.Header())
	}
}

// Historical signed packages are served from retained public material alone:
// the download server never reads Secrets, so a retired signing key (or
// current signing readiness) cannot affect them.
func TestSignedDownloadNeedsNoSigningSecret(t *testing.T) {
	e := newSignedEnv(t)
	e.srv.Reader = noSecrets{t: t, Reader: e.c}
	if w := e.get(teamSigPath, "team-token"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

type noSecrets struct {
	client.Reader
	t *testing.T
}

func (n noSecrets) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		n.t.Fatalf("the download server read Secret %s", key)
	}
	return n.Reader.Get(ctx, key, obj, opts...)
}

// stubSignatures serves one stored bundle; nothing else is used by verifyPair.
type stubSignatures struct {
	publication.Publisher
	bundle []byte
}

func (s stubSignatures) ReadSignature(context.Context, publication.RunRef) ([]byte, publication.Signature, error) {
	if s.bundle == nil {
		return nil, publication.Signature{}, publication.ErrNotFound
	}
	return s.bundle, publication.Signature{}, nil
}

// verifyPair checks each link on its own: even when the run's receipt, the
// stored commit and the stored bytes agree, the bundle must verify for the
// archive under the intent's retained key, and the receipt's key must be
// the intent's.
func TestVerifyPairChecksEveryLink(t *testing.T) {
	trusted, other := testSigner(t), testSigner(t)
	archive := evidencesign.DigestArchive([]byte("frozen archive"))
	good, _ := trusted.Sign(context.Background(), archive)
	byOther, _ := other.Sign(context.Background(), archive)
	forImpostor := byOther.Bundle
	// The other key's signature carrying the trusted key's hint.
	forged := bytes.Replace(byOther.Bundle, []byte(hintOf(t, byOther.Bundle)), []byte(hintOf(t, good.Bundle)), 1)
	setup := func(bundle []byte, mutate func(*v1alpha1.AssessmentRun, *publication.Status)) (stubSignatures, *v1alpha1.AssessmentRun, publication.Status) {
		sum := evidencesign.DigestArchive(bundle).String()
		sig := &publication.Signature{Key: "k", VersionID: "v1", SHA256: sum, Size: int64(len(bundle)), MediaType: evidencesign.BundleMediaType,
			Algorithm: evidencesign.Algorithm, KeyFingerprint: trusted.PublicKey().Fingerprint}
		st := publication.Status{Signature: sig}
		recorded := publication.ToAPI(publication.Status{Phase: publication.PhaseCommitted, PublicationID: "p", PackageSHA256: archive.String(), Signature: sig})
		pub := trusted.PublicKey()
		run := &v1alpha1.AssessmentRun{Status: v1alpha1.AssessmentRunStatus{Publication: &recorded, SigningIntent: &v1alpha1.SigningIntent{
			Mode: v1alpha1.SigningRequired, ArchiveSHA256: archive.String(),
			Key: &v1alpha1.SigningKey{Fingerprint: pub.Fingerprint, Algorithm: pub.Algorithm, PublicKey: string(pub.PEM)}}}}
		if mutate != nil {
			mutate(run, &st)
		}
		return stubSignatures{bundle: bundle}, run, st
	}
	cases := []struct {
		name   string
		bundle []byte
		mutate func(*v1alpha1.AssessmentRun, *publication.Status)
		code   int
	}{
		{"verified pair", good.Bundle, nil, http.StatusOK},
		{"consistent records, other key's signature", forImpostor, nil, http.StatusBadGateway},
		{"consistent records, forged key hint", forged, nil, http.StatusBadGateway},
		{"receipt names another key than the intent", good.Bundle, func(r *v1alpha1.AssessmentRun, st *publication.Status) {
			fp := other.PublicKey().Fingerprint
			r.Status.Publication.Signature.KeyFingerprint, st.Signature.KeyFingerprint = fp, fp
		}, http.StatusBadGateway},
		{"stored commit references another object", good.Bundle, func(_ *v1alpha1.AssessmentRun, st *publication.Status) {
			s := *st.Signature
			s.VersionID = "v2"
			st.Signature = &s
		}, http.StatusBadGateway},
		{"intent covers another archive", good.Bundle, func(r *v1alpha1.AssessmentRun, _ *publication.Status) {
			r.Status.SigningIntent.ArchiveSHA256 = strings.Repeat("0", 64)
		}, http.StatusBadGateway},
		{"intent not Required", good.Bundle, func(r *v1alpha1.AssessmentRun, _ *publication.Status) {
			r.Status.SigningIntent.Mode = v1alpha1.SigningDisabled
		}, http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub, run, st := setup(c.bundle, c.mutate)
			got, err := verifyPair(context.Background(), pub, publication.RunRef{}, run, st, archive)
			code := http.StatusOK
			var p problem
			if errors.As(err, &p) {
				code = p.code
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.code || (code == http.StatusOK && !bytes.Equal(got, c.bundle)) {
				t.Fatalf("got %d (%v), want %d", code, err, c.code)
			}
		})
	}
	pub, run, st := setup(good.Bundle, nil)
	pub.bundle = nil
	if _, err := verifyPair(context.Background(), pub, publication.RunRef{}, run, st, archive); !errors.As(err, new(problem)) || err.(problem).code != http.StatusServiceUnavailable {
		t.Fatalf("missing bundle: %v", err)
	}
}

func hintOf(t *testing.T, bundle []byte) string {
	t.Helper()
	var b struct {
		VerificationMaterial struct {
			PublicKey struct {
				Hint string `json:"hint"`
			} `json:"publicKey"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || b.VerificationMaterial.PublicKey.Hint == "" {
		t.Fatalf("hint: %v", err)
	}
	return b.VerificationMaterial.PublicKey.Hint
}
