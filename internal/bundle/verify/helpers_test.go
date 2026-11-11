package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Verification must never use the network: every HTTP request through the
// default transport fails the run.
var networkUse atomic.Int64

type noNetwork struct{}

func (noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	networkUse.Add(1)
	return nil, fmt.Errorf("network access during verification: %s", r.URL.Host)
}

func TestMain(m *testing.M) {
	http.DefaultTransport = noNetwork{}
	code := m.Run()
	if n := networkUse.Load(); n > 0 && code == 0 {
		fmt.Fprintf(os.Stderr, "verification attempted %d network requests\n", n)
		code = 1
	}
	os.Exit(code)
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// proofFrom builds a retrieved proof the way the registry adapter does, from
// a referrer manifest and its bundle layer.
func proofFrom(t *testing.T, kind registry.ProofKind, manifest, bundleJSON []byte) registry.Proof {
	t.Helper()
	pt := ""
	if manifest != nil {
		var m struct {
			Annotations map[string]string `json:"annotations"`
			Layers      []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(manifest, &m); err != nil {
			t.Fatal(err)
		}
		if len(m.Layers) != 1 || m.Layers[0].Digest != sha(bundleJSON) {
			t.Fatalf("fixture manifest does not reference this bundle")
		}
		pt = m.Annotations[registry.PredicateTypeAnnotation]
	}
	return registry.Proof{
		Kind:            kind,
		PredicateType:   pt,
		ManifestDigest:  sha(manifest),
		Manifest:        manifest,
		BundleMediaType: registry.SigstoreBundleArtifactType,
		BundleDigest:    sha(bundleJSON),
		Bundle:          bundleJSON,
	}
}

// rawProof wraps bundle bytes with no referrer manifest.
func rawProof(kind registry.ProofKind, b []byte) registry.Proof {
	return registry.Proof{Kind: kind, ManifestDigest: sha([]byte("manifest:" + string(b))),
		BundleMediaType: registry.SigstoreBundleArtifactType, BundleDigest: sha(b), Bundle: b}
}

func newVerifier(t *testing.T, r ObjectReader, now func() time.Time) *Verifier {
	t.Helper()
	opts := []Option{}
	if now != nil {
		opts = append(opts, WithClock(now))
	}
	v, err := New(r, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantErr(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	if len(sentinels) == 0 {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("verification succeeded; want %v", sentinels)
	}
	for _, s := range sentinels {
		if !errors.Is(err, s) {
			t.Fatalf("error %q does not match %q", err, s)
		}
	}
}

var testProvenance = bundle.ProvenanceRule{
	SourceRepository: "https://git.example.test/policies",
	Builder:          "https://ci.example.test/bundle-builder@refs/heads/main",
}

func keySource(name, fingerprint string) bundle.BundleSource {
	return bundle.BundleSource{
		Name:       "konstapel-privileged-containers",
		Repository: "registry.example.test/fixtures/konstapel-privileged-containers",
		Publisher: bundle.Publisher{
			Type:           bundle.SignerPublicKey,
			PublicKey:      &bundle.ObjectRef{Kind: bundle.KindSecret, Name: name},
			KeyFingerprint: fingerprint,
			Provenance:     testProvenance,
		},
	}
}

func keylessSource(issuer, identity string, rootRef *bundle.ObjectRef) bundle.BundleSource {
	return bundle.BundleSource{
		Name:       "konstapel-privileged-containers",
		Repository: "registry.example.test/fixtures/konstapel-privileged-containers",
		Publisher: bundle.Publisher{
			Type:       bundle.SignerKeyless,
			Issuer:     issuer,
			Identity:   identity,
			TrustRoot:  rootRef,
			Provenance: testProvenance,
		},
	}
}

func putValue(r *kubeaccess.MemoryReader, kind, name, key string, val []byte) {
	typ := ""
	if kind == bundle.KindSecret {
		typ = "Opaque"
	}
	r.Put(kind, name, kubeaccess.NewObject(typ, map[string][]byte{key: val}))
}

// statementFor is the statement `cosign sign` (v3, new bundle format) signs.
func statementFor(digest, predicateType string) []byte {
	return fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":%q},"annotations":{}}],"predicateType":%q,"predicate":{}}`,
		strings.TrimPrefix(digest, "sha256:"), predicateType)
}

func dsseSign(t *testing.T, priv crypto.Signer, statement []byte) (*dsse.Envelope, []byte) {
	t.Helper()
	var sv signature.Signer
	var err error
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		hf := crypto.SHA256
		if k.Curve == elliptic.P384() {
			hf = crypto.SHA384
		}
		sv, err = signature.LoadECDSASigner(k, hf)
	case ed25519.PrivateKey:
		sv, err = signature.LoadED25519Signer(k)
	default:
		t.Fatalf("unsupported test key %T", priv)
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: sv, Pub: priv.Public()})
	if err != nil {
		t.Fatal(err)
	}
	env, err := signer.SignPayload(context.Background(), inTotoPayloadType, statement)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	return env, sig
}

func envelopeProto(t *testing.T, env *dsse.Envelope) *protobundle.Bundle_DsseEnvelope {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var sigs []*protodsse.Signature
	for _, s := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, &protodsse.Signature{Sig: raw, Keyid: s.KeyID})
	}
	return &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{Payload: payload, PayloadType: env.PayloadType, Signatures: sigs}}
}

func marshalBundle(t *testing.T, b *protobundle.Bundle) []byte {
	t.Helper()
	raw, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// keyBundle signs a statement with a raw key, in the layout `cosign sign
// --key` writes: a DSSE envelope and a public-key hint.
func keyBundle(t *testing.T, priv crypto.Signer, statement []byte, hint string) []byte {
	t.Helper()
	env, _ := dsseSign(t, priv, statement)
	return marshalBundle(t, &protobundle.Bundle{
		MediaType: registry.SigstoreBundleArtifactType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{Hint: hint}},
		},
		Content: envelopeProto(t, env),
	})
}

func pemPublicKey(t *testing.T, pub crypto.PublicKey) ([]byte, string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "sha256:" + hex.EncodeToString(s[:])
}

// ---- keyless: isolated Sigstore instances --------------------------------

func newVirtualSigstore(t *testing.T) *ca.VirtualSigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// logsByRawID re-keys VirtualSigstore logs so that their IDs are the raw key
// IDs a serialized trusted root carries.
func logsByRawID(t *testing.T, logs map[string]*root.TransparencyLog) map[string]*root.TransparencyLog {
	t.Helper()
	out := map[string]*root.TransparencyLog{}
	for k, l := range logs {
		c := *l
		id, err := hex.DecodeString(k)
		if err != nil {
			t.Fatal(err)
		}
		c.ID = id
		out[k] = &c
	}
	return out
}

type rootParts struct {
	cas   []root.CertificateAuthority
	tsas  []root.TimestampingAuthority
	rekor map[string]*root.TransparencyLog
	ct    map[string]*root.TransparencyLog
}

func partsOf(t *testing.T, vs *ca.VirtualSigstore, withCT bool) rootParts {
	p := rootParts{cas: vs.FulcioCertificateAuthorities(), tsas: vs.TimestampingAuthorities(), rekor: logsByRawID(t, vs.RekorLogs())}
	if withCT {
		p.ct = logsByRawID(t, vs.CTLogs())
	}
	return p
}

func (p rootParts) json(t *testing.T) []byte {
	t.Helper()
	ct := p.ct
	if ct == nil {
		ct = map[string]*root.TransparencyLog{}
	}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, p.cas, ct, p.tsas, p.rekor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type keylessOpts struct {
	identity, issuer string
	statement        []byte
	at               time.Time // integrated time; default one minute into the leaf's validity
	noTlog           bool
	noSET            bool
	noTSA            bool
	logFrom, tsaFrom *ca.VirtualSigstore
	leaf             *x509.Certificate
	key              crypto.Signer
	chain            []*x509.Certificate // send an X.509 chain instead of one certificate
}

// keylessBundle produces a Sigstore bundle v0.3 like `cosign sign` keyless:
// a Fulcio-style leaf, a DSSE envelope, a Rekor dsse entry with inclusion
// proof and (unless disabled) signed entry timestamp, and an RFC 3161
// timestamp. Every part can be issued by a different isolated instance.
func keylessBundle(t *testing.T, vs *ca.VirtualSigstore, o keylessOpts) ([]byte, *x509.Certificate) {
	t.Helper()
	leaf, priv := o.leaf, o.key
	if leaf == nil {
		c, p, err := vs.GenerateLeafCert(o.identity, o.issuer)
		if err != nil {
			t.Fatal(err)
		}
		leaf, priv = c, p.(crypto.Signer)
	}
	env, sig := dsseSign(t, priv, o.statement)
	at := o.at
	if at.IsZero() {
		at = leaf.NotBefore.Add(time.Minute)
	}
	vm := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
	}
	if o.chain != nil {
		var certs []*protocommon.X509Certificate
		for _, c := range append([]*x509.Certificate{leaf}, o.chain...) {
			certs = append(certs, &protocommon.X509Certificate{RawBytes: c.Raw})
		}
		vm.Content = &protobundle.VerificationMaterial_X509CertificateChain{X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certs}}
	}
	if !o.noTlog {
		lf := vs
		if o.logFrom != nil {
			lf = o.logFrom
		}
		e, err := lf.GenerateTlogEntry(leaf, env, sig, at.Unix(), true)
		if err != nil {
			t.Fatal(err)
		}
		tle := e.TransparencyLogEntry()
		tle.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
		if !o.noSET {
			logID, err := lf.RekorLogID()
			if err != nil {
				t.Fatal(err)
			}
			set, err := lf.RekorSignPayload(tlog.RekorPayload{LogID: logID, IntegratedTime: at.Unix(), LogIndex: tle.LogIndex,
				Body: base64.StdEncoding.EncodeToString(tle.CanonicalizedBody)})
			if err != nil {
				t.Fatal(err)
			}
			tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
		}
		vm.TlogEntries = []*protorekor.TransparencyLogEntry{tle}
	}
	if !o.noTSA {
		tf := vs
		if o.tsaFrom != nil {
			tf = o.tsaFrom
		}
		tsr, err := tf.TimestampResponse(sig)
		if err != nil {
			t.Fatal(err)
		}
		vm.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: tsr}},
		}
	}
	return marshalBundle(t, &protobundle.Bundle{MediaType: registry.SigstoreBundleArtifactType, VerificationMaterial: vm, Content: envelopeProto(t, env)}), leaf
}

// customCA is a Fulcio-like CA under test control, for certificates the
// VirtualSigstore cannot issue (several SANs).
type customCA struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
}

func newCustomCA(t *testing.T) *customCA {
	t.Helper()
	rc, rk, err := ca.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ic, ik, err := ca.GenerateFulcioIntermediate(rc, rk)
	if err != nil {
		t.Fatal(err)
	}
	return &customCA{root: rc, inter: ic, interKey: ik}
}

func (c *customCA) authority() root.CertificateAuthority {
	return &root.FulcioCertificateAuthority{Root: c.root, Intermediates: []*x509.Certificate{c.inter},
		ValidityPeriodStart: time.Now().Add(-5 * time.Hour), ValidityPeriodEnd: time.Now().Add(time.Hour), URI: "https://custom.fulcio.test"}
}

func (c *customCA) leaf(t *testing.T, issuer string, uris []string, emails []string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	return c.leafWindow(t, issuer, uris, emails, time.Now().Add(-time.Second), time.Now().Add(10*time.Minute))
}

func (c *customCA) leafWindow(t *testing.T, issuer string, uris []string, emails []string, notBefore, notAfter time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(7),
		Subject:        pkix.Name{},
		EmailAddresses: emails,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(issuer),
		}},
	}
	for _, u := range uris {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.inter, &priv.PublicKey, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}
