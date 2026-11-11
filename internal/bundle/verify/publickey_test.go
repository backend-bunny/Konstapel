package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Fixtures produced by the pinned Cosign CLI (testdata/cosign/README.md).
type cosignFixtures struct {
	subject                string
	keyA, keyB             []byte
	fpA, fpB               string
	signA, signB, provA    registry.Proof
	signABytes, provABytes []byte
	signBBytes             []byte
	signAManifest          []byte
}

func loadCosign(t *testing.T) cosignFixtures {
	t.Helper()
	f := cosignFixtures{
		subject: sha(readFixture(t, "cosign", "subject-manifest.json")),
		keyA:    readFixture(t, "cosign", "key-a.pub"),
		keyB:    readFixture(t, "cosign", "key-b.pub"),
	}
	for _, line := range strings.Split(string(readFixture(t, "cosign", "fingerprints.txt")), "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "subject":
			if v != f.subject {
				t.Fatalf("subject manifest digest %s, fingerprints.txt says %s", f.subject, v)
			}
		case "key-a":
			f.fpA = v
		case "key-b":
			f.fpB = v
		}
	}
	f.signABytes = readFixture(t, "cosign", "sign-key-a.bundle.json")
	f.signBBytes = readFixture(t, "cosign", "sign-key-b.bundle.json")
	f.provABytes = readFixture(t, "cosign", "provenance-key-a.bundle.json")
	f.signAManifest = readFixture(t, "cosign", "sign-key-a.manifest.json")
	f.signA = proofFrom(t, registry.ProofSignature, f.signAManifest, f.signABytes)
	f.signB = proofFrom(t, registry.ProofSignature, readFixture(t, "cosign", "sign-key-b.manifest.json"), f.signBBytes)
	f.provA = proofFrom(t, registry.ProofProvenance, readFixture(t, "cosign", "provenance-key-a.manifest.json"), f.provABytes)
	return f
}

func keyReader(f cosignFixtures) *kubeaccess.MemoryReader {
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "key-a", bundle.DefaultPublicKey, f.keyA)
	putValue(r, bundle.KindSecret, "key-b", bundle.DefaultPublicKey, f.keyB)
	return r
}

// editJSON rewrites a bundle through a generic map, keeping it parseable.
func editJSON(t *testing.T, raw []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func envelopeOf(m map[string]any) map[string]any { return m["dsseEnvelope"].(map[string]any) }

func TestPublicKeyCosignFixtures(t *testing.T) {
	f := loadCosign(t)
	ctx := context.Background()
	other := "sha256:" + strings.Repeat("ab", 32)

	tamperedPayload := editJSON(t, f.signABytes, func(m map[string]any) {
		env := envelopeOf(m)
		p, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
		p = bytes.Replace(p, []byte(`"predicate":{}`), []byte(`"predicate":{"x":1}`), 1)
		env["payload"] = base64.StdEncoding.EncodeToString(p)
	})
	tamperedSig := editJSON(t, f.signABytes, func(m map[string]any) {
		sig := envelopeOf(m)["signatures"].([]any)[0].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(sig["sig"].(string))
		raw[len(raw)-1] ^= 1
		sig["sig"] = base64.StdEncoding.EncodeToString(raw)
	})
	hintOf := func(raw []byte) string {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m["verificationMaterial"].(map[string]any)["publicKey"].(map[string]any)["hint"].(string)
	}
	withHint := func(raw []byte, hint string) []byte {
		return editJSON(t, raw, func(m map[string]any) {
			m["verificationMaterial"] = map[string]any{"publicKey": map[string]any{"hint": hint}}
		})
	}
	unsigned := editJSON(t, f.signABytes, func(m map[string]any) { envelopeOf(m)["signatures"] = []any{} })
	twoSigs := editJSON(t, f.signABytes, func(m map[string]any) {
		s := envelopeOf(m)["signatures"].([]any)
		envelopeOf(m)["signatures"] = append(s, s[0])
	})
	dupKey := bytes.Replace(f.signABytes, []byte(`{"mediaType":`), []byte(`{"mediaType":"x","mediaType":`), 1)
	unknownField := bytes.Replace(f.signABytes, []byte(`{"mediaType":`), []byte(`{"trustedRoot":{},"mediaType":`), 1)
	oldMedia := editJSON(t, f.signABytes, func(m map[string]any) {
		m["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
	})
	// A bundle that brings its own trust: a certificate in place of the key.
	vs := newVirtualSigstore(t)
	certBundle, _ := keylessBundle(t, vs, keylessOpts{identity: "attacker@example.test", issuer: "https://issuer.example.test",
		statement: statementFor(f.subject, registry.CosignSignPredicateType)})

	cases := []struct {
		name    string
		src     bundle.BundleSource
		subject string
		kind    registry.ProofKind
		proof   registry.Proof
		want    []error
	}{
		{name: "valid signature", src: keySource("key-a", f.fpA), proof: f.signA},
		{name: "valid provenance attestation", src: keySource("key-a", f.fpA), kind: registry.ProofProvenance, proof: f.provA},
		{name: "fingerprint without sha256 prefix", src: keySource("key-a", strings.TrimPrefix(f.fpA, "sha256:")), proof: f.signA},
		{name: "wrong key", src: keySource("key-a", f.fpA), proof: f.signB, want: []error{ErrSignature}},
		{name: "rotated key no longer accepts the old signature", src: keySource("key-b", f.fpB), proof: f.signA, want: []error{ErrSignature}},
		{name: "rotated key accepts its own signature", src: keySource("key-b", f.fpB), proof: f.signB},
		{name: "fingerprint differs from referenced key", src: keySource("key-a", f.fpB), proof: f.signA, want: []error{ErrKeyFingerprint, ErrTrustConfig}},
		{name: "key not referenced by any object", src: keySource("key-c", f.fpA), proof: f.signA, want: []error{ErrTrustConfig}},
		{name: "tampered payload", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, tamperedPayload), want: []error{ErrSignature}},
		{name: "tampered signature", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, tamperedSig), want: []error{ErrSignature}},
		{name: "signed for another subject", src: keySource("key-a", f.fpA), subject: other, proof: f.signA, want: []error{ErrSubject}},
		{name: "attestation presented as a signature", src: keySource("key-a", f.fpA), proof: registry.Proof{
			Kind: registry.ProofSignature, PredicateType: registry.CosignSignPredicateType, ManifestDigest: f.provA.ManifestDigest,
			BundleMediaType: f.provA.BundleMediaType, BundleDigest: f.provA.BundleDigest, Bundle: f.provA.Bundle,
		}, want: []error{ErrPredicateType}},
		{name: "signature presented as provenance", src: keySource("key-a", f.fpA), kind: registry.ProofProvenance, proof: f.signA, want: []error{ErrPredicateType}},
		{name: "unsigned envelope", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, unsigned), want: []error{ErrMalformedProof}},
		{name: "two signatures", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, twoSigs), want: []error{ErrMalformedProof}},
		{name: "truncated bundle", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, f.signABytes[:len(f.signABytes)/2]), want: []error{ErrMalformedProof}},
		{name: "garbage", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, []byte("\x00\xffnot json")), want: []error{ErrMalformedProof}},
		{name: "duplicate key", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, dupKey), want: []error{ErrMalformedProof}},
		{name: "unknown field", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, unknownField), want: []error{ErrMalformedProof}},
		{name: "older bundle media type", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, oldMedia), want: []error{ErrMalformedProof}},
		{name: "oversized", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, append(bytes.Repeat([]byte(" "), MaxBundleBytes), f.signABytes...)), want: []error{ErrProofTooLarge}},
		{name: "bytes do not match recorded digest", src: keySource("key-a", f.fpA), proof: registry.Proof{
			Kind: registry.ProofSignature, BundleDigest: f.signB.BundleDigest, Bundle: f.signABytes}, want: []error{ErrMalformedProof}},
		{name: "empty proof", src: keySource("key-a", f.fpA), proof: registry.Proof{Kind: registry.ProofSignature}, want: []error{ErrMalformedProof}},
		{name: "key hint naming another key is ignored", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, withHint(f.signABytes, hintOf(f.signBBytes)))},
		{name: "key hint naming the configured key does not help another key", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, withHint(f.signBBytes, hintOf(f.signABytes))), want: []error{ErrSignature}},
		{name: "certificate instead of the configured key", src: keySource("key-a", f.fpA), proof: rawProof(registry.ProofSignature, certBundle), want: []error{ErrSigner}},
		{name: "public-key proof against a keyless rule", src: keylessSource("https://issuer.example.test", "attacker@example.test", nil), proof: f.signA, want: []error{ErrSigner}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.kind
			if kind == "" {
				kind = registry.ProofSignature
			}
			subject := tc.subject
			if subject == "" {
				subject = f.subject
			}
			v := newVerifier(t, keyReader(f), nil)
			got, err := v.VerifyProof(ctx, tc.src, subject, kind, tc.proof)
			wantErr(t, err, tc.want...)
			if err != nil {
				return
			}
			if got.Kind != kind || got.Subject != f.subject || got.Signer.Kind != bundle.SignerPublicKey ||
				got.Signer.KeyFingerprint != "sha256:"+strings.TrimPrefix(tc.src.Publisher.KeyFingerprint, "sha256:") {
				t.Fatalf("unexpected result %+v", got)
			}
			if got.TrustRootID != "" || !got.SigningTime.IsZero() || len(got.Evidence) != 0 {
				t.Fatalf("public-key result claims evidence it did not verify: %+v", got)
			}
			if got.BundleDigest != tc.proof.BundleDigest || got.StatementDigest == "" || got.Statement.PredicateType != predicateTypes[kind] {
				t.Fatalf("unexpected evidence digests %+v", got)
			}
		})
	}
}

func TestPublicKeyRejectsUnacceptableKeyObjects(t *testing.T) {
	f := loadCosign(t)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p384PEM, p384FP := pemPublicKey(t, &ecP384.PublicKey)
	rsaPEM, rsaFP := pemPublicKey(t, &rsaKey.PublicKey)
	edPEM, edFP := pemPublicKey(t, edPub)
	privDER, _ := x509.MarshalPKCS8PrivateKey(ecP384)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	withHeader := bytes.Replace(f.keyA, []byte("-----\n"), []byte("-----\nProc-Type: 4,ENCRYPTED\n\n"), 1)

	cases := []struct {
		name  string
		value []byte
		key   string
		fp    string
		want  error
	}{
		{"P-384 key", p384PEM, "", p384FP, ErrUnsupportedKey},
		{"RSA key", rsaPEM, "", rsaFP, ErrUnsupportedKey},
		{"Ed25519 key", edPEM, "", edFP, ErrUnsupportedKey},
		{"private key", privPEM, "", f.fpA, ErrTrustConfig},
		{"two keys", append(append([]byte{}, f.keyA...), f.keyB...), "", f.fpA, ErrTrustConfig},
		{"text around the key", append([]byte("trust me\n"), f.keyA...), "", f.fpA, ErrTrustConfig},
		{"PEM headers", withHeader, "", f.fpA, ErrTrustConfig},
		{"not PEM", []byte("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"), "", f.fpA, ErrTrustConfig},
		{"empty", []byte("  \n"), "", f.fpA, ErrTrustConfig},
		{"oversized", bytes.Repeat([]byte("A"), MaxPublicKeyBytes+1), "", f.fpA, ErrTrustConfig},
		{"configured data key missing", f.keyA, "other.pub", f.fpA, ErrTrustConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := kubeaccess.NewMemoryReader()
			putValue(r, bundle.KindSecret, "k", bundle.DefaultPublicKey, tc.value)
			src := keySource("k", tc.fp)
			src.Publisher.PublicKey.Key = tc.key
			_, err := newVerifier(t, r, nil).VerifyProof(context.Background(), src, f.subject, registry.ProofSignature, f.signA)
			wantErr(t, err, tc.want)
		})
	}

	t.Run("reader failure", func(t *testing.T) {
		r := keyReader(f)
		r.FailWith(errors.New("apiserver unavailable"))
		_, err := newVerifier(t, r, nil).VerifyProof(context.Background(), keySource("key-a", f.fpA), f.subject, registry.ProofSignature, f.signA)
		wantErr(t, err, ErrTrustConfig)
	})
	t.Run("invalid rule", func(t *testing.T) {
		src := keySource("key-a", f.fpA)
		src.Publisher.Issuer = "https://issuer.example.test"
		_, err := newVerifier(t, keyReader(f), nil).VerifyProof(context.Background(), src, f.subject, registry.ProofSignature, f.signA)
		wantErr(t, err, ErrTrustConfig)
	})
	t.Run("key in a ConfigMap", func(t *testing.T) {
		r := kubeaccess.NewMemoryReader()
		putValue(r, bundle.KindConfigMap, "pub", "org.pub", f.keyA)
		src := keySource("pub", f.fpA)
		src.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "pub", Key: "org.pub"}
		_, err := newVerifier(t, r, nil).VerifyProof(context.Background(), src, f.subject, registry.ProofSignature, f.signA)
		wantErr(t, err)
	})
}

// Statements Cosign would not write, signed with a key the rule trusts, so
// only the statement checks can reject them.
func TestPublicKeyStatementBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, fp := pemPublicKey(t, &priv.PublicKey)
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "k", bundle.DefaultPublicKey, pubPEM)
	subject := "sha256:" + strings.Repeat("1f", 32)
	hexS := strings.TrimPrefix(subject, "sha256:")
	other := strings.Repeat("2e", 32)
	sign := registry.CosignSignPredicateType
	st := func(body string) []byte { return []byte(body) }

	cases := []struct {
		name      string
		statement []byte
		want      []error
	}{
		{"cosign layout", statementFor(subject, sign), nil},
		{"named subject (name is informational)", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"mirror.example.test/x","digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{}}`), nil},
		{"two subjects including the pinned one", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + hexS + `"}},{"digest":{"sha256":"` + other + `"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrSubject}},
		{"no subjects", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrSubject}},
		{"second digest algorithm", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + hexS + `","sha512":"00"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrSubject}},
		{"uppercase digest", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + strings.ToUpper(hexS) + `"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrSubject}},
		{"other subject", statementFor("sha256:"+other, sign), []error{ErrSubject}},
		{"wrong predicate type", statementFor(subject, registry.SLSAProvenanceV1PredicateType), []error{ErrPredicateType}},
		{"duplicate subject key", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + other + `"}}],"subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrStatement}},
		{"case-variant key", st(`{"_type":"https://in-toto.io/Statement/v1","Subject":[{"digest":{"sha256":"` + other + `"}}],"subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrStatement}},
		{"Statement v0.1 (cosign attest)", st(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{}}`), nil},
		{"unknown statement type", st(`{"_type":"https://in-toto.io/Statement/v2","subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{}}`), []error{ErrStatement}},
		{"predicate not an object", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":"x"}`), []error{ErrStatement}},
		{"unknown statement field", st(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + hexS + `"}}],"predicateType":"` + sign + `","predicate":{},"trust":{}}`), []error{ErrStatement}},
		{"trailing data", append(statementFor(subject, sign), []byte(` {}`)...), []error{ErrStatement}},
		{"not JSON", st(`not json`), []error{ErrStatement}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := rawProof(registry.ProofSignature, keyBundle(t, priv, tc.statement, ""))
			got, err := newVerifier(t, r, nil).VerifyProof(context.Background(), keySource("k", fp), subject, registry.ProofSignature, p)
			wantErr(t, err, tc.want...)
			if err == nil && (len(got.Statement.Subjects) != 1 || got.Statement.Subjects[0].Digest != subject) {
				t.Fatalf("statement %+v", got.Statement)
			}
		})
	}
}

func TestVerifyProofsSelectsUnderOneRule(t *testing.T) {
	f := loadCosign(t)
	ctx := context.Background()
	res := &registry.Result{Digest: f.subject, Proofs: []registry.Proof{f.signB, f.provA, f.signA}}

	got, err := newVerifier(t, keyReader(f), nil).VerifyProofs(ctx, keySource("key-a", f.fpA), res)
	wantErr(t, err)
	if got.Signature.BundleDigest != f.signA.BundleDigest || got.Provenance.BundleDigest != f.provA.BundleDigest ||
		got.Signature.Signer != got.Provenance.Signer {
		t.Fatalf("unexpected selection %+v %+v", got.Signature, got.Provenance)
	}
	if !bytes.Contains(got.Provenance.Statement.Predicate, []byte("https://ci.example.test/bundle-builder@refs/heads/main")) {
		t.Fatalf("provenance predicate not exposed: %s", got.Provenance.Statement.Predicate)
	}

	// Key B signed the subject but not its provenance: the rule cannot be
	// satisfied by combining B's signature with A's attestation.
	_, err = newVerifier(t, keyReader(f), nil).VerifyProofs(ctx, keySource("key-b", f.fpB), res)
	wantErr(t, err, ErrNoValidProof, ErrSignature)

	_, err = newVerifier(t, keyReader(f), nil).VerifyProofs(ctx, keySource("key-a", f.fpA),
		&registry.Result{Digest: f.subject, Proofs: []registry.Proof{f.signA}})
	wantErr(t, err, registry.ErrMissingProofs)

	_, err = newVerifier(t, keyReader(f), nil).Verify(ctx, keySource("key-a", f.fpA),
		&registry.Result{Digest: f.subject}, registry.ProofSignature)
	wantErr(t, err, registry.ErrMissingProofs)

	// A provenance attestation labelled as a signature by the unauthenticated
	// annotation is still judged by its signed predicate type.
	mislabelled := f.provA
	mislabelled.Kind = registry.ProofSignature
	_, err = newVerifier(t, keyReader(f), nil).Verify(ctx, keySource("key-a", f.fpA),
		&registry.Result{Digest: f.subject, Proofs: []registry.Proof{mislabelled}}, registry.ProofSignature)
	wantErr(t, err, ErrNoValidProof, ErrPredicateType)
}

func TestNewRequiresReader(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}
