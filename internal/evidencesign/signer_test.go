package evidencesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

// testKey is a disposable key pair generated per test, encoded like
// `cosign generate-key-pair` output. Nothing here is ever written to disk.
type testKey struct {
	priv     crypto.Signer
	password []byte
	data     map[string][]byte
}

func newKey(t *testing.T, priv crypto.Signer, password string, pemType string) testKey {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encrypted.Encrypt(der, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv, password: []byte(password), data: map[string][]byte{
		SecretPrivateKey: pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: enc}),
		SecretPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		SecretPassword:   []byte(password),
	}}
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func cosignKey(t *testing.T, password string) testKey {
	return newKey(t, p256(t), password, pemSigstorePrivate)
}

func signer(t *testing.T, k testKey) *SecretSigner {
	t.Helper()
	s, err := NewSecretSigner(k.data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func with(m map[string][]byte, k string, v []byte) map[string][]byte {
	out := map[string][]byte{}
	for kk, vv := range m {
		out[kk] = vv
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

// secretsIn lists byte strings that must never appear in an error: the
// password, the private scalar, and every 12-character run of the encrypted
// key's base64 body.
func secretsIn(k testKey) []string {
	var out []string
	if len(k.password) >= 3 {
		out = append(out, string(k.password))
	}
	if ec, ok := k.priv.(*ecdsa.PrivateKey); ok {
		d := ec.D.Bytes()
		out = append(out, hex.EncodeToString(d), base64.StdEncoding.EncodeToString(d), string(d))
	}
	block, _ := pem.Decode(k.data[SecretPrivateKey])
	if block != nil {
		body := base64.StdEncoding.EncodeToString(block.Bytes)
		for i := 0; i+12 <= len(body); i += 6 {
			out = append(out, body[i:i+12])
		}
		out = append(out, string(block.Bytes))
	}
	return out
}

func assertSanitized(t *testing.T, err error, k testKey) {
	t.Helper()
	msg := err.Error()
	for _, s := range secretsIn(k) {
		if strings.Contains(msg, s) {
			t.Fatalf("error leaks secret material %q: %s", s, msg)
		}
	}
	for _, lib := range []string{"encrypted:", "asn1:", "x509:", "scrypt"} {
		if strings.Contains(msg, lib) {
			t.Fatalf("error propagates key-library text %q: %s", lib, msg)
		}
	}
}

func TestSecretSignerSignsAndVerifies(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, password, pemType string
	}{
		{"sigstore encoding", "correct horse", pemSigstorePrivate},
		{"empty password", "", pemSigstorePrivate},
		{"older cosign encoding", "pw-123", pemCosignPrivate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKey(t, p256(t), tc.password, tc.pemType)
			s := signer(t, k)
			pub := s.PublicKey()
			der, _ := x509.MarshalPKIXPublicKey(k.priv.Public())
			sum := sha256.Sum256(der)
			if want := "sha256:" + hex.EncodeToString(sum[:]); pub.Fingerprint != want {
				t.Fatalf("fingerprint %s, want SHA-256 of DER SPKI %s", pub.Fingerprint, want)
			}
			if pub.Algorithm != Algorithm || !bytes.Equal(pub.PEM, k.data[SecretPublicKey]) {
				t.Fatalf("public identity %+v", pub)
			}
			archive := []byte("frozen package.tar.gz bytes " + tc.name)
			d := DigestArchive(archive)
			a, err := s.Sign(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			b, err := s.Sign(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a.Bundle, b.Bundle) {
				t.Fatal("ECDSA signatures are randomized; two bundles were identical")
			}
			for _, sig := range []Signature{a, b} {
				bs := sha256.Sum256(sig.Bundle)
				if sig.BundleSHA256 != hex.EncodeToString(bs[:]) || sig.ArchiveSHA256 != hex.EncodeToString(d[:]) ||
					sig.KeyFingerprint != pub.Fingerprint || sig.Algorithm != Algorithm || sig.MediaType != BundleMediaType {
					t.Fatalf("signature metadata %+v", sig)
				}
				v, err := Verify(sig.Bundle, d, pub)
				if err != nil {
					t.Fatal(err)
				}
				if v.BundleSHA256 != sig.BundleSHA256 || v.KeyFingerprint != pub.Fingerprint || v.ArchiveSHA256 != sig.ArchiveSHA256 {
					t.Fatalf("verified %+v for %+v", v, sig)
				}
				// The independently parsed key verifies too.
				parsed, err := ParsePublicKey(k.data[SecretPublicKey])
				if err != nil || !parsed.Equal(pub) {
					t.Fatalf("ParsePublicKey: %v", err)
				}
				if _, err := Verify(sig.Bundle, d, parsed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// The bundle is a standard Sigstore bundle v0.3 with only a key hint and a
// message signature: no certificate, transparency-log entry, or timestamp
// that a public service could have supplied.
func TestBundleShape(t *testing.T) {
	k := cosignKey(t, "pw")
	s := signer(t, k)
	archive := []byte("archive")
	sig, err := s.Sign(context.Background(), DigestArchive(archive))
	if err != nil {
		t.Fatal(err)
	}
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(sig.Bundle); err != nil {
		t.Fatalf("sigstore-go rejects the bundle: %v", err)
	}
	if b.GetMediaType() != BundleMediaType || b.GetMessageSignature() == nil || b.GetDsseEnvelope() != nil {
		t.Fatalf("bundle content: %s", sig.Bundle)
	}
	vm := b.GetVerificationMaterial()
	if vm.GetPublicKey() == nil || vm.GetCertificate() != nil || vm.GetX509CertificateChain() != nil ||
		len(vm.GetTlogEntries()) != 0 || vm.GetTimestampVerificationData() != nil {
		t.Fatalf("verification material is not key-only: %s", sig.Bundle)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.priv.Public())
	sum := sha256.Sum256(der)
	if vm.GetPublicKey().GetHint() != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("hint %q is not Cosign's base64 SHA-256 of the DER key", vm.GetPublicKey().GetHint())
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(sig.Bundle, &top); err != nil || len(top) != 3 {
		t.Fatalf("top-level fields: %s", sig.Bundle)
	}
}

// The signed message digest is the SHA-256 of the archive bytes, signed
// directly; never a hash of the hex text, and never hashed again.
func TestNoDoubleHashing(t *testing.T) {
	k := cosignKey(t, "pw")
	s := signer(t, k)
	archive := bytes.Repeat([]byte("evidence"), 1000)
	d := DigestArchive(archive)
	sum := sha256.Sum256(archive)
	if d != sum {
		t.Fatal("DigestArchive is not SHA-256 of the bytes")
	}
	sig, err := s.Sign(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	var w wireBundle
	if err := json.Unmarshal(sig.Bundle, &w); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.MessageSignature.MessageDigest.Digest, sum[:]) {
		t.Fatal("messageDigest is not SHA-256(archive)")
	}
	pub := k.priv.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, sum[:], w.MessageSignature.Signature) {
		t.Fatal("signature is not over SHA-256(archive)")
	}
	twice := sha256.Sum256(sum[:])
	if ecdsa.VerifyASN1(pub, twice[:], w.MessageSignature.Signature) {
		t.Fatal("signature is over a double hash")
	}

	// A signer that hashes the textual digest produces a bundle for another
	// archive; it must not verify for this one.
	hexText := DigestArchive([]byte(d.String()))
	wrong, err := s.Sign(context.Background(), hexText)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(wrong.Bundle, d, s.PublicKey()); !errors.Is(err, ErrArchiveMismatch) {
		t.Fatalf("hex-text digest bundle: %v", err)
	}
	// Even with its messageDigest rewritten to the archive digest, that
	// signature does not verify.
	w2 := mustWire(t, wrong.Bundle)
	w2.MessageSignature.MessageDigest.Digest = d[:]
	if _, err := Verify(mustJSON(t, w2), d, s.PublicKey()); !errors.Is(err, ErrSignature) {
		t.Fatalf("rewritten digest: %v", err)
	}

	got, err := ParseArchiveDigest(d.String())
	if err != nil || got != d {
		t.Fatalf("ParseArchiveDigest round trip: %v", err)
	}
	for _, bad := range []string{"", "sha256:" + d.String(), strings.ToUpper(d.String()), d.String()[:63], d.String() + "0"} {
		if _, err := ParseArchiveDigest(bad); err == nil {
			t.Errorf("ParseArchiveDigest(%q) accepted", bad)
		}
	}
}

func mustWire(t *testing.T, raw []byte) wireBundle {
	t.Helper()
	var w wireBundle
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func editMap(t *testing.T, raw []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	return mustJSON(t, m)
}

func TestSecretSignerKeyFailures(t *testing.T) {
	good := cosignKey(t, "s3cret-pass")
	other := cosignKey(t, "other-pass")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalECPrivateKey(good.priv.(*ecdsa.PrivateKey))
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(good.priv)
	block, _ := pem.Decode(good.data[SecretPrivateKey])
	corrupt := bytes.Clone(block.Bytes)
	var env map[string]any
	_ = json.Unmarshal(corrupt, &env)
	ct, _ := base64.StdEncoding.DecodeString(env["ciphertext"].(string))
	ct[len(ct)/2] ^= 1
	env["ciphertext"] = base64.StdEncoding.EncodeToString(ct)
	corrupt, _ = json.Marshal(env)
	weakParams := editMap(t, block.Bytes, func(m map[string]any) {
		m["kdf"].(map[string]any)["params"].(map[string]any)["N"] = 1 << 22
	})
	notPKCS8, _ := encrypted.Encrypt([]byte("not a key"), good.password)
	encPEM := func(b []byte, typ string) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }

	cases := []struct {
		name string
		data map[string][]byte
		key  testKey
		want error
	}{
		{"no private key", with(good.data, SecretPrivateKey, nil), good, ErrKeyUnavailable},
		{"empty private key", with(good.data, SecretPrivateKey, []byte{}), good, ErrKeyUnavailable},
		{"no public key", with(good.data, SecretPublicKey, nil), good, ErrKeyUnavailable},
		{"no password entry", with(good.data, SecretPassword, nil), good, ErrKeyUnavailable},
		{"oversized private key", with(good.data, SecretPrivateKey, bytes.Repeat([]byte("a"), MaxPrivateKeyBytes+1)), good, ErrKeyUnavailable},
		{"oversized password", with(good.data, SecretPassword, bytes.Repeat([]byte("a"), MaxPasswordBytes+1)), good, ErrKeyUnavailable},
		{"wrong password", with(good.data, SecretPassword, []byte("wrong-pass")), good, ErrKeyPassword},
		{"empty instead of password", with(good.data, SecretPassword, []byte{}), good, ErrKeyPassword},
		{"password with trailing newline", with(good.data, SecretPassword, append(bytes.Clone(good.password), '\n')), good, ErrKeyPassword},
		{"corrupted ciphertext", with(good.data, SecretPrivateKey, encPEM(corrupt, pemSigstorePrivate)), good, ErrKeyPassword},
		{"unsupported scrypt parameters", with(good.data, SecretPrivateKey, encPEM(weakParams, pemSigstorePrivate)), good, ErrKeyMalformed},
		{"garbage in encrypted block", with(good.data, SecretPrivateKey, encPEM([]byte("garbage"), pemSigstorePrivate)), good, ErrKeyMalformed},
		{"decrypts to non-PKCS8", with(good.data, SecretPrivateKey, encPEM(notPKCS8, pemSigstorePrivate)), good, ErrKeyMalformed},
		{"not PEM", with(good.data, SecretPrivateKey, []byte("cosign.key contents")), good, ErrKeyMalformed},
		{"two PEM blocks", with(good.data, SecretPrivateKey, append(bytes.Clone(good.data[SecretPrivateKey]), good.data[SecretPrivateKey]...)), good, ErrKeyMalformed},
		{"trailing data", with(good.data, SecretPrivateKey, append(bytes.Clone(good.data[SecretPrivateKey]), "trailer"...)), good, ErrKeyMalformed},
		{"unencrypted EC key", with(good.data, SecretPrivateKey, encPEM(ecDER, "EC PRIVATE KEY")), good, ErrUnsupportedKey},
		{"unencrypted PKCS8 key", with(good.data, SecretPrivateKey, encPEM(pkcs8DER, "PRIVATE KEY")), good, ErrUnsupportedKey},
		{"other PEM type", with(good.data, SecretPrivateKey, encPEM([]byte("x"), "CERTIFICATE")), good, ErrKeyMalformed},
		{"mismatched public key", with(good.data, SecretPublicKey, other.data[SecretPublicKey]), good, ErrKeyMismatch},
		{"private key as public key", with(good.data, SecretPublicKey, good.data[SecretPrivateKey]), good, ErrKeyMalformed},
		{"malformed public key", with(good.data, SecretPublicKey, encPEM([]byte("junk"), "PUBLIC KEY")), good, ErrKeyMalformed},
		{"RSA key", newKey(t, rsaKey, "pw-rsa", pemSigstorePrivate).data, newKey(t, rsaKey, "pw-rsa", pemSigstorePrivate), ErrUnsupportedKey},
		{"ECDSA P-384 key", newKey(t, p384, "pw-384", pemSigstorePrivate).data, newKey(t, p384, "pw-384", pemSigstorePrivate), ErrUnsupportedKey},
		{"Ed25519 key", newKey(t, edKey, "pw-ed", pemSigstorePrivate).data, newKey(t, edKey, "pw-ed", pemSigstorePrivate), ErrUnsupportedKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSecretSigner(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v (signer %v), want %v", err, s != nil, tc.want)
			}
			if s != nil {
				t.Fatal("a signer was returned with an error")
			}
			assertSanitized(t, err, tc.key)
			assertSanitized(t, err, good)
		})
	}
	// The P-384 public key alone is refused as a verification key too.
	if _, err := ParsePublicKey(newKey(t, p384, "x", pemSigstorePrivate).data[SecretPublicKey]); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("P-384 public key: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()
	k := cosignKey(t, "pw")
	s := signer(t, k)
	attacker := signer(t, cosignKey(t, "attacker"))
	archive := []byte("the frozen archive")
	d := DigestArchive(archive)
	sig, err := s.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	pub := s.PublicKey()
	changed := bytes.Clone(archive)
	changed[0] ^= 1
	otherSig, err := attacker.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's signature with the trusted key's hint.
	forgedHint := mustWire(t, otherSig.Bundle)
	forgedHint.VerificationMaterial.PublicKey.Hint = pub.hint
	flipped := mustWire(t, sig.Bundle)
	flipped.MessageSignature.Signature = bytes.Clone(flipped.MessageSignature.Signature)
	flipped.MessageSignature.Signature[len(flipped.MessageSignature.Signature)-1] ^= 1
	shortDigest := mustWire(t, sig.Bundle)
	shortDigest.MessageSignature.MessageDigest.Digest = d[:31]
	noSig := mustWire(t, sig.Bundle)
	noSig.MessageSignature.Signature = nil
	spaced := bytes.ReplaceAll(sig.Bundle, []byte(`","`), []byte(`", "`))
	dup := bytes.Replace(sig.Bundle, []byte(`{"mediaType":`), []byte(`{"mediaType":"x","mediaType":`), 1)

	cases := []struct {
		name    string
		raw     []byte
		archive ArchiveDigest
		key     PublicKey
		want    error
	}{
		{"changed archive byte", sig.Bundle, DigestArchive(changed), pub, ErrArchiveMismatch},
		{"another archive", sig.Bundle, DigestArchive([]byte("other")), pub, ErrArchiveMismatch},
		{"wrong trusted key", sig.Bundle, d, attacker.PublicKey(), ErrWrongKey},
		{"untrusted key with trusted hint", mustJSON(t, forgedHint), d, pub, ErrSignature},
		{"untrusted key's own signature", otherSig.Bundle, d, pub, ErrWrongKey},
		{"flipped signature byte", mustJSON(t, flipped), d, pub, ErrSignature},
		{"no trusted key", sig.Bundle, d, PublicKey{}, ErrWrongKey},
		{"empty", nil, d, pub, ErrMalformedBundle},
		{"oversized", bytes.Repeat([]byte(" "), MaxBundleBytes+1), d, pub, ErrMalformedBundle},
		{"truncated", sig.Bundle[:len(sig.Bundle)/2], d, pub, ErrMalformedBundle},
		{"not JSON", []byte("not json"), d, pub, ErrMalformedBundle},
		{"trailing data", append(bytes.Clone(sig.Bundle), "{}"...), d, pub, ErrMalformedBundle},
		{"duplicate key", dup, d, pub, ErrMalformedBundle},
		{"non-canonical whitespace", spaced, d, pub, ErrMalformedBundle},
		{"short digest", mustJSON(t, shortDigest), d, pub, ErrMalformedBundle},
		{"no signature", mustJSON(t, noSig), d, pub, ErrMalformedBundle},
		{"wrong field type", editMap(t, sig.Bundle, func(m map[string]any) { m["mediaType"] = 3 }), d, pub, ErrMalformedBundle},
		{"bundle v0.2", editMap(t, sig.Bundle, func(m map[string]any) {
			m["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
		}), d, pub, ErrUnsupportedFormat},
		{"SHA-384 digest", editMap(t, sig.Bundle, func(m map[string]any) {
			m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_384"
		}), d, pub, ErrUnsupportedFormat},
		{"transparency-log entries", editMap(t, sig.Bundle, func(m map[string]any) {
			m["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{}
		}), d, pub, ErrUnsupportedFormat},
		{"certificate", editMap(t, sig.Bundle, func(m map[string]any) {
			m["verificationMaterial"].(map[string]any)["certificate"] = map[string]any{"rawBytes": "AA=="}
		}), d, pub, ErrUnsupportedFormat},
		{"timestamps", editMap(t, sig.Bundle, func(m map[string]any) {
			m["verificationMaterial"].(map[string]any)["timestampVerificationData"] = map[string]any{}
		}), d, pub, ErrUnsupportedFormat},
		{"DSSE envelope", editMap(t, sig.Bundle, func(m map[string]any) {
			m["dsseEnvelope"] = map[string]any{"payload": "", "payloadType": "x", "signatures": []any{}}
		}), d, pub, ErrUnsupportedFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Verify(tc.raw, tc.archive, tc.key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v (%+v), want %v", err, v, tc.want)
			}
			if v != (Verified{}) {
				t.Fatalf("partial result on failure: %+v", v)
			}
		})
	}
	// The untampered bundle still verifies: the cases above did not alter it.
	if _, err := Verify(sig.Bundle, d, pub); err != nil {
		t.Fatal(err)
	}
}

func TestSignContextAndConcurrency(t *testing.T) {
	s := signer(t, cosignKey(t, "pw"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sign(ctx, DigestArchive([]byte("x"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	var wg sync.WaitGroup
	seen := sync.Map{}
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := DigestArchive([]byte{byte(i)})
			sig, err := s.Sign(context.Background(), d)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := Verify(sig.Bundle, d, s.PublicKey()); err != nil {
				t.Error(err)
			}
			if _, dup := seen.LoadOrStore(sig.BundleSHA256, true); dup {
				t.Error("duplicate bundle")
			}
		}()
	}
	wg.Wait()
}

type recordingTransport struct{ calls atomic.Int64 }

func (r *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, errors.New("network access is not allowed in this test")
}

// Signing and verification use no network client and no ambient identity:
// with ambient Sigstore/GitHub OIDC variables set and every default HTTP
// transport replaced by a recorder, they succeed without one request, and
// the bundle carries only the operator key's material.
func TestNoNetworkOrAmbientIdentity(t *testing.T) {
	for _, v := range []string{"SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(v, "ambient-sentinel-"+v)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	rec := &recordingTransport{}
	saved := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = saved })

	k := cosignKey(t, "pw")
	s := signer(t, k)
	d := DigestArchive([]byte("archive"))
	sig, err := s.Sign(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig.Bundle, d, s.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if n := rec.calls.Load(); n != 0 {
		t.Fatalf("%d HTTP requests were attempted", n)
	}
	if bytes.Contains(sig.Bundle, []byte("ambient-sentinel")) || bytes.Contains(sig.Bundle, []byte("certificate")) || bytes.Contains(sig.Bundle, []byte("tlog")) {
		t.Fatalf("bundle carries ambient or service material: %s", sig.Bundle)
	}
}
