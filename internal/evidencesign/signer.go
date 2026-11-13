// Package evidencesign signs and verifies frozen evidence archives
// (package.tar.gz) for add-evidence-signing.
//
// The contract (docs/integration/evidence-signing.md):
//
//   - Keys are operator-provided Cosign key pairs: ECDSA P-256 private keys in
//     Cosign's encrypted PEM encoding ("ENCRYPTED SIGSTORE PRIVATE KEY", or the
//     older "ENCRYPTED COSIGN PRIVATE KEY"), with the matching PKIX public key.
//     A key is identified by the SHA-256 of its DER SubjectPublicKeyInfo.
//   - A signature is a Sigstore bundle v0.3 holding a message signature: the
//     SHA-256 of the exact archive bytes and an ASN.1 ECDSA signature over that
//     digest, plus the key hint Cosign writes. It has no certificate,
//     transparency-log entry, or timestamp. `cosign verify-blob --key <trusted
//     key> --bundle <bundle> --insecure-ignore-tlog=true <archive>` verifies it
//     offline.
//
// Signing happens in-process with maintained Sigstore libraries; nothing here
// runs Cosign, opens a network connection, reads ambient credentials, or
// writes key material anywhere. Callers pass the Secret's data and drop the
// signer after use.
package evidencesign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// Signing Secret entries: the names `cosign generate-key-pair k8s://...`
// writes. All three are required; cosign.password may be empty.
const (
	SecretPrivateKey = "cosign.key"
	SecretPublicKey  = "cosign.pub"
	SecretPassword   = "cosign.password"
)

// Size bounds on Secret entries. Cosign's P-256 keys are well below them.
const (
	MaxPrivateKeyBytes = 16 << 10
	MaxPublicKeyBytes  = 16 << 10
	MaxPasswordBytes   = 4 << 10
)

// Algorithm is the only supported signing algorithm, in Cosign's
// --signing-algorithm spelling (the default of `cosign generate-key-pair`).
const Algorithm = "ecdsa-sha2-256-nistp256"

// PEM block types of Cosign's encrypted private keys.
const (
	pemSigstorePrivate = "ENCRYPTED SIGSTORE PRIVATE KEY"
	pemCosignPrivate   = "ENCRYPTED COSIGN PRIVATE KEY"
)

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ArchiveDigest is the SHA-256 of the exact archive bytes: the value a
// message signature signs. It is raw digest bytes, never a hex string, so
// the textual digest cannot be hashed again by mistake.
type ArchiveDigest [sha256.Size]byte

// DigestArchive returns the digest of archive bytes.
func DigestArchive(archive []byte) ArchiveDigest { return sha256.Sum256(archive) }

// ParseArchiveDigest accepts the lowercase hex SHA-256 recorded by
// publication (publication.Staged.PackageSHA256).
func ParseArchiveDigest(s string) (ArchiveDigest, error) {
	var d ArchiveDigest
	if !hexSHA256.MatchString(s) {
		return d, fmt.Errorf("archive digest %q is not a lowercase hex SHA-256", s)
	}
	_, _ = hex.Decode(d[:], []byte(s))
	return d, nil
}

// String returns the lowercase hex digest.
func (d ArchiveDigest) String() string { return hex.EncodeToString(d[:]) }

// PublicKey is a parsed, supported verification key. The zero value is not
// usable; obtain one from ParsePublicKey or a Signer.
type PublicKey struct {
	// Fingerprint is "sha256:" and the lowercase hex SHA-256 of the DER
	// SubjectPublicKeyInfo: the key identity recorded with signatures.
	Fingerprint string
	// Algorithm is Algorithm.
	Algorithm string
	// PEM is the canonical PEM encoding of the key, suitable for retained
	// public verification material.
	PEM []byte

	key  *ecdsa.PublicKey
	hint string // what Cosign writes as the bundle's public-key hint
}

// ParsePublicKey accepts exactly one headerless PEM "PUBLIC KEY" block with
// only surrounding whitespace, holding an ECDSA P-256 key.
func ParsePublicKey(raw []byte) (PublicKey, error) {
	if len(raw) > MaxPublicKeyBytes {
		return PublicKey{}, fail(ErrKeyMalformed, "public key exceeds %d bytes", MaxPublicKeyBytes)
	}
	block, err := onePEM(raw, "public key")
	if err != nil {
		return PublicKey{}, err
	}
	switch {
	case bytes.Contains([]byte(block.Type), []byte("PRIVATE")):
		return PublicKey{}, fail(ErrKeyMalformed, "the public key entry holds a private key")
	case block.Type != "PUBLIC KEY":
		return PublicKey{}, fail(ErrKeyMalformed, "public key PEM block is %q, not PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return PublicKey{}, fail(ErrKeyMalformed, "public key is not a PKIX SubjectPublicKeyInfo")
	}
	return newPublicKey(pub)
}

func newPublicKey(pub crypto.PublicKey) (PublicKey, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return PublicKey{}, fail(ErrUnsupportedKey, "%s; only ECDSA P-256 (%s) is supported", keyKind(pub), Algorithm)
	}
	der, err := x509.MarshalPKIXPublicKey(ec)
	if err != nil {
		return PublicKey{}, fail(ErrKeyMalformed, "public key cannot be encoded")
	}
	sum := sha256.Sum256(der)
	return PublicKey{
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		Algorithm:   Algorithm,
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		key:         ec,
		hint:        base64.StdEncoding.EncodeToString(sum[:]),
	}, nil
}

func (k PublicKey) valid() bool { return k.key != nil }

// Equal reports whether two keys are the same public key.
func (k PublicKey) Equal(o PublicKey) bool { return k.valid() && o.valid() && k.key.Equal(o.key) }

func keyKind(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *ecdsa.PrivateKey:
		return "ECDSA " + k.Curve.Params().Name
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// onePEM decodes exactly one headerless PEM block surrounded by nothing but
// whitespace. Errors never echo the input.
func onePEM(raw []byte, what string) (*pem.Block, error) {
	rest := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) || bytes.Count(rest, []byte("-----BEGIN")) != 1 {
		return nil, fail(ErrKeyMalformed, "%s must be exactly one PEM block", what)
	}
	block, tail := pem.Decode(rest)
	switch {
	case block == nil:
		return nil, fail(ErrKeyMalformed, "%s is not PEM", what)
	case len(bytes.TrimSpace(tail)) > 0:
		return nil, fail(ErrKeyMalformed, "%s has data after its PEM block", what)
	case len(block.Headers) > 0:
		return nil, fail(ErrKeyMalformed, "%s PEM block has headers", what)
	}
	return block, nil
}

// Signature is verified signature material for one archive.
type Signature struct {
	// Bundle is the canonical package.sigstore.json bytes.
	Bundle []byte
	// BundleSHA256 is the lowercase hex SHA-256 of Bundle.
	BundleSHA256 string
	// MediaType is BundleMediaType.
	MediaType string
	// Algorithm is Algorithm.
	Algorithm string
	// KeyFingerprint is the signing key's PublicKey.Fingerprint.
	KeyFingerprint string
	// ArchiveSHA256 is the lowercase hex SHA-256 of the signed archive.
	ArchiveSHA256 string
}

// Signer signs archive digests under one fixed key and algorithm. Sign
// returns only signatures it has verified under PublicKey. Implementations
// are safe for concurrent use.
type Signer interface {
	PublicKey() PublicKey
	Sign(ctx context.Context, archive ArchiveDigest) (Signature, error)
}

// SecretSigner is the Kubernetes Secret-backed Signer. It holds the
// decrypted private key in memory only; it never persists, logs, or exports
// it. Drop it after use.
type SecretSigner struct {
	pub PublicKey
	sv  *signature.ECDSASignerVerifier
}

var _ Signer = (*SecretSigner)(nil)

// NewSecretSigner loads a Cosign key pair from a signing Secret's data. It
// decrypts cosign.key with cosign.password, requires an ECDSA P-256 key, and
// requires cosign.pub to be exactly its public key. Errors are sanitized:
// they wrap a sentinel and never contain Secret contents.
func NewSecretSigner(data map[string][]byte) (*SecretSigner, error) {
	privPEM, ok := data[SecretPrivateKey]
	pubPEM, okPub := data[SecretPublicKey]
	password, okPass := data[SecretPassword]
	switch {
	case !ok || len(privPEM) == 0:
		return nil, fail(ErrKeyUnavailable, "the Secret has no %s entry", SecretPrivateKey)
	case !okPub || len(pubPEM) == 0:
		return nil, fail(ErrKeyUnavailable, "the Secret has no %s entry", SecretPublicKey)
	case !okPass:
		return nil, fail(ErrKeyUnavailable, "the Secret has no %s entry (it may be empty, but must exist)", SecretPassword)
	case len(privPEM) > MaxPrivateKeyBytes:
		return nil, fail(ErrKeyUnavailable, "%s exceeds %d bytes", SecretPrivateKey, MaxPrivateKeyBytes)
	case len(password) > MaxPasswordBytes:
		return nil, fail(ErrKeyUnavailable, "%s exceeds %d bytes", SecretPassword, MaxPasswordBytes)
	}
	want, err := ParsePublicKey(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SecretPublicKey, err)
	}

	block, err := onePEM(privPEM, SecretPrivateKey)
	if err != nil {
		return nil, err
	}
	if block.Type != pemSigstorePrivate && block.Type != pemCosignPrivate {
		if bytes.Contains([]byte(block.Type), []byte("PRIVATE KEY")) {
			return nil, fail(ErrUnsupportedKey, "%s is an unencrypted %q block; only Cosign's encrypted key encoding is supported", SecretPrivateKey, block.Type)
		}
		return nil, fail(ErrKeyMalformed, "%s PEM block is %q, not %s", SecretPrivateKey, block.Type, pemSigstorePrivate)
	}
	// encrypted.Decrypt accepts only Cosign/securesystemslib's fixed scrypt
	// parameter sets, which bounds its memory use. Its error text is not
	// propagated; only its authentication failure is told apart (pinned by
	// TestSecretSignerKeyFailures).
	der, err := encrypted.Decrypt(block.Bytes, password)
	if err != nil {
		if err.Error() == "encrypted: decryption failed" {
			return nil, fail(ErrKeyPassword, "%s", SecretPrivateKey)
		}
		return nil, fail(ErrKeyMalformed, "%s is not a Cosign encrypted key with supported parameters", SecretPrivateKey)
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fail(ErrKeyMalformed, "decrypted %s is not a PKCS #8 private key", SecretPrivateKey)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, fail(ErrUnsupportedKey, "%s is %s; only ECDSA P-256 (%s) is supported", SecretPrivateKey, keyKind(parsed), Algorithm)
	}
	got, err := newPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if !got.Equal(want) {
		return nil, fail(ErrKeyMismatch, "%s has fingerprint %s, the private key's is %s", SecretPublicKey, want.Fingerprint, got.Fingerprint)
	}
	sv, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, fail(ErrUnsupportedKey, "the private key cannot sign with %s", Algorithm)
	}
	return &SecretSigner{pub: got, sv: sv}, nil
}

// PublicKey returns the signing key's public identity.
func (s *SecretSigner) PublicKey() PublicKey { return s.pub }

// Sign signs the archive digest (never a hash of it), encodes the bundle, and
// verifies it under the signer's own public key before returning it. ECDSA
// signatures are randomized: two calls return different valid bundles.
func (s *SecretSigner) Sign(ctx context.Context, archive ArchiveDigest) (Signature, error) {
	if err := ctx.Err(); err != nil {
		return Signature{}, err
	}
	sig, err := s.sv.SignMessage(bytes.NewReader(nil), options.WithDigest(archive[:]), options.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		return Signature{}, fmt.Errorf("evidence signing failed: %w", err)
	}
	raw, err := encodeBundle(s.pub.hint, archive, sig)
	if err != nil {
		return Signature{}, err
	}
	if _, err := Verify(raw, archive, s.pub); err != nil {
		return Signature{}, fmt.Errorf("a freshly made signature does not verify: %w", err)
	}
	return newSignature(raw, archive, s.pub), nil
}

func newSignature(raw []byte, archive ArchiveDigest, pub PublicKey) Signature {
	sum := sha256.Sum256(raw)
	return Signature{
		Bundle:         raw,
		BundleSHA256:   hex.EncodeToString(sum[:]),
		MediaType:      BundleMediaType,
		Algorithm:      Algorithm,
		KeyFingerprint: pub.Fingerprint,
		ArchiveSHA256:  archive.String(),
	}
}
