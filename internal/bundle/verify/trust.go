package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// ObjectReader reads one Secret or ConfigMap by name in the controller's own
// namespace. kubeaccess.ClientReader and kubeaccess.MemoryReader implement it.
// It is the verifier's only source of keys and trusted roots.
type ObjectReader interface {
	Get(ctx context.Context, kind, name string) (kubeaccess.Object, error)
}

// Bounds on referenced trust objects.
const (
	MaxPublicKeyBytes = 16 << 10
	MaxTrustRootBytes = 1 << 20
)

// PublicGoodTrustRootSHA256 is the SHA-256 of the embedded Sigstore
// public-good trusted root (publicgood/trusted_root.json; provenance and the
// refresh procedure are in publicgood/README.md).
const PublicGoodTrustRootSHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"

// TrustRootPublicGood names the embedded root in VerifiedProof.TrustRootSource.
const TrustRootPublicGood = "embedded:sigstore-public-good"

//go:embed publicgood/trusted_root.json
var publicGoodTrustRoot []byte

// trust is the verification material derived from one publisher rule and the
// objects it references, read once so that every proof checked in one call is
// judged against the same snapshot.
type trust struct {
	publisher bundle.Publisher

	// Keyless.
	root       *root.TrustedRoot
	rootID     string // sha256:<hex> of the trusted root JSON bytes
	rootSource string
	requireSCT bool

	// Public key.
	keyMaterial root.TrustedMaterial
	fingerprint string // sha256:<hex> of the DER SubjectPublicKeyInfo
}

func (v *Verifier) loadTrust(ctx context.Context, p bundle.Publisher) (*trust, error) {
	if err := p.Validate(); err != nil {
		return nil, fail(ErrTrustConfig, "publisher rule: %v", err)
	}
	t := &trust{publisher: p}
	switch p.Type {
	case bundle.SignerKeyless:
		// The rule validator already refuses patterns; the verifier refuses
		// them again rather than trust a caller to have validated.
		if strings.ContainsAny(p.Identity+p.Issuer, "*?[]{}()|^$\\") {
			return nil, fail(ErrTrustConfig, "keyless issuer and identity must be exact values")
		}
		raw, source := publicGoodTrustRoot, TrustRootPublicGood
		if p.TrustRoot != nil {
			var err error
			if raw, err = v.readRef(ctx, "trustRoot", p.TrustRoot, bundle.DefaultTrustRootKey, MaxTrustRootBytes); err != nil {
				return nil, err
			}
			source = refString(p.TrustRoot, bundle.DefaultTrustRootKey)
		} else if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != PublicGoodTrustRootSHA256 {
			return nil, fail(ErrTrustConfig, "embedded public-good trusted root does not match its pinned digest")
		}
		tr, err := parseTrustedRoot(raw)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		t.root, t.rootID, t.rootSource = tr, "sha256:"+hex.EncodeToString(sum[:]), source
		t.requireSCT = len(tr.CTLogs()) > 0
	case bundle.SignerPublicKey:
		raw, err := v.readRef(ctx, "publicKey", p.PublicKey, bundle.DefaultPublicKey, MaxPublicKeyBytes)
		if err != nil {
			return nil, err
		}
		pub, fp, err := parsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		want := strings.TrimPrefix(p.KeyFingerprint, "sha256:")
		if fp != want {
			return nil, fail(ErrKeyFingerprint, "key %s has fingerprint sha256:%s, the rule requires sha256:%s",
				refString(p.PublicKey, bundle.DefaultPublicKey), fp, want)
		}
		sv, err := signature.LoadECDSAVerifier(pub, crypto.SHA256)
		if err != nil {
			return nil, fail(ErrUnsupportedKey, "%v", err)
		}
		key := root.NewExpiringKey(sv, time.Time{}, time.Time{})
		// The bundle's key hint is attacker-controlled and only names a key;
		// whatever it says, the one configured key is used.
		t.keyMaterial = root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
			return key, nil
		})
		t.fingerprint = "sha256:" + fp
	default:
		return nil, fail(ErrTrustConfig, "publisher type %q", p.Type)
	}
	return t, nil
}

func refString(r *bundle.ObjectRef, defaultKey string) string {
	key := r.Key
	if key == "" {
		key = defaultKey
	}
	return fmt.Sprintf("%s/%s[%s]", r.Kind, r.Name, key)
}

// readRef reads one referenced value. A missing object or key, a read error
// or an oversized value is a trust configuration error; there is no default.
func (v *Verifier) readRef(ctx context.Context, what string, r *bundle.ObjectRef, defaultKey string, limit int) ([]byte, error) {
	if r == nil {
		return nil, fail(ErrTrustConfig, "publisher.%s is not configured", what)
	}
	key := r.Key
	if key == "" {
		key = defaultKey
	}
	obj, err := v.objects.Get(ctx, r.Kind, r.Name)
	if err != nil {
		return nil, fail(ErrTrustConfig, "publisher.%s %s: %v", what, refString(r, defaultKey), err)
	}
	val, ok := obj.Value(key)
	switch {
	case !ok:
		return nil, fail(ErrTrustConfig, "publisher.%s %s has no key %q", what, refString(r, defaultKey), key)
	case len(val) > limit:
		return nil, fail(ErrTrustConfig, "publisher.%s %s exceeds %d bytes", what, refString(r, defaultKey), limit)
	case len(bytes.TrimSpace(val)) == 0:
		return nil, fail(ErrTrustConfig, "publisher.%s %s is empty", what, refString(r, defaultKey))
	}
	return val, nil
}

// parsePublicKey accepts exactly one PEM "PUBLIC KEY" block (PKIX
// SubjectPublicKeyInfo) without headers and with nothing but whitespace around
// it, holding an ECDSA P-256 key: the type `cosign generate-key-pair` (v3.1.3)
// produces. Other key types are refused rather than verified with a guessed
// hash. It returns the key and the lowercase hex SHA-256 of its DER encoding.
func parsePublicKey(raw []byte) (*ecdsa.PublicKey, string, error) {
	rest := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) || bytes.Count(rest, []byte("-----BEGIN")) != 1 {
		return nil, "", fail(ErrTrustConfig, "public key must be exactly one PEM block")
	}
	block, tail := pem.Decode(rest)
	switch {
	case block == nil:
		return nil, "", fail(ErrTrustConfig, "public key is not PEM")
	case len(bytes.TrimSpace(tail)) > 0:
		return nil, "", fail(ErrTrustConfig, "public key has data after the PEM block")
	case strings.Contains(block.Type, "PRIVATE"):
		return nil, "", fail(ErrTrustConfig, "a private key was supplied; only the public key belongs here")
	case block.Type != "PUBLIC KEY":
		return nil, "", fail(ErrTrustConfig, "PEM block %q is not a PUBLIC KEY", block.Type)
	case len(block.Headers) > 0:
		return nil, "", fail(ErrTrustConfig, "public key PEM block has headers")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fail(ErrTrustConfig, "public key does not parse")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, "", fail(ErrUnsupportedKey, "%T; only ECDSA P-256 (Cosign's default) is accepted", pub)
	}
	sum := sha256.Sum256(block.Bytes)
	return ec, hex.EncodeToString(sum[:]), nil
}

// parseTrustedRoot parses a Sigstore trusted root (media type
// application/vnd.dev.sigstore.trustedroot+json;version=0.1) strictly and
// requires what keyless verification needs: a certificate authority and a
// transparency log.
func parseTrustedRoot(raw []byte) (*root.TrustedRoot, error) {
	if len(raw) > MaxTrustRootBytes {
		return nil, fail(ErrTrustConfig, "trusted root exceeds %d bytes", MaxTrustRootBytes)
	}
	if err := checkJSON(raw); err != nil {
		return nil, fail(ErrTrustConfig, "trusted root: %v", err)
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fail(ErrTrustConfig, "trusted root: %v", err)
	}
	if len(tr.FulcioCertificateAuthorities()) == 0 {
		return nil, fail(ErrTrustConfig, "trusted root has no certificate authority")
	}
	if len(tr.RekorLogs()) == 0 {
		return nil, fail(ErrTrustConfig, "trusted root has no transparency log")
	}
	return tr, nil
}

var errNoReader = errors.New("verify: an ObjectReader is required")
