package evidencesign

import (
	"errors"
	"fmt"
)

// Errors returned by this package wrap one of these sentinels; test with
// errors.Is. Messages are fixed text plus non-secret identifiers (digests,
// fingerprints, sizes, PEM block types). They never contain private-key
// bytes, passwords, or the error text of a key-decoding library.
var (
	// ErrKeyUnavailable: the signing Secret lacks a required entry
	// (cosign.key, cosign.pub, cosign.password) or an entry exceeds its
	// size bound. The password entry is required even when empty.
	ErrKeyUnavailable = errors.New("signing key material is unavailable")
	// ErrKeyMalformed: an entry is not the expected PEM encoding, or the
	// decrypted key is not PKCS #8.
	ErrKeyMalformed = errors.New("signing key material is malformed")
	// ErrKeyPassword: the encrypted private key cannot be decrypted with the
	// supplied password (wrong password or corrupted ciphertext; the
	// authenticated cipher cannot tell these apart).
	ErrKeyPassword = errors.New("signing key cannot be decrypted with the supplied password")
	// ErrKeyMismatch: the supplied public key is not the private key's
	// public key.
	ErrKeyMismatch = errors.New("signing public key does not match the private key")
	// ErrUnsupportedKey: the key is not ECDSA P-256, or not in the Cosign
	// encrypted encoding. No other algorithm is guessed or converted.
	ErrUnsupportedKey = errors.New("unsupported signing key")

	// ErrMalformedBundle: the signature bundle is empty, oversized, not
	// canonical Konstapel bundle JSON, or rejected by the Sigstore bundle
	// parser.
	ErrMalformedBundle = errors.New("malformed signature bundle")
	// ErrUnsupportedFormat: the bundle has another media type, digest
	// algorithm, content kind (for example a DSSE envelope), or verification
	// material (certificate, transparency-log entry, timestamp).
	ErrUnsupportedFormat = errors.New("unsupported signature bundle format")
	// ErrArchiveMismatch: the bundle signs another archive digest.
	ErrArchiveMismatch = errors.New("signature bundle is for another archive")
	// ErrWrongKey: the bundle's key hint names another key than the trusted
	// one. The hint only identifies a key; it never selects trust.
	ErrWrongKey = errors.New("signature bundle names another key")
	// ErrSignature: the signature does not verify under the trusted key.
	ErrSignature = errors.New("signature does not verify under the trusted key")
)

func fail(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, a...)...)
}
