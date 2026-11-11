package verify

import (
	"errors"
	"fmt"
)

// Errors returned by the verifier wrap one of these sentinels; test with
// errors.Is. A proof that fails any check is rejected as a whole: there is no
// partial acceptance and no verification-off switch. Messages never contain
// key material or credentials.
var (
	// ErrTrustConfig: the publisher rule is invalid, or a trust input it
	// references (public key, trusted root) is missing, unreadable or
	// malformed. There is no fallback to another rule or root.
	ErrTrustConfig = errors.New("publisher trust configuration is unavailable or invalid")
	// ErrKeyFingerprint: the referenced public key does not have the
	// fingerprint the rule fixes. It wraps ErrTrustConfig.
	ErrKeyFingerprint = fmt.Errorf("%w: public key fingerprint does not match the rule", ErrTrustConfig)
	// ErrUnsupportedKey: the referenced public key is not an accepted key
	// type. It wraps ErrTrustConfig.
	ErrUnsupportedKey = fmt.Errorf("%w: unsupported public key type", ErrTrustConfig)

	// ErrMalformedProof: the proof is not a well-formed Sigstore bundle v0.3
	// with a DSSE envelope (garbled or truncated JSON, duplicate or unknown
	// keys, another media type, a message signature, a certificate chain).
	ErrMalformedProof = errors.New("malformed verification proof")
	// ErrProofTooLarge: the proof or its statement exceeds the parsing bound.
	ErrProofTooLarge = errors.New("verification proof exceeds the size limit")
	// ErrSigner: the proof was signed by a signer the rule does not name: a
	// different OIDC issuer or identity, a certificate where the rule fixes
	// a key, or a key where the rule requires a keyless certificate.
	ErrSigner = errors.New("proof is not signed by the configured publisher")
	// ErrAlgorithm: the signing key or certificate key uses an algorithm
	// outside the accepted set.
	ErrAlgorithm = errors.New("unsupported signature algorithm")
	// ErrSignature: the signature does not verify under the configured trust
	// (tampered payload or signature, wrong key, a certificate that does not
	// chain to the configured root, a missing certificate transparency proof).
	ErrSignature = errors.New("signature does not verify under the configured trust")
	// ErrTransparency: a keyless proof has no transparency log entry that
	// verifies under the configured trusted root.
	ErrTransparency = errors.New("no verifiable transparency log entry")
	// ErrSigningTime: a keyless proof has no signing time authenticated by
	// the configured trusted root, or its certificate was not valid at an
	// authenticated signing time, or that time lies in the future.
	ErrSigningTime = errors.New("no valid authenticated signing time")
	// ErrStatement: the signed DSSE payload is not a well-formed in-toto
	// Statement v1.
	ErrStatement = errors.New("malformed signed statement")
	// ErrSubject: the signed statement is not for exactly the pinned OCI
	// manifest digest.
	ErrSubject = errors.New("signed statement is not for the pinned subject")
	// ErrPredicateType: the signed statement's predicate type is not the one
	// the requested proof kind requires.
	ErrPredicateType = errors.New("signed statement has the wrong predicate type")
	// ErrNoValidProof: candidate proofs of a required kind exist, but none
	// verifies. The error also matches each candidate's own failure.
	ErrNoValidProof = errors.New("no proof verifies under the publisher rule")

	// ErrMixedSigner: the signature and the provenance attestation were not
	// verified under the same signer, trusted root and subject.
	ErrMixedSigner = errors.New("signature and provenance were not verified under the same publisher")
	// ErrProvenanceContract: the verified SLSA predicate does not follow the
	// Konstapel bundle provenance contract (build type, required fields,
	// exact types, materials, bounds). Provenance in another shape, such as a
	// generic GitHub Actions workflow build, is refused rather than guessed.
	ErrProvenanceContract = errors.New("provenance does not follow the Konstapel bundle provenance contract")
	// ErrProvenanceBuilder: the attested builder is not the rule's builder.
	ErrProvenanceBuilder = errors.New("provenance builder is not the configured builder")
	// ErrProvenanceSource: the attested source repository or commit differs
	// from the rule or from the bundle's own source.
	ErrProvenanceSource = errors.New("provenance source does not match the rule and the bundle")
	// ErrProvenanceRelease: the attested bundle name or version differs from
	// the bundle's descriptor or the requested source name.
	ErrProvenanceRelease = errors.New("provenance release identity does not match the bundle")
	// ErrProvenanceMaterial: an attested material contradicts the payload.
	ErrProvenanceMaterial = errors.New("provenance materials contradict the bundle payload")

	// ErrRecheckBundle: retained recheck material is malformed, oversized, of
	// an unsupported version, or its bytes do not hash to the digests its
	// receipt names.
	ErrRecheckBundle = errors.New("invalid verification recheck material")
	// ErrContent: the bundle content does not belong to the verified subject.
	ErrContent = errors.New("bundle content does not match the verified subject")
)

func fail(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, a...)...)
}
