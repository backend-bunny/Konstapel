package evidencesign

import (
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"strings"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

// BundleMediaType is the only supported bundle version: Sigstore bundle
// v0.3, as written by the pinned Cosign's `sign-blob --bundle`.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// BundleFileName is the companion object stored beside package.tar.gz.
const BundleFileName = "package.sigstore.json"

// MaxBundleBytes bounds a bundle before it is parsed. A Konstapel bundle is
// about 400 bytes.
const MaxBundleBytes = 64 << 10

// digestAlgorithm is the Sigstore HashAlgorithm name of the message digest.
const digestAlgorithm = "SHA2_256"

// wireBundle is the exact JSON shape Konstapel writes: the fields of a
// Sigstore bundle v0.3 that a key-based, no-log message signature uses, in
// protobuf field order. []byte fields encode as standard base64, as in the
// protobuf JSON mapping.
type wireBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKey struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
}

func encodeBundle(hint string, archive ArchiveDigest, sig []byte) ([]byte, error) {
	var w wireBundle
	w.MediaType = BundleMediaType
	w.VerificationMaterial.PublicKey.Hint = hint
	w.MessageSignature.MessageDigest.Algorithm = digestAlgorithm
	w.MessageSignature.MessageDigest.Digest = archive[:]
	w.MessageSignature.Signature = sig
	return json.Marshal(&w)
}

// Verified describes a bundle that Verify accepted.
type Verified struct {
	BundleSHA256   string
	MediaType      string
	Algorithm      string
	KeyFingerprint string
	ArchiveSHA256  string
}

// Verify checks that raw is a canonical Konstapel signature bundle for
// exactly archive, signed by trusted. The trusted key is the caller's choice:
// the bundle's key hint must name it but never selects or adds trust. The
// check is offline and needs no private key, certificate authority,
// transparency log, or timestamp.
//
// Only the canonical encoding Sign produces is accepted. Cosign's own
// sign-blob output (same content, different whitespace) is verified by
// Cosign, not here.
func Verify(raw []byte, archive ArchiveDigest, trusted PublicKey) (Verified, error) {
	if !trusted.valid() {
		return Verified{}, fail(ErrWrongKey, "no trusted key was supplied")
	}
	if len(raw) == 0 {
		return Verified{}, fail(ErrMalformedBundle, "empty bundle")
	}
	if len(raw) > MaxBundleBytes {
		return Verified{}, fail(ErrMalformedBundle, "bundle is %d bytes, the limit is %d", len(raw), MaxBundleBytes)
	}

	// Strict shape first: unknown fields (a certificate, tlog entries,
	// timestamps, a DSSE envelope), duplicate keys, trailing data, and any
	// non-canonical spelling are refused by requiring the exact re-encoding.
	var w wireBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return Verified{}, fail(ErrUnsupportedFormat, "the bundle has content other than a key-based message signature")
		}
		return Verified{}, fail(ErrMalformedBundle, "bundle is not the expected JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Verified{}, fail(ErrMalformedBundle, "trailing data after the bundle")
	}
	switch {
	case w.MediaType != BundleMediaType:
		return Verified{}, fail(ErrUnsupportedFormat, "media type %.80q; only %s is supported", w.MediaType, BundleMediaType)
	case w.MessageSignature.MessageDigest.Algorithm != digestAlgorithm:
		return Verified{}, fail(ErrUnsupportedFormat, "message digest algorithm %.32q; only %s is supported", w.MessageSignature.MessageDigest.Algorithm, digestAlgorithm)
	case len(w.MessageSignature.MessageDigest.Digest) != len(archive):
		return Verified{}, fail(ErrMalformedBundle, "message digest is %d bytes", len(w.MessageSignature.MessageDigest.Digest))
	case len(w.MessageSignature.Signature) == 0:
		return Verified{}, fail(ErrMalformedBundle, "no signature")
	}
	canonical, err := encodeBundle(w.VerificationMaterial.PublicKey.Hint, ArchiveDigest(w.MessageSignature.MessageDigest.Digest), w.MessageSignature.Signature)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Verified{}, fail(ErrMalformedBundle, "bundle is not in canonical form")
	}
	if !bytes.Equal(w.MessageSignature.MessageDigest.Digest, archive[:]) {
		return Verified{}, fail(ErrArchiveMismatch, "bundle signs sha256:%x, the archive is sha256:%s", w.MessageSignature.MessageDigest.Digest, archive)
	}
	if w.VerificationMaterial.PublicKey.Hint != trusted.hint {
		return Verified{}, fail(ErrWrongKey, "bundle names another key than the trusted %s", trusted.Fingerprint)
	}

	// Authoritative: the Sigstore library parses the standard bundle and
	// checks the signature over the archive digest under the trusted key.
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Verified{}, fail(ErrMalformedBundle, "%v", err)
	}
	v, err := signature.LoadECDSAVerifier(trusted.key, crypto.SHA256)
	if err != nil {
		return Verified{}, fail(ErrUnsupportedFormat, "%v", err)
	}
	key := root.NewExpiringKey(v, time.Time{}, time.Time{})
	material := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) { return key, nil })
	verifier, err := sgverify.NewVerifier(material, sgverify.WithNoObserverTimestamps())
	if err != nil {
		return Verified{}, fail(ErrSignature, "%v", err)
	}
	if _, err := verifier.Verify(&b, sgverify.NewPolicy(sgverify.WithArtifactDigest("sha256", archive[:]), sgverify.WithKey())); err != nil {
		return Verified{}, fail(ErrSignature, "%v", err)
	}
	s := newSignature(raw, archive, trusted)
	return Verified{BundleSHA256: s.BundleSHA256, MediaType: s.MediaType, Algorithm: s.Algorithm, KeyFingerprint: s.KeyFingerprint, ArchiveSHA256: s.ArchiveSHA256}, nil
}
