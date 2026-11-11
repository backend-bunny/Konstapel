// Package verify checks that Sigstore proofs attached to a pinned policy
// bundle were signed by the publisher a central source rule names, for
// exactly that bundle's OCI manifest digest. It verifies offline with
// sigstore-go: trust comes only from the rule and the objects it references
// (a public key, or a trusted root for keyless signing), never from the
// fetched artifact or proof. CheckProvenance applies the bundle provenance
// policy to the verified attestation, Accept combines both with the content
// checks into a receipt, and Recheck repeats them later under current trust.
// It is a library only; nothing in the controller calls it yet. See
// docs/policy-bundles.md, "Signature verification" and "Provenance
// verification".
package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Limits and tolerances.
const (
	// MaxBundleBytes bounds one Sigstore bundle. The registry adapter bounds
	// downloads too; parsing is bounded independently.
	MaxBundleBytes = 4 << 20
	// MaxClockSkew is how far an authenticated signing time may lie ahead of
	// the verifier's clock.
	MaxClockSkew = 5 * time.Minute
	// sigstoreBundleV03 is the only accepted bundle media type: what the
	// pinned Cosign (v3.1.3) writes.
	sigstoreBundleV03 = registry.SigstoreBundleArtifactType
)

// EvidenceKind names a kind of verified signing-time or transparency evidence.
type EvidenceKind string

const (
	// EvidenceTransparencyLog: an inclusion promise (SET) or proof for a
	// transparency log in the configured trusted root.
	EvidenceTransparencyLog EvidenceKind = "transparency-log"
	// EvidenceLogIntegratedTime: a log's signed integrated time (SET).
	EvidenceLogIntegratedTime EvidenceKind = "log-integrated-time"
	// EvidenceRFC3161: an RFC 3161 timestamp from an authority in the root.
	EvidenceRFC3161 EvidenceKind = "rfc3161-timestamp"
	// EvidenceCertificateTransparency: an embedded SCT from a CT log in the root.
	EvidenceCertificateTransparency EvidenceKind = "certificate-transparency"
)

// TimeEvidence is one authenticated signing time.
type TimeEvidence struct {
	Kind EvidenceKind
	Time time.Time
	// Authority is the log or timestamp authority URL named by the trusted
	// root (not by the proof).
	Authority string
}

// VerifiedProof is the redaction-safe outcome of verifying one proof. It holds
// public identifiers and digests only: no key material and no credentials.
type VerifiedProof struct {
	// Kind is the proof kind its signed predicate type establishes.
	Kind registry.ProofKind
	// Subject is the pinned manifest digest the statement names.
	Subject string
	// Signer is the verified publisher: keyless issuer and identity, or the
	// public key fingerprint.
	Signer bundle.Signer
	// TrustRootID is sha256:<hex> of the trusted root JSON used (keyless);
	// TrustRootSource names where it came from. Both are empty for a
	// public-key rule, whose trust anchor is Signer.KeyFingerprint.
	TrustRootID     string
	TrustRootSource string
	// SigningTime is the earliest authenticated signing time; the
	// certificate was valid at every time in Evidence. It is zero for a
	// public-key proof, whose bundle carries no evidence this verifier
	// authenticates.
	SigningTime time.Time
	Evidence    []TimeEvidence
	// EvidenceKinds lists the kinds of evidence that verified, sorted.
	EvidenceKinds []EvidenceKind
	VerifiedAt    time.Time
	// ProofManifestDigest and BundleDigest identify the referrer manifest
	// and its Sigstore bundle; StatementDigest is the sha256 of the signed
	// DSSE payload. They let a receipt retain and recheck the evidence.
	ProofManifestDigest string
	BundleDigest        string
	StatementDigest     string
	// Statement is the verified in-toto statement, including the raw
	// predicate, for later policy stages.
	Statement Statement
}

// Verifier verifies proofs against central publisher rules.
type Verifier struct {
	objects ObjectReader
	now     func() time.Time
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock replaces time.Now, for tests. The clock only stamps VerifiedAt and
// rejects signing times in the future; certificate validity is judged at the
// authenticated signing time, never at the clock's time.
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// New returns a Verifier reading keys and trusted roots through objects.
func New(objects ObjectReader, opts ...Option) (*Verifier, error) {
	if objects == nil {
		return nil, errNoReader
	}
	v := &Verifier{objects: objects, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// predicateTypes is the signed predicate type each required proof kind needs.
var predicateTypes = map[registry.ProofKind]string{
	registry.ProofSignature:  registry.CosignSignPredicateType,
	registry.ProofProvenance: registry.SLSAProvenanceV1PredicateType,
}

// Proofs is the verified signature and provenance attestation of one subject,
// both under the same publisher rule and the same trust snapshot.
type Proofs struct {
	Signature  *VerifiedProof
	Provenance *VerifiedProof
}

// VerifyProofs verifies the required signature and provenance proofs of a
// retrieved subject under src's publisher rule. Trust inputs are read once,
// so both proofs are judged against one snapshot of the rule and its objects:
// a signature and an attestation can never be accepted under different rules,
// keys or roots. Provenance content (builder, source, version) is not checked
// here; CheckProvenance (or Accept) reads Provenance.Statement.
func (v *Verifier) VerifyProofs(ctx context.Context, src bundle.BundleSource, res *registry.Result) (*Proofs, error) {
	t, err := v.loadTrust(ctx, src.Publisher)
	if err != nil {
		return nil, err
	}
	sig, err := v.verifyKind(t, res, registry.ProofSignature)
	if err != nil {
		return nil, err
	}
	prov, err := v.verifyKind(t, res, registry.ProofProvenance)
	if err != nil {
		return nil, err
	}
	return &Proofs{Signature: sig, Provenance: prov}, nil
}

// Verify verifies the proofs of one kind attached to res under src's
// publisher rule and returns the first that verifies, in listing order.
// Candidates are chosen by the retrieval's unauthenticated predicate-type
// hint; the signed statement decides. No candidate is ErrMissingProofs; only
// failing candidates is ErrNoValidProof joined with each failure.
func (v *Verifier) Verify(ctx context.Context, src bundle.BundleSource, res *registry.Result, kind registry.ProofKind) (*VerifiedProof, error) {
	t, err := v.loadTrust(ctx, src.Publisher)
	if err != nil {
		return nil, err
	}
	return v.verifyKind(t, res, kind)
}

// VerifyProof verifies one proof of the given kind for the pinned subject.
func (v *Verifier) VerifyProof(ctx context.Context, src bundle.BundleSource, subject string, kind registry.ProofKind, p registry.Proof) (*VerifiedProof, error) {
	t, err := v.loadTrust(ctx, src.Publisher)
	if err != nil {
		return nil, err
	}
	return v.verifyOne(t, subject, kind, p)
}

func (v *Verifier) verifyKind(t *trust, res *registry.Result, kind registry.ProofKind) (*VerifiedProof, error) {
	if res == nil {
		return nil, fail(ErrMalformedProof, "no retrieval result")
	}
	var errs []error
	for _, p := range res.Proofs {
		if p.Kind != kind {
			continue
		}
		vp, err := v.verifyOne(t, res.Digest, kind, p)
		if err == nil {
			return vp, nil
		}
		errs = append(errs, fmt.Errorf("proof %s: %w", p.ManifestDigest, err))
	}
	if len(errs) == 0 {
		return nil, &registry.MissingProofsError{Digest: res.Digest, Missing: []registry.ProofKind{kind}, Skipped: len(res.Skipped)}
	}
	return nil, fmt.Errorf("%w (%s for %s): %w", ErrNoValidProof, kind, res.Digest, errors.Join(errs...))
}

func (v *Verifier) verifyOne(t *trust, subject string, kind registry.ProofKind, p registry.Proof) (*VerifiedProof, error) {
	wantType, ok := predicateTypes[kind]
	if !ok {
		return nil, fmt.Errorf("verify: unknown proof kind %q", kind)
	}
	if !hexDigest.MatchString(strings.TrimPrefix(subject, "sha256:")) || !strings.HasPrefix(subject, "sha256:") {
		return nil, fail(ErrSubject, "pinned subject %q is not a sha256 digest", subject)
	}
	b, bundleDigest, err := parseBundle(p)
	if err != nil {
		return nil, err
	}
	env := b.GetDsseEnvelope()
	if env.GetPayloadType() != inTotoPayloadType {
		return nil, fail(ErrStatement, "DSSE payload type %q is not %s", env.GetPayloadType(), inTotoPayloadType)
	}
	digestBytes, _ := hex.DecodeString(strings.TrimPrefix(subject, "sha256:"))

	var (
		verifier *sgverify.Verifier
		identity sgverify.PolicyOption
		signer   bundle.Signer
		leaf     *x509.Certificate
	)
	switch t.publisher.Type {
	case bundle.SignerPublicKey:
		if b.GetVerificationMaterial().GetPublicKey() == nil {
			return nil, fail(ErrSigner, "the rule fixes a public key, but the proof is not signed with a key")
		}
		if verifier, err = sgverify.NewVerifier(t.keyMaterial, sgverify.WithNoObserverTimestamps()); err != nil {
			return nil, fmt.Errorf("verify: %w", err)
		}
		identity = sgverify.WithKey()
		signer = bundle.Signer{Kind: bundle.SignerPublicKey, KeyFingerprint: t.fingerprint}
	case bundle.SignerKeyless:
		if leaf, err = keylessLeaf(b); err != nil {
			return nil, err
		}
		if err := checkIdentity(leaf, t.publisher); err != nil {
			return nil, err
		}
		opts := []sgverify.VerifierOption{sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1)}
		if t.requireSCT {
			opts = append(opts, sgverify.WithSignedCertificateTimestamps(1))
		}
		if verifier, err = sgverify.NewVerifier(t.root, opts...); err != nil {
			return nil, fmt.Errorf("verify: %w", err)
		}
		id, err := sgverify.NewShortCertificateIdentity(t.publisher.Issuer, "", t.publisher.Identity, "")
		if err != nil {
			return nil, fail(ErrTrustConfig, "keyless identity: %v", err)
		}
		identity = sgverify.WithCertificateIdentity(id)
		signer = bundle.Signer{Kind: bundle.SignerKeyless, Issuer: t.publisher.Issuer, Identity: t.publisher.Identity}
	}

	var times []TimeEvidence
	if leaf != nil {
		if times, err = v.signingTimes(verifier, b, leaf, t); err != nil {
			return nil, err
		}
	}

	// Signature and signer, before the statement is trusted at all. The
	// artifact binding is checked separately below so a failure is reported
	// precisely; the final call enforces everything together.
	if _, err := verifier.Verify(b, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), identity)); err != nil {
		return nil, classifySigstore(err)
	}
	payload := env.GetPayload()
	st, err := parseStatement(payload)
	if err != nil {
		return nil, err
	}
	if err := st.checkBinding(subject, wantType); err != nil {
		return nil, err
	}
	// Authoritative: signature, signer, evidence and the statement subject
	// digest, all checked by sigstore-go in one call.
	result, err := verifier.Verify(b, sgverify.NewPolicy(sgverify.WithArtifactDigest("sha256", digestBytes), identity))
	if err != nil {
		return nil, fail(ErrSubject, "%v", err)
	}
	if leaf != nil && len(result.VerifiedTimestamps) != len(times) {
		return nil, fail(ErrSigningTime, "verified timestamps changed between checks")
	}

	stSum := sha256.Sum256(payload)
	vp := &VerifiedProof{
		Kind:                kind,
		Subject:             subject,
		Signer:              signer,
		VerifiedAt:          v.now().UTC(),
		ProofManifestDigest: p.ManifestDigest,
		BundleDigest:        bundleDigest,
		StatementDigest:     "sha256:" + hex.EncodeToString(stSum[:]),
		Statement:           *st,
	}
	if leaf != nil {
		vp.TrustRootID, vp.TrustRootSource = t.rootID, t.rootSource
		vp.Evidence = times
		kinds := map[EvidenceKind]bool{EvidenceTransparencyLog: true}
		if t.requireSCT {
			kinds[EvidenceCertificateTransparency] = true
		}
		for _, e := range times {
			kinds[e.Kind] = true
			if vp.SigningTime.IsZero() || e.Time.Before(vp.SigningTime) {
				vp.SigningTime = e.Time
			}
		}
		for k := range kinds {
			vp.EvidenceKinds = append(vp.EvidenceKinds, k)
		}
		slices.Sort(vp.EvidenceKinds)
	}
	return vp, nil
}

// parseBundle bounds, strictly parses and structurally checks one proof.
func parseBundle(p registry.Proof) (*sgbundle.Bundle, string, error) {
	switch {
	case len(p.Bundle) == 0:
		return nil, "", fail(ErrMalformedProof, "empty proof")
	case len(p.Bundle) > MaxBundleBytes:
		return nil, "", fail(ErrProofTooLarge, "proof is %d bytes, the limit is %d", len(p.Bundle), MaxBundleBytes)
	case p.BundleMediaType != "" && p.BundleMediaType != sigstoreBundleV03:
		return nil, "", fail(ErrMalformedProof, "proof layer media type %q", p.BundleMediaType)
	}
	sum := sha256.Sum256(p.Bundle)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if p.BundleDigest != "" && p.BundleDigest != digest {
		return nil, "", fail(ErrMalformedProof, "proof bytes do not match their digest %s", p.BundleDigest)
	}
	if err := checkJSON(p.Bundle); err != nil {
		return nil, "", fail(ErrMalformedProof, "%v", err)
	}
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(p.Bundle); err != nil {
		return nil, "", fail(ErrMalformedProof, "%v", err)
	}
	if b.GetMediaType() != sigstoreBundleV03 {
		return nil, "", fail(ErrMalformedProof, "bundle media type %q; only %s is accepted", b.GetMediaType(), sigstoreBundleV03)
	}
	env := b.GetDsseEnvelope()
	if env == nil {
		return nil, "", fail(ErrMalformedProof, "proof is not a DSSE envelope; a signed in-toto statement is required")
	}
	if len(env.GetSignatures()) != 1 {
		return nil, "", fail(ErrMalformedProof, "DSSE envelope must carry exactly one signature, has %d", len(env.GetSignatures()))
	}
	return &b, digest, nil
}

// keylessLeaf returns the proof's single signing certificate, refusing a key
// or a certificate chain (which would let the proof supply intermediates).
func keylessLeaf(b *sgbundle.Bundle) (*x509.Certificate, error) {
	vm := b.GetVerificationMaterial()
	if vm.GetPublicKey() != nil {
		return nil, fail(ErrSigner, "the rule requires a keyless certificate, but the proof is signed with a key")
	}
	raw := vm.GetCertificate().GetRawBytes()
	if raw == nil {
		return nil, fail(ErrMalformedProof, "keyless proof has no single signing certificate")
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fail(ErrMalformedProof, "signing certificate does not parse")
	}
	switch k := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, fail(ErrAlgorithm, "ECDSA curve %s", k.Curve.Params().Name)
		}
	default:
		return nil, fail(ErrAlgorithm, "signing certificate key %T; only ECDSA P-256 and P-384 are accepted", leaf.PublicKey)
	}
	return leaf, nil
}

// checkIdentity requires the certificate to carry exactly one subject
// alternative name, equal to the rule's identity, and the rule's exact OIDC
// issuer. sigstore-go repeats the comparison, but only reads the first SAN.
func checkIdentity(leaf *x509.Certificate, p bundle.Publisher) error {
	var sans []string
	for _, u := range leaf.URIs {
		sans = append(sans, u.String())
	}
	sans = append(sans, leaf.EmailAddresses...)
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) != 1 {
		return fail(ErrSigner, "signing certificate carries %d subject alternative names; exactly one is required", len(sans))
	}
	if sans[0] != p.Identity {
		return fail(ErrSigner, "certificate identity %q is not the configured %q", sans[0], p.Identity)
	}
	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return fail(ErrMalformedProof, "signing certificate: %v", err)
	}
	if summary.Issuer != p.Issuer {
		return fail(ErrSigner, "certificate OIDC issuer %q is not the configured %q", summary.Issuer, p.Issuer)
	}
	return nil
}

// signingTimes establishes the authenticated signing times of a keyless proof
// under the configured root: transparency log inclusion (required), then the
// observer timestamps (log integrated times with a verified SET, and RFC 3161
// timestamps from authorities in the root; at least one is required). The
// certificate must be valid, and chain to the root, at every one of them, and
// none may lie in the future. The present time plays no part: a certificate
// that has expired since a valid signing event still verifies.
func (v *Verifier) signingTimes(verifier *sgverify.Verifier, b *sgbundle.Bundle, leaf *x509.Certificate, t *trust) ([]TimeEvidence, error) {
	logTimes, err := verifier.VerifyTransparencyLogInclusion(b)
	if err != nil {
		// sigstore-go reports a log's integrated time outside the
		// certificate's validity from this step.
		if strings.Contains(err.Error(), "integrated time outside certificate validity") {
			return nil, fail(ErrSigningTime, "%v", err)
		}
		return nil, fail(ErrTransparency, "%v", err)
	}
	observed, err := verifier.VerifyObserverTimestamps(b, logTimes)
	if err != nil {
		return nil, fail(ErrSigningTime, "%v", err)
	}
	now := v.now()
	var out []TimeEvidence
	for _, ts := range observed {
		var kind EvidenceKind
		switch ts.Type {
		case "Tlog":
			kind = EvidenceLogIntegratedTime
		case "TimestampAuthority":
			kind = EvidenceRFC3161
		default:
			return nil, fail(ErrSigningTime, "unexpected timestamp source %q", ts.Type)
		}
		switch {
		case ts.Timestamp.Before(leaf.NotBefore) || ts.Timestamp.After(leaf.NotAfter):
			return nil, fail(ErrSigningTime, "certificate valid %s to %s was not valid at the authenticated signing time %s (%s)",
				leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), ts.Timestamp.UTC().Format(time.RFC3339), kind)
		case ts.Timestamp.After(now.Add(MaxClockSkew)):
			return nil, fail(ErrSigningTime, "authenticated signing time %s is in the future", ts.Timestamp.UTC().Format(time.RFC3339))
		}
		if _, err := sgverify.VerifyLeafCertificate(ts.Timestamp, leaf, t.root); err != nil {
			return nil, fail(ErrSignature, "signing certificate does not chain to the configured trusted root at %s", ts.Timestamp.UTC().Format(time.RFC3339))
		}
		out = append(out, TimeEvidence{Kind: kind, Time: ts.Timestamp.UTC(), Authority: ts.URI})
	}
	if len(out) == 0 {
		return nil, fail(ErrSigningTime, "no authenticated signing time")
	}
	return out, nil
}

// classifySigstore maps a sigstore-go verification failure that survived the
// earlier, more specific checks.
func classifySigstore(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "failed to fetch envelope statement"):
		// The signature verified; its payload is not a statement sigstore-go
		// can parse (protojson: unknown or duplicate fields, not JSON).
		return fail(ErrStatement, "%v", err)
	case strings.Contains(msg, "failed to verify certificate identity"),
		strings.Contains(msg, "expected key signature, not certificate"),
		strings.Contains(msg, "entity was not signed with a certificate"):
		return fail(ErrSigner, "%v", err)
	case strings.Contains(msg, "failed to verify log inclusion"):
		return fail(ErrTransparency, "%v", err)
	case strings.Contains(msg, "failed to verify timestamps"):
		return fail(ErrSigningTime, "%v", err)
	}
	return fail(ErrSignature, "%v", err)
}
