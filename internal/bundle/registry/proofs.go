package registry

import (
	"fmt"
	"slices"
	"strings"
)

// Proof artifacts are recognized in the layout written by the pinned Cosign
// publisher (v3.1.3, the default "new bundle format"): each `cosign sign` and
// `cosign attest` uploads one OCI 1.1 image manifest whose subject is the
// signed manifest, whose artifactType is the Sigstore bundle v0.3 media type,
// whose single layer is the Sigstore bundle JSON, and whose
// "dev.sigstore.bundle.predicateType" annotation names the in-toto predicate.
// See docs/policy-bundles.md for the exact layout.
const (
	// SigstoreBundleArtifactType is the referrer artifactType and the proof
	// layer media type.
	SigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	// PredicateTypeAnnotation is the referrer manifest annotation that names
	// the bundle's in-toto predicate type.
	PredicateTypeAnnotation = "dev.sigstore.bundle.predicateType"
	// CosignSignPredicateType marks a `cosign sign` signature bundle.
	CosignSignPredicateType = "https://sigstore.dev/cosign/sign/v1"
	// SLSAProvenanceV1PredicateType marks a `cosign attest --type
	// slsaprovenance1` SLSA provenance v1 attestation.
	SLSAProvenanceV1PredicateType = "https://slsa.dev/provenance/v1"
)

// ProofKind is a kind of verification artifact attached to the subject.
type ProofKind string

const (
	ProofSignature  ProofKind = "signature"
	ProofProvenance ProofKind = "provenance"
)

// RequiredProofs are the kinds bundle acceptance needs (design section 5).
var RequiredProofs = []ProofKind{ProofSignature, ProofProvenance}

var predicateKinds = map[string]ProofKind{
	CosignSignPredicateType:       ProofSignature,
	SLSAProvenanceV1PredicateType: ProofProvenance,
}

// Proof is one retrieved, digest-checked proof artifact. Retrieval does not
// verify it: the predicate type comes from an unauthenticated annotation, so
// the verifier must check the signed statement itself.
type Proof struct {
	Kind          ProofKind
	PredicateType string
	// ManifestDigest and Manifest are the referrer manifest.
	ManifestDigest string
	Manifest       []byte
	// BundleDigest and Bundle are its single Sigstore bundle layer.
	BundleMediaType string
	BundleDigest    string
	Bundle          []byte
}

// Skipped is a listed referrer that was not used, with the reason.
type Skipped struct {
	Digest       string
	ArtifactType string
	Reason       string
}

// Result is a retrieved subject and its proofs. Its byte slices may be shared
// between deduplicated callers and must not be modified.
type Result struct {
	// Repository and Digest identify what was requested.
	Repository string
	Digest     string
	// Manifest is the pinned manifest; its sha256 equals Digest.
	Manifest []byte
	// Layer is the bundle's tar+gzip layer; its sha256 equals LayerDigest.
	LayerDigest string
	Layer       []byte
	// Proofs are referrers recognized as signature or provenance proofs for
	// exactly this subject, in listing order.
	Proofs []Proof
	// Skipped referrers were listed but are not usable proofs.
	Skipped []Skipped
	// ReferrerCount is how many referrers the registry listed.
	ReferrerCount int
	// MetadataBytes is the verification metadata downloaded.
	MetadataBytes int64
}

// Found reports which proof kinds were retrieved.
func (r *Result) Found() map[ProofKind]int {
	found := map[ProofKind]int{}
	for _, p := range r.Proofs {
		found[p.Kind]++
	}
	return found
}

// Missing returns the required kinds with no retrieved proof, in order.
func (r *Result) Missing(required ...ProofKind) []ProofKind {
	found := r.Found()
	var missing []ProofKind
	for _, k := range required {
		if found[k] == 0 && !slices.Contains(missing, k) {
			missing = append(missing, k)
		}
	}
	return missing
}

// RequireProofs returns a *MissingProofsError when a required kind is
// missing. Presence is not trust: verification is a separate step.
func (r *Result) RequireProofs(required ...ProofKind) error {
	if missing := r.Missing(required...); len(missing) > 0 {
		return &MissingProofsError{Digest: r.Digest, Missing: missing, Skipped: len(r.Skipped)}
	}
	return nil
}

// MissingProofsError lists the required proof kinds that were not found.
type MissingProofsError struct {
	Digest  string
	Missing []ProofKind
	// Skipped counts listed referrers that were not usable proofs.
	Skipped int
}

func (e *MissingProofsError) Error() string {
	kinds := make([]string, len(e.Missing))
	for i, k := range e.Missing {
		kinds[i] = string(k)
	}
	return fmt.Sprintf("%s for %s: %s (%d unusable referrers skipped)",
		ErrMissingProofs, e.Digest, strings.Join(kinds, ", "), e.Skipped)
}

func (e *MissingProofsError) Is(target error) bool { return target == ErrMissingProofs }
