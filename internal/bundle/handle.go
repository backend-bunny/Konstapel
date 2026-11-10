package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// HandleVersion versions the serialized resolved-content handle and receipt.
// It is independent of targeting.ContractVersion: nothing here changes the
// enforcement revision algorithm.
const HandleVersion = 1

const (
	// PredicateSLSAProvenanceV1 is the only accepted provenance predicate.
	PredicateSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

	// Publisher rule kinds.
	SignerKeyless   = "keyless"
	SignerPublicKey = "public-key"

	// Lease holders: why a cache entry is pinned.
	HolderProfile    = "profile"    // a desired ComplianceProfile references it
	HolderApplied    = "applied"    // the last applied contribution uses it
	HolderAssessment = "assessment" // an active assessment snapshot needs it

	// Engine states, reported separately from content compatibility.
	EngineUnknown     = "unknown"
	EngineReady       = "ready"
	EngineUnavailable = "unavailable"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Digests keeps every identity of a bundle separate. They answer different
// questions and are never interchangeable:
//
//   - Revision is the source commit the content was built from.
//   - Content is the digest of the canonical file inventory: what the payload
//     says, independent of tar/gzip packaging.
//   - Archive is the deterministic layer digest.
//   - OCI is the manifest digest, the identity that is signed and the only one
//     the targeting contract uses (Contribution.BundleDigest).
//
// Rendered engine-policy hashes belong to each policy (PolicyInfo.Rendered),
// because the renderer, not the bundle, produces them.
type Digests struct {
	Revision string `json:"revision"`
	Content  string `json:"content"`
	Archive  string `json:"archive"`
	OCI      string `json:"oci"`
}

// PolicyInfo is the logical metadata of one bundled policy.
type PolicyInfo struct {
	Name   string  `json:"name"`
	Path   string  `json:"path"`
	Checks []Check `json:"checks"`
	// ParameterSchema is the validated parameter schema path, if any.
	ParameterSchema string `json:"parameterSchema,omitempty"`
	// Rendered is the hash of the rendered engine policy, recorded by the
	// renderer after resolution; empty until then.
	Rendered string `json:"rendered,omitempty"`
}

// ContentCompatibility is the verdict on the content alone.
type ContentCompatibility struct {
	Compatible bool     `json:"compatible"`
	Provider   string   `json:"provider"`
	Konstapel  string   `json:"konstapel"`
	OSCAL      []string `json:"oscal"`
	// Reasons explain an incompatible verdict; bounded and attributable.
	Reasons []string `json:"reasons,omitempty"`
}

// CompatibilityResult keeps content compatibility apart from live engine readiness:
// a bundle can be compatible while the engine is not ready yet, and engine
// readiness never implies the content was trusted.
type CompatibilityResult struct {
	Content ContentCompatibility `json:"content"`
	Engine  string               `json:"engine"`
}

// Signer identifies who authorized the subject under a configured rule.
type Signer struct {
	Kind string `json:"kind"`
	// Keyless: exact OIDC issuer and certificate identity.
	Issuer   string `json:"issuer,omitempty"`
	Identity string `json:"identity,omitempty"`
	// Public key: the referenced key's fingerprint.
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
}

// Provenance records the attested origin that was checked against the descriptor.
type Provenance struct {
	PredicateType string `json:"predicateType"`
	Repository    string `json:"repository"`
	Revision      string `json:"revision"`
	Builder       string `json:"builder"`
}

// Receipt records one successful verification of one subject. It is evidence
// that a check happened under named trust inputs, not a standing authorization:
// acceptance is re-evaluated against current configuration.
type Receipt struct {
	Version    int       `json:"version"`
	VerifiedAt time.Time `json:"verifiedAt"`
	// Subject is the exact verified manifest, with its release identity.
	Subject struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	} `json:"subject"`
	// RetrievedFrom is where the bytes came from. A hostname is a retrieval
	// location, not publisher identity, and a mirror changes only this field.
	RetrievedFrom string `json:"retrievedFrom"`
	// SourceRule and TrustRevision name the central configuration revisions
	// the verification ran under; a change invalidates the receipt.
	SourceRule    string `json:"sourceRule"`
	TrustRevision string `json:"trustRevision"`
	TrustRoot     string `json:"trustRoot"`
	Signer        Signer `json:"signer"`
	// Proofs are digests of the retained signature and attestation, so the
	// check can be repeated locally.
	Proofs struct {
		Signature   string `json:"signature"`
		Attestation string `json:"attestation"`
	} `json:"proofs"`
	Provenance Provenance `json:"provenance"`
}

// Lease is an explicit pin on a cache entry. Entries with a lease are never
// evicted; a lease is released by its holder when it finishes or advances.
type Lease struct {
	ID         string    `json:"id"`
	Holder     string    `json:"holder"`
	Owner      string    `json:"owner"`
	Digest     string    `json:"digest"`
	AcquiredAt time.Time `json:"acquiredAt"`
}

// ResolvedContent is the handle the resolver publishes and the assessment
// producer and renderer consume. It carries no registry credentials and no
// payload bytes.
type ResolvedContent struct {
	HandleVersion int          `json:"handleVersion"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Digests       Digests      `json:"digests"`
	Policies      []PolicyInfo `json:"policies"`
	// CheckedPaths are the payload files whose digests were verified.
	CheckedPaths  []string            `json:"checkedPaths"`
	Compatibility CompatibilityResult `json:"compatibility"`
	Receipt       Receipt             `json:"receipt"`
	Lease         Lease               `json:"lease"`
}

// BundleDigest is the value for targeting.Contribution.BundleDigest and
// EnforcementInput.BundleDigest: the OCI manifest digest and nothing else, so
// a mirror, credential rotation or lease change cannot create a new revision.
func (r ResolvedContent) BundleDigest() string { return r.Digests.OCI }

// Policy returns the named policy's metadata.
func (r ResolvedContent) Policy(name string) (PolicyInfo, bool) {
	for _, p := range r.Policies {
		if p.Name == name {
			return p, true
		}
	}
	return PolicyInfo{}, false
}

// ContentDigest hashes the canonical file inventory (sorted path, role, size
// and sha256), identifying what the payload says independent of how it was
// packaged.
func (d *Descriptor) ContentDigest() string {
	files := append([]File(nil), d.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	b, _ := json.Marshal(files)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewHandle builds the handle for a verified archive. The receipt and lease
// are supplied by the resolver; the compatibility verdict is the caller's
// result of ValidateContent and version checks.
func NewHandle(a *Archive, compat ContentCompatibility, receipt Receipt, lease Lease) ResolvedContent {
	d := a.Descriptor
	h := ResolvedContent{
		HandleVersion: HandleVersion, Name: d.Name, Version: d.Version,
		Digests:       Digests{Revision: d.Source.Revision, Content: d.ContentDigest(), Archive: a.LayerDigest, OCI: a.ManifestDigest},
		Compatibility: CompatibilityResult{Content: compat, Engine: EngineUnknown},
		Receipt:       receipt, Lease: lease,
	}
	for _, p := range d.Policies {
		h.Policies = append(h.Policies, PolicyInfo{Name: p.Name, Path: p.Path, Checks: p.Checks, ParameterSchema: p.ParameterSchema})
	}
	for _, f := range d.Files {
		h.CheckedPaths = append(h.CheckedPaths, f.Path)
	}
	sort.Strings(h.CheckedPaths)
	return h
}

// Validate checks a handle's internal consistency: well-formed digests, a
// receipt for exactly this subject, a lease on exactly this entry, and engine
// state kept apart from content compatibility.
func (r ResolvedContent) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if r.HandleVersion != HandleVersion {
		fail("handleVersion %d: want %d", r.HandleVersion, HandleVersion)
	}
	if !namePattern.MatchString(r.Name) {
		fail("name %q must be a DNS label", r.Name)
	}
	if !semverPattern.MatchString(r.Version) {
		fail("version %q must be SemVer", r.Version)
	}
	if !revisionPat.MatchString(r.Digests.Revision) {
		fail("digests.revision must be a full commit")
	}
	for name, v := range map[string]string{"content": r.Digests.Content, "archive": r.Digests.Archive, "oci": r.Digests.OCI} {
		if !digestPattern.MatchString(v) {
			fail("digests.%s %q must be sha256:<64 hex>", name, v)
		}
	}
	if r.Digests.Archive == r.Digests.OCI {
		fail("digests.archive and digests.oci must identify different objects")
	}
	if len(r.Policies) == 0 || len(r.CheckedPaths) == 0 {
		fail("policies and checkedPaths must not be empty")
	}
	for _, p := range r.Policies {
		if p.Rendered != "" && !digestPattern.MatchString(p.Rendered) {
			fail("policy %q: rendered %q must be sha256:<64 hex>", p.Name, p.Rendered)
		}
	}
	switch r.Compatibility.Engine {
	case EngineUnknown, EngineReady, EngineUnavailable:
	default:
		fail("compatibility.engine %q is not a known state", r.Compatibility.Engine)
	}
	if !r.Compatibility.Content.Compatible && len(r.Compatibility.Content.Reasons) == 0 {
		fail("an incompatible verdict must give reasons")
	}
	if err := r.Receipt.Validate(); err != nil {
		errs = append(errs, err)
	} else {
		s := r.Receipt.Subject
		if s.Digest != r.Digests.OCI || s.Name != r.Name || s.Version != r.Version {
			fail("receipt subject %s %s@%s is not this bundle %s@%s (%s)", s.Digest, s.Name, s.Version, r.Name, r.Version, r.Digests.OCI)
		}
		if r.Receipt.Provenance.Revision != r.Digests.Revision {
			fail("provenance revision %q differs from digests.revision %q", r.Receipt.Provenance.Revision, r.Digests.Revision)
		}
	}
	l := r.Lease
	if l.ID == "" || l.Owner == "" || l.AcquiredAt.IsZero() {
		fail("lease needs an id, owner and acquisition time")
	}
	switch l.Holder {
	case HolderProfile, HolderApplied, HolderAssessment:
	default:
		fail("lease holder %q is not a known holder", l.Holder)
	}
	if l.Digest != r.Digests.OCI {
		fail("lease pins %q, not this bundle's manifest %q", l.Digest, r.Digests.OCI)
	}
	return errors.Join(errs...)
}

// Validate checks a receipt's shape. It does not verify any signature; that is
// the verifier's job, and a receipt is only evidence it was done.
func (r Receipt) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if r.Version != HandleVersion {
		fail("receipt version %d: want %d", r.Version, HandleVersion)
	}
	if r.VerifiedAt.IsZero() {
		fail("receipt needs a verification time")
	}
	if !digestPattern.MatchString(r.Subject.Digest) {
		fail("receipt subject digest %q must be sha256:<64 hex>", r.Subject.Digest)
	}
	if r.RetrievedFrom == "" || r.SourceRule == "" || r.TrustRevision == "" || r.TrustRoot == "" {
		fail("receipt must name retrievedFrom, sourceRule, trustRevision and trustRoot")
	}
	switch r.Signer.Kind {
	case SignerKeyless:
		if r.Signer.Issuer == "" || r.Signer.Identity == "" || r.Signer.KeyFingerprint != "" {
			fail("a keyless signer needs exactly an issuer and identity")
		}
	case SignerPublicKey:
		if r.Signer.KeyFingerprint == "" || r.Signer.Issuer != "" || r.Signer.Identity != "" {
			fail("a public-key signer needs exactly a key fingerprint")
		}
	default:
		fail("signer kind %q is not %q or %q", r.Signer.Kind, SignerKeyless, SignerPublicKey)
	}
	if !digestPattern.MatchString(r.Proofs.Signature) || !digestPattern.MatchString(r.Proofs.Attestation) {
		fail("receipt must retain signature and attestation digests")
	}
	if r.Provenance.PredicateType != PredicateSLSAProvenanceV1 {
		fail("provenance predicate %q: only %q is accepted", r.Provenance.PredicateType, PredicateSLSAProvenanceV1)
	}
	if !strings.HasPrefix(r.Provenance.Repository, "https://") || !revisionPat.MatchString(r.Provenance.Revision) || r.Provenance.Builder == "" {
		fail("provenance needs an https repository, a full revision and a builder")
	}
	return errors.Join(errs...)
}

// ParseHandle strictly decodes a serialized handle (unknown fields, repeated
// keys and trailing data are rejected) and validates it.
func ParseHandle(data []byte) (*ResolvedContent, error) {
	if err := noDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var h ResolvedContent
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("decode handle: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode handle: unexpected data after the handle")
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}
