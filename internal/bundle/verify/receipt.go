package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Recheck material bounds. The total equals the registry adapter's default
// verification-metadata budget (registry.DefaultLimits().MaxMetadataBytes):
// two Sigstore bundles at MaxBundleBytes, base64-encoded, plus three small
// manifests and the receipt fit within it.
const (
	// RecheckVersion is the only accepted RecheckBundle version.
	RecheckVersion = 1
	// MaxRecheckBytes bounds one serialized RecheckBundle.
	MaxRecheckBytes = 16 << 20
	// MaxRetainedManifestBytes bounds the retained subject manifest and each
	// retained referrer manifest. Bundle and Cosign referrer manifests are
	// well under 2 KiB.
	MaxRetainedManifestBytes = 64 << 10
)

// RecheckBundle is the persisted outcome of one verification: the receipt
// and the evidence needed to verify it again offline, later, under the
// trust configuration current at that time. The receipt is data to compare
// against, never authority: Recheck verifies the retained evidence from
// scratch and only then compares. It holds no credentials and no payload
// bytes; the bundle layer is cached separately by digest.
type RecheckBundle struct {
	Version int            `json:"version"`
	Receipt bundle.Receipt `json:"receipt"`
	// SubjectManifest is the pinned OCI manifest; its sha256 is the subject
	// and it names the bundle layer.
	SubjectManifest []byte `json:"subjectManifest"`
	// Signature and Attestation are the verified proofs, exactly as
	// retrieved: the referrer manifest and its Sigstore bundle layer, which
	// contains the signed statement.
	Signature   RetainedProof `json:"signature"`
	Attestation RetainedProof `json:"attestation"`
}

// RetainedProof is one proof's referrer manifest and Sigstore bundle bytes.
type RetainedProof struct {
	Manifest []byte `json:"manifest"`
	Bundle   []byte `json:"bundle"`
}

// Accepted is a subject whose signature and provenance verified and whose
// provenance satisfied the policy, with its receipt and recheck material.
type Accepted struct {
	Descriptor *bundle.Descriptor
	Proofs     *Proofs
	Provenance *VerifiedProvenance
	Receipt    bundle.Receipt
	Recheck    *RecheckBundle
}

// Accept verifies a retrieved subject end to end under src: the required
// signature and provenance under the publisher rule (VerifyProofs), the
// layer against the pinned manifest, the payload against its inventory, and
// the provenance policy (CheckProvenance). It returns the receipt and the
// bounded material to recheck it. Nothing is cached or persisted here.
func (v *Verifier) Accept(ctx context.Context, src bundle.BundleSource, res *registry.Result) (*Accepted, error) {
	if res == nil {
		return nil, fail(ErrMalformedProof, "no retrieval result")
	}
	proofs, err := v.VerifyProofs(ctx, src, res)
	if err != nil {
		return nil, err
	}
	d, err := subjectContent(res.Digest, res.Manifest, res.Layer)
	if err != nil {
		return nil, err
	}
	vp, err := CheckProvenance(src, d, res.Digest, proofs)
	if err != nil {
		return nil, err
	}
	rc, err := newReceipt(src, res.Repository, d, proofs, vp)
	if err != nil {
		return nil, err
	}
	rb := &RecheckBundle{Version: RecheckVersion, Receipt: rc, SubjectManifest: res.Manifest}
	if rb.Signature, err = retain(res, proofs.Signature); err != nil {
		return nil, err
	}
	if rb.Attestation, err = retain(res, proofs.Provenance); err != nil {
		return nil, err
	}
	if err := rb.Check(); err != nil {
		return nil, err
	}
	return &Accepted{Descriptor: d, Proofs: proofs, Provenance: vp, Receipt: rc, Recheck: rb}, nil
}

// subjectContent binds the layer to the pinned manifest and returns the
// descriptor of a payload that matches its own inventory.
func subjectContent(digest string, manifest, layer []byte) (*bundle.Descriptor, error) {
	if sha256Digest(manifest) != digest {
		return nil, fail(ErrContent, "manifest bytes do not hash to the pinned %s", digest)
	}
	layerDigest, size, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, fail(ErrContent, "manifest: %v", err)
	}
	if int64(len(layer)) != size || sha256Digest(layer) != layerDigest {
		return nil, fail(ErrContent, "layer is not the %s the manifest names", layerDigest)
	}
	d, payload, err := bundle.Unpack(layer)
	if err != nil {
		return nil, fail(ErrContent, "%v", err)
	}
	if err := d.VerifyPayload(payload); err != nil {
		return nil, fail(ErrContent, "%v", err)
	}
	return d, nil
}

func retain(res *registry.Result, vp *VerifiedProof) (RetainedProof, error) {
	for _, p := range res.Proofs {
		if p.ManifestDigest == vp.ProofManifestDigest && sha256Digest(p.Bundle) == vp.BundleDigest {
			if len(p.Manifest) == 0 {
				return RetainedProof{}, fail(ErrRecheckBundle, "%s proof %s has no referrer manifest to retain", vp.Kind, p.ManifestDigest)
			}
			return RetainedProof{Manifest: p.Manifest, Bundle: p.Bundle}, nil
		}
	}
	return RetainedProof{}, fail(ErrRecheckBundle, "verified %s proof %s is not in the retrieval result", vp.Kind, vp.ProofManifestDigest)
}

// RuleRevision is the revision of the central configuration a verification
// depends on: the SHA-256 of the canonical JSON encoding of the source name
// and its publisher rule (type, issuer, identity, trusted-root and public-key
// references with their default data keys filled in, the fingerprint with its
// sha256: prefix, and the provenance source repository and builder), in a
// fixed field order under a versioned domain string. The repository (a
// retrieval location: a mirror changes only that), credentials and CA
// references (transport only) are deliberately excluded. The revision of the
// trust inputs the references point to is the receipt's TrustRevision.
func RuleRevision(src bundle.BundleSource) (string, error) {
	p := src.Publisher
	if err := p.Validate(); err != nil {
		return "", fail(ErrTrustConfig, "publisher rule: %v", err)
	}
	ref := func(r *bundle.ObjectRef, def string) string {
		if r == nil {
			return ""
		}
		return refString(r, def)
	}
	fp := ""
	if p.KeyFingerprint != "" {
		fp = "sha256:" + strings.TrimPrefix(p.KeyFingerprint, "sha256:")
	}
	canonical, err := json.Marshal(struct {
		Domain           string `json:"domain"`
		Name             string `json:"name"`
		Type             string `json:"type"`
		Issuer           string `json:"issuer"`
		Identity         string `json:"identity"`
		TrustRoot        string `json:"trustRoot"`
		PublicKey        string `json:"publicKey"`
		KeyFingerprint   string `json:"keyFingerprint"`
		SourceRepository string `json:"sourceRepository"`
		Builder          string `json:"builder"`
	}{
		Domain: "konstapel.bundle.source-rule/v1", Name: src.Name, Type: p.Type,
		Issuer: p.Issuer, Identity: p.Identity,
		TrustRoot: ref(p.TrustRoot, bundle.DefaultTrustRootKey), PublicKey: ref(p.PublicKey, bundle.DefaultPublicKey),
		KeyFingerprint: fp, SourceRepository: p.Provenance.SourceRepository, Builder: p.Provenance.Builder,
	})
	if err != nil {
		return "", err
	}
	return sha256Digest(canonical), nil
}

func newReceipt(src bundle.BundleSource, retrievedFrom string, d *bundle.Descriptor, proofs *Proofs, vp *VerifiedProvenance) (bundle.Receipt, error) {
	rule, err := RuleRevision(src)
	if err != nil {
		return bundle.Receipt{}, err
	}
	sig, prov := proofs.Signature, proofs.Provenance
	var r bundle.Receipt
	r.Version = bundle.HandleVersion
	r.VerifiedAt = sig.VerifiedAt.UTC()
	r.Subject.Name, r.Subject.Version, r.Subject.Digest = d.Name, d.Version, vp.Subject
	r.RetrievedFrom = retrievedFrom
	r.SourceRule = rule
	switch sig.Signer.Kind {
	case bundle.SignerKeyless:
		r.TrustRevision, r.TrustRoot = sig.TrustRootID, sig.TrustRootSource
	case bundle.SignerPublicKey:
		r.TrustRevision, r.TrustRoot = sig.Signer.KeyFingerprint, refString(src.Publisher.PublicKey, bundle.DefaultPublicKey)
	}
	r.Signer = sig.Signer
	r.Proofs.Signature = bundle.ProofDigests{Manifest: sig.ProofManifestDigest, Bundle: sig.BundleDigest, Statement: sig.StatementDigest}
	r.Proofs.Attestation = bundle.ProofDigests{Manifest: prov.ProofManifestDigest, Bundle: prov.BundleDigest, Statement: prov.StatementDigest}
	r.Provenance = bundle.Provenance{
		PredicateType: prov.Statement.PredicateType, BuildType: vp.BuildType,
		Repository: vp.SourceRepository, Revision: vp.SourceRevision, Builder: vp.Builder, Content: vp.ContentDigest,
		Workflow:        bundle.WorkflowRef{Repository: vp.Workflow.Repository, Path: vp.Workflow.Path, Ref: vp.Workflow.Ref, Commit: vp.Workflow.Commit},
		BuilderRevision: vp.BuilderRevision,
	}
	if err := r.Validate(); err != nil {
		return bundle.Receipt{}, fmt.Errorf("verify: receipt: %w", err)
	}
	return r, nil
}

// Check validates the bundle's shape and integrity: the version, the
// receipt's shape, the bounds, and that every retained byte hashes to the
// digest the receipt names (subject manifest, referrer manifests, Sigstore
// bundles, signed statements) and that each referrer names the subject and
// its bundle. It verifies no signature: that is Recheck's job.
func (rb *RecheckBundle) Check() error {
	if rb == nil {
		return fail(ErrRecheckBundle, "no recheck material")
	}
	if rb.Version != RecheckVersion {
		return fail(ErrRecheckBundle, "version %d: want %d", rb.Version, RecheckVersion)
	}
	if err := rb.Receipt.Validate(); err != nil {
		return fail(ErrRecheckBundle, "receipt: %v", err)
	}
	rc := rb.Receipt
	switch {
	case len(rb.SubjectManifest) == 0 || len(rb.SubjectManifest) > MaxRetainedManifestBytes:
		return fail(ErrRecheckBundle, "subject manifest must be 1 to %d bytes", MaxRetainedManifestBytes)
	case sha256Digest(rb.SubjectManifest) != rc.Subject.Digest:
		return fail(ErrRecheckBundle, "retained subject manifest does not hash to the receipt's subject %s", rc.Subject.Digest)
	}
	if _, _, err := bundle.ValidateManifest(rb.SubjectManifest); err != nil {
		return fail(ErrRecheckBundle, "subject manifest: %v", err)
	}
	for _, c := range []struct {
		name string
		p    RetainedProof
		want bundle.ProofDigests
	}{{"signature", rb.Signature, rc.Proofs.Signature}, {"attestation", rb.Attestation, rc.Proofs.Attestation}} {
		if err := checkRetained(c.name, c.p, c.want, rc.Subject.Digest); err != nil {
			return err
		}
	}
	return nil
}

func checkRetained(name string, p RetainedProof, want bundle.ProofDigests, subject string) error {
	switch {
	case len(p.Manifest) == 0 || len(p.Manifest) > MaxRetainedManifestBytes:
		return fail(ErrRecheckBundle, "%s manifest must be 1 to %d bytes", name, MaxRetainedManifestBytes)
	case len(p.Bundle) == 0 || len(p.Bundle) > MaxBundleBytes:
		return fail(ErrRecheckBundle, "%s bundle must be 1 to %d bytes", name, MaxBundleBytes)
	case sha256Digest(p.Manifest) != want.Manifest:
		return fail(ErrRecheckBundle, "retained %s manifest does not hash to %s", name, want.Manifest)
	case sha256Digest(p.Bundle) != want.Bundle:
		return fail(ErrRecheckBundle, "retained %s bundle does not hash to %s", name, want.Bundle)
	}
	if err := checkJSON(p.Manifest); err != nil {
		return fail(ErrRecheckBundle, "%s manifest: %v", name, err)
	}
	var m struct {
		ArtifactType string `json:"artifactType"`
		Layers       []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
		Subject *struct {
			Digest string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(p.Manifest, &m); err != nil {
		return fail(ErrRecheckBundle, "%s manifest: %v", name, err)
	}
	switch {
	case m.ArtifactType != registry.SigstoreBundleArtifactType:
		return fail(ErrRecheckBundle, "%s manifest artifact type %q", name, m.ArtifactType)
	case m.Subject == nil || m.Subject.Digest != subject:
		return fail(ErrRecheckBundle, "%s manifest does not name the subject %s", name, subject)
	case len(m.Layers) != 1 || m.Layers[0].MediaType != registry.SigstoreBundleArtifactType ||
		m.Layers[0].Digest != want.Bundle || m.Layers[0].Size != int64(len(p.Bundle)):
		return fail(ErrRecheckBundle, "%s manifest does not name exactly its retained bundle", name)
	}
	b, _, err := parseBundle(registry.Proof{Bundle: p.Bundle, BundleDigest: want.Bundle})
	if err != nil {
		return fail(ErrRecheckBundle, "%s bundle: %v", name, err)
	}
	if sha256Digest(b.GetDsseEnvelope().GetPayload()) != want.Statement {
		return fail(ErrRecheckBundle, "retained %s statement does not hash to %s", name, want.Statement)
	}
	return nil
}

// Encode returns the deterministic serialization of a checked bundle.
func (rb *RecheckBundle) Encode() ([]byte, error) {
	if err := rb.Check(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rb)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxRecheckBytes {
		return nil, fail(ErrRecheckBundle, "serialized recheck material is %d bytes, the limit is %d", len(raw), MaxRecheckBytes)
	}
	return raw, nil
}

// DecodeRecheckBundle parses persisted recheck material strictly: bounded,
// valid UTF-8 JSON without duplicate keys, no unknown fields, no trailing
// data, a supported version, byte-for-byte the deterministic encoding (which
// also refuses case-variant keys and reordered or re-spaced input), and
// intact digests. It does not verify any signature.
func DecodeRecheckBundle(data []byte) (*RecheckBundle, error) {
	if len(data) > MaxRecheckBytes {
		return nil, fail(ErrRecheckBundle, "recheck material exceeds %d bytes", MaxRecheckBytes)
	}
	if err := checkJSON(data); err != nil {
		return nil, fail(ErrRecheckBundle, "%v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rb RecheckBundle
	if err := dec.Decode(&rb); err != nil {
		return nil, fail(ErrRecheckBundle, "%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(ErrRecheckBundle, "unexpected data after the recheck material")
	}
	if rb.Version != RecheckVersion {
		return nil, fail(ErrRecheckBundle, "version %d: want %d", rb.Version, RecheckVersion)
	}
	again, err := json.Marshal(&rb)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, data) {
		return nil, fail(ErrRecheckBundle, "recheck material is not in its canonical encoding")
	}
	if err := rb.Check(); err != nil {
		return nil, err
	}
	return &rb, nil
}

// RecheckOutcome is the verdict of rechecking retained evidence.
type RecheckOutcome string

const (
	// RecheckValid: the evidence verifies under current trust and yields
	// exactly the receipt's claims.
	RecheckValid RecheckOutcome = "valid"
	// RecheckChanged: the evidence verifies under current trust, but the
	// claims differ from the receipt (Differences); use Current, not the
	// old receipt.
	RecheckChanged RecheckOutcome = "changed"
	// RecheckInvalid: the evidence does not satisfy current trust (Reason).
	RecheckInvalid RecheckOutcome = "invalid"
)

// RecheckResult is the outcome of Recheck.
type RecheckResult struct {
	Outcome RecheckOutcome
	// Reason is why the evidence is invalid under current trust.
	Reason error
	// Differences names the receipt fields whose recomputed value differs.
	Differences []string
	// Current is the acceptance recomputed under current trust, with a fresh
	// receipt and recheck material; nil when invalid.
	Current *Accepted
}

// Recheck verifies retained evidence again, offline, under the CURRENT
// source rule and the trust objects it references now. The receipt in rb is
// never trusted: the subject digest comes from the retained manifest bytes,
// signer, trust and provenance claims are recomputed by Accept from the
// retained proofs and the cached layer, and only afterwards compared with the
// receipt. layer is the cached bundle layer, which must be the one the
// retained manifest names.
//
// A trust input that cannot be read or is invalid (ErrTrustConfig), recheck
// material that is malformed or fails its digests (ErrRecheckBundle), and a
// layer that is not the subject's (ErrContent) are errors: nothing can be
// concluded. Evidence that does not satisfy the current rule is
// RecheckInvalid. The verifier's injected clock stamps the new receipt; the
// receipt's own time plays no part, and leaf validity is judged at the
// authenticated signing times in the evidence.
func (v *Verifier) Recheck(ctx context.Context, src bundle.BundleSource, rb *RecheckBundle, layer []byte) (*RecheckResult, error) {
	if err := rb.Check(); err != nil {
		return nil, err
	}
	digest := sha256Digest(rb.SubjectManifest)
	layerDigest, _, err := bundle.ValidateManifest(rb.SubjectManifest)
	if err != nil {
		return nil, fail(ErrRecheckBundle, "subject manifest: %v", err)
	}
	if sha256Digest(layer) != layerDigest {
		return nil, fail(ErrContent, "the supplied layer is not the %s the subject names", layerDigest)
	}
	res := &registry.Result{
		Repository: rb.Receipt.RetrievedFrom, Digest: digest, Manifest: rb.SubjectManifest,
		LayerDigest: layerDigest, Layer: layer,
		Proofs: []registry.Proof{
			retainedProof(registry.ProofSignature, rb.Signature),
			retainedProof(registry.ProofProvenance, rb.Attestation),
		},
	}
	acc, err := v.Accept(ctx, src, res)
	switch {
	case errors.Is(err, ErrTrustConfig), errors.Is(err, ErrContent), errors.Is(err, ErrRecheckBundle):
		return nil, err
	case err != nil:
		return &RecheckResult{Outcome: RecheckInvalid, Reason: err}, nil
	}
	diffs := receiptDiff(rb.Receipt, acc.Receipt)
	if len(diffs) > 0 {
		return &RecheckResult{Outcome: RecheckChanged, Differences: diffs, Current: acc}, nil
	}
	return &RecheckResult{Outcome: RecheckValid, Current: acc}, nil
}

// RecheckSource selects the current source for name and rechecks under it. A
// name that is no longer configured is RecheckInvalid, not an error: the
// administrator removed its trust.
func (v *Verifier) RecheckSource(ctx context.Context, sources bundle.Sources, name string, rb *RecheckBundle, layer []byte) (*RecheckResult, error) {
	src, err := sources.Select(name)
	if errors.Is(err, bundle.ErrUnconfigured) {
		return &RecheckResult{Outcome: RecheckInvalid, Reason: err}, nil
	}
	if err != nil {
		return nil, err
	}
	return v.Recheck(ctx, src, rb, layer)
}

func retainedProof(kind registry.ProofKind, p RetainedProof) registry.Proof {
	return registry.Proof{
		Kind: kind, PredicateType: predicateTypes[kind],
		ManifestDigest: sha256Digest(p.Manifest), Manifest: p.Manifest,
		BundleMediaType: registry.SigstoreBundleArtifactType, BundleDigest: sha256Digest(p.Bundle), Bundle: p.Bundle,
	}
}

// receiptDiff names the fields in which two receipts disagree, ignoring the
// verification time and the retrieval location.
func receiptDiff(old, cur bundle.Receipt) []string {
	var out []string
	add := func(name string, differs bool) {
		if differs {
			out = append(out, name)
		}
	}
	add("version", old.Version != cur.Version)
	add("subject", old.Subject != cur.Subject)
	add("sourceRule", old.SourceRule != cur.SourceRule)
	add("trustRevision", old.TrustRevision != cur.TrustRevision)
	add("trustRoot", old.TrustRoot != cur.TrustRoot)
	add("signer", old.Signer != cur.Signer)
	add("proofs", old.Proofs != cur.Proofs)
	add("provenance", old.Provenance != cur.Provenance)
	return out
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
