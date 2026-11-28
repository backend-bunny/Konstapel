package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Cosign v3's `cosign verify` accepts a publisher's attestations as
// signatures: a subject carrying only a `cosign attest` provenance from the
// trusted key passes it (pinned in the registry compatibility suite,
// internal/bundle/registry/sign_compat_test.go). The bundle signature
// requirement is stricter: only a statement whose signed predicate type is
// https://sigstore.dev/cosign/sign/v1, for exactly the pinned digest, is the
// signature. These are regression guards; the verifier has required it since
// it was written.
func TestAttestationOnlyIsNotASignature(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	v := newVerifier(t, f.reader(), clockAt(t0))
	src := f.orgSource()
	// The control: the real Cosign signature and attestation of the trusted
	// key, as acceptValid uses them.
	if _, err := v.Accept(ctx, src, f.result("sign-org", "prov-valid")); err != nil {
		t.Fatalf("control: %v", err)
	}
	// The real `cosign attest` referrer, relabelled as a signature: what the
	// adapter reports when a referrer's unsigned predicate-type annotation
	// claims https://sigstore.dev/cosign/sign/v1.
	relabelled := f.proofs["prov-valid"]
	relabelled.Kind, relabelled.PredicateType = registry.ProofSignature, registry.CosignSignPredicateType

	t.Run("only the trusted publisher's attestation", func(t *testing.T) {
		res := f.result("prov-valid")
		_, err := v.Accept(ctx, src, res)
		wantErr(t, err, registry.ErrMissingProofs)
		var missing *registry.MissingProofsError
		if !errors.As(err, &missing) || !slices.Equal(missing.Missing, []registry.ProofKind{registry.ProofSignature}) {
			t.Fatalf("want the signature reported missing, got %v", err)
		}
		_, err = v.Verify(ctx, src, res, registry.ProofSignature)
		wantErr(t, err, registry.ErrMissingProofs)
	})
	t.Run("the attestation relabelled as the signature", func(t *testing.T) {
		res := f.result("prov-valid")
		res.Proofs = append(res.Proofs, relabelled)
		_, err := v.Accept(ctx, src, res)
		wantErr(t, err, ErrNoValidProof, ErrPredicateType)
		_, err = v.VerifyProof(ctx, src, f.subject, registry.ProofSignature, relabelled)
		wantErr(t, err, ErrPredicateType)
	})
	t.Run("every attestation of the subject, none a signature", func(t *testing.T) {
		// Each provenance fixture is the trusted key's attestation of this
		// subject; relabelled, none of them is a signature either.
		res := f.result()
		for name, p := range f.proofs {
			if !strings.HasPrefix(name, "prov-") || name == "prov-other-subject" || name == "prov-valid-other" {
				continue
			}
			p.Kind, p.PredicateType = registry.ProofSignature, registry.CosignSignPredicateType
			_, err := v.VerifyProof(ctx, src, f.subject, registry.ProofSignature, p)
			wantErr(t, err, ErrPredicateType)
			res.Proofs = append(res.Proofs, p, f.proofs[name])
		}
		if len(res.Proofs) < 2*12 {
			t.Fatalf("only %d attestation fixtures", len(res.Proofs)/2)
		}
		_, err := v.Verify(ctx, src, res, registry.ProofSignature)
		wantErr(t, err, ErrNoValidProof, ErrPredicateType)
		_, err = v.Accept(ctx, src, res)
		wantErr(t, err, ErrNoValidProof, ErrPredicateType)
	})
	t.Run("a recheck bundle retaining the attestation as the signature", func(t *testing.T) {
		// Another real attestation of this subject by the trusted key (the
		// receipt refuses the same proof twice), retained as the signature
		// with digests that match, so only verification can refuse it.
		att := f.proofs["prov-wrong-builder"]
		b, _, err := parseBundle(att)
		if err != nil {
			t.Fatal(err)
		}
		rb := *acceptValid(t, f).Recheck
		rb.Signature = RetainedProof{Manifest: att.Manifest, Bundle: att.Bundle}
		rb.Receipt.Proofs.Signature = bundle.ProofDigests{Manifest: att.ManifestDigest, Bundle: att.BundleDigest,
			Statement: sha256Digest(b.GetDsseEnvelope().GetPayload())}
		got, err := newVerifier(t, f.reader(), clockAt(t1)).Recheck(ctx, src, &rb, f.layer)
		if err != nil {
			t.Fatalf("recheck: %v", err)
		}
		if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, ErrPredicateType) {
			t.Fatalf("want RecheckInvalid for the predicate type, got %+v", got)
		}
	})
}

// Statements and bundles that are not the `cosign sign` signature, each
// signed by the key the rule trusts so only the signature requirement can
// reject them.
func TestSignatureRequiresTheCosignSignStatement(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, fp := pemPublicKey(t, &priv.PublicKey)
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "k", bundle.DefaultPublicKey, pubPEM)
	src := keySource("k", fp)
	subject := "sha256:" + strings.Repeat("5a", 32)
	other := "sha256:" + strings.Repeat("6b", 32)
	sign := registry.CosignSignPredicateType

	cases := []struct {
		name string
		raw  []byte
		want []error
	}{
		{"cosign sign statement (control)", keyBundle(t, priv, statementFor(subject, sign), ""), nil},
		{"SLSA provenance attestation", keyBundle(t, priv, statementFor(subject, registry.SLSAProvenanceV1PredicateType), ""), []error{ErrPredicateType}},
		{"SPDX SBOM attestation", keyBundle(t, priv, statementFor(subject, "https://spdx.dev/Document"), ""), []error{ErrPredicateType}},
		{"custom attestation", keyBundle(t, priv, statementFor(subject, "https://github.com/backend-bunny/Konstapel/notices/v1"), ""), []error{ErrPredicateType}},
		{"legacy simple-signing type", keyBundle(t, priv, statementFor(subject, "cosign container image signature"), ""), []error{ErrPredicateType}},
		{"sign type with a trailing slash", keyBundle(t, priv, statementFor(subject, sign+"/"), ""), []error{ErrPredicateType}},
		{"sign type of another version", keyBundle(t, priv, statementFor(subject, "https://sigstore.dev/cosign/sign/v2"), ""), []error{ErrPredicateType}},
		{"sign type in another case", keyBundle(t, priv, statementFor(subject, strings.ToUpper(sign)), ""), []error{ErrPredicateType}},
		{"sign statement for another subject", keyBundle(t, priv, statementFor(other, sign), ""), []error{ErrSubject}},
		{"message signature instead of a statement", marshalBundle(t, &protobundle.Bundle{
			MediaType: registry.SigstoreBundleArtifactType,
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{}},
			},
			Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: make([]byte, 32)},
				Signature:     []byte("sig"),
			}},
		}), []error{ErrMalformedProof}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Labelled as a signature, as an annotation claiming the sign
			// predicate type would make the adapter label it.
			p := referrerProof(t, registry.ProofSignature, subject, tc.raw)
			got, err := newVerifier(t, r, nil).VerifyProof(context.Background(), src, subject, registry.ProofSignature, p)
			wantErr(t, err, tc.want...)
			if err == nil && (got.Statement.PredicateType != sign || got.Subject != subject) {
				t.Fatalf("accepted %+v", got.Statement)
			}
		})
	}
}

// The same for a keyless rule: the trusted identity's attestation, with
// valid transparency and timestamp evidence, is not its signature.
func TestKeylessAttestationIsNotASignature(t *testing.T) {
	good := newVirtualSigstore(t)
	rootJSON := partsOf(t, good, false).json(t)
	src := keylessSource(testIssuer, testIdentity, rootRef)
	v := newVerifier(t, rootReader(rootJSON), clockAt(time.Now()))
	att, _ := keylessBundle(t, good, keylessOpts{identity: testIdentity, issuer: testIssuer,
		statement: statementFor(keylessSubject, registry.SLSAProvenanceV1PredicateType)})
	ctx := context.Background()

	if _, err := v.VerifyProof(ctx, src, keylessSubject, registry.ProofProvenance, rawProof(registry.ProofProvenance, att)); err != nil {
		t.Fatalf("control: the attestation verifies as provenance: %v", err)
	}
	_, err := v.VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, att))
	wantErr(t, err, ErrPredicateType)
	_, err = v.VerifyProofs(ctx, src, &registry.Result{Digest: keylessSubject, Proofs: []registry.Proof{rawProof(registry.ProofProvenance, att)}})
	wantErr(t, err, registry.ErrMissingProofs)
}
