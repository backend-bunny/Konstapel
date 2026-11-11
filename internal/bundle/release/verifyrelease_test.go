package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

const verifyTestdata = "../verify/testdata"

func vfixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{verifyTestdata}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// proof builds a retrieved proof as the registry adapter does.
func proof(t *testing.T, kind registry.ProofKind, manifest, bundleJSON []byte) registry.Proof {
	t.Helper()
	var m struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	return registry.Proof{
		Kind: kind, PredicateType: m.Annotations[registry.PredicateTypeAnnotation],
		ManifestDigest: digestOf(manifest), Manifest: manifest,
		BundleMediaType: registry.SigstoreBundleArtifactType, BundleDigest: digestOf(bundleJSON), Bundle: bundleJSON,
	}
}

// keyRelease is the cosign-signed release fixture (verify/testdata/release):
// the generator's provenance under a test public-key rule.
type keyRelease struct {
	src    bundle.BundleSource
	rec    publish.Record
	res    *registry.Result
	reader *kubeaccess.MemoryReader
}

func loadKeyRelease(t *testing.T, provName string) keyRelease {
	t.Helper()
	srcs, err := bundle.ParseSources(vfixture(t, "release", "rule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	k := keyRelease{src: srcs.Sources[0], reader: kubeaccess.NewMemoryReader()}
	if k.rec, err = publish.ParseRecord(vfixture(t, "release", "publication-record.json")); err != nil {
		t.Fatal(err)
	}
	k.reader.Put(bundle.KindSecret, k.src.Publisher.PublicKey.Name, kubeaccess.NewObject("Opaque", map[string][]byte{bundle.DefaultPublicKey: vfixture(t, "release", "org.pub")}))
	manifest := vfixture(t, "provenance", "subject-manifest.json")
	ld, _, _ := bundle.ValidateManifest(manifest)
	k.res = &registry.Result{
		Repository: k.src.Repository, Digest: digestOf(manifest), Manifest: manifest, LayerDigest: ld, Layer: vfixture(t, "provenance", "subject-layer.tar.gz"),
		Proofs: []registry.Proof{
			proof(t, registry.ProofSignature, vfixture(t, "release", "sign.manifest.json"), vfixture(t, "release", "sign.bundle.json")),
			proof(t, registry.ProofProvenance, vfixture(t, "release", provName+".manifest.json"), vfixture(t, "release", provName+".bundle.json")),
		},
	}
	return k
}

func newVerifier(t *testing.T, r verify.ObjectReader) *verify.Verifier {
	t.Helper()
	v, err := verify.New(r)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCheckReleaseUnderTheConfiguredRule(t *testing.T) {
	ctx := context.Background()
	k := loadKeyRelease(t, "prov-valid")
	c := ReleaseCheck{Source: k.src, Digest: k.res.Digest, Verifier: newVerifier(t, k.reader), Record: &k.rec}
	acc, err := CheckRelease(ctx, c, k.res)
	if err != nil {
		t.Fatal(err)
	}
	rc := acc.Receipt
	if rc.Subject.Digest != k.res.Digest || rc.Signer.KeyFingerprint != k.src.Publisher.KeyFingerprint ||
		rc.Provenance.Revision != k.rec.Source.Commit || rc.Provenance.Workflow.Commit == rc.Provenance.Revision {
		t.Fatalf("receipt %+v", rc)
	}

	other := k.rec
	other.Definition.SHA256 = strings.Repeat("c", 64) // binds to the bytes, but the provenance attests another definition
	otherTests := k.rec
	otherTests.Tests.Files = otherTests.Tests.Files[:1] // fewer tests than were attested
	wrongKey := k.src
	wrongKey.Publisher.KeyFingerprint = "sha256:" + strings.Repeat("d", 64)
	for _, tc := range []struct {
		name string
		c    ReleaseCheck
		res  *registry.Result
		want error
	}{
		{"record names another definition", ReleaseCheck{Source: k.src, Digest: k.res.Digest, Verifier: c.Verifier, Record: &other}, k.res, ErrReleaseRecord},
		{"record names other tests", ReleaseCheck{Source: k.src, Digest: k.res.Digest, Verifier: c.Verifier, Record: &otherTests}, k.res, ErrReleaseRecord},
		{"provenance by another builder", c, loadKeyRelease(t, "prov-wrong-builder").res, verify.ErrProvenanceBuilder},
		{"rule requires another key", ReleaseCheck{Source: wrongKey, Digest: k.res.Digest, Verifier: c.Verifier}, k.res, verify.ErrKeyFingerprint},
		{"another digest than asked", ReleaseCheck{Source: k.src, Digest: "sha256:" + strings.Repeat("e", 64), Verifier: c.Verifier}, k.res, nil},
		{"no signature", c, &registry.Result{Repository: k.res.Repository, Digest: k.res.Digest, Manifest: k.res.Manifest, Layer: k.res.Layer, Proofs: k.res.Proofs[1:]}, registry.ErrMissingProofs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckRelease(ctx, tc.c, tc.res)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Under the checked-in official rule, real keyless Cosign proofs signed in
// GitHub Actions by another workflow of this repository (publish.yml, the
// application image's) are refused: only the bundle-release identity on main
// is accepted, whatever the proof carries.
func TestCheckReleaseRejectsAnotherKeylessIdentity(t *testing.T) {
	off := loadOfficial(t)
	src := off.Sources[0]
	const imageDigest = "sha256:20711e1fbda7982615945cf775fbcc4d245fea428900c5dca4fa701eded20407"
	res := &registry.Result{Repository: src.Repository, Digest: imageDigest, Proofs: []registry.Proof{
		proof(t, registry.ProofSignature, vfixture(t, "ghcr", "signature.manifest.json"), vfixture(t, "ghcr", "signature.bundle.json")),
		proof(t, registry.ProofProvenance, vfixture(t, "ghcr", "provenance.manifest.json"), vfixture(t, "ghcr", "provenance.bundle.json")),
	}}
	_, err := CheckRelease(context.Background(), ReleaseCheck{Source: src, Digest: imageDigest, Verifier: newVerifier(t, kubeaccess.NewMemoryReader())}, res)
	if !errors.Is(err, verify.ErrSigner) {
		t.Fatalf("got %v, want ErrSigner: the proof's identity is publish.yml, the rule's bundle-release.yml", err)
	}
	// The same proofs verify for their real identity, so the refusal above is
	// the identity alone.
	ok := src
	ok.Publisher.Identity = "https://github.com/backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/main"
	if _, err := newVerifier(t, kubeaccess.NewMemoryReader()).VerifyProofs(context.Background(), ok, res); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestVerifyReleaseReadsAnonymously(t *testing.T) {
	k := loadKeyRelease(t, "prov-valid")
	src := k.src
	src.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
	_, _, err := VerifyRelease(context.Background(), ReleaseCheck{Source: src, Digest: k.res.Digest, Verifier: newVerifier(t, k.reader)})
	if !errors.Is(err, ErrNotAnonymous) || errors.Is(err, registry.ErrCredentials) {
		t.Fatalf("a credentialed source was accepted: %v", err)
	}
}
