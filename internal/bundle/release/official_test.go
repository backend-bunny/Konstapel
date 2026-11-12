package release

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// The first official bundle release, as the bundle release workflow published
// and signed it keylessly with the pinned Cosign CLI on 2026-11-12
// (testdata/official/README.md).
const (
	officialName         = "konstapel-privileged-containers"
	officialDigest       = "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8"
	officialSourceCommit = "863f4853151bb342a46eefa57c31cb2d46e17cff"
	officialSourcesPath  = "../../../" + OfficialSourcesFile
)

// officialRule is the rule for the official bundle exactly as
// bundles/official-sources.yaml configures it.
func officialRule(t *testing.T) bundle.BundleSource {
	t.Helper()
	srcs, err := LoadSources(officialSourcesPath)
	if err != nil {
		t.Fatal(err)
	}
	src, err := srcs.Select(officialName)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func officialFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "official", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// officialResult is the retrieval of the published subject and its two
// Cosign referrers, from the read-only copy in testdata/official.
func officialResult(t *testing.T) *registry.Result {
	t.Helper()
	manifest := officialFixture(t, "subject-manifest.json")
	if digestOf(manifest) != officialDigest {
		t.Fatalf("subject manifest hashes to %s", digestOf(manifest))
	}
	ld, _, err := bundle.ValidateManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	layer := officialFixture(t, "subject-layer.tar.gz")
	if digestOf(layer) != ld {
		t.Fatalf("layer hashes to %s, the manifest names %s", digestOf(layer), ld)
	}
	return &registry.Result{
		Repository: "ghcr.io/backend-bunny/bundles/" + officialName, Digest: officialDigest,
		Manifest: manifest, LayerDigest: ld, Layer: layer,
		Proofs: []registry.Proof{
			proof(t, registry.ProofSignature, officialFixture(t, "signature.manifest.json"), officialFixture(t, "signature.bundle.json")),
			proof(t, registry.ProofProvenance, officialFixture(t, "provenance.manifest.json"), officialFixture(t, "provenance.bundle.json")),
		},
	}
}

// checkOfficialAccepted asserts what the production verifier established for
// the official release under the official rule.
func checkOfficialAccepted(t *testing.T, acc *verify.Accepted) {
	t.Helper()
	rc, vp := acc.Receipt, acc.Provenance
	switch {
	case rc.Signer != bundle.Signer{Kind: bundle.SignerKeyless, Issuer: GitHubIssuer, Identity: OfficialIdentity()}:
		t.Fatalf("signer %+v", rc.Signer)
	case rc.TrustRoot != verify.TrustRootPublicGood || rc.TrustRevision != "sha256:"+verify.PublicGoodTrustRootSHA256:
		t.Fatalf("trust root %s %s", rc.TrustRoot, rc.TrustRevision)
	case acc.Proofs.Signature.SigningTime.IsZero() || acc.Proofs.Provenance.SigningTime.IsZero():
		t.Fatal("no authenticated signing time")
	case vp.Builder != OfficialIdentity() || vp.SourceRepository != OfficialRepositoryURL || vp.SourceRevision != officialSourceCommit:
		t.Fatalf("provenance %+v", vp)
	case vp.Workflow.Repository != OfficialRepositoryURL || vp.Workflow.Path != OfficialWorkflowPath || vp.Workflow.Ref != OfficialWorkflowRef ||
		vp.Workflow.Commit != officialSourceCommit || vp.BuilderRevision != "":
		t.Fatalf("workflow record %+v, builder revision %q", vp.Workflow, vp.BuilderRevision)
	case vp.BundleName != officialName || vp.BundleVersion != "0.1.0" || rc.Subject.Digest != officialDigest:
		t.Fatalf("release %s@%s %s", vp.BundleName, vp.BundleVersion, rc.Subject.Digest)
	}
}

// officialNegatives are rules that must not accept the official release:
// trusting the public-good root authorizes only the exact configured
// publisher, builder and source.
func officialNegatives(t *testing.T) map[string]struct {
	src  bundle.BundleSource
	want []error
} {
	t.Helper()
	with := func(edit func(*bundle.Publisher)) bundle.BundleSource {
		s := officialRule(t)
		edit(&s.Publisher)
		return s
	}
	const otherWorkflow = OfficialRepositoryURL + "/.github/workflows/publish.yml@refs/heads/main"
	return map[string]struct {
		src  bundle.BundleSource
		want []error
	}{
		"identity of another workflow": {with(func(p *bundle.Publisher) { p.Identity, p.Provenance.Builder = otherWorkflow, otherWorkflow }),
			[]error{verify.ErrNoValidProof, verify.ErrSigner}},
		"identity on another ref": {with(func(p *bundle.Publisher) {
			id := OfficialRepositoryURL + "/" + OfficialWorkflowPath + "@refs/heads/dev"
			p.Identity, p.Provenance.Builder = id, id
		}), []error{verify.ErrNoValidProof, verify.ErrSigner}},
		"identity of a fork": {with(func(p *bundle.Publisher) {
			id := "https://github.com/example-fork/Konstapel/" + OfficialWorkflowPath + "@" + OfficialWorkflowRef
			p.Identity, p.Provenance.Builder = id, id
		}), []error{verify.ErrNoValidProof, verify.ErrSigner}},
		"another issuer": {with(func(p *bundle.Publisher) { p.Issuer = "https://token.actions.example.test" }),
			[]error{verify.ErrNoValidProof, verify.ErrSigner}},
		"another builder": {with(func(p *bundle.Publisher) { p.Provenance.Builder = otherWorkflow }), []error{verify.ErrProvenanceBuilder}},
		"another source repository": {with(func(p *bundle.Publisher) { p.Provenance.SourceRepository = "https://github.com/example-fork/Konstapel" }),
			[]error{verify.ErrProvenanceSource}},
	}
}

// The official release's real keyless proofs, verified offline through the
// production verifier and the consumer's release check under the official
// rule with the embedded public-good root.
func TestOfficialReleaseVerifiesOffline(t *testing.T) {
	ctx := context.Background()
	v, err := verify.New(kubeaccess.NewMemoryReader())
	if err != nil {
		t.Fatal(err)
	}
	src := officialRule(t)
	acc, err := CheckRelease(ctx, ReleaseCheck{Source: src, Digest: officialDigest, Verifier: v}, officialResult(t))
	if err != nil {
		t.Fatal(err)
	}
	checkOfficialAccepted(t, acc)

	for name, c := range officialNegatives(t) {
		t.Run(name, func(t *testing.T) {
			_, err := CheckRelease(ctx, ReleaseCheck{Source: c.src, Digest: officialDigest, Verifier: v}, officialResult(t))
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("error %v does not match %v", err, w)
				}
			}
		})
	}
	t.Run("a referenced root replaces the embedded one, with no fallback", func(t *testing.T) {
		s := officialRule(t)
		s.Publisher.TrustRoot = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "other-root"}
		r := kubeaccess.NewMemoryReader()
		r.Put(bundle.KindConfigMap, "other-root", kubeaccess.NewObject("", map[string][]byte{bundle.DefaultTrustRootKey: officialFixture(t, "../../../verify/publicgood/trusted_root.json")}))
		// The same root bytes under a reference: still verifies (the source is
		// configuration, not the bytes' origin) ...
		v2, _ := verify.New(r)
		if _, err := CheckRelease(ctx, ReleaseCheck{Source: s, Digest: officialDigest, Verifier: v2}, officialResult(t)); err != nil {
			t.Fatalf("the public-good root referenced explicitly: %v", err)
		}
		// ... a missing referenced root fails closed, with no fallback.
		_, err := CheckRelease(ctx, ReleaseCheck{Source: s, Digest: officialDigest, Verifier: v}, officialResult(t))
		if !errors.Is(err, verify.ErrTrustConfig) {
			t.Fatalf("missing referenced root: %v", err)
		}
	})
}
