package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Fixtures produced by the pinned Cosign CLI for the real official bundle
// (testdata/provenance/README.md).
const (
	provSourceRepo   = "https://github.com/backend-bunny/Konstapel"
	provSourceCommit = "e30d50760b498cbb17012742c7789a414a1e1d6b"
	provBuilder      = "https://ci.example.test/konstapel/bundle-release@refs/heads/main"
	// provGitHubBuilder is a GitHub Actions workflow builder: its provenance
	// carries the workflow record instead of the builder record.
	provGitHubBuilder = "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"
)

type provFixtures struct {
	subject, otherSubject string
	builderRevision       string
	fpOrg, fpOther        string
	pubOrg, pubOther      []byte
	manifest, layer       []byte
	layerDigest           string
	desc                  *bundle.Descriptor
	proofs                map[string]registry.Proof
	validPredicate        []byte
}

func loadProv(t *testing.T) provFixtures {
	t.Helper()
	f := provFixtures{
		manifest:       readFixture(t, "provenance", "subject-manifest.json"),
		layer:          readFixture(t, "provenance", "subject-layer.tar.gz"),
		pubOrg:         readFixture(t, "provenance", "org.pub"),
		pubOther:       readFixture(t, "provenance", "other.pub"),
		validPredicate: readFixture(t, "provenance", "valid.predicate.json"),
		proofs:         map[string]registry.Proof{},
	}
	f.subject = sha(f.manifest)
	for _, line := range strings.Split(string(readFixture(t, "provenance", "facts.txt")), "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "subject":
			if v != f.subject {
				t.Fatalf("facts.txt subject %s, manifest hashes to %s", v, f.subject)
			}
		case "other-subject":
			f.otherSubject = v
		case "builder-revision":
			f.builderRevision = v
		case "org":
			f.fpOrg = v
		case "other":
			f.fpOther = v
		case "builder":
			if v != provBuilder {
				t.Fatalf("facts.txt builder %s", v)
			}
		}
	}
	var err error
	f.layerDigest, _, err = bundle.ValidateManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if f.desc, _, err = bundle.Unpack(f.layer); err != nil {
		t.Fatal(err)
	}
	if f.desc.Source.Revision != provSourceCommit || f.builderRevision == "" || f.builderRevision == provSourceCommit {
		t.Fatalf("fixture source %s builder revision %s", f.desc.Source.Revision, f.builderRevision)
	}
	for _, n := range []string{"sign-org", "sign-other"} {
		f.proofs[n] = proofFrom(t, registry.ProofSignature, readFixture(t, "provenance", n+".manifest.json"), readFixture(t, "provenance", n+".bundle.json"))
	}
	for _, n := range []string{"valid", "valid-other", "other-subject", "wrong-builder", "wrong-source-repo", "wrong-source-commit",
		"dispatch-as-source", "workflow-record", "wrong-version", "wrong-name", "forged-content", "forged-test", "no-resolved-dependencies", "no-source-material"} {
		f.proofs["prov-"+n] = proofFrom(t, registry.ProofProvenance, readFixture(t, "provenance", "prov-"+n+".manifest.json"), readFixture(t, "provenance", "prov-"+n+".bundle.json"))
	}
	return f
}

func (f provFixtures) reader() *kubeaccess.MemoryReader {
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "org", bundle.DefaultPublicKey, f.pubOrg)
	putValue(r, bundle.KindSecret, "other", bundle.DefaultPublicKey, f.pubOther)
	return r
}

// orgSource is the organization-key rule for the official bundle.
func (f provFixtures) orgSource() bundle.BundleSource {
	src := keySource("org", f.fpOrg)
	src.Publisher.Provenance = bundle.ProvenanceRule{SourceRepository: provSourceRepo, Builder: provBuilder}
	return src
}

func (f provFixtures) result(proofs ...string) *registry.Result {
	res := &registry.Result{Repository: "registry.example.test/fixtures/konstapel-privileged-containers", Digest: f.subject,
		Manifest: f.manifest, LayerDigest: f.layerDigest, Layer: f.layer}
	for _, p := range proofs {
		res.Proofs = append(res.Proofs, f.proofs[p])
	}
	return res
}

func TestProvenanceCosignFixtures(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	with := func(edit func(*bundle.BundleSource)) bundle.BundleSource { s := f.orgSource(); edit(&s); return s }
	cases := []struct {
		name   string
		src    bundle.BundleSource
		proofs []string
		want   []error
	}{
		{"organization-key provenance for the official bundle", f.orgSource(), []string{"sign-org", "prov-valid"}, nil},
		{"wrong builder", f.orgSource(), []string{"sign-org", "prov-wrong-builder"}, []error{ErrProvenanceBuilder}},
		{"wrong source repository", f.orgSource(), []string{"sign-org", "prov-wrong-source-repo"}, []error{ErrProvenanceSource}},
		{"wrong source commit", f.orgSource(), []string{"sign-org", "prov-wrong-source-commit"}, []error{ErrProvenanceSource}},
		{"builder revision attested as the source", f.orgSource(), []string{"sign-org", "prov-dispatch-as-source"}, []error{ErrProvenanceSource}},
		{"GitHub workflow record for an organization builder", f.orgSource(), []string{"sign-org", "prov-workflow-record"}, []error{ErrProvenanceBuilder}},
		{"rule names a GitHub workflow builder, provenance has the builder record", with(func(s *bundle.BundleSource) {
			s.Publisher.Provenance.Builder = "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"
		}), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceBuilder}},
		{"wrong version", f.orgSource(), []string{"sign-org", "prov-wrong-version"}, []error{ErrProvenanceRelease}},
		{"wrong bundle name", f.orgSource(), []string{"sign-org", "prov-wrong-name"}, []error{ErrProvenanceRelease}},
		{"forged content digest", f.orgSource(), []string{"sign-org", "prov-forged-content"}, []error{ErrProvenanceMaterial}},
		{"forged test material", f.orgSource(), []string{"sign-org", "prov-forged-test"}, []error{ErrProvenanceMaterial}},
		{"no resolvedDependencies", f.orgSource(), []string{"sign-org", "prov-no-resolved-dependencies"}, []error{ErrProvenanceContract}},
		{"no source material (builder revision only)", f.orgSource(), []string{"sign-org", "prov-no-source-material"}, []error{ErrProvenanceContract}},
		{"provenance for another digest", f.orgSource(), []string{"sign-org", "prov-other-subject"}, []error{ErrNoValidProof, ErrSubject}},
		{"missing attestation", f.orgSource(), []string{"sign-org"}, []error{registry.ErrMissingProofs}},
		{"missing signature", f.orgSource(), []string{"prov-valid"}, []error{registry.ErrMissingProofs}},
		{"rule names another builder", with(func(s *bundle.BundleSource) { s.Publisher.Provenance.Builder = "https://ci.example.test/other" }), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceBuilder}},
		{"rule builder differs by a suffix", with(func(s *bundle.BundleSource) { s.Publisher.Provenance.Builder = provBuilder + "/" }), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceBuilder}},
		{"rule names another source repository", with(func(s *bundle.BundleSource) {
			s.Publisher.Provenance.SourceRepository = "https://github.com/example-fork/Konstapel"
		}), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceSource}},
		{"rule source repository with .git is not normalized", with(func(s *bundle.BundleSource) { s.Publisher.Provenance.SourceRepository = provSourceRepo + ".git" }), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceSource}},
		{"source serves another bundle name", with(func(s *bundle.BundleSource) { s.Name = "konstapel-other-bundle" }), []string{"sign-org", "prov-valid"}, []error{ErrProvenanceRelease}},
		// Mixed signers: one rule authorizes both proofs, or nothing.
		{"provenance by another key", f.orgSource(), []string{"sign-org", "prov-valid-other"}, []error{ErrNoValidProof, ErrSignature}},
		{"signature by another key", f.orgSource(), []string{"sign-other", "prov-valid"}, []error{ErrNoValidProof, ErrSignature}},
		{"other key's rule with org provenance", with(func(s *bundle.BundleSource) {
			s.Publisher.PublicKey.Name = "other"
			s.Publisher.KeyFingerprint = f.fpOther
		}),
			[]string{"sign-other", "prov-valid"}, []error{ErrNoValidProof, ErrSignature}},
		{"both keys' proofs listed: only the rule's are used", f.orgSource(), []string{"sign-other", "prov-valid-other", "sign-org", "prov-valid"}, nil},
		{"public-key proofs against a keyless rule", keylessSource("https://issuer.example.test", "https://ci.example.test/x", nil), []string{"sign-org", "prov-valid"}, []error{ErrNoValidProof, ErrSigner}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acc, err := newVerifier(t, f.reader(), nil).Accept(ctx, tc.src, f.result(tc.proofs...))
			wantErr(t, err, tc.want...)
			if err != nil {
				return
			}
			p := acc.Provenance
			if p.Builder != provBuilder || p.SourceRepository != provSourceRepo || p.SourceRevision != provSourceCommit ||
				p.BundleName != "konstapel-privileged-containers" || p.BundleVersion != "0.1.0" ||
				p.ContentDigest != f.desc.ContentDigest() || p.BuilderRevision != f.builderRevision || p.Workflow != (Workflow{}) ||
				p.BuildType != ProvenanceBuildType || p.Subject != f.subject {
				t.Fatalf("provenance %+v", p)
			}
			tests := 0
			for _, file := range f.desc.Files {
				if file.Role == bundle.RoleTest {
					tests++
				}
			}
			if len(p.Tests) != tests || tests == 0 || len(p.Tools) != 2 || !strings.HasPrefix(p.Definition.URI, "git+"+provSourceRepo+"@"+provSourceCommit+"#") {
				t.Fatalf("materials %d tests (want %d), tools %+v, definition %+v", len(p.Tests), tests, p.Tools, p.Definition)
			}
		})
	}
}

// The real GitHub CI provenance (generic Actions workflow build type) does
// not follow the bundle contract and is refused, not reinterpreted.
func TestGitHubWorkflowProvenanceIsNotTheBundleContract(t *testing.T) {
	ctx := context.Background()
	sig := proofFrom(t, registry.ProofSignature, readFixture(t, "ghcr", "signature.manifest.json"), readFixture(t, "ghcr", "signature.bundle.json"))
	prov := proofFrom(t, registry.ProofProvenance, readFixture(t, "ghcr", "provenance.manifest.json"), readFixture(t, "ghcr", "provenance.bundle.json"))
	v := newVerifier(t, kubeaccess.NewMemoryReader(), clockAt(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)))
	src := keylessSource(realIssuer, realIdentity, nil)
	src.Publisher.Provenance = bundle.ProvenanceRule{SourceRepository: provSourceRepo, Builder: realIdentity}
	proofs, err := v.VerifyProofs(ctx, src, &registry.Result{Digest: realSubject, Proofs: []registry.Proof{sig, prov}})
	wantErr(t, err)
	d := loadProv(t).desc
	_, err = CheckProvenance(src, d, realSubject, proofs)
	wantErr(t, err, ErrProvenanceContract)
	if !strings.Contains(err.Error(), "https://actions.github.io/buildtypes/workflow/v1") {
		t.Fatalf("error does not name the foreign build type: %v", err)
	}
}

// The defensive same-signer check holds even for a caller that combines
// results of separate verifications.
func TestCheckProvenanceRefusesMixedResults(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	good, err := newVerifier(t, f.reader(), nil).VerifyProofs(ctx, f.orgSource(), f.result("sign-org", "prov-valid"))
	wantErr(t, err)
	otherSrc := f.orgSource()
	otherSrc.Publisher.PublicKey.Name, otherSrc.Publisher.KeyFingerprint = "other", f.fpOther
	otherProv, err := newVerifier(t, f.reader(), nil).Verify(ctx, otherSrc, f.result("prov-valid-other"), registry.ProofProvenance)
	wantErr(t, err)

	mixed := func(edit func(p *Proofs)) *Proofs {
		s, pv := *good.Signature, *good.Provenance
		p := &Proofs{Signature: &s, Provenance: &pv}
		edit(p)
		return p
	}
	cases := []struct {
		name   string
		proofs *Proofs
		pinned string
		want   []error
	}{
		{"consistent", good, f.subject, nil},
		{"signature by org, provenance verified separately for other", &Proofs{Signature: good.Signature, Provenance: otherProv}, f.subject, []error{ErrMixedSigner}},
		{"keyless signer for one proof", mixed(func(p *Proofs) {
			p.Provenance.Signer = bundle.Signer{Kind: bundle.SignerKeyless, Issuer: "https://issuer.example.test", Identity: "x"}
		}), f.subject, []error{ErrMixedSigner}},
		{"different trusted root", mixed(func(p *Proofs) { p.Provenance.TrustRootID = "sha256:" + strings.Repeat("0", 64) }), f.subject, []error{ErrMixedSigner}},
		{"different subjects", mixed(func(p *Proofs) { p.Provenance.Subject = f.otherSubject }), f.subject, []error{ErrMixedSigner}},
		{"kinds swapped", &Proofs{Signature: good.Provenance, Provenance: good.Signature}, f.subject, []error{ErrMixedSigner}},
		{"another pinned subject", good, f.otherSubject, []error{ErrSubject}},
		{"statement subject differs", mixed(func(p *Proofs) {
			p.Provenance.Statement.Subjects = []Subject{{Digest: f.otherSubject}}
		}), f.subject, []error{ErrSubject}},
		{"no provenance", &Proofs{Signature: good.Signature}, f.subject, []error{registry.ErrMissingProofs}},
		{"nothing", nil, f.subject, []error{registry.ErrMissingProofs}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckProvenance(f.orgSource(), f.desc, tc.pinned, tc.proofs)
			wantErr(t, err, tc.want...)
		})
	}
}

// Keyless: identity X signed the subject, identity Y attested it.
func TestProvenanceKeylessMixedIdentities(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	vs := newVirtualSigstore(t)
	r := rootReader(partsOf(t, vs, false).json(t))
	other := "https://git.example.test/org/policies/.github/workflows/other.yml@refs/heads/main"
	sigX, _ := keylessBundle(t, vs, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: statementFor(f.subject, registry.CosignSignPredicateType)})
	provY, _ := keylessBundle(t, vs, keylessOpts{identity: other, issuer: testIssuer, statement: provenanceStatement(t, f.subject, f.validPredicate)})
	provX, _ := keylessBundle(t, vs, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: provenanceStatement(t, f.subject, f.validPredicate)})
	src := keylessSource(testIssuer, testIdentity, rootRef)
	src.Publisher.Provenance = bundle.ProvenanceRule{SourceRepository: provSourceRepo, Builder: provBuilder}
	res := func(prov []byte) *registry.Result {
		r := f.result()
		r.Proofs = []registry.Proof{referrerProof(t, registry.ProofSignature, f.subject, sigX), referrerProof(t, registry.ProofProvenance, f.subject, prov)}
		return r
	}
	_, err := newVerifier(t, r, nil).Accept(ctx, src, res(provY))
	wantErr(t, err, ErrNoValidProof, ErrSigner)
	acc, err := newVerifier(t, r, nil).Accept(ctx, src, res(provX))
	wantErr(t, err)
	if acc.Receipt.Signer.Identity != testIdentity || acc.Receipt.TrustRevision != acc.Proofs.Signature.TrustRootID || acc.Receipt.TrustRoot != "ConfigMap/sigstore-root[trusted_root.json]" {
		t.Fatalf("receipt %+v", acc.Receipt)
	}
}

// provenanceStatement wraps a predicate as `cosign attest` does.
func provenanceStatement(t *testing.T, subject string, predicate []byte) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, predicate); err != nil {
		t.Fatal(err)
	}
	return fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"registry.example.test/x","digest":{"sha256":%q}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":%s}`,
		strings.TrimPrefix(subject, "sha256:"), compact.Bytes())
}

// referrerManifest is a referrer in the layout the pinned Cosign writes.
func referrerManifest(subject, predicateType string, bundleJSON []byte) []byte {
	m := map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"artifactType": registry.SigstoreBundleArtifactType,
		"config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": bundle.EmptyConfigDigest,
			"artifactType": registry.SigstoreBundleArtifactType},
		"layers":      []any{map[string]any{"mediaType": registry.SigstoreBundleArtifactType, "size": len(bundleJSON), "digest": sha(bundleJSON)}},
		"annotations": map[string]string{registry.PredicateTypeAnnotation: predicateType},
		"subject":     map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 460, "digest": subject},
	}
	raw, _ := json.Marshal(m)
	return raw
}

func referrerProof(t *testing.T, kind registry.ProofKind, subject string, bundleJSON []byte) registry.Proof {
	return proofFrom(t, kind, referrerManifest(subject, predicateTypes[kind], bundleJSON), bundleJSON)
}

// Contract strictness, signed with a key the rule trusts so that only the
// provenance policy can reject.
func TestProvenanceContract(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, fp := pemPublicKey(t, &priv.PublicKey)
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "k", bundle.DefaultPublicKey, pubPEM)
	src := keySource("k", fp)
	src.Publisher.Provenance = bundle.ProvenanceRule{SourceRepository: provSourceRepo, Builder: provBuilder}
	sig := rawProof(registry.ProofSignature, keyBundle(t, priv, statementFor(f.subject, registry.CosignSignPredicateType), ""))

	var base map[string]any
	if err := json.Unmarshal(f.validPredicate, &base); err != nil {
		t.Fatal(err)
	}
	edit := func(fn func(p map[string]any)) []byte {
		var p map[string]any
		raw, _ := json.Marshal(base)
		_ = json.Unmarshal(raw, &p)
		fn(p)
		out, _ := json.Marshal(p)
		return out
	}
	bd := func(p map[string]any) map[string]any { return p["buildDefinition"].(map[string]any) }
	ext := func(p map[string]any, k string) map[string]any {
		return bd(p)["externalParameters"].(map[string]any)[k].(map[string]any)
	}
	in := func(p map[string]any) map[string]any { return bd(p)["internalParameters"].(map[string]any) }
	br := func(p map[string]any) map[string]any { return in(p)["builder"].(map[string]any) }
	// ghWorkflow turns the predicate into one for a GitHub Actions workflow
	// builder (the rule's builder in the cases that set ghRule).
	ghWorkflow := func(p map[string]any) {
		p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = provGitHubBuilder
		bd(p)["internalParameters"] = map[string]any{"workflow": map[string]any{
			"repository": provSourceRepo, "path": ".github/workflows/bundle-release.yml", "ref": "refs/heads/main", "commit": f.builderRevision,
		}}
	}
	wf := func(p map[string]any) map[string]any { return in(p)["workflow"].(map[string]any) }
	gh := func(fn func(p map[string]any)) []byte {
		return edit(func(p map[string]any) { ghWorkflow(p); fn(p) })
	}
	deps := func(p map[string]any) []any { return bd(p)["resolvedDependencies"].([]any) }
	dep := func(p map[string]any, name string) map[string]any {
		for _, d := range deps(p) {
			if d.(map[string]any)["name"] == name {
				return d.(map[string]any)
			}
		}
		t.Fatalf("no %s material", name)
		return nil
	}
	licenseSHA := ""
	for _, file := range f.desc.Files {
		if file.Path == "LICENSE" {
			licenseSHA = file.SHA256
		}
	}
	valid := edit(func(map[string]any) {})
	raw := func(s string) []byte { return []byte(s) }

	ghRule := src
	ghRule.Publisher.Provenance.Builder = provGitHubBuilder
	cases := []struct {
		name  string
		pred  []byte
		want  error
		ghWfl bool // judged under the GitHub workflow builder rule
	}{
		{"valid", valid, nil, false},
		{"builder revision equal to the source commit is allowed", edit(func(p map[string]any) { br(p)["revision"] = provSourceCommit }), nil, false},
		{"builder revision is free-form text", edit(func(p map[string]any) { br(p)["revision"] = "pipeline 2026.11.12-3" }), nil, false},
		{"empty builder revision", edit(func(p map[string]any) { br(p)["revision"] = "" }), ErrProvenanceContract, false},
		{"builder revision as a number", edit(func(p map[string]any) { br(p)["revision"] = 7 }), ErrProvenanceContract, false},
		{"unknown builder record field", edit(func(p map[string]any) { br(p)["workflow"] = "x" }), ErrProvenanceContract, false},
		{"no build record", edit(func(p map[string]any) { bd(p)["internalParameters"] = map[string]any{} }), ErrProvenanceContract, false},
		{"both build records", gh(func(p map[string]any) { in(p)["builder"] = map[string]any{"revision": "r"} }), ErrProvenanceContract, true},
		{"unknown internalParameters field", edit(func(p map[string]any) { in(p)["runner"] = map[string]any{} }), ErrProvenanceContract, false},
		{"workflow record for an organization builder", gh(func(p map[string]any) {
			p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = provBuilder
		}), ErrProvenanceBuilder, false},
		{"GitHub workflow builder with its workflow record", gh(func(map[string]any) {}), nil, true},
		{"GitHub workflow builder with a builder record", edit(func(p map[string]any) {
			p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = provGitHubBuilder
		}), ErrProvenanceBuilder, true},
		{"workflow commit equal to the source commit is allowed", gh(func(p map[string]any) { wf(p)["commit"] = provSourceCommit }), nil, true},
		{"workflow ref omitted", gh(func(p map[string]any) { delete(wf(p), "ref") }), ErrProvenanceBuilder, true},
		{"workflow of another repository", gh(func(p map[string]any) { wf(p)["repository"] = "https://github.com/example-fork/Konstapel" }), ErrProvenanceBuilder, true},
		{"workflow at another path", gh(func(p map[string]any) { wf(p)["path"] = ".github/workflows/other.yml" }), ErrProvenanceBuilder, true},
		{"workflow on another ref", gh(func(p map[string]any) { wf(p)["ref"] = "refs/heads/dev" }), ErrProvenanceBuilder, true},
		{"short workflow commit", gh(func(p map[string]any) { wf(p)["commit"] = "591d6fe" }), ErrProvenanceContract, true},
		{"metadata omitted", edit(func(p map[string]any) { delete(p["runDetails"].(map[string]any), "metadata") }), nil, false},
		{"builder version recorded", edit(func(p map[string]any) {
			p["runDetails"].(map[string]any)["builder"].(map[string]any)["version"] = map[string]any{"go": "1.27.3"}
		}), nil, false},
		{"tool with a digest", edit(func(p map[string]any) { dep(p, "tool")["digest"] = map[string]any{"sha256": strings.Repeat("a", 64)} }), nil, false},
		{"GitHub workflow build type", edit(func(p map[string]any) { bd(p)["buildType"] = "https://actions.github.io/buildtypes/workflow/v1" }), ErrProvenanceContract, false},
		{"unknown top-level field", edit(func(p map[string]any) { p["byproducts"] = []any{} }), ErrProvenanceContract, false},
		{"unknown runDetails field", edit(func(p map[string]any) { p["runDetails"].(map[string]any)["byproducts"] = []any{} }), ErrProvenanceContract, false},
		{"unknown externalParameters field", edit(func(p map[string]any) { bd(p)["externalParameters"].(map[string]any)["trust"] = "me" }), ErrProvenanceContract, false},
		{"case-variant key", edit(func(p map[string]any) { ext(p, "source")["Commit"] = strings.Repeat("0", 40) }), ErrProvenanceContract, false},
		// Refused already by the statement parser; parsePredicate refuses it
		// too (below).
		{"duplicate key", bytes.Replace(valid, []byte(`"buildType":`), []byte(`"buildType":"x","buildType":`), 1), ErrStatement, false},
		{"version as a number", edit(func(p map[string]any) { ext(p, "bundle")["version"] = 1 }), ErrProvenanceContract, false},
		{"builder id null", edit(func(p map[string]any) { p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = nil }), ErrProvenanceContract, false},
		{"empty bundle name", edit(func(p map[string]any) { ext(p, "bundle")["name"] = "" }), ErrProvenanceContract, false},
		{"oversized builder id", edit(func(p map[string]any) {
			p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = strings.Repeat("x", MaxProvenanceString+1)
		}), ErrProvenanceContract, false},
		{"control character", edit(func(p map[string]any) { ext(p, "bundle")["name"] = "konstapel\n" }), ErrProvenanceContract, false},
		{"short source commit", edit(func(p map[string]any) { ext(p, "source")["commit"] = provSourceCommit[:12] }), ErrProvenanceContract, false},
		{"no internalParameters", edit(func(p map[string]any) { delete(bd(p), "internalParameters") }), ErrProvenanceContract, false},
		{"bad startedOn", edit(func(p map[string]any) {
			p["runDetails"].(map[string]any)["metadata"].(map[string]any)["startedOn"] = "yesterday"
		}), ErrProvenanceContract, false},
		{"two source materials", edit(func(p map[string]any) {
			d := map[string]any{"name": "source", "uri": "git+https://github.com/example-fork/Konstapel", "digest": map[string]any{"gitCommit": provSourceCommit}}
			bd(p)["resolvedDependencies"] = append(deps(p), d)
		}), ErrProvenanceContract, false},
		{"repeated material", edit(func(p map[string]any) { bd(p)["resolvedDependencies"] = append(deps(p), dep(p, "tool")) }), ErrProvenanceContract, false},
		{"unknown material name", edit(func(p map[string]any) {
			bd(p)["resolvedDependencies"] = append(deps(p), map[string]any{"name": "cache", "uri": "x", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}})
		}), ErrProvenanceContract, false},
		{"material without a name", edit(func(p map[string]any) { delete(dep(p, "bundle-content"), "name") }), ErrProvenanceContract, false},
		{"no tool", edit(func(p map[string]any) {
			var keep []any
			for _, d := range deps(p) {
				if d.(map[string]any)["name"] != "tool" {
					keep = append(keep, d)
				}
			}
			bd(p)["resolvedDependencies"] = keep
		}), ErrProvenanceContract, false},
		{"source digest is sha256", edit(func(p map[string]any) { dep(p, "source")["digest"] = map[string]any{"sha256": strings.Repeat("a", 64)} }), ErrProvenanceContract, false},
		{"second digest algorithm", edit(func(p map[string]any) { dep(p, "bundle-content")["digest"].(map[string]any)["sha512"] = "00" }), ErrProvenanceContract, false},
		{"uppercase content digest", edit(func(p map[string]any) {
			d := dep(p, "bundle-content")["digest"].(map[string]any)
			d["sha256"] = strings.ToUpper(d["sha256"].(string))
		}), ErrProvenanceContract, false},
		{"test uri without prefix", edit(func(p map[string]any) { dep(p, "test")["uri"] = "tests/x.yaml" }), ErrProvenanceContract, false},
		{"too many materials", edit(func(p map[string]any) {
			l := deps(p)
			for i := 0; i < MaxMaterials; i++ {
				l = append(l, map[string]any{"name": "tool", "uri": fmt.Sprintf("pkg:generic/t@%d", i)})
			}
			bd(p)["resolvedDependencies"] = l
		}), ErrProvenanceContract, false},
		{"test not in the payload", edit(func(p map[string]any) { dep(p, "test")["uri"] = "bundle-file:tests/missing.yaml" }), ErrProvenanceMaterial, false},
		{"test naming a non-test payload file", edit(func(p map[string]any) {
			d := dep(p, "test")
			d["uri"], d["digest"] = "bundle-file:LICENSE", map[string]any{"sha256": licenseSHA}
		}), ErrProvenanceMaterial, false},
		{"definition of another commit", edit(func(p map[string]any) {
			d := dep(p, "bundle-definition")
			d["uri"] = strings.Replace(d["uri"].(string), provSourceCommit, strings.Repeat("0", 40), 1)
		}), ErrProvenanceMaterial, false},
		{"content of another version", edit(func(p map[string]any) {
			dep(p, "bundle-content")["uri"] = "bundle-content:konstapel-privileged-containers@0.0.9"
		}), ErrProvenanceMaterial, false},
		{"source material without git+", edit(func(p map[string]any) { dep(p, "source")["uri"] = provSourceRepo }), ErrProvenanceSource, false},
		{"source material at another commit", edit(func(p map[string]any) {
			dep(p, "source")["digest"] = map[string]any{"gitCommit": strings.Repeat("0", 40)}
		}), ErrProvenanceSource, false},
		{"builder revision is the descriptor's, source is not", edit(func(p map[string]any) {
			br(p)["revision"] = provSourceCommit
			ext(p, "source")["commit"] = f.builderRevision
			dep(p, "source")["digest"] = map[string]any{"gitCommit": f.builderRevision}
		}), ErrProvenanceSource, false},
		{"workflow revision is the descriptor's, source is not", gh(func(p map[string]any) {
			wf(p)["commit"] = provSourceCommit
			ext(p, "source")["commit"] = f.builderRevision
			dep(p, "source")["digest"] = map[string]any{"gitCommit": f.builderRevision}
		}), ErrProvenanceSource, true},
		{"not an object", raw(`["buildDefinition"]`), ErrStatement, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := src
			if tc.ghWfl {
				rule = ghRule
			}
			prov := rawProof(registry.ProofProvenance, keyBundle(t, priv, provenanceStatement(t, f.subject, tc.pred), ""))
			proofs, err := newVerifier(t, r, nil).VerifyProofs(ctx, rule, &registry.Result{Digest: f.subject, Proofs: []registry.Proof{sig, prov}})
			if err != nil {
				wantErr(t, err, tc.want)
				return
			}
			_, err = CheckProvenance(rule, f.desc, f.subject, proofs)
			if tc.want == nil {
				wantErr(t, err)
			} else {
				wantErr(t, err, tc.want)
			}
		})
	}

	// The build-record guards report which record is wrong.
	for _, c := range []struct {
		name, msg string
		rule      bundle.BundleSource
		pred      []byte
	}{
		{"neither record", "must hold a workflow or a builder record", src, edit(func(p map[string]any) { bd(p)["internalParameters"] = map[string]any{} })},
		{"builder record under a GitHub workflow builder", "has no internalParameters.workflow record", ghRule, edit(func(p map[string]any) {
			p["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = provGitHubBuilder
		})},
	} {
		t.Run("build record: "+c.name, func(t *testing.T) {
			prov := rawProof(registry.ProofProvenance, keyBundle(t, priv, provenanceStatement(t, f.subject, c.pred), ""))
			proofs, err := newVerifier(t, r, nil).VerifyProofs(ctx, c.rule, &registry.Result{Digest: f.subject, Proofs: []registry.Proof{sig, prov}})
			if err == nil {
				_, err = CheckProvenance(c.rule, f.desc, f.subject, proofs)
			}
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("got %v, want %q", err, c.msg)
			}
		})
	}

	t.Run("duplicate key in the predicate", func(t *testing.T) {
		_, err := parsePredicate(bytes.Replace(valid, []byte(`"buildType":`), []byte(`"buildType":"x","buildType":`), 1))
		wantErr(t, err, ErrProvenanceContract)
	})
	t.Run("oversized predicate", func(t *testing.T) {
		big := bytes.Replace(valid, []byte(`"invocationId":"test-only"`), []byte(`"invocationId":"`+strings.Repeat("x", MaxPredicateBytes)+`"`), 1)
		_, err := parsePredicate(big)
		wantErr(t, err, ErrProvenanceContract)
	})
	t.Run("descriptor from another source repository", func(t *testing.T) {
		proofs, err := newVerifier(t, r, nil).VerifyProofs(ctx, src, &registry.Result{Digest: f.subject, Proofs: []registry.Proof{sig,
			rawProof(registry.ProofProvenance, keyBundle(t, priv, provenanceStatement(t, f.subject, valid), ""))}})
		wantErr(t, err)
		d := *f.desc
		d.Source.Repository = "https://github.com/example-fork/Konstapel"
		_, err = CheckProvenance(src, &d, f.subject, proofs)
		wantErr(t, err, ErrProvenanceSource)
		d = *f.desc
		d.Source.Revision = f.builderRevision
		_, err = CheckProvenance(src, &d, f.subject, proofs)
		wantErr(t, err, ErrProvenanceSource)
		d = *f.desc
		d.Version = "0.1.1"
		_, err = CheckProvenance(src, &d, f.subject, proofs)
		wantErr(t, err, ErrProvenanceRelease)
		_, err = CheckProvenance(src, nil, f.subject, proofs)
		wantErr(t, err, ErrProvenanceContract)
	})
}
