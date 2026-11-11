package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Fixtures in testdata/release: the release tool's provenance generator
// output, signed and attested by the pinned Cosign CLI (README.md there).
type releaseFixtures struct {
	facts    map[string]string
	record   publish.Record
	src      bundle.BundleSource
	reader   *kubeaccess.MemoryReader
	manifest []byte
	layer    []byte
	proof    func(name string, kind registry.ProofKind) registry.Proof
}

func loadRelease(t *testing.T) releaseFixtures {
	t.Helper()
	f := releaseFixtures{facts: map[string]string{}}
	for _, line := range strings.Split(strings.TrimSpace(string(readFixture(t, "release", "facts.txt"))), "\n") {
		k, v, _ := strings.Cut(line, " ")
		f.facts[k] = v
	}
	var err error
	if f.record, err = publish.ParseRecord(readFixture(t, "release", "publication-record.json")); err != nil {
		t.Fatal(err)
	}
	srcs, err := bundle.ParseSources(readFixture(t, "release", "rule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if f.src, err = srcs.Select("konstapel-privileged-containers"); err != nil {
		t.Fatal(err)
	}
	if f.src.Publisher.KeyFingerprint != f.facts["org"] || f.src.Publisher.Provenance.Builder != f.facts["builder"] {
		t.Fatalf("rule.yaml does not match facts.txt")
	}
	f.reader = kubeaccess.NewMemoryReader()
	putValue(f.reader, bundle.KindSecret, f.src.Publisher.PublicKey.Name, bundle.DefaultPublicKey, readFixture(t, "release", "org.pub"))
	// The subject bytes are identical to testdata/provenance's.
	f.manifest = readFixture(t, "provenance", "subject-manifest.json")
	f.layer = readFixture(t, "provenance", "subject-layer.tar.gz")
	if sha(f.manifest) != f.facts["subject"] || f.record.ManifestDigest != f.facts["subject"] {
		t.Fatalf("subject %s, record %s, facts %s", sha(f.manifest), f.record.ManifestDigest, f.facts["subject"])
	}
	f.proof = func(name string, kind registry.ProofKind) registry.Proof {
		return proofFrom(t, kind, readFixture(t, "release", name+".manifest.json"), readFixture(t, "release", name+".bundle.json"))
	}
	return f
}

func (f releaseFixtures) input(builder string) publish.ProvenanceInput {
	return publish.ProvenanceInput{
		Builder: builder,
		Workflow: publish.Workflow{
			Repository: "https://github.com/backend-bunny/Konstapel", Path: ".github/workflows/bundle-release.yml",
			Ref: "refs/heads/main", Commit: f.facts["workflow"],
		},
		SigningTools: []publish.Tool{{Name: "cosign", Version: f.facts["cosign"]}},
	}
}

func (f releaseFixtures) result(proofs ...registry.Proof) *registry.Result {
	ld, _, _ := bundle.ValidateManifest(f.manifest)
	return &registry.Result{Repository: f.src.Repository, Digest: f.facts["subject"], Manifest: f.manifest, LayerDigest: ld, Layer: f.layer, Proofs: proofs}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

// The release tool's generator conforms to the contract the consumer
// enforces: its output, signed by the real Cosign CLI, is accepted by
// VerifyProofs and CheckProvenance, and a retry from a newer workflow
// revision records the older source commit as the source and the workflow
// commit apart.
func TestReleaseGeneratorOutputPassesTheVerifier(t *testing.T) {
	if publish.ProvenanceBuildType != ProvenanceBuildType {
		t.Fatalf("publish and verify disagree on the build type: %q vs %q", publish.ProvenanceBuildType, ProvenanceBuildType)
	}
	f := loadRelease(t)
	gen, err := publish.BuildProvenance(f.record, f.input(f.facts["builder"]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gen, readFixture(t, "release", "valid.predicate.json")) {
		t.Fatalf("the generator no longer produces the signed fixture predicate:\n%s", gen)
	}
	v := newVerifier(t, f.reader, nil)
	acc, err := v.Accept(context.Background(), f.src, f.result(f.proof("sign", registry.ProofSignature), f.proof("prov-valid", registry.ProofProvenance)))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, acc.Proofs.Provenance.Statement.Predicate, gen) {
		t.Fatalf("the signed predicate is not the generator's:\n%s", acc.Proofs.Provenance.Statement.Predicate)
	}
	vp := acc.Provenance
	if vp.SourceRevision != f.record.Source.Commit || vp.Workflow.Commit != f.facts["workflow"] || vp.SourceRevision == vp.Workflow.Commit {
		t.Fatalf("source %s, workflow %s: want the record's source and the newer workflow recorded apart", vp.SourceRevision, vp.Workflow.Commit)
	}
	if acc.Receipt.Provenance.Revision != f.record.Source.Commit || acc.Receipt.Provenance.Workflow.Commit != f.facts["workflow"] {
		t.Fatalf("receipt provenance %+v", acc.Receipt.Provenance)
	}
	if vp.Definition.Digest != "sha256:"+f.record.Definition.SHA256 || vp.ContentDigest != f.record.ContentDigest || len(vp.Tests) != len(f.record.Tests.Files) {
		t.Fatalf("materials %+v", vp)
	}
	for i, tf := range f.record.Tests.Files {
		if vp.Tests[i].URI != "bundle-file:"+tf.Path || vp.Tests[i].Digest != "sha256:"+tf.SHA256 {
			t.Fatalf("test %d: %+v", i, vp.Tests[i])
		}
	}
	var tools []string
	for _, tl := range vp.Tools {
		tools = append(tools, tl.URI)
	}
	if strings.Join(tools, " ") != "pkg:golang/go@1.27.3 pkg:github/kyverno/kyverno@v1.19.2 pkg:github/sigstore/cosign@v3.1.3" {
		t.Fatalf("tools %v", tools)
	}

	// Real Cosign output of the generator with another builder.
	gen, _ = publish.BuildProvenance(f.record, f.input(f.facts["other-builder"]))
	if !bytes.Equal(gen, readFixture(t, "release", "wrong-builder.predicate.json")) {
		t.Fatal("wrong-builder fixture is not the generator's output")
	}
	_, err = v.Accept(context.Background(), f.src, f.result(f.proof("sign", registry.ProofSignature), f.proof("prov-wrong-builder", registry.ProofProvenance)))
	wantErr(t, err, ErrProvenanceBuilder)
}

// Generator outputs for wrong inputs, signed at run time with a key the rule
// trusts so that only the provenance policy decides: the verifier refuses
// each.
func TestReleaseGeneratorNegatives(t *testing.T) {
	f := loadRelease(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, fp := pemPublicKey(t, &priv.PublicKey)
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindSecret, "k", bundle.DefaultPublicKey, pubPEM)
	src := f.src
	src.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "k"}
	src.Publisher.KeyFingerprint = fp
	subject := f.facts["subject"]
	sig := referrerProof(t, registry.ProofSignature, subject, keyBundle(t, priv, statementFor(subject, registry.CosignSignPredicateType), ""))
	v := newVerifier(t, r, nil)

	tamper := func(fn func(*publish.Record)) publish.Record {
		rec := f.record
		rec.Tests.Files = append([]publish.FileDigest(nil), rec.Tests.Files...)
		rec.Tools = append([]publish.Tool(nil), rec.Tools...)
		fn(&rec)
		return rec
	}
	for _, c := range []struct {
		name    string
		rec     publish.Record
		builder string
		want    error
	}{
		{"valid (control)", f.record, f.facts["builder"], nil},
		{"workflow commit attested as the source (older source, newer workflow, confused)",
			tamper(func(r *publish.Record) { r.Source.Commit = f.facts["workflow"] }), f.facts["builder"], ErrProvenanceSource},
		{"builder is not the rule's", f.record, f.facts["other-builder"], ErrProvenanceBuilder},
		{"tests that are not the payload's",
			tamper(func(r *publish.Record) { r.Tests.Files[0].SHA256 = strings.Repeat("1", 64) }), f.facts["builder"], ErrProvenanceMaterial},
		{"a test file that is not a test",
			tamper(func(r *publish.Record) { r.Tests.Files[0].Path = "bundle.json" }), f.facts["builder"], ErrProvenanceMaterial},
		{"tampered record: other content", tamper(func(r *publish.Record) { r.ContentDigest = "sha256:" + strings.Repeat("0", 64) }), f.facts["builder"], ErrProvenanceMaterial},
		{"tampered record: other version", tamper(func(r *publish.Record) { r.Version = "0.1.1" }), f.facts["builder"], ErrProvenanceRelease},
		{"tampered record: another source repository",
			tamper(func(r *publish.Record) { r.Source.Repository = "https://github.com/example-fork/Konstapel" }), f.facts["builder"], ErrProvenanceSource},
	} {
		t.Run(c.name, func(t *testing.T) {
			pred, err := publish.BuildProvenance(c.rec, f.input(c.builder))
			if err != nil {
				t.Fatal(err)
			}
			prov := referrerProof(t, registry.ProofProvenance, subject, keyBundle(t, priv, provenanceStatement(t, subject, pred), ""))
			_, err = v.Accept(context.Background(), src, f.result(sig, prov))
			wantErr(t, err, nonNil(c.want)...)
		})
	}
}

func nonNil(err error) []error {
	if err == nil {
		return nil
	}
	return []error{err}
}
