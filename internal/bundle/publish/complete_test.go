package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// A retry from a newer workflow revision packaging an older source commit.
var (
	olderSource   = strings.Repeat("a", 40) // revA: the frozen bundle's source
	newerWorkflow = "0123456789abcdef0123456789abcdef01234567"
	testBuilder   = "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"
)

func testProvenanceInput() ProvenanceInput {
	return ProvenanceInput{
		Builder: testBuilder,
		Workflow: Workflow{
			Repository: "https://github.com/backend-bunny/Konstapel", Path: ".github/workflows/bundle-release.yml",
			Ref: "refs/heads/main", Commit: newerWorkflow,
		},
		InvocationID: "https://github.com/backend-bunny/Konstapel/actions/runs/1/attempts/2",
		SigningTools: []Tool{{Name: "cosign", Version: "v3.1.3"}},
	}
}

// predicateView decodes the fields a test inspects.
type predicateView struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Bundle struct{ Name, Version string }      `json:"bundle"`
			Source struct{ Repository, Commit string } `json:"source"`
		} `json:"externalParameters"`
		InternalParameters struct {
			Workflow Workflow `json:"workflow"`
		} `json:"internalParameters"`
		ResolvedDependencies []struct {
			Name   string            `json:"name"`
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata map[string]string `json:"metadata"`
	} `json:"runDetails"`
}

func decodePredicate(t *testing.T, b []byte) predicateView {
	t.Helper()
	var p predicateView
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("predicate %s: %v", b, err)
	}
	return p
}

func TestBuildProvenanceFollowsTheContract(t *testing.T) {
	f := frozenAt(t, olderSource, testTime)
	b, err := BuildProvenance(f.Record, testProvenanceInput())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := BuildProvenance(f.Record, testProvenanceInput())
	if !bytes.Equal(b, again) {
		t.Fatal("provenance is not deterministic")
	}
	p := decodePredicate(t, b)
	bd := p.BuildDefinition
	rec := f.Record
	if bd.BuildType != ProvenanceBuildType || p.RunDetails.Builder.ID != testBuilder ||
		p.RunDetails.Metadata["invocationId"] != testProvenanceInput().InvocationID {
		t.Fatalf("build type, builder or metadata: %s", b)
	}
	if bd.ExternalParameters.Bundle.Name != rec.Name || bd.ExternalParameters.Bundle.Version != rec.Version ||
		bd.ExternalParameters.Source.Repository != rec.Source.Repository {
		t.Fatalf("external parameters %+v", bd.ExternalParameters)
	}
	// The content source and the workflow revision are both recorded, each
	// in its own place, and never confused.
	if bd.ExternalParameters.Source.Commit != olderSource || bd.InternalParameters.Workflow.Commit != newerWorkflow {
		t.Fatalf("source commit %s, workflow commit %s", bd.ExternalParameters.Source.Commit, bd.InternalParameters.Workflow.Commit)
	}
	if bd.InternalParameters.Workflow != testProvenanceInput().Workflow {
		t.Fatalf("workflow %+v", bd.InternalParameters.Workflow)
	}
	var got []string
	for _, d := range bd.ResolvedDependencies {
		got = append(got, fmt.Sprintf("%s %s %v", d.Name, d.URI, d.Digest))
	}
	want := []string{
		fmt.Sprintf("source git+%s map[gitCommit:%s]", rec.Source.Repository, olderSource),
		fmt.Sprintf("bundle-definition git+%s@%s#bundles/%s/definition.json map[sha256:%s]", rec.Source.Repository, olderSource, rec.Name, rec.Definition.SHA256),
		fmt.Sprintf("bundle-content bundle-content:%s@%s map[sha256:%s]", rec.Name, rec.Version, strings.TrimPrefix(rec.ContentDigest, "sha256:")),
	}
	for _, tf := range rec.Tests.Files {
		want = append(want, fmt.Sprintf("test bundle-file:%s map[sha256:%s]", tf.Path, tf.SHA256))
	}
	want = append(want, "tool pkg:golang/go@1.27.3 map[]", "tool pkg:github/kyverno/kyverno@v0.0.0-test map[]",
		"tool pkg:github/sigstore/cosign@v3.1.3 map[]")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("materials:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(rec.Tests.Files) == 0 {
		t.Fatal("the frozen record names no tests")
	}
}

// An organization builder that is not a GitHub Actions workflow records its
// own revision in internalParameters.builder, apart from the source commit,
// and no workflow.
func TestBuildProvenanceOrganizationBuilder(t *testing.T) {
	f := frozenAt(t, olderSource, testTime)
	in := ProvenanceInput{Builder: "https://ci.acme.example/pipelines/policy-release", BuilderRevision: newerWorkflow,
		SigningTools: []Tool{{Name: "cosign", Version: "v3.1.3"}}}
	b, err := BuildProvenance(f.Record, in)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		BuildDefinition struct {
			ExternalParameters struct {
				Source struct{ Commit string } `json:"source"`
			} `json:"externalParameters"`
			InternalParameters map[string]map[string]string `json:"internalParameters"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	ip := p.BuildDefinition.InternalParameters
	if len(ip) != 1 || len(ip["builder"]) != 1 || ip["builder"]["revision"] != newerWorkflow ||
		p.BuildDefinition.ExternalParameters.Source.Commit != olderSource || p.RunDetails.Builder.ID != in.Builder {
		t.Fatalf("predicate %s", b)
	}
}

func TestBuildProvenanceRefusesBadInputs(t *testing.T) {
	f := frozenAt(t, olderSource, testTime)
	for name, c := range map[string]struct {
		rec func(*Record)
		in  func(*ProvenanceInput)
	}{
		"no builder":                       {in: func(i *ProvenanceInput) { i.Builder = "" }},
		"builder not https":                {in: func(i *ProvenanceInput) { i.Builder = "http://ci.example/x" }},
		"short workflow commit":            {in: func(i *ProvenanceInput) { i.Workflow.Commit = "0123abc" }},
		"workflow path escapes":            {in: func(i *ProvenanceInput) { i.Workflow.Path = ".github/../x.yml" }},
		"absolute workflow path":           {in: func(i *ProvenanceInput) { i.Workflow.Path = "/etc/x.yml" }},
		"workflow repository":              {in: func(i *ProvenanceInput) { i.Workflow.Repository = "git@github.com:o/r" }},
		"control character in ref":         {in: func(i *ProvenanceInput) { i.Workflow.Ref = "refs/heads/main\n" }},
		"workflow of another repository":   {in: func(i *ProvenanceInput) { i.Workflow.Repository = "https://github.com/example-fork/Konstapel" }},
		"workflow at another path":         {in: func(i *ProvenanceInput) { i.Workflow.Path = ".github/workflows/other.yml" }},
		"workflow on another ref":          {in: func(i *ProvenanceInput) { i.Workflow.Ref = "refs/heads/dev" }},
		"workflow ref omitted":             {in: func(i *ProvenanceInput) { i.Workflow.Ref = "" }},
		"GitHub builder, builder revision": {in: func(i *ProvenanceInput) { i.BuilderRevision = "r1" }},
		"org builder with a workflow":      {in: func(i *ProvenanceInput) { i.Builder = "https://ci.acme.example/release"; i.BuilderRevision = "r1" }},
		"org builder without a revision": {in: func(i *ProvenanceInput) {
			i.Builder, i.Workflow = "https://ci.acme.example/release", Workflow{}
		}},
		"org builder, unprintable revision": {in: func(i *ProvenanceInput) {
			i.Builder, i.Workflow, i.BuilderRevision = "https://ci.acme.example/release", Workflow{}, "r1\n"
		}},
		"unprintable signing tool":  {in: func(i *ProvenanceInput) { i.SigningTools = []Tool{{Name: "cosign", Version: ""}} }},
		"record without tests":      {rec: func(r *Record) { r.Tests.Files = nil }},
		"record with short commit":  {rec: func(r *Record) { r.Source.Commit = "abc" }},
		"record with wrong format":  {rec: func(r *Record) { r.Format = "other" }},
		"record with failed result": {rec: func(r *Record) { r.Tests.Result = "failed" }},
	} {
		t.Run(name, func(t *testing.T) {
			rec, in := f.Record, testProvenanceInput()
			rec.Tests.Files = append([]FileDigest(nil), rec.Tests.Files...)
			if c.rec != nil {
				c.rec(&rec)
			}
			if c.in != nil {
				c.in(&in)
			}
			if b, err := BuildProvenance(rec, in); err == nil {
				t.Fatalf("accepted: %s", b)
			}
		})
	}
}

func TestToolURI(t *testing.T) {
	for in, want := range map[Tool]string{
		{Name: "go", Version: "go1.27.3"}:   "pkg:golang/go@1.27.3",
		{Name: "cosign", Version: "v3.1.3"}: "pkg:github/sigstore/cosign@v3.1.3",
		{Name: "kyverno", Version: "v1.19"}: "pkg:github/kyverno/kyverno@v1.19",
		{Name: "jq", Version: "1.8 beta"}:   "pkg:generic/jq@1.8%20beta",
	} {
		if got := ToolURI(in); got != want {
			t.Errorf("%+v: %s, want %s", in, got, want)
		}
	}
}

// fakeSigner is a ProofSigner that attaches cosign-shaped referrers to the
// fake registry, records every call and can fail.
type fakeSigner struct {
	w          *registry.Client
	name       string
	size       int64
	fail       string
	calls      []string
	predicates [][]byte
}

func (s *fakeSigner) Tool(context.Context) (Tool, error) {
	return Tool{Name: "cosign", Version: "v3.1.3"}, nil
}

func (s *fakeSigner) Sign(ctx context.Context, ref string) error {
	s.calls = append(s.calls, "sign "+ref)
	if s.fail == "sign" {
		return errors.New("injected sign failure")
	}
	return s.push(ctx, ref, registry.CosignSignPredicateType)
}

func (s *fakeSigner) Attest(ctx context.Context, ref string, predicate []byte) error {
	s.calls = append(s.calls, "attest "+ref)
	s.predicates = append(s.predicates, predicate)
	if s.fail == "attest" {
		return errors.New("injected attest failure")
	}
	return s.push(ctx, ref, registry.SLSAProvenanceV1PredicateType)
}

func (s *fakeSigner) push(ctx context.Context, ref, pt string) error {
	repo, d, _ := strings.Cut(ref, "@")
	sess, err := s.w.Open(ctx, bundle.BundleSource{Name: s.name, Repository: repo, CredentialSecret: &PublisherCredential})
	if err != nil {
		return err
	}
	layer := []byte(fmt.Sprintf(`{"mediaType":%q,"proof":%q}`, registry.SigstoreBundleArtifactType, pt))
	ld := ocispec.Descriptor{MediaType: registry.SigstoreBundleArtifactType, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
	if ok, _ := sess.Repository.Blobs().Exists(ctx, ld); !ok {
		if err := sess.Repository.Blobs().Push(ctx, ld, bytes.NewReader(layer)); err != nil {
			return err
		}
	}
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "artifactType": registry.SigstoreBundleArtifactType,
		"config":      map[string]any{"mediaType": bundle.EmptyConfigMediaType, "digest": bundle.EmptyConfigDigest, "size": 2},
		"layers":      []any{ld},
		"subject":     map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": d, "size": s.size},
		"annotations": map[string]string{registry.PredicateTypeAnnotation: pt},
	})
	md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
	return sess.Repository.Manifests().Push(ctx, md, bytes.NewReader(m))
}

// The release completer signs the published digest (never a tag) for only
// the kinds still missing, after reading the subject back through the
// consumer adapter and binding it to its record; a rerun after a failed
// attestation adds only the attestation; nothing is signed twice.
func TestCompleterSignsOnlyMissingKindsOfTheDigest(t *testing.T) {
	forBothListings(t, func(t *testing.T, tagSchema bool) {
		f := newFaultRegistry(t, tagSchema)
		fr := frozenAt(t, olderSource, testTime)
		tgt := newTarget(t, f)
		s := &fakeSigner{w: tgt.Writer, name: fr.Record.Name, size: int64(len(fr.Manifest)), fail: "attest"}
		tgt.Proofs = &Completer{Signer: s, Reader: tgt.Reader, Provenance: testProvenanceInput()}
		ref := tgt.Repository + "@" + fr.ManifestDigest

		res, err := Publish(context.Background(), fr, tgt)
		if !errors.Is(err, ErrIncompleteRemote) || res.Complete {
			t.Fatalf("a failed attestation must leave the publication incomplete: %v", err)
		}
		if fmt.Sprint(s.calls) != fmt.Sprint([]string{"sign " + ref, "attest " + ref}) {
			t.Fatalf("calls %q: want the digest signed, then attested", s.calls)
		}
		// The rerun signs nothing again: only the missing provenance.
		s.fail, s.calls = "", nil
		res, err = Publish(context.Background(), fr, tgt)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(s.calls) != fmt.Sprint([]string{"attest " + ref}) || fmt.Sprint(res.ProofsAdded) != "[provenance]" || !res.Complete {
			t.Fatalf("calls %q, added %v, complete %t", s.calls, res.ProofsAdded, res.Complete)
		}
		p := decodePredicate(t, s.predicates[len(s.predicates)-1])
		if p.BuildDefinition.ExternalParameters.Source.Commit != fr.Record.Source.Commit ||
			p.BuildDefinition.InternalParameters.Workflow.Commit != newerWorkflow || p.RunDetails.Builder.ID != testBuilder {
			t.Fatalf("attested predicate: %s", s.predicates[len(s.predicates)-1])
		}
		// Both present: Publish does not ask, and asking directly writes nothing.
		s.calls = nil
		from := len(f.log())
		if res, err = Publish(context.Background(), fr, tgt); err != nil || res.Outcome != AlreadyPublished || len(s.calls) != 0 {
			t.Fatalf("rerun with both proofs: %v %+v %q", err, res, s.calls)
		}
		sub := Subject{Repository: tgt.Repository, Digest: fr.ManifestDigest, Size: int64(len(fr.Manifest)), Record: fr.Record}
		if err := tgt.Proofs.Complete(context.Background(), sub, registry.RequiredProofs); err != nil || len(s.calls) != 0 || len(f.writes(from)) != 0 {
			t.Fatalf("present proofs were signed again: %v %q %v", err, s.calls, f.writes(from))
		}
	})
}

func TestCompleterRefusesAnotherSubject(t *testing.T) {
	// Two registries (the fake serves one repository each): A holds frA, B frB.
	f, fB := newFaultRegistry(t, true), newFaultRegistry(t, true)
	frA := frozenAt(t, olderSource, testTime)
	frB := frozenAt(t, revB, testTime)
	tgt, tgtB := newTarget(t, f), newTarget(t, fB)
	if _, err := Publish(context.Background(), frA, tgt); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(context.Background(), frB, tgtB); err != nil {
		t.Fatal(err)
	}
	repoA := tgt.Repository
	s := &fakeSigner{w: tgt.Writer, name: frA.Record.Name, size: int64(len(frA.Manifest))}
	c := &Completer{Signer: s, Reader: tgt.Reader, Provenance: testProvenanceInput()}
	ctx := context.Background()
	good := Subject{Repository: repoA, Digest: frA.ManifestDigest, Size: int64(len(frA.Manifest)), Record: frA.Record}
	tampered := frA.Record
	tampered.ContentDigest = "sha256:" + strings.Repeat("0", 64)
	tamperedTests := frA.Record
	tamperedTests.Tests.Files = []FileDigest{{Path: frA.Record.Tests.Files[0].Path, SHA256: strings.Repeat("1", 64)}}
	for name, sub := range map[string]Subject{
		"digest is not the record's":           {Repository: repoA, Digest: frB.ManifestDigest, Size: good.Size, Record: frA.Record},
		"another repository's bytes":           {Repository: tgtB.Repository, Digest: frA.ManifestDigest, Size: good.Size, Record: frA.Record},
		"record of other content (tampered)":   {Repository: repoA, Digest: frA.ManifestDigest, Size: good.Size, Record: tampered},
		"record with other tests (tampered)":   {Repository: repoA, Digest: frA.ManifestDigest, Size: good.Size, Record: tamperedTests},
		"size differs":                         {Repository: repoA, Digest: frA.ManifestDigest, Size: good.Size + 1, Record: frA.Record},
		"tag instead of digest":                {Repository: repoA, Digest: "0.1.0", Size: good.Size, Record: frA.Record},
		"repository with an embedded tag":      {Repository: repoA + ":0.1.0", Digest: frA.ManifestDigest, Size: good.Size, Record: frA.Record},
		"record for B presented as A's digest": {Repository: repoA, Digest: frA.ManifestDigest, Size: good.Size, Record: frB.Record},
	} {
		t.Run(name, func(t *testing.T) {
			from := len(f.log())
			err := c.Complete(ctx, sub, registry.RequiredProofs)
			if err == nil || len(s.calls) != 0 || len(f.writes(from)) != 0 {
				t.Fatalf("signed or wrote: %v %q", err, s.calls)
			}
			if name != "another repository's bytes" && !errors.Is(err, ErrProofSubject) {
				t.Fatalf("want ErrProofSubject, got %v", err)
			}
		})
	}
	for name, kinds := range map[string][]registry.ProofKind{
		"unknown kind": {"sbom"}, "repeated kind": {registry.ProofSignature, registry.ProofSignature},
	} {
		if err := c.Complete(ctx, good, kinds); err == nil || len(s.calls) != 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if err := c.Complete(ctx, good, nil); err != nil || len(s.calls) != 0 {
		t.Fatalf("nothing missing must sign nothing: %v %q", err, s.calls)
	}
	// The real subject is signed by digest, signature first.
	if err := c.Complete(ctx, good, []registry.ProofKind{registry.ProofProvenance, registry.ProofSignature}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(s.calls) != fmt.Sprint([]string{"sign " + repoA + "@" + frA.ManifestDigest, "attest " + repoA + "@" + frA.ManifestDigest}) {
		t.Fatalf("calls %q", s.calls)
	}
}
