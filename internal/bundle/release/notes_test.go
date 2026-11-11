package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

const (
	notesCommit   = "0123456789abcdef0123456789abcdef01234567"
	notesWFCommit = "89abcdef0123456789abcdef0123456789abcdef"
	notesIdentity = "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"
	notesIssuer   = "https://token.actions.githubusercontent.com"
)

func sha(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// notesFixture is a complete, consistent release of the official bundle: the
// frozen package and the verification of its published digest.
func notesFixture(t *testing.T) NotesInput {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "bundles", "konstapel-privileged-containers", "definition.json"))
	if err != nil {
		t.Fatal(err)
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = notesCommit
	a, err := bundle.Build(def, os.DirFS(root), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	d := a.Descriptor

	var rec publish.Record
	rec.Name, rec.Version = d.Name, d.Version
	rec.Source.Repository, rec.Source.Commit = d.Source.Repository, notesCommit
	rec.Definition = publish.FileDigest{Path: "bundles/" + d.Name + "/definition.json", SHA256: strings.Repeat("d", 64)}
	rec.ManifestDigest, rec.LayerDigest, rec.ContentDigest = a.ManifestDigest, a.LayerDigest, d.ContentDigest()
	rec.Tools = []publish.Tool{{Name: "kyverno", Version: "1.17.2"}, {Name: "go", Version: "go1.27.4"}, {Name: "cosign", Version: "v3.1.3"}}
	rec.Tests = publish.Tests{Runner: "kyverno test --require-tests", Result: "pass"}
	for _, f := range d.Files {
		if f.Role == bundle.RoleTest {
			rec.Tests.Files = append(rec.Tests.Files, publish.FileDigest{Path: f.Path, SHA256: f.SHA256})
		}
	}

	var rc bundle.Receipt
	rc.Version = bundle.HandleVersion
	rc.VerifiedAt = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	rc.Subject.Name, rc.Subject.Version, rc.Subject.Digest = d.Name, d.Version, a.ManifestDigest
	rc.RetrievedFrom = OfficialRegistry + "/" + d.Name
	rc.SourceRule, rc.TrustRevision, rc.TrustRoot = sha("1"), sha("2"), "embedded Sigstore public-good root"
	rc.Signer = bundle.Signer{Kind: bundle.SignerKeyless, Issuer: notesIssuer, Identity: notesIdentity}
	rc.Proofs.Signature = bundle.ProofDigests{Manifest: sha("3"), Bundle: sha("4"), Statement: sha("5")}
	rc.Proofs.Attestation = bundle.ProofDigests{Manifest: sha("6"), Bundle: sha("7"), Statement: sha("8")}
	rc.Provenance = bundle.Provenance{
		PredicateType: bundle.PredicateSLSAProvenanceV1, BuildType: "https://example.test/buildtype",
		Repository: d.Source.Repository, Revision: notesCommit, Builder: notesIdentity, Content: d.ContentDigest(),
		Workflow: bundle.WorkflowRef{Repository: "https://github.com/backend-bunny/Konstapel", Path: ".github/workflows/bundle-release.yml", Ref: "refs/heads/main", Commit: notesWFCommit},
	}
	if err := rc.Validate(); err != nil {
		t.Fatalf("fixture receipt: %v", err)
	}
	return NotesInput{
		Frozen: &publish.Frozen{Descriptor: d, ManifestDigest: a.ManifestDigest, LayerDigest: a.LayerDigest, Record: rec},
		Verification: &Verification{
			Format: VerificationFormat, Status: StatusComplete, Repository: OfficialRegistry + "/" + d.Name, Digest: a.ManifestDigest,
			ReferrersSource: registry.ReferrersFromTagSchema, SigningTime: "2026-11-12T08:59:12Z", Receipt: &rc,
		},
	}
}

func TestRenderNotesGolden(t *testing.T) {
	in := notesFixture(t)
	got, err := RenderNotes(in)
	if err != nil {
		t.Fatal(err)
	}
	// Rendering is a pure function of the inputs: no clock, no map order.
	again, err := RenderNotes(notesFixture(t))
	if err != nil || again != got {
		t.Fatalf("notes are not deterministic: %v", err)
	}
	// Re-verifying later produces a new receipt time; the notes must not change.
	in.Verification.Receipt.VerifiedAt = in.Verification.Receipt.VerifiedAt.Add(72 * time.Hour)
	if later, _ := RenderNotes(in); later != got {
		t.Fatal("the notes change when only the verification time changes, so an update would never be a no-op")
	}

	path := filepath.Join("testdata", "notes-official.golden.md")
	if os.Getenv("KONSTAPEL_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (regenerate with KONSTAPEL_UPDATE_GOLDEN=1)", err)
	}
	if string(want) != got {
		t.Fatalf("notes drifted from %s (regenerate with KONSTAPEL_UPDATE_GOLDEN=1 only for an intended change)\n--- golden\n%s\n--- got\n%s", path, want, got)
	}
}

func TestRenderedNotesContent(t *testing.T) {
	in := notesFixture(t)
	got, err := RenderNotes(in)
	if err != nil {
		t.Fatal(err)
	}
	d := in.Frozen.Descriptor
	ref := OfficialRegistry + "/" + d.Name + "@" + in.Frozen.ManifestDigest
	for _, want := range []string{
		"# " + d.Name + " " + d.Version,
		"**Status: complete.**",
		// The exact digest, copyable verification of both proofs under the exact identity.
		"ref=" + ref,
		"cosign verify \"$ref\"",
		"cosign verify-attestation \"$ref\" --type slsaprovenance1",
		"--certificate-identity '" + notesIdentity + "'",
		"--certificate-oidc-issuer '" + notesIssuer + "'",
		"devbox run -- go run ./cmd/bundlerelease verify-release -name " + d.Name + " -digest " + in.Frozen.ManifestDigest,
		// Source and workflow are separate facts.
		"at commit `" + notesCommit + "`", "at commit `" + notesWFCommit + "`",
		d.Compatibility.Provider, d.Compatibility.Konstapel,
		"`disallow-privileged-containers`", "`LICENSE`", "`NOTICE`",
		"kyverno test --require-tests", "OCI referrers tag schema",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notes lack %q", want)
		}
	}
	// A tag is never what a reader is told to verify.
	if strings.Contains(got, ":"+d.Version+"\"") || strings.Contains(got, "@"+d.Version) {
		t.Error("notes reference the version tag as the verified reference")
	}
}

func TestRenderNotesRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*NotesInput)
		want   error
	}{
		"no verification":             {func(in *NotesInput) { in.Verification = nil }, ErrNotComplete},
		"incomplete":                  {func(in *NotesInput) { in.Verification.Status = "incomplete: verification failed" }, ErrNotComplete},
		"complete without receipt":    {func(in *NotesInput) { in.Verification.Receipt = nil }, ErrNotComplete},
		"empty status":                {func(in *NotesInput) { in.Verification.Status = "" }, ErrNotComplete},
		"no frozen package":           {func(in *NotesInput) { in.Frozen = nil }, ErrNotesInput},
		"verified another digest":     {func(in *NotesInput) { in.Verification.Digest = sha("9") }, ErrNotesInput},
		"receipt for another digest":  {func(in *NotesInput) { in.Verification.Receipt.Subject.Digest = sha("9") }, ErrNotesInput},
		"record for another digest":   {func(in *NotesInput) { in.Frozen.Record.ManifestDigest = sha("9") }, ErrNotesInput},
		"receipt for another name":    {func(in *NotesInput) { in.Verification.Receipt.Subject.Name = "other" }, ErrNotesInput},
		"receipt for another version": {func(in *NotesInput) { in.Verification.Receipt.Subject.Version = "9.9.9" }, ErrNotesInput},
		"record for another version":  {func(in *NotesInput) { in.Frozen.Record.Version = "9.9.9" }, ErrNotesInput},
		"attested content differs":    {func(in *NotesInput) { in.Verification.Receipt.Provenance.Content = sha("9") }, ErrNotesInput},
		"record content differs":      {func(in *NotesInput) { in.Frozen.Record.ContentDigest = sha("9") }, ErrNotesInput},
		"attested commit differs":     {func(in *NotesInput) { in.Verification.Receipt.Provenance.Revision = strings.Repeat("9", 40) }, ErrNotesInput},
		"record commit differs":       {func(in *NotesInput) { in.Frozen.Record.Source.Commit = strings.Repeat("9", 40) }, ErrNotesInput},
		"attested repository differs": {func(in *NotesInput) {
			in.Verification.Receipt.Provenance.Repository = "https://github.com/fork/Konstapel"
		}, ErrNotesInput},
		"repository of another bundle": {func(in *NotesInput) { in.Verification.Repository = OfficialRegistry + "/other" }, ErrNotesInput},
		"invalid receipt":              {func(in *NotesInput) { in.Verification.Receipt.Proofs.Signature.Bundle = "" }, ErrNotesInput},
		"public-key signer": {func(in *NotesInput) {
			in.Verification.Receipt.Signer = bundle.Signer{Kind: bundle.SignerPublicKey, KeyFingerprint: strings.Repeat("a", 64)}
		}, ErrNotesUnsupported},
		"identity that would break a command": {func(in *NotesInput) {
			in.Verification.Receipt.Signer.Identity = "https://x/y' ; rm -rf / #"
		}, ErrNotesInput},
		"issuer with a space": {func(in *NotesInput) { in.Verification.Receipt.Signer.Issuer = "https://a b" }, ErrNotesInput},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := notesFixture(t)
			tc.mutate(&in)
			out, err := RenderNotes(in)
			if !errors.Is(err, tc.want) || out != "" {
				t.Fatalf("got %q, %v; want no notes and %v", out, err, tc.want)
			}
		})
	}
}

func TestParseVerification(t *testing.T) {
	good := `{"format":"` + VerificationFormat + `","status":"complete","repository":"r/x","digest":"` + sha("a") + `"}`
	if v, err := ParseVerification(strings.NewReader(good)); err != nil || v.Status != StatusComplete {
		t.Fatalf("valid record: %v %v", v, err)
	}
	for name, in := range map[string]string{
		"unknown field": strings.Replace(good, `"status"`, `"extra":1,"status"`, 1),
		"trailing data": good + `{}`,
		"other format":  strings.Replace(good, VerificationFormat, "x/v2", 1),
		"not json":      "nope",
		"oversized":     `{"format":"` + VerificationFormat + `","error":"` + strings.Repeat("a", maxVerificationBytes) + `"}`,
	} {
		if _, err := ParseVerification(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
