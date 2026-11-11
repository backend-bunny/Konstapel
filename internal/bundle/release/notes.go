package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// VerificationFormat is the format of the record verify-release writes.
const VerificationFormat = "konstapel.policy.bundle.release-verification/v1"

// StatusComplete is the only status that lets a release be announced.
const StatusComplete = "complete"

// maxVerificationBytes bounds the verification record the renderer reads.
const maxVerificationBytes = 1 << 20

// Verification is the bounded record verify-release writes: the outcome of
// retrieving a published digest anonymously and verifying it under the
// central publisher rule.
type Verification struct {
	Format          string                   `json:"format"`
	Status          string                   `json:"status"`
	Error           string                   `json:"error,omitempty"`
	Repository      string                   `json:"repository"`
	Digest          string                   `json:"digest"`
	ReferrersSource registry.ReferrersSource `json:"referrersSource,omitempty"`
	SigningTime     string                   `json:"signingTime,omitempty"`
	Receipt         *bundle.Receipt          `json:"receipt,omitempty"`
}

// ParseVerification strictly decodes a verification record: bounded size,
// unknown fields, trailing data and other formats are rejected.
func ParseVerification(r io.Reader) (*Verification, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxVerificationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxVerificationBytes {
		return nil, fmt.Errorf("verification record exceeds %d bytes", maxVerificationBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v Verification
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode verification record: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode verification record: unexpected data after the record")
	}
	if v.Format != VerificationFormat {
		return nil, fmt.Errorf("verification record format %q is not %q", v.Format, VerificationFormat)
	}
	return &v, nil
}

var (
	// ErrNotComplete: the release has not been verified end to end, so it must
	// not be announced.
	ErrNotComplete = errors.New("the release is not complete")
	// ErrNotesInput: the frozen package and the verification record describe
	// different releases, or a value is unsafe to print into a command.
	ErrNotesInput = errors.New("release notes inputs disagree")
	// ErrNotesUnsupported: notes are written for keyless official releases.
	ErrNotesUnsupported = errors.New("release notes support keyless releases")
)

// NotesInput is everything a release's notes are rendered from.
type NotesInput struct {
	// Frozen is the package that was published: descriptor and the publication
	// record bound to its bytes.
	Frozen *publish.Frozen
	// Verification is the outcome of verifying the published digest.
	Verification *Verification
}

func notesFail(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNotesInput, fmt.Sprintf(format, a...))
}

// safeToken reports whether v can be pasted inside single quotes in a shell
// command without surprises.
func safeToken(v string) bool {
	return v != "" && !strings.ContainsAny(v, "'\"`$\\\n\r\t ") && strings.TrimSpace(v) == v
}

func code(v string) string { return "`" + v + "`" }

// RenderNotes renders the release notes of a verified release as Markdown.
// It refuses anything that is not a complete, consistent verification of the
// exact frozen package, so an incomplete publication can never be announced.
// The output depends only on the inputs (no clock, no ordering of maps), so
// rendering the same release twice gives the same bytes.
func RenderNotes(in NotesInput) (string, error) {
	v, f := in.Verification, in.Frozen
	if v == nil || v.Status != StatusComplete || v.Receipt == nil {
		status := "missing"
		if v != nil {
			status = v.Status
		}
		return "", fmt.Errorf("%w: verification status is %q", ErrNotComplete, status)
	}
	if f == nil || f.Descriptor == nil {
		return "", notesFail("no frozen package")
	}
	d, rec, rc := f.Descriptor, f.Record, v.Receipt

	if err := rc.Validate(); err != nil {
		return "", notesFail("the receipt is invalid: %v", err)
	}
	if rc.Signer.Kind != bundle.SignerKeyless {
		return "", fmt.Errorf("%w: the signer is %q", ErrNotesUnsupported, rc.Signer.Kind)
	}
	switch {
	case v.Digest != f.ManifestDigest || rc.Subject.Digest != f.ManifestDigest:
		return "", notesFail("verified digest %s, receipt subject %s, frozen manifest %s must be one digest", v.Digest, rc.Subject.Digest, f.ManifestDigest)
	case rec.ManifestDigest != f.ManifestDigest:
		return "", notesFail("the publication record is for %s, not %s", rec.ManifestDigest, f.ManifestDigest)
	case rc.Subject.Name != d.Name || rec.Name != d.Name:
		return "", notesFail("bundle names differ: receipt %q, record %q, descriptor %q", rc.Subject.Name, rec.Name, d.Name)
	case rc.Subject.Version != d.Version || rec.Version != d.Version:
		return "", notesFail("versions differ: receipt %q, record %q, descriptor %q", rc.Subject.Version, rec.Version, d.Version)
	case rc.Provenance.Content != rec.ContentDigest || rec.ContentDigest != d.ContentDigest():
		return "", notesFail("the attested content digest, the record's and the descriptor's must be one digest")
	case rc.Provenance.Revision != rec.Source.Commit || d.Source.Revision != rec.Source.Commit:
		return "", notesFail("source commits differ: attested %s, record %s, descriptor %s", rc.Provenance.Revision, rec.Source.Commit, d.Source.Revision)
	case rc.Provenance.Repository != rec.Source.Repository:
		return "", notesFail("source repositories differ: attested %q, record %q", rc.Provenance.Repository, rec.Source.Repository)
	}
	if err := bundle.ValidateRepository(v.Repository); err != nil || !strings.HasSuffix(v.Repository, "/"+d.Name) {
		return "", notesFail("repository %q is not a registry repository for %s", v.Repository, d.Name)
	}
	for what, val := range map[string]string{
		"repository": v.Repository, "digest": v.Digest, "issuer": rc.Signer.Issuer, "identity": rc.Signer.Identity, "name": d.Name,
	} {
		if !safeToken(val) {
			return "", notesFail("%s %q cannot be printed in a copyable command", what, val)
		}
	}

	ref := v.Repository + "@" + v.Digest
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# %s %s\n\n", d.Name, d.Version)
	w("A Konstapel policy bundle release. It is versioned and published independently of the Konstapel application, image and charts, and contains no controller code.\n\n")
	w("**Status: complete.** The published bytes were retrieved anonymously by digest, and their signature, build provenance and content were verified under the official publisher rule for this bundle (rule revision %s).\n\n", code(rc.SourceRule))

	w("## Identity\n\n| | |\n| --- | --- |\n")
	w("| Registry | %s |\n", code(v.Repository))
	w("| Manifest digest | %s |\n", code(v.Digest))
	w("| Pin in a profile | `spec.bundle.name` %s and `spec.bundle.digest` %s |\n", code(d.Name), code(v.Digest))
	w("| Version tag | %s |\n", code(d.Version))
	w("| Source | %s at commit %s |\n", rec.Source.Repository, code(rec.Source.Commit))
	wf := rc.Provenance.Workflow
	w("| Release workflow (recorded separately from the source) | %s %s at commit %s |\n", wf.Repository, code(wf.Path), code(wf.Commit))
	w("| Content digest | %s |\n", code(rec.ContentDigest))
	w("| Archive (layer) digest | %s |\n", code(rec.LayerDigest))
	w("| Bundle definition | %s, sha256 %s |\n", code(rec.Definition.Path), code(rec.Definition.SHA256))
	w("| Builder | %s |\n", rc.Provenance.Builder)
	w("| Signer | %s (issuer %s) |\n", rc.Signer.Identity, rc.Signer.Issuer)
	if v.SigningTime != "" {
		w("| Signing time | %s |\n", v.SigningTime)
	}
	w("| Trust root | %s (revision %s) |\n", rc.TrustRoot, code(rc.TrustRevision))
	w("\n")

	w("## Compatibility\n\n")
	w("- Provider contract: %s\n", code(d.Compatibility.Provider))
	w("- Minimum Konstapel release: %s\n", code(d.Compatibility.Konstapel))
	var oscal []string
	for _, o := range d.OSCAL {
		oscal = append(oscal, code(o.Version)+" ("+o.Path+")")
	}
	sort.Strings(oscal)
	w("- OSCAL documents: %s\n", strings.Join(oscal, ", "))
	w("- Workload kinds: %s\n", strings.Join(sorted(d.Scope.Workloads), ", "))
	w("- Operating systems: %s\n\n", strings.Join(sorted(d.Scope.OS), ", "))
	w("This is the bundle's declared contract. It does not claim enforcement on a particular cluster: live acceptance evidence for these exact inputs is separate, and the controller's own compatibility checks still apply.\n\n")

	w("## Policies\n\n| Policy | Rule and check IDs | Source file |\n| --- | --- | --- |\n")
	policies := append([]bundle.Policy(nil), d.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	for _, p := range policies {
		var ids []string
		for _, c := range p.Checks {
			ids = append(ids, code(c.RuleID))
		}
		sort.Strings(ids)
		w("| %s | %s | %s |\n", code(p.Name), strings.Join(ids, ", "), code(p.Path))
	}
	w("\n")

	w("## Tests\n\n")
	w("Declarative policy fixtures ran against the unpacked, frozen bytes with `%s` before publication: **%s**, %d fixture files.\n\n", rec.Tests.Runner, rec.Tests.Result, len(rec.Tests.Files))
	if len(rec.Tests.Files) > 0 {
		w("<details><summary>Fixture files and SHA-256 digests</summary>\n\n| File | SHA-256 |\n| --- | --- |\n")
		files := append([]publish.FileDigest(nil), rec.Tests.Files...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for _, t := range files {
			w("| %s | %s |\n", code(t.Path), code(t.SHA256))
		}
		w("\n</details>\n\n")
	}

	w("## Licenses\n\nThe archive carries its license and notice texts; they are part of the signed content:\n\n")
	var licenses []string
	for _, fl := range d.Files {
		if fl.Role == bundle.RoleLicense {
			licenses = append(licenses, code(fl.Path))
		}
	}
	sort.Strings(licenses)
	for _, l := range licenses {
		w("- %s\n", l)
	}
	w("\n")

	w("## Build tools\n\n")
	tools := append([]publish.Tool(nil), rec.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	for _, t := range tools {
		w("- %s %s\n", t.Name, t.Version)
	}
	w("\n")

	w("## Verify it yourself\n\nBoth commands check the exact digest and fail if the signer is not exactly this workflow identity:\n\n")
	w("```sh\nref=%s\n", ref)
	w("cosign verify \"$ref\" \\\n  --certificate-identity '%s' \\\n  --certificate-oidc-issuer '%s'\n", rc.Signer.Identity, rc.Signer.Issuer)
	w("cosign verify-attestation \"$ref\" --type slsaprovenance1 \\\n  --certificate-identity '%s' \\\n  --certificate-oidc-issuer '%s'\n```\n\n", rc.Signer.Identity, rc.Signer.Issuer)
	w("Cosign checks the signatures and who made them; it does not check what the provenance says. The Konstapel verifier (run it from a checkout of this repository at or after the source commit) also checks the attested builder, source repository and commit, bundle name and version, the content and test materials, and that the archive matches its manifest:\n\n")
	w("```sh\ndevbox run -- go run ./cmd/bundlerelease verify-release -name %s -digest %s\n```\n\n", d.Name, v.Digest)
	w("Referrers were listed through the %s.\n", referrersSource(v.ReferrersSource))
	return b.String(), nil
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	for i := range out {
		out[i] = code(out[i])
	}
	return out
}

func referrersSource(s registry.ReferrersSource) string {
	switch s {
	case registry.ReferrersFromAPI:
		return "OCI referrers API"
	case registry.ReferrersFromTagSchema:
		return "OCI referrers tag schema (`sha256-<hex>` index tag)"
	default:
		return "registry"
	}
}
