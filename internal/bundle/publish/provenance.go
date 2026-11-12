package publish

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// The Konstapel bundle provenance contract (docs/policy-bundles.md, "Bundle
// provenance v1"). The verifier (internal/bundle/verify) defines the same
// values; a test keeps them equal. They are repeated here so this build-tool
// package does not link the verifier and its Sigstore dependencies.
const (
	// ProvenanceBuildType is buildDefinition.buildType.
	ProvenanceBuildType = "https://github.com/backend-bunny/Konstapel/blob/main/docs/policy-bundles.md#bundle-provenance-v1"

	materialSource     = "source"
	materialDefinition = "bundle-definition"
	materialContent    = "bundle-content"
	materialTest       = "test"
	materialTool       = "tool"
)

// maxProvenanceString is the contract's bound on every string.
const maxProvenanceString = 2048

var (
	workflowPath = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	uriText      = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Workflow is the GitHub Actions workflow revision that ran a release: the
// repository and path of the workflow definition, the ref it ran from and its
// commit. It is recorded in internalParameters.workflow, separately from the
// content source, so a retry from a newer workflow revision that packages an
// older source commit stays distinguishable. It never stands in for the
// source. Only a GitHub Actions workflow builder records it
// (bundle.GitHubWorkflowBuilder), and its repository, path and ref must be
// the builder's.
type Workflow struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Ref        string `json:"ref,omitempty"`
	Commit     string `json:"commit"`
}

// ProvenanceInput is what provenance records beyond the publication record.
type ProvenanceInput struct {
	// Builder is runDetails.builder.id: the exact builder identity the
	// central publisher rule names (for official releases, the release
	// workflow identity, which is also the keyless certificate identity).
	Builder string
	// Exactly one build record, chosen by the builder: Workflow, the run's
	// GitHub Actions workflow revision, for a GitHub Actions workflow
	// builder; BuilderRevision, the revision of the organization's own
	// builder (for example its pipeline definition's commit), for any other
	// builder. Both are recorded apart from the source commit.
	Workflow        Workflow
	BuilderRevision string
	// InvocationID optionally identifies the run (runDetails.metadata).
	InvocationID string
	// SigningTools are recorded as tool materials after the record's tools
	// (for example the Cosign CLI that signs the attestation).
	SigningTools []Tool
}

// BuildProvenance returns the SLSA provenance v1 predicate for the bundle a
// publication record describes, following the Konstapel bundle provenance
// contract: the requested release and content source come only from the
// record (externalParameters, and the source, bundle-definition and
// bundle-content materials), the record's tests become test materials and its
// tools tool materials, and the workflow revision is recorded separately in
// internalParameters. The record must be bound to the published bytes by the
// caller (Completer does); this only checks its syntax.
func BuildProvenance(rec Record, in ProvenanceInput) ([]byte, error) {
	if err := rec.validate(); err != nil {
		return nil, fmt.Errorf("publication record: %w", err)
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	type dep struct {
		Name   string            `json:"name"`
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest,omitempty"`
	}
	deps := []dep{
		{Name: materialSource, URI: "git+" + rec.Source.Repository, Digest: map[string]string{"gitCommit": rec.Source.Commit}},
		{
			Name:   materialDefinition,
			URI:    "git+" + rec.Source.Repository + "@" + rec.Source.Commit + "#" + rec.Definition.Path,
			Digest: map[string]string{"sha256": rec.Definition.SHA256},
		},
		{Name: materialContent, URI: "bundle-content:" + rec.Name + "@" + rec.Version, Digest: map[string]string{"sha256": strings.TrimPrefix(rec.ContentDigest, "sha256:")}},
	}
	for _, f := range rec.Tests.Files {
		deps = append(deps, dep{Name: materialTest, URI: "bundle-file:" + f.Path, Digest: map[string]string{"sha256": f.SHA256}})
	}
	seen := map[string]bool{}
	for _, t := range append(append([]Tool(nil), rec.Tools...), in.SigningTools...) {
		uri := ToolURI(t)
		if seen[uri] {
			continue
		}
		seen[uri] = true
		deps = append(deps, dep{Name: materialTool, URI: uri})
	}
	for _, d := range deps {
		if len(d.URI) > maxProvenanceString || !uriText.MatchString(d.URI) {
			return nil, fmt.Errorf("provenance material %s %q is not a printable URI of at most %d bytes", d.Name, d.URI, maxProvenanceString)
		}
	}

	type metadata struct {
		InvocationID string `json:"invocationId,omitempty"`
	}
	var p struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				Bundle struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"bundle"`
				Source struct {
					Repository string `json:"repository"`
					Commit     string `json:"commit"`
				} `json:"source"`
			} `json:"externalParameters"`
			InternalParameters struct {
				Workflow *Workflow `json:"workflow,omitempty"`
				Builder  *struct {
					Revision string `json:"revision"`
				} `json:"builder,omitempty"`
			} `json:"internalParameters"`
			ResolvedDependencies []dep `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata *metadata `json:"metadata,omitempty"`
		} `json:"runDetails"`
	}
	bd := &p.BuildDefinition
	bd.BuildType = ProvenanceBuildType
	bd.ExternalParameters.Bundle.Name, bd.ExternalParameters.Bundle.Version = rec.Name, rec.Version
	bd.ExternalParameters.Source.Repository, bd.ExternalParameters.Source.Commit = rec.Source.Repository, rec.Source.Commit
	if in.BuilderRevision != "" {
		bd.InternalParameters.Builder = &struct {
			Revision string `json:"revision"`
		}{in.BuilderRevision}
	} else {
		w := in.Workflow
		bd.InternalParameters.Workflow = &w
	}
	bd.ResolvedDependencies = deps
	p.RunDetails.Builder.ID = in.Builder
	if in.InvocationID != "" {
		p.RunDetails.Metadata = &metadata{InvocationID: in.InvocationID}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (in ProvenanceInput) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	httpsText := func(what, v string) {
		if !strings.HasPrefix(v, "https://") || !printable.MatchString(v) {
			fail("%s %q must be an https URL of printable characters", what, v)
		}
	}
	httpsText("builder", in.Builder)
	gh, github := bundle.GitHubWorkflowBuilder(in.Builder)
	w := in.Workflow
	switch {
	case !github && w != (Workflow{}):
		fail("builder %q is not a GitHub Actions workflow: record its own revision (builder revision), not a workflow", in.Builder)
	case !github && (in.BuilderRevision == "" || !printable.MatchString(in.BuilderRevision)):
		fail("builder %q is not a GitHub Actions workflow: its provenance needs a printable builder revision", in.Builder)
	case github && in.BuilderRevision != "":
		fail("builder %q is a GitHub Actions workflow: record the workflow run, not a builder revision", in.Builder)
	case github:
		httpsText("workflow repository", w.Repository)
		if !workflowPath.MatchString(w.Path) || strings.Contains("/"+w.Path+"/", "/../") || strings.Contains("/"+w.Path+"/", "/./") {
			fail("workflow path %q must be a relative path inside the repository", w.Path)
		}
		if !commitHex.MatchString(w.Commit) {
			fail("workflow commit %q must be a full 40-character SHA", w.Commit)
		}
		if w.Ref != "" && !printable.MatchString(w.Ref) {
			fail("workflow ref %q is not printable", w.Ref)
		}
		if w.Repository != gh.Repository || w.Path != gh.Path || w.Ref != gh.Ref {
			fail("workflow %s %s@%s is not the builder's %s %s@%s", w.Repository, w.Path, w.Ref, gh.Repository, gh.Path, gh.Ref)
		}
	}
	if in.InvocationID != "" && !printable.MatchString(in.InvocationID) {
		fail("invocation ID %q is not printable", in.InvocationID)
	}
	for _, t := range in.SigningTools {
		if !printable.MatchString(t.Name) || !printable.MatchString(t.Version) {
			fail("signing tool %q %q needs a printable name and version", t.Name, t.Version)
		}
	}
	return errors.Join(errs...)
}

// ToolURI is the tool material URI of a recorded tool: a package URL for the
// tools a release uses, pkg:generic otherwise.
func ToolURI(t Tool) string {
	v := url.PathEscape(t.Version)
	switch t.Name {
	case "go":
		return "pkg:golang/go@" + url.PathEscape(strings.TrimPrefix(t.Version, "go"))
	case "cosign":
		return "pkg:github/sigstore/cosign@" + v
	case "kyverno":
		return "pkg:github/kyverno/kyverno@" + v
	}
	return "pkg:generic/" + url.PathEscape(t.Name) + "@" + v
}
