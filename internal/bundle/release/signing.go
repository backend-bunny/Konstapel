package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
)

// The official publisher. bundles/official-sources.yaml is the checked-in
// central source configuration for official bundles; its rules must name
// exactly this workflow identity (a test enforces it), and the release
// workflow signs and verifies against that file as it is on main.
const (
	OfficialRepositoryURL = "https://github.com/backend-bunny/Konstapel"
	OfficialWorkflowPath  = ".github/workflows/bundle-release.yml"
	OfficialWorkflowRef   = "refs/heads/main"
	// GitHubIssuer is the OIDC issuer of GitHub Actions tokens.
	GitHubIssuer = bundle.GitHubActionsIssuer
	// OfficialSourcesFile is the official central source configuration,
	// relative to the repository root.
	OfficialSourcesFile = "bundles/official-sources.yaml"
	// OfficialRegistry is the repository prefix of official bundles.
	OfficialRegistry = "ghcr.io/backend-bunny/bundles"
)

// OfficialIdentity is the keyless certificate identity of the release
// workflow on main, and the provenance builder of official bundles.
func OfficialIdentity() string {
	return OfficialRepositoryURL + "/" + OfficialWorkflowPath + "@" + OfficialWorkflowRef
}

// Run is the pipeline run that signs: its build record (recorded in
// provenance apart from the content source: the GitHub Actions workflow
// revision for a workflow builder, otherwise the builder's own revision), the
// keyless identity its OIDC token carries, and an invocation ID.
type Run struct {
	Workflow        publish.Workflow
	BuilderRevision string
	// Identity is the certificate identity Fulcio issues for this run's
	// token (<server>/<GITHUB_WORKFLOW_REF>); empty outside GitHub Actions.
	Identity     string
	InvocationID string
}

var (
	ownerRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)
	numeric   = regexp.MustCompile(`^[0-9]{1,20}$`)
	serverURL = regexp.MustCompile(`^https://[a-z0-9.-]+(:[0-9]{1,5})?$`)
)

// RunFromGitHub reads the workflow run from GitHub Actions' default
// environment through getenv (os.Getenv in the tool, a map in tests):
// GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_WORKFLOW_REF (owner/repo/
// path@ref), GITHUB_REF (must equal that ref), GITHUB_SHA (the workflow
// revision that runs, which may be newer than the source commit),
// GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT.
func RunFromGitHub(getenv func(string) string) (Run, error) {
	server, repo, wref := getenv("GITHUB_SERVER_URL"), getenv("GITHUB_REPOSITORY"), getenv("GITHUB_WORKFLOW_REF")
	sha, ref := getenv("GITHUB_SHA"), getenv("GITHUB_REF")
	var errs []error
	if !serverURL.MatchString(server) {
		errs = append(errs, fmt.Errorf("GITHUB_SERVER_URL %q is not an https origin", server))
	}
	if !ownerRepo.MatchString(repo) {
		errs = append(errs, fmt.Errorf("GITHUB_REPOSITORY %q is not owner/name", repo))
	}
	rest, ok := strings.CutPrefix(wref, repo+"/")
	path, wfRef, ok2 := strings.Cut(rest, "@")
	if !ok || !ok2 || path == "" || wfRef == "" {
		errs = append(errs, fmt.Errorf("GITHUB_WORKFLOW_REF %q is not %s/<path>@<ref>", wref, repo))
	} else if ref != wfRef {
		errs = append(errs, fmt.Errorf("GITHUB_REF %q differs from the workflow ref %q", ref, wfRef))
	}
	if !commitPattern.MatchString(sha) {
		errs = append(errs, fmt.Errorf("GITHUB_SHA %q is not a full commit", sha))
	}
	if err := errors.Join(errs...); err != nil {
		return Run{}, err
	}
	r := Run{
		Workflow: publish.Workflow{Repository: server + "/" + repo, Path: path, Ref: wfRef, Commit: sha},
		Identity: server + "/" + wref,
	}
	if id, n := getenv("GITHUB_RUN_ID"), getenv("GITHUB_RUN_ATTEMPT"); numeric.MatchString(id) && numeric.MatchString(n) {
		r.InvocationID = server + "/" + repo + "/actions/runs/" + id + "/attempts/" + n
	}
	return r, nil
}

// ErrSigningRule: the configured publisher rule and the signing run do not
// fit together, so proofs made now could never verify under the rule.
var ErrSigningRule = errors.New("the publisher rule does not match this signing run")

// CheckSigningRule refuses to sign unless proofs made by this run will be
// judged by src's rule as intended. Keyless: the rule's identity must be
// the run's certificate identity and also its provenance builder (the
// builder is the signing workflow), and the issuer GitHub's. Key: the rule
// must be a public-key rule. Either way the rule must allow the record's
// source repository.
func CheckSigningRule(src bundle.BundleSource, keyless bool, run Run, rec publish.Record) error {
	if err := src.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrSigningRule, err)
	}
	p := src.Publisher
	var errs []error
	if keyless {
		switch {
		case p.Type != bundle.SignerKeyless:
			errs = append(errs, fmt.Errorf("keyless signing, but the rule for %s is %q", src.Name, p.Type))
		case p.Issuer != GitHubIssuer:
			errs = append(errs, fmt.Errorf("rule issuer %q is not %q", p.Issuer, GitHubIssuer))
		case p.Identity != run.Identity:
			errs = append(errs, fmt.Errorf("this run signs as %q, the rule requires %q", run.Identity, p.Identity))
		case p.Provenance.Builder != p.Identity:
			errs = append(errs, fmt.Errorf("rule builder %q differs from its signing identity %q", p.Provenance.Builder, p.Identity))
		}
	} else if p.Type != bundle.SignerPublicKey {
		errs = append(errs, fmt.Errorf("key signing, but the rule for %s is %q", src.Name, p.Type))
	}
	if p.Provenance.SourceRepository != rec.Source.Repository {
		errs = append(errs, fmt.Errorf("the bundle's source %q is not the rule's %q", rec.Source.Repository, p.Provenance.SourceRepository))
	}
	if src.Name != rec.Name {
		errs = append(errs, fmt.Errorf("rule %q selected for bundle %q", src.Name, rec.Name))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrSigningRule, err)
	}
	return nil
}

// LoadSources reads a central source configuration file (bounded, strict).
func LoadSources(path string) (bundle.Sources, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return bundle.Sources{}, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return bundle.Sources{}, fmt.Errorf("%s must be a regular file of at most 1 MiB", path)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return bundle.Sources{}, err
	}
	s, err := bundle.ParseSources(raw)
	if err != nil {
		return bundle.Sources{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}
