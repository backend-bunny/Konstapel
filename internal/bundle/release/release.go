// Package release validates an independent policy-bundle release request and
// creates or verifies its Git release tag.
//
// A bundle release is selected by a bundle name and a full, reviewed source
// commit on main. The version comes from bundles/<name>/definition.json in
// that commit, and the release is marked by the Git tag
// bundle/<name>/v<version>, a namespace separate from application vX.Y.Z tags.
// Nothing here reads the application VERSION file, Helm charts or
// release-please state. Tags are created once and never moved or deleted.
package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// TagPrefix starts every bundle release tag. Application releases use bare
// vX.Y.Z tags, so the two namespaces cannot overlap.
const TagPrefix = "bundle/"

var (
	// Bundle names are DNS labels: they become a directory, a Git tag segment
	// and an OCI repository path segment.
	namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// SemVer 2.0.0 without build metadata; pre-release identifiers follow the
	// SemVer rules (no empty identifiers, no leading zeros in numeric ones).
	versionPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(-(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	remotePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// maxVersionLen keeps the later OCI tag (at most 128 characters) and the Git
// tag comfortably bounded.
const maxVersionLen = 64

// ValidateName accepts a bundle name usable as a directory, tag segment and
// OCI repository segment.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("bundle name %q must be a DNS label (lowercase letters, digits and inner hyphens, at most 63 characters)", name)
	}
	return nil
}

// ValidateVersion accepts the version a bundle definition may release.
// Pre-release versions (1.0.0-rc.1) are allowed. Build metadata (1.0.0+x) is
// rejected: SemVer ignores it for precedence, so two such releases would be
// the same version with different bytes, and OCI tags cannot contain '+'.
func ValidateVersion(v string) error {
	switch {
	case strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V"):
		return fmt.Errorf("version %q must not start with %q: the definition holds bare SemVer and the tag adds the v", v, v[:1])
	case strings.Contains(v, "+"):
		return fmt.Errorf("version %q has build metadata, which bundle releases do not allow", v)
	case len(v) > maxVersionLen:
		return fmt.Errorf("version %q is longer than %d characters", v, maxVersionLen)
	case !versionPattern.MatchString(v):
		return fmt.Errorf("version %q is not SemVer MAJOR.MINOR.PATCH[-PRERELEASE]", v)
	}
	return nil
}

// TagName is the Git release tag for a validated name and version.
func TagName(name, version string) string {
	return TagPrefix + name + "/v" + version
}

// Request selects a release: a bundle and the reviewed commit it is built from.
type Request struct {
	Name   string
	Commit string
	// MainRef is the fully qualified ref holding reviewed main history,
	// normally refs/remotes/origin/main.
	MainRef string
	// Version, when set, is the version the caller already packaged; the
	// commit's definition must declare exactly it.
	Version string
}

// Release is a validated request with the version declared at its commit.
type Release struct {
	Name    string
	Version string
	Commit  string
	Tag     string
}

// Result is the outcome of one git invocation.
type Result struct {
	Stdout, Stderr string
	// Code is git's exit status. A non-zero code is an answer ("no such
	// object", "not an ancestor"), not a failure to ask.
	Code int
}

// Git runs git in one repository. Implementations return an error only when
// git could not be run at all.
type Git interface {
	Run(ctx context.Context, args ...string) (Result, error)
}

// ExecGit runs the git executable in Dir.
type ExecGit struct{ Dir string }

// Run implements Git.
func (g ExecGit) Run(ctx context.Context, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", g.Dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errOut.String()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		res.Code = exit.ExitCode()
		return res, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return res, nil
}

// git runs a command that must succeed and returns its standard output.
func git(ctx context.Context, g Git, args ...string) (string, error) {
	res, err := g.Run(ctx, args...)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("git %s: exit status %d: %s", strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

// resolveCommit returns the commit a revision names, or "" when it does not
// name one in this repository.
func resolveCommit(ctx context.Context, g Git, rev string) (string, error) {
	res, err := g.Run(ctx, "rev-parse", "--verify", "--quiet", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", nil
	}
	return strings.TrimSpace(res.Stdout), nil
}

// Validate checks a release request against the repository without changing
// it: the name, the commit's presence and ancestry on MainRef, the bundle
// definition and version at that commit, the tag syntax, and any local tag
// already marking this version.
func Validate(ctx context.Context, g Git, req Request) (Release, error) {
	if err := ValidateName(req.Name); err != nil {
		return Release{}, err
	}
	if !commitPattern.MatchString(req.Commit) {
		return Release{}, fmt.Errorf("source commit %q must be a full 40-character lowercase hexadecimal SHA, not a branch, tag or abbreviation", req.Commit)
	}
	if !strings.HasPrefix(req.MainRef, "refs/") {
		return Release{}, fmt.Errorf("main ref %q must be fully qualified (refs/...)", req.MainRef)
	}
	got, err := resolveCommit(ctx, g, req.Commit)
	if err != nil {
		return Release{}, err
	}
	if got != req.Commit {
		return Release{}, fmt.Errorf("source commit %s is not a commit in this repository (is the history fetched?)", req.Commit)
	}
	main, err := resolveCommit(ctx, g, req.MainRef)
	if err != nil {
		return Release{}, err
	}
	if main == "" {
		return Release{}, fmt.Errorf("main ref %s does not exist", req.MainRef)
	}
	res, err := g.Run(ctx, "merge-base", "--is-ancestor", req.Commit, main)
	switch {
	case err != nil:
		return Release{}, err
	case res.Code == 1:
		return Release{}, fmt.Errorf("source commit %s is not on reviewed main history (not an ancestor of %s at %s)", req.Commit, req.MainRef, main)
	case res.Code != 0:
		return Release{}, fmt.Errorf("git merge-base --is-ancestor: exit status %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}

	dir := path.Join("bundles", req.Name)
	kind, err := g.Run(ctx, "cat-file", "-t", req.Commit+":"+dir)
	if err != nil {
		return Release{}, err
	}
	if kind.Code != 0 || strings.TrimSpace(kind.Stdout) != "tree" {
		return Release{}, fmt.Errorf("source commit %s has no bundle directory %s", req.Commit, dir)
	}
	raw, err := g.Run(ctx, "cat-file", "blob", req.Commit+":"+dir+"/definition.json")
	if err != nil {
		return Release{}, err
	}
	if raw.Code != 0 {
		return Release{}, fmt.Errorf("source commit %s has no %s/definition.json", req.Commit, dir)
	}
	def, err := bundle.LoadDefinition([]byte(raw.Stdout))
	if err != nil {
		return Release{}, fmt.Errorf("%s/definition.json at %s: %w", dir, req.Commit, err)
	}
	if def.Name != req.Name {
		return Release{}, fmt.Errorf("%s/definition.json at %s names %q; the directory and name must match", dir, req.Commit, def.Name)
	}
	if err := ValidateVersion(def.Version); err != nil {
		return Release{}, fmt.Errorf("%s/definition.json at %s: %w", dir, req.Commit, err)
	}
	if req.Version != "" && req.Version != def.Version {
		return Release{}, fmt.Errorf("%s/definition.json at %s declares version %s, but %s was packaged", dir, req.Commit, def.Version, req.Version)
	}
	rel := Release{Name: req.Name, Version: def.Version, Commit: req.Commit, Tag: TagName(req.Name, def.Version)}
	if _, err := git(ctx, g, "check-ref-format", "refs/tags/"+rel.Tag); err != nil {
		return Release{}, fmt.Errorf("tag %s is not a valid Git ref: %w", rel.Tag, err)
	}
	local, err := resolveCommit(ctx, g, "refs/tags/"+rel.Tag)
	if err != nil {
		return Release{}, err
	}
	if local != "" && local != rel.Commit {
		return Release{}, fmt.Errorf("tag %s already marks %s, not %s; a released version is never moved", rel.Tag, local, rel.Commit)
	}
	return rel, nil
}

// TagState reports what EnsureTag found.
type TagState string

const (
	// TagCreated: the tag did not exist and now points at the source commit.
	TagCreated TagState = "created"
	// TagExisting: the tag already pointed at the source commit (a retry).
	TagExisting TagState = "existing"
)

// remoteTags lists the remote's tags, peeled to the commits they mark.
func remoteTags(ctx context.Context, g Git, remote string) (map[string]string, error) {
	out, err := git(ctx, g, "ls-remote", "--tags", remote)
	if err != nil {
		return nil, fmt.Errorf("list tags on %s: %w", remote, err)
	}
	tags := map[string]string{}
	peeled := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		sha, ref, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasPrefix(ref, "refs/tags/") {
			return nil, fmt.Errorf("unexpected ls-remote line %q", line)
		}
		name := strings.TrimPrefix(ref, "refs/tags/")
		if base, ok := strings.CutSuffix(name, "^{}"); ok {
			peeled[base] = sha
		} else {
			tags[name] = sha
		}
	}
	for name, sha := range peeled {
		tags[name] = sha // an annotated tag marks the commit it peels to
	}
	return tags, nil
}

// checkRemote reports whether the remote already has the release tag and
// rejects a tag at another commit or a ref that blocks creating it.
func checkRemote(tags map[string]string, rel Release) (bool, error) {
	for name, sha := range tags {
		switch {
		case name == rel.Tag && sha == rel.Commit:
			return true, nil
		case name == rel.Tag:
			return false, fmt.Errorf("remote tag %s already marks %s, not %s; a released version is never moved", rel.Tag, sha, rel.Commit)
		case strings.HasPrefix(rel.Tag, name+"/"), strings.HasPrefix(name, rel.Tag+"/"):
			return false, fmt.Errorf("remote tag %s occupies the bundle tag namespace and blocks %s", name, rel.Tag)
		}
	}
	return false, nil
}

// EnsureTag creates the release tag on the remote, or verifies an existing
// one, after re-validating the request. An existing tag must mark exactly the
// source commit; it is never moved, replaced or deleted. The push is not
// forced, so a tag created concurrently elsewhere is never overwritten.
func EnsureTag(ctx context.Context, g Git, req Request, remote string) (Release, TagState, error) {
	if !remotePattern.MatchString(remote) {
		return Release{}, "", fmt.Errorf("remote %q must be a configured remote name", remote)
	}
	rel, err := Validate(ctx, g, req)
	if err != nil {
		return Release{}, "", err
	}
	tags, err := remoteTags(ctx, g, remote)
	if err != nil {
		return Release{}, "", err
	}
	if exists, err := checkRemote(tags, rel); err != nil || exists {
		return rel, TagExisting, err
	}
	// Never --force: an existing remote tag makes the push fail, not move.
	push, err := g.Run(ctx, "push", "--no-verify", "--porcelain", remote, rel.Commit+":refs/tags/"+rel.Tag)
	if err != nil {
		return Release{}, "", err
	}
	// Read back what the remote now holds, whether or not the push won.
	if tags, err = remoteTags(ctx, g, remote); err != nil {
		return Release{}, "", err
	}
	exists, err := checkRemote(tags, rel)
	switch {
	case err != nil:
		return Release{}, "", err
	case !exists:
		return Release{}, "", fmt.Errorf("push of %s exited %d and the remote does not hold it: %s", rel.Tag, push.Code, strings.TrimSpace(push.Stderr))
	case push.Code != 0:
		return rel, TagExisting, nil // created concurrently at the same commit
	}
	return rel, TagCreated, nil
}

// VerifyPackage checks that a frozen bundle layout, as written by
// scripts/bundles/package.sh, holds exactly this release: a verified OCI
// layout whose descriptor and package record name the release's bundle,
// version and source commit. It returns the manifest digest.
func VerifyPackage(dir string, rel Release) (string, error) {
	desc, digest, err := bundle.VerifyLayout(dir)
	if err != nil {
		return "", fmt.Errorf("frozen layout: %w", err)
	}
	if desc.Name != rel.Name || desc.Version != rel.Version || desc.Source.Revision != rel.Commit {
		return "", fmt.Errorf("frozen layout is %s@%s from %s, want %s@%s from %s",
			desc.Name, desc.Version, desc.Source.Revision, rel.Name, rel.Version, rel.Commit)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return "", err
	}
	rec, err := parseRecord(raw)
	if err != nil {
		return "", err
	}
	if rec.Name != rel.Name || rec.Version != rel.Version || rec.Source.Revision != rel.Commit || rec.ManifestDigest != digest {
		return "", fmt.Errorf("package.json (%s@%s from %s, %s) does not match the verified layout (%s@%s from %s, %s)",
			rec.Name, rec.Version, rec.Source.Revision, rec.ManifestDigest, rel.Name, rel.Version, rel.Commit, digest)
	}
	return digest, nil
}

// record is the part of package.json that identifies a frozen package.
type record struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Revision string `json:"revision"`
	} `json:"source"`
	ManifestDigest string `json:"manifestDigest"`
}

func parseRecord(raw []byte) (record, error) {
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return record{}, fmt.Errorf("package.json: %w", err)
	}
	return rec, nil
}
