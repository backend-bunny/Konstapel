package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrReleaseDraft: a draft release already exists for the tag. Drafts are
	// never published or edited; resolve it by hand.
	ErrReleaseDraft = errors.New("a draft release exists for the tag")
	// ErrReleaseTag: the tag is not the bundle release tag for this version.
	ErrReleaseTag = errors.New("not a bundle release tag")
)

// GitHubRelease is the part of a GitHub release the bundle release manages.
type GitHubRelease struct {
	Title      string `json:"name"`
	Body       string `json:"body"`
	Prerelease bool   `json:"isPrerelease"`
	Draft      bool   `json:"isDraft"`
}

// Releases is the GitHub releases surface EnsureRelease needs.
type Releases interface {
	// Get returns the release for tag, or nil, nil when there is none.
	Get(ctx context.Context, tag string) (*GitHubRelease, error)
	// Create makes a release for an existing tag. It never moves the tag and
	// never becomes the repository's "latest" release.
	Create(ctx context.Context, tag string, r GitHubRelease) error
	// Edit updates an existing release's title, notes and pre-release flag.
	Edit(ctx context.Context, tag string, r GitHubRelease) error
}

// EnsureOutcome is what EnsureRelease did.
type EnsureOutcome string

const (
	ReleaseCreated   EnsureOutcome = "created"
	ReleaseUpdated   EnsureOutcome = "updated"
	ReleaseUnchanged EnsureOutcome = "unchanged"
)

// ReleaseSpec returns the GitHub release a verified bundle release is
// announced with. Versions with a pre-release part are marked as such.
func ReleaseSpec(name, version, notes string) (tag string, r GitHubRelease, err error) {
	if err := ValidateName(name); err != nil {
		return "", r, err
	}
	if err := ValidateVersion(version); err != nil {
		return "", r, err
	}
	if strings.TrimSpace(notes) == "" {
		return "", r, errors.New("release notes are empty")
	}
	return TagName(name, version), GitHubRelease{Title: name + " " + version, Body: notes, Prerelease: strings.Contains(version, "-")}, nil
}

// EnsureRelease makes the GitHub release for a verified bundle release match
// want: created when absent, updated when its title, notes or pre-release flag
// differ, and left alone when identical, so repeated runs write nothing. A
// draft is refused. The caller must only call it for a complete release.
func EnsureRelease(ctx context.Context, g Releases, name, version, notes string) (EnsureOutcome, error) {
	tag, want, err := ReleaseSpec(name, version, notes)
	if err != nil {
		return "", err
	}
	have, err := g.Get(ctx, tag)
	if err != nil {
		return "", fmt.Errorf("read release %s: %w", tag, err)
	}
	switch {
	case have == nil:
		if err := g.Create(ctx, tag, want); err != nil {
			return "", fmt.Errorf("create release %s: %w", tag, err)
		}
		return ReleaseCreated, nil
	case have.Draft:
		return "", fmt.Errorf("%w %s", ErrReleaseDraft, tag)
	case have.Title == want.Title && strings.TrimSpace(have.Body) == strings.TrimSpace(want.Body) && have.Prerelease == want.Prerelease:
		return ReleaseUnchanged, nil
	}
	if err := g.Edit(ctx, tag, want); err != nil {
		return "", fmt.Errorf("update release %s: %w", tag, err)
	}
	return ReleaseUpdated, nil
}

// Runner runs one command with exactly the given environment.
type Runner func(ctx context.Context, bin string, args []string, env []string) (stdout []byte, exit int, err error)

// GH implements Releases through the GitHub CLI. The notes go through a
// private temporary file and the token only through the environment: neither
// is ever an argument. Everything else in the environment is dropped.
type GH struct {
	// Repo is OWNER/REPO.
	Repo string
	// Token is passed as GH_TOKEN.
	Token string
	// Bin is the gh executable (default "gh").
	Bin string
	// Run runs it (default: os/exec).
	Run Runner
}

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func (g *GH) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "gh"
}

func (g *GH) run(ctx context.Context, home string, args ...string) ([]byte, int, error) {
	if !repoPattern.MatchString(g.Repo) {
		return nil, 0, fmt.Errorf("repository %q is not OWNER/REPO", g.Repo)
	}
	if g.Token == "" {
		return nil, 0, errors.New("a GitHub token is required (GH_TOKEN)")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GH_TOKEN=" + g.Token, "GH_PROMPT_DISABLED=1", "NO_COLOR=1", "GH_NO_UPDATE_NOTIFIER=1"}
	run := g.Run
	if run == nil {
		run = execRun
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, exit, err := run(ctx, g.bin(), args, env)
	if err != nil {
		return out, exit, g.redact(err)
	}
	return out, exit, nil
}

func (g *GH) redact(err error) error {
	if err == nil || g.Token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), g.Token, "[REDACTED]"))
}

func execRun(ctx context.Context, bin string, args []string, env []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// The message is gh's own and may name the tag; it carries no token.
		return stderr.Bytes(), ee.ExitCode(), fmt.Errorf("%s exited %d: %s", filepath.Base(bin), ee.ExitCode(), strings.TrimSpace(stderr.String()))
	}
	return nil, -1, err
}

func checkTag(tag string) error {
	if !strings.HasPrefix(tag, TagPrefix) || strings.ContainsAny(tag, " \t\r\n\\'\"`$") || strings.Contains(tag, "..") {
		return fmt.Errorf("%w: %q", ErrReleaseTag, tag)
	}
	return nil
}

// Get implements Releases.
func (g *GH) Get(ctx context.Context, tag string) (*GitHubRelease, error) {
	if err := checkTag(tag); err != nil {
		return nil, err
	}
	home, cleanup, err := privateDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	out, exit, err := g.run(ctx, home, "release", "view", tag, "--repo", g.Repo, "--json", "name,body,isPrerelease,isDraft")
	if err != nil {
		if exit == 1 && strings.Contains(err.Error(), "release not found") {
			return nil, nil
		}
		return nil, err
	}
	var r GitHubRelease
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &r, nil
}

// Create implements Releases. --verify-tag refuses to create the tag as a
// side effect; --latest=false keeps application releases the latest release.
func (g *GH) Create(ctx context.Context, tag string, r GitHubRelease) error {
	args := []string{"release", "create", tag, "--repo", g.Repo, "--verify-tag", "--latest=false", "--title", r.Title}
	if r.Prerelease {
		args = append(args, "--prerelease")
	}
	return g.write(ctx, tag, r, args)
}

// Edit implements Releases.
func (g *GH) Edit(ctx context.Context, tag string, r GitHubRelease) error {
	args := []string{"release", "edit", tag, "--repo", g.Repo, "--latest=false", "--title", r.Title, fmt.Sprintf("--prerelease=%t", r.Prerelease)}
	return g.write(ctx, tag, r, args)
}

func (g *GH) write(ctx context.Context, tag string, r GitHubRelease, args []string) error {
	if err := checkTag(tag); err != nil {
		return err
	}
	home, cleanup, err := privateDir()
	if err != nil {
		return err
	}
	defer cleanup()
	notes := filepath.Join(home, "notes.md")
	if err := os.WriteFile(notes, []byte(r.Body), 0o600); err != nil {
		return err
	}
	_, _, err = g.run(ctx, home, append(args, "--notes-file", notes)...)
	return err
}

func privateDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "bundlerelease-gh-*")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}
