package publish

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// FixtureFile is the file name of a declarative policy fixture. Every
// directory of the payload holding one (with role "test") is run.
const FixtureFile = "kyverno-test.yaml"

// TestRunner runs declarative policy fixtures against an unpacked payload.
type TestRunner interface {
	// Name identifies the runner in the record, e.g. "kyverno test".
	Name() string
	// Version is the runner's version, recorded as a tool.
	Version(ctx context.Context) (string, error)
	// Run runs the fixtures in each of dirs (inside root) and returns an
	// error unless all of them ran and passed.
	Run(ctx context.Context, root string, dirs []string) error
}

// Kyverno runs `kyverno test --require-tests` from the pinned Devbox CLI.
type Kyverno struct {
	// Path to the kyverno executable; empty looks it up on PATH.
	Path string
}

func (k Kyverno) bin() (string, error) {
	if k.Path != "" {
		return k.Path, nil
	}
	return exec.LookPath("kyverno")
}

// Name implements TestRunner.
func (Kyverno) Name() string { return "kyverno test --require-tests" }

var (
	kyvernoVersion = regexp.MustCompile(`(?m)^Version: (v?[0-9][0-9A-Za-z.+-]*)\s*$`)
	kyvernoSummary = regexp.MustCompile(`(?m)^Test Summary: ([0-9]+) tests passed and ([0-9]+) tests failed\s*$`)
)

// Version implements TestRunner.
func (k Kyverno) Version(ctx context.Context) (string, error) {
	bin, err := k.bin()
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("kyverno version: %w", err)
	}
	m := kyvernoVersion.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("kyverno version: unrecognized output %q", out)
	}
	return string(m[1]), nil
}

// Run implements TestRunner. Each directory must report at least one passed
// and zero failed tests.
func (k Kyverno) Run(ctx context.Context, root string, dirs []string) error {
	bin, err := k.bin()
	if err != nil {
		return err
	}
	for _, d := range dirs {
		cmd := exec.CommandContext(ctx, bin, "test", d, "--require-tests", "--remove-color")
		cmd.Dir = root
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("kyverno test %s: %w\n%s", d, err, tail(out.String()))
		}
		m := kyvernoSummary.FindStringSubmatch(out.String())
		if m == nil || m[1] == "0" || m[2] != "0" {
			return fmt.Errorf("kyverno test %s did not report passing tests and no failures:\n%s", d, tail(out.String()))
		}
	}
	return nil
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 30 {
		lines = lines[len(lines)-30:]
	}
	return strings.Join(lines, "\n")
}

// FreezeInput is what Freeze cannot derive from the layout itself.
type FreezeInput struct {
	// DefinitionSHA256 is the SHA-256 (hex) of bundles/<name>/definition.json
	// at the source commit, read from Git by the caller.
	DefinitionSHA256 string
	// Tools that built the layout (for example the Go toolchain recorded in
	// package.json). The runner and its version are added.
	Tools []Tool
	// Runner runs the fixtures; nil uses Kyverno{}.
	Runner TestRunner
}

// Freeze runs the bundle's declarative policy fixtures against the unpacked
// layer of the verified layout in dir and, only when they pass, writes the
// publication record next to it. An existing record is never replaced. It
// returns the frozen bundle Publish takes.
func Freeze(ctx context.Context, dir string, in FreezeInput) (*Frozen, error) {
	if in.Runner == nil {
		in.Runner = Kyverno{}
	}
	recPath := filepath.Join(dir, RecordFile)
	if _, err := os.Lstat(recPath); err == nil {
		return nil, fmt.Errorf("%w: %s exists; a frozen record is never replaced", ErrFrozenInputs, recPath)
	}
	desc, manifestDigest, err := bundle.VerifyLayout(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	manifest, err := readBlob(dir, manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	layerDigest, _, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	layer, err := readBlob(dir, layerDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}

	var fixtures []FileDigest
	dirs := map[string]bool{}
	for _, f := range desc.Files {
		if f.Role == bundle.RoleTest && path.Base(f.Path) == FixtureFile {
			fixtures = append(fixtures, FileDigest{Path: f.Path, SHA256: f.SHA256})
			dirs[path.Dir(f.Path)] = true
		}
	}
	if len(fixtures) == 0 {
		return nil, fmt.Errorf("%w: the bundle has no declarative policy fixtures (%s with role %q)", ErrFrozenInputs, FixtureFile, bundle.RoleTest)
	}
	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].Path < fixtures[j].Path })

	// Run against the payload unpacked from the frozen layer, not the
	// source tree.
	_, payload, err := bundle.Unpack(layer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	root, err := os.MkdirTemp("", "bundle-freeze-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	for p, f := range payload {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, f.Data, 0o644); err != nil {
			return nil, err
		}
	}
	var runDirs []string
	for d := range dirs {
		runDirs = append(runDirs, filepath.FromSlash(d))
	}
	sort.Strings(runDirs)
	if err := in.Runner.Run(ctx, root, runDirs); err != nil {
		return nil, fmt.Errorf("policy fixtures failed against the frozen layer; not freezing: %w", err)
	}
	version, err := in.Runner.Version(ctx)
	if err != nil {
		return nil, err
	}

	tools := append([]Tool(nil), in.Tools...)
	tools = append(tools, Tool{Name: firstWord(in.Runner.Name()), Version: version})
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	rec := Record{
		Format: RecordFormat, Name: desc.Name, Version: desc.Version,
		Definition:     FileDigest{Path: "bundles/" + desc.Name + "/definition.json", SHA256: in.DefinitionSHA256},
		ManifestDigest: manifestDigest, LayerDigest: layerDigest, ContentDigest: desc.ContentDigest(),
		Tools: tools,
		Tests: Tests{Runner: in.Runner.Name(), Result: TestsPassed, Files: fixtures},
	}
	rec.Source.Repository, rec.Source.Commit = desc.Source.Repository, desc.Source.Revision
	f, err := newFrozen(manifest, layer, rec)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	fh, err := os.OpenFile(recPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	if _, err := fh.Write(f.RecordJSON); err != nil {
		fh.Close()
		return nil, err
	}
	if err := fh.Close(); err != nil {
		return nil, err
	}
	return f, nil
}

func firstWord(s string) string {
	w, _, _ := strings.Cut(s, " ")
	return w
}
