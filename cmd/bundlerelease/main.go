// Command bundlerelease validates an independent policy-bundle release,
// creates or verifies its bundle/<name>/vX.Y.Z Git tag, freezes the tested
// package and publishes it write-once. It is a build tool run by
// .github/workflows/bundle-release.yml; it is not part of the shipped image.
//
//	bundlerelease verify  -name NAME -commit SHA [-main REF] [-package DIR]
//	bundlerelease freeze  -name NAME -commit SHA -package DIR [-main REF]
//	bundlerelease tag     -name NAME -commit SHA -version V [-main REF] [-remote NAME]
//	bundlerelease publish -name NAME -commit SHA -version V -package DIR -out FILE
//	                      [-registry PREFIX] [-defer-proofs] [-main REF]
//
// verify is read-only. It prints name, version, commit and tag (and digest
// when -package is given) as key=value lines for $GITHUB_OUTPUT; with
// -package the layout must also carry a publication record bound to it.
// freeze runs the package's declarative policy fixtures (kyverno test) against
// the unpacked frozen layer and writes the publication record. tag
// re-validates, requires the packaged version, then creates the tag on the
// remote or verifies that it already marks the same commit. publish requires
// that tag, re-verifies the frozen package and publishes it to
// PREFIX/NAME:VERSION write-once, reading it back anonymously. The registry
// credential comes only from the environment (BUNDLE_REGISTRY_USERNAME,
// BUNDLE_REGISTRY_PASSWORD), never from a flag, and is never printed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/release"
)

// DefaultRegistry is where official bundles are published.
const DefaultRegistry = "ghcr.io/backend-bunny/bundles"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bundlerelease:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	cmds := map[string]bool{"verify": true, "tag": true, "freeze": true, "publish": true}
	if len(args) == 0 || !cmds[args[0]] {
		return fmt.Errorf("usage: bundlerelease verify|freeze|tag|publish -name NAME -commit SHA ...")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	repo := fs.String("repo", ".", "repository checkout with reviewed main history and tags fetched")
	name := fs.String("name", "", "bundle name (directory under bundles/)")
	commit := fs.String("commit", "", "full reviewed source commit on main")
	mainRef := fs.String("main", "refs/remotes/origin/main", "fully qualified ref of reviewed main history")
	pkg := fs.String("package", "", "frozen layout written by scripts/bundles/package.sh")
	version := fs.String("version", "", "tag, publish: the version that was packaged")
	remote := fs.String("remote", "origin", "tag: remote that holds release tags")
	registryPrefix := fs.String("registry", DefaultRegistry, "publish: repository prefix; the bundle is pushed to PREFIX/NAME")
	out := fs.String("out", "", "publish: new file for the publication record of this run")
	deferProofs := fs.Bool("defer-proofs", false, "publish: succeed although required proofs are missing (a later step adds them)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	g := release.ExecGit{Dir: *repo}
	req := release.Request{Name: *name, Commit: *commit, MainRef: *mainRef}

	switch args[0] {
	case "verify":
		rel, err := release.Validate(ctx, g, req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "name=%s\nversion=%s\ncommit=%s\ntag=%s\n", rel.Name, rel.Version, rel.Commit, rel.Tag)
		if *pkg != "" {
			f, err := verifyFrozen(*pkg, rel)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "digest=%s\n", f.ManifestDigest)
		}
		return nil
	case "freeze":
		return freeze(ctx, g, req, *pkg, stdout)
	case "tag":
		if *version == "" {
			return fmt.Errorf("tag requires -version, the version that was packaged")
		}
		req.Version = *version
		rel, state, err := release.EnsureTag(ctx, g, req, *remote)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "tag=%s\ncommit=%s\nstate=%s\n", rel.Tag, rel.Commit, state)
		return nil
	}
	if *version == "" || *pkg == "" || *out == "" {
		return fmt.Errorf("publish requires -version, -package and -out")
	}
	req.Version = *version
	return publishRelease(ctx, g, req, *pkg, *registryPrefix, *out, *deferProofs, stdout)
}

// verifyFrozen checks the layout, its package record and its publication
// record against the validated release.
func verifyFrozen(dir string, rel release.Release) (*publish.Frozen, error) {
	digest, err := release.VerifyPackage(dir, rel)
	if err != nil {
		return nil, err
	}
	f, err := publish.Load(dir)
	if err != nil {
		return nil, err
	}
	if f.ManifestDigest != digest {
		return nil, fmt.Errorf("%w: record names %s, layout %s", publish.ErrFrozenInputs, f.ManifestDigest, digest)
	}
	if f.Record.Definition.SHA256 != rel.DefinitionSHA256 {
		return nil, fmt.Errorf("%w: the record's definition digest %s is not bundles/%s/definition.json at %s (%s)",
			publish.ErrFrozenInputs, f.Record.Definition.SHA256, rel.Name, rel.Commit, rel.DefinitionSHA256)
	}
	return f, nil
}

func freeze(ctx context.Context, g release.Git, req release.Request, dir string, stdout io.Writer) error {
	if dir == "" {
		return fmt.Errorf("freeze requires -package")
	}
	rel, err := release.Validate(ctx, g, req)
	if err != nil {
		return err
	}
	if _, err := release.VerifyPackage(dir, rel); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return err
	}
	var pj struct {
		Tools map[string]string `json:"tools"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return fmt.Errorf("package.json: %w", err)
	}
	if pj.Tools["go"] == "" {
		return fmt.Errorf("package.json records no Go toolchain")
	}
	f, err := publish.Freeze(ctx, dir, publish.FreezeInput{
		DefinitionSHA256: rel.DefinitionSHA256,
		Tools:            []publish.Tool{{Name: "go", Version: pj.Tools["go"]}},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "digest=%s\ncontent=%s\ntests=%d\n", f.ManifestDigest, f.Record.ContentDigest, len(f.Record.Tests.Files))
	return nil
}

// envCredential reads the registry credential from the environment and
// removes it, so no child process inherits it.
func envCredential() (registry.Credential, error) {
	c := registry.Credential{Username: os.Getenv("BUNDLE_REGISTRY_USERNAME"), Password: os.Getenv("BUNDLE_REGISTRY_PASSWORD")}
	os.Unsetenv("BUNDLE_REGISTRY_PASSWORD")
	os.Unsetenv("BUNDLE_REGISTRY_USERNAME")
	if c.Username == "" || c.Password == "" {
		return registry.Credential{}, fmt.Errorf("BUNDLE_REGISTRY_USERNAME and BUNDLE_REGISTRY_PASSWORD must be set")
	}
	return c, nil
}

// hostCredential answers only for the publishing registry's host.
type hostCredential struct {
	host string
	cred registry.Credential
}

func (h hostCredential) Credential(_ context.Context, _ bundle.BundleSource, host string) (registry.Credential, error) {
	if host != h.host {
		return registry.Credential{}, fmt.Errorf("no credential for %s", host)
	}
	return h.cred, nil
}

// publication is the bounded record of one run: the result plus the
// workflow run that produced it, recorded separately from the source.
type publication struct {
	Format   string            `json:"format"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Source   string            `json:"sourceCommit"`
	Status   string            `json:"status"`
	Error    string            `json:"error,omitempty"`
	Result   *publish.Result   `json:"result,omitempty"`
	Workflow map[string]string `json:"workflow,omitempty"`
	At       string            `json:"recordedAt"`
}

const maxPublicationBytes = 64 << 10

func publishRelease(ctx context.Context, g release.Git, req release.Request, dir, prefix, out string, deferProofs bool, stdout io.Writer) error {
	rel, err := release.Validate(ctx, g, req)
	if err != nil {
		return err
	}
	if err := release.RequireTag(ctx, g, rel); err != nil {
		return err
	}
	f, err := verifyFrozen(dir, rel)
	if err != nil {
		return err
	}
	cred, err := envCredential()
	if err != nil {
		return err
	}
	repository := strings.TrimSuffix(prefix, "/") + "/" + rel.Name
	host, _, _ := strings.Cut(repository, "/")
	writer, err := registry.NewClient(registry.Options{Credentials: hostCredential{host: host, cred: cred}})
	if err != nil {
		return err
	}
	// The reader has no credentials: read-back proves anonymous access, the
	// consumer contract for the official registry.
	reader, err := registry.NewClient(registry.Options{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	res, perr := publish.Publish(ctx, f, publish.Target{Repository: repository, Writer: writer, Reader: reader})

	rec := publication{
		Format: "konstapel.policy.bundle.publication-run/v1", Name: rel.Name, Version: rel.Version, Source: rel.Commit,
		Result: res, Workflow: workflowEnv(), At: time.Now().UTC().Format(time.RFC3339),
	}
	switch {
	case perr != nil:
		rec.Status, rec.Error = "failed", perr.Error()
	case res.Complete:
		rec.Status = "complete"
	default:
		rec.Status = "incomplete: missing " + joinKinds(res.Missing)
	}
	if err := writeNew(out, rec); err != nil {
		return errors.Join(perr, err)
	}
	if perr != nil {
		return perr
	}
	fmt.Fprintf(stdout, "repository=%s\ntag=%s\ndigest=%s\noutcome=%s\nrecovered=%t\nrecord=%s\nmissing=%s\nstatus=%s\n",
		res.Repository, res.Tag, res.Digest, res.Outcome, res.Recovered, res.RecordDigest, joinKinds(res.Missing), rec.Status)
	if !res.Complete && !deferProofs {
		return fmt.Errorf("published %s@%s, but required proofs are missing: %s", repository, res.Digest, joinKinds(res.Missing))
	}
	return nil
}

func joinKinds(ks []registry.ProofKind) string {
	s := make([]string, len(ks))
	for i, k := range ks {
		s[i] = string(k)
	}
	return strings.Join(s, ",")
}

// workflowEnv records the run that published, separately from the source.
func workflowEnv() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SERVER_URL"} {
		if v := os.Getenv(k); v != "" && len(v) <= 512 {
			m[k] = v
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// writeNew writes v as JSON to a new file of bounded size.
func writeNew(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxPublicationBytes {
		return fmt.Errorf("publication record is %d bytes, limit %d", len(b), maxPublicationBytes)
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.Write(append(b, '\n')); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
