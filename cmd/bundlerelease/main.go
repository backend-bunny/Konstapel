// Command bundlerelease validates an independent policy-bundle release,
// creates or verifies its bundle/<name>/vX.Y.Z Git tag, freezes the tested
// package, publishes it write-once, signs and attests the published digest,
// and verifies the result through the consumer's trust contract. It is a
// build tool run by .github/workflows/bundle-release.yml; it is not part of
// the shipped image.
//
//	bundlerelease verify  -name NAME -commit SHA [-main REF] [-package DIR]
//	bundlerelease freeze  -name NAME -commit SHA -package DIR [-main REF]
//	bundlerelease tag     -name NAME -commit SHA -version V [-main REF] [-remote NAME]
//	bundlerelease publish -name NAME -commit SHA -version V -package DIR -out FILE
//	                      [-registry PREFIX] [-main REF] [-record-out FILE]
//	                      [-signing keyless|key [-key REF] [-tlog-upload]] [-sources FILE]
//	                      [-defer-proofs] [-workflow-* ...]
//	bundlerelease verify-release -name NAME -digest sha256:HEX [-sources FILE]
//	                      [-record FILE] [-public-key-file FILE] [-trust-root-file FILE] [-out FILE]
//	bundlerelease provenance -package DIR -out FILE [-sources FILE] [-workflow-* ...]
//
// verify is read-only. It prints name, version, commit and tag (and digest
// when -package is given) as key=value lines for $GITHUB_OUTPUT; with
// -package the layout must also carry a publication record bound to it.
// freeze runs the package's declarative policy fixtures (kyverno test) against
// the unpacked frozen layer and writes the publication record. tag
// re-validates, requires the packaged version, then creates the tag on the
// remote or verifies that it already marks the same commit. publish requires
// that tag, re-verifies the frozen package and publishes it to
// PREFIX/NAME:VERSION write-once, reading it back anonymously; with -signing
// it then signs and attests exactly the missing proofs of that digest with
// the pinned Cosign CLI, under the rule for NAME in the central source
// configuration (-sources, default bundles/official-sources.yaml in -repo).
// publish never reports a release complete: verify-release does, after
// retrieving the digest anonymously through the consumer's adapter and
// verifying its signature, provenance and content under that configured
// rule. provenance writes the Konstapel provenance predicate of a frozen
// package, for publishers who sign by hand.
//
// The registry credential comes only from the environment
// (BUNDLE_REGISTRY_USERNAME, BUNDLE_REGISTRY_PASSWORD), never from a flag, and
// is never printed. Keyless signing uses GitHub Actions' ambient OIDC
// credentials, which reach Cosign only through its environment; key mode reads
// the key password from COSIGN_PASSWORD. Inside GitHub Actions the workflow
// revision recorded in provenance comes from the run's environment; outside,
// from the -workflow-* flags.
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
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/release"
	"github.com/backend-bunny/Konstapel/internal/bundle/sign"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// DefaultRegistry is where official bundles are published.
const DefaultRegistry = release.OfficialRegistry

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bundlerelease:", err)
		os.Exit(1)
	}
}

// options are the parsed flags of one subcommand.
type options struct {
	repo, name, commit, mainRef, pkg, version, remote, registryPrefix, out string
	deferProofs                                                            bool
	sources, signing, key, recordOut, record, digest                       string
	publicKeyFile, trustRootFile                                           string
	tlogUpload                                                             bool
	wf                                                                     publish.Workflow
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	cmds := map[string]bool{"verify": true, "tag": true, "freeze": true, "publish": true, "verify-release": true, "provenance": true}
	if len(args) == 0 || !cmds[args[0]] {
		return fmt.Errorf("usage: bundlerelease verify|freeze|tag|publish|verify-release|provenance -name NAME ...")
	}
	var o options
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.StringVar(&o.repo, "repo", ".", "repository checkout with reviewed main history and tags fetched")
	fs.StringVar(&o.name, "name", "", "bundle name (directory under bundles/)")
	fs.StringVar(&o.commit, "commit", "", "full reviewed source commit on main")
	fs.StringVar(&o.mainRef, "main", "refs/remotes/origin/main", "fully qualified ref of reviewed main history")
	fs.StringVar(&o.pkg, "package", "", "frozen layout written by scripts/bundles/package.sh")
	fs.StringVar(&o.version, "version", "", "tag, publish: the version that was packaged")
	fs.StringVar(&o.remote, "remote", "origin", "tag: remote that holds release tags")
	fs.StringVar(&o.registryPrefix, "registry", DefaultRegistry, "publish: repository prefix; the bundle is pushed to PREFIX/NAME")
	fs.StringVar(&o.out, "out", "", "publish: new file for the run record; verify-release: new file for the receipt; provenance: new predicate file")
	fs.BoolVar(&o.deferProofs, "defer-proofs", false, "publish: succeed although required proofs are missing (a later step adds them)")
	fs.StringVar(&o.sources, "sources", release.OfficialSourcesFile, "central source configuration with the publisher rule (relative paths are inside -repo)")
	fs.StringVar(&o.signing, "signing", "", "publish: sign missing proofs with Cosign: keyless (GitHub OIDC) or key")
	fs.StringVar(&o.key, "key", "", "publish -signing key: Cosign private key file (absolute) or env://NAME; its password comes from COSIGN_PASSWORD")
	fs.BoolVar(&o.tlogUpload, "tlog-upload", false, "publish -signing key: also upload to the transparency log of Cosign's signing configuration")
	fs.StringVar(&o.recordOut, "record-out", "", "publish: new file for the publication record in effect")
	fs.StringVar(&o.record, "record", "", "verify-release: publication record the provenance must attest")
	fs.StringVar(&o.digest, "digest", "", "verify-release: the published manifest digest (sha256:<hex>)")
	fs.StringVar(&o.publicKeyFile, "public-key-file", "", "verify-release: the public key a public-key rule references")
	fs.StringVar(&o.trustRootFile, "trust-root-file", "", "verify-release: the trusted root a keyless rule references (default: embedded public-good root)")
	fs.StringVar(&o.wf.Repository, "workflow-repository", "", "outside GitHub Actions: the pipeline's repository URL recorded in provenance")
	fs.StringVar(&o.wf.Path, "workflow-path", "", "outside GitHub Actions: the pipeline definition's path")
	fs.StringVar(&o.wf.Ref, "workflow-ref", "", "outside GitHub Actions: the pipeline's ref (optional)")
	fs.StringVar(&o.wf.Commit, "workflow-commit", "", "outside GitHub Actions: the pipeline's full commit")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if !filepath.IsAbs(o.sources) {
		o.sources = filepath.Join(o.repo, o.sources)
	}
	g := release.ExecGit{Dir: o.repo}
	req := release.Request{Name: o.name, Commit: o.commit, MainRef: o.mainRef}

	switch args[0] {
	case "verify":
		rel, err := release.Validate(ctx, g, req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "name=%s\nversion=%s\ncommit=%s\ntag=%s\n", rel.Name, rel.Version, rel.Commit, rel.Tag)
		if o.pkg != "" {
			f, err := verifyFrozen(o.pkg, rel)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "digest=%s\n", f.ManifestDigest)
		}
		return nil
	case "freeze":
		return freeze(ctx, g, req, o.pkg, stdout)
	case "tag":
		if o.version == "" {
			return fmt.Errorf("tag requires -version, the version that was packaged")
		}
		req.Version = o.version
		rel, state, err := release.EnsureTag(ctx, g, req, o.remote)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "tag=%s\ncommit=%s\nstate=%s\n", rel.Tag, rel.Commit, state)
		return nil
	case "verify-release":
		return verifyRelease(ctx, o, stdout)
	case "provenance":
		return writeProvenance(ctx, o, stdout)
	}
	if o.version == "" || o.pkg == "" || o.out == "" {
		return fmt.Errorf("publish requires -version, -package and -out")
	}
	req.Version = o.version
	return publishRelease(ctx, g, req, o, stdout)
}

// selectRule reads the central source configuration and returns the rule
// for name: the rule always comes from configuration, never from the
// artifact.
func selectRule(path, name string) (bundle.BundleSource, error) {
	srcs, err := release.LoadSources(path)
	if err != nil {
		return bundle.BundleSource{}, fmt.Errorf("central source configuration: %w", err)
	}
	return srcs.Select(name)
}

// workflowRun is the run recorded in provenance: inside GitHub Actions it
// comes from the run's environment and the -workflow-* flags are refused;
// outside, from those flags.
func workflowRun(o options) (release.Run, error) {
	flags := o.wf != (publish.Workflow{})
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		if flags {
			return release.Run{}, errors.New("-workflow-* flags are not accepted inside GitHub Actions; the run's environment is recorded")
		}
		return release.RunFromGitHub(os.Getenv)
	}
	if !flags {
		return release.Run{}, errors.New("outside GitHub Actions, provenance needs -workflow-repository, -workflow-path and -workflow-commit (and optionally -workflow-ref)")
	}
	return release.Run{Workflow: o.wf}, nil
}

// signer prepares the proof completer for -signing, after checking that
// proofs made now can verify under the configured rule.
func signer(o options, repository string, f *publish.Frozen, reader *registry.Client, cred registry.Credential) (*publish.Completer, error) {
	keyless := false
	switch o.signing {
	case string(sign.Keyless):
		keyless = true
		if o.key != "" || o.tlogUpload {
			return nil, errors.New("-key and -tlog-upload are for -signing key")
		}
	case string(sign.Key):
	default:
		return nil, fmt.Errorf("-signing %q: want keyless or key", o.signing)
	}
	src, err := selectRule(o.sources, f.Record.Name)
	if err != nil {
		return nil, err
	}
	if src.Repository != repository {
		return nil, fmt.Errorf("%w: publishing to %s, but the rule for %s names %s", release.ErrSigningRule, repository, src.Name, src.Repository)
	}
	run, err := workflowRun(o)
	if err != nil {
		return nil, err
	}
	if keyless && run.Identity == "" {
		return nil, errors.New("keyless signing runs only inside GitHub Actions, whose workflow identity the rule fixes")
	}
	if err := release.CheckSigningRule(src, keyless, run, f.Record); err != nil {
		return nil, err
	}
	host, _, _ := strings.Cut(repository, "/")
	c := &sign.Cosign{Mode: sign.Mode(o.signing), Key: o.key, TlogUpload: o.tlogUpload, RegistryHost: host, Credential: cred, Log: os.Stderr}
	return &publish.Completer{
		Signer: c, Reader: reader,
		Provenance: publish.ProvenanceInput{Builder: src.Publisher.Provenance.Builder, Workflow: run.Workflow, InvocationID: run.InvocationID},
	}, nil
}

func publishRelease(ctx context.Context, g release.Git, req release.Request, o options, stdout io.Writer) error {
	rel, err := release.Validate(ctx, g, req)
	if err != nil {
		return err
	}
	if err := release.RequireTag(ctx, g, rel); err != nil {
		return err
	}
	f, err := verifyFrozen(o.pkg, rel)
	if err != nil {
		return err
	}
	cred, err := envCredential()
	if err != nil {
		return err
	}
	repository := strings.TrimSuffix(o.registryPrefix, "/") + "/" + rel.Name
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
	tgt := publish.Target{Repository: repository, Writer: writer, Reader: reader}
	if o.signing != "" {
		if o.deferProofs {
			return errors.New("-signing and -defer-proofs are exclusive")
		}
		if tgt.Proofs, err = signer(o, repository, f, reader, cred); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	res, perr := publish.Publish(ctx, f, tgt)

	rec := publication{
		Format: "konstapel.policy.bundle.publication-run/v1", Name: rel.Name, Version: rel.Version, Source: rel.Commit,
		Result: res, Workflow: workflowEnv(), At: time.Now().UTC().Format(time.RFC3339),
	}
	rec.Status = publishStatus(res, perr)
	if perr != nil {
		rec.Error = perr.Error()
	}
	if err := writeNew(o.out, rec); err != nil {
		return errors.Join(perr, err)
	}
	if perr != nil {
		return perr
	}
	if o.recordOut != "" && res.Frozen != nil {
		if err := writeNewBytes(o.recordOut, res.Frozen.RecordJSON); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "repository=%s\ntag=%s\ndigest=%s\noutcome=%s\nrecovered=%t\nrecord=%s\nmissing=%s\nadded=%s\nstatus=%s\n",
		res.Repository, res.Tag, res.Digest, res.Outcome, res.Recovered, res.RecordDigest, joinKinds(res.Missing), joinKinds(res.ProofsAdded), rec.Status)
	if !res.Complete && !o.deferProofs {
		return fmt.Errorf("published %s@%s, but required proofs are missing: %s; the release is incomplete", repository, res.Digest, joinKinds(res.Missing))
	}
	return nil
}

// publishStatus is how publish reports a run. It never says "complete":
// every required proof may be present, but nothing here verified them, and
// only verify-release may report the release complete.
func publishStatus(res *publish.Result, err error) string {
	switch {
	case err != nil:
		return "failed"
	case res.Complete:
		return "proofs attached; unverified until verify-release passes"
	default:
		return "incomplete: missing " + joinKinds(res.Missing)
	}
}

// trustObjects supplies the key or trusted root a rule references from
// local files, as the controller would read them from its namespace.
func trustObjects(src bundle.BundleSource, publicKeyFile, trustRootFile string) (*kubeaccess.MemoryReader, error) {
	r := kubeaccess.NewMemoryReader()
	put := func(flagName, file string, ref *bundle.ObjectRef, defaultKey string) error {
		if file == "" {
			if ref != nil {
				return fmt.Errorf("the rule references %s %s; pass it with %s", ref.Kind, ref.Name, flagName)
			}
			return nil
		}
		if ref == nil {
			return fmt.Errorf("%s given, but the rule references no such object", flagName)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		key, typ := ref.Key, ""
		if key == "" {
			key = defaultKey
		}
		if ref.Kind == bundle.KindSecret {
			typ = "Opaque"
		}
		r.Put(ref.Kind, ref.Name, kubeaccess.NewObject(typ, map[string][]byte{key: b}))
		return nil
	}
	if err := put("-public-key-file", publicKeyFile, src.Publisher.PublicKey, bundle.DefaultPublicKey); err != nil {
		return nil, err
	}
	if err := put("-trust-root-file", trustRootFile, src.Publisher.TrustRoot, bundle.DefaultTrustRootKey); err != nil {
		return nil, err
	}
	return r, nil
}

// verification is the bounded record verify-release writes.
type verification struct {
	Format          string                   `json:"format"`
	Status          string                   `json:"status"`
	Error           string                   `json:"error,omitempty"`
	Repository      string                   `json:"repository"`
	Digest          string                   `json:"digest"`
	ReferrersSource registry.ReferrersSource `json:"referrersSource,omitempty"`
	SigningTime     string                   `json:"signingTime,omitempty"`
	Receipt         *bundle.Receipt          `json:"receipt,omitempty"`
}

// verifyRelease verifies a published digest through the consumer's trust
// contract and reports the release complete only if it passes.
func verifyRelease(ctx context.Context, o options, stdout io.Writer) error {
	if o.name == "" || o.digest == "" {
		return errors.New("verify-release requires -name and -digest")
	}
	src, err := selectRule(o.sources, o.name)
	if err != nil {
		return err
	}
	objects, err := trustObjects(src, o.publicKeyFile, o.trustRootFile)
	if err != nil {
		return err
	}
	v, err := verify.New(objects)
	if err != nil {
		return err
	}
	c := release.ReleaseCheck{Source: src, Digest: o.digest, Verifier: v}
	if o.record != "" {
		raw, err := os.ReadFile(o.record)
		if err != nil {
			return err
		}
		rec, err := publish.ParseRecord(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", o.record, err)
		}
		c.Record = &rec
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	acc, res, verr := release.VerifyRelease(ctx, c)
	out := verification{Format: "konstapel.policy.bundle.release-verification/v1", Repository: src.Repository, Digest: o.digest}
	if res != nil {
		out.ReferrersSource = res.ReferrersSource
	}
	if verr != nil {
		out.Status, out.Error = "incomplete: verification failed", verr.Error()
	} else {
		out.Status, out.Receipt = "complete", &acc.Receipt
		if t := acc.Proofs.Signature.SigningTime; !t.IsZero() {
			out.SigningTime = t.UTC().Format(time.RFC3339)
		}
	}
	if o.out != "" {
		if err := writeNew(o.out, out); err != nil {
			return errors.Join(verr, err)
		}
	}
	if verr != nil {
		fmt.Fprintf(stdout, "repository=%s\ndigest=%s\nstatus=%s\n", src.Repository, o.digest, out.Status)
		return fmt.Errorf("verify-release %s@%s under the configured rule for %s: %w; the release is incomplete", src.Repository, o.digest, src.Name, verr)
	}
	rc := acc.Receipt
	signer := rc.Signer.Identity + " (issuer " + rc.Signer.Issuer + ")"
	if rc.Signer.KeyFingerprint != "" {
		signer = "key " + rc.Signer.KeyFingerprint
	}
	signingTime := out.SigningTime
	if signingTime == "" {
		signingTime = "none (public-key rule)"
	}
	fmt.Fprintf(stdout, "name=%s\nversion=%s\nrepository=%s\ndigest=%s\nsigner=%s\nsigningTime=%s\ntrustRoot=%s\ntrustRevision=%s\nsourceRule=%s\n",
		rc.Subject.Name, rc.Subject.Version, src.Repository, rc.Subject.Digest, signer, signingTime, rc.TrustRoot, rc.TrustRevision, rc.SourceRule)
	fmt.Fprintf(stdout, "sourceRepository=%s\nsourceCommit=%s\nworkflowCommit=%s\nbuilder=%s\ncontent=%s\nsignature=%s\nattestation=%s\nstatus=complete\n",
		rc.Provenance.Repository, rc.Provenance.Revision, rc.Provenance.Workflow.Commit, rc.Provenance.Builder, rc.Provenance.Content,
		rc.Proofs.Signature.Manifest, rc.Proofs.Attestation.Manifest)
	return nil
}

// writeProvenance writes the provenance predicate of a frozen package for
// a publisher that signs by hand (cosign attest --type slsaprovenance1).
func writeProvenance(ctx context.Context, o options, stdout io.Writer) error {
	if o.pkg == "" || o.out == "" {
		return errors.New("provenance requires -package and -out")
	}
	f, err := publish.Load(o.pkg)
	if err != nil {
		return err
	}
	src, err := selectRule(o.sources, f.Record.Name)
	if err != nil {
		return err
	}
	run, err := workflowRun(o)
	if err != nil {
		return err
	}
	if src.Publisher.Provenance.SourceRepository != f.Record.Source.Repository {
		return fmt.Errorf("%w: the bundle's source %q is not the rule's %q", release.ErrSigningRule, f.Record.Source.Repository, src.Publisher.Provenance.SourceRepository)
	}
	tool, err := (&sign.Cosign{Mode: sign.Key}).Tool(ctx)
	if err != nil {
		return err
	}
	p, err := publish.BuildProvenance(f.Record, publish.ProvenanceInput{
		Builder: src.Publisher.Provenance.Builder, Workflow: run.Workflow, InvocationID: run.InvocationID, SigningTools: []publish.Tool{tool},
	})
	if err != nil {
		return err
	}
	if err := writeNewBytes(o.out, p); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "digest=%s\nbuilder=%s\nsourceCommit=%s\nworkflowCommit=%s\n", f.ManifestDigest, src.Publisher.Provenance.Builder, f.Record.Source.Commit, run.Workflow.Commit)
	return nil
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

// writeNewBytes writes b to a new file of bounded size.
func writeNewBytes(path string, b []byte) error {
	if len(b) > maxPublicationBytes {
		return fmt.Errorf("%s would be %d bytes, limit %d", path, len(b), maxPublicationBytes)
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
