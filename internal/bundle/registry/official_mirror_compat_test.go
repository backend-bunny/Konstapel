//go:build registrycompat

package registry_test

// The official, independently released bundle and its private mirror. The
// real keyless (GitHub OIDC, Sigstore public-good) release of
// konstapel-privileged-containers is read anonymously from ghcr.io (referrers
// through the tag schema fallback) and verified directly through the
// production verifier under bundles/official-sources.yaml; mirror.Mirror then
// copies it, with its real referrers, into the private TLS registries of
// TestRegistryCompat (Zot with htpasswd writes and the referrers API; the
// distribution registry with htpasswd reads and writes and the tag schema),
// and the copies are verified through the same verifier under the official
// rule with only the location changed. The bundlerelease mirror and
// verify-release commands and the pinned Cosign CLI repeat it the way an
// organization would. Mirrors that lack a referrer, or that carry the
// official proofs for another subject, are refused.
//
// It needs network access to ghcr.io (and, for Cosign, the Sigstore TUF
// repository) and runs only with KONSTAPEL_NETWORK_INTEROP=1; otherwise it
// is recorded as skipped. Proof verification in Go stays offline (embedded
// public-good root).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/mirror"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/release"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

func init() { registry.CompatCases = append(registry.CompatCases, officialMirrorCompat) }

// NetworkInteropEnv enables the cases that read the real official release.
const NetworkInteropEnv = "KONSTAPEL_NETWORK_INTEROP"

// The first official release (internal/bundle/release/testdata/official).
const (
	officialName         = "konstapel-privileged-containers"
	officialDigest       = "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8"
	officialSourceCommit = "863f4853151bb342a46eefa57c31cb2d46e17cff"
)

func officialMirrorCompat(t *testing.T, env registry.CompatEnv) {
	const caseName = "official mirror: the official OIDC-signed release and its private mirror through the production verifier"
	if os.Getenv(NetworkInteropEnv) != "1" {
		env.Skip(caseName, NetworkInteropEnv+"=1 not set: needs anonymous network access to ghcr.io")
		t.Logf("skipping %q: set %s=1 (network access to ghcr.io)", caseName, NetworkInteropEnv)
		return
	}
	t.Run("official mirror", func(t *testing.T) { runOfficialMirror(t, env) })
}

func runOfficialMirror(t *testing.T, env registry.CompatEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	check := func(name string, ok bool, err error, detail string) {
		t.Helper()
		var rerr error
		if !ok {
			rerr = fmt.Errorf("unexpected result: %v", err)
		}
		env.Record("official mirror: "+name, rerr, detail)
		if !ok {
			t.Fatalf("%s: %v (%s)", name, err, detail)
		}
	}

	srcs, err := release.LoadSources("../../../" + release.OfficialSourcesFile)
	if err != nil {
		t.Fatal(err)
	}
	official, err := srcs.Select(officialName)
	if err != nil {
		t.Fatal(err)
	}
	v, err := verify.New(kubeaccess.NewMemoryReader())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(env.CAPEM)
	local := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	creds := registry.Credential{Username: env.User, Password: env.Pass}

	// 1. The official release, directly: anonymous retrieval from ghcr.io by
	// digest and the production verifier under the official rule.
	direct, ghcr, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: official, Digest: officialDigest, Verifier: v})
	ok := err == nil && officialAccepted(direct) == "" && ghcr.ReferrersSource == registry.ReferrersFromTagSchema
	check("ghcr.io: the official release verifies anonymously under bundles/official-sources.yaml", ok, err,
		fmt.Sprintf("%s@%s, referrers via %s, %s", official.Repository, officialDigest, sourceOf(ghcr), officialAccepted(direct)))
	t.Logf("direct: signer %s (issuer %s), source %s@%s, workflow commit %s, signed %s, rule %s",
		direct.Receipt.Signer.Identity, direct.Receipt.Signer.Issuer, direct.Provenance.SourceRepository, direct.Provenance.SourceRevision,
		direct.Provenance.Workflow.Commit, direct.Proofs.Signature.SigningTime.UTC().Format(time.RFC3339), direct.Receipt.SourceRule)

	// The mirror rules change the location only: the publisher rule and its
	// revision are the official ones.
	officialRev, err := verify.RuleRevision(official)
	if err != nil {
		t.Fatal(err)
	}
	at := func(repo string) bundle.BundleSource {
		s := official
		s.Repository = repo
		return s
	}

	src, err := registry.NewClient(registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dst, err := registry.NewClient(registry.Options{Transport: local, Credentials: hostCred{env.APIAuthd: creds, env.Authd: creds}})
	if err != nil {
		t.Fatal(err)
	}
	// The controller's own access path: kubeaccess with a ConfigMap CA added
	// to the system roots and a dockerconfigjson Secret.
	objs := kubeaccess.NewMemoryReader()
	objs.Put(bundle.KindConfigMap, "mirror-ca", caConfigMap(env.CAPEM))
	objs.Put(bundle.KindSecret, "mirror-creds", dockerSecret(env.Authd, env.User, env.Pass))
	kp, err := kubeaccess.New(kubeaccess.Options{Reader: objs})
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Close()
	kc, err := kubeaccess.NewClient(kp, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range []struct {
		label, host string
		authRead    bool
		via         registry.ReferrersSource
	}{
		{"Zot (htpasswd writes, anonymous reads, referrers API)", env.APIAuthd, false, registry.ReferrersFromAPI},
		{"distribution registry (htpasswd reads and writes, tag schema)", env.Authd, true, registry.ReferrersFromTagSchema},
	} {
		repo := m.host + "/mirror/" + officialName
		dest := bundle.BundleSource{Name: officialName, Repository: repo, CredentialSecret: &publish.PublisherCredential}
		res, err := mirror.Mirror(ctx, src, dst, mirror.Request{Source: official, Destination: dest, Digest: officialDigest})
		ok := err == nil && res.Digest == officialDigest && slices.Equal(res.Proofs, proofManifests(ghcr))
		check(m.label+": mirror.Mirror copies the subject and both real referrers by digest", ok, err, fmt.Sprintf("proofs %v", proofsOrNone(res)))

		rule := at(repo)
		if m.authRead {
			rule.CredentialSecret = &bundle.ObjectRef{Name: "mirror-creds"}
		}
		rule.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "mirror-ca"}
		rev, err := verify.RuleRevision(rule)
		ok = err == nil && rev == officialRev && reflect.DeepEqual(rule.Publisher, official.Publisher) && rule.Name == official.Name
		check(m.label+": the mirror rule is the official rule with only the location (repository, CA, credential) changed", ok, err, "rule revision "+rev)

		got, err := kc.Fetch(ctx, rule, officialDigest)
		var acc *verify.Accepted
		if err == nil {
			acc, err = release.CheckRelease(ctx, release.ReleaseCheck{Source: rule, Digest: officialDigest, Verifier: v}, got)
		}
		diff := ""
		if err == nil {
			diff = sameContent(ghcr, got) + sameReceipt(direct, acc, repo)
		}
		ok = err == nil && diff == "" && got.ReferrersSource == m.via && officialAccepted(acc) == ""
		check(m.label+": the mirror verifies through kubeaccess and the production verifier with identical digests and receipt", ok, err,
			fmt.Sprintf("referrers via %s; %s%s", sourceOf(got), diff, officialAccepted(acc)))

		if !m.authRead {
			acc, _, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: at(repo), Digest: officialDigest, Verifier: v, Transport: local})
			diff := ""
			if err == nil {
				diff = sameReceipt(direct, acc, repo)
			}
			check(m.label+": verify-release's check accepts the mirror anonymously under the official rule with only repository changed",
				err == nil && diff == "", err, diff)
		}
	}

	// Refusals, on the Zot mirror registry.
	raw := func(repo string) *registry.Session {
		s, err := dst.Open(ctx, bundle.BundleSource{Name: officialName, Repository: repo, CredentialSecret: &publish.PublisherCredential})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	refused := func(repo, digest string) error {
		_, _, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: at(repo), Digest: digest, Verifier: v, Transport: local})
		return err
	}

	subjectOnly := env.APIAuthd + "/mirror/subject-only"
	pushSubject(ctx, t, raw(subjectOnly), ghcr.Manifest, ghcr.Layer, ghcr.LayerDigest)
	err = refused(subjectOnly, officialDigest)
	check("a mirror of the official subject without referrers is refused by verification", errors.Is(err, registry.ErrMissingProofs), err, "ErrMissingProofs")
	_, err = mirror.Mirror(ctx, dst, dst, mirror.Request{
		Source:      bundle.BundleSource{Name: officialName, Repository: subjectOnly},
		Destination: bundle.BundleSource{Name: officialName, Repository: env.APIAuthd + "/mirror/from-subject-only", CredentialSecret: &publish.PublisherCredential},
		Digest:      officialDigest,
	})
	_, ferr := dst.Fetch(ctx, bundle.BundleSource{Name: officialName, Repository: env.APIAuthd + "/mirror/from-subject-only"}, officialDigest)
	check("mirroring a copy without referrers is refused before any write", errors.Is(err, registry.ErrMissingProofs) && errors.Is(ferr, registry.ErrNotFound), err, fmt.Sprint(ferr))

	for _, drop := range []registry.ProofKind{registry.ProofSignature, registry.ProofProvenance} {
		repo := env.APIAuthd + "/mirror/without-" + string(drop)
		s := raw(repo)
		pushSubject(ctx, t, s, ghcr.Manifest, ghcr.Layer, ghcr.LayerDigest)
		for _, p := range ghcr.Proofs {
			if p.Kind != drop {
				pushProof(ctx, t, s, p, p.Manifest)
			}
		}
		err := refused(repo, officialDigest)
		check(fmt.Sprintf("a mirror that dropped the %s referrer is refused", drop), errors.Is(err, registry.ErrMissingProofs), err, "ErrMissingProofs")
	}

	// The official proofs re-pointed at another subject: the bytes of the
	// official manifest re-serialized (a tampered subject with another
	// digest), and an unrelated bundle built from the same definition.
	other := compatFrozen(t, strings.Repeat("c", 40))
	var indented bytes.Buffer
	if err := json.Indent(&indented, ghcr.Manifest, "", " "); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		label           string
		manifest, layer []byte
		layerDigest     string
	}{
		{"a re-serialized (tampered) official manifest", indented.Bytes(), ghcr.Layer, ghcr.LayerDigest},
		{"another bundle", other.Manifest, other.Layer, other.LayerDigest},
	} {
		repo := env.APIAuthd + "/mirror/other-subject-" + digest.FromBytes(s.manifest).Encoded()[:12]
		sess := raw(repo)
		subject := pushSubject(ctx, t, sess, s.manifest, s.layer, s.layerDigest)
		for _, p := range ghcr.Proofs {
			pushProof(ctx, t, sess, p, repoint(t, p.Manifest, subject))
		}
		err := refused(repo, subject.Digest.String())
		check("the official proofs re-pointed at "+s.label+" are refused", errors.Is(err, verify.ErrNoValidProof) || errors.Is(err, verify.ErrSubject), err,
			fmt.Sprintf("%s: %v", subject.Digest, err))
	}

	// A mirror rule that changes more than the location is not the official
	// rule and does not accept the mirror.
	fork := at(env.APIAuthd + "/mirror/" + officialName)
	fork.Publisher.Identity = "https://github.com/example-fork/Konstapel/" + release.OfficialWorkflowPath + "@" + release.OfficialWorkflowRef
	fork.Publisher.Provenance.Builder = fork.Publisher.Identity
	_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: fork, Digest: officialDigest, Verifier: v, Transport: local})
	check("the mirror under a rule naming another identity is refused", errors.Is(err, verify.ErrSigner), err, "ErrSigner")

	cliAndCosign(ctx, t, env, check)
}

// cliAndCosign repeats the mirror with the commands an organization runs:
// bundlerelease mirror and verify-release (the private CA added through Go's
// SSL_CERT_DIR, the system roots kept for ghcr.io) and the pinned Cosign CLI.
func cliAndCosign(ctx context.Context, t *testing.T, env registry.CompatEnv, check func(string, bool, error, string)) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "mirror-ca.pem"), env.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bundlerelease")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", bin, "../../../cmd/bundlerelease")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build bundlerelease: %v\n%s", err, out)
	}
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	baseEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SSL_CERT_DIR=" + caDir}
	var transcript bytes.Buffer
	run := func(env []string, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		fmt.Fprintf(&transcript, "$ %s %s\n%s(exit: %v)\n\n", filepath.Base(name), strings.Join(args, " "), out, err)
		return string(out), err
	}
	repo := env.APIAuthd + "/org/" + officialName
	ref := repo + "@" + officialDigest
	out, err := run(append(baseEnv, "BUNDLE_REGISTRY_USERNAME="+env.User, "BUNDLE_REGISTRY_PASSWORD="+env.Pass), bin, "mirror",
		"-from", "ghcr.io/backend-bunny/bundles/"+officialName, "-to", repo, "-digest", officialDigest)
	check("bundlerelease mirror copies the official release into the private TLS registry (SSL_CERT_DIR)",
		err == nil && strings.Contains(out, "digest="+officialDigest) && strings.Contains(out, "proofs=2"), err, strings.TrimSpace(out))

	// The official sources file with only repository changed.
	raw, err := os.ReadFile("../../../" + release.OfficialSourcesFile)
	if err != nil {
		t.Fatal(err)
	}
	mirrorSources := filepath.Join(dir, "mirror-sources.yaml")
	edited := strings.Replace(string(raw), "repository: ghcr.io/backend-bunny/bundles/"+officialName, "repository: "+repo, 1)
	if edited == string(raw) {
		t.Fatal("official sources file has no repository line to change")
	}
	if err := os.WriteFile(mirrorSources, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = run(baseEnv, bin, "verify-release", "-sources", mirrorSources, "-name", officialName, "-digest", officialDigest)
	ok := err == nil && strings.Contains(out, "status=complete") && strings.Contains(out, "sourceCommit="+officialSourceCommit) &&
		strings.Contains(out, "workflowCommit="+officialSourceCommit) && strings.Contains(out, "repository="+repo) &&
		strings.Contains(out, "signer="+release.OfficialIdentity()+" (issuer "+release.GitHubIssuer+")")
	check("bundlerelease verify-release accepts the mirror under the official rule with only repository changed", ok, err, strings.TrimSpace(out))

	cosignBin, lerr := exec.LookPath("cosign")
	if lerr != nil {
		t.Fatalf("the pinned Cosign CLI is required (devbox run): %v", lerr)
	}
	// Cosign reads the private registry with a docker config of its own and
	// fetches the public-good trusted root through Sigstore's TUF repository.
	dockerDir := filepath.Join(dir, "docker")
	_ = os.Mkdir(dockerDir, 0o700)
	cfg, _ := json.Marshal(map[string]any{"auths": map[string]any{env.Authd: map[string]string{
		"auth": base64.StdEncoding.EncodeToString([]byte(env.User + ":" + env.Pass))}}})
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	cenv := append(baseEnv, "DOCKER_CONFIG="+dockerDir)
	id, iss := release.OfficialIdentity(), release.GitHubIssuer
	for _, r := range []string{ref, env.Authd + "/mirror/" + officialName + "@" + officialDigest} {
		_, err := run(cenv, cosignBin, "verify", r, "--certificate-identity", id, "--certificate-oidc-issuer", iss)
		check("cosign verify accepts the mirror "+r, err == nil, err, "")
		_, err = run(cenv, cosignBin, "verify-attestation", r, "--type", "slsaprovenance1", "--certificate-identity", id, "--certificate-oidc-issuer", iss)
		check("cosign verify-attestation slsaprovenance1 accepts the mirror "+r, err == nil, err, "")
	}
	_, err = run(cenv, cosignBin, "verify", ref, "--certificate-identity", strings.Replace(id, "@refs/heads/main", "@refs/heads/dev", 1), "--certificate-oidc-issuer", iss)
	check("cosign verify refuses the mirror under another identity", err != nil, err, "")

	if out := os.Getenv("KONSTAPEL_REGISTRY_OUTPUT"); out != "" {
		// Credentials never reach the transcript.
		s := strings.ReplaceAll(transcript.String(), env.Pass, "<redacted>")
		if err := os.WriteFile(filepath.Join(out, "official-mirror-commands.txt"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// officialAccepted returns what differs from the official release's known
// signer, trust root and provenance ("" when it all matches).
func officialAccepted(acc *verify.Accepted) string {
	if acc == nil {
		return "not accepted"
	}
	rc, vp := acc.Receipt, acc.Provenance
	var d []string
	if rc.Signer != (bundle.Signer{Kind: bundle.SignerKeyless, Issuer: release.GitHubIssuer, Identity: release.OfficialIdentity()}) {
		d = append(d, fmt.Sprintf("signer %+v", rc.Signer))
	}
	if rc.TrustRoot != verify.TrustRootPublicGood || rc.TrustRevision != "sha256:"+verify.PublicGoodTrustRootSHA256 {
		d = append(d, "trust root "+rc.TrustRoot+" "+rc.TrustRevision)
	}
	if acc.Proofs.Signature.SigningTime.IsZero() || acc.Proofs.Provenance.SigningTime.IsZero() {
		d = append(d, "no authenticated signing time")
	}
	if vp.Builder != release.OfficialIdentity() || vp.SourceRepository != release.OfficialRepositoryURL || vp.SourceRevision != officialSourceCommit ||
		vp.Workflow.Commit != officialSourceCommit || vp.Workflow.Path != release.OfficialWorkflowPath || vp.Workflow.Ref != release.OfficialWorkflowRef {
		d = append(d, fmt.Sprintf("provenance %s %s@%s workflow %+v", vp.Builder, vp.SourceRepository, vp.SourceRevision, vp.Workflow))
	}
	if vp.BundleName != officialName || vp.BundleVersion != "0.1.0" || rc.Subject.Digest != officialDigest {
		d = append(d, fmt.Sprintf("release %s@%s %s", vp.BundleName, vp.BundleVersion, rc.Subject.Digest))
	}
	return strings.Join(d, "; ")
}

// sameContent compares the mirror's bytes and proofs with ghcr.io's.
func sameContent(want, got *registry.Result) string {
	switch {
	case got.Digest != want.Digest || !bytes.Equal(got.Manifest, want.Manifest):
		return "manifest differs; "
	case got.LayerDigest != want.LayerDigest || !bytes.Equal(got.Layer, want.Layer):
		return "layer differs; "
	case len(got.Proofs) != len(want.Proofs):
		return fmt.Sprintf("%d proofs, want %d; ", len(got.Proofs), len(want.Proofs))
	}
	type key struct{ kind, manifest, bundle string }
	set := func(r *registry.Result) []key {
		var k []key
		for _, p := range r.Proofs {
			k = append(k, key{string(p.Kind), p.ManifestDigest, p.BundleDigest})
		}
		slices.SortFunc(k, func(a, b key) int { return strings.Compare(a.kind, b.kind) })
		return k
	}
	if !slices.Equal(set(got), set(want)) {
		return fmt.Sprintf("proofs %v, want %v; ", set(got), set(want))
	}
	return ""
}

// sameReceipt: a mirror changes only where the bytes came from.
func sameReceipt(direct, acc *verify.Accepted, repo string) string {
	a, b := direct.Receipt, acc.Receipt
	if b.RetrievedFrom != repo {
		return "retrievedFrom " + b.RetrievedFrom + "; "
	}
	a.VerifiedAt, b.VerifiedAt = time.Time{}, time.Time{}
	a.RetrievedFrom, b.RetrievedFrom = "", ""
	if !reflect.DeepEqual(a, b) {
		return fmt.Sprintf("receipt %+v, direct %+v; ", b, a)
	}
	return ""
}

func proofManifests(r *registry.Result) []string {
	var d []string
	for _, p := range r.Proofs {
		d = append(d, p.ManifestDigest)
	}
	return d
}

func proofsOrNone(r *mirror.Result) []string {
	if r == nil {
		return nil
	}
	return r.Proofs
}

func sourceOf(r *registry.Result) registry.ReferrersSource {
	if r == nil {
		return ""
	}
	return r.ReferrersSource
}

// pushSubject writes a bundle manifest with its config and layer, without
// referrers, and returns its descriptor.
func pushSubject(ctx context.Context, t *testing.T, s *registry.Session, manifest, layer []byte, layerDigest string) ocispec.Descriptor {
	t.Helper()
	repo := s.Repository
	cfg := ocispec.Descriptor{MediaType: bundle.EmptyConfigMediaType, Digest: bundle.EmptyConfigDigest, Size: 2}
	if err := repo.Blobs().Push(ctx, cfg, bytes.NewReader([]byte("{}"))); err != nil {
		t.Fatal(s.Err("push config", err))
	}
	ld := ocispec.Descriptor{MediaType: bundle.LayerMediaType, Digest: digest.Digest(layerDigest), Size: int64(len(layer))}
	if err := repo.Blobs().Push(ctx, ld, bytes.NewReader(layer)); err != nil {
		t.Fatal(s.Err("push layer", err))
	}
	md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(manifest), Size: int64(len(manifest))}
	if err := repo.Manifests().Push(ctx, md, bytes.NewReader(manifest)); err != nil {
		t.Fatal(s.Err("push manifest", err))
	}
	return md
}

// pushProof writes a referrer manifest (manifest) carrying proof p's
// Sigstore bundle.
func pushProof(ctx context.Context, t *testing.T, s *registry.Session, p registry.Proof, manifest []byte) {
	t.Helper()
	repo := s.Repository
	bd := ocispec.Descriptor{MediaType: p.BundleMediaType, Digest: digest.Digest(p.BundleDigest), Size: int64(len(p.Bundle))}
	if ok, err := repo.Blobs().Exists(ctx, bd); err != nil {
		t.Fatal(s.Err("check bundle", err))
	} else if !ok {
		if err := repo.Blobs().Push(ctx, bd, bytes.NewReader(p.Bundle)); err != nil {
			t.Fatal(s.Err("push bundle", err))
		}
	}
	cfg := ocispec.Descriptor{MediaType: bundle.EmptyConfigMediaType, Digest: bundle.EmptyConfigDigest, Size: 2}
	if ok, _ := repo.Blobs().Exists(ctx, cfg); !ok {
		if err := repo.Blobs().Push(ctx, cfg, bytes.NewReader([]byte("{}"))); err != nil {
			t.Fatal(s.Err("push config", err))
		}
	}
	md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(manifest), Size: int64(len(manifest))}
	if err := repo.Manifests().Push(ctx, md, bytes.NewReader(manifest)); err != nil {
		t.Fatal(s.Err("push referrer", err))
	}
}

// repoint returns referrer manifest m with its subject replaced.
func repoint(t *testing.T, m []byte, subject ocispec.Descriptor) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(m, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["subject"]; !ok {
		t.Fatal("referrer has no subject")
	}
	doc["subject"] = map[string]any{"mediaType": subject.MediaType, "digest": subject.Digest.String(), "size": subject.Size}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
