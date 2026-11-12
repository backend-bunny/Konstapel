//go:build registrycompat

package registry_test

// Release signing (internal/bundle/sign with the pinned Cosign CLI in key
// mode, publish.Completer) and release verification (release.VerifyRelease)
// against the real registries of TestRegistryCompat: the distribution
// registry (referrers tag schema, which Cosign maintains itself, as on
// ghcr.io) and Zot (referrers API, htpasswd writes and anonymous reads).
// Keyless signing needs GitHub's OIDC token and the public Sigstore services
// and is not exercised here: Cosign runs offline (no transparency log, no
// signing configuration) with outbound HTTP(S) routed to a closed port.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/mirror"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/release"
	"github.com/backend-bunny/Konstapel/internal/bundle/sign"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

func init() { registry.CompatCases = append(registry.CompatCases, signCompat) }

// compatBuilder is an organization builder that is not a GitHub Actions
// workflow: its provenance carries the builder record. compatGitHubBuilder
// is a GitHub Actions workflow builder signing with an organization key: its
// provenance carries the workflow record.
const (
	compatBuilder       = "https://ci.example.test/konstapel/bundle-release@refs/heads/main"
	compatGitHubBuilder = "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"
)

// countingSigner records which proofs the real signer was asked to make.
type countingSigner struct {
	publish.ProofSigner
	mu    sync.Mutex
	calls []string
}

func (c *countingSigner) Sign(ctx context.Context, ref string) error {
	c.mu.Lock()
	c.calls = append(c.calls, "sign")
	c.mu.Unlock()
	return c.ProofSigner.Sign(ctx, ref)
}

func (c *countingSigner) Attest(ctx context.Context, ref string, p []byte) error {
	c.mu.Lock()
	c.calls = append(c.calls, "attest")
	c.mu.Unlock()
	return c.ProofSigner.Attest(ctx, ref, p)
}

func (c *countingSigner) take() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := strings.Join(c.calls, ",")
	c.calls = nil
	return s
}

func signCompat(t *testing.T, env registry.CompatEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cosignBin, err := exec.LookPath("cosign")
	if err != nil {
		t.Fatalf("the pinned Cosign CLI is required (devbox run): %v", err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, env.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(env.CAPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	// A fresh test key (empty password), its public key and fingerprint.
	home := filepath.Join(dir, "home")
	_ = os.Mkdir(home, 0o700)
	cosignEnv := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TUF_ROOT=" + filepath.Join(dir, "tuf-unused"), "COSIGN_PASSWORD=",
		"HTTPS_PROXY=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost",
	}
	gen := exec.Command(cosignBin, "generate-key-pair", "--output-key-prefix", "release")
	gen.Dir, gen.Env = dir, cosignEnv
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate-key-pair: %v\n%s", err, out)
	}
	pubPEM, _ := os.ReadFile(filepath.Join(dir, "release.pub"))
	blk, _ := pem.Decode(pubPEM)
	sum := sha256.Sum256(blk.Bytes)
	fingerprint := "sha256:" + hex.EncodeToString(sum[:])
	keys := kubeaccess.NewMemoryReader()
	keys.Put(bundle.KindSecret, "release-key", kubeaccess.NewObject("Opaque", map[string][]byte{bundle.DefaultPublicKey: pubPEM}))
	v, err := verify.New(keys)
	if err != nil {
		t.Fatal(err)
	}

	frozenA := compatFrozen(t, strings.Repeat("e", 40))
	frozenB := compatFrozen(t, strings.Repeat("f", 40))
	creds := registry.Credential{Username: env.User, Password: env.Pass}
	// The organization builder's own revision, newer than the source commit.
	builderRevision := "pipeline@" + strings.Repeat("1", 40)
	orgInput := publish.ProvenanceInput{Builder: compatBuilder, BuilderRevision: builderRevision, InvocationID: "compat"}
	// A GitHub Actions workflow revision newer than the source commit.
	workflow := publish.Workflow{Repository: "https://github.com/backend-bunny/Konstapel", Path: ".github/workflows/bundle-release.yml", Ref: "refs/heads/main", Commit: strings.Repeat("1", 40)}

	ruleFor := func(repo, builder string) bundle.BundleSource {
		return bundle.BundleSource{Name: frozenA.Record.Name, Repository: repo, Publisher: bundle.Publisher{
			Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "release-key"}, KeyFingerprint: fingerprint,
			Provenance: bundle.ProvenanceRule{SourceRepository: frozenA.Record.Source.Repository, Builder: builder},
		}}
	}
	rule := func(repo string) bundle.BundleSource { return ruleFor(repo, compatBuilder) }
	setupWith := func(host string, authRead bool, in publish.ProvenanceInput) (publish.Target, *countingSigner, *recorder) {
		rec := &recorder{base: &http.Transport{TLSClientConfig: tlsConfig(pool)}}
		w, err := registry.NewClient(registry.Options{Transport: rec, Credentials: hostCred{host: creds}})
		if err != nil {
			t.Fatal(err)
		}
		ropts := registry.Options{Transport: transport}
		if authRead {
			ropts.Credentials = hostCred{host: creds}
		}
		r, err := registry.NewClient(ropts)
		if err != nil {
			t.Fatal(err)
		}
		cs := &countingSigner{ProofSigner: &sign.Cosign{
			Path: cosignBin, Mode: sign.Key, Key: filepath.Join(dir, "release.key"), RegistryCA: caFile,
			RegistryHost: host, Credential: creds, Environ: cosignEnv, Timeout: 2 * time.Minute,
		}}
		tgt := publish.Target{Writer: w, Reader: r, ReadBackDelay: 200 * time.Millisecond, AuthenticatedReadBack: authRead,
			Proofs: &publish.Completer{Signer: cs, Reader: r, AuthenticatedRead: authRead,
				Provenance: in}}
		return tgt, cs, rec
	}
	setup := func(host string, authRead bool) (publish.Target, *countingSigner, *recorder) {
		return setupWith(host, authRead, orgInput)
	}
	record := func(name string, ok bool, err error, detail string) {
		if !ok && err == nil {
			err = errors.New("unexpected result")
		}
		if ok {
			err = nil
		}
		env.Record(name, err, detail)
		if !ok {
			t.Errorf("%s: %v (%s)", name, err, detail)
		}
	}

	for i, r := range []struct {
		label, host string
		via         registry.ReferrersSource
	}{
		{"distribution registry (tag schema)", env.Anon, registry.ReferrersFromTagSchema},
		{"Zot (referrers API), htpasswd writes, anonymous reads", env.APIAuthd, registry.ReferrersFromAPI},
	} {
		t.Run("sign: "+r.label, func(t *testing.T) {
			tgt, cs, rec := setup(r.host, false)
			tgt.Repository = fmt.Sprintf("%s/bundles/sign-compat-%d", r.host, i)

			res, err := publish.Publish(ctx, frozenA, tgt)
			record(t.Name()+": publish, then Cosign signs and attests the digest",
				err == nil && res.Outcome == publish.Created && res.Complete && fmt.Sprint(res.ProofsAdded) == "[signature provenance]" && cs.take() == "sign,attest",
				err, fmt.Sprintf("digest %s, added %v", res.Digest, res.ProofsAdded))

			got, err := tgt.Reader.Fetch(ctx, bundle.BundleSource{Name: frozenA.Record.Name, Repository: tgt.Repository}, frozenA.ManifestDigest)
			record(t.Name()+": the consumer adapter lists both Cosign referrers",
				err == nil && got.RequireProofs(registry.RequiredProofs...) == nil && got.ReferrersSource == r.via && len(got.Proofs) == 2,
				err, fmt.Sprintf("referrers via %s", got.ReferrersSource))

			acc, _, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(tgt.Repository), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenA.Record})
			ok := err == nil && acc.Receipt.Provenance.Revision == frozenA.Record.Source.Commit && acc.Receipt.Provenance.BuilderRevision == builderRevision &&
				acc.Receipt.Provenance.Workflow == (bundle.WorkflowRef{}) && acc.Receipt.Signer.KeyFingerprint == fingerprint
			detail := ""
			if acc != nil {
				detail = fmt.Sprintf("signer %s, source %s, builder revision %s", acc.Receipt.Signer.KeyFingerprint, acc.Receipt.Provenance.Revision, acc.Receipt.Provenance.BuilderRevision)
			}
			record(t.Name()+": verify-release passes anonymously under the organization-key rule (builder record)", ok, err, detail)

			other := rule(tgt.Repository)
			other.Publisher.Provenance.Builder = "https://ci.example.test/other@refs/heads/main"
			_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: other, Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
			record(t.Name()+": verify-release refuses a rule naming another builder", errors.Is(err, verify.ErrProvenanceBuilder), err, "")
			_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: ruleFor(tgt.Repository, compatGitHubBuilder), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
			record(t.Name()+": verify-release refuses a GitHub workflow builder rule for builder-record provenance", errors.Is(err, verify.ErrProvenanceBuilder), err, "")
			other = rule(tgt.Repository)
			other.Publisher.Provenance.SourceRepository = "https://github.com/example-fork/Konstapel"
			_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: other, Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
			record(t.Name()+": verify-release refuses a rule naming another source repository", errors.Is(err, verify.ErrProvenanceSource), err, "")
			_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(tgt.Repository), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenB.Record})
			record(t.Name()+": verify-release refuses a record of another subject", errors.Is(err, release.ErrReleaseRecord), err, "")

			n := rec.len()
			res, err = publish.Publish(ctx, frozenA, tgt)
			record(t.Name()+": rerun with both proofs signs and writes nothing",
				err == nil && res.Outcome == publish.AlreadyPublished && cs.take() == "" && len(rec.writesSince(n)) == 0, err, "")
		})
	}

	t.Run("sign: GitHub workflow builder with an organization key", func(t *testing.T) {
		tgt, cs, _ := setupWith(env.Anon, false, publish.ProvenanceInput{Builder: compatGitHubBuilder, Workflow: workflow, InvocationID: "compat"})
		tgt.Repository = env.Anon + "/bundles/sign-github-builder"
		res, err := publish.Publish(ctx, frozenA, tgt)
		record(t.Name()+": publish, then Cosign signs and attests the workflow record",
			err == nil && res.Complete && cs.take() == "sign,attest", err, fmt.Sprintf("added %v", res.ProofsAdded))
		acc, _, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: ruleFor(tgt.Repository, compatGitHubBuilder), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenA.Record})
		record(t.Name()+": verify-release accepts the workflow record of the rule's workflow builder",
			err == nil && acc.Receipt.Provenance.Workflow.Commit == workflow.Commit && acc.Receipt.Provenance.BuilderRevision == "", err, "")
		_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(tgt.Repository), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
		record(t.Name()+": an organization builder rule refuses it", errors.Is(err, verify.ErrProvenanceBuilder), err, "")

		// A run whose workflow is not the builder's never signs.
		bad, cs2, _ := setupWith(env.Anon, false, publish.ProvenanceInput{Builder: compatBuilder, Workflow: workflow, InvocationID: "compat"})
		bad.Repository = env.Anon + "/bundles/sign-mismatched-record"
		res, err = publish.Publish(ctx, frozenA, bad)
		record(t.Name()+": a workflow record for an organization builder is refused before signing",
			err != nil && !res.Complete && cs2.take() == "", err, "")
	})

	t.Run("sign: recovery signs only the missing kind", func(t *testing.T) {
		tgt, cs, rec := setup(env.Anon, false)
		tgt.Repository = env.Anon + "/bundles/sign-recovery"
		proofs := tgt.Proofs
		tgt.Proofs = nil
		res, err := publish.Publish(ctx, frozenA, tgt)
		if err != nil || res.Complete {
			t.Fatalf("publish without proofs: %v", err)
		}
		sub := publish.Subject{Repository: tgt.Repository, Digest: frozenA.ManifestDigest, Size: int64(len(frozenA.Manifest)), Record: frozenA.Record}
		// A run that signed, then failed before attesting.
		if err := proofs.Complete(ctx, sub, []registry.ProofKind{registry.ProofSignature}); err != nil {
			t.Fatal(err)
		}
		cs.take()
		tgt.Proofs = proofs
		res, err = publish.Publish(ctx, frozenA, tgt)
		record(t.Name()+": signature present, provenance missing: only the attestation is made",
			err == nil && res.Outcome == publish.Completed && res.Complete && fmt.Sprint(res.ProofsAdded) == "[provenance]" && cs.take() == "attest",
			err, fmt.Sprintf("added %v", res.ProofsAdded))
		n := rec.len()
		err = proofs.Complete(ctx, sub, registry.RequiredProofs)
		record(t.Name()+": both present: asking again signs nothing", err == nil && cs.take() == "" && len(rec.writesSince(n)) == 0, err, "")
		changed := sub
		changed.Digest = frozenB.ManifestDigest
		err = proofs.Complete(ctx, changed, registry.RequiredProofs)
		record(t.Name()+": another subject than the record's is refused", errors.Is(err, publish.ErrProofSubject) && cs.take() == "", err, "")
		_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(tgt.Repository), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenA.Record})
		record(t.Name()+": the recovered release verifies", err == nil, err, "")
	})

	t.Run("sign: verify-release reads anonymously", func(t *testing.T) {
		tgt, _, _ := setup(env.Authd, true)
		tgt.Repository = env.Authd + "/bundles/sign-private"
		res, err := publish.Publish(ctx, frozenA, tgt)
		if err != nil || !res.Complete {
			t.Fatalf("authenticated publication with proofs: %v", err)
		}
		_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(tgt.Repository), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
		record(t.Name()+": a signed release that anonymous consumers cannot read is not complete",
			errors.Is(err, registry.ErrUnauthorized) && !strings.Contains(err.Error(), env.Pass), err, "")
	})

	t.Run("mirror: a copy keeps digests and the original provenance", func(t *testing.T) {
		tgt, _, _ := setup(env.Anon, false)
		tgt.Repository = env.Anon + "/bundles/mirror-src"
		if res, err := publish.Publish(ctx, frozenA, tgt); err != nil || !res.Complete {
			t.Fatalf("publish source: %v", err)
		}
		src, err := registry.NewClient(registry.Options{Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		dst, err := registry.NewClient(registry.Options{Transport: transport, Credentials: hostCred{env.APIAuthd: creds}})
		if err != nil {
			t.Fatal(err)
		}
		dstRepo := env.APIAuthd + "/bundles/mirror-dst"
		req := mirror.Request{
			Source:      bundle.BundleSource{Name: frozenA.Record.Name, Repository: tgt.Repository},
			Destination: bundle.BundleSource{Name: frozenA.Record.Name, Repository: dstRepo, CredentialSecret: &publish.PublisherCredential},
			Digest:      frozenA.ManifestDigest,
		}
		res, err := mirror.Mirror(ctx, src, dst, req)
		record(t.Name()+": subject and both referrers are copied by digest",
			err == nil && res.Digest == frozenA.ManifestDigest && len(res.Proofs) == 2, err, "")

		want, _ := src.Fetch(ctx, req.Source, frozenA.ManifestDigest)
		got, err := tgt.Reader.Fetch(ctx, bundle.BundleSource{Name: frozenA.Record.Name, Repository: dstRepo}, frozenA.ManifestDigest)
		same := err == nil && want != nil && len(got.Proofs) == len(want.Proofs)
		for i := 0; same && i < len(got.Proofs); i++ {
			same = got.Proofs[i].ManifestDigest == want.Proofs[i].ManifestDigest && got.Proofs[i].BundleDigest == want.Proofs[i].BundleDigest
		}
		record(t.Name()+": the mirror lists the identical proofs anonymously", same, err, "")

		acc, _, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(dstRepo), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport})
		record(t.Name()+": the original signature and provenance verify under the same rule, only the repository changed",
			err == nil && acc.Receipt.Provenance.Revision == frozenA.Record.Source.Commit && acc.Receipt.Signer.KeyFingerprint == fingerprint, err, "")

		// A source without required proofs is refused before any write.
		bare, _, _ := setup(env.Anon, false)
		bare.Proofs = nil
		bare.Repository = env.Anon + "/bundles/mirror-bare"
		if _, err := publish.Publish(ctx, frozenB, bare); err != nil {
			t.Fatal(err)
		}
		breq := mirror.Request{
			Source:      bundle.BundleSource{Name: frozenB.Record.Name, Repository: bare.Repository},
			Destination: bundle.BundleSource{Name: frozenB.Record.Name, Repository: env.APIAuthd + "/bundles/mirror-bare", CredentialSecret: &publish.PublisherCredential},
			Digest:      frozenB.ManifestDigest,
		}
		_, err = mirror.Mirror(ctx, src, dst, breq)
		_, ferr := dst.Fetch(ctx, breq.Destination, frozenB.ManifestDigest)
		record(t.Name()+": a source missing required evidence is not mirrored", errors.Is(err, registry.ErrMissingProofs) && errors.Is(ferr, registry.ErrNotFound), err, fmt.Sprint(ferr))

		// A subject copied without its referrers is not verifiable.
		sub := bare
		sub.Repository = env.APIAuthd + "/bundles/mirror-subject-only"
		sub.Writer = dst
		if _, err := publish.Publish(ctx, frozenB, sub); err != nil {
			t.Fatal(err)
		}
		_, _, err = release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(sub.Repository), Digest: frozenB.ManifestDigest, Verifier: v, Transport: transport})
		record(t.Name()+": a copy without referrers is refused by verification", errors.Is(err, registry.ErrMissingProofs), err, "")
	})
}
