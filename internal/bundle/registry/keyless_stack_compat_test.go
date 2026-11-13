//go:build registrycompat

package registry_test

// Real Cosign keyless signing against the disposable Sigstore instance of
// sigstore_stack_compat_test.go, verified by the unchanged production
// verifier (release.VerifyRelease / CheckRelease, verify.Verifier.Accept and
// Recheck) under an explicitly configured test trusted root and exact test
// issuer and identity. This is protocol compatibility: pinned Cosign
// (sign.Cosign in keyless mode, through publish.Publish and publish.Completer)
// talks to real Fulcio, Rekor v1 and timestamp-authority servers, and the Go
// verifier accepts exactly what they produce. Public trust-root compatibility
// (the public-good instance and its embedded root) is covered separately by
// the official release fixtures and the publicinterop and
// KONSTAPEL_NETWORK_INTEROP cases.
//
// KONSTAPEL_SIGSTORE_STACK=1 runs every case, including the expired
// certificate, which waits until the real Fulcio certificates (10 minutes)
// have expired: about 11 minutes after signing. KONSTAPEL_SIGSTORE_STACK=fast
// records the expiry cases as skipped. Unset, the whole group is skipped.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/release"
	"github.com/backend-bunny/Konstapel/internal/bundle/sign"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

func init() { registry.CompatCases = append(registry.CompatCases, keylessStackCompat) }

const (
	stackIdentity = "bundle-release@konstapel.example.test"
	stackOther    = "mallory@konstapel.example.test"
	// Trust objects in the verifier's (in-memory) namespace.
	stackRoot       = "isolated-sigstore-root"
	stackRootRekor  = "isolated-sigstore-root-other-rekor"
	stackRootNoTSA  = "isolated-sigstore-root-no-tsa"
	stackCaseFormat = "keyless stack: %s"
)

// stackEvidence is what the run writes to OUTPUT/sigstore-stack.json.
type stackEvidence struct {
	Run        string            `json:"run"`
	RecordedAt string            `json:"recordedAt"`
	Mode       string            `json:"mode"`
	Components map[string]string `json:"components"`
	Cosign     string            `json:"cosign"`
	Go         string            `json:"go"`
	TrustRoot  string            `json:"trustRootRevision"`
	Signing    map[string]string `json:"signing"`
	Expiry     map[string]string `json:"expiry,omitempty"`
}

func keylessStackCompat(t *testing.T, env registry.CompatEnv) {
	mode := os.Getenv("KONSTAPEL_SIGSTORE_STACK")
	const group = "keyless stack: real Cosign keyless signing through a disposable Sigstore instance"
	if mode != "1" && mode != "fast" {
		env.Skip(group, "KONSTAPEL_SIGSTORE_STACK is not set (opt-in: needs the pinned Sigstore images, about 12 minutes)")
		return
	}
	run := os.Getenv("KONSTAPEL_REGISTRY_RUN")
	cosignBin, err := exec.LookPath("cosign")
	if err != nil {
		t.Fatalf("the pinned Cosign CLI is required (devbox run): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	s := startSigstoreStack(t, run, cosignBin)
	wrapper := s.cosignWrapper(t, cosignBin)

	caFile := filepath.Join(s.dir, "registry-ca.pem")
	if err := os.WriteFile(caFile, env.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(env.CAPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	creds := registry.Credential{Username: env.User, Password: env.Pass}

	// Trust objects: the stack's root, and two variants for the negative cases.
	otherRekor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKIXPublicKey(&otherRekor.PublicKey)
	otherPath := filepath.Join(s.dir, "material", "other-rekor.pub")
	if err := os.WriteFile(otherPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	objects := kubeaccess.NewMemoryReader()
	put := func(name string, root []byte) {
		objects.Put(bundle.KindConfigMap, name, kubeaccess.NewObject("", map[string][]byte{bundle.DefaultTrustRootKey: root}))
	}
	put(stackRoot, s.rootJSON)
	put(stackRootRekor, s.trustedRoot(t, cosignBin, filepath.Join(s.dir, "material", "root-other-rekor.json"), otherPath, filepath.Join(s.dir, "material", "tsa.pem")))
	put(stackRootNoTSA, s.trustedRoot(t, cosignBin, filepath.Join(s.dir, "material", "root-no-tsa.json"), filepath.Join(s.dir, "material", "rekor.pub"), ""))
	v, err := verify.New(objects) // the production verifier, real clock
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(s.rootJSON)
	rootRev := "sha256:" + hex.EncodeToString(rootSum[:])

	frozenA := compatFrozen(t, strings.Repeat("a", 40))
	frozenB := compatFrozen(t, strings.Repeat("b", 40))
	builderRevision := "pipeline@" + strings.Repeat("2", 40)
	in := publish.ProvenanceInput{Builder: compatBuilder, BuilderRevision: builderRevision, InvocationID: "sigstore-stack"}

	ruleWith := func(repo, issuer, identity, root string) bundle.BundleSource {
		p := bundle.Publisher{Type: bundle.SignerKeyless, Issuer: issuer, Identity: identity,
			Provenance: bundle.ProvenanceRule{SourceRepository: frozenA.Record.Source.Repository, Builder: compatBuilder}}
		if root != "" {
			p.TrustRoot = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: root}
		}
		return bundle.BundleSource{Name: frozenA.Record.Name, Repository: repo, Publisher: p}
	}
	rule := func(repo string) bundle.BundleSource { return ruleWith(repo, issuerA, stackIdentity, stackRoot) }
	check := func(src bundle.BundleSource, d string) release.ReleaseCheck {
		return release.ReleaseCheck{Source: src, Digest: d, Verifier: v, Transport: transport}
	}

	record := func(name string, ok bool, err error, detail string) {
		name = fmt.Sprintf(stackCaseFormat, name)
		if ok {
			err = nil
		} else if err == nil {
			err = errors.New("unexpected acceptance")
		}
		env.Record(name, err, detail)
		if !ok {
			t.Errorf("%s: %v (%s)", name, err, detail)
		}
	}
	// refused records a case that must be refused with one of wants.
	refused := func(name string, err error, wants ...error) {
		ok := err != nil
		if ok && len(wants) > 0 {
			ok = false
			for _, w := range wants {
				ok = ok || errors.Is(err, w)
			}
		}
		detail := "accepted"
		if err != nil {
			detail = err.Error()
			if len(detail) > 400 {
				detail = "..." + detail[len(detail)-400:]
			}
		}
		if ok {
			env.Record(fmt.Sprintf(stackCaseFormat, name), nil, "refused: "+detail)
			return
		}
		record(name, false, fmt.Errorf("want one of %v, got: %s", wants, detail), "")
	}

	// publishSigned publishes f into repo and has the release signer sign and
	// attest it keylessly as identity at issuer.
	publishSigned := func(f *publish.Frozen, host, repo, issuer, identity string, authRead bool) (*publish.Result, error) {
		token := s.issuers[issuer].token(t, identity, 10*time.Minute)
		environ := append(s.cosignEnv(), "SIGSTORE_ID_TOKEN="+token)
		w, err := registry.NewClient(registry.Options{Transport: transport, Credentials: hostCred{host: creds}})
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
		signer := &sign.Cosign{Path: wrapper, Mode: sign.Keyless, RegistryCA: caFile, RegistryHost: host, Credential: creds,
			Environ: environ, Timeout: 3 * time.Minute}
		tgt := publish.Target{Repository: repo, Writer: w, Reader: r, ReadBackDelay: 200 * time.Millisecond,
			Proofs: &publish.Completer{Signer: signer, Reader: r, Provenance: in}}
		return publish.Publish(ctx, f, tgt)
	}

	// 1. Valid: tag schema (distribution) and referrers API (Zot, htpasswd
	// writes, anonymous reads, as on ghcr.io).
	repoTag := env.Anon + "/bundles/keyless-stack"
	repoAPI := env.APIAuthd + "/bundles/keyless-stack"
	var (
		acc *verify.Accepted
		res *registry.Result
	)
	for _, c := range []struct{ label, host, repo string }{
		{"distribution registry (tag schema)", env.Anon, repoTag},
		{"Zot (referrers API), htpasswd writes", env.APIAuthd, repoAPI},
	} {
		pr, err := publishSigned(frozenA, c.host, c.repo, issuerA, stackIdentity, false)
		record("publish and sign keylessly with the pinned Cosign: "+c.label,
			err == nil && pr.Complete && fmt.Sprint(pr.ProofsAdded) == "[signature provenance]", err, "")
		if err != nil {
			t.Fatalf("keyless publication failed; the remaining cases need it: %v", err)
		}
		a, r, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(c.repo), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenA.Record})
		ok := err == nil && a.Receipt.Signer == (bundle.Signer{Kind: bundle.SignerKeyless, Issuer: issuerA, Identity: stackIdentity}) &&
			a.Receipt.TrustRevision == rootRev && a.Receipt.TrustRoot == "ConfigMap/"+stackRoot+"["+bundle.DefaultTrustRootKey+"]" &&
			a.Receipt.Subject.Digest == frozenA.ManifestDigest && a.Receipt.Provenance.Revision == frozenA.Record.Source.Commit &&
			a.Receipt.Provenance.BuilderRevision == builderRevision &&
			fmt.Sprint(a.Proofs.Signature.EvidenceKinds) == "[log-integrated-time rfc3161-timestamp transparency-log]" &&
			fmt.Sprint(a.Proofs.Provenance.EvidenceKinds) == "[log-integrated-time rfc3161-timestamp transparency-log]"
		detail := ""
		if a != nil {
			leaf := leafOf(t, a.Proofs.Signature.ProofManifestDigest, r)
			detail = fmt.Sprintf("signer %s %s, trust %s (%s), evidence %v, signing time %s, certificate %s to %s",
				a.Receipt.Signer.Issuer, a.Receipt.Signer.Identity, a.Receipt.TrustRevision, a.Receipt.TrustRoot, a.Proofs.Signature.EvidenceKinds,
				a.Proofs.Signature.SigningTime.Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		record("verify-release accepts it under the test root, issuer and identity: "+c.label, ok, err, detail)
		if acc == nil && a != nil {
			acc, res = a, r
		}
	}
	if acc == nil {
		t.Fatal("no accepted keyless release")
	}

	// The isolated root is never trusted implicitly.
	_, _, err = release.VerifyRelease(ctx, check(ruleWith(repoTag, issuerA, stackIdentity, ""), frozenA.ManifestDigest))
	refused("the same proofs under the embedded public-good root", err, verify.ErrSignature, verify.ErrTransparency, verify.ErrSigningTime)

	// 2. Wrong issuer: a real certificate from the other trusted issuer, and
	// rules naming another or a near-miss issuer.
	repoB := env.Anon + "/bundles/keyless-stack-issuer-b"
	if pr, err := publishSigned(frozenA, env.Anon, repoB, issuerB, stackIdentity, false); err != nil || !pr.Complete {
		t.Fatalf("publish as issuer B: %v", err)
	}
	_, _, err = release.VerifyRelease(ctx, check(rule(repoB), frozenA.ManifestDigest))
	refused("same identity, certificate from another issuer the instance trusts", err, verify.ErrSigner)
	if _, _, err := release.VerifyRelease(ctx, check(ruleWith(repoB, issuerB, stackIdentity, stackRoot), frozenA.ManifestDigest)); err != nil {
		record("control: the issuer-B release verifies under an issuer-B rule", false, err, "")
	}
	for _, iss := range []string{issuerB, issuerA + "/", issuerA + ".evil.test", strings.TrimSuffix(issuerA, "t"), "https://ISSUER-A.test"} {
		_, err := release.CheckRelease(ctx, check(ruleWith(repoTag, iss, stackIdentity, stackRoot), frozenA.ManifestDigest), res)
		refused("rule issuer "+iss+" for an issuer-A certificate", err, verify.ErrSigner)
	}

	// 3. Wrong identity: a real certificate for another identity at the same
	// issuer, and near-miss rules.
	repoM := env.Anon + "/bundles/keyless-stack-other-identity"
	if pr, err := publishSigned(frozenA, env.Anon, repoM, issuerA, stackOther, false); err != nil || !pr.Complete {
		t.Fatalf("publish as another identity: %v", err)
	}
	_, _, err = release.VerifyRelease(ctx, check(rule(repoM), frozenA.ManifestDigest))
	refused("another identity at the same issuer", err, verify.ErrSigner)
	for _, id := range []string{stackOther, strings.TrimSuffix(stackIdentity, ".test"), stackIdentity + ".evil.test", "x" + stackIdentity, strings.ToUpper(stackIdentity)} {
		_, err := release.CheckRelease(ctx, check(ruleWith(repoTag, issuerA, id, stackRoot), frozenA.ManifestDigest), res)
		refused(fmt.Sprintf("rule identity %q for certificate identity %q", id, stackIdentity), err, verify.ErrSigner, verify.ErrTrustConfig)
	}

	// 4. Wrong subject: valid proofs of A attached to B in the registry, and
	// listed for B by the consumer adapter.
	repoMoved := env.Anon + "/bundles/keyless-stack-moved"
	if _, err := publishUnsigned(ctx, frozenB, repoMoved, transport, hostCred{env.Anon: creds}); err != nil {
		t.Fatal(err)
	}
	reattach(t, ctx, repoMoved, pool, frozenB, res.Proofs)
	_, got, err := release.VerifyRelease(ctx, check(rule(repoMoved), frozenB.ManifestDigest))
	listed := got != nil && len(got.Proofs) == 2
	if !listed {
		record("the moved proofs are listed for the other subject", false, err, "")
	}
	refused("proofs of another digest attached to the subject", err, verify.ErrSubject)

	// 5. Signing-time and transparency evidence, removed or tampered.
	editAll := func(edit func(t *testing.T, b map[string]any)) *registry.Result {
		return withProofs(t, res, func(raw []byte) []byte { return editBundle(t, raw, edit) })
	}
	verifyEdited := func(name string, r *registry.Result, wants ...error) {
		_, err := release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), r)
		refused(name, err, wants...)
	}
	verifyEdited("no signing-time evidence: SET and RFC 3161 timestamps removed, inclusion proof kept",
		editAll(func(t *testing.T, b map[string]any) { dropSET(t, b); dropTimestamps(b) }), verify.ErrSigningTime)
	verifyEdited("no transparency log entry", editAll(func(t *testing.T, b map[string]any) {
		vm(b)["tlogEntries"] = []any{}
	}), verify.ErrTransparency)
	verifyEdited("integrated time moved by one second (SET no longer verifies)", editAll(func(t *testing.T, b map[string]any) {
		e := tlog(b)
		var n int64
		fmt.Sscan(fmt.Sprint(e["integratedTime"]), &n)
		e["integratedTime"] = fmt.Sprint(n + 1)
	}), verify.ErrTransparency, verify.ErrSigningTime)
	verifyEdited("signed entry timestamp tampered", editAll(func(t *testing.T, b map[string]any) {
		p := tlog(b)["inclusionPromise"].(map[string]any)
		p["signedEntryTimestamp"] = flipB64(t, p["signedEntryTimestamp"].(string))
	}), verify.ErrTransparency, verify.ErrSigningTime)
	verifyEdited("inclusion proof root hash tampered", editAll(func(t *testing.T, b map[string]any) {
		p := tlog(b)["inclusionProof"].(map[string]any)
		p["rootHash"] = flipB64(t, p["rootHash"].(string))
	}), verify.ErrTransparency)
	verifyEdited("RFC 3161 timestamp tampered, SET removed", editAll(func(t *testing.T, b map[string]any) {
		dropSET(t, b)
		ts := tsList(b)[0].(map[string]any)
		ts["signedTimestamp"] = flipB64(t, ts["signedTimestamp"].(string))
	}), verify.ErrSigningTime)
	_, err = release.CheckRelease(ctx, check(ruleWith(repoTag, issuerA, stackIdentity, stackRootRekor), frozenA.ManifestDigest), res)
	refused("a root with another Rekor key (log entry from an unknown log)", err, verify.ErrTransparency)
	noSET := editAll(func(t *testing.T, b map[string]any) { dropSET(t, b) })
	_, err = release.CheckRelease(ctx, check(ruleWith(repoTag, issuerA, stackIdentity, stackRootNoTSA), frozenA.ManifestDigest), noSET)
	refused("SET removed and a root without the timestamp authority", err, verify.ErrSigningTime)
	if _, err := release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), noSET); err != nil {
		record("control: SET removed, the RFC 3161 timestamp alone is accepted", false, err, "")
	} else {
		env.Record(fmt.Sprintf(stackCaseFormat, "control: SET removed, the RFC 3161 timestamp alone is accepted"), nil, "")
	}

	ev := stackEvidence{
		Run: run, RecordedAt: time.Now().UTC().Format(time.RFC3339), Mode: mode, Components: s.versions(t), Go: runtime.Version(),
		TrustRoot: rootRev, Signing: map[string]string{
			"issuer": issuerA, "identity": stackIdentity, "signingTime": acc.Proofs.Signature.SigningTime.UTC().Format(time.RFC3339),
			"evidence": fmt.Sprint(acc.Proofs.Signature.EvidenceKinds),
		},
	}
	if out, err := exec.Command(cosignBin, "version", "--json").Output(); err == nil {
		var cv struct{ GitVersion string }
		_ = json.Unmarshal(out, &cv)
		ev.Cosign = cv.GitVersion
	}

	// 6. Expired certificate with valid authenticated signing-time evidence.
	expiry := []string{
		"the release verifies after its certificates expired (real clock)",
		"its receipt rechecks as valid after expiry",
		"expired certificate without signing-time evidence",
		"expired certificate with only a post-expiry RFC 3161 timestamp",
		"expired certificate whose first RFC 3161 timestamp is after expiry, the original second",
		"control: a post-expiry timestamp after the original one from the same authority is ignored",
	}
	if mode == "fast" {
		for _, n := range expiry {
			env.Skip(fmt.Sprintf(stackCaseFormat, n), "KONSTAPEL_SIGSTORE_STACK=fast does not wait for certificate expiry")
		}
	} else {
		var notAfter time.Time
		for _, p := range res.Proofs {
			if l := leafOf(t, p.ManifestDigest, res); l.NotAfter.After(notAfter) {
				notAfter = l.NotAfter
			}
		}
		wait := time.Until(notAfter) + 5*time.Second
		t.Logf("waiting %s for the Fulcio certificates to expire at %s", wait.Round(time.Second), notAfter.UTC().Format(time.RFC3339))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		a, r, err := release.VerifyRelease(ctx, release.ReleaseCheck{Source: rule(repoTag), Digest: frozenA.ManifestDigest, Verifier: v, Transport: transport, Record: &frozenA.Record})
		now := time.Now()
		ok := err == nil && now.After(notAfter) && a.Proofs.Signature.SigningTime.Before(notAfter)
		record(expiry[0], ok, err, fmt.Sprintf("now %s, certificate notAfter %s", now.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339)))
		rc, err := v.Recheck(ctx, rule(repoTag), acc.Recheck, res.Layer)
		record(expiry[1], err == nil && rc.Outcome == verify.RecheckValid, err, fmt.Sprintf("outcome %v", outcomeOf(rc)))
		if r == nil {
			r = res
		}
		_, err = release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), withProofs(t, r, func(raw []byte) []byte {
			return editBundle(t, raw, func(t *testing.T, b map[string]any) { dropSET(t, b); dropTimestamps(b) })
		}))
		refused(expiry[2], err, verify.ErrSigningTime)
		// late adds a post-expiry timestamp from the stack's authority: alone
		// (SET removed), before the original or after it. sigstore-go counts
		// one timestamp per authority, the first that verifies.
		late := func(how string) *registry.Result {
			return withProofs(t, r, func(raw []byte) []byte {
				return editBundle(t, raw, func(t *testing.T, b map[string]any) {
					fresh := base64.StdEncoding.EncodeToString(s.timestamp(t, dsseSignature(t, b)))
					entry := map[string]any{"signedTimestamp": fresh}
					switch how {
					case "alone":
						dropSET(t, b)
						tsData(b)["rfc3161Timestamps"] = []any{entry}
					case "first":
						tsData(b)["rfc3161Timestamps"] = append([]any{entry}, tsList(b)...)
					default:
						tsData(b)["rfc3161Timestamps"] = append(tsList(b), entry)
					}
				})
			})
		}
		_, err = release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), late("alone"))
		refused(expiry[3], err, verify.ErrSigningTime)
		_, err = release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), late("first"))
		refused(expiry[4], err, verify.ErrSigningTime)
		_, err = release.CheckRelease(ctx, check(rule(repoTag), frozenA.ManifestDigest), late("last"))
		record(expiry[5], err == nil, err, "accepted on the original in-validity time; the later timestamp is a duplicate authority")
		ev.Expiry = map[string]string{"certificateNotAfter": notAfter.UTC().Format(time.RFC3339), "verifiedAt": now.UTC().Format(time.RFC3339)}
	}

	if out := os.Getenv("KONSTAPEL_REGISTRY_OUTPUT"); out != "" {
		b, _ := json.MarshalIndent(ev, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "sigstore-stack.json"), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func outcomeOf(rc *verify.RecheckResult) string {
	if rc == nil {
		return "none"
	}
	if rc.Reason != nil {
		return fmt.Sprintf("%s (%v)", rc.Outcome, rc.Reason)
	}
	return string(rc.Outcome)
}

// publishUnsigned publishes f without proofs.
func publishUnsigned(ctx context.Context, f *publish.Frozen, repo string, transport http.RoundTripper, creds registry.CredentialProvider) (*publish.Result, error) {
	c, err := registry.NewClient(registry.Options{Transport: transport, Credentials: creds})
	if err != nil {
		return nil, err
	}
	return publish.Publish(ctx, f, publish.Target{Repository: repo, Writer: c, Reader: c, ReadBackDelay: 200 * time.Millisecond})
}

// reattach pushes the given proofs' Sigstore bundles, unchanged, as Cosign
// referrers of f's manifest in repo (the registry maintains the referrers
// tag schema through ORAS).
func reattach(t *testing.T, ctx context.Context, repo string, pool *x509.CertPool, f *publish.Frozen, proofs []registry.Proof) {
	t.Helper()
	r, err := remote.NewRepository(repo)
	if err != nil {
		t.Fatal(err)
	}
	r.Client = &auth.Client{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}}
	push := func(mediaType string, body []byte) {
		d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(body), Size: int64(len(body))}
		if err := r.Push(ctx, d, strings.NewReader(string(body))); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("push %s: %v", d.Digest, err)
		}
	}
	push(ocispec.MediaTypeEmptyJSON, []byte("{}"))
	for _, p := range proofs {
		push(registry.SigstoreBundleArtifactType, p.Bundle)
		m, _ := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "artifactType": registry.SigstoreBundleArtifactType,
			"config":      map[string]any{"mediaType": ocispec.MediaTypeEmptyJSON, "digest": bundle.EmptyConfigDigest, "size": 2},
			"layers":      []any{map[string]any{"mediaType": registry.SigstoreBundleArtifactType, "digest": digest.FromBytes(p.Bundle).String(), "size": len(p.Bundle)}},
			"subject":     map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": f.ManifestDigest, "size": len(f.Manifest)},
			"annotations": map[string]string{"dev.sigstore.bundle.content": "dsse-envelope", registry.PredicateTypeAnnotation: p.PredicateType},
		})
		push(ocispec.MediaTypeImageManifest, m)
	}
}

// withProofs returns a copy of res whose proof bundles are edited, with their
// digests and referrer manifests rewritten to match, as a registry serving
// the edited referrers would list them.
func withProofs(t *testing.T, res *registry.Result, edit func([]byte) []byte) *registry.Result {
	t.Helper()
	c := *res
	c.Proofs = nil
	for _, p := range res.Proofs {
		p.Bundle = edit(append([]byte(nil), p.Bundle...))
		p.BundleDigest = digest.FromBytes(p.Bundle).String()
		var m map[string]any
		if err := json.Unmarshal(p.Manifest, &m); err != nil {
			t.Fatal(err)
		}
		layer := m["layers"].([]any)[0].(map[string]any)
		layer["digest"], layer["size"] = p.BundleDigest, len(p.Bundle)
		p.Manifest, _ = json.Marshal(m)
		p.ManifestDigest = digest.FromBytes(p.Manifest).String()
		c.Proofs = append(c.Proofs, p)
	}
	return &c
}

func editBundle(t *testing.T, raw []byte, edit func(t *testing.T, b map[string]any)) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	edit(t, b)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func vm(b map[string]any) map[string]any { return b["verificationMaterial"].(map[string]any) }

func tlog(b map[string]any) map[string]any {
	return vm(b)["tlogEntries"].([]any)[0].(map[string]any)
}

func tsData(b map[string]any) map[string]any {
	d, ok := vm(b)["timestampVerificationData"].(map[string]any)
	if !ok {
		d = map[string]any{}
		vm(b)["timestampVerificationData"] = d
	}
	return d
}

func tsList(b map[string]any) []any {
	l, _ := tsData(b)["rfc3161Timestamps"].([]any)
	return l
}

// dropSET removes the log's signed entry timestamp, the only thing that
// authenticates the integrated time; the inclusion proof stays.
func dropSET(t *testing.T, b map[string]any) {
	t.Helper()
	e := tlog(b)
	if _, ok := e["inclusionProof"]; !ok {
		t.Fatal("bundle has no inclusion proof")
	}
	delete(e, "inclusionPromise")
	e["integratedTime"] = "0"
}

func dropTimestamps(b map[string]any) { delete(vm(b), "timestampVerificationData") }

func flipB64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		t.Fatalf("not base64: %v", err)
	}
	raw[len(raw)/2] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

// dsseSignature is the DSSE signature bytes, which RFC 3161 timestamps cover.
func dsseSignature(t *testing.T, b map[string]any) []byte {
	t.Helper()
	sig := b["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)["sig"].(string)
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// leafOf is the signing certificate of the proof with the given referrer digest.
func leafOf(t *testing.T, manifestDigest string, res *registry.Result) *x509.Certificate {
	t.Helper()
	for _, p := range res.Proofs {
		if p.ManifestDigest != manifestDigest {
			continue
		}
		var b struct {
			VerificationMaterial struct {
				Certificate struct {
					RawBytes []byte `json:"rawBytes"`
				} `json:"certificate"`
			} `json:"verificationMaterial"`
		}
		if err := json.Unmarshal(p.Bundle, &b); err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(b.VerificationMaterial.Certificate.RawBytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatalf("no proof %s", manifestDigest)
	return nil
}
