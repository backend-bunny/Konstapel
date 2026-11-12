package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

var (
	t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(90 * 24 * time.Hour)
)

func acceptValid(t *testing.T, f provFixtures) *Accepted {
	t.Helper()
	acc, err := newVerifier(t, f.reader(), clockAt(t0)).Accept(context.Background(), f.orgSource(), f.result("sign-org", "prov-valid"))
	wantErr(t, err)
	return acc
}

func TestAcceptBuildsReceipt(t *testing.T) {
	f := loadProv(t)
	acc := acceptValid(t, f)
	rc := acc.Receipt
	rule, err := RuleRevision(f.orgSource())
	wantErr(t, err)
	sigM, sigB := readFixture(t, "provenance", "sign-org.manifest.json"), readFixture(t, "provenance", "sign-org.bundle.json")
	provM, provB := readFixture(t, "provenance", "prov-valid.manifest.json"), readFixture(t, "provenance", "prov-valid.bundle.json")
	switch {
	case rc.Version != bundle.HandleVersion || !rc.VerifiedAt.Equal(t0):
		t.Fatalf("version/time %d %s", rc.Version, rc.VerifiedAt)
	case rc.Subject.Name != "konstapel-privileged-containers" || rc.Subject.Version != "0.1.0" || rc.Subject.Digest != f.subject:
		t.Fatalf("subject %+v", rc.Subject)
	case rc.RetrievedFrom != "registry.example.test/fixtures/konstapel-privileged-containers":
		t.Fatalf("retrievedFrom %s", rc.RetrievedFrom)
	case rc.SourceRule != rule || rc.TrustRevision != f.fpOrg || rc.TrustRoot != "Secret/org[cosign.pub]":
		t.Fatalf("rule/trust %s %s %s", rc.SourceRule, rc.TrustRevision, rc.TrustRoot)
	case rc.Signer != (bundle.Signer{Kind: bundle.SignerPublicKey, KeyFingerprint: f.fpOrg}):
		t.Fatalf("signer %+v", rc.Signer)
	case rc.Proofs.Signature.Manifest != sha(sigM) || rc.Proofs.Signature.Bundle != sha(sigB) ||
		rc.Proofs.Attestation.Manifest != sha(provM) || rc.Proofs.Attestation.Bundle != sha(provB) ||
		rc.Proofs.Attestation.Statement != acc.Proofs.Provenance.StatementDigest:
		t.Fatalf("proofs %+v", rc.Proofs)
	case rc.Provenance != bundle.Provenance{PredicateType: bundle.PredicateSLSAProvenanceV1, BuildType: ProvenanceBuildType,
		Repository: provSourceRepo, Revision: provSourceCommit, Builder: provBuilder, Content: f.desc.ContentDigest(),
		BuilderRevision: f.builderRevision}:
		t.Fatalf("provenance %+v", rc.Provenance)
	}
	// The receipt fills a valid resolved-content handle for this subject.
	a := &bundle.Archive{Descriptor: acc.Descriptor, LayerDigest: f.layerDigest, ManifestDigest: f.subject}
	h := bundle.NewHandle(a, bundle.ContentCompatibility{Compatible: true, Provider: "konstapel-kyverno/v1", Konstapel: "0.1.0", OSCAL: []string{"1.1.3"}},
		rc, bundle.Lease{ID: "l", Holder: bundle.HolderProfile, Owner: "profile/x", Digest: f.subject, AcquiredAt: t0})
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := acc.Recheck.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptRejectsForeignContent(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	for name, edit := range map[string]func(r *registry.Result){
		"layer of other bytes":     func(r *registry.Result) { r.Layer = append(bytes.Clone(r.Layer), 0) },
		"manifest of other digest": func(r *registry.Result) { r.Manifest = readFixture(t, "provenance", "other-subject-manifest.json") },
		"no layer":                 func(r *registry.Result) { r.Layer = nil },
	} {
		t.Run(name, func(t *testing.T) {
			res := f.result("sign-org", "prov-valid")
			edit(res)
			_, err := newVerifier(t, f.reader(), nil).Accept(ctx, f.orgSource(), res)
			wantErr(t, err, ErrContent)
		})
	}
}

func TestRuleRevision(t *testing.T) {
	f := loadProv(t)
	base, err := RuleRevision(f.orgSource())
	wantErr(t, err)
	if again, _ := RuleRevision(f.orgSource()); again != base || !strings.HasPrefix(base, "sha256:") || len(base) != 71 {
		t.Fatalf("revision %q is not a stable sha256", base)
	}
	same := map[string]func(s *bundle.BundleSource){
		"mirror repository":         func(s *bundle.BundleSource) { s.Repository = "mirror.example.test/bundles/x" },
		"credential secret":         func(s *bundle.BundleSource) { s.CredentialSecret = &bundle.ObjectRef{Name: "pull"} },
		"custom CA":                 func(s *bundle.BundleSource) { s.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "ca"} },
		"fingerprint prefix":        func(s *bundle.BundleSource) { s.Publisher.KeyFingerprint = strings.TrimPrefix(f.fpOrg, "sha256:") },
		"default key made explicit": func(s *bundle.BundleSource) { s.Publisher.PublicKey.Key = bundle.DefaultPublicKey },
	}
	differ := map[string]func(s *bundle.BundleSource){
		"name":              func(s *bundle.BundleSource) { s.Name = "other" },
		"key reference":     func(s *bundle.BundleSource) { s.Publisher.PublicKey.Name = "other" },
		"key kind":          func(s *bundle.BundleSource) { s.Publisher.PublicKey.Kind = bundle.KindConfigMap },
		"fingerprint":       func(s *bundle.BundleSource) { s.Publisher.KeyFingerprint = f.fpOther },
		"builder":           func(s *bundle.BundleSource) { s.Publisher.Provenance.Builder += "x" },
		"source repository": func(s *bundle.BundleSource) { s.Publisher.Provenance.SourceRepository += "x" },
		"keyless": func(s *bundle.BundleSource) {
			*s = keylessSource(testIssuer, testIdentity, nil)
			s.Publisher.Provenance = f.orgSource().Publisher.Provenance
		},
	}
	for name, edit := range same {
		s := f.orgSource()
		s.Publisher.PublicKey = &bundle.ObjectRef{Kind: s.Publisher.PublicKey.Kind, Name: s.Publisher.PublicKey.Name}
		edit(&s)
		if got, err := RuleRevision(s); err != nil || got != base {
			t.Errorf("%s changed the rule revision (%v)", name, err)
		}
	}
	for name, edit := range differ {
		s := f.orgSource()
		s.Publisher.PublicKey = &bundle.ObjectRef{Kind: s.Publisher.PublicKey.Kind, Name: s.Publisher.PublicKey.Name}
		edit(&s)
		if got, err := RuleRevision(s); err != nil || got == base {
			t.Errorf("%s did not change the rule revision (%v)", name, err)
		}
	}
	k1 := keylessSource(testIssuer, testIdentity, nil)
	k2 := keylessSource(testIssuer, testIdentity, rootRef)
	k3 := keylessSource(testIssuer, testIdentity+"x", nil)
	r1, _ := RuleRevision(k1)
	r2, _ := RuleRevision(k2)
	r3, _ := RuleRevision(k3)
	if r1 == r2 || r1 == r3 {
		t.Error("keyless root reference or identity did not change the revision")
	}
	bad := f.orgSource()
	bad.Publisher.Issuer = "https://issuer.example.test"
	if _, err := RuleRevision(bad); !errors.Is(err, ErrTrustConfig) {
		t.Errorf("invalid rule: %v", err)
	}
}

func TestRecheckBundleEncoding(t *testing.T) {
	f := loadProv(t)
	rb := acceptValid(t, f).Recheck
	raw, err := rb.Encode()
	wantErr(t, err)
	again, _ := rb.Encode()
	if !bytes.Equal(raw, again) {
		t.Fatal("encoding is not deterministic")
	}
	back, err := DecodeRecheckBundle(raw)
	wantErr(t, err)
	if back2, _ := back.Encode(); !bytes.Equal(back2, raw) {
		t.Fatal("does not round-trip")
	}

	marshal := func(edit func(rb *RecheckBundle)) []byte {
		c := *rb
		c.Signature, c.Attestation = RetainedProof{Manifest: bytes.Clone(rb.Signature.Manifest), Bundle: bytes.Clone(rb.Signature.Bundle)},
			RetainedProof{Manifest: bytes.Clone(rb.Attestation.Manifest), Bundle: bytes.Clone(rb.Attestation.Bundle)}
		c.SubjectManifest = bytes.Clone(rb.SubjectManifest)
		edit(&c)
		out, err := json.Marshal(&c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	flip := func(b []byte) { b[len(b)/2] ^= 0x01 }
	var indented bytes.Buffer
	_ = json.Indent(&indented, raw, "", " ")
	cases := map[string][]byte{
		"unknown field":        bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"trusted":true,"version":1,`), 1),
		"repeated key":         bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"version":1,"version":1,`), 1),
		"case-variant key":     bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"Version":1,`), 1),
		"trailing data":        append(bytes.Clone(raw), []byte(" {}")...),
		"not canonical":        indented.Bytes(),
		"version 2":            marshal(func(c *RecheckBundle) { c.Version = 2 }),
		"oversized":            append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxRecheckBytes)...),
		"not JSON":             []byte("\x00"),
		"subject bytes edited": marshal(func(c *RecheckBundle) { flip(c.SubjectManifest) }),
		"signature bundle edited": marshal(func(c *RecheckBundle) {
			c.Signature.Bundle = bytes.Replace(c.Signature.Bundle, []byte(`"mediaType"`), []byte(` "mediaType"`), 1)
		}),
		"attestation manifest edited": marshal(func(c *RecheckBundle) { flip(c.Attestation.Manifest) }),
		"proofs swapped":              marshal(func(c *RecheckBundle) { c.Signature, c.Attestation = c.Attestation, c.Signature }),
		"receipt subject edited":      marshal(func(c *RecheckBundle) { c.Receipt.Subject.Digest = f.otherSubject }),
		"receipt bundle digest edited": marshal(func(c *RecheckBundle) {
			c.Receipt.Proofs.Signature.Bundle = "sha256:" + strings.Repeat("0", 64)
		}),
		"receipt statement digest edited": marshal(func(c *RecheckBundle) {
			c.Receipt.Proofs.Attestation.Statement = "sha256:" + strings.Repeat("0", 64)
		}),
		"receipt without signer": marshal(func(c *RecheckBundle) { c.Receipt.Signer = bundle.Signer{} }),
		"empty subject":          marshal(func(c *RecheckBundle) { c.SubjectManifest = nil }),
		"oversized manifest": marshal(func(c *RecheckBundle) {
			c.Attestation.Manifest = append(c.Attestation.Manifest, bytes.Repeat([]byte(" "), MaxRetainedManifestBytes)...)
		}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeRecheckBundle(in)
			wantErr(t, err, ErrRecheckBundle)
		})
	}
}

func TestRecheckUnderCurrentTrust(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	rb := acceptValid(t, f).Recheck
	later := newVerifier(t, f.reader(), clockAt(t1))

	t.Run("unchanged trust", func(t *testing.T) {
		got, err := later.Recheck(ctx, f.orgSource(), rb, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckValid || len(got.Differences) != 0 || !got.Current.Receipt.VerifiedAt.Equal(t1) {
			t.Fatalf("%+v", got)
		}
		cur := got.Current.Receipt
		cur.VerifiedAt = rb.Receipt.VerifiedAt
		if cur != rb.Receipt {
			t.Fatalf("recomputed receipt %+v differs from %+v", cur, rb.Receipt)
		}
	})

	// The receipt is data to compare with, never authority: edited claims
	// are reported against the recomputed ones.
	edited := func(edit func(r *bundle.Receipt)) *RecheckBundle {
		c := *rb
		edit(&c.Receipt)
		return &c
	}
	for name, c := range map[string]struct {
		rb   *RecheckBundle
		diff []string
	}{
		"forged signer":          {edited(func(r *bundle.Receipt) { r.Signer.KeyFingerprint = f.fpOther }), []string{"signer"}},
		"forged builder":         {edited(func(r *bundle.Receipt) { r.Provenance.Builder = "https://ci.example.test/other" }), []string{"provenance"}},
		"forged trust revision":  {edited(func(r *bundle.Receipt) { r.TrustRevision = "sha256:" + strings.Repeat("e", 64) }), []string{"trustRevision"}},
		"forged rule revision":   {edited(func(r *bundle.Receipt) { r.SourceRule = "sha256:" + strings.Repeat("e", 64) }), []string{"sourceRule"}},
		"forged source revision": {edited(func(r *bundle.Receipt) { r.Provenance.Revision = f.builderRevision }), []string{"provenance"}},
		"forged version":         {edited(func(r *bundle.Receipt) { r.Subject.Version = "9.9.9" }), []string{"subject"}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := later.Recheck(ctx, f.orgSource(), c.rb, f.layer)
			wantErr(t, err)
			if got.Outcome != RecheckChanged || !slices.Equal(got.Differences, c.diff) || got.Current.Receipt.Signer.KeyFingerprint != f.fpOrg {
				t.Fatalf("%+v", got)
			}
		})
	}

	t.Run("receipt claiming success over evidence that does not verify", func(t *testing.T) {
		// Evidence signed by another key, with the receipt's digests made
		// consistent, so only verification can reject it.
		c := *rb
		for _, p := range []struct {
			slot   *RetainedProof
			digest *bundle.ProofDigests
			name   string
		}{{&c.Signature, &c.Receipt.Proofs.Signature, "sign-other"}, {&c.Attestation, &c.Receipt.Proofs.Attestation, "prov-valid-other"}} {
			src := f.proofs[p.name]
			*p.slot = RetainedProof{Manifest: src.Manifest, Bundle: src.Bundle}
			*p.digest = bundle.ProofDigests{Manifest: src.ManifestDigest, Bundle: src.BundleDigest, Statement: statementDigest(t, src.Bundle)}
		}
		if err := c.Check(); err != nil {
			t.Fatalf("consistent forgery should pass the integrity check: %v", err)
		}
		got, err := later.Recheck(ctx, f.orgSource(), &c, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, ErrSignature) || got.Current != nil {
			t.Fatalf("%+v", got)
		}
	})

	otherKey := f.orgSource()
	otherKey.Publisher.PublicKey.Name, otherKey.Publisher.KeyFingerprint = "other", f.fpOther
	renamed := f.orgSource()
	renamed.Publisher.PublicKey.Name = "org-renamed"
	r2 := f.reader()
	putValue(r2, bundle.KindSecret, "org-renamed", bundle.DefaultPublicKey, f.pubOrg)
	t.Run("rule moved to another key reference with the same key", func(t *testing.T) {
		got, err := newVerifier(t, r2, clockAt(t1)).Recheck(ctx, renamed, rb, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckChanged || !slices.Equal(got.Differences, []string{"sourceRule", "trustRoot"}) {
			t.Fatalf("%+v", got)
		}
	})

	for name, c := range map[string]struct {
		src  bundle.BundleSource
		want error
	}{
		"rule now requires another key":     {otherKey, ErrSignature},
		"rule now requires another builder": {func() bundle.BundleSource { s := f.orgSource(); s.Publisher.Provenance.Builder += "/v2"; return s }(), ErrProvenanceBuilder},
		"rule now requires another source": {func() bundle.BundleSource {
			s := f.orgSource()
			s.Publisher.Provenance.SourceRepository += "-fork"
			return s
		}(), ErrProvenanceSource},
		"rule now requires keyless signing": {func() bundle.BundleSource {
			s := keylessSource(testIssuer, testIdentity, nil)
			s.Publisher.Provenance = f.orgSource().Publisher.Provenance
			return s
		}(), ErrSigner},
		"rule now serves another bundle name": {func() bundle.BundleSource { s := f.orgSource(); s.Name = "renamed"; return s }(), ErrProvenanceRelease},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := later.Recheck(ctx, c.src, rb, f.layer)
			wantErr(t, err)
			if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, c.want) {
				t.Fatalf("%+v", got)
			}
		})
	}

	t.Run("source removed", func(t *testing.T) {
		got, err := later.RecheckSource(ctx, bundle.Sources{Version: 1}, "konstapel-privileged-containers", rb, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, bundle.ErrUnconfigured) {
			t.Fatalf("%+v", got)
		}
		got, err = later.RecheckSource(ctx, bundle.Sources{Version: 1, Sources: []bundle.BundleSource{f.orgSource()}}, "konstapel-privileged-containers", rb, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckValid {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("unreadable or inconsistent trust input is an error", func(t *testing.T) {
		missing := f.orgSource()
		missing.Publisher.PublicKey.Name = "deleted"
		_, err := later.Recheck(ctx, missing, rb, f.layer)
		wantErr(t, err, ErrTrustConfig)
		swapped := f.reader()
		putValue(swapped, bundle.KindSecret, "org", bundle.DefaultPublicKey, f.pubOther)
		_, err = newVerifier(t, swapped, clockAt(t1)).Recheck(ctx, f.orgSource(), rb, f.layer)
		wantErr(t, err, ErrKeyFingerprint)
	})

	t.Run("tampered retained bytes", func(t *testing.T) {
		c := *rb
		c.Attestation.Bundle = append(bytes.Clone(rb.Attestation.Bundle), ' ')
		_, err := later.Recheck(ctx, f.orgSource(), &c, f.layer)
		wantErr(t, err, ErrRecheckBundle)
		_, err = later.Recheck(ctx, f.orgSource(), nil, f.layer)
		wantErr(t, err, ErrRecheckBundle)
	})

	t.Run("layer that is not the subject's", func(t *testing.T) {
		_, err := later.Recheck(ctx, f.orgSource(), rb, append(bytes.Clone(f.layer), 0))
		wantErr(t, err, ErrContent)
	})

	t.Run("decoded material rechecks the same", func(t *testing.T) {
		raw, err := rb.Encode()
		wantErr(t, err)
		back, err := DecodeRecheckBundle(raw)
		wantErr(t, err)
		got, err := later.Recheck(ctx, f.orgSource(), back, f.layer)
		wantErr(t, err)
		if got.Outcome != RecheckValid {
			t.Fatalf("%+v", got)
		}
	})
}

func statementDigest(t *testing.T, bundleJSON []byte) string {
	t.Helper()
	var m struct {
		DsseEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleJSON, &m); err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(m.DsseEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return sha(p)
}

// Keyless recheck: the retained evidence is judged at its authenticated
// signing time under whatever root is configured now.
func TestRecheckKeylessRootChanges(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	vs, other := newVirtualSigstore(t), newVirtualSigstore(t)
	sig, leaf := keylessBundle(t, vs, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: statementFor(f.subject, registry.CosignSignPredicateType)})
	prov, _ := keylessBundle(t, vs, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: provenanceStatement(t, f.subject, f.validPredicate)})
	src := keylessSource(testIssuer, testIdentity, rootRef)
	src.Publisher.Provenance = bundle.ProvenanceRule{SourceRepository: provSourceRepo, Builder: provBuilder}
	res := f.result()
	res.Proofs = []registry.Proof{referrerProof(t, registry.ProofSignature, f.subject, sig), referrerProof(t, registry.ProofProvenance, f.subject, prov)}
	good := partsOf(t, vs, false).json(t)
	r := rootReader(good)
	now := time.Now()
	acc, err := newVerifier(t, r, clockAt(now)).Accept(ctx, src, res)
	wantErr(t, err)
	rb := acc.Recheck

	// Long after the short-lived leaf expired, under the same root: valid.
	afterExpiry := leaf.NotAfter.Add(30 * 24 * time.Hour)
	got, err := newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, src, rb, f.layer)
	wantErr(t, err)
	if got.Outcome != RecheckValid || !got.Current.Receipt.VerifiedAt.Equal(afterExpiry) {
		t.Fatalf("%+v", got)
	}

	// The root is replaced by an unrelated one: invalid.
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, partsOf(t, other, false).json(t))
	got, err = newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, src, rb, f.layer)
	wantErr(t, err)
	if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, ErrTransparency) {
		t.Fatalf("%+v", got)
	}

	// A root that also lists the other instance: valid, but the trust
	// revision differs from the receipt.
	both := partsOf(t, vs, false)
	np := partsOf(t, other, false)
	both.cas = append(both.cas, np.cas...)
	for k, l := range np.rekor {
		both.rekor[k] = l
	}
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, both.json(t))
	got, err = newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, src, rb, f.layer)
	wantErr(t, err)
	if got.Outcome != RecheckChanged || !slices.Equal(got.Differences, []string{"trustRevision"}) {
		t.Fatalf("%+v", got)
	}

	// The certificate authority's validity in the current root ended before
	// the signing time: invalid.
	expired := partsOf(t, vs, false)
	for i, c := range expired.cas {
		fc := *c.(*root.FulcioCertificateAuthority)
		fc.ValidityPeriodEnd = leaf.NotBefore.Add(-time.Hour)
		expired.cas[i] = &fc
	}
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, expired.json(t))
	got, err = newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, src, rb, f.layer)
	wantErr(t, err)
	if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, ErrSignature) {
		t.Fatalf("%+v", got)
	}

	// The rule now names another identity: invalid.
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, good)
	moved := src
	moved.Publisher.Identity = testIdentity + "-v2"
	got, err = newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, moved, rb, f.layer)
	wantErr(t, err)
	if got.Outcome != RecheckInvalid || !errors.Is(got.Reason, ErrSigner) {
		t.Fatalf("%+v", got)
	}

	// Unreadable root: error, not a verdict.
	r.FailWith(errors.New("apiserver unavailable"))
	_, err = newVerifier(t, r, clockAt(afterExpiry)).Recheck(ctx, src, rb, f.layer)
	wantErr(t, err, ErrTrustConfig)
}

// ---- credentials never reach the receipt or the recheck material ---------

const (
	plantedUser     = "planted-user-5d1c"
	plantedPassword = "planted-password-8e2f-SECRET"
)

type staticCreds struct{ c registry.Credential }

func (s staticCreds) Credential(context.Context, bundle.BundleSource, string) (registry.Credential, error) {
	return s.c, nil
}

// authRegistry serves the fixture subject, its layer and two referrers
// behind Basic authentication.
type authRegistry struct {
	blobs, manifests map[string][]byte
	referrers        []map[string]any
	authorized       atomic.Int64
	refused          atomic.Int64
}

func (a *authRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != plantedUser || p != plantedPassword {
		a.refused.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	a.authorized.Add(1)
	const prefix = "/v2/fixtures/konstapel-privileged-containers/"
	if r.URL.Path == "/v2/" {
		return
	}
	kind, ref, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
	switch kind {
	case "manifests":
		b, ok := a.manifests[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		if r.Method == http.MethodGet {
			w.Write(b)
		}
	case "blobs":
		b, ok := a.blobs[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	case "referrers":
		body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": a.referrers})
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Write(body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestReceiptExcludesCredentials(t *testing.T) {
	f := loadProv(t)
	ctx := context.Background()
	reg := &authRegistry{blobs: map[string][]byte{f.layerDigest: f.layer, bundle.EmptyConfigDigest: []byte("{}")},
		manifests: map[string][]byte{f.subject: f.manifest}}
	for _, n := range []string{"sign-org", "prov-valid"} {
		p := f.proofs[n]
		reg.manifests[p.ManifestDigest] = p.Manifest
		reg.blobs[p.BundleDigest] = p.Bundle
		reg.referrers = append(reg.referrers, map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": p.ManifestDigest, "size": len(p.Manifest),
			"artifactType": registry.SigstoreBundleArtifactType,
			"annotations":  map[string]string{registry.PredicateTypeAnnotation: predicateTypes[p.Kind]},
		})
	}
	srv := httptest.NewServer(reg)
	defer srv.Close()

	client, err := registry.NewClient(registry.Options{
		Transport:         &http.Transport{},
		Credentials:       staticCreds{registry.Credential{Username: plantedUser, Password: plantedPassword}},
		TestOnlyPlainHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	src := f.orgSource()
	src.Repository = strings.TrimPrefix(srv.URL, "http://") + "/fixtures/konstapel-privileged-containers"
	src.CredentialSecret = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "registry-pull"}
	res, err := client.Fetch(ctx, src, f.subject)
	if err != nil {
		t.Fatal(err)
	}
	if reg.authorized.Load() == 0 {
		t.Fatal("the fetch was not authenticated")
	}
	acc, err := newVerifier(t, f.reader(), clockAt(t0)).Accept(ctx, src, res)
	wantErr(t, err)
	receiptJSON, err := json.Marshal(acc.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	rbJSON, err := acc.Recheck.Encode()
	wantErr(t, err)
	provJSON, _ := json.Marshal(acc.Provenance)

	basic := base64.StdEncoding.EncodeToString([]byte(plantedUser + ":" + plantedPassword))
	forbidden := []string{plantedUser, plantedPassword, basic, "Authorization", "authorization", "Basic ", "Bearer", "bearer ",
		"PRIVATE KEY", "-----BEGIN", "auths", "dockerconfigjson", "identitytoken", "registrytoken", "password"}
	for name, out := range map[string][]byte{"receipt": receiptJSON, "recheck material": rbJSON, "provenance": provJSON} {
		// Also the decoded retained bytes, which are base64 inside the JSON.
		var rb RecheckBundle
		_ = json.Unmarshal(rbJSON, &rb)
		scan := [][]byte{out, rb.SubjectManifest, rb.Signature.Manifest, rb.Signature.Bundle, rb.Attestation.Manifest, rb.Attestation.Bundle}
		for _, s := range forbidden {
			for _, b := range scan {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s contains %q", name, s)
				}
			}
		}
	}
	if acc.Receipt.RetrievedFrom != src.Repository {
		t.Fatalf("retrievedFrom %q", acc.Receipt.RetrievedFrom)
	}
	// The credential source is transport configuration, not trust: it does
	// not change the rule revision.
	anon := src
	anon.CredentialSecret = nil
	if a, _ := RuleRevision(anon); a != acc.Receipt.SourceRule {
		t.Fatal("credential reference changed the rule revision")
	}
}
