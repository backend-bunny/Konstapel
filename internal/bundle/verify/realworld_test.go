package verify

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// Real Cosign v3 CI output: the signature and SLSA provenance referrers of
// ghcr.io/backend-bunny/konstapel:0.1.0, fetched read-only (testdata/ghcr/
// README.md), verified offline against the embedded public-good root. Both
// leaf certificates expired ten minutes after signing (2026-11-09), so this
// is also a real expired-leaf case.
const (
	realSubject  = "sha256:20711e1fbda7982615945cf775fbcc4d245fea428900c5dca4fa701eded20407"
	realIssuer   = "https://token.actions.githubusercontent.com"
	realIdentity = "https://github.com/backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/main"
)

func TestRealCosignV3Proofs(t *testing.T) {
	ctx := context.Background()
	sig := proofFrom(t, registry.ProofSignature, readFixture(t, "ghcr", "signature.manifest.json"), readFixture(t, "ghcr", "signature.bundle.json"))
	prov := proofFrom(t, registry.ProofProvenance, readFixture(t, "ghcr", "provenance.manifest.json"), readFixture(t, "ghcr", "provenance.bundle.json"))
	res := &registry.Result{Digest: realSubject, Proofs: []registry.Proof{prov, sig}}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	v := newVerifier(t, kubeaccess.NewMemoryReader(), clockAt(now))
	src := keylessSource(realIssuer, realIdentity, nil)

	got, err := v.VerifyProofs(ctx, src, res)
	wantErr(t, err)
	for _, p := range []*VerifiedProof{got.Signature, got.Provenance} {
		if p.TrustRootSource != TrustRootPublicGood || p.TrustRootID != "sha256:"+PublicGoodTrustRootSHA256 {
			t.Fatalf("root %s %s", p.TrustRootSource, p.TrustRootID)
		}
		if p.SigningTime.IsZero() || !p.SigningTime.Before(time.Date(2026, 11, 9, 11, 40, 0, 0, time.UTC)) {
			t.Fatalf("signing time %s", p.SigningTime)
		}
		if p.Subject != realSubject || len(p.Statement.Subjects) != 1 {
			t.Fatalf("subject %+v", p.Statement.Subjects)
		}
	}
	if got.Signature.Statement.PredicateType != registry.CosignSignPredicateType ||
		got.Provenance.Statement.PredicateType != registry.SLSAProvenanceV1PredicateType {
		t.Fatalf("predicate types %q %q", got.Signature.Statement.PredicateType, got.Provenance.Statement.PredicateType)
	}
	if got.Provenance.Statement.Subjects[0].Name != "ghcr.io/backend-bunny/konstapel" || got.Signature.Statement.Subjects[0].Name != "" {
		t.Fatalf("subject names %+v %+v", got.Signature.Statement.Subjects, got.Provenance.Statement.Subjects)
	}
	if !bytes.Contains(got.Provenance.Statement.Predicate, []byte(`"buildDefinition"`)) {
		t.Fatal("provenance predicate not exposed")
	}
	// The signature carries a Rekor entry (SET and inclusion proof), an
	// RFC 3161 timestamp and an embedded SCT; the provenance no timestamp.
	for _, c := range []struct {
		p    *VerifiedProof
		want string
	}{
		{got.Signature, "certificate-transparency,log-integrated-time,rfc3161-timestamp,transparency-log"},
		{got.Provenance, "certificate-transparency,log-integrated-time,transparency-log"},
	} {
		if s := strings.Join(kindsString(c.p.EvidenceKinds), ","); s != c.want {
			t.Fatalf("evidence %s, want %s", s, c.want)
		}
	}

	for _, c := range []struct {
		name string
		src  bundle.BundleSource
		subj string
		want error
	}{
		{"identity of another workflow", keylessSource(realIssuer, "https://github.com/backend-bunny/Konstapel/.github/workflows/release-please.yml@refs/heads/main", nil), realSubject, ErrSigner},
		{"identity on another ref", keylessSource(realIssuer, "https://github.com/backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/dev", nil), realSubject, ErrSigner},
		{"another issuer", keylessSource("https://token.actions.githubusercontent.com/", realIdentity, nil), realSubject, ErrSigner},
		{"another subject", src, "sha256:" + realSubject[len(realSubject)-64:len(realSubject)-1] + "0", ErrSubject},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.VerifyProof(ctx, c.src, c.subj, registry.ProofSignature, sig)
			wantErr(t, err, c.want)
		})
	}
	// Trusting the public-good root authorizes no publisher by itself: a
	// keyless rule without an exact issuer and identity is a configuration
	// error, never a match for every identity the root certifies.
	for name, edit := range map[string]func(*bundle.Publisher){
		"empty identity":          func(p *bundle.Publisher) { p.Identity = "" },
		"wildcard identity":       func(p *bundle.Publisher) { p.Identity = "*" },
		"match-anything identity": func(p *bundle.Publisher) { p.Identity = ".*" },
		"identity pattern":        func(p *bundle.Publisher) { p.Identity = "^https://github.com/backend-bunny/.+$" },
		"identity prefix glob":    func(p *bundle.Publisher) { p.Identity = "https://github.com/backend-bunny/Konstapel/*" },
		"empty issuer":            func(p *bundle.Publisher) { p.Issuer = "" },
		"wildcard issuer":         func(p *bundle.Publisher) { p.Issuer = "https://*.githubusercontent.com" },
		"empty builder":           func(p *bundle.Publisher) { p.Provenance.Builder = "" },
		"non-workflow builder":    func(p *bundle.Publisher) { p.Provenance.Builder = "https://ci.example.test/x" },
	} {
		t.Run("open rule: "+name, func(t *testing.T) {
			s := src
			edit(&s.Publisher)
			_, err := v.VerifyProof(ctx, s, realSubject, registry.ProofSignature, sig)
			wantErr(t, err, ErrTrustConfig)
		})
	}
	t.Run("an unrelated operator root replaces the public-good root", func(t *testing.T) {
		r := rootReader(partsOf(t, newVirtualSigstore(t), false).json(t))
		_, err := newVerifier(t, r, clockAt(now)).VerifyProof(ctx, keylessSource(realIssuer, realIdentity, rootRef), realSubject, registry.ProofSignature, sig)
		wantErr(t, err, ErrTransparency)
	})
}
