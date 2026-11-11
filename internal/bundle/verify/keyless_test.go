package verify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

const (
	testIssuer   = "https://token.actions.example.test"
	testIdentity = "https://git.example.test/org/policies/.github/workflows/bundle-release.yml@refs/heads/main"
)

var keylessSubject = "sha256:" + strings.Repeat("3c", 32)

var rootRef = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "sigstore-root"}

func rootReader(rootJSON []byte) *kubeaccess.MemoryReader {
	r := kubeaccess.NewMemoryReader()
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, rootJSON)
	return r
}

func clockAt(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestKeyless(t *testing.T) {
	ctx := context.Background()
	good := newVirtualSigstore(t) // the configured Sigstore instance
	evil := newVirtualSigstore(t) // an unrelated instance (another root)
	rootJSON := partsOf(t, good, false).json(t)
	sign := statementFor(keylessSubject, registry.CosignSignPredicateType)
	base := keylessOpts{identity: testIdentity, issuer: testIssuer, statement: sign}
	with := func(edit func(*keylessOpts)) keylessOpts { o := base; edit(&o); return o }
	in30Days := time.Now().Add(30 * 24 * time.Hour)

	type tc struct {
		name    string
		vs      *ca.VirtualSigstore
		opts    keylessOpts
		src     bundle.BundleSource
		root    []byte
		kind    registry.ProofKind
		clock   time.Time
		want    []error
		evident []EvidenceKind
	}
	src := keylessSource(testIssuer, testIdentity, rootRef)
	cases := []tc{
		{name: "valid with log time and RFC 3161 time", opts: base,
			evident: []EvidenceKind{EvidenceLogIntegratedTime, EvidenceRFC3161, EvidenceTransparencyLog}},
		{name: "valid with RFC 3161 time only (log entry proven, no SET)", opts: with(func(o *keylessOpts) { o.noSET = true }),
			evident: []EvidenceKind{EvidenceRFC3161, EvidenceTransparencyLog}},
		{name: "valid with log time only", opts: with(func(o *keylessOpts) { o.noTSA = true }),
			evident: []EvidenceKind{EvidenceLogIntegratedTime, EvidenceTransparencyLog}},
		{name: "valid provenance attestation", kind: registry.ProofProvenance,
			opts: with(func(o *keylessOpts) {
				o.statement = statementFor(keylessSubject, registry.SLSAProvenanceV1PredicateType)
			})},
		{name: "leaf expired after a valid authenticated signing time", opts: base, clock: in30Days},
		{name: "leaf expired after a valid RFC 3161 time", opts: with(func(o *keylessOpts) { o.noSET = true }), clock: in30Days},

		{name: "wrong issuer", src: keylessSource("https://other-issuer.example.test", testIdentity, rootRef), opts: base, want: []error{ErrSigner}},
		{name: "wrong identity", src: keylessSource(testIssuer, "https://git.example.test/org/other/.github/workflows/x.yml@refs/heads/main", rootRef), opts: base, want: []error{ErrSigner}},
		{name: "identity prefix of the configured one", opts: with(func(o *keylessOpts) { o.identity = testIdentity[:len(testIdentity)-1] }), want: []error{ErrSigner}},
		{name: "identity with a suffix", opts: with(func(o *keylessOpts) { o.identity = testIdentity + "x" }), want: []error{ErrSigner}},
		{name: "identity in another case", opts: with(func(o *keylessOpts) { o.identity = strings.ToUpper(testIdentity) }), want: []error{ErrSigner}},
		{name: "issuer with a trailing slash", opts: with(func(o *keylessOpts) { o.issuer = testIssuer + "/" }), want: []error{ErrSigner}},
		{name: "configured identity is a pattern", src: keylessSource(testIssuer, "https://git.example.test/.*", rootRef), opts: base, want: []error{ErrTrustConfig}},

		{name: "no transparency log entry", opts: with(func(o *keylessOpts) { o.noTlog = true }), want: []error{ErrTransparency}},
		{name: "log entry from a log outside the root", opts: with(func(o *keylessOpts) { o.logFrom = evil }), want: []error{ErrTransparency}},
		{name: "no authenticated signing time", opts: with(func(o *keylessOpts) { o.noSET = true; o.noTSA = true }), want: []error{ErrSigningTime}},
		{name: "signing time only from an authority outside the root", opts: with(func(o *keylessOpts) { o.noSET = true; o.tsaFrom = evil }), want: []error{ErrSigningTime}},
		{name: "expired leaf, signing time after expiry", clock: in30Days,
			opts: with(func(o *keylessOpts) { o.at = time.Now().Add(15 * time.Minute) }), want: []error{ErrSigningTime}},
		{name: "expired leaf, no authenticated signing time", clock: in30Days,
			opts: with(func(o *keylessOpts) { o.noSET = true; o.noTSA = true }), want: []error{ErrSigningTime}},
		{name: "expired leaf, signing time from an authority outside the root", clock: in30Days,
			opts: with(func(o *keylessOpts) { o.noSET = true; o.tsaFrom = evil }), want: []error{ErrSigningTime}},
		{name: "signing time in the future", clock: time.Now().Add(-time.Hour), opts: base, want: []error{ErrSigningTime}},

		{name: "signed for another subject", opts: with(func(o *keylessOpts) {
			o.statement = statementFor("sha256:"+strings.Repeat("4d", 32), registry.CosignSignPredicateType)
		}), want: []error{ErrSubject}},
		{name: "wrong predicate type", opts: with(func(o *keylessOpts) { o.statement = statementFor(keylessSubject, "https://example.test/other/v1") }), want: []error{ErrPredicateType}},
		{name: "signature presented as provenance", kind: registry.ProofProvenance, opts: base, want: []error{ErrPredicateType}},

		{name: "certificate from another root, evidence from the configured instance", vs: evil,
			opts: with(func(o *keylessOpts) { o.logFrom = good; o.tsaFrom = good }), want: []error{ErrSignature}},
		{name: "everything from another root", vs: evil, opts: base, want: []error{ErrTransparency}},
		{name: "root swapped to another instance", root: partsOf(t, evil, false).json(t), opts: base, want: []error{ErrTransparency}},
		{name: "root with the configured logs but another CA", root: rootParts{cas: evil.FulcioCertificateAuthorities(),
			tsas: good.TimestampingAuthorities(), rekor: logsByRawID(t, good.RekorLogs())}.json(t), opts: base, want: []error{ErrSignature}},
		{name: "root requires certificate transparency, leaf has no SCT", root: partsOf(t, good, true).json(t), opts: base, want: []error{ErrSignature}},
		{name: "default public-good root does not trust test instances", src: keylessSource(testIssuer, testIdentity, nil), opts: base, want: []error{ErrTransparency}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := c.vs
			if vs == nil {
				vs = good
			}
			raw, leaf := keylessBundle(t, vs, c.opts)
			s := c.src
			if s.Name == "" {
				s = src
			}
			rj := c.root
			if rj == nil {
				rj = rootJSON
			}
			clock := c.clock
			if clock.IsZero() {
				clock = time.Now()
			}
			kind := c.kind
			if kind == "" {
				kind = registry.ProofSignature
			}
			got, err := newVerifier(t, rootReader(rj), clockAt(clock)).VerifyProof(ctx, s, keylessSubject, kind, rawProof(kind, raw))
			wantErr(t, err, c.want...)
			if err != nil {
				return
			}
			sum := sha256.Sum256(rj)
			if got.TrustRootID != "sha256:"+hex.EncodeToString(sum[:]) || got.TrustRootSource != "ConfigMap/sigstore-root[trusted_root.json]" {
				t.Fatalf("trust root %q from %q", got.TrustRootID, got.TrustRootSource)
			}
			if got.Signer != (bundle.Signer{Kind: bundle.SignerKeyless, Issuer: testIssuer, Identity: testIdentity}) {
				t.Fatalf("signer %+v", got.Signer)
			}
			if got.SigningTime.Before(leaf.NotBefore) || got.SigningTime.After(leaf.NotAfter) || !got.VerifiedAt.Equal(clock.UTC()) {
				t.Fatalf("signing time %s outside leaf validity %s-%s or verifiedAt %s", got.SigningTime, leaf.NotBefore, leaf.NotAfter, got.VerifiedAt)
			}
			if c.clock.After(leaf.NotAfter) && !got.VerifiedAt.After(leaf.NotAfter) {
				t.Fatal("expired-leaf case did not verify after expiry")
			}
			if c.evident != nil && strings.Join(kindsString(got.EvidenceKinds), ",") != strings.Join(kindsString(c.evident), ",") {
				t.Fatalf("evidence kinds %v, want %v", got.EvidenceKinds, c.evident)
			}
		})
	}
}

func kindsString(ks []EvidenceKind) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return out
}

func TestKeylessRootChangeChangesOutcome(t *testing.T) {
	ctx := context.Background()
	oldVS, newVS := newVirtualSigstore(t), newVirtualSigstore(t)
	oldRoot, newRoot := partsOf(t, oldVS, false).json(t), partsOf(t, newVS, false).json(t)
	raw, _ := keylessBundle(t, oldVS, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: statementFor(keylessSubject, registry.CosignSignPredicateType)})
	r := rootReader(oldRoot)
	v := newVerifier(t, r, nil)
	src := keylessSource(testIssuer, testIdentity, rootRef)
	first, err := v.VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
	wantErr(t, err)
	// The operator replaces the root: the same verifier reads it again and
	// the proof valid only under the old root is rejected.
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, newRoot)
	_, err = v.VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
	wantErr(t, err, ErrTransparency)
	// A root listing both instances accepts it again, under a new root ID.
	both := partsOf(t, oldVS, false)
	np := partsOf(t, newVS, false)
	both.cas = append(both.cas, np.cas...)
	for k, l := range np.rekor {
		both.rekor[k] = l
	}
	putValue(r, bundle.KindConfigMap, rootRef.Name, bundle.DefaultTrustRootKey, both.json(t))
	again, err := v.VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
	wantErr(t, err)
	if again.TrustRootID == first.TrustRootID {
		t.Fatal("root ID did not change with the root")
	}
	if r.Reads(bundle.KindConfigMap, rootRef.Name) != 3 {
		t.Fatalf("root read %d times; each verification must read the current root", r.Reads(bundle.KindConfigMap, rootRef.Name))
	}
}

func TestKeylessCertificateShape(t *testing.T) {
	ctx := context.Background()
	vs := newVirtualSigstore(t)
	custom := newCustomCA(t)
	parts := partsOf(t, vs, false)
	parts.cas = append(parts.cas, custom.authority())
	rj := parts.json(t)
	sign := statementFor(keylessSubject, registry.CosignSignPredicateType)
	src := keylessSource(testIssuer, testIdentity, rootRef)

	t.Run("single URI SAN from a custom CA verifies", func(t *testing.T) {
		leaf, key := custom.leaf(t, testIssuer, []string{testIdentity}, nil)
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err)
	})
	t.Run("configured identity plus another SAN", func(t *testing.T) {
		leaf, key := custom.leaf(t, testIssuer, []string{testIdentity}, []string{"someone@example.test"})
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrSigner)
	})
	t.Run("another SAN first, configured identity second", func(t *testing.T) {
		leaf, key := custom.leaf(t, testIssuer, []string{"https://git.example.test/attacker", testIdentity}, nil)
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrSigner)
	})
	t.Run("RFC 3161 time after the leaf expired, log time inside", func(t *testing.T) {
		// The intermediate is valid from two minutes ago; the leaf was valid
		// for one minute until 30 seconds ago. The log time lies inside its
		// validity, the timestamp authority's (now) outside: every
		// authenticated time must fall within the leaf's validity.
		now := time.Now()
		leaf, key := custom.leafWindow(t, testIssuer, []string{testIdentity}, nil, now.Add(-90*time.Second), now.Add(-30*time.Second))
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key, at: now.Add(-60 * time.Second)})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrSigningTime)
		raw, _ = keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key, at: now.Add(-60 * time.Second), noTSA: true})
		_, err = newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err)
	})
	t.Run("certificate chain carried by the proof", func(t *testing.T) {
		attacker := newCustomCA(t)
		leaf, key := attacker.leaf(t, testIssuer, []string{testIdentity}, nil)
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key, chain: []*x509.Certificate{attacker.inter, attacker.root}})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrMalformedProof)
	})
	t.Run("leaf from a CA only the proof knows", func(t *testing.T) {
		attacker := newCustomCA(t)
		leaf, key := attacker.leaf(t, testIssuer, []string{testIdentity}, nil)
		raw, _ := keylessBundle(t, vs, keylessOpts{statement: sign, leaf: leaf, key: key})
		_, err := newVerifier(t, rootReader(rj), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrSignature)
	})
	t.Run("Ed25519 leaf", func(t *testing.T) {
		ed, err := ca.NewVirtualSigstoreWithSigningAlg(v1.PublicKeyDetails_PKIX_ED25519)
		if err != nil {
			t.Fatal(err)
		}
		c, p, err := ed.GenerateLeafCert(testIdentity, testIssuer)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := keylessBundle(t, ed, keylessOpts{statement: sign, leaf: c, key: p.(crypto.Signer)})
		_, err = newVerifier(t, rootReader(partsOf(t, ed, false).json(t)), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrAlgorithm)
	})
}

func TestKeylessTrustRootInput(t *testing.T) {
	ctx := context.Background()
	vs := newVirtualSigstore(t)
	good := partsOf(t, vs, false).json(t)
	raw, _ := keylessBundle(t, vs, keylessOpts{identity: testIdentity, issuer: testIssuer, statement: statementFor(keylessSubject, registry.CosignSignPredicateType)})
	noLogs, err := root.NewTrustedRoot(root.TrustedRootMediaType01, vs.FulcioCertificateAuthorities(), nil, vs.TimestampingAuthorities(), nil)
	if err != nil {
		t.Fatal(err)
	}
	noLogsJSON, err := noLogs.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		val  []byte
	}{
		{"not JSON", []byte("not json")},
		{"duplicate key", append([]byte(`{"mediaType":"x",`), good[1:]...)},
		{"unknown field", append([]byte(`{"extra":1,`), good[1:]...)},
		{"no transparency log", noLogsJSON},
		{"empty", []byte(" ")},
		{"oversized", append(good, make([]byte, MaxTrustRootBytes)...)},
	}
	src := keylessSource(testIssuer, testIdentity, rootRef)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newVerifier(t, rootReader(c.val), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
			wantErr(t, err, ErrTrustConfig)
		})
	}
	t.Run("referenced root missing: no fallback to the public-good root", func(t *testing.T) {
		_, err := newVerifier(t, kubeaccess.NewMemoryReader(), nil).VerifyProof(ctx, src, keylessSubject, registry.ProofSignature, rawProof(registry.ProofSignature, raw))
		wantErr(t, err, ErrTrustConfig)
	})
}
