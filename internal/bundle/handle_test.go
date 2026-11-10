package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func d(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// sampleHandle is a hand-written handle, so its golden fixture does not churn
// when bundle content changes.
func sampleHandle() ResolvedContent {
	var r Receipt
	r.Version = HandleVersion
	r.VerifiedAt = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	r.Subject.Name, r.Subject.Version, r.Subject.Digest = "konstapel-privileged-containers", "0.1.0", d("4")
	r.RetrievedFrom = "ghcr.io/backend-bunny/bundles/konstapel-privileged-containers"
	r.SourceRule, r.TrustRevision, r.TrustRoot = "official", "rev-7", "sigstore-public-good"
	r.Signer = Signer{Kind: SignerKeyless, Issuer: "https://token.actions.githubusercontent.com",
		Identity: "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle.yml@refs/heads/main"}
	r.Proofs.Signature, r.Proofs.Attestation = d("5"), d("6")
	r.Provenance = Provenance{PredicateType: PredicateSLSAProvenanceV1, Repository: "https://github.com/backend-bunny/Konstapel",
		Revision: strings.Repeat("a", 40), Builder: "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle.yml@refs/heads/main"}
	return ResolvedContent{
		HandleVersion: HandleVersion, Name: "konstapel-privileged-containers", Version: "0.1.0",
		Digests: Digests{Revision: strings.Repeat("a", 40), Content: d("2"), Archive: d("3"), OCI: d("4")},
		Policies: []PolicyInfo{{Name: "disallow-privileged-containers", Path: "content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml",
			Checks: []Check{{RuleID: "disallow-privileged-containers", CheckID: "disallow-privileged-containers"}}}},
		CheckedPaths:  []string{"LICENSE", "bundle.json", "content/component-definition.json"},
		Compatibility: CompatibilityResult{Content: ContentCompatibility{Compatible: true, Provider: "konstapel-kyverno/v1", Konstapel: "0.1.0", OSCAL: []string{"1.1.3", "1.2.3"}}, Engine: EngineUnknown},
		Receipt:       r,
		Lease:         Lease{ID: "lease-1", Holder: HolderProfile, Owner: "profile/baseline", Digest: d("4"), AcquiredAt: time.Date(2026, 11, 10, 9, 0, 1, 0, time.UTC)},
	}
}

func golden(t *testing.T, name string, v any) []byte {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	p := filepath.Join("../../testdata/bundles/contract", name)
	if os.Getenv("KONSTAPEL_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (regenerate with KONSTAPEL_UPDATE_GOLDEN=1)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s drifted from its fixture; the serialized contract changed (regenerate with KONSTAPEL_UPDATE_GOLDEN=1 only for an intended, versioned change)\n--- fixture\n%s\n--- got\n%s", name, want, got)
	}
	return want
}

func TestHandleSerializationFixtures(t *testing.T) {
	h := sampleHandle()
	raw := golden(t, "handle.json", h)
	back, err := ParseHandle(raw)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	if back.BundleDigest() != d("4") {
		t.Fatalf("bundle digest %q", back.BundleDigest())
	}
	again, _ := json.MarshalIndent(back, "", "  ")
	if string(again)+"\n" != string(raw) {
		t.Fatal("handle does not round-trip")
	}
	rawReceipt := golden(t, "receipt.json", h.Receipt)
	var rc Receipt
	if err := json.Unmarshal(rawReceipt, &rc); err != nil || rc.Validate() != nil {
		t.Fatalf("receipt fixture: %v %v", err, rc.Validate())
	}
}

func TestHandleValidationRejections(t *testing.T) {
	cases := map[string]struct {
		mutate func(*ResolvedContent)
		want   string
	}{
		"version":               {func(h *ResolvedContent) { h.HandleVersion = 2 }, "handleVersion"},
		"bad digest":            {func(h *ResolvedContent) { h.Digests.Content = "md5:1" }, "digests.content"},
		"archive equals oci":    {func(h *ResolvedContent) { h.Digests.Archive = h.Digests.OCI }, "different objects"},
		"rendered malformed":    {func(h *ResolvedContent) { h.Policies[0].Rendered = "x" }, "rendered"},
		"unknown engine":        {func(h *ResolvedContent) { h.Compatibility.Engine = "maybe" }, "engine"},
		"unexplained verdict":   {func(h *ResolvedContent) { h.Compatibility.Content.Compatible = false }, "reasons"},
		"receipt other subject": {func(h *ResolvedContent) { h.Receipt.Subject.Digest = d("9") }, "is not this bundle"},
		"receipt other version": {func(h *ResolvedContent) { h.Receipt.Subject.Version = "9.9.9" }, "is not this bundle"},
		"provenance revision":   {func(h *ResolvedContent) { h.Receipt.Provenance.Revision = strings.Repeat("b", 40) }, "provenance revision"},
		"keyless without id":    {func(h *ResolvedContent) { h.Receipt.Signer.Identity = "" }, "keyless signer"},
		"key and identity": {func(h *ResolvedContent) {
			h.Receipt.Signer = Signer{Kind: SignerPublicKey, KeyFingerprint: "ab", Identity: "x"}
		}, "public-key signer"},
		"unknown signer":         {func(h *ResolvedContent) { h.Receipt.Signer.Kind = "none" }, "signer kind"},
		"no proofs":              {func(h *ResolvedContent) { h.Receipt.Proofs.Attestation = "" }, "signature and attestation"},
		"archive-hash predicate": {func(h *ResolvedContent) { h.Receipt.Provenance.PredicateType = "https://example.com/hash" }, "only"},
		"no trust revision":      {func(h *ResolvedContent) { h.Receipt.TrustRevision = "" }, "trustRevision"},
		"lease other entry":      {func(h *ResolvedContent) { h.Lease.Digest = d("9") }, "lease pins"},
		"lease no owner":         {func(h *ResolvedContent) { h.Lease.Owner = "" }, "lease needs"},
		"unknown holder":         {func(h *ResolvedContent) { h.Lease.Holder = "cron" }, "lease holder"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := sampleHandle()
			h.Policies = append([]PolicyInfo(nil), h.Policies...)
			tc.mutate(&h)
			if err := h.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	raw, _ := json.Marshal(sampleHandle())
	for name, in := range map[string]string{
		"unknown field": strings.Replace(string(raw), `{"handleVersion"`, `{"extra":1,"handleVersion"`, 1),
		"repeated key":  strings.Replace(string(raw), `{"handleVersion":1`, `{"handleVersion":1,"handleVersion":1`, 1),
		"trailing":      string(raw) + "{}",
	} {
		if _, err := ParseHandle([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A handle built from a real archive is consistent, keeps the four digests
// distinct, and starts with the engine state unknown rather than assumed.
func TestNewHandleFromArchive(t *testing.T) {
	a, _ := buildOfficial(t)
	s := sampleHandle()
	receipt := s.Receipt
	receipt.Subject.Name, receipt.Subject.Version, receipt.Subject.Digest = a.Descriptor.Name, a.Descriptor.Version, a.ManifestDigest
	receipt.Provenance.Revision = a.Descriptor.Source.Revision
	lease := s.Lease
	lease.Digest = a.ManifestDigest
	h := NewHandle(a, s.Compatibility.Content, receipt, lease)
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if h.Compatibility.Engine != EngineUnknown {
		t.Errorf("engine = %q: readiness must not be assumed", h.Compatibility.Engine)
	}
	seen := map[string]bool{}
	for _, v := range []string{h.Digests.Content, h.Digests.Archive, h.Digests.OCI} {
		if seen[v] {
			t.Fatalf("digests are not distinct: %+v", h.Digests)
		}
		seen[v] = true
	}
	if p, ok := h.Policy("disallow-privileged-containers"); !ok || len(p.Checks) != 1 {
		t.Fatalf("policy metadata lost: %+v", h.Policies)
	}
	if len(h.CheckedPaths) != len(a.Descriptor.Files) {
		t.Errorf("checked %d paths for %d files", len(h.CheckedPaths), len(a.Descriptor.Files))
	}
}

// recordedRevision pins targeting.EnforcementRevision for the sample input as
// computed before this contract existed: publishing the handle must not change
// the revision algorithm or its result.
const recordedRevision = "sha256:7e73f76da2b355e7a0545eb77bcc91fbc582248191d1d0d5aea39cf9da63e594"

func enforcementInput(h ResolvedContent) targeting.EnforcementInput {
	return targeting.EnforcementInput{
		Cluster: "kube-system:cluster-uid", BindingUID: "binding-uid", BindingEpoch: 3,
		ProfileUID: "profile-uid", ProfileGeneration: 2, Policy: h.Policies[0].Name,
		BundleDigest: h.BundleDigest(), ConfigurationDigest: d("7"), Mode: v1alpha1.EnforcementMode("Audit"),
	}
}

func TestHandleKeepsTheTargetingRevisionUnchanged(t *testing.T) {
	if targeting.ContractVersion != 1 {
		t.Fatalf("targeting contract version is %d; the handle contract assumes the revision algorithm is unchanged", targeting.ContractVersion)
	}
	h := sampleHandle()
	base := targeting.EnforcementRevision(enforcementInput(h))
	if base != recordedRevision {
		t.Fatalf("EnforcementRevision = %s, want recorded %s", base, recordedRevision)
	}

	// Mirror, credentials, receipts, leases, engine state and rendered hashes
	// are not enforcement inputs.
	for name, mutate := range map[string]func(*ResolvedContent){
		"mirror": func(h *ResolvedContent) { h.Receipt.RetrievedFrom = "registry.internal/mirror/bundles/x" },
		"reverified": func(h *ResolvedContent) {
			h.Receipt.VerifiedAt = h.Receipt.VerifiedAt.Add(time.Hour)
			h.Receipt.TrustRevision = "rev-8"
		},
		"lease":       func(h *ResolvedContent) { h.Lease.ID = "lease-2"; h.Lease.Holder = HolderApplied },
		"engine":      func(h *ResolvedContent) { h.Compatibility.Engine = EngineReady },
		"rendered":    func(h *ResolvedContent) { h.Policies[0].Rendered = d("8") },
		"other proof": func(h *ResolvedContent) { h.Receipt.Proofs.Signature = d("a") },
	} {
		c := sampleHandle()
		c.Policies = append([]PolicyInfo(nil), c.Policies...)
		mutate(&c)
		if got := targeting.EnforcementRevision(enforcementInput(c)); got != base {
			t.Errorf("%s changed the enforcement revision", name)
		}
	}

	// A different manifest digest is a different semantic revision.
	c := sampleHandle()
	c.Digests.OCI = d("b")
	if targeting.EnforcementRevision(enforcementInput(c)) == base {
		t.Error("a new manifest digest did not change the revision")
	}
}

// The handle supplies exactly the existing contribution fields.
func TestHandleFillsExistingContributionFields(t *testing.T) {
	h := sampleHandle()
	c := targeting.Contribution{Policy: h.Policies[0].Name, BundleName: h.Name, BundleDigest: h.BundleDigest()}
	raw, _ := json.Marshal(c)
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m["policy"] != "disallow-privileged-containers" || m["bundleName"] != h.Name || m["bundleDigest"] != d("4") {
		t.Fatalf("contribution fields: %v", m)
	}
}
