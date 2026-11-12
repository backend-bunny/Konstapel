package collector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// craftedFrozen freezes the crafted bundle (whose mapping and catalog
// differ from the vendored content) into a new directory.
func craftedFrozen(t *testing.T, o bundletest.Options) (string, *bundle.Frozen) {
	t.Helper()
	a, err := bundletest.Differing(repo(t), o)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.ValidateContent(a.Descriptor, payload); err != nil {
		t.Fatalf("the crafted bundle is not valid bundle content: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "frozen")
	f, err := bundle.WriteFrozen(dir, a.Manifest, a.Layer, bundletest.Identity(a, "rule-rev-1", "trust-rev-1", time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return dir, f
}

// ociCapture is the fresh contract capture re-pointed at bundle name@digest:
// contributions and subjects name it, and engine policies are re-rendered
// from the (byte-identical) policy source so they verify against it.
func ociCapture(t *testing.T, name, digest string) CaptureV2 {
	t.Helper()
	c := freshCapture(t)
	raw, err := os.ReadFile(filepath.Join(repo(t), assessment.SourcePolicy))
	if err != nil {
		t.Fatal(err)
	}
	m, err := targeting.ParsePolicyManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	src := targeting.PolicySource{Manifest: m, SourceDigest: "sha256:" + assessment.Hash(raw)}
	var policies []assessment.Object
	for i := range c.Contributions {
		c.Contributions[i].BundleName, c.Contributions[i].BundleDigest = name, digest
		u, err := targeting.Render(c.Contributions[i], src)
		if err != nil {
			t.Fatal(err)
		}
		policies = append(policies, SanitizeEnginePolicy(u.Object))
	}
	c.EnginePolicies = policies
	for i := range c.Subjects {
		c.Subjects[i].BundleName, c.Subjects[i].BundleDigest = name, digest
	}
	return c
}

func ociExport(t *testing.T, c CaptureV2, dir string, f *bundle.Frozen) (ExportRequest, publication.Descriptor) {
	t.Helper()
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), dir)
	req.Bundle, req.TrustedRoot = f, repo(t)
	ref := v1alpha1.BundleReference{Name: f.Identity.Name, Digest: f.Identity.Digests.OCI}
	req.ContentRef = &ref
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return req, d
}

// requireCraftedOSCAL fails unless the package's OSCAL was derived from the
// crafted bundle: its mapping (cm-7_smt.b with the crafted rationale), its
// catalog, and its identity. A package exported from the vendored content
// maps the check to ac-6_smt and fails here.
func requireCraftedOSCAL(t *testing.T, out string, f *bundle.Frozen) {
	t.Helper()
	ar := string(mustRead(t, filepath.Join(out, "assessment-results.json")))
	ssp := string(mustRead(t, filepath.Join(out, "system-security-plan.json")))
	ap := string(mustRead(t, filepath.Join(out, "assessment-plan.json")))
	for name, doc := range map[string]string{"results": ar, "ssp": ssp} {
		if !strings.Contains(doc, bundletest.Rationale) {
			t.Fatalf("%s does not carry the bundle's mapping rationale", name)
		}
	}
	if !strings.Contains(ssp, `"`+bundletest.Statement+`"`) || strings.Contains(ssp, `"`+bundletest.VendoredStatement+`"`) {
		t.Fatalf("the SSP does not map the bundle's statement %s (or maps the vendored %s)", bundletest.Statement, bundletest.VendoredStatement)
	}
	if !strings.Contains(ap, `"`+bundletest.Control+`"`) || strings.Contains(ap, `"control-id": "ac-6"`) {
		t.Fatal("the plan does not review the bundle's control")
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(out, assessment.NIST+"NIST_SP-800-53_rev5_catalog.json"))), bundletest.CatalogTitle) {
		t.Fatal("the packaged catalog is not the bundle's")
	}
	for _, want := range []string{f.Identity.Digests.OCI, f.Identity.Digests.Content, `"bundle-name"`, bundle.FrozenIdentityFile} {
		if !strings.Contains(ar, want) {
			t.Fatalf("results do not identify the bundle (%s)", want)
		}
	}
}

func TestExportFrozenBundleUsesItsOwnContent(t *testing.T) {
	dir, f := craftedFrozen(t, bundletest.Options{})
	c := ociCapture(t, f.Identity.Name, f.Identity.Digests.OCI)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	req, d := ociExport(t, c, dir, f)
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("package %s: %+v", d.PackageKind, d.Diagnostic)
	}
	requireCraftedOSCAL(t, req.Out, f)
	// The descriptor records the frozen identity and verification context.
	cr := d.Revisions.Content
	if cr == nil || !cr.Frozen || cr.ManifestDigest != f.Identity.Digests.OCI || cr.ContentDigest != f.Identity.Digests.Content ||
		cr.ArchiveDigest != f.Identity.Digests.Archive || cr.SourceRule != "rule-rev-1" || cr.TrustRevision != "trust-rev-1" || cr.VerifiedAt == nil {
		t.Fatalf("content revision %+v", cr)
	}
	if !slices.Contains(d.Producer.Checks, "frozen-bundle-content") {
		t.Fatalf("checks %v", d.Producer.Checks)
	}
	// The package verifies offline from its own frozen proofs.
	if err := VerifyPackage(req.Out); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ReadFrozen(req.Out); err != nil {
		t.Fatal(err)
	}
	// Editing a packaged mapping is detected against the bundle digest.
	cd := filepath.Join(req.Out, "content/component-definition.json")
	if err := os.WriteFile(cd, []byte(strings.Replace(string(mustRead(t, cd)), bundletest.Statement, "cm-7_smt.a", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(req.Out); err == nil {
		t.Fatal("an edited packaged mapping verified")
	}
}

// With nothing in scope, the plan names the frozen bundle's mappings, never
// the vendored first-loop check.
func TestExportFrozenBundleZeroTargets(t *testing.T) {
	dir, f := craftedFrozen(t, bundletest.Options{})
	c := ociCapture(t, f.Identity.Name, f.Identity.Digests.OCI)
	c.Subjects, c.Contributions, c.EnginePolicies, c.Checks = nil, nil, nil, []Check{}
	c.Workloads, c.Expected = []Workload{}, []Expected{}
	req, d := ociExport(t, c, dir, f)
	if d.PackageKind != publication.KindAssessment || d.Evidence.Completeness != publication.NoTargets {
		t.Fatalf("%s %+v %+v", d.PackageKind, d.Evidence, d.Diagnostic)
	}
	requireCraftedOSCAL(t, req.Out, f)
}

// Vendored exports are unchanged: no bundle directory, no content
// revision, no frozen check.
func TestExportVendoredHasNoBundleRecord(t *testing.T) {
	c := freshCapture(t)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Revisions.Content != nil || slices.Contains(d.Producer.Checks, "frozen-bundle-content") {
		t.Fatalf("vendored descriptor changed: %+v %v", d.Revisions, d.Producer.Checks)
	}
	if _, err := os.Stat(filepath.Join(req.Out, bundle.FrozenDir)); !os.IsNotExist(err) {
		t.Fatal("vendored package has a bundle directory")
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(req.Out, "system-security-plan.json"))), `"`+bundletest.VendoredStatement+`"`) {
		t.Fatal("vendored mapping changed")
	}
}

// Content problems are explicit diagnostics; no OSCAL is produced from any
// other content.
func TestExportContentFailuresAreDiagnostics(t *testing.T) {
	requireDiagnostic := func(t *testing.T, req ExportRequest, d publication.Descriptor, reason string) {
		t.Helper()
		if d.PackageKind != publication.KindDiagnostic || d.Diagnostic == nil || d.Diagnostic.Reason != reason {
			t.Fatalf("want diagnostic %s, got %s %+v", reason, d.PackageKind, d.Diagnostic)
		}
		for _, p := range []string{"assessment-results.json", "assessment-plan.json", "system-security-plan.json", "content", bundle.FrozenDir} {
			if _, err := os.Stat(filepath.Join(req.Out, p)); !os.IsNotExist(err) {
				t.Fatalf("%s left in a diagnostic package", p)
			}
		}
		if d.Revisions.Content == nil || d.Revisions.Content.Frozen {
			t.Fatalf("diagnostic content revision %+v", d.Revisions.Content)
		}
		if err := publication.VerifyDir(req.Out, d); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("unresolved", func(t *testing.T) {
		c := freshCapture(t)
		req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
		ref := v1alpha1.BundleReference{Name: "org-bundle", Digest: "sha256:" + strings.Repeat("a", 64)}
		req.ContentRef = &ref
		req.Content = &ContentFailure{Reason: ReasonContentUnavailable, Message: "untrusted"}
		d, err := Export(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		requireDiagnostic(t, req, d, ReasonContentUnavailable)
		if d.Revisions.Content.Bundle != "org-bundle" {
			t.Fatalf("%+v", d.Revisions.Content)
		}
	})
	t.Run("capture names another bundle", func(t *testing.T) {
		dir, f := craftedFrozen(t, bundletest.Options{})
		c := ociCapture(t, f.Identity.Name, "sha256:"+strings.Repeat("b", 64))
		req, d := ociExport(t, c, dir, f)
		requireDiagnostic(t, req, d, ReasonContentMismatch)
	})
	t.Run("vendored capture", func(t *testing.T) {
		dir, f := craftedFrozen(t, bundletest.Options{})
		req, d := ociExport(t, freshCapture(t), dir, f)
		requireDiagnostic(t, req, d, ReasonContentMismatch)
	})
	t.Run("incompatible schema", func(t *testing.T) {
		schema := mustRead(t, filepath.Join(repo(t), "content/schemas/oscal-1.1.3.json"))
		dir, f := craftedFrozen(t, bundletest.Options{Schema113: append(append([]byte{}, schema...), '\n')})
		c := ociCapture(t, f.Identity.Name, f.Identity.Digests.OCI)
		req, d := ociExport(t, c, dir, f)
		requireDiagnostic(t, req, d, ReasonContentIncompatible)
	})
}
