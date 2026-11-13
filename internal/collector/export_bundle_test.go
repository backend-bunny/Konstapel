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

// frozenMember is the content-set member of a frozen bundle; applied
// unless the capture assesses nothing (the desired bundle the plan names).
func frozenMember(dir string, f *bundle.Frozen, applied bool) ContentMember {
	return ContentMember{Ref: v1alpha1.BundleReference{Name: f.Identity.Name, Digest: f.Identity.Digests.OCI}, Applied: applied, Root: dir, Frozen: f}
}

func ociExport(t *testing.T, c CaptureV2, dir string, f *bundle.Frozen) (ExportRequest, publication.Descriptor) {
	t.Helper()
	m := frozenMember(dir, f, len(c.Subjects) > 0)
	return contentExport(t, c, &RunContent{Desired: &m.Ref, Members: []ContentMember{m}})
}

func contentExport(t *testing.T, c CaptureV2, rc *RunContent) (ExportRequest, publication.Descriptor) {
	t.Helper()
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	req.Content, req.TrustedRoot = rc, repo(t)
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
	member := filepath.Join(out, filepath.FromSlash(publication.ContentPath(f.Identity.Digests.OCI)))
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
	if !strings.Contains(string(mustRead(t, filepath.Join(member, assessment.NIST+"NIST_SP-800-53_rev5_catalog.json"))), bundletest.CatalogTitle) {
		t.Fatal("the packaged catalog is not the bundle's")
	}
	for _, want := range []string{f.Identity.Digests.OCI, f.Identity.Digests.Content, `"bundle-name"`, publication.ContentPath(f.Identity.Digests.OCI) + "/" + bundle.FrozenIdentityFile} {
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
	// The descriptor records the frozen identity and verification context
	// of the applied bundle, which is also the desired one.
	rc := d.Revisions.Content
	if rc == nil || len(rc.Applied) != 1 || rc.Desired == nil || rc.Desired.Frozen || len(rc.Differences) != 0 {
		t.Fatalf("content %+v", rc)
	}
	cr := rc.Applied[0]
	if !cr.Frozen || cr.Path != publication.ContentPath(f.Identity.Digests.OCI) || cr.ManifestDigest != f.Identity.Digests.OCI || cr.ContentDigest != f.Identity.Digests.Content ||
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
	if err := VerifyContent(req.Out, d.Revisions.Content); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ReadFrozen(filepath.Join(req.Out, cr.Path)); err != nil {
		t.Fatal(err)
	}
	// A descriptor naming other frozen identities does not match the package.
	other := *rc
	other.Applied = []publication.ContentRevision{cr}
	other.Applied[0].TrustRevision = "trust-rev-2"
	if err := VerifyContent(req.Out, &other); err == nil {
		t.Fatal("a different recorded verification context matched the package")
	}
	if err := VerifyContent(req.Out, nil); err == nil {
		t.Fatal("packaged bundle content verified without a content record")
	}
	// Editing a packaged mapping is detected against the bundle digest.
	cd := filepath.Join(req.Out, cr.Path, "content/component-definition.json")
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
	// Nothing was applied: the desired bundle is the packaged content.
	if rc := d.Revisions.Content; len(rc.Applied) != 0 || rc.Desired == nil || !rc.Desired.Frozen ||
		!slices.Equal(rc.Differences, []publication.ContentDifference{{Kind: publication.DesiredNotApplied, Bundle: f.Identity.Name, ManifestDigest: f.Identity.Digests.OCI}}) {
		t.Fatalf("content %+v", rc)
	}
}

// A run whose contributions were applied from the vendored content while
// the profile desires an OCI bundle exports from the vendored content (its
// own member), records the OCI bundle as desired, and never exports the
// desired bundle's content.
func TestExportVendoredAppliedOCIDesired(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	vendored := v1alpha1.BundleReference{Name: c.Subjects[0].BundleName, Digest: c.Subjects[0].BundleDigest}
	desired := v1alpha1.BundleReference{Name: "org-bundle", Digest: "sha256:" + strings.Repeat("d", 64)}
	req, d := contentExport(t, c, &RunContent{Desired: &desired, Members: []ContentMember{{Ref: vendored, Applied: true, Vendored: true, Root: repo(t)}}})
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("%s %+v", d.PackageKind, d.Diagnostic)
	}
	rc := d.Revisions.Content
	want := []publication.ContentDifference{{Kind: publication.DesiredNotApplied, Bundle: desired.Name, ManifestDigest: desired.Digest},
		{Kind: publication.AppliedNotDesired, Bundle: vendored.Name, ManifestDigest: vendored.Digest}}
	if len(rc.Applied) != 1 || !rc.Applied[0].Vendored || !rc.Applied[0].Frozen || rc.Desired.Frozen || !slices.Equal(rc.Differences, want) {
		t.Fatalf("content %+v", rc)
	}
	ssp := string(mustRead(t, filepath.Join(req.Out, "system-security-plan.json")))
	if !strings.Contains(ssp, `"`+bundletest.VendoredStatement+`"`) {
		t.Fatal("the vendored mapping is not exported")
	}
	if err := VerifyContent(req.Out, rc); err != nil {
		t.Fatal(err)
	}
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
		for _, p := range []string{"assessment-results.json", "assessment-plan.json", "system-security-plan.json", "content", bundle.FrozenDir, bundlesDir} {
			if _, err := os.Stat(filepath.Join(req.Out, p)); !os.IsNotExist(err) {
				t.Fatalf("%s left in a diagnostic package", p)
			}
		}
		rc := d.Revisions.Content
		if rc == nil || slices.ContainsFunc(rc.Applied, func(r publication.ContentRevision) bool { return r.Frozen }) || rc.Desired != nil && rc.Desired.Frozen {
			t.Fatalf("diagnostic content revision %+v", rc)
		}
		if err := publication.VerifyDir(req.Out, d); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("unresolved", func(t *testing.T) {
		c := freshCapture(t)
		req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
		ref := v1alpha1.BundleReference{Name: "org-bundle", Digest: "sha256:" + strings.Repeat("a", 64)}
		req.Content = &RunContent{Desired: &ref, Members: []ContentMember{{Ref: ref, Applied: true,
			Failure: &ContentFailure{Reason: ReasonContentUnavailable, Message: "untrusted"}}}}
		req.TrustedRoot = repo(t)
		d, err := Export(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		requireDiagnostic(t, req, d, ReasonContentUnavailable)
		if rc := d.Revisions.Content; len(rc.Applied) != 1 || rc.Applied[0].Bundle != "org-bundle" || rc.Desired.Bundle != "org-bundle" {
			t.Fatalf("%+v", rc)
		}
	})
	t.Run("one of two applied bundles unavailable", func(t *testing.T) {
		// The available one is never exported alone in its place.
		dir, f := craftedFrozen(t, bundletest.Options{})
		c := ociCapture(t, f.Identity.Name, f.Identity.Digests.OCI)
		lost := v1alpha1.BundleReference{Name: f.Identity.Name, Digest: "sha256:" + strings.Repeat("0", 64)}
		req, d := contentExport(t, c, &RunContent{Desired: &lost, Members: []ContentMember{
			{Ref: lost, Applied: true, Failure: &ContentFailure{Reason: ReasonContentUnavailable, Message: "evicted and the registry is down"}},
			frozenMember(dir, f, true)}})
		requireDiagnostic(t, req, d, ReasonContentUnavailable)
		if !strings.Contains(d.Diagnostic.Message, "registry is down") {
			t.Fatalf("%+v", d.Diagnostic)
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
