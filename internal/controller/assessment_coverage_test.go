package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// unpackFake writes a published package archive into a directory.
func unpackFake(t *testing.T, archive []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := publication.Extract(bytes.NewReader(archive), dir); err != nil {
		t.Fatalf("malformed package archive: %v", err)
	}
	return dir
}

// publishedPackage runs the binding's scheduled run to publication, with
// edit applied to staging after start, and returns the package directory.
func publishedPackage(t *testing.T, edit func(e *runEnv, r *v1alpha1.AssessmentRun)) (*runEnv, *v1alpha1.AssessmentRun, string) {
	t.Helper()
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if edit != nil {
		edit(e, e.run(name))
	}
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(90 * time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("phase %s %+v", r.Status.Phase, r.Status.Conditions)
	}
	rc, _, err := e.pub.Open(context.Background(), e.ref(r))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	archive, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return e, r, unpackFake(t, archive)
}

func packagedCoverage(t *testing.T, dir string) (*coverage.Report, publication.Descriptor) {
	t.Helper()
	d, err := s3store.ValidatePackage(dir)
	if err != nil {
		t.Fatalf("the published package does not validate: %v", err)
	}
	var f coverage.Files
	if f.JSON, err = os.ReadFile(filepath.Join(dir, coverage.JSONFile)); err != nil {
		t.Fatal(err)
	}
	if f.Text, err = os.ReadFile(filepath.Join(dir, coverage.TextFile)); err != nil {
		t.Fatal(err)
	}
	if err := coverage.VerifyFiles(f); err != nil {
		t.Fatal(err)
	}
	r, err := coverage.Parse(f.JSON)
	if err != nil {
		t.Fatal(err)
	}
	return r, d
}

// A real run's package carries coverage built from its packaged content,
// its frozen selection and its evaluated capture, with summary roles and
// verified references, and the technical evidence is exactly as without.
func TestRunPackageCarriesCoverage(t *testing.T) {
	_, run, dir := publishedPackage(t, nil)
	r, d := packagedCoverage(t, dir)
	roles := map[string]publication.FileRole{}
	for _, f := range d.Files {
		roles[f.Path] = f.Role
	}
	if roles[publication.CoverageFile] != publication.RoleCoverage || roles[publication.CoverageTextFile] != publication.RoleCoverageText ||
		!slices.Contains(d.Producer.Checks, "coverage-references") || d.PackageKind != publication.KindAssessment {
		t.Fatalf("descriptor %+v %+v", d.Producer, d.Files)
	}
	// The vendored run: the Moderate inventory resolves from the packaged
	// content/ tree; the shipped mappings are outside its SHA256SUMS
	// closure, so they are unresolved, never assumed absent.
	if !r.Inventory.Resolved || r.Inventory.Controls != 287 || len(r.Controls) != 287 || r.Mappings.Resolved || r.Inputs.ContentPath != "" {
		t.Fatalf("inventory %+v mappings %+v", r.Inventory, r.Mappings.Resolved)
	}
	if r.Scope.Kind != "Binding" || r.Scope.Binding == nil || r.Scope.Binding.UID != run.Status.Binding.UID ||
		len(r.Scope.Namespaces) != 1 || r.Scope.Namespaces[0].Name != "prod" {
		t.Fatalf("scope %+v", r.Scope)
	}
	te := r.TechnicalEvidence
	if te.State != coverage.EvidenceResolved || *te.Evidence != d.Evidence || *te.Outcomes != d.Outcomes || !r.AsOf.Equal(d.Window.Closed) {
		t.Fatalf("technical evidence %+v %+v; descriptor %+v %+v", te.Evidence, te.Outcomes, d.Evidence, d.Outcomes)
	}
	if len(r.Inputs.Selection.Policies) != 1 || r.Inputs.Selection.Policies[0].Name != pol {
		t.Fatalf("selection %+v", r.Inputs.Selection)
	}
	// The attachment integration feeds coverage: no record names this
	// binding, so the context is available with no entry (documents were
	// considered and none is associated), and nothing is protected.
	if se := r.SupportingEvidence; se.Integration != coverage.IntegrationAvailable || se.Projection != coverage.ProjectionPlatform || len(se.Entries) != 0 || d.Protected() {
		t.Fatalf("supporting evidence %+v protection %+v", se, d.Protection)
	}
	// The run's status reports the technical evidence, unchanged.
	if run.Status.Summary.Evidence.Completeness != "Complete" || run.Status.Summary.Outcomes.Fail != 1 {
		t.Fatalf("summary %+v", run.Status.Summary)
	}
}

// Hand-break guard (fabricated finding on an unresolved baseline): a run
// whose selection was not recorded still publishes the same technical
// evidence and OSCAL findings, with a coverage diagnostic and no controls.
func TestRunCoverageDiagnosticDoesNotChangeEvidence(t *testing.T) {
	_, base, baseDir := publishedPackage(t, nil)
	_, run, dir := publishedPackage(t, func(e *runEnv, r *v1alpha1.AssessmentRun) {
		if err := os.Remove(filepath.Join(e.rr.staging(r), runSelectionFile)); err != nil {
			t.Fatal(err)
		}
	})
	r, d := packagedCoverage(t, dir)
	if r.Inventory.Resolved || len(r.Controls) != 0 || !hasLimitation(r, coverage.CodeSelectionUnavailable) {
		t.Fatalf("coverage %+v %+v", r.Inventory, r.Limitations)
	}
	if *r.TechnicalEvidence.Evidence != d.Evidence || run.Status.Summary.Evidence != base.Status.Summary.Evidence || run.Status.Summary.Outcomes != base.Status.Summary.Outcomes {
		t.Fatalf("evidence changed: %+v vs %+v", run.Status.Summary, base.Status.Summary)
	}
	findings := func(dir string) []string {
		var ar struct {
			AR struct {
				Results []struct {
					Findings []struct {
						Target struct {
							TargetID string `json:"target-id"`
						} `json:"target"`
					} `json:"findings"`
				} `json:"results"`
			} `json:"assessment-results"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, "assessment-results.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &ar); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, res := range ar.AR.Results {
			for _, f := range res.Findings {
				out = append(out, f.Target.TargetID)
			}
		}
		return out
	}
	if got, want := findings(dir), findings(baseDir); !slices.Equal(got, want) || len(want) == 0 {
		t.Fatalf("findings %v, without the diagnostic %v", got, want)
	}
}

// Coverage is never built from content the package does not carry.
func TestCoverageReportUsesOnlyPackagedContent(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	run := e.run(name)
	var c collector.CaptureV2
	b := epochBinding("audit-prod", nil)
	scope := publication.Scope{Kind: publication.ScopeBinding, ClusterID: "c", BindingUID: string(b.UID), NamespaceUIDs: []string{}}
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: digest(t)}
	for what, p := range map[string]collector.CoveragePackage{
		"diagnostic": {Dir: t.TempDir(), Kind: publication.KindDiagnostic, Diagnostic: &publication.Diagnostic{Reason: "ContentLost"}},
		"not packaged": {Dir: t.TempDir(), Kind: publication.KindAssessment, Content: []collector.PackagedContent{
			{Ref: v1alpha1.BundleReference{Name: "other", Digest: "sha256:" + string(bytes.Repeat([]byte("a"), 64))}, Path: "bundles/aa", Applied: true}}},
		"unreadable": {Dir: t.TempDir(), Kind: publication.KindAssessment, Content: []collector.PackagedContent{{Ref: v1alpha1.BundleReference{Digest: ref.Digest}, Vendored: true, Applied: true}}},
	} {
		r := e.rr.coverageReport(run, b, scope, c, collector.Evaluation{}, p, nil)
		if r.Inventory.Resolved || len(r.Controls) != 0 || !slices.ContainsFunc(r.Limitations, func(l coverage.Limitation) bool {
			return l.Code == coverage.CodeContentUnavailable && l.Blocking
		}) {
			t.Errorf("%s: %+v %+v", what, r.Inventory, r.Limitations)
		}
		if r.Inputs.Bundle != ref {
			t.Errorf("%s: report names %+v", what, r.Inputs.Bundle)
		}
	}
	// No profile when the run started: no baseline.
	if err := e.rr.freezeSelection(run, nil); err != nil {
		t.Fatal(err)
	}
	r := e.rr.coverageReport(run, b, scope, c, collector.Evaluation{}, collector.CoveragePackage{Dir: t.TempDir(), Kind: publication.KindAssessment}, nil)
	if r.Inventory.Resolved || !hasLimitation(r, coverage.CodeBaselineNotSelected) {
		t.Errorf("no profile: %+v", r.Limitations)
	}
}

// rewrite replaces a package file and its descriptor entry, as a tamperer
// who also regenerates the inventory would.
func rewrite(t *testing.T, dir, rel string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), b, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := publication.LoadDescriptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range d.Files {
		if d.Files[i].Path == rel {
			h := sha256.Sum256(b)
			d.Files[i].SHA256, d.Files[i].Size = hex.EncodeToString(h[:]), int64(len(b))
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, publication.DescriptorFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Hand-break guards (JSON/text divergence; checksum mismatch accepted):
// the storage validator rejects a published package whose coverage text
// no longer renders its JSON, or whose JSON is no longer canonical, even
// with a regenerated inventory.
func TestValidatePackageRejectsTamperedCoverage(t *testing.T) {
	_, _, dir := publishedPackage(t, nil)
	for name, edit := range map[string]func(j, txt []byte) (string, []byte){
		"text body": func(_, txt []byte) (string, []byte) {
			return coverage.TextFile, bytes.Replace(txt, []byte("Inventory: resolved"), []byte("Inventory: resolved, satisfied"), 1)
		},
		"json body": func(j, _ []byte) (string, []byte) {
			return coverage.JSONFile, bytes.Replace(j, []byte(`"automation": "unknown"`), []byte(`"automation": "partial"`), 1)
		},
		"checksum only": func(j, _ []byte) (string, []byte) { return coverage.JSONFile, j },
	} {
		cp := filepath.Join(t.TempDir(), "pkg")
		if err := os.CopyFS(cp, os.DirFS(dir)); err != nil {
			t.Fatal(err)
		}
		j, _ := os.ReadFile(filepath.Join(cp, coverage.JSONFile))
		txt, _ := os.ReadFile(filepath.Join(cp, coverage.TextFile))
		rel, b := edit(j, txt)
		if name == "checksum only" {
			// Bytes changed without the descriptor: VerifyDir's mismatch.
			if err := os.WriteFile(filepath.Join(cp, rel), append(b, ' '), 0o644); err != nil {
				t.Fatal(err)
			}
		} else {
			if bytes.Equal(b, map[string][]byte{coverage.JSONFile: j, coverage.TextFile: txt}[rel]) {
				t.Fatalf("%s: edit did not apply", name)
			}
			rewrite(t, cp, rel, b)
		}
		if _, err := s3store.ValidatePackage(cp); err == nil {
			t.Errorf("%s: tampered coverage accepted", name)
		}
	}
}

// An OCI run's coverage is built from the frozen bundle packaged under its
// member directory, verified again, and references it by package path.
func TestCoverageReportFromFrozenMember(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	run := e.run(name)

	// The released 0.1.0 definition: an old pinned package stays readable.
	raw, err := os.ReadFile("../../bundles/konstapel-linux-hardening/released/0.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = strings.Repeat("e", 40)
	a, err := bundle.Build(def, os.DirFS("../.."), a0)
	if err != nil {
		t.Fatal(err)
	}
	id := bundle.FrozenIdentity{FrozenVersion: bundle.FrozenVersion, Name: a.Descriptor.Name, Version: a.Descriptor.Version, Source: a.Descriptor.Source,
		Digests: bundle.Digests{Revision: a.Descriptor.Source.Revision, Content: a.Descriptor.ContentDigest(), Archive: a.LayerDigest, OCI: a.ManifestDigest}}
	ref := v1alpha1.BundleReference{Name: a.Descriptor.Name, Digest: a.ManifestDigest}
	pkg := t.TempDir()
	path := publication.ContentPath(ref.Digest)
	if _, err := bundle.WriteFrozen(filepath.Join(pkg, filepath.FromSlash(path)), a.Manifest, a.Layer, id); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"capture.json", "evaluation.json"} {
		if err := os.WriteFile(filepath.Join(pkg, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	profile := &v1alpha1.ComplianceProfile{Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: []v1alpha1.ProfilePolicy{{Name: "require-run-as-nonroot"}}}}
	profile.Name, profile.UID = "hardening", "uid-hardening"
	if err := e.rr.freezeSelection(run, profile); err != nil {
		t.Fatal(err)
	}
	b := epochBinding("audit-prod", nil)
	scope := publication.Scope{Kind: publication.ScopeBinding, ClusterID: "c", BindingUID: string(b.UID), NamespaceUIDs: []string{}}
	var c collector.CaptureV2
	p := collector.CoveragePackage{Dir: pkg, Kind: publication.KindAssessment, Content: []collector.PackagedContent{{Ref: ref, Path: path, Applied: true}}}
	r := e.rr.coverageReport(run, b, scope, c, collector.Evaluation{}, p, nil)
	if !r.Inventory.Resolved || !r.Mappings.Resolved || r.Inputs.ContentPath != path || r.Inputs.Bundle != ref {
		t.Fatalf("frozen member: %+v %+v %v", r.Inventory, r.Mappings, r.Limitations)
	}
	partial := 0
	for _, ctl := range r.Controls {
		if ctl.Automation == coverage.AutomationPartial {
			partial++
		}
	}
	if partial == 0 {
		t.Fatal("no selected check is mapped")
	}
	for _, s := range r.Sources {
		if s.Kind != coverage.SourceCapture && s.Kind != coverage.SourceEvaluation && !strings.HasPrefix(s.Path, path+"/content/") {
			t.Errorf("source %s is not under the member's packaged content", s.Path)
		}
	}
	// A frozen copy that no longer verifies is a diagnostic, never re-read.
	if err := os.WriteFile(filepath.Join(pkg, filepath.FromSlash(path), "content", "linux-hardening", "component-definition.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = e.rr.coverageReport(run, b, scope, c, collector.Evaluation{}, p, nil)
	if r.Inventory.Resolved || !hasLimitation(r, coverage.CodeContentUnavailable) {
		t.Fatalf("altered member: %+v", r.Limitations)
	}
}

func hasLimitation(r *coverage.Report, code string) bool {
	return slices.ContainsFunc(r.Limitations, func(l coverage.Limitation) bool { return l.Code == code && l.Blocking })
}
