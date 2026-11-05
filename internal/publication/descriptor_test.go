package publication_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

var update = flag.Bool("update", false, "regenerate testdata/publication descriptors")

const fixtureRoot = "../../testdata/publication"

var (
	t0 = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	t1 = t0.Add(4*time.Minute + 30*time.Second)
)

func role(p string) publication.FileRole {
	switch {
	case p == "assessment-results.json":
		return publication.RoleAssessmentResults
	case p == "summary.json":
		return publication.RoleSummary
	case p == "diagnostic.json":
		return publication.RoleDiagnostic
	case strings.HasPrefix(p, "evidence/"):
		return publication.RoleEvidenceExtract
	}
	return ""
}

func namespaceScope(run publication.RunRef, ns, uid string) publication.Scope {
	return publication.Scope{Kind: publication.ScopeNamespace, ClusterID: run.ClusterID, BindingUID: run.BindingUID,
		Request:       &publication.RequestRef{Namespace: ns, Name: "nightly-check", UID: "req-uid-" + ns, NamespaceUID: uid},
		NamespaceUIDs: []string{uid}, Revision: "scope-rev-1"}
}

// fixtures defines every frozen package's metadata. Files and checksums are
// computed from the fixture directories.
func fixtures() map[string]publication.Descriptor {
	run := func(id string) publication.RunRef {
		return publication.RunRef{ClusterID: "kube-system:fixture-cluster", BindingUID: "binding-uid-1", RunUID: id}
	}
	base := func(r publication.RunRef, kind publication.PackageKind, scope publication.Scope, ev publication.EvidenceSummary, out publication.OutcomeCounts) publication.Descriptor {
		return publication.Descriptor{APIVersion: publication.APIVersion, Kind: publication.DescriptorKind, Run: r, PackageKind: kind,
			Scope: scope, ScopeSHA256: scope.Digest(),
			Revisions: publication.Revisions{BindingConfiguration: "binding-config-3", Enforcement: []string{"enf-binding-uid-1-e2-0f1e2d3c"}, MappingSHA256: strings.Repeat("ab", 32)},
			Window:    publication.Window{Started: t0, Closed: t1}, Evidence: ev, Outcomes: out,
			Producer: publication.Producer{Name: "konstapel-controller", Version: "fixture", ValidatedAt: t1, Checks: []string{"scope-projection", "oscal-schema-1.1.3"}}}
	}
	ra, rb, rc, rd := run("run-uid-ns-complete"), run("run-uid-ns-incomplete"), run("run-uid-binding-diagnostic"), run("run-uid-binding-no-targets")
	diag := base(rc, publication.KindDiagnostic,
		publication.Scope{Kind: publication.ScopeBinding, ClusterID: rc.ClusterID, BindingUID: rc.BindingUID, NamespaceUIDs: []string{"ns-uid-team-a", "ns-uid-team-b"}, Revision: "scope-rev-1"},
		publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 4, Attributable: 2, Unresolved: 2},
		publication.OutcomeCounts{Pass: 1, Fail: 1})
	diag.Diagnostic = &publication.Diagnostic{Reason: "ExportFailed", MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: "mapping digest did not match the enforcement revision"}
	diag.Producer.Checks = []string{"scope-projection"}
	return map[string]publication.Descriptor{
		"namespace-complete": base(ra, publication.KindAssessment, namespaceScope(ra, "team-a", "ns-uid-team-a"),
			publication.EvidenceSummary{Completeness: publication.Complete, Expected: 3, Attributable: 3},
			publication.OutcomeCounts{Pass: 1, Fail: 1, AcceptedRisk: 1}),
		"namespace-incomplete": base(rb, publication.KindAssessment, namespaceScope(rb, "team-b", "ns-uid-team-b"),
			publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 3, Attributable: 1, Missing: 1, Rejected: 1},
			publication.OutcomeCounts{Pass: 1}),
		"binding-diagnostic": diag,
		"binding-no-targets": base(rd, publication.KindAssessment,
			publication.Scope{Kind: publication.ScopeBinding, ClusterID: rd.ClusterID, BindingUID: rd.BindingUID, NamespaceUIDs: []string{"ns-uid-team-c"}, Revision: "scope-rev-1"},
			publication.EvidenceSummary{Completeness: publication.NoTargets}, publication.OutcomeCounts{}),
	}
}

func TestFixturesRoundTrip(t *testing.T) {
	root, _ := filepath.Abs("../..")
	for name, want := range fixtures() {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, name)
			files, err := publication.Inventory(dir, role)
			if err != nil {
				t.Fatal(err)
			}
			want.Files = files
			b, _ := json.MarshalIndent(want, "", "  ")
			b = append(b, '\n')
			path := filepath.Join(dir, publication.DescriptorFile)
			if *update {
				if err = os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(disk, b) {
				t.Fatalf("%s is stale; run go test ./internal/publication -update", path)
			}
			got, err := publication.LoadDescriptor(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.Digest() != want.Digest() {
				t.Fatal("descriptor does not round-trip")
			}
			if err = publication.VerifyDir(dir, got); err != nil {
				t.Fatal(err)
			}
			for _, f := range got.Files {
				if f.Role == publication.RoleAssessmentResults {
					if err = assessment.Schema(filepath.Join(dir, f.Path), filepath.Join(root, "content/schemas/oscal-1.1.3.json")); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestFixtureStatesStaySeparate(t *testing.T) {
	f := fixtures()
	complete := f["namespace-complete"]
	if complete.Evidence.Completeness != publication.Complete || complete.Outcomes.Fail == 0 || complete.Outcomes.AcceptedRisk == 0 {
		t.Fatal("complete evidence must keep failures and accepted risk")
	}
	if f["binding-no-targets"].Evidence.Completeness != publication.NoTargets || f["binding-no-targets"].Outcomes.Pass != 0 {
		t.Fatal("zero targets must not establish a pass")
	}
	pending := publication.Status{Phase: publication.PhaseFailed, PublicationID: "x", Availability: publication.AvailabilityUnavailable, Failure: &publication.Failure{Reason: "BackendUnavailable"}}
	s := publication.Summarize(complete, pending)
	if s.Evidence.Completeness != publication.Complete || s.Publication != publication.PhaseFailed || s.ArtifactRef != "" {
		t.Fatalf("publication failure must not alter evidence or expose an artifact: %+v", s)
	}
	if publication.Summarize(f["binding-diagnostic"], pending).Export != publication.ExportDiagnostic {
		t.Fatal("diagnostic export not reported")
	}
}

func valid() publication.Descriptor {
	d := fixtures()["namespace-complete"]
	d.Files = []publication.File{{Path: "assessment-results.json", Role: publication.RoleAssessmentResults, SHA256: strings.Repeat("0", 64), Size: 1}}
	return d
}

func TestDescriptorValidation(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*publication.Descriptor){
		"scope digest": func(d *publication.Descriptor) { d.Scope.Revision = "scope-rev-2" },
		"namespace scope widened": func(d *publication.Descriptor) {
			d.Scope.NamespaceUIDs = append(d.Scope.NamespaceUIDs, "ns-uid-z")
			d.ScopeSHA256 = d.Scope.Digest()
		},
		"binding scope w/ request": func(d *publication.Descriptor) {
			d.Scope.Kind = publication.ScopeBinding
			d.ScopeSHA256 = d.Scope.Digest()
		},
		"scope other binding": func(d *publication.Descriptor) { d.Scope.BindingUID = "other"; d.ScopeSHA256 = d.Scope.Digest() },
		"traversal":           func(d *publication.Descriptor) { d.Files[0].Path = "../x.json" },
		"absolute":            func(d *publication.Descriptor) { d.Files[0].Path = "/etc/passwd" },
		"unclean":             func(d *publication.Descriptor) { d.Files[0].Path = "a/./b" },
		"descriptor listed":   func(d *publication.Descriptor) { d.Files[0].Path = publication.DescriptorFile },
		"bad checksum":        func(d *publication.Descriptor) { d.Files[0].SHA256 = "ABC" },
		"unknown role":        func(d *publication.Descriptor) { d.Files[0].Role = "credentials" },
		"no results":          func(d *publication.Descriptor) { d.Files[0].Role = publication.RoleSummary },
		"zero targets complete": func(d *publication.Descriptor) {
			d.Evidence = publication.EvidenceSummary{Completeness: publication.Complete}
		},
		"incomplete hidden":       func(d *publication.Descriptor) { d.Evidence.Missing = 1; d.Evidence.Expected = 4 },
		"complete claims missing": func(d *publication.Descriptor) { d.Evidence.Attributable = 2; d.Evidence.Missing = 1 },
		"diagnostic with oscal": func(d *publication.Descriptor) {
			d.PackageKind = publication.KindDiagnostic
			d.Diagnostic = &publication.Diagnostic{Reason: "ExportFailed", MissingExports: []publication.FileRole{publication.RoleAssessmentResults}}
			d.Files = append(d.Files, publication.File{Path: "diagnostic.json", Role: publication.RoleDiagnostic, SHA256: strings.Repeat("0", 64)})
		},
		"window": func(d *publication.Descriptor) { d.Window.Closed = d.Window.Started.Add(-time.Second) },
	}
	for name, mutate := range cases {
		d := valid()
		mutate(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted invalid descriptor", name)
		}
	}
}

func TestVerifyDirRejectsTampering(t *testing.T) {
	src := filepath.Join(fixtureRoot, "namespace-complete")
	d, err := publication.LoadDescriptor(src)
	if err != nil {
		t.Fatal(err)
	}
	copyDir := func(t *testing.T) string {
		dir := t.TempDir()
		for _, f := range append(d.Files, publication.File{Path: publication.DescriptorFile}) {
			b, _ := os.ReadFile(filepath.Join(src, f.Path))
			_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, f.Path)), 0o755)
			if err := os.WriteFile(filepath.Join(dir, f.Path), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	for name, tamper := range map[string]func(string) error{
		"modified": func(dir string) error { return os.WriteFile(filepath.Join(dir, "summary.json"), []byte("{}"), 0o644) },
		"extra":    func(dir string) error { return os.WriteFile(filepath.Join(dir, "sibling.json"), []byte("{}"), 0o644) },
		"missing":  func(dir string) error { return os.Remove(filepath.Join(dir, "evidence/extracts.json")) },
		"symlink": func(dir string) error {
			_ = os.Remove(filepath.Join(dir, "summary.json"))
			return os.Symlink("/etc/hostname", filepath.Join(dir, "summary.json"))
		},
	} {
		dir := copyDir(t)
		if err := tamper(dir); err != nil {
			t.Fatal(err)
		}
		if publication.VerifyDir(dir, d) == nil {
			t.Errorf("%s: tampered package accepted", name)
		}
	}
}

func TestPublicationIDDeterministic(t *testing.T) {
	r := publication.RunRef{ClusterID: "c", BindingUID: "b", RunUID: "r"}
	if r.PublicationID() != r.PublicationID() || r.PublicationID() == (publication.RunRef{ClusterID: "c", BindingUID: "b", RunUID: "r2"}).PublicationID() {
		t.Fatal("publication identity must be deterministic and run-specific")
	}
	if (publication.RunRef{ClusterID: "c\x00b", RunUID: "r"}).PublicationID() == (publication.RunRef{ClusterID: "c", BindingUID: "b", RunUID: "r"}).PublicationID() {
		t.Fatal("identity components must not be ambiguous")
	}
}

func TestStaleScopeIsNeverComplete(t *testing.T) {
	for name, ev := range map[string]publication.EvidenceSummary{
		"complete with stale":   {Completeness: publication.Complete, Expected: 2, Attributable: 2, StaleScopes: 1},
		"no targets with stale": {Completeness: publication.NoTargets, StaleScopes: 1},
	} {
		d := valid()
		d.Evidence = ev
		if d.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, ev := range map[string]publication.EvidenceSummary{
		"all attributable but stale": {Completeness: publication.Incomplete, Expected: 2, Attributable: 2, StaleScopes: 1},
		"only stale scope":           {Completeness: publication.Incomplete, StaleScopes: 1},
	} {
		d := valid()
		d.Evidence = ev
		if err := d.Validate(); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}
