package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

func exportReq(t *testing.T, c CaptureV2, ev Evaluation, root string) ExportRequest {
	t.Helper()
	var nsUIDs []string
	seen := map[string]bool{}
	for _, s := range c.Subjects {
		if !seen[string(s.NamespaceUID)] {
			seen[string(s.NamespaceUID)] = true
			nsUIDs = append(nsUIDs, string(s.NamespaceUID))
		}
	}
	if nsUIDs == nil {
		nsUIDs = []string{}
	}
	run := publication.RunRef{ClusterID: c.Cluster, BindingUID: "uid-audit-all", RunUID: "run-1"}
	return ExportRequest{Root: root, Out: filepath.Join(t.TempDir(), "pkg"), Run: run,
		Scope:                publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: nsUIDs, Revision: "scope-1"},
		BindingConfiguration: "binding-config-1", Capture: c, Evaluation: ev}
}

func results(t *testing.T, dir string) assessment.Object {
	t.Helper()
	var ar assessment.Object
	if err := assessment.Read(filepath.Join(dir, "assessment-results.json"), &ar); err != nil {
		t.Fatal(err)
	}
	return assessment.Map(ar["assessment-results"])
}

func firstResult(t *testing.T, dir string) assessment.Object {
	rs, _ := results(t, dir)["results"].([]any)
	if len(rs) != 1 {
		t.Fatalf("want one result, got %d", len(rs))
	}
	return assessment.Map(rs[0])
}

func subjects(r assessment.Object) []assessment.Object {
	var out []assessment.Object
	obs, _ := r["observations"].([]any)
	for _, o := range obs {
		ss, _ := assessment.Map(o)["subjects"].([]any)
		for _, s := range ss {
			out = append(out, assessment.Map(s))
		}
	}
	return out
}

func prop(s assessment.Object, name string) (string, bool) {
	ps, _ := s["props"].([]any)
	for _, p := range ps {
		if m := assessment.Map(p); m["name"] == name {
			return assessment.Str(m["value"]), true
		}
	}
	return "", false
}

func TestExportCompleteEvidenceWithFailures(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindAssessment || d.Evidence.Completeness != publication.Complete || d.Outcomes.Fail != 2 {
		t.Fatalf("descriptor %+v %+v", d.Evidence, d.Outcomes)
	}
	r := firstResult(t, req.Out)
	findings, _ := r["findings"].([]any)
	if len(findings) == 0 || assessment.Str(assessment.At(assessment.Map(findings[0]), "target", "status", "state")) != "not-satisfied" {
		t.Fatalf("an attributable failure must be a not-satisfied finding: %v", findings)
	}
	ss := subjects(r)
	if len(ss) != 3 {
		t.Fatalf("want 3 subjects (overlapping contributions stay distinct), got %d", len(ss))
	}
	obs, _ := r["observations"].([]any)
	if len(obs) != 1 {
		t.Fatalf("one logical policy must be one check, got %d observations", len(obs))
	}
	for _, s := range ss {
		if v, _ := prop(s, "evidence-state"); v != "Attributable" {
			t.Fatalf("subject %v", s)
		}
		if _, ok := prop(s, "evaluated-on"); !ok {
			t.Fatal("attributable subject lacks its evaluation time")
		}
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(req.Out, "assessment-results.json"))), "partial technical evidence") {
		t.Fatal("results do not state partial coverage")
	}
	// A storage backend accepts the package through the shared contract.
	p := fake.New(func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) })
	if _, err := p.Stage(context.Background(), publication.StageRequest{Run: req.Run, Dir: req.Out}); err != nil {
		t.Fatal(err)
	}
}

func TestExportIncompleteEvidenceMakesNoClaim(t *testing.T) {
	c := freshCapture(t) // no reports at all
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindAssessment || d.Evidence.Completeness != publication.Incomplete || d.Evidence.Missing != 3 {
		t.Fatalf("%s %+v %+v", d.PackageKind, d.Evidence, d.Diagnostic)
	}
	r := firstResult(t, req.Out)
	if _, has := r["findings"]; has {
		t.Fatal("missing evidence produced a control finding")
	}
	for _, s := range subjects(r) {
		if _, ok := prop(s, "evaluated-on"); ok {
			t.Fatal("missing evidence presented an evaluation time")
		}
		if v, _ := prop(s, "evidence-state"); v != "Missing" {
			t.Fatalf("subject state %q", v)
		}
	}
}

func TestExportZeroTargetsIsNotAPass(t *testing.T) {
	c := freshCapture(t)
	c.Workloads, c.Expected = []Workload{}, []Expected{}
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Evidence.Completeness != publication.NoTargets || d.Outcomes != (publication.OutcomeCounts{}) {
		t.Fatalf("%+v", d.Evidence)
	}
	raw := string(mustRead(t, filepath.Join(req.Out, "assessment-results.json")))
	if strings.Contains(raw, `"satisfied"`) || strings.Contains(raw, "not-satisfied") {
		t.Fatal("zero targets produced a control determination")
	}
}

func TestExportFailureIsATypedDiagnostic(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, "content"), os.DirFS(filepath.Join(repo(t), "content"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "content/component-definition.json"), []byte(`{"component-definition": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, root)
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindDiagnostic || d.Diagnostic == nil || d.Diagnostic.Reason != "ExportFailed" {
		t.Fatalf("%+v", d)
	}
	// Evidence is reported unchanged; no OSCAL document survives.
	if d.Evidence != ev.Evidence || d.Outcomes != ev.Outcomes {
		t.Fatal("export failure changed evidence or outcomes")
	}
	for _, f := range []string{"assessment-results.json", "assessment-plan.json", "system-security-plan.json", "content"} {
		if _, err := os.Stat(filepath.Join(req.Out, f)); !os.IsNotExist(err) {
			t.Fatalf("%s left in a diagnostic package", f)
		}
	}
	if err := publication.VerifyDir(req.Out, d); err != nil {
		t.Fatal(err)
	}
}

func TestExportRefusesNonEmptyOutput(t *testing.T) {
	c := freshCapture(t)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	if err := os.MkdirAll(req.Out, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(req.Out, "stale"), []byte("x"), 0o644)
	if _, err := Export(context.Background(), req); err == nil {
		t.Fatal("non-empty output accepted")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExportMalformedAndOldEvidenceStaysValidAndUnclaimed(t *testing.T) {
	c := freshCapture(t)
	e0, e1 := c.Expected[0], c.Expected[1]
	bad := result(e0.Check.EnginePolicy, e0.Check.Index, e0.Workload.UID, "fail", time.Time{})
	bad["timestamp"] = assessment.Object{"seconds": "not-a-number"}
	c.Reports = []assessment.Object{
		report("malformed", "ns", e0.Workload.UID, bad),
		report("old-state", "ns", e1.Workload.UID, result(e1.Check.EnginePolicy, e1.Check.Index, e1.Workload.UID, "fail", c.Window.Started.Add(-time.Hour))),
	}
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindAssessment || d.Evidence.Rejected != 2 || d.Outcomes.Fail != 0 {
		t.Fatalf("%s %+v %+v", d.PackageKind, d.Evidence, d.Diagnostic)
	}
	r := firstResult(t, req.Out)
	if _, has := r["findings"]; has {
		t.Fatal("rejected evidence produced a control finding")
	}
	states := map[string]int{}
	for _, s := range subjects(r) {
		v, _ := prop(s, "evidence-state")
		states[v]++
	}
	if states["Rejected"] != 2 || states["Missing"] != 1 {
		t.Fatalf("subject states %v", states)
	}
}
