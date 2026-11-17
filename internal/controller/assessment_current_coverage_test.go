package controller

// Current coverage summaries (add-control-coverage-reporting 3.3, 3.4).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// rereport replaces pod's PolicyReport with one evaluated at at.
func (e *assessEnv) rereport(ns, podUID, policy, outcome string, at time.Time) {
	e.t.Helper()
	old := &unstructured.Unstructured{}
	old.SetGroupVersionKind(PolicyReportGVK)
	old.SetNamespace(ns)
	old.SetName("r-" + podUID)
	if err := e.c.Delete(context.Background(), old); err != nil {
		e.t.Fatal(err)
	}
	e.report(ns, podUID, policy, outcome, at)
}

func packageBytes(t *testing.T, e *runEnv, r *v1alpha1.AssessmentRun) []byte {
	t.Helper()
	rc, _, err := e.pub.Open(context.Background(), e.ref(r))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fileSHA256(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// The run's summary references exactly the coverage.json its published
// package carries, with the report's bounded counts, the inputs the run
// assessed and the owner's evidence expiry at closure.
func TestRunSummaryReferencesPackagedCoverage(t *testing.T) {
	_, run, dir := publishedPackage(t, nil)
	rep, d := packagedCoverage(t, dir)
	got := run.Status.Summary.Coverage
	if got == nil {
		t.Fatalf("run summary has no coverage: %+v", run.Status.Summary)
	}
	sha := fileSHA256(t, filepath.Join(dir, coverage.JSONFile))
	var inventoried string
	for _, f := range d.Files {
		if f.Role == publication.RoleCoverage {
			inventoried = f.SHA256
		}
	}
	if got.SHA256 != sha || inventoried != sha {
		t.Fatalf("summary names %s, package coverage.json is %s (descriptor %s)", got.SHA256, sha, inventoried)
	}
	want := coverage.Summarize(rep, sha)
	var ns []string
	for _, n := range rep.Scope.Namespaces {
		ns = append(ns, n.UID)
	}
	want.InputsSHA256 = coverage.InputsDigest(rep.Scope.Binding.UID, ns, &rep.Inputs.Selection)
	evaluated := run.Status.Summary.OldestEvaluation.UTC()
	vu := evaluated.Add(2 * time.Hour)
	want.ValidUntil = &vu
	if back := publication.CoverageFromAPI(got); !reflect.DeepEqual(*back, want) {
		t.Fatalf("summary\n%+v\nwant\n%+v", *back, want)
	}
	if got.Controls != 287 || got.Automation.None+got.Automation.Unselected+got.Automation.Partial+got.Automation.Unknown != got.Controls ||
		!got.AsOf.Equal(run.Status.Window.Closed) {
		t.Fatalf("counts %+v", got)
	}
}

// Hand-break guard (EvidenceComplete follows coverage): a coverage
// diagnostic is summarized as unresolved without inputs, and the run's
// evidence, outcomes and EvidenceComplete condition are those of a run
// with resolved coverage.
func TestCoverageSummaryLeavesEvidenceCompleteUnchanged(t *testing.T) {
	_, base, _ := publishedPackage(t, nil)
	_, run, _ := publishedPackage(t, func(e *runEnv, r *v1alpha1.AssessmentRun) {
		if err := os.Remove(filepath.Join(e.rr.staging(r), runSelectionFile)); err != nil {
			t.Fatal(err)
		}
	})
	cov := run.Status.Summary.Coverage
	if cov == nil || cov.InventoryResolved || cov.Controls != 0 || cov.InputsSHA256 != "" || len(cov.BlockingCodes) != 1 || cov.BlockingCodes[0] != coverage.CodeSelectionUnavailable {
		t.Fatalf("diagnostic summary %+v", cov)
	}
	if !base.Status.Summary.Coverage.InventoryResolved {
		t.Fatalf("base summary %+v", base.Status.Summary.Coverage)
	}
	strip := func(c *metav1.Condition) metav1.Condition {
		return metav1.Condition{Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message}
	}
	a := meta.FindStatusCondition(base.Status.Conditions, v1alpha1.ConditionEvidenceComplete)
	b := meta.FindStatusCondition(run.Status.Conditions, v1alpha1.ConditionEvidenceComplete)
	if a == nil || b == nil || strip(a) != strip(b) || a.Status != metav1.ConditionTrue ||
		base.Status.Summary.Evidence != run.Status.Summary.Evidence || base.Status.Summary.Outcomes != run.Status.Summary.Outcomes {
		t.Fatalf("EvidenceComplete %+v vs %+v; summaries %+v vs %+v", a, b, base.Status.Summary, run.Status.Summary)
	}
}

// Hand-break guard (summary without packaged bytes): coverage left out of
// the package, or other bytes packaged than rendered, leaves no summary.
func TestCoverageSummaryOnlyForPackagedReport(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	run := e.run(name)
	b := e.binding("audit-prod")
	req := collector.ExportRequest{Scope: publication.Scope{Kind: publication.ScopeBinding, BindingUID: string(b.UID), NamespaceUIDs: []string{}}}
	packaged := e.rr.exportCoverage(context.Background(), run, b, &req, nil)
	files, err := req.Coverage(collector.CoveragePackage{Dir: t.TempDir(), Kind: publication.KindDiagnostic, Diagnostic: &publication.Diagnostic{Reason: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(files.JSON)
	sha := hex.EncodeToString(h[:])
	with := func(sha string) publication.Descriptor {
		return publication.Descriptor{Files: []publication.File{{Path: publication.CoverageFile, Role: publication.RoleCoverage, SHA256: sha}}}
	}
	if s := packaged(with(sha)); s == nil || s.SHA256 != sha {
		t.Fatalf("packaged report not summarized: %+v", s)
	}
	if s := packaged(with(fileSHA256Of([]byte("other")))); s != nil {
		t.Fatalf("summarized bytes the package does not carry: %+v", s)
	}
	req.CoverageOmitted(os.ErrInvalid)
	if s := packaged(with(sha)); s != nil {
		t.Fatalf("summarized coverage the export left out: %+v", s)
	}
}

func fileSHA256Of(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// The current summary follows the clock without new events: it is Current
// until the report's validUntil, the owner requeues exactly then, and it
// becomes Expired while the run's summary, the published package bytes and
// the report's closure-time interpretation stay unchanged. The binding's
// live evidence (fresher than the report) is not affected.
func TestCurrentCoverageExpiresOnTheClock(t *testing.T) {
	e, run, dir := publishedPackage(t, nil)
	before := packageBytes(t, e, run)
	rep, _ := packagedCoverage(t, dir)
	sum := run.Status.Summary.Coverage
	if sum.ValidUntil == nil {
		t.Fatal("no validUntil")
	}
	validUntil := sum.ValidUntil.Time

	// Fresher live evidence: the binding's own expiry is later than the
	// report's, so only coverage can schedule the earlier requeue.
	e.rereport("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(30*time.Minute))
	e.now = a0.Add(40 * time.Minute)
	res := e.assess("audit-prod")
	cur := e.current("audit-prod")
	if cur.Coverage == nil || cur.Coverage.State != v1alpha1.CoverageCurrent || cur.Coverage.Run == nil || cur.Coverage.Run.UID != string(run.UID) ||
		!reflect.DeepEqual(cur.Coverage.Summary, sum) {
		t.Fatalf("current coverage %s", asJSON(cur.Coverage))
	}
	if cur.NextExpiry == nil || !cur.NextExpiry.After(validUntil) {
		t.Fatalf("live expiry %v is not after the report's %v", cur.NextExpiry, validUntil)
	}
	if want := validUntil.Sub(e.now) + time.Second; res.RequeueAfter != want {
		t.Fatalf("requeue after %v, want %v (the report's validUntil)", res.RequeueAfter, want)
	}

	e.now = validUntil
	e.assess("audit-prod")
	cur = e.current("audit-prod")
	if cur.Coverage.State != v1alpha1.CoverageExpired || !reflect.DeepEqual(cur.Coverage.Summary, sum) {
		t.Fatalf("at validUntil: %s", asJSON(cur.Coverage))
	}
	if cur.Evidence.Completeness != "Complete" || cur.Outcomes.Fail != 1 {
		t.Fatalf("coverage expiry changed live evidence: %+v %+v", cur.Evidence, cur.Outcomes)
	}
	after := e.run(run.Name)
	if !reflect.DeepEqual(after.Status.Summary, run.Status.Summary) || string(packageBytes(t, e, after)) != string(before) {
		t.Fatal("expiry changed the run's summary or its published package")
	}
	again, _ := packagedCoverage(t, unpackFake(t, before))
	if !again.AsOf.Equal(rep.AsOf) || *again.TechnicalEvidence.Evidence != *rep.TechnicalEvidence.Evidence || again.TechnicalEvidence.Evidence.Completeness != publication.Complete {
		t.Fatalf("the retained report no longer reads as evaluated at closure: %+v", again.TechnicalEvidence.Evidence)
	}
}

// Scope changes make the current summary ScopeChanged: namespaces leaving
// the binding and a changed profile selection, each picked up by the owner's
// reconcile of the event, never by re-reading the report.
func TestCurrentCoverageScopeChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(e *runEnv)
	}{
		{"namespace relabelled", func(e *runEnv) {
			ns := nsObj("prod")
			if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(ns), ns); err != nil {
				t.Fatal(err)
			}
			ns.Labels = map[string]string{"environment": "staging"}
			if err := e.c.Update(context.Background(), ns); err != nil {
				t.Fatal(err)
			}
		}},
		{"profile selection edited", func(e *runEnv) {
			p := &v1alpha1.ComplianceProfile{}
			if err := e.c.Get(context.Background(), client.ObjectKey{Name: "baseline"}, p); err != nil {
				t.Fatal(err)
			}
			p.Spec.Policies = append(p.Spec.Policies, v1alpha1.ProfilePolicy{Name: "another-policy"})
			if err := e.c.Update(context.Background(), p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, run, _ := publishedPackage(t, nil)
			e.assess("audit-prod")
			if c := e.current("audit-prod").Coverage; c.State != v1alpha1.CoverageCurrent {
				t.Fatalf("before: %s", asJSON(c))
			}
			tc.change(e)
			e.assess("audit-prod")
			c := e.current("audit-prod").Coverage
			if c.State != v1alpha1.CoverageScopeChanged || c.Run.UID != string(run.UID) || !reflect.DeepEqual(c.Summary, run.Status.Summary.Coverage) {
				t.Fatalf("after: %s", asJSON(c))
			}
		})
	}
}

// Only the newest committed full-binding run stands for the binding:
// namespace runs, uncommitted runs and other bindings' runs never do, and
// a newest run without coverage is NoReport rather than an older report.
func TestCurrentCoverageSelectsNewestCommittedBindingRun(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	b := e.binding("audit-prod")
	ctx := context.Background()
	sum := func(sha string) *v1alpha1.AssessmentSummary {
		return &v1alpha1.AssessmentSummary{Export: "Assessment", Coverage: &v1alpha1.CoverageSummary{SHA256: sha, InputsSHA256: "in", TechnicalEvidence: "resolved"}}
	}
	mk := func(name string, bindingUID types.UID, scope v1alpha1.RunScope, closed time.Time, phase v1alpha1.RunPhase, pub v1alpha1.PublicationPhase, s *v1alpha1.AssessmentSummary) {
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{LabelRunBinding: string(bindingUID)}},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-prod"}, Scope: scope}}
		if scope == v1alpha1.RunScopeNamespace {
			r.Spec.Request = &v1alpha1.RequestReference{Namespace: "prod", Name: "q", UID: "q"}
			r.Spec.Trigger = &v1alpha1.RunTrigger{Type: v1alpha1.TriggerRequest}
		}
		if err := e.c.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
		c := metav1.NewTime(closed)
		r.Status = v1alpha1.AssessmentRunStatus{Phase: phase, Window: &v1alpha1.CaptureWindow{Started: c, Closed: &c}, Summary: s,
			Publication: &v1alpha1.PublicationStatus{Phase: pub, Availability: "Available"}}
		if err := e.c.Status().Update(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	check := func(state v1alpha1.CurrentCoverageState, run, sha string) {
		t.Helper()
		got, err := e.ar.currentCoverage(ctx, b, a0.Add(time.Hour), "in")
		if err != nil {
			t.Fatal(err)
		}
		gotRun, gotSHA := "", ""
		if got.Run != nil {
			gotRun = got.Run.Name
		}
		if got.Summary != nil {
			gotSHA = got.Summary.SHA256
		}
		if got.State != state || gotRun != run || gotSHA != sha {
			t.Fatalf("got %s, want %s %s %s", asJSON(got), state, run, sha)
		}
	}
	check(v1alpha1.CoverageNoReport, "", "")
	mk("old", b.UID, v1alpha1.RunScopeBinding, a0, v1alpha1.RunCompleted, "Committed", sum("old"))
	check(v1alpha1.CoverageCurrent, "old", "old")
	mk("ns-newer", b.UID, v1alpha1.RunScopeNamespace, a0.Add(10*time.Minute), v1alpha1.RunCompleted, "Committed", sum("ns"))
	mk("failed-newer", b.UID, v1alpha1.RunScopeBinding, a0.Add(10*time.Minute), v1alpha1.RunFailed, "Failed", sum("failed"))
	mk("other-binding", "uid-other", v1alpha1.RunScopeBinding, a0.Add(10*time.Minute), v1alpha1.RunCompleted, "Committed", sum("other"))
	check(v1alpha1.CoverageCurrent, "old", "old")
	if got, _ := e.ar.currentCoverage(ctx, b, a0.Add(time.Hour), "changed"); got.State != v1alpha1.CoverageScopeChanged {
		t.Fatalf("other inputs: %s", asJSON(got))
	}
	mk("newest-without", b.UID, v1alpha1.RunScopeBinding, a0.Add(20*time.Minute), v1alpha1.RunCompleted, "Committed", &v1alpha1.AssessmentSummary{Export: "Assessment"})
	check(v1alpha1.CoverageNoReport, "newest-without", "")
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// docBlock returns the fenced text between <!-- name:begin --> and
// <!-- name:end --> of a document.
func docBlock(t *testing.T, doc, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(doc, "<!-- "+name+":begin -->\n```\n")
	body, _, ok2 := strings.Cut(rest, "```\n<!-- "+name+":end -->")
	if !ok || !ok2 {
		t.Fatalf("no %s block", name)
	}
	return body
}

// The status example of docs/control-coverage.md is the binding's current
// coverage after a real (vendored) run, and the documented jsonpaths read
// it from the run, the binding and a team's request. Run with
// KONSTAPEL_UPDATE_DOCS=1 to print the current block.
func TestCoverageStatusDocExample(t *testing.T) {
	const docPath = "../../docs/control-coverage.md"
	e, run, _ := publishedPackage(t, nil)
	e.assess("audit-prod")
	cur := e.current("audit-prod").Coverage
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want := string(b) + "\n"
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	if os.Getenv("KONSTAPEL_UPDATE_DOCS") != "" {
		fmt.Printf("<!-- coverage-status:begin -->\n```\n%s```\n<!-- coverage-status:end -->\n", want)
	} else if got := docBlock(t, doc, "coverage-status"); got != want {
		t.Errorf("coverage-status block is stale; want:\n%s", want)
	}
	if cur.State != v1alpha1.CoverageCurrent || !reflect.DeepEqual(cur.Summary, run.Status.Summary.Coverage) {
		t.Fatalf("example is not the run's current summary: %s", asJSON(cur))
	}
	// The documented jsonpaths name these fields.
	jsonpath := func(v any, path ...string) any {
		var m any
		raw, _ := json.Marshal(v)
		_ = json.Unmarshal(raw, &m)
		for _, p := range path {
			mm, _ := m.(map[string]any)
			m = mm[p]
		}
		return m
	}
	req := v1alpha1.AssessmentRequest{Status: v1alpha1.AssessmentRequestStatus{Summary: run.Status.Summary}}
	for what, v := range map[string]any{
		"{.status.summary.coverage}":            jsonpath(run, "status", "summary", "coverage"),
		"{.status.assessment.current.coverage}": jsonpath(e.binding("audit-prod"), "status", "assessment", "current", "coverage"),
		"request {.status.summary.coverage}":    jsonpath(req, "status", "summary", "coverage"),
	} {
		path := strings.TrimPrefix(what, "request ")
		if v == nil || !strings.Contains(doc, "jsonpath='"+path+"'") {
			t.Errorf("documented jsonpath %s reads nothing or is not documented", what)
		}
	}
}
