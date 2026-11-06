package collector

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const sibling = "SIBLING-SECRET"

// mixedCapture has one report holding results for shop-dev and shop-prod,
// a result spanning both namespaces, and a result without resource identity.
func mixedCapture(t *testing.T) (CaptureV2, Expected) {
	c := freshCapture(t)
	at := c.Window.Started.Add(time.Minute)
	var dev, prod Expected
	for _, e := range c.Expected {
		switch e.NamespaceUID {
		case "uid-shop-dev":
			dev = e
		case "uid-shop-prod":
			prod = e
		}
	}
	devRes := result(dev.Check.EnginePolicy, dev.Check.Index, dev.Workload.UID, "pass", at)
	devRes["message"] = "dev workload fine"
	devRes["resources"] = []any{assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": "shop-dev", "name": "web", "uid": dev.Workload.UID}}
	prodRes := result(prod.Check.EnginePolicy, prod.Check.Index, prod.Workload.UID, "fail", at)
	prodRes["message"] = sibling + " privileged container in shop-prod"
	prodRes["resources"] = []any{assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": "shop-prod", "name": "web", "uid": prod.Workload.UID}}
	both := result(prod.Check.EnginePolicy, prod.Check.Index, prod.Workload.UID, "fail", at)
	both["message"] = sibling + " shared finding"
	both["resources"] = []any{
		assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": "shop-prod", "name": "web", "uid": prod.Workload.UID},
		assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": "shop-dev", "name": "other", "uid": "pod-dev-other"},
	}
	opaque := result(dev.Check.EnginePolicy, dev.Check.Index, dev.Workload.UID, "fail", at)
	opaque["resources"] = []any{assessment.Object{"name": "web"}} // no namespace or UID
	opaque["message"] = sibling + " unattributable"
	report := assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "ClusterPolicyReport",
		"metadata": assessment.Object{"uid": "mixed-report", "labels": assessment.Object{"team": sibling}},
		"summary":  assessment.Object{"fail": 2, "note": sibling},
		"results":  []any{prodRes, devRes, both, opaque}}
	devRes["annotations"] = assessment.Object{"leak": sibling}
	c.Reports = []assessment.Object{report}
	return c, dev
}

func TestProjectionExcludesSiblingData(t *testing.T) {
	c, dev := mixedCapture(t)
	p, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	for _, leak := range []string{sibling, "uid-shop-prod", "pod-prod", "shop-prod"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("projection contains %q", leak)
		}
	}
	if err := ValidateProjection(p); err != nil {
		t.Fatal(err)
	}
	if len(p.Subjects) != 1 || len(p.Expected) != 1 || len(p.Workloads) != 1 || p.Projection.Extracts != 2 || p.Projection.WithheldTotal != 1 {
		t.Fatalf("projection %+v subjects %d expected %d", p.Projection, len(p.Subjects), len(p.Expected))
	}
	results := p.Reports[0]["results"].([]any)
	exact, filtered := assessment.Map(results[0]), assessment.Map(results[1])
	if src := assessment.Map(exact[SourceField]); src["transformation"] != TransformExact || src["resultIndex"] != 1 || src["report"] != "mixed-report" || src["reportSha256"] == "" {
		t.Fatalf("exact provenance %v", src)
	}
	if exact["message"] != "dev workload fine" {
		t.Fatal("exact extract lost its in-scope message")
	}
	if src := assessment.Map(filtered[SourceField]); src["transformation"] != TransformResourceFiltered || src["resultIndex"] != 2 || filtered["message"] != nil {
		t.Fatalf("filtered extract %v", filtered)
	}
	if refs := filtered["resources"].([]any); len(refs) != 1 || assessment.Map(refs[0])["uid"] != "pod-dev-other" {
		t.Fatalf("filtered extract kept %v", refs)
	}
	// The team's evidence stays attributable and traces to the source index.
	ev := evaluate(t, p, nil, maxAge)
	if ev.Evidence.Completeness != publication.Complete || ev.Outcomes.Pass != 1 || ev.Observations[0].Index != 1 || ev.Observations[0].Report != "mixed-report" {
		t.Fatalf("%+v %+v", ev.Evidence, ev.Observations)
	}
	_ = dev
}

func TestProjectionRejectsOutOfScopeNamespace(t *testing.T) {
	c, _ := mixedCapture(t)
	if _, err := Project(c, "uid-shop-elsewhere"); err == nil {
		t.Fatal("projected to a namespace outside the frozen scope")
	}
	if err := ValidateProjection(c); err == nil {
		t.Fatal("unprojected capture passed projection validation")
	}
}

func TestStaleAndChangeMessagesAreRedacted(t *testing.T) {
	c, _ := mixedCapture(t)
	c.Stale = []targeting.StaleScope{{Binding: targeting.ObjectRevision{Name: "dangling", UID: "uid-dangling"}, Reason: targeting.ReasonProfileNotFound, Message: sibling + " stale detail"}}
	NewTracker(&c).Configuration(c.Window.Started.Add(time.Minute), c.Subjects, c.Stale)
	tr := NewTracker(&c)
	prod := c.Workloads[1]
	prod.StateSHA256 = "changed"
	tr.Workload(c.Window.Started.Add(time.Minute), prod, false)
	p, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), sibling) || strings.Contains(string(b), "uid-shop-prod") {
		t.Fatal("stale or change detail leaked into the projection")
	}
	if len(p.Stale) != len(c.Stale) || p.Stale[0].Reason != c.Stale[0].Reason {
		t.Fatal("stale scope reasons must remain visible")
	}
}

func TestNamespacePackageContainsOnlyItsScope(t *testing.T) {
	c, _ := mixedCapture(t)
	p, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	ev := evaluate(t, p, nil, maxAge)
	run := publication.RunRef{ClusterID: p.Cluster, BindingUID: "uid-audit-all", RunUID: "run-ns"}
	req := ExportRequest{Root: repo(t), Out: filepath.Join(t.TempDir(), "pkg"), Run: run, BindingConfiguration: "b",
		Scope: publication.Scope{Kind: publication.ScopeNamespace, ClusterID: run.ClusterID, BindingUID: run.BindingUID,
			Request:       &publication.RequestRef{Namespace: "shop-dev", Name: "r", UID: "req-1", NamespaceUID: "uid-shop-dev"},
			NamespaceUIDs: []string{"uid-shop-dev"}, Revision: "s"},
		Capture: p, Evaluation: ev}
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindAssessment || d.Scope.Kind != publication.ScopeNamespace {
		t.Fatalf("%+v", d)
	}
	// No packaged file outside the shared content tree mentions the sibling.
	err = filepath.WalkDir(req.Out, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if rel, _ := filepath.Rel(req.Out, path); strings.HasPrefix(rel, "content/") {
			return nil
		}
		b, _ := os.ReadFile(path)
		for _, leak := range []string{sibling, "uid-shop-prod", "pod-prod", "shop-prod"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s contains %q", path, leak)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// An unprojected capture cannot become a namespace package, and a
	// projection cannot be relabeled as a binding package.
	req.Capture, req.Out = c, filepath.Join(t.TempDir(), "x")
	if _, err := Export(context.Background(), req); err == nil {
		t.Fatal("unprojected capture exported as a namespace package")
	}
	req.Capture, req.Out = p, filepath.Join(t.TempDir(), "y")
	req.Scope = publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: []string{"uid-shop-dev"}, Revision: "s"}
	if _, err := Export(context.Background(), req); err == nil {
		t.Fatal("namespace projection relabeled as a binding package")
	}
}
