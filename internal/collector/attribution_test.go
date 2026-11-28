package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Owner decisions 2026-11-27 on the shared namespace projection: sanitized
// namespace diagnostics, no sibling report counts or metadata, and
// per-result attribution by the frozen identities.

// wholeReport is mixedCapture's source report as a reader decodes it.
func wholeReport(t *testing.T) map[string]any {
	t.Helper()
	c, _ := mixedCapture(t)
	var m map[string]any
	b, _ := json.Marshal(c.Reports[0])
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// crossCapture has a shop-prod PolicyReport whose results are shop-dev's
// and shop-prod's, a shop-dev report with a shop-prod result, and results
// whose attribution the frozen identities cannot resolve.
func crossCapture(t *testing.T) (CaptureV2, Expected, Expected) {
	t.Helper()
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
	pod := func(ns, uid string) assessment.Object {
		return assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": ns, "name": "web", "uid": uid}
	}
	res := func(e Expected, outcome, msg string, refs ...assessment.Object) assessment.Object {
		r := result(e.Check.EnginePolicy, e.Check.Index, e.Workload.UID, outcome, at)
		r["message"] = msg
		rs := make([]any, len(refs))
		for i, x := range refs {
			rs[i] = x
		}
		r["resources"] = rs
		return r
	}
	ambiguous := []any{
		// shop-dev's name with shop-prod's frozen workload.
		res(prod, "fail", sibling+" name and identity disagree", pod("shop-dev", prod.Workload.UID)),
		// shop-dev's name with an identity no namespace froze.
		res(dev, "fail", sibling+" unfrozen identity", pod("shop-dev", "pod-dev-unfrozen")),
		// shop-dev's frozen workload under shop-prod's name.
		res(dev, "fail", sibling+" renamed identity", pod("shop-prod", dev.Workload.UID)),
		// No namespace.
		res(dev, "fail", sibling+" no namespace", assessment.Object{"kind": "Pod", "name": "web", "uid": dev.Workload.UID}),
	}
	prodReport := assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
		"metadata": assessment.Object{"uid": "prod-report", "name": "prod-report-" + sibling, "namespace": "shop-prod", "labels": assessment.Object{"team": sibling}},
		"summary":  assessment.Object{"pass": 1, "fail": 1, "note": sibling},
		"results": append([]any{
			res(prod, "fail", sibling+" privileged container in shop-prod", pod("shop-prod", prod.Workload.UID)),
			res(dev, "pass", "dev workload fine", pod("shop-dev", dev.Workload.UID)),
		}, ambiguous...)}
	devReport := assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
		"metadata": assessment.Object{"uid": "dev-report", "name": "dev-report", "namespace": "shop-dev"},
		"results": append([]any{
			res(prod, "fail", sibling+" from the dev report", pod("shop-prod", prod.Workload.UID)),
		}, ambiguous...)}
	c.Reports = []assessment.Object{prodReport, devReport}
	return c, dev, prod
}

// observation is ev's observation of e.
func observation(ev Evaluation, e Expected) Observation {
	for _, o := range ev.Observations {
		if o.Key == e.Key() {
			return o
		}
	}
	return Observation{}
}

func projected(t *testing.T, c CaptureV2, uid string) CaptureV2 {
	t.Helper()
	p, err := Project(c, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProjection(roundTrip(t, p)); err != nil {
		t.Fatalf("%s: %v", uid, err)
	}
	return p
}

// A mixed-namespace report is attributed per result: each namespace view
// gets exactly its own results, whichever namespace the report lives in.
func TestMixedNamespaceReportSplitsPerResult(t *testing.T) {
	c, dev, prod := crossCapture(t)
	for _, tc := range []struct {
		uid, ns, msg string
		want         Expected
		reports      int
	}{
		{"uid-shop-dev", "shop-dev", "dev workload fine", dev, 1},
		{"uid-shop-prod", "shop-prod", sibling + " privileged container in shop-prod", prod, 2},
	} {
		p := projected(t, c, tc.uid)
		if len(p.Reports) != tc.reports || p.Projection.Extracts != tc.reports {
			t.Fatalf("%s: %d extracts in %d reports, want %d", tc.ns, p.Projection.Extracts, len(p.Reports), tc.reports)
		}
		for _, r := range p.Reports {
			results := r["results"].([]any)
			if len(results) != 1 {
				t.Fatalf("%s: %v", tc.ns, results)
			}
			x := assessment.Map(results[0])
			for _, ref := range x["resources"].([]any) {
				if m := assessment.Map(ref); m["namespace"] != tc.ns || m["uid"] != tc.want.Workload.UID {
					t.Fatalf("%s: extract names %v", tc.ns, m)
				}
			}
		}
		ev := evaluate(t, p, nil, maxAge)
		if err := ValidateProjectedEvaluation(p, ev); err != nil {
			t.Fatal(err)
		}
		if o := observation(ev, tc.want); o.State != Attributable || o.Report != assessment.Str(assessment.At(p.Reports[0], "metadata", "uid")) && tc.ns == "shop-dev" {
			t.Fatalf("%s: %+v %+v", tc.ns, ev.Evidence, ev.Observations)
		}
	}
	// shop-dev's own result in shop-prod's report reaches shop-dev only
	// through a sealed reference: nothing of the report is disclosed.
	p := projected(t, c, "uid-shop-dev")
	b, _ := json.Marshal(p)
	for _, leak := range []string{sibling, "shop-prod", "uid-shop-prod", "pod-prod", "prod-report", assessment.Digest(c.Reports[0])} {
		if strings.Contains(string(b), leak) {
			t.Errorf("shop-dev's projection contains %q", leak)
		}
	}
	src := assessment.Map(assessment.Map(p.Reports[0]["results"].([]any)[0])[SourceField])
	if len(src) != 2 || src["report"] != sealedSource("prod-report", "uid-shop-dev") || src["report"] != assessment.At(p.Reports[0], "metadata", "uid") {
		t.Fatalf("sealed provenance %v", src)
	}
	if sealedSource("prod-report", "uid-shop-dev") == sealedSource("prod-report", "uid-shop-prod") {
		t.Fatal("a sealed reference links namespaces")
	}
	// The report shop-prod owns keeps its full provenance there.
	q := projected(t, c, "uid-shop-prod")
	for _, r := range q.Reports {
		src := assessment.Map(assessment.Map(r["results"].([]any)[0])[SourceField])
		switch assessment.Str(assessment.At(r, "metadata", "uid")) {
		case "prod-report":
			if src["report"] != "prod-report" || src["reportSha256"] != assessment.Digest(c.Reports[0]) || src["resultIndex"] != 0 {
				t.Fatalf("own provenance %v", src)
			}
		case sealedSource("dev-report", "uid-shop-prod"):
			if len(src) != 2 {
				t.Fatalf("sealed provenance %v", src)
			}
		default:
			t.Fatalf("unexpected extract %v", r["metadata"])
		}
	}
}

// A result whose attribution the frozen identities cannot resolve is
// disclosed in no namespace view, and nothing about it is recorded there.
func TestAmbiguousResultsAppearInNoNamespaceView(t *testing.T) {
	c, _, _ := crossCapture(t)
	for _, uid := range []string{"uid-shop-dev", "uid-shop-prod"} {
		p := projected(t, c, uid)
		b, _ := json.Marshal(p)
		for _, leak := range []string{"disagree", "unfrozen", "renamed", "no namespace", "pod-dev-unfrozen"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s: an ambiguous result is disclosed (%q)", uid, leak)
			}
		}
	}
	// Each one alone is withheld from both views.
	for i := 2; i < 6; i++ {
		x := c
		r := assessment.Object{}
		for k, v := range c.Reports[0] {
			r[k] = v
		}
		r["results"] = []any{c.Reports[0]["results"].([]any)[i]}
		x.Reports = []assessment.Object{r}
		for _, uid := range []string{"uid-shop-dev", "uid-shop-prod"} {
			if p := projected(t, x, uid); len(p.Reports) != 0 || p.Projection.Extracts != 0 {
				t.Errorf("ambiguous result %d is disclosed in %s: %v", i, uid, p.Reports)
			}
		}
	}
}

// The serialized projection counts and names nothing of sibling reports,
// however many there are and whatever their results.
func TestSerializedProjectionHasNoSiblingCounts(t *testing.T) {
	c, _, _ := crossCapture(t)
	c2 := c
	c2.Reports = append(append([]assessment.Object{}, c.Reports...),
		report("sibling-only", "shop-prod", "pod-prod", result("p", 0, "pod-prod", "fail", c.Window.Started.Add(time.Minute))))
	a, b := projected(t, c, "uid-shop-dev"), projected(t, c2, "uid-shop-dev")
	ja, _ := json.Marshal(a.Projection)
	jb, _ := json.Marshal(b.Projection)
	if string(ja) != string(jb) {
		t.Fatalf("a sibling report changes the projection: %s vs %s", ja, jb)
	}
	var m map[string]any
	if err := json.Unmarshal(ja, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sourceReports", "withheld", "withheldTotal"} {
		if _, ok := m[k]; ok {
			t.Errorf("the projection records %s: %s", k, ja)
		}
	}
	if len(m) != 3 || m["extracts"] != float64(1) {
		t.Fatalf("projection %s", ja)
	}
}

// No extract copies its source report: provenance is a reference or a
// digest, and a whole source report in an extract is refused.
func TestProvenanceDoesNotEmbedTheReport(t *testing.T) {
	c, _, _ := crossCapture(t)
	for _, uid := range []string{"uid-shop-dev", "uid-shop-prod"} {
		p := projected(t, c, uid)
		for _, r := range p.Reports {
			for _, f := range []string{"summary", "scope"} {
				if _, ok := r[f]; ok {
					t.Errorf("%s: extract keeps %s", uid, f)
				}
			}
			if m := assessment.Map(r["metadata"]); len(m) != 2 {
				t.Errorf("%s: extract metadata %v", uid, m)
			}
			for _, x := range r["results"].([]any) {
				for k, v := range assessment.Map(assessment.Map(x)[SourceField]) {
					if _, ok := v.(string); !ok && k != "resultIndex" {
						t.Errorf("%s: provenance %s embeds %T", uid, k, v)
					}
				}
			}
		}
		// The report copied whole into the extract is refused.
		bad := roundTrip(t, p)
		var whole map[string]any
		raw, _ := json.Marshal(c.Reports[0])
		_ = json.Unmarshal(raw, &whole)
		bad.Reports = []assessment.Object{whole}
		err := ValidateProjection(bad)
		if err == nil {
			t.Fatalf("%s: a whole source report passed", uid)
		}
		noLeak(t, "the refusal", err.Error())
	}
}

// A namespace diagnostic is the stable reason's fixed text: hostile content
// failure messages never reach diagnostic.json or the descriptor.
func TestNamespaceDiagnosticIsSanitized(t *testing.T) {
	hostile := "subject shop-prod-only references org-bundle@sha256:" + strings.Repeat("a", 64) +
		", which the run did not freeze; uid-shop-prod pod-prod " + sibling + "\n\x1b[31mGET https://u:" + credential + "@registry.example/v2/: 500‮"
	for _, reason := range []string{ReasonContentUnavailable, ReasonContentLost, ReasonContentIncompatible, ReasonContentMismatch, "Injected " + sibling} {
		dir, d := NamespaceDiagnosticPackage(t, &ContentFailure{Reason: reason, Message: hostile})
		want := reason
		if strings.HasPrefix(reason, "Injected") {
			want = ReasonExportFailed
		}
		var file publication.Diagnostic
		if err := assessment.Read(filepath.Join(dir, "diagnostic.json"), &file); err != nil {
			t.Fatal(err)
		}
		for what, got := range map[string]*publication.Diagnostic{"descriptor": d.Diagnostic, "diagnostic.json": &file} {
			if got.Reason != want || got.Message != namespaceDiagnostics[want] {
				t.Errorf("%s %s: %+v", reason, what, got)
			}
			if err := ValidateNamespaceDiagnostic(got); err != nil {
				t.Errorf("%s %s: %v", reason, what, err)
			}
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "diagnostic.json"))
		desc, _ := os.ReadFile(filepath.Join(dir, publication.DescriptorFile))
		for _, s := range []string{string(raw), string(desc)} {
			for _, leak := range append(leaks, "org-bundle", "registry.example", credential, "\\u001b", "\\u202e") {
				if strings.Contains(s, leak) {
					t.Errorf("%s: the package contains %q", reason, leak)
				}
			}
		}
	}
	// A binding package keeps the operator detail.
	c, _ := mixedCapture(t)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	req.Content = &RunContent{Failure: &ContentFailure{Reason: ReasonContentLost, Message: "detail for operators"}}
	d, err := Export(context.Background(), req)
	if err != nil || d.Diagnostic == nil || !strings.Contains(d.Diagnostic.Message, "detail for operators") {
		t.Fatalf("%v %+v", err, d.Diagnostic)
	}
	for name, bad := range map[string]publication.Diagnostic{
		"raw message":    {Reason: ReasonContentLost, MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: hostile},
		"unknown reason": {Reason: sibling, MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: namespaceDiagnostics[ReasonExportFailed]},
		"other text":     {Reason: ReasonContentLost, MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: namespaceDiagnostics[ReasonExportFailed]},
	} {
		err := ValidateNamespaceDiagnostic(&bad)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		noLeak(t, "the refusal", err.Error())
	}
}
