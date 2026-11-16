package publication_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// coverageSummary is a summary at its bounds: the largest counts the
// status schema allows and the maximum number of blocking codes.
func coverageSummary() publication.CoverageSummary {
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	until := at.Add(2 * time.Hour)
	codes := []string{"ContentUnavailable", "DocumentInvalid", "DocumentUnavailable", "ImportCycle", "ImportUnresolved",
		"MappingSourceUnresolved", "SemanticsUnsupported", strings.Repeat("X", 64)}
	return publication.CoverageSummary{AsOf: at, SHA256: strings.Repeat("c", 64), InputsSHA256: strings.Repeat("d", 64),
		Bundle:            &publication.CoverageBundle{Name: "konstapel-linux-hardening", Digest: "sha256:" + strings.Repeat("e", 64)},
		InventoryResolved: true, MappingsResolved: true, Controls: 2147483647, Enhancements: 2147483647,
		Automation:        publication.AutomationCounts{None: 2147483647, Unselected: 1, Partial: 2, Unknown: 3},
		TechnicalEvidence: "resolved", ValidUntil: &until, Limitations: 2147483647, BlockingCodes: codes}
}

// The coverage summary's contract and status forms have the same fields
// and convert without loss.
func TestCoverageSummaryMatchesContractAndRoundTrips(t *testing.T) {
	a, b := map[string]bool{}, map[string]bool{}
	jsonFields(reflect.TypeOf(publication.CoverageSummary{}), "", a)
	jsonFields(reflect.TypeOf(v1alpha1.CoverageSummary{}), "", b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("publication.CoverageSummary and v1alpha1.CoverageSummary differ:\n%v\n%v", keys(a), keys(b))
	}
	unresolved := publication.CoverageSummary{AsOf: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), SHA256: strings.Repeat("0", 64),
		TechnicalEvidence: "unresolved", Limitations: 1, BlockingCodes: []string{"SelectionUnavailable"}}
	for _, s := range []publication.CoverageSummary{coverageSummary(), unresolved} {
		back := publication.CoverageFromAPI(publication.CoverageToAPI(&s))
		if !reflect.DeepEqual(*back, s) {
			t.Fatalf("conversion is lossy:\n%+v\n%+v", s, *back)
		}
	}
	if publication.CoverageToAPI(nil) != nil || publication.CoverageFromAPI(nil) != nil {
		t.Fatal("an absent summary converted to a present one")
	}
}

// A run summary with coverage has a fixed encoding (golden), and one
// without coverage encodes exactly as before the field existed.
func TestRunSummaryCoverageEncoding(t *testing.T) {
	sum := publication.Summarize(fixtures()["namespace-complete"], publication.Committed(receipt()))
	before, _ := json.Marshal(publication.SummaryToAPI(sum))
	if strings.Contains(string(before), "coverage") {
		t.Fatalf("absent coverage is encoded: %s", before)
	}
	c := coverageSummary()
	sum.Coverage = &c
	raw, err := json.Marshal(publication.SummaryToAPI(sum))
	if err != nil {
		t.Fatal(err)
	}
	goldenFile(t, "run-summary-coverage.json", raw)
	var o map[string]any
	_ = json.Unmarshal(raw, &o)
	delete(o, "coverage")
	again, _ := json.Marshal(o)
	var x, y any
	_ = json.Unmarshal(again, &x)
	_ = json.Unmarshal(before, &y)
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("coverage changed the rest of the summary:\n%s\n%s", again, before)
	}
}

// Status bounds: the bounded summary is accepted on runs, team requests
// and binding current status, and the schema refuses unbounded or
// malformed values.
func TestCoverageSummaryValidatesInCRDs(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	statusOf := func(kind string, cov *v1alpha1.CoverageSummary) map[string]any {
		var o any
		switch kind {
		case "AssessmentRun":
			r := v1alpha1.AssessmentRun{Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "b"}, Scope: v1alpha1.RunScopeBinding}}
			r.APIVersion, r.Kind, r.Name = v1alpha1.GroupVersion.String(), kind, "run"
			r.Status.Summary = &v1alpha1.AssessmentSummary{Evidence: v1alpha1.EvidenceSummary{Completeness: "Complete"}, Export: "Assessment", Coverage: cov}
			o = r
		case "AssessmentRequest":
			r := v1alpha1.AssessmentRequest{Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "b"}}}
			r.APIVersion, r.Kind, r.Name, r.Namespace = v1alpha1.GroupVersion.String(), kind, "q", "team-a"
			r.Status.Summary = &v1alpha1.AssessmentSummary{Evidence: v1alpha1.EvidenceSummary{Completeness: "Complete"}, Export: "Assessment", Coverage: cov}
			o = r
		case "ComplianceBinding":
			b := v1alpha1.ComplianceBinding{Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "p"}, Mode: v1alpha1.ModeAudit,
				NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "prod"}}}}
			b.APIVersion, b.Kind, b.Name = v1alpha1.GroupVersion.String(), kind, "b"
			b.Status.Assessment = &v1alpha1.BindingAssessmentStatus{Current: &v1alpha1.CurrentEvidence{
				Evidence: v1alpha1.EvidenceSummary{Completeness: "Complete"}, EvaluatedAt: metav1.NewTime(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)),
				Coverage: &v1alpha1.CurrentCoverage{State: v1alpha1.CoverageCurrent, Run: &v1alpha1.RunReference{Name: "run", UID: "uid"}, Summary: cov}}}
			o = b
		}
		raw, _ := json.Marshal(o)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	bounded := coverageSummary()
	for _, kind := range []string{"AssessmentRun", "AssessmentRequest", "ComplianceBinding"} {
		if errs := crds[kind].Validate(statusOf(kind, publication.CoverageToAPI(&bounded))); len(errs) > 0 {
			t.Fatalf("%s rejects a bounded summary: %v", kind, errs.ToAggregate())
		}
		for name, mutate := range map[string]func(*v1alpha1.CoverageSummary){
			"nine blocking codes": func(c *v1alpha1.CoverageSummary) { c.BlockingCodes = append(c.BlockingCodes, "Ninth") },
			"long code":           func(c *v1alpha1.CoverageSummary) { c.BlockingCodes[0] = strings.Repeat("X", 65) },
			"not a sha256":        func(c *v1alpha1.CoverageSummary) { c.SHA256 = "sha256:" + strings.Repeat("c", 64) },
			"negative count":      func(c *v1alpha1.CoverageSummary) { c.Automation.Partial = -1 },
			"unknown evidence":    func(c *v1alpha1.CoverageSummary) { c.TechnicalEvidence = "satisfied" },
		} {
			c := publication.CoverageToAPI(&bounded)
			mutate(c)
			if errs := crds[kind].Validate(statusOf(kind, c)); len(errs) == 0 {
				t.Errorf("%s accepts a summary with %s", kind, name)
			}
		}
	}
	m := statusOf("ComplianceBinding", publication.CoverageToAPI(&bounded))
	m["status"].(map[string]any)["assessment"].(map[string]any)["current"].(map[string]any)["coverage"].(map[string]any)["state"] = "Satisfied"
	if errs := crds["ComplianceBinding"].Validate(m); len(errs) == 0 {
		t.Error("a current coverage state outside the enum is accepted")
	}
}
