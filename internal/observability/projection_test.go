package observability

import (
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	// Controllers link the upstream Go and process collectors.
	_ "sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func descriptor(t *testing.T, fixture string) publication.Descriptor {
	t.Helper()
	d, err := publication.LoadDescriptor(filepath.Join(repoRoot, "testdata/publication", fixture))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// counts projects s and returns its status and non-nil counts.
func project(s Summary) (AssessmentStatus, map[string]int, *bool) {
	p := projectSummary(s)
	return p.status, p.counts, p.complete
}

// Every display state the owner's normalized summary can express maps to
// exactly one label, and known counts sum to the expected inventory.
func TestSummaryDisplayStates(t *testing.T) {
	mixed := Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 13, Attributable: 7, Missing: 3, Rejected: 2, Unresolved: 1},
		Outcomes: publication.OutcomeCounts{Pass: 1, Fail: 1, Error: 1, Skip: 1, AcceptedRisk: 1, NotApplicable: 1, Unknown: 1},
	}
	status, counts, complete := project(mixed)
	if status != AssessmentKnown || complete == nil || *complete {
		t.Fatalf("mixed incomplete summary: %s complete=%v", status, complete)
	}
	sum := 0
	for _, s := range CheckStates {
		n, ok := counts[s]
		if !ok {
			t.Errorf("state %s missing", s)
		}
		if n != 1 && s != "missing" && s != "rejected" {
			t.Errorf("state %s = %d, want 1", s, n)
		}
		sum += n
	}
	if len(counts) != len(CheckStates) || sum != mixed.Evidence.Expected {
		t.Errorf("states %v do not partition the %d expected checks", counts, mixed.Evidence.Expected)
	}
	if counts["missing"] != 3 || counts["rejected"] != 2 {
		t.Errorf("evidence gaps = %v", counts)
	}

	// Accepted risk and non-applicability are never passes.
	_, counts, _ = project(Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 2, Attributable: 2},
		Outcomes: publication.OutcomeCounts{AcceptedRisk: 1, NotApplicable: 1},
	})
	if counts["pass"] != 0 || counts["accepted_risk"] != 1 || counts["out_of_scope"] != 1 {
		t.Errorf("accepted risk / out of scope = %v", counts)
	}

	cases := []struct {
		name string
		s    Summary
		want AssessmentStatus
	}{
		{"complete", completeSummary(2, 0), AssessmentKnown},
		{"zero targets", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.NoTargets}}, AssessmentNoTargets},
		{"lost inventory", Summary{InventoryUnknown: true, Evidence: completeSummary(1, 0).Evidence, Outcomes: completeSummary(1, 0).Outcomes}, AssessmentUnknown},
		{"stale scope", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 1, Attributable: 1, StaleScopes: 1}, Outcomes: publication.OutcomeCounts{Pass: 1}}, AssessmentUnknown},
		{"stale scope without known checks", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, StaleScopes: 1}}, AssessmentUnknown},
		{"evidence does not add up", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 3, Attributable: 1}, Outcomes: publication.OutcomeCounts{Pass: 1}}, AssessmentUnknown},
		{"outcomes do not add up", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 2, Attributable: 2}, Outcomes: publication.OutcomeCounts{Pass: 1}}, AssessmentUnknown},
		{"complete claims with gaps", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 2, Attributable: 1, Missing: 1}, Outcomes: publication.OutcomeCounts{Pass: 1}}, AssessmentUnknown},
		{"negative outcome", Summary{Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: 1, Attributable: 1}, Outcomes: publication.OutcomeCounts{Pass: 2, Fail: -1}}, AssessmentUnknown},
		{"unrecognized completeness", Summary{Evidence: publication.EvidenceSummary{Completeness: "Partial", Expected: 1, Attributable: 1}, Outcomes: publication.OutcomeCounts{Pass: 1}}, AssessmentUnknown},
	}
	for _, c := range cases {
		status, counts, complete := project(c.s)
		if status != c.want {
			t.Errorf("%s: %s, want %s", c.name, status, c.want)
		}
		switch status {
		case AssessmentUnknown:
			if counts != nil || complete != nil {
				t.Errorf("%s: unknown view exposes counts or completeness", c.name)
			}
		case AssessmentNoTargets:
			if complete != nil {
				t.Errorf("%s: no-target scope asserts completeness", c.name)
			}
			for s, n := range counts {
				if n != 0 {
					t.Errorf("%s: %s = %d", c.name, s, n)
				}
			}
		}
	}

	if p := projectClosed(nil); p.status != AssessmentNone || p.counts != nil {
		t.Errorf("no closed run: %+v", p)
	}
	if p := projectCurrent(nil, t0); p.status != AssessmentUnknown || p.counts != nil {
		t.Errorf("no current evidence: %+v", p)
	}
}

// The owner's frozen full-binding package fixtures project to the latest
// closed view; namespace packages never do.
func TestOwnerPackageFixtures(t *testing.T) {
	diag, ok := ClosedFromDescriptor(descriptor(t, "binding-diagnostic"))
	if !ok {
		t.Fatal("diagnostic binding package is not a closed run")
	}
	status, counts, complete := project(diag.Summary)
	if status != AssessmentKnown || *complete || counts["pass"] != 1 || counts["fail"] != 1 || counts["unresolved"] != 2 {
		t.Errorf("diagnostic with a known inventory: %s %v complete=%v", status, counts, *complete)
	}
	if !diag.Closed.Equal(time.Date(2026, 11, 5, 10, 4, 30, 0, time.UTC)) || !diag.CollectionStarted.Equal(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("window = %s..%s", diag.CollectionStarted, diag.Closed)
	}
	empty, _ := ClosedFromDescriptor(descriptor(t, "binding-no-targets"))
	if status, _, _ := project(empty.Summary); status != AssessmentNoTargets {
		t.Errorf("no-target package: %s", status)
	}
	for _, ns := range []string{"namespace-complete", "namespace-incomplete"} {
		if _, ok := ClosedFromDescriptor(descriptor(t, ns)); ok {
			t.Errorf("%s replaced the full-binding view", ns)
		}
	}
}

func run(name, uid string, scope v1alpha1.RunScope, started, closed time.Time, s *v1alpha1.AssessmentSummary) v1alpha1.AssessmentRun {
	r := v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.AssessmentRunSpec{Scope: scope}}
	r.Status.Binding = &v1alpha1.ResolvedBinding{Name: "alpha", UID: uid}
	r.Status.Window = &v1alpha1.CaptureWindow{Started: metav1.NewTime(started)}
	if !closed.IsZero() {
		r.Status.Window.Closed = ptr(metav1.NewTime(closed))
	}
	r.Status.Summary = s
	return r
}

func statusSummary(c v1alpha1.EvidenceCompleteness, pass, missing int32, export v1alpha1.ExportState) *v1alpha1.AssessmentSummary {
	return &v1alpha1.AssessmentSummary{Export: export,
		Evidence: v1alpha1.EvidenceSummary{Completeness: c, Expected: pass + missing, Attributable: pass, Missing: missing},
		Outcomes: v1alpha1.OutcomeCounts{Pass: pass}}
}

// The latest closure of the binding's own full-binding runs wins, even when
// it is incomplete or diagnostic; namespace requests, open runs and runs of
// an earlier object with the same name do not.
func TestLatestClosedSelection(t *testing.T) {
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	good := run("good", "uid-1", v1alpha1.RunScopeBinding, at(0), at(5), statusSummary(v1alpha1.EvidenceCompleteness(publication.Complete), 4, 0, "Assessment"))
	incomplete := run("incomplete", "uid-1", v1alpha1.RunScopeBinding, at(60), at(66), statusSummary(v1alpha1.EvidenceCompleteness(publication.Incomplete), 1, 3, "Diagnostic"))
	request := run("request", "uid-1", v1alpha1.RunScopeNamespace, at(70), at(71), statusSummary(v1alpha1.EvidenceCompleteness(publication.Complete), 9, 0, "Assessment"))
	open := run("open", "uid-1", v1alpha1.RunScopeBinding, at(80), time.Time{}, nil)
	former := run("former", "uid-0", v1alpha1.RunScopeBinding, at(90), at(95), statusSummary(v1alpha1.EvidenceCompleteness(publication.Complete), 9, 0, "Assessment"))

	got := LatestClosed("uid-1", []v1alpha1.AssessmentRun{good, incomplete, request, open, former})
	if got == nil || !got.Closed.Equal(at(66)) || !got.CollectionStarted.Equal(at(60)) {
		t.Fatalf("latest closed = %+v, want the incomplete run", got)
	}
	if status, counts, complete := project(got.Summary); status != AssessmentKnown || *complete || counts["missing"] != 3 {
		t.Errorf("incomplete latest run: %s %v", status, counts)
	}
	if LatestClosed("uid-2", []v1alpha1.AssessmentRun{good, request}) != nil {
		t.Error("another binding's runs selected")
	}
	if LatestClosed("uid-1", []v1alpha1.AssessmentRun{request, open}) != nil {
		t.Error("a namespace request or open run counts as a closed full-binding run")
	}

	// A lost capture closes without a trustworthy inventory: unknown, with
	// its actual closure, never zero checks.
	lost := run("lost", "uid-1", v1alpha1.RunScopeBinding, at(100), at(101), &v1alpha1.AssessmentSummary{Export: "CaptureLost", Evidence: v1alpha1.EvidenceSummary{Completeness: "Incomplete"}})
	got = LatestClosed("uid-1", []v1alpha1.AssessmentRun{good, incomplete, lost})
	if got == nil || !got.Closed.Equal(at(101)) || projectClosed(got).status != AssessmentUnknown || projectClosed(got).counts != nil {
		t.Errorf("capture-lost latest run = %+v", got)
	}
	failed := run("failed", "uid-1", v1alpha1.RunScopeBinding, at(110), at(111), nil)
	if got = LatestClosed("uid-1", []v1alpha1.AssessmentRun{good, failed}); projectClosed(got).status != AssessmentUnknown {
		t.Error("a closed run without a summary is not unknown")
	}

	// Equal closures are ordered deterministically.
	a := run("a", "uid-1", v1alpha1.RunScopeBinding, at(0), at(5), statusSummary("Complete", 1, 0, "Assessment"))
	b := run("b", "uid-1", v1alpha1.RunScopeBinding, at(0), at(5), statusSummary("Complete", 2, 0, "Assessment"))
	x, y := LatestClosed("uid-1", []v1alpha1.AssessmentRun{a, b}), LatestClosed("uid-1", []v1alpha1.AssessmentRun{b, a})
	if x.Outcomes != y.Outcomes || x.Outcomes.Pass != 2 {
		t.Error("tie-break depends on input order")
	}
}

// Current status adapts without its free text, and expiry comes from the
// owner's next expiry.
func TestCurrentFromStatus(t *testing.T) {
	if CurrentFromStatus(nil) != nil {
		t.Fatal("absent current evidence must stay absent")
	}
	exp := metav1.NewTime(t0.Add(time.Hour))
	c := CurrentFromStatus(&v1alpha1.CurrentEvidence{
		Evidence:    v1alpha1.EvidenceSummary{Completeness: "Incomplete", Expected: 3, Attributable: 2, Rejected: 1},
		Outcomes:    v1alpha1.OutcomeCounts{Pass: 1, AcceptedRisk: 1},
		EvaluatedAt: metav1.NewTime(t0), NextExpiry: &exp,
		Limitations: []string{"1 of 3 expected observations lack attributable evidence"},
	})
	if c.ValidUntil == nil || !c.ValidUntil.Equal(exp.Time) || c.OldestEvaluated != nil {
		t.Errorf("validity/oldest = %v %v", c.ValidUntil, c.OldestEvaluated)
	}
	p := projectCurrent(c, t0)
	if p.status != AssessmentKnown || p.counts["rejected"] != 1 || p.counts["accepted_risk"] != 1 || p.counts["pass"] != 1 {
		t.Errorf("current projection = %+v", p)
	}
	if projectCurrent(c, exp.Time).status != AssessmentUnknown {
		t.Error("current evidence is still known at its expiry")
	}
}

// Equivalent summaries attributed to different OSCAL catalogs and mappings
// expose the same metrics; framework attribution never reaches the
// contract. This does not claim runtime support for another framework.
func TestFrameworkNeutralProjection(t *testing.T) {
	expose := func(d publication.Descriptor) string {
		h, _ := newHub(t, DomainAssessment)
		term := h.Acquire()
		closed, ok := ClosedFromDescriptor(d)
		if !ok {
			t.Fatal("not a closed full-binding package")
		}
		mustOK(t, h.PublishAssessment(term, t0, AssessmentSnapshot{Bindings: []BindingAssessment{{Binding: alpha, LatestClosed: closed}}}))
		return exposition(t, h)
	}
	for _, fixture := range []string{"binding-diagnostic", "binding-no-targets"} {
		nist := descriptor(t, fixture)
		other := nist
		// Another catalog's mapping and producer attribution.
		other.Revisions.MappingSHA256 = strings.Repeat("cd", 32)
		other.Producer.Checks = []string{"scope-projection", "oscal-schema-1.1.3", "catalog:iso-27001-2022"}
		if err := other.Validate(); err != nil {
			t.Fatal(err)
		}
		a, b := expose(nist), expose(other)
		if a != b {
			t.Errorf("%s: exposition differs between catalogs:\n%s\n%s", fixture, a, b)
		}
		for _, leak := range []string{nist.Revisions.MappingSHA256, other.Revisions.MappingSHA256, "iso-27001", "oscal", nist.Run.RunUID, nist.Run.BindingUID} {
			if strings.Contains(strings.ToLower(a), strings.ToLower(leak)) {
				t.Errorf("%s: exposition contains %q", fixture, leak)
			}
		}
	}

	// The projection's inputs cannot carry framework or identity content.
	banned := regexp.MustCompile(`(?i)catalog|control|framework|profile|mapping|policy|digest|sha|reason|message|limitation|namespace|workload|key|url|secret|credential`)
	for _, typ := range []any{TargetingSnapshot{}, AssessmentSnapshot{}, StorageSnapshot{}, BindingTargeting{}, BindingAssessment{}, CurrentView{}, ClosedRun{}, Summary{}, BindingRef{}} {
		walkFields(reflect.TypeOf(typ), func(path string) {
			if banned.MatchString(path) && path != "TargetNamespaces" {
				t.Errorf("%T has field %s", typ, path)
			}
		})
	}
}

func walkFields(t reflect.Type, visit func(string)) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t.PkgPath() == "time" {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.Anonymous {
			visit(f.Name)
		}
		walkFields(f.Type, visit)
	}
}

// Series grow with configured bindings and fixed enums, not with workloads,
// policy revisions or retained runs.
func TestSeriesBoundedAsWorkloadsAndHistoryGrow(t *testing.T) {
	count := func(scale int) int {
		h, _ := newHub(t, Domains...)
		term := h.Acquire()
		refs := []BindingRef{alpha, beta, {Name: "gamma", UID: "uid-gamma"}}
		as := assessmentOf(refs...)
		for i := range as.Bindings {
			var runs []v1alpha1.AssessmentRun
			for j := range scale {
				at := t0.Add(-time.Duration(scale-j) * time.Hour)
				runs = append(runs, run(fmt.Sprintf("r%d", j), refs[i].UID, v1alpha1.RunScopeBinding, at, at.Add(time.Minute),
					statusSummary("Incomplete", int32(10*scale), int32(scale), "Assessment")))
				runs = append(runs, run(fmt.Sprintf("n%d", j), refs[i].UID, v1alpha1.RunScopeNamespace, at, at.Add(time.Minute), statusSummary("Complete", 1, 0, "Assessment")))
			}
			as.Bindings[i].LatestClosed = LatestClosed(refs[i].UID, runs)
			as.Bindings[i].Current = &CurrentView{Summary: Summary{
				Evidence: publication.EvidenceSummary{Completeness: publication.Incomplete, Expected: 100 * scale, Attributable: 99 * scale, Missing: scale},
				Outcomes: publication.OutcomeCounts{Pass: 50 * scale, Fail: 40 * scale, AcceptedRisk: 9 * scale}}}
		}
		mustOK(t, h.PublishAssessment(term, t0, as))
		mustOK(t, h.PublishTargeting(term, t0, targetingOf(refs...)))
		mustOK(t, h.PublishStorage(term, t0, StorageSnapshot{PublicationPending: scale, CleanupPending: scale, OldestCleanupExpiry: &t0}))
		mustOK(t, h.PublishBundleResolution(term, t0))
		for range scale {
			h.ObserveOperation(OperationEvidencePublication, ResultSuccess, time.Second)
		}
		return len(scrape(t, h))
	}
	small, large := count(1), count(500)
	if small != large {
		t.Errorf("series grew from %d to %d with workloads and history", small, large)
	}
	// 3 bindings: per binding 1 created + 6 condition + 1 targets + 8 status
	// + 20 checks + 2 complete + 2 closure times + 4 schedule = 44. Global:
	// 12 domain availability + 6 capability + 5 storage + 12 operation.
	if want := 3*44 + 12 + 6 + 5 + 12; small != want {
		t.Errorf("series = %d, want %d", small, want)
	}
}

// Free text, identities and credential-like content in owner records never
// reach the exposition.
func TestNoFreeTextOrCredentialLeakage(t *testing.T) {
	secret := "AKIAEXAMPLESECRET"
	cur := CurrentFromStatus(&v1alpha1.CurrentEvidence{
		Evidence: v1alpha1.EvidenceSummary{Completeness: "Complete", Expected: 1, Attributable: 1}, Outcomes: v1alpha1.OutcomeCounts{Fail: 1},
		Limitations: []string{"s3 credential " + secret + " rejected for bucket evidence-prod"}})
	d := descriptor(t, "binding-diagnostic")
	d.Diagnostic.Message = "upload to s3://evidence-prod/" + secret + " failed"
	closed, _ := ClosedFromDescriptor(d)
	r := run("run-"+secret, "uid-1", v1alpha1.RunScopeBinding, t0, t0.Add(time.Minute), statusSummary("Complete", 1, 0, "Assessment"))
	r.Status.Conditions = []metav1.Condition{{Type: "Published", Message: secret}}
	fromRun := LatestClosed("uid-1", []v1alpha1.AssessmentRun{r})

	h, _ := newHub(t, Domains...)
	term := h.Acquire()
	mustOK(t, h.PublishAssessment(term, t0, AssessmentSnapshot{Bindings: []BindingAssessment{
		{Binding: alpha, Current: cur, LatestClosed: closed}, {Binding: beta, LatestClosed: fromRun}}}))
	out := exposition(t, h)
	for _, leak := range []string{secret, "evidence-prod", "s3://", "ExportFailed", d.Run.RunUID, "uid-1", "uid-alpha", "team-"} {
		if strings.Contains(out, leak) {
			t.Errorf("exposition contains %q", leak)
		}
	}
}

// Registering in controller-runtime's registry adds only the contract's
// families next to the retained upstream collectors.
func TestRegisterInControllerRuntimeRegistry(t *testing.T) {
	before, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	upstream := map[string]bool{}
	for _, f := range before {
		upstream[f.GetName()] = true
	}
	h, _ := newHub(t, Domains...)
	term := h.Acquire()
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	if err := ctrlmetrics.Registry.Register(h); err != nil {
		t.Fatal(err)
	}
	defer ctrlmetrics.Registry.Unregister(h)
	if err := ctrlmetrics.Registry.Register(h); err == nil {
		t.Error("registering the hub twice succeeded")
	}
	after, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range after {
		n := f.GetName()
		if seen[n] {
			t.Errorf("family %s exposed twice", n)
		}
		seen[n] = true
		if strings.HasPrefix(n, "konstapel_") == upstream[n] {
			t.Errorf("family %s: konstapel family shadows or replaces an upstream one", n)
		}
	}
	for _, retained := range []string{"go_goroutines", "go_memstats_alloc_bytes", "process_cpu_seconds_total"} {
		if !upstream[retained] || !seen[retained] {
			t.Errorf("upstream collector %s is not retained", retained)
		}
	}
	for _, m := range []string{"konstapel_observation_ready", "konstapel_binding_condition", "konstapel_operation_attempts_total"} {
		if !seen[m] {
			t.Errorf("%s not served", m)
		}
	}
}

// Attempt counters count each completed attempt and start from zero in a
// new process.
func TestOperationCountersArePerProcess(t *testing.T) {
	h, _ := newHub(t)
	h.ObserveOperation(OperationBundleResolution, ResultFailure, 3*time.Second)
	h.ObserveOperation(OperationBundleResolution, ResultFailure, 3*time.Second) // a retry is another attempt
	h.ObserveOperation(OperationBundleResolution, ResultSuccess, time.Second)
	got := scrape(t, h)
	if got[`konstapel_operation_attempts_total{operation="bundle_resolution",result="failure"}`] != 2 ||
		got[`konstapel_operation_attempts_total{operation="bundle_resolution",result="success"}`] != 1 ||
		got[`konstapel_operation_duration_seconds{operation="bundle_resolution",result="failure"}`] != 2 {
		t.Errorf("attempts = %v", withPrefix(got, "konstapel_operation_"))
	}
	restarted, _ := newHub(t)
	for k, v := range withPrefix(scrape(t, restarted), "konstapel_operation_") {
		if v != 0 {
			t.Errorf("%s = %v after restart", k, v)
		}
	}
	if n := len(withPrefix(scrape(t, restarted), "konstapel_operation_attempts_total")); n != len(operationValues)*len(resultValues) {
		t.Errorf("%d attempt series before any attempt", n)
	}
}
