package coverage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Supporting-evidence consumer fixtures (add-control-coverage-reporting
// 4.1, 4.3), shared with add-supporting-evidence-attachments: its coverage
// integration must produce contexts these tests accept. Every fixture is
// for binding bind-a of the pinned Moderate catalog, observed before the
// fixtures' closure (evClosed).
const supportingDir = "testdata/supporting"

// supportingFixtures are the shared fixtures by name.
var supportingFixtures = []string{"disabled", "empty", "unavailable", "current", "expired", "future", "restricted"}

// Private metadata of the fixtures, which no namespace report may contain.
var privateMetadata = []string{
	"Datacenter physical access audit", "Example Audit GmbH", "Hall 3, cages", "application/pdf",
	"5b2e8f0a1c3d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7", "482113",
	"7a1c0e5d9b3f2a4c6e8d0b1f3a5c7e9d1b3f5a7c9e1d3b5f7a9c1e3d5b7f9a1c", SupportingCopyDir,
}

func supportingFixture(t *testing.T, name string) *SupportingEvidenceContext {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(supportingDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseSupportingContext(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// supportingInput is the hardening states fixture as bind-a's binding
// package.
func supportingInput(t *testing.T) Input {
	t.Helper()
	c, ev := statesFixture(t)
	return Input{Scope: Scope{Kind: "Binding", Cluster: evCluster, Binding: &ObjectRef{Name: "bind-a", UID: "bind-a"},
		Namespaces: []NamespaceRef{{Name: evNS, UID: evNSUID}}}, Content: c, Selection: allHardening(c), Options: opts(t), Evidence: ev,
		Packaging: &Packaging{ContentPath: "bundles/x", Evidence: goldenEvidence}}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// technical is everything of r that is not documentary: the inventory,
// mappings, technical evidence, every row without its supporting
// references, and the summary's automation and evidence state.
func technical(t *testing.T, r *Report) string {
	t.Helper()
	rows := slices.Clone(r.Controls)
	for i := range rows {
		rows[i].SupportingEvidence = nil
	}
	s := Summarize(r, "")
	return mustJSON(t, []any{r.AsOf, r.Scope, r.Inputs, r.Inventory, r.Mappings, r.TechnicalEvidence, rows, r.Sources,
		s.Automation, s.TechnicalEvidence, s.Controls, s.InventoryResolved, s.MappingsResolved})
}

// Hand-break guard (documents become technical evidence): no fixture, in
// any integration, temporal, content or access state, adds a check, an
// expected observation, an outcome, an automation state or an evidence
// view; the physical controls it supports stay without automated
// assessment.
func TestSupportingFixturesNeverChangeTechnicalEvidence(t *testing.T) {
	base := Build(supportingInput(t))
	want := technical(t, base)
	if row(t, base, "pe-3").Automation != AutomationNone || base.SupportingEvidence.Integration != IntegrationDisabled ||
		base.SupportingEvidence.ContextVersion != "" || len(base.SupportingEvidence.Entries) != 0 {
		t.Fatalf("baseline: %+v", base.SupportingEvidence)
	}
	for _, name := range supportingFixtures {
		t.Run(name, func(t *testing.T) {
			in := supportingInput(t)
			in.Supporting = supportingFixture(t, name)
			r := Build(in)
			if got := technical(t, r); got != want {
				t.Fatalf("the context changed the technical report")
			}
			for _, id := range []string{"pe-3", "pe-6"} {
				x := row(t, r, id)
				if x.Automation != AutomationNone || x.Evidence != nil || len(x.Checks) != 0 || len(x.StatementEvidence) != 0 {
					t.Errorf("%s: %+v", id, x)
				}
			}
			f, err := Render(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyFiles(f); err != nil {
				t.Fatal(err)
			}
			se := r.SupportingEvidence
			refs := func(id string) []SupportingRef { return row(t, r, id).SupportingEvidence }
			switch name {
			case "disabled", "empty":
				wantInt := map[string]string{"disabled": IntegrationDisabled, "empty": IntegrationAvailable}[name]
				if se.Integration != wantInt || len(se.Entries) != 0 || len(r.Limitations) != len(base.Limitations) {
					t.Errorf("%+v %v", se, r.Limitations)
				}
			case "unavailable":
				if se.Integration != IntegrationUnavailable || se.Reason != "RecordsUnavailable" || len(se.Entries) != 0 ||
					!hasBlocking(r.Limitations, CodeSupportingEvidenceUnavailable) {
					t.Errorf("%+v %v", se, r.Limitations)
				}
				if !bytes.Contains(f.Text, []byte("this is not an empty document list")) {
					t.Error("the text presents an unavailable context as an empty list")
				}
			case "current", "expired", "future", "restricted":
				temporal := map[string]string{"current": SupportingCurrent, "expired": SupportingExpired, "future": SupportingNotYetValid,
					"restricted": SupportingCurrent}[name]
				e := se.Entries[0]
				if se.Integration != IntegrationAvailable || e.Attribution != SupportingAttributed || e.Temporal != temporal {
					t.Fatalf("%+v", se)
				}
				p3, p6 := refs("pe-3"), refs("pe-6")
				if len(p3) != 1 || len(p6) != 1 || p3[0].Temporal != temporal || !slices.Equal(p3[0].Statements, []string{"pe-3_smt.a"}) ||
					len(p6[0].Statements) != 0 || p3[0].Access != e.Access {
					t.Errorf("rows: %+v %+v", p3, p6)
				}
				if name == "restricted" && (e.Document != nil || e.Access != AccessRestricted) {
					t.Errorf("restricted entry: %+v", e)
				}
				if name == "current" {
					// The datacenter document also supports bind-b: listed for
					// the platform, never attributed to bind-a's rows twice.
					if len(se.Entries) != 2 || se.Entries[1].BindingUID != "bind-b" || se.Entries[1].Attribution != SupportingOtherBinding ||
						!hasCode(r.Limitations, CodeSupportingNotAttributed) {
						t.Errorf("other binding: %+v", se.Entries)
					}
				}
			}
			// No rendering claims satisfaction or a verdict.
			for _, b := range [][]byte{f.JSON, f.Text} {
				lb := bytes.ToLower(b)
				if bytes.Contains(lb, []byte("satisfied\"")) || bytes.Contains(lb, []byte("verdict\"")) || bytes.Contains(b, []byte(`"full"`)) {
					t.Errorf("%s claims satisfaction", name)
				}
			}
		})
	}
}

func must(f Files, err error) Files {
	if err != nil {
		panic(err)
	}
	return f
}

func hasBlocking(ls []Limitation, code string) bool {
	return slices.ContainsFunc(ls, func(l Limitation) bool { return l.Code == code && l.Blocking })
}

// Hand-break guard (validity boundaries): the declared window is half
// open at the report's asOf, as the attachment owner computes it.
func TestSupportingTemporalBoundaries(t *testing.T) {
	for _, tc := range []struct {
		from, until time.Time
		want        string
	}{
		{evClosed, evClosed.Add(time.Hour), SupportingCurrent},
		{evClosed.Add(-time.Hour), evClosed, SupportingExpired},
		{evClosed.Add(time.Nanosecond), evClosed.Add(time.Hour), SupportingNotYetValid},
		{evClosed.Add(-time.Hour), evClosed.Add(time.Nanosecond), SupportingCurrent},
	} {
		ctx := clone(*supportingFixture(t, "current"))
		ctx.Entries = ctx.Entries[:1]
		ctx.Entries[0].ValidFrom, ctx.Entries[0].ValidUntil = tc.from, tc.until
		in := supportingInput(t)
		in.Supporting = &ctx
		r := Build(in)
		if got := r.SupportingEvidence.Entries[0].Temporal; got != tc.want || row(t, r, "pe-3").SupportingEvidence[0].Temporal != tc.want {
			t.Errorf("[%s, %s) at %s: %s, want %s", tc.from, tc.until, evClosed, got, tc.want)
		}
	}
}

// The contract is strict: unknown fields (an outcome, a verdict), trailing
// data and other versions fail to parse.
func TestParseSupportingContextIsStrict(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(supportingDir, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	edit := func(old, new string) []byte {
		if !bytes.Contains(raw, []byte(old)) {
			t.Fatalf("no %q", old)
		}
		return bytes.Replace(raw, []byte(old), []byte(new), 1)
	}
	for name, b := range map[string][]byte{
		"outcome":  edit(`"access": "notIncluded"`, `"access": "notIncluded", "outcome": "pass"`),
		"verdict":  edit(`"integration": "available"`, `"integration": "available", "verdict": "satisfied"`),
		"trailing": append(slices.Clone(raw), []byte("{}")...),
		"version":  edit(SupportingContextVersion, "konstapel.io/supporting-evidence-context/v2"),
	} {
		if _, err := ParseSupportingContext(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Hand-break guard (an invalid context is trusted): a context breaking the
// contract is reported unavailable with a blocking limitation, never as a
// partial or empty list, and its message never echoes a value.
func TestSupportingContextInvalidFailsClosed(t *testing.T) {
	cases := map[string]func(c *SupportingEvidenceContext){
		"version":             func(c *SupportingEvidenceContext) { c.Version = "v0" },
		"integration":         func(c *SupportingEvidenceContext) { c.Integration = "partial" },
		"disabled entries":    func(c *SupportingEvidenceContext) { c.Integration = IntegrationDisabled },
		"unavailable entries": func(c *SupportingEvidenceContext) { c.Integration, c.Reason = IntegrationUnavailable, "Down" },
		"free-text reason": func(c *SupportingEvidenceContext) {
			c.Integration, c.Reason, c.Entries = IntegrationUnavailable, "Datacenter physical access audit failed", nil
		},
		"reason when available": func(c *SupportingEvidenceContext) { c.Reason = "Down" },
		"source":                func(c *SupportingEvidenceContext) { c.Entries[0].Source = "Datacenter physical access audit" },
		"revision":              func(c *SupportingEvidenceContext) { c.Entries[0].Revision = "md5:x" },
		"catalog digest":        func(c *SupportingEvidenceContext) { c.Entries[0].CatalogDigest = "64ca6b" },
		"no controls":           func(c *SupportingEvidenceContext) { c.Entries[0].Controls = nil },
		"repeated control":      func(c *SupportingEvidenceContext) { c.Entries[0].Controls[1].ID = "pe-3" },
		"repeated statement": func(c *SupportingEvidenceContext) {
			c.Entries[0].Controls[0].Statements = []string{"pe-3_smt.a", "pe-3_smt.a"}
		},
		"association":      func(c *SupportingEvidenceContext) { c.Entries[0].Association = "approved" },
		"content":          func(c *SupportingEvidenceContext) { c.Entries[0].Content = "verified" },
		"content reason":   func(c *SupportingEvidenceContext) { c.Entries[0].ContentReason = "bucket gone" },
		"empty validity":   func(c *SupportingEvidenceContext) { c.Entries[0].ValidUntil = c.Entries[0].ValidFrom },
		"no observedAt":    func(c *SupportingEvidenceContext) { c.Entries[0].ObservedAt = time.Time{} },
		"observed later":   func(c *SupportingEvidenceContext) { c.Entries[0].ObservedAt = evClosed.Add(time.Second) },
		"access":           func(c *SupportingEvidenceContext) { c.Entries[0].Access = "public" },
		"included no copy": func(c *SupportingEvidenceContext) { c.Entries[0].Access = AccessIncluded },
		"copy not included": func(c *SupportingEvidenceContext) {
			c.Entries[0].Document.Copy = SupportingCopyDir + "audit.pdf"
		},
		"copy traversal": func(c *SupportingEvidenceContext) {
			c.Entries[0].Access, c.Entries[0].Document.Copy = AccessIncluded, SupportingCopyDir+"../capture.json"
		},
		"copy outside": func(c *SupportingEvidenceContext) {
			c.Entries[0].Access, c.Entries[0].Document.Copy = AccessIncluded, "capture.json"
		},
		"restricted with metadata": func(c *SupportingEvidenceContext) { c.Entries[0].Access = AccessRestricted },
		"document sha256":          func(c *SupportingEvidenceContext) { c.Entries[0].Document.SHA256 = "x" },
		"document title":           func(c *SupportingEvidenceContext) { c.Entries[0].Document.Title = "" },
		"duplicate source":         func(c *SupportingEvidenceContext) { c.Entries[1].BindingUID = "bind-a" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := clone(*supportingFixture(t, "current"))
			mutate(&ctx)
			in := supportingInput(t)
			in.Supporting = &ctx
			r := Build(in)
			se := r.SupportingEvidence
			if se.Integration != IntegrationUnavailable || se.Reason != "ContextInvalid" || len(se.Entries) != 0 ||
				!hasBlocking(r.Limitations, CodeSupportingContextInvalid) {
				t.Fatalf("accepted: %+v", se)
			}
			for _, c := range r.Controls {
				if len(c.SupportingEvidence) > 0 {
					t.Fatalf("%s references %v", c.ID, c.SupportingEvidence)
				}
			}
			f := must(Render(r))
			for _, p := range []string{"Datacenter", "bucket gone", "md5:x"} {
				if bytes.Contains(f.JSON, []byte(p)) || bytes.Contains(f.Text, []byte(p)) {
					t.Errorf("the diagnostic echoes %q", p)
				}
			}
		})
	}
}

// Hand-break guard (identifier from another catalog or outside the
// baseline is attributed): only exact catalog-qualified controls of the
// selected baseline, with their own statements, get references.
func TestSupportingAttribution(t *testing.T) {
	cases := map[string]struct {
		mutate func(c *SupportingEvidenceContext)
		want   string
	}{
		"other catalog": {func(c *SupportingEvidenceContext) {
			c.Entries[0].CatalogDigest = "sha256:" + strings.Repeat("0", 64)
		}, SupportingOtherCatalog},
		"control not selected": {func(c *SupportingEvidenceContext) { c.Entries[0].Controls[1].ID = "pe-7" }, SupportingNotInBaseline},
		"statement of another control": {func(c *SupportingEvidenceContext) {
			c.Entries[0].Controls[0].Statements = []string{"pe-6_smt.a"}
		}, SupportingNotInBaseline},
		"other binding": {func(c *SupportingEvidenceContext) { c.Entries[0].BindingUID = "bind-c" }, SupportingOtherBinding},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := clone(*supportingFixture(t, "current"))
			ctx.Entries = ctx.Entries[:1]
			tc.mutate(&ctx)
			in := supportingInput(t)
			in.Supporting = &ctx
			r := Build(in)
			if len(r.SupportingEvidence.Entries) != 1 || r.SupportingEvidence.Entries[0].Attribution != tc.want ||
				!hasCode(r.Limitations, CodeSupportingNotAttributed) {
				t.Fatalf("%+v", r.SupportingEvidence)
			}
			for _, c := range r.Controls {
				if len(c.SupportingEvidence) > 0 {
					t.Errorf("%s references %v", c.ID, c.SupportingEvidence)
				}
			}
		})
	}
	// Without an inventory nothing is attributed.
	in := supportingInput(t)
	in.Supporting = supportingFixture(t, "current")
	r := Unavailable(in, CodeContentUnavailable, "", "no content")
	if len(r.SupportingEvidence.Entries) != 2 || r.SupportingEvidence.Entries[0].Attribution != SupportingUnresolved {
		t.Fatalf("%+v", r.SupportingEvidence)
	}
}

// An included copy is a package source the verifier checks; a namespace
// projection never names it.
func TestSupportingCopyIsASource(t *testing.T) {
	ctx := clone(*supportingFixture(t, "current"))
	ctx.Entries[0].Access, ctx.Entries[0].Document.Copy = AccessIncluded, SupportingCopyDir+"0f1e2d3c/audit.pdf"
	in := supportingInput(t)
	in.Supporting = &ctx
	r := Build(in)
	if !slices.Contains(r.Sources, Source{Path: SupportingCopyDir + "0f1e2d3c/audit.pdf", Kind: SourceSupportingDocument, SHA256: ctx.Entries[0].Document.SHA256}) {
		t.Fatalf("sources %+v", r.Sources)
	}
	ns := namespaceInput(t)
	ns.Supporting = &ctx
	for _, s := range Build(ns).Sources {
		if s.Kind == SourceSupportingDocument {
			t.Fatalf("namespace report names copy %s", s.Path)
		}
	}
}

// Namespace projection fixtures: binding bind-a selects team-a and team-b;
// team-a's package is projected by the owner (collector.Project) and
// evaluated as the controller does.
const (
	sibNS    = "team-b"
	sibNSUID = "ns-uid-b"
)

// sibling are the strings of team-b that no team-a report may contain.
var sibling = []string{sibNS, sibNSUID, "uid-q1", "uid-q2", "state-q1", "report-q1"}

// twoNamespaces is bind-a's binding-wide capture over both namespaces.
func twoNamespaces(t *testing.T) (Content, collector.CaptureV2) {
	t.Helper()
	c := official(t, hardening)
	esc := contrib{binding: "bind-a", revision: "r1", policy: pEsc, bundle: c.Bundle}
	cp := capture(t, nil)
	a := esc.subject()
	b := a
	b.Namespace, b.NamespaceUID = sibNS, types.UID(sibNSUID)
	cp.Subjects = []targeting.EvidenceSubject{a, b}
	cp.Checks = []collector.Check{{EnginePolicy: esc.enginePolicy(), Index: 0, SHA256: "check-" + esc.enginePolicy() + "-0"}}
	q := func(name string) collector.Workload {
		return collector.Workload{Resource: "/v1/pods", Namespace: sibNS, NamespaceUID: sibNSUID, Name: name, UID: "uid-" + name, StateSHA256: "state-" + name}
	}
	cp.Workloads = []collector.Workload{pod("p1"), q("q1"), q("q2")}
	var err error
	if cp.Expected, err = collector.BuildInventory(cp.Subjects, cp.Checks, cp.Workloads, cp.MappingSHA256); err != nil {
		t.Fatal(err)
	}
	at := evStarted.Add(time.Minute)
	for _, w := range cp.Workloads {
		r := result(esc.enginePolicy(), 0, w, "fail", at)
		r["metadata"].(assessment.Object)["namespace"] = w.Namespace
		r["metadata"].(assessment.Object)["uid"] = "report-" + w.Name
		r["scope"].(assessment.Object)["namespace"] = w.Namespace
		cp.Reports = append(cp.Reports, r)
	}
	if err := cp.Validate(); err != nil {
		t.Fatal(err)
	}
	return c, cp
}

func namespaceScope() Scope {
	return Scope{Kind: "Namespace", Cluster: evCluster, Binding: &ObjectRef{Name: "bind-a", UID: "bind-a"},
		Namespaces: []NamespaceRef{{Name: evNS, UID: evNSUID}}}
}

// namespaceInput is team-a's namespace package input, projected and
// evaluated by the owner, with the platform's full supporting context.
func namespaceInput(t *testing.T) Input {
	t.Helper()
	c, full := twoNamespaces(t)
	proj, err := collector.Project(full, evNSUID)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Scope: namespaceScope(), Content: c, Selection: selecting(c, pEsc), Options: opts(t), Evidence: evaluated(t, proj, evMaxAge),
		Packaging: &Packaging{ContentPath: "bundles/x", Evidence: goldenEvidence}, Supporting: supportingFixture(t, "current")}
}

// leaks fails when a rendering of r contains a sibling or private string.
func leaks(t *testing.T, r *Report) {
	t.Helper()
	f := must(Render(r))
	for _, s := range append(slices.Clone(sibling), privateMetadata...) {
		if bytes.Contains(f.JSON, []byte(s)) || bytes.Contains(f.Text, []byte(s)) {
			t.Errorf("the namespace report contains %q", s)
		}
	}
	if err := VerifyFiles(f); err != nil {
		t.Fatal(err)
	}
}

// A team's namespace report keeps the whole public baseline, its own
// findings exactly as the owner evaluated them, and sanitized supporting
// context only: no sibling evidence, private metadata, digest or copy.
func TestNamespaceReportIsProjected(t *testing.T) {
	in := namespaceInput(t)
	r := Build(in)
	leaks(t, r)
	te := r.TechnicalEvidence
	if te.State != EvidenceResolved || *te.Evidence != in.Evidence.Evaluation.Evidence || te.Evidence.Expected != 1 || te.Outcomes.Fail != 1 {
		t.Fatalf("technical evidence %+v %+v", te.Evidence, te.Outcomes)
	}
	if r.Inventory.Controls != moderateCount || len(r.Controls) != moderateCount {
		t.Fatalf("inventory %d rows %d", r.Inventory.Controls, len(r.Controls))
	}
	se := r.SupportingEvidence
	if se.Projection != ProjectionNamespace || len(se.Entries) != 1 || se.Entries[0].BindingUID != "bind-a" ||
		se.Entries[0].Access != AccessRestricted || se.Entries[0].Document != nil || se.Entries[0].Revision != "" ||
		se.Entries[0].Temporal != SupportingCurrent || se.Entries[0].Attribution != SupportingAttributed {
		t.Fatalf("supporting %+v", se)
	}
	if refs := row(t, r, "pe-3").SupportingEvidence; len(refs) != 1 || refs[0].Access != AccessRestricted {
		t.Fatalf("pe-3 refs %+v", refs)
	}
	// The same input as the platform's binding view shows the metadata:
	// the projection, not the fixture, removes it.
	in.Scope.Kind = "Binding"
	if f := must(Render(Build(in))); !bytes.Contains(f.JSON, []byte(privateMetadata[0])) {
		t.Fatal("the platform view lost the document metadata")
	}
}

// Hand-break guards (leaks through error paths): whatever is wrong with a
// namespace report's inputs, its renderings and diagnostics never contain
// sibling evidence or private document metadata.
func TestNamespaceProjectionErrorPathsDoNotLeak(t *testing.T) {
	_, full := twoNamespaces(t)
	fullEval, err := full.Evaluate(nil, evMaxAge)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mutate func(in *Input)
		code   string
	}{
		// The binding-wide evaluation with the projected capture: its
		// observations and summary are the siblings'.
		"unprojected evaluation": {func(in *Input) { in.Evidence.Evaluation = fullEval }, CodeEvidenceWithheld},
		// The binding-wide capture itself.
		"unprojected capture": {func(in *Input) { in.Evidence = &Evidence{Capture: full, Evaluation: fullEval} }, CodeEvidenceWithheld},
		// A sibling workload smuggled into the projection: the owner's
		// check names its UID, which must not reach the report.
		"tampered projection": {func(in *Input) {
			in.Evidence.Capture.Workloads = append(in.Evidence.Capture.Workloads, full.Workloads[1])
		}, CodeEvidenceWithheld},
		// The projected observations with the binding-wide counts.
		"inflated summary": {func(in *Input) {
			in.Evidence.Evaluation.Evidence, in.Evidence.Evaluation.Outcomes = fullEval.Evidence, fullEval.Outcomes
		}, CodeEvidenceWithheld},
		// A sibling observation appended to the evaluation.
		"sibling observation": {func(in *Input) {
			for _, o := range fullEval.Observations {
				if strings.Contains(o.Key, sibNSUID) {
					in.Evidence.Evaluation.Observations = append(in.Evidence.Evaluation.Observations, o)
					break
				}
			}
		}, CodeEvidenceWithheld},
		// Projected to another namespace than the scope's.
		"other namespace": {func(in *Input) {
			p, err := collector.Project(full, sibNSUID)
			if err != nil {
				t.Fatal(err)
			}
			in.Evidence = evaluated(t, p, evMaxAge)
		}, CodeEvidenceWithheld},
		// A scope naming both namespaces, or a kind that is not a binding.
		"two namespaces": {func(in *Input) {
			in.Scope.Namespaces = append(in.Scope.Namespaces, NamespaceRef{Name: sibNS, UID: sibNSUID})
		}, CodeScopeProjectionInvalid},
		"unknown kind": {func(in *Input) { in.Scope.Kind = "Cluster" }, CodeScopeProjectionInvalid},
		// An invalid context whose broken entry is another binding's.
		"invalid sibling entry": {func(in *Input) {
			ctx := clone(*in.Supporting)
			ctx.Entries[1].Document.Copy = SupportingCopyDir + sibNS + ".pdf"
			in.Supporting = &ctx
		}, CodeSupportingContextInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := namespaceInput(t)
			ev := clone(*in.Evidence)
			in.Evidence = &ev
			tc.mutate(&in)
			r := Build(in)
			leaks(t, r)
			if !hasBlocking(r.Limitations, tc.code) {
				t.Fatalf("no %s: %v", tc.code, r.Limitations)
			}
			te := r.TechnicalEvidence
			if tc.code != CodeSupportingContextInvalid {
				if te.State != EvidenceUnresolved || te.Evidence != nil || te.Outcomes != nil || len(te.Observations) != 0 {
					t.Fatalf("evidence not withheld: %+v", te)
				}
				for _, c := range r.Controls {
					if c.Evidence != nil {
						t.Fatalf("%s has evidence", c.ID)
					}
				}
			}
			if r.Inventory.Controls != moderateCount {
				t.Errorf("the public inventory was lost: %d", r.Inventory.Controls)
			}
			// The failing entry is not identified: it may be another
			// binding's.
			if strings.Contains(mustJSON(t, r.Limitations), "entry 1") {
				t.Error("the namespace diagnostic identifies the failing entry")
			}
		})
	}
	// Coverage diagnostics: the caller's detail is replaced in a namespace
	// projection.
	in := namespaceInput(t)
	r := Unavailable(in, CodeContentUnavailable, sibNS, "bundle of %s is missing (%s)", sibNS, privateMetadata[0])
	leaks(t, r)
	if !hasBlocking(r.Limitations, CodeContentUnavailable) || r.TechnicalEvidence.State != EvidenceResolved {
		t.Fatalf("%v %+v", r.Limitations, r.TechnicalEvidence)
	}
	in.Scope.Kind = "Binding"
	if r := Unavailable(in, CodeContentUnavailable, "", "detail %s", "kept"); !strings.Contains(mustJSON(t, r.Limitations), "detail kept") {
		t.Error("the platform diagnostic lost its detail")
	}
}
