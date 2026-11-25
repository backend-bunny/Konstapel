package reporttest_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

const (
	nsTeam    = "ns-team"
	nsSibling = "ns-sibling"
	// leak marks every piece of data the team's extract must not contain.
	leak = "SIBLING-SECRET"
)

func digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// mixedInput is a payload whose cluster-wide source spans two namespaces:
// the team and a sibling share one image (and so one report), the sibling
// alone runs another, and a subject of unknown scope runs a third. Reports
// also carry a verdict for a check that is not frozen.
func mixedInput(t *testing.T) json.RawMessage {
	t.Helper()
	at := time.Date(2026, 11, 20, 11, 50, 0, 0, time.UTC)
	in := reporttest.Input{PayloadVersion: reporttest.PayloadVersion, MaxEvidenceAge: "1h",
		Checks: []string{"no-critical", "signed"},
		Subjects: []reporttest.Subject{
			{NamespaceUID: nsTeam, WorkloadUID: "w-web", Container: "app", Image: "registry.example/shop@" + digest('a')},
			{NamespaceUID: nsTeam, WorkloadUID: "w-web", Container: "proxy", Image: "registry.example/proxy:latest"},
			{NamespaceUID: nsSibling, WorkloadUID: "w-" + leak, Container: "app", Image: "registry.example/shop@" + digest('a')},
			{NamespaceUID: nsSibling, WorkloadUID: "w-db", Container: "db", Image: "registry.example/" + strings.ToLower(leak) + "@" + digest('b')},
			{NamespaceUID: "", WorkloadUID: "w-orphan", Container: "app", Image: "registry.example/orphan@" + digest('c')},
		},
		Reports: []reporttest.Report{
			{ID: "r-shared", Digest: digest('a'), EvaluatedAt: &at, Verdicts: map[string]string{"no-critical": "Violated", "signed": "Passed", "private-" + leak: "Violated"}},
			{ID: "r-" + leak, Digest: digest('b'), EvaluatedAt: &at, Verdicts: map[string]string{"no-critical": "Violated"}},
			{ID: "r-orphan-" + leak, Digest: digest('c'), EvaluatedAt: &at, Verdicts: map[string]string{"no-critical": "Passed"}},
		}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func extractors() collector.NamespaceExtractors {
	return collector.NamespaceExtractors{{Provider: reporttest.Contract, Version: reporttest.PayloadVersion}: reporttest.Extractor{}}
}

func readMixed(t *testing.T, input json.RawMessage) collector.CaptureDocument {
	t.Helper()
	r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: reporttest.Contract,
		PayloadVersion: reporttest.PayloadVersion, EvaluatorVersion: 1, Payload: input})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, r)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// A shared, cluster-wide source spanning namespaces yields a team extract
// with only the team's subjects and the reports for images the team runs,
// traceable to their source IDs. The team's inventory and results are
// exactly its part of the full payload's.
func TestNamespaceExtractOfSharedSource(t *testing.T) {
	full := mixedInput(t)
	team := projection.Scope{UID: nsTeam}
	doc, err := readMixed(t, full).ProjectNamespace(team, extractors())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Header.Provider != reporttest.Contract || doc.Header.PayloadVersion != reporttest.PayloadVersion {
		t.Fatalf("the extract changed the capture header: %s", doc.Header)
	}
	for _, s := range []string{leak, strings.ToLower(leak), nsSibling, digest('b'), digest('c'), "w-orphan", "w-db"} {
		if strings.Contains(string(doc.Payload), s) {
			t.Errorf("the team's extract contains %q", s)
		}
	}
	var got reporttest.Input
	if err := json.Unmarshal(doc.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Subjects) != 2 || len(got.Reports) != 1 || got.Reports[0].ID != "r-shared" || got.Reports[0].Digest != digest('a') {
		t.Fatalf("extract %+v", got)
	}
	if err := doc.ValidateNamespace(team, extractors()); err != nil {
		t.Fatalf("the extract fails the shared check: %v", err)
	}

	ours := func(subject string) bool { return strings.HasPrefix(subject, nsTeam+"/") }
	a := reporttest.Adapter{}
	// Inventory refuses a subject without identity, so the full inventory
	// is taken without the subject of unknown scope.
	var known reporttest.Input
	if err := json.Unmarshal(full, &known); err != nil {
		t.Fatal(err)
	}
	known.Subjects = slices.DeleteFunc(known.Subjects, func(s reporttest.Subject) bool { return s.NamespaceUID == "" })
	knownRaw, _ := json.Marshal(known)
	inv, err := a.Inventory(knownRaw)
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := a.Inventory(doc.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.DeleteFunc(inv, func(e conformance.Expectation) bool { return !ours(e.Subject) }); !slices.Equal(want, extracted) {
		t.Fatalf("the extract's inventory %v is not the team's part %v", extracted, want)
	}
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ev, err := a.Evaluate(full, at)
	if err != nil {
		t.Fatal(err)
	}
	evx, err := a.Evaluate(doc.Payload, at)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.DeleteFunc(ev.Observations, func(o conformance.Observation) bool { return !ours(o.Subject) })
	b1, _ := json.Marshal(want)
	b2, _ := json.Marshal(evx.Observations)
	if string(b1) != string(b2) {
		t.Fatalf("extraction changed the team's results:\nfull  %s\nextract %s", b1, b2)
	}
}

// Unknown scope fails closed: a scope without a namespace instance projects
// nothing, a subject without a namespace is never disclosed, and a payload
// without an installed extractor has no namespace package.
func TestNamespaceExtractUnknownScopeFailsClosed(t *testing.T) {
	doc := readMixed(t, mixedInput(t))
	if _, err := doc.ProjectNamespace(projection.Scope{}, extractors()); !errors.Is(err, collector.ErrNamespaceProjection) {
		t.Fatalf("projected to an unknown scope: %v", err)
	}
	if _, err := (reporttest.Extractor{}).Extract(doc.Payload, projection.Scope{}); err == nil {
		t.Fatal("the extractor projected to an unknown scope")
	}
	for name, x := range map[string]collector.NamespaceExtractors{
		"none installed":          nil,
		"another payload version": {{Provider: reporttest.Contract, Version: reporttest.PayloadVersion + 1}: reporttest.Extractor{}},
		"another provider":        {{Provider: "example-scanner/v1", Version: reporttest.PayloadVersion}: reporttest.Extractor{}},
	} {
		if _, err := doc.ProjectNamespace(projection.Scope{UID: nsTeam}, x); !errors.Is(err, collector.ErrNamespaceProjection) {
			t.Errorf("%s: projected without an installed extractor: %v", name, err)
		}
		if err := doc.ValidateNamespace(projection.Scope{UID: nsTeam}, x); !errors.Is(err, collector.ErrNamespaceProjection) {
			t.Errorf("%s: validated without an installed extractor: %v", name, err)
		}
	}
	// The unprojected payload is not the team's extract: it keeps a private
	// check's verdict and, without it, still discloses the sibling and the
	// subject and report of unknown scope.
	err := doc.ValidateNamespace(projection.Scope{UID: nsTeam}, extractors())
	if !errors.Is(err, projection.ErrDisclosure) {
		t.Fatalf("the unprojected payload passed the shared check: %v", err)
	}
	var in reporttest.Input
	if err := json.Unmarshal(doc.Payload, &in); err != nil {
		t.Fatal(err)
	}
	delete(in.Reports[0].Verdicts, "private-"+leak)
	raw, _ := json.Marshal(in)
	err = readMixed(t, raw).ValidateNamespace(projection.Scope{UID: nsTeam}, extractors())
	for _, want := range []string{"subjects[2]: another namespace instance", "subjects[4]: unknown scope", "reports[1]: another namespace instance", "reports[2]: unknown scope"} {
		if !errors.Is(err, projection.ErrDisclosure) || !strings.Contains(err.Error(), want) {
			t.Errorf("the unprojected payload's refusal does not say %q: %v", want, err)
		}
	}
	if err != nil && (strings.Contains(err.Error(), nsSibling) || strings.Contains(err.Error(), leak)) {
		t.Fatalf("the refusal repeats sibling data: %v", err)
	}
}

// Every way an extract could carry the sibling's data, an unattributable
// report or a private check's verdict is refused by the shared check, even
// when the extract is otherwise the team's own.
func TestTamperedNamespaceExtractsAreRefused(t *testing.T) {
	team := projection.Scope{UID: nsTeam}
	doc, err := readMixed(t, mixedInput(t)).ProjectNamespace(team, extractors())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 20, 11, 50, 0, 0, time.UTC)
	for name, tamper := range map[string]func(*reporttest.Input){
		"sibling subject": func(in *reporttest.Input) {
			in.Subjects = append(in.Subjects, reporttest.Subject{NamespaceUID: nsSibling, WorkloadUID: "w-db", Container: "db", Image: "x@" + digest('b')})
		},
		"subject of unknown scope": func(in *reporttest.Input) {
			in.Subjects = append(in.Subjects, reporttest.Subject{WorkloadUID: "w-orphan", Container: "app", Image: "x@" + digest('c')})
		},
		"sibling-only report": func(in *reporttest.Input) {
			in.Reports = append(in.Reports, reporttest.Report{ID: "r-db", Digest: digest('b'), EvaluatedAt: &at, Verdicts: map[string]string{"no-critical": "Violated"}})
		},
		"private check verdict": func(in *reporttest.Input) {
			in.Reports[0].Verdicts["private-"+leak] = "Violated"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var in reporttest.Input
			if err := json.Unmarshal(doc.Payload, &in); err != nil {
				t.Fatal(err)
			}
			tamper(&in)
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			bad := readMixed(t, raw)
			if err := bad.ValidateNamespace(team, extractors()); !errors.Is(err, projection.ErrDisclosure) {
				t.Fatalf("a tampered extract passed the shared check: %v", err)
			}
		})
	}
	// A field outside the payload is not the provider's extract.
	var m map[string]any
	if err := json.Unmarshal(doc.Payload, &m); err != nil {
		t.Fatal(err)
	}
	m["siblings"] = []string{leak}
	raw, _ := json.Marshal(m)
	if err := readMixed(t, raw).ValidateNamespace(team, extractors()); !errors.Is(err, projection.ErrDisclosure) {
		t.Fatalf("an extract with an unknown field passed: %v", err)
	}
}

// leaky extracts nothing: it returns the source payload as its extract.
type leaky struct{ reporttest.Extractor }

func (leaky) Extract(raw json.RawMessage, _ projection.Scope) (json.RawMessage, error) {
	return raw, nil
}

// The host does not trust an extractor's extraction: the shared check reads
// the extract back and refuses what a faulty extractor let through, and a
// scope without a namespace instance is refused before any extractor runs.
func TestFaultyExtractorIsCaughtByTheSharedCheck(t *testing.T) {
	doc := readMixed(t, mixedInput(t))
	x := collector.NamespaceExtractors{{Provider: reporttest.Contract, Version: reporttest.PayloadVersion}: leaky{}}
	_, err := doc.ProjectNamespace(projection.Scope{UID: nsTeam}, x)
	if !errors.Is(err, projection.ErrDisclosure) {
		t.Fatalf("a faulty extract was disclosed: %v", err)
	}
	if strings.Contains(err.Error(), leak) || strings.Contains(err.Error(), nsSibling) {
		t.Fatalf("the refusal repeats sibling data: %v", err)
	}
	if _, err := doc.ProjectNamespace(projection.Scope{}, x); !errors.Is(err, collector.ErrNamespaceProjection) {
		t.Fatalf("a faulty extractor ran for an unknown scope: %v", err)
	}
}
