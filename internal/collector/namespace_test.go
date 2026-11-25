package collector

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Shared namespace projection (add-assessment-provider-contract 3.3).

// credential marks credential-like source data no team output may contain.
const credential = "tok-" + sibling

// leaks are the strings no namespace output, or refusal, may contain.
var leaks = []string{sibling, "uid-shop-prod", "pod-prod", "shop-prod"}

func noLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(s, l) {
			t.Errorf("%s contains %q", what, l)
		}
	}
}

// projectedDev is shop-dev's projection of mixedCapture after collection
// the way the controller continues it: binding-wide stale scopes and
// configuration changes redacted, a restart discontinuity, an in-namespace
// workload change, and the reports projected again.
func projectedDev(t *testing.T) (CaptureV2, CaptureV2) {
	t.Helper()
	c, _ := mixedCapture(t)
	c.Stale = []targeting.StaleScope{{Binding: targeting.ObjectRevision{Name: "dangling", UID: "uid-dangling"}, Reason: targeting.ReasonProfileNotFound, Message: sibling + " stale detail"}}
	p, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	at := c.Window.Started.Add(time.Minute)
	NewTracker(&p).Discontinuity(at, ObserverDiscontinuity)
	stale := []targeting.StaleScope{{Binding: c.Stale[0].Binding, Reason: c.Stale[0].Reason, Message: RedactedInNamespace}}
	tr := NewTracker(&p)
	tr.Configuration(at, p.Subjects, stale)
	w := p.Workloads[0]
	w.StateSHA256 = "changed"
	tr.Workload(at, w, false)
	np := Projection{Namespace: p.Projection.Namespace, NamespaceUID: p.Projection.NamespaceUID}
	p.Reports = ProjectReports(c.Reports, &np)
	p.Projection = &np
	return c, p
}

// roundTrip is the capture as a later reader decodes it.
func roundTrip(t *testing.T, c CaptureV2) CaptureV2 {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out CaptureV2
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// What the owner's projection produces, in memory and as read back, passes
// the shared check.
func TestOwnersProjectionsPassTheSharedCheck(t *testing.T) {
	c, p := projectedDev(t)
	b, _ := json.Marshal(p)
	noLeak(t, "the projection", string(b))
	if !strings.Contains(string(b), ObserverDiscontinuity) || !strings.Contains(string(b), "stale: ProfileNotFound: "+RedactedInNamespace) {
		t.Fatalf("the projection lacks the binding-wide changes under test: %s", b)
	}
	for name, x := range map[string]CaptureV2{"in memory": p, "read back": roundTrip(t, p)} {
		if err := ValidateProjection(x); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ValidateProjectedEvaluation(x, evaluate(t, x, nil, maxAge)); err != nil {
			t.Fatalf("%s evaluation: %v", name, err)
		}
	}
	for _, uid := range []string{"uid-shop-dev", "uid-shop-prod"} {
		q, err := Project(c, uid)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateProjection(q); err != nil {
			t.Fatalf("%s: %v", uid, err)
		}
	}
}

// Every way a namespace extract could disclose a sibling's findings,
// private source metadata or credentials, or an item of unknown scope, is
// refused, and no refusal repeats the data it refuses.
func TestValidateProjectionRefusesEveryLeak(t *testing.T) {
	_, base := projectedDev(t)
	base = roundTrip(t, base)
	if len(base.Reports) != 1 || len(base.Reports[0]["results"].([]any)) != 2 {
		t.Fatalf("unexpected base projection %v", base.Reports)
	}
	rep := func(c *CaptureV2) map[string]any { return c.Reports[0] }
	res := func(c *CaptureV2, i int) map[string]any { return rep(c)["results"].([]any)[i].(map[string]any) }
	src := func(c *CaptureV2) map[string]any { return res(c, 0)[SourceField].(map[string]any) }
	ref := func(c *CaptureV2) map[string]any { return res(c, 0)["resources"].([]any)[0].(map[string]any) }
	sibWorkload := Workload{Resource: "/v1/pods", Namespace: "shop-prod", NamespaceUID: "uid-shop-prod", Name: "web", UID: "pod-prod"}
	for name, mutate := range map[string]func(*CaptureV2){
		// Source report fields.
		"report summary": func(c *CaptureV2) { rep(c)["summary"] = map[string]any{"fail": 2, "note": sibling} },
		"report scope":   func(c *CaptureV2) { rep(c)["scope"] = map[string]any{"namespace": "shop-prod", "uid": "pod-prod"} },
		"report labels":  func(c *CaptureV2) { rep(c)["metadata"].(map[string]any)["labels"] = map[string]any{"team": sibling} },
		"report annotations": func(c *CaptureV2) {
			rep(c)["metadata"].(map[string]any)["annotations"] = map[string]any{"token": credential}
		},
		"report name":            func(c *CaptureV2) { rep(c)["metadata"].(map[string]any)["name"] = sibling },
		"report without uid":     func(c *CaptureV2) { delete(rep(c)["metadata"].(map[string]any), "uid") },
		"report of sibling":      func(c *CaptureV2) { rep(c)["metadata"].(map[string]any)["namespace"] = "shop-prod" },
		"report of no scope":     func(c *CaptureV2) { delete(rep(c)["metadata"].(map[string]any), "namespace") },
		"report with no results": func(c *CaptureV2) { rep(c)["results"] = []any{} },
		// Result fields.
		"result annotations": func(c *CaptureV2) { res(c, 0)["annotations"] = map[string]any{"leak": sibling} },
		"result severity":    func(c *CaptureV2) { res(c, 0)["severity"] = sibling },
		"result category":    func(c *CaptureV2) { res(c, 0)["category"] = sibling },
		"supporting reference": func(c *CaptureV2) {
			res(c, 0)["properties"].(map[string]any)["evidence"] = "https://u:" + credential + "@store.example/doc"
		},
		"non-string index": func(c *CaptureV2) {
			res(c, 0)["properties"].(map[string]any)["cel.validationIndex"] = map[string]any{"n": sibling}
		},
		"object rule":      func(c *CaptureV2) { res(c, 0)["rule"] = map[string]any{"text": sibling} },
		"object message":   func(c *CaptureV2) { res(c, 0)["message"] = []any{sibling} },
		"filtered message": func(c *CaptureV2) { res(c, 1)["message"] = sibling + " shared finding" },
		"timestamp text":   func(c *CaptureV2) { res(c, 0)["timestamp"] = map[string]any{"seconds": 1, "zone": sibling} },
		"timestamp string": func(c *CaptureV2) { res(c, 0)["timestamp"] = sibling },
		// Provenance.
		"no provenance":         func(c *CaptureV2) { delete(res(c, 0), SourceField) },
		"provenance extra":      func(c *CaptureV2) { src(c)["sourceMessage"] = sibling },
		"provenance no digest":  func(c *CaptureV2) { delete(src(c), "reportSha256") },
		"provenance other uid":  func(c *CaptureV2) { src(c)["report"] = "sibling-report" },
		"provenance transform":  func(c *CaptureV2) { src(c)["transformation"] = "copied/v0" },
		"provenance index":      func(c *CaptureV2) { src(c)["resultIndex"] = -1 },
		"provenance text index": func(c *CaptureV2) { src(c)["resultIndex"] = sibling },
		// Resource references.
		"reference extra":       func(c *CaptureV2) { ref(c)["labels"] = map[string]any{"team": sibling} },
		"reference without uid": func(c *CaptureV2) { delete(ref(c), "uid") },
		"reference of sibling":  func(c *CaptureV2) { ref(c)["namespace"] = "shop-prod" },
		"reference of no scope": func(c *CaptureV2) { delete(ref(c), "namespace") },
		"reference object name": func(c *CaptureV2) { ref(c)["name"] = map[string]any{"n": sibling} },
		"result without refs":   func(c *CaptureV2) { res(c, 0)["resources"] = []any{} },
		"sibling reference added": func(c *CaptureV2) {
			res(c, 0)["resources"] = append(res(c, 0)["resources"].([]any), map[string]any{"kind": "Pod", "namespace": "shop-prod", "name": "web", "uid": "pod-prod"})
		},
		// Frozen scope.
		"sibling subject": func(c *CaptureV2) {
			s := c.Subjects[0]
			s.Namespace, s.NamespaceUID = "shop-prod", "uid-shop-prod"
			c.Subjects = append(c.Subjects, s)
		},
		"subject of sibling name":  func(c *CaptureV2) { c.Subjects[0].Namespace = "shop-prod" },
		"subject of unknown scope": func(c *CaptureV2) { c.Subjects[0].Namespace, c.Subjects[0].NamespaceUID = "", "" },
		"sibling workload":         func(c *CaptureV2) { c.Workloads = append(c.Workloads, sibWorkload) },
		"workload of sibling name": func(c *CaptureV2) { c.Workloads[0].Namespace = "shop-prod" },
		"sibling expected": func(c *CaptureV2) {
			e := c.Expected[0]
			e.NamespaceUID = "uid-shop-prod"
			c.Expected = append(c.Expected, e)
		},
		"expected sibling workload": func(c *CaptureV2) {
			e := c.Expected[0]
			e.Workload = sibWorkload
			c.Expected = append(c.Expected, e)
		},
		"stale message":     func(c *CaptureV2) { c.Stale[0].Message = sibling + " stale detail" },
		"collection errors": func(c *CaptureV2) { c.CollectionErrors = []string{"policyreports is forbidden in namespace shop-prod"} },
		"sibling check": func(c *CaptureV2) {
			c.Checks = append(c.Checks, Check{EnginePolicy: "shop-prod-only", Index: 0, SHA256: sibling})
		},
		"sibling engine policy": func(c *CaptureV2) {
			c.EnginePolicies = append(c.EnginePolicies, assessment.Object{"metadata": map[string]any{"name": "shop-prod-only"}, "spec": map[string]any{"note": sibling}})
		},
		"sibling contribution": func(c *CaptureV2) {
			c.Contributions = append(c.Contributions, targeting.Contribution{Policy: "shop-prod-only", Revision: sibling})
		},
		// Scope changes.
		"binding-wide detail": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: ConfigurationChanged, Detail: "stale: ProfileNotFound: " + sibling})
		},
		"binding-wide unredacted stale": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: ConfigurationChanged, Detail: "stale: ShopProdPayrollOnly"})
		},
		"binding-wide stale reason text": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: ConfigurationChanged, Detail: "stale: shop-prod payroll: " + RedactedInNamespace})
		},
		"binding-wide discontinuity text": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: WatchDiscontinuity, Detail: "relisted shop-prod"})
		},
		"binding-wide workload change": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: WorkloadAdded, Detail: sibling})
		},
		"sibling namespace change": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: NamespaceJoined, Namespace: "shop-prod", NamespaceUID: "uid-shop-prod"})
		},
		"sibling change by name only": func(c *CaptureV2) {
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: NamespaceLeft, Namespace: "shop-prod"})
		},
		"change of sibling workload": func(c *CaptureV2) {
			w := sibWorkload
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: WorkloadRemoved, Previous: &w})
		},
		"own change, sibling workload": func(c *CaptureV2) {
			w := sibWorkload
			c.ScopeChanges = append(c.ScopeChanges, ScopeChange{Kind: WorkloadReplaced, Namespace: "shop-dev", NamespaceUID: "uid-shop-dev", Previous: &c.Workloads[0], Current: &w})
		},
		// Withheld results.
		"withheld text":  func(c *CaptureV2) { c.Projection.Withheld[0].Reason = sibling + " privileged" },
		"withheld count": func(c *CaptureV2) { c.Projection.WithheldTotal = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			c := roundTrip(t, base)
			mutate(&c)
			err := ValidateProjection(c)
			if err == nil {
				t.Fatal("the shared check accepted the leak")
			}
			noLeak(t, "the refusal", err.Error())
		})
	}
}

// An evaluation is checked against its projection before its summary or
// any export uses it.
func TestProjectedEvaluationIsChecked(t *testing.T) {
	c, p := projectedDev(t)
	ev := evaluate(t, p, nil, maxAge)
	if err := ValidateProjectedEvaluation(p, ev); err != nil {
		t.Fatal(err)
	}
	full := evaluate(t, c, nil, maxAge)
	var sib Observation
	for _, o := range full.Observations {
		if strings.Contains(o.Key, "uid-shop-prod") {
			sib = o
		}
	}
	if sib.Key == "" {
		t.Fatal("no sibling observation")
	}
	for name, mutate := range map[string]func(*Evaluation){
		"sibling observation": func(e *Evaluation) {
			e.Observations = append(e.Observations, sib)
			e.Evidence, e.Outcomes = Tally(e.Observations, len(p.Stale))
		},
		"repeated observation": func(e *Evaluation) {
			e.Observations = append(e.Observations, e.Observations[0])
			e.Evidence, e.Outcomes = Tally(e.Observations, len(p.Stale))
		},
		"sibling report": func(e *Evaluation) { e.Observations[0].Report = "sibling-report" },
		"summary of more": func(e *Evaluation) {
			e.Evidence.Expected++
			e.Outcomes.Fail++
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := ev
			e.Observations = append([]Observation(nil), ev.Observations...)
			mutate(&e)
			err := ValidateProjectedEvaluation(p, e)
			if err == nil {
				t.Fatal("the evaluation check accepted it")
			}
			noLeak(t, "the refusal", err.Error())
		})
	}
	// An unprojected capture has no projected evaluation.
	if err := ValidateProjectedEvaluation(c, full); err == nil {
		t.Fatal("an unprojected capture passed")
	}
}

// Export refuses a namespace package whose evaluation, or whose scope's
// namespace name, is not its projection's, before writing anything.
func TestNamespaceExportChecksEvaluationAndScope(t *testing.T) {
	c, p := projectedDev(t)
	ev := evaluate(t, p, nil, maxAge)
	full := evaluate(t, c, nil, maxAge)
	run := publication.RunRef{ClusterID: p.Cluster, BindingUID: "uid-audit-all", RunUID: "run-ns"}
	req := func(out string) ExportRequest {
		return ExportRequest{Root: repo(t), Out: filepath.Join(t.TempDir(), out), Run: run, BindingConfiguration: "b",
			Scope: publication.Scope{Kind: publication.ScopeNamespace, ClusterID: run.ClusterID, BindingUID: run.BindingUID,
				Request:       &publication.RequestRef{Namespace: "shop-dev", Name: "r", UID: "req-1", NamespaceUID: "uid-shop-dev"},
				NamespaceUIDs: []string{"uid-shop-dev"}, Revision: "s"},
			Capture: p, Evaluation: ev}
	}
	if _, err := Export(context.Background(), req("ok")); err != nil {
		t.Fatal(err)
	}
	r := req("sibling")
	r.Evaluation.Observations = append(append([]Observation(nil), ev.Observations...), full.Observations...)
	r.Evaluation.Evidence, r.Evaluation.Outcomes = Tally(r.Evaluation.Observations, len(p.Stale))
	if _, err := Export(context.Background(), r); err == nil {
		t.Fatal("a namespace package summarized sibling observations")
	}
	r = req("renamed")
	r.Scope.Request.Namespace = "shop-prod"
	if _, err := Export(context.Background(), r); err == nil {
		t.Fatal("a namespace package was labeled with another namespace's name")
	}
	// Protected supporting evidence stays out of every namespace package,
	// whatever its provider payload references.
	r = req("supporting")
	r.Supporting = &SupportingFiles{Context: []byte(`{"version":1}`)}
	if _, err := Export(context.Background(), r); err == nil || !strings.Contains(err.Error(), "cannot carry protected supporting evidence") {
		t.Fatalf("a namespace package carried supporting evidence: %v", err)
	}
}

// The shared entry dispatches by provider: a Kyverno payload 2 capture,
// legacy or envelope, projects exactly as Project does; a version 1
// capture and any payload without an installed extractor fail closed.
func TestNamespaceProjectionDispatch(t *testing.T) {
	c, _ := mixedCapture(t)
	want, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	legacy, _ := json.Marshal(c)
	env, _ := json.Marshal(CaptureEnvelope{Version: CaptureEnvelopeVersion, Provider: LegacyProvider, PayloadVersion: CaptureV2Version,
		EvaluatorVersion: LegacyEvaluatorVersion, Payload: legacy})
	dev := projection.Scope{Name: "shop-dev", UID: "uid-shop-dev"}
	for name, raw := range map[string][]byte{"legacy": legacy, "envelope": env} {
		doc, err := ReadCapture(raw, installedReaders)
		if err != nil {
			t.Fatal(err)
		}
		x, err := doc.ProjectNamespace(dev, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := x.V2()
		if err != nil {
			t.Fatal(err)
		}
		gotJSON, _ := json.Marshal(got)
		if string(gotJSON) != string(wantJSON) || string(x.Payload) != string(wantJSON) || x.Header != doc.Header {
			t.Fatalf("%s: the shared entry projects differently from Project", name)
		}
		if err := x.ValidateNamespace(dev, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for scope, ns := range map[string]projection.Scope{
			"sibling":      {Name: "shop-prod", UID: "uid-shop-prod"},
			"sibling name": {Name: "shop-prod", UID: "uid-shop-dev"},
			"no instance":  {Name: "shop-dev"},
		} {
			if err := x.ValidateNamespace(ns, nil); err == nil {
				t.Errorf("%s: the shop-dev extract validated for %s", name, scope)
			}
		}
		if _, err := doc.ProjectNamespace(projection.Scope{UID: "uid-shop-elsewhere"}, nil); !errors.Is(err, ErrNotInScope) {
			t.Errorf("%s: projected outside the frozen scope: %v", name, err)
		}
		if _, err := doc.ProjectNamespace(projection.Scope{Name: "shop-prod", UID: "uid-shop-dev"}, nil); err == nil {
			t.Errorf("%s: projected to a scope whose name is another namespace's", name)
		}
		if err := doc.ValidateNamespace(dev, nil); err == nil {
			t.Errorf("%s: the unprojected capture validated as an extract", name)
		}
	}
	v1, err := ReadCapture([]byte(`{"version":1}`), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ReadCapture([]byte(`{"version":3,"provider":"`+posture+`","payloadVersion":1,"evaluatorVersion":1,"payload":{"subjects":[]}}`), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]CaptureDocument{"version 1": v1, "another provider": other} {
		if _, err := doc.ProjectNamespace(dev, nil); !errors.Is(err, ErrNamespaceProjection) {
			t.Errorf("%s: projected without an extractor: %v", name, err)
		}
		if err := doc.ValidateNamespace(dev, nil); !errors.Is(err, ErrNamespaceProjection) {
			t.Errorf("%s: validated without an extractor: %v", name, err)
		}
	}
}
