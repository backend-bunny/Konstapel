package kyverno_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
)

var update = flag.Bool("update", false, "rewrite the Kyverno conformance golden results")

const cases = "testdata/providers/conformance/v1/konstapel-kyverno"

// input is the Kyverno conformance payload: a saved CaptureV2 (repository
// relative) or an inline one (a collected, replayed or projected capture),
// the evidence-age limit, and optionally reports that replace the
// capture's own, over the same frozen scope.
type input struct {
	Capture        string               `json:"capture,omitempty"`
	Inline         json.RawMessage      `json:"inline,omitempty"`
	MaxEvidenceAge string               `json:"maxEvidenceAge"`
	Reports        *[]assessment.Object `json:"reports,omitempty"`
}

// adapter drives the existing, unchanged Kyverno evaluator
// (kyverno.Evaluate over collector.CaptureV2.EvaluateAt) and the host's
// Kyverno paths through the shared suite: collection under the host's
// bounds (provider.Collect over kyverno.Collect), the capture boundary with
// the production registry (collector.ReadCapture), the run's applied
// content (RunContent.Resolve) and Kyverno's namespace projection
// (CaptureDocument.ProjectNamespace and ValidateNamespace).
type adapter struct{ root string }

var _ conformance.Provider = adapter{}

func (adapter) Contract() string { return kyverno.Contract }

func (a adapter) load(raw json.RawMessage) (collector.CaptureV2, time.Duration, error) {
	var in input
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return collector.CaptureV2{}, 0, err
	}
	age, err := time.ParseDuration(in.MaxEvidenceAge)
	if err != nil {
		return collector.CaptureV2{}, 0, err
	}
	var c collector.CaptureV2
	switch {
	case (in.Capture == "") == (in.Inline == nil):
		return c, 0, errors.New("the input names exactly one of capture and inline")
	case in.Inline != nil:
		doc, err := collector.ReadCapture(in.Inline, installed.Registry())
		if err != nil {
			return c, 0, err
		}
		if c, err = doc.V2(); err != nil {
			return c, 0, err
		}
	case filepath.IsAbs(in.Capture) || strings.Contains(in.Capture, ".."):
		return c, 0, fmt.Errorf("capture %q must be a repository-relative path", in.Capture)
	default:
		if err := assessment.Read(filepath.Join(a.root, in.Capture), &c); err != nil {
			return c, 0, err
		}
	}
	if in.Reports != nil {
		c.Reports = *in.Reports
	}
	return c, age, c.Validate()
}

// inline is the input of capture c, written as the controller writes it.
func inline(c collector.CaptureV2, age time.Duration) (json.RawMessage, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return json.Marshal(input{Inline: raw, MaxEvidenceAge: age.String()})
}

func key(e collector.Expected) conformance.Expectation {
	w := e.Workload
	return conformance.Expectation{
		Subject: fmt.Sprintf("%s %s/%s uid=%s", w.Resource, w.Namespace, w.Name, w.UID),
		Check:   fmt.Sprintf("%s#%d", e.Check.EnginePolicy, e.Check.Index),
	}
}

func (a adapter) Inventory(raw json.RawMessage) ([]conformance.Expectation, error) {
	c, _, err := a.load(raw)
	if err != nil {
		return nil, err
	}
	out := make([]conformance.Expectation, len(c.Expected))
	for i, e := range c.Expected {
		out[i] = key(e)
	}
	return out, nil
}

// normalized is collector.Tally's outcome mapping.
func normalized(raw string) conformance.Outcome {
	switch raw {
	case "pass", "fail", "error", "skip":
		return conformance.Outcome(raw)
	}
	return conformance.Unknown
}

func (a adapter) evaluate(raw json.RawMessage, at time.Time) (collector.Evaluation, collector.CaptureV2, error) {
	c, age, err := a.load(raw)
	if err != nil {
		return collector.Evaluation{}, c, err
	}
	// The case's explicit time is the evaluation boundary; the capture's
	// own closure is never substituted for it.
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: age}, at)
	return ev, c, err
}

func (a adapter) Evaluate(raw json.RawMessage, at time.Time) (conformance.Evaluation, error) {
	ev, c, err := a.evaluate(raw, at)
	if err != nil {
		return conformance.Evaluation{}, err
	}
	byKey := map[string]collector.Expected{}
	for _, e := range c.Expected {
		byKey[e.Key()] = e
	}
	out := conformance.Evaluation{StaleScopes: len(c.Stale)}
	for _, o := range ev.Observations {
		e, ok := byKey[o.Key]
		if !ok {
			return out, errors.New("observation for an unexpected key")
		}
		k := key(e)
		obs := conformance.Observation{Subject: k.Subject, Check: k.Check, State: conformance.State(o.State)}
		if o.State == collector.Attributable {
			obs.Raw, obs.Outcome, obs.NotApplicable, obs.Evaluated = o.Outcome, normalized(o.Outcome), o.Applicability == collector.NotApplicable, o.Evaluated
		}
		out.Observations = append(out.Observations, obs)
	}
	return out, nil
}

func (a adapter) WithoutEvidence(raw json.RawMessage) (json.RawMessage, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	none := []assessment.Object{}
	in.Reports = &none
	return json.Marshal(in)
}

func (a adapter) MaxEvidenceAge(raw json.RawMessage) (time.Duration, error) {
	_, age, err := a.load(raw)
	return age, err
}

// collectionScope is the capture's frozen namespace scope, in name order.
func collectionScope(c collector.CaptureV2) provider.Scope {
	s := provider.Scope{Cluster: c.Cluster}
	for _, sub := range c.Subjects {
		n := provider.Namespace{Name: sub.Namespace, UID: string(sub.NamespaceUID)}
		if !slices.Contains(s.Namespaces, n) {
			s.Namespaces = append(s.Namespaces, n)
		}
	}
	slices.SortFunc(s.Namespaces, func(x, y provider.Namespace) int { return strings.Compare(x.Name, y.Name) })
	return s
}

// Cluster serves the capture's reports as PolicyReport objects.
func (a adapter) Cluster(raw json.RawMessage) (client.Client, []client.Object, error) {
	c, _, err := a.load(raw)
	if err != nil {
		return nil, nil, err
	}
	var objs []client.Object
	for i, r := range c.Reports {
		var u unstructured.Unstructured
		b, err := json.Marshal(r)
		if err == nil {
			err = json.Unmarshal(b, &u.Object)
		}
		if err != nil {
			return nil, nil, err
		}
		if u.GetName() == "" {
			u.SetName(fmt.Sprintf("report-%d", i))
		}
		u.SetResourceVersion("")
		objs = append(objs, &u)
	}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(policyReport, meta.RESTScopeNamespace)
	mapper.Add(clusterPolicyReport, meta.RESTScopeRoot)
	return fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build(), objs, nil
}

// Collect is the controller's bounded collection of the capture's scope.
func (a adapter) Collect(ctx context.Context, cl client.Reader, raw json.RawMessage) (json.RawMessage, []string, error) {
	c, age, err := a.load(raw)
	if err != nil {
		return nil, nil, err
	}
	s := collectionScope(c)
	reports, limits, err := provider.Collect(ctx, cl, kyverno.Descriptor(), s, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) ([]assessment.Object, []string, error) {
			return kyverno.Collect(ctx, s, src)
		})
	if err != nil {
		return nil, nil, err
	}
	c.Reports = reports
	out, err := inline(c, age)
	return out, limits, err
}

// retained is a run's retained Kyverno capture and the applied content the
// run froze for it.
type retained struct {
	Capture        json.RawMessage            `json:"capture"`
	MaxEvidenceAge string                     `json:"maxEvidenceAge"`
	Applied        []v1alpha1.BundleReference `json:"applied"`
}

func (a adapter) Retain(raw json.RawMessage) ([]byte, error) {
	c, age, err := a.load(raw)
	if err != nil {
		return nil, err
	}
	capture, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	doc, err := collector.ReadCapture(capture, installed.Registry())
	if err != nil {
		return nil, err
	}
	use, err := doc.ContentUse(installed.Registry())
	if err != nil {
		return nil, err
	}
	return json.Marshal(retained{Capture: capture, MaxEvidenceAge: age.String(), Applied: use.Bundles()})
}

// Replay reads the retained capture through the production capture
// boundary and resolves its applied content against what the run froze,
// available or not.
func (a adapter) Replay(b []byte, content conformance.Content) (json.RawMessage, error) {
	var r retained
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	age, err := time.ParseDuration(r.MaxEvidenceAge)
	if err != nil {
		return nil, err
	}
	reg := installed.Registry()
	doc, err := collector.ReadCapture(r.Capture, reg)
	if err != nil {
		return nil, err
	}
	if err := doc.CheckEvaluator(reg); err != nil {
		return nil, err
	}
	use, err := doc.ContentUse(reg)
	if err != nil {
		return nil, err
	}
	rc := &collector.RunContent{}
	for _, ref := range r.Applied {
		m := collector.ContentMember{Ref: ref, Applied: true}
		if content == conformance.ContentUnavailable {
			m.Failure = &collector.ContentFailure{Reason: collector.ReasonContentUnavailable, Message: "the applied bundle was not packaged with the run"}
		}
		rc.Members = append(rc.Members, m)
	}
	if _, err := rc.Resolve(use); err != nil {
		var cf *collector.ContentFailure
		if errors.As(err, &cf) && cf.Reason == collector.ReasonContentUnavailable {
			return nil, fmt.Errorf("%w: %w", conformance.ErrContentUnavailable, err)
		}
		return nil, err
	}
	c, err := doc.V2()
	if err != nil {
		return nil, err
	}
	return inline(c, age)
}

func (a adapter) Namespaces(raw json.RawMessage) ([]projection.Scope, error) {
	c, _, err := a.load(raw)
	if err != nil {
		return nil, err
	}
	var out []projection.Scope
	for _, n := range collectionScope(c).Namespaces {
		out = append(out, projection.Scope{Name: n.Name, UID: n.UID})
	}
	return out, nil
}

func (a adapter) document(raw json.RawMessage) (collector.CaptureDocument, time.Duration, error) {
	c, age, err := a.load(raw)
	if err != nil {
		return collector.CaptureDocument{}, 0, err
	}
	capture, err := json.Marshal(c)
	if err != nil {
		return collector.CaptureDocument{}, 0, err
	}
	doc, err := collector.ReadCapture(capture, installed.Registry())
	return doc, age, err
}

func (a adapter) Extract(raw json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
	doc, age, err := a.document(raw)
	if err != nil {
		return nil, err
	}
	ext, err := doc.ProjectNamespace(ns, nil)
	if err != nil {
		return nil, err
	}
	c, err := ext.V2()
	if err != nil {
		return nil, err
	}
	return inline(c, age)
}

func (a adapter) Validate(raw json.RawMessage, ns projection.Scope) error {
	doc, _, err := a.document(raw)
	if err != nil {
		return err
	}
	return doc.ValidateNamespace(ns, nil)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestKyvernoConformance(t *testing.T) {
	root := repoRoot(t)
	conformance.Run(t, adapter{root: root}, filepath.Join(root, cases), *update)
}

// Every deliberate regression of the Kyverno provider fails the shared
// suite for its own reason.
func TestKyvernoConformanceCatchesRegressions(t *testing.T) {
	root := repoRoot(t)
	conformance.RunMutations(t, adapter{root: root}, filepath.Join(root, cases))
}

// The harness's provider-neutral summary is exactly the controller's
// summary (collector.Tally) for the same frozen inputs, so the shared
// contract cannot drift from what assessments publish.
func TestKyvernoHarnessSummaryMatchesCollector(t *testing.T) {
	root := repoRoot(t)
	a := adapter{root: root}
	dirs, err := conformance.Dirs(filepath.Join(root, cases))
	if err != nil || len(dirs) < 2 {
		t.Fatalf("cases %v: %v", dirs, err)
	}
	for _, dir := range dirs {
		c, _, err := conformance.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		ev, _, err := a.evaluate(c.Input, c.EvaluationTime)
		if err != nil {
			t.Fatal(err)
		}
		shared, err := a.Evaluate(c.Input, c.EvaluationTime)
		if err != nil {
			t.Fatal(err)
		}
		evidence, outcomes := conformance.Summarize(shared)
		if evidence != ev.Evidence || outcomes != ev.Outcomes {
			t.Errorf("%s: harness %+v %+v, collector %+v %+v", filepath.Base(dir), evidence, outcomes, ev.Evidence, ev.Outcomes)
		}
	}
}

// The saved live evidence keeps its documented interpretation
// (internal/collector TestSavedPolicyLevelPassEvidence) through the harness.
func TestKyvernoSavedEvidenceInterpretation(t *testing.T) {
	root := repoRoot(t)
	c, want, err := conformance.Load(filepath.Join(root, cases, "background-1.19.2"))
	if err != nil || want == nil {
		t.Fatal(err)
	}
	e, o := want.Evidence, want.Outcomes
	if e.Expected != 30 || e.Attributable != 28 || e.Missing != 2 || e.Completeness != "Incomplete" || o.Pass != 24 || o.Fail != 4 {
		t.Fatalf("golden summary %+v %+v", e, o)
	}
	if c.Provider != kyverno.Contract {
		t.Fatal(c.Provider)
	}
}

// The case's evaluation time is used, never replaced by the capture's
// closure: evaluated past every result's evidence-age limit, the saved
// evidence no longer matches its golden result and is all rejected, and a
// zero time is refused.
func TestKyvernoHonorsTheExplicitEvaluationTime(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, cases, "background-1.19.2")
	c, want, err := conformance.Load(dir)
	if err != nil || want == nil {
		t.Fatal(err)
	}
	later := c
	later.EvaluationTime = c.EvaluationTime.Add(3 * time.Hour)
	if errs := conformance.Verify(adapter{root: root}, later, *want); len(errs) == 0 {
		t.Fatal("a later evaluation time reproduced the closure result")
	}
	got, errs := conformance.Check(adapter{root: root}, later)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if e := got.Evidence; e.Attributable != 0 || e.Rejected != want.Evidence.Attributable || got.Outcomes.Pass != 0 || got.Outcomes.Fail != 0 {
		t.Fatalf("three hours later: %+v %+v", e, got.Outcomes)
	}
	zero := c
	zero.EvaluationTime = time.Time{}
	if _, err := (adapter{root: root}).Evaluate(zero.Input, zero.EvaluationTime); err == nil {
		t.Fatal("a zero evaluation time was accepted")
	}
}

var _ conformance.Leaker = adapter{}

// WithSiblingCounts re-adds the count of every source report, as releases
// up to 0.3.0 recorded it in the projection.
func (a adapter) WithSiblingCounts(input, extract json.RawMessage, _ projection.Scope) (json.RawMessage, bool, error) {
	in, _, err := a.load(input)
	if err != nil {
		return nil, false, err
	}
	ext, age, err := a.load(extract)
	if err != nil || ext.Projection == nil || len(in.Reports) == 0 {
		return nil, false, err
	}
	p := *ext.Projection
	p.SourceReports = len(in.Reports)
	ext.Projection = &p
	out, err := inline(ext, age)
	return out, true, err
}

// WithSourceCopy replaces each report extract with its whole source
// report.
func (a adapter) WithSourceCopy(input, extract json.RawMessage, _ projection.Scope) (json.RawMessage, bool, error) {
	in, _, err := a.load(input)
	if err != nil {
		return nil, false, err
	}
	ext, age, err := a.load(extract)
	if err != nil || len(ext.Reports) == 0 {
		return nil, false, err
	}
	ext.Reports = slices.Clone(in.Reports)
	out, err := inline(ext, age)
	return out, true, err
}
