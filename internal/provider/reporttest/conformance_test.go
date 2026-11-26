package reporttest_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

var update = flag.Bool("update", false, "rewrite the synthetic reporting conformance golden results")

// selection is the bundle a reporting run froze as its selection when it
// started (collector.ContentSelected).
var selection = v1alpha1.BundleReference{Name: "reporttest-selection", Digest: "sha256:" + strings.Repeat("5", 64)}

// suite drives the synthetic provider through the host's paths for the
// shared conformance suite: collection under the host's bounds
// (provider.Collect over reporttest.Collect), the provider-discriminated
// capture envelope (collector.ReadCapture with a registry that installs the
// provider), its frozen selection (RunContent.Resolve) and namespace
// projection (CaptureDocument.ProjectNamespace and ValidateNamespace).
type suite struct{ reporttest.Adapter }

var _ conformance.Provider = suite{}

func testRegistry() *provider.Registry {
	r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		panic(err)
	}
	return r
}

func decodeInput(raw json.RawMessage) (reporttest.Input, error) {
	var in reporttest.Input
	if _, err := (reporttest.Adapter{}).MaxEvidenceAge(raw); err != nil {
		return in, err
	}
	return in, json.Unmarshal(raw, &in)
}

func scopeOf(in reporttest.Input) provider.Scope {
	s := provider.Scope{Cluster: "c"}
	for _, sub := range in.Subjects {
		if !slices.ContainsFunc(s.Namespaces, func(n provider.Namespace) bool { return n.UID == sub.NamespaceUID }) {
			s.Namespaces = append(s.Namespaces, provider.Namespace{Name: sub.NamespaceUID, UID: sub.NamespaceUID})
		}
	}
	return s
}

// Cluster serves each report of the input as a posture object.
func (suite) Cluster(raw json.RawMessage) (client.Client, []client.Object, error) {
	in, err := decodeInput(raw)
	if err != nil {
		return nil, nil, err
	}
	var objs []client.Object
	for _, r := range in.Reports {
		verdicts := map[string]any{}
		for k, v := range r.Verdicts {
			verdicts[k] = v
		}
		u := &unstructured.Unstructured{Object: map[string]any{"digest": r.Digest, "verdicts": verdicts}}
		if r.EvaluatedAt != nil {
			u.Object["evaluatedAt"] = r.EvaluatedAt.UTC().Format(time.RFC3339)
		}
		if r.UpdatedAt != nil {
			u.Object["updatedAt"] = r.UpdatedAt.UTC().Format(time.RFC3339)
		}
		u.SetGroupVersionKind(postureGVK)
		u.SetName(r.ID)
		objs = append(objs, u)
	}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(postureGVK, meta.RESTScopeRoot)
	return fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build(), objs, nil
}

// Collect is the host's bounded collection of the input's frozen scope.
func (suite) Collect(ctx context.Context, c client.Reader, raw json.RawMessage) (json.RawMessage, []string, error) {
	in, err := decodeInput(raw)
	if err != nil {
		return nil, nil, err
	}
	s := scopeOf(in)
	reports, limits, err := provider.Collect(ctx, c, reporttest.Descriptor(), s, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) ([]reporttest.Report, []string, error) {
			return reporttest.Collect(ctx, s, in.Subjects, src)
		})
	if err != nil {
		return nil, nil, err
	}
	in.Reports = reports
	if in.Reports == nil {
		in.Reports = []reporttest.Report{}
	}
	out, err := json.Marshal(in)
	return out, limits, err
}

// retained is a run's retained reporting capture and the selection the run
// froze for it.
type retained struct {
	Capture   json.RawMessage          `json:"capture"`
	Selection v1alpha1.BundleReference `json:"selection"`
}

func envelope(raw json.RawMessage) ([]byte, error) {
	return json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: reporttest.Contract,
		PayloadVersion: reporttest.PayloadVersion, EvaluatorVersion: 1, Payload: raw})
}

func (suite) Retain(raw json.RawMessage) ([]byte, error) {
	env, err := envelope(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(retained{Capture: env, Selection: selection})
}

// Replay reads the capture through the boundary and resolves its content
// role against the run's frozen selection, available or not.
func (suite) Replay(b []byte, content conformance.Content) (json.RawMessage, error) {
	var r retained
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	reg := testRegistry()
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
	m := collector.ContentMember{Ref: r.Selection}
	if content == conformance.ContentUnavailable {
		m.Failure = &collector.ContentFailure{Reason: collector.ReasonContentUnavailable, Message: "the selection was not packaged with the run"}
	}
	rc := &collector.RunContent{Desired: &r.Selection, Members: []collector.ContentMember{m}}
	if _, err := rc.Resolve(use); err != nil {
		return nil, contentError(err)
	}
	return doc.Payload, nil
}

// contentError marks the run content's own unavailability for the harness.
func contentError(err error) error {
	var cf *collector.ContentFailure
	if errors.As(err, &cf) && cf.Reason == collector.ReasonContentUnavailable {
		return fmt.Errorf("%w: %w", conformance.ErrContentUnavailable, err)
	}
	return err
}

func (suite) Namespaces(raw json.RawMessage) ([]projection.Scope, error) {
	in, err := decodeInput(raw)
	if err != nil {
		return nil, err
	}
	var out []projection.Scope
	for _, n := range scopeOf(in).Namespaces {
		out = append(out, projection.Scope{UID: n.UID})
	}
	return out, nil
}

func document(raw json.RawMessage) (collector.CaptureDocument, error) {
	env, err := envelope(raw)
	if err != nil {
		return collector.CaptureDocument{}, err
	}
	return collector.ReadCapture(env, testRegistry())
}

func (suite) Extract(raw json.RawMessage, ns projection.Scope) (json.RawMessage, error) {
	doc, err := document(raw)
	if err != nil {
		return nil, err
	}
	ext, err := doc.ProjectNamespace(ns, extractors())
	if err != nil {
		return nil, err
	}
	return ext.Payload, nil
}

func (suite) Validate(raw json.RawMessage, ns projection.Scope) error {
	doc, err := document(raw)
	if err != nil {
		return err
	}
	return doc.ValidateNamespace(ns, extractors())
}

func cases(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../testdata/providers/conformance/v1/konstapel-reporttest")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReportingConformance(t *testing.T) {
	conformance.Run(t, suite{}, cases(t), *update)
}

// Every deliberate regression of the synthetic provider fails the shared
// suite for its own reason.
func TestReportingConformanceCatchesRegressions(t *testing.T) {
	conformance.RunMutations(t, suite{}, cases(t))
}
