package reporttest_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// A reporting payload, image subjects shared across workloads, passes the
// provider-discriminated capture boundary of a registry that installs the
// provider. The payload is returned as written and evaluates to the
// conformance golden. It is never read as a Kyverno capture, and the
// production registry rejects it.
func TestReportingCaptureCrossesTheBoundary(t *testing.T) {
	dir, err := filepath.Abs("../../../testdata/providers/conformance/v1/konstapel-reporttest/shared-image-evidence")
	if err != nil {
		t.Fatal(err)
	}
	c, want, err := conformance.Load(dir)
	if err != nil || want == nil {
		t.Fatal(err)
	}
	env := func(payload, evaluator int, input json.RawMessage) []byte {
		b, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: reporttest.Contract,
			PayloadVersion: payload, EvaluatorVersion: evaluator, Payload: input})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(env(reporttest.PayloadVersion, 1, c.Input), r)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckEvaluator(r); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.V2(); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("a reporting payload read as a Kyverno capture: %v", err)
	}
	replayed := c
	replayed.Input = doc.Payload
	if errs := conformance.Verify(reporttest.Adapter{}, replayed, *want); len(errs) > 0 {
		t.Fatalf("the payload read through the boundary does not evaluate to the golden: %v", errors.Join(errs...))
	}

	var serr *provider.SelectionError
	if _, err := collector.ReadCapture(env(reporttest.PayloadVersion, 1, c.Input), installed.Registry()); !errors.As(err, &serr) || serr.Reason != provider.ReasonUnknownProvider {
		t.Fatalf("the production registry reads the test-only provider: %v", err)
	}
	if _, err := collector.ReadCapture(env(reporttest.PayloadVersion+1, 1, c.Input), r); !errors.As(err, &serr) || serr.Reason != provider.ReasonIncompatibleVersion {
		t.Fatalf("an unknown reporting payload version was read: %v", err)
	}
	doc, err = collector.ReadCapture(env(reporttest.PayloadVersion, 2, c.Input), r)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckEvaluator(r); !errors.As(err, &serr) || serr.Reason != provider.ReasonIncompatibleVersion {
		t.Fatalf("an unknown reporting evaluator was accepted: %v", err)
	}
	// The provider validates its own payload: a header that agrees with the
	// registry does not make a payload of another version readable.
	var in map[string]any
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatal(err)
	}
	in["payloadVersion"] = reporttest.PayloadVersion + 1
	other, _ := json.Marshal(in)
	doc, err = collector.ReadCapture(env(reporttest.PayloadVersion, 1, other), r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (reporttest.Adapter{}).Evaluate(doc.Payload, c.EvaluationTime); err == nil {
		t.Fatal("the reporting adapter evaluated a payload of another version")
	}
}
