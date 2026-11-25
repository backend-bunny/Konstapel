package reporttest_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"

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

// A reporting capture connects to the run's content as its frozen
// selection: with a registry that installs the provider it names no
// applied content, resolves to the one bundle frozen when the run started,
// and evaluates unchanged. Applied content is never read as its selection;
// an unavailable selection stays a failure and nothing is substituted. The
// production registry has no reporting-only provider: Kyverno names applied
// content.
func TestReportingCaptureUsesFrozenSelection(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	c, want, err := conformance.Load(filepath.Join(root, "testdata/providers/conformance/v1/konstapel-reporttest/shared-image-evidence"))
	if err != nil || want == nil {
		t.Fatal(err)
	}
	a, err := bundletest.Differing(root, bundletest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "frozen")
	f, err := bundle.WriteFrozen(dir, a.Manifest, a.Layer, bundletest.Identity(a, "rule-rev-1", "trust-rev-1", time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	sel := v1alpha1.BundleReference{Name: f.Identity.Name, Digest: f.Identity.Digests.OCI}
	r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: reporttest.Contract,
		PayloadVersion: reporttest.PayloadVersion, EvaluatorVersion: 1, Payload: c.Input})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, r)
	if err != nil {
		t.Fatal(err)
	}
	use, err := doc.ContentUse(r)
	if err != nil || use.Role != collector.ContentSelected || len(use.Bundles()) != 0 {
		t.Fatalf("%+v %v", use, err)
	}
	rc := &collector.RunContent{Desired: &sel, Members: []collector.ContentMember{{Ref: sel, Root: dir, Frozen: f}}}
	members, err := rc.Resolve(use)
	if err != nil || len(members) != 1 || members[0].Root != dir || members[0].Applied {
		t.Fatalf("%+v %v", members, err)
	}
	if _, err := collector.FrozenContentSet(members[0].Frozen); err != nil {
		t.Fatal(err)
	}
	replayed := c
	replayed.Input = doc.Payload
	if errs := conformance.Verify(reporttest.Adapter{}, replayed, *want); len(errs) > 0 {
		t.Fatal(errors.Join(errs...))
	}

	var cf *collector.ContentFailure
	applied := &collector.RunContent{Desired: &sel, Members: []collector.ContentMember{{Ref: sel, Applied: true, Root: dir, Frozen: f}}}
	if _, err := applied.Resolve(use); !errors.As(err, &cf) || cf.Reason != collector.ReasonContentMismatch {
		t.Fatalf("applied content read as a reporting-only selection: %v", err)
	}
	unavailable := &collector.RunContent{Desired: &sel, Members: []collector.ContentMember{{Ref: sel,
		Failure: &collector.ContentFailure{Reason: collector.ReasonContentUnavailable, Message: "not resolvable"}}}}
	if _, err := unavailable.Resolve(use); !errors.As(err, &cf) || cf.Reason != collector.ReasonContentUnavailable {
		t.Fatalf("an unavailable selection resolved: %v", err)
	}
	if ro, err := installed.Registry().ReportingOnly(kyverno.Contract); err != nil || ro {
		t.Fatalf("Kyverno is reporting-only: %v %v", ro, err)
	}
	if _, err := doc.ContentUse(installed.Registry()); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("the production registry decided a test-only provider's content: %v", err)
	}
}
