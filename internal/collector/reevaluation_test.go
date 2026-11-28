package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// earlierReaders mirror the unreleased builds that read envelopes before
// payload 3: Kyverno payloads 1 and 2 with evaluator 1.
var earlierReaders = readers{LegacyProvider: {[]int{1, 2}, 1}}

// continuousCapture is a run that started after its workloads' reports
// were evaluated, on a host that observed every workload continuously
// from an hour before: the usual scheduled run against background reports.
// Its closure evaluation attributes the reports only through the
// boundaries.
func continuousCapture(t *testing.T) (CaptureV2, []Boundary) {
	t.Helper()
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(-30*time.Minute), failProd)
	var bs []Boundary
	for _, w := range c.Workloads {
		bs = append(bs, Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: c.Window.Started.Add(-time.Hour)})
	}
	return c, bs
}

func frozenPayload(t *testing.T) (CaptureV3, Evaluation) {
	t.Helper()
	c, bs := continuousCapture(t)
	closure, err := c.EvaluateAt(c.Window.Closed, bs, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Evidence.Attributable != closure.Evidence.Expected || closure.Evidence.Expected == 0 {
		t.Fatalf("the closure evaluation does not attribute through the boundaries: %+v", closure.Evidence)
	}
	return CaptureV3{Version: CaptureV3Version, Capture: c, EvaluationInputs: FreezeEvaluationInputs(maxAge, bs)}, closure
}

func encodeV3(t *testing.T, p CaptureV3) []byte {
	t.Helper()
	raw, err := EncodeCaptureV3(p, LegacyEvaluatorVersion)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A payload 3 reads back with its inputs, re-evaluates from them alone to
// its closure evaluation, and converts that stored evaluation.
func TestCaptureV3ReevaluatesFromItsFrozenInputs(t *testing.T) {
	p, closure := frozenPayload(t)
	raw := encodeV3(t, p)
	doc, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Header != (CaptureHeader{Version: CaptureEnvelopeVersion, Provider: LegacyProvider, PayloadVersion: CaptureV3Version, EvaluatorVersion: LegacyEvaluatorVersion}) {
		t.Fatalf("header %s", doc.Header)
	}
	if !doc.Continuous() {
		t.Fatal("a payload 3 is not a controller capture")
	}
	frozen, err := doc.Frozen()
	if err != nil {
		t.Fatal(err)
	}
	if frozen.EvaluationInputs.MaxEvidenceAge != "2h0m0s" || len(frozen.EvaluationInputs.Boundaries) != len(p.Capture.Workloads) {
		t.Fatalf("inputs %+v", frozen.EvaluationInputs)
	}
	again, err := doc.Reevaluate(installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if !SameEvaluation(again, closure) {
		t.Fatal("the package's frozen inputs do not reproduce the closure evaluation")
	}
	stored, _ := json.Marshal(closure)
	s, err := ReadSnapshot(doc, installedReaders, stored)
	if err != nil {
		t.Fatal(err)
	}
	if !SameEvaluation(s.Evaluation, closure) {
		t.Fatal("the snapshot is not the stored evaluation")
	}
	// Without the recorded boundaries, the window start rejects the
	// reports: the inputs are needed, not decoration.
	without, err := p.Capture.EvaluateAt(p.Capture.Window.Closed, nil, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if without.Evidence.Attributable != 0 || without.Evidence.Rejected == 0 {
		t.Fatalf("the boundaries do not matter to this capture: %+v", without.Evidence)
	}
}

// Kyverno captures before payload 3 record no inputs: re-evaluation is
// explicitly unavailable, and their stored evaluation is still read.
func TestEarlierCapturesReevaluationUnavailable(t *testing.T) {
	c, bs := continuousCapture(t)
	closure, err := c.EvaluateAt(c.Window.Closed, bs, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(c)
	env, err := EncodeEnvelope(CaptureHeader{Provider: LegacyProvider, PayloadVersion: CaptureV2Version, EvaluatorVersion: LegacyEvaluatorVersion}, legacy)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := json.Marshal(closure)
	for name, raw := range map[string][]byte{"legacy version 2": legacy, "payload 2 envelope": env} {
		doc, err := ReadCapture(raw, installedReaders)
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := doc.Frozen(); !errors.Is(err, ErrReevaluationUnavailable) {
			t.Errorf("%s: frozen inputs %v", name, err)
		}
		if _, err := doc.Reevaluate(installedReaders); !errors.Is(err, ErrReevaluationUnavailable) || !strings.Contains(err.Error(), "retrieved, not recomputed") {
			t.Errorf("%s: re-evaluation %v", name, err)
		}
		s, err := ReadSnapshot(doc, installedReaders, stored)
		if err != nil || !SameEvaluation(s.Evaluation, closure) {
			t.Errorf("%s: the stored evaluation is no longer retrieved: %v", name, err)
		}
	}
	proto, err := os.ReadFile(filepath.Join(repo(t), prototypeFixture))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadCapture(proto, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.Reevaluate(installedReaders); !errors.Is(err, ErrReevaluationUnavailable) {
		t.Errorf("prototype capture: %v", err)
	}
}

// Every reader before payload 3 refuses it rather than ignoring the
// inputs: 0.3.0 and earlier refuse the envelope that carries it, the
// unreleased envelope readers refuse its payload version, and a strict
// payload 2 decoding refuses its fields. This build never reads it as a
// payload 2 either.
func TestEarlierReadersRefuseEvaluationInputs(t *testing.T) {
	p, _ := frozenPayload(t)
	raw := encodeV3(t, p)
	// 0.3.0 and earlier: their version dispatch, CaptureV2 validation and
	// evaluation, and the prototype's reconciliation.
	if _, err := CaptureVersion(raw); err == nil {
		t.Error("the earlier releases' version dispatch accepts it")
	}
	var asV2 CaptureV2
	if err := json.Unmarshal(raw, &asV2); err != nil {
		t.Fatal(err)
	}
	if err := asV2.Validate(); err == nil {
		t.Error("the earlier releases' CaptureV2 validation accepts it")
	}
	if _, err := asV2.Evaluate(nil, maxAge); err == nil {
		t.Error("the earlier releases' CaptureV2 evaluation accepts it")
	}
	var asV1 assessment.Capture
	_ = json.Unmarshal(raw, &asV1)
	if _, _, err := assessment.Reconcile(asV1); err == nil {
		t.Error("the prototype's reconciliation accepts it")
	}
	// The unreleased builds that read envelopes: their Kyverno descriptor
	// reads payloads 1 and 2 only.
	if _, err := ReadCapture(raw, earlierReaders); !errors.Is(err, ErrUnsupportedCapture) || !strings.Contains(err.Error(), "not 3") {
		t.Errorf("the earlier envelope readers: %v", err)
	}
	// Their payload decoding was strict CaptureV2 of payload version 2.
	var e CaptureEnvelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	var strict CaptureV2
	if err := decodeStrict(e.Payload, &strict); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("a strict payload 2 decoding: %v", err)
	}
	// This build's payload 2 reader refuses it.
	doc, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.V2(); !errors.Is(err, ErrUnsupportedCapture) || !strings.Contains(err.Error(), "ignore them") {
		t.Errorf("V2 reads a payload 3: %v", err)
	}
}

// A payload 3 is decoded strictly and its inputs must belong to its
// capture; anything else is refused, never read with defaults.
func TestCaptureV3Validation(t *testing.T) {
	p, _ := frozenPayload(t)
	for name, mutate := range map[string]func(*CaptureV3){
		"payload version 2":       func(p *CaptureV3) { p.Version = 2 },
		"open window":             func(p *CaptureV3) { p.Capture.Window.Closed = time.Time{} },
		"no limit":                func(p *CaptureV3) { p.EvaluationInputs.MaxEvidenceAge = "" },
		"zero limit":              func(p *CaptureV3) { p.EvaluationInputs.MaxEvidenceAge = "0s" },
		"negative limit":          func(p *CaptureV3) { p.EvaluationInputs.MaxEvidenceAge = "-2h0m0s" },
		"non-canonical limit":     func(p *CaptureV3) { p.EvaluationInputs.MaxEvidenceAge = "2h" },
		"absent boundaries":       func(p *CaptureV3) { p.EvaluationInputs.Boundaries = nil },
		"unknown workload":        func(p *CaptureV3) { p.EvaluationInputs.Boundaries[0].WorkloadUID = "pod-elsewhere" },
		"another state":           func(p *CaptureV3) { p.EvaluationInputs.Boundaries[0].StateSHA256 = "other" },
		"repeated workload":       func(p *CaptureV3) { p.EvaluationInputs.Boundaries[1] = p.EvaluationInputs.Boundaries[0] },
		"boundary without time":   func(p *CaptureV3) { p.EvaluationInputs.Boundaries[0].Since = time.Time{} },
		"invalid inner capture":   func(p *CaptureV3) { p.Capture.Expected = p.Capture.Expected[1:] },
		"inner capture version 3": func(p *CaptureV3) { p.Capture.Version = 3 },
	} {
		q := p
		q.EvaluationInputs.Boundaries = append([]Boundary(nil), p.EvaluationInputs.Boundaries...)
		if name == "absent boundaries" {
			q.EvaluationInputs.Boundaries = nil
		}
		q.Capture.Expected = append([]Expected(nil), p.Capture.Expected...)
		mutate(&q)
		if err := q.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
		if _, err := EncodeCaptureV3(q, LegacyEvaluatorVersion); err == nil {
			t.Errorf("%s: encoded", name)
		}
		payload, _ := json.Marshal(q)
		env, err := EncodeEnvelope(CaptureHeader{Provider: LegacyProvider, PayloadVersion: CaptureV3Version, EvaluatorVersion: LegacyEvaluatorVersion}, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadCapture(env, installedReaders); !errors.Is(err, ErrUnsupportedCapture) {
			t.Errorf("%s: read (%v)", name, err)
		}
	}
	// Unknown fields, at either level, are refused.
	raw, _ := json.Marshal(p)
	for name, payload := range map[string][]byte{
		"unknown payload field": bytes.Replace(raw, []byte(`"version":3,`), []byte(`"version":3,"note":"x",`), 1),
		"unknown input field":   bytes.Replace(raw, []byte(`"evaluationInputs":{`), []byte(`"evaluationInputs":{"evaluatedAt":"2026-01-01T00:00:00Z",`), 1),
		"inputs absent":         bytes.Replace(raw, []byte(`"evaluationInputs":`), []byte(`"ignored":`), 1),
	} {
		if bytes.Equal(payload, raw) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		env, err := EncodeEnvelope(CaptureHeader{Provider: LegacyProvider, PayloadVersion: CaptureV3Version, EvaluatorVersion: LegacyEvaluatorVersion}, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadCapture(env, installedReaders); !errors.Is(err, ErrUnsupportedCapture) {
			t.Errorf("%s: read (%v)", name, err)
		}
	}
	// A payload 3 only exists in an envelope: a version 3 document is an
	// envelope, and a legacy document carries payload 1 or 2.
	if _, err := ReadCapture(raw, installedReaders); !errors.Is(err, ErrUnsupportedCapture) {
		t.Errorf("a bare payload 3 document: %v", err)
	}
}

// A stored evaluation that the recorded inputs do not reproduce is
// refused when read, and never written.
func TestStoredEvaluationMustBeTheReevaluation(t *testing.T) {
	p, closure := frozenPayload(t)
	// The closure used another limit than the one recorded.
	shorter, err := p.Capture.EvaluateAt(p.Capture.Window.Closed, p.EvaluationInputs.Boundaries, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if SameEvaluation(shorter, closure) {
		t.Fatal("the limit does not matter to this capture")
	}
	doc, err := ReadCapture(encodeV3(t, p), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := json.Marshal(shorter)
	if _, err := ReadSnapshot(doc, installedReaders, stored); err == nil || !strings.Contains(err.Error(), "not the re-evaluation") {
		t.Fatalf("a stored evaluation of other inputs was read: %v", err)
	}
	req := exportReq(t, p.Capture, shorter, repo(t))
	req.Inputs = &p.EvaluationInputs
	if _, err := Export(t.Context(), req); err == nil || !strings.Contains(err.Error(), "do not reproduce") {
		t.Fatalf("a package recorded inputs its evaluation was not made with: %v", err)
	}
}

// With inputs, export writes the payload 3 envelope; without, the version
// 2 document exactly as before.
func TestExportWritesPayload3OnlyWithInputs(t *testing.T) {
	p, closure := frozenPayload(t)
	legacy := exportReq(t, p.Capture, closure, repo(t))
	if _, err := Export(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(legacy.Out, CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := CaptureVersion(raw); err != nil || v != CaptureV2Version {
		t.Fatalf("without inputs: version %d %v", v, err)
	}
	if !bytes.Contains(raw, []byte("\n  \"version\": 2,")) {
		t.Fatal("the version 2 document is no longer written as before")
	}
	req := exportReq(t, p.Capture, closure, repo(t))
	req.Inputs = &p.EvaluationInputs
	d, err := Export(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(req.Out, CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Header.PayloadVersion != CaptureV3Version {
		t.Fatalf("with inputs: %s", doc.Header)
	}
	ev, err := os.ReadFile(filepath.Join(req.Out, EvaluationFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSnapshot(doc, installedReaders, ev); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(req.Out); err != nil {
		t.Fatal(err)
	}
	// The descriptor is the same either way: the inputs are the capture's.
	if d.Evidence != closure.Evidence || d.Outcomes != closure.Outcomes || d.Window != (publication.Window{Started: p.Capture.Window.Started, Closed: p.Capture.Window.Closed}) {
		t.Fatalf("descriptor %+v", d)
	}
}

// A namespace projection keeps only its own workloads' boundaries, and the
// projected payload 3 validates as that namespace's extract.
func TestProjectedPayload3KeepsOnlyItsBoundaries(t *testing.T) {
	c, _ := mixedCapture(t)
	var bs []Boundary
	for _, w := range c.Workloads {
		bs = append(bs, Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: c.Window.Started.Add(-time.Hour)})
	}
	doc, err := ReadCapture(encodeV3(t, CaptureV3{Version: CaptureV3Version, Capture: c, EvaluationInputs: FreezeEvaluationInputs(maxAge, bs)}), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	ns := projection.Scope{Name: "shop-dev", UID: "uid-shop-dev"}
	projected, err := doc.ProjectNamespace(ns, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(projected.Payload), "pod-prod") {
		t.Fatal("the projection discloses a sibling workload's boundary")
	}
	frozen, err := projected.Frozen()
	if err != nil {
		t.Fatal(err)
	}
	if len(frozen.EvaluationInputs.Boundaries) != 1 || frozen.EvaluationInputs.Boundaries[0].WorkloadUID != "pod-dev" {
		t.Fatalf("projected boundaries %+v", frozen.EvaluationInputs.Boundaries)
	}
	if err := projected.ValidateNamespace(ns, nil); err != nil {
		t.Fatal(err)
	}
}
