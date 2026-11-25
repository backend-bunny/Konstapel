package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// readers stands in for the installed provider registry (the production
// registry's own tests are in internal/provider/installed): each contract
// reads some payload versions and evaluates with one evaluator version.
type readers map[string]struct {
	payloads  []int
	evaluator int
}

func (r readers) CheckCapture(contract string, v int) error {
	p, ok := r[contract]
	switch {
	case !ok:
		return fmt.Errorf("provider %q is not installed", contract)
	case !slices.Contains(p.payloads, v):
		return fmt.Errorf("%s reads payloads %v, not %d", contract, p.payloads, v)
	}
	return nil
}

func (r readers) CheckEvaluator(contract string, v int) error {
	p, ok := r[contract]
	switch {
	case !ok:
		return fmt.Errorf("provider %q is not installed", contract)
	case p.evaluator != v:
		return fmt.Errorf("%s evaluates with %d, not %d", contract, p.evaluator, v)
	}
	return nil
}

const posture = "example-posture/v1"

// installedReaders mirrors this build: Kyverno reads its payloads 1 and 2
// with evaluator 1, and another provider reads its own payload 1.
var installedReaders = readers{LegacyProvider: {[]int{1, 2}, 1}, posture: {[]int{1}, 1}}

// The saved legacy captures, pinned by digest: a retained capture is never
// rewritten to suit a reader.
const (
	prototypeFixture = "testdata/capture.json"
	v2Fixture        = "testdata/assessments/kyverno-1.19.2-background/capture.json"
)

var fixtureDigests = map[string]string{
	prototypeFixture: "d7bb94aa5dc968ae6951e4a806ddb7349d163ba0700fcd5613ec03ae505546e8",
	v2Fixture:        "b6dfee9fba0d6f1f7f9a847e8d7fb822c890f90a8e6d7a2ee24565a0b5364a5f",
}

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo(t), path))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if got := hex.EncodeToString(h[:]); got != fixtureDigests[path] {
		t.Fatalf("%s changed (sha256 %s): saved captures are never rewritten", path, got)
	}
	return raw
}

func envelope(t *testing.T, provider string, payloadVersion, evaluatorVersion int, payload []byte) []byte {
	t.Helper()
	b, err := json.Marshal(CaptureEnvelope{Version: CaptureEnvelopeVersion, Provider: provider, PayloadVersion: payloadVersion, EvaluatorVersion: evaluatorVersion, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// edit decodes a JSON object, applies f to it and encodes it again.
func edit(t *testing.T, raw []byte, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(x, y)
}

// Supported legacy captures read through the boundary exactly as before:
// their provider, payload and evaluator are implied by the version, their
// bytes are the payload, and the saved CaptureV2 decodes and evaluates
// identically to the direct path every earlier reader used.
func TestLegacyCapturesReadUnchanged(t *testing.T) {
	for path, want := range map[string]CaptureHeader{
		prototypeFixture: {Version: 1, Provider: LegacyProvider, PayloadVersion: 1, EvaluatorVersion: LegacyEvaluatorVersion},
		v2Fixture:        {Version: 2, Provider: LegacyProvider, PayloadVersion: 2, EvaluatorVersion: LegacyEvaluatorVersion},
	} {
		t.Run(path, func(t *testing.T) {
			raw := fixture(t, path)
			doc, err := ReadCapture(raw, installedReaders)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Header != want || !doc.Header.Legacy() || !bytes.Equal(doc.Payload, raw) {
				t.Fatalf("header %+v (want %+v), payload is the document: %t", doc.Header, want, bytes.Equal(doc.Payload, raw))
			}
			if err := doc.CheckEvaluator(installedReaders); err != nil {
				t.Fatalf("legacy evaluator not accepted: %v", err)
			}
			if want.Version == 1 {
				if _, err := doc.V2(); !errors.Is(err, ErrUnsupportedCapture) {
					t.Fatalf("the prototype capture read as a CaptureV2: %v", err)
				}
				return
			}
			got, err := doc.V2()
			if err != nil {
				t.Fatal(err)
			}
			var direct CaptureV2
			if err := json.Unmarshal(raw, &direct); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, direct) || !sameJSON(t, got, direct) {
				t.Fatal("the boundary decodes the saved CaptureV2 differently from the direct path")
			}
			ev, err := got.Evaluate(nil, 2*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			before, err := direct.Evaluate(nil, 2*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if !sameJSON(t, ev, before) {
				t.Fatal("evaluation through the boundary differs from the direct path")
			}
			e, o := ev.Evidence, ev.Outcomes
			if e.Expected != 30 || e.Attributable != 28 || e.Missing != 2 || e.Completeness != publication.Incomplete || o.Pass != 24 || o.Fail != 4 {
				t.Fatalf("saved evidence evaluates to %+v %+v", e, o)
			}
			fixture(t, path) // reading wrote nothing
		})
	}
}

// A legacy document is decoded with the same lenient decoding as before the
// envelope: a field this build does not know is ignored, as every earlier
// reader ignored it. Only the envelope's own fields are refused.
func TestLegacyDecodingIsNotTightened(t *testing.T) {
	raw := edit(t, fixture(t, v2Fixture), func(m map[string]any) { m["notesFromAnOlderBuild"] = "kept as before" })
	doc, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.V2(); err != nil {
		t.Fatalf("a legacy capture with an unknown field is no longer read: %v", err)
	}
}

// The Kyverno envelope of payload 2 holds a CaptureV2 document verbatim and
// reads to the same capture and evaluation as the legacy document.
func TestKyvernoEnvelopeReadsLikeTheLegacyDocument(t *testing.T) {
	raw := fixture(t, v2Fixture)
	doc, err := ReadCapture(envelope(t, LegacyProvider, 2, 1, raw), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if want := (CaptureHeader{Version: 3, Provider: LegacyProvider, PayloadVersion: 2, EvaluatorVersion: 1}); doc.Header != want || doc.Header.Legacy() {
		t.Fatalf("header %+v", doc.Header)
	}
	got, err := doc.V2()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	want, err := legacy.V2()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the envelope's payload decodes differently from the legacy document")
	}
	a, err := got.Evaluate(nil, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := want.Evaluate(nil, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, a, b) {
		t.Fatal("the envelope evaluates differently from the legacy document")
	}
}

// Unknown or malformed documents, providers, payloads and versions are
// explicit errors, never an empty or partial capture.
func TestCaptureBoundaryRejectsWhatItDoesNotSupport(t *testing.T) {
	v1, v2 := fixture(t, prototypeFixture), fixture(t, v2Fixture)
	kyverno := func(f func(map[string]any)) []byte {
		return edit(t, envelope(t, LegacyProvider, 2, 1, v2), f)
	}
	payload := func(f func(map[string]any)) []byte {
		return envelope(t, LegacyProvider, 2, 1, edit(t, v2, f))
	}
	for name, raw := range map[string][]byte{
		"not JSON":       []byte(`{"version": 2`),
		"an array":       []byte(`[]`),
		"null":           []byte(`null`),
		"no version":     []byte(`{"cluster": "c"}`),
		"null version":   []byte(`{"version": null}`),
		"string version": []byte(`{"version": "2"}`),
		"version 0":      []byte(`{"version": 0}`),
		"version 4":      []byte(`{"version": 4}`),
		// Older readers ignore unknown fields, so each of these would read
		// as a plain Kyverno capture there: refused here.
		"legacy v2 naming another provider":   edit(t, v2, func(m map[string]any) { m["provider"] = posture }),
		"legacy v2 recording an evaluator":    edit(t, v2, func(m map[string]any) { m["evaluatorVersion"] = 2 }),
		"legacy v2 recording a payload":       edit(t, v2, func(m map[string]any) { m["payloadVersion"] = 3 }),
		"legacy v1 carrying a payload":        edit(t, v1, func(m map[string]any) { m["payload"] = map[string]any{} }),
		"envelope without a provider":         kyverno(func(m map[string]any) { delete(m, "provider") }),
		"envelope with an empty provider":     kyverno(func(m map[string]any) { m["provider"] = "" }),
		"unknown provider":                    kyverno(func(m map[string]any) { m["provider"] = "example-scanner/v1" }),
		"another Kyverno contract":            kyverno(func(m map[string]any) { m["provider"] = "konstapel-kyverno/v2" }),
		"a path as provider":                  kyverno(func(m map[string]any) { m["provider"] = "./konstapel-provider" }),
		"unknown payload version":             kyverno(func(m map[string]any) { m["payloadVersion"] = 3 }),
		"payload version 0":                   kyverno(func(m map[string]any) { m["payloadVersion"] = 0 }),
		"evaluator version 0":                 kyverno(func(m map[string]any) { m["evaluatorVersion"] = 0 }),
		"no evaluator version":                kyverno(func(m map[string]any) { delete(m, "evaluatorVersion") }),
		"no payload":                          kyverno(func(m map[string]any) { delete(m, "payload") }),
		"null payload":                        kyverno(func(m map[string]any) { m["payload"] = nil }),
		"array payload":                       kyverno(func(m map[string]any) { m["payload"] = []any{} }),
		"string payload":                      kyverno(func(m map[string]any) { m["payload"] = "e30=" }),
		"unknown envelope field":              kyverno(func(m map[string]any) { m["cluster"] = "c" }),
		"trailing data":                       append(envelope(t, LegacyProvider, 2, 1, v2), []byte(` {}`)...),
		"Kyverno payload 1 in an envelope":    envelope(t, LegacyProvider, 1, 1, v1),
		"a CaptureV2 labeled payload 1":       envelope(t, LegacyProvider, 1, 1, v2),
		"payload of another version":          payload(func(m map[string]any) { m["version"] = 3 }),
		"payload with an unknown field":       payload(func(m map[string]any) { m["providerData"] = map[string]any{} }),
		"payload that is not a CaptureV2":     payload(func(m map[string]any) { m["expected"] = m["expected"].([]any)[1:] }),
		"payload with a wrongly typed field":  payload(func(m map[string]any) { m["checks"] = "none" }),
		"posture payload of another version":  envelope(t, posture, 2, 1, []byte(`{"subjects": []}`)),
		"posture payload that is not encoded": edit(t, envelope(t, posture, 1, 1, []byte(`{}`)), func(m map[string]any) { m["payload"] = 1 }),
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := ReadCapture(raw, installedReaders)
			if !errors.Is(err, ErrUnsupportedCapture) {
				t.Fatalf("accepted as %+v (%v)", doc.Header, err)
			}
			if doc.Header != (CaptureHeader{}) || doc.Payload != nil {
				t.Fatalf("a rejected capture still returned %+v", doc.Header)
			}
			if _, err := readCaptureV2(raw); err == nil {
				t.Fatal("package verification reads it as a CaptureV2")
			}
		})
	}
	if _, err := ReadCapture(v2, nil); !errors.Is(err, ErrUnsupportedCapture) {
		t.Fatalf("read without installed providers: %v", err)
	}
}

// Another provider's payload passes the shared boundary as read: it is not
// forced into Kyverno's shape, and no Kyverno reader accepts it.
func TestOtherProvidersPayloadsStayTheirs(t *testing.T) {
	payload := []byte(`{"subjects":[{"image":"registry.example/app@sha256:` + strings.Repeat("a", 64) + `"}],"reports":[]}`)
	raw := envelope(t, posture, 1, 1, payload)
	doc, err := ReadCapture(raw, installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Header.Provider != posture || doc.Header.Legacy() || !bytes.Equal(doc.Payload, payload) {
		t.Fatalf("header %+v payload %s", doc.Header, doc.Payload)
	}
	if _, err := doc.V2(); !errors.Is(err, ErrUnsupportedCapture) {
		t.Fatalf("another provider's payload read as a CaptureV2: %v", err)
	}
	if _, err := readCaptureV2(raw); err == nil {
		t.Fatal("package verification reads another provider's payload as a CaptureV2")
	}
}

// The evaluator is a separate dimension: a capture this build can read is
// evaluated only by a provider with the recorded evaluator, never by newer
// semantics.
func TestEvaluatorCompatibility(t *testing.T) {
	v1, v2 := fixture(t, prototypeFixture), fixture(t, v2Fixture)
	later := readers{LegacyProvider: {[]int{1, 2}, 2}}
	for name, raw := range map[string][]byte{"prototype": v1, "legacy v2": v2, "envelope": envelope(t, LegacyProvider, 2, 1, v2)} {
		doc, err := ReadCapture(raw, later)
		if err != nil {
			t.Fatalf("%s: the payload is still readable: %v", name, err)
		}
		if err := doc.CheckEvaluator(later); !errors.Is(err, ErrUnsupportedCapture) {
			t.Errorf("%s: evaluator 1 accepted by a provider that evaluates with 2: %v", name, err)
		}
		if err := doc.CheckEvaluator(installedReaders); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	doc, err := ReadCapture(envelope(t, LegacyProvider, 2, 2, v2), installedReaders)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckEvaluator(installedReaders); !errors.Is(err, ErrUnsupportedCapture) {
		t.Fatalf("evaluator 2 accepted by a build that evaluates with 1: %v", err)
	}
	if err := doc.CheckEvaluator(later); err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckEvaluator(nil); !errors.Is(err, ErrUnsupportedCapture) {
		t.Fatalf("evaluated without installed providers: %v", err)
	}
}

// Readers before writers. The controller writes only the legacy version 2,
// which this build and every earlier release read. The envelope this build
// reads is refused explicitly by the earlier releases' readers, which are
// the unchanged legacy functions in this package, rather than read as an
// empty Kyverno capture. A field appended to version 2 instead would be
// silently ignored by them: the reason version 2 never carries one.
func TestReadersBeforeWriters(t *testing.T) {
	subjects, stale := contractSubjects(t)
	c, err := FreezeScope(subjects[0].Cluster, time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC), "mapping-1", subjects, stale, renderedPolicies(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	written, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadCapture(written, installedReaders)
	if err != nil || doc.Header != (CaptureHeader{Version: 2, Provider: LegacyProvider, PayloadVersion: 2, EvaluatorVersion: LegacyEvaluatorVersion}) {
		t.Fatalf("the written capture reads as %+v (%v)", doc.Header, err)
	}
	if v, err := CaptureVersion(written); err != nil || v != CaptureV2Version {
		t.Fatalf("an earlier release cannot read the written capture: %d %v", v, err)
	}

	env := envelope(t, LegacyProvider, 2, 1, fixture(t, v2Fixture))
	if _, err := CaptureVersion(env); err == nil {
		t.Error("the earlier releases' version dispatch accepts the envelope")
	}
	var asV2 CaptureV2
	if err := json.Unmarshal(env, &asV2); err != nil {
		t.Fatal(err)
	}
	if err := asV2.Validate(); err == nil {
		t.Error("the earlier releases' CaptureV2 validation accepts the envelope")
	}
	if _, err := asV2.Evaluate(nil, 2*time.Hour); err == nil {
		t.Error("the earlier releases' evaluation accepts the envelope")
	}
	var asV1 assessment.Capture
	if err := json.Unmarshal(env, &asV1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := assessment.Reconcile(asV1); err == nil {
		t.Error("the prototype's reconciliation accepts the envelope")
	}

	appended := edit(t, fixture(t, v2Fixture), func(m map[string]any) { m["evaluatorVersion"] = 2 })
	var old CaptureV2
	if err := json.Unmarshal(appended, &old); err != nil || old.Validate() != nil {
		t.Fatalf("expected an earlier reader to ignore the appended field: %v", err)
	}
	if _, err := ReadCapture(appended, installedReaders); !errors.Is(err, ErrUnsupportedCapture) {
		t.Fatalf("an appended evaluator is accepted on version 2: %v", err)
	}
}

// Package verification reads both forms of the Kyverno payload 2, verifies
// an envelope's payload against the packaged content like a legacy capture,
// and refuses anything else. It never rewrites the capture.
func TestPackageVerificationReadsBothForms(t *testing.T) {
	req, d := exported(t)
	path := filepath.Join(req.Out, "capture.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(req.Out); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, raw) {
		t.Fatal("verification rewrote the capture")
	}
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		rehash(t, req.Out, d)
	}
	write(envelope(t, LegacyProvider, 2, 1, raw))
	if err := VerifyPackage(req.Out); err != nil {
		t.Fatalf("a Kyverno envelope package does not verify: %v", err)
	}
	var c CaptureV2
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(tamperExpression(t, c))
	if err != nil {
		t.Fatal(err)
	}
	write(envelope(t, LegacyProvider, 2, 1, tampered))
	if err := VerifyPackage(req.Out); err == nil || !strings.Contains(err.Error(), "differs from the render") {
		t.Fatalf("a tampered envelope payload verified: %v", err)
	}
	for name, b := range map[string][]byte{
		"another provider":  envelope(t, posture, 1, 1, raw),
		"prototype capture": fixture(t, prototypeFixture),
	} {
		write(b)
		if err := VerifyPackage(req.Out); !errors.Is(err, ErrUnsupportedCapture) {
			t.Errorf("%s: verified as a CaptureV2: %v", name, err)
		}
	}
}
