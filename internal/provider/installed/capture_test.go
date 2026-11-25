package installed_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// The saved legacy captures: the prototype's (version 1) and a live
// Kyverno 1.19.2 controller capture (version 2).
var legacyCaptures = map[string]int{
	"testdata/capture.json": 1,
	"testdata/assessments/kyverno-1.19.2-background/capture.json": 2,
}

// The collector's implied legacy identity is the installed Kyverno
// provider's, and the production registry reads and evaluates every saved
// legacy capture. When the Kyverno evaluator changes, this fails until
// evaluator 1 stays installed: retained captures are never evaluated with
// newer semantics, and never silently dropped.
func TestProductionRegistryReadsLegacyCaptures(t *testing.T) {
	d := kyverno.Descriptor()
	if collector.LegacyProvider != kyverno.Contract || collector.LegacyEvaluatorVersion != d.EvaluatorVersion {
		t.Fatalf("legacy captures imply %s evaluator %d; the installed Kyverno provider is %s evaluator %d",
			collector.LegacyProvider, collector.LegacyEvaluatorVersion, kyverno.Contract, d.EvaluatorVersion)
	}
	// Readers before writers: the controller writes a legacy version, which
	// every release reads, and never the envelope this build only reads.
	if d.Capture.Write != collector.CaptureV2Version || d.Capture.Write == collector.CaptureEnvelopeVersion {
		t.Fatalf("the Kyverno provider writes %d", d.Capture.Write)
	}
	r := installed.Registry()
	for path, version := range legacyCaptures {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := collector.ReadCapture(raw, r)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := doc.CheckEvaluator(r); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if doc.Header.Provider != kyverno.Contract || doc.Header.PayloadVersion != version || !slices.Contains(d.Capture.Read, version) {
			t.Fatalf("%s: %+v", path, doc.Header)
		}
	}
}

// Against the production registry, an envelope fails with the registry's
// reason for each dimension, and an envelope without a provider never
// falls back to the registry default.
func TestProductionRegistryRejectsUnsupportedCaptures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata/assessments/kyverno-1.19.2-background/capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	env := func(contract string, payload, evaluator int) []byte {
		b, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: contract, PayloadVersion: payload, EvaluatorVersion: evaluator, Payload: raw})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r := installed.Registry()
	for name, tc := range map[string]struct {
		raw    []byte
		reason provider.SelectionReason
	}{
		"test-only provider":        {env("konstapel-reporttest/v1", 1, 1), provider.ReasonUnknownProvider},
		"unknown provider":          {env("example-scanner/v1", 1, 1), provider.ReasonUnknownProvider},
		"another Kyverno contract":  {env("konstapel-kyverno/v2", 2, 1), provider.ReasonIncompatibleVersion},
		"unknown Kyverno payload":   {env(kyverno.Contract, 3, 1), provider.ReasonIncompatibleVersion},
		"malformed contract":        {env("./konstapel-provider", 2, 1), provider.ReasonInvalidSelection},
		"no provider, not defaults": {env("", 2, 1), ""},
	} {
		_, err := collector.ReadCapture(tc.raw, r)
		var serr *provider.SelectionError
		switch {
		case !errors.Is(err, collector.ErrUnsupportedCapture):
			t.Errorf("%s: read (%v)", name, err)
		case tc.reason != "" && (!errors.As(err, &serr) || serr.Reason != tc.reason):
			t.Errorf("%s: %v, want %s", name, err, tc.reason)
		}
	}
	doc, err := collector.ReadCapture(env(kyverno.Contract, 2, 2), r)
	if err != nil {
		t.Fatalf("evaluator 2 is a separate dimension; the payload is readable: %v", err)
	}
	var serr *provider.SelectionError
	if err := doc.CheckEvaluator(r); !errors.As(err, &serr) || serr.Reason != provider.ReasonIncompatibleVersion {
		t.Fatalf("evaluator 2 accepted by the production registry: %v", err)
	}
}

// documentedCapture is one capture of the guide's capture examples.
type documentedCapture struct {
	Capture string                   `json:"capture"`
	Header  *collector.CaptureHeader `json:"header,omitempty"`
	Error   string                   `json:"error,omitempty"`
}

// captureExamples reads the saved legacy captures and envelopes of the
// saved CaptureV2 through the boundary with the production registry, as the
// storage backend's package validation does.
func captureExamples(t *testing.T) (read, rejected []documentedCapture) {
	t.Helper()
	const v2 = "testdata/assessments/kyverno-1.19.2-background/capture.json"
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), v2))
	if err != nil {
		t.Fatal(err)
	}
	env := func(contract string, payload, evaluator int) []byte {
		b, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: contract, PayloadVersion: payload, EvaluatorVersion: evaluator, Payload: raw})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r := installed.Registry()
	readAll := func(name string, b []byte) documentedCapture {
		doc, err := collector.ReadCapture(b, r)
		if err == nil {
			err = doc.CheckEvaluator(r)
		}
		if err != nil {
			return documentedCapture{Capture: name, Error: err.Error()}
		}
		return documentedCapture{Capture: name, Header: &doc.Header}
	}
	for _, path := range []string{"testdata/capture.json", v2} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatal(err)
		}
		read = append(read, readAll(path, b))
	}
	read = append(read, readAll("Kyverno envelope of "+v2, env(kyverno.Contract, 2, 1)))
	rejected = []documentedCapture{
		readAll("version 4", []byte(`{"version":4}`)),
		readAll("version 2 with an evaluatorVersion", append(raw[:len(raw)-2:len(raw)-2], []byte(`,"evaluatorVersion":2}`)...)),
		readAll("envelope of konstapel-reporttest/v1", env("konstapel-reporttest/v1", 1, 1)),
		readAll("envelope of Kyverno payload 3", env(kyverno.Contract, 3, 1)),
		readAll("envelope of Kyverno evaluator 2", env(kyverno.Contract, 2, 2)),
	}
	return read, rejected
}
