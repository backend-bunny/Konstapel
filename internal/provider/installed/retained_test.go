package installed_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// The maximum evidence age of the chart's defaults.
const retainedMaxEvidenceAge = 2 * time.Hour

// retainedInterpretation is how this build interprets one saved capture.
type retainedInterpretation struct {
	Capture  string `json:"capture"`
	SHA256   string `json:"sha256"`
	Evidence any    `json:"evidence"`
	Outcomes any    `json:"outcomes"`
}

// retainedInterpretations reads every saved legacy capture through the
// capture boundary with the production registry and evaluates it with the
// evaluator its version implies, as replay and package validation do: the
// prototype capture with assessment.Reconcile, the controller capture with
// CaptureV2.Evaluate. Neither file is rewritten.
func retainedInterpretations(t *testing.T) []retainedInterpretation {
	t.Helper()
	r := installed.Registry()
	var out []retainedInterpretation
	for _, path := range []string{"testdata/capture.json", "testdata/assessments/kyverno-1.19.2-background/capture.json"} {
		file := filepath.Join(repoRoot(t), path)
		raw, err := os.ReadFile(file)
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
		h := sha256.Sum256(raw)
		got := retainedInterpretation{Capture: path, SHA256: hex.EncodeToString(h[:])}
		switch doc.Header.PayloadVersion {
		case 1:
			var c assessment.Capture
			if err := json.Unmarshal(doc.Payload, &c); err != nil {
				t.Fatal(err)
			}
			ev, _, err := assessment.Reconcile(c)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			outcomes := map[string]int{}
			for _, e := range ev.Evaluations {
				outcomes[e.Normalized]++
			}
			got.Evidence = map[string]any{"complete": ev.Complete, "missing": len(ev.Missing), "rejected": len(ev.Rejected)}
			got.Outcomes = outcomes
		case 2:
			c, err := doc.V2()
			if err != nil {
				t.Fatal(err)
			}
			ev, err := c.Evaluate(nil, retainedMaxEvidenceAge)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			got.Evidence, got.Outcomes = ev.Evidence, ev.Outcomes
		default:
			t.Fatalf("%s: payload %d", path, doc.Header.PayloadVersion)
		}
		if after, err := os.ReadFile(file); err != nil || string(after) != string(raw) {
			t.Fatalf("%s was rewritten by reading it", path)
		}
		out = append(out, got)
	}
	return out
}

// earlierReader is what one reader of the earlier releases does with an
// envelope.
type earlierReader struct {
	Reader string `json:"reader"`
	Error  string `json:"error"`
}

// earlierReaders hands a Kyverno envelope of the saved CaptureV2 to every
// capture reader of the earlier releases (up to 0.3.0). They are the
// legacy functions this build keeps unchanged, so each refusal is what a
// rolled-back controller, storage backend or prototype reports. Every one
// must refuse: none reads the envelope as an empty Kyverno capture.
func earlierReaders(t *testing.T) []earlierReader {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata/assessments/kyverno-1.19.2-background/capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: kyverno.Contract, PayloadVersion: 2, EvaluatorVersion: 1, Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	refused := func(reader string, err error) earlierReader {
		if err == nil {
			t.Errorf("%s accepts the envelope", reader)
			return earlierReader{Reader: reader}
		}
		return earlierReader{Reader: reader, Error: err.Error()}
	}
	var v2 collector.CaptureV2
	if err := json.Unmarshal(env, &v2); err != nil {
		t.Fatal(err)
	}
	var v1 assessment.Capture
	if err := json.Unmarshal(env, &v1); err != nil {
		t.Fatal(err)
	}
	_, versionErr := collector.CaptureVersion(env)
	_, evaluateErr := v2.Evaluate(nil, retainedMaxEvidenceAge)
	_, _, reconcileErr := assessment.Reconcile(v1)
	return []earlierReader{
		refused("collector.CaptureVersion", versionErr),
		refused("CaptureV2.Validate", v2.Validate()),
		refused("CaptureV2.Evaluate", evaluateErr),
		refused("assessment.Reconcile", reconcileErr),
	}
}

// earlierReadersOfPayload3 is what every reader before payload 3 does with
// one: the readers of 0.3.0 and earlier, the envelope readers of the
// unreleased builds before it (the Kyverno descriptor read payloads 1 and
// 2), and this build's own payload 2 reader. Each refuses it; none reads
// it as payload 2 and ignores the inputs.
func earlierReadersOfPayload3(t *testing.T) []earlierReader {
	t.Helper()
	raw := payload3(t)
	refused := func(reader string, err error) earlierReader {
		if err == nil {
			t.Errorf("%s accepts a payload 3", reader)
			return earlierReader{Reader: reader}
		}
		return earlierReader{Reader: reader, Error: err.Error()}
	}
	var v2 collector.CaptureV2
	if err := json.Unmarshal(raw, &v2); err != nil {
		t.Fatal(err)
	}
	_, versionErr := collector.CaptureVersion(raw)
	d := kyverno.Descriptor()
	d.Capture = provider.CaptureCompatibility{Write: collector.CaptureV2Version, Read: []int{1, collector.CaptureV2Version}}
	earlier, err := provider.New(kyverno.Contract, d)
	if err != nil {
		t.Fatal(err)
	}
	_, envelopeErr := collector.ReadCapture(raw, earlier)
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	_, v2Err := doc.V2()
	return []earlierReader{
		refused("collector.CaptureVersion (0.3.0)", versionErr),
		refused("CaptureV2.Validate (0.3.0)", v2.Validate()),
		refused("collector.ReadCapture with Kyverno capture.read [1 2] (builds before payload 3)", envelopeErr),
		refused("CaptureDocument.V2 (this build)", v2Err),
	}
}
