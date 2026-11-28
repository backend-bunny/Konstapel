package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Package inputs for semantic re-evaluation (add-assessment-provider-contract
// 4.5). A closing run evaluates its capture with two inputs the capture does
// not hold: the host's continuity boundaries for the frozen workload states
// and the binding's effective evidence-age limit. Kyverno payload 3 records
// both, frozen at the run's closure next to the capture they were used
// with, so a package alone re-evaluates to its closure evaluation.
//
// Payload 3 is a payload version, not optional fields: readers that predate
// it refuse it explicitly. 0.3.0 and earlier read only capture documents 1
// and 2, so they refuse the envelope that carries it. The unreleased builds
// that read envelopes check the payload version against the Kyverno
// descriptor's capture.read ([1 2]), so they refuse payload 3 as an
// incompatible version. Neither reads it as payload 2 and ignores the
// inputs. Payload 3 exists only inside an envelope (CaptureEnvelopeVersion).

// CaptureV3Version is the Kyverno payload that records the capture's frozen
// evaluation inputs: a CaptureV2 document and the EvaluationInputs its
// closure evaluation used.
const CaptureV3Version = 3

// ErrReevaluationUnavailable marks a capture that records no frozen
// evaluation inputs: every Kyverno capture before payload 3. Its stored
// closure evaluation can still be retrieved, validated and converted;
// re-evaluating it would need inputs from outside the package (the current
// binding configuration, the current time or reconstructed continuity), so
// it is never recomputed.
var ErrReevaluationUnavailable = errors.New("re-evaluation unavailable")

// EvaluationInputs are the inputs of a closure evaluation that the capture
// does not hold, frozen at closure: the effective evidence-age limit of the
// binding and the continuity boundaries the host passed for the frozen
// workload states. The evaluation time is the capture's Window.Closed.
type EvaluationInputs struct {
	// MaxEvidenceAge is the effective limit, as time.Duration.String
	// writes it (for example "2h0m0s").
	MaxEvidenceAge string `json:"maxEvidenceAge"`
	// Boundaries are exactly the boundaries the closure evaluation was
	// given, at most one per frozen workload and only for the state the
	// capture froze. Empty when the host had none; never absent.
	Boundaries []Boundary `json:"boundaries"`
}

// FreezeEvaluationInputs records the inputs a closure evaluation is given.
// The boundaries are copied.
func FreezeEvaluationInputs(maxEvidenceAge time.Duration, boundaries []Boundary) EvaluationInputs {
	b := make([]Boundary, len(boundaries))
	copy(b, boundaries)
	return EvaluationInputs{MaxEvidenceAge: maxEvidenceAge.String(), Boundaries: b}
}

// Age returns the recorded evidence-age limit. Only a positive duration in
// its canonical form is accepted, so a limit has exactly one recording.
func (in EvaluationInputs) Age() (time.Duration, error) {
	d, err := time.ParseDuration(in.MaxEvidenceAge)
	if err != nil || d <= 0 || d.String() != in.MaxEvidenceAge {
		return 0, fmt.Errorf("maxEvidenceAge %q is not a positive duration in canonical form", in.MaxEvidenceAge)
	}
	return d, nil
}

// validate checks the inputs against the capture they were frozen with:
// a canonical limit, a boundaries list (possibly empty), and every
// boundary naming a distinct frozen workload in the state the capture
// froze, with a time. A boundary for any other workload or state was never
// used by the closure, and in a namespace package it would disclose a
// workload outside the namespace.
func (in EvaluationInputs) validate(c CaptureV2) error {
	if _, err := in.Age(); err != nil {
		return err
	}
	if in.Boundaries == nil {
		return errors.New("boundaries must be recorded, as an empty list when there are none")
	}
	states := map[string]string{}
	for _, w := range c.Workloads {
		states[w.UID] = w.StateSHA256
	}
	seen := map[string]bool{}
	for i, b := range in.Boundaries {
		state, ok := states[b.WorkloadUID]
		switch {
		case !ok:
			return fmt.Errorf("boundaries[%d] names a workload the capture did not freeze", i)
		case b.StateSHA256 != state:
			return fmt.Errorf("boundaries[%d] is for another state than the capture froze", i)
		case seen[b.WorkloadUID]:
			return fmt.Errorf("boundaries[%d] repeats a workload", i)
		case b.Since.IsZero():
			return fmt.Errorf("boundaries[%d] has no time", i)
		}
		seen[b.WorkloadUID] = true
	}
	return nil
}

// CaptureV3 is Kyverno payload 3: a closed CaptureV2 document, unchanged,
// and the evaluation inputs its closure evaluation used.
type CaptureV3 struct {
	Version          int              `json:"version"`
	Capture          CaptureV2        `json:"capture"`
	EvaluationInputs EvaluationInputs `json:"evaluationInputs"`
}

// Validate checks the payload version, that the capture is a valid, closed
// CaptureV2, and that the inputs belong to it.
func (p CaptureV3) Validate() error {
	if p.Version != CaptureV3Version {
		return fmt.Errorf("payload version %d is not %d", p.Version, CaptureV3Version)
	}
	if err := p.Capture.Validate(); err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	if p.Capture.Window.Closed.IsZero() {
		return errors.New("capture: the window is not closed")
	}
	if err := p.EvaluationInputs.validate(p.Capture); err != nil {
		return fmt.Errorf("evaluationInputs: %w", err)
	}
	return nil
}

// Reevaluate evaluates the frozen capture with its frozen inputs at its
// closure, with evaluator 1 (CaptureV2.EvaluateAt, which the Kyverno
// provider's Evaluate adapter calls). It takes no limit, boundaries or time:
// replay never substitutes the current binding configuration, the current
// time or reconstructed continuity for what the package recorded.
func (p CaptureV3) Reevaluate() (Evaluation, error) {
	if err := p.Validate(); err != nil {
		return Evaluation{}, err
	}
	age, err := p.EvaluationInputs.Age()
	if err != nil {
		return Evaluation{}, err
	}
	return p.Capture.EvaluateAt(p.Capture.Window.Closed, p.EvaluationInputs.Boundaries, age)
}

// EncodeCaptureV3 writes the version 3 envelope of a Kyverno payload 3 for
// the given evaluator version. The payload is validated first; it reads back
// through ReadCapture only with readers of payload 3.
func EncodeCaptureV3(p CaptureV3, evaluatorVersion int) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("capture payload %d: %w", CaptureV3Version, err)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return EncodeEnvelope(CaptureHeader{Provider: LegacyProvider, PayloadVersion: CaptureV3Version, EvaluatorVersion: evaluatorVersion}, payload)
}

// KyvernoCapture returns the CaptureV2 of a controller capture: a Kyverno
// payload 2 (legacy document or envelope) or the capture a payload 3
// records. It is for structural readers (package verification, content
// use, namespace projection, snapshot validation). Evaluating it with
// inputs from elsewhere would ignore what a payload 3 records: evaluate a
// payload 3 through Frozen and CaptureV3.Reevaluate.
func (d CaptureDocument) KyvernoCapture() (CaptureV2, error) {
	if d.Header.Provider == LegacyProvider && d.Header.PayloadVersion == CaptureV3Version {
		if d.v3 == nil {
			return CaptureV2{}, fmt.Errorf("%w: %s was not read through ReadCapture", ErrUnsupportedCapture, d.Header)
		}
		return d.v3.Capture, nil
	}
	return d.V2()
}

// Continuous reports whether the capture is a controller capture: Kyverno
// payload 2 or 3.
func (d CaptureDocument) Continuous() bool {
	return d.Header.Provider == LegacyProvider && (d.Header.PayloadVersion == CaptureV2Version || d.Header.PayloadVersion == CaptureV3Version)
}

// Frozen returns the capture's frozen evaluation inputs with the capture
// they belong to. A Kyverno payload 1 or 2 capture records none and is an
// ErrReevaluationUnavailable; another provider's capture has no
// re-evaluation in this build (ErrUnsupportedCapture).
func (d CaptureDocument) Frozen() (CaptureV3, error) {
	h := d.Header
	switch {
	case h.Provider != LegacyProvider:
		return CaptureV3{}, fmt.Errorf("%w: %s has no package re-evaluation in this build", ErrUnsupportedCapture, h)
	case h.PayloadVersion == CaptureV3Version && d.v3 != nil:
		return *d.v3, nil
	case h.PayloadVersion == CaptureV3Version:
		return CaptureV3{}, fmt.Errorf("%w: %s was not read through ReadCapture", ErrUnsupportedCapture, h)
	default:
		return CaptureV3{}, fmt.Errorf("%w: %s records no frozen evaluation inputs (continuity boundaries and maxEvidenceAge); "+
			"its stored evaluation can be retrieved, not recomputed", ErrReevaluationUnavailable, h)
	}
}

// Reevaluate re-evaluates a capture from its frozen inputs alone, after
// checking that its recorded evaluator is installed. A capture without
// frozen inputs is an ErrReevaluationUnavailable.
func (d CaptureDocument) Reevaluate(readers CaptureReaders) (Evaluation, error) {
	if err := d.CheckEvaluator(readers); err != nil {
		return Evaluation{}, err
	}
	p, err := d.Frozen()
	if err != nil {
		return Evaluation{}, err
	}
	if d.Header.EvaluatorVersion != LegacyEvaluatorVersion {
		return Evaluation{}, fmt.Errorf("%w: %s: only evaluator %d re-evaluates a payload %d", ErrUnsupportedCapture, d.Header, LegacyEvaluatorVersion, CaptureV3Version)
	}
	return p.Reevaluate()
}

// SameEvaluation reports whether two evaluations are the same: the same
// observations (keys, states, outcomes, attribution, evaluation times and
// reasons), summaries and next expiry, compared in their JSON form.
func SameEvaluation(a, b Evaluation) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

// project keeps the boundaries of the projected capture's workloads.
func (in EvaluationInputs) project(c CaptureV2) EvaluationInputs {
	frozen := map[string]bool{}
	for _, w := range c.Workloads {
		frozen[w.UID] = true
	}
	out := EvaluationInputs{MaxEvidenceAge: in.MaxEvidenceAge, Boundaries: []Boundary{}}
	for _, b := range in.Boundaries {
		if frozen[b.WorkloadUID] {
			out.Boundaries = append(out.Boundaries, b)
		}
	}
	return out
}
