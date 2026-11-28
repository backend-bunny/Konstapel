package c2p

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Package replay (add-assessment-provider-contract 4.5) keeps two results
// apart: the evaluation stored at closure, which every continuous package
// holds and replay retrieves, and the re-evaluation of the package's frozen
// inputs, which only a package that records them (Kyverno payload 3)
// supports. It reads the package's local files only: no cluster, registry,
// content cache, binding or clock.

// ReevaluationStatus says whether a package's frozen inputs were
// re-evaluated.
type ReevaluationStatus string

const (
	// Recomputed: the package records its evaluation inputs, and
	// re-evaluating them at the recorded closure gave exactly the stored
	// evaluation.
	Recomputed ReevaluationStatus = "Recomputed"
	// Unavailable: the package records no evaluation inputs, so it is not
	// re-evaluated. Its stored evaluation is still retrieved and validated.
	Unavailable ReevaluationStatus = "Unavailable"
)

// Replay is the result of replaying one continuous package.
type Replay struct {
	// Capture is the capture's compatibility identity.
	Capture collector.CaptureHeader
	// Stored is the closure evaluation retrieved from evaluation.json and
	// validated against its capture. It is never recomputed.
	Stored collector.Evaluation
	// Status says whether Recomputed holds a re-evaluation.
	Status ReevaluationStatus
	// Recomputed is the re-evaluation of the frozen inputs, nil when
	// Status is Unavailable.
	Recomputed *collector.Evaluation
	// Inputs are the frozen inputs Recomputed was evaluated with, nil when
	// Status is Unavailable.
	Inputs *collector.EvaluationInputs
	// EvaluatedAt is the recorded closure, the time of both evaluations.
	EvaluatedAt time.Time
	// Reason explains an Unavailable status. It wraps
	// collector.ErrReevaluationUnavailable.
	Reason error
}

// ReplayPackage replays the continuous package in dir: its files must be
// exactly those its descriptor inventories, its capture a Kyverno payload 2
// or 3 read through the capture boundary with the production registry and
// its recorded evaluator, and evaluation.json one evaluation of that
// capture. A payload 3 is re-evaluated from its frozen inputs alone and
// must reproduce the stored evaluation exactly; anything else is an error.
// A payload 2 records no inputs: the replay returns its stored evaluation
// with status Unavailable, never a recomputation with inputs from
// elsewhere.
func ReplayPackage(dir string) (Replay, error) {
	d, err := publication.LoadDescriptor(dir)
	if err != nil {
		return Replay{}, err
	}
	if err := publication.VerifyDir(dir, d); err != nil {
		return Replay{}, err
	}
	readers := installed.Registry()
	raw, err := os.ReadFile(filepath.Join(dir, collector.CaptureFile))
	if err != nil {
		return Replay{}, err
	}
	doc, err := collector.ReadCapture(raw, readers)
	if err != nil {
		return Replay{}, err
	}
	if !doc.Continuous() {
		return Replay{}, fmt.Errorf("%w: %s is not a continuous package's capture", collector.ErrUnsupportedCapture, doc.Header)
	}
	ev, err := os.ReadFile(filepath.Join(dir, collector.EvaluationFile))
	if err != nil {
		return Replay{}, err
	}
	// ReadSnapshot also requires a payload 3's stored evaluation to be the
	// re-evaluation of its inputs.
	s, err := collector.ReadSnapshot(doc, readers, ev)
	if err != nil {
		return Replay{}, err
	}
	out := Replay{Capture: doc.Header, Stored: s.Evaluation, EvaluatedAt: s.Capture.Window.Closed}
	again, err := doc.Reevaluate(readers)
	switch {
	case errors.Is(err, collector.ErrReevaluationUnavailable):
		out.Status, out.Reason = Unavailable, err
		return out, nil
	case err != nil:
		return Replay{}, err
	}
	frozen, err := doc.Frozen()
	if err != nil {
		return Replay{}, err
	}
	out.Status, out.Recomputed, out.Inputs = Recomputed, &again, &frozen.EvaluationInputs
	return out, nil
}

// ReplayReport is the JSON form of a Replay that `konstapel replay`
// prints: the stored evaluation and the re-evaluation in separate fields,
// so a stored result is never presented as a recomputed one.
type ReplayReport struct {
	Capture collector.CaptureHeader `json:"capture"`
	// EvaluatedAt is the recorded closure.
	EvaluatedAt  time.Time          `json:"evaluatedAt"`
	Stored       StoredReport       `json:"stored"`
	Reevaluation ReevaluationReport `json:"reevaluation"`
}

// StoredReport summarizes the evaluation stored at closure.
type StoredReport struct {
	// Source is the package file the evaluation was retrieved from.
	Source   string                      `json:"source"`
	Evidence publication.EvidenceSummary `json:"evidence"`
	Outcomes publication.OutcomeCounts   `json:"outcomes"`
}

// ReevaluationReport summarizes the re-evaluation, or says why there is
// none.
type ReevaluationReport struct {
	Status ReevaluationStatus `json:"status"`
	// Reason is set when Status is Unavailable.
	Reason string `json:"reason,omitempty"`
	// MaxEvidenceAge and Boundaries are the frozen inputs used: the limit
	// and the number of continuity boundaries.
	MaxEvidenceAge string `json:"maxEvidenceAge,omitempty"`
	Boundaries     *int   `json:"boundaries,omitempty"`
	// Equivalent reports that the re-evaluation equals the stored
	// evaluation; a replay that does not is an error, not a report.
	Equivalent *bool                        `json:"equivalent,omitempty"`
	Evidence   *publication.EvidenceSummary `json:"evidence,omitempty"`
	Outcomes   *publication.OutcomeCounts   `json:"outcomes,omitempty"`
}

// Report is the replay's JSON form.
func (r Replay) Report() ReplayReport {
	out := ReplayReport{Capture: r.Capture, EvaluatedAt: r.EvaluatedAt,
		Stored:       StoredReport{Source: collector.EvaluationFile, Evidence: r.Stored.Evidence, Outcomes: r.Stored.Outcomes},
		Reevaluation: ReevaluationReport{Status: r.Status}}
	switch {
	case r.Status == Recomputed && r.Recomputed != nil && r.Inputs != nil:
		n, same := len(r.Inputs.Boundaries), collector.SameEvaluation(*r.Recomputed, r.Stored)
		ev, oc := r.Recomputed.Evidence, r.Recomputed.Outcomes
		out.Reevaluation.MaxEvidenceAge, out.Reevaluation.Boundaries = r.Inputs.MaxEvidenceAge, &n
		out.Reevaluation.Equivalent, out.Reevaluation.Evidence, out.Reevaluation.Outcomes = &same, &ev, &oc
	case r.Reason != nil:
		out.Reevaluation.Reason = r.Reason.Error()
	}
	return out
}
