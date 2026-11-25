package kyverno

import (
	"errors"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
)

// Evaluation adapter around the existing Kyverno evaluator
// (add-assessment-provider-contract 4.1). It moves no semantics: the
// freshness, attribution, applicability and summary rules stay
// collector.CaptureV2.EvaluateAt and collector.Tally at EvaluatorVersion.
// What it adds is the shape every caller uses: frozen inputs plus an
// explicit evaluation time, so the current projection (the current
// assessment boundary), a closing run and replay (the frozen closure
// boundary) differ only in the time they pass.

// EvaluationInput is the frozen input of one evaluation: the capture (its
// expected inventory, engine policies, scope changes, stale scopes and
// collected reports), the host's continuity boundaries for its workloads,
// and the binding's evidence-age limit.
type EvaluationInput struct {
	Capture        collector.CaptureV2
	Boundaries     []collector.Boundary
	MaxEvidenceAge time.Duration
}

// Evaluate evaluates in at the explicit time at. It is pure: it reads no
// clock, cluster, registry or engine, so equal inputs and times give equal
// evaluations. Raw Kyverno results are kept on each observation; the
// summary maps warn (and any other unrecognized result) once to unknown,
// never to pass, fail or accepted risk, and counts out-of-scope checks as
// not applicable. A zero time is refused rather than replaced by the
// capture's own closure or the wall clock.
func Evaluate(in EvaluationInput, at time.Time) (collector.Evaluation, error) {
	if at.IsZero() {
		return collector.Evaluation{}, errors.New("an explicit evaluation time is required")
	}
	return in.Capture.EvaluateAt(at, in.Boundaries, in.MaxEvidenceAge)
}
