package conformance

import (
	"errors"
	"fmt"
	"slices"
)

// Kind names the conformance rule a violation breaks. Negative tests assert
// the kind, so a deliberate regression must fail for its own reason, not
// merely produce some error.
type Kind string

// Violation kinds of the case and evaluation checks (Check, Verify).
const (
	// KindCase: the case or its golden is malformed (version, provider,
	// evaluation time, input, evidence-age limit).
	KindCase Kind = "case"
	// KindInventory: the inventory cannot be derived or repeats an entry.
	KindInventory Kind = "inventory"
	// KindEvaluate: the adapter fails to evaluate a valid input.
	KindEvaluate Kind = "evaluate"
	// KindNondeterministic: equal inputs and times evaluate differently.
	KindNondeterministic Kind = "nondeterministic"
	// KindUnexpected: an observation outside the expected inventory.
	KindUnexpected Kind = "unexpected-observation"
	// KindDuplicate: an expected observation evaluated twice.
	KindDuplicate Kind = "duplicate-observation"
	// KindDropped: an expected observation was not evaluated.
	KindDropped Kind = "dropped-observation"
	// KindRawOutcome: attributable evidence without its raw outcome.
	KindRawOutcome Kind = "raw-outcome"
	// KindNormalizedOutcome: a normalized outcome outside the summary
	// vocabulary.
	KindNormalizedOutcome Kind = "normalized-outcome"
	// KindNormalization: one raw outcome normalizes two ways.
	KindNormalization Kind = "normalization"
	// KindSourceTime: attributable evidence without a source evaluation
	// time, or with one after the evaluation time.
	KindSourceTime Kind = "source-time"
	// KindStaleEvidence: evidence older than the evidence-age limit is
	// attributable, or stale evidence is reported as Missing.
	KindStaleEvidence Kind = "stale-evidence"
	// KindOutcomeWithoutEvidence: a Missing, Rejected or Unresolved
	// observation carries an outcome.
	KindOutcomeWithoutEvidence Kind = "outcome-without-evidence"
	// KindState: an evidence state outside the shared vocabulary.
	KindState Kind = "state"
	// KindSummary: the evidence summary is invalid.
	KindSummary Kind = "summary"
	// KindIndependence: the inventory changes when evidence is removed.
	KindIndependence Kind = "inventory-from-evidence"
	// KindMissingEvidence: without source evidence (removed from the input,
	// or from the cluster before collection) something is attributable,
	// has an outcome or is complete.
	KindMissingEvidence Kind = "missing-evidence"
	// KindGolden: the result differs from the reviewed golden.
	KindGolden Kind = "golden"
)

// Violation kinds of the lifecycle checks (CheckLifecycle).
const (
	// KindCollection: collection fails, or what it collects from a
	// cluster serving the case's evidence evaluates differently.
	KindCollection Kind = "collection"
	// KindCancellation: a canceled collection returned a result or a
	// limitation instead of the cancellation.
	KindCancellation Kind = "cancellation"
	// KindWrite: collection made a request that changes cluster state.
	KindWrite Kind = "write"
	// KindUnavailableSource: a failing evidence source was not recorded
	// as a limitation, or its absence established an outcome.
	KindUnavailableSource Kind = "unavailable-source"
	// KindReplay: replay of the retained capture failed or evaluates
	// differently from the collection it retained.
	KindReplay Kind = "replay"
	// KindContent: replay with the run's content unavailable did not fail
	// as unavailable content.
	KindContent Kind = "unavailable-content"
)

// Violation kinds of the projection checks (CheckProjection).
const (
	// KindProjection: a namespace extract is refused by the shared check,
	// discloses another namespace's observations, changes results, or an
	// unknown scope is projected.
	KindProjection Kind = "projection"
)

// AllKinds are every violation kind, in declaration order.
var AllKinds = []Kind{KindCase, KindInventory, KindEvaluate, KindNondeterministic, KindUnexpected, KindDuplicate,
	KindDropped, KindRawOutcome, KindNormalizedOutcome, KindNormalization, KindSourceTime, KindStaleEvidence,
	KindOutcomeWithoutEvidence, KindState, KindSummary, KindIndependence, KindMissingEvidence, KindGolden,
	KindCollection, KindCancellation, KindWrite, KindUnavailableSource, KindReplay, KindContent, KindProjection}

// Violation is one broken conformance rule.
type Violation struct {
	Kind   Kind
	Detail string
}

func (v *Violation) Error() string { return string(v.Kind) + ": " + v.Detail }

func violation(k Kind, format string, args ...any) error {
	return &Violation{Kind: k, Detail: fmt.Sprintf(format, args...)}
}

// KindOf is the kind of a violation, or "" for any other error.
func KindOf(err error) Kind {
	var v *Violation
	if errors.As(err, &v) {
		return v.Kind
	}
	return ""
}

// Kinds are the distinct kinds of errs, sorted. An error that is not a
// Violation is reported as "".
func Kinds(errs []error) []Kind {
	var out []Kind
	for _, err := range errs {
		if k := KindOf(err); !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
