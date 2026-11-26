// Package conformance is the shared, provider-neutral conformance harness
// for assessment providers (add-assessment-provider-contract 1.2).
//
// A conformance case is a versioned input (case.json) and its expected
// result (expected.json) in one directory. The input payload is opaque to
// the harness: each provider's Adapter decodes its own shape. The harness
// knows only subjects, checks, evidence states, raw and normalized
// outcomes, and the existing publication summary types. It imports no
// provider package, so no engine policy names, validation indexes or report
// layouts leak into the shared contract (conformance_test.go checks this).
//
// Besides comparing a case to its golden result, Check enforces invariants
// every provider must satisfy: the expected inventory is derived from the
// input alone and is unchanged when all evidence is removed, which leaves
// every observation Missing (or Unresolved for scope it cannot attribute);
// every expected observation is evaluated exactly once; only attributable
// evidence carries an outcome, within the evidence-age limit, and is stale
// once older; unknown evidence is never a pass; a raw outcome always
// normalizes the same way; and evaluation is deterministic for an explicit
// evaluation time. CheckLifecycle and CheckProjection (suite.go) cover a
// provider's collection, retention, replay and namespace projection for
// the same cases, and RunMutations (mutations.go) proves that deliberate
// regressions fail for their own Kind.
//
// This package is test infrastructure. It is never linked into a shipped
// binary (internal/provider/installed tests the boundary).
package conformance

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// CaseVersion versions the case and expected-result formats. Unknown
// versions are rejected, never interpreted.
const CaseVersion = "konstapel.provider-conformance/v1"

// Case file names inside a case directory.
const (
	CaseFile     = "case.json"
	ExpectedFile = "expected.json"
)

// Case is one versioned conformance input.
type Case struct {
	Version string `json:"version"`
	// Provider is the provider contract ("name/vN") the case is for.
	Provider    string `json:"provider"`
	Description string `json:"description"`
	// EvaluationTime is the explicit evaluation boundary. Adapters must not
	// read a clock.
	EvaluationTime time.Time `json:"evaluationTime"`
	// Input is the provider-specific payload: frozen inventory inputs and
	// source evidence.
	Input json.RawMessage `json:"input"`
}

// State is a provider-neutral evidence state of one expected observation.
type State string

const (
	Attributable State = "Attributable"
	// Missing: no evidence for the observation.
	Missing State = "Missing"
	// Rejected: evidence exists, none of it is usable (stale, untimed,
	// after the evaluation boundary).
	Rejected State = "Rejected"
	// Unresolved: evidence cannot be attributed (ambiguous identity,
	// conflicting results, a scope change).
	Unresolved State = "Unresolved"
)

// Outcome is a normalized check outcome, the existing summary vocabulary.
type Outcome string

const (
	Pass    Outcome = "pass"
	Fail    Outcome = "fail"
	Error   Outcome = "error"
	Skip    Outcome = "skip"
	Unknown Outcome = "unknown"
)

// Expectation is one expected observation, identified by provider-defined
// opaque subject and check keys. The pair is unique.
type Expectation struct {
	Subject string `json:"subject"`
	Check   string `json:"check"`
}

// Observation is the evaluation of one expectation.
type Observation struct {
	Subject string `json:"subject"`
	Check   string `json:"check"`
	State   State  `json:"state"`
	// Raw is the producer's own outcome, retained verbatim; set only when
	// the observation is attributable.
	Raw string `json:"raw,omitempty"`
	// Outcome is Raw normalized; set only when attributable.
	Outcome Outcome `json:"outcome,omitempty"`
	// NotApplicable marks attributable evidence outside the check's scope;
	// it is never counted as a pass.
	NotApplicable bool `json:"notApplicable,omitempty"`
	// Evaluated is the source evaluation time of attributable evidence.
	Evaluated *time.Time `json:"evaluated,omitempty"`
}

// Evaluation is what an adapter returns for a case.
type Evaluation struct {
	Observations []Observation `json:"observations"`
	// StaleScopes counts scopes whose expected checks are unknown; any makes
	// evidence Incomplete.
	StaleScopes int `json:"staleScopes,omitempty"`
}

// Expected is the golden result of a case.
type Expected struct {
	Version      string                      `json:"version"`
	Provider     string                      `json:"provider"`
	Inventory    []Expectation               `json:"inventory"`
	Observations []Observation               `json:"observations"`
	Evidence     publication.EvidenceSummary `json:"evidence"`
	Outcomes     publication.OutcomeCounts   `json:"outcomes"`
}

// Adapter connects one provider's collection inputs and evaluator to the
// harness. Every method is pure over its arguments.
type Adapter interface {
	// Contract is the provider contract the adapter implements.
	Contract() string
	// Inventory derives the expected observations from the input's frozen
	// scope alone, never from its evidence.
	Inventory(input json.RawMessage) ([]Expectation, error)
	// Evaluate evaluates the input's evidence at the explicit time.
	Evaluate(input json.RawMessage, at time.Time) (Evaluation, error)
	// WithoutEvidence returns the input with every piece of source evidence
	// removed and its frozen scope unchanged.
	WithoutEvidence(input json.RawMessage) (json.RawMessage, error)
	// MaxEvidenceAge is the input's evidence-age limit: attributable
	// evidence is at most this old at the evaluation time.
	MaxEvidenceAge(input json.RawMessage) (time.Duration, error)
}

// Load reads a case directory. A missing expected.json is returned as a
// nil Expected, so a new case can be bootstrapped.
func Load(dir string) (Case, *Expected, error) {
	var c Case
	if err := readStrict(filepath.Join(dir, CaseFile), &c); err != nil {
		return c, nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, ExpectedFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil, nil
	}
	if err != nil {
		return c, nil, err
	}
	var want Expected
	if err := decodeStrict(raw, &want); err != nil {
		return c, nil, fmt.Errorf("%s: %w", ExpectedFile, err)
	}
	return c, &want, nil
}

// Check runs the case through the adapter, enforces the shared invariants,
// and returns the result in golden form with every violation found. Each
// violation is a *Violation whose Kind names the rule it breaks.
func Check(a Adapter, c Case) (Expected, []error) {
	var errs []error
	fail := func(k Kind, format string, args ...any) { errs = append(errs, violation(k, format, args...)) }
	got := Expected{Version: CaseVersion, Provider: c.Provider}
	switch {
	case c.Version != CaseVersion:
		fail(KindCase, "case version %q is not %q", c.Version, CaseVersion)
		return got, errs
	case c.Provider != a.Contract():
		fail(KindCase, "case is for %s, adapter implements %s", c.Provider, a.Contract())
		return got, errs
	case c.EvaluationTime.IsZero():
		fail(KindCase, "case has no explicit evaluationTime")
		return got, errs
	case len(bytes.TrimSpace(c.Input)) == 0:
		fail(KindCase, "case has no input")
		return got, errs
	}

	inv, err := a.Inventory(c.Input)
	if err != nil {
		fail(KindInventory, "inventory: %v", err)
		return got, errs
	}
	inv = sortedExpectations(inv)
	keys := map[Expectation]bool{}
	for _, e := range inv {
		if e.Subject == "" || e.Check == "" {
			fail(KindInventory, "inventory entry %+v lacks a subject or check", e)
		}
		if keys[e] {
			fail(KindInventory, "inventory repeats %s / %s", e.Subject, e.Check)
		}
		keys[e] = true
	}
	got.Inventory = inv

	age, err := a.MaxEvidenceAge(c.Input)
	if err != nil || age <= 0 {
		fail(KindCase, "the input has no positive evidence-age limit (%v)", err)
		return got, errs
	}
	ev, err := a.Evaluate(c.Input, c.EvaluationTime)
	if err != nil {
		fail(KindEvaluate, "evaluate: %v", err)
		return got, errs
	}
	again, err := a.Evaluate(c.Input, c.EvaluationTime)
	if err != nil || !sameJSON(normalize(ev), normalize(again)) {
		fail(KindNondeterministic, "evaluation is not deterministic for the same input and time (%v)", err)
	}
	ev = normalize(ev)
	errs = append(errs, observationErrors(keys, ev, c.EvaluationTime, age)...)
	got.Observations = ev.Observations
	got.Evidence, got.Outcomes = Summarize(ev)
	if err := got.Evidence.Validate(); err != nil {
		fail(KindSummary, "summary: %v", err)
	}
	errs = append(errs, staleErrors(a, c, keys, ev, age)...)

	// Independence: removing all evidence keeps the inventory and leaves
	// every observation explicitly missing, never passing.
	bare, err := a.WithoutEvidence(c.Input)
	if err != nil {
		fail(KindEvaluate, "without evidence: %v", err)
		return got, errs
	}
	bareInv, err := a.Inventory(bare)
	if err != nil || !sameJSON(sortedExpectations(bareInv), inv) {
		fail(KindIndependence, "inventory changes when evidence is removed (%v): expected subjects must not come from evidence", err)
	}
	bareEv, err := a.Evaluate(bare, c.EvaluationTime)
	if err != nil {
		fail(KindEvaluate, "evaluate without evidence: %v", err)
		return got, errs
	}
	bareEv = normalize(bareEv)
	errs = append(errs, observationErrors(keys, bareEv, c.EvaluationTime, age)...)
	errs = append(errs, missingErrors("without evidence", inv, bareEv)...)
	return got, errs
}

// staleErrors evaluates the case again once all of its attributable
// evidence is older than the evidence-age limit. Evidence that was
// attributable must then be stale: Rejected (or attributable from newer
// evidence the earlier time did not admit), never still attributable from
// the same source time and never Missing, since it still exists.
func staleErrors(a Adapter, c Case, keys map[Expectation]bool, ev Evaluation, age time.Duration) []error {
	before := map[Expectation]Observation{}
	for _, o := range ev.Observations {
		if o.State == Attributable && o.Evaluated != nil {
			before[Expectation{Subject: o.Subject, Check: o.Check}] = o
		}
	}
	if len(before) == 0 {
		return nil
	}
	later := c.EvaluationTime.Add(age + time.Second)
	aged, err := a.Evaluate(c.Input, later)
	if err != nil {
		return []error{violation(KindEvaluate, "evaluate at %s: %v", later.Format(time.RFC3339), err)}
	}
	aged = normalize(aged)
	errs := observationErrors(keys, aged, later, age)
	for _, o := range aged.Observations {
		was, ok := before[Expectation{Subject: o.Subject, Check: o.Check}]
		switch {
		case !ok:
		case o.State == Missing:
			errs = append(errs, violation(KindStaleEvidence, "%s / %s: stale evidence became Missing; evidence that exists but is too old is Rejected", o.Subject, o.Check))
		case o.State == Attributable && o.Evaluated != nil && o.Evaluated.Equal(*was.Evaluated):
			errs = append(errs, violation(KindStaleEvidence, "%s / %s: evidence evaluated at %s is still attributable %s later", o.Subject, o.Check, was.Evaluated.Format(time.RFC3339), age+time.Second))
		}
	}
	return errs
}

// missingErrors checks an evaluation that has no source evidence: every
// expected observation is Missing (or Unresolved for scope it cannot
// attribute), nothing has an outcome, and anything expected is Incomplete.
func missingErrors(what string, inv []Expectation, ev Evaluation) []error {
	var errs []error
	// Unresolved stays possible: an unattributable identity or a scope
	// change is a property of the frozen scope, not of evidence.
	for _, o := range ev.Observations {
		if o.State != Missing && o.State != Unresolved {
			errs = append(errs, violation(KindMissingEvidence, "%s %s / %s is %s, want Missing (or Unresolved for an unattributable scope)", what, o.Subject, o.Check, o.State))
		}
	}
	sum, out := Summarize(ev)
	if out != (publication.OutcomeCounts{}) {
		errs = append(errs, violation(KindMissingEvidence, "%s the outcomes are %+v, want none", what, out))
	}
	if len(inv) > 0 && sum.Completeness != publication.Incomplete {
		errs = append(errs, violation(KindMissingEvidence, "%s completeness is %s, want Incomplete", what, sum.Completeness))
	}
	return errs
}

// Verify is Check plus an exact comparison with the golden result.
func Verify(a Adapter, c Case, want Expected) []error {
	got, errs := Check(a, c)
	if want.Version != CaseVersion {
		errs = append(errs, violation(KindCase, "expected result version %q is not %q", want.Version, CaseVersion))
	}
	if !sameJSON(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		errs = append(errs, violation(KindGolden, "result differs from %s:\n%s", ExpectedFile, g))
	}
	return errs
}

// Write stores a result as the case's golden expected.json.
func Write(dir string, e Expected) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ExpectedFile), append(b, '\n'), 0o644)
}

// Summarize counts observations with the existing summary rules: one count
// per observation; NotApplicable is never a pass; unknown outcomes count
// once as unknown; completeness is NoTargets with nothing expected or
// stale, Complete when everything is attributable and nothing is stale,
// and Incomplete otherwise.
func Summarize(ev Evaluation) (publication.EvidenceSummary, publication.OutcomeCounts) {
	e := publication.EvidenceSummary{Expected: len(ev.Observations), StaleScopes: ev.StaleScopes}
	var o publication.OutcomeCounts
	for _, obs := range ev.Observations {
		switch obs.State {
		case Attributable:
			e.Attributable++
			if obs.NotApplicable {
				o.NotApplicable++
				continue
			}
			switch obs.Outcome {
			case Pass:
				o.Pass++
			case Fail:
				o.Fail++
			case Error:
				o.Error++
			case Skip:
				o.Skip++
			default:
				o.Unknown++
			}
		case Missing:
			e.Missing++
		case Rejected:
			e.Rejected++
		default:
			e.Unresolved++
		}
	}
	switch {
	case e.Expected == 0 && e.StaleScopes == 0:
		e.Completeness = publication.NoTargets
	case e.Attributable == e.Expected && e.StaleScopes == 0:
		e.Completeness = publication.Complete
	default:
		e.Completeness = publication.Incomplete
	}
	return e, o
}

func observationErrors(inventory map[Expectation]bool, ev Evaluation, at time.Time, age time.Duration) []error {
	var errs []error
	fail := func(k Kind, format string, args ...any) { errs = append(errs, violation(k, format, args...)) }
	seen := map[Expectation]bool{}
	normalized := map[string]Outcome{}
	for _, o := range ev.Observations {
		k := Expectation{Subject: o.Subject, Check: o.Check}
		switch {
		case !inventory[k]:
			fail(KindUnexpected, "observation %s / %s is not in the expected inventory", o.Subject, o.Check)
		case seen[k]:
			fail(KindDuplicate, "observation %s / %s is evaluated twice", o.Subject, o.Check)
		}
		seen[k] = true
		switch o.State {
		case Attributable:
			if o.Raw == "" {
				fail(KindRawOutcome, "%s / %s: attributable evidence without its raw outcome", o.Subject, o.Check)
			}
			if !slices.Contains([]Outcome{Pass, Fail, Error, Skip, Unknown}, o.Outcome) {
				fail(KindNormalizedOutcome, "%s / %s: normalized outcome %q is not pass, fail, error, skip or unknown", o.Subject, o.Check, o.Outcome)
			}
			if prev, ok := normalized[o.Raw]; ok && prev != o.Outcome {
				fail(KindNormalization, "raw outcome %q normalizes to both %s and %s", o.Raw, prev, o.Outcome)
			}
			normalized[o.Raw] = o.Outcome
			switch {
			case o.Evaluated == nil || o.Evaluated.After(at):
				fail(KindSourceTime, "%s / %s: attributable evidence needs a source evaluation time not after %s", o.Subject, o.Check, at.Format(time.RFC3339))
			case at.Sub(*o.Evaluated) > age:
				fail(KindStaleEvidence, "%s / %s: attributable evidence evaluated at %s is older than %s at %s", o.Subject, o.Check, o.Evaluated.Format(time.RFC3339), age, at.Format(time.RFC3339))
			}
		case Missing, Rejected, Unresolved:
			if o.Raw != "" || o.Outcome != "" || o.NotApplicable || o.Evaluated != nil {
				fail(KindOutcomeWithoutEvidence, "%s / %s: %s evidence carries an outcome; unknown evidence never establishes one", o.Subject, o.Check, o.State)
			}
		default:
			fail(KindState, "%s / %s: state %q is not Attributable, Missing, Rejected or Unresolved", o.Subject, o.Check, o.State)
		}
	}
	for k := range inventory {
		if !seen[k] {
			fail(KindDropped, "expected observation %s / %s was dropped; missing evidence must stay expected", k.Subject, k.Check)
		}
	}
	slices.SortFunc(errs, func(a, b error) int { return cmp.Compare(a.Error(), b.Error()) })
	return errs
}

func normalize(ev Evaluation) Evaluation {
	ev.Observations = slices.Clone(ev.Observations)
	if ev.Observations == nil {
		ev.Observations = []Observation{}
	}
	for i := range ev.Observations {
		if t := ev.Observations[i].Evaluated; t != nil {
			u := t.UTC()
			ev.Observations[i].Evaluated = &u
		}
	}
	slices.SortStableFunc(ev.Observations, func(a, b Observation) int {
		return cmp.Or(cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Check, b.Check))
	})
	return ev
}

func sortedExpectations(in []Expectation) []Expectation {
	out := slices.Clone(in)
	if out == nil {
		out = []Expectation{}
	}
	slices.SortFunc(out, func(a, b Expectation) int {
		return cmp.Or(cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Check, b.Check))
	})
	return out
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func readStrict(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := decodeStrict(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// decodeStrict rejects unknown fields and trailing data, so a newer case
// format is never read as this one.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected data after the document")
	}
	return nil
}
