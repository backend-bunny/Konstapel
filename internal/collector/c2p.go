package collector

import (
	"context"
	"errors"
	"fmt"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// C2P conversion of a frozen, evaluated Kyverno capture
// (add-assessment-provider-contract 4.2). Continuous export and the
// konstapel-provider plugin convert through the same SnapshotProvider,
// dispatched by the pinned C2P framework's Configure/GetResults contract,
// so a package and an offline conversion of its retained files cannot
// derive different results. Conversion evaluates nothing: it reads the
// evaluation kyverno.Evaluate made at the run's closure, frozen with its
// capture. It reads no clock, cluster, registry, cache or engine.

// CaptureFile and EvaluationFile are the package files that retain a
// snapshot, side by side.
const (
	CaptureFile    = "capture.json"
	EvaluationFile = "evaluation.json"
)

// Snapshot is the frozen input of C2P conversion: a closed Kyverno capture
// and the evaluation the installed evaluator made of it at its closure. A
// package retains it as CaptureFile and EvaluationFile; a closing run
// freezes it before export.
type Snapshot struct {
	Capture    CaptureV2
	Evaluation Evaluation
}

// Validate checks that the snapshot is one evaluation of its capture: the
// capture is a valid closed CaptureV2, and the evaluation holds exactly one
// observation per expected observation and no other, names only reports
// the capture holds, and summarizes exactly its observations. A snapshot
// that fails is never converted.
func (s Snapshot) Validate() error {
	c, ev := s.Capture, s.Evaluation
	if err := c.Validate(); err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	expected := map[string]bool{}
	for _, e := range c.Expected {
		expected[e.Key()] = true
	}
	reports := map[string]bool{}
	for _, r := range c.Reports {
		reports[assessment.Str(assessment.At(r, "metadata", "uid"))] = true
	}
	var errs []error
	seen := map[string]bool{}
	for i, o := range ev.Observations {
		switch {
		case !expected[o.Key]:
			errs = append(errs, fmt.Errorf("observations[%d] is not an expected observation of the capture", i))
		case seen[o.Key]:
			errs = append(errs, fmt.Errorf("observations[%d] repeats an observation", i))
		}
		seen[o.Key] = true
		if o.Report != "" && !reports[o.Report] {
			errs = append(errs, fmt.Errorf("observations[%d] names a report the capture does not hold", i))
		}
	}
	for _, e := range c.Expected {
		if !seen[e.Key()] {
			errs = append(errs, fmt.Errorf("expected observation %s has no observation in the evaluation", e.Key()))
		}
	}
	if e, o := Tally(ev.Observations, len(c.Stale)); e != ev.Evidence || o != ev.Outcomes {
		errs = append(errs, errors.New("the evaluation summary does not count exactly its observations"))
	}
	if err := ev.Evidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("evidence summary: %w", err))
	}
	return errors.Join(errs...)
}

// ReadSnapshot is a retained snapshot read through the capture boundary:
// doc must be a Kyverno payload 2 capture (legacy or envelope) recorded
// under an installed evaluator, and evaluation the strict JSON of its
// evaluation. Anything else is an explicit error, never an empty snapshot
// or one read with other semantics.
func ReadSnapshot(doc CaptureDocument, readers CaptureReaders, evaluation []byte) (Snapshot, error) {
	if err := doc.CheckEvaluator(readers); err != nil {
		return Snapshot{}, err
	}
	c, err := doc.V2()
	if err != nil {
		return Snapshot{}, err
	}
	var ev Evaluation
	if err := decodeStrict(evaluation, &ev); err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", EvaluationFile, err)
	}
	s := Snapshot{Capture: c, Evaluation: ev}
	if err := s.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("frozen snapshot: %w", err)
	}
	return s, nil
}

// part is the snapshot of part of its capture (one applied bundle's
// expected observations): their observations, counted again.
func (s Snapshot) part(c CaptureV2) Snapshot {
	keys := map[string]bool{}
	for _, e := range c.Expected {
		keys[e.Key()] = true
	}
	ev := Evaluation{Observations: []Observation{}}
	for _, o := range s.Evaluation.Observations {
		if keys[o.Key] {
			ev.Observations = append(ev.Observations, o)
		}
	}
	ev.Evidence, ev.Outcomes = Tally(ev.Observations, len(c.Stale))
	return Snapshot{Capture: c, Evaluation: ev}
}

// SnapshotProvider is the in-tree C2P provider (policy.Provider) of one
// frozen snapshot. Continuous export dispatches to it in process, and the
// konstapel-provider plugin serves it for a retained package.
type SnapshotProvider struct {
	Snapshot   Snapshot
	configured bool
}

var _ policy.Provider = (*SnapshotProvider)(nil)

// Configure validates the frozen snapshot. The snapshot is the provider's
// only input: the options the C2P manifest declares for the prototype's
// rendering (content root, output, namespace, owner, action) are not read,
// and nothing is fetched or collected.
func (p *SnapshotProvider) Configure(context.Context, map[string]string) error {
	p.configured = false
	if err := p.Snapshot.Validate(); err != nil {
		return fmt.Errorf("frozen snapshot: %w", err)
	}
	p.configured = true
	return nil
}

// Generate is refused: a frozen snapshot is converted, never regenerated.
// Its engine policies were rendered and applied before its capture froze,
// and regenerating them from current content would not be what was
// assessed. Only the prototype renders policy artifacts, locally.
func (p *SnapshotProvider) Generate(context.Context, policy.Policy) error {
	return errors.New("a frozen snapshot is converted, never regenerated: its engine policies were applied before its capture froze")
}

// GetResults converts the frozen snapshot: one C2P check per logical
// policy, one subject per expected observation. Every check must be one of
// the policy it is converted for; otherwise no results are returned, so no
// OSCAL is derived from results its mapping does not name.
func (p *SnapshotProvider) GetResults(_ context.Context, pl policy.Policy) (policy.PVPResult, error) {
	if !p.configured {
		return policy.PVPResult{}, errors.New("provider not configured")
	}
	checks := map[string]bool{}
	for _, rs := range pl {
		for _, c := range rs.Checks {
			checks[c.ID] = true
		}
	}
	results, _ := pvpResults(p.Snapshot.Capture, p.Snapshot.Evaluation)
	for _, o := range results[0].ObservationsByCheck {
		if !checks[o.CheckID] {
			return policy.PVPResult{}, fmt.Errorf("check %s of the frozen snapshot is not a check of the policy it is converted for", o.CheckID)
		}
	}
	return results[0], nil
}

// convert dispatches the conversion of s through the C2P framework for
// input, exactly as for the plugin, and returns its one result.
func convert(ctx context.Context, input *actions.InputContext, s Snapshot) ([]policy.PVPResult, error) {
	p := &SnapshotProvider{Snapshot: s}
	if err := p.Configure(ctx, nil); err != nil {
		return nil, err
	}
	results, err := actions.AggregateResults(ctx, input, map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): p})
	if err != nil {
		return nil, err
	}
	// The framework skips a provider its input has no validation
	// component for; that is no conversion, not an empty one.
	if len(results) != 1 {
		return nil, fmt.Errorf("the C2P dispatch returned %d results for %s, want one", len(results), assessment.ProviderID)
	}
	return results, nil
}

// attributableFailure reports whether results claim an observed violation:
// only an attributable, applicable failure is converted to a failing
// subject.
func attributableFailure(results []policy.PVPResult) bool {
	for _, r := range results {
		for _, o := range r.ObservationsByCheck {
			for _, s := range o.Subjects {
				if s.Result == policy.ResultFail {
					return true
				}
			}
		}
	}
	return false
}
