package collector

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// WatchDiscontinuity records a watch gap or controller restart. Continuity
// established before it is discarded: relisting does not create history.
const WatchDiscontinuity ChangeKind = "WatchDiscontinuity"

// Boundary is the earliest time the collector has continuously observed a
// workload in its frozen state. Only evaluations after it can be attributed
// to that state; a result timestamp alone does not prove which state an
// engine evaluated.
type Boundary struct {
	WorkloadUID string    `json:"workloadUID"`
	StateSHA256 string    `json:"stateSha256"`
	Since       time.Time `json:"since"`
}

// ObservationState classifies one expected observation.
type ObservationState string

const (
	Attributable ObservationState = "Attributable"
	Missing      ObservationState = "Missing"
	// Rejected: matching results exist but none is usable evidence.
	Rejected ObservationState = "Rejected"
	// Unresolved: evidence cannot be attributed because scope changed or
	// matching results conflict.
	Unresolved ObservationState = "Unresolved"
)

// Observation is the evaluation of one expected observation.
type Observation struct {
	Key       string           `json:"key"`
	State     ObservationState `json:"state"`
	Outcome   string           `json:"outcome,omitempty"`
	Evaluated *time.Time       `json:"evaluated,omitempty"`
	Report    string           `json:"report,omitempty"`
	Index     int              `json:"resultIndex"`
	// Reasons explain every rejected or unresolved candidate.
	Reasons []string `json:"reasons,omitempty"`
	// Applicability is NotApplicable when the check is outside the
	// workload's scope: a Linux-only check on a workload that explicitly
	// declares Windows. Its raw outcome is kept but never counted as a pass.
	Applicability string `json:"applicability,omitempty"`
}

// NotApplicable marks an observation outside the check's scope.
const NotApplicable = "NotApplicable"

// linuxOnly reports, per engine policy and validation index, the checks
// that exclude explicit Windows workloads: the bundle convention is that
// such a validation short-circuits through variables.isWindowsPod, so a
// Windows workload's raw pass means "not evaluated", not compliance.
func linuxOnly(policies []assessment.Object) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	for _, p := range policies {
		name := assessment.Str(assessment.At(p, "metadata", "name"))
		validations, _ := assessment.At(p, "spec", "validations").([]any)
		for i, v := range validations {
			if strings.Contains(assessment.Str(assessment.Map(v)["expression"]), "variables.isWindowsPod") {
				if out[name] == nil {
					out[name] = map[int]bool{}
				}
				out[name][i] = true
			}
		}
	}
	return out
}

// Evaluation is the outcome of applying freshness rules at closure.
type Evaluation struct {
	Observations []Observation               `json:"observations"`
	Evidence     publication.EvidenceSummary `json:"evidence"`
	Outcomes     publication.OutcomeCounts   `json:"outcomes"`
	// NextExpiry is when the first attributable observation exceeds
	// maxEvidenceAge, for re-evaluating current status without an event.
	NextExpiry *time.Time `json:"nextExpiry,omitempty"`
}

type candidate struct {
	outcome   string
	evaluated time.Time
	report    string
	index     int
}

// Evaluate applies the freshness rules to a capture closed at c.Window.Closed.
// An expected observation is attributable only if a matching result:
//   - names its engine policy (whose name binds binding, policy, and revision)
//     and sub-validation index, and its workload UID;
//   - has a valid source evaluation time, not after closure;
//   - was evaluated strictly after the workload's continuity boundary and
//     after any later watch discontinuity;
//   - is no older than maxEvidenceAge at closure;
//   - belongs to a subject whose scope did not change during collection;
//   - does not conflict with another result evaluated at the same time.
//
// Collection time and report update time are never used as evaluation time.
func (c CaptureV2) Evaluate(boundaries []Boundary, maxEvidenceAge time.Duration) (Evaluation, error) {
	if err := c.Validate(); err != nil {
		return Evaluation{}, err
	}
	if maxEvidenceAge <= 0 {
		return Evaluation{}, fmt.Errorf("maxEvidenceAge must be positive")
	}
	closed := c.Window.Closed
	since := map[string]Boundary{}
	for _, b := range boundaries {
		since[b.WorkloadUID] = b
	}
	var discontinuity time.Time
	for _, ch := range c.ScopeChanges {
		if ch.Kind == WatchDiscontinuity && ch.Observed.After(discontinuity) {
			discontinuity = ch.Observed
		}
	}

	// Index results by workload UID, engine policy, and sub-validation.
	found := map[string][]candidate{}
	problems := map[string][]string{}
	for _, report := range c.Reports {
		if report["apiVersion"] != "wgpolicyk8s.io/v1alpha2" || (report["kind"] != "PolicyReport" && report["kind"] != "ClusterPolicyReport") {
			return Evaluation{}, fmt.Errorf("unsupported report layout %v/%v", report["apiVersion"], report["kind"])
		}
		reportUID := assessment.Str(assessment.At(report, "metadata", "uid"))
		results, _ := report["results"].([]any)
		for i, raw := range results {
			r := assessment.Map(raw)
			refs, ok := r["resources"].([]any)
			if !ok {
				if scope := assessment.Map(report["scope"]); scope != nil {
					refs = []any{scope}
				}
			}
			index := assessment.Str(assessment.At(r, "properties", "cel.validationIndex"))
			for _, ref := range refs {
				key := resultKey(assessment.Str(assessment.Map(ref)["uid"]), assessment.Str(r["policy"]), index)
				t, err := evaluationTime(r)
				if err != nil {
					problems[key] = append(problems[key], fmt.Sprintf("report %s result %d: %v", reportUID, sourceIndex(r, i), err))
					continue
				}
				found[key] = append(found[key], candidate{outcome: assessment.Str(r["result"]), evaluated: t, report: reportUID, index: sourceIndex(r, i)})
			}
		}
	}

	// Kyverno reports a ValidatingPolicy that passes every validation for a
	// resource as one result without cel.validationIndex; only failing
	// validations carry an index. An unindexed pass therefore attests every
	// validation of that engine policy for that resource. Any other
	// unindexed outcome cannot identify its validation, so it is evidence
	// only when the policy has a single validation.
	validations := map[string]map[int]bool{}
	for _, e := range c.Expected {
		if validations[e.Check.EnginePolicy] == nil {
			validations[e.Check.EnginePolicy] = map[int]bool{}
		}
		validations[e.Check.EnginePolicy][e.Check.Index] = true
	}

	scoped := linuxOnly(c.EnginePolicies)
	ev := Evaluation{Observations: []Observation{}, Evidence: publication.EvidenceSummary{Expected: len(c.Expected), StaleScopes: len(c.Stale)}}
	for _, e := range c.Expected {
		o := Observation{Key: e.Key()}
		if e.Workload.OS == "windows" && scoped[e.Check.EnginePolicy][e.Check.Index] {
			o.Applicability = NotApplicable
			o.Reasons = append(o.Reasons, "the workload declares Windows (spec.os.name); this Linux check does not assess it")
		}
		key := resultKey(e.Workload.UID, e.Check.EnginePolicy, strconv.Itoa(e.Check.Index))
		policyKey := resultKey(e.Workload.UID, e.Check.EnginePolicy, "")
		candidates := slices.Clone(found[key])
		single := len(validations[e.Check.EnginePolicy]) == 1
		for _, cand := range found[policyKey] {
			if cand.outcome == "pass" || single {
				candidates = append(candidates, cand)
			}
		}
		o.Reasons = append(o.Reasons, problems[key]...)
		o.Reasons = append(o.Reasons, problems[policyKey]...)
		if ch, changed := c.ChangeFor(e); changed {
			o.State = Unresolved
			o.Reasons = append(o.Reasons, fmt.Sprintf("%s during collection at %s", ch.Kind, ch.Observed.Format(time.RFC3339)))
			ev.add(o)
			continue
		}
		boundary := c.Window.Started
		if b, ok := since[e.Workload.UID]; ok && b.StateSHA256 == e.Workload.StateSHA256 && b.Since.Before(boundary) {
			boundary = b.Since
		}
		if discontinuity.After(boundary) {
			boundary = discontinuity
		}
		var usable []candidate
		for _, cand := range candidates {
			switch {
			case cand.evaluated.After(closed):
				o.Reasons = append(o.Reasons, fmt.Sprintf("report %s result %d: evaluation time %s is after closure", cand.report, cand.index, cand.evaluated.Format(time.RFC3339)))
			case !cand.evaluated.After(boundary):
				o.Reasons = append(o.Reasons, fmt.Sprintf("report %s result %d: evaluated %s, not after the observed-state boundary %s", cand.report, cand.index, cand.evaluated.Format(time.RFC3339), boundary.Format(time.RFC3339)))
			case closed.Sub(cand.evaluated) > maxEvidenceAge:
				o.Reasons = append(o.Reasons, fmt.Sprintf("report %s result %d: %s old at closure exceeds maxEvidenceAge %s", cand.report, cand.index, closed.Sub(cand.evaluated), maxEvidenceAge))
			case cand.outcome == "":
				o.Reasons = append(o.Reasons, fmt.Sprintf("report %s result %d: missing outcome", cand.report, cand.index))
			default:
				usable = append(usable, cand)
			}
		}
		slices.SortFunc(usable, func(a, b candidate) int { return b.evaluated.Compare(a.evaluated) })
		switch {
		case len(usable) == 0 && len(candidates) == 0 && len(problems[key]) == 0 && len(problems[policyKey]) == 0:
			o.State = Missing
		case len(usable) == 0:
			o.State = Rejected
		case len(usable) > 1 && usable[0].evaluated.Equal(usable[1].evaluated) && usable[0].outcome != usable[1].outcome:
			o.State = Unresolved
			o.Reasons = append(o.Reasons, "conflicting results evaluated at the same time")
		default:
			best := usable[0]
			o.State, o.Outcome, o.Report, o.Index = Attributable, best.outcome, best.report, best.index
			t := best.evaluated
			o.Evaluated = &t
			expiry := t.Add(maxEvidenceAge)
			if ev.NextExpiry == nil || expiry.Before(*ev.NextExpiry) {
				ev.NextExpiry = &expiry
			}
		}
		ev.add(o)
	}
	switch {
	case ev.Evidence.Expected == 0 && ev.Evidence.StaleScopes == 0:
		ev.Evidence.Completeness = publication.NoTargets
	case ev.Evidence.Attributable == ev.Evidence.Expected && ev.Evidence.StaleScopes == 0:
		ev.Evidence.Completeness = publication.Complete
	default:
		ev.Evidence.Completeness = publication.Incomplete
	}
	slices.SortFunc(ev.Observations, func(a, b Observation) int { return cmp.Compare(a.Key, b.Key) })
	return ev, ev.Evidence.Validate()
}

func (ev *Evaluation) add(o Observation) {
	ev.Observations = append(ev.Observations, o)
	switch o.State {
	case Attributable:
		ev.Evidence.Attributable++
		if o.Applicability == NotApplicable {
			ev.Outcomes.NotApplicable++
			return
		}
		switch o.Outcome {
		case "pass":
			ev.Outcomes.Pass++
		case "fail":
			ev.Outcomes.Fail++
		case "error":
			ev.Outcomes.Error++
		case "skip":
			ev.Outcomes.Skip++
		default:
			ev.Outcomes.Unknown++
		}
	case Missing:
		ev.Evidence.Missing++
	case Rejected:
		ev.Evidence.Rejected++
	default:
		ev.Evidence.Unresolved++
	}
}

// sourceIndex is a result's index in its source report: the recorded
// provenance for projected extracts, otherwise its position.
func sourceIndex(r assessment.Object, i int) int {
	if n, ok := integral(assessment.At(r, SourceField, "resultIndex")); ok {
		return int(n)
	}
	return i
}

func resultKey(uid, policy, index string) string { return uid + "\x00" + policy + "\x00" + index }

// evaluationTime reads a result's source evaluation timestamp. Missing or
// malformed timestamps are errors, never replaced by another time. Integers
// arrive as int64 from the Kubernetes unstructured decoder and as float64
// from encoding/json; both are accepted.
func evaluationTime(r assessment.Object) (time.Time, error) {
	stamp := assessment.Map(r["timestamp"])
	seconds, ok := integral(stamp["seconds"])
	if !ok {
		if _, present := stamp["seconds"]; !present {
			return time.Time{}, fmt.Errorf("missing source evaluation timestamp")
		}
		return time.Time{}, fmt.Errorf("invalid source evaluation timestamp")
	}
	nanos, ok := integral(stamp["nanos"])
	if _, present := stamp["nanos"]; !present {
		nanos, ok = 0, true
	}
	if !ok || seconds <= 0 || nanos < 0 || nanos >= 1e9 {
		return time.Time{}, fmt.Errorf("invalid source evaluation timestamp")
	}
	return time.Unix(seconds, nanos).UTC(), nil
}

// integral converts a decoded JSON integer to int64.
func integral(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		if math.Trunc(n) != n || math.Abs(n) > 1<<53 {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// Discontinuity records a watch gap or controller restart at time at.
func (t *Tracker) Discontinuity(at time.Time, detail string) {
	t.record(ScopeChange{Kind: WatchDiscontinuity, Observed: at, Detail: detail})
}
