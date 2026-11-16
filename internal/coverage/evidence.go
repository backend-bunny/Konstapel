package coverage

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Evidence is the assessment owner's frozen, evaluated capture: the expected
// inventory and raw reports frozen by internal/collector, and the evaluation
// applied to them at closure (capture.json and evaluation.json of a package).
//
// Coverage consumes the evaluation as recorded. It never re-evaluates
// freshness, attribution or continuity, never reads a clock, and never turns
// a missing, rejected or unresolved observation into an outcome.
type Evidence struct {
	Capture    collector.CaptureV2
	Evaluation collector.Evaluation
}

// States of a report's technical evidence.
const (
	// EvidenceNotProvided: the report was built without an evaluated
	// capture. Controls carry no evidence; this is not "no findings".
	EvidenceNotProvided = "notProvided"
	// EvidenceResolved: the evaluation is consistent with its capture and
	// the report's scope, and is joined to the controls.
	EvidenceResolved = "resolved"
	// EvidenceUnresolved: the evaluation does not match its capture or the
	// report's scope. The owner's summary and observations are retained
	// as recorded, but none is attributed to a control.
	EvidenceUnresolved = "unresolved"
)

// Attribution of a contribution's observations to the report's controls.
const (
	// AttributionAttributed: a selected, resolved check of a baseline
	// control is provided by the contribution's logical policy.
	AttributionAttributed = "attributed"
	// AttributionOtherContent: the contribution was applied from another
	// bundle than the report's content. Its checks are that content's;
	// the same identifiers are never attributed to this baseline.
	AttributionOtherContent = "otherContent"
	// AttributionNotSelected: the selection does not select the policy.
	AttributionNotSelected = "notSelected"
	// AttributionUnmapped: the policy is selected but no selected control
	// of the baseline maps one of its checks.
	AttributionUnmapped = "unmapped"
	// AttributionUnresolved: the mapping, the check, or the evidence
	// itself is unresolved, so the observations cannot be attributed.
	AttributionUnresolved = "unresolved"
)

// TechnicalEvidence is the report's technical-evidence section: the
// assessment owner's summary, copied unchanged, and every observation of
// the capture with the controls that reference it.
//
// Its counts are the owner's: one per unique expected observation of the
// capture's scope. Control, statement and check rows reference the same
// observations; their counts overlap and are never added together.
type TechnicalEvidence struct {
	State   string                   `json:"state"`
	Cluster string                   `json:"cluster,omitempty"`
	Window  *collector.CaptureWindow `json:"window,omitempty"`
	// MappingSHA256 is the capture's recorded mapping digest.
	MappingSHA256 string `json:"mappingSha256,omitempty"`
	// Evidence and Outcomes are the owner's evaluation summary, verbatim.
	Evidence *publication.EvidenceSummary `json:"evidence,omitempty"`
	Outcomes *publication.OutcomeCounts   `json:"outcomes,omitempty"`
	// StaleScopes are the bindings or policies whose expected checks are
	// unknown; ScopeChanges counts the changes recorded during collection.
	StaleScopes  []targeting.StaleScope `json:"staleScopes,omitempty"`
	ScopeChanges int                    `json:"scopeChanges,omitempty"`
	// Contributions are the capture's binding contributions and how their
	// observations are attributed.
	Contributions []ContributionRef `json:"contributions,omitempty"`
	// Observations are every expected observation, ordered by key.
	Observations []ObservationRecord `json:"observations,omitempty"`
}

// ContributionRef is one binding contribution of the capture.
type ContributionRef struct {
	BindingUID    string                   `json:"bindingUID"`
	Revision      string                   `json:"revision"`
	EnginePolicy  string                   `json:"enginePolicy"`
	LogicalPolicy string                   `json:"logicalPolicy"`
	Mode          string                   `json:"mode"`
	Bundle        v1alpha1.BundleReference `json:"bundle"`
	Attribution   string                   `json:"attribution"`
}

// ObservationRecord is one expected observation and the owner's evaluation
// of it, both exactly as recorded, with the controls that reference it.
// A shared check is one record referenced by several controls, never
// several evaluations.
type ObservationRecord struct {
	Expected    collector.Expected    `json:"expected"`
	Observation collector.Observation `json:"observation"`
	Controls    []string              `json:"controls,omitempty"`
}

// EvidenceView counts the unique observations a row references, with the
// owner's rules (collector.Tally). An unresolved view carries no counts:
// part of its evidence could not be attributed, so any count would be a
// guess.
type EvidenceView struct {
	Resolved bool                         `json:"resolved"`
	Evidence *publication.EvidenceSummary `json:"evidence,omitempty"`
	Outcomes *publication.OutcomeCounts   `json:"outcomes,omitempty"`
}

// CheckEvidence is the evidence of one selected check: the observations of
// every contribution of its logical policy from the report's content.
type CheckEvidence struct {
	EvidenceView
	Contributions []ContributionEvidence `json:"contributions,omitempty"`
}

// ContributionEvidence is one contribution's share of a check's evidence.
// Overlapping bindings, revisions and configurations stay separate.
type ContributionEvidence struct {
	BindingUID   string                      `json:"bindingUID"`
	Revision     string                      `json:"revision"`
	EnginePolicy string                      `json:"enginePolicy"`
	Mode         string                      `json:"mode"`
	Evidence     publication.EvidenceSummary `json:"evidence"`
	Outcomes     publication.OutcomeCounts   `json:"outcomes"`
	// Observations are the referenced observation keys, sorted.
	Observations []string `json:"observations"`
}

// StatementEvidence is the evidence of the selected checks mapped to one
// statement. Requirement-level mappings count only for the control.
type StatementEvidence struct {
	ID    string   `json:"id"`
	Rules []string `json:"rules"`
	EvidenceView
}

// contribKey identifies a contribution as export does: binding, revision
// and engine policy (whose name binds all three).
type contribKey struct{ binding, revision, enginePolicy string }

func contribOf(e collector.Expected) contribKey {
	return contribKey{e.Contribution.BindingUID, e.Contribution.Revision, e.Contribution.EnginePolicy}
}

// evidenceJoin is the evidence of one report, indexed for the rows.
type evidenceJoin struct {
	resolved bool
	stale    []targeting.StaleScope
	// byPolicy: observations of this content's contributions, by logical
	// policy, in key order.
	byPolicy map[string][]collector.Observation
	expected map[string]collector.Expected
	// ambiguous policies declare several checks: their sub-validations
	// cannot be attributed to one rule.
	ambiguous map[string]bool
}

// joinEvidence adds the evaluated capture to r. Rows are already built;
// it only adds evidence views and references.
func joinEvidence(r *Report, in Input) {
	ev := in.Evidence
	te := &r.TechnicalEvidence
	c := ev.Capture
	window := c.Window
	evidence, outcomes := ev.Evaluation.Evidence, ev.Evaluation.Outcomes
	*te = TechnicalEvidence{State: EvidenceResolved, Cluster: c.Cluster, Window: &window, MappingSHA256: c.MappingSHA256,
		Evidence: &evidence, Outcomes: &outcomes, StaleScopes: slices.Clone(c.Stale), ScopeChanges: len(c.ScopeChanges),
		Contributions: []ContributionRef{}, Observations: []ObservationRecord{}}
	if in.AsOf.IsZero() {
		r.AsOf = c.Window.Closed.UTC()
	}

	var lims []Limitation
	fail := func(code, subject, format string, a ...any) {
		lims = append(lims, *blocking(code, "", subject, format, a...))
	}
	if err := c.Validate(); err != nil {
		fail(CodeEvidenceInconsistent, "", "the capture is invalid: %v", err)
	}
	expected := map[string]collector.Expected{}
	for _, e := range c.Expected {
		expected[e.Key()] = e
	}
	obs := map[string]collector.Observation{}
	for _, o := range ev.Evaluation.Observations {
		if prev, dup := obs[o.Key]; dup {
			if !sameObservation(prev, o) {
				fail(CodeEvidenceInconsistent, "", "the evaluation records observation %s twice with different results", printableKey(o.Key))
			} else {
				lims = append(lims, *notice(CodeDuplicateObservation, "", "", "the evaluation repeats observation %s; it is counted once", printableKey(o.Key)))
			}
			continue
		}
		if _, ok := expected[o.Key]; !ok {
			fail(CodeEvidenceInconsistent, "", "observation %s is not in the capture's expected inventory", printableKey(o.Key))
			continue
		}
		obs[o.Key] = o
	}
	for k := range expected {
		if _, ok := obs[k]; !ok {
			fail(CodeEvidenceInconsistent, "", "expected observation %s has no evaluation", printableKey(k))
		}
	}
	all := slices.Collect(maps.Values(obs))
	gotE, gotO := collector.Tally(all, len(c.Stale))
	if gotE != evidence || gotO != outcomes {
		fail(CodeEvidenceInconsistent, "", "the evaluation summary %+v %+v does not count its observations (%+v %+v)", evidence, outcomes, gotE, gotO)
	}
	if r.Scope.Cluster != "" && r.Scope.Cluster != c.Cluster {
		fail(CodeEvidenceScopeMismatch, r.Scope.Cluster, "the capture is of cluster %s, not %s", c.Cluster, r.Scope.Cluster)
	}
	bundleOf := map[contribKey]v1alpha1.BundleReference{}
	subjectOf := map[contribKey]targeting.EvidenceSubject{}
	for _, s := range c.Subjects {
		k := contribKey{string(s.BindingUID), s.Revision, s.EnginePolicy}
		bundleOf[k] = v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}
		subjectOf[k] = s
		if r.Scope.Binding != nil && string(s.BindingUID) != r.Scope.Binding.UID {
			fail(CodeEvidenceScopeMismatch, string(s.BindingUID), "the capture contains binding %s outside the report's binding %s", s.BindingUID, r.Scope.Binding.UID)
		}
	}
	if !in.AsOf.IsZero() && !in.AsOf.Equal(c.Window.Closed) {
		fail(CodeEvidenceScopeMismatch, "", "the report is as of %s but the capture closed at %s", in.AsOf.UTC().Format("2006-01-02T15:04:05Z07:00"), c.Window.Closed.UTC().Format("2006-01-02T15:04:05Z07:00"))
	}
	resolved := !anyBlocking(lims)
	if !resolved {
		te.State = EvidenceUnresolved
	}

	// Join contributions of this content to the logical policies' checks.
	checksOf := map[string]int{}
	for _, p := range in.Content.Policies {
		checksOf[p.Name] = len(p.Checks)
	}
	j := &evidenceJoin{resolved: resolved, stale: c.Stale, byPolicy: map[string][]collector.Observation{}, expected: expected, ambiguous: map[string]bool{}}
	for _, k := range slices.Sorted(maps.Keys(obs)) {
		e := expected[k]
		if bundleOf[contribOf(e)] != in.Content.Bundle {
			continue
		}
		j.byPolicy[e.Contribution.LogicalPolicy] = append(j.byPolicy[e.Contribution.LogicalPolicy], obs[k])
	}
	for p, n := range checksOf {
		if n > 1 {
			j.ambiguous[p] = true
		}
	}

	controlsOf := map[string][]string{} // key -> controls
	selectedIn := map[string]bool{}     // policy -> a selected check of a row
	unresolvedIn := map[string]bool{}   // policy -> an unresolved check of a row
	for i := range r.Controls {
		row := &r.Controls[i]
		for ci := range row.Checks {
			ch := &row.Checks[ci]
			switch ch.Selection {
			case CheckUnresolved:
				unresolvedIn[ch.Policy] = true
				continue
			case CheckUnselected:
				continue
			}
			ch.Evidence = j.check(ch.Policy)
			if !ch.Evidence.Resolved {
				unresolvedIn[ch.Policy] = true
				if resolved && j.ambiguous[ch.Policy] {
					row.Limitations = append(row.Limitations, *blocking(CodeEvidenceCheckAmbiguous, "", ch.RuleID,
						"policy %s declares %d checks; its sub-validations cannot be attributed to rule %s", ch.Policy, checksOf[ch.Policy], ch.RuleID))
				}
				continue
			}
			selectedIn[ch.Policy] = true
			for _, o := range j.byPolicy[ch.Policy] {
				if !slices.Contains(controlsOf[o.Key], row.ID) {
					controlsOf[o.Key] = append(controlsOf[o.Key], row.ID)
				}
			}
		}
		j.views(row)
		row.Limitations = sortLimitations(row.Limitations)
	}

	selected := map[string]bool{}
	if in.Selection.Bundle == in.Content.Bundle {
		for _, p := range in.Selection.Policies {
			selected[p.Name] = true
		}
	}
	seen := map[contribKey]bool{}
	noted := map[[2]string]bool{}
	for _, e := range c.Expected {
		k := contribOf(e)
		if seen[k] {
			continue
		}
		seen[k] = true
		s := subjectOf[k]
		ref := ContributionRef{BindingUID: k.binding, Revision: k.revision, EnginePolicy: k.enginePolicy,
			LogicalPolicy: e.Contribution.LogicalPolicy, Mode: e.Contribution.Mode, Bundle: v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}}
		p := ref.LogicalPolicy
		code := ""
		switch {
		case !resolved:
			ref.Attribution = AttributionUnresolved
		case ref.Bundle != in.Content.Bundle:
			ref.Attribution, code = AttributionOtherContent, CodeEvidenceOtherContent
		case selectedIn[p]:
			ref.Attribution = AttributionAttributed
		case unresolvedIn[p] || checksOf[p] == 0 || !r.Inventory.Resolved || !r.Mappings.Resolved:
			ref.Attribution, code = AttributionUnresolved, CodeEvidenceUnattributed
		case !selected[p]:
			ref.Attribution, code = AttributionNotSelected, CodeEvidenceNotSelected
		default:
			ref.Attribution, code = AttributionUnmapped, CodeEvidenceUnmapped
		}
		te.Contributions = append(te.Contributions, ref)
		if code == "" || noted[[2]string{p, ref.Attribution}] {
			continue
		}
		noted[[2]string{p, ref.Attribution}] = true
		switch code {
		case CodeEvidenceOtherContent:
			lims = append(lims, *notice(code, "", p, "observations of %s applied from %s@%s are not attributed to the controls of %s@%s",
				p, ref.Bundle.Name, ref.Bundle.Digest, in.Content.Bundle.Name, in.Content.Bundle.Digest))
		case CodeEvidenceUnattributed:
			lims = append(lims, *notice(code, "", p, "observations of %s are not attributed: the baseline, its mappings, or its checks are unresolved", p))
		case CodeEvidenceNotSelected:
			lims = append(lims, *notice(code, "", p, "observations of %s are not attributed: the selection does not select it", p))
		case CodeEvidenceUnmapped:
			lims = append(lims, *notice(code, "", p, "observations of %s are not attributed: no selected baseline control maps its checks", p))
		}
	}
	slices.SortFunc(te.Contributions, func(a, b ContributionRef) int {
		return cmp.Or(strings.Compare(a.BindingUID, b.BindingUID), strings.Compare(a.Revision, b.Revision), strings.Compare(a.EnginePolicy, b.EnginePolicy))
	})
	for _, o := range ev.Evaluation.Observations {
		e, ok := expected[o.Key]
		if !ok || obs[o.Key].Key == "" {
			continue
		}
		rec := ObservationRecord{Expected: e, Observation: o}
		if ctl := controlsOf[o.Key]; len(ctl) > 0 {
			rec.Controls = slices.Clone(ctl)
			slices.SortFunc(rec.Controls, compareIDs)
		}
		te.Observations = append(te.Observations, rec)
		delete(obs, o.Key) // a repeated observation is recorded once
	}
	slices.SortFunc(te.Observations, func(a, b ObservationRecord) int { return strings.Compare(a.Observation.Key, b.Observation.Key) })
	r.Limitations = append(r.Limitations, lims...)
}

// check is the evidence view of one selected check of policy p.
func (j *evidenceJoin) check(p string) *CheckEvidence {
	if !j.resolved || j.ambiguous[p] {
		return &CheckEvidence{EvidenceView: EvidenceView{}}
	}
	ce := &CheckEvidence{Contributions: []ContributionEvidence{}}
	byContrib := map[contribKey][]collector.Observation{}
	for _, o := range j.byPolicy[p] {
		k := contribOf(j.expected[o.Key])
		byContrib[k] = append(byContrib[k], o)
	}
	keys := slices.SortedFunc(maps.Keys(byContrib), func(a, b contribKey) int {
		return cmp.Or(strings.Compare(a.binding, b.binding), strings.Compare(a.revision, b.revision), strings.Compare(a.enginePolicy, b.enginePolicy))
	})
	for _, k := range keys {
		group := byContrib[k]
		e, o := collector.Tally(group, 0)
		ref := ContributionEvidence{BindingUID: k.binding, Revision: k.revision, EnginePolicy: k.enginePolicy,
			Mode: j.expected[group[0].Key].Contribution.Mode, Evidence: e, Outcomes: o, Observations: []string{}}
		for _, x := range group {
			ref.Observations = append(ref.Observations, x.Key)
		}
		ce.Contributions = append(ce.Contributions, ref)
	}
	ce.EvidenceView = j.view([]string{p}, j.byPolicy[p])
	return ce
}

// view counts observations (unique by key) of policies, with the stale
// scopes that make those policies' expected checks unknown.
func (j *evidenceJoin) view(policies []string, obs []collector.Observation) EvidenceView {
	stale := 0
	for _, s := range j.stale {
		if s.Policy == "" || slices.Contains(policies, s.Policy) {
			stale++
		}
	}
	e, o := collector.Tally(obs, stale)
	return EvidenceView{Resolved: true, Evidence: &e, Outcomes: &o}
}

// views sets the control and statement views of a row: unique observations
// of its selected checks. Any unresolved selected check leaves the view
// unresolved.
func (j *evidenceJoin) views(row *ControlCoverage) {
	type acc struct {
		rules    []string
		policies []string
		resolved bool
	}
	ctl := &acc{resolved: true}
	stmts := map[string]*acc{}
	has := false
	for _, ch := range row.Checks {
		if ch.Evidence == nil {
			continue
		}
		has = true
		add := func(a *acc) {
			a.rules = append(a.rules, ch.RuleID)
			if !slices.Contains(a.policies, ch.Policy) {
				a.policies = append(a.policies, ch.Policy)
			}
			a.resolved = a.resolved && ch.Evidence.Resolved
		}
		add(ctl)
		for _, s := range ch.Statements {
			if stmts[s.ID] == nil {
				stmts[s.ID] = &acc{resolved: true}
			}
			add(stmts[s.ID])
		}
	}
	if !has {
		return
	}
	viewOf := func(a *acc) EvidenceView {
		if !a.resolved {
			return EvidenceView{}
		}
		seen := map[string]bool{}
		var obs []collector.Observation
		for _, p := range a.policies {
			for _, o := range j.byPolicy[p] {
				if !seen[o.Key] {
					seen[o.Key] = true
					obs = append(obs, o)
				}
			}
		}
		return j.view(a.policies, obs)
	}
	v := viewOf(ctl)
	row.Evidence = &v
	row.StatementEvidence = []StatementEvidence{}
	for _, id := range slices.SortedFunc(maps.Keys(stmts), compareIDs) {
		a := stmts[id]
		slices.Sort(a.rules)
		row.StatementEvidence = append(row.StatementEvidence, StatementEvidence{ID: id, Rules: a.rules, EvidenceView: viewOf(a)})
	}
}

func sameObservation(a, b collector.Observation) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// printableKey renders an observation key's NUL separators visibly.
func printableKey(k string) string {
	return fmt.Sprintf("%q", strings.ReplaceAll(k, "\x00", "|"))
}
