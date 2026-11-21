package preview

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file is the evidence part of the report (task 5.3). Evidence is
// context about the observed configuration, never a policy impact and never
// a reason for an incomplete report. It consumes two owner contracts:
//
//   - targeting.ExpectedEvidence, the subjects (contribution, namespace
//     instance, revision) and stale scopes the assessment collector expects
//     evidence for, derived from the observed configuration;
//   - the assessment owner's current-evidence read model, the binding's
//     status.assessment.current. The owner writes it after applying its
//     attribution rules (collector.CaptureV2.Evaluate) and its freshness
//     rules (maxEvidenceAge, next expiry), and summarizes it with
//     collector.Tally's vocabulary. The preview does not re-run attribution:
//     it has neither the engine reports nor the controller's continuity
//     boundaries, and it reads no workload.
//
// The owner's status is per binding and does not record which revisions or
// namespaces it evaluated, so every subject of a binding carries the
// binding's state. A proposed revision that differs from the observed one has
// no evidence at all: it is reported not-evaluated, and whatever exists for
// the observed revision stays historical context for that revision only.

// ObservedEvidence is a binding's evidence state as the cluster records it,
// read with the binding in the final capture. It is informational, so it is
// not part of the rechecked projections: the owner rewrites it whenever
// evidence changes, and a recapture for it would never settle.
type ObservedEvidence struct {
	Binding    string    `json:"binding"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
	// ObservedGeneration is the targeting controller's
	// status.observedGeneration.
	ObservedGeneration int64 `json:"observedGeneration"`
	// Current is the assessment owner's status.assessment.current; nil when
	// none is recorded.
	Current *v1alpha1.CurrentEvidence `json:"current,omitempty"`
	// Invalid explains a status.assessment.current that does not match the
	// supported contract.
	Invalid string `json:"invalid,omitempty"`
}

// EvidenceState is the state of the evidence for observed revisions.
type EvidenceState string

const (
	// EvidenceCurrent: the owner's current evidence is fresh at the end of
	// the observation, consistent, and Complete: every expected observation
	// of the binding is attributable.
	EvidenceCurrent EvidenceState = "current"
	// EvidenceIncomplete: fresh and consistent, but some expected
	// observations of the binding lack attributable evidence. The owner's
	// status does not say which; the run's package does.
	EvidenceIncomplete EvidenceState = "incomplete"
	// EvidenceNoTargets: the owner evaluated an empty scope and the observed
	// configuration expects no subject either. Never a pass.
	EvidenceNoTargets EvidenceState = "no-targets"
	// EvidenceStale: the owner's next expiry passed by the end of the
	// observation, so its evidence is no longer current.
	EvidenceStale EvidenceState = "stale"
	// EvidenceMissing: no current evidence is recorded for the binding.
	EvidenceMissing EvidenceState = "missing"
	// EvidenceUnattributable: current evidence is recorded but cannot be
	// attributed to the observed revisions (see the binding's reason).
	EvidenceUnattributable EvidenceState = "unattributable"
	// EvidenceNotObserved: the subject exists only in the proposal; there
	// is no observed revision to have evidence for.
	EvidenceNotObserved EvidenceState = "not-observed"
)

// EvidenceProposal says what the proposal does to a subject's evidence.
type EvidenceProposal string

const (
	// ProposalUnchanged: the proposal keeps the subject's revision, so the
	// observed evidence describes the proposed configuration too.
	ProposalUnchanged EvidenceProposal = "unchanged"
	// ProposalNotEvaluated: the proposed revision is new or replaces the
	// observed one. Nothing has evaluated it; observed evidence is
	// historical context for the observed revision only.
	ProposalNotEvaluated EvidenceProposal = "not-evaluated"
	// ProposalWithdrawn: the subject leaves the proposed configuration (its
	// contribution is removed or the namespace leaves its scope).
	ProposalWithdrawn EvidenceProposal = "withdrawn"
)

// Evidence limitation codes. All are informational.
const (
	LimitEvidenceMissing        ObserveCode = "evidence-missing"
	LimitEvidenceStale          ObserveCode = "evidence-stale"
	LimitEvidenceUnattributable ObserveCode = "evidence-unattributable"
	LimitEvidenceIncomplete     ObserveCode = "evidence-incomplete"
	// LimitEvidenceNotEvaluated: proposed revisions have no evidence until
	// they are applied and assessed.
	LimitEvidenceNotEvaluated ObserveCode = "evidence-not-evaluated"
	// LimitEvidencePerBinding: the owner records current evidence per
	// binding, without the revisions or namespaces it evaluated.
	LimitEvidencePerBinding ObserveCode = "evidence-per-binding"
)

// OwnerCurrentEvidence is the assessment owner's current evidence of one
// binding, as recorded, without its free-text limitations.
type OwnerCurrentEvidence struct {
	Evidence    v1alpha1.EvidenceSummary `json:"evidence"`
	Outcomes    v1alpha1.OutcomeCounts   `json:"outcomes"`
	EvaluatedAt time.Time                `json:"evaluatedAt"`
	// OldestEvaluation is the source evaluation time of the oldest
	// attributable observation, as the owner records it.
	OldestEvaluation *time.Time `json:"oldestEvaluation,omitempty"`
	NextExpiry       *time.Time `json:"nextExpiry,omitempty"`
	// OwnerLimitations counts the owner's limitation messages, which the
	// report does not copy; read them from the binding's status.
	OwnerLimitations int `json:"ownerLimitations"`
}

// EvidenceStaleScope is a policy (or, without one, the whole binding) of the
// observed configuration for which no subject can be expected: it does not
// resolve, or the controller cannot render it.
type EvidenceStaleScope struct {
	Policy string           `json:"policy,omitempty"`
	Reason targeting.Reason `json:"reason"`
}

// BindingEvidence is the evidence context of one observed binding that the
// proposal involves.
type BindingEvidence struct {
	Binding            string        `json:"binding"`
	UID                types.UID     `json:"uid"`
	Generation         int64         `json:"generation"`
	ObservedGeneration int64         `json:"observedGeneration"`
	State              EvidenceState `json:"state"`
	Reason             string        `json:"reason"`
	// ExpectedSubjects is the number of targeting.ExpectedEvidence subjects
	// of the observed configuration.
	ExpectedSubjects int                   `json:"expectedSubjects"`
	StaleScopes      []EvidenceStaleScope  `json:"staleScopes"`
	Current          *OwnerCurrentEvidence `json:"current"`
}

// bindingSubjects are the expected-evidence subjects and stale scopes of one
// observed binding, or why they could not be derived.
type bindingSubjects struct {
	subjects []targeting.EvidenceSubject
	stale    []EvidenceStaleScope
	err      error
}

// expectedEvidence derives the observed subjects of the named bindings with
// targeting.ExpectedEvidence, one binding at a time so that content another
// binding cannot resolve does not hide these. Render failures, which the
// controller holds as undelivered, count as stale scopes.
func (a *adapter) expectedEvidence(names []string) map[string]*bindingSubjects {
	out := map[string]*bindingSubjects{}
	for _, n := range names {
		br := a.base.results[n]
		if br == nil {
			continue
		}
		bs := &bindingSubjects{stale: []EvidenceStaleScope{}}
		subjects, stale, err := targeting.ExpectedEvidence(targeting.Result{ContractVersion: targeting.ContractVersion, Cluster: a.base.res.Cluster,
			Bindings: []targeting.BindingResult{*br}}, a.resolved)
		if err != nil {
			bs.err = err
		}
		bs.subjects = subjects
		for _, s := range stale {
			bs.stale = append(bs.stale, EvidenceStaleScope{Policy: s.Policy, Reason: s.Reason})
		}
		for _, e := range a.base.renderErrs[n] {
			bs.stale = append(bs.stale, EvidenceStaleScope{Policy: e.Policy, Reason: e.Reason})
		}
		slices.SortFunc(bs.stale, func(x, y EvidenceStaleScope) int {
			return cmp.Or(cmp.Compare(x.Policy, y.Policy), cmp.Compare(x.Reason, y.Reason))
		})
		bs.stale = slices.Compact(bs.stale)
		out[n] = bs
	}
	return out
}

// evidenceBindings are the observed bindings the proposal involves: those
// with a contribution row, and bindings the proposal restates or removes
// (a reporting-only edit changes how fresh their evidence must be).
func evidenceBindings(c *Comparison, live map[string]bool) []string {
	names := map[string]bool{}
	for _, r := range c.Contributions {
		if live[r.Key.Binding] {
			names[r.Key.Binding] = true
		}
	}
	for _, o := range c.Objects {
		if kind, name, _ := strings.Cut(o.Identity, "/"); kind == KindBinding && live[name] {
			names[name] = true
		}
	}
	return slices.Sorted(maps.Keys(names))
}

// judgeEvidence decides a binding's evidence state at time at, the end of
// the observation, with the owner's precedence: nothing recorded, expiry,
// then whether the record can describe the observed revisions at all.
func judgeEvidence(ob *ObservedEvidence, bs *bindingSubjects, at time.Time) (EvidenceState, string) {
	cur := ob.Current
	switch {
	case ob.Invalid != "":
		return EvidenceUnattributable, "status.assessment.current does not match the supported contract: " + ob.Invalid
	case cur == nil:
		return EvidenceMissing, "no current evidence is recorded: continuous assessment is not installed or has not evaluated this binding yet"
	case cur.NextExpiry != nil && !at.Before(cur.NextExpiry.Time):
		return EvidenceStale, fmt.Sprintf("the owner's current evidence expired at %s, before the end of the observation; it is not current until the owner evaluates again", cur.NextExpiry.UTC().Format(time.RFC3339))
	case ob.ObservedGeneration != ob.Generation:
		return EvidenceUnattributable, fmt.Sprintf("the controller has observed generation %d of this binding, not the current generation %d, so its current evidence may describe an earlier configuration", ob.ObservedGeneration, ob.Generation)
	case bs.err != nil:
		return EvidenceUnattributable, "the expected-evidence subjects of the observed configuration cannot be derived: " + bs.err.Error()
	case len(bs.stale) > 0 || cur.Evidence.StaleScopes > 0:
		return EvidenceUnattributable, "part of the binding's observed configuration does not resolve or is not delivered (stale scope), so its evidence is unresolved"
	}
	e, o := cur.Evidence, cur.Outcomes
	summary := publication.EvidenceSummary{Completeness: publication.Completeness(e.Completeness), Expected: int(e.Expected), Attributable: int(e.Attributable),
		Missing: int(e.Missing), Rejected: int(e.Rejected), Unresolved: int(e.Unresolved), StaleScopes: int(e.StaleScopes)}
	if err := summary.Validate(); err != nil || o.Pass+o.Fail+o.Error+o.Skip+o.AcceptedRisk+o.NotApplicable+o.Unknown != e.Attributable {
		return EvidenceUnattributable, "the owner's evidence counts do not add up, so they cannot be attributed"
	}
	switch summary.Completeness {
	case publication.NoTargets:
		if len(bs.subjects) > 0 {
			return EvidenceUnattributable, fmt.Sprintf("the owner evaluated no targets, but the observed configuration expects %d subjects", len(bs.subjects))
		}
		return EvidenceNoTargets, "the owner evaluated an empty scope; this is not a pass"
	case publication.Complete:
		return EvidenceCurrent, "every expected observation of the binding is attributable and fresh"
	}
	return EvidenceIncomplete, fmt.Sprintf("%d of %d expected observations of the binding lack attributable evidence (missing %d, rejected %d, unresolved %d); the owner's status does not say which subjects",
		e.Expected-e.Attributable, e.Expected, e.Missing, e.Rejected, e.Unresolved)
}

func timePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

func ownerCurrent(c *v1alpha1.CurrentEvidence) *OwnerCurrentEvidence {
	if c == nil {
		return nil
	}
	o := &OwnerCurrentEvidence{Evidence: c.Evidence, Outcomes: c.Outcomes, EvaluatedAt: c.EvaluatedAt.UTC(), OwnerLimitations: len(c.Limitations)}
	if c.OldestEvaluation != nil {
		o.OldestEvaluation = timePtr(&c.OldestEvaluation.Time)
	}
	if c.NextExpiry != nil {
		o.NextExpiry = timePtr(&c.NextExpiry.Time)
	}
	return o
}

// evidenceLimit maps a binding state to its limitation code.
var evidenceLimit = map[EvidenceState]ObserveCode{
	EvidenceMissing: LimitEvidenceMissing, EvidenceStale: LimitEvidenceStale,
	EvidenceUnattributable: LimitEvidenceUnattributable, EvidenceIncomplete: LimitEvidenceIncomplete,
}

const evidenceAnalyzedReason = "the assessment owner's current evidence (status.assessment.current) of each observed binding the proposal involves, judged at the end of the observation, for the subjects targeting.ExpectedEvidence derives from the observed configuration; evidence is context, never an impact, and a proposed revision is never shown as evaluated"

// fillEvidence builds the evidence part from the comparison's observed
// subjects and the owner's recorded current evidence. It adds limitations
// only: evidence never makes a report incomplete.
func (r *Report) fillEvidence(snap *Snapshot, c *Comparison) {
	r.Evidence = EvidenceReport{Analysis: AnalysisAvailable, Reason: evidenceAnalyzedReason, Bindings: []BindingEvidence{}, Entries: []EvidenceEntry{}}
	observed := map[string]*ObservedEvidence{}
	for i := range snap.Evidence {
		observed[snap.Evidence[i].Binding] = &snap.Evidence[i]
	}
	rows := map[[2]string]*ContributionChange{}
	for i := range c.Contributions {
		rows[[2]string{c.Contributions[i].Key.Binding, c.Contributions[i].Key.Policy}] = &c.Contributions[i]
	}
	states := map[string]BindingEvidence{}
	for _, n := range slices.Sorted(maps.Keys(c.subjects)) {
		bs, ob := c.subjects[n], observed[n]
		if ob == nil {
			continue
		}
		be := BindingEvidence{Binding: n, UID: ob.UID, Generation: ob.Generation, ObservedGeneration: ob.ObservedGeneration,
			ExpectedSubjects: len(bs.subjects), StaleScopes: bs.stale, Current: ownerCurrent(ob.Current)}
		be.State, be.Reason = judgeEvidence(ob, bs, snap.End)
		states[n] = be
		r.Evidence.Bindings = append(r.Evidence.Bindings, be)
		if code, ok := evidenceLimit[be.State]; ok {
			r.Limitations = append(r.Limitations, ReportDiagnostic{Code: code, Stage: StageEvidence, Resource: resourceString(gvrBindings), Name: n, Message: be.Reason})
		}
	}

	seen := map[string]bool{}
	notEvaluated := 0
	add := func(e EvidenceEntry) {
		seen[e.Key.Binding+"\x00"+e.Key.Policy+"\x00"+string(e.Namespace.UID)] = true
		if e.Proposed == ProposalNotEvaluated {
			notEvaluated++
		}
		r.Evidence.Entries = append(r.Evidence.Entries, e)
	}
	for _, n := range slices.Sorted(maps.Keys(c.subjects)) {
		be, ok := states[n]
		if !ok {
			continue
		}
		for _, s := range c.subjects[n].subjects {
			key := ContributionKey{Cluster: s.Cluster, Binding: s.BindingName, BindingUID: s.BindingUID, Policy: s.LogicalPolicy}
			e := EvidenceEntry{Key: key, Namespace: targeting.NamespaceRef{Name: s.Namespace, UID: s.NamespaceUID}, State: be.State,
				ObservedRevision: s.Revision, Proposed: ProposalUnchanged}
			if be.State == EvidenceCurrent && be.Current != nil {
				e.EvaluatedAt = be.Current.OldestEvaluation
			}
			if row := rows[[2]string{s.BindingName, s.LogicalPolicy}]; row != nil {
				switch {
				case row.After == nil || !slices.ContainsFunc(row.After.Targets, func(t targeting.NamespaceRef) bool { return t.UID == s.NamespaceUID }):
					e.Proposed = ProposalWithdrawn
				case row.RevisionEffect != RevisionUnchanged:
					e.Proposed = ProposalNotEvaluated
				}
			}
			add(e)
		}
	}
	// Subjects that exist only in the proposal: new contributions and newly
	// targeted namespaces. Nothing observed describes them.
	for _, row := range c.Contributions {
		if row.After == nil {
			continue
		}
		for _, t := range row.After.Targets {
			if seen[row.Key.Binding+"\x00"+row.Key.Policy+"\x00"+string(t.UID)] {
				continue
			}
			add(EvidenceEntry{Key: row.Key, Namespace: t, State: EvidenceNotObserved, Proposed: ProposalNotEvaluated})
		}
	}
	slices.SortFunc(r.Evidence.Entries, func(x, y EvidenceEntry) int {
		return cmp.Or(cmp.Compare(x.Key.Binding, y.Key.Binding), cmp.Compare(x.Key.Policy, y.Key.Policy),
			cmp.Compare(x.Namespace.Name, y.Namespace.Name), cmp.Compare(x.Namespace.UID, y.Namespace.UID))
	})
	if notEvaluated > 0 {
		r.Limitations = append(r.Limitations, ReportDiagnostic{Code: LimitEvidenceNotEvaluated, Stage: StageEvidence,
			Message: fmt.Sprintf("%d proposed subjects have a new or replaced revision: nothing has evaluated it, and evidence of the observed revision stays historical context for that revision only", notEvaluated)})
	}
	if len(r.Evidence.Bindings) > 0 {
		r.Limitations = append(r.Limitations, ReportDiagnostic{Code: LimitEvidencePerBinding, Stage: StageEvidence,
			Message: "the assessment owner records current evidence per binding, without the revisions or namespaces it evaluated: each subject carries its binding's state, and an evaluation still pending after a recent change is not visible"})
	}
}
