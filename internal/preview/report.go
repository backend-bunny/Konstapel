package preview

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file is the versioned preview report (task 6.2): one model that the
// JSON output serializes and the text output renders, so both formats carry
// the same meaning. The report describes one earlier observation; it holds
// capture times only, no rendering time and no random identifiers, so the
// same captured inputs give the same bytes.

// ReportKind and ReportSchemaVersion identify the JSON report contract. The
// version is independent of targeting.ContractVersion; the consumed contract
// versions are recorded in Observation.Contracts.
const (
	ReportKind          = "PolicyChangePreview"
	ReportSchemaVersion = 1
)

// Stage is where in the preview a diagnostic arose.
type Stage string

const (
	StageInput       Stage = "input"
	StageKubeconfig  Stage = "kubeconfig"
	StageObservation Stage = "observation"
	StageContent     Stage = "content"
	StageComparison  Stage = "comparison"
	StageExceptions  Stage = "exceptions"
	StageEvidence    Stage = "evidence"
)

var stageOrder = map[Stage]int{StageInput: 0, StageKubeconfig: 1, StageObservation: 2, StageContent: 3, StageComparison: 4, StageExceptions: 5, StageEvidence: 6}

// Report-level codes. Errors make a report incomplete; limitations do not.
const (
	// ReportKubeconfigInvalid: the kubeconfig or the selected context could
	// not be loaded. Nothing was observed.
	ReportKubeconfigInvalid ObserveCode = "kubeconfig-invalid"
	// ReportObservationFailed: the observation could not start.
	ReportObservationFailed ObserveCode = "observation-failed"
	// ReportContentSetupFailed: the verified content source could not be
	// assembled over the observed configuration.
	ReportContentSetupFailed ObserveCode = "content-setup-failed"
	// ReportComparisonFailed: the comparison stopped without a result.
	ReportComparisonFailed ObserveCode = "comparison-failed"
	// ReportSourcesRequired: OCI bundles are pinned but the caller did not
	// say which bundle-source ConfigMap the controller uses.
	ReportSourcesRequired ObserveCode = "bundle-sources-required"
	// ReportExceptionImpactUndetermined: an observed ComplianceException
	// lies in a namespace and policy that the proposal changes, and the
	// acceptance comparison is not available, so its consequence is unknown.
	ReportExceptionImpactUndetermined ObserveCode = "exception-impact-undetermined"
	// LimitExceptionAnalysisUnavailable: acceptance consequences (renewal,
	// newly forbidden, lifetime, removed scope) are not analyzed yet.
	LimitExceptionAnalysisUnavailable ObserveCode = "exception-analysis-unavailable"
)

// ReportDiagnostic is one coded error or limitation with its location: an
// input position for input problems, a resource for cluster problems.
type ReportDiagnostic struct {
	Code      ObserveCode `json:"code"`
	Stage     Stage       `json:"stage"`
	Resource  string      `json:"resource,omitempty"`
	Namespace string      `json:"namespace,omitempty"`
	Name      string      `json:"name,omitempty"`
	Source    string      `json:"source,omitempty"`
	Document  int         `json:"document,omitempty"`
	Line      int         `json:"line,omitempty"`
	Identity  string      `json:"identity,omitempty"`
	Field     string      `json:"field,omitempty"`
	Message   string      `json:"message"`
}

func fromDiagnostic(stage Stage, d Diagnostic) ReportDiagnostic {
	return ReportDiagnostic{Code: d.Code, Stage: stage, Resource: d.Resource, Namespace: d.Namespace, Name: d.Name, Message: d.Message}
}

func fromInputError(e InputError) ReportDiagnostic {
	return ReportDiagnostic{Code: ObserveCode(e.Code), Stage: StageInput, Source: e.Source, Document: e.Document, Line: e.Line,
		Identity: e.Identity, Field: e.Field, Message: e.Message}
}

// Summary restates counts of the report. ImpactCount (top level) counts
// contribution and namespace rows with at least one impact; it is not a
// number of workloads, failures, violations or controls.
type Summary struct {
	// Compared is true when a comparison produced Changes. Without it no
	// count below describes the cluster.
	Compared            bool `json:"compared"`
	Objects             int  `json:"objects"`
	ReportingOnly       int  `json:"reportingOnlyObjects"`
	ContributionRows    int  `json:"contributionRows"`
	ContributionImpacts int  `json:"contributionImpacts"`
	NamespaceRows       int  `json:"namespaceRows"`
	NamespaceImpacts    int  `json:"namespaceImpacts"`
	// EquivalentReplacements counts contribution rows whose configuration
	// is semantically equal but whose enforcement revision is still replaced
	// (reordered lists, respelled durations, a restated shared profile).
	// They rotate real engine policies and invalidate revision-bound
	// acceptances, so they are impacts and are included in ImpactCount.
	EquivalentReplacements int `json:"equivalentReplacements"`
	// Categories counts impact entries per category.
	Categories map[Category]int `json:"categories"`
}

// ReportObservation is the provenance of the observed cluster: identity,
// window, collections and object revisions. It is a description of that
// observation, not of the cluster at apply time.
type ReportObservation struct {
	Complete            bool   `json:"complete"`
	Cluster             string `json:"cluster,omitempty"`
	Context             string `json:"context"`
	Server              string `json:"server,omitempty"`
	ControllerNamespace string `json:"controllerNamespace"`
	SourcesConfigMap    string `json:"sourcesConfigMap,omitempty"`
	// ControllerVersion is the controller release that OCI bundle
	// compatibility is checked against, as given to the preview.
	ControllerVersion string              `json:"controllerVersion,omitempty"`
	Start             time.Time           `json:"start"`
	End               time.Time           `json:"end"`
	Captures          int                 `json:"captures"`
	Drift             []Drift             `json:"drift,omitempty"`
	Collections       []Collection        `json:"collections"`
	Objects           []ObjectRef         `json:"objects"`
	Namespaces        []ObservedNamespace `json:"namespaces"`
	Sources           *ObservedSources    `json:"sources,omitempty"`
	Contracts         map[string]int      `json:"contracts"`
}

// InputObject is one validated input object.
type InputObject struct {
	Role        Role   `json:"role"`
	Identity    string `json:"identity"`
	Source      string `json:"source"`
	Document    int    `json:"document"`
	Line        int    `json:"line"`
	Fingerprint string `json:"configurationFingerprint"`
	// Ignored are exported server-owned fields that were discarded.
	Ignored []string `json:"ignoredFields,omitempty"`
}

// ReportInputs are the input streams and the validated objects. Objects is
// empty when the input is invalid.
type ReportInputs struct {
	Streams []Stream      `json:"streams"`
	Objects []InputObject `json:"objects"`
}

// ReportChanges are the compared differences.
type ReportChanges struct {
	Objects        []ObjectChange       `json:"objects"`
	AbsentRemovals []string             `json:"absentRemovals"`
	Contributions  []ContributionChange `json:"contributions"`
	Namespaces     []NamespaceChange    `json:"namespaces"`
}

// Analysis says whether an integration produced its part of the report.
type Analysis string

const (
	// AnalysisNotAvailable: the owning integration is not available to this
	// preview, so the part is not analyzed. Its entries are always empty;
	// that emptiness never means "nothing is affected".
	AnalysisNotAvailable Analysis = "not-available"
	// AnalysisAvailable: the owning integration produced the part.
	AnalysisAvailable Analysis = "available"
)

// ExceptionSubject is one observed ComplianceException that lies in a
// namespace and policy the proposal changes. It names the record and the
// responsible contribution rows, never reasons, actors, claims or secrets.
type ExceptionSubject struct {
	Namespace          string            `json:"namespace"`
	Name               string            `json:"name"`
	UID                types.UID         `json:"uid"`
	Policy             string            `json:"policy"`
	AcceptanceRevision int64             `json:"acceptanceRevision"`
	Accepted           bool              `json:"accepted"`
	Contributions      []ContributionKey `json:"contributions"`
	NamespaceRows      int               `json:"namespaceRows"`
}

// ExceptionConsequence is the shape of one analyzed acceptance consequence.
// No consequence is produced until the exception owner's acceptance
// comparison is integrated.
type ExceptionConsequence struct {
	Exception     ExceptionSubject  `json:"exception"`
	Consequence   string            `json:"consequence"`
	Contributions []ContributionKey `json:"contributions"`
	Reason        string            `json:"reason"`
}

// ExceptionReport is the acceptance part of the report.
type ExceptionReport struct {
	Analysis Analysis `json:"analysis"`
	Reason   string   `json:"reason"`
	// Observed is the number of ComplianceExceptions in the complete
	// observation; null when the cluster was not completely observed.
	Observed            *int                   `json:"observed"`
	PotentiallyAffected []ExceptionSubject     `json:"potentiallyAffected"`
	Consequences        []ExceptionConsequence `json:"consequences"`
}

// EvidenceEntry is the evidence context of one expected-evidence subject:
// one contribution in one namespace instance. State describes the evidence
// of the observed revision (the binding's state, see BindingEvidence);
// Proposed says whether that evidence also describes the proposal.
type EvidenceEntry struct {
	Key       ContributionKey        `json:"key"`
	Namespace targeting.NamespaceRef `json:"namespace"`
	State     EvidenceState          `json:"state"`
	// ObservedRevision is the subject's observed enforcement revision;
	// empty for a subject that exists only in the proposal.
	ObservedRevision string `json:"observedRevision,omitempty"`
	// EvaluatedAt is set only for current evidence: the binding's oldest
	// source evaluation, so every observation of this subject was evaluated
	// at or after it.
	EvaluatedAt *time.Time       `json:"evaluatedAt,omitempty"`
	Proposed    EvidenceProposal `json:"proposed"`
}

// EvidenceReport is the evidence part of the report. Evidence is context,
// never a policy impact, and never makes a report incomplete.
type EvidenceReport struct {
	Analysis Analysis `json:"analysis"`
	Reason   string   `json:"reason"`
	// Bindings is the owner's current evidence of every observed binding the
	// proposal involves.
	Bindings []BindingEvidence `json:"bindings"`
	Entries  []EvidenceEntry   `json:"entries"`
}

// Report is the preview result, version ReportSchemaVersion. A report is
// complete only when the observation, content and comparison all finished
// without error; only a complete report supports a statement that no impact
// exists. Changes and AppliedState are null when no comparison ran, so an
// undetermined result is never an empty one.
type Report struct {
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schemaVersion"`
	Complete      bool   `json:"complete"`
	// ImpactCount counts contribution and namespace rows with at least one
	// impact. In an incomplete report it covers only what was determined.
	ImpactCount  int                `json:"impactCount"`
	Summary      Summary            `json:"summary"`
	Observation  *ReportObservation `json:"observation"`
	Inputs       ReportInputs       `json:"inputs"`
	Content      []ContentRecord    `json:"content"`
	Changes      *ReportChanges     `json:"changes"`
	AppliedState *AppliedState      `json:"appliedState"`
	Exceptions   ExceptionReport    `json:"exceptions"`
	Evidence     EvidenceReport     `json:"evidence"`
	Limitations  []ReportDiagnostic `json:"limitations"`
	Errors       []ReportDiagnostic `json:"errors"`
}

const (
	exceptionsReason = "the exception owner's acceptance comparison (add-self-service-policy-exceptions) is not integrated yet: renewal, newly forbidden, lifetime and removed-scope consequences are not analyzed"
	evidenceReason   = "no comparison ran, so no observed subject is known and no evidence is reported"
)

func newReport() *Report {
	return &Report{Kind: ReportKind, SchemaVersion: ReportSchemaVersion,
		Summary:     Summary{Categories: map[Category]int{}},
		Inputs:      ReportInputs{Streams: []Stream{}, Objects: []InputObject{}},
		Content:     []ContentRecord{},
		Exceptions:  ExceptionReport{Analysis: AnalysisNotAvailable, Reason: exceptionsReason, PotentiallyAffected: []ExceptionSubject{}, Consequences: []ExceptionConsequence{}},
		Evidence:    EvidenceReport{Analysis: AnalysisNotAvailable, Reason: evidenceReason, Bindings: []BindingEvidence{}, Entries: []EvidenceEntry{}},
		Limitations: []ReportDiagnostic{}, Errors: []ReportDiagnostic{}}
}

// MarshalReport is the JSON encoding of a report: indented, with a final
// newline, deterministic for the same report.
func MarshalReport(r *Report) ([]byte, error) {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func (r *Report) fail(stage Stage, code ObserveCode, msg string) {
	r.Errors = append(r.Errors, ReportDiagnostic{Code: code, Stage: stage, Message: msg})
}

func (r *Report) inputErrors(err error) bool {
	ie, ok := err.(InputErrors)
	if !ok {
		return false
	}
	for _, e := range ie {
		r.Errors = append(r.Errors, fromInputError(e))
	}
	return true
}

func inputsOf(streams []Stream, proposed, before *Set) ReportInputs {
	in := ReportInputs{Streams: slices.Clone(streams), Objects: []InputObject{}}
	if in.Streams == nil {
		in.Streams = []Stream{}
	}
	for _, s := range []struct {
		role Role
		set  *Set
	}{{RoleProposed, proposed}, {RoleBefore, before}} {
		if s.set == nil {
			continue
		}
		for _, o := range s.set.Objects {
			in.Objects = append(in.Objects, InputObject{Role: s.role, Identity: o.Identity.String(), Source: o.Source, Document: o.Document,
				Line: o.Line, Fingerprint: o.Fingerprint, Ignored: slices.Clone(o.Ignored)})
		}
	}
	return in
}

func observationOf(s *Snapshot, sourcesConfigMap, controllerVersion string) *ReportObservation {
	o := &ReportObservation{Complete: s.Complete, Cluster: s.Cluster, Context: s.Context, Server: s.Server, ControllerNamespace: s.Namespace,
		SourcesConfigMap: sourcesConfigMap, Start: s.Start, End: s.End, Captures: s.Captures, Drift: s.Drift,
		Collections: slices.Clone(s.Collections), Objects: slices.Clone(s.Objects), Namespaces: slices.Clone(s.Namespaces),
		Sources: s.Sources, Contracts: maps.Clone(s.Contracts)}
	if sourcesConfigMap != "" {
		o.ControllerVersion = controllerVersion
	}
	if o.Collections == nil {
		o.Collections = []Collection{}
	}
	if o.Objects == nil {
		o.Objects = []ObjectRef{}
	}
	if o.Namespaces == nil {
		o.Namespaces = []ObservedNamespace{}
	}
	if o.Contracts == nil {
		o.Contracts = map[string]int{}
	}
	return o
}

// contentStage attributes comparison codes about bundle content.
func contentStage(c ObserveCode) Stage {
	switch c {
	case CompareContentFailed, CompareContentMismatch, CompareContentAccessDenied, CompareContentUnavailable, LimitControllerVersion:
		return StageContent
	}
	return StageComparison
}

// fillComparison copies a comparison into the report.
func (r *Report) fillComparison(c *Comparison, snapLimitations []Diagnostic) {
	ch := &ReportChanges{Objects: c.Objects, AbsentRemovals: c.AbsentRemovals, Contributions: c.Contributions, Namespaces: c.Namespaces}
	if ch.Objects == nil {
		ch.Objects = []ObjectChange{}
	}
	if ch.AbsentRemovals == nil {
		ch.AbsentRemovals = []string{}
	}
	r.Changes = ch
	applied := c.Applied
	if applied.Policies == nil {
		applied.Policies = []AppliedEntry{}
	}
	r.AppliedState = &applied
	if c.Content != nil {
		r.Content = c.Content
	}
	r.ImpactCount = c.ImpactCount
	if r.Observation != nil {
		for k, v := range c.Contracts {
			r.Observation.Contracts[k] = v
		}
	}
	fromSnap := map[Diagnostic]bool{}
	for _, d := range snapLimitations {
		fromSnap[d] = true
	}
	for _, d := range c.Limitations {
		stage := contentStage(d.Code)
		if fromSnap[d] {
			stage = StageObservation
		}
		r.Limitations = append(r.Limitations, fromDiagnostic(stage, d))
	}
	for _, d := range c.Errors {
		r.Errors = append(r.Errors, fromDiagnostic(contentStage(d.Code), d))
	}
	s := &r.Summary
	s.Compared, s.Objects, s.ContributionRows, s.NamespaceRows = true, len(ch.Objects), len(ch.Contributions), len(ch.Namespaces)
	for _, o := range ch.Objects {
		if o.ReportingOnly {
			s.ReportingOnly++
		}
	}
	for _, row := range ch.Contributions {
		if len(row.Impacts) > 0 {
			s.ContributionImpacts++
		}
		if row.SemanticallyEquivalent && row.RevisionEffect == RevisionReplacement {
			s.EquivalentReplacements++
		}
		for _, i := range row.Impacts {
			s.Categories[i.Category]++
		}
	}
	for _, row := range ch.Namespaces {
		if len(row.Impacts) > 0 {
			s.NamespaceImpacts++
		}
		for _, i := range row.Impacts {
			s.Categories[i.Category]++
		}
	}
}

// fillExceptions lists the observed ComplianceExceptions whose namespace and
// policy the proposal changes. Until the acceptance comparison is
// integrated, each of them makes the report incomplete: the preview cannot
// claim that their acceptance is unaffected. Exceptions elsewhere cannot be
// affected by this proposal, because acceptance depends only on the
// contributions of its own namespace and policy.
func (r *Report) fillExceptions(snap *Snapshot, ch *ReportChanges) {
	n := len(snap.Exceptions)
	r.Exceptions.Observed = &n
	for _, ex := range snap.Exceptions {
		sub := ExceptionSubject{Namespace: ex.Namespace, Name: ex.Name, UID: ex.UID, Policy: ex.Policy, AcceptanceRevision: ex.AcceptanceRevision,
			Accepted: ex.Acceptance != nil, Contributions: []ContributionKey{}}
		for _, row := range ch.Contributions {
			if row.Key.Policy == ex.Policy && rowTouches(row, ex.Namespace) {
				sub.Contributions = append(sub.Contributions, row.Key)
			}
		}
		for _, row := range ch.Namespaces {
			if row.Policy == ex.Policy && row.Namespace.Name == ex.Namespace {
				sub.NamespaceRows++
			}
		}
		if len(sub.Contributions) == 0 && sub.NamespaceRows == 0 {
			continue
		}
		r.Exceptions.PotentiallyAffected = append(r.Exceptions.PotentiallyAffected, sub)
		r.Errors = append(r.Errors, ReportDiagnostic{Code: ReportExceptionImpactUndetermined, Stage: StageExceptions,
			Resource: resourceString(gvrExceptions), Namespace: ex.Namespace, Name: ex.Name,
			Message: "the proposal changes contributions of policy " + ex.Policy + " in this exception's namespace, and the acceptance comparison is not available, so whether the exception needs renewal, becomes forbidden or loses scope is unknown"})
	}
	slices.SortFunc(r.Exceptions.PotentiallyAffected, func(a, b ExceptionSubject) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	r.Limitations = append(r.Limitations,
		ReportDiagnostic{Code: LimitExceptionAnalysisUnavailable, Stage: StageExceptions, Message: exceptionsReason})
}

func rowTouches(row ContributionChange, namespace string) bool {
	has := func(ns []targeting.NamespaceRef) bool {
		return slices.ContainsFunc(ns, func(n targeting.NamespaceRef) bool { return n.Name == namespace })
	}
	for _, s := range []*ContributionSide{row.Before, row.After} {
		if s != nil && has(s.Targets) {
			return true
		}
	}
	return has(row.NamespacesAdded) || has(row.NamespacesRemoved)
}

// compareReportDiagnostics orders diagnostics by stage, then by input
// position (input problems) or subject (cluster problems), then by code.
func compareReportDiagnostics(a, b ReportDiagnostic) int {
	return cmp.Or(cmp.Compare(stageOrder[a.Stage], stageOrder[b.Stage]),
		cmp.Compare(a.Source, b.Source), cmp.Compare(a.Document, b.Document), cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Code, b.Code), cmp.Compare(a.Identity, b.Identity), cmp.Compare(a.Field, b.Field), strings.Compare(a.Message, b.Message))
}

// finish sorts the diagnostics and decides completeness: complete only with
// a comparison and no error at any stage.
func (r *Report) finish() *Report {
	for _, l := range []*[]ReportDiagnostic{&r.Errors, &r.Limitations} {
		slices.SortFunc(*l, compareReportDiagnostics)
		*l = slices.Compact(*l)
	}
	r.Complete = r.Changes != nil && len(r.Errors) == 0
	return r
}
