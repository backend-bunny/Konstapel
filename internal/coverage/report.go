package coverage

import (
	"bytes"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// SchemaVersion versions the coverage report model.
const SchemaVersion = "konstapel.io/coverage/v1"

// Automation states of a control. None of them is a verdict: no state
// claims a control, statement, or baseline is satisfied, and there is no
// "full" state.
const (
	// AutomationNone: no authored technical mapping targets the control.
	// It has no automated assessment; it is not passing or not applicable.
	AutomationNone = "none"
	// AutomationUnselected: authored mappings exist, but the binding's
	// profile selects none of their checks; nothing is evaluated.
	AutomationUnselected = "unselected"
	// AutomationPartial: at least one selected check is mapped. Technical
	// coverage is bounded by each mapping's authored description.
	AutomationPartial = "partial"
	// AutomationUnknown: a mapping for the control could not be resolved
	// (or the mapping documents themselves could not be read), so neither
	// "none" nor "partial" can be stated.
	AutomationUnknown = "unknown"
)

// Selection states of a mapped check.
const (
	CheckSelected   = "selected"
	CheckUnselected = "unselected"
	CheckUnresolved = "unresolved"
)

// Report is coverage report v1 for one assessment scope: the inventory,
// the authored technical coverage, and the assessment owner's technical
// evidence joined to it. A later group of add-control-coverage-reporting
// adds the supporting-evidence context.
type Report struct {
	SchemaVersion string `json:"schemaVersion"`
	// AsOf is the closure/observation time of the inputs, never the
	// rendering time.
	AsOf      time.Time      `json:"asOf"`
	Scope     Scope          `json:"scope"`
	Inputs    Inputs         `json:"inputs"`
	Inventory Inventory      `json:"inventory"`
	Mappings  MappingSummary `json:"mappings"`
	// Controls are every selected control, ordered by identifier; empty
	// when the inventory is unresolved (never a guessed list).
	Controls []ControlCoverage `json:"controls"`
	// TechnicalEvidence is the owner's evaluated capture, when provided.
	TechnicalEvidence TechnicalEvidence `json:"technicalEvidence"`
	// Limitations are not attributable to one control row.
	Limitations []Limitation `json:"limitations"`
	// Sources are the package files the report was built from, by
	// package-relative path, with their sha256: every OSCAL document read
	// and the packaged capture and evaluation. Empty outside a package.
	Sources []Source `json:"sources"`
}

// Source kinds.
const (
	SourceCapture    = "capture"
	SourceEvaluation = "evaluation"
)

// Source is a package-relative reference to one input file. Kind is an
// OSCAL model (catalog, profile, component-definition), SourceCapture or
// SourceEvaluation. SHA256 is lowercase hex, as in the package descriptor.
type Source struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// Packaging places a report in an assessment package.
type Packaging struct {
	// ContentPath is the package directory holding the content handle's
	// files: "" for the package root (a vendored run's content/ tree), or
	// "bundles/<hex>" for one member of a run's content set.
	ContentPath string
	// Evidence are the packaged capture and evaluation files.
	Evidence []Source
}

// Scope identifies the assessment scope a report describes.
type Scope struct {
	// Kind is the package scope kind (Binding or Namespace), when packaged.
	Kind       string         `json:"kind,omitempty"`
	Cluster    string         `json:"cluster,omitempty"`
	Binding    *ObjectRef     `json:"binding,omitempty"`
	Namespaces []NamespaceRef `json:"namespaces,omitempty"`
}

// ObjectRef names a cluster-scoped object by name and UID.
type ObjectRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// NamespaceRef names a namespace by name and UID.
type NamespaceRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// Inputs are the content and selection a report was built from.
type Inputs struct {
	// Bundle is the content handle's pinned name and digest.
	Bundle v1alpha1.BundleReference `json:"bundle"`
	// Selection is the binding profile's policy selection.
	Selection Selection `json:"selection"`
	// Semantics is the profile-resolution contract (Semantics).
	Semantics string `json:"semantics"`
	// ContentPath is the package directory of the content (Packaging);
	// document paths of the inventory and mappings are relative to it.
	ContentPath string `json:"contentPath,omitempty"`
}

// Inventory is the resolution state and size of the selected baseline,
// independent of mappings and evidence.
type Inventory struct {
	Resolved bool         `json:"resolved"`
	Profile  *DocumentRef `json:"profile,omitempty"`
	// Catalog qualifies every control and statement ID of the report: a
	// control's identity is this digest plus its ID.
	Catalog *DocumentRef  `json:"catalog,omitempty"`
	Imports []DocumentRef `json:"imports,omitempty"`
	// Documents are what was read when the inventory is unresolved.
	Documents []DocumentRef `json:"documents,omitempty"`
	// Controls counts selected controls including enhancements; Enhancements
	// counts those with a parent; Statements counts their statement parts.
	Controls     int `json:"controls"`
	Enhancements int `json:"enhancements"`
	Statements   int `json:"statements"`
}

// MappingSummary describes the authored mapping documents.
type MappingSummary struct {
	Resolved    bool          `json:"resolved"`
	Definitions []DocumentRef `json:"definitions"`
}

// Selection is the binding profile's selected logical policies.
type Selection struct {
	Bundle   v1alpha1.BundleReference `json:"bundle"`
	Policies []SelectedPolicy         `json:"policies"`
}

// SelectedPolicy is one selected logical policy. Parameters are the
// policy's engine settings from the profile; they are never values of OSCAL
// control parameters.
type SelectedPolicy struct {
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

// SelectionOf is the selection a ComplianceProfile makes.
func SelectionOf(spec v1alpha1.ComplianceProfileSpec) Selection {
	s := Selection{Bundle: spec.Bundle, Policies: []SelectedPolicy{}}
	for _, p := range spec.Policies {
		sp := SelectedPolicy{Name: p.Name}
		if p.Parameters != nil && len(p.Parameters.Raw) > 0 {
			sp.Parameters = slices.Clone(p.Parameters.Raw)
		}
		s.Policies = append(s.Policies, sp)
	}
	return s
}

// ControlCoverage is one selected control's row.
type ControlCoverage struct {
	Control
	// QualifiedID is the control's identity: the catalog digest and its ID.
	QualifiedID string `json:"qualifiedId"`
	// Automation is the control's technical coverage state.
	Automation string `json:"automation"`
	// Checks are the authored checks mapped to the control, by rule ID.
	Checks []CheckCoverage `json:"checks"`
	// Evidence counts the unique observations of the control's selected
	// checks, and StatementEvidence those of each mapped statement. Both
	// are set only with technical evidence and a selected check. They
	// describe evidence, not satisfaction, and are not additive across
	// rows: a shared check's observations count under every row.
	Evidence          *EvidenceView       `json:"evidence,omitempty"`
	StatementEvidence []StatementEvidence `json:"statementEvidence,omitempty"`
	// Limitations explain an unknown state.
	Limitations []Limitation `json:"limitations,omitempty"`
}

// CheckCoverage is one rule/check mapped to a control.
type CheckCoverage struct {
	RuleID  string `json:"ruleId"`
	CheckID string `json:"checkId,omitempty"`
	// Policy is the logical policy providing the check; PolicyDigest is
	// the sha256 of its source file.
	Policy       string `json:"policy,omitempty"`
	PolicyDigest string `json:"policyDigest,omitempty"`
	Selection    string `json:"selection"`
	// Description is the rule's authored coverage limit (Rule_Description).
	Description      string `json:"description,omitempty"`
	CheckDescription string `json:"checkDescription,omitempty"`
	// RequirementDescription is the implemented requirement's description.
	RequirementDescription string `json:"requirementDescription,omitempty"`
	// Statements are the mapped statements; a mapping that names no
	// statement covers the requirement as authored, not every statement.
	Statements  []StatementMapping `json:"statements"`
	Definitions []string           `json:"definitions"`
	// RuleParameters configure the rule; OSCALParameters are authored
	// settings of the control's OSCAL parameters. PolicyParameters are the
	// profile's engine settings for a selected policy, kept apart from both.
	RuleParameters   []RuleParameter    `json:"ruleParameters,omitempty"`
	OSCALParameters  []ParameterSetting `json:"oscalParameters,omitempty"`
	PolicyParameters json.RawMessage    `json:"policyParameters,omitempty"`
	// Evidence is a selected check's technical evidence, when provided.
	Evidence *CheckEvidence `json:"evidence,omitempty"`
}

// StatementMapping is one mapped statement and its authored description.
type StatementMapping struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
}

// Input is everything a report is built from. It is pure data: Build reads
// no clock and no cluster.
type Input struct {
	// AsOf is the inputs' closure time. With Evidence it may be left zero
	// and is then the capture's closure; any other time is a mismatch.
	AsOf      time.Time
	Scope     Scope
	Content   Content
	Selection Selection
	Options   Options
	// Evidence is the owner's evaluated capture; nil builds the inventory
	// and authored coverage only.
	Evidence *Evidence
	// Packaging, when set, records the package-relative sources.
	Packaging *Packaging
}

// Build resolves the baseline and mappings of in.Content and joins them to
// the selection. An unresolved inventory yields a report with no controls
// and its limitations, never a guessed list.
func Build(in Input) *Report {
	in.Selection = sortedSelection(in.Selection)
	sel := in.Selection
	r := newReport(in)
	defer finish(r, in)
	l := newLoader(in.Content, in.Options)
	b, err := readBaseline(l)
	if err != nil {
		ue := err.(*UnresolvedError)
		r.Inventory.Documents = ue.Documents
		r.Limitations = ue.Limitations
		return r
	}
	inv := &r.Inventory
	inv.Resolved, inv.Profile, inv.Catalog, inv.Imports = true, &b.Profile, &b.Catalog, b.Imports
	for _, c := range b.Controls {
		inv.Controls++
		if c.Parent != "" {
			inv.Enhancements++
		}
		inv.Statements += len(c.Statements)
	}
	r.Limitations = append(r.Limitations, b.Limitations...)

	m := readMappings(l, b)
	r.Mappings = MappingSummary{Resolved: m.Resolved, Definitions: m.Definitions}
	if r.Mappings.Definitions == nil {
		r.Mappings.Definitions = []DocumentRef{}
	}
	r.Limitations = append(r.Limitations, m.Limitations...)

	j := newJoin(in.Content, sel)
	r.Limitations = append(r.Limitations, j.limitations...)
	for _, c := range b.Controls {
		row := j.control(c, m)
		row.QualifiedID = b.Qualified(c.ID)
		r.Controls = append(r.Controls, row)
	}
	return r
}

// Unavailable is the report of a scope whose baseline content cannot be
// read at all (no packaged content, no recorded selection, no profile): an
// unresolved inventory with one blocking limitation, and the technical
// evidence retained as recorded but attributed to no control. It is the
// coverage diagnostic; it never lists or guesses controls.
//
// in.Content carries only the intended bundle reference (its zero handle
// reads nothing), so the evidence of that bundle is reported unattributed
// rather than as another bundle's.
func Unavailable(in Input, code, subject, format string, a ...any) *Report {
	in.Selection = sortedSelection(in.Selection)
	r := newReport(in)
	r.Limitations = append(r.Limitations, *blocking(code, "", subject, format, a...))
	finish(r, in)
	return r
}

func newReport(in Input) *Report {
	r := &Report{SchemaVersion: SchemaVersion, AsOf: in.AsOf.UTC(), Scope: in.Scope,
		Inputs:   Inputs{Bundle: in.Content.Bundle, Selection: in.Selection, Semantics: Semantics},
		Mappings: MappingSummary{Definitions: []DocumentRef{}}, Controls: []ControlCoverage{}, Limitations: []Limitation{},
		TechnicalEvidence: TechnicalEvidence{State: EvidenceNotProvided}, Sources: []Source{}}
	if in.Packaging != nil {
		r.Inputs.ContentPath = in.Packaging.ContentPath
	}
	return r
}

// finish joins the evidence, records the sources and orders limitations.
func finish(r *Report, in Input) {
	if in.Evidence != nil {
		joinEvidence(r, in)
	}
	r.Limitations = sortLimitations(r.Limitations)
	if in.Packaging != nil {
		r.Sources = sources(r, *in.Packaging)
	}
}

// sortedSelection orders the selected policies by name: the profile's
// listing order carries no meaning and must not change the report.
func sortedSelection(sel Selection) Selection {
	sel.Policies = slices.Clone(sel.Policies)
	if sel.Policies == nil {
		sel.Policies = []SelectedPolicy{}
	}
	slices.SortStableFunc(sel.Policies, func(a, b SelectedPolicy) int { return strings.Compare(a.Name, b.Name) })
	return sel
}

// sources are the package-relative references of every document the report
// read and of the packaged evidence, ordered by path.
func sources(r *Report, p Packaging) []Source {
	out := []Source{}
	seen := map[string]bool{}
	add := func(s Source) {
		if s.Path == "" || seen[s.Path] {
			return
		}
		seen[s.Path] = true
		out = append(out, s)
	}
	doc := func(d *DocumentRef) {
		if d == nil || d.Digest == "" {
			return
		}
		add(Source{Path: path.Join(p.ContentPath, d.Path), Kind: d.Model, SHA256: strings.TrimPrefix(d.Digest, "sha256:")})
	}
	inv := r.Inventory
	doc(inv.Profile)
	doc(inv.Catalog)
	for i := range inv.Imports {
		doc(&inv.Imports[i])
	}
	for i := range inv.Documents {
		doc(&inv.Documents[i])
	}
	for i := range r.Mappings.Definitions {
		doc(&r.Mappings.Definitions[i])
	}
	for _, s := range p.Evidence {
		add(s)
	}
	slices.SortFunc(out, func(a, b Source) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// join resolves rules to the content's policies and the selection.
type join struct {
	policyOf    map[string]policyRef // rule -> policy
	selected    map[string]json.RawMessage
	mismatch    bool
	limitations []Limitation
}

type policyRef struct {
	name, path, digest string
}

func newJoin(c Content, sel Selection) *join {
	j := &join{policyOf: map[string]policyRef{}, selected: map[string]json.RawMessage{}}
	known := map[string]bool{}
	for _, p := range c.Policies {
		known[p.Name] = true
		ref := policyRef{name: p.Name, path: p.Path}
		if f, ok := c.files[p.Path]; ok {
			ref.digest = "sha256:" + f.sha256
		}
		for _, ch := range p.Checks {
			j.policyOf[ch.RuleID] = ref
		}
	}
	if sel.Bundle == (v1alpha1.BundleReference{}) {
		j.mismatch = true
		j.limitations = append(j.limitations, *blocking(CodeSelectionUnavailable, "", "",
			"the binding profile's policy selection was not recorded for this scope; no check is joined, and none is assumed selected or unselected"))
		return j
	}
	if sel.Bundle != c.Bundle {
		j.mismatch = true
		j.limitations = append(j.limitations, *blocking(CodeSelectionContentMismatch, "", sel.Bundle.Name+"@"+sel.Bundle.Digest,
			"the selection pins %s@%s but the content is %s@%s; no check is joined", sel.Bundle.Name, sel.Bundle.Digest, c.Bundle.Name, c.Bundle.Digest))
		return j
	}
	for _, p := range sel.Policies {
		if !known[p.Name] {
			j.limitations = append(j.limitations, *blocking(CodePolicyNotInContent, "", p.Name, "selected policy %s is not a policy of %s", p.Name, c.Bundle.Name))
			continue
		}
		j.selected[p.Name] = compactJSON(p.Parameters)
	}
	return j
}

func compactJSON(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return slices.Clone(raw)
	}
	return buf.Bytes()
}

func (j *join) control(c Control, m *Mappings) ControlCoverage {
	row := ControlCoverage{Control: c, Checks: []CheckCoverage{}}
	byRule := map[string]*CheckCoverage{}
	unresolved := map[string]bool{}
	for _, e := range m.edges[c.ID] {
		ch := byRule[e.rule]
		if ch == nil {
			ch = &CheckCoverage{RuleID: e.rule, Description: e.ruleDescription, CheckDescription: e.checkDescription,
				RequirementDescription: e.requirementDesc, Statements: []StatementMapping{}, Definitions: []string{}}
			if len(e.checkIDs) > 0 {
				ch.CheckID = e.checkIDs[0]
			}
			if p, ok := j.policyOf[e.rule]; ok {
				ch.Policy, ch.PolicyDigest = p.name, p.digest
			}
			byRule[e.rule] = ch
		}
		if len(e.problems) > 0 {
			unresolved[e.rule] = true
			row.Limitations = append(row.Limitations, e.problems...)
		} else if e.statement != "" {
			ch.Statements = append(ch.Statements, StatementMapping{ID: e.statement, Description: e.statementDesc})
		}
		for _, d := range e.definitions {
			if !slices.Contains(ch.Definitions, d) {
				ch.Definitions = append(ch.Definitions, d)
			}
		}
		ch.RuleParameters = mergeRuleParams(ch.RuleParameters, e.ruleParams)
		for _, s := range e.oscalParams {
			if !slices.ContainsFunc(ch.OSCALParameters, func(x ParameterSetting) bool { return x.ParamID == s.ParamID }) {
				ch.OSCALParameters = append(ch.OSCALParameters, s)
			}
		}
	}
	anySelected := false
	for _, rule := range slices.Sorted(maps.Keys(byRule)) {
		ch := byRule[rule]
		params, selected := j.selected[ch.Policy]
		switch {
		case unresolved[rule] || j.mismatch || ch.Policy == "":
			ch.Selection = CheckUnresolved
		case selected:
			ch.Selection, ch.PolicyParameters = CheckSelected, params
			anySelected = true
		default:
			ch.Selection = CheckUnselected
		}
		slices.SortFunc(ch.Statements, func(a, b StatementMapping) int { return compareIDs(a.ID, b.ID) })
		slices.SortFunc(ch.OSCALParameters, func(a, b ParameterSetting) int { return compareIDs(a.ParamID, b.ParamID) })
		slices.Sort(ch.Definitions)
		row.Checks = append(row.Checks, *ch)
	}
	switch {
	case len(unresolved) > 0 || (j.mismatch && len(row.Checks) > 0):
		row.Automation = AutomationUnknown
	case anySelected:
		row.Automation = AutomationPartial
	case len(row.Checks) > 0:
		row.Automation = AutomationUnselected
	case !m.Resolved:
		row.Automation = AutomationUnknown
	default:
		row.Automation = AutomationNone
	}
	row.Limitations = sortLimitations(row.Limitations)
	return row
}

func mergeRuleParams(have, add []RuleParameter) []RuleParameter {
	for _, p := range add {
		i := slices.IndexFunc(have, func(x RuleParameter) bool { return x.ID == p.ID })
		if i < 0 {
			have = append(have, p)
		} else if len(have[i].Values) == 0 {
			have[i].Values = p.Values
		}
	}
	slices.SortFunc(have, func(a, b RuleParameter) int { return compareIDs(a.ID, b.ID) })
	return have
}
