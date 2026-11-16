package coverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Package file names of a rendered report (publication.CoverageFile and
// publication.CoverageTextFile).
const (
	JSONFile = publication.CoverageFile
	TextFile = publication.CoverageTextFile
)

// Files are the two renderings of one report: the versioned JSON and the
// readable text derived from the same model. The text names the sha256 of
// the JSON it was rendered with, so the pair is bound together.
type Files struct {
	JSON []byte
	Text []byte
}

// Render renders r as coverage.json and coverage.txt. Both are
// deterministic: the same report always renders the same bytes, and they
// read no clock (times come from the report's inputs).
func Render(r *Report) (Files, error) {
	j, err := RenderJSON(r)
	if err != nil {
		return Files{}, err
	}
	sum := sha256.Sum256(j)
	return Files{JSON: j, Text: RenderText(r, hex.EncodeToString(sum[:]))}, nil
}

// RenderJSON is the canonical JSON encoding of r: two-space indentation and
// a final newline. Field order is the model's; every list is ordered by
// Build.
func RenderJSON(r *Report) ([]byte, error) {
	if r == nil || r.SchemaVersion != SchemaVersion {
		return nil, errors.New("coverage: not a coverage report of this version")
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Parse decodes coverage.json strictly: an unknown field or another schema
// version fails closed.
func Parse(raw []byte) (*Report, error) {
	var head struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("coverage: %w", err)
	}
	if head.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("coverage: unsupported schema version %q", head.SchemaVersion)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("coverage: %w", err)
	}
	if dec.More() {
		return nil, errors.New("coverage: trailing data")
	}
	return &r, nil
}

// VerifyFiles checks that a packaged pair is one report's rendering: the
// JSON parses strictly and is canonical (re-renders to the same bytes),
// and the text is exactly the rendering of that JSON. Any divergence
// between the two fails.
func VerifyFiles(f Files) error {
	r, err := Parse(f.JSON)
	if err != nil {
		return err
	}
	want, err := Render(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(want.JSON, f.JSON) {
		return fmt.Errorf("coverage: %s is not the canonical rendering of its report", JSONFile)
	}
	if !bytes.Equal(want.Text, f.Text) {
		return fmt.Errorf("coverage: %s is not the rendering of %s", TextFile, JSONFile)
	}
	return nil
}

// TextReportLine is the line of coverage.txt naming the JSON it renders,
// followed by the JSON's lowercase hex sha256.
const TextReportLine = "Report JSON: " + JSONFile + " sha256 "

// RenderText renders r as readable text. jsonSHA256 is the hex sha256 of
// r's JSON rendering, named in the header. Every value of the JSON report
// appears; content strings are printed with control characters replaced.
func RenderText(r *Report, jsonSHA256 string) []byte {
	w := &textWriter{}
	w.line(0, "Konstapel control coverage report")
	w.line(0, "Schema: %s", r.SchemaVersion)
	w.line(0, "%s%s", TextReportLine, jsonSHA256)
	w.blank()
	w.line(0, "This report lists every control of the selected baseline, the authored")
	w.line(0, "technical checks mapped to it, and the evidence observed for them. It is")
	w.line(0, "not a compliance verdict: no control, statement, or baseline is marked")
	w.line(0, "satisfied. Automation \"partial\" means at least one selected check is")
	w.line(0, "mapped, bounded by its authored coverage limit; \"none\" means no technical")
	w.line(0, "mapping, so no automated assessment (not passing, not not-applicable);")
	w.line(0, "\"unselected\" means mapped checks exist but the profile selects none;")
	w.line(0, "\"unknown\" means a mapping could not be resolved. Evidence counts are")
	w.line(0, "unique observations per row and are not additive across rows.")
	w.blank()

	w.line(0, "As of: %s", ts(r.AsOf))
	sc := r.Scope
	w.line(0, "Scope:")
	w.field(1, "Kind", sc.Kind)
	w.field(1, "Cluster", sc.Cluster)
	if sc.Binding != nil {
		w.line(1, "Binding: %s (uid %s)", txt(sc.Binding.Name), txt(sc.Binding.UID))
	}
	for _, n := range sc.Namespaces {
		w.line(1, "Namespace: %s (uid %s)", txt(n.Name), txt(n.UID))
	}
	if win := r.TechnicalEvidence.Window; win != nil {
		w.line(0, "Observation window: %s to %s", ts(win.Started), ts(win.Closed))
	} else {
		w.line(0, "Observation window: none (no technical evidence)")
	}
	w.blank()

	in := r.Inputs
	w.line(0, "Inputs:")
	w.line(1, "Bundle: %s", bundleRef(in.Bundle.Name, in.Bundle.Digest))
	w.field(1, "Content path", in.ContentPath)
	w.line(1, "Resolution semantics: %s", txt(in.Semantics))
	w.line(1, "Selection: %s", bundleRef(in.Selection.Bundle.Name, in.Selection.Bundle.Digest))
	if len(in.Selection.Policies) == 0 {
		w.line(2, "Selected policies: none")
	}
	for _, p := range in.Selection.Policies {
		if len(p.Parameters) > 0 {
			w.line(2, "Selected policy: %s parameters %s", txt(p.Name), txt(string(compactJSON(p.Parameters))))
		} else {
			w.line(2, "Selected policy: %s", txt(p.Name))
		}
	}
	w.blank()

	inv := r.Inventory
	w.line(0, "Inventory: %s", resolved(inv.Resolved))
	w.doc(1, "Profile", inv.Profile)
	w.doc(1, "Catalog", inv.Catalog)
	for i := range inv.Imports {
		w.doc(1, "Import", &inv.Imports[i])
	}
	for i := range inv.Documents {
		w.doc(1, "Document read", &inv.Documents[i])
	}
	w.line(1, "Selected controls: %d (%d enhancements, %d statement parts)", inv.Controls, inv.Enhancements, inv.Statements)
	w.line(0, "Mappings: %s", resolved(r.Mappings.Resolved))
	for i := range r.Mappings.Definitions {
		w.doc(1, "Definition", &r.Mappings.Definitions[i])
	}
	w.blank()

	w.technical(r.TechnicalEvidence)
	w.blank()

	w.line(0, "Controls: %d", len(r.Controls))
	if !inv.Resolved {
		w.line(1, "None listed: the inventory is unresolved, and no control list is guessed.")
	}
	for i := range r.Controls {
		w.control(&r.Controls[i])
	}
	w.blank()

	w.line(0, "Limitations: %d", len(r.Limitations))
	for _, l := range r.Limitations {
		w.limitation(1, l)
	}
	w.blank()

	w.line(0, "Sources: %d", len(r.Sources))
	for _, s := range r.Sources {
		w.line(1, "Source: %s (%s) sha256 %s", txt(s.Path), txt(s.Kind), txt(s.SHA256))
	}
	return w.buf.Bytes()
}

func (w *textWriter) technical(te TechnicalEvidence) {
	w.line(0, "Technical evidence: %s", te.State)
	w.field(1, "Cluster", te.Cluster)
	w.field(1, "Mapping sha256", te.MappingSHA256)
	if te.Evidence != nil {
		w.line(1, "Evidence: %s", summary(*te.Evidence))
	}
	if te.Outcomes != nil {
		w.line(1, "Outcomes: %s", outcomes(*te.Outcomes))
	}
	for _, s := range te.StaleScopes {
		w.line(1, "Stale scope: binding %s (uid %s, generation %d) policy %s reason %s: %s",
			txt(s.Binding.Name), txt(string(s.Binding.UID)), s.Binding.Generation, orAll(s.Policy), txt(string(s.Reason)), txt(s.Message))
	}
	if te.ScopeChanges > 0 {
		w.line(1, "Scope changes during collection: %d", te.ScopeChanges)
	}
	for _, c := range te.Contributions {
		w.line(1, "Contribution: binding %s revision %s engine policy %s logical policy %s mode %s from %s: %s",
			txt(c.BindingUID), txt(c.Revision), txt(c.EnginePolicy), txt(c.LogicalPolicy), txt(c.Mode), bundleRef(c.Bundle.Name, c.Bundle.Digest), c.Attribution)
	}
	if te.State != EvidenceNotProvided {
		w.line(1, "Observations: %d", len(te.Observations))
	}
	for _, o := range te.Observations {
		e, ob := o.Expected, o.Observation
		w.line(2, "Observation %s", txt(printableKey(ob.Key)))
		w.line(3, "Workload: %s %s/%s (uid %s, namespace uid %s, state %s, os %s)", txt(e.Workload.Resource), txt(e.Workload.Namespace),
			txt(e.Workload.Name), txt(e.Workload.UID), txt(e.NamespaceUID), txt(e.Workload.StateSHA256), orNone(e.Workload.OS))
		w.line(3, "Check: %s validation %d name %s sha256 %s; source %s mapping %s", txt(e.Check.EnginePolicy), e.Check.Index,
			orNone(e.Check.Name), txt(e.Check.SHA256), txt(e.SourceSHA256), txt(e.MappingSHA256))
		w.line(3, "Contribution: binding %s revision %s logical policy %s mode %s (cluster %s)", txt(e.Contribution.BindingUID),
			txt(e.Contribution.Revision), txt(e.Contribution.LogicalPolicy), txt(e.Contribution.Mode), txt(e.Cluster))
		ev := "not evaluated"
		if ob.Evaluated != nil {
			ev = ts(*ob.Evaluated)
		}
		w.line(3, "State: %s outcome %s evaluated %s report %s result %d applicability %s", ob.State, orNone(ob.Outcome), ev,
			orNone(ob.Report), ob.Index, orNone(ob.Applicability))
		for _, reason := range ob.Reasons {
			w.line(3, "Reason: %s", txt(reason))
		}
		if len(o.Controls) > 0 {
			w.line(3, "Referenced by controls: %s", txt(strings.Join(o.Controls, ", ")))
		} else {
			w.line(3, "Referenced by controls: none")
		}
	}
}

func (w *textWriter) control(c *ControlCoverage) {
	w.blank()
	w.line(1, "Control %s [%s] %s", txt(c.ID), c.Automation, txt(c.Title))
	w.line(2, "Qualified ID: %s", txt(c.QualifiedID))
	w.field(2, "Label", c.Label)
	w.field(2, "Class", c.Class)
	w.field(2, "Parent", c.Parent)
	w.field(2, "Status", c.Status)
	for _, g := range c.Groups {
		w.line(2, "Group: %s %s", orNone(g.ID), txt(g.Title))
	}
	w.line(2, "Statements: %s", list(c.Statements))
	for _, p := range c.Parameters {
		w.line(2, "OSCAL parameter: %s label %s values %s", txt(p.ID), orNone(p.Label), list(p.Values))
	}
	if len(c.Checks) == 0 {
		w.line(2, "Checks: none")
	}
	for i := range c.Checks {
		w.check(&c.Checks[i])
	}
	if c.Evidence != nil {
		w.line(2, "Control evidence (unique observations of its selected checks): %s", view(*c.Evidence))
	}
	for _, s := range c.StatementEvidence {
		w.line(2, "Statement evidence %s (rules %s): %s", txt(s.ID), list(s.Rules), view(s.EvidenceView))
	}
	for _, l := range c.Limitations {
		w.limitation(2, l)
	}
}

func (w *textWriter) check(ch *CheckCoverage) {
	w.line(2, "Check %s [%s] policy %s", txt(ch.RuleID), ch.Selection, orNone(ch.Policy))
	w.field(3, "Check ID", ch.CheckID)
	w.field(3, "Policy sha256", ch.PolicyDigest)
	w.field(3, "Coverage limit", ch.Description)
	w.field(3, "Check description", ch.CheckDescription)
	w.field(3, "Requirement", ch.RequirementDescription)
	if len(ch.Statements) == 0 {
		w.line(3, "Statements: the requirement as authored (no statement named)")
	}
	for _, s := range ch.Statements {
		if s.Description != "" {
			w.line(3, "Statement: %s: %s", txt(s.ID), txt(s.Description))
		} else {
			w.line(3, "Statement: %s", txt(s.ID))
		}
	}
	w.line(3, "Definitions: %s", list(ch.Definitions))
	for _, p := range ch.RuleParameters {
		w.line(3, "Rule parameter: %s description %s alternatives %s values %s", txt(p.ID), orNone(p.Description), orNone(p.Alternatives), list(p.Values))
	}
	for _, p := range ch.OSCALParameters {
		w.line(3, "OSCAL parameter setting: %s values %s", txt(p.ParamID), list(p.Values))
	}
	if len(ch.PolicyParameters) > 0 {
		w.line(3, "Policy parameters (engine configuration, not OSCAL values): %s", txt(string(compactJSON(ch.PolicyParameters))))
	}
	if e := ch.Evidence; e != nil {
		w.line(3, "Evidence: %s", view(e.EvidenceView))
		for _, c := range e.Contributions {
			w.line(4, "Contribution: binding %s revision %s engine policy %s mode %s", txt(c.BindingUID), txt(c.Revision), txt(c.EnginePolicy), txt(c.Mode))
			w.line(5, "Evidence: %s", summary(c.Evidence))
			w.line(5, "Outcomes: %s", outcomes(c.Outcomes))
			for _, k := range c.Observations {
				w.line(5, "Observation: %s", txt(printableKey(k)))
			}
		}
	}
}

func (w *textWriter) limitation(depth int, l Limitation) {
	kind := "notice"
	if l.Blocking {
		kind = "blocking"
	}
	where := ""
	if l.Document != "" {
		where += " in " + txt(l.Document)
	}
	if l.Subject != "" {
		where += " about " + txt(l.Subject)
	}
	w.line(depth, "Limitation %s (%s)%s: %s", l.Code, kind, where, txt(l.Message))
}

func (w *textWriter) doc(depth int, what string, d *DocumentRef) {
	if d == nil {
		return
	}
	w.line(depth, "%s: %s (%s, OSCAL %s) %s", what, txt(d.Path), txt(d.Model), txt(d.OSCALVersion), txt(d.Digest))
	if d.Title != "" || d.Version != "" {
		w.line(depth+1, "Title: %s; version %s", orNone(d.Title), orNone(d.Version))
	}
}

type textWriter struct{ buf bytes.Buffer }

func (w *textWriter) blank() { w.buf.WriteByte('\n') }

// line writes one indented line; continuation lines of a multi-line value
// are indented one level deeper.
func (w *textWriter) line(depth int, format string, a ...any) {
	ind := strings.Repeat("  ", depth)
	for i, l := range strings.Split(fmt.Sprintf(format, a...), "\n") {
		if i > 0 {
			l = "  " + l
		}
		w.buf.WriteString(strings.TrimRight(ind+l, " "))
		w.buf.WriteByte('\n')
	}
}

// field writes "name: value" when value is set.
func (w *textWriter) field(depth int, name, value string) {
	if value != "" {
		w.line(depth, "%s: %s", name, txt(value))
	}
}

// txt replaces control characters other than newline, so content strings
// cannot drive a terminal.
func txt(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && (unicode.IsControl(r) || r == ' ' || r == ' ') {
			return '�'
		}
		return r
	}, s)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return txt(s)
}

func orAll(s string) string {
	if s == "" {
		return "(all policies)"
	}
	return txt(s)
}

func list(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return txt(strings.Join(ss, ", "))
}

func bundleRef(name, digest string) string {
	if name == "" && digest == "" {
		return "none"
	}
	return txt(name) + "@" + txt(digest)
}

func resolved(b bool) string {
	if b {
		return "resolved"
	}
	return "unresolved"
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339Nano)
}

func summary(e publication.EvidenceSummary) string {
	return fmt.Sprintf("%s; expected %d, attributable %d, missing %d, rejected %d, unresolved %d, stale scopes %d",
		e.Completeness, e.Expected, e.Attributable, e.Missing, e.Rejected, e.Unresolved, e.StaleScopes)
}

func outcomes(o publication.OutcomeCounts) string {
	return fmt.Sprintf("pass %d, fail %d, error %d, skip %d, accepted risk %d, not applicable %d, unknown %d",
		o.Pass, o.Fail, o.Error, o.Skip, o.AcceptedRisk, o.NotApplicable, o.Unknown)
}

func view(v EvidenceView) string {
	if !v.Resolved || v.Evidence == nil || v.Outcomes == nil {
		return "unresolved (part of its evidence cannot be attributed; no counts are given)"
	}
	return summary(*v.Evidence) + "; outcomes " + outcomes(*v.Outcomes)
}
