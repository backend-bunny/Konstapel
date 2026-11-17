package coverage

// The supporting-evidence context (add-control-coverage-reporting 4.1).
//
// Coverage owns this narrow, versioned input; add-supporting-evidence-
// attachments owns everything behind it: acquisition, authenticated
// attribution, storage, validity and association computation, and the
// authorized copies of documents. Coverage only checks the context, applies
// the scope's projection (projection.go) and references the entries from
// the control rows they name.
//
// The context is documentary only. It has no outcome, verdict or
// satisfaction field, and nothing in it can add a check, an expected
// observation, a finding or an automation state: Build joins it after, and
// independently of, the technical evidence.

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// SupportingContextVersion versions the SupportingEvidenceContext contract.
const SupportingContextVersion = "konstapel.io/supporting-evidence-context/v1"

// Integration states of a context.
const (
	// IntegrationDisabled: no supporting-evidence integration supplies
	// context. Documents are not considered; this is not "no documents".
	IntegrationDisabled = "disabled"
	// IntegrationAvailable: the integration supplied its context. An empty
	// entry list then means no document is associated with the scope.
	IntegrationAvailable = "available"
	// IntegrationUnavailable: the integration is enabled but could not
	// supply its context. It is never reported as an empty list.
	IntegrationUnavailable = "unavailable"
)

// Association states of an entry: the attachment owner's resolution of the
// document's association with the binding, catalog and baseline.
const (
	SupportingAssociationPending    = "pending"
	SupportingAssociationValid      = "valid"
	SupportingAssociationMismatched = "mismatched"
)

// Content states of an entry: whether the document's committed bytes are
// available.
const (
	SupportingContentPending     = "pending"
	SupportingContentAvailable   = "available"
	SupportingContentUnavailable = "unavailable"
)

// Temporal states, computed by coverage from the declared validity at the
// report's asOf (validFrom <= asOf < validUntil).
const (
	SupportingNotYetValid = "notYetValid"
	SupportingCurrent     = "current"
	SupportingExpired     = "expired"
	// SupportingTemporalUnknown: the report has no asOf to classify at.
	SupportingTemporalUnknown = "unknown"
)

// Access dispositions of an entry.
const (
	// AccessIncluded: an authorized copy of the document is in this
	// package, at Document.Copy.
	AccessIncluded = "included"
	// AccessNotIncluded: platform metadata is shown, but no copy is in
	// this package.
	AccessNotIncluded = "notIncluded"
	// AccessRestricted: the scope may not read the document or its private
	// metadata; only its sanitized states and opaque identity are shown.
	AccessRestricted = "restricted"
)

// Attribution of an entry to the report's control rows.
const (
	// SupportingAttributed: every control the entry names is selected by
	// the report's baseline of the same catalog digest, and every
	// statement belongs to its control.
	SupportingAttributed = "attributed"
	// SupportingOtherBinding: the entry is for another binding.
	SupportingOtherBinding = "otherBinding"
	// SupportingOtherCatalog: the entry references another catalog; the
	// same identifiers are never attributed to this baseline.
	SupportingOtherCatalog = "otherCatalog"
	// SupportingNotInBaseline: a named control is not selected, or a
	// statement does not belong to its control.
	SupportingNotInBaseline = "notInBaseline"
	// SupportingUnresolved: the inventory is unresolved, so no control
	// can be named.
	SupportingUnresolved = "unresolved"
)

// SupportingEvidenceContext is the supporting-evidence input of one report:
// the attachment owner's already authorized projection for the report's
// binding, frozen for the run. A nil context is IntegrationDisabled.
type SupportingEvidenceContext struct {
	Version     string `json:"version"`
	Integration string `json:"integration"`
	// Reason is a coded CamelCase reason for IntegrationUnavailable. It is
	// never free text.
	Reason  string            `json:"reason,omitempty"`
	Entries []SupportingEntry `json:"entries"`
}

// SupportingEntry is one document's context for one binding. Its states
// are separate axes; none of them, alone or together, is a verdict.
type SupportingEntry struct {
	// Source is the document's opaque identity (the record UID).
	Source string `json:"source"`
	// Revision is the opaque digest of the immutable registration
	// (sha256:<hex>). It is platform metadata.
	Revision string `json:"revision,omitempty"`
	// ObservedAt is when the attachment owner observed the entry's states;
	// never after the report's asOf.
	ObservedAt time.Time `json:"observedAt"`
	// BindingUID is the binding the association names.
	BindingUID string `json:"bindingUID"`
	// CatalogDigest qualifies Controls: sha256:<hex> of the catalog.
	CatalogDigest string              `json:"catalogDigest"`
	Controls      []SupportingControl `json:"controls"`
	Association   string              `json:"association"`
	Content       string              `json:"content"`
	// ContentReason is the owner's coded CamelCase reason for the content
	// state, if any.
	ContentReason string `json:"contentReason,omitempty"`
	// ValidFrom and ValidUntil are the declared validity, half open. They
	// are a platform's claim, not an evaluation time.
	ValidFrom  time.Time `json:"validFrom"`
	ValidUntil time.Time `json:"validUntil"`
	// Withdrawn: the document was withdrawn during the capture. Changed:
	// its association or content changed during the capture.
	Withdrawn bool   `json:"withdrawn,omitempty"`
	Changed   bool   `json:"changed,omitempty"`
	Access    string `json:"access"`
	// Document is the platform's private metadata. A namespace projection
	// always removes it.
	Document *SupportingDocument `json:"document,omitempty"`
}

// SupportingControl is one control the document is associated with, and
// optionally some of its statements.
type SupportingControl struct {
	ID         string   `json:"id"`
	Statements []string `json:"statements,omitempty"`
}

// SupportingDocument is a document's private platform metadata.
type SupportingDocument struct {
	Title     string `json:"title"`
	Issuer    string `json:"issuer,omitempty"`
	Scope     string `json:"scope,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	// Copy is the package-relative path of the authorized copy, under
	// supporting-evidence/; set only with AccessIncluded.
	Copy string `json:"copy,omitempty"`
}

// SupportingEvidence is the report's supporting-evidence section: the
// context as projected for the scope, each entry with its temporal state
// at the report's asOf and its attribution to the control rows.
type SupportingEvidence struct {
	// ContextVersion is the consumed contract version; empty when no
	// context was supplied (disabled).
	ContextVersion string `json:"contextVersion,omitempty"`
	Integration    string `json:"integration"`
	Reason         string `json:"reason,omitempty"`
	// Projection is how the context was projected: ProjectionPlatform or
	// ProjectionNamespace.
	Projection string             `json:"projection"`
	Entries    []SupportingRecord `json:"entries"`
}

// SupportingRecord is one projected entry of a report.
type SupportingRecord struct {
	SupportingEntry
	Temporal    string `json:"temporal"`
	Attribution string `json:"attribution"`
}

// SupportingRef is a control row's reference to an attributed entry, with
// the entry's states repeated for reading. It adds nothing to the row's
// automation or evidence.
type SupportingRef struct {
	Source string `json:"source"`
	// Statements are the row's statements the entry names; empty for the
	// control as a whole.
	Statements  []string `json:"statements,omitempty"`
	Temporal    string   `json:"temporal"`
	Content     string   `json:"content"`
	Association string   `json:"association"`
	Access      string   `json:"access"`
	Withdrawn   bool     `json:"withdrawn,omitempty"`
}

// SupportingCopyDir is the package directory of authorized document copies.
const SupportingCopyDir = "supporting-evidence/"

// SourceSupportingDocument is the source kind of an included document copy.
const SourceSupportingDocument = "supporting-document"

// ParseSupportingContext decodes a context strictly: an unknown field, a
// trailing value or another version fails.
func ParseSupportingContext(raw []byte) (*SupportingEvidenceContext, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c SupportingEvidenceContext
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("supporting-evidence context: %w", err)
	}
	if dec.More() {
		return nil, errors.New("supporting-evidence context: trailing data")
	}
	if c.Version != SupportingContextVersion {
		return nil, fmt.Errorf("supporting-evidence context: unsupported version %q", c.Version)
	}
	return &c, nil
}

var (
	opaqueID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	oscalToken = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	reasonCode = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	digestRef  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Bounds of private metadata strings.
const (
	maxTitle = 512
	maxText  = 2048
)

// Validate checks a context against the contract for a report as of asOf
// (zero skips the observation-time check). Its errors name the entry index
// and the rule broken, never a value. A producer can use it to keep an
// invalid context out of a package; Build reports one as ContextInvalid.
func (c *SupportingEvidenceContext) Validate(asOf time.Time) error { return c.validate(asOf) }

// validate checks a context against the contract. Its errors name the
// entry index and the rule broken, never a value: an invalid value may be
// private metadata.
func (c *SupportingEvidenceContext) validate(asOf time.Time) error {
	if c.Version != SupportingContextVersion {
		return errors.New("the context version is not supported")
	}
	switch c.Integration {
	case IntegrationDisabled, IntegrationAvailable:
		if c.Reason != "" {
			return fmt.Errorf("a %s context carries a reason", c.Integration)
		}
		if c.Integration == IntegrationDisabled && len(c.Entries) > 0 {
			return errors.New("a disabled context carries entries")
		}
	case IntegrationUnavailable:
		if !reasonCode.MatchString(c.Reason) {
			return errors.New("an unavailable context has no coded reason")
		}
		if len(c.Entries) > 0 {
			return errors.New("an unavailable context carries entries")
		}
	default:
		return errors.New("the integration state is unknown")
	}
	seen := map[[2]string]bool{}
	for i := range c.Entries {
		if err := c.Entries[i].validate(asOf); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		k := [2]string{c.Entries[i].Source, c.Entries[i].BindingUID}
		if seen[k] {
			return fmt.Errorf("entry %d: the source is listed twice for one binding", i)
		}
		seen[k] = true
	}
	return nil
}

func (e *SupportingEntry) validate(asOf time.Time) error {
	switch {
	case !opaqueID.MatchString(e.Source):
		return errors.New("the source is not an opaque identifier")
	case e.Revision != "" && !digestRef.MatchString(e.Revision):
		return errors.New("the revision is not a sha256 digest")
	case !opaqueID.MatchString(e.BindingUID):
		return errors.New("the binding UID is not an opaque identifier")
	case !digestRef.MatchString(e.CatalogDigest):
		return errors.New("the catalog digest is not a sha256 digest")
	case len(e.Controls) == 0:
		return errors.New("no control is named")
	case !slices.Contains([]string{SupportingAssociationPending, SupportingAssociationValid, SupportingAssociationMismatched}, e.Association):
		return errors.New("the association state is unknown")
	case !slices.Contains([]string{SupportingContentPending, SupportingContentAvailable, SupportingContentUnavailable}, e.Content):
		return errors.New("the content state is unknown")
	case e.ContentReason != "" && !reasonCode.MatchString(e.ContentReason):
		return errors.New("the content reason is not a code")
	case e.ValidFrom.IsZero() || e.ValidUntil.IsZero() || !e.ValidFrom.Before(e.ValidUntil):
		return errors.New("the declared validity is not a non-empty window")
	case e.ObservedAt.IsZero():
		return errors.New("the observation time is missing")
	case !asOf.IsZero() && e.ObservedAt.After(asOf):
		return errors.New("the entry was observed after the report's asOf")
	}
	ids := map[string]bool{}
	for _, ctl := range e.Controls {
		if !oscalToken.MatchString(ctl.ID) || ids[ctl.ID] {
			return errors.New("a control ID is invalid or repeated")
		}
		ids[ctl.ID] = true
		st := map[string]bool{}
		for _, s := range ctl.Statements {
			if !oscalToken.MatchString(s) || st[s] {
				return errors.New("a statement ID is invalid or repeated")
			}
			st[s] = true
		}
	}
	switch e.Access {
	case AccessIncluded:
		if e.Document == nil || e.Document.Copy == "" {
			return errors.New("an included document has no copy")
		}
	case AccessNotIncluded:
		if e.Document != nil && e.Document.Copy != "" {
			return errors.New("a document that is not included has a copy")
		}
	case AccessRestricted:
		if e.Document != nil || e.Revision != "" {
			return errors.New("a restricted entry carries private metadata")
		}
	default:
		return errors.New("the access disposition is unknown")
	}
	if d := e.Document; d != nil {
		switch {
		case d.Title == "" || len(d.Title) > maxTitle || len(d.Issuer) > maxText || len(d.Scope) > maxText || len(d.MediaType) > maxTitle:
			return errors.New("the document metadata is missing or too long")
		case d.Size < 0 || !hexDigest.MatchString(d.SHA256):
			return errors.New("the document size or sha256 is invalid")
		case d.Copy != "" && !safeCopyPath(d.Copy):
			return errors.New("the document copy is not a clean path under " + SupportingCopyDir)
		}
	}
	return nil
}

func safeCopyPath(p string) bool {
	return strings.HasPrefix(p, SupportingCopyDir) && len(p) > len(SupportingCopyDir) && path.Clean(p) == p &&
		!strings.Contains(p, "..") && !strings.ContainsAny(p, "\\\x00")
}

// temporal classifies the declared validity at asOf.
func temporal(e SupportingEntry, asOf time.Time) string {
	switch {
	case asOf.IsZero():
		return SupportingTemporalUnknown
	case asOf.Before(e.ValidFrom):
		return SupportingNotYetValid
	case asOf.Before(e.ValidUntil):
		return SupportingCurrent
	}
	return SupportingExpired
}

// joinSupporting adds the projected context to r. It runs after the
// technical evidence and touches only the supporting section, the rows'
// supporting references and limitations.
func joinSupporting(r *Report, ctx *SupportingEvidenceContext, p projection) {
	se := &r.SupportingEvidence
	*se = SupportingEvidence{Integration: IntegrationDisabled, Projection: p.kind, Entries: []SupportingRecord{}}
	if ctx == nil {
		return
	}
	se.ContextVersion = ctx.Version
	if err := ctx.validate(r.AsOf); err != nil {
		se.Integration = IntegrationUnavailable
		se.Reason = "ContextInvalid"
		why := err.Error()
		if p.kind != ProjectionPlatform {
			// The failing entry may be another binding's or scope's.
			why = "details are in the platform report"
		}
		r.Limitations = append(r.Limitations, *blocking(CodeSupportingContextInvalid, "", "supportingEvidence",
			"the supporting-evidence context is invalid (%s); no document is reported, and this is not an empty list", why))
		return
	}
	se.Integration, se.Reason = ctx.Integration, ctx.Reason
	if ctx.Integration == IntegrationUnavailable {
		r.Limitations = append(r.Limitations, *blocking(CodeSupportingEvidenceUnavailable, "", "supportingEvidence",
			"the supporting-evidence integration could not supply its context (%s); this is not an empty attachment list, and the technical evidence is unaffected", ctx.Reason))
		return
	}
	rows := map[string]*ControlCoverage{}
	for i := range r.Controls {
		rows[r.Controls[i].ID] = &r.Controls[i]
	}
	binding := ""
	if r.Scope.Binding != nil {
		binding = r.Scope.Binding.UID
	}
	catalog := ""
	if r.Inventory.Catalog != nil {
		catalog = r.Inventory.Catalog.Digest
	}
	for _, e := range ctx.Entries {
		e = p.supporting(e)
		if p.kind == ProjectionNamespace && e.BindingUID != binding {
			continue // not part of this scope at all
		}
		e.Controls = slices.Clone(e.Controls)
		for i := range e.Controls {
			e.Controls[i].Statements = slices.Clone(e.Controls[i].Statements)
			slices.SortFunc(e.Controls[i].Statements, compareIDs)
		}
		slices.SortFunc(e.Controls, func(a, b SupportingControl) int { return compareIDs(a.ID, b.ID) })
		rec := SupportingRecord{SupportingEntry: e, Temporal: temporal(e, r.AsOf)}
		switch {
		case binding != "" && e.BindingUID != binding:
			rec.Attribution = SupportingOtherBinding
		case !r.Inventory.Resolved:
			rec.Attribution = SupportingUnresolved
		case e.CatalogDigest != catalog:
			rec.Attribution = SupportingOtherCatalog
		case !inBaseline(e, rows):
			rec.Attribution = SupportingNotInBaseline
		default:
			rec.Attribution = SupportingAttributed
		}
		se.Entries = append(se.Entries, rec)
		if rec.Attribution != SupportingAttributed {
			r.Limitations = append(r.Limitations, *notice(CodeSupportingNotAttributed, "", e.Source,
				"supporting document %s is not attributed to a control (%s)", e.Source, rec.Attribution))
			continue
		}
		for _, ctl := range e.Controls {
			row := rows[ctl.ID]
			row.SupportingEvidence = append(row.SupportingEvidence, SupportingRef{Source: e.Source, Statements: ctl.Statements,
				Temporal: rec.Temporal, Content: e.Content, Association: e.Association, Access: e.Access, Withdrawn: e.Withdrawn})
		}
	}
	slices.SortFunc(se.Entries, func(a, b SupportingRecord) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.BindingUID, b.BindingUID))
	})
	for i := range r.Controls {
		slices.SortFunc(r.Controls[i].SupportingEvidence, func(a, b SupportingRef) int { return strings.Compare(a.Source, b.Source) })
	}
}

// inBaseline: every named control is a row, and every statement is the
// row's own.
func inBaseline(e SupportingEntry, rows map[string]*ControlCoverage) bool {
	for _, ctl := range e.Controls {
		row := rows[ctl.ID]
		if row == nil {
			return false
		}
		for _, s := range ctl.Statements {
			if !slices.Contains(row.Statements, s) {
				return false
			}
		}
	}
	return true
}
