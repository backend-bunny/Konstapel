// Package attachments implements supporting-evidence attachments
// (add-supporting-evidence-attachments): platform-registered documents that
// support selected controls of explicitly named bindings without recording
// a control verdict.
//
// This file validates an attachment's catalog/control/statement references
// against the catalog and selected baseline a binding resolves. It reads the
// same verified content the binding's bundle pins: the OSCAL catalog and the
// Moderate baseline profile every bundle ships at fixed paths
// (internal/bundle content validation requires them).
package attachments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// Paths of the catalog and selected baseline within bundle content (the
// payload root of an OCI bundle, or the parent of a vendored content/ tree).
const (
	CatalogPath  = assessment.NIST + "NIST_SP-800-53_rev5_catalog.json"
	BaselinePath = assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
)

// Baseline is the control inventory an association is validated against.
type Baseline struct {
	// CatalogDigest is "sha256:<hex>" of the catalog file bytes.
	CatalogDigest string
	// Controls maps each selected control ID to the IDs of its statement
	// parts (the "statement" part and its nested "item" parts). A control
	// absent from the map is not in the selected baseline.
	Controls map[string]map[string]bool
}

// ErrBaseline marks content whose catalog or baseline cannot be read. It is
// a resolution failure (the association stays pending), never a mismatch.
var ErrBaseline = errors.New("catalog or baseline unavailable")

// ReadBaseline reads the catalog and selected baseline from content. Only
// an explicit include-controls with-ids selection is supported; include-all,
// matching rules or an unresolved import fail closed.
func ReadBaseline(content fs.FS) (*Baseline, error) {
	rawCatalog, err := fs.ReadFile(content, CatalogPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBaseline, err)
	}
	rawProfile, err := fs.ReadFile(content, BaselinePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBaseline, err)
	}
	var catalog struct {
		Catalog struct {
			Groups   []group   `json:"groups"`
			Controls []control `json:"controls"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(rawCatalog, &catalog); err != nil {
		return nil, fmt.Errorf("%w: catalog: %v", ErrBaseline, err)
	}
	var profile struct {
		Profile struct {
			Imports []struct {
				Href            string `json:"href"`
				IncludeAll      any    `json:"include-all"`
				IncludeControls []struct {
					WithIDs  []string `json:"with-ids"`
					Matching any      `json:"matching"`
				} `json:"include-controls"`
				ExcludeControls []struct {
					WithIDs  []string `json:"with-ids"`
					Matching any      `json:"matching"`
				} `json:"exclude-controls"`
			} `json:"imports"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(rawProfile, &profile); err != nil {
		return nil, fmt.Errorf("%w: baseline: %v", ErrBaseline, err)
	}
	statements := map[string]map[string]bool{}
	var visit func(cs []control)
	visit = func(cs []control) {
		for _, c := range cs {
			s := map[string]bool{}
			for _, p := range c.Parts {
				if p.Name == "statement" {
					p.collect(s)
				}
			}
			statements[c.ID] = s
			visit(c.Controls)
		}
	}
	var groups func(gs []group)
	groups = func(gs []group) {
		for _, g := range gs {
			visit(g.Controls)
			groups(g.Groups)
		}
	}
	groups(catalog.Catalog.Groups)
	visit(catalog.Catalog.Controls)

	if len(profile.Profile.Imports) != 1 {
		return nil, fmt.Errorf("%w: baseline must import exactly one catalog, has %d imports", ErrBaseline, len(profile.Profile.Imports))
	}
	imp := profile.Profile.Imports[0]
	if imp.IncludeAll != nil || len(imp.IncludeControls) == 0 {
		return nil, fmt.Errorf("%w: baseline must select controls explicitly with include-controls", ErrBaseline)
	}
	selected := map[string]map[string]bool{}
	for _, inc := range imp.IncludeControls {
		if inc.Matching != nil {
			return nil, fmt.Errorf("%w: baseline selection by matching is not supported", ErrBaseline)
		}
		for _, id := range inc.WithIDs {
			s, ok := statements[id]
			if !ok {
				return nil, fmt.Errorf("%w: baseline selects %q, which is not in the catalog", ErrBaseline, id)
			}
			selected[id] = s
		}
	}
	for _, exc := range imp.ExcludeControls {
		if exc.Matching != nil {
			return nil, fmt.Errorf("%w: baseline exclusion by matching is not supported", ErrBaseline)
		}
		for _, id := range exc.WithIDs {
			delete(selected, id)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w: baseline selects no controls", ErrBaseline)
	}
	sum := sha256.Sum256(rawCatalog)
	return &Baseline{CatalogDigest: "sha256:" + hex.EncodeToString(sum[:]), Controls: selected}, nil
}

type group struct {
	Groups   []group   `json:"groups"`
	Controls []control `json:"controls"`
}

type control struct {
	ID       string    `json:"id"`
	Parts    []part    `json:"parts"`
	Controls []control `json:"controls"`
}

type part struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Parts []part `json:"parts"`
}

// collect records a statement part and its nested item parts.
func (p part) collect(into map[string]bool) {
	if p.ID != "" {
		into[p.ID] = true
	}
	for _, c := range p.Parts {
		if c.Name == "item" || c.Name == "statement" {
			c.collect(into)
		}
	}
}

// Mismatch explains why an association does not apply.
type Mismatch struct {
	Reason  string
	Message string
}

func (m *Mismatch) Error() string { return m.Message }

// maxListed bounds the identifiers quoted in a mismatch message.
const maxListed = 8

// Check validates one association's catalog and control references against
// the binding's baseline. It returns nil when every control is selected and
// every statement belongs to its control; otherwise the first failing
// category with the offending identifiers (sorted, bounded).
func (b *Baseline) Check(a v1alpha1.AttachmentAssociation) *Mismatch {
	if a.CatalogDigest != b.CatalogDigest {
		return &Mismatch{Reason: v1alpha1.ReasonCatalogMismatch,
			Message: fmt.Sprintf("registered against catalog %s; the binding resolves catalog %s", a.CatalogDigest, b.CatalogDigest)}
	}
	var missing, foreign []string
	for _, c := range a.Controls {
		stmts, ok := b.Controls[c.ID]
		if !ok {
			missing = append(missing, c.ID)
			continue
		}
		for _, s := range c.Statements {
			if !stmts[s] {
				foreign = append(foreign, c.ID+"/"+s)
			}
		}
	}
	if len(missing) > 0 {
		return &Mismatch{Reason: v1alpha1.ReasonControlNotInBaseline,
			Message: "controls not in the binding's selected baseline: " + list(missing)}
	}
	if len(foreign) > 0 {
		return &Mismatch{Reason: v1alpha1.ReasonStatementNotInControl,
			Message: "statements that are not statement parts of their control: " + list(foreign)}
	}
	return nil
}

func list(ids []string) string {
	slices.Sort(ids)
	if len(ids) > maxListed {
		return strings.Join(ids[:maxListed], ", ") + fmt.Sprintf(" and %d more", len(ids)-maxListed)
	}
	return strings.Join(ids, ", ")
}
