// Package attachments implements supporting-evidence attachments
// (add-supporting-evidence-attachments): platform-registered documents that
// support selected controls of explicitly named bindings without recording
// a control verdict.
//
// This file validates an attachment's catalog/control/statement references
// against the catalog and selected baseline a binding resolves, as the
// coverage owner's baseline reader (coverage.ReadBaseline) resolves them
// from the same verified content the binding's bundle pins: its declared
// baseline profile and the one catalog it resolves to. Content that does
// not resolve is a resolution failure (the association stays pending),
// never a mismatch.
package attachments

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/coverage"
)

// Paths of the vendored catalog and Moderate baseline profile, relative to
// the parent of the image's content/ tree.
const (
	CatalogPath  = assessment.NIST + "NIST_SP-800-53_rev5_catalog.json"
	BaselinePath = assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
)

// Baseline is the control inventory an association is validated against.
type Baseline struct {
	// CatalogDigest is "sha256:<hex>" of the catalog file bytes, the
	// identity coverage qualifies controls with.
	CatalogDigest string
	// Controls maps each selected control ID to the IDs of its statement
	// parts (the "statement" part and its nested "item" parts). A control
	// absent from the map is not in the selected baseline.
	Controls map[string]map[string]bool
}

// ErrBaseline marks content whose catalog or baseline cannot be resolved.
// It is a resolution failure (the association stays pending), never a
// mismatch. Errors from an unresolved coverage inventory also match
// coverage.ErrUnresolved.
var ErrBaseline = errors.New("catalog or baseline unavailable")

// ReadBaseline resolves the content's baseline with the coverage owner's
// reader (o carries the controller's trusted OSCAL schemas and, for
// vendored content, the profile entry point).
func ReadBaseline(c coverage.Content, o coverage.Options) (*Baseline, error) {
	b, err := coverage.ReadBaseline(c, o)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBaseline, err)
	}
	out := &Baseline{CatalogDigest: b.Catalog.Digest, Controls: make(map[string]map[string]bool, len(b.Controls))}
	for _, ctl := range b.Controls {
		s := make(map[string]bool, len(ctl.Statements))
		for _, id := range ctl.Statements {
			s[id] = true
		}
		out.Controls[ctl.ID] = s
	}
	if len(out.Controls) == 0 {
		return nil, fmt.Errorf("%w: baseline selects no controls", ErrBaseline)
	}
	return out, nil
}

// VendoredContent is the coverage handle of the image's vendored content
// tree at root (the parent of content/), served under name, with the
// options that resolve its Moderate baseline against the image's own
// trusted OSCAL schemas (content/schemas). Its digest is the sha256 of
// content/SHA256SUMS.
func VendoredContent(root fs.FS, name string) (coverage.Content, coverage.Options, error) {
	sums, err := fs.ReadFile(root, "content/SHA256SUMS")
	if err != nil {
		return coverage.Content{}, coverage.Options{}, fmt.Errorf("%w: %v", ErrBaseline, err)
	}
	ref := v1alpha1.BundleReference{Name: name, Digest: bundleDigest(sums)}
	c, err := coverage.FromVendored(root, ref, []bundle.OSCALDocument{{Path: CatalogPath, Version: "1.2.3"}, {Path: BaselinePath, Version: "1.2.3"}}, nil)
	if err != nil {
		return coverage.Content{}, coverage.Options{}, fmt.Errorf("%w: %v", ErrBaseline, err)
	}
	o := coverage.Options{Profile: BaselinePath, Schemas: map[string][]byte{}}
	for _, v := range coverage.SupportedOSCAL {
		b, err := fs.ReadFile(root, "content/schemas/oscal-"+v+".json")
		if err != nil {
			return coverage.Content{}, coverage.Options{}, fmt.Errorf("%w: %v", ErrBaseline, err)
		}
		o.Schemas[v] = b
	}
	return c, o, nil
}

// ReadVendoredBaseline resolves the vendored content's baseline.
func ReadVendoredBaseline(root fs.FS) (*Baseline, error) {
	c, o, err := VendoredContent(root, "vendored")
	if err != nil {
		return nil, err
	}
	return ReadBaseline(c, o)
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

func bundleDigest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
