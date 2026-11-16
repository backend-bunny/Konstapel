package coverage

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Limitation codes. A blocking limitation makes what it qualifies (the
// inventory, the mapping set, or one check) unresolved; a non-blocking one
// records a deduplication or an unattributed mapping that changes nothing
// in the resolved result.
const (
	// Inventory: the content, documents and profile resolution.
	CodeProfileNotDeclared       = "ProfileNotDeclared"
	CodeProfileAmbiguous         = "ProfileAmbiguous"
	CodeDocumentUnavailable      = "DocumentUnavailable"
	CodeDocumentInvalid          = "DocumentInvalid"
	CodeSchemaVersionUnsupported = "SchemaVersionUnsupported"
	CodeSchemaVersionMismatch    = "SchemaVersionMismatch"
	CodeImportUnresolved         = "ImportUnresolved"
	CodeImportExternal           = "ImportExternal"
	CodeImportOutsideContent     = "ImportOutsideContent"
	CodeImportAmbiguous          = "ImportAmbiguous"
	CodeImportCycle              = "ImportCycle"
	CodeImportDepth              = "ImportDepth"
	CodeSemanticsUnsupported     = "SemanticsUnsupported"
	CodeSelectionNotInSource     = "SelectionNotInSource"
	CodeMultipleCatalogs         = "MultipleCatalogs"
	CodeDuplicateCatalogID       = "DuplicateCatalogID"
	CodeEmptySelection           = "EmptySelection"
	CodeDuplicateSelection       = "DuplicateSelection" // non-blocking: deduplicated

	// Mappings: authored component definitions and the profile selection.
	CodeMappingSourceUnresolved   = "MappingSourceUnresolved"
	CodeMappingCatalogMismatch    = "MappingCatalogMismatch"    // non-blocking: not attributed
	CodeMappingControlUnknown     = "MappingControlUnknown"     // non-blocking: not attributed
	CodeMappingControlNotSelected = "MappingControlNotSelected" // non-blocking: not attributed
	CodeDuplicateMapping          = "DuplicateMapping"          // non-blocking: deduplicated
	CodeStatementNotInControl     = "StatementNotInControl"
	CodeRuleUndeclared            = "RuleUndeclared"
	CodeRuleNotInContent          = "RuleNotInContent"
	CodeCheckUndeclared           = "CheckUndeclared"
	CodeParameterUnresolved       = "ParameterUnresolved"
	CodeSelectionContentMismatch  = "SelectionContentMismatch"
	CodePolicyNotInContent        = "PolicyNotInContent"
)

// Limitation is a coded, bounded explanation of what could not be resolved
// or was deliberately not attributed.
type Limitation struct {
	Code string `json:"code"`
	// Blocking: the qualified result is unresolved, never guessed.
	Blocking bool `json:"blocking,omitempty"`
	// Document is the content path the limitation was found in, if any.
	Document string `json:"document,omitempty"`
	// Subject is the identifier concerned: a control, statement, rule,
	// policy or reference.
	Subject string `json:"subject,omitempty"`
	Message string `json:"message"`
}

func blocking(code, doc, subject, format string, a ...any) *Limitation {
	return &Limitation{Code: code, Blocking: true, Document: doc, Subject: subject, Message: fmt.Sprintf(format, a...)}
}

func notice(code, doc, subject, format string, a ...any) *Limitation {
	return &Limitation{Code: code, Document: doc, Subject: subject, Message: fmt.Sprintf(format, a...)}
}

// sortLimitations orders by document, subject, code and message and drops
// exact duplicates.
func sortLimitations(ls []Limitation) []Limitation {
	slices.SortFunc(ls, func(a, b Limitation) int {
		return cmp.Or(strings.Compare(a.Document, b.Document), compareIDs(a.Subject, b.Subject),
			strings.Compare(a.Code, b.Code), strings.Compare(a.Message, b.Message))
	})
	return slices.Compact(ls)
}

func anyBlocking(ls []Limitation) bool {
	return slices.ContainsFunc(ls, func(l Limitation) bool { return l.Blocking })
}

// compareIDs orders identifiers naturally: digit runs compare by value, so
// ac-2 sorts before ac-10 and ac-2.3 before ac-2.10. Equal-valued runs with
// different spellings (01, 1) fall back to a byte comparison, keeping the
// order total.
func compareIDs(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if isDigit(a[i]) && isDigit(b[j]) {
			si, sj := i, j
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
			x, y := strings.TrimLeft(a[si:i], "0"), strings.TrimLeft(b[sj:j], "0")
			if c := cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y)); c != 0 {
				return c
			}
			continue
		}
		if a[i] != b[j] {
			return cmp.Compare(a[i], b[j])
		}
		i, j = i+1, j+1
	}
	return cmp.Or(cmp.Compare(len(a)-i, len(b)-j), strings.Compare(a, b))
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
