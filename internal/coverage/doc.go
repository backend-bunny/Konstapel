// Package coverage builds the control-oriented coverage view of
// add-control-coverage-reporting: every control the pinned, resolved OSCAL
// baseline selects, with the authored technical mappings available for it and
// whether the binding's ComplianceProfile selects those checks.
//
// The inventory comes from the selected baseline alone. Mappings, selected
// policies and findings never decide which controls exist; a control without a
// mapping stays in the report with no automated assessment.
//
// Everything is read from one verified content handle (Content): the frozen
// copy of an applied bundle, an integrity-checked cache entry, or the image's
// vendored tree checked against its SHA256SUMS. Only files the handle
// inventories are read, each re-checked against its recorded digest; imports
// never leave that closure and are never fetched.
//
// The reader supports a declared subset of OSCAL profile resolution
// (Semantics); anything else makes the inventory unresolved with coded
// limitations instead of a guessed control list. Nothing here is specific to
// one framework: NIST SP 800-53 Rev. 5 Moderate is the first real fixture, not
// a special case.
//
// This package is pure: it performs no Kubernetes or network access and
// reads no clock. Evidence joins, rendering, and the supporting-evidence
// context are added by later groups of the change.
package coverage
