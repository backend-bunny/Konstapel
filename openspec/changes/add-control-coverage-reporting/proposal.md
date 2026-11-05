# Proposal

## Why

Policy check results do not show which parts of the selected compliance baseline
Konstapel can assess or which requirements still lack evidence. Operators need
every selected control to remain visible, including organizational and physical
controls without automated checks.

## What Changes

- Produce a control-oriented view for each binding and authorized assessment
  scope from its pinned, resolved OSCAL baseline, rather than only listing
  controls that have mappings or received reports.
- Separate authored technical coverage, selected checks, evidence freshness and
  completeness, raw findings, accepted risks, and supporting-document context.
  Preserve partial coverage; neither passing checks nor attached documents imply
  satisfaction of a whole control or baseline.
- Preserve catalog/profile identities, statements, mappings, scope, and evidence
  revisions. Keep unsupported controls, unselected checks, unresolved content,
  missing observations, and zero targets distinguishable.
- Add versioned JSON and readable coverage files to assessment packages, with
  bounded current summaries using the assessment owner's existing status path.
  Historical coverage remains tied to its original observation window.
- Define a narrow supporting-evidence projection consumed by
  `add-supporting-evidence-attachments`, so document availability does not change
  automated check counts or outcomes.
- Keep control identities and categories framework-neutral. NIST SP 800-53 Rev. 5
  Moderate is the first real content fixture, not a hard-coded report model.

## Capabilities

### New Capabilities

- `control-coverage-reporting`: Describe selected OSCAL controls and the bounded
  technical and documentary evidence available for each assessment scope.

### Modified Capabilities

None. The existing `kyverno-assessment-loop` remains a bounded AC-6 prototype;
this change consumes the active targeting, bundle, assessment, exception, and
publication contracts without redefining their results.

## Impact

Adds a coverage model, validated baseline/mapping reader, report renderer,
assessment producer integration, fixtures, and documentation. Reuses
`internal/collector`, `internal/targeting`, and `internal/publication`; extensions
to shared summaries and package validation must use those owners' contracts.
The coverage core can proceed before attachment ingestion is implemented.

No new policy engine, automatic remediation, compliance percentage, manual
control verdict, baseline-tailoring UI, dashboard, external scanner importer,
or fleet aggregator is introduced. Supporting-document ingestion, storage,
validity, and authorization belong to the separate attachment change.
