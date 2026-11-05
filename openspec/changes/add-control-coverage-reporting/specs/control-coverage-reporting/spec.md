# Spec Delta

## Purpose

Show every control in the selected OSCAL baseline with its bounded technical
coverage, evidence state, findings, and supporting-document context, preserving
the distinction between available evidence and compliance judgments.

## ADDED Requirements

### Requirement: The selected baseline defines the control inventory

Each scoped coverage report SHALL enumerate every control selected by the pinned,
resolved OSCAL profile, including controls without mapped checks or observations.
Selected enhancements SHALL retain their distinct identities and hierarchy.
Policies selected in a ComplianceProfile and received findings MUST NOT determine
which baseline controls exist in the report.

#### Scenario: Physical controls have no automated checks

- **WHEN** the selected baseline contains physical-security controls without
  technical mappings
- **THEN** those controls remain visible with no automated assessment, rather
  than disappearing or becoming passing controls

#### Scenario: A mapped policy is not selected

- **WHEN** bundle content maps a control to a policy omitted from the binding's
  ComplianceProfile
- **THEN** the control and available mapping remain visible, with that check
  identified as unselected rather than evaluated

### Requirement: Control identity and profile resolution are authoritative

Control and statement references SHALL be qualified by pinned catalog and profile
identities and digests. Selected controls, enhancements, parameters, and mapping
targets SHALL follow validated OSCAL resolution. Invalid, unsupported, or missing
content SHALL produce explicit inventory or mapping limitations; the report MUST
NOT silently substitute the full catalog, another revision, or only mapped IDs.

#### Scenario: Baseline cannot be resolved

- **WHEN** a required profile import cannot be resolved or uses unsupported
  selection semantics
- **THEN** the report declares the inventory unresolved and does not present a
  guessed control list or a zero-control success

#### Scenario: Same identifier occurs in another catalog

- **WHEN** an observation or document references an ID from a different catalog
  revision than the selected baseline
- **THEN** it is not automatically attributed to that baseline control

### Requirement: Technical coverage states retain their limits

Coverage SHALL distinguish absent mappings, available mappings, selected checks,
and unresolved mappings. Authored statement-level coverage limits SHALL remain
visible. Mapped or passing checks MUST NOT establish full-control satisfaction.
No automatic framework-specific score or whole-baseline pass SHALL be produced.

#### Scenario: All AC-6 privileged-container observations pass

- **WHEN** every attributable observation of the shipped privileged-container
  check passes
- **THEN** the report retains the authored partial AC-6 coverage and does not
  mark all of AC-6 or the Moderate baseline satisfied

### Requirement: Evidence completeness and findings are separate dimensions

For selected technical checks, the report SHALL preserve the assessment
contract's expected inventory, attributable outcomes, missing/rejected/unresolved
observations, and freshness reasons. A report's inventory completeness, technical
evidence completeness, document availability, and publication state SHALL remain
separate. Checks without observations MUST NOT be inferred to pass.

#### Scenario: A check has a failure and missing observations

- **WHEN** available findings include a failure while another expected resource
  has no usable result
- **THEN** both the failure and incomplete technical evidence remain visible
  under the relevant control

#### Scenario: Zero targets and no mapped checks

- **WHEN** one control has a selected check with zero targets and another has no
  mapped check
- **THEN** the report distinguishes those states without counting either as a
  pass or inventing missing observations for an unimplemented check

### Requirement: Applicability and risk disposition remain explicit

Workload applicability SHALL come from validated policy scope and assessment
context. Missing automation or documents MUST NOT mark a control not applicable.
Accepted risk SHALL follow authenticated acceptance snapshots and remain distinct
from raw outcomes. Uploading documents MUST NOT grant exceptions or alter
enforcement, applicability, or accepted-risk disposition.

#### Scenario: Linux-only automation excludes a Windows workload

- **WHEN** a workload is outside the supported check's Linux scope
- **THEN** the check's applicability limit is retained without declaring the
  corresponding baseline control globally not applicable

#### Scenario: A violation has a valid acceptance

- **WHEN** a captured observation is associated with a valid accepted risk
- **THEN** its source outcome and acceptance reference remain traceable and do
  not add to passing checks or satisfied controls

### Requirement: Aggregation preserves contribution and mapping identity

A control SHALL appear once per catalog/profile and assessment scope, with
traceable statement/check/contribution references. Duplicate report entries or
repeated mapping edges MUST NOT inflate counts. Distinct binding contributions
and check configurations SHALL remain distinguishable. Shared evidence mapped to
multiple controls SHALL NOT be presented as multiple independent evaluations.

#### Scenario: Overlapping bindings and repeated reports

- **WHEN** two bindings contribute checks for one control and reports repeat a
  source result
- **THEN** the view preserves the distinct contributions and source references
  without inventing extra observations or summing control satisfaction

### Requirement: Coverage is scoped to the authorized assessment

Coverage SHALL identify its cluster, binding UID, namespace identities where
applicable, input revisions, and observation window. Namespace views SHALL use
only the authorized namespace projection while retaining the public baseline
inventory. Sibling findings, private attachment metadata, and broader document
bytes MUST NOT be disclosed through control rows or links.

#### Scenario: A team reads its namespace package

- **WHEN** a binding selects several namespaces and one team downloads its
  assessment
- **THEN** the coverage contains that namespace's findings and permitted
  supporting-evidence context, without sibling observations or private documents

### Requirement: Historical views do not masquerade as current assessments

Snapshot coverage SHALL be immutable and evaluated at its recorded closure time.
Current summaries SHALL use the assessment owner's freshness and scope rules,
including time-based expiry without new events. Changed inputs or missing
continuity SHALL remain explicit. Rendering an old package MUST NOT renew its
evidence or replace its recorded validity with the reader's current clock.

#### Scenario: A document or technical observation expires after a snapshot

- **WHEN** its validity ends after a historical report was closed
- **THEN** the historical report preserves its original context while the current
  summary marks the affected context expired or stale

### Requirement: Supporting documents are attributed without becoming verdicts

The coverage model SHALL accept a separately versioned, scope-projected
supporting-evidence context. It SHALL distinguish no attachments, unavailable
integration, unavailable bytes, restricted access, and documentary validity.
Document presence or a submitter's description MUST NOT become a technical
outcome, a control verdict, or a substitute for a missing expected observation.

#### Scenario: A datacenter audit supports a physical-security control

- **WHEN** the attachment integration supplies a currently valid document
  association for that control and binding
- **THEN** the report shows supporting material and its attributed validity
  without marking the control satisfied or adding an automated pass

#### Scenario: Attachment lookup is unavailable

- **WHEN** the enabled supporting-evidence integration cannot supply its context
- **THEN** the report records unavailable context rather than an empty successful
  attachment list, while preserving independently known technical findings

### Requirement: Reports are versioned, deterministic, and inspectable

Assessment packages SHALL provide readable text and versioned JSON coverage
derived from the same model. Ordering SHALL be stable for the same frozen inputs.
Rows SHALL retain control titles/IDs, statement mappings, coverage limits,
evidence/findings, and source references. Full inventories SHALL remain package
data; Kubernetes status SHALL contain only bounded summaries and references.

#### Scenario: Inspect a retained package

- **WHEN** an operator opens its coverage text and JSON
- **THEN** both describe the same scope and results, and mapped findings can be
  traced to their packaged evidence and OSCAL context

### Requirement: Coverage extends the existing assessment contract safely

Coverage production SHALL reuse established collection, attribution, exception,
and publication semantics. Invalid report inputs SHALL yield explicit coverage
diagnostics rather than fabricated OSCAL findings or successful complete views.
Any necessary shared schema extension SHALL remain versioned and compatible with
retained packages. Existing prototype output SHALL remain supported.

#### Scenario: Coverage mapping fails while technical evidence exists

- **WHEN** valid captured results cannot be connected to validated control
  mappings
- **THEN** the results remain retained with an explicit coverage limitation and
  are not reassigned to guessed controls
