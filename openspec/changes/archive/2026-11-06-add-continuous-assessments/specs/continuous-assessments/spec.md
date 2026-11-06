# Spec Delta

## Purpose

Keep assessment state current and produce scoped, traceable snapshots on a
binding's interval or an authorized request, with explicit evidence limitations.

## ADDED Requirements

### Requirement: Per-binding assessment configuration

Each ComplianceBinding SHALL support positive duration settings for interval,
maximum evidence age, collection timeout, and retention. Defaults SHALL be 24h,
2h, 5m, and 2160h respectively. Invalid, zero, negative, or overflowing durations
SHALL be rejected. Snapshot schedules SHALL use intervals rather than cron or
wall-clock expressions.

#### Scenario: Use defaults and override a cadence

- **WHEN** a binding omits assessment settings
- **THEN** the four defaults apply
- **AND** another binding can override its interval without changing the first binding

#### Scenario: Reject an invalid duration

- **WHEN** an administrator sets an invalid duration or cron expression
- **THEN** admission rejects the setting with a field-specific explanation

### Requirement: Reporting changes preserve enforcement identities

Changes only to assessment settings SHALL NOT replace engine policy instances,
alter workload enforcement, or invalidate otherwise valid exceptions. Status
SHALL observe the updated configuration while preserving the enforcement revision.
Changes to policy semantics SHALL still create distinct enforcement revisions,
including when previous policy settings are restored.

#### Scenario: Change reporting frequency and retention

- **WHEN** an administrator changes only interval or retention
- **THEN** the new reporting settings take effect without policy replacement or exception renewal
- **AND** observed configuration generation advances independently of enforcement revision

### Requirement: Continuous state and periodic snapshots

Relevant workload, namespace, policy, report, and exception changes SHALL trigger
assessment-state reconciliation independently of snapshot intervals. Freshness
expiry SHALL also invalidate current status without requiring an event. Status
SHALL distinguish current evidence state, historical snapshots, and policy-engine
readiness, and SHALL NOT infer a pass from zero targets.

#### Scenario: Evidence ages between daily snapshots

- **WHEN** the last usable observation exceeds a binding's maximum evidence age
- **THEN** current status identifies stale evidence before the next scheduled snapshot
- **AND** the previous immutable snapshot remains unchanged

### Requirement: Durable scheduling and bounded concurrency

Scheduled and on-demand runs SHALL share a limit of one active run per binding.
Runs SHALL have durable identities and lifecycle status. Retries or leader changes
SHALL NOT create duplicate snapshots for the same trigger. After missed intervals,
Konstapel SHALL create at most one catch-up assessment of current state and record
the gap rather than inventing historical evaluations.

#### Scenario: Restart after several missed intervals

- **WHEN** the controller resumes after missing three scheduled times
- **THEN** it records the missed interval range and schedules one current assessment
- **AND** it does not claim to have assessed each missed historical state

#### Scenario: A request arrives during an active run

- **WHEN** another scheduled or manual trigger targets the same binding
- **THEN** it remains pending or is explicitly coalesced according to its trigger type
- **AND** another binding can continue independently

### Requirement: Namespace-bounded on-demand requests

Application teams SHALL be able to create namespaced AssessmentRequest resources
under Kubernetes RBAC, referencing a binding that selects that namespace.
Platform operators SHALL be able to request full-binding runs. Namespace requests
SHALL assess only their namespace and SHALL NOT change binding settings, policy
enforcement, central exception eligibility, or the scheduled cadence.

#### Scenario: A team requests an assessment

- **WHEN** an authorized team requests a binding assessment in its selected namespace
- **THEN** the run and returned evidence are restricted to that namespace identity
- **AND** no platform approval queue is required

#### Scenario: A requested namespace is outside binding scope

- **WHEN** the binding does not select the request's namespace at execution
- **THEN** the request is rejected or terminated with an explicit scope reason
- **AND** no full-binding assessment is substituted

### Requirement: Snapshot scope and revision boundaries

Each run SHALL record its binding UID, configuration, enforcement revisions,
cluster identity, selected namespace UIDs, expected checks and resources, and
collection window. Inventory SHALL be derived independently of received reports.
Changes during collection SHALL remain visible and SHALL NOT silently broaden
scope, remove expected violations, or turn old resource state into current evidence.

#### Scenario: A workload changes during collection

- **WHEN** an expected workload is updated, removed, or replaced during the run
- **THEN** its original identity/state and the detected change are recorded
- **AND** unverifiable results remain incomplete rather than being dropped from the denominator

#### Scenario: A namespace joins while a run is active

- **WHEN** labels make a new namespace match after the run's scope was captured
- **THEN** current status reconciles the new membership and the snapshot records the scope change
- **AND** that namespace is not silently added to the frozen run scope

### Requirement: Freshness requires attributable evaluation

Usable evidence SHALL have a source evaluation time within maxEvidenceAge at
snapshot closure and attributable cluster, resource state, check, and policy
revision identities. Collection time or a recent report update SHALL NOT replace
evaluation time. Ambiguous correlation, missing timestamps, future timestamps,
or an unobserved state transition SHALL remain incomplete or unknown.

#### Scenario: A recent report describes an old workload state

- **WHEN** a report is collected recently but its evaluation cannot be linked to the expected workload state
- **THEN** it is retained as rejected or unresolved evidence and does not establish a current pass

#### Scenario: Restart loses observation continuity

- **WHEN** the collector cannot establish which state a historical result evaluated
- **THEN** it waits for attributable evidence within the collection deadline or marks the result incomplete
- **AND** relisting resources does not manufacture evaluation provenance

### Requirement: Bounded collection produces explicit incomplete snapshots

Each materialized run SHALL close collection by its configured timeout and
produce a snapshot for publication, including incomplete assessments. Missing,
stale, malformed, or unavailable evidence SHALL be explained. A run that cannot
produce valid OSCAL SHALL expose an export failure and diagnostic snapshot rather
than fabricated assessment output. Unavailable storage SHALL remain a publication
failure, never a successful published snapshot.

#### Scenario: Some observations never arrive

- **WHEN** collection reaches its deadline with missing evidence
- **THEN** the snapshot preserves available results and identifies missing observations
- **AND** it is eligible for publication with incomplete assessment status

#### Scenario: Export cannot produce a valid document

- **WHEN** input or conversion errors prevent valid OSCAL export
- **THEN** the run records that failure in a diagnostic snapshot
- **AND** it does not label invalid or absent OSCAL as a successful assessment export

### Requirement: Completeness and results remain separate

Snapshots SHALL distinguish evidence completeness, individual check outcomes,
accepted-risk disposition, applicability, and publication state. Raw outcomes,
evaluation times, and available exception snapshots SHALL remain traceable.
Complete evidence with violations is not passing compliance; accepted risk,
out-of-scope subjects, and duplicate binding contributions SHALL NOT inflate
control or baseline satisfaction.

#### Scenario: A complete assessment contains a failure and an exception

- **WHEN** every expected check is attributable but results include failure and accepted risk
- **THEN** evidence completeness can be complete while outcomes retain those dispositions
- **AND** no full-control or Moderate-baseline satisfaction is inferred

### Requirement: Namespace packages preserve isolation and provenance

A namespace request's summary, raw-evidence extracts, diagnostics, OSCAL, and
packaged references SHALL contain only its authorized scope. Mixed-scope reports
SHALL NOT be copied wholesale into team packages. Extracts SHALL identify their
source and transformation; unresolvable scope SHALL prevent disclosure of the
affected content. Full-binding packages SHALL remain platform-scoped.

#### Scenario: A report includes another team's workload

- **WHEN** one source report contains results for two namespaces
- **THEN** a team package includes only safely attributable content for its namespace
- **AND** it preserves source-result traceability without exposing the sibling's evidence or diagnostics

### Requirement: Run recovery does not rewrite history

Run recovery SHALL resume the same frozen capture or explicitly record loss of
that capture. A new observation SHALL NOT replace an already closed snapshot.
Deleting a request or binding SHALL NOT delete retained published artifacts or
change their expiry. Binding or namespace recreation under the same name SHALL
NOT adopt prior request identities or grant access to prior evidence.

#### Scenario: Retry after publication response loss

- **WHEN** the publisher completed a snapshot but the controller did not receive confirmation
- **THEN** recovery reconciles the same run and publication identity
- **AND** it does not collect a different snapshot under the old identity
