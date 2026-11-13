# Spec Delta

## Purpose

Let platform operators monitor Konstapel's health and assessment state through
standard Prometheus tooling without coupling the monitoring contract to a
particular compliance framework or confusing operational success with compliance.

## ADDED Requirements

### Requirement: Standard framework-neutral metrics

Konstapel SHALL expose documented Prometheus metric names, types, units, labels,
and meanings for controller operations and per-binding assessment summaries.
The contract SHALL be independent of catalog names, framework versions and
control identifiers. It SHALL NOT calculate framework compliance percentages
from check counts or equate an available OSCAL catalog with automated coverage.

#### Scenario: Observe different framework metadata

- **WHEN** equivalent assessment fixtures identify different OSCAL catalogs and mappings
- **THEN** the metric names, dimensions and outcome semantics remain identical
- **AND** the test does not claim that either fixture establishes runtime support for a new framework

### Requirement: Protected metrics access

The metrics endpoint SHALL use verified TLS and Kubernetes authentication and
authorization for a platform monitoring identity. Metrics access SHALL be
explicitly granted separately from namespace exception or assessment-request
permissions. Authentication/authorization caching and its revocation delay SHALL
be documented and bounded; TLS failures SHALL NOT cause plaintext fallback.

#### Scenario: Scrape as the monitoring service account

- **WHEN** the configured monitoring identity has metrics permission and valid trust
- **THEN** it can scrape the endpoint
- **AND** an unauthorized namespace identity cannot retrieve the same platform-wide summaries

#### Scenario: Rotate credentials or certificates

- **WHEN** serving certificates or monitoring credentials rotate or access is revoked
- **THEN** scraping follows the new trust and authorization within the documented bounds
- **AND** failure remains visible to monitoring without weakening access controls

### Requirement: Bounded dimensions and data exposure

Custom metric dimensions SHALL use bounded state vocabularies and centrally
managed binding names where needed. They SHALL NOT include workload identities,
run or resource UIDs, policy/control IDs, bundle digests, framework metadata,
exception reasons, raw errors, credentials, or storage object references. Metric
cardinality SHALL NOT grow with workloads, retained runs or policy versions.

#### Scenario: Increase workloads and retained history

- **WHEN** a fixed set of bindings acquires more workloads, policy revisions, exceptions and assessment runs
- **THEN** values change without creating a metric series per such object or revision
- **AND** detailed attribution remains in authorized status and evidence paths

### Requirement: Resolution and engine health are separate signals

Metrics SHALL distinguish binding resolution, engine capability readiness,
unknown or stale status, and controller operation outcomes. Observed generations
and effective revisions SHALL be checked before reporting current readiness.
Successful reconciliation or bundle verification SHALL NOT imply passing
workload checks or complete evidence.

#### Scenario: Evidence access fails while enforcement remains available

- **WHEN** reporting prerequisites fail but existing policy delivery remains available
- **THEN** monitoring distinguishes those capabilities and the affected bindings
- **AND** it does not report workload compliance from the healthy capability

### Requirement: Honest current assessment summaries

Per-binding current summaries SHALL derive from the assessment capability's
expected inventory and its normalized dispositions, without reclassifying engine
results. Each expected check instance SHALL be counted in exactly one of these
states: `pass`, `fail`, `error`, `skip`, `accepted_risk`, `out_of_scope` (known
non-applicability), `unknown` (an attributable outcome the assessment capability
does not distinguish, including an engine warning), `missing` (no matching
result), `rejected` (matching results without usable evidence, including
evidence older than the evidence-age limit) and `unresolved` (scope changed
during collection or results conflict). A summary whose inventory cannot be
fully established, or whose counts are inconsistent, SHALL omit these counts.
An accepted risk SHALL be counted once, as accepted risk, whatever its raw
outcome. Completeness and no-target scope SHALL remain separate, and neither
accepted risk nor missing, rejected, unresolved or warning evidence SHALL count
as a pass.

#### Scenario: Aggregate mixed evidence

- **WHEN** a binding has passing, violating, excepted, missing, age-rejected, unresolved and out-of-scope check instances
- **THEN** counts preserve those distinctions without multiplying subjects through duplicate reports or exception references
- **AND** the counts of a fully established inventory sum to its expected check instances

#### Scenario: An engine reports a warning

- **WHEN** the engine reports a warning result for an expected check
- **THEN** the check is counted as `unknown`, neither passing nor failing
- **AND** the raw warning outcome remains in the assessment evidence
- **AND** counts describe check instances rather than satisfied controls

#### Scenario: No targets or no reliable inventory

- **WHEN** a binding has zero targets or its expected inventory cannot be established
- **THEN** monitoring distinguishes known empty scope from unknown assessment state
- **AND** neither case implies a passing assessment

### Requirement: Historical summaries do not replace current evidence

The latest closed full-binding assessment summary SHALL be distinct from current
evidence and publication state. Its times SHALL describe the actual source
evaluation and collection window; scrape, upload and report-update times SHALL
NOT refresh evidence age. Namespace-only requests SHALL NOT replace a
full-binding summary, and newer incomplete runs SHALL remain visible.

#### Scenario: Evidence ages after a complete snapshot

- **WHEN** previously usable observations exceed the binding's evidence-age limit
- **THEN** current monitoring exposes staleness independently of the snapshot interval: the current evidence expiry time stays queryable, the current summary becomes unknown at that time, and a later evaluation counts the aged observations as rejected
- **AND** previously passing observations are never counted as current passes once they are stale
- **AND** the historical snapshot remains identifiable as historical rather than refreshed by a scrape

#### Scenario: A newer run is incomplete or fails export

- **WHEN** a full-binding run closes with incomplete evidence or a diagnostic export failure
- **THEN** it is visible as the latest closed run with its limitations
- **AND** monitoring does not silently keep an older successful run as the latest assessment

### Requirement: Scheduling signals follow the binding's cadence

Assessment timing metrics and overdue alerts SHALL use the scheduler's recorded
interval, due times and outstanding scheduled work. They SHALL cover a binding
that has never completed a scheduled assessment. Manual requests, failed runs,
interval changes and missed-tick coalescing SHALL NOT fabricate successful
scheduled work or erase an outstanding overdue condition.

#### Scenario: Compare different cadences

- **WHEN** one binding uses an hourly interval and another uses the daily default
- **THEN** each overdue decision follows its own schedule and configured grace
- **AND** a recent namespace request cannot conceal overdue scheduled work

### Requirement: Publication and cleanup have independent health

Metrics SHALL distinguish assessment results from publication attempts, durable
publication failures and retention cleanup progress. Expired-but-retained
artifacts and blocked cleanup SHALL remain observable after their binding is
deleted. Metrics SHALL NOT expose object keys or imply that a successful upload
or delete request changed assessment meaning or proved complete cleanup.

#### Scenario: Publish an incomplete assessment

- **WHEN** incomplete evidence is successfully published
- **THEN** monitoring shows publication success and incomplete assessment independently

#### Scenario: Cleanup outlives a binding

- **WHEN** a binding is deleted while retained artifacts cannot be cleaned up
- **THEN** retention backlog and its age remain visible through aggregate operational metrics
- **AND** no metrics state is transferred to a newly created binding with the same name

### Requirement: Missing or outdated observations are not healthy zeroes

Metrics SHALL expose whether their source projection is initialized and usable.
Unsynchronized caches, expired projection validity or unavailable producers SHALL
NOT yield fabricated zero failures or ready state. Known zeroes SHALL be emitted
only for known state. Alert rules SHALL distinguish unavailable monitoring data
from healthy empty results.

#### Scenario: Restart before source state is reconstructed

- **WHEN** a serving controller has not rebuilt authoritative monitoring state
- **THEN** it exposes projection unavailability and omits misleading assessment values
- **AND** monitoring can detect that condition even when the HTTP scrape succeeds

### Requirement: Lifecycle and replica handling preserve meaning

Deleting a binding SHALL remove its current series; recreation SHALL reset them
using the new object identity internally. Durable gauges SHALL be reconstructed
from owning records after restart. Operation counters SHALL document process
resets and attempts as their unit. Supported replica aggregation SHALL NOT sum
duplicate binding summaries or expose a former leader's stale state as current.

#### Scenario: Recreate a binding during a leader transition

- **WHEN** the controller changes leader and a binding name is reused with a new UID
- **THEN** current metrics reflect the new instance after synchronization or explicitly remain unavailable
- **AND** old run summaries and replica duplicates do not inflate its counts

### Requirement: Optional standard monitoring resources

The controller Helm chart SHALL offer independently configurable ServiceMonitor
and PrometheusRule resources using `monitoring.coreos.com/v1`. It SHALL integrate
with an existing monitoring stack and SHALL NOT install Prometheus, its operator,
or their CRDs. Missing required monitoring APIs when an option is enabled SHALL
produce an explicit installation/rendering error instead of silently omitting it.

#### Scenario: Install with or without monitoring integrations

- **WHEN** both integrations are disabled
- **THEN** chart installation requires no Prometheus Operator APIs
- **AND** enabling either option with its prerequisites produces correctly selected, release-scoped resources

### Requirement: Configurable starter alerts and runbooks

Optional starter rules SHALL detect sustained unresolved bindings, unavailable
engine capabilities, overdue assessments, recurring publication failures and
blocked cleanup, with configurable thresholds and hold durations. They SHALL
also distinguish scrape/projection unavailability. Each alert SHALL explain its
meaning and link to a runbook; notification routing remains operator-controlled.

#### Scenario: Tune operational alerts

- **WHEN** an operator changes a rule's threshold, hold duration, severity or enablement
- **THEN** the rendered rule reflects that configuration and can be tested before deployment
- **AND** no metric or alert changes policy mode, exception eligibility or assessment cadence

#### Scenario: A transient failure recovers

- **WHEN** a failure resolves before its configured hold duration
- **THEN** the corresponding sustained-failure alert does not fire
- **AND** persistent failures and missing source data remain detectable by their appropriate rules

### Requirement: Monitoring is passive and verifiable

Scraping SHALL NOT trigger policy evaluation, content retrieval, assessment runs,
or evidence-storage operations. Slow or unavailable monitoring SHALL NOT block
controller work. Verification SHALL exercise exposition, normalization, time and
lifecycle edge cases, actual Prometheus rule evaluation and authenticated
ServiceMonitor discovery before claiming the integration works.

#### Scenario: Scrape repeatedly during a registry or storage outage

- **WHEN** Prometheus continues scraping while a dependency is unavailable
- **THEN** it observes the controller's recorded state without causing additional dependency operations
- **AND** normal bounded reconciliation and retry behavior remains unchanged
