# Design

## Context

See [proposal.md](proposal.md) and the
[capability spec](specs/prometheus-observability/spec.md). The checkout at
`88a96a4` has profile/binding CRDs and the pure targeting resolver. It does not
yet have a production manager, metrics endpoint, charts or continuous assessment
producer. `go.mod` already selects controller-runtime v0.23.3 and Prometheus
client_golang v1.23.2 indirectly; `cmd/konstapel` remains the prototype CLI.

The targeting contract distinguishes resolution and engine readiness. Assessment
planning distinguishes current evidence from immutable full-binding and namespace
snapshots; S3 planning distinguishes publication from cleanup. Those owners must
remain authoritative. This change adds projections and instrumentation around
their states, rather than reinterpreting raw Kyverno reports in an exporter.

## Goals / Non-Goals

**Goals:** Give existing Prometheus installations useful operational signals,
bounded binding summaries, and tested starter alerts with explicit unknown-data
semantics. Make instrumentation and rule work independently implementable.

**Non-Goals:** New compliance evaluation logic, another scheduler or manager,
monitoring-stack installation, dashboards, tracing, alert delivery, framework
coverage scoring, or establishing a complete controller high-availability design.

## Decisions

### 1. Keep the metrics contract independent of framework content

Use a `konstapel_` prefix, Prometheus naming conventions and base units: counters
end in `_total`, durations use seconds, and timestamps are Unix seconds. Retain
controller-runtime reconciliation/workqueue and Go/process collectors instead
of duplicating them. Promote client_golang to a direct Go dependency when imported;
do not introduce another exporter process or independent registry.

Document metric names, types, units, label vocabularies, source of truth, reset
behavior and availability conditions. Test the exposition contract. NIST names,
control IDs, framework revisions and coverage percentages have no place in that
contract. Catalog/profile attribution stays in bundle metadata and OSCAL reports.
Equivalent summary fixtures with unrelated catalog metadata must expose the same
metric structure; this does not claim support for those frameworks at runtime.

Custom labels are limited to binding name and finite enums such as condition,
status, view, capability, operation and result. Do not attach profile/policy names,
workload namespaces/names, UIDs, run identities, versions, hashes, reasons, error
strings or storage references. Counts scale with configured bindings and fixed
enum sizes, not the workload population or retained history. Runtime collectors
retain their documented upstream labels. Scrape target labels identify the
release, namespace and instance; cluster identity comes from the monitoring
installation's labels, preserving future multicluster separation without a new
Konstapel cluster-registration API.

### 2. Project immutable owner snapshots without work on scrape

Add a small observability package with registered collectors and pure projections
of owner-provided snapshots. Producers publish coherent snapshots containing
internal binding UID/revision, observed generations, state, source timestamps and
validity boundaries. The collector reads immutable in-memory snapshots; it never
queries reports, registries or S3 to satisfy a scrape. HTTP authentication may
perform its standard Kubernetes token/access reviews.

Separate source domains for targeting, assessment, bundle resolution and evidence
storage. Emit `konstapel_observation_ready{domain}` and
`konstapel_observation_updated_timestamp_seconds{domain}`. Unknown or stale
domains are not ready and do not emit healthy-looking aggregate zeroes. Known
empty domains emit zeroes where defined. Expose enabled domains separately with
`konstapel_observation_enabled{domain}` so unimplemented/disabled features are
not reported as working or paged as enabled features.

Owners refresh projections on relevant events and at a bounded health/expiry
refresh, initially 30 seconds with a 2-minute maximum projection age. Refresh
requires synchronized, usable owner state; it cannot extend lost watch continuity
or accept stale observed generations. The exporter also checks age/validity using
the clock, so a stalled producer loses ready status even if HTTP still responds.
Current evidence expiry uses the producer's next validity deadline and is never
extended by projection refresh. Scrape/projection times are operational liveness
signals, not evidence evaluation times.

Use the manager's existing leadership boundary for binding/global state
projections. Every replica exposes its process and attempt metrics; only the
current synchronized leader exposes authoritative binding/backlog summaries.
On leadership loss clear ready state and its projections. Reconstruct state on
acquisition before exposing summaries. Rules select fresh ready projections from
successful scrape targets and preserve release/cluster scope. Do not sum duplicate
binding gauges across replicas; use owner filtering and conservative aggregation,
with ambiguous ownership treated as unavailable. This tests monitoring behavior
around existing leader election without designing a second election mechanism.

### 3. Define binding summaries with explicit current and historical views

The initial binding metric catalog has these families:

| Metric | Type and dimensions | Meaning |
| --- | --- | --- |
| `konstapel_binding_created_timestamp_seconds` | Gauge, binding | Current object's creation time; internal matching still uses UID |
| `konstapel_binding_condition` | Gauge, binding/condition/status | One-hot Resolved or EngineReady, with true/false/unknown |
| `konstapel_binding_target_namespaces` | Gauge, binding | Known target count, even if content is unresolved; absent only when target inventory is unknown |
| `konstapel_capability_condition` | Gauge, capability/status | Enabled policy-delivery, assessment or exception prerequisite state |
| `konstapel_binding_assessment_status` | Gauge, binding/view/status | Known summary, no targets, no assessment yet, or unknown |
| `konstapel_binding_assessment_checks` | Gauge, binding/view/state | Count of independently identified check instances |
| `konstapel_binding_assessment_complete` | Gauge, binding/view | Evidence completeness when a known nonempty summary exists |
| `konstapel_binding_oldest_evaluation_timestamp_seconds` | Gauge, binding/view | Oldest attributable source evaluation in that view, absent if none |
| `konstapel_binding_current_evidence_expiry_timestamp_seconds` | Gauge, binding | Owner's next expiry of current evidence; the bounded freshness signal |
| `konstapel_binding_snapshot_collection_started_timestamp_seconds` | Gauge, binding | Actual collection start of the latest closed full-binding run, absent if none |
| `konstapel_binding_last_closed_timestamp_seconds` | Gauge, binding | Closure of the latest full-binding run, including incomplete/diagnostic closure |
| `konstapel_binding_assessment_interval_seconds` | Gauge, binding | Effective configured cadence |
| `konstapel_binding_max_evidence_age_seconds` | Gauge, binding | Effective evidence-age limit |
| `konstapel_binding_scheduled_due_timestamp_seconds` | Gauge, binding | Earliest outstanding scheduled due time, or next due time when none is outstanding |
| `konstapel_binding_collection_timeout_seconds` | Gauge, binding | Configured collection limit used with overdue grace |

Views are `current` and `latest_closed`. The current view uses the continuous
assessment producer's current expected inventory and applied configuration; the
historical view uses the latest closed full-binding run for the current binding
UID. A namespace-only AssessmentRequest never replaces the full-binding view.
Later incomplete or diagnostic runs supersede older successful runs as the latest
closure. If a diagnostic has no trustworthy inventory, expose its unknown view
and actual closure time, not zero checks. Publication status cannot choose which
assessment appears newest.

The aggregation unit is one logical check/sub-validation against one expected
resource state within a binding contribution, as defined by the assessment owner.
Deduplicate report/exception references at that boundary; distinct bindings
remain distinct contributions. Do not interpret a sum across bindings as unique
workloads or satisfied controls. Use fixed mutually exclusive display states
taken from the owner's normalized summary (`OutcomeCounts` and
`EvidenceSummary`): `pass`, `fail`, `error`, `skip`, `accepted_risk`,
`out_of_scope` (owner `notApplicable`), `unknown` (an attributable outcome the
owner does not distinguish), `missing`, `rejected` (including evidence older
than `maxEvidenceAge`) and `unresolved`. The catalog has no `warn` or `stale`
state; their replacements are:

- **warn.** Kyverno reports `warn` for a failing policy annotated
  `policies.kyverno.io/scored: "false"` (confirmed with the pinned Kyverno CLI
  1.19.2 on a ValidatingPolicy). Rendering keeps source annotations, so
  organization bundles can produce it; the vendored and official content does
  not. The continuous assessment owner keeps the raw `warn` on the observation
  and in the OSCAL export (`ResultWarning`, `source-outcome`), but its summary
  counts it as `outcomes.unknown`. The metric therefore counts it as
  `unknown`: counted once, never pass, fail or accepted risk. `unknown`
  therefore includes unsupported warning outcomes and must not be read as
  missing evidence alone (that is `missing`). Find warnings through the raw
  outcome in the retained observation (`evaluation.json`) or in OSCAL (subject
  `result` warning, `source-outcome` warn).
- **Follow-up: native warning count.** Add a warning count to the assessment
  summary (assessment API/CRD `OutcomeCounts` + `continuous-assessments` spec)
  and a `warn` catalog state; not required for 0.2.0.
- **stale.** Stale current evidence is never a current pass. When the owner
  evaluates, aged results are `rejected`. Between evaluations the current view
  becomes `unknown` at the owner's next expiry, and
  `konstapel_binding_current_evidence_expiry_timestamp_seconds` keeps that
  deadline queryable before and after it passes (`time() >= expiry` means the
  current evidence is stale). `rejected` does not separate age from other
  unusable evidence; the owner's per-observation reasons do.

State precedence for one view, most conservative first: current evidence
expired, inventory lost, stale (unresolved) scope, inconsistent counts, no
targets, known. Only `no_targets` and `known` expose counts. Later query
examples (1.6), rules and their fixtures (5.x) must use these ten states and the
expiry gauge, and must not reference `warn` or `stale` states. Their
projection consumes the owner's normalized outcome, applicability, evidence
usability and risk attribution, with a documented table:

- Known non-applicability is out_of_scope, never passing coverage.
- Unestablished inventory makes the view unknown; unestablished correlation is
  unresolved and evidence rejected for age is rejected. None can authorize an
  accepted-risk or pass count.
- An accepted risk is counted once; a summary whose counts would also include
  its raw outcome does not add up and is withheld as unknown.
- An attributable, valid acceptance is accepted_risk regardless of whether the
  underlying engine reported pass or skip; the raw result remains in evidence.
- Remaining attributable ordinary results map to their explicit outcome; an
  unrecognized value becomes unknown, never pass.

Reuse the assessment owner's classification helpers and fixtures; do not create
a second authority for expiry or exception acceptance. For a known nonempty
inventory, state counts sum to that inventory. Known empty scope is `no_targets`
with zero counts and no asserted completeness/pass. An unknown inventory omits
counts. A known summary with missing observations can have unknown counts and
`complete=0`; availability of a summary is different from complete evidence.

Current evidence ages on source evaluation time. Historical source times and
closure remain unchanged; querying them later does not make that snapshot current.
Use actual binding UID internally to clear state on delete/recreate. Remove its
current series on deletion and initialize the recreated name without old runs.
Prometheus retains old samples in history under the name, so expose creation time
and document that queries crossing recreation must account for the boundary.

### 4. Observe scheduling, publication and cleanup without taking ownership

Consume cadence and outstanding-trigger state from the assessment scheduler.
The due timestamp refers to the earliest scheduled collection/export obligation
not yet closed as a valid assessment, even if that assessment is incomplete.
A diagnostic/export failure does not satisfy that obligation. If no obligation
is outstanding, expose the scheduler's next due time, including the initial due
time before any run. On-demand requests do not advance scheduled success.

An interval edit can reset a future schedule anchor as the owning design allows,
but cannot discard already outstanding work. Catch-up completion assesses current
state and can resolve operational lateness while leaving missed ranges recorded.
If the scheduler's initial shared contract lacks the required watermark, extend
its bounded status through that owner; do not infer it from last scrape/upload
time or implement another scheduler in metrics code.

The owner's status initially lacked both watermarks, so this change adds them
through the owner (spec delta `continuous-assessments`):

- `oldestEvaluation` on current evidence and on run (and request)
  summaries: the source evaluation time of the oldest attributable observation,
  computed by the collector from evaluated results. Closed runs record it at
  closure and keep it through publication; the frozen package descriptor is
  unchanged. The field sits beside the evidence counts, not inside them, so
  the API evidence summary stays identical to the descriptor's. It is never derived from `nextExpiry - maxEvidenceAge`, and is
  absent on summaries recorded before it existed.
- `schedule.outstandingSince`: the earliest scheduled time, including missed
  times, not yet met by a scheduled run that closed with an assessment export.
  A diagnostic or lost capture does not meet it; publication failure after an
  export does (publication is reported separately). The scheduler sets it when
  it starts a scheduled run and clears it when such a run finishes; no
  scheduling decision reads it. The metric's due time is
  `outstandingSince`, or else the first scheduled time after the newest
  scheduled run, which may already have passed while the slot was held.

Add `konstapel_operation_attempts_total{operation,result}` and
`konstapel_operation_duration_seconds{operation,result}` for bundle resolution,
evidence publication and cleanup. Operations/results are fixed enums. Each
completed attempt increments once; retries are separate attempts and counters
reset on process restart. Use standard histogram buckets suited to bounded
operations and document them. These counters are diagnostics, not durable run
totals or exactly-once publication evidence.

Expose durable aggregate gauges for `konstapel_publication_pending`,
`konstapel_publication_failed`, `konstapel_cleanup_pending`, and
`konstapel_cleanup_blocked`, plus
`konstapel_cleanup_oldest_expiry_timestamp_seconds`. Their source is the storage
owner's retained records, not bucket listing during scrape. Document actionable
pending/failed states separately from completed historical failures. Reconstruct
gauges on startup; do not reconstruct counters by recounting historical records.
These global gauges remain available for cleanup obligations after binding
deletion and carry no run/binding/object identifiers. A successful delete request
does not decrement backlog until the storage contract confirms completion.

### 5. Use the existing authenticated metrics server and chart TLS modes

Integrate with the owning controller-runtime manager's metrics server. Use its
`WithAuthenticationAndAuthorization` filter, a TLS-only metrics Service, and
the chart's cert-manager or operator-supplied-certificate modes. Configure the
certificate SAN and ServiceMonitor server name for the actual metrics Service;
support certificate reload and CA rotation. Do not use `insecureSkipVerify` as
the install path, or reuse a certificate for an unrelated service identity.

Grant the controller TokenReview and SubjectAccessReview create permissions,
reusing existing role rules where already supplied. The grant is a separate
ClusterRole bound only while `metrics.enabled`; the controller's generated
role is unchanged. A certificate that is missing or fails verification at
start stops the controller instead of falling back to a self-signed one. Provide a reader ClusterRole
granting `get` on non-resource URL `/metrics`; bind only explicitly configured
monitoring ServiceAccount subjects, with their namespaces. Namespace exception
and assessment-request roles do not inherit it. This endpoint provides
platform-wide summaries, not a namespace-filtered self-service API.

Document the [pinned upstream filter's caches](https://github.com/kubernetes-sigs/controller-runtime/blob/v0.23.3/pkg/metrics/filters/filters.go): token authentication can be cached
for 1 minute, successful authorization for 5 minutes, and denied authorization
for 30 seconds. Test revocation within those bounds and fail requests without
usable authorization; do not promise immediate revocation or unbounded cached
access during API failure. Use the maintained filter rather than another custom
auth proxy. Validate bounds again when upgrading controller-runtime.

The ServiceMonitor uses standard bearer authorization for the Prometheus service
account and verified CA/server-name configuration. Support the Operator's
`authorization` options, with the documented projected ServiceAccount token path
as the ordinary credentials-file setup. Operators whose file-access policy
prohibits that mode must supply an allowed credential configuration; do not
disable their policy or generate a long-lived token secretly. Do not assume the
monitoring ServiceAccount exists in Konstapel's namespace. Document required
Operator versions and validate the actual selected schema in acceptance.

### 6. Make Helm integrations independently optional

Add `metrics.enabled` (default **false**, an owner decision: the endpoint
gives the controller ServiceAccount cluster-scoped TokenReview and
SubjectAccessReview `create`, so it is opt-in), `metrics.serviceMonitor.enabled` (default
false), and `metrics.prometheusRule.enabled` (default false) to the implemented
controller chart. Monitoring integrations require metrics to be enabled. The
two Operator resources use `monitoring.coreos.com/v1`; each requires its own API
when enabled. Never ship those CRDs in either Konstapel chart or add Prometheus
as a subchart. Operator-managed scraping without a ServiceMonitor is supported,
including use of the optional rules with a separately configured scrape job.

Use stable release-scoped Service selectors and a named HTTPS port. Expose
ServiceMonitor discovery labels, interval (default 30s), timeout (default 10s),
authorization/TLS settings and target-label integration. Validate positive
durations and timeout less than interval. Keep rule/monitor selectors compatible
with the existing Prometheus installation; document namespace and label selection
on both the Prometheus and ServiceMonitor sides. Do not imply creating an object
alone guarantees that Prometheus discovers it.

Render-time capability checks report enabled-but-missing APIs explicitly.
Disconnected Helm render tests supply `--api-versions` for enabled resources;
both disabled options render successfully without them. Use values.schema.json
for incompatible option checks and safe bounded configuration. A ServiceMonitor
is owned by the controller release, not the CRD chart. Extend certificate/config
templates only after rebasing onto the Helm implementation.

### 7. Ship conservative configurable rules with an availability prerequisite

Starter rules are opt-in as a group and individually configurable. Use warning
severity by default; operators control routing, grouping, severity and thresholds.
No default framework score or violation-count paging policy is provided. Queries
for accepted-risk and outcome counts are documented for custom alerts.

| Alert | Initial trigger and hold |
| --- | --- |
| KonstapelMetricsUnavailable | Expected release has no successful scrape for 5m |
| KonstapelObservationUnavailable | Enabled domain has no fresh ready owner projection for 5m |
| KonstapelBindingUnresolved | Current Resolved is false or unknown for 10m |
| KonstapelEngineUnavailable | An enabled required engine capability is false or unknown for 10m |
| KonstapelAssessmentOverdue | Time exceeds scheduled due + collection timeout + 10m grace, held for 5m |
| KonstapelPublicationFailing | At least 3 failed attempts in 15m with current actionable publication failure, held for 5m |
| KonstapelCleanupBlocked | Blocked cleanup, or pending cleanup past its oldest expiry by 1h, held for 15m |

Render thresholds, time windows and `for` durations from validated chart values.
Scoping selectors include the release's scrape identity, with configurable
equivalents for externally managed scraping. Use `up` and an explicit absent-series
case for the expected release; counting only `up == 0` misses a ServiceMonitor
that discovers no targets. Enabled domains have expected availability even
before their first useful data, so absence of domain series is an availability
failure, not a healthy empty input.

Operational rules require a successful scrape and usable source projection.
Loss of that prerequisite produces the availability alert instead of treating
absent gauges as zero failures. Alert resolution in that case does not establish
recovery of the underlying operation; explain this in runbooks. Keep joins scoped
to release/namespace and preserve cluster labels where present. Attempt counters
can be summed after `increase` across instances; binding/backlog gauges cannot
be summed across replicas. Test resets, failover, stale samples, absent domains
and two releases with identical binding names in Prometheus rule fixtures.

Each rule includes actionable annotations and a runbook link explaining source
state, timing, relevant Conditions, diagnostic commands and recovery checks.
Runbooks do not prescribe disabling verification, deleting retained records,
relaxing policy mode or granting exceptions to silence monitoring.

### 8. Keep implementation dependencies and validation explicit

This change owns metric definitions/projections, instrumentation hooks, metrics
access integration, monitoring templates, rule tests and runbooks. It consumes
the targeting resolver/manager and the assessment, bundle and S3 state contracts.
Publish projection interfaces and fixtures first; add source adapters after the
owning contracts merge. If a needed timestamp is absent, coordinate a bounded
field with that owner rather than altering scheduling or evidence semantics.

Core metric and rule tests can start now. Manager instrumentation waits for the
manager implementation. Assessment views require the current-state and run
producer, not merely the CRD schema. Storage backlog integration requires the
publication/cleanup implementation. Authenticated ServiceMonitor acceptance waits
for the Helm chart. Do not emit fabricated healthy metrics for unfinished domains.

Use Prometheus `promtool check rules` and `promtool test rules` on the exact rendered
rule content, promoting a pinned Prometheus tooling package into Devbox when
implemented. Put formatting, exposition and rule tests behind existing
`task check`; extend the chart plan's `charts:acceptance` workflow with a
monitoring scenario. No new public task is necessary for each rule/helper.

Live acceptance uses pinned Prometheus Operator/Prometheus versions in the
existing disposable chart test environment. Confirm actual discovery, TLS,
authorized/unauthorized scrapes, CA/token rotation, fixture failure/recovery and
alert transitions. Keep absence-of-Operator rendering coverage without installing
it for default charts. Record versions and evidence; clean up task-owned
monitoring/cluster resources. This does not claim broader HA or framework support.

## Risks / Trade-offs

- **A current-looking metric hides old evidence:** separate source time, closure,
  projection validity and publication; invalidate current views at expiry.
- **A false healthy zero masks a broken producer:** explicit ready/enabled domains,
  omitted unknown values, and missing-series alert tests.
- **Identity/cardinality leaks through labels:** fixed enums and binding names,
  UID-aware internal lifecycle, and workload/history scaling fixtures.
- **Auth or selectors prevent scraping:** test the actual Operator integration,
  document reader identities and cache bounds, and alert on absent targets.
- **Replica transitions duplicate data:** select the synchronized owner and test
  scoped rule aggregation without promising a new HA architecture.
- **Shared implementations are still landing:** isolate contracts and fixtures,
  rebase before integration, and preserve owner-defined semantics.

## Migration Plan

Land the metric catalog/projection tests and rules first, then wire implemented
domains into the manager. Deploy metrics TLS and reader RBAC, verify an authorized
scrape, and opt into ServiceMonitor discovery. Review rendered rules against real
binding intervals before enabling PrometheusRule; use controlled failures to
verify firing and recovery. Retain NIST Moderate as the initial content set.

Rollback by disabling optional rules/ServiceMonitor, or the metrics endpoint when
necessary, without changing enforcement, assessment schedules or S3 retention.
Remove only owned monitoring resources and reader bindings. Historical monitoring
data remains under the external monitoring system's retention policy.
