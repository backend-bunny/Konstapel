# Prometheus metrics

This page tracks `add-prometheus-observability`. It defines the **metric
contract** (the families Konstapel exposes, their types, units, label
vocabularies, availability and reset semantics) and the **projection rules**
that turn owner state into those families. The controller registers the
families in controller-runtime's metrics registry, next to its retained
reconciliation, workqueue, client, Go and process collectors, and serves them
on `--metrics-bind-address` (disabled by default). Targeting, assessment,
evidence storage and, with bundle sources enabled, bundle resolution publish
projections; see [Producers](#producers). Authenticated serving (group 3), Helm
integration (group 4) and starter alerts (group 5) come later.

## Rules of the contract

- **Names:** every family is prefixed `konstapel_` and uses Prometheus naming:
  counters end in `_total`, durations are in seconds, and timestamps are Unix
  seconds ending in `_timestamp_seconds`.
- **Bounded, framework-neutral labels.** The only labels are the binding name
  and fixed enums: `domain`, `condition`, `status`, `capability`, `view`,
  `state`, `operation` and `result`. There are no namespace, workload, run,
  UID, policy or profile names, no reasons or error strings, no versions or
  digests, no storage references, and no framework content (catalogs,
  controls, baselines). Series per family are bounded by the number of
  bindings times the enum sizes, not by workloads or retained history.
  Framework attribution stays in bundle metadata and OSCAL reports; equivalent
  summaries attributed to different catalogs expose identical metrics.
- **Domains:** every family belongs to one owner domain (`targeting`,
  `assessment`, `bundle_resolution`, `evidence_storage`), or is process-local.
  A domain's families are emitted only while its projection is fresh and
  ready. Missing or stale data is never shown as a healthy zero;
  `konstapel_observation_ready` and `konstapel_observation_enabled` say which
  case applies.
- **Retained upstream metrics:** controller-runtime's reconciliation,
  workqueue, client, Go and process metrics are kept as upstream provides them
  and are not duplicated here.
- **Operation durations** use the buckets 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
  30, 60, 120 and 300 seconds.

`internal/observability/catalog.go` is the source of truth. The tests check
the conventions above. They also pin the full exposition
(`testdata/observability/exposition.txt`) and generate the table below.
After changing the catalog, regenerate both with
`go test ./internal/observability -update`.

## Projections

Owners publish immutable snapshots of their synchronized state into the
`observability.Hub`; a scrape only reads those snapshots. It never lists
reports, resolves bundles, reads storage, or asks an owner to recompute, so
scraping during a registry or storage outage causes no dependency work.

### Freshness and readiness

A domain is ready (`konstapel_observation_ready 1`) only while all of these
hold, checked against the clock at every scrape:

- the domain is enabled in this process;
- this replica is the elected leader and an owner published in the current
  leadership term;
- the published snapshot is at most 2 minutes old (its production time is
  `konstapel_observation_updated_timestamp_seconds`).

An owner republishes on relevant events and at a bounded refresh interval,
and withdraws its projection when its watch continuity or cache
synchronization is lost. Snapshots older than the one held are rejected. A
stalled owner therefore loses readiness and all its families while HTTP
scrapes still succeed; its last production time stays visible so its age can
be queried.

### Leadership

Owner projections are leader-scoped. Leadership follows the manager's
existing Lease election: when this replica is elected a new term starts with
no projections, and when the leader context ends every projection is cleared
and writes from the old term are rejected. A successor exposes summaries only
after owners republish from reconstructed state. Followers expose
`konstapel_observation_enabled`, `konstapel_observation_ready 0` and their own
operation counters. Operation counters are process-local on every replica and
reset on restart; they are never reconstructed from records.

### Binding summaries

Binding series are keyed internally by binding UID and labelled by name.
Deleting a binding removes its series; a binding recreated with the same name
starts without the old object's runs. While the targeting and assessment
projections disagree about which object a name denotes, none of that name's
series is exposed. Prometheus retains old samples under the name, so queries
spanning a recreation must use `konstapel_binding_created_timestamp_seconds`
as the boundary.

Each binding has two views, `current` and `latest_closed`, with one-hot
`konstapel_binding_assessment_status`:

| Status | Meaning | Counts | `complete` |
| --- | --- | --- | --- |
| `known` | Nonempty, consistent inventory | All states, summing to the inventory | 1 when every expected observation is attributable |
| `no_targets` | Known empty scope; not a pass | All states, 0 | Absent |
| `no_assessment` | No full-binding run has closed for this object (`latest_closed` only) | Absent | Absent |
| `unknown` | No current evaluation yet, expired current evidence, a lost capture, a stale (unresolved) scope, or counts that do not add up | Absent | Absent |

`state` uses the assessment owner's normalized vocabulary; the projection
renames it and never reclassifies engine results:

| State | Owner field | Meaning |
| --- | --- | --- |
| `pass`, `fail`, `error`, `skip` | `outcomes` | Attributable engine outcome |
| `accepted_risk` | `outcomes.acceptedRisk` | Attributable, valid accepted risk; never a pass |
| `out_of_scope` | `outcomes.notApplicable` | Known non-applicability; never a pass |
| `unknown` | `outcomes.unknown` | Attributable outcome the owner does not distinguish, including unsupported warning outcomes such as Kyverno `warn`. Not missing evidence (that is `missing`). |
| `missing` | `evidence.missing` | No matching result |
| `rejected` | `evidence.rejected` | Matching results, none usable (including older than `maxEvidenceAge`) |
| `unresolved` | `evidence.unresolved` | Scope changed during collection or results conflict |

The status follows a fixed precedence, most conservative first: current
evidence expired, inventory lost, stale (unresolved) scope, counts that do not
add up, no targets, known. An accepted risk is counted once, whatever the
engine reported; a summary that would also count its raw outcome is withheld
as `unknown`.

There is no `warn` or `stale` state:

- **Warnings.** Kyverno reports `warn` for a failing policy annotated
  `policies.kyverno.io/scored: "false"`. Konstapel keeps source annotations
  when it renders policies, so organization bundles can produce warnings; the
  vendored content does not. The assessment owner keeps the raw `warn` in the
  observation and the OSCAL export but counts it as `unknown` in its summary,
  so the metric does too. It is counted once, never as a pass, a failure or an
  accepted risk. `unknown` therefore includes unsupported warning outcomes and
  must not be read as missing evidence alone. To find the warnings, look at the
  raw outcome in the package's retained `evaluation.json` (observation
  `outcome: warn`) or in OSCAL (subject `result` property `warning`,
  `source-outcome` property `warn`). A native warning count is a tracked
  follow-up; it is not required for 0.2.0.
- **Stale evidence.** Evidence older than `maxEvidenceAge` is never a current
  pass. The owner counts it as `rejected` when it evaluates. Between
  evaluations the current view becomes `unknown` at the owner's next expiry,
  and `konstapel_binding_current_evidence_expiry_timestamp_seconds` keeps that
  time queryable. `time() >= konstapel_binding_current_evidence_expiry_timestamp_seconds`
  means the binding's current evidence is stale. Republishing the same summary
  does not extend the expiry. The `latest_closed` view
is the latest closed full-binding run of the current binding object,
including incomplete and diagnostic closures, selected by closure time.
Namespace-scope request runs never replace it and publication state does not
choose it. Its source and closure times stay the run's own: querying it later
does not make it current.

### Storage backlog

Publication and cleanup gauges count the storage owner's retained records and
remain available after a binding is deleted. A known empty backlog is 0; an
unknown one is absent.

## Producers

Each implemented owner runs a leader-elected refresher that waits for the
manager's cache to synchronize, then republishes on every change of its
objects and every 30 seconds. If it cannot read its state it withdraws the
projection, so the domain stops being ready. It does not keep serving old
values.

| Domain | Source | Notes |
| --- | --- | --- |
| `targeting` | ComplianceBindings in the manager cache; the capability monitor's cached `PolicyDelivery` and `Assessment` results | A Condition or `targetCount` observed for an older generation is `unknown` or absent. A capability that cannot be checked (`DependencyUnavailable`) is `unknown`. A missing API or denied access is `false`. Policy delivery and assessment reporting are reported separately, so reporting can be unavailable while delivery works. |
| `assessment` | ComplianceBindings and AssessmentRuns in the manager cache | Current view: `status.assessment.current`, including the owner's `oldestEvaluation` and `nextExpiry`. Latest closed view: the binding object's latest closed full-binding run with its own summary and window. Interval, evidence-age limit and collection timeout are the binding's effective settings; a binding whose settings do not parse is left out. Due time: `schedule.outstandingSince`, or else the first scheduled time after the newest scheduled run (which may already have passed while another run held the slot). It is absent while the binding has never been planned. Overdue means `time() > due + collection timeout + grace`. |
| `evidence_storage` | AssessmentRun records in the manager cache, including runs whose binding was deleted | See the backlog table below. |
| `bundle_resolution` | The bundle sources Watcher | Ready while the Watcher's latest Sync read its configuration within two refresh intervals plus one read timeout. A missing or invalid sources ConfigMap is still a successful read; it shows up in profile Conditions, not here. |

| Gauge | Counted runs |
| --- | --- |
| `konstapel_publication_pending` | `Publishing` runs whose last attempt did not fail |
| `konstapel_publication_failed` | `Publishing` runs whose last attempt failed and is retried (`Published=False`, reason `Retrying`, or `SigningPending` while required signing is unmet). This is an actionable failure. A run that exhausted the publish timeout is `Failed` with `PublicationFailed`; that is a historical failure and is not counted. |
| `konstapel_cleanup_pending` | Committed packages past their recorded expiry whose deletion is not confirmed, including deletions that failed and are retried with backoff |
| `konstapel_cleanup_blocked` | Deletions refused by storage retention (`RetentionBlocked`), which need action |
| `konstapel_cleanup_oldest_expiry_timestamp_seconds` | Oldest recorded expiry among pending and blocked cleanup |

Deleted and operator-owned (orphaned) packages are not backlog. A delete
request reduces the backlog only after the run records the confirmed
deletion. After a restart the gauges are rebuilt from the records.

`konstapel_operation_attempts_total` and `konstapel_operation_duration_seconds`
count completed storage and resolution attempts on the replica that made them,
and reset when that process restarts:

- `evidence_publication`: one attempt per stage-and-commit. A failed stage or a
  commit result completes it.
- `evidence_cleanup`: one per expiry deletion. A package that is already gone
  counts as success.
- `bundle_resolution`: one per resolution that rechecks retained evidence,
  retrieves, or fails before either. Reuse under a current acceptance is not
  counted.

Labels carry only the operation and `success`/`failure`. Repositories, digests,
identities and error text are never labels.

## Catalog

<!-- catalog:begin -->
| Metric | Type | Labels | Meaning | Availability | Reset |
| --- | --- | --- | --- | --- | --- |
| `konstapel_observation_enabled` | gauge | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | 1 when the observation domain's feature is enabled and expected to report, 0 when disabled. | Always, for every domain. | Configuration state; constant for a process. |
| `konstapel_observation_ready` | gauge | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | 1 when this replica holds an enabled domain's synchronized leader projection within its maximum age, otherwise 0. | Always, for every domain; 0 while disabled, not leading, unsynchronized or older than the maximum projection age. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_observation_updated_timestamp_seconds` | gauge, seconds | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | Unix time the owner produced the domain's current projection from synchronized state. | While this replica holds a projection for the domain, even a stale one; cleared on leadership loss or owner withdrawal. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_binding_created_timestamp_seconds` | gauge, seconds | `binding` | Creation time of the current binding object with this name. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_condition` | gauge | `binding`<br>`condition` (Resolved, EngineReady)<br>`status` (true, false, unknown) | One-hot binding condition state: 1 for the current status of Resolved and EngineReady. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_target_namespaces` | gauge | `binding` | Known number of target namespaces, even when content is unresolved. | Only when the target inventory is known. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_capability_condition` | gauge | `capability` (policy_delivery, assessment, exceptions)<br>`status` (true, false, unknown) | One-hot prerequisite state of an enabled capability. | Only while the targeting projection is fresh and ready, for capabilities the owner reports as enabled. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_binding_assessment_status` | gauge | `binding`<br>`view` (current, latest_closed)<br>`status` (known, no_targets, no_assessment, unknown) | One-hot summary availability per view: known, no_targets, no_assessment or unknown. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_checks` | gauge | `binding`<br>`view` (current, latest_closed)<br>`state` (pass, fail, error, skip, accepted_risk, out_of_scope, unknown, missing, rejected, unresolved) | Expected check instances per display state; the states sum to the view's known inventory. | Only while the view's status is known or no_targets (all zero); omitted when the inventory is unknown or the current view expired. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_complete` | gauge | `binding`<br>`view` (current, latest_closed) | 1 when every expected observation in the view is attributable, otherwise 0. | Only while the view's status is known (a nonempty inventory). | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_oldest_evaluation_timestamp_seconds` | gauge, seconds | `binding`<br>`view` (current, latest_closed) | Oldest attributable source evaluation time in the view. | Only while the view's status is known and its owner records an attributable source evaluation time. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_current_evidence_expiry_timestamp_seconds` | gauge, seconds | `binding` | When the oldest attributable current evidence exceeds the evidence-age limit; from then on the current view is unknown until re-evaluated. | While the assessment projection is fresh and ready and the owner records a next expiry for current evidence, including after it has passed. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_snapshot_collection_started_timestamp_seconds` | gauge, seconds | `binding` | Collection start of the latest closed full-binding run. | Only after a full-binding run has closed. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_last_closed_timestamp_seconds` | gauge, seconds | `binding` | Closure time of the latest full-binding run, including incomplete and diagnostic closures. | Only after a full-binding run has closed. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_interval_seconds` | gauge, seconds | `binding` | Effective scheduled assessment cadence. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_max_evidence_age_seconds` | gauge, seconds | `binding` | Effective evidence-age limit. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_scheduled_due_timestamp_seconds` | gauge, seconds | `binding` | Earliest outstanding scheduled due time, or the next due time when none is outstanding. | Only while the assessment projection is fresh and ready and the scheduler records a due time. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_collection_timeout_seconds` | gauge, seconds | `binding` | Configured collection limit, used with the overdue grace period. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_operation_attempts_total` | counter | `operation` (bundle_resolution, evidence_publication, evidence_cleanup)<br>`result` (success, failure) | Completed attempts of a bounded operation; each retry is a separate attempt. | Always; zero until the first attempt. | Process-local counter; resets to zero on restart; never reconstructed. |
| `konstapel_operation_duration_seconds` | histogram, seconds | `operation` (bundle_resolution, evidence_publication, evidence_cleanup)<br>`result` (success, failure) | Duration of completed attempts of a bounded operation. | Always; empty until the first attempt. | Process-local counter; resets to zero on restart; never reconstructed. |
| `konstapel_publication_pending` | gauge |  | Closed runs whose evidence package is not yet committed and is still being attempted. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_publication_failed` | gauge |  | Closed runs whose publication currently fails and needs action. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_pending` | gauge |  | Retained packages past expiry whose deletion is not yet confirmed. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_blocked` | gauge |  | Retained packages whose deletion is blocked and needs action. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_oldest_expiry_timestamp_seconds` | gauge, seconds |  | Expiry of the oldest package with pending or blocked cleanup. | Only while the storage projection is fresh and ready and cleanup is pending or blocked. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
<!-- catalog:end -->
