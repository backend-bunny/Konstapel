# Prometheus metrics

This page tracks `add-prometheus-observability`. It defines the **metric
contract** (the families Konstapel exposes, their types, units, label
vocabularies, availability and reset semantics) and the **projection rules**
that turn owner state into those families. The controller registers the
families in controller-runtime's metrics registry, next to its retained
reconciliation, workqueue, client, Go and process collectors.

The controller serves them only over HTTPS, with a verified certificate
(`--metrics-bind-address`, `--metrics-cert-dir`, `--metrics-server-name`).
Every scrape is authenticated with a TokenReview and authorized with a
SubjectAccessReview for `get` on `/metrics`. Metrics are off by default; the
runtime chart's `metrics.enabled` turns them on, as described in
[Controller metrics](../charts.md#controller-metrics), together with reader
access and the revocation bounds.

Targeting, assessment, evidence storage and, with bundle sources enabled,
bundle resolution publish projections; see [Producers](#producers). The
optional ServiceMonitor and PrometheusRule are described in
[Monitoring integration](../charts.md#monitoring-integration), and the
starter alerts with their runbooks in [Alert runbooks](alert-runbooks.md).
The documented setup is verified against a real, pinned Prometheus Operator
and a Prometheus in another namespace ([Verified Operator
setup](../charts.md#verified-operator-setup)): discovery through the chart's
ServiceMonitor, authenticated TLS scrapes, the starter rules loaded, denial
for an unbound identity, the Operator's file-access policy with the Secret
fallback, and revocation within the cache bound. The
[integrated acceptance](#integrated-acceptance) then drives real failures,
replica changes and credential changes through that scrape and the starter
alerts.

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
| `evidence_storage` | AssessmentRun and EvidenceSigningRequest records in the manager cache, including runs whose binding was deleted | See the backlog table below. |
| `bundle_resolution` | The bundle sources Watcher | Ready while the Watcher's latest Sync read its configuration within two refresh intervals plus one read timeout. A missing or invalid sources ConfigMap is still a successful read; it shows up in profile Conditions, not here. |

| Gauge | Counted runs |
| --- | --- |
| `konstapel_publication_pending` | `Publishing` runs whose last attempt did not fail |
| `konstapel_publication_failed` | Unpublished runs that need action: `Publishing` runs whose last attempt failed and is retried (`Published=False`, reason `Retrying`, or `SigningPending` while required signing is unmet), and `Failed` runs with `SigningFailed` that keep their staged evidence, until recovery publishes them or their `expiresAt` passes. A run that exhausted the publish timeout with `PublicationFailed` keeps no evidence; that is a historical failure and is not counted. |
| `konstapel_publication_retained_signing_failures` | The retained `SigningFailed` runs among `konstapel_publication_failed`. They no longer retry; an administrator recovers them with an EvidenceSigningRequest. Subtract them to get the retrying runs. |
| `konstapel_cleanup_pending` | Retained packages past their recorded expiry whose deletion is not confirmed, including deletions that failed and are retried with backoff. A retained package is a committed package or the staged evidence a `SigningFailed` run keeps until its expiry. |
| `konstapel_cleanup_blocked` | Deletions refused by storage retention (`RetentionBlocked`), which need action |
| `konstapel_cleanup_oldest_expiry_timestamp_seconds` | Oldest recorded expiry among pending and blocked cleanup |
| `konstapel_evidence_signing_recovery_requests` | EvidenceSigningRequests by recorded `status.phase` and `status.reason`; every reason allowed with its phase is a series, zero when unused. Requests not yet accepted (no phase) are not counted. |

A retained `SigningFailed` run leaves `konstapel_publication_failed` in one of
two ways. Recovery publishes it: the run becomes a committed package with the
same expiry in one record update, so it is counted once. Otherwise its
`expiresAt` passes and its evidence becomes cleanup backlog until the deletion
is confirmed.

Signing recovery emits no Kubernetes Events. The controller's Event recorder
writes only in the controller namespace, and Konstapel does not grant Event
writes outside it. EvidenceSigningRequests and AssessmentRuns are
cluster-scoped, so their Events would need such a grant. Recovery is observed
through the durable request and run status, the request gauge, the publication
gauges, and controller logs, which name the run and request but never key
material.

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

## Query examples

These queries are evaluated in `task test` with `promtool test rules`. They run
against series generated from the observability Hub
(`testdata/observability/queries.test.yml`), and the expected results are in
`testdata/observability/queries.cases.yaml`. A test fails if any query below is
not one of those cases. Regenerate the series with
`go test ./internal/observability -update` after changing the catalog or the
projections.

Rules for aggregating safely:

- **Binding and backlog gauges come from the leader only.** Aggregate them with
  `max by (job, binding)` (or `max by (job)`). Never use `sum`, which would
  double-count during a leader change.
- **Counters are per replica and reset on restart.** Use `increase` or `rate`
  first, then `sum` across replicas.
- **Group by the scrape identity (`job`, and your cluster label if any).** Two
  releases can have bindings with the same name.
- **Gate on readiness.** A domain that is not ready exposes no values at all,
  so check `konstapel_observation_ready` alongside any query on its series.
  Absence never means zero.

An enabled domain without a fresh, ready projection on any replica:

```promql
max by (job, domain) (konstapel_observation_enabled) == 1
unless on (job, domain)
max by (job, domain) (konstapel_observation_ready) == 1
```

Projection age per domain. This measures the owner's production time, not
scrape time:

```promql
time() - max by (job, domain) (konstapel_observation_updated_timestamp_seconds)
```

Bindings whose `Resolved` condition is not `true` (false, or unknown for the
current generation):

```promql
max by (job, binding) (konstapel_binding_condition{condition="Resolved", status!="true"}) == 1
```

Failing checks in current evidence:

```promql
max by (job, binding) (konstapel_binding_assessment_checks{view="current", state="fail"}) > 0
```

Accepted risks. These are counted separately and are never passes:

```promql
max by (job, binding) (konstapel_binding_assessment_checks{view="current", state="accepted_risk"})
```

Checks without a usable result. `unknown` includes engine warnings; find
them through the raw outcome in the run's evidence:

```promql
sum by (job, binding) (
  max by (job, binding, state) (
    konstapel_binding_assessment_checks{view="current", state=~"unknown|missing|rejected|unresolved"}
  )
)
```

Current evidence past the owner's expiry. The current view is then `unknown`
until the owner evaluates again:

```promql
time() >= max by (job, binding) (konstapel_binding_current_evidence_expiry_timestamp_seconds)
```

Scheduled work overdue past its collection timeout plus a 10-minute grace. A
binding that has never been planned has no due time:

```promql
time() >
  max by (job, binding) (konstapel_binding_scheduled_due_timestamp_seconds)
+ max by (job, binding) (konstapel_binding_collection_timeout_seconds)
+ 600
```

Age of the latest closed full-binding run. This is history: querying it never
makes that snapshot current, and Prometheus keeps a deleted binding's old
samples under the same name. Use `konstapel_binding_created_timestamp_seconds`
as the boundary when a query spans a recreation.

```promql
time() - max by (job, binding) (konstapel_binding_last_closed_timestamp_seconds)
```

Failed publication attempts in 15 minutes, across replicas:

```promql
sum by (job) (increase(konstapel_operation_attempts_total{operation="evidence_publication", result="failure"}[15m]))
```

Failed publications, including retained signing failures:

```promql
max by (job) (konstapel_publication_failed)
```

Retained signing failures awaiting recovery (see
[signing recovery](evidence-signing.md)):

```promql
max by (job) (konstapel_publication_retained_signing_failures) > 0
```

A retrying publication failure with recent failed attempts:

```promql
max by (job) (konstapel_publication_failed - konstapel_publication_retained_signing_failures) > 0
and on (job)
sum by (job) (increase(konstapel_operation_attempts_total{operation="evidence_publication", result="failure"}[15m])) >= 3
```

Blocked retention cleanup:

```promql
max by (job) (konstapel_cleanup_blocked) > 0
```

Binding summaries come from exactly one replica. A count above 1 means
ownership is ambiguous:

```promql
count by (job, binding) (konstapel_binding_assessment_status{view="current"} == 1)
```

## Integrated acceptance

`TestLiveHelmMonitoring` (the `monitoring` acceptance group; [Verified Operator
setup](../charts.md#verified-operator-setup)) checks these semantics end to
end. The Helm-installed controller is scraped over verified TLS by a real
Prometheus. Real failures, replica changes and credential changes then go
through that scrape and Prometheus's own evaluation of the chart's rendered
starter alerts. The test reads alert states from the Prometheus alerts API
and series from its query API; it never evaluates a rule itself. It first
checks that the defaults are loaded (holds 5m, 5m, 10m, 10m, 5m, 2m and 15m,
all `warning`). It then tunes them with `helm upgrade` as an operator would:
1-minute holds, overdue grace 30s, cleanup lateness 120s,
`KonstapelBindingUnresolved` at `critical`, and `KonstapelCleanupBlocked`
disabled and later re-enabled. The controller Deployment is not touched.
`KonstapelPublicationFailing` keeps its default 2-minute hold.

| Scenario | Real cause | Checked through Prometheus |
| --- | --- | --- |
| Baseline | three bindings: no workload, a passing and a failing Pod every 2 minutes, one passing Pod with a 90s evidence-age limit | one owner per enabled domain (the Lease holder); `bundle_resolution` disabled and never ready; followers expose no owner series; `no_targets` with zero counts and no completeness; expiry = oldest evaluation + `maxEvidenceAge`; no alert firing |
| Publication failing | the test S3 fault proxy refuses one binding's requests during a manual run | `KonstapelPublicationFailing` fires before the 5-minute publish timeout; the gauge is 1 and at least 3 attempts failed; after storage returns, the run commits and the alert resolves |
| Cleanup blocked | an S3 legal hold on a package in an object-lock bucket | `KonstapelCleanupBlocked` fires once the expiry deletion is refused (`RetentionBlocked`); it keeps firing after the binding is deleted; lifting the hold lets the next backed-off attempt delete the package and resolves it |
| Binding deleted and recreated | the binding is deleted while its package's cleanup is blocked, then recreated with the same name | every series of the old object disappears; the backlog outlives it; the new object has a newer creation time, one series per view, and never the old object's latest closed run |
| Binding unresolved | a binding names a missing profile | `KonstapelBindingUnresolved` fires with the configured `critical` severity |
| Evidence expiry | Kyverno's reports and background controllers are stopped | once the expiry passes, the current view is `unknown` or re-evaluated as `rejected`, never a pass; a run closed afterwards counts the aged observation as `rejected` and is incomplete; after reporting resumes the view is current again |
| Reporting access lost | the controller's ClusterRole loses `wgpolicyk8s.io` | `KonstapelEngineUnavailable` fires for `assessment` while `policy_delivery` stays true and never alerts; current evidence is never a pass; scheduling stops and `KonstapelAssessmentOverdue` fires; both resolve once access returns |
| Leader killed | the Lease holder's pod is force-deleted while a run is in flight | a surviving replica (the follower, or the Deployment's replacement pod if it wins the expired Lease first) takes the Lease and becomes the only owner; every binding gauge is exposed once, by it, with unchanged values; the killed pod's series are gone; the other replica exposes no owner series, readiness 0 and zero counters; the run completes |
| No leader | the controller's Role loses Lease access, so the leader exits with `leader election lost` and restarts and no replica can lead | both targets still scrape (`up` 1); `KonstapelObservationUnavailable` fires for exactly the three enabled domains; no binding, capability or backlog series is exposed; the firing `KonstapelBindingUnresolved` resolves although nothing recovered; the restarted process's counters reset (`resets`) without an alert; after access returns, one owner is back and `KonstapelBindingUnresolved` fires again only after its full hold, then resolves when its profile exists |
| Certificate rotation | cert-manager reissues the metrics certificate in place (manual renewal) | the new serial is served without a restart, and `min_over_time(up[…])` stays 1 for every target |
| Token rotation | a new reader token, bound to a Secret, goes into the Secret-mode ServiceMonitor's Secret; after propagation the old token's anchor Secret is deleted | the controller refuses the old token within the 1-minute authentication cache; every target keeps scraping with the new one |
| Revocation | the `konstapel-metrics-reader` binding is deleted and a replica is replaced | every target is refused with `403` within the 5-minute allow cache (the new replica at once); `KonstapelMetricsUnavailable` fires; a run still publishes; after the binding is restored, scrapes return within the 30-second denial cache and the alert resolves |

Each measured time and the full alert timeline are recorded in
`TestLiveHelmMonitoring.json` of the group's evidence. One CI run (GitHub
runner, 15s scrape and evaluation interval, the tuned holds above) measured:

| Scenario | Measured |
| --- | --- |
| Publication failing | pending 26s and firing 146s after the run closed, inside its 300s publish timeout, after 11 failed attempts; committed 10s and resolved 28s after storage returned |
| Cleanup blocked | firing 106s after the package's expiry (1m hold); deleted 53s and resolved 67s after the hold was lifted (the deletion backs off from 1 minute) |
| Binding recreated | the old object's series gone 6s after its deletion |
| Evidence expiry | the owner re-evaluated at the expiry, so the current view showed `rejected`, never a pass; current again 54s after reporting resumed |
| Reporting access lost | `KonstapelEngineUnavailable` firing 83s and `KonstapelAssessmentOverdue` 219s after the access was removed; both resolved 44s after it returned |
| Leader killed | Lease taken after 14s, the successor the only owner after 20s; `KonstapelObservationUnavailable` did not fire (1m hold) |
| No leader | the leader restarted 12s after losing Lease access; `KonstapelObservationUnavailable` firing for the three enabled domains 90s after; one owner 9s after access returned; `KonstapelBindingUnresolved` firing again 101s after that (1m hold) |
| Certificate rotation | the new certificate served after 48s, no failed scrape |
| Token rotation | the revoked token refused after 60s (`500 invalid bearer token`, the 1-minute authentication cache); no failed scrape |
| Revocation | every target refused after 135s (bound: 5 minutes plus a scrape); `KonstapelMetricsUnavailable` firing after 192s; a run published 33s after the revocation; scrapes back 39s after the binding returned, and the alert resolved |

The whole test takes about 30 minutes; the `monitoring` job about 35.

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
| `konstapel_publication_failed` | gauge |  | Closed runs whose publication currently fails and needs action, including retained signing failures until recovery or expiry. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_publication_retained_signing_failures` | gauge |  | Runs counted in konstapel_publication_failed that ended SigningFailed and keep their staged evidence for recovery until their expiry. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_pending` | gauge |  | Retained packages past expiry whose deletion is not yet confirmed. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_blocked` | gauge |  | Retained packages whose deletion is blocked and needs action. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_oldest_expiry_timestamp_seconds` | gauge, seconds |  | Expiry of the oldest package with pending or blocked cleanup. | Only while the storage projection is fresh and ready and cleanup is pending or blocked. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_evidence_signing_recovery_requests` | gauge | `phase` (Pending, Running, Succeeded, Failed)<br>`reason` (Accepted, Waiting, Signing, Committing, Recovered, AlreadyRecovered, RunNotFound, RunDeleting, NotRecoverable, Expired, Orphaned, EvidenceLost, KeyConfirmationRequired, KeyMismatch, SigningFailed, Conflict) | EvidenceSigningRequests by recorded status phase and reason, including terminal requests kept as audit records. | Only while the storage projection is fresh and ready, for every reason allowed with its phase (zero when none); requests without a recorded phase are not counted. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
<!-- catalog:end -->
