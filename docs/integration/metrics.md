# Prometheus metrics

This page tracks `add-prometheus-observability`. It currently defines the
**metric contract**: the families Konstapel will expose, their types, units,
label vocabularies, availability and reset semantics. No collector is
registered with the controller yet. Projections (tasks 1.2–1.4), producer
wiring (group 2), authenticated serving (group 3), Helm integration
(group 4) and starter alerts (group 5) come later.

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
  Framework attribution stays in bundle metadata and OSCAL reports.
- **Domains:** every family belongs to one owner domain (`targeting`,
  `assessment`, `bundle_resolution`, `evidence_storage`), or is process-local.
  A domain's families are emitted only while its projection is fresh and
  ready. Missing or stale data is never shown as a healthy zero;
  `konstapel_observation_ready` and `konstapel_observation_enabled` say which
  case applies.
- **Retained upstream metrics:** controller-runtime's reconciliation,
  workqueue, Go and process metrics are kept as upstream provides them and are
  not duplicated here.
- **Operation durations** use the buckets 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
  30, 60, 120 and 300 seconds.

`internal/observability/catalog.go` is the source of truth. The tests check
the conventions above. They also pin the full exposition
(`testdata/observability/exposition.txt`) and generate the table below.
After changing the catalog, regenerate both with
`go test ./internal/observability -update`.

## Catalog

<!-- catalog:begin -->
| Metric | Type | Labels | Meaning | Availability | Reset |
| --- | --- | --- | --- | --- | --- |
| `konstapel_observation_enabled` | gauge | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | 1 when the observation domain's feature is enabled and expected to report, 0 when disabled. | Always, for every domain. | Configuration state; constant for a process. |
| `konstapel_observation_ready` | gauge | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | 1 when the domain has a synchronized projection within its maximum age, otherwise 0. | Always, for every enabled domain; unknown or stale domains are 0, never healthy zeroes elsewhere. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_observation_updated_timestamp_seconds` | gauge, seconds | `domain` (targeting, assessment, bundle_resolution, evidence_storage) | Unix time the domain's projection was last refreshed from synchronized owner state. | After the domain's first synchronized projection. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_binding_created_timestamp_seconds` | gauge, seconds | `binding` | Creation time of the current binding object with this name. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_condition` | gauge | `binding`<br>`condition` (Resolved, EngineReady)<br>`status` (true, false, unknown) | One-hot binding condition state: 1 for the current status of Resolved and EngineReady. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_target_namespaces` | gauge | `binding` | Known number of target namespaces, even when content is unresolved. | Only when the target inventory is known. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_capability_condition` | gauge | `capability` (policy_delivery, assessment, exceptions)<br>`status` (true, false, unknown) | One-hot prerequisite state of an enabled capability. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_binding_assessment_status` | gauge | `binding`<br>`view` (current, latest_closed)<br>`status` (known, no_targets, no_assessment, unknown) | One-hot summary availability per view: known, no_targets, no_assessment or unknown. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_checks` | gauge | `binding`<br>`view` (current, latest_closed)<br>`state` (pass, fail, accepted_risk, error, warn, skip, unknown, stale, out_of_scope) | Independently identified check instances per display state; for a known inventory the states sum to it. | Only for a known inventory; omitted when the inventory is unknown. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_complete` | gauge | `binding`<br>`view` (current, latest_closed) | 1 when every expected observation in the view is attributable, otherwise 0. | Only for a known nonempty summary. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_oldest_evaluation_timestamp_seconds` | gauge, seconds | `binding`<br>`view` (current, latest_closed) | Oldest attributable source evaluation time in the view. | Only when the view has an attributable observation. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_snapshot_collection_started_timestamp_seconds` | gauge, seconds | `binding` | Collection start of the latest closed full-binding run. | Only after a full-binding run has closed. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_last_closed_timestamp_seconds` | gauge, seconds | `binding` | Closure time of the latest full-binding run, including incomplete and diagnostic closures. | Only after a full-binding run has closed. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_assessment_interval_seconds` | gauge, seconds | `binding` | Effective scheduled assessment cadence. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_max_evidence_age_seconds` | gauge, seconds | `binding` | Effective evidence-age limit. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_scheduled_due_timestamp_seconds` | gauge, seconds | `binding` | Earliest outstanding scheduled due time, or the next due time when none is outstanding. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_binding_collection_timeout_seconds` | gauge, seconds | `binding` | Configured collection limit, used with the overdue grace period. | Only while the domain's projection is fresh and ready; absent otherwise. | Per binding UID: removed when the binding is deleted; a recreated name starts without old values. |
| `konstapel_operation_attempts_total` | counter | `operation` (bundle_resolution, evidence_publication, evidence_cleanup)<br>`result` (success, failure) | Completed attempts of a bounded operation; each retry is a separate attempt. | Always; zero until the first attempt. | Process-local counter; resets to zero on restart; never reconstructed. |
| `konstapel_operation_duration_seconds` | histogram, seconds | `operation` (bundle_resolution, evidence_publication, evidence_cleanup)<br>`result` (success, failure) | Duration of completed attempts of a bounded operation. | Always; empty until the first attempt. | Process-local counter; resets to zero on restart; never reconstructed. |
| `konstapel_publication_pending` | gauge |  | Closed runs whose evidence package is not yet committed and is still being attempted. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_publication_failed` | gauge |  | Closed runs whose publication currently fails and needs action. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_pending` | gauge |  | Retained packages past expiry whose deletion is not yet confirmed. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_blocked` | gauge |  | Retained packages whose deletion is blocked and needs action. | Only while the domain's projection is fresh and ready; absent otherwise. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
| `konstapel_cleanup_oldest_expiry_timestamp_seconds` | gauge, seconds |  | Expiry of the oldest package with pending cleanup. | Only while cleanup is pending. | Gauge reflecting current owner state; reconstructed from owner state after restart. |
<!-- catalog:end -->
