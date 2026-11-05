# Tasks

## Execution boundaries

The assessment-loop Go implementation is already on main; preserve its supported
commands and capture format. Targeting and exception runtime contracts still
require their merged implementations. Pure scheduling/correlation fixtures and
package-contract work can start now. Rebase before API registration or shared
`internal/assessment` edits, coordinating with the Linux bundle implementation.

This change owns assessment APIs/generated files, binding assessment fields,
enforcement-identity integration, scoped collection/export, and the shared
publication interface. Group 1 is a separately mergeable contract phase. The S3
agent consumes it and can merge backend work before the scheduler is complete.
Final integration requires both changes; neither agent should wait for the other
change's entire task list before landing the shared contract or adapter.

## 1. Establish the shared request, run, and package contract

- [x] 1.1 Add versioned package descriptors and publication interfaces/status types for scope, checksums, staging, commit receipts, retention, availability, and cleanup; verify serialization fixtures round-trip without bulk reports or credentials in status.
- [x] 1.2 Add namespaced AssessmentRequest and protected cluster-scoped AssessmentRun types/CRDs after coordinating API registration with targeting; verify API-server validation enforces immutable requests, controller-owned resolved fields, and namespace versus full-binding scope.
- [x] 1.3 Add request/run RBAC and authenticated requester attribution, including controller-only status updates; verify team roles cannot create full-binding runs, forge requester identity, or read another namespace's request.
- [x] 1.4 Add a fake publisher and scoped complete/incomplete/diagnostic package fixtures; verify idempotent run/publication identities and separate completeness, result, and publication states without a real backend.
- [x] 1.5 Document the contract and its ownership, scope-projection rules, download authorization attributes, and initial integration sequence; verify the S3 implementation can consume the fixtures/interfaces without editing these APIs or depending on a finished scheduler.

## 2. Add binding settings without changing enforcement on reporting edits

- [x] 2.1 Add the four defaulted positive duration settings and validation; verify omitted settings and explicit nulls resolve to 24h/2h/5m/2160h, and cron syntax, zero, negative, and overflowing values are rejected.
- [x] 2.2 Implement the protected admission-maintained enforcement epoch and integrate it with targeting revision calculation; verify reporting-only edits retain policy identities, forged epochs fail, and A-to-B-to-A enforcement changes create new identities even across missed watch events.
- [x] 2.3 Update exception contribution comparison to use enforcement identity while retaining observed generation as provenance; verify interval, timeout, freshness, and retention edits leave valid grants intact and actual enforcement changes still require renewed acceptance. Contribution and eligibility revisions are verified here; the grant runtime that compares accepted revisions is implemented in `add-self-service-policy-exceptions` task 4.3.
- [x] 2.4 Add migration from existing applied revisions without rotating unchanged policies; verify restarts and initialization retries preserve policy identity and cannot reactivate an old exception.
- [x] 2.5 Document defaults, duration syntax, epoch migration, and controller compatibility; verify configuration examples validate and the documented reporting-only update preserves enforcement in the disposable cluster.

## 3. Reconcile current state and durable run scheduling

- [ ] 3.1 Implement persisted schedule anchors/due times and deterministic scheduled-run identities with a fake clock; verify independent intervals, initial runs, interval edits, and manual requests that do not reset cadence.
- [ ] 3.2 Add one-active-run-per-binding coordination, leader recovery, bounded workers/queues, and deterministic request ordering; verify concurrent reconciles cannot duplicate a trigger and an overdue scheduled run is not starved by manual requests.
- [ ] 3.3 Implement missed-interval coalescing and restart recovery; verify downtime records a gap and produces one current run without fabricated historical evaluations or an unbounded backlog.
- [ ] 3.4 Add workload/namespace/policy/report/exception watches and age-expiry reconciliation for current status; verify a 2h-old result becomes stale before a 24h snapshot tick and zero targets does not establish a pass.
- [ ] 3.5 Implement bounded collection/export/publication execution and failure release of active slots; verify unready policies, plugin hangs, and publisher outages produce explicit limitations/failures without blocking the binding forever.
- [ ] 3.6 Document scheduling, request quotas, pending/failed runs, and recovery; verify a fake-clock and disposable-cluster walkthrough reproduces cadence, gap, and concurrency behavior.

## 4. Correlate changing resources with expected evidence

- [x] 4.1 Add a versioned controller capture format and independent multi-policy/check inventory preserving the prototype v1 path; verify identities distinguish contributions, sub-validations, resource state, namespace UIDs, and source/mapping revisions.
- [x] 4.2 Capture initial scope and track workload/namespace/configuration changes during collection; verify removed/replaced/updated subjects remain visible as changed evidence and newly matching namespaces do not silently broaden the snapshot.
- [ ] 4.3 Investigate and exercise the pinned engine's evaluation-to-resource-state correlation using live in-place workload updates; retain results and verify unsupported or ambiguous correlation remains unknown rather than treating timestamp recency as proof.
- [x] 4.4 Implement per-observation freshness checks and conservative continuity boundaries, including watch gaps/restarts; verify old-state results, missing/future timestamps, age-at-closure expiry, and unproven history cannot produce current passing evidence.
- [ ] 4.5 Generalize source/render verification through the merged targeting/content contract; verify changed policy expressions or digests cannot be legitimized by a recomputed capture hash and the original prototype provenance regressions still pass.
- [ ] 4.6 Document capture revisions, supported correlation, scope windows, and remaining engine limits; verify saved fixtures reproduce the documented incomplete and attributable cases without a live cluster.

## 5. Produce scoped snapshots and handle incomplete evidence

- [ ] 5.1 Implement namespace evidence projection before export, including mixed report scopes, result messages, diagnostics, embedded resources, and links; verify sibling data and unsafe opaque content are excluded while source-result/digest provenance is retained.
- [ ] 5.2 Produce schema-valid incomplete OSCAL and clearly typed diagnostic packages when valid export is impossible; verify missing/malformed evidence and zero-target cases never fabricate a pass or a successful OSCAL export.
- [ ] 5.3 Integrate exception snapshots, applicability, and independent check outcomes through final OSCAL export; verify accepted risk, failures, and repeated binding contributions do not inflate passing/control coverage.
- [ ] 5.4 Freeze package bytes/digests and implement recoverable staging plus explicit CaptureLost handling; verify retry preserves the same snapshot and a restart without recoverable data cannot substitute newer observations under its identity.
- [ ] 5.5 Connect request status to sanitized summaries and opaque artifact references; verify team-visible status exposes no full-binding inventory, credentials, or sibling errors and request deletion does not remove retained publication records.
- [ ] 5.6 Document scheduled/on-demand workflows, incomplete versus diagnostic results, and namespace download handoff; verify the published examples use only the intended namespace or platform permissions.

## 6. Verify integrated continuous assessment

- [ ] 6.1 With the S3 adapter merged, run scheduled and team-requested assessments for two namespaces and overlapping bindings; verify current status, immutable scope, publication, authorized package contents, and validated OSCAL together.
- [ ] 6.2 Exercise controller/engine restarts, watch discontinuity, workload mutation, missing evidence, and interrupted publication end to end; verify bounded failures, recorded gaps, honest freshness, and no duplicate or silently rewritten snapshots.
- [ ] 6.3 Run the existing prototype regressions plus the documented controller workflow and retention handoff; retain versioned evidence and verify all task-owned clusters, services, objects, and processes are removed after the tests.
