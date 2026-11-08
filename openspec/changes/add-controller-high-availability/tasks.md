# Tasks

## Execution boundaries

Independent lifecycle/failure fixtures and the Helm owner's values/rendering
fixtures can start now. Runtime integration requires the merged targeting
manager. Admission, collector, S3, bundle and metrics cases require the relevant
owner's actual implementation; their planning artifacts are not prerequisites
satisfied. Rebase before changing shared manager registration or generated RBAC.

This change owns runtime lifecycle integration and cross-feature availability
acceptance. The Helm change owns chart templates, values, scheduling/PDB resources
and chart rendering tests; consume those outputs rather than implementing them
twice. Preserve existing feature APIs and the publication conformance suite.
Do not create another manager, shared filesystem, or placeholder service.

## 1. Establish lifecycle contracts and independent failure fixtures

- [x] 1.1 Add a lifecycle fixture matrix for startup, leadership, serving, termination and recovery boundaries; verify every availability requirement maps to an expected state or observable result and name the implementing feature owner.
- [ ] 1.2 Add fault fixtures around the existing publication contract for lost responses, same-run conflicting bytes and recovery from a separate client; verify matching operations retain identity/expiry and fixtures distinguish a shared fake store from real durable-backend acceptance.
  <!-- agent: tier=deep risk=high reason="Replica lifecycle, authorization, and durable recovery" -->
- [x] 1.3 Document the manager/Helm integration contract, defaults, dependencies and fixture commands; verify it names existing entry points/interfaces after their owners merge and marks unimplemented services unavailable.

## 2. Integrate election and background worker lifecycle

- [x] 2.1 Configure the merged manager with the shared namespace-local Lease, election enabled in both replica modes, namespace-scoped RBAC and validated 15s/10s/2s defaults; verify simultaneous candidates, stable identity across upgrades and denied Lease access without an election bypass.
- [x] 2.2 Classify/register background workers under synchronized leadership and keep required per-replica initialization independent; verify followers start no reconciliation and unsynchronized leaders cannot expose authoritative state or mutate managed resources.
- [x] 2.3 Propagate leadership cancellation through worker retries and owned C2P processes, retaining normal manager error/exit behavior and no early Lease release; verify leadership loss stops new work and terminates children within the configured bound.
- [x] 2.4 Exercise delayed former-leader Kubernetes writes/deletes against newer generations and ownership; verify optimistic conflicts trigger fresh resolution and stale attempts cannot overwrite protected state or withdraw a current/unmanaged contribution.
- [ ] 2.5 Integrate lifecycle transitions with the observability owner's projections when available; verify former-leader summaries clear, successors reconstruct before publishing, and document Lease inspection, permission failures and measured recovery limits.
  <!-- agent: tier=deep risk=medium reason="Leadership-aware observability projections" -->

## 3. Serve and authorize requests on every ready replica

- [ ] 3.1 Register implemented admission/download servers outside the elected worker group and wire startup/readiness/liveness to their local prerequisites; verify a ready follower serves requests, invalid TLS/unsynchronized state prevents readiness, and missing external capabilities fail only affected operations.
  <!-- agent: tier=deep risk=high reason="Replica lifecycle, authorization, and durable recovery" -->
- [ ] 3.2 Exercise protected admission against each replica during central edits, renewal and leadership changes; verify authoritative scope/revision checks, authenticated attribution and dry-run behavior remain intact and no grant is broadened or renewed by failover.
  <!-- agent: tier=deep risk=high reason="Replica lifecycle, authorization, and durable recovery" -->
- [x] 3.3 Integrate follower downloads with durable request/run lookup and the S3 owner; verify identical package digests after the producing pod is removed, current authorization on retry, namespace-UID isolation and explicit expiry/backend errors without leader-local files.
- [x] 3.4 Exercise certificate/credential rotation and authorization revocation on both serving pods; verify each uses current trust/access rules, records no secret values and does not depend on session affinity or a leader proxy.
- [x] 3.5 Document serving versus leadership readiness and client retry behavior; verify the Helm owner can select/probe all ready replicas and the documented service requests work through a known follower.

## 4. Recover state and drain bounded work

- [x] 4.1 Integrate recovery of durable runs and staging on leadership acquisition; verify one-active-run coordination, deterministic triggers and same-byte recovery using the real S3 backend, with uncertain backend access kept distinct from CaptureLost.
- [x] 4.2 Inject loss before staging and after commit but before the Kubernetes receipt; verify diagnostic CaptureLost/new-run identity in the former case and original package/expiry recovery in the latter, without duplicate publication or lost retention obligations.
- [x] 4.3 Reconstruct local bundle/observation state after pod loss using the owners' contracts; verify current trust revalidation, explicit cold-cache outages, retained applied policies and incomplete evidence when watch continuity cannot be established.
- [x] 4.4 Implement the 45s application/20s HTTP drain defaults within 60s pod grace, cancellation and owned-child cleanup with validated overrides; verify a long download or provider call cannot hold termination indefinitely and interrupted work remains recoverable or explicitly lost.
- [x] 4.5 Document per-pod storage/concurrency budgets, shutdown, CaptureLost, backend-response loss and retention recovery; verify the failure walkthrough preserves committed artifacts and cleans only owned incomplete attempts.

## 5. Verify chart defaults and integrated availability

- [x] 5.1 Consume the Helm owner's merged availability values and render tests; verify default two replicas, explicit development one, preferred hostname separation, default multi-replica minAvailable 1 PDB, development PDB omission and zero-unavailable/one-surge rolling updates without duplicating chart ownership.
- [x] 5.2 Extend the shared chart acceptance harness with a pinned multi-node cluster, real packaged image and test-owned S3 backend; verify both pods become ready, record their placement/Lease holder, and prove admission/download requests reach the follower when those features are enabled.
- [ ] 5.3 Exercise abrupt leader failure, graceful leader/follower replacement and node loss under traffic; verify bounded cancellation/recovery, retained policy/acceptance identities, same-run publication recovery and truthful metrics/evidence rather than inferring correctness from Lease ownership.
  <!-- agent: tier=deep risk=high reason="Replica lifecycle, authorization, and durable recovery" -->
- [x] 5.4 Exercise a supported rolling image upgrade and sequential voluntary evictions; verify replacement readiness before normal rollout retirement, PDB rejection of an availability-breaking eviction and explicit pending rollout when surge capacity is constrained.
- [x] 5.5 Run single-node preferred-placement and single-replica development cases; verify both replicas can co-locate when capacity permits, development permits drain, and documentation does not claim node redundancy or redundant single-replica service.
- [ ] 5.6 Exercise leader API loss, registry/backend outages, trust rotation and authorization revocation during handover; verify fail-closed affected operations, stable retained enforcement/expiry, no stale healthy summaries and recovery without fabricated evidence.
  <!-- agent: tier=deep risk=high reason="Replica lifecycle, authorization, and durable recovery" -->
- [ ] 5.7 Record the supported version matrix, observed recovery/traffic results and operational runbook, then run the applicable existing checks; verify release acceptance covers every advertised enabled feature and tear down task-owned clusters, releases, objects and processes while retaining diagnostics.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 5.8 Interrupt the Helm-installed multi-replica controller at durable publication boundaries with test-owned S3 fault injection (a controller defect found this way is fixed with unit tests; the first-schedule adoption fix is the one so far); verify that after the Lease holder's pod is removed the other replica commits a run staged but not committed with the same identity and exact staged bytes under the binding's retention at commit, records a run committed but not receipted with its original commit and expiry despite a later retention change, commits nothing twice, and keeps the run Publishing (never CaptureLost) while S3 is held or unreachable.
  <!-- agent: tier=deep risk=high reason="Distributed recovery and immutable publication" -->
