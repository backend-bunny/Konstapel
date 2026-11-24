# Design

## Context

See [proposal.md](proposal.md) and the
[availability requirements](specs/controller-availability/spec.md). At `15fb990`,
the repository has the prototype CLI/provider, profile/binding resolution and
delivery, assessment APIs, and `internal/publication` with a fake backend and
conformance tests. The production manager, charts, protected exception admission,
continuous collector, and S3 transport are still owned by active changes.

The assessment design already requires Lease election, optimistic updates,
deterministic triggers, and one active run per binding. `Publisher.Stage` promises
durable frozen bytes; `Recover` and `ErrCaptureLost` distinguish recoverable
staging from lost capture. Observability exposes authoritative summaries only on
the synchronized leader. The Helm plan supports one cluster-wide installation
and preserves CRDs independently of controller lifecycle. These remain the
authoritative boundaries.

## Goals / Non-Goals

**Goals:** Establish a shared replica lifecycle, separate serving from background
leadership, and test recovery and maintenance against the real packaged runtime.
Make the agreed two-replica defaults safe to advertise.

**Non-Goals:** A second manager, new API schemas, distributed transactions,
sharding, autoscaling, multiple competing installations, remote-cluster control,
shared persistent volumes, or a new assessment/storage protocol. This does not
promise survival of every unstaged capture, uninterrupted individual HTTP
connections, or availability of the Kubernetes API, Kyverno, S3, or registry.

## Decisions

### 1. Integrate through the existing implementation owners

| Owner | Contract consumed by availability work |
| --- | --- |
| `add-compliance-targeting-api` | Manager, policy identity/ownership, resolution and delivery status |
| `add-continuous-assessments` | Run coordination, frozen capture, recovery and publication interface |
| `add-self-service-policy-exceptions` | Protected admission, immutable acceptance, native governance and expiry gate |
| `add-s3-evidence-publishing` | Durable staging/commit/recovery, downloads, credentials and retention |
| `add-policy-bundle-distribution` | Verified cache handles, current trust and last-applied preservation |
| `add-prometheus-observability` | Process metrics, leader-only projections and transition alerts |
| `add-helm-oci-distribution` | Deployment, Services, TLS, scheduling, probes and release acceptance |

This change owns lifecycle integration in the merged manager and cross-feature
failure tests/runbooks. The Helm owner implements chart templates and rendering
fixtures using this contract. Land a small manager lifecycle integration before
feature wiring; do not bootstrap another entry point while the targeting manager
is in flight. Add admission/download integration only when those handlers exist.
Mark unavailable features as such instead of using stubs to pass release tests.

This division preserves independently implementable chart fixtures and existing
feature work. A single replacement change owning every controller would duplicate
the contracts and create unnecessary merge conflicts.

### 2. Use one stable Lease with standard controller-runtime behavior

Keep election enabled for both production and development. Use a namespace-local
`coordination.k8s.io/v1` Lease named `konstapel-controller-leader-election` in the
controller namespace, shared by every pod and supported old/new runtime revision
of the installation. The Lease name must not include a pod name, image digest,
or chart version; each candidate process uses its own unique holder identity.
Scope Lease RBAC to that namespace and required operations: the pinned
client-go LeaseLock only gets, creates and updates the Lease (acquisition,
renewal, takeover after expiry and release are get+update), so the Role grants
`get`/`update` on that Lease by name and `create`, which the API server cannot
restrict by name, plus Event `create`/`patch` for the election's recorder.
Nothing lists, watches, patches or deletes Leases. Acceptance runs creation,
renewal under contention, takeover and restart under exactly these grants. A second
cluster-wide installation remains unsupported even in a different namespace;
separate Lease namespaces would not partition cluster-scoped resource ownership.

Use the pinned manager's conventional defaults: 15s lease duration, 10s renewal
deadline, and 2s retry period. Allow documented deployment overrides with positive
durations and the upstream ordering/jitter constraints validated before startup.
Do not silently disable election on a permission or connectivity failure. Keep
`LeaderElectionReleaseOnCancel` false initially: early voluntary release requires
proof that all mutating work has ended. Automatic expiry provides a bounded wait
without releasing the Lease while shutdown is still draining work.

The leader starts background targeting, exception delivery, assessments,
publication and retention workers only after their required caches/state are
synchronized. Followers keep the watches and local initialization needed to serve
and take over, but do not run those workers. Current bundle/source configuration
loading, TLS reload and serving authentication remain available on each replica;
leader-only adoption/status changes must stay distinct from local preparation.

Retain the manager's normal leadership-loss error/process restart behavior.
Cancel the leader context immediately on loss, stop new queue work, terminate
owned C2P child processes, clear authoritative metric projections, and exit within
the shutdown bound. Do not invent a second election loop or have the old process
continue background retries as an unelected follower.

Election timings are not a hard recovery SLA: cache sync, API latency, startup,
and dependencies affect takeover. Record measured election and useful-work
recovery separately in acceptance evidence.

### 3. Preserve mutation safety across overlapping attempts

The pinned client-go explicitly states that Lease election does not provide
fencing. A paused process or an in-flight request can outlive its leadership.
Context cancellation and process exit limit that window but do not replace the
feature owners' concurrency protections.

Use resourceVersion comparisons and UID/generation/ownership checks for protected
Kubernetes updates, including delete preconditions where needed. Re-resolve
current desired state after a conflict instead of retrying a stale object or
deletion decision. Validate native exception operations through the existing
acceptance/governance boundary. Preserve deterministic trigger/run names and
one-active-run claims; only matching frozen bytes can share a run identity.

Use the publication interface's durable staging and conditional immutable commit
for storage. After an uncertain result, inspect/recover before preparing another
attempt. An old request completing an already authorized matching commit is
reconciled as that original commit; it is not a second snapshot. Different bytes
under the same identity remain a conflict. Retention cleanup retains the recorded
destination, expiry and owned keys across leaders.

Inject delayed former-leader completions after newer Kubernetes revisions and
storage commits in tests. No test should infer exactly-once side effects solely
from the observed Lease holder. If an owner lacks a required mutation guard, fix
that integration with the owner before enabling its replicated execution.

### 4. Serve on every ready replica without a leader proxy

Admission and download servers are manager runnables that do not require
leadership. Each pod runs its own TLS reload, handler registration and required
state synchronization. Service selectors include all ready release pods, without
a leader label or session affinity. Leader-only endpoints would make the standby
irrelevant during elections and complicate routing.

Serving readiness requires usable TLS, registered enabled handlers and usable
local dependencies such as synchronized Kubernetes state. Liveness measures
process operation, not external engine/storage health or election success. A
startup probe allows initialization before liveness applies. Readiness does not
require leadership, completed assessments, a populated bundle cache or global
Kyverno readiness. Missing external capabilities remain operation-specific
failures under their owners' contracts; invalid local serving state is unready.

Every replica applies the same protected admission rules, request identity and
dry-run handling. Authorization-sensitive decisions use the feature's required
authoritative reads/version checks; an old informer view cannot grant a revoked
permission or fabricate current acceptance. Bindings or trust configurations
changing between replica reads must be tested. No admission handler forwards a
request to the leader or relies on that pod's in-memory acceptance set.

Downloads authenticate and authorize each new request, resolve request/run and
namespace UIDs, and retrieve the durable published package directly through the
backend contract. Bounded local download staging is disposable. Verify checksums
before serving, retain private response semantics and apply credential rotation
on every replica. New requests after revocation are denied regardless of which
pod receives them. No sticky routing, local-only artifact URL, or authorization
bypass is introduced.

### 5. Keep working data local and durable state in its existing stores

Use per-pod bounded writable storage for verified bundle caches, capture/export,
provider work and download buffers. Cache limits and concurrency remain owned by
the relevant feature; document which limits are per pod because two serving pods
multiply potential resource use. Do not add an RWX volume or share mutable cache
directories to make failover work.

Kubernetes stores protected acceptance snapshots, run identities and receipts;
the publisher provides durable staging and committed packages in S3. A successor
recovers these independently of the previous pod's filesystem. A `Stage` success
must be observable through `Recover` from another replica; a process-local fake
publisher is insufficient evidence for that guarantee.

Before durable staging, loss of frozen capture can produce `CaptureLost` as the
existing assessment contract permits. Retain the diagnostic run; any subsequent
assessment receives a new identity. Do not reinterpret a temporary backend outage
as proof that bytes are lost, or overwrite evidence while recovering from a lost
response. Retained publication/cleanup metadata survives binding/request deletion.

After lost watch continuity, rebuild current inventory and require attributable
new evidence under the existing collection deadline. Relisting does not restore
historical observations. Bundle cache misses retain last-applied owned policies
and report unavailability; cached content must still satisfy current trust. This
accepts an explicit evidence gap while preserving honest history.

### 6. Apply the agreed scheduling and maintenance defaults in Helm

The Helm owner renders the following values and documents safe overrides:

| Setting | Default |
| --- | --- |
| `replicaCount` | 2; development explicitly sets 1 |
| Node separation | Preferred pod anti-affinity, weight 100, `kubernetes.io/hostname` |
| PodDisruptionBudget | Enabled when replicas exceed 1, `minAvailable: 1`; omitted by default for 1 |
| Deployment rolling update | `maxUnavailable: 0`, `maxSurge: 1` |
| Pod termination grace | 60s |

Use the same stable release-scoped pod labels across revisions for Deployment,
Service, PDB and anti-affinity matching, scoped to the installation namespace.
Do not include a pod-template hash in selectors. Permit operator scheduling and
budget overrides without silently strengthening the default node preference.
Reject invalid replica counts, timing values and incompatible budget options in
the values schema. Keep the development example explicit and tested.

Two replicas can share one suitable node; that is process redundancy, not node
redundancy. Test a multi-node cluster for actual placement and node-loss recovery,
and a constrained single-node case for absence of a required anti-affinity rule.
A PDB governs voluntary eviction, not crashes, direct pod deletion, scale-down,
or Deployment rollout. The rolling strategy supplies rollout protection. With
two replicas it allows a third non-terminating pod; Kubernetes can temporarily
retain additional terminating pods, so this is not a strict total pod quota.
Insufficient capacity for the surge leaves the rollout pending.

### 7. Bound shutdown and make retries the recovery path

Use a 45s overall application shutdown budget within the 60s pod grace period.
On SIGTERM or manager failure, mark serving readiness false, stop new background
work and cancel its context, then drain already accepted HTTP requests for at
most 20s within that total budget. Bound provider subprocess termination and
force cleanup of owned children before exit. Expose validated overrides while
retaining headroom before Kubernetes forces termination. Avoid shell-based
preStop hooks because the shipped image has no shell.

Do not hold termination open for the normal five-minute collection timeout or
for all S3 retries. Record recoverable intent where possible; existing durable
recovery handles abrupt death before the final status write. Canceled local work
must not delete a committed package or another attempt's staging. A long download
can be interrupted and retried in full through its original route with fresh
authorization; no resumable/range-download contract is added here.

Endpoint removal and connection draining are asynchronous. Test traffic against
the Service during replacement, and record bounded transient transport failures
and retry recovery rather than asserting zero interrupted TCP connections.
Supported rolling version pairs share the Lease, schemas and storage contracts
from the Helm upgrade matrix. A version-incompatible pair cannot be made safe by
increasing its replica count.

### 8. Prove the integrated failure boundaries before release

Extend the Helm owner's disposable-cluster acceptance harness, using its exact
packaged image and real enabled features. Run a default two-replica deployment
on at least two schedulable nodes. Pin and record Kubernetes, Kyverno, Helm,
certificate and S3-compatible backend versions. Keep the exception expiry gate:
Konstapel replica redundancy does not fix the known native-engine expiry issue.

Cover simultaneous startup, abrupt leader kill, graceful follower/leader
replacement, voluntary eviction, a rolling image change, and a node failure.
Record pod placement, Lease transitions, ready endpoints, request success/error
times, policy identities, run/commit IDs, expiry and resulting status. Verify
admission/download traffic reaches each pod through test-only routing or pod
attribution, including on the non-leader; a load-balanced request to an unknown
pod does not establish follower-serving behavior.

Exercise failures before staging, after staging, after S3 commit and before its
Kubernetes receipt. Include delayed old attempts, API loss for the leader,
backend/registry unavailability, credential/certificate rotation and authorization
revocation during handover. Preserve enforcement resources, reject unauthorized
operations, retain explicit evidence gaps and clear stale metric projections.
Run the single-replica development and one-node scheduling cases separately.

Use meaningful failure/integration tests through existing Devbox/Task workflows;
do not add a public task for each fault helper. Retain a versioned result summary
and diagnostics, and delete only task-owned releases, clusters and storage data.
Publication of enabled features requires their actual integration cases to pass.

## Risks / Trade-offs

- **Lease election is not fencing:** combine cancellation with optimistic API
  transitions and immutable storage commits, and test delayed old operations.
- **Preferred separation can co-locate replicas:** document the boundary and
  measure placement; capacity and stricter topology remain operator decisions.
- **Per-pod files can be lost:** use durable staging/receipts for recovery and
  preserve explicit CaptureLost outcomes before that boundary.
- **Services can observe different cached revisions:** preserve authoritative
  authorization checks and fail affected operations when state is uncertain.
- **Graceful shutdown cannot preserve every connection:** bound draining and
  verify retries retain authorization and package identity.
- **Several changes share manager integration:** consume merged owners first,
  separate lifecycle and feature wiring, and avoid duplicate chart work.

## Migration Plan

Land lifecycle registration/coordination after the targeting manager, then wire
implemented endpoints and recovery producers. The Helm owner adds the agreed
values and runs chart fixtures while the availability owner extends integrated
fault acceptance. Enable and advertise two-replica support only after the real
runtime passes the applicable release matrix.

For an existing single-replica installation, keep its Lease, CRDs, UIDs and
publication destinations while increasing replicas. Test rollout of a compatible
image without deleting retained data. Operational rollback can restore a tested
controller version or explicitly scale to one, accepting reduced service
availability; it must not disable election, authentication, or retention recovery.
