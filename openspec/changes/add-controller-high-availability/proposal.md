# Proposal

## Why

Konstapel's planned controller must tolerate pod replacement and maintenance
without making its admission and evidence services depend on one elected pod.
The existing feature contracts cover pieces of recovery; they need one tested
availability contract before the default two-replica installation can ship.

## What Changes

- Default the controller to two replicas, with an explicit single-replica
  development configuration and preferred separation across Kubernetes nodes.
- Keep at least one replica available during voluntary disruption in the default
  installation; use rolling updates with zero unavailable replicas and one surge
  replica, allowing three pods temporarily. Disable the default disruption
  budget for single-replica development.
- Use the existing controller-runtime manager and Kubernetes Lease election for
  background reconciliation, while every ready replica serves implemented
  admission and authenticated download endpoints.
- Define synchronized startup, leadership loss, bounded shutdown, and recovery
  using the existing policy ownership, assessment identities, and immutable
  publication contracts. Leadership alone is not a write-fencing mechanism.
- Keep replica-local caches and working files recoverable or explicitly lost;
  preserve durable acceptances, staged evidence, receipts, and retention work.
- Verify leader failure, rolling replacement, voluntary eviction, dependency
  outages, and single-node placement without bypassing authorization or claiming
  continuous evidence when observation continuity was lost.
- Align the active Helm distribution plan with these defaults and release gates.

## Capabilities

### New Capabilities

- `controller-availability`: Coordinate controller replicas, serving readiness,
  leadership transitions, and maintenance with traceable recovery.

### Modified Capabilities

None. The existing `kyverno-assessment-loop` prototype remains supported. This
change integrates the contracts owned by the active targeting, assessment,
exception, storage, bundle, observability, and Helm changes.

## Impact

Extends the targeting-owned manager once merged; adds lifecycle integration,
failure fixtures, and operational documentation. The Helm change remains the
owner of chart templates and their scheduling/disruption values. Feature owners
retain their APIs, protected admission, evidence semantics, and storage protocols.

No new CRDs, controller framework, shared-filesystem requirement, remote-cluster
management, concurrent independent cluster-wide installations, or horizontal
sharding are introduced. Full acceptance requires the actual enabled feature
implementations; planning artifacts and fake publishers do not establish runtime
availability.
