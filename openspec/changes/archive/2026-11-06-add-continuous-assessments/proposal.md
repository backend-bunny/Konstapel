# Proposal

## Why

The shipped assessment loop proves a controlled, single-policy run. Operators
and application teams need continuing evidence for changing workloads, with
scheduled snapshots and on-demand assessments whose scope and freshness are clear.

## What Changes

- Add per-ComplianceBinding assessment settings: `interval` defaults to `24h`,
  `maxEvidenceAge` to `2h`, `collectionTimeout` to `5m`, and `retention` to
  `2160h` (90 days). Retention execution belongs to the S3 publishing change.
- Reconcile current assessment status independently of snapshot cadence and
  policy enforcement; reporting-only edits must not rotate engine policies or
  invalidate accepted exceptions.
- Add durable run records, interval scheduling, one active run per binding,
  recovery with one current run and recorded missed intervals, and bounded waits.
- Publish each materialized run's snapshot even when evidence is incomplete;
  distinguish collection completeness, check outcomes, and publication failures.
- Support namespaced application-team requests and platform full-binding runs,
  with independently scoped inventory, evidence packages, and authorization.
- Correlate observations to workload state and policy revisions, preserving raw
  outcomes, accepted risk, evaluation times, and unsupported or missing evidence.
- Define the shared package/publication contract consumed by S3 publishing.

## Capabilities

### New Capabilities

- `continuous-assessments`: Maintain current assessment state and create scoped,
  scheduled or requested snapshots with explicit evidence completeness.

### Modified Capabilities

None. The existing `kyverno-assessment-loop` remains the supported prototype
workflow. The new controller capability extends its capture/export boundaries
without changing that workflow's acceptance contract.

## Impact

Extends the targeting API after its implementation lands; adds assessment request
and run APIs, scheduler/controller logic, scoped capture/export support, tests,
and documentation. Reuses the Go module, provider protocol, and provenance checks
already shipped in `internal/assessment`, while removing single-policy and
quiescent-run assumptions from the new controller path.

This change owns all assessment API/generated files and the shared publication
contract. Land that contract as an initial implementation PR so
`add-s3-evidence-publishing` can implement the backend in parallel with scheduler
and collector work. Full acceptance requires the S3 backend plus merged targeting
and exception contracts. No remote-cluster management, cron expressions, policy
remediation, or fabricated historical backfill is introduced.
