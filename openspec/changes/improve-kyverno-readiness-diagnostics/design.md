# Design

## Context

Issue #358 reports Konstapel 0.3.0 with Kyverno 1.19.2/chart 3.9.2.
internal/targeting/deliver.go reads RBACPermissionsGranted and WebhookConfigured
as booleans. DeliveryResult.NotReady holds names; binding.go emits only those
names in ReplacementPending. The actionable source condition is discarded.

scripts/environment.sh installs the upstream ephemeral-rbac.yaml fixture before
tests. It grants admission get/list/watch/update and reports get/list/watch on
pods/ephemeralcontainers using Kyverno aggregation labels. This establishes what
the existing fixture grants, not that every verb is minimal for every mode.

## Goals / Non-Goals

**Goals:** surface actionable prerequisites at the binding, publish a reproducible
operator procedure, and prove absence-to-repair recovery against the real engine.

**Non-Goals:** install Kyverno, alter another operator's RBAC automatically,
change readiness semantics, bypass permissions, or fix missing sibling outcomes.

## Decisions

### 1. Preserve readiness and enrich the existing diagnostic path

Keep KyvernoReady semantics and existing EngineReady reason vocabulary.
Add bounded typed readiness detail to DeliveryResult for owned desired policies.
The controller formats the actionable condition before long policy-name lists.
Retain existing Pending/retained-policy behavior and no readiness-as-compliance
claims. Do not copy entire policy objects or status blobs into binding status.

Sort by policy and condition, deduplicate equivalent failures and apply per-field
and total budgets. Preserve policy attribution, condition type, reason/message and
an omitted-count plus kubectl inspection guidance when truncated. Sanitize control
characters; malformed/missing status gets a clear unknown fallback. Only expected
readiness conditions are inspected. Keep messages out of metric labels.

Alternative: require operators to inspect all policies. That reproduces the issue.
New CRDs/status inventories are unnecessary for this bounded diagnostic.

### 2. Operator-applied, least-privilege example

Add a maintained example under the existing examples layout, not a .chainsaw-test
path. Use Kyverno aggregation labels, separate roles for admission and reporting,
and no wildcards or grant to Konstapel's service account. Document how to inspect
the installed chart's aggregation selectors and actual service-account names.

Use the current upstream manifest as the starting point. Verify each verb against
the pinned engine, including its readiness checks and actual admission/reporting
operations: remove grants individually in the disposable fixture and retain the
observed reason for those required. In particular do not infer that update is
needed merely because it appears upstream, or that Audit needs no permissions.
Record the tested mode/operation matrix and explain API subresource requirements.

Link the example from docs/charts.md, docs/policy-bundles.md and the bundle Audit
walkthrough. Include inspect/apply/auth-can-i/observe-recovery commands and what
still-incomplete evidence means after readiness returns. Do not promise this
example matches all future Kyverno versions without verification.

### 3. Acceptance must expose the prerequisite

Add a focused case that creates a disposable installation without automatically
applying ephemeral grants. Do not let scripts/environment.sh hide the missing
permission. Exercise Audit reporting and Deny admission as appropriate; assert the
reported source condition is visible through the binding before repair.

Apply the documented example, wait for RBAC aggregation and normal reconciliation,
verify policy readiness and attributable reports without controller restart.
Retain policy UIDs and check retained revision behavior. Verify removing/readding
a tested prerequisite is visible where the pinned engine supports reevaluation.
Keep helpers private behind existing acceptance groups; CI runs the same workflow.

### 4. Bounded readiness recheck of owned policies

The verified matrix (2.1) found that Kyverno 1.19.2 computes
RBACPermissionsGranted only when a policy is created or updated, so a repaired
grant is never noticed by an unchanged policy. Owner decision (2026-11-27):
Konstapel may nudge its own pending policies with a dedicated metadata
annotation, after live proof that this makes Kyverno re-evaluate.

Delivery writes compliance.erenius.io/readiness-recheck ("attempt@time") only
on current, owned policies at the desired revision whose readiness details
report RBACPermissionsGranted False or Unknown. The write is a metadata-only
merge patch conditional on the resourceVersion read; a conflict re-reads and
re-decides, a bounded number of times. Backoff: 30s after creation, then
doubling to a 15-minute cap; nothing is written once the policy is ready.
The spec, revision, epoch, ownership and other metadata are never changed,
and Konstapel still never changes RBAC. Removing a grant from a ready policy
stays unnoticed until the engine re-evaluates for another reason.

Alternatives: restarting Kyverno (another operator's workload) or touching the
spec (changes rendered identity) were rejected; doing nothing leaves bindings
pending indefinitely after a correct repair.

## Risks / Trade-offs

- Large engine messages -> bounded sanitized summaries with inspection fallback.
- Version-specific readiness checks -> pinned live matrix, no inferred privileges.
- Shared fixture pollution -> dedicated test installation and owned-role cleanup.
- Recovery may reveal unrelated evidence gaps -> assert permission recovery
  separately from complete compliance and sibling-policy behavior.

## Migration Plan

Ship additive diagnostic improvements and documentation; no operator permissions
change until the administrator applies the example. Existing bundles and policy
identities remain unchanged. Documentation-only rollback does not remove grants;
operators manage removal according to their installed Kyverno needs.
