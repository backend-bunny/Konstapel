# Design

## Context

Issue #362 reports all 292 missing observations attributable to unreported siblings.
internal/collector/policy_pass_fixture_test.go preserves the engine behavior:
unindexed all-pass is attributable, while indexed failures do not establish sibling
outcomes. Single-validation unindexed outcomes are already supported.

content/linux-hardening/variants/disallow-capabilities-strict.yaml and
restrict-seccomp-strict.yaml each have two validations. Existing variants include
Linux handling and exception inputs that must remain identical. Upstream originals,
sources.json, variants.json and component-definition.json track derivation.

## Goals / Non-Goals

**Goals:** explicit per-check producer evidence, equivalent security behavior,
versioned mappings and a documented safe transition between logical IDs.

**Non-Goals:** infer missing passes, reduce expected inventory, repair historical
freshness/UID gaps, rewrite old packages, enable native exceptions, or publish a
production version without separate authorization.

## Decisions

### 1. Four single-validation variants

Use descriptive new logical IDs:
- require-drop-all-capabilities: old capabilities validation 0.
- restrict-added-capabilities: old capabilities validation 1.
- restrict-pod-seccomp-profile: old seccomp validation 0.
- require-container-seccomp-profile: old seccomp validation 1.

Each retains the original variables, match constraints, operations, applicable
messages, Windows guard and its exact validation expression. Do not refactor CEL
while splitting. Each new validation has engine index 0, with its old identity
recorded in migration provenance. Keep the two unaffected hardening variants and
the privileged policy. The original bundle has five policies/seven validations;
the replacement has seven policies/seven validations, preserving the logical
check denominator for equivalent selected subjects.

Alternative producer-side fixes may be evaluated separately, but this plan does
not wait for engine changes or weaken the collector's attribution contract.

### 2. Content, mapping and compatibility ownership

Create new variants, update generated inventory/component/check mappings through
their owning build paths, and retain immutable upstream originals and licenses.
Record original source hash and local split derivation. Map each old validation
to its new policy/check identity and retain its bounded NIST rationale; multiple
checks still do not imply whole-control satisfaction.

Prepare a new independently versioned OCI bundle via existing tooling. Do not
overwrite linux-hardening 0.1.0 or mutate old pinned content. Update vendored
content and default examples coherently where they select this revision, while
preserving historical fixtures and frozen-content replay.

The active add-linux-workload-hardening-bundle describes the original families.
At implementation handoff reconcile its remaining tasks and wording with the
new revision, preserving initial-release evidence and upstream-blocked exception
requirements. This follow-up must not falsely mark that whole change complete.

### 3. Explicit staged migration avoids cross-ID retirement gaps

Current delivery readiness retention is keyed by logical policy identity; new
IDs are not automatically recognized as replacements for old IDs. Do not assume
a same-binding pin change keeps old enforcement.

Document and acceptance-test a staged migration: retain the old enforcing binding,
install a separate binding/profile selecting the new digest and replacement pairs,
wait for every new contribution to become EngineReady, verify mode/scope, then
retire the old binding. Preserve unrelated overlapping bindings and ownership.
For partially selected profiles provide a complete old-ID-to-pair mapping.
Unknown old IDs on a new pin must fail resolution rather than silently disappear.

This uses existing overlapping binding behavior instead of introducing a generic
cross-ID migration controller. Rollback retains/reinstates the old pin before
removing replacements; never patch generated engine policies. Upgrade overlap may
produce distinct old/new evidence; preserve per-contribution identities and do not
double-count control satisfaction.

### 4. Exception compatibility is explicit

Keep exception expressions and supported allowedValues/allowedImages semantics.
Because identities/revisions change, historical acceptances do not automatically
transfer. Copy central eligibility/lifetime settings deliberately to both new
policies where appropriate, maintaining Forbidden precedence. Explain that the
new checks can have narrower individual acceptance scope and that old whole-policy
waivers need explicit review under the current acceptance contract.

Do not claim transparent exception migration. Native grant cases remain blocked
when upstream prerequisites are missing; verify available contract/unit fixtures
and keep the live requirement explicitly tracked with its owner.

### 5. Real outcome matrix and export

For each pair exercise:
- both pass;
- validation 0 fails, validation 1 passes;
- validation 0 passes, validation 1 fails;
- both fail.

Construct valid seccomp combinations using container overrides to independently
exercise Pod and effective-container outcomes. Test on Pods and representative
supported templates, init containers and ephemeral updates; keep API-invalid
objects separate from policy denials. Use pre-existing or Audit-admitted subjects
for background reporting, since denied creates are not existing report subjects.

Verify exact selected-check denominator, workload UID, policy identity/index,
revision, raw/normalized outcomes and source evaluation time. Export a frozen
assessment through C2P and verify mapped independent outcomes. Retain regression
tests for truly absent reports, changed workloads and stale evidence; preserve the
old saved fixture rather than updating history to look complete.

### 6. Delivery and release evidence

CI exercises shipped rendered content through existing live acceptance groups,
plus source/checksum/OSCAL validation and signed bundle fixture verification.
Prepare publishable inputs and migration documentation; real version/tag
publication and post-publication digest verification are an operator release
follow-up, not permission implied by applying this change.

## Risks / Trade-offs

- More engine policy objects -> bounded increase from five to seven for a full
  bundle contribution; preserve ownership and report attribution.
- Cross-ID transitions -> staged overlap with explicit readiness before retirement.
- Exception waiver differences -> explicit reacceptance, no silent transfer.
- CI engine drift -> record exact supported pin and rerun matrix on upgrades.
- Existing incomplete captures -> preserve their honest historical interpretation.

## Migration Plan

Implement and validate new content and release inputs, publish only after separate
approval, then document verified new digest selection. Operators stage new bindings,
verify readiness/results and retire old bindings. Keep the previous digest and
historical capture readers available; never remove stored evidence on migration.
