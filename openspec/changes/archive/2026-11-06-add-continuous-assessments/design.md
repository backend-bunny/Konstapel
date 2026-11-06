# Design

## Context

See [proposal.md](proposal.md) and the
[capability spec](specs/continuous-assessments/spec.md). The assessment prototype
is implemented and archived. `internal/assessment/reports.go` accepts one named
policy, uses a run-wide evaluation boundary, and keys results primarily by
resource identity. `live.go` captures reports across the cluster and rechecks
resource UIDs. `export.go` packages local evidence and validates its provenance.
These are useful foundations, but UID continuity alone does not identify the
state of a workload that changed in place.

The targeting and exception changes are still implementation prerequisites.
They introduce the manager, policy contributions, central eligibility, and
accepted-risk context. This design extends those contracts after they land.

## Goals / Non-Goals

**Goals:** Keep current evidence status separate from immutable historical
snapshots, bound collection and concurrency, and provide namespace self-service
without leaking a broader binding's evidence.

**Non-Goals:** Cron/time-zone scheduling, historical replay of missed states,
remote-cluster operation, workload remediation, or treating an assessment request
as a request to reconfigure Kyverno's background scanner.

## Decisions

### 1. Extend the binding with ordinary duration settings

Add `spec.assessment` with `interval: 24h`, `maxEvidenceAge: 2h`,
`collectionTimeout: 5m`, and `retention: 2160h` as defaulted duration strings.
Use the Kubernetes duration convention: 90 days is expressed as 2160 hours,
without inventing a `d` suffix. Reject invalid, nonpositive, or overflowing values;
omission defaults. An explicit null also defaults: the API server prunes it before
validation and CEL cannot distinguish null from omission, so no null is stored.
The settings are independent:
a short interval does not require Kyverno to reevaluate unchanged resources at
that cadence. Document combinations that repeatedly yield stale evidence.

The starting Kyverno chart scans in the background hourly, motivating the two-hour
age default. This is an allowance, not a guarantee that every source evaluation
timestamp advances hourly. Preserve actual evaluation times and verify behavior
on the installed engine. The publisher consumes retention at publication.

An interval is simpler than creating Kubernetes CronJobs for each binding and
fits the controller's existing reconciliation model. All writes remain centrally
authorized through binding RBAC.

### 2. Separate enforcement revision from API generation

The targeting design currently includes binding generation in engine identities.
Refine that rule when adding assessment settings: `observedGeneration` tracks all
spec changes, while enforcement identity covers only profile reference, selector,
mode, and their resolved policy configuration. Assessment settings are excluded.

Use a protected, admission-maintained enforcement epoch on the binding. Compare
old/new enforcement fields on each spec write; preserve the epoch for reporting
edits and advance it for actual enforcement changes. Include binding UID, epoch,
profile UID/generation, and resolved policy digests in the enforcement revision.
This records A-to-B-to-A transitions even if a controller misses the intermediate
watch event. Users cannot forge or reset the epoch. Admission failure must not
allow an untracked enforcement change.

Update exception contribution comparison to use this enforcement identity;
observed binding generation remains provenance, not automatic invalidation.
Keep previously applied identities stable when initializing the epoch for existing
bindings, using their recorded applied revision as the migration anchor. Never
rewrite historical snapshots or reactivate an old grant during migration.

Hashing only present field values would reuse an old name on rollback. Hashing the
entire spec would invalidate exceptions when changing an export interval. The
protected epoch avoids both problems. This is a narrow evolution of the targeting
contract, not a competing policy ownership scheme.

### 3. Use a namespaced request and a protected cluster run

Add namespaced `AssessmentRequest` and cluster-scoped `AssessmentRun` resources
in `compliance.erenius.io/v1alpha1`. An application request contains an immutable
binding reference; its namespace defines its maximum scope. Admission captures
the authenticated requester, and reconciliation resolves the binding UID and
namespace UID. Recheck membership when execution starts. The team may read its
request/status and receive the separately granted download permission.

The controller creates an internal scoped run for that request. Platform roles
may create full-binding runs directly; application roles cannot create or read
cluster-scoped runs. Validate user-created run fields so only the controller can
set resolved scope, trigger identity, captured data, or publication state. Use
immutable specs, controller-only status, and explicit Conditions.

Request status contains a sanitized summary, run identifier, and opaque artifact
reference. It contains no full-binding inventory, storage credentials, or reusable
download token. Do not add cross-scope owner references: a cluster-scoped run
cannot be owned by a namespaced request. Deletion of a request prevents future
team downloads through it but does not cancel retained publication cleanup.

Namespaced requests provide normal Kubernetes RBAC and ResourceQuota boundaries.
A cluster-scoped request with a caller-supplied namespace would require another
delegation policy and is unnecessary for the initial self-service workflow.

### 4. Persist schedule decisions and serialize each binding

Record the schedule anchor, next due time, active run UID, and missed-interval
summary in bounded controller-owned state. Establish an initial current run when
the binding is first reconciled for assessments; subsequent due times advance by
interval from the anchor, not from upload completion. An interval edit establishes
a new schedule anchor without altering an active run or historical records.

Use leader election plus API resourceVersion compare-and-swap and deterministic
scheduled-trigger identities. Pending namespace requests retain their individual
identities and are not merged into another team's run. Run at most one active
collection/export/publication attempt per binding, with bounded global workers.
After an active run, service an overdue scheduled trigger before more manual work;
order manual requests deterministically. Apply namespace quotas and bounded queues.

Missed scheduled ticks coalesce into one current run with the gap recorded. Never
label it as an evaluation of the missed times. On-demand runs do not reset the
periodic schedule. Missing content or engine readiness becomes an explicit run
limitation within the collection deadline rather than suppressing scheduled records.

Bound plugin calls, storage attempts, and retry duration as well as collection.
The publisher's final failure releases the active slot; repeated outages remain
visible through failed runs and gap summaries. A single unresponsive dependency
must not block a binding forever or cause an unbounded catch-up queue.

### 5. Freeze an honest assessment window

At run start capture binding UID/settings, enforcement contributions, mapping
digests, namespace UIDs, expected resources/checks, and scope revision. Store the
large inventory in the package/staging path rather than CRD status. Track changes
during the bounded window, including added members, removed resources, in-place
updates, exceptions, and changed policy readiness. Keep the starting inventory
and report scope changes; do not improve completeness by dropping changed subjects.

Use a versioned controller capture format with keys containing cluster identity,
namespace/resource UID, workload-state digest, logical check/sub-validation,
contribution, and enforcement revision. Keep the prototype v1 capture path
working. Generalize its actual source/render verification instead of accepting
an arbitrary captured spec with a self-consistent hash. Preserve distinct checks
and binding contributions when aggregating C2P observations.

Relevant workload state includes spec, labels used by policy/exception selection,
and any other inputs used by the supported policy. ResourceVersion is an opaque
identifier, not a sortable clock; status-only updates need not invalidate checks
that do not read status. Unknown policy dependencies require conservative
invalidation. Namespace selection, engine configuration, and exception changes
also create observation boundaries.

Require source evaluation time within maxEvidenceAge at closure, no later than
collection time, and attributable state/policy identities. Prefer engine-provided
state correlation when available and verified. Otherwise establish a conservative
boundary after observing the current state, require a subsequent evaluation, and
recheck the state before closing. A result timestamp alone is not proof of which
version was evaluated: verify the pinned engine's report semantics. If correlation
cannot be established, keep the result unknown rather than weakening the rule.

Watch discontinuities or restarts discard unsupported continuity assumptions;
relisting does not create history. Tests must cover recent results from older
workload state. Continuous status watches the same inputs and schedules age-based
invalidation independently of the snapshot timer. Snapshots describe a bounded
observation window, not an atomic transaction across the whole cluster.

### 6. Close incomplete runs and build scope-safe packages

Close collection after at most collectionTimeout, or earlier when sufficient
current evidence is available. Preserve raw outcomes, rejected observations,
missing checks, applicability, and accepted risk separately from completeness.
Zero targets is explicit no-target coverage, not a passing assessment. Produce
schema-valid incomplete OSCAL when the mapping/context permits it. If malformed
inputs prevent valid export, produce a clearly typed diagnostic package containing
only safely scoped context; never publish invalid OSCAL as an assessment.

The existing collector reads reports with `-A` and exports them wholesale. The
controller path must first project evidence to the frozen scope, including
report-level scope, result-level resources, message text, annotations, errors,
and links. Preserve exact source values when scope is established. Mixed-scope
results require safe extracts with source report UID/digest, original result
index, and documented transformation. A hash/reference is provenance, not a team
download capability for the original cluster-wide report. Exclude unsafe opaque
content and mark its evidence unresolved rather than guessing it contains no
other namespace data. Do not copy arbitrary live objects or credentials into
packages merely because they were fetched during reconciliation.

Frozen capture bytes and package digests cannot change on retry. Recover a staged
capture where available. If a restart loses an unstaged capture, mark CaptureLost
and retain the diagnostic run record; a later current assessment gets a new run
identity. Do not silently reconstruct the closed snapshot from the changed cluster.

### 7. Share a producer/publication contract with the S3 change

This change owns request/run types and generated files, all four binding fields,
package descriptors, and publication status fields. The descriptor identifies
run UID, package kind, frozen scope/digest, file checksums, capture window, and
trusted producer validation. Publication status records destination identity,
owned keys/version IDs, package checksum, commit reference, publication time,
effective retention/expiry, availability, and cleanup state. It holds no bulk data.

Define staging, publish/recover, inspect, and delete operations as a small storage
boundary. Storage errors cannot change evaluation outcomes. A retained run has no
garbage-collection owner reference to its binding; publication cleanup owns its
finalization. The publisher maintains that record across binding/request deletion.
Namespace downloads are addressed through the original request UID and namespace
UID; platform downloads use the cluster run. The S3 change owns authenticated
download transport and retention execution.

Land the shared-contract implementation first in a focused PR. Scheduler and
collector work can then use a fake publisher while S3 work uses frozen package
fixtures. The S3 adapter can merge before complete scheduler integration; neither
change must be fully finished to merge this initial contract. Full acceptance
requires both implementations and the targeting/exception contracts. Coordinate
edits to `internal/assessment` with the Linux bundle agent after rebasing; do not
duplicate its policy-content work or the existing Go module.

## Risks / Trade-offs

- **Existing reports lack workload-state correlation:** establish conservative
  boundaries, validate engine semantics, and expose incomplete results when proof
  is absent; never infer freshness from collection time.
- **Namespace packages leak global reports:** project before export, validate
  package contents and links, and test deliberately mixed-scope/error fixtures.
- **Reporting fields rotate enforcement identities:** protect a separate epoch
  and test exception continuity across reporting-only edits and restarts.
- **Backlog or storage outage grows without bound:** serialize per binding, cap
  workers/retries, coalesce scheduled gaps, and enforce namespace request quotas.
- **A shared schema creates circular delivery dependencies:** merge its contract
  phase first, then build backend and scheduler independently before integration.

## Migration Plan

After targeting lands, extend the alpha API and initialize enforcement epochs
without replacing unchanged managed policies. Preserve the shipped prototype
commands and capture version. Deploy scheduling only with a configured ready
publisher; expose missing publisher configuration explicitly. Validate initially
with one Audit binding and two isolated namespaces, then introduce exceptions.

Rollback by disabling new run scheduling, draining or explicitly failing active
attempts, and retaining run/publication records for the S3 cleanup worker. Do not
remove CRDs with retained artifacts or remove governance protecting enforcement
epochs before coordinating the corresponding controller downgrade. Remove only
task-owned test infrastructure after validation and preserve test evidence.

## References

- [Assessment loop guide](../../../docs/integration/assessment-loop.md)
- [Kyverno starting scan interval](https://github.com/kyverno/kyverno/blob/v1.19.2/charts/kyverno/values.yaml#L863)
- [S3 publishing design](../add-s3-evidence-publishing/design.md)
