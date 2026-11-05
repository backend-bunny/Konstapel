# Design

## Context

See [proposal.md](proposal.md) and [policy-exceptions](specs/policy-exceptions/spec.md).
The targeting change supplies versioned policy contributions and effective
eligibility. The assessment loop supplies raw report capture, C2P-Go v2 conversion,
and OSCAL export. This change joins those contracts with attributable acceptance.

Kyverno's new-group v1 `PolicyException` supports `policyRefs`, CEL match
conditions, `reportResult`, `expiresAt`, and properties. These fields are engine
configuration, not an authorization or audit system. The implementation must use
the served `policies.kyverno.io/v1` API, regardless of internal Go type aliases.

## Goals / Non-Goals

**Goals:** Automatically activate bounded, authorized exceptions and retain their
meaning at evaluation time. Protect the native bypass path and make withdrawal
state visible. Persist attribution before making an engine grant effective.

**Non-Goals:** A central approval queue, permanent exceptions, arbitrary user CEL,
image/value-specific waivers, cross-namespace delegation, a second workload
admission engine, or a full audit archive service. Cluster administrators remain
trusted; this design constrains namespace application roles.

## Decisions

### 1. Use a namespaced acceptance resource with explicit renewal

Add `ComplianceException` in `compliance.konstapel.io/v1alpha1`. Its spec contains
one logical policy reference, a required workload `LabelSelector`, a nonblank
reason, an RFC3339 `expiresAt`, and an acceptance revision. An explicit empty
workload selector selects all applicable workloads in its own namespace; missing
or null selectors are invalid. Namespace RBAC grants application teams authority
to accept risk only where they can manage these resources.

The policy reference and selector are immutable. Wider scope requires a new
resource. Creation starts acceptance revision 1. Explicit renewal increments the
revision and supplies a current reason and future expiry, triggering fresh
eligibility and lifetime validation. Metadata-only updates and controller
reconciliation cannot renew an exception. Concurrent/stale updates use Kubernetes
resourceVersion conflict handling. Revocation is terminal for that acceptance;
reactivation requires a new acceptance revision or resource and fresh validation.

Selectors match the evaluated object's labels. A Deployment and its Pods are
distinct objects: teams must label controller metadata and Pod templates when
both need exemption. There is no implicit owner traversal. A stable selector
intentionally includes future matching workloads in the same namespace identity;
it is not a frozen list of Pod UIDs. Label access is part of the namespace team's
delegated authority. A resource in another namespace never inherits acceptance.

Per-policy records keep the reason, renewal, and revocation boundary clear.
Combining arbitrary policies into one acceptance would obscure which risk a team
accepted when one policy becomes non-negotiable.

### 2. Authenticate acceptance at API admission

Use narrowly scoped mutating/validating admission for `ComplianceException`
operations to capture Kubernetes `AdmissionReview.userInfo`, the acceptance time,
the resolved contribution/revision set, and the requested acceptance revision
into protected metadata. Overwrite caller-supplied
attribution on a genuine acceptance operation; validate it against the authenticated
operation and reject changes outside that operation. Ordinary metadata edits
preserve the existing acceptance. Only controller credentials can write status
and stored acceptance snapshots. Admission is side-effect-free for dry runs.

Record username, UID when provided, and relevant authenticated groups, distinguishing
them from optional ticket or claimed human references. A GitOps service account
is the authenticated actor; a commit author string is not verified human identity.
Admission validates expiry against the shortest effective maximum lifetime from
the targeting contract. Unresolved policy/configuration or any Forbidden
contribution rejects acceptance. Reconciliation rechecks those dependencies
before activation to handle changes after admission. A changed contribution set
invalidates that acceptance; reconciliation must not substitute a newer set.

These webhooks govern configuration and authorization. Kyverno remains responsible
for accepting or denying workloads. Caller-owned annotations and approval queues
are unsuitable substitutes for authenticated, automatic acceptance.

### 3. Freeze a resolved acceptance before granting it

Persist a controller-owned immutable snapshot in the protected Konstapel namespace
before creating native exceptions. Include exception UID/revision, namespace
name/UID, cluster identity, authenticated actor, reason, acceptance time, expiry,
selector, and the complete accepted contribution/revision set. Store its digest
and reference in status and native metadata. A small immutable Kubernetes object
per acceptance is sufficient initially; no external history service is required.

The snapshot copies the contribution set protected at acceptance admission.
Reconciliation must never resolve a replacement set silently. New policy/configuration revisions,
additional binding contributions, or new restrictive eligibility invalidate the
grant and require renewed acceptance. Removing contributions cannot authorize
new ones. Namespace recreation under the same name is a different identity.

Package the snapshot and observed activation/withdrawal context with each retained
assessment. Live snapshots can be retained according to documented operator
retention; they must not be deleted before an assessment depending on them has
captured its reference. Historical output remains interpretable after live cleanup.
If evidence arrives after the necessary history is unavailable, attribution is
unresolved; reconstructing an acceptance from current settings is forbidden.

### 4. Render a constrained native exception in a protected namespace

Enable Kyverno exceptions only in the configured Konstapel exception namespace.
Application roles receive no native exception write permission there. Add admission
validation for native exceptions that can affect managed policies: require the
controller identity, a recorded acceptance, exact policy refs, bounded conditions,
and an expiry no later than the acceptance. Validate all native versions served
by the engine so another API version cannot bypass the guard; emit only v1.

Generate one native object per acceptance revision, referencing only the exact
versioned managed `ValidatingPolicy` instances. Use `reportResult: skip` with no
`images` or `allowedValues`, so the waiver is for the named logical policy. Render
CEL conditions for the target namespace name and UID and the workload selector,
using safe literal encoding and standard label operator semantics. The exception
object's own namespace does not constrain its workload targets. Validate
`namespaceObject` availability and namespace UID matching on admission and
background paths; an unavailable identity must not grant an exception.

Use recorded ownership and deterministic names. A central native object cannot
use a cross-namespace owner reference to the application record. Use finalization,
orphan reconciliation, and native expiry instead; refuse unmanaged collisions.
Do not install upstream sample exceptions or accept caller-written native refs.

### 5. Treat expiry support as an engine release prerequisite

The starting Kyverno pin is 1.19.2. Source inspection finds `IsExpired` filtering
in `pkg/cel/engine/exception.go` during policy compilation, while the cached
ValidatingPolicy evaluation loop in `pkg/cel/policies/vpol/compiler/policy.go`
does not recheck expiry. An `expiresAt` field alone therefore is not sufficient
evidence of automatic expiry for an already compiled grant.

Before enabling this capability, reproduce the behavior with a short-lived
exception while Konstapel is stopped. Require an engine runtime that checks
expiry during evaluation, including cached policies. Resolve the gap with a
pinned upstream release or a narrowly scoped upstream/backported engine fix and
record the tested image digest. The feature remains disabled if that prerequisite
is unmet. Re-run the assessment-loop and bundle compatibility cases when the
engine pin changes. Do not invent a Konstapel workload webhook as a fallback.

Always render native `expiresAt`, schedule controller reconciliation at expiry,
and rescan after restart. Scheduled deletion provides cleanup, not the sole
security guarantee for time limits. Explicit deletion, revocation, and central
policy changes trigger withdrawal of managed native resources. Observe engine
convergence before claiming withdrawal is complete; an API delete alone is not
proof that every engine replica has refreshed its cache. Use available readiness
signals and bounded live verification in acceptance tests, retaining unknown or
pending status when confirmation is unavailable.

Expose eligibility, desired activation/withdrawal, and observed engine state
separately. Never delete existing workloads as part of exception withdrawal.
Clock skew and asynchronous propagation are recorded operational limits; expiry
tests must exercise engine replicas and restarts, not only controller timers.

### 6. Keep raw evaluation separate from risk disposition

Extend the captured assessment package with an exception-context sidecar keyed by
cluster identity, namespace/resource identity, policy revision, acceptance
revision, and source evaluation time. Resolve exception references from native
report properties and verify the corresponding snapshot and observed lifecycle.
Collection time cannot substitute for evaluation time. Ambiguous report-to-policy
or acceptance correlation remains incomplete, following the first loop's rule.

Record raw outcomes unchanged and derive a separate disposition: unexcepted,
self-accepted risk, or unresolved exception attribution. A skipped evaluation
does not prove an underlying failure; a pass influenced by an exception does not
prove an unexcepted pass. Preserve multiple contributing exception references
without multiplying control coverage.

C2P-Go v2's result enum has no accepted-risk member. Carry the disposition in the
adapter's explicit metadata and add schema-valid OSCAL properties/evidence links
at export where C2P drops metadata. Verify the final Assessment Results, not just
an intermediate Go object. Include the acceptance context in retained artifacts,
exclude accepted/unresolved results from ordinary passing totals, and preserve
partial-control coverage. This extends the adapter boundary without forking C2P.

### 7. Respect parallel implementation boundaries

Lifecycle/authorization/report fixtures can be prepared independently. Go API and
runtime integration consume the merged targeting contribution/eligibility
contract and the assessment-loop evidence/export boundaries. This change owns
exception types/CRDs, its controller and admission handlers, native governance,
and acceptance enrichment. It does not concurrently rewrite profile/binding
schemas or the root Go module. Shared manager/chart/generated-output edits happen
after rebasing onto those prerequisites.

## Risks / Trade-offs

- **Native exception access bypasses central settings:** restrict engine-enabled
  namespaces, RBAC, and served-version admission; test with real application roles.
- **Cached engine grants outlive expiry:** block feature enablement until the
  runtime expiry gate passes, including Konstapel downtime.
- **Policy changes race activation:** freeze the accepted set, recheck before
  delivery, and use versioned native policy names plus explicit withdrawal state.
- **Admission infrastructure is unavailable:** fail closed for acceptance/native
  grant writes; existing workload enforcement remains Kyverno's responsibility.
- **History disappears before late reports arrive:** retain snapshots and export
  copies; classify missing evaluation-time attribution as unresolved.
- **Self-service can waive a whole eligible policy:** make that scope explicit in
  documentation and central defaults; finer container/value waivers are later work.

## Migration Plan

First establish the compatible engine runtime, then install exception CRDs,
restricted RBAC, admission governance, and snapshot storage. Keep engine exception
enablement off until the governance checks pass. Use a disposable namespace and a
single eligible policy to prove acceptance, sibling isolation, expiry, revocation,
and export before enabling broader self-service.

Rollback by preventing new acceptances, withdrawing native grants with observed
convergence, and retaining snapshots/output. Disable engine exception support
before removing its governance. Removing the controller alone is not a safe
revocation procedure. Preserve existing workloads and their historical evidence.

## References

- [Pinned native exception fields](https://github.com/kyverno/api/blob/fb2785727f98/api/policies.kyverno.io/v1alpha1/policy_exception.go) (definitions aliased by the v1 API)
- [Pinned exception filtering](https://github.com/kyverno/kyverno/blob/v1.19.2/pkg/cel/engine/exception.go)
- [Pinned cached policy evaluation](https://github.com/kyverno/kyverno/blob/v1.19.2/pkg/cel/policies/vpol/compiler/policy.go)
- [Pinned exception CEL environment](https://github.com/kyverno/kyverno/blob/v1.19.2/pkg/cel/compiler/policy_exception.go)
