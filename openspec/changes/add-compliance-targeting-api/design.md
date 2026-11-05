# Design

## Context

See [proposal.md](proposal.md) for motivation and
[compliance-targeting](specs/compliance-targeting/spec.md) for behavior. The
assessment-loop change owns the first Go module, cluster client, policy delivery,
and evidence conversion. This change introduces the controller configuration
contract on those boundaries; it does not create a competing integration runner.

The engine is Kyverno 1.19.2 using `policies.kyverno.io/v1`. Configuration must
remain meaningful independently of engine resource names so later engines and
remote cluster clients can consume it.

## Goals / Non-Goals

**Goals:** Use ordinary Kubernetes reconciliation, deterministic contributions,
and an explicit shared contract for exception eligibility and evidence identity.
Make namespace changes observable without turning status into a compliance score.

**Non-Goals:** Remote-cluster registration, arbitrary cluster-scoped workload
policies, exception activation, or changes to the first assessment provider's
plugin protocol. Konstapel does not evaluate workload admission itself.

## Decisions

### 1. Define two centrally administered alpha resources

Use the API group `compliance.konstapel.io/v1alpha1` for cluster-scoped
`ComplianceProfile` and `ComplianceBinding` resources. A profile identifies a
pinned bundle digest and logical policy settings, including per-policy exception
eligibility. A binding contains `profileRef`, a required `namespaceSelector`, and
an explicit `mode` of `Audit` or `Deny`. Missing mode is rejected rather than
inheriting the prototype runner's default. References resolve in the local
cluster; there is no remote target field in this version.

Use `metav1.LabelSelector` and Kubernetes selector validation, with schema rules
that reject absent/null selectors while accepting `{}`. Profile validation rejects
unknown policy identities and incompatible configuration once content resolves.
`Forbidden` is the default exception setting. `SelfService` requires a positive
`maxLifetime` duration; invalid or missing limits cannot grant eligibility.

Cluster RBAC restricts profile and binding writes to platform administrators.
Namespace exception roles do not include these permissions. Separating reusable
content from binding scope avoids duplicated profiles for Audit and Deny rollout;
embedding configuration in workload annotations would give application teams
control over central policy.

### 2. Resolve independently owned contributions

Implement a pure resolver over profiles, bindings, namespaces, and pinned bundle
metadata. Its output is a deterministically sorted set of contributions, each
carrying binding UID/generation, profile UID/generation, logical policy identity,
bundle digest, configuration digest, selector, mode, and explicit cluster identity.
The assessment-loop cluster identity scheme remains authoritative.

Keep overlapping contributions separate, including different parameters for the
same policy. Kyverno evaluates every applicable policy; any failing Deny
contribution denies admission. Audit cannot cancel Deny. Do not select a winning
binding or merge parameter maps: neither preserves the meaning of arbitrary
constraints. Keep multiple contributions traceable without counting repeated
checks as independent control coverage.

Expose a namespace/policy eligibility result for the exceptions controller.
Any matching `Forbidden` wins even when its mode is Audit; otherwise use the
shortest maximum lifetime. Unresolved applicable configuration is not permission.
Return the contributing revisions and resolution errors, not only a Boolean.

### 3. Carry standard selectors through to the engine

Render the binding's selector into the native policy's namespace matching field,
and watch Namespace events to maintain resolved membership, readiness, expected
evidence, and exception eligibility. Preserve Kubernetes label operators rather
than expanding selectors into a one-time list of namespace names. New matching
namespaces then use the same policy and later label changes converge naturally.

Accept only bundle checks whose matched workload resources are namespaced.
Namespace matching alone does not constrain cluster-scoped resources in Kubernetes
admission; reject such content with a resolution error. Include no implicit
system-namespace exclusions. Engine-wide exclusions and webhook configuration
remain visible deployment prerequisites and coverage limits.

Alternative: create a policy per namespace. That multiplies engine objects and
creates unnecessary delivery windows for every namespace event. A native selector
plus explicit observed membership gives the same intended scope with fewer objects.

### 4. Version policy instances and preserve ownership

Use deterministic engine names derived from binding UID, logical policy identity,
and a resolved configuration revision. The revision covers binding/profile
UIDs and generations, content, policy parameters, mode, selector, and exception
settings. Rolling back spec values creates a new generation and cannot resurrect
an old engine name or acceptance. Keep descriptive provenance
in labels/annotations and full values in recorded configuration snapshots. Add a
cluster-scoped owner reference to the binding where Kubernetes permits it.

Never reuse an engine name for changed policy semantics. This is necessary because
native exceptions reference policy names: in-place replacement could make an old
acceptance authorize a new revision. Namespace membership changes alone do not
change the selector's configuration revision; evidence still records namespace
UID and the membership observed for that evaluation.

Create replacement instances and confirm readiness before retiring superseded
owned instances. Report transition state; overlapping old/new instances can
temporarily enforce the stricter combination. A failed replacement retains the
last applied owned revision with explicit stale/not-ready status. A deleted
binding removes its own instances, including superseded revisions, without
affecting other owners. Refuse unmanaged name collisions.

Reusing one policy name would simplify resource counts, but cannot provide the
revision boundary required by risk acceptance. The exception change consumes
these versioned names and must not invent its own profile revision scheme.

### 5. Reconcile with standard controller patterns

Introduce a controller-runtime manager in the existing Go module and reuse the
foundation's cluster client and delivery boundaries. Use declarative desired
state, idempotent reconciliation, field ownership, bounded retries, and Conditions with
`observedGeneration`. Watch profiles, bindings, namespaces, and owned engine
objects; index profile references and affected contributions to avoid requiring
an engine write for every unrelated namespace event. Re-list after restart to
recover desired state. Do not use a custom polling database as the source of truth.

Status distinguishes configuration resolution, engine readiness, and observed
target counts. Include resolved profile generation/content digest and reasons
such as unresolved references, unsupported scope, ownership conflict, or a stale
applied revision. Bound status size: keep counts and revision summaries there,
with per-resource evaluation context in evidence. Zero targets is a valid resolved
scope, not a passing assessment. Readiness never asserts workload compliance.

### 6. Establish ownership before parallel integration

This change owns profile/binding Go types, their CRDs and generated files, the
resolver, watches/status, and corresponding controller integration. Use the root
module/toolchain and delivery interfaces from
`prove-kyverno-v1-assessment-loop` once merged; do not bootstrap a second module
or rewrite that agent's tasks. Schema examples and resolver input/output fixtures
can be prepared independently; Go builds require the foundation module.

Publish the contribution/revision/eligibility contract with this implementation.
`add-self-service-policy-exceptions` consumes the merged contract and owns its
own resource types and controller. The bundle change owns new content directories.
Coordinate manager registration and shared generated outputs only after rebasing
onto the prerequisite implementation.

## Risks / Trade-offs

- **Namespace-label changes alter enforcement:** document this central scope
  boundary and require platform-controlled labels where teams must not opt out.
- **Policy replacement is asynchronous:** retain the old applied revision until
  replacement readiness, expose transition conditions, and test overlap and failure.
- **Multiple bindings increase policy/report counts:** preserve contributions for
  correctness, use bounded status, and deduplicate only control coverage claims.
- **Missing references leave stale applied policies:** surface the exact applied
  revision and error; never label it current or silently remove working enforcement.
- **Alpha APIs and shared generated files create merge conflicts:** land this
  contract before dependent API integration and keep ownership boundaries explicit.

## Migration Plan

Install the new CRDs/RBAC and controller after the assessment-loop foundation.
Introduce an Audit profile/binding in a disposable cluster, exercise membership
changes, then add an overlapping Deny binding. The initial prototype-owned policy
is not adopted implicitly; remove it only through its existing owner workflow.

Rollback configuration by restoring a prior profile/binding revision and waiting
for replacement readiness, or explicitly delete test bindings to withdraw their
policies. Stop the controller only after deciding how to retain or remove its
managed policies. Remove CRDs last; deleting CRDs is not a routine rollback step
because it destroys their configuration records.
