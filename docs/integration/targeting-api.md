# Compliance targeting API (v1alpha1)

Platform administrators configure compliance enforcement centrally with two
cluster-scoped resources in `compliance.erenius.io/v1alpha1`:

- **ComplianceProfile** pins bundle content by digest and selects logical
  policies from it, with optional parameters and an exception setting for each
  policy.
- **ComplianceBinding** applies one profile to the namespaces its selector
  matches, in `Audit` or `Deny` mode.

This is an alpha API. The schema, validation, RBAC, shared contract and the pure
resolver exist; the controller and engine delivery come in later task groups of
`add-compliance-targeting-api`. Applying these CRDs does not enforce anything
yet. The capability spec is
[compliance-targeting](../../openspec/changes/add-compliance-targeting-api/specs/compliance-targeting/spec.md).

## Files

| Path | Contents |
| --- | --- |
| `api/v1alpha1/` | Go types and the group registration. Generated `zz_generated.deepcopy.go`. |
| `config/crd/bases/` | Generated CRDs. Do not edit by hand. |
| `config/rbac/` | Platform-admin and viewer ClusterRoles. |
| `internal/targeting/` | The shared contribution, revision and eligibility contract. |
| `testdata/targeting/examples/` | Valid and invalid API examples, each tied to a spec scenario. |
| `testdata/targeting/resolver/` | Resolver input/output cases ([format](../../testdata/targeting/resolver/README.md)). |
| `testdata/targeting/contract/` | Serialized `targeting.Result` golden file. |

After editing types in `api/`, regenerate inside the Devbox environment:

```sh
devbox run -- scripts/generate.sh
```

`task lint`, and therefore `task check`, fails when the generated deepcopy code
or CRDs are stale. The tests in `api/v1alpha1` use `internal/crdtest` to run every
example through the same create-time steps the API server performs, with no
cluster: CRD structural and CEL cost checks, null pruning, defaulting, OpenAPI
validation and CEL rules.

## Examples

```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: baseline
spec:
  bundle:
    name: example-workload-hardening
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
  policies:
    - name: disallow-privileged-containers
      exceptions:
        eligibility: SelfService
        maxLifetime: 720h
    - name: require-run-as-non-root   # exceptions default to Forbidden
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-deny-production
spec:
  profileRef:
    name: baseline
  namespaceSelector:
    matchLabels:
      environment: production
  mode: Deny
```

## Rules

**Mode is explicit.** `spec.mode` is required and must be `Audit` or `Deny`.
There is no default, so a binding cannot silently inherit the prototype runner's
behaviour.

**Selectors are explicit.** `spec.namespaceSelector` is required. `{}` selects
every namespace, including namespaces created later. A missing or `null`
selector is rejected, never treated as "everything". The selector has the same
JSON shape and matching semantics as a Kubernetes `LabelSelector` and matches
**Namespace** labels, not workload labels. Admission rejects, with a
field-specific message:

- operators other than `In`, `NotIn`, `Exists` or `DoesNotExist`;
- `In`/`NotIn` without values, or `Exists`/`DoesNotExist` with values;
- invalid label keys or values.

The selector type is bounded: at most 64 `matchLabels`, 32 `matchExpressions`
and 64 values per expression. Without bounds, the API server refuses to install
a CRD with these CEL rules, because the estimated rule cost is unbounded. Use
`NamespaceSelector.AsSelector()` to get a standard `labels.Selector`.

**Bindings are cumulative.** Bindings never override each other. Every matching
binding contributes its own policy instance, so Audit cannot relax a Deny
contribution, and different parameters for the same policy are evaluated
separately.

**Exceptions default to Forbidden.** Each profile policy has
`exceptions.eligibility`, which defaults to `Forbidden`. `SelfService` requires
a positive `maxLifetime`, and `Forbidden` must not set one. Across all
contributions that apply to a policy in a namespace, any `Forbidden` wins, even
from an Audit binding. Otherwise the shortest `maxLifetime` applies. Unresolved
configuration never grants eligibility.

**Content is pinned.** `spec.bundle.digest` must be a `sha256:` digest. The
controller checks that policy names exist in that content once it resolves.

## Who controls scope

Bindings select namespaces by label, so whoever can change a namespace's labels
can move it in or out of a binding. Use labels that application teams cannot
change for scope that teams must not opt out of, for example labels set by the
platform's namespace provisioning and protected by admission policy. Konstapel
has no implicit system-namespace exclusions; an empty selector includes
`kube-system`.

Only namespaced workload checks can be targeted. Namespace selection cannot
constrain cluster-scoped resources, so the resolver reports an `UnsupportedScope`
error for such checks instead of enforcing them cluster-wide.

## RBAC

| ClusterRole | Grants |
| --- | --- |
| `konstapel-compliance-admin` | Full write access to profiles and bindings. Bind to platform administrators only. |
| `konstapel-compliance-viewer` | Read-only access to profiles, bindings and their status. |

Neither role is aggregated into the built-in `admin`, `edit` or `view` roles,
so namespace teams never gain them through their namespace roles. Status is
written only by the controller. `api/v1alpha1/rbac_test.go` checks every Role
and ClusterRole in `config/rbac/`, including roles added by later changes. Only
`konstapel-compliance-admin` may write profiles or bindings, and no role except
the controller's may write their status.

## Status

Binding status reports resolution and engine readiness separately, never
compliance. It has two conditions: `Resolved` and `EngineReady`.
`status.targetCount` is absent while unknown; `0` is a valid resolved scope and
never implies a passing assessment. `status.profile` records the profile UID,
generation and bundle digest last resolved, and `status.configurationRevision`
records the revision in force.

## Resolver

`targeting.Resolve(Input) Result` is a pure function over a snapshot of
profiles, bindings, namespaces and available bundle metadata. It reads no
cluster state and returns the same `Result`, revisions included, for any order
of its input lists. For each binding, `Result` contains:

- `targets`: the namespaces its selector matches, by name and UID, sorted by
  name. `targetCount` is always present and may be `0`.
- `contributions`: one per selected policy, sorted by policy. Each carries
  the cluster, binding and profile revisions, bundle name and digest,
  configuration digest, mode, selector, normalised exception settings and its
  `revision`.
- `errors`: the reasons the binding, or individual policies, did not resolve.

`Result.eligibility` has one entry per namespace and policy with at least one
contribution, sorted by namespace then policy.

### Overlap

Contributions are never merged or ranked. Two bindings that select the same
policy for a namespace produce two contributions, each with its own parameters
and mode, and the engine evaluates both. Adding Audit bindings never removes or
changes a Deny contribution. See
[`overlapping-parameters.yaml`](../../testdata/targeting/resolver/overlapping-parameters.yaml)
and
[`audit-all-deny-production.yaml`](../../testdata/targeting/resolver/audit-all-deny-production.yaml).

### Errors

| Reason | Scope | Effect |
| --- | --- | --- |
| `InvalidSelector` | binding | No targets and no contributions. Admission prevents this; it covers stored objects that bypassed validation. |
| `ProfileNotFound` | binding | Targets resolve, but there are no contributions. Every policy in those targets is ineligible for exceptions, because the missing settings could forbid them. |
| `ContentUnavailable` | binding | As `ProfileNotFound`. Raised when no available bundle has the pinned digest, or the bundle name does not match it. |
| `UnknownPolicy` | policy | That policy is skipped; the profile's other policies still contribute. |
| `UnsupportedScope` | policy | A cluster-scoped check is skipped, even under `namespaceSelector: {}`. |
| `InvalidConfiguration` | policy or binding | Invalid parameters or exception settings, or an unknown mode. That policy is skipped and is ineligible for exceptions in the binding's targets. |

A binding-scope error blocks exceptions only in the namespaces that binding
targets. Policy-scope errors block only that policy there. Every error that
forced `Forbidden` is listed in `eligibility[].errors`. See
[`unresolved-reference.yaml`](../../testdata/targeting/resolver/unresolved-reference.yaml),
[`unresolved-blocks-eligibility.yaml`](../../testdata/targeting/resolver/unresolved-blocks-eligibility.yaml),
[`cluster-scoped-check.yaml`](../../testdata/targeting/resolver/cluster-scoped-check.yaml)
and
[`zero-targets.yaml`](../../testdata/targeting/resolver/zero-targets.yaml).

### Eligibility

For one policy in one namespace, `effective` is `SelfService` only if every
contribution is `SelfService` with a positive lifetime and no error applies.
Then `maxLifetime` is the shortest of their lifetimes. Mode does not matter: a
`Forbidden` Audit contribution still forbids. `contributors` lists every
contribution considered, with its binding and profile revisions, mode and
`revision`. See
[`restrictive-eligibility.yaml`](../../testdata/targeting/resolver/restrictive-eligibility.yaml)
and
[`shortest-lifetime.yaml`](../../testdata/targeting/resolver/shortest-lifetime.yaml).

**Handoff to exceptions.** An exception acceptance records the contributor
`revision` values it was granted against. When any contributor's revision
changes, or a contributor is added, the acceptance no longer covers the current
configuration and must be revalidated.

### Membership

Namespace creation, deletion and label changes alter `targets` and
`eligibility`, but never a contribution's `revision`. A recreated namespace has
a new UID, so evidence and eligibility never reuse the old one. See
[`membership-change.yaml`](../../testdata/targeting/resolver/membership-change.yaml).

## Downstream contract

Other changes consume these files but do not edit them:

| Consumer | Uses |
| --- | --- |
| `add-self-service-policy-exceptions` | `targeting.Eligibility` (effective eligibility, shortest lifetime, contributor revisions) and `Contribution.Revision`. An acceptance is scoped to a revision and is never reused across revisions. |
| `add-continuous-assessments` | Adds `spec.assessment` to the binding and its own kinds as new files in `api/v1alpha1`. It supplies the binding's enforcement epoch through `EnforcementInput.BindingEpoch`. |
| `add-linux-workload-hardening-bundle` | Bundle policy metadata (logical name and resource scope) that the resolver reads. |

`targeting.EnforcementRevision` is the only place revisions are calculated. Its
binding-side input is the single `BindingEpoch` value. Today that is the
binding's `metadata.generation`; `add-continuous-assessments` replaces it with
an admission-maintained epoch, so reporting-only edits do not rotate policies.
Namespace membership is not an input: a namespace entering or leaving scope
does not create a new revision. The revision algorithm is pinned by a test, and
changing it requires bumping `targeting.ContractVersion`.
