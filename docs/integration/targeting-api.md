# Compliance targeting API (v1alpha1)

Platform administrators configure compliance enforcement centrally with two
cluster-scoped resources in `compliance.erenius.io/v1alpha1`:

- **ComplianceProfile** pins bundle content by digest and selects logical
  policies from it, with optional parameters and an exception setting for each
  policy.
- **ComplianceBinding** applies one profile to the namespaces its selector
  matches, in `Audit` or `Deny` mode.

This is an alpha API. The schema, validation, RBAC, shared contract, resolver,
engine delivery and the controller (`konstapel controller`) exist. Resolved scope
feeds the [continuous assessment collector](assessment-contract.md). Packaging
the controller as a Helm chart is owned by `add-helm-oci-distribution`.
Enforcement requires the running controller, selected content, and a compatible
Kyverno installation; installing CRDs alone does not enforce policy. The capability spec is
[compliance-targeting](../../openspec/specs/compliance-targeting/spec.md).

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

## Delivery

Delivery turns resolved contributions into Kyverno `policies.kyverno.io/v1`
ValidatingPolicies: one per contribution, cluster-scoped, owned by the binding.

### Content

`targeting.ContentSource` returns verified content for a profile's pinned
`bundle.name` and `bundle.digest`, or `ErrContentUnavailable`. `LocalContent`
serves the vendored `content/` tree under a configured bundle name. Its digest is
`sha256:` plus the sha256 of `content/SHA256SUMS`, and every listed file is
checked against that file on each call. `add-policy-bundle-distribution`
supplies the verified OCI source behind the same interface.

A policy can be namespace-targeted only if it is a `policies.kyverno.io/v1`
ValidatingPolicy and every resource it matches is a known namespaced workload
resource. Wildcards and unknown resources count as cluster scope, and the
resolver reports `UnsupportedScope` for them.

Profile `parameters` are rejected with `InvalidConfiguration` unless the content
declares how to render them; they are never silently dropped. The vendored
policy accepts none. Parameter rendering is defined by the bundle format in
`add-policy-bundle-distribution`.

### Rendering

`targeting.Render` copies the source policy unchanged, then sets only what
Konstapel owns:

- `metadata.name`: `konstapel-<policy, at most 36 characters>-<16 hex>`, at most
  63 characters. The suffix is derived from the binding UID, policy and
  revision, so a new revision always gets a new name.
- Labels: `app.kubernetes.io/managed-by: konstapel`,
  `compliance.erenius.io/binding-uid`, and `compliance.erenius.io/policy-hash`
  (a hash, because policy names can exceed label limits).
- Annotations under `compliance.erenius.io/`: revision, policy, binding name,
  profile name, UID and generation, bundle name and digest, configuration
  digest, source file digest, cluster and mode. The source's own annotations
  are kept. There is no binding generation: reporting-only edits such as
  `spec.assessment` advance it, and must not write to engine policies.
- A controller owner reference to the ComplianceBinding.
- `spec.validationActions: [<mode>]`, `spec.evaluation.background.enabled: true`,
  and `spec.matchConstraints.namespaceSelector` set from the binding.

A source that sets its own `namespaceSelector` is rejected rather than
overwritten. Rules, variables and validations are never changed. The golden
output for the Audit-all and Deny-production example is in
`testdata/targeting/rendered/`, and `task policies:test` runs the Kyverno CLI
against it. Kyverno CLI 1.19 reports resources excluded by a selector as
passing, so selector inclusion is also checked in Go.

### Ownership, readiness and transitions

`Delivery.Sync(binding UID, desired, hold)` is idempotent:

- **Create.** Missing desired policies are created. If an owned policy has
  drifted, its spec, labels and annotations are restored.
- **Conflicts.** If a desired name is held by a resource without Konstapel's
  labels and a controller reference to this binding, it is reported in
  `Conflicts` and left unchanged. Labels alone do not confer ownership.
- **Readiness.** A policy is ready when Kyverno reports
  `RBACPermissionsGranted` and `WebhookConfigured`. `NotReady` lists desired
  policies that are not ready yet.
- **Replacement.** When a revision changes, the new policy is created next to
  the old one. The old one stays in `Retained` until every desired instance of
  that logical policy is ready, and only then is it deleted. During the overlap
  both are enforced, so the stricter combination applies. A replacement that
  never becomes ready keeps the last applied revision enforcing indefinitely.
- **Holds.** Owned policies for logical policies listed in `hold` are never
  removed. The controller holds every policy that failed to resolve, so a
  missing profile or unavailable content leaves working enforcement in place.
  It never resolves to an empty desired set.
- **Removal.** An owned policy whose logical policy is no longer desired, and
  not held, is deleted.
- **Stale snapshots.** With `Delivery.Current` set (the controller sets it),
  the binding and profile are re-read from the API server before the first
  write and again before any delete. If either has a new UID or generation,
  the Sync stops with `ErrStaleSnapshot`, and the binding resolves again.
  Deletes carry the listed policy's UID and `resourceVersion` as
  preconditions. A delayed attempt from an old snapshot, such as a former
  leader resuming, can't withdraw a newer revision. See
  [Controller availability](availability.md#delayed-former-leaders).

`Delivery.Withdraw(binding UID)` deletes every policy the binding owns,
including superseded revisions, and nothing else. Owner references also let
Kubernetes garbage-collect them when the binding is deleted.

### Rollback

To roll back, restore the earlier profile or binding spec. The restore is a new
generation, so it gets a new revision and a new engine policy name; the old
name, and any exception acceptance tied to it, is never revived. Delivery
creates the new policy and retires the current one once the new one is ready.
To withdraw enforcement instead, delete the binding.

### Live acceptance

`task acceptance` runs `scripts/targeting-live.sh` on its disposable kind
cluster after the prototype checks. The script can also be run against any
disposable cluster with Kyverno installed, given an explicit kubeconfig,
context and output directory. The `live`-tagged Go test
`TestLiveDelivery`:

1. installs the generated CRDs and creates a profile, an Audit binding for all
   namespaces and a Deny binding for `environment: production`, then checks that
   the API server rejects a binding without a selector;
2. delivers both, then shows privileged pods are denied in production (server-side
   dry run), admitted in development, and reported as failing in a development
   PolicyReport;
3. relabels the development namespace into production and back: denial follows
   the label, and the policy name, and therefore the revision, does not change;
4. edits the profile: a new revision is created, the old one is retained until
   the new one is ready and then removed, and denial continues;
5. withdraws the Deny binding: exactly its policy is removed and production
   admits again;
6. requires that a prototype-style unmanaged policy created at the start was
   never modified or adopted.

Each step is recorded in `targeting/targeting-live.json` in the acceptance
output.

The same script then runs the controller's `live` tests against the running
manager. Each writes its steps to `targeting/<TestName>.json`:

| Test | Verifies |
| --- | --- |
| `TestLiveManager` | Manager delivery, the troubleshooting commands, restart without writes, relabel without new revisions, profile replacement, binding deletion. |
| `TestLiveTargetingWorkflow` | Audit everywhere (`namespaceSelector: {}`) with Deny in production; audit evidence attributed to its binding; namespace creation, relabel and deletion; removing one overlapping binding leaves the other's policies unchanged and enforcing. |
| `TestLiveTargetingFailures` | Missing content for new and working bindings (last applied policies kept), an ownership conflict found after a restart and its recovery, a Kyverno outage during replacement (`ReplacementPending`, old revision kept). No failure state reports Complete evidence. |
| `TestLiveEnforcementEpoch` | Enforcement epoch admission, migration and reporting-only edits. |
| `TestLiveAssessmentStatus`, `TestLiveAssessmentRuns`, `TestLiveEngineCorrelation` | The assessment side (see [assessment contract](assessment-contract.md)). |

[targeting-acceptance.json](targeting-acceptance.json) records a full run from
clean state: versions, rendered engine policy identities, test results, and the
output package digests.

The assessment-loop prototype's policy (`disallow-privileged-containers`,
labelled `konstapel.io/owner`) has no Konstapel controller reference, and its
name cannot collide with a rendered name. Delivery never adopts or removes it.
Remove it through the prototype's own workflow.

## Controller

`konstapel controller` runs the targeting manager from the existing image
(`/usr/bin/konstapel controller`). It uses in-cluster configuration, or
`KUBECONFIG` when run outside a cluster.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--content-root` | `/usr/share/konstapel/content` | Vendored content, served as bundle `konstapel-vendored`. |
| `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz`. They report process health only, never engine readiness or compliance. |
| `--metrics-bind-address` | `0` (off) | controller-runtime metrics. |
| `--leader-elect` | `true` | Lease `konstapel-controller-leader-election` in the pod namespace, shared by every replica and supported revision. |
| `--leader-election-lease-duration`, `--leader-election-renew-deadline`, `--leader-election-retry-period` | `15s`, `10s`, `2s` | Election timings. Startup fails unless lease > renew > 1.2 × retry, all positive. |
| `--leader-election-namespace` | `$POD_NAMESPACE` | Namespace of the Lease. |

Profiles pin the vendored content as bundle `konstapel-vendored` at
`sha256:` plus the sha256 of the shipped `content/SHA256SUMS`:

```sh
echo "sha256:$(sha256sum content/SHA256SUMS | cut -d' ' -f1)"
```

### Deployment and RBAC

Install the CRDs from `config/crd/bases/` first. The controller runs as service
account `konstapel-controller` in `konstapel-system`. That name is shared with
`add-continuous-assessments`, whose run-scope admission policy trusts it.
`config/rbac/controller/role.yaml` is generated from the reconcilers' markers
(`scripts/generate.sh`) and contains:

- ClusterRole `konstapel-controller`: read profiles, bindings and namespaces;
  write only their `status`; manage `policies.kyverno.io` ValidatingPolicies.
- Role `konstapel-controller` in `konstapel-system`: leader-election Leases and
  events.

Bind both to the service account. The controller cannot create or change
profiles or bindings; `api/v1alpha1/rbac_test.go` enforces that for every role
under `config/rbac/`.

### What it watches

- **ComplianceBinding** (spec changes) and **ComplianceProfile** (spec changes,
  mapped to referencing bindings through a `spec.profileRef.name` index).
- **Namespace** label changes, creation and deletion. Only bindings whose
  selector matches the old or new labels are reconciled, and only their status
  changes: selectors are rendered into the policy, never expanded into names.
- **Owned ValidatingPolicies**, once discovery finds
  `policies.kyverno.io/v1 validatingpolicies`. The manager starts without
  Kyverno. Until the capability monitor finds the API usable, bindings report
  the precise reason (see the table below) and are retried every 5 seconds.
  Delivery reads engine policies uncached, so no Kyverno informer is needed.
  Each engine watch registers once its own capability is available. After
  that, its informer re-lists and re-watches by itself when the API is removed
  and restored. See [Helm charts](../charts.md#external-engine-capabilities).

Deleting a binding needs no finalizer: its policies, including superseded
revisions, carry a controller owner reference, and Kubernetes garbage
collection removes them. A restart re-lists everything; when nothing changed it
writes neither policies nor status.

### Reading status

Binding status separates three questions. None of them is a compliance result.

| Question | Where | Current only when |
| --- | --- | --- |
| Is the configuration resolved? | `Resolved` condition, `status.profile`, `status.targetCount` | `Resolved=True` and its `observedGeneration` equals `metadata.generation` |
| Is the engine enforcing the current revision? | `EngineReady` condition, `status.configurationRevision` | `EngineReady=True` with the same `observedGeneration` |
| Is the evidence for this scope complete? | An assessment run's `evidence.completeness` (`Complete`, `NoTargets` or `Incomplete`) | Decided by the collector, never by binding status ([rules](assessment-contract.md#collector-evidence-rules)) |
| Is the cluster compliant? | The run's check outcomes, which are kept separate from completeness | Never inferred from binding status or from completeness |

The answers are independent, as `internal/controller/semantics_test.go`
shows with the collector:

- **Ready but incomplete.** A binding with `Resolved=True` and
  `EngineReady=True` still yields `Incomplete` evidence until reports for every
  expected observation are attributable.
- **Stale scope is incomplete.** A binding whose configuration did not resolve
  becomes a `StaleScope` in `targeting.ExpectedEvidence`, counted in the run's
  `staleScopes`. Evidence is then `Incomplete`, never `NoTargets`, even when
  nothing is expected.
- **Zero targets is `NoTargets`.** `targetCount: 0` with `EngineReady=True`
  gives `NoTargets` evidence, never `Complete`.

| `EngineReady` reason | Meaning |
| --- | --- |
| `Ready` | Every desired policy exists at the current revision and Kyverno reports it ready. The message says this is not a compliance result. |
| `ReplacementPending` | New policies are not ready yet; earlier revisions stay applied until they are. Retried every 5 seconds. |
| `StaleRevision` | Configuration did not resolve (see `Resolved`). The last applied policies, if any, stay in force and are named in the message. |
| `OwnershipConflict` | An unmanaged resource holds a desired name. It is left untouched; the binding re-checks every minute and delivers once the name is free. |
| `EngineAPINotServed` | `policies.kyverno.io/v1` is not served. Nothing is changed. |
| `EngineResourceMissing` | The group is served without `validatingpolicies`. Nothing is changed. |
| `EngineResourceUnsupported` | `validatingpolicies` has another kind or scope, or lacks a verb Konstapel needs. Nothing is changed. |
| `EngineAccessDenied` | Discovery, or an operation on `validatingpolicies` the controller needs, is forbidden to its service account. Nothing is changed. |
| `EngineUnavailable` | Discovery or the access review failed (transport, timeout, server error). Nothing is changed. |
| `NoContributions` | The binding resolved to no deliverable policies. |

`status.targetCount` is absent until the first reconcile. `0` means no namespace
currently matches, while the policies stay installed for namespaces created
later. `status.configurationRevision` is the revision when there is one
contribution, otherwise a digest of all contribution revisions. Messages are
capped at 1024 bytes.

Profile status has one `Resolved` condition: `ContentUnavailable`,
`UnknownPolicy`, `UnsupportedScope`, or `Resolved`.

### Engine exclusions

Konstapel adds no namespace exclusions: `namespaceSelector: {}` includes
`kube-system` and the controller's own namespace. Kyverno's own configuration
can still exempt resources, for example through its webhook
`namespaceSelector`, resource filters or excluded groups. Konstapel does not
detect those, so an excluded namespace can be a target in status while Kyverno
never evaluates it. Review the engine's exclusions when you choose selectors,
and rely on assessment evidence, not binding status, for what was evaluated.

### Troubleshooting

Replace `BINDING` and `POLICY` with real names.

```sh
# Scope, readiness and revision per binding
kubectl get compliancebindings
kubectl get compliancebinding BINDING -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
# Engine policies a binding owns, with their revisions
kubectl get validatingpolicies -l compliance.erenius.io/binding-uid=$(kubectl get compliancebinding BINDING -o jsonpath='{.metadata.uid}') \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.compliance\.erenius\.io/revision}{"\n"}{end}'
# Kyverno's view of one policy
kubectl get validatingpolicy POLICY -o jsonpath='{.status.conditionStatus.conditions}'
```

- `Resolved=False`: the reason is `ProfileNotFound`, `ContentUnavailable`,
  `UnknownPolicy`, `UnsupportedScope`, `InvalidConfiguration` or
  `InvalidSelector`. Fix the profile or binding; the previous enforcement stays
  in force meanwhile.
- `EngineReady=False, ReplacementPending` for a long time: check Kyverno's
  conditions on the new policy (`RBACPermissionsGranted`, `WebhookConfigured`)
  and the Kyverno admission controller logs.
- `OwnershipConflict`: the named resource was not created by this binding.
  Remove or rename it deliberately; Konstapel never adopts it.
- `EngineAPINotServed`, `EngineResourceMissing`, `EngineResourceUnsupported`:
  install Kyverno 1.19 with the `policies.kyverno.io/v1` ValidatingPolicy API.
- `EngineAccessDenied`: grant the controller's generated RBAC
  (`config/rbac/controller/role.yaml`).
- `EngineUnavailable`: check API server and aggregation health. It retries by
  itself.

## Downstream contract

These capabilities share the targeting contract:

| Consumer | Uses |
| --- | --- |
| `add-self-service-policy-exceptions` | `targeting.Eligibility` (effective eligibility, shortest lifetime, contributor revisions) and `Contribution.Revision`. An acceptance is scoped to a revision and is never reused across revisions. |
| Continuous assessments | Uses `spec.assessment`, AssessmentRequest/AssessmentRun, the admission-maintained enforcement epoch through `EnforcementInput.BindingEpoch`, and `targeting.ExpectedEvidence`. |
| `add-linux-workload-hardening-bundle` | Bundle policy metadata (logical name and resource scope) that the resolver reads. |

The repository has one Go module (`go.mod` at the root) and one API group
(`compliance.erenius.io/v1alpha1`, in `api/v1alpha1`). Downstream changes add
files there and do not create their own module or group. The exceptions change
compares accepted contributions by `Contribution.Revision`; its native-grant
lifecycle remains in progress. The hardening bundle already serves its policy
variants alongside the privileged policy. Shared contracts are exported from
`internal/targeting` and pinned by tests; coordinate changes with their consumers.

### Expected evidence

`targeting.ExpectedEvidence(result, content)` turns a resolver `Result` into the
expected-evidence subjects consumed by `internal/collector`. The original runner
and provider remain in `internal/assessment`. There is
one `EvidenceSubject` per namespace UID × contribution, carrying:

- cluster, namespace name and UID, binding name and UID;
- `revision` (the contribution's `EnforcementRevision`) and `enginePolicy`
  (the rendered name);
- logical policy, mode, matched `resources` as `group/version/resource`;
- profile name, UID and generation, and bundle, configuration and source digests.

The rules:

- **Keyed by namespace UID.** A recreated namespace is a new subject; old
  subjects are never reused.
- **Overlaps stay separate.** Overlapping bindings produce separate subjects with
  distinct revisions and engine policies. The collector must not count them as
  independent control coverage.
- **Checks are not enumerated here.** `checks` is empty for the vendored
  policy, whose validations are unnamed; the collector enumerates them from the
  rendered policy.
- **Stale scope is reported.** Bindings or policies that did not resolve are
  returned as `StaleScope` entries with their reason. Their last applied
  policies may still be enforcing, so the collector records a limitation rather
  than a silent gap.
- **Missing content is an error.** A contribution whose bundle digest has no
  content fails instead of guessing.

Subjects are sorted by namespace UID, binding UID, logical policy and revision.
The output is pinned by `testdata/targeting/contract/evidence.json`; changing it
requires bumping `targeting.ContractVersion`.

`targeting.EnforcementRevision` is the only place revisions are calculated. Its
binding-side input is the single `BindingEpoch` value, taken from the
admission-maintained `spec.enforcementEpoch`, so reporting-only edits do not rotate
policies. Legacy bindings without that field fall back to `metadata.generation`
until admission initializes the epoch on their next write.
Namespace membership is not an input: a namespace entering or leaving scope
does not create a new revision. The revision algorithm is pinned by a test, and
changing it requires bumping `targeting.ContractVersion`.
