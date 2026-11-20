# Policy change preview

> **Status: input model, cluster observation and comparison core only.** The
> `konstapel preview` command, its JSON report and exit codes are not
> implemented yet. This page documents the parts that exist in
> `internal/preview`: how rendered manifests are read and validated, how the
> candidate configuration is formed (tasks 1.1 to 1.3 of the
> `add-policy-change-preview` change), the read-only cluster observation with
> its access contract and limits (tasks 2.1 to 2.3), and the semantic comparison
> with its impact categories (tasks 3.1 to 3.4). No command line exposes any of
> them yet. Treat the planned command line in the change's
> [design](../openspec/changes/add-policy-change-preview/design.md) as not available.

The preview is meant to show how proposed compliance configuration would change
namespace coverage, enforcement and accepted risks before GitOps applies it. It
describes configuration effects. It does not evaluate workloads, predict
admission, or promise that existing workloads pass a new policy.

## Rendered-input model

The caller renders the compliance configuration (Helm, Kustomize, or by hand)
and names the files explicitly. Two roles exist:

- **Proposed** (`-f`/`--file`, repeatable, at least one): the complete proposed
  specification of every object it contains.
- **Previous** (`--before`, repeatable, optional): the previously rendered set.
  It declares removal scope and provenance. It is never the baseline: the
  observed cluster is.

Each role accepts multi-document YAML or JSON. JSON is read as YAML, so separate
several JSON documents with `---`. Standard input (`-`) may supply at most one
stream across both roles, so two sets cannot consume the same input. All inputs
share one budget of 16 MiB; exceeding it is an error, never a truncated read.
Empty and `null` documents are skipped. An empty stream is valid and, with a
previous set, proposes removing exactly that set.

### Supported objects

Only the cluster-scoped `compliance.erenius.io/v1alpha1` `ComplianceProfile` and
`ComplianceBinding` are accepted, each with an explicit `metadata.name` and no
`metadata.namespace`. Namespaces, Secrets, `ComplianceException`s, bundle-source
configuration, other versions and arbitrary engine policies are errors, not
skipped documents: the preview never silently filters a whole application's
manifests.

An input is invalid, and the preview does not proceed, when it has:

- duplicate mapping keys (at any depth) or two objects with the same identity
  within one role;
- unknown fields (the API server would prune them; the preview refuses),
  `generateName`, an unsupported kind or version, or an invalid name;
- a spec that the CRD schema or its rules reject, for example a missing
  `namespaceSelector` (never read as the explicit `{}` that selects every
  namespace), a bad selector, `SelfService` without a positive `maxLifetime`,
  or a duration written as `90d`;
- YAML aliases, anchors, merge keys, non-string keys, non-standard tags, or
  nesting deeper than 64 levels;
- unquoted scalars that YAML 1.1 and YAML 1.2 parsers read differently
  (`y`, `yes`, `no`, `on`, `off` and sexagesimal numbers such as `1:30`).
  `kubectl` and GitOps appliers use a YAML 1.1 reader, so quote these values.

Every problem is reported with its source, document, line and `Kind/name`, and a
stable code such as `unknown-field` or `invalid-spec`.

<!-- Examples below are test fixtures: each block equals the named file. -->

A proposed profile and binding:

<!-- fixture: testdata/preview/examples/valid/proposed.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: workload-baseline
spec:
  bundle:
    name: konstapel-privileged-containers
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  policies:
    - name: disallow-privileged-containers
      exceptions:
        eligibility: SelfService
        maxLifetime: 720h
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-production
spec:
  profileRef:
    name: workload-baseline
  namespaceSelector:
    matchLabels:
      environment: production
  mode: Deny
```

Rejected inputs (the first line states the error code):

<!-- fixture: testdata/preview/examples/invalid/missing-selector.yaml -->
```yaml
# expect: invalid-spec
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: no-selector
spec:
  profileRef:
    name: workload-baseline
  mode: Audit
```

<!-- fixture: testdata/preview/examples/invalid/duplicate-binding.yaml -->
```yaml
# expect: duplicate-identity
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: twice
spec:
  profileRef: {name: workload-baseline}
  namespaceSelector: {}
  mode: Audit
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: twice
spec:
  profileRef: {name: workload-baseline}
  namespaceSelector: {}
  mode: Deny
```

<!-- fixture: testdata/preview/examples/invalid/namespace-object.yaml -->
```yaml
# expect: unsupported-kind
apiVersion: v1
kind: Namespace
metadata:
  name: production
```

<!-- fixture: testdata/preview/examples/invalid/unknown-field.yaml -->
```yaml
# expect: unknown-field
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: typo
spec:
  profileRef: {name: workload-baseline}
  namespaceSelector: {}
  mode: Audit
  enforcment: Deny
```

<!-- fixture: testdata/preview/examples/invalid/unquoted-yes.yaml -->
```yaml
# expect: ambiguous-scalar
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: ambiguous
spec:
  bundle:
    name: konstapel-privileged-containers
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  policies:
    - name: disallow-privileged-containers
      parameters:
        allowHostPath: no
```

### Exported live objects

Server-managed values never establish proposed identity, acceptance or
readiness. `metadata` other than `name` and `namespace`, `status`, and the
admission-maintained `spec.enforcementEpoch` are discarded and recorded as
ignored. Defaults are applied before comparison, so an input that writes out a
default, reorders policies or selector expressions, reorders parameter keys, or
spells `24h` as `1440m` has the same fingerprint as one that does not. The
fingerprint identifies normalized configuration only. It is a semantic
equivalence aid, not an enforcement revision and not an acceptance token: some
of these equivalent edits still replace enforcement revisions (see
[Revision effects](#revision-effects-and-identities)).

<!-- fixture: testdata/preview/examples/valid/exported.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-production
  uid: 5b7e8f3a-0000-4000-8000-000000000000
  generation: 4
spec:
  profileRef:
    name: workload-baseline
  namespaceSelector:
    matchLabels:
      environment: production
  mode: Deny
  enforcementEpoch: 3
status:
  observedGeneration: 4
```

## Candidate configuration

The candidate is built from the **observed live desired state** (supplied by the
caller; this layer never reads a cluster), the proposed objects, and the
declared removals:

1. Each proposed object replaces the live object of the same group, kind and name
   as its complete specification. A proposal whose normalized configuration
   equals the live one keeps the observed object as a configuration no-op. It is
   a server no-op only if the API server would also store the same
   specification; otherwise enforcement revisions can still rotate (see
   [Revision effects](#revision-effects-and-identities)).
2. Identities in the previous set but not in the proposed set are removed. If the
   live cluster no longer has such an object, the removal is recorded as already
   absent and creates no impact.
3. Every other live object is preserved, including objects that overlap the
   proposed ones or share a profile with them.

With only the proposed binding below and no previous set, every other live
profile and binding stays in the candidate. With an explicitly empty proposed
stream and the previous set, only the identities in the previous set are removed:

<!-- fixture: testdata/preview/examples/valid/previous.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-staging
spec:
  profileRef:
    name: workload-baseline
  namespaceSelector:
    matchLabels:
      environment: staging
  mode: Audit
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-production
spec:
  profileRef:
    name: workload-baseline
  namespaceSelector:
    matchLabels:
      environment: production
  mode: Audit
```

<!-- fixture: testdata/preview/examples/valid/empty.yaml -->
```yaml
# An explicitly empty stream: with --before it proposes removing every
# identity of the previous set and nothing else.
```

Replaced and created objects carry only their name and candidate specification.
Their server identity (UID, generation, enforcement epoch) is pending
application and is never copied from the live object, so a changed object cannot
be mistaken for the observed revision.

A profile that the candidate removes while a surviving binding still references
it is an invalid candidate. The error names the binding and the profile and notes
that policies already applied for it may remain enforcing. A proposed binding
that references a profile found neither live nor in the proposal is an error. An
unrelated, already dangling live reference is a baseline condition for the
resolver to report, not an input error.

## Cluster observation

The baseline is the selected cluster, read with the caller's own kubeconfig
credentials: an explicit or standard kubeconfig and a named or current context.
There is no fallback to an in-cluster ServiceAccount, and the preview never uses
or impersonates the controller's identity. The caller also names the Konstapel
controller namespace and, when the controller runs with
`--bundle-sources-configmap`, the same ConfigMap name.

### Cluster access

The observation sends only `GET` requests: API discovery, `get` and `list`. A
guard in the client refuses anything else before it is sent, including writes,
server-side dry-run, `SelfSubjectAccessReview`-style authorization probes,
watches and any Secret request. Tests run the observation against a recording API
server and a disposable cluster and check that no other request occurs.

| Resource | API group | Where | Verbs | Read for |
| --- | --- | --- | --- | --- |
| `namespaces` | core | cluster | `get` (`kube-system`), `list` | Cluster identity (`kube-system:<uid>`, as the controller records it); namespace instances (name, UID, labels) |
| `complianceprofiles`, `compliancebindings` | `compliance.erenius.io` | cluster | `list` | Live desired configuration, including every binding of a shared profile |
| `complianceexceptions` | `compliance.erenius.io` | all namespaces | `list` | Protected acceptance records and snapshot references |
| `validatingpolicies` | `policies.kyverno.io` | cluster | `list`, label `app.kubernetes.io/managed-by=konstapel` | Applied engine policies, their recorded contribution and readiness |
| `configmaps` | core | controller namespace | `list` (acceptance snapshots, by label); `get` (the bundle-source ConfigMap and the trust ConfigMaps it names) | Frozen acceptance snapshots; source and trust configuration |
| discovery | `/api/v1`, `/apis/compliance.erenius.io/v1alpha1`, `/apis/policies.kyverno.io/v1` | | `GET` | Required APIs are served (granted to authenticated users by `system:discovery`) |

`secrets` are not read. A bundle source's `credentialSecret` and any Secret trust
reference are listed by name as `secret-not-read` limitations; caller-authorized
bundle access is a later part of the change. A ready-made ClusterRole and Role
with exactly these permissions is in
[`docs/examples/policy-preview/reader-rbac.yaml`](examples/policy-preview/reader-rbac.yaml).
Overlap and shared-profile analysis needs cluster-wide reads, so a namespace
service account of an application team is usually not enough.

A label without a matching controller reference does not make an engine policy
Konstapel's: the observation applies the delivery rule (ownership labels and a
controller reference to the same binding UID). Such a policy is reported as
unowned. A policy owned by a binding UID that no longer exists is reported as
orphaned, because it may still enforce. A policy whose recorded contribution
cannot be read is unknown applied state, never an absent one.

Exception acceptance is observed from what the exception owner provides today:
the admission-protected acceptance record, the controller's snapshot reference
in `status.acceptance`, and the frozen snapshot ConfigMaps, each verified
against its recorded digest. Reasons, actors and claims are not kept.
Revocation (`spec.revoked` and revocation records) does not exist yet and is
reported as the `exception-revocation-unavailable` limitation.

### Consistency and limits

Kubernetes has no transaction across these APIs. The observation reads every
collection completely, following list continuations, records each list's
`resourceVersion` and every object's UID, `resourceVersion` and generation, and
then reads everything again as a recheck. It compares only relevant projections:
specifications, generations, enforcement epochs, namespace UIDs and labels,
ownership and provenance of engine policies and their derived readiness,
acceptance records and snapshots, and source and trust data. Status timestamps,
report times and unrelated annotations are ignored, so constantly changing
status does not force retries. If a relevant projection changed, or a list
continuation expired, the whole capture is repeated, at most two recaptures.
Two consecutive agreeing captures detect drift; they do not prove an atomic
snapshot or describe the cluster at apply time.

| Limit | Default |
| --- | --- |
| Total time, all captures included | 60 seconds |
| Recaptures after drift or expired pagination | two recaptures (the maximum) |
| Objects collected per capture | 100,000 |
| Page size / requests per capture | 500 / 1,000 |
| Response bytes per capture | 512 MiB |
| Manifest input (all files) | 16 MiB |

Denied or unauthorized reads, an API that is not served, a missing cluster
identity, an object that does not match the supported API contract, persistent
drift, persistent pagination expiry, an exhausted limit, a timeout or a
cancellation make the observation **incomplete**. An incomplete observation
carries only provenance and coded diagnostics, never a partial object set, so a
truncated or empty read can never pass for the cluster. A missing or invalid
bundle-source ConfigMap is recorded as found, like the controller would find it.

## Semantic comparison

The comparison takes a complete observation, the validated input sets and a
verified content source. It refuses an incomplete observation, a missing
content source and an invalid candidate outright. Otherwise it resolves two
configurations with the controller's own `targeting.Resolve`:

- the **baseline**: the observed live profiles, bindings and namespace
  instances; and
- the **candidate**: the [candidate configuration](#candidate-configuration)
  against the same namespace instances.

Both sides read content through the same `targeting.ContentSource` seam that the
controller uses, by exact bundle name and digest, and never substitute other
content. Terminating bindings and namespaces are left out, as the controller
leaves them out. Every binding of a changed profile is resolved, including
bindings that do not appear in any input, so overlap and shared-profile
consumers stay visible.

The comparison is **incomplete** (`complete: false`, coded `errors`) when it
cannot determine an affected contribution:

| Code | Meaning |
| --- | --- |
| `unresolved-candidate` | A binding that the proposal affects does not resolve in the candidate (missing or untrusted content, unknown policy, unsupported policy scope, unrenderable configuration). The controller would keep the previously applied policies for it. |
| `unresolved-baseline` | The live configuration of an affected binding does not resolve, so its current contributions cannot be determined. Previously applied policies may remain enforcing. |
| `content-failed`, `content-mismatch` | The content source failed for another reason than unavailable content, or returned content for another reference. |

Unresolved contributions in the candidate are never reported as withdrawn, and
an unresolved overlap keeps exception eligibility `Forbidden` rather than
permitting exceptions. A live binding that does not resolve but that the
proposal does not touch is the `baseline-unresolved` limitation of a complete
comparison. Every comparison also carries the `rendered-input-assumptions` and
`no-workload-evaluation` limitations.

### What is compared

| Part | One entry per | Contents |
| --- | --- | --- |
| `objects` | Proposed, removed or restated profile or binding | Disposition, observed identity, `pendingIdentity`, `configurationChanged`, `storedSpec`, `reportingOnly`, configuration fingerprints, input location |
| `contributions` | Binding and logical policy whose contribution differs | Stable key, `added`/`removed`/`changed`, `revisionEffect`, observed `before` and proposed `after` sides, namespace instances added and removed, responsible inputs, impacts |
| `namespaces` | Observed namespace instance and logical policy whose applicable contributions or effective eligibility differ | Contributions added, removed, replaced and **remaining**, effective eligibility before and after |
| `appliedState` | Observed Konstapel-owned engine policy | How it relates to the live and the proposed configuration (see [Applied state](#observed-applied-state)) |

The key of a contribution is the cluster, the binding name, the observed binding
UID when the binding exists, and the logical policy. A contribution row exists
even when its binding selects no namespace. A namespace is identified by name
and UID, so a recreated namespace is another subject. Selectors are compared as
the namespaces they can select: reordered expressions or values are not a
selector change. Parameter key order is not a parameter change.

### Impact categories

Every impact has a category, an area, the before and after values where they are
short enough to state, and a reason. Categories describe what changes and in
which direction. They do not score compliance, refer to any framework, or treat a
tightening as good or a relaxation as bad.

| Category | Area | Raised when |
| --- | --- | --- |
| `contribution-added` | policy | A binding gains a contribution: a new binding, a profile that gains a policy, or a profile reference that now provides it. The row lists the observed namespaces it selects now. |
| `contribution-removed` | policy | A contribution disappears. This requests withdrawal of its engine policy after application; it is not an immediate withdrawal. |
| `profile-changed` | policy | The binding takes the same logical policy from another profile. |
| `bundle-pin-changed` | policy | The pinned bundle name or digest changes, even if the rendered rules look identical. |
| `parameters-changed` | policy | The policy's parameters change. |
| `selector-changed` | scope | The binding's namespace selector selects differently. It counts with zero matching namespaces. |
| `namespace-added` | scope | Observed namespace instances become subject to the contribution. |
| `namespace-removed` | scope | Observed namespace instances leave the contribution. Other contributions may still apply there; see `remaining`. |
| `mode-changed` | enforcement | `Audit` becomes `Deny` or the reverse. Audit never overrides an overlapping Deny contribution. |
| `revision-replaced` | enforcement | The controller would compute a new enforcement revision (see [Revision effects](#revision-effects-and-identities)). |
| `exception-rule-changed` | exception | The profile's exception settings for the policy change. |
| `eligibility-changed` | exception | The effective self-service eligibility of a namespace and policy changes across all its contributions: `Forbidden` takes precedence, even from an Audit binding, and the shortest lifetime applies. |

`impactCount` counts contribution rows and namespace rows with at least one
impact. It is not a number of workloads, failures, violations or controls.
Formatting, key order, written-out defaults, descriptive metadata and exported
server fields create no contribution or namespace row. A reporting-only binding edit
(`spec.assessment`) is listed under `objects` with `reportingOnly` and is not an
impact unless it also rotates revisions, as described below. Exception
acceptance consequences and evidence are later parts of the change and are not
part of these categories yet.

### Revision effects and identities

Observed and proposed values are kept apart. The `before` side of a contribution
carries observed values: profile UID and generation and the desired revision the
controller computes from the live configuration. The `after` side carries
configuration only. Objects that the candidate creates or changes report
`pendingIdentity: true`, because the API server assigns their UID, generation
and enforcement epoch on application.

To decide whether a revision changes, the candidate is resolved with private
provisional values: the next generation for an object whose stored
specification would change, the enforcement epoch that the
`konstapel-binding-enforcement-epoch` admission policy would assign, and a
placeholder UID for a created object. Revisions come from the controller's own
`EnforcementRevision`, unchanged. Only their equality with the observed
revision is used. Provisional UIDs, generations, revisions and engine policy
names never appear in a comparison. Each contribution reports a
`revisionEffect` instead:

| `revisionEffect` | Meaning |
| --- | --- |
| `unchanged` | The controller would compute the observed revision. Its engine policy and anything bound to it stay. |
| `replacement-required` | The controller would compute a new revision. The engine policy is replaced under a new name, and anything bound to the current revision, such as an accepted exception, no longer matches it. |
| `new` | The contribution does not exist in the live configuration. Its revision is assigned after application. |

Equal configuration fingerprints do not mean unchanged revisions. The
fingerprint is only an aid for recognizing semantically equal configuration.
The revision follows what the API server stores and what the controller
hashes:

- **Stored differently, configuration equal.** Reordered selector expressions or
  values, reordered profile policies, and respelled durations (`60m` for `1h`)
  are stored as written. The generation advances. For a profile, this rotates
  the revisions of every binding that uses it. For a binding, a reordered
  selector also advances the enforcement epoch, because the admission policy
  compares the atomic selector lists in order, and `EnforcementRevision` hashes
  the selector as written. These rows are `replacement-required` with
  `semanticallyEquivalent: true`.
- **Stored identically.** Written-out defaults, map key order and exported
  metadata or status are stored as the live object already is. The generation
  does not advance and no contribution or namespace row is created.
- **Reporting only.** A binding edit outside `profileRef`, `namespaceSelector` and
  `mode` keeps the enforcement epoch, so its revisions stay `unchanged`.
- **No observed epoch.** A binding written before the epoch policy existed has no
  `enforcementEpoch`. The preview cannot see whether the admission policy is
  installed, so it assumes the generation fallback, where every stored change
  rotates the binding's revisions. It reports `replacement-required` with the
  `enforcement-epoch-unavailable` limitation. This can overstate a replacement.
  It never reports `unchanged` where the controller would replace a policy.
- **Unknown stored specification.** If the live stored specification was not
  observed, the preview cannot show that a restatement is stored unchanged. It
  assumes that it is not.
- **Rollback.** Restoring earlier values is still a new write. The epoch or
  generation advances and the revision is new, even if an older engine policy
  with those values is still applied. That older policy is not revived (see
  below).

### Observed applied state

Engine policies are read separately from the desired configuration and
correlated through their controller ownership and recorded contribution. Their
`scope` is the observed namespaces that their own recorded selector matches now.
For a policy that is not current, this is a stale scope.

| `condition` | Relation to the live configuration |
| --- | --- |
| `current` | At the revision the live configuration desires. |
| `superseded` | An earlier revision of a logical policy that the binding still desires. Delivery keeps it until the replacement is ready, so both can enforce at the same time. |
| `held` | The binding or policy does not resolve live. The controller keeps what it last applied. |
| `not-desired` | The binding resolves but no longer desires this policy. The controller removes it on its next reconcile. |
| `withdrawing` | The owning binding is being deleted. Garbage collection removes the policy. |
| `orphaned` | No observed binding has the owner UID. The policy may enforce until garbage collection removes it. |
| `unknown` | The recorded contribution cannot be read. This is unknown state, never an absent policy. |

| `proposed` | What the candidate asks of the policy |
| --- | --- |
| `kept` | The candidate desires exactly this revision. |
| `replacement-pending` | The candidate desires another revision of the logical policy. This one stays until the replacement is ready, so old and new can overlap temporarily. |
| `withdrawal-requested` | The candidate no longer desires the policy, or removes the binding. Removal follows application and reconciliation. |
| `held` | The candidate does not resolve the policy, so the controller would keep it enforcing. |
| `not-attributable` | Orphaned, withdrawing or unreadable policies are outside what the candidate controls. |

`pending` lists live contributions that have no ready engine policy at their
revision yet. This is reconciliation lag. It is informational, as is everything
in `appliedState`. None of it is a new desired impact, and none of it shows
that enforcement has converged or been withdrawn.

### Worked examples

The live cluster has three namespaces, `prod` (`env: production`), `staging`
(`env: staging`) and `dev` (`env: development`), and one profile `shared` with
the policies `run-as-non-root` and `privileged`. Two bindings use it:
`audit-all` (Audit, selector `{}`) and `deny-prod` (Deny, `env: production`).
The proposal moves `deny-prod` to staging:

<!-- fixture: testdata/preview/examples/valid/selector-change.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: deny-prod
spec:
  profileRef:
    name: shared
  namespaceSelector:
    matchLabels:
      env: staging
  mode: Deny
```

The comparison is complete with `impactCount` 2: one contribution row for each
policy of `deny-prod`, each with `selector-changed` (`env=production` to
`env=staging`), `namespace-added` (`staging` with its UID), `namespace-removed`
(`prod` with its UID) and `revision-replaced`. The four namespace rows (`prod`
and `staging` for each policy) show `deny-prod` removed from `prod` and added
in `staging`. In each, `audit-all` stays in `remaining` with revision effect
`unchanged`. The Deny contribution leaves `prod`, but Audit still applies
there. Eligibility stays `Forbidden` everywhere, so the namespace rows carry no
impact of their own. Nothing here says that a workload in `staging` will be
admitted or rejected, or that any workload is evicted.

In a second cluster, the binding `deny` (Deny) selects `env In (production,
staging)` and `tier Exists`, in that order, and has an enforcement epoch. A
proposal that only swaps the two expressions selects exactly the same namespaces:

<!-- fixture: testdata/preview/examples/valid/reordered-selector.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: deny
spec:
  profileRef:
    name: shared
  namespaceSelector:
    matchExpressions:
      - key: tier
        operator: Exists
      - key: env
        operator: In
        values: [production, staging]
  mode: Deny
```

The object is `unchanged` with `configurationChanged: false` and the same
fingerprint as the live object. Its `storedSpec` is `different`, because the
API server stores the new order and the admission policy advances the
enforcement epoch. Each of its contributions is therefore `replacement-required`
with `semanticallyEquivalent: true` and a single `revision-replaced` impact. The
preview does not claim that nothing changes: the engine policies are replaced
and any acceptance bound to the current revisions no longer matches them.
Keeping the live order in the rendered manifest avoids the replacement.

## Not covered

The preview does not emulate server-side apply, field ownership, admission
mutation or admission validation beyond the schema rules above, and it cannot
express deleting and recreating one name in a single step. Applying the
configuration stays a separate Kubernetes or GitOps action. Bundle verification
beyond the content seam, exception acceptance impact, evidence, reports and exit
codes are later tasks of the change and are not described here as available.
