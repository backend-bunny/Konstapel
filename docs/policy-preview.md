# Policy change preview

> **Status: input model and cluster observation only.** The `konstapel preview`
> command, comparison and reporting are not implemented yet. This page documents
> the parts that exist in `internal/preview`: how rendered manifests are read and
> validated, how the candidate configuration is formed (tasks 1.1 to 1.3 of the
> `add-policy-change-preview` change), and the read-only cluster observation
> with its access contract and limits (tasks 2.1 to 2.3). No command line
> exposes either yet. Treat the planned command line in the change's
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
fingerprint identifies normalized configuration only. It is not an enforcement
revision and not an acceptance token.

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
   as its complete specification. A proposal that equals the live configuration
   is a no-op and keeps the observed object.
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

## Not covered

The preview does not emulate server-side apply, field ownership, admission
mutation or admission validation beyond the schema rules above, and it cannot
express deleting and recreating one name in a single step. Applying the
configuration stays a separate Kubernetes or GitOps action. Bundle verification,
exception impact, evidence, comparison, reports and exit codes are later tasks of
the change and are not described here as available.
