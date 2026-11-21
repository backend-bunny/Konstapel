# Policy change preview

> **Status: the `konstapel preview` command, its JSON report v1 and its exit
> statuses are implemented, including evidence context, but without
> exception-acceptance consequences.** Those depend on the exception owner
> (`add-policy-change-preview` 5.1). Until then the exceptions part states
> `not-available`, and a preview whose proposal changes the namespace and
> policy of an observed ComplianceException is **incomplete** (exit status 1)
> rather than claiming that no acceptance is affected. See
> [Command line](#command-line), [Report](#report-json-v1),
> [Exit status](#exit-status) and [Local and CI use](#local-and-ci-use). The
> rest of this page describes the parts underneath: how rendered manifests are
> read and validated, how the candidate configuration is formed, the read-only
> cluster observation with its access contract and limits, the semantic
> comparison with its impact categories, and verified bundle content under the
> caller's access.

The preview is meant to show how proposed compliance configuration would change
namespace coverage, enforcement and accepted risks before GitOps applies it. It
describes configuration effects. It does not evaluate workloads, predict
admission, or promise that existing workloads pass a new policy.

## Command line

```text
konstapel preview -f FILE [-f FILE ...] [--before FILE ...] [flags]
```

`preview` is dispatched before every other `konstapel` command and shares none
of their startup: it starts no controller manager, C2P provider, policy
delivery, metrics server or leader election, and it never writes to the
cluster (see [Cluster access](#cluster-access)). `konstapel preview -h` prints
the flags.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-f`, `--file` | required, repeatable | Proposed rendered manifests; `-` reads standard input (at most one stream across all flags) |
| `--before` | none, repeatable | The previous rendered set: identities in it and absent from the proposed files are removed |
| `--kubeconfig` | `$KUBECONFIG`, then `~/.kube/config` | The caller's kubeconfig. There is no in-cluster fallback |
| `--context` | the current context | The kubeconfig context, recorded in the report |
| `--controller-namespace` | `konstapel-system` | The controller's namespace (its `POD_NAMESPACE`), as the charts install it |
| `--bundle-sources-configmap` | not given | The controller's `--bundle-sources-configmap`; give it explicitly, empty (`--bundle-sources-configmap=`) for a controller without bundle sources (see [Bundle-source selection](#bundle-source-selection)) |
| `--controller-version` | this binary's release | Controller release (SemVer) for OCI bundle compatibility checks |
| `--content-root` | `/usr/share/konstapel/content` | The vendored content tree, as in the image; use `content` in a checkout |
| `--bundle-cache-dir` | a temporary directory | Verified OCI bundle cache kept between previews (one preview at a time); needs `--bundle-sources-configmap` |
| `--format` | `text` | `text` or `json` |
| `-o`, `--output` | `-` (standard output) | Write the report to a file instead |
| `--fail-on-impact` | off | Exit 2 when a complete preview has policy impacts |
| `--timeout` | `60s` | Total time for the preview, observation recaptures included |

Invalid flags print a message on standard error and exit 1 without
contacting the cluster. Once the flags are valid, every later problem
(invalid manifests, kubeconfig, observation, content, comparison) is a coded
error of an incomplete report, written in the requested format. Standard
output carries only the report; progress and diagnostics go to standard
error.

## Report (JSON v1)

`--format json` writes one JSON document, `kind: PolicyChangePreview` with
`schemaVersion: 1`, independent of the consumed contract versions, which are
recorded in `observation.contracts`. The text format renders the same model:
a report decoded from saved JSON renders to the same text. The report contains
capture times only, no rendering time and no random identifiers, and every list
has a stable order, so the same captured inputs give the same bytes.

<!-- report-fields -->
| Field | Meaning |
| --- | --- |
| `kind`, `schemaVersion` | The report contract |
| `complete` | `true` only when the observation, content resolution and comparison finished without any error. Only a complete report supports a statement that no impact exists |
| `impactCount` | Contribution and namespace rows with at least one impact (see [Impact categories](#impact-categories)); in an incomplete report, only what was determined. Not a number of workloads, failures or controls |
| `summary` | Row counts, `reportingOnlyObjects`, `equivalentReplacements` and impacts per category |
| `observation` | Cluster identity, context, API server host, controller namespace, selected sources and assumed controller release, capture window, captures and drift, collections with their resourceVersions, every object's UID, resourceVersion and generation, namespace instances, observed source configuration. `null` when nothing was observed |
| `inputs` | Every input stream with its role and the sha256 of its bytes, and every validated object with its location and configuration fingerprint |
| `content` | Every pinned bundle read, with `digestKind` (see [Digest meanings](#digest-meanings)) |
| `changes` | `objects`, `absentRemovals`, `contributions` and `namespaces` of the [comparison](#what-is-compared). `null` when no comparison ran: undetermined, never empty |
| `appliedState` | [Observed applied state](#observed-applied-state), informational. `null` when no comparison ran |
| `exceptions`, `evidence` | [Exceptions and evidence](#exceptions-and-evidence): acceptance consequences, and evidence context of the observed bindings the proposal involves |
| `limitations` | Coded informational bounds, each with its `stage` |
| `errors` | Coded problems that make the report incomplete, each with its `stage` (`input`, `kubeconfig`, `observation`, `content`, `comparison`, `exceptions`) and location |

A CI job can therefore tell policy impacts (`impactCount`, `changes`),
informational bounds (`limitations`) and fatal problems (`complete: false`,
`errors`) apart without reading prose. Fields may be added within version 1;
a change of meaning or a removal needs a new `schemaVersion`.

Rows whose configuration is semantically equivalent but whose enforcement
revision is still replaced (`semanticallyEquivalent: true` with
`revisionEffect: replacement-required`, for example reordered selector
expressions or profile policies) count as impacts: the engine policies are
really replaced and any acceptance bound to their revisions no longer matches.
`summary.equivalentReplacements` counts them, and the text marks each one.

### Exceptions and evidence

The acceptance comparison of the exception owner is not integrated yet, so
the exceptions part reports `analysis: not-available` with a reason, and its
`consequences` are always empty. That emptiness never means "nothing
affected":

- `exceptions.observed` is the number of ComplianceExceptions in the complete
  observation. Each one in a namespace and policy that a changed contribution
  or namespace row touches is listed under `potentiallyAffected` with the
  responsible contribution keys, and adds the error
  `exception-impact-undetermined`: the report is incomplete, because whether it
  needs renewal, becomes forbidden or loses scope is not known. An exception
  elsewhere cannot be affected by the proposal, because acceptance depends only
  on the contributions of its own namespace and policy. Every compared report
  also carries the `exception-analysis-unavailable` limitation.

Evidence is context, never an impact: it never makes a report incomplete,
never counts in `impactCount`, and never changes the exit status. A compared
report has `evidence.analysis: available` (without a comparison it stays
`not-available` and empty). It is built from two contracts of their owners:

- The subjects are `targeting.ExpectedEvidence` of the observed
  configuration: one per contribution and namespace instance (by UID), with
  the revision the controller computes from the live configuration. These are
  the subjects the assessment collector expects evidence for. A policy or
  binding whose observed configuration does not resolve, or that the
  controller cannot render, is a stale scope instead.
- The evidence is the assessment owner's current evidence,
  `status.assessment.current` of each ComplianceBinding, read with the binding
  in the final capture (no extra request and no extra permission). The owner
  writes it after its own attribution rules (results that name the engine
  policy, its revision and the workload, evaluated after the workload's
  continuity boundary and within `maxEvidenceAge`) and its freshness rules.
  The preview does not re-run attribution: it reads no engine report and no
  workload. Because the owner rewrites this status whenever evidence changes,
  it is not part of the rechecked projections (see
  [Consistency and limits](#consistency-and-limits)).

`evidence.bindings` lists every observed binding the proposal involves (it has
a contribution row, or the proposal restates or removes it) with the owner's
counts and times as recorded (`evaluatedAt`, `oldestEvaluation`,
`nextExpiry`, and the number of the owner's limitation messages, which are not
copied), its `expectedSubjects` and `staleScopes`, and a `state` judged at the
end of the observation, in this order:

| `state` | Meaning |
| --- | --- |
| `missing` | No current evidence is recorded: continuous assessment is not installed or has not evaluated the binding yet |
| `stale` | The owner's `nextExpiry` passed by the end of the observation |
| `unattributable` | The record cannot describe the observed revisions: it does not match the supported contract, the targeting controller has not observed the binding's current generation, part of the observed configuration is a stale scope, the counts do not add up, or the owner evaluated no targets while subjects are expected |
| `no-targets` | The owner evaluated an empty scope and none is expected. Not a pass |
| `incomplete` | Fresh and consistent, but some expected observations lack attributable evidence; the owner's status does not say which |
| `current` | Fresh, consistent and `Complete`: every expected observation of the binding is attributable |

`evidence.entries` has one entry per subject of those bindings, plus one per
subject that only the proposal has (a new contribution or a newly targeted
namespace):

| Field | Meaning |
| --- | --- |
| `key`, `namespace` | Contribution and namespace instance |
| `state` | The binding's state for the observed revision, or `not-observed` for a subject only the proposal has |
| `observedRevision` | The observed enforcement revision; absent for `not-observed` |
| `evaluatedAt` | Only for `current`: the binding's oldest source evaluation, so this subject was evaluated at or after it |
| `proposed` | `unchanged` (the proposal keeps the revision, so the evidence describes it too), `not-evaluated` (a new or replaced revision: nothing has evaluated it), or `withdrawn` (the subject leaves the proposal) |

Existing results are never attached to a proposed revision: an entry whose
`proposed` is `not-evaluated` describes evidence of its observed revision
only, as historical context, and the `evidence-not-evaluated` limitation
counts those subjects. The owner records current evidence per binding, not
per revision or namespace, so every subject carries its binding's state, and
an owner evaluation still pending right after a binding change is not visible
(`evidence-per-binding`). Each binding in another state than `current` or
`no-targets` adds the limitation `evidence-missing`, `evidence-stale`,
`evidence-unattributable` or `evidence-incomplete`. None of them is an error.
By contrast, an exception input the preview needs but cannot obtain (a denied
or unserved exception or snapshot read, or an exception whose consequence is
undetermined, above) makes the report incomplete.

## Exit status

| Outcome | Default | `--fail-on-impact` |
| --- | --- | --- |
| Complete, no policy impacts (reporting-only edits and missing, stale or unattributable evidence included) | 0 | 0 |
| Complete, policy impacts | 0 | 2 |
| Invalid flags or inputs, failed or incomplete preview, or a report that cannot be written | 1 | 1 |

Failure takes precedence: an incomplete preview exits 1 even when it found
impacts and `--fail-on-impact` is set. A report that cannot be written (a
closed pipe, a full disk, an unwritable `--output`) exits 1 as well. The
exit status of every other `konstapel` command is unchanged.

## Local and CI use

The examples below run against a cluster with the namespaces `prod`
(`env: production`) and `staging` (`env: staging`), one profile `baseline`
with two vendored policies, and two bindings that use it: `audit-all`
(Audit, every namespace) and `deny-prod` (Deny, `env: production`). They
use a binary built from a checkout (`devbox run -- task build`), hence
`--content-root content`; the image's binary needs no `--content-root`.
The reader permissions are in
[`reader-rbac.yaml`](examples/policy-preview/reader-rbac.yaml).

<!-- preview-files: proposed.yaml=testdata/preview/cli/proposed.yaml previous.yaml=testdata/preview/cli/previous.yaml -->

The proposal moves `deny-prod` to staging:

<!-- fixture: testdata/preview/cli/proposed.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: deny-prod
spec:
  profileRef:
    name: baseline
  namespaceSelector:
    matchLabels:
      env: staging
  mode: Deny
```

### Local preview

A local preview is informational and exits 0 when it is complete:

<!-- preview-run: exit=0 -->
```sh
bin/konstapel preview -f proposed.yaml --context staging --content-root content
```

An excerpt of the text report:

<!-- preview-output -->
```text
Result: complete, 2 policy impacts
...
    binding deny-prod (uid b-deny-prod) policy disallow-privileged-containers: changed, revision replacement-required
...
      selector-changed [scope] env=production -> env=staging: the namespace selector changes
...
    prod (ns-prod) policy disallow-privileged-containers
      removed: deny-prod Deny
      remaining: audit-all Audit, unchanged
```

The Deny contribution leaves `prod`, but `audit-all` still applies there.
Nothing says that a workload will be admitted, rejected or evicted.

### CI

In CI, render the previous and the proposed configuration (for example the
target branch and the pull request) into two files, and let the preview
declare the removals between them. Here the previous set also had
`audit-all`, which the proposal no longer contains:

<!-- fixture: testdata/preview/cli/previous.yaml -->
```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: deny-prod
spec:
  profileRef:
    name: baseline
  namespaceSelector:
    matchLabels:
      env: production
  mode: Deny
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: audit-all
spec:
  profileRef:
    name: baseline
  namespaceSelector: {}
  mode: Audit
```

Start informational: save the JSON report as a job artifact and fail the job
only when the preview is incomplete (exit 1):

<!-- preview-run: exit=0 -->
```sh
bin/konstapel preview --before previous.yaml -f proposed.yaml \
  --context production --content-root content \
  --format json --output preview.json
jq -e '.complete' preview.json
jq '{impactCount, categories: .summary.categories, errors: [.errors[].code]}' preview.json
```

Once the team reviews every impact, gate on it. Exit 2 means a complete
preview with impacts, exit 1 an invalid, failed or incomplete one:

<!-- preview-run: exit=2 -->
```sh
bin/konstapel preview --before previous.yaml -f proposed.yaml \
  --context production --content-root content \
  --format json --output preview.json --fail-on-impact
```

These commands, the excerpt and the saved report are verified by
`TestDocumentedPreviewCommands` in `cmd/konstapel` against a recording API
server with exactly this cluster. In that test the context names reach it
through `KUBECONFIG`.

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
controller namespace (`--controller-namespace`, default `konstapel-system`) and,
when the controller runs with `--bundle-sources-configmap`, the same ConfigMap
name (see [Command line](#command-line)).

### Cluster access

The observation sends only `GET` requests: API discovery, `get` and `list`. A
guard in the client refuses anything else before it is sent, including writes,
server-side dry-run, `SelfSubjectAccessReview`-style authorization probes and
watches (the `watch` parameter and the legacy `/watch/` paths). The only Secret
request it lets through is a plain `get` of one named Secret in the controller
namespace that the observed bundle-source configuration references; a Secret
list (in a namespace or across all), a watch, a subresource, a query, another
namespace and every unreferenced name are refused. Tests run the observation
against a recording API server and a disposable cluster and check that no
other request occurs.

| Resource | API group | Where | Verbs | Read for |
| --- | --- | --- | --- | --- |
| `namespaces` | core | cluster | `get` (`kube-system`), `list` | Cluster identity (`kube-system:<uid>`, as the controller records it); namespace instances (name, UID, labels) |
| `complianceprofiles`, `compliancebindings` | `compliance.erenius.io` | cluster | `list` | Live desired configuration, including every binding of a shared profile; the bindings' `status.observedGeneration` and `status.assessment.current` for [evidence](#exceptions-and-evidence) |
| `complianceexceptions` | `compliance.erenius.io` | all namespaces | `list` | Protected acceptance records and snapshot references |
| `validatingpolicies` | `policies.kyverno.io` | cluster | `list`, label `app.kubernetes.io/managed-by=konstapel` | Applied engine policies, their recorded contribution and readiness |
| `configmaps` | core | controller namespace | `list` (acceptance snapshots, by label); `get` (the bundle-source ConfigMap and the trust ConfigMaps it names) | Frozen acceptance snapshots; source and trust configuration |
| `secrets` | core | controller namespace | `get`, only the names the bundle-source ConfigMap references (optional) | Registry credentials and Secret-held trust material of private bundle sources |
| discovery | `/api/v1`, `/apis/compliance.erenius.io/v1alpha1`, `/apis/policies.kyverno.io/v1` | | `GET` | Required APIs are served (granted to authenticated users by `system:discovery`) |

A bundle source's `credentialSecret` and its Secret-held trust references
(`ca`, `publicKey` or `trustRoot` of kind `Secret`) are read by name with the
caller's own identity, never listed. Their identity and access outcome
(`read`, `missing` or `denied`) are reported; their values are held in memory
for [bundle content](#bundle-content) only and never appear in a report,
diagnostic, error or log. A Secret the caller may not read is the
`secret-not-read` limitation, and any content that needs it makes the
comparison incomplete (`content-access-denied`). A ready-made ClusterRole and
Role with exactly these permissions, plus the optional Role
`konstapel-policy-preview-bundle-secrets` with `get` on the named Secrets of a
private source, is in
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
acceptance records and snapshots, and source and trust data, including the
referenced values of Secrets (compared as a digest keyed per run, so not even
a digest of a credential leaves the process). Status timestamps,
report times and unrelated annotations are ignored, so constantly changing
status does not force retries. The bindings' recorded current evidence is
informational and taken from the final capture without a recheck. If a
relevant projection changed, or a list continuation expired, the whole capture
is repeated, at most two recaptures.
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
| `content-access-denied` | The caller may not read a Secret that the bundle's source references. Raised for every pinned bundle of that source, whether or not the proposal touches the bindings that pin it. |
| `content-unavailable` | A live binding that the proposal does not touch pins content the preview could not read for a reason that depends on where it runs (retrieval, missing proofs, the cache, or this installation's vendored tree). Whether the controller resolves it is not observed, so its overlap is unknown. |

Unresolved contributions in the candidate are never reported as withdrawn, and
an unresolved overlap keeps exception eligibility `Forbidden` rather than
permitting exceptions. A live binding that does not resolve but that the
proposal does not touch is the `baseline-unresolved` limitation of a complete
comparison when the reason is the observed configuration itself: a missing
profile, an unknown policy, an unsupported scope, or content that the
observed sources and trust refuse (no configured source, untrusted,
incompatible, a digest mismatch, malformed). The controller reaches the same
verdict. A content failure that depends on the preview's own environment is
`content-unavailable` instead. Every comparison also carries the `rendered-input-assumptions` and
`no-workload-evaluation` limitations.

### What is compared

| Part | One entry per | Contents |
| --- | --- | --- |
| `content` | Pinned bundle read | Name, digest and `digestKind` (see [Digest meanings](#digest-meanings)), the configured repository, whether it resolved under current trust, and the bounded error class and text |
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
acceptance consequences and evidence are not part of these categories (see
[Exceptions and evidence](#exceptions-and-evidence)).

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
  `mode` keeps the enforcement epoch, so its revisions stay `unchanged`, and an
  exception accepted for them stays bound to them. The classification is the
  assessment owner's: the `enforcementChanged` expression of the
  `konstapel-binding-enforcement-epoch` admission policy, which the CRD's
  transition rule enforces independently. The owner ships it as CEL only, so
  the preview applies it through a Go equivalent that the tests evaluate
  against both the policy's own expression and the CRD rule.
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

## Bundle content

The comparison reads bundle content through the controller's own content
source, assembled without a manager, a provider subprocess or any watcher
(`OpenContent` in `internal/preview`):

- The **vendored bundle** (the controller's `konstapel-vendored` name) is served
  by `targeting.LocalContent` from this installation's content tree. Every read
  checks every file against `SHA256SUMS`; a changed or missing file fails, and
  nothing is served from a corrupted tree.
- **Every other name** goes through the bundle owner's stack
  (`internal/bundle/stack`), routed exactly as the controller routes it: the
  central source mapping, the exact-digest resolver, the current-trust
  verifier (signature and provenance under the source's publisher rule), the
  content cache and the Secret-backed registry credential and CA provider.
  There is no unsigned, unverified or substituted fallback. See
  [Policy bundles](policy-bundles.md) for the trust model.

### Bundle-source selection

Name the controller namespace and, when the controller runs with
`--bundle-sources-configmap`, the same ConfigMap. The preview uses that
configuration as observed; proposed manifests can never replace sources,
publisher rules, trust material or credentials. Without a selected ConfigMap
only the vendored bundle resolves, like a controller without bundle sources,
and an OCI pin is unavailable with error class `Config`. A missing or invalid
ConfigMap makes every OCI bundle unavailable, as it would for the controller.

The bundle stack is not given a Kubernetes client. It is served the values
that the observation read and rechecked: the source document, the trust
ConfigMaps and the referenced Secrets. So it sends no request of its own, and
what it verifies against is the observed state, drift-checked like the rest of
the snapshot. Registry requests go from where the preview runs to the
configured repository, with the configured CA and the credential from the
referenced Secret. Local Docker credentials, node or kubelet credentials and
the controller's ServiceAccount are never used.

Bundle compatibility is checked against a controller release that the caller
supplies (the `controller-version-assumed` limitation): the running
controller's release is not observed. `--controller-version` defaults to the
release of the `konstapel` binary itself, so a preview run with the
controller's own release needs no flag. A development build (`dev`) is not
SemVer: with a bundle-source ConfigMap named, the command then refuses to
start until `--controller-version` names the controller's release.

The preview cannot see the controller's flags, and reading its Deployment
would widen the reader permissions, so it does not guess. When
`--bundle-sources-configmap` is not given at all and an observed or proposed
profile pins any bundle other than the vendored one, the report is incomplete
with `bundle-sources-required`. Pass the controller's ConfigMap name, or an
explicitly empty value (`--bundle-sources-configmap=`) for a controller that
runs without bundle sources.

### Required caller access

| Source | Access the caller needs |
| --- | --- |
| Vendored bundle only | The [observation permissions](#cluster-access) |
| Public OCI source (no `credentialSecret`, ConfigMap trust) | The observation permissions; network access to the registry |
| Private OCI source | Also `get` on each referenced Secret by name (`konstapel-policy-preview-bundle-secrets` in the reader RBAC example), and network access to the registry |

A referenced Secret the caller may not read is never replaced by the
controller's access, an anonymous request or an earlier value. Its bundles are
`content-access-denied` and the comparison is incomplete. The report names the
Secret and never carries its value, the API server's message or a registry
response.

### Digest meanings

| `digestKind` | The pinned digest identifies |
| --- | --- |
| `vendored-checksum-manifest` | The sha256 of the vendored tree's `SHA256SUMS`, which lists every vendored file's checksum. It is not an OCI digest and changes with any vendored file of the release. |
| `oci-manifest` | The OCI image manifest of a bundle in the configured repository. Its config, layer and proofs are verified against it. |
| `unknown` | Only for a content source that does not say how it interprets names (test doubles); a digest is never labelled as the other kind. |

The vendored digest the preview serves is that of its own installation. A
profile pinned to the vendored digest of another release is unavailable to
it, and the comparison is incomplete rather than assuming the controller's
image serves it.

### Cache and trust

`--bundle-cache-dir` (`ContentOptions.CacheDir`) keeps verified content between
previews; without it a temporary directory is used and removed afterwards. The cache is owned by one process at a
time. Cached content is reused only after it is verified again under the
trust observed now, with its retained proofs, so a warm cache serves through a
registry outage, while content cached under a key that the publisher rule no
longer trusts is refused.

### Trust and content errors

Each `content` record carries the bundle owner's error class. An affected
binding whose content fails is `unresolved-candidate` or `unresolved-baseline`
and makes the comparison incomplete.

| Class | Meaning | Untouched live binding |
| --- | --- | --- |
| `Untrusted` | No proof satisfies the publisher rule now: unsigned, another signer, tampered proofs or provenance, or trust that changed since the content was cached | `baseline-unresolved` limitation |
| `Config` | No usable source for the name (none selected, missing or invalid configuration, or publisher trust material that cannot be read) | `baseline-unresolved` limitation |
| `Incompatible`, `DigestMismatch`, `Malformed` | The content does not fit the given controller release, is not exactly the pin, or is not readable policy content | `baseline-unresolved` limitation |
| `ContentUnavailable`, `ProofUnavailable` | The content or its proofs could not be retrieved (not in the repository, registry down or refusing the credential, bytes that do not match the pinned digest) | `content-unavailable` error |
| `Capacity`, `Stale`, `Unresolved`, none | A cache, concurrency or vendored-tree failure | `content-unavailable` error |

A denied referenced Secret adds `content-access-denied` to any of these.

### Private-source workflow

1. Create the controller's private source as in
   [Private registry setup](policy-bundles.md#private-registry-setup): the
   sources ConfigMap, the registry credential Secret, the CA ConfigMap and the
   publisher key Secret in the controller namespace.
2. Bind the reader ClusterRole and Role of
   [`reader-rbac.yaml`](examples/policy-preview/reader-rbac.yaml) to the
   identity that runs previews, and the
   `konstapel-policy-preview-bundle-secrets` Role with your Secret names.
3. Preview with `--controller-namespace` and `--bundle-sources-configmap` set
   to the controller's namespace and sources ConfigMap name. The
   bundles of that source are read with the referenced credential, verified
   under its publisher rule and reported with `digestKind: oci-manifest`.

`TestLivePolicyPreviewPrivateBundle` (the `bundles` acceptance group) runs
this workflow on a disposable cluster against the bundle owner's
organization-key fixture in a disposable TLS and htpasswd registry, with
exactly the documented names: complete with the Secret Role, and
`content-access-denied` without it.

## Not covered

The preview does not emulate server-side apply, field ownership, admission
mutation or admission validation beyond the schema rules above, and it cannot
express deleting and recreating one name in a single step. Applying the
configuration stays a separate Kubernetes or GitOps action. Exception
acceptance consequences are not analyzed yet; the report says so instead of
describing them. Evidence is the assessment owner's recorded current evidence
of the observed configuration; the preview evaluates no workload, reads no
policy report, retrieves no archived evidence and schedules no assessment (see
[Exceptions and evidence](#exceptions-and-evidence)).
