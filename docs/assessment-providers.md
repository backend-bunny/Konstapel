# Assessment providers

An assessment provider is the in-tree code that turns one kind of external
evidence into Konstapel check outcomes. Kyverno (ValidatingPolicy delivery
and PolicyReport evidence) is the only installed provider. This guide covers
the provider contract from
[`add-assessment-provider-contract`](../openspec/changes/add-assessment-provider-contract/proposal.md).

**Status.** Group 1 of that change is implemented: the installed-provider
descriptor and registry, the selection checks, and the conformance harness
with its versioned fixtures. Task 2.1 is implemented too: the controller's
Kyverno assessment path now reaches PolicyReports through a narrow
collection adapter ([Inventory and collection](#inventory-and-collection)).
Task 2.2 derives each installed provider's availability, and its evidence
watches, from its descriptor ([Availability](#availability)). Task 2.3
bounds every collection with host-owned deadlines, cancellation and
resource limits ([Collection limits](#collection-limits)), which an
operator can raise or lower with controller flags, and task 2.4
documents the [capabilities and permissions](#capabilities-and-permissions)
of each provider. Task 3.1 adds the provider-discriminated capture
boundary and its version checks ([Captures](#captures)). The storage
backend reads every package capture through it, and nothing the controller
writes changes. Task 3.2 connects captures to the run's content set
([Run content](#run-content)): the controller and the exporter derive a
Kyverno capture's applied content through it, with unchanged results.
Task 3.3 adds the shared namespace projection check and provider-specific
extraction ([Namespace projection](#namespace-projection)). Every namespace
package's capture and evaluation pass that check before export, summaries
and archiving. Task 4.1 routes evaluation through
[pure evaluators](#pure-evaluators), and task 4.2 connects continuous
export and the C2P plugin to one conversion of the frozen snapshot
([C2P conversion](#c2p-conversion)), with unchanged packages.
Within the collection limits, nothing in this guide
changes how existing bindings, profiles, delivery, collection, evaluation
or export behave:

- The bundle compatibility check (`content.Compatibility`, allowlist
  `konstapel-kyverno/v1`) and the targeting resolver still make the
  production decisions.
- The registry encodes those decisions, and tests keep the two in
  agreement.
- The registry does not yet gate the resolver.

Task 4.4 adds the [worked authoring recipe](#authoring-a-provider), with
the commands that check each step, and states which parts are
[versioned contracts, internal Go interfaces and supported producers](#contracts-interfaces-and-producer-support).
No Trivy or other producer is supported. See
[What this contract does not establish](#what-this-contract-does-not-establish).

## Registration is code, not data

Providers are registered by compiling a descriptor into the binary.
`internal/provider/installed.Registry()` is the production registry: a fixed
list that today contains only `kyverno.Descriptor()`. There is no runtime
registration API, plugin directory, provider CRD or configuration flag.

Verified bundle content can only name a provider contract
(`compatibility.provider` in `bundle.json`, for example
`konstapel-kyverno/v1`) and check definitions of kinds that a provider owns.
Selection looks those names up in the registry. Bundle content therefore
cannot:

- install, download or select an executable, Go module, command path or
  plugin manifest. A contract is `name/vN` and nothing else. A value such as
  `./konstapel-provider` is an `InvalidSelection`, never a path.
- add a provider, a check kind, a mode or a parameter contract.
- change a provider's declared reads or prerequisites, the controller's
  RBAC or its capability requirements. These come from the descriptor in
  code, the Helm chart and `internal/capability`.

The C2P plugin binary `konstapel-provider` and its manifest are build
outputs (`scripts/build.sh`). They are not bundle content. The pinned C2P-Go v2
packaging stays authoritative.

## The descriptor

`provider.Descriptor` is the versioned capability contract of one installed
provider:

| Field | Meaning |
| --- | --- |
| `name`, `version` | Identity. The contract `name/v<version>` is what bundles select. A registry holds one version per name. Requesting another version of an installed provider is `IncompatibleVersion`, never adapted. |
| `evaluatorVersion` | Version of the evaluation semantics. It is separate from the contract version and the capture version. |
| `checks[]` | Check kinds (`group/version/Kind` of the check definition in content). Each kind belongs to exactly one installed provider. |
| `checks[].delivery` | `true` when the delivery owner renders engine resources for the kind (enforcement-capable). `false` is reporting-only: no engine policy, scanner job or workload write, and only `Audit`. |
| `checks[].modes` | Binding modes the kind accepts. `Deny` requires `delivery`. |
| `checks[].parameters` | `Content`: the bundle declares a schema per check and delivery decides whether it renders parameters. `Descriptor`: a schema in the descriptor. `None`: no parameters. |
| `capture` | Capture payload versions it `write`s and `read`s. `write` must be in `read`, so readers ship before writers. A capture document's own format version is a separate number ([Captures](#captures)). |
| `reads[]` | External evidence-source operations its collection performs: the resource, its `kind` and whether it is `namespaced`, and read-only verbs (`get`, `list`, `watch`). A collection adapter can list only these ([readers](#narrow-readers)). Each read is also an availability prerequisite: served in that shape, and allowed ([Availability](#availability)). |
| `requires[]` | APIs the evidence source must serve, in the same shape and with read-only discovery verbs, that collection never reads. Discovery checks them. No access is reviewed and no reader is granted. |
| `testOnly` | A synthetic provider. Never in the production registry, and never a registry default. |

`provider.New` rejects these registries:

- an invalid descriptor
- a provider name registered twice
- a check kind claimed by two providers
- a write verb in `reads`, a read without its kind, or a read declared twice
- a prerequisite with a write verb or without its kind, or one declared
  twice or also declared as a read
- a reporting-only kind that accepts `Deny`
- a descriptor schema that is not a self-contained object schema
- an unreadable capture writer
- a default that is missing or test-only

The installed Kyverno descriptor, as `TestDocumentedExamples` checks it
against `kyverno.Descriptor()`:

<!-- verified: kyverno-descriptor -->
```json
{
  "name": "konstapel-kyverno",
  "version": 1,
  "evaluatorVersion": 1,
  "checks": [
    {
      "kind": "policies.kyverno.io/v1/ValidatingPolicy",
      "delivery": true,
      "modes": ["Audit", "Deny"],
      "parameters": {"source": "Content"}
    }
  ],
  "capture": {"write": 2, "read": [1, 2]},
  "reads": [
    {
      "group": "wgpolicyk8s.io",
      "version": "v1alpha2",
      "resource": "policyreports",
      "kind": "PolicyReport",
      "namespaced": true,
      "verbs": ["get", "list", "watch"]
    }
  ],
  "requires": [
    {
      "group": "wgpolicyk8s.io",
      "version": "v1alpha2",
      "resource": "clusterpolicyreports",
      "kind": "ClusterPolicyReport",
      "namespaced": false,
      "verbs": ["get", "list", "watch"]
    }
  ]
}
```

Notes on the Kyverno entry:

- `capture.read` covers the prototype's single-policy capture (1) and the
  controller's CaptureV2 (2), exactly the versions `collector.CaptureVersion`
  accepts. The controller writes 2. The capture envelope (document
  version 3) is not a Kyverno payload version: it can hold payload 2.
- `reads` lists only the evidence source. The host owns namespace and
  workload listing for the expected inventory. ValidatingPolicy writes
  belong to delivery (`capability.Delivery`), not to evidence collection.
- `requires` names ClusterPolicyReports, which the same reports API serves
  and the collector never reads.
- Together they are the assessment capability:
  `capability.Requirements[Assessment]` is derived from them
  ([Availability](#availability)).
- `reads` document and bound the provider's own access. They are not a
  sandbox: adapters are trusted in-tree code, and the controller service
  account's RBAC is shared and broader. Do not read a descriptor as
  per-provider security isolation.
- Parameters keep today's behavior. A policy's bundle schema validates them,
  and delivery does not render parameters yet, so any non-empty parameters
  are rejected, never dropped.

The production registry's contracts:

<!-- verified: installed-contracts -->
```json
["konstapel-kyverno/v1"]
```

## Selection

`Registry.Select` checks one binding's request: one provider, one mode and
the profile's checks. It returns a `Plan` or every reason for rejecting the
selection. A rejected selection has no plan, so nothing is applied in part. A
rejection never affects another binding's selection. The check is pure: no
cluster, registry or file access.

- **Implied provider.** An empty provider means the registry default,
  `konstapel-kyverno/v1`. Every existing bundle names that contract
  explicitly, and both forms resolve identically.
  `TestDefaultSelectionMatchesTheResolver` checks the default selection
  against the targeting resolver over the resolver fixtures and an exhaustive
  mode × scope × parameter matrix.
- **One provider per binding.** Checks whose kinds belong to more than one
  provider, or to a provider other than the selected one, are
  `MixedProviders`. Overlapping bindings over the same namespace stay
  independent selections: a reporting Audit binding never weakens a Kyverno
  Deny binding.

Each reason maps to an existing ComplianceBinding condition reason
(`SelectionReason.BindingReason`). Surfacing selection errors therefore needs
no new API reason:

| Reason | Meaning | Binding reason |
| --- | --- | --- |
| `UnknownProvider` | No installed provider has that name. | `ContentUnavailable` (content `Incompatible`, as today) |
| `IncompatibleVersion` | The provider is installed at another contract version, cannot read the capture version, or does not evaluate with the recorded evaluator version. | `ContentUnavailable` |
| `UnsupportedCheck` | No installed provider evaluates the check kind. | `UnsupportedScope` (as for an unsupported policy type today) |
| `MixedProviders` | The checks span providers, or belong to another provider. | `InvalidConfiguration` |
| `UnsupportedMode` | The kind does not accept the mode (`Deny` for reporting-only). | `InvalidConfiguration` |
| `InvalidParameters` | The parameters violate the check's contract. | `InvalidConfiguration` |
| `InvalidSelection` | No checks, a repeated check, an invalid mode or a malformed contract. | `InvalidConfiguration` |

Example: a `Deny` selection for `konstapel-kyverno/v1` with two checks. The
first is `disallow-privileged-containers` (a ValidatingPolicy) with the
parameters `{"allowPrivileged":true}`. The second is `image-vulnerabilities`
of kind `scanner.example.io/v1/ImageReport`. The selection is rejected:

<!-- verified: rejected-selection -->
```json
[
  {
    "reason": "InvalidParameters",
    "check": "disallow-privileged-containers",
    "message": "policy \"disallow-privileged-containers\" does not accept parameters"
  },
  {
    "reason": "UnsupportedCheck",
    "check": "image-vulnerabilities",
    "message": "no installed provider evaluates \"scanner.example.io/v1/ImageReport\""
  }
]
```

A selection that names a provider this build does not contain:

<!-- verified: unknown-provider -->
```json
[
  {
    "reason": "UnknownProvider",
    "message": "provider example-scanner/v1 is not installed (installed: konstapel-kyverno/v1)"
  }
]
```

`Registry.CheckCapture(contract, version)` answers whether a retained capture
can be read, and `Registry.CheckEvaluator(contract, version)` whether it can
be evaluated with the evaluator it records. Neither falls back to another
provider or version. The capture boundary uses both ([Captures](#captures)).

## Inventory and collection

The host owns scope. A provider derives expected observations from what
the host froze, and reads its own evidence source inside that scope. It
never decides which namespaces, workloads or checks are expected. For a
Kyverno snapshot (`AssessmentReconciler.snapshotContent`, used by current
status and by every run poll), the steps are:

1. Targeting resolves the binding's subjects. The host reads the binding's
   delivered engine policies, verifies them against their content, and adds
   still-applied revisions. An undelivered or drifted policy is stale
   scope, not a subject.
2. `collectionScope` takes the subjects' namespace instances, in name
   order, and the resources they match. This is the `provider.Scope`.
3. `listWorkloads` lists each collected resource in each scope namespace.
   This is a host read, not a provider read. A resource the controller does
   not collect becomes the limitation `resource … is not collected`. Its
   subject is unsupported and gets no expected observation.
4. If the assessment capability is available, `kyverno.Collect` lists
   PolicyReports through the narrow readers described below, under the
   host's [collection limits](#collection-limits).
5. `kyverno.Inventory` derives the expected inventory from the host input
   alone (`collector.FreezeScope`, unchanged). Reports are attached
   afterwards and are evaluated unchanged by `kyverno.Evaluate` at an explicit
   time (see [pure evaluators](#pure-evaluators)).

What `kyverno.Collect` does:

- It lists each scope namespace, in scope order, page by page. It
  returns the reports unevaluated and unfiltered. The evaluator attributes
  results by workload UID, engine policy and validation index. A report about
  another workload, a replaced workload or an unsupported resource
  establishes nothing.
- A shared result that names several workloads credits each of them once.
- A failed list ends collection with the limitation
  `policy reports unavailable: <error>`. Reports from earlier namespaces are
  kept. Namespaces that were not read have missing evidence, never a pass.
  A host bound or a canceled reconcile is decided by the host instead,
  and then no report is kept ([Collection limits](#collection-limits)).
- An empty scope (no targets) reads nothing. ClusterPolicyReports are never
  read. Collection never triggers the engine and never writes.

The test-only reporting adapter (`reporttest.Collect`) is deliberately
different:

- Its source is cluster-scoped and shared across namespaces, so it lists
  the source once.
- It keeps only the reports for an image digest that some frozen subject
  runs. Other images' reports are never retained.
- An object with another layout becomes a limitation and is not used as
  evidence. It is never empty evidence.
- A tag-only image needs no report: that subject is unresolved.
- A subject outside the scope is an error before any read.

Behavior equivalence is pinned at three levels:

- `TestCollectionMatchesTheDirectPath` compares the adapter output with the
  pre-adapter listing path over shared, unsupported, replaced and
  out-of-scope fixtures: same capture, limitations and evaluation.
- Controller tests written against the pre-adapter code still pass,
  among them `TestSnapshotReadsReportsOnlyInScopeNamespacesAndWritesNothing`,
  `TestReportListFailureIsALimitationAndKeepsEarlierNamespaces` and
  `TestRunKeepsReplacedWorkloadUnresolved`.
- The Kyverno conformance goldens are unchanged.

### Narrow readers

`provider.Sources` gives an adapter one `provider.SourceReader` per
declared read. The host implementation, `provider.ClientSources(client,
descriptor, scope)`, enforces these rules:

- It grants only a read that the descriptor declares, with the same kind and
  scope and the `list` verb. Any other read is refused before any request is
  made (`TestSourcesGrantOnlyDeclaredListReads`).
- A namespaced reader lists only scope namespace names, one namespaced list
  each. It never lists cluster-wide (`TestNamespacedReaderStaysInScope`).
- A cluster-scoped reader lists once, without a namespace, and only for a
  non-empty scope. The adapter must keep only what its inventory can
  attribute (`TestClusterScopedReaderNeedsAScope`).
- A list is read in pages and returned complete, or not at all
  ([Collection limits](#collection-limits)).
- A refused read returns `provider.ErrOutOfScope` without making a request.
- A reader calls only `List` on a `client.Reader`, so it cannot write even
  when the underlying client can. Neither `Sources` nor a `SourceReader` is
  a client writer, status writer or subresource client
  (`TestCollectionCannotWrite`).

`conformance.RecordingClient` is the recording API fixture. Give it to
collection code as a fully capable client, then check the requests it saw,
writes of every kind included: create, update, patch, apply, delete,
deletecollection and their subresource forms. For a scope of namespaces
`a` and `b`, the Kyverno adapter makes exactly these requests under the
host's bounds (`TestDocumentedExamples` runs it):

<!-- verified: kyverno-collection-requests -->
```json
[
  {"verb": "list", "kind": "PolicyReportList", "namespace": "a"},
  {"verb": "list", "kind": "PolicyReportList", "namespace": "b"}
]
```

## Collection limits

The host bounds every collection; an adapter cannot widen or skip a
bound. The controller runs the Kyverno adapter through
`provider.Collect(ctx, client, descriptor, scope, limits, adapter)`. It
gives the adapter readers that share one budget, and a context that ends at
the collection deadline or when the reconcile's context ends. When the
adapter returns, the host decides what its result means:

| What happened | Result | What is recorded |
| --- | --- | --- |
| The reconcile's context ended (leadership loss, shutdown) | the context's error, no result | Nothing. Current status is not written, and a run poll freezes no capture and no closure. The next leader's poll collects again for the same run. |
| A bound stopped the collection, or its deadline passed before the adapter returned | no result, one limitation | The limitation `<contract> evidence is not used: collection stopped (<code>): <bound>`. Every expected observation lacks evidence, so the evidence is `Incomplete` (`NoTargets` when nothing is expected), never `Complete`. |
| Neither | the adapter's result, unchanged | As before, including the adapter's own limitations such as `policy reports unavailable: <error>`. |

A stopped collection uses nothing it read, not even the namespaces that
completed. The Kyverno adapter keeps earlier namespaces' reports after a
failed list, and a stopped list may have read only some pages. Discarding
everything means truncated input never looks complete. Three tests check
this: `TestBoundsStopTheWholeCollection` with an adapter that ignores every
error, and `TestStoppedCollectionUsesNoReports` and
`TestCollectionLimitIsExplicitlyIncomplete` with the Kyverno path.

The default limits, `provider.DefaultLimits` (`TestDefaultLimits`):

<!-- verified: collection-limits -->
```json
{
  "timeout": "5m0s",
  "pageSize": 500,
  "maxPages": 20000,
  "maxObjects": 100000,
  "maxBytes": 536870912
}
```

| Limit | Default | Why |
| --- | --- | --- |
| Deadline | the binding's `spec.assessment.collectionTimeout`; 5m when it is unset or invalid | It is the existing collection budget of a run. One collection pass cannot outlast it, so a run's closing poll ends at most one deadline after its window. `TestCollectionDeadlineIsTheCollectionTimeout` checks it. |
| Page size | 500 objects per list request | The page size of client-go's pager and of the preview observation. |
| Requests | 20,000 list requests per collection | One list for each namespace of a 10,000-namespace scope (Kubernetes' namespace scalability threshold), plus the 200 full pages that 100,000 objects need, with headroom for short pages. |
| Objects | 100,000 objects per collection | The preview observation's bound. Kyverno writes one PolicyReport per resource, so this is about 100,000 workload objects in one binding's scope. |
| Bytes | 512 MiB of object JSON per collection | The preview observation's bound. Decoded objects take about 2.4 times their JSON size (measured on the saved Kyverno 1.19.2 reports), so 512 MiB decodes to about 1.2 GiB. That is more than the chart's 1 GiB controller memory limit, so a collection that completes under the default chart stays below this bound. |

How the bounds apply:

- **Pages.** A reader sends `limit=500` and follows `continue` until the
  list ends. A list is one consistent snapshot. An adapter gets a complete
  list or no objects, never part of one (`TestPaginatedListIsComplete`).
- **Expired continuation.** If a continuation expires (`410 Gone`), the
  list restarts once from its first page. The discarded pages do not count
  against the object and byte limits. A second expiry stops the collection
  (`TestExpiredContinuationRestartsOnce`).
- **Objects and bytes** are counted per collection, across all namespaces
  and readers. Bytes are each object's JSON encoding, which is what a
  capture keeps. A page is decoded before it is counted, so at most one
  page is held beyond the bound.
- **Invalid lists.** An object returned twice in one list stops the
  collection.
- **After a stop**, every further read of that collection returns the same
  `*provider.LimitError` (`errors.Is(err, provider.ErrCollectionStopped)`)
  and makes no request (`TestStoppedCollectionRefusesLaterReads`).
- **Deadline.** A request after the deadline, or one that client-side rate
  limiting cannot send before it, is refused and stops the collection. An
  adapter still running at the deadline gets no result, even when its
  reads completed (`TestDeadlineStopsTheCollection`).
- **Cancellation.** A request refused because the reconcile's context ended
  stops the collection, and `Collect` returns the context's error
  (`TestCancellationIsAnError`).
- **Source failures are not bounds.** A forbidden or failed request is
  returned to the adapter unchanged, as before, and the adapter decides
  what it means (`TestSourceFailuresAreTheAdapters`).

The stop codes are `timeout`, `canceled`, `object-limit`, `byte-limit`,
`page-limit`, `pagination-expired` and `invalid-list`.

`conformance.PagingClient` serves lists in pages as the API server does;
the fake client returns every object at once. For namespace `a` with 1,001
reports and `b` with one, the Kyverno adapter reads these pages:

<!-- verified: kyverno-collection-pages -->
```json
[
  {"kind": "PolicyReport", "namespace": "a", "page": 0},
  {"kind": "PolicyReport", "namespace": "a", "page": 1},
  {"kind": "PolicyReport", "namespace": "a", "page": 2},
  {"kind": "PolicyReport", "namespace": "b", "page": 0}
]
```

Behavior within the limits is unchanged:

- `TestBoundedCollectionMatchesTheDirectPath` reads 1,104 reports in pages
  and gets the same reports, limitations and evaluation as the direct path.
- `TestCollectionLimitIsExplicitlyIncomplete` checks that a binding at
  exactly the object limit gets the same status as an unbounded one.
- The collection characterization tests of task 2.1 are unchanged.

Leadership loss: `TestCanceledCollectionIsAnError`,
`TestLeadershipLossDuringCollectionRecordsNothing` (no status write) and
`TestLeadershipLossAtRunClosureFreezesNothing` (a poll after the window
closes writes no closure; the next poll closes the same run from a complete
collection). A run whose closing collection meets a bound closes with
missing evidence (`TestRunClosesIncompleteWhenACollectionLimitIsMet`).
The reporting adapter meets every bound the same way
(`TestReportingCollectionUnderHostBounds`).

What the bounds do not cover:

- Host reads: workload and engine policy listing, the binding's profile and
  content resolution. They run on the reconcile context, as before.
- Availability checks. They have their own bound of 10 seconds for each
  discovery or access review request.
- Watches. The host's report informer lists and watches with client-go's
  own pager. Collection never reads the informer cache.
- The reason in a run's package. The package records the missing
  observations, not the limitation text, which current status shows.
  The capture boundary (task 3.1) does not record limitations either.
  The v2 capture's `collectionErrors` field, which the controller leaves
  empty, is the candidate place. The owner has not yet decided which task
  records them.

### Configuring the limits

The page size and the request, object and byte limits are host
configuration: controller flags, set through the runtime chart's
`controller.collection` values ([values contract](charts.md#values-contract)).
They apply to every collection of every binding. No bundle, profile or
binding field changes them, and an adapter cannot. The deadline is not a
flag: it stays each binding's `spec.assessment.collectionTimeout`.

| Flag | Chart value | Default | Accepted |
| --- | --- | --- | --- |
| `--collection-page-size` | `controller.collection.pageSize` | 500 | 1 to 10,000, and at most the object limit |
| `--collection-max-requests` | `controller.collection.maxRequests` | 20,000 | 1 to 1,000,000, and at least the pages the object limit takes (objects / page size, rounded up) |
| `--collection-max-objects` | `controller.collection.maxObjects` | 100,000 | 1 to 10,000,000 |
| `--collection-max-bytes` | `controller.collection.maxBytes` | 536,870,912 (512 MiB) | 1,572,864 (1.5 MiB) to 68,719,476,736 (64 GiB), and at least page size × 4,096 |

Unset flags keep the defaults, so behavior is unchanged without them. The
controller checks the values at startup
(`provider.Limits.ValidateConfiguration`) and refuses to start with one out
of range, naming the flag. It never clamps a value. The ranges:

- Each ceiling keeps a configured collection bounded: 50 times the default
  requests, 100 times the default objects, 128 times the default bytes, and
  a page of at most 10,000 objects.
- A page larger than the object limit could pass it in one response.
- Fewer requests than the object limit's pages would make the object limit
  unreachable. Raising the object limit, or lowering the page size, can
  therefore need more requests too.
- 1.5 MiB is etcd's default request size limit, about the largest object an
  API server stores, so a smaller budget could refuse one legitimate
  report. 4,096 bytes per object of a full page is above the 2.4 to 2.9 KiB
  of the saved Kyverno 1.19.2 reports.

The chart's schema checks each range and its render checks the
combinations, with the same rules, so an install the controller would
refuse fails at `helm install` (`TestRuntimeChartCollectionLimits`). The
flags' parsing and checks are `TestCollectionFlags` and
`TestValidateConfiguration`. `TestConfiguredCollectionLimitsReachTheCollection`
checks that the configured limits are the ones the collection enforces: a
namespace with 100,001 reports is `Incomplete` under the defaults and
`Complete` with `maxObjects` raised to 200,000, and a lowered limit makes a
three-report collection `Incomplete`.

**When to raise them.** A binding whose scope has more reports than the
object limit, or more report JSON than the byte budget, always gets the
`object-limit` or `byte-limit` limitation and `Incomplete` evidence. Raise
the limit that its limitation names. A `page-limit` stop means more
namespaces than requests: raise `maxRequests`.

**Memory.** A collection holds the objects it reads in controller memory,
and decoded objects take about 2.4 times their JSON size. The default
512 MiB budget therefore decodes to about 1.2 GiB, above the chart's 1 GiB
controller memory limit: with the default chart, memory runs out before the
byte budget does for a collection of large reports. Size the byte budget
with the memory limit, and raise `controller.resources.limits.memory` (and its
request) together with `maxBytes` or `maxObjects`, at about 2.4 times
`maxBytes` plus the controller's baseline. Otherwise a collection that the
limits allow can get the controller OOM-killed before the byte limit stops
it. Lowering the limits is the way to keep a controller with less memory
from reading more than it can hold; the affected bindings then report
`Incomplete` evidence instead.

For example, for bindings of up to about 300,000 reports of about 3 KiB:

```yaml
controller:
  collection:
    maxObjects: 300000
    maxRequests: 20000      # 600 pages at 500 per page, plus one per namespace
    maxBytes: 1073741824    # 1 GiB of JSON, about 2.4 GiB decoded
  resources:
    requests: {cpu: 100m, memory: 3Gi}
    limits: {memory: 3Gi}
```

`AssessmentReconciler.CollectionLimits` carries the configured limits
(`controller.Options.CollectionLimits`). Tests also set it directly.

## Capabilities and permissions

Three things are easy to confuse:

- **The narrow reader** is what an adapter can request through its Go
  interface: `list` of its declared reads, inside the host-frozen scope,
  bounded by the [collection limits](#collection-limits).
- **The availability checks** are what the host asks before it collects:
  discovery of every read and prerequisite, and an access review of each
  read's verbs ([Availability](#availability)).
- **The controller's effective RBAC** is what its service account may do.
  Every feature of the controller shares that service account, so its RBAC
  is broader than any provider's reads. A narrow reader does not reduce it
  and does not isolate one provider from another. Adapters are trusted
  in-tree code.

The matrix for each provider, as `TestDocumentedExamples` computes it. It
uses the descriptors, `capability.ForProvider`, the requests recorded
during collection and the shipped ClusterRole `konstapel-controller`
(`config/rbac/controller/role.yaml`, rendered by the chart as
`generated-controller-role.yaml`):

<!-- verified: capability-matrix -->
```json
[
  {
    "provider": "konstapel-kyverno/v1",
    "evidenceCapability": "Assessment",
    "enforcement": "PolicyDelivery",
    "collection": [
      {"resource": "policyreports.wgpolicyk8s.io/v1alpha2", "scope": "namespaced", "verbs": ["list"]}
    ],
    "hostWatches": ["policyreports.wgpolicyk8s.io/v1alpha2"],
    "discovery": [
      {"resource": "policyreports.wgpolicyk8s.io/v1alpha2", "verbs": ["get", "list", "watch"]},
      {"resource": "clusterpolicyreports.wgpolicyk8s.io/v1alpha2", "verbs": ["get", "list", "watch"]}
    ],
    "accessReview": [
      {"resource": "policyreports.wgpolicyk8s.io/v1alpha2", "verbs": ["get", "list", "watch"]}
    ],
    "controllerRole": [
      {"resource": "policyreports.wgpolicyk8s.io", "verbs": ["get", "list", "watch"]},
      {"resource": "clusterpolicyreports.wgpolicyk8s.io", "verbs": []}
    ]
  },
  {
    "provider": "konstapel-reporttest/v1",
    "evidenceCapability": "Assessment(konstapel-reporttest/v1)",
    "enforcement": "NotApplicable",
    "collection": [
      {"resource": "postures.reporttest.konstapel.io/v1", "scope": "cluster", "verbs": ["list"]}
    ],
    "hostWatches": [],
    "discovery": [
      {"resource": "postures.reporttest.konstapel.io/v1", "verbs": ["get", "list"]}
    ],
    "accessReview": [
      {"resource": "postures.reporttest.konstapel.io/v1", "verbs": ["get", "list"]}
    ],
    "controllerRole": [
      {"resource": "postures.reporttest.konstapel.io", "verbs": []}
    ]
  }
]
```

Reading the matrix:

- `collection` lists the requests that the recording fixture saw. Kyverno
  makes one `list` per scope namespace and page, as in
  `kyverno-collection-requests` above. The reporting provider makes one
  cluster-wide `list` per page, as in `reporttest-collection-requests`
  below.
- `hostWatches` are the host's cluster-wide watches
  ([Availability](#availability)). The reporting provider has none: its
  source is read only during collection.
- `controllerRole` is what the shipped ClusterRole grants on each resource
  in every namespace. It grants Kyverno's reads in full: `get`, `list` and
  `watch` on policyreports cluster-wide, far more than one list for each
  scope namespace. It grants nothing on ClusterPolicyReports, which are
  only discovered.
- The role grants nothing on the test-only source. The reporting provider
  is never shipped, and its availability is tested only against fake
  discovery and access reviews. A new provider adds its reads to the role
  in its own change. `TestReadersAreNarrowerThanTheControllerRole` then
  requires every reviewed verb to be granted.

The test-only reporting adapter, for subjects in two namespaces, makes this
one request:

<!-- verified: reporttest-collection-requests -->
```json
[
  {"verb": "list", "kind": "PostureList"}
]
```

The other reads of a snapshot are the host's, not a provider's:

| Reader | Operations | Scope | Owner |
| --- | --- | --- | --- |
| Expected inventory | `list` namespaces and `get` the binding's ComplianceProfile; `list` the binding's managed `validatingpolicies`; `list` pods, replicationcontrollers, deployments, daemonsets, statefulsets, replicasets, jobs and cronjobs | workloads in scope namespaces only | host (`snapshotContent`, `listWorkloads`) |
| Engine delivery (not collection) | create, update, patch, delete `validatingpolicies` | cluster | delivery (`capability.Delivery`) |

The ClusterRole also grants these writes. No reader can reach them, and
every feature of the controller shares them:

<!-- verified: controller-role-writes -->
```json
[
  {"resource": "assessmentrequests.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "assessmentruns.compliance.erenius.io", "verbs": ["create", "patch", "update"]},
  {"resource": "assessmentruns.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "compliancebindings.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "complianceexceptions.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "complianceprofiles.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "evidenceattachments.compliance.erenius.io", "verbs": ["patch", "update"]},
  {"resource": "evidenceattachments.compliance.erenius.io/finalizers", "verbs": ["update"]},
  {"resource": "evidenceattachments.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "evidencedestinations.compliance.erenius.io", "verbs": ["patch", "update"]},
  {"resource": "evidencedestinations.compliance.erenius.io/finalizers", "verbs": ["update"]},
  {"resource": "evidencedestinations.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "evidencesigningrequests.compliance.erenius.io/status", "verbs": ["patch", "update"]},
  {"resource": "selfsubjectaccessreviews.authorization.k8s.io", "verbs": ["create"]},
  {"resource": "validatingpolicies.policies.kyverno.io", "verbs": ["create", "delete", "patch", "update"]}
]
```

The same file holds a namespaced Role `konstapel-controller` in the
controller namespace (ConfigMaps, Events, Secrets reads and the
leader-election Lease). When exception revocation processing is enabled,
`config/rbac/controller/exception-revocation.yaml` adds a gated grant.
None of them is a provider read.

## Availability

The host decides whether a provider can be used, from the provider's
descriptor alone. `capability.ForProvider` turns the descriptor into
capability requirements:

- Each `reads[]` entry must be served in its declared group, version,
  resource, kind and scope, and advertise its verbs. The controller service
  account must be allowed those verbs in every namespace
  (SelfSubjectAccessReview).
- Each `requires[]` entry must be served in its shape and advertise its
  verbs. No access is reviewed.
- Reads are checked first, in declaration order, then prerequisites. The
  first unmet requirement is the result.

`capability.Providers` checks every installed provider through the one
capability monitor, so the existing bounds apply: each discovery or review
request is bounded at 10 seconds, and a result is reused for one poll
interval. Each provider has its own result:

| Provider | Evidence capability | Enforcement |
| --- | --- | --- |
| `konstapel-kyverno/v1` | `Assessment`, with its existing name, messages, Conditions, limitations and metrics label | `PolicyDelivery`, the delivery owner's capability |
| any other provider (tests only) | `Assessment(<contract>)` | `NotApplicable` (reporting-only) |

`capability.Requirements[Assessment]` is `ForProvider(kyverno.Descriptor())`,
not a second list. `TestAssessmentIsTheKyvernoDescriptorsPrerequisites`
pins it to the requirements that were hard-coded before.
`TestKyvernoAvailabilityIsTheExistingCapabilities` checks that the Kyverno
provider's evidence and enforcement checks give the same result, reason and
message as the existing capabilities in every discovery and access state.
`capability.NewProviders` refuses to start with a Kyverno descriptor whose
prerequisites differ from the Assessment capability. It also refuses any
other provider that delivers engine resources: only the Kyverno engine has
a delivery capability.

A result's reason says what is wrong. It is never a check outcome or an
evidence-completeness state:

| Reason | Meaning |
| --- | --- |
| `Available` | Every prerequisite is met. |
| `APINotServed` | The group/version is not served. |
| `ResourceMissing` | The group/version is served without the resource. |
| `UnsupportedResource` | The resource has another kind or scope, or lacks a verb. |
| `AccessDenied` | Discovery or a reviewed verb is forbidden to the service account. |
| `DependencyUnavailable` | Discovery or the access review could not be completed. |
| `NotApplicable` | Enforcement by a reporting-only provider. It is never `Available`. |

Messages name the capability, for example
`Assessment(konstapel-reporttest/v1): reporttest.konstapel.io/v1 is not served`,
so a diagnostic is attributable to its provider.

**Independence.** One provider's missing API, denied read or unreachable
dependency never makes another provider unavailable. A reporting-only
provider's checks never consult the delivery capability. Delivery never
depends on any provider's evidence source.
`TestProviderAvailabilityIsIndependent` covers each failure for each
provider. `TestUnavailableProviderDoesNotDegradeKyverno` checks the
controller path: the Kyverno assessment keeps delivering and assessing,
with a complete pass, while the reporting source is absent or denied.

**Recovery without restart.** Nothing is decided once. Every check is
repeated after one poll interval, so a source that is installed, removed,
denied or allowed again shows up in the next result
(`TestProviderAvailabilityRecoversWithoutRestart`).

**Watches.** Each read that declares `watch` gets one cluster-wide host
watch (`providerWatches`). The watch starts once its own provider's
evidence capability is available, and never because another provider's is.
It starts at most once, without a restart, and after that the informer
re-lists and re-watches by itself. For the production registry this is
exactly the existing `assessment-policy-reports` PolicyReport watch
(`TestProviderWatchesKeepTheKyvernoReportWatch`).
`TestProviderWatchesStartIndependentlyAndRecover` covers absent and denied
sources for both providers. A provider without a watchable read, such as
the reporting provider, gets no informer. Its source is read only during
collection. The capability trigger re-reconciles every binding when any
provider's result changes (`TestCapabilityTriggerFollowsEachProvider`).

**Enforcement.** A reporting-only provider reports enforcement as
`NotApplicable`, never as ready or satisfied
(`TestReportingOnlyEnforcementIsNotApplicable`). Its readiness never claims
enforcement, and it renders no engine resources.

Not yet connected:

- No binding can select a provider other than Kyverno: the registry does
  not gate the targeting resolver. Binding Conditions and status therefore
  carry only the Kyverno results.
- Metrics report only `PolicyDelivery` and `Assessment`
  (`konstapel_capability_condition`). Another installed provider would need
  its own metric label before it ships.

## Captures

A capture is the frozen evidence of one run, `capture.json` in a package
(role `capture`). Its top-level `version` is the document format. Three
compatibility dimensions are separate from it, and from the C2P protocol
version of the pinned plugin:

- the provider contract (`name/vN`)
- the provider's payload version (the descriptor's `capture.read`)
- the evaluator version (the descriptor's `evaluatorVersion`)

| `version` | Document | Provider, payload, evaluator |
| --- | --- | --- |
| 1 | The prototype's single-policy `assessment.Capture` | Implied: `konstapel-kyverno/v1`, payload 1, evaluator 1 |
| 2 | The controller's `collector.CaptureV2` | Implied: `konstapel-kyverno/v1`, payload 2, evaluator 1 |
| 3 | The envelope `collector.CaptureEnvelope` | Recorded in the envelope |

Evaluator 1 is the 0.3.0 Kyverno semantics: `assessment.Reconcile` for
payload 1 and `CaptureV2.Evaluate` for payload 2. Versions 1 and 2 predate
provider discrimination, so their identity is implied by the version and
never read from the document.

The envelope names its provider, payload and evaluator, and carries the
provider's payload:

```json
{
  "version": 3,
  "provider": "konstapel-kyverno/v1",
  "payloadVersion": 2,
  "evaluatorVersion": 1,
  "payload": {"version": 2, "cluster": "...", "expected": ["..."]}
}
```

Every field is required, and no other field is accepted, so a field added
later needs a new version instead of being ignored. A Kyverno envelope holds
payload 2 only: a complete CaptureV2 document, decoded strictly and
validated with `CaptureV2.Validate`. Kyverno payload 1 exists only as a
version 1 document. Another provider's payload is that provider's to decode
and validate. The reporting adapter, for example, decodes its payload
strictly and checks the payload's own version.

### Reading a capture

`collector.ReadCapture(raw, registry)` is the boundary. It returns the
header and the payload as read, or an error that wraps
`collector.ErrUnsupportedCapture`. A rejection by the registry also carries
its [selection reason](#selection). It rejects:

- a document without a version, or with a version other than 1, 2 or 3
- a version 1 or 2 document with an envelope field (`provider`,
  `payloadVersion`, `evaluatorVersion` or `payload`). Older readers would
  ignore the field and read the document as Kyverno's
- an envelope with a missing or unknown field, an empty provider (never
  the registry default), a version below 1, or a payload that is not a
  JSON object
- a provider that is not installed, or a payload version it does not read
- a Kyverno envelope payload that is not exactly a valid CaptureV2

`ReadCapture` does not decode a legacy document. `CaptureDocument.V2()`
decodes it exactly as every earlier reader did, with `encoding/json`, which
ignores unknown fields. Retained captures therefore keep both their bytes
and their interpretation.

`ReadCapture` does not check the evaluator.
`CaptureDocument.CheckEvaluator(registry)` does, and a reader that
evaluates, replays or vouches for a retained capture calls it as well. A
capture recorded under an evaluator this build does not have is refused. It
is never evaluated with this build's semantics.

With the production registry, the saved legacy captures and a Kyverno
envelope of the saved CaptureV2 read as (`TestDocumentedExamples`):

<!-- verified: capture-headers -->
```json
[
  {
    "capture": "testdata/capture.json",
    "header": {"version": 1, "provider": "konstapel-kyverno/v1", "payloadVersion": 1, "evaluatorVersion": 1}
  },
  {
    "capture": "testdata/assessments/kyverno-1.19.2-background/capture.json",
    "header": {"version": 2, "provider": "konstapel-kyverno/v1", "payloadVersion": 2, "evaluatorVersion": 1}
  },
  {
    "capture": "Kyverno envelope of testdata/assessments/kyverno-1.19.2-background/capture.json",
    "header": {"version": 3, "provider": "konstapel-kyverno/v1", "payloadVersion": 2, "evaluatorVersion": 1}
  }
]
```

These are refused:

<!-- verified: capture-rejections -->
```json
[
  {
    "capture": "version 4",
    "error": "unsupported capture: capture version 4 is not supported (this build reads 1, 2 and 3)"
  },
  {
    "capture": "version 2 with an evaluatorVersion",
    "error": "unsupported capture: a version 2 capture has no provider, payload or evaluator fields; a provider-discriminated capture is version 3"
  },
  {
    "capture": "envelope of konstapel-reporttest/v1",
    "error": "unsupported capture: capture version 3 (konstapel-reporttest/v1 payload 1, evaluator 1): UnknownProvider: provider konstapel-reporttest/v1 is not installed (installed: konstapel-kyverno/v1)"
  },
  {
    "capture": "envelope of Kyverno payload 3",
    "error": "unsupported capture: capture version 3 (konstapel-kyverno/v1 payload 3, evaluator 1): IncompatibleVersion: konstapel-kyverno/v1 reads capture versions [1 2], not 3"
  },
  {
    "capture": "envelope of Kyverno evaluator 2",
    "error": "unsupported capture: capture version 3 (konstapel-kyverno/v1 payload 2, evaluator 2): IncompatibleVersion: konstapel-kyverno/v1 evaluates with evaluator version 1, not 2"
  }
]
```

The guarantees and their tests:

- The saved captures are pinned by digest and never rewritten. Through the
  boundary, the saved CaptureV2 decodes and evaluates exactly as on the
  direct path: 30 expected, 28 attributable, 2 missing, 24 pass and 4
  fail (`TestLegacyCapturesReadUnchanged`). Legacy decoding is not
  tightened (`TestLegacyDecodingIsNotTightened`), and the production
  registry reads and evaluates both captures
  (`TestProductionRegistryReadsLegacyCaptures`).
- A Kyverno envelope reads and evaluates like the document it holds
  (`TestKyvernoEnvelopeReadsLikeTheLegacyDocument`).
- Every rejection above, and more, is an explicit error that returns no
  capture (`TestCaptureBoundaryRejectsWhatItDoesNotSupport`,
  `TestProductionRegistryRejectsUnsupportedCaptures`).
- Another provider's payload is returned as written, is never read as a
  CaptureV2, and evaluates to its conformance golden
  (`TestOtherProvidersPayloadsStayTheirs`,
  `TestReportingCaptureCrossesTheBoundary`).
- An evaluator that is not installed is refused
  (`TestEvaluatorCompatibility`, `TestCheckEvaluator`).

### Readers of captures

| Reader | Reads |
| --- | --- |
| Storage backend validation before archiving (`s3store.ValidatePackage`) | Through `ReadCapture` and `CheckEvaluator` with the production registry. Only Kyverno captures have package verification, so another installed provider's capture is refused, not archived unverified. A version 1 capture is accepted as before: only in a binding-scope package, without engine-policy verification. Payload 2, legacy or envelope, gets engine-policy verification and, in a namespace package, projection checks. |
| Engine-policy verification (`collector.VerifyPackage`) | Kyverno payload 2, legacy or envelope. Anything else is an explicit error. It used to decode any capture as a CaptureV2. |
| Controller staging (`capture.json` and `closed.json` of a run in progress) | Unchanged: CaptureV2 only. `CaptureV2.Validate` refuses any other version. Staging is an `emptyDir`, so with the chart a staged capture never outlives the controller version that wrote it. |
| Prototype `konstapel convert` | Version 1 only. It refuses any other version before converting, and `assessment.Reconcile` refuses it too. |
| C2P plugin (`konstapel-provider`) | Through `ReadCapture` and `CheckEvaluator` with the production registry ([C2P conversion](#c2p-conversion)). Version 1 goes to the prototype provider. Kyverno payload 2, legacy or envelope, is converted with the package's `evaluation.json`. Anything else is an explicit error. |

`TestStorageValidationOfCapturePackages` validates binding and namespace
packages: legacy ones unchanged, with their bytes kept; Kyverno envelope
ones with the same descriptor meaning; and refuses unknown providers,
payloads, evaluators and versions.
`TestPackageVerificationReadsBothForms` checks that an envelope's payload
is verified against the packaged content like a legacy capture, and
`TestPackageCaptureRefusesProvidersWithoutVerification` covers an
installed provider without package verification.

### Run content

A run's content set (`collector.RunContent`) stays owned by the collector
and the controller that freezes it (see
[policy bundles](policy-bundles.md)). A provider never resolves, fetches or
caches content. A capture uses the set in one of two roles, decided by its
installed provider (`CaptureDocument.ContentUse(registry)`):

| Capture | Role | Content it is evaluated and exported from |
| --- | --- | --- |
| Kyverno payload 2, legacy or envelope | `Applied` | The bundles its subjects and contributions name (`KyvernoContentUse`), each by name and manifest digest. When nothing was applied, the desired bundle the plan names. |
| A provider whose check kinds all have `delivery: false` (`Registry.ReportingOnly`) | `Selected` | The run's frozen selection: the one bundle the binding selected when the run started, frozen then. The capture names no bundle and has no engine-applied state. |
| Kyverno payload 1 (the prototype capture) | refused | It predates content sets and is read only against its package's vendored content. |
| Any other provider | refused | Only the Kyverno payload names the content its checks were applied from. |

`RunContent.Resolve(use)` returns the members a capture reads, or an
explicit content failure that makes the package a Diagnostic:

- A run-level or member failure (`ContentUnavailable`, `ContentLost`) is
  returned unchanged. Desired, vendored or another provider's content is
  never substituted.
- `Applied`: every reference must name an applied member, and every applied
  member must be referenced. An enforcing contribution still applied from
  bundle A while the profile desires B reads A, and B stays desired intent.
  Overlapping applied revisions keep their own members.
- `Selected`: the run must have frozen exactly one member, not applied, and
  that member must be the selection it recorded when it started. Applied
  content is never read as a selection, and no selection is invented. A
  binding that changes after the freeze affects the next run; this run keeps
  its frozen copy. Its descriptor records the selection as the frozen
  desired bundle (`DesiredNotApplied`), with no applied identity.
- Identity is the bundle name and manifest digest, never the digest alone:
  another name for a frozen digest is a `ContentMismatch`.

Replay reads a retained package alone. `collector.PackageContent(dir,
descriptor)` returns the members packaged under their recorded paths,
verified against the descriptor's record (`VerifyContent`). It never reads
the cache, a registry or this image's vendored content. A packaged vendored
member is the copy the run packaged. A missing, altered or renamed member is
`ContentLost`, and a bundle a Diagnostic package did not carry is
`ContentUnavailable`. A vendored run has no content record, so its content
is its own `content/` tree. The tests are `TestResolve*`,
`TestPackageContent*`, `TestCaptureContentUseByProvider`,
`TestReportingCaptureUsesFrozenSelection` and
`TestOCIRunReplaysFromPackageAfterEviction`.

No wire format changes. The controller still writes CaptureV2 and the same
content record, and the descriptor's `revisions.content` is unchanged. A
reporting-only capture is not exported or collected yet. No provider other
than Kyverno has a C2P conversion, so the plugin refuses such a capture
explicitly ([C2P conversion](#c2p-conversion)). The registry does not gate
the targeting resolver.

## Namespace projection

A namespace package discloses one namespace instance's evidence to the team
that requested it. It must never contain a sibling namespace's subjects or
findings, private source metadata, credentials, or anything whose scope
cannot be established. Two parts keep every provider's payload safe to
disclose:

- **Provider-specific safe extraction.** Only a provider can read its own
  payload, so it extracts the payload for one namespace
  (`projection.Extractor.Extract`). It rebuilds each item it keeps
  from allowlisted fields, records the item's provenance, and withholds
  what it cannot attribute. A source object shared with other namespaces
  contributes only its attributable part.
- **Shared validation.** The host checks the scope of every
  namespace-attributable item (`projection.Check`). The provider reads that
  scope back from the extract alone (`projection.Extractor.Disclosures`),
  never from the source, and lists
  every item, including one it cannot attribute. Each item must name the
  authorized namespace instance by UID, by name, or by both. An item that
  names neither has unknown scope, and an extract with such an item is
  refused. A refusal locates the offending items. It never repeats their
  content or another namespace's name or UID.

Package `internal/provider/projection` holds the scope, the shared check and
the extractor interface. It imports no provider or Kyverno package
(`TestHarnessHasNoKyvernoDependencies`), so any provider can implement an
extractor. `collector.CaptureDocument.ProjectNamespace(scope, extractors)`
and `ValidateNamespace(scope, extractors)` are the shared entry points. They
dispatch by the capture's provider and payload version:

| Capture | Extraction | Validation |
| --- | --- | --- |
| Kyverno payload 2, legacy or envelope | `collector.Project` and `ProjectReports` | `collector.ValidateProjection`: Kyverno's field allowlist, then `projection.Check` |
| Kyverno payload 1 (the prototype capture) | refused | refused: it predates namespace projection |
| Any other payload | its installed extractor | its extractor's `Disclosures`, then `projection.Check` |
| A payload without an installed extractor | refused (`ErrNamespaceProjection`) | refused: it is never disclosed unprojected |

The production build installs no extractor besides Kyverno's, so only a
Kyverno projection can be a namespace package. The storage backend also
refuses every non-Kyverno package capture
([Readers of captures](#readers-of-captures)).

`ValidateProjection` accepts exactly what the Kyverno extraction produces:

- A report extract keeps only `apiVersion`, `kind`, `metadata.uid`,
  `metadata.namespace` and at least one result. It has no `summary`,
  `scope`, labels or annotations.
- A result keeps only its policy, result, source, rule, timestamp,
  `cel.validationIndex` and in-scope resource references, with their source
  types. Its provenance (`konstapelSource`) names its own source report,
  report digest, result index and transformation. Only an exact extract
  keeps its message. A resource-filtered result of a mixed-namespace report
  loses its message, because the message may describe the sibling.
- Stale scopes keep their reasons, and their messages are redacted. The
  capture keeps no collection errors.
- A binding-wide scope change is a configuration change or a watch
  discontinuity. It names no namespace or workload, and its detail is empty,
  the controller's fixed restart text, or a stale reason with its message
  redacted.
- Checks, engine policies and contributions belong to a projected subject.
- A withheld result records only its source report UID and index, with the
  fixed reason.
- Subjects, workloads, expected observations, scope changes (with their
  workloads), report extracts and resource references all name the
  projection's namespace instance.

`collector.ValidateProjectedEvaluation` checks the evaluation that a
package or summary reports from a projection. Every observation must be
one of the projection's expected observations, evaluated once. Every
report an observation references must be one of its extracts, and the
summary must count exactly those observations. Three readers run it before
anything is disclosed:

- `collector.Export` runs it, and requires the scope's namespace UID and
  name to be the projection's, before it writes a namespace package.
- The namespace coverage projection (`coverage.Build`) runs it before it
  reports any technical evidence.
- The storage backend's `ValidatePackage` runs it before archiving, together
  with `ValidateNamespace` against the descriptor's scope.

Protected supporting evidence keeps its existing boundary. Only a
binding-scope package carries it, and a namespace package's coverage shows
only sanitized supporting context. A provider payload that references a
supporting document, such as a result property with a document link, loses
that reference in extraction, and an extract that keeps it is refused.

The synthetic `reporttest` provider proves the seam with a shape unlike
Kyverno's. Its posture reports are cluster-wide, are shared by every
namespace that runs an image, and name no namespace. Its
`reporttest.Extractor` keeps the team's subjects and only the reports for
images they run, each with the frozen checks' verdicts only. It attributes
a kept report to the subjects that run its image.

The tests are `TestCheck`,
`TestOwnersProjectionsPassTheSharedCheck`,
`TestValidateProjectionRefusesEveryLeak`,
`TestProjectedEvaluationIsChecked`,
`TestNamespaceExportChecksEvaluationAndScope`,
`TestNamespaceProjectionDispatch`,
`TestStorageRefusesTamperedNamespacePackages`,
`TestStorageRefusesNamespacePackageOfAnotherScope`,
`TestNamespaceExtractOfSharedSource`,
`TestNamespaceExtractUnknownScopeFailsClosed`,
`TestTamperedNamespaceExtractsAreRefused` and
`TestFaultyExtractorIsCaughtByTheSharedCheck`. The existing projection
tests (`TestProjectionExcludesSiblingData`,
`TestNamespacePackageContainsOnlyItsScope`) are unchanged. The Kyverno
extraction and everything the controller writes are unchanged, so today's
namespace packages keep their bytes. The check refuses only what the
extraction never produces.

## Compatibility, retention and rollback

A package outlives the release that wrote it. Retention keeps it for the
configured period, and replay reads it alone. Every build therefore keeps
the readers that its retained packages need, and a rollback is safe only to
a release that reads everything written since. This section covers the
capture and package formats only. Other rollback constraints, such as those
for signing destinations, are in
[release readiness](release-readiness.md).

### Retained formats

| Retained form | Written by | This build | 0.3.0 and earlier |
| --- | --- | --- | --- |
| Capture version 1 | The prototype `konstapel convert` only | Read with evaluator 1, only in a binding-scope package. The C2P plugin converts it with the prototype provider | Read by the prototype and the C2P plugin |
| Capture version 2 | The controller, in every release including this one | Read with evaluator 1, unchanged | Read |
| Capture version 3 (envelope) | Nothing yet | Read: in production, Kyverno payload 2 only | Refused explicitly |
| Descriptor, file roles and content record | Unchanged since 0.3.0 | Read | 0.3.0 reads them. 0.2.0 refuses the `coverage-summary`, `coverage-summary-text` and `supporting-*` roles 0.3.0 added as unknown roles |

The file roles are a closed set, so a descriptor reader that predates a role
refuses the package instead of ignoring the file (`TestDescriptorValidation`).
This change adds no role, no descriptor field and no change to the content
record.

### Retained interpretation

The saved captures keep their bytes and their interpretation. Read through
the boundary with the production registry, and evaluated with the evaluator
their version implies (`assessment.Reconcile` for version 1 and
`CaptureV2.Evaluate` for version 2, with the chart's 2h maximum evidence
age), they give (`TestDocumentedExamples`):

<!-- verified: retained-interpretations -->
```json
[
  {
    "capture": "testdata/capture.json",
    "sha256": "d7bb94aa5dc968ae6951e4a806ddb7349d163ba0700fcd5613ec03ae505546e8",
    "evidence": {"complete": true, "missing": 0, "rejected": 0},
    "outcomes": {"pass": 1, "fail": 1}
  },
  {
    "capture": "testdata/assessments/kyverno-1.19.2-background/capture.json",
    "sha256": "b6dfee9fba0d6f1f7f9a847e8d7fb822c890f90a8e6d7a2ee24565a0b5364a5f",
    "evidence": {"completeness": "Incomplete", "expected": 30, "attributable": 28, "missing": 2, "rejected": 0, "unresolved": 0},
    "outcomes": {"pass": 24, "fail": 4, "error": 0, "skip": 0, "acceptedRisk": 0, "notApplicable": 0, "unknown": 0}
  }
]
```

The digests are the same pins `TestLegacyCapturesReadUnchanged` checks. A
change to the Kyverno evaluation that changes these results needs a new
evaluator version, with evaluator 1 still installed for the captures that
record it. `TestProductionRegistryReadsLegacyCaptures` fails if the
installed Kyverno provider stops reading payload 1 or 2 or evaluator 1.

### Content retention

A package carries the content its capture was evaluated from, under the
paths and digests its descriptor records ([Run content](#run-content)). The
content is retained, and retired, with the package. Replay never reads the
bundle cache, a registry or the image's vendored content, so cache eviction
or a removed bundle does not change a retained package's interpretation
(`TestOCIRunReplaysFromPackageAfterEviction`). A missing or altered member
is an explicit `ContentLost`, never a substitute.

Package validation, including the namespace projection checks, runs when a
package is staged for publication (`s3store.ValidatePackage` in
`Publisher.Stage`). It never rewrites a package, and an archived package is
not revalidated. The projection checks refuse only what the Kyverno
extraction never produces, and the extraction is unchanged, so packages
written by earlier releases would pass them too.

### Rollback

- **This build writes nothing new.** The controller still writes capture
  version 2 (`kyverno.Descriptor().capture.write`), with the same
  descriptor, roles and content record as 0.3.0. No production code writes
  an envelope. A rollback to 0.3.0 reads every package this build wrote.
- **The envelope is read here and written nowhere.** A later release may
  write it only after a release with these readers has shipped (readers
  before writers). A rollback from that release is supported only to a
  release with these readers. The earlier releases (up to 0.3.0) refuse an
  envelope package explicitly. Their capture readers are
  `CaptureVersion`, `CaptureV2.Validate` and `assessment.Reconcile`,
  unchanged in this build, and none reads an envelope as an empty Kyverno
  capture (`TestReadersBeforeWriters`). Given a Kyverno envelope of the
  saved CaptureV2, they report:

<!-- verified: earlier-release-readers -->
```json
[
  {"reader": "collector.CaptureVersion", "error": "unsupported capture version 3"},
  {"reader": "CaptureV2.Validate", "error": "capture version 3 is not 2"},
  {"reader": "CaptureV2.Evaluate", "error": "capture version 3 is not 2"},
  {"reader": "assessment.Reconcile", "error": "invalid capture identity, time boundary, or empty expected inventory"}
]
```

- **Version 2 never grows envelope fields.** An earlier reader ignores an
  appended `evaluatorVersion`, and would read the capture as evaluator 1
  whatever it says (`TestReadersBeforeWriters`). So version 2 captures
  record their evaluator only implicitly, and this build refuses a version
  2 capture with an envelope field. A capture records `evaluatorVersion`
  explicitly once a release writes the envelope.
- **Readers stay while their packages are retained.** A rollback, or a
  later release, can disable selecting a provider. It must not remove the
  provider's capture or evaluator readers while packages that need them
  are retained. A build without them refuses those packages explicitly
  (`TestCaptureBoundaryRejectsWhatItDoesNotSupport`,
  `TestProductionRegistryRejectsUnsupportedCaptures`,
  `TestEvaluatorCompatibility`). It never evaluates them with other
  semantics or drops them.
- **Older package readers fail closed.** A role a reader does not know
  refuses the package. 0.2.0 cannot read packages with coverage or
  supporting evidence, as recorded in the 0.3.0 rollback constraints.

## Conformance

`internal/provider/conformance` is the shared harness. It imports no
Kyverno package. `TestHarnessHasNoKyvernoDependencies` checks this with
`go list -deps`. A case is a directory with two files:

- `case.json`, format `konstapel.provider-conformance/v1`. It holds the
  provider contract, an explicit `evaluationTime` and an opaque
  provider-specific `input`.
- `expected.json`. It holds the golden inventory and observations, plus the
  existing `EvidenceSummary` and `OutcomeCounts`.

The harness rejects unknown case versions and unknown fields. A provider
supplies a `conformance.Provider`: its `Adapter` (`Inventory`, `Evaluate`,
`WithoutEvidence`, `MaxEvidenceAge`), its `Lifecycle` (`Cluster`, `Collect`,
`Retain`, `Replay`) and its `Projector` (`Namespaces`, `Extract`,
`Validate`). `conformance.Run` requires all three, so no provider passes on
evaluation alone. Besides the golden comparison, every case must satisfy
these rules:

- The expected inventory comes from the frozen scope alone. It is unchanged
  when all evidence is removed. Without evidence, every observation is
  `Missing`, or `Unresolved` for scope it cannot attribute. Nothing passes.
- Every expected observation is evaluated exactly once. None is dropped,
  invented or duplicated.
- Only `Attributable` evidence has a raw outcome, a normalized outcome
  (`pass`, `fail`, `error`, `skip`, `unknown`) and an evaluation time no
  later than the evaluation time and no older than the input's
  evidence-age limit. `Missing`, `Rejected` and `Unresolved` carry no
  outcome.
- Evaluated again once all of it is older than the evidence-age limit,
  attributable evidence is stale: `Rejected`, never still attributable from
  the same source time and never `Missing`.
- A raw outcome always normalizes the same way. Raw values without a summary
  field, such as a warning, count once as `unknown`, and the raw value is
  kept. `NotApplicable` is never a pass.
- Evaluation is deterministic for the same input and time.

`CheckLifecycle` drives the provider through the host's own paths for the
same case. The Kyverno and reporting suites use `provider.Collect` over
their collection adapters with the default limits, `collector.ReadCapture`,
the capture's content role and `RunContent.Resolve`:

- Collected from a cluster serving the case's evidence, the evidence
  evaluates exactly as the case's own, and collection writes nothing.
- A collection canceled before it starts or at its first request returns
  only the cancellation: no result and no limitation.
- A source whose every request fails is a limitation, and nothing is
  attributable.
- After the source objects are removed, collection finds no evidence and
  evaluates as the case without evidence.
- The retained capture, replayed after that removal and without a
  cluster, evaluates exactly as the collection it retained.
- Replayed with the run's content unavailable, it fails as unavailable
  content (`conformance.ErrContentUnavailable` wrapping the
  `ContentUnavailable` failure) and returns nothing.

`CheckProjection` projects the case to each namespace instance of its frozen
scope through `CaptureDocument.ProjectNamespace` and checks it with
`ValidateNamespace`. Each extract passes the shared check for its namespace
and is refused for every other one. No two namespaces disclose the same
expected observation. Projection never changes an observation's result. A
scope without a namespace instance is refused.

Each violation is a `conformance.Violation` whose `Kind` names the broken
rule. `conformance.RunMutations` applies the harness's catalog of
deliberate regressions to every case that can expose them. The suite must
report each regression's own kind, and some case must expose every
regression. The catalog covers evaluation (missing evidence that passes, an
inventory derived from evidence, a warning counted as a pass, an outcome on
rejected evidence, a report update time used as freshness, an ignored
evaluation time, duplicate credit, inconsistent normalization,
nondeterminism and others), lifecycle (a collection that ignores
cancellation, writes, drops evidence, reuses the input's evidence or hides a
failed source, a retention that drops evidence, a replay that substitutes
unavailable content) and projection (an extract that discloses the whole
payload or drops evidence, a projected unknown scope).
`TestKyvernoConformanceCatchesRegressions` and
`TestReportingConformanceCatchesRegressions` run it for both providers.
`TestMutationsCoverEveryRule` checks that every rule has a regression,
except a malformed case, which `TestHarnessRejectsMalformedCases` covers by
kind, an adapter error and an invalid summary.

Cases live under `testdata/providers/conformance/v1/<provider>/`:

- `konstapel-kyverno/background-1.19.2`: the saved live Kyverno 1.19.2
  background evidence, evaluated unchanged by `kyverno.Evaluate` at its closure.
  The result is 30 expected, 28 attributable, 2 missing, 24 pass and 4 fail.
- `konstapel-kyverno/synthetic-unknowns`: synthetic reports over that frozen
  scope, with a warn, conflicting results, untimed and future results, and a
  skip.
- `konstapel-kyverno/windows-not-applicable`: the same saved evidence with
  one workload declaring Windows in its frozen scope. Its six Linux checks
  keep their raw results and are not applicable.
- `konstapel-reporttest/*`: the synthetic reporting shape described below.

`TestKyvernoHarnessSummaryMatchesCollector` checks that the harness summary
equals the controller's `collector.Tally` result for the Kyverno cases.

## Pure evaluators

Evaluation takes frozen inputs and an explicit evaluation time, and nothing
else: no clock, cluster, registry or engine access. Callers differ only in
the time they pass.

- `kyverno.Evaluate(EvaluationInput{Capture, Boundaries, MaxEvidenceAge}, at)`
  is the Kyverno evaluator. It is `collector.CaptureV2.EvaluateAt`, the
  unchanged freshness and attribution rules with the capture closed at
  `at`, summarized by `collector.Tally`. The current projection passes the
  current assessment boundary. A closing run passes the closure it freezes,
  and replay passes the frozen closure (`CaptureV2.Evaluate`). A zero time,
  a time before the window started or one before a recorded scope change is
  refused, never replaced by another time.
- `reporttest.Evaluate(Input, at)` is the test-only reporting evaluator;
  its conformance adapter only decodes the payload strictly first.

Both evaluators apply the same rules:

- Evidence exactly `maxEvidenceAge` old at `at` is still current; older
  evidence, or evidence evaluated after `at`, is `Rejected`.
- Conflicting results evaluated at the same time are `Unresolved`, as is
  evidence that cannot name its subject (a Kyverno scope change, a
  tag-only image). An unindexed Kyverno non-pass of a multi-validation
  policy names no validation and establishes nothing.
- Repeated or shared evidence attributes each expected observation once.
  A reporting payload that lists a subject or check twice is refused.
- Out-of-scope checks are `NotApplicable`, keep their raw result and never
  count as a pass.
- A raw warning (Kyverno `warn`) stays on the observation and counts once
  as `unknown`. No new outcome field or accepted risk is introduced.

`internal/provider/kyverno/evaluate_test.go` and
`internal/provider/reporttest/evaluate_test.go` test these boundaries.
`TestEvaluatorsReadNoClockAndCallersPassTime` checks that neither evaluator
calls a `time` clock function. It also checks that non-test code reaches
Kyverno evaluation only through `kyverno.Evaluate`.
`TestKyvernoHonorsTheExplicitEvaluationTime` checks that the conformance
adapter uses the case's time: three hours after closure the saved evidence
is all rejected.

The cases run in the normal test entry points (`task test`, `task check`).
After an intended semantic change, rewrite the golden results and review the
diff with the fixture commands of the [authoring recipe](#8-run-the-checks).

## C2P conversion

Continuous export and the C2P plugin share one conversion. The pinned C2P-Go
v2 `Configure`/`Generate`/`GetResults` contract and plugin packaging are
unchanged: same plugin ID, manifest options and build. The conversion's input
is a frozen snapshot (`collector.Snapshot`). It is a closed capture plus the
evaluation `kyverno.Evaluate` made of it at the closure boundary. The
controller freezes both before export. A package retains them as
`capture.json` and `evaluation.json`.

- **Continuous export.** `collector.Export` dispatches each part of the
  package through the C2P framework (`actions.AggregateResults`) to the
  in-tree `collector.SnapshotProvider`. Each part is one applied bundle's
  share of the snapshot, or the whole snapshot for a vendored run. Before
  writing anything, `Export` checks that the evaluation belongs to its
  capture (`Snapshot.Validate`): one observation per expected observation
  and no other, only reports the capture holds, and a summary that counts
  exactly its observations. A failed check returns an error and writes no
  package. A failure in the conversion makes the package a typed
  Diagnostic, with no OSCAL. The conversion also fails when a result names
  a check that is not in the mapping's policy, or when the framework
  skips the provider.
- **The plugin.** `konstapel-provider` serves `c2p.Provider`. `Configure`
  reads the configured capture through the capture boundary with the
  production registry and checks the recorded evaluator. It then selects
  one of three paths:
  - No capture (`generate`, `deliver`, `acceptance`), or a version 1
    capture, goes to the prototype `assessment.Provider`, unchanged.
  - Kyverno payload 2, legacy or envelope, goes to `SnapshotProvider`. It
    reads the `evaluation.json` beside the capture, decodes it strictly
    and validates it as `Export` does (`collector.ReadSnapshot`).
  - Any other capture is an `ErrUnsupportedCapture` that names the
    capture. This includes another installed provider's capture, an
    evaluator that is not installed and an unknown version. No OSCAL is
    guessed, and nothing is read as Kyverno's.

  A failed `Configure` leaves the plugin unconfigured. It never keeps an
  earlier configuration.
- **Generate.** The prototype renders the vendored policy into the output
  directory from local files. A frozen snapshot refuses `Generate`,
  because its engine policies were applied before its capture froze.
  Generation never delivers anything; only `konstapel deliver` and
  `acceptance` reach a cluster, through their own client.
- **Local only.** Every path reads local files only. It uses no cluster,
  registry, content cache, scanner or clock. Conversion reads the frozen
  evaluation and does not re-evaluate, so the replay's wall clock changes
  nothing.

The package does not record the host's continuity boundaries or the
binding's maximum evidence age. Exact re-evaluation of a retained capture
is therefore possible only when its boundaries did not matter. This is why
conversion reads the frozen evaluation and checks that it is consistent
with the capture, instead of re-evaluating.

The tests:

- `TestDispatchedConversionEqualsTheDirectOne` checks that dispatch adds
  nothing to the direct conversion. It covers failures, warnings,
  missing, rejected and zero-target evidence and stale scopes.
- `TestExportRefusesAnEvaluationThatIsNotOfItsCapture`,
  `TestSnapshotProviderConvertsOnlyForItsChecks` and
  `TestConvertRefusesASkippedProvider` cover the refusals above.
- `TestDispatchConvertsTheExportedSnapshot` checks that the plugin's
  dispatch, given a package's files, converts exactly what export
  converted. The normalized subjects of the package's
  `assessment-results.json` match those results, and an envelope converts
  identically.
- `TestReplayKeepsTheRetainedInterpretation` re-evaluates the retained
  capture at its closure and gets the retained evaluation. A later time
  changes freshness, but not the conversion.
- `TestDispatchKeepsThePrototype` and `TestDispatchRefusesWhatItCannotConvert`
  cover the other two dispatch paths.
- `TestPluginBinaryIsLocalAndConvertsLikeTheDispatch` builds the plugin
  binary and runs `Configure`, `GetResults` and `Generate` through gRPC.
  `KUBECONFIG` and the HTTP proxies point at a trap that must stay
  unused. `TestConversionPathImportsNoClusterOrRegistryClient` checks that
  the conversion files import no network, Kubernetes or registry client.
- `TestOCIRunConvertsAndReExportsFromPackageAfterEviction` replays a
  published OCI run after cache eviction with the registry down. The
  plugin's dispatch converts it, and a fresh export from the packaged
  content gives the same normalized assessment plan and results. Nothing
  is fetched.
- `TestConvertRefusesAContinuousCapture` checks that `konstapel convert`
  refuses a continuous capture before converting.

## Test-only boundary

`internal/provider/reporttest` (`konstapel-reporttest/v1`) is a synthetic
reporting-only provider. It checks that the shared contract does not depend
on Kyverno:

- Its subjects are workload containers and the images they run.
- One posture report per image digest is shared evidence for every
  workload that runs that image.
- Its checks are named verdicts.
- Freshness comes from the report's evaluation time, never from its update
  time.
- Tag-only images are `Unresolved`.

It has no engine policy, validation index or PolicyReport. The following
guards keep it out of production builds:

- The production registry is a closed list and never contains a `testOnly`
  descriptor. A test-only descriptor cannot be a registry default.
- `TestTestOnlyProvidersAreNotLinkedIntoShippedBinaries` runs `go list -deps`
  over every main package under `cmd/` and over the registry packages. It
  fails if any of them links `reporttest` or the conformance harness.
- Linking `reporttest` into a non-test binary panics at startup
  (`testing.Testing()`). `TestLinkingIntoABinaryPanics` builds such a binary
  and checks the panic.

The shipped artifacts are checked too, for the provider's package paths
and identities (its contract name, source group and check kind):

- `TestShippedBinariesCarryNoTestOnlyProvider` builds both binaries as
  `scripts/build.sh` does and scans them. A binary that links `reporttest`
  must show the markers, so the scan is real.
- `TestImagePayloadCarriesNoTestOnlyProvider` scans the rest of the image
  payload: the content tree, the notices, and the script that writes the
  C2P plugin manifest for the installed Kyverno provider.
- `TestShippedBundlesNameNoTestOnlyProvider` builds every bundle under
  `bundles/` as it is published. Each one must name an installed production
  provider, and no file in it may carry the markers.
- `TestChartsShipNoTestOnlyProvider` renders both charts, with the defaults
  and with every documented values example, and scans the output.
- `task image:test` scans every Konstapel file of the built image, including
  the plugin manifest.

Build tags were not used: the cases must run in the plain `go test ./...`
behind `task check`.

The reporting provider and its fixtures prove plumbing only. They are not a
model of Trivy or of any real producer, and they are not producer
compatibility evidence.

## Authoring a provider

This recipe builds an in-tree provider against the contract above. The
worked example is the test-only reporting provider
`internal/provider/reporttest` (`konstapel-reporttest/v1`): every step
names the file that implements it. Following the recipe gives a provider
that passes shared conformance in tests. It does not make the provider
supported or installable; see
[what a production provider still needs](#what-a-production-provider-still-needs).

Providers that run as separately installed services, with a versioned
remote protocol, are planned in the separate
`add-external-assessment-providers` change. Nothing in this recipe is that
protocol: every provider here is Go code compiled into the repository. The
remote protocol is described in the
[external provider protocol reference](integration/external-provider-protocol.md),
and the [reporting quickstart](integration/external-provider-quickstart.md)
runs a synthetic provider from an independent module. External providers
cannot be registered yet.

### 1. Declare the descriptor

Write a `Descriptor()` function returning a `provider.Descriptor`
([The descriptor](#the-descriptor)). Choose:

- a name and contract version, which bundles will select as
  `compatibility.provider`
- one check kind per kind of check definition the provider evaluates. A
  provider that does not render engine resources sets `delivery: false`
  and accepts only `Audit`.
- the parameter contract of each kind
- the capture payload version it writes and the versions it reads
- its evaluator version
- its evidence-source `reads` (read-only verbs only) and any `requires`

The reporting provider (`reporttest.Descriptor` in
`internal/provider/reporttest/reporttest.go`, its read in `collect.go`):

<!-- verified: reporttest-descriptor -->
```json
{
  "name": "konstapel-reporttest",
  "version": 1,
  "evaluatorVersion": 1,
  "checks": [
    {
      "kind": "reporttest.konstapel.io/v1/ImagePosture",
      "delivery": false,
      "modes": ["Audit"],
      "parameters": {
        "source": "Descriptor",
        "schema": {"type": "object", "additionalProperties": false, "properties": {"maxEvidenceAge": {"type": "string", "pattern": "^[0-9]+(s|m|h)$"}}}
      }
    }
  ],
  "capture": {"write": 1, "read": [1]},
  "reads": [
    {
      "group": "reporttest.konstapel.io",
      "version": "v1",
      "resource": "postures",
      "kind": "Posture",
      "namespaced": false,
      "verbs": ["get", "list"]
    }
  ],
  "testOnly": true
}
```

A provider written only to exercise the contract sets `testOnly` and, like
`reporttest`, panics in `init` when `testing.Testing()` is false.

### 2. Register it in a test registry

Register the descriptor next to Kyverno's with `provider.New`, which
rejects every inconsistency listed under [The descriptor](#the-descriptor).
The reporting provider's conformance suite does this in `testRegistry`
(`internal/provider/reporttest/conformance_test.go`):

```go
r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
```

Use that registry for `Registry.Select`, `collector.ReadCapture`,
`CheckEvaluator` and `ContentUse` in the provider's tests. Do not add the
descriptor to `installed.Registry()`: that is the production registry, and
adding to it is a production-support decision made in the provider's own
change (step 9). It refuses a `testOnly` descriptor at startup.

### 3. Collect inside the host's scope

Write a collection function that takes the host-frozen `provider.Scope`
and a `provider.Sources`, asks `Sources.Source` for a reader of each
declared read, and calls only `SourceReader.List`
([Narrow readers](#narrow-readers)). The host runs it through
`provider.Collect(ctx, client, descriptor, scope, limits, adapter)`, which
applies the [collection limits](#collection-limits) and decides what a
stopped or canceled collection means. The function:

- never decides what is expected. The host owns scope.
- returns a failed list as a limitation, never as empty evidence
- keeps only the evidence that the frozen scope can attribute. A
  cluster-scoped source is read once and filtered.

Example: `reporttest.Collect` in `internal/provider/reporttest/collect.go`,
which lists postures once and keeps only those for image digests that a
frozen subject runs.

### 4. Evaluate purely, at an explicit time

Write an evaluator over the frozen payload and an evaluation time, with no
clock, cluster or registry access ([Pure evaluators](#pure-evaluators)).
Keep each producer outcome verbatim as the observation's raw outcome and
map it to a normalized outcome (`pass`, `fail`, `error`, `skip`,
`unknown`). Anything unrecognized normalizes to `unknown`, never `pass`.
Not-applicable evidence keeps its raw value and is never a pass. The
reporting provider maps `Passed` to `pass`, `Violated` to `fail`, `Errored`
to `error`, `NotApplicable` to not applicable, and anything else to
`unknown` (`reporttest.Evaluate` and `normalized` in `reporttest.go`).

Then implement `conformance.Adapter` over the provider's case input:
`Inventory` from the frozen scope alone, `Evaluate`, `WithoutEvidence` and
`MaxEvidenceAge` (`reporttest.Adapter`).

### 5. Write a capture payload

The provider owns its payload format and version. It is retained inside
the capture envelope (document version 3), which records the provider
contract, payload version and evaluator version ([Captures](#captures)).
Decode the payload strictly and check its own version. Bump the payload
version for any format change, and the evaluator version for any change in
results. Keep every version a retained package records readable
([Compatibility, retention and rollback](#compatibility-retention-and-rollback)).
The reporting suite's `Retain` wraps the payload in a
`collector.CaptureEnvelope`, and its `Replay` reads it back through
`collector.ReadCapture` and `CheckEvaluator`.

A reporting-only provider's capture reads the run's frozen selection
(`Selected` content); it never resolves or fetches content itself
([Run content](#run-content)).

### 6. Project to a namespace

Implement `projection.Extractor` for the payload: `Extract` rebuilds each
kept item from allowlisted fields for one namespace instance, and
`Disclosures` reads every item's scope back from the extract
([Namespace projection](#namespace-projection)). The host's
`CaptureDocument.ProjectNamespace` and `ValidateNamespace` dispatch to it
through a `collector.NamespaceExtractors` entry keyed by contract and
payload version. Example: `reporttest.Extractor` in `project.go`, wired in
the tests' `extractors`.

### 7. Add conformance cases

Create `testdata/providers/conformance/v1/<name>/<case>/case.json` in the
`konstapel.provider-conformance/v1` format ([Conformance](#conformance)),
with the contract, an explicit `evaluationTime` and the provider's input.
Add a README to the provider's directory saying whether its cases are
saved real producer output or synthetic, as
`testdata/providers/conformance/v1/konstapel-reporttest/README.md` does.

In a `_test.go` file, implement `conformance.Lifecycle` (`Cluster`,
`Collect`, `Retain`, `Replay`) and `conformance.Projector` (`Namespaces`,
`Extract`, `Validate`) through the host's own paths, then run the suite and
the regression catalog. The reporting provider's
`internal/provider/reporttest/conformance_test.go` is the complete example:

```go
func TestReportingConformance(t *testing.T) {
	conformance.Run(t, suite{}, cases(t), *update)
}

func TestReportingConformanceCatchesRegressions(t *testing.T) {
	conformance.RunMutations(t, suite{}, cases(t))
}
```

A new case has no `expected.json`, and the suite fails until one is
written. Generate it with `-update` (below). A case is written only when
all its invariants and the lifecycle and projection suites pass. Review
the generated result by hand before committing it: the golden is the
provider's claimed interpretation.

### 8. Run the checks

Run every command in the pinned Devbox environment from the repository
root. The first four run individual Go test packages directly. There is no
separate Task for them: they all run in `task test`, which `task check`
runs.

```sh
# Registration: registry validation, selection, the production registry's
# closed list, the test-only absence checks and this guide's verified
# examples.
devbox run -- go test ./internal/provider ./internal/provider/installed

# Fixtures: the conformance cases and the regression catalog of both
# providers.
devbox run -- go test ./internal/provider/kyverno ./internal/provider/reporttest -run Conformance

# Fixture goldens, for a new case or after an intended semantic change.
devbox run -- go test ./internal/provider/kyverno ./internal/provider/reporttest -run Conformance -update
git diff -- testdata/providers

# Replay: the capture boundary, C2P dispatch and plugin replay, and package
# replay after cache eviction.
devbox run -- go test ./internal/provider/c2p ./internal/provider/reporttest ./internal/bundle/stack \
  -run 'Replay|Dispatch|PluginBinary|CrossesTheBoundary|AfterEviction'

# Everything CI checks without a cluster.
devbox run -- task check
```

With the providers in this repository, the `-update` run writes no change
to `testdata/providers`. The replay tests reach no cluster or registry:
`TestPluginBinaryIsLocalAndConvertsLikeTheDispatch` builds the plugin and
points `KUBECONFIG` and the proxies at a trap, and
`TestOCIRunConvertsAndReExportsFromPackageAfterEviction` replays with the
registry down.

### What a production provider still needs

Conformance in tests is necessary, not sufficient. These connections are
Kyverno-only today, and a real provider adds each in its own change:

- **Registration.** Add the descriptor to `installed.Registry()`. The
  registry does not yet gate the targeting resolver, so selection by
  bindings is not connected either.
- **Permissions.** Add its reads to the controller ClusterRole
  (`config/rbac/controller/role.yaml`) and the charts.
  `TestReadersAreNarrowerThanTheControllerRole` then requires every
  reviewed verb to be granted.
- **Availability and metrics.** `capability.Providers` already checks any
  installed descriptor. A provider that delivers engine resources is
  refused, because only Kyverno has a delivery capability. Metrics need a
  label for its capability.
- **Captures and export.** The controller writes only Kyverno capture
  version 2. Package validation, the storage backend, namespace packages
  and C2P conversion accept only Kyverno payloads, and production installs
  no other namespace extractor.
- **Producer evidence.** Live compatibility tests against the real
  producer and its saved real output, proving attribution, evaluation
  time, filtering and missing evidence. Synthetic fixtures never count.

## Contracts, interfaces and producer support

### Versioned contracts

These are recorded in bundles or retained packages, or are fixture formats
other changes depend on. A change to one needs a new version, and readers
of every retained version stay installed:

- the bundle descriptor's `compatibility.provider` value (`name/vN`)
- the capture versions recorded in packages: the document versions 1, 2
  and 3, the identity that versions 1 and 2 imply, the envelope's fields,
  and each provider's payload versions and evaluator versions
- the package descriptor, its closed set of file roles and its content
  record, unchanged by this change
- the conformance case format `konstapel.provider-conformance/v1`
- the pinned C2P-Go v2 `Configure`/`Generate`/`GetResults` plugin contract
  and the `konstapel-provider` plugin manifest, owned upstream and by the
  build, not by this change
- the external provider protocol `konstapel.provider.v1`
  ([`provider.proto`](../proto/konstapel/provider/v1/provider.proto),
  [protocol reference](integration/external-provider-protocol.md), from
  [`add-external-assessment-providers`](../openspec/changes/add-external-assessment-providers/proposal.md))
  and its wire fixtures. Its provider contract, payload and evaluator
  versions are this guide's descriptor version, `capture` versions and
  `evaluatorVersion`, not parallel ones; its protocol revision is a fourth,
  separate dimension. Its public Go types (`pkg/providerapi/v1`) and
  authoring kit (`pkg/providerkit`) import nothing internal. The kit's
  transport is mutual TLS 1.3 with configured trust and exact DNS-name peer
  authorization in both directions, material reloaded from mounted files
  without a restart (connections the rotated trust no longer authorizes are
  closed), required call deadlines and bounded messages and streams. No
  external provider can be registered or selected yet.

### Internal Go interfaces

The Go types (`provider.Descriptor`, `Registry`, `Selection`, `Scope`,
`Sources`, `SourceReader`, `Limits`, `Collect`, `LimitError`,
`collector.ReadCapture`, `CaptureDocument`, `CaptureReaders`,
`ContentRoles`, `ContentUse`, `RunContent.Resolve`, `PackageContent`,
`NamespaceExtractors`, `ProjectNamespace`, `ValidateNamespace`,
`ValidateProjectedEvaluation`, `projection.Scope`, `Disclosure`, `Check`,
`Extractor`, `collector.Snapshot`, `ReadSnapshot`, `SnapshotProvider`,
`c2p.Provider`,
`conformance.Adapter`, `Lifecycle`, `Projector`, `Provider`, `Violation`,
`RunMutations`, `RecordingClient`, `PagingClient`, and the provider
adapters) are internal to this repository. They are not a stable
third-party SDK, Go module API or plugin interface, and may change in any
commit. The descriptor's Go fields and its JSON form in this guide document
the in-tree contract; they are not a file format anyone loads. The
collection limits are host configuration
([Configuring the limits](#configuring-the-limits)), not part of a
provider's contract.

### Producer support

| Provider | Status | Evidence |
| --- | --- | --- |
| `konstapel-kyverno/v1` (Kyverno 1.19.2 ValidatingPolicy and PolicyReport) | Installed and supported: the only provider in the production registry | The saved live Kyverno 1.19.2 reports, the Kyverno conformance cases, and the live acceptance groups |
| `konstapel-reporttest/v1` | Test-only. Never registered, shipped or selectable | Synthetic fixtures. They prove the shared plumbing only |
| Trivy, or any other producer | Not supported | None. Each needs its own change with live producer compatibility tests |

## What this contract does not establish

- No new production provider. A provider is supported only after it passes
  shared conformance and its own live compatibility tests against the real
  producer, through its own change. Trivy integration is deferred by the
  owner and must prove digest/owner correlation, evaluation time, filtering
  and missing evidence against real reports.
- No runtime plugin loading, provider CRD, marketplace, scanner
  orchestration, mixed-provider binding, or new outcome or exception API.
