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
of each provider. Within the collection limits, nothing in this guide
changes how existing bindings, profiles, delivery, collection, evaluation
or export behave:

- The bundle compatibility check (`content.Compatibility`, allowlist
  `konstapel-kyverno/v1`) and the targeting resolver still make the
  production decisions.
- The registry encodes those decisions, and tests keep the two in
  agreement.
- The registry does not yet gate the resolver.
- The provider-aware capture boundary, shared evaluation and the full
  authoring recipe are later tasks of the change.

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
| `capture` | Capture payload versions it `write`s and `read`s. `write` must be in `read`, so readers ship before writers. |
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
  accepts. The controller writes 2.
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
| `IncompatibleVersion` | The provider is installed at another contract version, or cannot read the capture version. | `ContentUnavailable` |
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
can be read. It never falls back to another provider or version.

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
   afterwards and are evaluated unchanged by `collector.CaptureV2.Evaluate`.

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
  Recording collection limitations in a capture belongs to the capture
  boundary (task 3.1).

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
supplies an `Adapter` (`Inventory`, `Evaluate`, `WithoutEvidence`). Besides
the golden comparison, every case must satisfy these rules:

- The expected inventory comes from the frozen scope alone. It is unchanged
  when all evidence is removed. Without evidence, every observation is
  `Missing`, or `Unresolved` for scope it cannot attribute. Nothing passes.
- Every expected observation is evaluated exactly once. None is dropped,
  invented or duplicated.
- Only `Attributable` evidence has a raw outcome, a normalized outcome
  (`pass`, `fail`, `error`, `skip`, `unknown`) and an evaluation time no
  later than the evaluation time. `Missing`, `Rejected` and `Unresolved`
  carry no outcome.
- A raw outcome always normalizes the same way. Raw values without a summary
  field, such as a warning, count once as `unknown`, and the raw value is
  kept. `NotApplicable` is never a pass.
- Evaluation is deterministic for the same input and time.

`TestHarnessCatchesSemanticRegressions` mutates a working adapter in
specific ways. Each mutation must fail the harness: missing evidence that
passes, an inventory derived from evidence, a warning counted as a pass, an
outcome on rejected evidence, a report update time used as freshness,
duplicate credit, inconsistent normalization, nondeterminism, and others.

Cases live under `testdata/providers/conformance/v1/<provider>/`:

- `konstapel-kyverno/background-1.19.2`: the saved live Kyverno 1.19.2
  background evidence, evaluated unchanged by `collector.CaptureV2.Evaluate`.
  The result is 30 expected, 28 attributable, 2 missing, 24 pass and 4 fail.
- `konstapel-kyverno/synthetic-unknowns`: synthetic reports over that frozen
  scope, with a warn, conflicting results, untimed and future results, and a
  skip.
- `konstapel-reporttest/*`: the synthetic reporting shape described below.

`TestKyvernoHarnessSummaryMatchesCollector` checks that the harness summary
equals the controller's `collector.Tally` result for the Kyverno cases. The
current Kyverno evaluator closes at the capture window. Its adapter refuses
any other evaluation time rather than substituting the closure; explicit
time inputs are task 4.1.

The cases run in the normal test entry points (`task test`, `task check`).
After an intended semantic change, rewrite the golden results and review the
diff:

```sh
go test ./internal/provider/kyverno ./internal/provider/reporttest -run Conformance -update
```

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

Build tags were not used: the cases must run in the plain `go test ./...`
behind `task check`.

The reporting provider and its fixtures prove plumbing only. They are not a
model of Trivy or of any real producer, and they are not producer
compatibility evidence.

## Internal interfaces and versioned contracts

These are versioned contracts:

- the bundle descriptor's `compatibility.provider` value
- the capture versions recorded in packages
- the conformance case format `konstapel.provider-conformance/v1`

The Go types (`provider.Descriptor`, `Registry`, `Selection`, `Scope`,
`Sources`, `SourceReader`, `Limits`, `Collect`, `LimitError`,
`conformance.Adapter`, `RecordingClient`, `PagingClient`, and the provider
adapters) are internal to this repository. They are not a stable
third-party SDK and may change with the remaining groups of the change. The
collection limits are host constants, not a configuration contract.

## What this contract does not establish

- No new production provider. A provider is supported only after it passes
  shared conformance and its own live compatibility tests against the real
  producer, through its own change. Trivy integration is deferred by the
  owner and must prove digest/owner correlation, evaluation time, filtering
  and missing evidence against real reports.
- No runtime plugin loading, provider CRD, marketplace, scanner
  orchestration, mixed-provider binding, or new outcome or exception API.
