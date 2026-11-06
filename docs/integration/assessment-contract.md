# Continuous assessment contract (v1alpha1)

This guide documents the shared request, run, and package contract owned by
`add-continuous-assessments`. Application teams create namespaced
`AssessmentRequest` resources; the controller and platform operators create
protected, cluster-scoped `AssessmentRun` resources. Each run freezes a scope
and produces one package, which a storage backend publishes.

This is an alpha API and the contract phase only (task group 1). The scheduler,
collector, scoped export, and binding `spec.assessment` settings arrive in later
task groups. Applying these CRDs schedules nothing yet. The capability spec is
[continuous-assessments](../../openspec/specs/continuous-assessments/spec.md).

For operator and team workflows (schedules, on-demand runs, reading results,
namespace download handoff), see [assessment workflows](assessment-workflows.md).

## Ownership

| Path | Owner | Contents |
| --- | --- | --- |
| `api/v1alpha1/assessment*_types.go` | continuous assessments | AssessmentRequest, AssessmentRun, shared summary and publication status types |
| `config/crd/bases/compliance.erenius.io_assessment*.yaml` | continuous assessments | Generated CRDs. Do not edit by hand. |
| `config/rbac/assessment-*.yaml`, `config/rbac/controller-assessments.yaml` | continuous assessments | Team, platform, and controller ClusterRoles |
| `config/admission/` | continuous assessments | Requester attribution and run-scope admission policies |
| `internal/publication/` | continuous assessments | Package descriptor, publication status/receipt, `Publisher` interface, API converters |
| `internal/publication/fake/` | continuous assessments | In-memory publisher for scheduler/collector tests |
| `testdata/publication/` | continuous assessments | Frozen package fixtures |
| `testdata/assessments/examples/` | continuous assessments | Valid request/run examples |
| S3 adapter, archive/commit logic, download service, retention execution | `add-s3-evidence-publishing` | Implements `publication.Publisher`; does not edit the files above |

API changes the S3 work needs go through this change after rebasing; there is no
second schema generator. Regenerate after editing `api/`:

```sh
devbox run -- scripts/generate.sh
```

## Resources

### AssessmentRequest (namespaced)

```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRequest
metadata: {name: nightly-check, namespace: team-a}
spec:
  bindingRef: {name: baseline-audit}
```

- The request's namespace is its maximum scope. The spec is immutable.
- `spec.requester` is set at admission from the authenticated user (see
  [Admission](#admission)). Any value the creator supplies is overwritten.
- The controller resolves the binding UID and namespace UID, rechecks that the
  binding selects the namespace when execution starts, and otherwise sets
  `Rejected` with reason `NamespaceNotInScope`. It never substitutes a
  full-binding run.
- Status holds only a sanitized summary (evidence completeness, outcome counts,
  export state), the internal run reference, and an opaque `artifactRef`. It
  holds no inventory, storage location, credential, or download token.
- Deleting a request stops future team downloads through it. It does not delete
  the run record or cancel retention cleanup.

### AssessmentRun (cluster-scoped, protected)

| Field | Platform operator | Controller |
| --- | --- | --- |
| `spec.bindingRef` | yes | yes |
| `spec.scope` | `Binding` only | `Binding` or `Namespace` |
| `spec.request` | no | `Namespace` scope only, required |
| `spec.trigger.type` | absent or `Manual` | `Manual`, `Scheduled` (with `scheduledTime`), `Request` |
| `status` | read | read/write |

CRD rules enforce that the spec is immutable, that `request` is present exactly
for `Namespace` scope, that `Namespace` scope pairs with a `Request` trigger, and
that `scheduledTime` appears only on `Scheduled` triggers. Admission policy
enforces the operator/controller column split.

A run has no owner reference to its binding or request: a cluster-scoped run
cannot be owned by a namespaced request, and retained runs must outlive both.
The publisher's retention finalizer owns run finalization.

Run status records the frozen scope summary (cluster ID, namespace UID for
namespace runs, namespace count, scope revision and SHA-256), binding
configuration and enforcement revisions, the capture window, the summary, the
package descriptor digest, and the publication record. The full inventory lives
in the package, never in status.

## Access control

| Role | Bind with | Grants |
| --- | --- | --- |
| `konstapel-assessment-requester` | RoleBinding in the team namespace | get/list/watch/create/delete `assessmentrequests`; get `assessmentrequests/status` and `assessmentrequests/download` |
| `konstapel-assessment-operator` | ClusterRoleBinding to platform subjects | get/list/watch/create/delete `assessmentruns`; read runs/status, requests, request status; get `assessmentruns/download` |
| `konstapel-controller-assessments` | ClusterRoleBinding to the controller service account (the one configured for admission) | Create and manage runs; the only writer of request and run status; read bindings, profiles, namespaces |

None of these roles aggregates into the built-in `admin`, `edit`, or `view`
roles. Teams have no access to `AssessmentRun` objects.

### Download authorization attributes

`assessmentrequests/download` and `assessmentruns/download` are authorization
attributes checked by the evidence download service with SubjectAccessReview,
together with read permission on the object. They are not CRD subresources.

- Namespace downloads are addressed by request namespace, name, and UID. The
  service verifies the request UID and the namespace UID recorded at resolution,
  so a recreated namespace or request with the same name cannot reach earlier
  evidence.
- Platform downloads are addressed by run UID and stay platform-scoped even when
  a run happened to select one namespace.

### Admission

`config/admission/` contains in-tree admission policies (no webhook):

- `assessment-requester.yaml`: a MutatingAdmissionPolicy sets
  `spec.requester` from `request.userInfo` on create. A ValidatingAdmissionPolicy
  then rejects a request whose requester does not match the authenticated user.
  Both fail closed.
- `assessment-run-scope.yaml`: rejects `Namespace`-scope runs and
  `Scheduled`/`Request` triggers from any identity other than the controller
  service account. The policy reads that identity from the
  `konstapel-system/konstapel-assessment-admission` ConfigMap
  (`controllerServiceAccountNamespace`, `controllerServiceAccountName`,
  default `konstapel-system`/`konstapel-controller`). To run the controller
  under another service account, edit the ConfigMap, not the policy. Anyone who
  can write that ConfigMap can grant controller rights, so only platform
  administrators should have write access. Missing configuration fails closed:
  without the ConfigMap, every AssessmentRun create is denied, and with an empty
  key no identity counts as the controller.

Both use `admissionregistration.k8s.io/v1`. MutatingAdmissionPolicy at v1 needs
Kubernetes 1.36 or later; the pinned acceptance node image is 1.36.1.

## Package and publication contract

`internal/publication` is plain Go, apart from converters to the API types.

**Descriptor.** Each package directory contains `descriptor.json`
(`compliance.erenius.io/v1alpha1`, kind `PackageDescriptor`). It records:

- the run reference (cluster ID, binding UID, run UID)
- the package kind: `Assessment` or `Diagnostic`
- the frozen scope and its SHA-256
- the binding configuration, enforcement, and mapping revisions
- the capture window
- evidence counts, and outcome counts kept separately
- the producer and its validation checks
- a sorted file inventory with roles, SHA-256 digests, and sizes

`Descriptor.Validate` and `VerifyDir` enforce these rules:

- A namespace scope contains exactly its request's namespace UID. A binding
  scope carries no request.
- Paths are clean and relative, with no symlinks, special files, or
  uninventoried files.
- `Complete` requires every expected check to be attributable. `NoTargets` means
  zero expected checks. Missing, rejected, and unresolved checks stay in the
  denominator.
- Assessment packages contain OSCAL assessment results. Diagnostic packages
  declare a reason and the missing exports, and contain no OSCAL assessment
  documents.

**Scope projection.** The producer, not the publisher, projects evidence to the
frozen scope before export. A namespace package contains only safely
attributable content for its namespace. Extracts from mixed-scope reports keep
their source report UID and digest, the original result index, and a named
transformation. Content whose scope cannot be established is excluded and
counted as unresolved. A source digest is provenance, not a download capability
for the original report. The publisher independently validates descriptor scope
and file inventory, and it never re-labels a binding package as a namespace
package.

**Publisher.** A backend implements:

| Method | Contract |
| --- | --- |
| `Stage` | Verify the directory against its descriptor and stage it durably. Identical bytes for the same run return the existing staging; different bytes return `ErrConflict`. |
| `Recover` | Return the durable staging, or `ErrCaptureLost` if the bytes were lost before durable staging. The run then records `CaptureLost`; a newer assessment gets a new run identity. |
| `Publish` | Commit once. A retry after a lost response returns the original receipt, including its original retention and dates. |
| `Inspect` | Report `Status`. Only `Committed` is published output. |
| `Delete` | Remove owned objects after expiry, or return `ErrRetentionActive`. |

`RunRef.PublicationID()` is deterministic, so retries and new leaders converge
on one identity. `Receipt.ExpiresAt` must equal `PublishedAt` plus the retention
recorded at the first commit. `Status` holds only bounded references (at most
32 owned objects and 512-byte messages), and a Secret reference rather than
credentials. `ToAPI`/`FromAPI` convert it losslessly to
`AssessmentRun.status.publication`, and a test keeps the two field sets
identical. Storage errors are publication state only and never change evidence
or outcomes.

## Fixtures

| Fixture | Scope | Kind | Evidence | Outcomes |
| --- | --- | --- | --- | --- |
| `namespace-complete` | Namespace `team-a` | Assessment | Complete 3/3 | pass, fail, accepted risk |
| `namespace-incomplete` | Namespace `team-b` | Assessment | Incomplete: 1 attributable, 1 missing, 1 rejected | pass |
| `binding-diagnostic` | Binding, 2 namespaces | Diagnostic (`ExportFailed`) | Incomplete: 2 unresolved | pass, fail |
| `binding-no-targets` | Binding | Assessment | NoTargets | none |

After changing fixture files, regenerate their descriptors with
`devbox run -- go test ./internal/publication -run TestFixturesRoundTrip -update`.

These static fixtures are contract fixtures. Their assessment results are
schema-valid OSCAL 1.1.3, but their `import-ap` is a `urn:` reference, so they
do not pass full package validation (reference closure).

For a complete package, call
`publicationtest.FullAssessmentPackage(root, dir, run)` from
`internal/publication/publicationtest`. It exports the saved prototype capture
(`testdata/capture.json`) through the prototype's own export path, with no
plugin or cluster, and writes a descriptor. The result passes
`assessment.ValidatePackage`:

- OSCAL schemas for the plan, results, and SSP
- policy provenance and content checksums
- reference closure through the plan, SSP, and NIST catalog

It is a complete Binding-scope package with failing outcomes. Every reference
chain ends at the pinned NIST catalog (about 10 MB), so the package is generated
on demand rather than committed as a second copy. OSCAL UUIDs differ on every
call, so compare these packages by descriptor, not bytes.

## Binding assessment settings and the enforcement epoch

`ComplianceBinding.spec.assessment` configures continuous assessment:

| Setting | Default | Meaning |
| --- | --- | --- |
| `interval` | `24h` | Time between scheduled snapshots, measured from a persisted anchor. |
| `maxEvidenceAge` | `2h` | Oldest source evaluation accepted as current evidence at closure. |
| `collectionTimeout` | `5m` | Upper bound on how long a run waits for evidence. |
| `retention` | `2160h` | How long published packages are kept, fixed at publication (90 days). |

Values are positive Kubernetes/Go duration strings with the units `h`, `m`,
`s`, `ms`, `us` or `ns`, for example `90m`, `1h30m` or `8760h`. The API server
rejects days (`90d`), cron expressions, signs, zero, and values that overflow a
duration. Omitted settings default. An explicit `null` behaves like omission:
the API server prunes it and applies the default, so a null is never stored.
Short intervals do not make Kyverno re-evaluate unchanged resources faster; with
the starting chart's hourly background scan, a `maxEvidenceAge` below about an
hour repeatedly yields stale evidence.

Changing `spec.assessment` is a reporting-only edit. It advances
`metadata.generation` and `status.observedGeneration`, but not
`spec.enforcementEpoch`. Engine policy names, specs, and the contribution
revisions that exceptions bind to stay the same, so enforcement and accepted
exceptions are unaffected. The controller may still update provenance
annotations on the engine policies.

`spec.enforcementEpoch` is maintained by the MutatingAdmissionPolicy in
`config/admission/binding-enforcement-epoch.yaml`:

| Write | Epoch |
| --- | --- |
| create | 1 |
| update without a change to `profileRef`, `namespaceSelector` or `mode` | unchanged (carried forward even when the request omits it, as server-side apply and GitOps tools do) |
| update that changes any of them, including a rollback to earlier values | previous + 1 |

User-supplied values are overwritten. A CRD transition rule independently
rejects an epoch that disappears, decreases, or does not follow these rules.
`targeting.BindingEpoch` feeds the epoch into `EnforcementRevision`. Because
the epoch, not the generation, identifies enforcement, an A→B→A change gets a
new revision even if the controller missed the intermediate state.

**Migration.** Bindings created before the policy existed have no epoch.
`BindingEpoch` falls back to `metadata.generation`, which is the value their
current revisions were computed with. On their next write, the policy
initializes the epoch from the old generation (+1 if enforcement changed).
Unchanged bindings therefore keep their engine policies, and a later rollback
cannot reuse an old revision.

**Prerequisite.** The policy needs MutatingAdmissionPolicy at
`admissionregistration.k8s.io/v1`, which requires Kubernetes 1.36 or later. It
is served and enabled by default on the pinned 1.36.1 kind node. Install it
before the controller:

```sh
kubectl apply --server-side -f config/crd/bases -f config/admission
```

Without the policy:

- Updates to bindings that already have an epoch fail with
  `enforcementEpoch is maintained by admission`. They fail closed instead of
  silently rotating policies.
- Bindings created without it keep the generation fallback, and every edit,
  including reporting-only edits, rotates their policies, as before this
  change. The assessment controller will surface this as a run limitation when
  it is wired into the manager.

Verification: `scripts/targeting-live.sh` runs `TestLiveEnforcementEpoch` on a
disposable cluster with Kyverno. It checks migration, creation, a
reporting-only server-side apply that omits the epoch, a forged epoch, an
A→B→A change while the manager is stopped, and the fail-closed behavior without
the policy.

## Scheduling and run execution

**Prerequisite.** Scheduling runs only when an evidence publisher, a staging
directory, and a content root are configured through
`controller.ConfigureAssessments`. `add-s3-evidence-publishing` supplies the
production publisher. Until one is configured, every binding's
`status.assessment.current.limitations` says
`scheduled snapshots are disabled: no evidence publisher is configured`, and no
runs are created. Current evidence status (above) works without a publisher.

**Planning.** On every reconcile, the assessment controller runs
`schedule.Plan` for the binding and persists the result in
`status.assessment.schedule` and `latestRun`, applied together with `current`:

- The first plan starts an initial scheduled run. Later runs are due at
  `anchor + k × interval`. Changing the interval re-anchors at the last
  scheduled time.
- Runs are created only from the binding's current version, re-read without
  the cache. A plan from a stale cached binding conflicts and replans, so
  a scheduled run (named from its due time) is never created twice.
- Missed due times coalesce into one run at the latest due time. The skipped
  times are recorded in `gaps` and `missedTotal` and never claimed as
  assessed.
- Each binding has at most one active run (`schedule.activeRun`). When the slot
  frees, an overdue scheduled run starts before queued platform manual runs,
  which wait as `Pending` in creation order. Manual runs never move the
  schedule.
- Scheduled runs are named `<binding>-s-<hash(binding UID, scheduled time)>`.
  A retry or a new leader finds the existing run instead of creating a
  duplicate snapshot.

**Execution.** The run controller (bounded concurrency, default 4) executes
only the run its binding's schedule admitted:

| Phase | What happens |
| --- | --- |
| `Pending` | Not yet admitted. |
| `Collecting` | Scope frozen into `<staging>/<run UID>/capture.json`. Each poll records workload, namespace, and configuration changes against the frozen scope and attaches the current reports. Collection closes at `collectionTimeout`, or earlier once evidence is `Complete`. |
| `Publishing` | The capture is evaluated and exported (Assessment or Diagnostic package). The summary, descriptor digest, and `EvidenceComplete` condition are recorded, then the frozen package is staged and published with the binding's retention. Failures retry until `PublishTimeout` after closure. |
| `Completed` | `status.publication` holds the commit receipt; staging is removed. |
| `Failed` | An explicit condition reason, then the slot is released. Recorded evidence is kept. |

Failure reasons:

- `PublicationFailed`: the publisher was still failing at the timeout.
- `CaptureLost`: the staged capture or package disappeared, for example after
  a restart without durable staging. The run is never reconstructed from the
  changed cluster, and a later run assesses current state.
- `BindingNotFound`: the binding is missing or was replaced.
- `NamespaceNotInScope`: the binding no longer selects the request's
  namespace when the run starts, or the namespace was recreated.
- `RequestNotFound`: the request was deleted or recreated before the run
  started.

**Recovery and frozen snapshots.** A run's staging directory holds:

- `capture.json`: the frozen scope plus the observations so far;
- `closed.json`: written at closure, before export, holding the closed
  capture and its evaluation;
- `package/`: the exported package.

Recovery follows from these:

- **Restart during collection.** The run resumes the same frozen capture:
  window, scope, and expected inventory are unchanged. Each capture records the
  controller instance observing it. A different instance (restart or leader
  change) records a `WatchDiscontinuity`, so evaluations from before the gap no
  longer count as current evidence.
- **Crash after closure.** If export or the status update did not complete, the
  retry exports the same `closed.json` snapshot, with the same closing time and
  evaluation. It never collects newer observations under the run's identity.
- **After the descriptor digest is recorded.** Publication uses only package
  bytes with that digest. A changed staged package fails the run as
  `CaptureLost`. If the local package is gone, the publisher's durable staging
  is recovered (`Publisher.Recover`). If that is gone too, the run fails as
  `CaptureLost`, with export state `CaptureLost`.
- **Lost responses.** Stage and publish are idempotent per run, so a lost
  response converges on the original commit receipt.

`AssessmentRuntime.StagingDir` must be on a persistent volume for runs to
survive a controller restart. On ephemeral storage, a restart turns in-flight
runs into explicit `CaptureLost` failures, and a later run assesses current
state.

**Team requests.** A team creates an `AssessmentRequest` in its namespace:

1. The controller resolves the binding UID and namespace UID into the
   request's status. If the binding's selector does not match the namespace,
   the request becomes `Rejected` with reason `NamespaceNotInScope`, and no
   broader run is substituted.
2. In-scope requests queue behind the binding's single slot, in creation
   order, after any overdue scheduled run. Each binding queues at most
   `AssessmentRuntime.MaxQueue` (default 100) pending requests; newer ones are
   `Rejected` with reason `QueueFull`. Bound each team with a ResourceQuota on
   `count/assessmentrequests.compliance.erenius.io` in its namespace.
3. An admitted request gets a namespace run named
   `<binding>-r-<hash(binding UID, request UID)>`, and the request becomes
   `Running` with a reference to it. When the run starts, it rechecks that the
   request and namespace UIDs are unchanged and that the binding still
   selects the namespace. Its capture is projected to the namespace at freeze
   and on every poll, and the package is exported with namespace scope.
4. When the run ends, the request becomes `Completed`, `Failed`, or
   `Rejected`, with a sanitized status: evidence and outcome counts, the run
   reference, and `artifactRef` (the opaque publication ID). Condition
   messages are fixed, team-safe texts. Operator detail such as storage
   errors stays on the platform-scoped run.

Deleting a request does not cancel a run that has started; its publication
record is retained. A recreated request or namespace is never adopted.
Requests never change the binding's schedule, settings, or enforcement.

## Collector evidence rules

`internal/collector` implements the controller's capture path (prototype v1
captures stay in `internal/assessment`).

- **Expected inventory.** `FreezeScope` builds the frozen inventory when a run
  starts, from three inputs: `targeting.ExpectedEvidence` subjects, one check
  per CEL sub-validation of each rendered engine policy, and the listed
  workloads. Reports are never an input, so a missing report stays missing.
  Overlapping bindings remain separate contributions. An observation's
  identity covers:
  - cluster
  - namespace UID
  - workload UID and state digest (spec, labels, annotations)
  - check
  - binding and revision
  - source and mapping digests
- **Scope changes.** The `Tracker` records changes during collection without
  altering the frozen scope:
  - workloads updated, removed, replaced, or added
  - namespaces joined, left, or recreated
  - revision changes and stale scope
  - watch discontinuities
- **Attributable evidence.** `CaptureV2.Evaluate` counts an expected
  observation as attributable only if a report result meets all of these:
  - it names the observation's engine policy (whose name binds the binding,
    policy, and revision), sub-validation index, and workload UID
  - it has a valid source evaluation time, no later than closure
  - it was evaluated strictly after the workload's continuity boundary and
    after the last watch discontinuity
  - it is at most `maxEvidenceAge` old at closure
  - its subject is unchanged during collection
  - it does not conflict with another result evaluated at the same time

  A result timestamp alone never proves which state was evaluated, and
  relisting after a restart does not create history.
- **Completeness.** Each observation is `Attributable`, `Missing` (no
  matching result), `Rejected` (results exist but none qualifies, with
  reasons), or `Unresolved` (scope changed or results conflict). Evidence
  completeness is:
  - `Complete`: every expected observation is attributable and no binding or
    policy scope is stale
  - `NoTargets`: nothing is expected and nothing is stale
  - `Incomplete`: everything else

  A stale scope (`staleScopes`) always makes evidence `Incomplete`. Outcome
  counts are reported separately and never aggregate into a pass.
  `NextExpiry` gives the time current status must be re-evaluated, without
  waiting for an event.

Engine-provided state correlation (task 4.3) may later replace the
conservative continuity boundary where it is verified.

**Engine policy verification.** Every capture records its subjects'
contributions and the engine policies observed at freeze (name, labels,
annotations, spec). `collector.VerifyEnginePolicies` re-renders each policy
with targeting's `Render`, from the contribution and the source manifest
named by the subject's source digest. It then requires:

- the same name, which binds binding, policy, and revision;
- an identical spec;
- the rendered labels and annotations;
- checks enumerated from that spec.

This is the comparison delivery uses to decide a policy is current.

- At runtime, a live engine policy that differs from the render of the
  verified content (drift, for example a hand edit) yields no evidence. It
  counts as stale scope `EnginePolicyDrift` until delivery repairs it.
- In packages, `collector.VerifyPackage` rebuilds the sources from the
  packaged `content/`: `content/SHA256SUMS` must hash to every contribution's
  pinned bundle digest, and every listed file must match its sum. Export runs
  it before accepting an assessment package, and a failure becomes a
  `Diagnostic` package. A changed policy expression or source digest
  therefore cannot be legitimized by recomputing the capture's or the
  descriptor's own hashes.
- Limitation: a verifier cannot recompute `EnforcementRevision` from a
  recorded contribution, because the contribution does not carry the binding
  enforcement epoch. The revision is bound through the engine policy name and
  its revision annotation, not recomputed. The prototype v1 capture keeps its
  own `assessment.VerifyPolicy` provenance checks unchanged.

## Package export

`collector.Export` packages one frozen, evaluated capture.

- **Assessment package.** When the mapping and content allow it, the package
  holds the OSCAL 1.1.3 assessment plan, results, and a generated context SSP,
  plus the content they reference. Schemas and reference closure are checked
  before the package is accepted. This applies to incomplete evidence too.
  - Each logical policy is one C2P check, with one subject per expected
    observation. Overlapping binding contributions are therefore distinct
    subjects of one control mapping and never add coverage.
  - Each subject records its evidence state and full identity props. Only
    attributable subjects carry an evaluation time and source report
    reference.
  - A not-satisfied finding is emitted only for an attributable failure.
    Missing, rejected, or unresolved evidence and zero targets make no control
    determination. No result ever claims a control is satisfied.
- **Diagnostic package.** If plan, report, schema, or reference validation
  fails, every OSCAL document and the copied content are removed. The package
  becomes `Diagnostic` with reason `ExportFailed` and the error message.
  Evidence completeness and outcome counts are recorded unchanged: export
  state is separate from evidence.
- **Always present:** `capture.json`, `evaluation.json` (per-observation states
  and reasons), `summary.json`, and `descriptor.json`. The descriptor is
  verified against the directory before `Export` returns.

**Namespace packages.** A namespace package is exported only from
`collector.Project(capture, namespaceUID)`, and `Export` re-checks the
projection with `ValidateProjection`. It refuses an unprojected capture with
namespace scope, and a projection relabelled as a binding package. The
projection:

- keeps only the namespace's subjects, checks, workloads, expected
  observations, and scope changes;
- keeps stale-scope reasons and policies, but drops their messages and
  configuration-change details, which may name other namespaces;
- rebuilds every report result from allowlisted fields (policy, outcome,
  rule, validation index, timestamp, in-scope resource references).
  Report-level labels, summaries, annotations, and any other fields are
  dropped;
- copies a result's message only when all of its resources are in the
  namespace (`exact`). A mixed-scope result keeps only its in-scope references
  and loses its message (`resource-filtered/v1`);
- withholds results whose resources lack a namespace or UID, recording only
  the source report UID and result index;
- records each extract's source report UID, report SHA-256, and original
  result index under `konstapelSource`. Evaluation and OSCAL subjects
  reference that original index, so team evidence stays traceable to the
  cluster-wide report without disclosing it.

## Capture revisions, correlation, and engine limits

**Capture revisions.** Prototype captures are version 1 (`internal/assessment`,
unchanged). Controller captures are version 2 (`internal/collector`).
`CaptureVersion` dispatches between them, and neither path accepts the
other's format. A v2 capture records:

- its frozen scope: subjects, stale scopes, checks, workloads, and the derived
  expected inventory;
- the contributions and engine policies needed to re-verify;
- reports, scope changes, and the observing controller instance;
- for namespace packages, the projection.

**Supported correlation.** Evidence from the pinned engine (Kyverno 1.19.2,
see [versions.json](versions.json)) cannot be attributed to a workload state by
the engine's own data. `TestLiveEngineCorrelation` recorded a pod before and
after an in-place label update; the raw reports are in
[engine-correlation.json](engine-correlation.json):

- A PolicyReport's `scope` names the resource by apiVersion, kind, namespace,
  name, and UID only. It has no `resourceVersion`, generation, or state
  digest.
- Results carry outcome, timestamp, and `properties` (`cel.validationIndex` and
  `process: background scan`). Report metadata has only a `managed-by` label.
- An in-place label change keeps the pod's `metadata.generation` at 1.
- The background scan (15s in the test environment) rewrites the report with a
  new timestamp whether or not anything changed.

Engine-provided correlation is therefore unsupported, and Konstapel uses only
the conservative rule:

- a result counts for a workload state only if it was evaluated strictly after
  the controller observed that state;
- no watch discontinuity may lie between that observation and the evaluation;
- the state must be unchanged at closure.

In the recorded run, current evidence went `Incomplete` within a second of the
update. It became `Complete` again only with the first background evaluation
after the update. `TestSavedEngineCorrelationEvidence` replays the recorded
reports without a cluster: the pre-update result is rejected for the new state,
and the next evaluation is attributable.

**Scope windows.** A run's snapshot is a bounded observation window from
freeze to closure (at most `collectionTimeout`), not an atomic transaction
across the cluster. Changes inside the window are recorded against the frozen
scope and never broaden or shrink it.

**Remaining engine limits.**

- Kyverno's background scan evaluates from its own informer cache. A result
  stamped after the controller's observation could, in principle, describe a
  cached object older than the one the controller observed. No report field
  can rule this out, so the rule above bounds the risk by ordering and the
  state recheck; it does not prove it absent.
- After a controller start, restart, or leader change, earlier evaluations no
  longer count. Evidence becomes attributable again only after the next
  engine evaluation (one background scan interval).
- Admission results (`process` other than background scan) describe the
  admitted object. They follow the same rule and get no special trust.

## Integration sequence

1. This contract merges first. It needs no scheduler.
2. `add-s3-evidence-publishing` implements `publication.Publisher` against the
   fixtures and the fake's behavior. It can merge its adapter before the
   scheduler is complete. `internal/publication/fake` already consumes this
   contract through exported API only, which is the same position as the S3
   adapter.
3. The scheduler and collector (groups 3–5) use the fake publisher until the
   S3 adapter lands. They then write `publication.ToAPI(status)` into run
   status.
4. Full acceptance (group 6) joins both implementations with the targeting and
   exception contracts.

## Acceptance evidence

[assessment-acceptance.json](assessment-acceptance.json) records the final
`task acceptance` run from clean state. It includes the prototype regressions,
Chainsaw, offline replay, every live assessment, targeting and storage test,
and exception admission, with versions, results, per-test evidence steps and
package digests. `scripts/check-assessment-access.sh` was run on its own
disposable cluster. All task-owned clusters and containers were removed
afterwards.

## Validation

- `devbox run -- task check` runs the cluster-free checks:
  - CRD create and update validation through `internal/crdtest`, including CEL
    transition rules
  - static RBAC rules
  - descriptor and status validation
  - fixture round-trips
  - fake-publisher idempotence, conflict, outage, capture-loss, and retention
    cases
- `devbox run -- scripts/check-assessment-access.sh KUBECONFIG OUTPUT` checks
  RBAC, admission policies, and CRD validation on a disposable cluster that you
  create and delete. On 2026-11-05 it passed 24/24 checks on kind with
  Kubernetes 1.36.1:
  - requester identity is recorded, and a forged requester is overwritten
  - cross-namespace reads and creates are denied
  - teams cannot create or read runs, and cannot write status
  - platform operators cannot create Namespace-scope runs or forge Scheduled
    triggers
  - the controller can create runs and write status
  - specs are immutable for every identity
