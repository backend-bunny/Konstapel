# Continuous assessment contract (v1alpha1)

This guide documents the shared request, run, and package contract owned by
`add-continuous-assessments`. Application teams create namespaced
`AssessmentRequest` resources; the controller and platform operators create
protected, cluster-scoped `AssessmentRun` resources. Each run freezes a scope
and produces one package, which a storage backend publishes.

This is an alpha API and the contract phase only (task group 1). The scheduler,
collector, scoped export, and binding `spec.assessment` settings arrive in later
task groups. Applying these CRDs schedules nothing yet. The capability spec is
[continuous-assessments](../../openspec/changes/add-continuous-assessments/specs/continuous-assessments/spec.md).

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
