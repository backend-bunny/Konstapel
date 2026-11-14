# S3 evidence backend

`add-s3-evidence-publishing` stores assessment packages in an S3-compatible
bucket. This guide covers the parts implemented so far: the platform-controlled
destination, setup and permissions, the compatibility probe that decides whether
a backend may be used, package kinds, the publisher's commit protocol, recovery,
the download service, retention, and teardown.

## EvidenceDestination (API)

Destinations are moving from a deployment file to the cluster-scoped,
platform-managed `EvidenceDestination` resource
(`compliance.erenius.io/v1alpha1`, short name `evdest`):

```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceDestination
metadata: {name: primary}
spec:
  s3:
    endpoint: https://s3.example.internal   # immutable
    bucket: konstapel-evidence              # immutable
    region: eu-north-1                      # immutable
    prefix: clusters/prod                   # immutable (adding or removing it too)
    addressing: path                        # default
    credentialSecret: {name: konstapel-s3}  # or workloadIdentity: true; rotatable
    caTrust: {name: s3-ca, key: ca.crt}     # optional ConfigMap; rotatable
  deletionPolicy: Retire                    # default; Orphan is the audited handoff
```

- **Immutable location.** The API server rejects any change to endpoint, bucket,
  region or prefix, including while the destination is retiring. A new location
  is a new resource and an explicit reference switch, so no edit moves
  evidence. Credentials, CA trust and the credential source can rotate.
- **Credential and trust references.** These resolve only in the controller
  namespace. Setting a `namespace` on them is rejected, and there are no file
  paths.
- **Validation.** Exactly one credential source must be set. `https` is
  required, except for an isolated `developmentFixture`.
- **Access.** Only `konstapel-compliance-admin` can create or change
  destinations, and `konstapel-compliance-viewer` can read them. Only the
  controller writes status. Application teams and the assessment operator
  cannot create, read or change destinations, or read Secrets in the
  controller namespace. `scripts/check-assessment-access.sh` verifies this
  against a real API server.
- **Status.** Status reports the observed generation, the `Ready` and
  `Retiring` conditions, outstanding run and package counts, runs whose
  expiry is still unknown, the latest retained expiry, and cleanup blockers.
- **Signing.** The optional `spec.signing` sets the destination's evidence
  signing policy and key Secret; with it, status adds `signing` and a
  `SigningReady` condition. Without it nothing changes. See
  [evidence signing](evidence-signing.md#set-up-signing-for-a-destination).

**Readiness.** The controller probes each destination's backend with its
current credentials and CA trust when the spec changes and every 5 minutes. It
records the `Ready` condition, with the probe's problem as the message, for the
observed generation.

**Selection.** A binding selects its destination with
`spec.assessment.destinationRef: {name, uid}`. Without one it inherits the
central default, set in the ConfigMap
`konstapel-system/konstapel-evidence-destination` (keys
`defaultDestinationName` and `defaultDestinationUID`). Only platform
administrators should be able to write that ConfigMap. AssessmentRequests have
no storage selector and always inherit their binding.

The resolved selection appears in `status.assessment.destination`:

| Field | Meaning |
| --- | --- |
| `source` | `Binding`, `Default`, or `None` |
| `ref` | The selected destination |
| `ready` | Whether the selection can be used |
| `reason` | `Selected`, `NoDefaultDestination`, `InvalidDefaultDestination`, `DestinationNotFound`, `DestinationUIDMismatch` (the name now refers to a recreated destination), `DestinationRetiring`, or `DestinationNotReady` |

An unusable selection is reported and never replaced by the default or any
other destination. It does not touch `Resolved`/`EngineReady`, and changing
`destinationRef` is a reporting-only edit, so it never changes the enforcement
epoch or engine policy identities.

**Run pins.** When a run starts, it pins its binding's selected destination
before anything reaches storage:

1. **Intent.** The run is labelled `compliance.erenius.io/destination-uid`
   with the destination's UID. The label is never changed afterwards.
2. **Confirmation.** The destination is re-read without the cache. It must
   have the same UID and must not be retiring. The finalizer
   `compliance.erenius.io/destination` is added with an update conditioned on
   the destination's resourceVersion, so a deletion racing the confirmation
   conflicts and the start retries.
3. **Recording.** `status.destination` (name, UID, endpoint, bucket, region,
   prefix, source, `pinnedAt`) is written with the run's transition to
   `Collecting`.

A selection that loses to deletion, replacement or readiness fails the run as
`DestinationUnavailable` with no storage writes. A start interrupted after step
1 keeps the labelled destination when it resumes, whatever the selection says
by then.

Staging, publication, retries, recovery, integrity checks, expiry deletion,
attempt cleanup and downloads all use the pinned destination. Its publisher is
built from that destination's current credentials and CA, and rebuilt when
its generation changes, so rotation applies to historical packages. A pin is
served only by the destination with its UID and recorded location. A recreated
destination with the same name never serves it. Missing credentials are a
visible, retryable failure of each operation, never a fallback.

Scheduling follows the selection. While a binding's selected destination is
unusable, no runs start and `status.assessment.current` names the reason.
A binding with no selection has no destination: scheduling is disabled with
`no evidence destination is selected`. The legacy `--evidence-destination`
file has been removed. To move runs it published, see Upgrading from the legacy
destination file.

**Retirement.** Deleting a destination retires it (`deletionPolicy: Retire`).
The destination reconciler counts what the destination still owes from an
uncached list of runs labelled with its UID:
- `outstandingRuns`: runs still starting or running. A labelled run that is
  not pinned yet counts, because it may still be accepted.
- `unknownExpiryRuns`: those same runs, whose expiry is not known yet.
- `outstandingPackages`: completed runs whose package is not deleted yet.
- `latestRetainedExpiry`: the latest expiry among those packages.
- `cleanupBlockers`: runs whose expiry deletion or attempt cleanup is
  `RetentionBlocked`, `DeletionFailed` or `CleanupPending`, with the message.

While deleting, the `Retiring` condition is `Retiring`, or `RetirementBlocked`
when blockers exist. New runs are refused, because selection reports
`DestinationRetiring` with no fallback. Pinned runs finish publishing there,
packages stay downloadable until expiry, and expiry deletion and attempt
cleanup carry on with the original UID and credentials (which can still
rotate). Blockers are retried. Unfinished publication is never treated as an
empty destination. The finalizer is removed only when nothing is outstanding.
**Orphan intent.** An administrator can choose to hand the remaining storage
responsibility to an operator instead of retiring normally, either before
deleting the destination or as an escalation of a blocked retirement:

```sh
kubectl patch evidencedestination primary --type=merge \
  -p '{"spec":{"deletionPolicy":"Orphan","orphan":{"reason":"bucket handed to the archive team"}}}'
```

- **Reason required.** A non-blank `spec.orphan.reason` is required with
  `deletionPolicy: Orphan`, and `orphan` is allowed only with that policy.
- **Actor recorded by admission.** The `konstapel-destination-orphan`
  admission policies (`config/admission/evidence-destination-orphan.yaml`)
  write the authenticated user into `spec.orphan.actor`/`actorUID` whenever
  the request is set or its reason changes. A forged actor is overwritten,
  or rejected when the reason is unchanged. Nothing is inferred from
  annotations, managedFields or the controller's account.
- **Selecting Orphan alone does nothing.** It doesn't delete, move or stop
  anything while the destination exists.
- **Acceptance is irreversible.** When the destination is deleted, the
  controller records `status.orphanIntent` (reason, actor, actorUID,
  `acceptedAt`), which only it can write. An unattributed request, with no
  actor because the policy isn't installed, is not accepted, and the
  `Retiring` condition says so. From acceptance on, admission freezes
  `deletionPolicy: Orphan` and `spec.orphan`, so the handoff can't be changed
  or reversed. Credentials can still rotate.

**Orphan fence.** From acceptance on, Konstapel issues no remote operation for
that destination of any kind:
- **Run reconciler.** A run pinned to the destination re-reads it uncached on
  every reconcile. When the handoff is accepted, the run starts no
  publication, retry, recovery, retention deletion, attempt cleanup
  (multipart uploads are never aborted) or integrity check. Its record is held
  unchanged, and a restarted controller sees the same fence from the durable
  status.
- **Destination reconciler.** It stops probing (`Ready=HandedOff`), cancels
  this process's in-flight operations for the destination and waits up to 30s
  for them to drain. It records `status.orphanHandoff` with `fencedAt`,
  `drained`, and the operations still in flight at the deadline
  (`uncertainOperations`). Their remote outcome is unknown, and nothing claims
  they were reversed or that stored bytes were removed. Probes are bounded at
  30s, so an unreachable backend never stalls handoff.
- **Download service.** It answers 410 for the destination's packages.
  Already delivered bytes are not revoked.
- **Late responses.** A response that arrives after the fence may record what
  really happened, such as a commit that completed. It never restarts
  retention or cleanup.

**Orphan inventory.** After the fence, the destination reconciler saves an
independent record of what was handed off. It is a set of immutable
ConfigMaps in `konstapel-system` with no owner references, so it outlives the
destination, its runs, and package expiry. Konstapel never deletes it; a
platform administrator removes it after the external handoff.
- **Header** `konstapel-orphan-<destination UID>` (written last, so its
  presence means the record is complete): handoff identity, reason, actor and
  actorUID, `acceptedAt`, `fencedAt`, whether in-flight work drained, the
  uncertain operations, the destination UID and location (endpoint, bucket,
  region, prefix), and the name and SHA-256 of every chunk.
- **Chunks** `konstapel-orphan-<destination UID>-<n>` (each under 512 KiB):
  every run pinned to the destination, including records already pending
  deletion, with binding, cluster and namespace scope UIDs, phase, the run's
  owned key prefix, and its original publication receipt (owned keys,
  version and upload IDs, commit manifest and archive versions, package
  digest and size, `publishedAt`, `expiresAt`, cleanup state).
- **Remote state.** The inventory is built from cluster state only. Under the
  fence the backend is not contacted, so `remoteState: NotEnumerated` says
  the objects, versions, and incomplete uploads under each owned prefix must
  be listed at the destination itself.
- **No credentials.** Credential references are removed from receipts, and
  no evidence bytes are copied.
- **Failure.** If the ConfigMaps can't be saved, the fence and every
  finalizer stay in place, `Retiring` reports `OrphanInventoryPending`, and
  the save is retried. Retries are idempotent: an existing inventory is kept,
  never rewritten.

`status.orphanHandoff.inventory` names the header, chunk and run counts, and
`savedAt`. Export it with:

```sh
kubectl -n konstapel-system get configmap \
  -l compliance.erenius.io/orphan-handoff=<destination UID> -o yaml
```

**Orphaned disposition.** Once the inventory is saved, each run pinned to the
destination is marked handed off and its retention finalizer is released.
Nothing here contacts storage.
- `status.destination.orphanedAt` is set. Konstapel never issues a storage
  operation for the run again, even after the destination is gone or another
  destination uses the same location.
- A publication becomes `phase: Orphaned`, `availability: Unavailable`,
  `cleanup.state: Orphaned`. Its original receipt is kept: publication ID,
  commit manifest and archive versions, digests, size, `publishedAt`, and
  `expiresAt`. The expiry is now historical; Konstapel won't delete the
  package when it passes. Managed downloads answer 410.
- A publication already verified `Deleted` stays `Deleted`.
- An unfinished run ends `Failed` with `Published=False`
  (`DestinationOrphaned`). It never claims success, and its binding's active
  run slot is released.
- Runs already being deleted are in the inventory before their finalizer is
  released.

When every run is handed off, the destination's own finalizer is released and
the destination is deleted. The inventory ConfigMaps remain.

**Handed-off ownership is never adopted.** No automatic path picks up
orphaned evidence again:
- **Per-run cleanup only.** Publication, recovery, attempt cleanup,
  integrity checks, and retention deletion run per run, under that run's own
  key prefix, and only for runs that aren't handed off. No worker sweeps a
  destination's bucket or prefix. Probes write and remove only their own
  random `konstapel-probe/` keys.
- **Recreated destinations.** A destination recreated under the same name, or
  any destination at the same bucket and prefix, has a new UID. Old pins
  never resolve to it, its obligations count only its own runs, and handed-off
  runs keep their original pin.
- **Expiry and restarts.** The recorded expiry stays historical, and a
  restarted controller reads the same `orphanedAt` and `Orphaned` state from
  status.
- **Forced removal.** If the destination's finalizer is stripped after its
  inventory was saved but before its runs were handed off, the saved
  inventory still marks that storage as handed off. The runs take the
  `Orphaned` disposition instead of recovering, and downloads answer 410.
- **Inventory lifetime.** Nothing in Konstapel deletes the inventory
  ConfigMaps. A platform administrator removes them after the external
  handoff.

`TestLiveOrphanFence` checks this with a real S3 test service that is paused
(unreachable) while the run's publication is pending and the handoff is
requested and accepted. The pending publication is drained at the fence, or
listed in `uncertainOperations`. While the backend
is down, the inventory is saved, the collecting run ends `DestinationOrphaned`
and frees its binding slot, and the destination is finalized. Once the
backend returns, nothing for the run reached storage. A destination recreated
under the same name at the same location becomes ready without adopting the
run. The operator steps are under Recovery and handoff walkthrough.

## Legacy destination file

Before EvidenceDestinations, the destination was a YAML file passed to
`konstapel controller` and `konstapel download-server` with
`--evidence-destination`. That flag has been removed. The format below survives
only as the **preserved legacy configuration** that migration verifies against
(`s3store.ParseDestination`). Unknown fields are rejected.
`AssessmentRequest`, `AssessmentRun`, and `ComplianceBinding` have no endpoint,
bucket, prefix, or credential fields, so application requests cannot redirect
evidence. A test enforces this.

```yaml
id: primary                        # stable; recorded with every publication
endpoint: https://s3.example.internal
bucket: konstapel-evidence
region: eu-north-1
prefix: clusters/prod              # optional; Konstapel only uses keys below it
addressing: path                   # or virtual
credentialSecret:                  # a Secret in the controller namespace, or…
  name: konstapel-s3
  accessKeyIDKey: accessKeyID      # optional data key names
  secretAccessKeyKey: secretAccessKey
# workloadIdentity: true           # …the SDK's standard workload-identity chain
caBundle: /etc/konstapel/s3-ca.pem # optional extra trusted roots
```

Rules:

- The endpoint must be `https`. Plain `http` is accepted only with
  `developmentFixture: true`, for an explicitly isolated local test service.
  TLS certificate verification is never disabled.
- The bucket must follow S3 naming rules. The prefix must be a clean relative
  key prefix.
- Exactly one credential source is set. Credentials never appear in the
  destination file; a file containing `secretAccessKey` without a Secret
  reference is rejected. Credential values are redacted from errors and
  string output.
- Konstapel never creates buckets or changes bucket configuration.

## Upgrading from the legacy destination file

Runs published through the legacy file recorded the file's `id`, endpoint,
bucket, and prefix in their receipt, but no destination UID or region. After
the upgrade, a run like that is attached to an EvidenceDestination only after
three things are verified against each other:
- the receipt;
- the preserved legacy file;
- exactly one destination that declares the legacy ID.

Nothing is matched by name or location alone, and nothing is taken from the
current default.

**Order:**
1. **Install the API first.** Apply the CRDs, RBAC, and admission policies
   (`config/crd`, `config/rbac`, `config/admission`).
2. **Quiesce legacy writers.** Stop the old controller, for example by scaling
   it to zero, and wait for it to exit. Leave the old download server running
   until step 6 if you want downloads to continue.
3. **Preserve the legacy file.** Copy it, unchanged, into a ConfigMap in the
   controller namespace:

   ```sh
   kubectl -n konstapel-system create configmap konstapel-legacy-destination \
     --from-file=destination.yaml=<old destination file>
   ```
4. **Declare the destination.** Create an EvidenceDestination with the same
   location and a `legacy` declaration. `spec.legacy` can be set only when the
   destination is created, and it never changes.

   | Legacy file | EvidenceDestination |
   | --- | --- |
   | `id` | `spec.legacy.destinationID` |
   | `endpoint`, `bucket`, `region`, `prefix` | `spec.s3.endpoint`, `bucket`, `region`, `prefix` (identical) |
   | `addressing`, `developmentFixture` | `spec.s3.addressing`, `developmentFixture` |
   | `credentialSecret` (Secret in the controller namespace) | `spec.s3.credentialSecret` (same Secret and keys) |
   | `workloadIdentity: true` | `spec.s3.workloadIdentity: true` |
   | `caBundle` (PEM file path) | `spec.s3.caTrust` (a ConfigMap holding the PEM) |

   ```yaml
   apiVersion: compliance.erenius.io/v1alpha1
   kind: EvidenceDestination
   metadata: {name: primary}
   spec:
     s3:
       endpoint: https://s3.example.internal
       bucket: konstapel-evidence
       region: eu-north-1
       prefix: clusters/prod
       credentialSecret: {name: konstapel-s3}
     legacy:
       destinationID: primary              # the legacy file's id
       configuration:
         name: konstapel-legacy-destination
         key: destination.yaml             # default
   ```
5. **Select it for new runs.** Set it as the central default (Selection),
   or in each binding's `destinationRef`.
6. **Deploy the new controller and download server** without
   `--evidence-destination`.

**What the controller does with each run that has no pin.** This takes no
storage action except as noted:
- **Has a receipt.** The legacy ID must be declared by exactly one destination,
  and the receipt, the preserved file, and that destination must agree on
  endpoint, bucket, and prefix. The region comes from the preserved file and
  must match the destination. The run is then pinned like a starting run:
  labelled, destination finalizer added, and `status.destination` recorded
  with `source: Migrated` and `legacy.destinationID`. That recorded
  association governs every later download, check, and expiry deletion. The
  receipt, archive, commit manifest, keys, versions, publication time, and
  expiry are unchanged, because the destination resolves to the same keys.
  Repeating the migration changes nothing.
- **Still collecting.** It stored nothing yet, so it ends `Failed`
  (`DestinationUnavailable`) and a new run starts against the selected
  destination.
- **Publishing, or terminal, without a receipt.** It may own upload attempts at
  a location that can't be established. It stays blocked, unless its attempts
  were already cleaned.

**Blocked runs.** A run that can't be migrated keeps its record and finalizer,
touches no storage, and reports `LegacyMigrated=False`. It is checked again
every 10 minutes and whenever a destination declaring a legacy ID changes. The
reasons:

| Reason | Fix |
| --- | --- |
| `NoDestination` | Declare the legacy ID on a destination (step 4). |
| `AmbiguousDestination` | More than one destination declares it, and none is chosen. Delete the extras. Their `legacy` can't be edited. |
| `ConfigurationUnavailable` | Create the preserved ConfigMap or key (step 3). |
| `LocationMismatch` | The message names the field and all three values. Recreate the destination with the historical location. Never change the receipt. |
| `DestinationUnavailable` | The declaring destination is being deleted. Recreate it, or hand off the storage. |
| `ReceiptMissing` | Recover or clean the run's attempts externally, then remove its finalizer by hand (Recovery). |

```sh
kubectl get assessmentruns -o custom-columns='NAME:.metadata.name,MIGRATED:.status.conditions[?(@.type=="LegacyMigrated")].reason,DEST:.status.destination.name'
```

**Afterwards.** A recreated destination has a new UID, so it never inherits a
migrated run. Handed-off (orphaned) evidence stays handed off.
`TestLiveLegacyMigration` covers this path on a disposable cluster:
1. A run publishes through the legacy destination on the S3 test service.
2. After the upgrade it is blocked (`NoDestination`) until a destination
   declares it.
3. It is then migrated, with its receipt and stored objects unchanged, and
   expiry deletes it through the destination.

## Setup

1. Create the bucket yourself. Konstapel never creates buckets or changes
   their configuration. Versioning may be enabled, suspended, or off.
2. Choose a dedicated `prefix`. Konstapel writes only below it:
   `<prefix>/evidence/...` for packages, and `<prefix>/konstapel-probe/...` for
   readiness probes, which it removes again.
3. Grant the controller's identity the minimum permissions on that prefix:

   | Operation | S3 action | Used for |
   | --- | --- | --- |
   | Bucket check | `s3:ListBucket` (`HeadBucket`, `ListObjectsV2`) | readiness, recovery, cleanup listing |
   | Version listing | `s3:ListBucketVersions` | cleanup in versioned buckets |
   | Upload | `s3:PutObject` | attempts, intents, the conditional commit |
   | Read | `s3:GetObject`, `s3:GetObjectVersion` | verification, recovery, receipts |
   | Delete | `s3:DeleteObject`, `s3:DeleteObjectVersion` | probe cleanup, attempt cleanup, expiry |
   | Multipart cleanup | `s3:ListBucketMultipartUploads`, `s3:AbortMultipartUpload` | attempt cleanup |
   | Versioning check | `s3:GetBucketVersioning` | readiness |

   Scope object actions to `arn:aws:s3:::<bucket>/<prefix>/*`, and bucket
   actions to the bucket with an `s3:prefix` condition of `<prefix>/*`. No
   bucket-administration action is needed.
4. Provide credentials in one of two ways. Either use workload identity
   (`workloadIdentity: true`), or create a Secret in the controller namespace
   and reference it as `credentialSecret`.
5. Create an EvidenceDestination for the bucket (see EvidenceDestination
   (API)), select it as the central default or in a binding's
   `destinationRef`, and start the controller with a persistent
   `--evidence-staging-dir`. Bindings show `scheduled snapshots are disabled:
   evidence destination DestinationNotReady: ...` until its probe passes.

**Credential rotation.** Update the Secret's data in place. The controller
reads it again within 5 minutes (`s3store.CredentialRefresh`), with no
restart. Keep the old key valid until then. Deleting the Secret or a key makes
the backend not ready, with the Secret and key named but never their values.

## Compatibility probe

`s3store.Probe` checks a destination under a unique
`<prefix>/konstapel-probe/<random>/` key prefix and removes every object version
it wrote. It needs these semantics:

| Check | Required behavior |
| --- | --- |
| Bucket access | `HeadBucket` succeeds with the configured credentials. |
| Content verification | SHA-256 is verified from server checksums (`x-amz-checksum-sha256`) or by reading the object back. ETags are never used as content hashes. |
| Create-if-absent | A second `PutObject` with `If-None-Match: *` fails with 412, and the first content is kept. |
| Server time | `LastModified` is returned and is within 5 minutes of the controller clock. |
| Versions | Version IDs match the bucket's versioning mode, and a specific version can be deleted. |

Any failed check makes the backend not ready. Publication must then fail
visibly; it never falls back to local storage.

## Package kinds

Every package has a `descriptor.json` with an inventory of its files, each
with a role, size and SHA-256. Its `packageKind` says what the package means:

| Kind | When | Contains | Meaning |
| --- | --- | --- | --- |
| `Assessment`, `Complete` | every expected check was attributable | OSCAL assessment results, plan, SSP, component definition, the vendored content they reference, the capture, a summary | a full assessment of the frozen scope; it still asserts only the mapped coverage |
| `Assessment`, `Incomplete` | some expected evidence was missing, rejected, or stale | the same files, with missing evidence recorded as such | a valid, publishable assessment that says what it could not establish. It is never upgraded to complete |
| `Assessment`, `NoTargets` | the scope selected no workloads | the same files with zero subjects | not a pass. It records that nothing was in scope |
| `Diagnostic` | valid OSCAL could not be produced | `diagnostic.json` (`reason`, `missingExports`, detail, evidence counts) and a summary. No OSCAL at all | why no assessment exists. Invalid OSCAL is never packaged as an assessment |

The publisher re-validates assessment packages before upload (schemas,
reference closure, engine-policy provenance, and namespace projection for
team packages). The archive is self-contained: every reference resolves
inside it, and nothing depends on another package's lifetime or a live
cluster object. `TestPublishedPackagesKeepTheirMeaningAfterDownload` publishes
a complete, an incomplete and a diagnostic package, downloads and unpacks each
archive, and checks the following:
- the descriptor is unchanged (kind, completeness, outcomes, diagnostic reason)
  and has the committed digest;
- every inventoried file verifies;
- assessment packages still pass full OSCAL reference validation.

## Publisher and commit protocol

`s3store.Publisher` implements `publication.Publisher`. All of a run's objects
live under one opaque, UID-based prefix. It contains no names, reasons, or
workload identities:

```text
<prefix>/evidence/<cluster uid>/<binding uid>/<run uid>/
  attempts/<random>/package.tar.gz   one per staging attempt
  attempts/<random>/attempt.json     the attempt's descriptor/package digests and archive version
  commit.json                        the run's single, fixed commit key
```

1. **Stage** validates the package directory:
   - the descriptor and its exact file inventory: no traversal, symlinks, or
     extra files;
   - for assessment packages, the OSCAL 1.1.3 schemas (from the packaged
     content) and reference closure;
   - for controller (v2) captures, engine-policy re-verification;
   - for namespace packages, the projection.

   It then builds a deterministic `tar.gz` archive: sorted entries, fixed
   modes, owners, and times, so the same package always yields the same digest.
   The archive is uploaded in a single request, never multipart, with an
   explicit SHA-256. The stored content is verified from the server checksum,
   or by reading it back. ETags are never used as content hashes.
   A retry uploads nothing new. If the run is already committed with the same
   content, or an earlier attempt with the same bytes still verifies, Stage
   returns that staging. This covers a lost upload or commit response and a
   receipt that never reached Kubernetes. An attempt that no longer verifies
   is replaced by a fresh upload.
2. **Publish** creates `commit.json` with `If-None-Match: *`. It records the
   run, the package and descriptor digests, the archive key and version, and
   the retention chosen at that first commit. Its successful creation is the
   publication commit.
   - If the commit already exists for the same content, as after a lost
     response, a retry, or a concurrent attempt, the original receipt is
     returned.
   - Different content for the same run is `ErrConflict` and never
     overwrites.
3. **The receipt** takes `publishedAt` from the commit object's server
   `LastModified`, and computes `expiresAt` from the retention recorded in the
   commit. A retry's clock or a later retention value never changes them.
4. **Recover** returns the newest staged attempt whose archive still verifies,
   or `ErrCaptureLost`. **Inspect** reports `Uploading` before the commit,
   then `Committed`, then `Expired`.
5. **Delete** refuses before expiry. After expiry it removes every object
   version and delete marker under the run's prefix, and nothing else. Full
   retention reconciliation (finalizers, partial failures, object locks) comes
   later.
6. **Ready** runs the compatibility probe. An incompatible or unreachable
   backend is `ErrUnavailable`.

### Installing with Helm

The [Helm charts](../charts.md) ship everything this guide relies on, so
nothing here needs to be applied by hand:

| Resource | Chart | Source |
| --- | --- | --- |
| `EvidenceDestination` CRD (including the create-only `spec.legacy` declaration) | `konstapel-crds` | generated `config/crd/bases`, kept on uninstall |
| Controller access to destinations, their finalizers, and Secrets/ConfigMaps in `konstapel-system` | `konstapel` | the generated controller roles (`config/rbac/controller`) |
| Download server access (destinations, credential Secret, CA ConfigMap) | `konstapel` | `config/rbac/evidence-download.yaml` |
| Admission policies protecting destination and run status | `konstapel` | `config/admission/*.yaml` |

The chart has no values for locations or credentials. After installing both
charts, create the bucket, the credential Secret in `konstapel-system` and the
`EvidenceDestination` as in [Setup](#setup), then select it.

The runtime chart gives each controller pod a size-limited `emptyDir` for
`--evidence-staging-dir` (`controller.stagingSizeLimit`, 2Gi). It survives
container restarts but not pod deletion. A run staged durably in S3 is
recovered by the next leader. A capture lost with its pod before durable
staging is reported as `CaptureLost`, never published
([Controller availability](availability.md#where-a-lost-leaders-work-ends-up)).

`TestLiveHelmInstall` and `TestLiveHelmAvailability` publish through such a
destination from the installed image to a test-owned S3 service. The
`TestLiveCRDChartLifecycle` test upgrades, uninstalls and reinstalls the CRD
chart with a populated `EvidenceDestination` carrying a finalizer. The
`charts` and `availability` groups belong to the required `acceptance`
check.

**Upgrading from the legacy file with Helm.** `--evidence-destination` was
removed, so the chart can't run the legacy file mode. Follow
[Upgrading from the legacy destination file](#upgrading-from-the-legacy-destination-file)
with two substitutions:
- in step 1, install the `konstapel-crds` chart (and keep the old controller
  stopped) instead of applying `config/crd`;
- where that procedure starts the new controller, install the `konstapel`
  chart.

Declare the `EvidenceDestination` with `spec.legacy` before the runtime chart
starts the controller, so the old runs are attached on its first reconcile.

## Controller use

**Configuration.** `konstapel controller` publishes only through
EvidenceDestinations. A binding without a selected, ready destination has
scheduling disabled, and says why.
`--evidence-staging-dir` (default `/var/lib/konstapel/staging`, created `0700`)
must be writable and should survive restarts so staged captures can be
recovered. `--content-root` must name the vendored `content` directory, which
the exporter copies into each package. A `credentialSecret` is read from the
controller's namespace (`POD_NAMESPACE`) with an uncached `get`; the generated
controller Role grants `get` on Secrets in `konstapel-system` only (any name,
because the name is chosen here; no `list` or `watch`; see
[Controller ServiceAccount boundary](../charts.md#controller-serviceaccount-boundary)). Values are
reused for `s3store.CredentialRefresh` (5 minutes), so a rotated Secret takes
effect without a restart. Starting the controller never contacts the backend:
a missing Secret or an unreachable or incompatible endpoint shows up as the
not-ready limitation below.


**Retention selection.** When a run closes collection, the executor records
the binding's resolved retention in the run's `status.retention`. At the first
commit it uses the binding's current retention if the same binding (same UID)
still exists, so an edit made before the first commit applies. If the binding
was deleted, or replaced by a new binding with the same name, the run publishes
with the retention recorded at closure and says so in
`publication.retention.bindingConfiguration`. A replacement binding is never
adopted. After the first commit, the recorded commit retention is fixed (see
above).

**Receipt recovery.** If the commit succeeds but the run's status update
fails, the run stays `Publishing`. The next reconcile, on any leader, stages
and publishes again. That uploads nothing and returns the original receipt,
so the run records the original digest, `publishedAt`, `expiresAt` and
namespace scope, and the request completes with the original publication ID.

**Attempt cleanup.** Each attempt directory
(`<run prefix>/attempts/<random id>/`) gets an `intent.json` naming its run
before any bytes are uploaded, so an interrupted upload can always be
identified. Once a run is `Completed` or `Failed`, the executor calls
`CleanupAttempts`. That removes every version and delete marker of the run's
other attempt directories, keeping the committed attempt and `commit.json`. It
also aborts incomplete multipart uploads under the run's prefix. A directory
without an owner record naming the run, a key outside an attempt directory,
and anything outside the run's prefix are never deleted. The run's
`AttemptsCleaned` condition records the result. A failure is
`CleanupPending` and is retried every minute, and after a restart, since
terminal runs are re-listed. Cleanup needs `ListBucketVersions` (or
`ListBucket`), `GetObject`, `DeleteObject`/`DeleteObjectVersion`,
`ListBucketMultipartUploads` and `AbortMultipartUpload` on the destination
prefix.

**Readiness gating.** A binding schedules only while its selected
EvidenceDestination is `Ready` (probed every 5 minutes, and on every change).
Otherwise its current assessment carries the limitation `scheduled snapshots
are disabled: evidence destination <reason>: <message>`. Evidence never falls
back to local storage or to another destination. Scheduling resumes once the
destination is ready again.

Credentials for a `credentialSecret` destination are read from that Secret in
the controller's own namespace (keys `accessKeyID` and `secretAccessKey` by
default) each time a client is built, so a rotated Secret takes effect. A
missing Secret or key names the Secret and key, never their values. TLS
verification cannot be disabled: an untrusted endpoint fails until its CA is in
`caBundle`.

## Downloads

`konstapel download-server` serves committed packages over TLS. It takes
`--tls-cert-file`, `--tls-private-key-file`, optionally `--tls-ca-file` and
repeatable `--tls-server-name` (it refuses to start unless the certificate is
currently valid, covers those names and chains to that CA), and `--audience`
(default `konstapel-download`). It re-reads those files every 10 seconds and
serves a rotated certificate once it passes the same checks. `GET /readyz`
fails while the files are invalid or the served certificate has expired, and
`GET /healthz` reports only that the process is serving. Neither probe needs a
token. Its service account needs
`config/rbac/evidence-download.yaml`. That file holds a ClusterRole with
TokenReview and SubjectAccessReview `create` plus read on requests, runs and
namespaces, and for a `credentialSecret` destination a Role reading that
Secret. Bind both to the download service account only.

| Route | Caller needs (SubjectAccessReview) | Serves |
| --- | --- | --- |
| `GET /v1/namespaces/<ns>/assessmentrequests/<name>/download?uid=<request uid>` | `get` on `assessmentrequests/download` and `assessmentrequests`, name `<name>`, in `<ns>`, from `konstapel-assessment-requester` | that request's own namespace-scoped package |
| `GET /v1/assessmentruns/<run uid>/download` | `get` on `assessmentruns/download` and `assessmentruns`, name of the run, from `konstapel-assessment-operator` | any run's package |
| `GET /v1/namespaces/<ns>/assessmentrequests/<name>/signature?uid=<request uid>` and `GET /v1/assessmentruns/<run uid>/signature` | exactly the same as the matching `/download` route | the package's signature bundle ([evidence signing](evidence-signing.md#download-a-signed-package)) |

Each request is checked as follows:

1. The bearer token goes to TokenReview with the service's audience. A token
   minted for another audience is refused. Forwarded or impersonation headers
   are ignored.
2. Current RBAC is checked with SubjectAccessReview on both attributes, so
   revoking a role stops the next download. Bytes already received cannot be
   revoked.
3. The object is resolved and checked:
   - the request UID must match `?uid=`;
   - the namespace's current UID must equal the request's recorded
     `namespaceUID`, so a recreated namespace is refused;
   - the run must be that request's namespace-scoped run, and its publication
     must be the request's `artifactRef`.

   A team permission never reaches a full-binding run, a sibling namespace, or
   a run through the platform route. Storage keys, URLs and endpoints are never
   accepted as addresses.
4. The committed archive is fetched into bounded temporary storage
   (`--max-temp-bytes`, `--max-concurrent`). Its size and SHA-256 are checked
   against the run's receipt and the stored commit before any byte is sent, and
   the temporary file is always removed.
5. For a signed publication, the signature is checked with the archive
   ([evidence signing](evidence-signing.md#download-a-signed-package)), and
   neither artifact is served unless the pair verifies.

A successful response is `Cache-Control: private, no-store`, with
`Repr-Digest: sha-256=:…:`, `X-Konstapel-Publication`,
`X-Konstapel-Descriptor-SHA256`, `X-Konstapel-Published-At` and
`X-Konstapel-Expires-At`.

| Status | Meaning |
| --- | --- |
| 401 | no token, or TokenReview did not accept it for the audience |
| 403 | not authorized, or not found. The two are indistinguishable, so UIDs are not an existence oracle |
| 409 | the request or run has no committed package yet |
| 410 | the package expired and is no longer served |
| 429 | too many concurrent downloads (`Retry-After`) |
| 404 | (signature routes) the package was published unsigned: `X-Konstapel-Signing: unsigned` |
| 502 | the stored package or its signature does not match the receipt or fails verification |
| 503 | TokenReview/SubjectAccessReview unavailable (fail closed), storage unavailable, the archive or the signature of a signed package missing before expiry, or temp space full (`Retry-After`) |

Roles:

- **Teams** get `konstapel-assessment-requester` through a RoleBinding in
  their namespace. It allows creating and reading `AssessmentRequest`s and
  `get` on `assessmentrequests/download` there. That reaches only their own
  requests' namespace packages, never a full-binding run, a sibling
  namespace, or a run through the platform route.
- **Platform operators** get `konstapel-assessment-operator` through a
  ClusterRoleBinding. It allows `get` on `assessmentruns/download` for every
  run's package, including full-binding ones.
- **The download service** gets `konstapel-evidence-download` (above). Nobody
  else needs TokenReview or SubjectAccessReview.

`TestLiveEvidenceDownload` (in `scripts/targeting-live.sh`) runs this workflow
on a disposable cluster against the pinned S3 test service:

1. The manager publishes a team request's package through the real
   publisher.
2. A namespace service account bound to the requester role gets a token for
   the `konstapel-download` audience and downloads the package. The archive
   unpacks into a namespace-scoped package of the team's own namespace UID,
   and it passes the publisher's full validation (inventory, OSCAL schemas and
   references, engine-policy provenance, namespace projection).
3. The same token gets 403 for the full-binding run, for its own run through
   the platform route, for a sibling namespace, and for a wrong request UID.
   A token for the API server audience gets 401.
4. After the RoleBinding is deleted, the next download gets 403.

Error bodies never contain storage locations, credentials, tokens, or another
scope's data. A team downloads its package like this:

```sh
# A service account in the team namespace; other identities need a token
# issued for the konstapel-download audience by their identity provider.
TOKEN=$(kubectl create token ci-reader -n dev --audience konstapel-download)
REQUEST_UID=$(kubectl get assessmentrequest nightly -n dev -o jsonpath='{.metadata.uid}')
curl --cacert ca.crt -H "Authorization: Bearer $TOKEN" -o package.tar.gz \
  "https://<download-service>/v1/namespaces/dev/assessmentrequests/nightly/download?uid=$REQUEST_UID"
```

## Tested compatibility

Compatibility is a tested claim, not an assumption. [s3-compat.json](s3-compat.json)
records the suite against the pinned test service:

| Service | Image | Unversioned | Versioning enabled | Versioning suspended |
| --- | --- | --- | --- | --- |
| RustFS | `KONSTAPEL_S3_IMAGE` in `scripts/runtime.env` (1.0.3, digest-pinned) | ready | ready | ready |

All modes used server SHA-256 checksums and enforced create-if-absent. The
same run publishes a complete package to each mode (`TestPublisherRoundTrip`):

- stage and commit;
- an idempotent retry returning the original receipt;
- refusal of conflicting content;
- the downloaded archive matching its committed SHA-256;
- `publishedAt` within clock tolerance of the server's commit time;
- deletion after expiry, leaving no owned versions or delete markers;
- no re-upload on retry, receipt recovery by a new leader, and attempt cleanup
  (an interrupted attempt and a real incomplete multipart upload are removed,
  an unrelated object in the same bucket survives).

| Backend | Status |
| --- | --- |
| RustFS 1.0.3 (self-hosted) | **tested**, all three versioning modes |
| AWS S3 | **untested.** It is expected to work (conditional writes and SHA-256 checksums are documented features) but not claimed |
| Other S3-compatible services (Ceph RGW, Garage, SeaweedFS, MinIO) | **untested.** Run the suite against them before relying on them |

The MinIO community image is not used because it is no longer published to a
public registry. Known limits: conditional create is required, so services
without `If-None-Match: *` support are refused at readiness. Archives are
capped at 512 MiB because they are uploaded in a single request.

**Final evidence for this change (v0.1.0 candidate).** Validation matrix:

| Component | Version |
| --- | --- |
| S3 service | RustFS 1.0.3 (`KONSTAPEL_S3_IMAGE`, digest-pinned): compatibility suite passed in all three versioning modes on 2026-11-08 ([s3-compat.json](s3-compat.json)) |
| Kubernetes | 1.37.0 (kind node pinned in `scripts/runtime.env`) |
| Kyverno | 1.19.2 (chart 3.9.2) |
| cert-manager | v1.21.3 (`charts` group) |
| Helm | 4.3.1 |

CI acceptance: main-branch run [42491849299](https://github.com/backend-bunny/Konstapel/actions/runs/42491849299) for `9f130990a348ea23b1e4fefc02baf3bba6c2415a`. Every
group passed. The S3 behaviour is exercised by:
- `storage`: destinations, pins, downloads, retention, orphaning, legacy
  migration;
- `recovery`: outages, faults, handover recovery and loss;
- `charts` and `availability`: publication from the Helm-installed image;
- `admission`: the preserved prototype runner validation (`konstapel
  acceptance`/`validate`, the upstream Chainsaw fixtures, the offline replay).

Each group tears down its own cluster and S3 container.
`TestLiveOrphanFence` closes its intentional orphan handoff through the
documented operator path ([Removing the inventory](#recovery-and-handoff-walkthrough)):
it keeps the inventory as evidence (run identities, keys and receipts, no
credentials), then deletes the handoff's ConfigMaps by label.

Run the suite against a disposable, test-owned instance:

```sh
devbox run -- scripts/s3-compat.sh /tmp/konstapel-s3-compat
```

The script starts the pinned image with random credentials on a loopback port,
creates one test bucket per versioning mode inside that container, writes
`s3-compat.json` and the log to the output directory, and always removes the
container. Renovate updates the image pin; `task deps:check` requires it to
carry a full digest.

The suite refuses to run unless the endpoint is the loopback service the
script started (`requireTestOwned`), because it creates buckets. Its objects
live under `konstapel-test/` in `konstapel-compat-*` buckets inside that
container.

## Retention

Every run gets the finalizer `compliance.erenius.io/retention` before it can
write to storage. Runs carry no owner reference to their binding or request.

- **Expiry is fixed at the first commit.** `expiresAt` = commit time +
  the binding's `spec.assessment.retention` at that moment (default `2160h`,
  for scheduled and manual runs alike). Editing the binding's retention
  later changes only new publications.
- **Records outlive their owners.** Deleting the binding, the request, or the
  run itself before expiry does not end retention. The run stays (marked for
  deletion) as the package's cleanup record, and a controller restart
  resumes it. A new namespace or request with the same name never gains
  access, because downloads check UIDs.
- **At expiry** new downloads are refused (410), and the executor deletes every
  owned object version and delete marker under the run's prefix. Then it
  verifies that none remain and records `publication.phase: Deleted`,
  `availability: Expired` and `cleanup.state: Deleted`. Only then is the
  finalizer removed. A run that was marked for deletion then goes away; one
  that wasn't keeps that small tombstone.
- **Failures are truthful and retried.** Storage refusing deletion (object
  lock, legal hold, `AccessDenied`) is `RetentionBlocked`. Other errors, or
  versions that remain after deletion, are `DeletionFailed`. Either way the
  run keeps its commit and ownership metadata, records attempts and the
  last error, and retries with backoff from one minute to one hour. Konstapel
  never requests bypass permissions. An administrator resolves the lock or
  permission.
- **Availability before expiry** is re-checked at most once a day
  (`AssessmentRuntime.IntegrityInterval`) and after a controller restart. The
  check reads only the archive's metadata: it must exist with its committed
  size and, where the service returns it, its committed SHA-256. A missing
  archive gives `availability: Unavailable` with failure reason
  `ObjectMissing`; a size or checksum mismatch gives `IntegrityFailed`. The
  assessment summary, receipt and expiry never change. If the same bytes are
  restored, availability returns to `Available`. A storage outage leaves the
  last known availability. Downloads verify the full SHA-256 on every request
  regardless.
- **External lifecycle rules** must not expire evidence before Konstapel's
  recorded expiry. Konstapel does not change bucket rules. Early removal shows
  up as `ObjectMissing`, never as successful retention, and the record is still
  cleaned up at expiry.

A run deleted while still collecting has written nothing to storage and is
released immediately.

**Recovery.** Each failure state has a fix, and nothing needs restarting:

- `RetentionBlocked`: remove the object lock or legal hold, or grant the delete
  permissions listed under Setup, on the run's prefix. The next retry (within an
  hour) deletes the package and releases the record.
- `DeletionFailed`: check `publication.cleanup.message` and the backend's
  health. Retries continue with backoff, and the commit and owned-object
  metadata stay on the run until deletion is confirmed.
- `availability: Unavailable` before expiry: restore the archive's original
  bytes (same key and version, for example from a backup), and the next
  daily check reports `Available`. Konstapel never re-uploads or
  re-exports under the old identity.
- Removing the finalizer by hand releases the record without deleting storage.
  Do this only after cleaning up the run's prefix yourself.

**Retention versus destination pinning.** These are two separate decisions
at two moments:

| | When | Chosen from | Later edits affect |
| --- | --- | --- | --- |
| Destination | Run start, before any storage write (Run pins) | The binding's `destinationRef`, or else the central default | Only runs that start afterwards |
| Retention | First commit preparation | The binding's `spec.assessment.retention` (default `2160h`) | Only publications committed afterwards |

A run that starts under destination A and is committed after the binding's
retention was shortened publishes at A, with the shortened retention. A run
committed before the edit keeps its original expiry wherever it is stored.

**Changing the destination.** Locations are immutable, so moving evidence
storage means creating a new `EvidenceDestination` and switching the
binding's `destinationRef` or the central default. Runs already started stay
pinned to the old destination, and their packages are downloaded, checked and
deleted there until expiry. Later runs use the new one. Then delete the old
destination. It retires (see Retirement): it refuses new runs, finishes its
obligations, and is released when none remain. A name recreated for a
different location is a new UID and never serves the old packages.

**Rotating credentials or CA trust.** Update the referenced Secret's data in
place (read again within 5 minutes), or point `credentialSecret`/`caTrust` at a
new Secret or ConfigMap. The latter is a new generation, so the controller
rebuilds that destination's publisher. Both apply to every package pinned to
the destination, including historical ones, and both work while it retires.
Deleting old credentials while packages still need them makes their
operations fail visibly (`DeletionFailed`, `Unavailable`, retirement
`RetirementBlocked`) and retry. There is no fallback to other credentials or
another destination.

**Blocked retirement.** A destination that cannot finish, because of an
outage, missing credentials, or a lock on one of its packages, stays
terminating with `Retiring=RetirementBlocked`. Its `cleanupBlockers` name the
run and the failure. Fix the cause as described under Recovery, and the
retries finish the work and release it. Elapsed time alone never releases a
destination, and unfinished publication with unknown expiry is never treated
as empty.

**Short-duration verification.** `TestLiveRetentionLifecycle` (in
`scripts/targeting-live.sh`) runs the whole lifecycle on a disposable cluster
against the pinned S3 test service, with a 45s binding retention instead of 90
days:
1. A scheduled and a manual run publish, with `expiresAt = publishedAt + 45s`
   and the finalizer set.
2. A platform operator downloads the scheduled package.
3. The scheduled run is deleted before expiry. Its record stays until expiry,
   then new downloads are refused, its storage versions are deleted, and the
   record is released.
4. The undeleted manual run's storage is deleted and it keeps a `Deleted`
   tombstone.

`TestLiveDestinationPins` covers destination pinning, retirement and
finalization in the same short-duration way:
1. Two destinations on the test service are probed `Ready`.
2. A run pins the default destination. The default switches mid-run, the run
   still commits at its pinned prefix, and the next run commits at the new
   one.
3. dp-primary's credential Secret reference is pointed at a missing Secret. It
   reports `Ready=False`, naming the Secret but no credential material, and
   doesn't fall back to dp-secondary's Secret. It is then pointed at a rotated
   Secret and its original Secret is deleted.
4. Both destinations are then deleted with a 150s binding retention, on a
   bucket with versioning enabled. Each stays `Retiring` with its retained
   package counted. It is released only after that package expires and every
   version and delete marker of it is gone. dp-primary's is removed through
   the rotated credentials.

`TestLiveIntegratedAssessments` runs continuous assessments end to end
through destinations on the S3 test service:
1. One binding uses the central default, and an overlapping binding has its
   own `destinationRef`.
2. Scheduled, manual, and team-requested (namespace-scoped) runs each pin
   their destination at start. They are committed only under that
   destination's prefix.
3. The download service serves each package from its run's pinned
   destination. A team gets only its own namespace package, and a platform
   operator gets binding packages.
4. An engine reporting outage, with a workload added during it, publishes an
   `Incomplete` package.
5. An impossible OSCAL export publishes a typed `Diagnostic` package. Both
   are downloaded and validated.

`TestLiveEvidenceRecovery` exercises recovery on an object-lock bucket
through a pinned destination:
1. **Retention edit.** Editing a binding's retention changes only later
   publications. The earlier receipt and the engine policies keep their
   identity, because the shipped epoch policy is installed.
2. **Legal hold.** A legal hold on a package makes expiry cleanup
   `RetentionBlocked`, with the storage message and a destination cleanup
   blocker. Retries wait for their backoff, one minute and doubling, and the
   stored bytes are unchanged.
3. **Hold lifted.** Once the hold is lifted, the next retry deletes every
   version and leaves a `Deleted` tombstone.
4. **Binding deleted during an outage.** A binding is deleted while its run
   publishes against a storage outage. The run publishes with its recorded
   retention when storage returns, and a binding recreated under the same
   name never adopts it.
5. **RBAC revoked.** Revoking a platform operator's binding makes downloads
   answer 403.

## Recovery and handoff walkthrough

Two different mechanisms deal with storage that Konstapel can't finish
normally. They never overlap:

| | Automatic abandoned-attempt cleanup | Explicit Orphan handoff |
| --- | --- | --- |
| Started by | The controller, when a run is `Completed` or `Failed` | A platform administrator: `deletionPolicy: Orphan` with a reason, then deleting the destination |
| Scope | One run's prefix: attempt directories it owns (`intent.json`) and its incomplete multipart uploads. Never the committed attempt or unowned keys | Everything pinned to the destination: committed packages, attempts, versions, uploads |
| Storage operations | Deletes and aborts, retried until they succeed | None. Konstapel stops all remote work, even while the backend is down |
| After a restart | Resumes from the run records | Stays stopped. `orphanedAt`, `Orphaned` and the saved inventory are durable |
| Who owns what remains | Konstapel, until expiry deletion | The operator, including future retention |
| Reversible | Not needed | No. An accepted handoff is frozen |

### Recovering from storage faults

Each fault leaves visible diagnostics on the run, and none of them recollects
newer evidence under an old run's identity.

- **Backend outage while publishing.** The run stays `Publishing`, with
  `Published=False` (`Retrying`) and the cause. Its frozen package
  (`status.descriptorSha256`) doesn't change. Retries continue for 5 minutes
  after collection closes. If the backend returns in time, the same package
  is committed exactly once. Otherwise the run ends `Failed`
  (`PublicationFailed`, with the cause). Its assessment summary is kept, and
  its binding's active run slot is released. While the backend is not ready,
  scheduled snapshots are disabled with a visible limitation (see Readiness
  gating). Once storage is back, nothing needs restarting: the next run
  assesses the current state. `TestLiveAssessmentFaults` (step
  `storage-outage`) pauses the S3 test service during publication and checks
  that the frozen package is committed once after recovery.
- **Lost commit response or receipt update.** The next reconcile finds the
  existing commit and records the original receipt (see Receipt recovery).
  It never makes a second snapshot (`TestLostPublishResponseKeepsOriginalReceipt`).
- **CaptureLost.** If the frozen bytes are lost before durable staging, the
  run ends `Failed` with reason and export state `CaptureLost`. Nothing is
  published under that run's identity, and a new run is needed
  (`TestChangedStagedPackageIsCaptureLost`, `TestPublisherRecoveryAndCaptureLost`).
- **Partial uploads.** An interrupted attempt is identified by its
  `intent.json`. When the run is terminal, attempt cleanup removes it and
  aborts the run's incomplete multipart uploads. Failures show as
  `AttemptsCleaned=False` (`CleanupPending`) and are retried every minute.
  The committed attempt and unowned keys are never touched
  (`TestCleanupAttemptsKeepsCommittedAndUnowned`, `TestCleanupAttemptsWithoutCommit`).
- **Destination change.** Runs keep their pinned destination, and history is
  served and deleted there (see Changing the destination). A destination that
  can't finish retiring is `RetirementBlocked` with named blockers (see
  Blocked retirement). If its storage will never be reachable or cleanable
  again, the remedy is an Orphan handoff, not deleting the prefix by hand.
- **Orphaned evidence.** None of the automatic paths above runs for it, at
  expiry, after restarts, or through a destination recreated at the same
  location (`TestLiveOrphanFence`, `TestOrphanedOwnershipIsNeverAdopted`).

### Deleting a destination

**1. Normal deletion (retire).** Switch bindings and the default away first
(see Changing the destination), then delete it:

```sh
kubectl delete evidencedestination primary --wait=false
kubectl get evidencedestination primary \
  -o jsonpath='{.status.outstandingRuns} {.status.outstandingPackages} {.status.latestRetainedExpiry}{"\n"}{.status.cleanupBlockers}{"\n"}'
```

It is released when nothing is outstanding, at the latest after
`latestRetainedExpiry` and its expiry deletions. Fix any `cleanupBlockers`
as described under Recovery.

**2. Choosing Orphan.** Hand the storage off when Konstapel should stop
managing it, for example:
- the backend is decommissioned or permanently unreachable;
- the bucket is transferred to another owner or retention regime;
- a lock blocks deletion and won't be lifted.

Request it with a reason, before deletion or as an escalation of a
terminating destination. Admission records you as the actor.

```sh
kubectl patch evidencedestination primary --type=merge \
  -p '{"spec":{"deletionPolicy":"Orphan","orphan":{"reason":"backend decommissioned, archive team owns the bucket"}}}'
kubectl get evidencedestination primary -o jsonpath='{.metadata.uid}{"\n"}'   # note the UID
kubectl delete evidencedestination primary --wait=false                       # if not already deleting
```

Acceptance on deletion is irreversible. Konstapel then:
- fences the destination;
- saves the inventory;
- marks every pinned run (see Orphaned disposition);
- releases the destination.

None of this needs the backend. If `Retiring` shows `OrphanInventoryPending`,
the inventory couldn't be saved yet. Typical causes are ConfigMap quota or
RBAC in `konstapel-system`. The fence and finalizers hold until it succeeds.

**3. Export the inventory.** The header is complete once it exists:

```sh
uid=<destination UID>
kubectl -n konstapel-system get configmap -l compliance.erenius.io/orphan-handoff=$uid -o yaml > orphan-$uid.yaml
kubectl -n konstapel-system get configmap konstapel-orphan-$uid -o jsonpath='{.data.inventory\.json}'
```

- **Header.** It names the actor, reason, `acceptedAt`, `fencedAt`, the
  destination location, and `uncertainOperations`. It also lists each chunk
  (`konstapel-orphan-$uid-<n>`) with its SHA-256 over the chunk's
  `inventory.json`.
- **Chunks.** Each run entry has its `ownedPrefix` and, where it published,
  its original receipt: commit manifest and archive keys and versions,
  `packageSha256`, `packageSize`, `publishedAt` and `expiresAt`.
- **Lost UID.** If you didn't note the UID, list the labels:
  `kubectl -n konstapel-system get configmap -l compliance.erenius.io/orphan-handoff -L compliance.erenius.io/orphan-handoff`.

**4. What users see.**
- **Completed runs:** `publication.phase: Orphaned`, `availability:
  Unavailable`, `cleanup.state: Orphaned`, with the original receipt. Managed
  downloads answer 410. Bytes already downloaded aren't revoked.
- **Interrupted runs:** they end `Failed`, `Published=False`
  (`DestinationOrphaned`), and never claim success.
- **Deleted records:** they stay `Deleted`.
- **New runs:** bindings that selected the destination need a new one.

**5. External recovery and cleanup are the operator's job.**
- **Unreachable storage.** The inventory's `remoteState` is `NotEnumerated`,
  because Konstapel didn't contact the backend. When the storage is
  reachable, enumerate each run's `ownedPrefix`, including every version,
  delete marker and incomplete upload:

  ```sh
  aws s3api list-object-versions --bucket <bucket> --prefix <ownedPrefix>
  aws s3api list-multipart-uploads --bucket <bucket> --prefix <ownedPrefix>
  ```
- **Retained versions and uploads.** Konstapel did not abort multipart
  uploads or delete versions during the handoff. Everything under the
  prefixes is still there, and object locks still apply.
- **Uncertain operations.** These were in flight at the fence (for example a
  publication), and their outcome is unknown. A `commit.json` under the
  run's prefix means that commit completed, even if the run doesn't record
  it.
- **Moving evidence.** Copy the receipt's archive version and check it
  against `packageSha256` and `packageSize`.
- **Future retention.** `expiresAt` is historical. Konstapel will never
  delete these packages. Apply your own lifecycle rules, or delete them when
  your retention ends.
- **Removing the inventory.** Konstapel never deletes it. Remove it after
  the handoff is complete:
  `kubectl -n konstapel-system delete configmap -l compliance.erenius.io/orphan-handoff=$uid`.

**6. Last resort: removing finalizers by hand.** Use this only when the
controller can't finish, for example because it is uninstalled, or the
inventory can never be saved. Export first, because removing a finalizer
deletes the record Konstapel would otherwise keep:

```sh
kubectl get evidencedestination primary -o yaml > destination-primary.yaml
kubectl get assessmentrun -l compliance.erenius.io/destination-uid=$uid -o yaml > runs-$uid.yaml
kubectl patch evidencedestination primary --type=json -p '[{"op":"remove","path":"/metadata/finalizers"}]'
# Only for runs whose storage you now own; this releases their records:
kubectl patch assessmentrun <run> --type=json -p '[{"op":"remove","path":"/metadata/finalizers"}]'
```

Removing finalizers never deletes storage and never moves evidence to
another destination.
- **Inventory saved.** Runs whose destination is gone are still recognized
  as handed off. They take the `Orphaned` disposition, downloads answer 410,
  and the storage is never touched again.
- **No inventory.** Runs pinned to the removed destination only report it as
  unavailable. They issue no storage operation, because no destination
  resolves their pin, and they keep their records until their finalizers
  are removed as above.

## Teardown

- **Test service:** `scripts/s3-compat.sh` always removes its container, with
  its buckets and data. Nothing outside it is touched.
- **Disabling publication:** remove the central default and the bindings'
  `destinationRef`. Scheduling stops with a visible limitation. Published packages stay in the bucket until their
  recorded expiry.
- **Removing evidence:** packages are deleted only after expiry, by the
  controller, within the run's own prefix. Deleting the prefix by hand also
  removes evidence whose retention has not ended. Do that only when retiring
  the evidence on purpose.
