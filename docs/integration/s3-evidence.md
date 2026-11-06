# S3 evidence backend

`add-s3-evidence-publishing` stores assessment packages in an S3-compatible
bucket. This guide covers the parts implemented so far: the platform-controlled
destination, setup and permissions, the compatibility probe that decides whether
a backend may be used, package kinds, the publisher's commit protocol, recovery,
and teardown. The download service and retention reconciliation come in later
task groups.

## Destination configuration

The evidence destination is deployment configuration, read by
`s3store.LoadDestination` from a YAML file. Unknown fields are rejected.
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
5. Write the destination file (above) and start the controller with
   `--evidence-destination=<file>` and a persistent `--evidence-staging-dir`.
   Bindings show `scheduled snapshots are disabled: evidence backend is not
   ready: ...` until the probe passes.

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

## Controller use

**Configuration.** `konstapel controller --evidence-destination=<file>` loads
the destination YAML above and enables scheduled snapshots. Without the flag
the controller runs with scheduling disabled and says so on every binding.
`--evidence-staging-dir` (default `/var/lib/konstapel/staging`, created `0700`)
must be writable and should survive restarts so staged captures can be
recovered. `--content-root` must name the vendored `content` directory, which
the exporter copies into each package. A `credentialSecret` is read from the
controller's namespace (`POD_NAMESPACE`) with an uncached `get`; the generated
controller Role grants `get` on Secrets in `konstapel-system` only. Values are
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

**Readiness gating.** When the controller runtime has a readiness check, the
assessment scheduler calls it at most once per `ReadyInterval` (5 minutes by
default). While the backend is not ready, scheduled snapshots are disabled and
the binding's current assessment carries the limitation
`scheduled snapshots are disabled: evidence backend is not ready: <reason>`.
Evidence never falls back to local storage. Scheduling resumes on the first
successful check.

Credentials for a `credentialSecret` destination are read from that Secret in
the controller's own namespace (keys `accessKeyID` and `secretAccessKey` by
default) each time a client is built, so a rotated Secret takes effect. A
missing Secret or key names the Secret and key, never their values. TLS
verification cannot be disabled: an untrusted endpoint fails until its CA is in
`caBundle`.

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

## Teardown

- **Test service:** `scripts/s3-compat.sh` always removes its container, with
  its buckets and data. Nothing outside it is touched.
- **Disabling publication:** remove `--evidence-destination`. Scheduling stops
  with a visible limitation. Published packages stay in the bucket until their
  recorded expiry.
- **Removing evidence:** packages are deleted only after expiry, by the
  controller, within the run's own prefix. Deleting the prefix by hand also
  removes evidence whose retention has not ended. Do that only when retiring
  the evidence on purpose.
