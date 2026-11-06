# S3 evidence backend

`add-s3-evidence-publishing` stores assessment packages in an S3-compatible
bucket. This guide covers the parts implemented so far: the platform-controlled
destination, client construction, the compatibility probe that decides whether
a backend may be used, and the publisher's commit protocol. The download service
and retention reconciliation come in later task groups.

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
- deletion after expiry, leaving no owned versions or delete markers. Cloud
S3 and other self-hosted services are not claimed until the same suite passes
against them. The MinIO community image is not used because it is no longer
published to a public registry.

Run the suite against a disposable, test-owned instance:

```sh
devbox run -- scripts/s3-compat.sh /tmp/konstapel-s3-compat
```

The script starts the pinned image with random credentials on a loopback port,
creates one test bucket per versioning mode inside that container, writes
`s3-compat.json` and the log to the output directory, and always removes the
container. Renovate updates the image pin; `task deps:check` requires it to
carry a full digest.
