# Supporting evidence

Some controls in the selected baseline, such as datacenter physical security
(PE-3), can't be checked by workload policies. Platform operators can register
supporting documents for those controls as `EvidenceAttachment` records
(`compliance.erenius.io/v1alpha1`, cluster-scoped). An attachment is
supporting material. It has no verdict field, and it never changes technical
findings, expected checks, enforcement or risk acceptance.

**Status.** This is the `add-supporting-evidence-attachments` change, task
groups 1 to 7. The following are implemented:

- the API;
- authenticated registrant attribution;
- association validation by the controller;
- the retention finalizer;
- the platform roles (group 1);
- destination pinning;
- the S3 storage and commit contract with its recorded commitment;
- frozen source retention;
- owned attempt cleanup;
- retention-gated withdrawal (group 2);
- authenticated upload and download routes on the download service;
- the `konstapel evidence` CLI (group 3);
- separately reconciled validity, content, association and withdrawal
  states, expiry without an event, and bounded, recoverable cleanup
  ([Lifecycle](#lifecycle), group 4);
- supporting context in coverage reports, verified document copies in
  platform assessment packages, protected package roles and the
  document-read check on package downloads
  ([Coverage and assessment packages](#coverage-and-assessment-packages),
  group 5);
- the local RustFS workflow ([Local development](#local-development),
  group 6);
- chart integration, and integrated acceptance and recovery
  ([Integrated acceptance](#integrated-acceptance), group 7).

The runtime chart's download service serves the attachment routes; its
limits and source retention are the `download.attachments` chart values
([values contract](charts.md#values-contract)).

Platform operators manage attachments. Application-team attachments are
future work, and no namespace role can register or read them.

## Registering a document

The [example](examples/supporting-evidence/attachment-datacenter.yaml)
registers one audit report for PE-3 of two bindings:

```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata:
  name: dc-north-physical-access-2026
spec:
  document:
    title: DC North physical access control audit 2026
    mediaType: application/pdf
    size: 482113
    sha256: sha256:9f2b…2a10
  source:
    issuer: Example Audit AB on behalf of the DC North facility operator
    url: https://audits.example.com/reports/dc-north-2026
  validity:
    validFrom: "2026-01-01T00:00:00Z"
    validUntil: "2027-01-01T00:00:00Z"
  scope:
    description: DC North halls A and B, which host every node of this cluster.
  associations:
    - binding: {name: baseline-audit, uid: 0b6c1f0e-…}
      catalogDigest: sha256:64ca6b41…5eeb
      controls:
        - id: pe-3
          statements: [pe-3_smt.a, pe-3_smt.b]
        - id: pe-6
    - binding: {name: payments-deny, uid: 6a2e9d47-…}
      catalogDigest: sha256:64ca6b41…5eeb
      controls:
        - id: pe-3
```

`konstapel evidence register` completes and creates the record from that
manifest and the document file:

```sh
konstapel evidence register -f attachment.yaml --document dc-north-2026.pdf --dry-run
konstapel evidence register -f attachment.yaml --document dc-north-2026.pdf
```

- **Document identity.** `spec.document.size` and `sha256` may be omitted.
  The command computes them from the file. A value in the manifest that
  differs from the file is an error, so the registered identity is always
  the file you will upload.
- **Binding identity.** `binding.uid` may be omitted. The command reads each
  named binding and fills in its current UID. A UID in the manifest that
  differs from the binding's current UID is an error: the binding was
  recreated, and an association never moves to a replacement.
- **Refused input.** The command refuses `spec.registeredBy` (admission
  records the registrant), `status`, unknown fields, and other kinds. The
  create uses strict field validation.
- **Review.** `--dry-run` runs a server-side dry run, including admission,
  and prints the completed record without creating it. The printed
  `registeredBy` is the registrant admission would record.

The command prints the new record's UID; transfers address the record by it.
It needs `konstapel-evidence-attachment-registrar` and read access to the
named bindings (for example `konstapel-compliance-viewer`). Without the
command, collect the same identities by hand:

```sh
kubectl get compliancebinding baseline-audit -o jsonpath='{.metadata.uid}'
sha256sum dc-north-2026.pdf          # spec.document.sha256 is "sha256:<hex>"
stat -c %s dc-north-2026.pdf         # spec.document.size
kubectl create -f attachment.yaml    # as a konstapel-evidence-attachment-registrar subject
```

`catalogDigest` is the SHA-256 of the OSCAL catalog file in the bundle the
binding's profile pins, at
`content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json`.
For the vendored NIST SP 800-53 Rev 5 catalog it is
`sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb`.
If the binding resolves a different catalog, the record's status shows that
catalog as `observedCatalogDigest`. Bindings don't publish their catalog
digest, so `konstapel evidence register` doesn't fill it in: the manifest
always states it.

| Field | Meaning | Checked |
| --- | --- | --- |
| `document.title`, `mediaType` | Descriptive. The media type is lowercase `type/subtype` with no parameters. Downloads are always passive attachments. | non-blank title; media-type syntax |
| `document.size`, `sha256` | The exact bytes the transfer service will accept | 1 byte to 1 GiB (the transfer service's own default upload limit is lower, 32 MiB); `sha256:` + 64 lowercase hex |
| `source.issuer`, `source.url` | Declared provenance. Konstapel never fetches the URL and never authenticates the issuer. | non-blank; `http(s)://` URL |
| `validity.validFrom`, `validUntil` | The declared coverage window, `validFrom <= T < validUntil`. Upload time never changes it. | both required RFC 3339 timestamps; `validFrom < validUntil` |
| `scope.description` | The platform's statement of the facility or system covered | non-blank |
| `associations[]` | 1–32 associations, each naming an exact binding (name and UID), a catalog digest, and 1–64 controls with optional statement parts | structure at the API; meaning by the controller (below); a binding UID at most once |
| `registeredBy` | Set by admission; don't supply it | see [Attribution](#attribution) |

The CRD prunes unknown fields, and `kubectl create` (strict field validation)
rejects them. The record can't carry document bytes, credentials, storage
locations or verdicts.

## Immutable records and replacement

Every `spec` field is fixed when the record is created. The API server rejects
any change, even from a cluster administrator:

```text
spec: Invalid value: "object": spec is immutable; register a new EvidenceAttachment
```

Each of these needs a new record and a new upload:

- a corrected document;
- a different validity period;
- a different catalog mapping;
- another binding.

Delete the old record to withdraw it. A record never acquires a new evidence
revision in place, and re-registering the same document can't make an expired
period current.

Labels, annotations and the controller's finalizer are not evidence. You can
change labels and annotations.

## Attribution

The `konstapel-evidence-attachment-registrant` admission policies
(`config/admission/evidence-attachment-registrant.yaml`) set
`spec.registeredBy` from the API server's authenticated user (username and
UID) on create. A submitted value is replaced as a whole, so another
user's name or a UID the caller doesn't have never survives, and the
validating policy fails closed if the stored value doesn't match the caller.
Combined with spec immutability, nobody can later rewrite the registrant.
The record's `metadata.creationTimestamp` is the API server's submission time.

Three identities stay distinct:

| Identity | Recorded by | Authenticated |
| --- | --- | --- |
| Registrant (`spec.registeredBy`) | admission, on create | yes |
| Uploader (`status.storage.commitment.uploader`) | the transfer service, in the commit manifest | yes: the TokenReview identity of the upload that committed |
| Declared source (`spec.source`) | the registrant | no; it is a claim |

The uploader can be a different authorized identity from the registrant, and
neither is the declared issuer. Once a document is committed, a later upload
of the same bytes by anyone returns the first commitment and its uploader;
it is never re-attributed. A declared `source.url` is shown as informational
provenance and is never fetched by the controller, the transfer service or
the CLI.

## Associations

The controller validates every association before it applies. The result is
shown in `status.associations[]` (in spec order) and the `AssociationsValid`
condition:

| State | Reason | When |
| --- | --- | --- |
| `Valid` | `Valid` | The binding exists with the registered UID and has resolved a profile revision. That revision's verified bundle has the registered catalog digest, and its baseline selects every control. Every statement is a `statement` or `item` part of its own control. |
| `Pending` | `BindingUnresolved` | The binding hasn't resolved a profile, its resolution failed, or it is resolving a profile revision with other bundle content. Rechecked every minute and on binding changes. |
| `Pending` | `BaselineUnavailable` | The bundle's catalog and baseline don't resolve. The controller reads vendored content of its own digest, or a frozen copy of verified OCI content, with the coverage reader. Other content is never substituted. |
| `Mismatched` | `BindingNotFound` | No binding has that name. |
| `Mismatched` | `BindingReplaced` | The binding was recreated, so its UID changed. The association is never inherited. |
| `Mismatched` | `CatalogMismatch` | The binding now resolves a different catalog revision. |
| `Mismatched` | `ControlNotInBaseline` | A control isn't in the binding's selected baseline, for example after new bundle content removed it. |
| `Mismatched` | `StatementNotInControl` | A statement isn't one of its control's statement parts, for example `pe-2_smt.a` under `pe-3`, or a guidance part. |

The catalog and baseline are resolved by the same reader control coverage
uses (`coverage.ReadBaseline`, see
[supported profile resolution](control-coverage.md#supported-profile-resolution)).
For OCI bundles that is the bundle's declared baseline profile; for the
vendored content it is the Moderate profile. Every document is checked
against the controller's own OSCAL schemas. The catalog digest is the SHA-256
of the catalog file, the identity coverage qualifies controls with. A profile
the reader can't resolve, for example one that selects controls with
`matching`, keeps associations `Pending` (`BaselineUnavailable`); it is never
read as a mismatch or as an empty baseline.

`AssociationsValid` is `True` when every association is Valid, `False` when
any is Mismatched, and `Unknown` while any is Pending. A recreated binding
never comes back. A catalog or baseline mismatch lasts until the binding
again resolves exactly the registered catalog and controls. To correct an
association, register a new record.

The binding's resolved profile revision is the content it enforces, so the
controller validates against it. These edits keep an association `Valid`
the whole time, including while the binding re-resolves:

- reporting-only binding edits (`spec.assessment`);
- policy-parameter and exception-setting edits of the profile: a newer
  revision with the same bundle digest.

A profile revision with other bundle content makes the association
`Pending` until the binding resolves it, and then `Valid` or `Mismatched`.

Associations can target physical or organizational controls that have no
technical mapping. One record can support several explicitly named bindings
in this cluster. Konstapel doesn't infer datacenter membership from labels,
and records are never imported across clusters.

Associating a document with a binding covers that binding's namespace scope
for reporting. It gives the binding's teams no access to the document or its
metadata.

## Storage and the commit boundary

Document bytes live in S3, at an `EvidenceDestination` the controller pins
for each record. Records never carry bytes, keys or credentials.

**Pinning.** The first reconcile pins the central default destination (the
`konstapel-evidence-destination` ConfigMap, the same one assessments use):

1. The controller labels the record
   `compliance.erenius.io/attachment-destination-uid`.
2. It re-reads the destination, adds the destination's finalizer with an
   update conditioned on its resourceVersion, and records
   `status.storage.destination`.

The API rejects any change to a recorded pin. A later default never relocates
a document; new records use the new default. Credentials and CA trust rotate
through the pinned destination, and the controller rebuilds its client when
the destination changes. A destination with pinned attachments doesn't retire
while any of them still owns storage: committed documents count as retained
packages until their expiry, and pinned uncommitted records count as cleanups.

**Keys.** Everything an attachment owns is under
`<prefix>/attachments/<cluster UID>/<attachment UID>/`:

| Object | Written by | Purpose |
| --- | --- | --- |
| `attempts/<random>/intent.json` | the transfer service, before any bytes | the owning attachment and the authenticated uploader, so an interrupted attempt is always identifiable |
| `attempts/<random>/document` | the transfer service | the bytes, uploaded with their SHA-256 |
| `attempts/<random>/attempt.json` | the transfer service, after verification | the verified document version and uploader |
| `commit.json` | the transfer service, conditionally (`If-None-Match: *`) | the one commitment |

**Staging and commit.** Bytes are checked twice before they can be committed:

- before upload, the transfer service hashes the bytes against the registered
  size and SHA-256 and uploads nothing that differs;
- after upload, it verifies the stored version from the server's SHA-256 or
  by reading it back. ETags are never treated as content hashes.

The commit is the conditional creation of `commit.json`. The manifest binds:

- the document digest, size and version;
- the record's spec digest (the SHA-256 of its immutable spec, registrant
  included);
- the uploader recorded with the verified attempt;
- the destination ID (the EvidenceDestination UID);
- `validUntil` and the retention.

The manifest's server time is `committedAt`. Every later commit for the
record returns that first commitment, whether it's a retry, a concurrent
writer on another replica, or a call after a lost response. A request for
other bytes or another spec is a conflict and never replaces it. A request
with another retention or validity is ignored in favor of the first values.
Interrupted, unverified, or losing attempts never become the document.

**Recording.** The controller reads the commitment from storage and records
it in `status.storage.commitment`, with the `DocumentCommitted` condition. A
lost upload response, or a status write lost to a restart or leader change,
is recovered by reading the manifest again. A commitment that doesn't match
the record's spec digest, registered document or validity is never recorded
(`StorageConflict`). Once recorded, the commitment is immutable at the API.
`DocumentCommitted` attests storage and integrity only.

| `DocumentCommitted` | Meaning |
| --- | --- |
| `False/NoDestination` | No default destination is configured, or it's replaced, retiring or not ready. Nothing is pinned or stored. |
| `False/AwaitingUpload` | Pinned; no commitment yet. Rechecked every minute. |
| `False/StorageUnavailable` | The pinned destination can't be reached or was handed off to an operator. |
| `False/StorageConflict` | Storage holds a commitment for this UID that doesn't match this record. |
| `True/Committed` | The commitment is recorded. |

The controller removes uncommitted attempts once they are 24 hours old, along
with incomplete multipart uploads under the record's prefix. A committed
record's losing attempts are removed the same way. Only attempt directories
whose records name this attachment are removed. Other objects under the
prefix, and other attachments' prefixes, are never touched.

**Tested compatibility.** `scripts/s3-compat.sh` runs
`TestAttachmentStoreCompatibility` alongside the publisher suite. It uses the
same pinned, test-owned RustFS service (`KONSTAPEL_S3_IMAGE`) in each
versioning mode: unversioned, enabled and suspended. In each mode it checks:

- mismatched bytes are rejected;
- three concurrent writers, one of which loses its commit response, converge
  on one commitment;
- a retry with another retention returns the first commitment, and another
  spec conflicts;
- health checks pass;
- owned attempt and multipart cleanup leaves the unrelated object;
- deletion is refused before expiry;
- full owned deletion at expiry removes null versions and delete markers in
  a suspended bucket.

On 2026-11-17 it passed against RustFS 1.0.3
(`docker.io/rustfs/rustfs:1.0.3@sha256:9ca9559533b537d10482fe923288b676ad08f92a7069d9a17327fbae3cab688b`)
in all three modes. The run records the image, the version the container
reports (`s3-version.txt`) and the supported modes in `attachment-compat.json`,
and fails if either result file is missing. Other services and the semantics
this suite doesn't exercise are unsupported: a service that lacks conditional
create, server checksums or readback fails the destination probe and blocks
readiness rather than weakening the commit protocol. This makes no claim about
AWS S3 or Object Lock.

### Local development

There is one S3 fixture: the digest-pinned RustFS service of
`scripts/runtime.env` (`KONSTAPEL_S3_IMAGE`), driven by `scripts/s3-compat.sh`.
The production chart doesn't ship it, and there is no second S3 image and no
filesystem attachment backend. Controller, download service and CLI use the
production S3 adapter with an `EvidenceDestination` that sets
`developmentFixture: true`, the only way plain http to a loopback endpoint is
accepted.

```sh
# Start the fixture: random credentials, a loopback port, a bucket and a
# data volume it owns. Settings go to a 0600 file; never commit it.
devbox run -- bash scripts/s3-compat.sh --serve /tmp/konstapel-attachments-dev
# In another shell: source it, create a credential Secret and a destination
# whose endpoint, bucket and prefix match, then register, upload, capture and
# download as in "Workflow" below.
. /tmp/konstapel-attachments-dev/dev.env
# Stop with Ctrl-C (or EOF) in the first shell.
```

Teardown removes exactly the container and volume the run labelled
(`konstapel.s3-compat=<name>`), also on failure or interrupt, so unrelated
containers and volumes are untouched. Delete the output directory (it holds the
credentials) and the Secret you created from them. For the whole flow, including
capture into a platform package and download through the real controller, run
`task acceptance GROUP=storage OUTPUT=/absolute/fresh/path`
(`TestLiveAttachmentTransfer` and the lifecycle tests). To rerun just the
compatibility suites, use
`devbox run -- bash scripts/s3-compat.sh /absolute/fresh/path`. No Task task
wraps this script.

The transfer service (below) writes documents only through this adapter
(`internal/s3store.AttachmentStore`) and this contract.

## Uploading and downloading

Document bytes move through the evidence download service
(`konstapel download-server`, see [Downloads](integration/s3-evidence.md#downloads)),
the same TLS service and the same authentication as package downloads.
Every ready replica serves transfers; no leader is involved. There are no
presigned URLs and no direct bucket access for users.

| Route | Caller needs (SubjectAccessReview, name of the record) |
| --- | --- |
| `PUT /v1/evidenceattachments/<uid>/upload` | `create` on `evidenceattachments/upload` and `get` on `evidenceattachments` (`konstapel-evidence-attachment-uploader`) |
| `GET /v1/evidenceattachments/<uid>/download` | `get` on `evidenceattachments/download` and `get` on `evidenceattachments` (`konstapel-evidence-attachment-downloader`) |

Records are addressed by UID only. A recreated record has a new address, and
an unknown UID gets the same 403 as a denial. The bearer token goes to
TokenReview with the service's audience (`konstapel-download` by default), and
both attributes are checked with SubjectAccessReview against current RBAC.
Forwarded or impersonation headers are ignored, and review failures fail
closed.

**Upload.** Before reading any byte, the service requires:

- a live record (not withdrawn);
- a destination the controller has pinned (`status.storage.destination`);
- a registered size within the upload limit;
- no declared `Content-Length` other than the registered size.

Then it holds one of the replica's transfer slots and:

1. receives the bytes into bounded temporary storage within the transfer
   deadline, hashing them, and refuses anything other than exactly the
   registered size and SHA-256. Nothing has been stored at that point;
2. checks the caller's authorization and the record again (same UID, not
   withdrawn, same pin), so a revoked uploader or a withdrawn record never
   reaches storage;
3. answers a retry with the existing commitment if there is one;
4. otherwise stages the bytes in the record's pinned destination, never
   another one. Staging verifies the stored version (see above);
5. checks once more that the record isn't withdrawn and that its destination
   wasn't handed off to an operator, then commits.

The answer is the commitment: document digest and size, uploader,
`committedAt`, retention and `expiresAt`. A retry after a lost response, or a
concurrent upload on another replica, returns that same commitment. The
retention comes from the service's `--attachment-retention` setting
(default 2160h) and is frozen into the first commitment. The controller
records the commitment in `status.storage.commitment` (`DocumentCommitted=True`)
within about a minute.

**Withdrawal during an upload.** An upload is refused once the record is
withdrawn: before reading, before staging, and just before the commit.
Withdrawal removes uncommitted attempts. If a commit still lands while the
controller removes those attempts, the controller sees it, records it, and
retains it until its expiry like any other commitment. The withdrawn record
never becomes current evidence through it, and the upload's caller gets 409.

**Download.** The service serves only the commitment the controller recorded,
and only before its `expiresAt`. It first reads the stored commit manifest,
which must match the recorded commitment exactly: keys, versions, document,
spec digest, uploader and times, for this record's UID. It fetches the bytes
into bounded temporary storage and verifies them against the registered size
and SHA-256 before sending anything. A withdrawn record's retained document
stays downloadable until `expiresAt`, with `X-Konstapel-Withdrawn: true`.

Downloads are passive attachments:

- `Content-Type: application/octet-stream`, whatever the declared media type;
- `X-Content-Type-Options: nosniff`;
- `Content-Security-Policy: default-src 'none'; sandbox`;
- `Content-Disposition: attachment; filename="<record name>"`;
- `Cache-Control: private, no-store`.

The response also carries `Repr-Digest`, `X-Konstapel-Attachment-UID`,
`X-Konstapel-Document-SHA256`, `X-Konstapel-Declared-Media-Type`,
`X-Konstapel-Valid-From`, `X-Konstapel-Valid-Until`,
`X-Konstapel-Committed-At` and `X-Konstapel-Expires-At`. Konstapel never
opens, renders, decompresses or interprets a document. Responses and error
bodies never contain storage locations or credentials.

| Status | Upload | Download |
| --- | --- | --- |
| 200 | committed: the new or existing commitment | the verified document |
| 400 | the upload was interrupted; nothing was stored | |
| 401 | no token, or TokenReview did not accept it for the audience | same |
| 403 | not authorized, or no record has that UID | same |
| 408 | the bytes did not arrive within the transfer deadline; nothing was stored | |
| 409 | no destination pinned yet; the record is withdrawn; the bytes are not the registered size and SHA-256 (nothing was stored); storage holds a different commitment for this UID (it is preserved) | the commitment is not recorded yet |
| 410 | the destination was handed off to an operator | the source document expired, or its destination was handed off |
| 413 | the registered size exceeds the upload limit | |
| 429 | all transfer slots of the replica are busy (`Retry-After`) | same |
| 502 | storage did not verify the stored version; nothing was committed | the recorded or stored commitment, or the stored bytes, don't match the record |
| 503 | TokenReview/SubjectAccessReview or storage unavailable, or temporary space full (`Retry-After`) | same, or the committed document is missing before its expiry |

**Limits.** Each replica enforces these `konstapel download-server` flags:

| Flag | Default | Valid range | Bounds |
| --- | --- | --- | --- |
| `--attachment-max-bytes` | 32 MiB | 1 byte to 1 GiB, and at most `--max-temp-bytes` | the largest registered document accepted for upload; downloads of committed documents are not limited by it |
| `--attachment-timeout` | 5m | 1s to 1h | one transfer, receiving and storing included |
| `--attachment-max-concurrent` | 2 | 1 to 64 | simultaneous uploads and downloads on the replica |
| `--attachment-retention` | 2160h | positive whole seconds | the source retention frozen into each new commitment |

The service refuses to start with values outside these ranges. In the
runtime chart they are `download.attachments.maxBytes`, `timeout`,
`maxConcurrent` and `retention`, and the render refuses what the service
would refuse. Uploads and
downloads also share the package downloads' temporary storage budget
(`--max-temp-bytes`). A transfer cut off by a replica shutdown is retried by
the client; a retried upload converges on the same commitment.

**The service account.** `konstapel-evidence-download`
(`config/rbac/evidence-download.yaml`) lets the service read
`evidenceattachments` (get, list) to resolve UIDs and pins, and read the pinned
destination and its credential Secret. It never writes records or status.

### Workflow

`konstapel evidence` drives the whole platform workflow. It talks only to the
Kubernetes API and the download service. It never starts the C2P provider,
renders or delivers policies, or fetches a declared source URL. Kubeconfig
handling follows kubectl: `--kubeconfig`, else `KUBECONFIG`, else
`~/.kube/config`, with `--context` selecting a context. Transfers need
`--server` (https only; the token is never sent unencrypted), `--token-file`
with a token for the service's audience, and `--ca-file` unless the system
roots trust the service. `upload` and `download` take the record's name and
its exact `--uid`. A name that now has another UID is refused before anything
is sent.

Register, upload and download a document:

```sh
# As a registrar: review the completed record, then create it.
konstapel evidence register -f attachment.yaml --document dc-north-2026.pdf --dry-run
konstapel evidence register -f attachment.yaml --document dc-north-2026.pdf
ATTACHMENT_UID=$(kubectl get evidenceattachment dc-north-physical-access-2026 -o jsonpath='{.metadata.uid}')
# As an uploader (konstapel-evidence-attachment-uploader).
kubectl create token platform-uploader -n platform-ops --audience konstapel-download > upload.token
konstapel evidence upload dc-north-physical-access-2026 --uid "$ATTACHMENT_UID" --file dc-north-2026.pdf --server https://konstapel-download.konstapel-system.svc --ca-file ca.crt --token-file upload.token
kubectl wait evidenceattachment/dc-north-physical-access-2026 --for=condition=DocumentCommitted --timeout=3m
konstapel evidence status dc-north-physical-access-2026 --uid "$ATTACHMENT_UID"
# As a downloader (konstapel-evidence-attachment-downloader).
kubectl create token platform-auditor -n platform-ops --audience konstapel-download > download.token
konstapel evidence download dc-north-physical-access-2026 --uid "$ATTACHMENT_UID" --output dc-north-2026-copy.pdf --server https://konstapel-download.konstapel-system.svc --ca-file ca.crt --token-file download.token
```

`kubectl create token` issues tokens for service accounts. Other identities
need a token for the `konstapel-download` audience from their identity
provider.

- `upload` refuses a local file whose size or SHA-256 isn't the registered
  one, without sending it, and refuses a withdrawn record. It waits up to
  `--pin-wait` (default 1m) for the controller to pin a new record's
  destination, then reports the `DocumentCommitted` reason instead of
  sending. It prints the commitment. Rerunning it after a lost response is
  safe.
- `status` shows the record's three identities separately (registrant,
  uploader, declared source), plus validity, associations, the pinned
  destination, the commitment and the conditions. `-o json` prints them as
  JSON.
- `download` writes the output only after the received bytes match the
  record's registered size and SHA-256 and the service's `Repr-Digest`. It
  never replaces an existing file. It prints the declared media type and
  validity for context, without opening the document.

`TestLiveAttachmentTransfer` (acceptance group `storage`) runs these commands
unchanged, apart from names, against a real API server, the cluster's own
TokenReview and SubjectAccessReview, and the pinned RustFS service. It runs
them as separate registrar, uploader, reader and downloader service accounts
bound to the shipped roles, and also checks the denials, mismatches, limits,
interruptions, revocation, withdrawal and expiry above.

## Retention

The source document's expiry is fixed at commitment:

```text
expiresAt = max(committedAt, validUntil) + retention      (retention: 2160h by default)
```

The retention is positive, central (not a record field), and recorded in the
manifest. Later changes to the setting, a retry with another value, and
withdrawal can't change an existing commitment.

Source and assessment-copy retention are independent. Assessment packages
keep their own copies under their own per-binding retention (task group 5).
For example, a document valid for 2026, committed on 2026-03-01:

| | Expires | Why |
| --- | --- | --- |
| Source document | 2027-04-01 (`2027-01-01` + 2160h) | stays downloadable for its whole declared period and a tail for later assessments |
| A package from a run on 2026-06-01 with 90-day retention | 2026-08-30 | the package's own retention; deleting it never deletes the source |
| A package from a run on 2027-03-01 | 2027-05-30 | its own copy outlives the source; source cleanup never breaks it |

A document that has already expired (`validUntil` 2025-12-31) and is
committed on 2026-03-01 is kept until 2026-05-30 (`committedAt` + 2160h).
Re-registering an expired document doesn't make it current: validity is
declared in the immutable spec.

## Lifecycle

The controller reconciles four states of each record separately. None of
them is a verdict, and there is no combined "compliant" state:

| State | Field | Values | Changes when |
| --- | --- | --- | --- |
| Validity | `status.validity.state`, `nextTransition` | `NotYetValid`, `Current`, `Expired` | the controller's clock reaches `validFrom` or `validUntil` (`validFrom <= T < validUntil`). The controller requeues itself at the next boundary, so no other event is needed. Upload, commitment, re-upload and copy times never change it. |
| Content | `status.content` | `Pending` (`AwaitingUpload`, `NoDestination`, `StorageUnavailable`), `Available` (`Verified`), `Unavailable` (`ObjectMissing`, `IntegrityFailed`, `StorageUnavailable`, `StorageConflict`, `DestinationHandedOff`, `SourceExpired`) | a commitment is recorded; a metadata check of the committed version finds it present with its registered size (and SHA-256, where storage reports one), or not; the source reaches `expiresAt` |
| Association | `status.associations[]`, `AssociationsValid` | `Pending`, `Valid`, `Mismatched` | binding and profile changes ([Associations](#associations)) |
| Withdrawal | `status.withdrawal.withdrawnAt` | absent, or the deletion time | the record is deleted. It is never removed or changed afterwards. |

`kubectl get evidenceattachments` shows each of them. Content is checked
when the controller starts or a new leader takes over, then once a day while
`Available` and every minute while `Unavailable`. The check reads object
metadata only; downloads always verify the full bytes. At `expiresAt` the
content becomes `Unavailable/SourceExpired` without contacting storage, and
downloads answer 410. A live record's bytes stay in storage until the record
is withdrawn. `DocumentCommitted` keeps attesting the recorded commitment
whatever the content state.

New coverage (task group 5) reads these states through
`attachments.ForBinding` and maps them onto the coverage owner's
[`SupportingEvidenceContext`](control-coverage.md#the-consumer-contract). It never selects a withdrawn record. It selects
every other record associated with the binding's exact UID, with its
validity computed at the report's own instant, so an expired, future,
unavailable or mismatched document is explained rather than omitted.

### Example timeline

A record valid for 2026, with the default 2160h retention, on the
controller's clock:

| Time (UTC) | What happens | Validity | Content | Withdrawal |
| --- | --- | --- | --- | --- |
| 2025-12-15T09:00:00Z | registered; the controller pins the default destination | `NotYetValid` until 2026-01-01T00:00:00Z | `Pending/AwaitingUpload` | no |
| 2025-12-20T10:00:00Z | uploaded and committed; `expiresAt` is 2027-04-01T00:00:00Z | `NotYetValid` until 2026-01-01T00:00:00Z | `Available/Verified` | no |
| 2026-01-01T00:00:00Z | nothing: the controller's own timer | `Current` until 2027-01-01T00:00:00Z | `Available/Verified` | no |
| 2026-12-31T23:59:59Z | nothing | `Current` until 2027-01-01T00:00:00Z | `Available/Verified` | no |
| 2027-01-01T00:00:00Z | nothing: the controller's own timer | `Expired` | `Available/Verified` | no |
| 2027-01-10T12:00:00Z | the same file is uploaded again | `Expired` | `Available/Verified` | no |
| 2027-02-01T00:00:00Z | the record is deleted | `Expired` | `Available/Verified` | withdrawn; `SourceRetained=True/RetentionActive` |
| 2027-04-01T00:00:00Z | nothing: the controller's own timer | | | released; the owned source is removed |

The upload on 2027-01-10 answers with the first commitment: committed
2025-12-20T10:00:00Z by the first uploader, `expiresAt`
2027-04-01T00:00:00Z. `TestDocumentedAttachmentTimeline` runs this table
against the controller with an injected clock.

### Re-uploads and corrections

A re-upload never renews anything. Every upload of a committed record
returns the first commitment, with its uploader, `committedAt` and
`expiresAt`, and validity comes only from the immutable `spec.validity`.
An expired document uploaded today stays `Expired`; its source is kept for
the retention tail after the upload (see [Retention](#retention)).

A corrected period, a corrected document, another catalog mapping or another
binding is a new record ([Immutable records](#immutable-records-and-replacement)).
Register and upload the new record, then withdraw the old one:

```sh
konstapel evidence register -f attachment-2026-corrected.yaml --document dc-north-2026.pdf
konstapel evidence upload dc-north-physical-access-2026-corrected --uid "$NEW_UID" --file dc-north-2026.pdf --server https://konstapel-download.konstapel-system.svc --ca-file ca.crt --token-file upload.token
kubectl delete evidenceattachment dc-north-physical-access-2026 --wait=false
```

The old record leaves new coverage at once. Its source stays downloadable
until its own `expiresAt`, and historical packages keep their copies.

## Withdrawal and cleanup

Deleting a record withdraws it from new current evidence immediately and
permanently: the controller records `status.withdrawal.withdrawnAt`, the
API rejects any later change to it, and new coverage never selects the
record. Its associations stay as last resolved. (Controllers before task
group 4 also set `AssociationsValid=False/Withdrawn`; that condition is now
left alone.) The `compliance.erenius.io/evidence-attachment-retention`
finalizer then keeps the record, and with it the storage ownership, until
no owned storage remains:

| Record | On deletion |
| --- | --- |
| never pinned | released at once: nothing can be stored |
| pinned, no commitment | storage is read once more. A commitment found there (its status write was lost) is recorded and governs retention like any other. Otherwise every owned attempt and multipart upload is removed, then the record is released. |
| committed, before `expiresAt` | kept: `SourceRetained=True/RetentionActive`, `status.storage.cleanup.state: NotDue`. Withdrawal never shortens the commitment. Nothing is deleted, and storage is contacted only for the content check. The retained source stays downloadable, marked withdrawn. |
| committed, at or after `expiresAt` | downloads answer 410. Every owned object version and delete marker is removed, each attempt's document before its ownership records and the commit manifest last. Once storage confirms nothing owned remains, the record is released. |

Cleanup removes only what the attachment owns: the `document`,
`attempt.json` and `intent.json` of attempts whose records name it, and its
`commit.json`. Other objects under its prefix, even inside one of its
attempt directories, other attachments, and assessment packages are never
touched. Package copies keep their own retention.

### Recovery

All lifecycle state is durable on the API server or in storage; the
controller keeps nothing in memory that a restart or a new leader needs.
After a restart or a leader change, the controller reconciles every record
again: it re-evaluates validity at once, re-checks content, and resumes a
withdrawal or cleanup where it stopped. Each step is repeatable:

- a commitment whose status write was lost is read from storage again;
- a withdrawal found before its status write is recorded on the next pass;
- a deletion that removed part of the owned objects keeps the attempt's
  ownership records and the commit manifest, so the next attempt finds the
  rest;
- a status write from a former leader that read the record before its
  deletion is rejected by its resourceVersion precondition and can't undo
  the withdrawal.

`TestAttachmentRecoversFromACrashAtEveryDurableStep` stops the controller
before each of its writes in this lifecycle and restarts it with empty
memory. Every run ends the same way.

A failed or refused deletion is never treated as cleanup. Causes include an
unreachable destination, a destination handed off to an operator, Object
Lock, a legal hold, or missing delete permission. The record keeps its
finalizer, its pin and its commitment, and the destination keeps its own
finalizer and lists the record among its cleanup blockers.
`status.storage.cleanup` shows `DeletionFailed` or `RetentionBlocked`, the
number of failed `attempts`, the `lastAttempt` time and the storage message
(at most 1024 characters), and `SourceRetained` says when the next attempt
is due. Attempts back off; in between, the controller neither contacts
storage nor writes status:

| Failed attempts | Next attempt after |
| --- | --- |
| 1 | 1m |
| 2 | 2m |
| 3 | 4m |
| 4 | 8m |
| 5 | 16m |
| 6 | 32m |
| 7 or more | 1h |

Once the cause is fixed (the lock expired, the permission granted, the
destination reachable again) the next attempt completes the cleanup. Nothing
needs to be reset.

`TestLiveAttachmentLifecycle` (acceptance group `storage`) checks this
lifecycle against a real API server and the pinned RustFS service: validity
changing at its boundaries with no other event, policy-preserving binding and
profile edits that never change a valid association, a removed document
version reported `Unavailable/ObjectMissing`, a withdrawal kept across a
controller restart until its fixed expiry, and a cleanup refused while the
destination rejects the controller's credentials, retried after its backoff
and completed once access returns.

### A destination handed off to an operator

A destination handed off with `deletionPolicy: Orphan` is never contacted
again. Its attachments are not part of the orphan inventory yet (a tracked
follow-up of this change), so the handoff fails safe:

- transfers for its attachments answer 410. An upload already in progress
  re-reads the destination just before it commits; only a commit already
  under way at that moment can still land, inside the attachment's own
  prefix, which the administrator takes over below;
- each pinned attachment keeps its finalizer, its pin and its commitment.
  Its content is `Unavailable/DestinationHandedOff`; cleanup reports
  `DeletionFailed` and is retried with the backoff above, without contacting
  storage;
- the destination keeps counting them (committed ones as packages, the rest
  as cleanups) and is not released while any remains.

An administrator resolves this by taking over the attachments' storage and
then releasing their records:

```sh
uid=<destination UID>
cluster=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')
# 1. Export the records: each commitment names its document and commit keys,
#    versions, SHA-256, size and expiresAt.
kubectl get evidenceattachment -l compliance.erenius.io/attachment-destination-uid=$uid -o yaml > attachments-$uid.yaml
# 2. Take over the objects under <prefix>/attachments/$cluster/<attachment UID>/
#    (every version, delete marker and incomplete upload), and apply your own
#    retention. Konstapel never deletes them after the handoff.
aws s3api list-object-versions --bucket <bucket> --prefix <prefix>/attachments/$cluster/
# 3. Withdraw records that are still live.
kubectl delete evidenceattachment <name> --wait=false
# 4. Only for records whose storage you now own: release them.
kubectl patch evidenceattachment <name> --type=json -p '[{"op":"remove","path":"/metadata/finalizers"}]'
```

Removing a finalizer never deletes or moves storage. Once no pinned
attachment remains, the destination is released. Records still in use need a
new registration and upload, which pins the current default destination.

If the controller isn't running, deleted records wait for it. Attachments
have no owner references, so deleting a binding or namespace never deletes
an attachment or its document.

## Coverage and assessment packages

Supporting documents reach assessments through the coverage owner's
`SupportingEvidenceContext` contract
(`konstapel.io/supporting-evidence-context/v1`, see
[control coverage](control-coverage.md#supporting-evidence)). A document is
supporting material: it never adds a check, an expected observation, a
finding, an outcome or an automation state, and it changes no evidence
count, policy revision or risk acceptance.

### What a run freezes

When a run starts, it freezes every record that names its binding's exact
UID and isn't withdrawn, whatever its other states: the record UID and
name, the immutable registration and its digest, the association, its last
resolution, the content state and the recorded commitment. A record that is
withdrawn before the run starts never enters it. A record registered later
doesn't enter it either.

While the run collects, a platform run (scope `Binding`) copies each frozen
document whose association is `Valid` and whose content is `Available`. It
reads the document from the record's own pinned destination and checks the
bytes against the registered size and SHA-256 before staging them. Reads
stop when the collection window closes. A namespace run copies nothing.

At closure the run reads the records again. A record that was deleted or
withdrawn meanwhile is marked `withdrawn`. A record whose association or
content state changed is marked `changed`. The states reported are the ones
frozen at start, and coverage classifies the declared validity at the
closure time, so an expired or not-yet-valid document is reported with that
state, never as current. The context is frozen with the closure. A re-export
after a crash uses the same context and the same staged copies. If a staged
copy is lost or no longer matches, the run fails with `CaptureLost`: it never
reads a newer document under the run's identity.

| Integration problem | Reported as |
| --- | --- |
| Records can't be read at start or at closure | `integration: unavailable`, reason `RecordsUnavailable` (a blocking coverage limitation, never an empty list) |
| A platform run names documents but the download replicas aren't verified to enforce document read at closure ([protected-package readers](charts.md#protected-package-readers)) | `integration: unavailable`, reason `ProtectedReadersUnverified`; no context or copy is packaged. Permanent for that run: it is never rewritten after the readers are verified |
| A run started by an earlier controller | `integration: disabled` (documents not considered) |
| No record names the binding | `integration: available` with no entries; the package is unchanged |

### Platform packages

A platform package that reports at least one document carries two protected
file roles:

| Path | Role | Content |
| --- | --- | --- |
| `supporting-evidence/context.json` | `supporting-context` | The run's frozen context, with each document's private metadata (title, issuer, scope description, media type, size, SHA-256) and, for included documents, the copy's path. |
| `supporting-evidence/documents/<record UID>` | `supporting-document` | A verified, independent copy of the document. |

Nothing else may be placed under `supporting-evidence/`. The descriptor
records the protected roles it carries:

```json
"protection": {
  "version": "konstapel.io/package-protection/v1",
  "roles": ["supporting-context", "supporting-document"]
}
```

The marker is derived from the inventoried roles and must match them
exactly; a descriptor with protected roles and no marker, or a marker
without them, doesn't validate. The producer adds the
`supporting-evidence` check. The OSCAL assessment results reference each
copy from a back-matter resource, by its relative path and SHA-256. That
resource is the only OSCAL change: there is no observation, finding or
control result for a document, and no link to live storage. The declared
source URL is never packaged.

Each entry's `access` says what the package holds:

| `access` | When | `content` |
| --- | --- | --- |
| `included` | A `Valid`, `Available` document that was copied and verified. | `available` |
| `notIncluded` | An association that isn't `Valid`, content that isn't `Available` at start, a source past its expiry, or one of the reasons below. | the frozen state, or `unavailable` with a reason |

| `contentReason` | Meaning |
| --- | --- |
| `NotRetrieved` | The document was available at start but wasn't retrieved and verified before the collection window closed (storage unavailable, damaged bytes, a fenced or handed-off destination). |
| `PackageLimit` | The package already holds 64 copies or 256 MiB of copies. |

A package copy belongs to its package. It follows the package's own
retention and stays readable after the source record is withdrawn or its
source bytes are deleted. Source cleanup never touches it. The package
verifier (`s3store.ValidatePackage`, run before staging) checks that the
context is the contract, valid at the closure, `available`, and only for the
package's binding; that each included entry's copy is inventoried at
`supporting-evidence/documents/<source>` with the registered SHA-256 and
size; and that every copy is cited by exactly one included entry.

A package whose context names no document carries neither file and isn't
protected. A context that breaks the contract is never packaged: coverage
reports it as `ContextInvalid` instead.

### Namespace packages

A team's namespace package never carries a document copy, the context file,
or a protected role. The descriptor verifier rejects them, and the exporter
refuses them. Its coverage report lists the binding's entries as
`restricted`: the opaque record UID, the associated controls, the declared
validity and the content, association and withdrawal states. There is no
title, issuer, scope description, registration digest, document digest,
copy or link. The report doesn't claim to hold the restricted evidence.

### Downloading a protected package

A protected package needs the cluster-wide document-read grant in addition
to run access. `GET /v1/assessmentruns/<run uid>/download` (and
`/signature`) checks, after the archive is verified and before any byte is
served:

1. `get assessmentruns/download` and `get assessmentruns` for the run, as
   for every platform package;
2. for a protected package, `get evidenceattachments/download` and `get
   evidenceattachments` with no resource name: the
   `konstapel-evidence-attachment-downloader` role. A grant restricted to
   some record names isn't enough. There are no per-document ACLs.

Without the second grant the answer is `403`, and the package isn't
redacted on the fly. The check runs on every request, so removing the
binding stops new downloads at once. Protection is read from the verified
package's own descriptor, so downloading a historical package never
depends on the attachment records still existing. A namespace request's
route (`/v1/namespaces/<ns>/assessmentrequests/<name>/download`) never
serves a protected package. A descriptor whose protection this service
can't verify (an unknown protection version, protected files without the
marker) gets `502` and nothing is served.

```sh
# A platform auditor who reads runs and supporting documents.
kubectl create clusterrolebinding auditor-runs --clusterrole=konstapel-assessment-operator --serviceaccount=platform-ops:platform-auditor
kubectl create clusterrolebinding auditor-documents --clusterrole=konstapel-evidence-attachment-downloader --serviceaccount=platform-ops:platform-auditor
```

### Reading the report

In `coverage.json` and `coverage.txt`, the `supportingEvidence` section
lists the entries, and each control row the entries name references them.
Read them as follows:

- `temporal` is the declared validity at the report's `asOf`: `current`,
  `expired` or `notYetValid`. Upload and copy times never change it.
- `content: available` with `access: included` means the package holds
  verified bytes. It says nothing about the truth of the document's claims.
- `association: valid` means the controller resolved the association
  against the binding's baseline when the run started.
- `withdrawn: true` means the record was withdrawn during the capture.
  `changed: true` means its association or content state changed during
  the capture. Neither is current, unconditional evidence.
- A row's `automation` stays what the technical mappings make it, `none`
  for a physical control. A document is never a verdict.

### Compatibility and rollout

| Reader | Package without protected roles | Package with protected roles |
| --- | --- | --- |
| This version | Read as before. The download service only decodes the descriptor to find its protection; it doesn't re-validate packages produced under earlier rules. | Validated fully. An unknown protection version fails closed. |
| Earlier versions of `s3store.ValidatePackage` and `publication.LoadDescriptor` | Read as before. | Rejected: unknown roles and an unknown descriptor field. |
| Earlier download services | Served. | **Served without the document-read check.** They don't read descriptors. |

The controller and the download service ship in the same image and chart.
The controller writes a protected package only while every download replica
runs its own image ([protected-package readers](charts.md#protected-package-readers)).
While that isn't so, during an upgrade's download rollout for example, a
platform run's supporting evidence is reported unavailable
(`ProtectedReadersUnverified`) and its package carries none.

**The limitation is permanent for a run that closed in that state.** The
reader check is asked once, at closure, and the answer is frozen with the
run. A run that closes during a rollout keeps `integration: unavailable`
(reason `ProtectedReadersUnverified`) with no document copy and no protection
marker in its package, even after every download replica runs the controller's
image. Nothing re-evaluates, rewrites or republishes a closed run's report,
package or status, and a document registered or withdrawn later does not
change it. Only its supporting context is affected: its outcomes, evidence
completeness (`EvidenceComplete`) and technical evidence in the coverage
report are those of a run that closed with verified readers. The next run
that closes after the rollout carries its supporting evidence normally. To
have documents for the affected period, time upgrades so that no platform
run with associated documents closes during the download rollout, or start a
new run once it is complete. A run you must not lose its supporting context
for is one to re-run, not one that is repaired in place.

Don't roll the download service back below this version while protected
packages are retained: an earlier one is not a supported downgrade.

To roll back the feature, stop registering documents and withdraw the
records whose copies new runs should not carry. Keep this version's
download service, and keep attachment cleanup running until every
commitment and every protected package has expired. Never delete retained
source documents, packages or the CRDs as rollback cleanup.

## Integrated acceptance

Two live tests run the whole platform workflow together, against a real API
server with its own TokenReview and SubjectAccessReview, the pinned RustFS
service, and service accounts bound to the shipped roles.

`TestLiveSupportingEvidenceAcceptance` (acceptance group `assessments`):

- `konstapel evidence register` registers one facility document for two
  bindings, filling both binding UIDs; the uploader commits it through the
  transfer service. Expired, not-yet-valid and never-uploaded documents are
  registered beside it. Registration changes no binding and no engine
  policy.
- Each binding's platform package carries the shared document under the
  same record UID and registration digest, with the declared facility
  scope. The expired and not-yet-valid copies carry their temporal state.
  The never-uploaded document is reported `pending` and not included. The
  technical evidence, outcomes, control rows and enforcement revisions are
  those of the run before any document existed.
- Run access alone, document read alone and namespace credentials each get
  `403` for the protected packages and source documents they may not read.
  Both grants together download the package. Each team's package lists
  only its own binding's documents, as `restricted` entries without bytes,
  private metadata or links.
- Retention is independent. A package deleted at its expiry leaves the
  source document, and a later run copies it again. A withdrawn source
  deleted at its own expiry leaves the package that copied it readable and
  valid.

`TestLiveSupportingEvidenceRecovery` (acceptance group `recovery`). The
documents' storage is an object-lock bucket behind the test's fault proxy;
controllers are leader-elected candidates, each with its own staging
directory:

- A transfer replica lost after staging and before its commit leaves an
  owned, uncommitted attempt, which attempt cleanup removes; the caller's
  retry on another replica commits once. A replica lost after its commit
  landed loses the response; the retry is answered with the original
  commitment and uploader. A replica with another retention setting changes
  neither. An interrupted upload stores nothing.
- A platform run reports a pending upload as `pending`, and a document
  whose storage refuses reads for the whole collection window as
  `unavailable`/`NotRetrieved`; its source download answers `503`
  meanwhile. A document withdrawn during the capture keeps its verified
  copy, marked withdrawn, and its retained source stays downloadable.
- A leader lost before durable staging fails the run as `CaptureLost`, with
  nothing stored. A leader lost after durable staging is recovered by the
  next leader, which commits the staged bytes unchanged, although documents
  were withdrawn in between.
- A legal hold denies a withdrawn document's source deletion at its expiry.
  The record keeps its finalizer, pin and commitment, the destination stays,
  the source download answers `410`, and the package's copy stays readable.
  After the hold is lifted, the next attempt removes every owned version, and
  the package still validates.

## Authority

All roles are ClusterRoles in `config/rbac/evidence-attachments.yaml`, shipped
in the runtime chart. None is aggregated into the built-in `admin`, `edit` or
`view` roles. Bind them with ClusterRoleBindings to platform subjects only.

| Role | Grants | Purpose |
| --- | --- | --- |
| `konstapel-evidence-attachment-registrar` | `evidenceattachments`: get, list, watch, create, delete; `status`: get | Register and withdraw records. There is no update or patch: the spec is immutable. |
| `konstapel-evidence-attachment-uploader` | `evidenceattachments`: get; `evidenceattachments/upload`: create | Upload a registered record's bytes through the transfer service |
| `konstapel-evidence-attachment-reader` | `evidenceattachments` and `status`: get, list, watch | Read metadata and status, never bytes |
| `konstapel-evidence-attachment-downloader` | `evidenceattachments`: get; `evidenceattachments/download`: get | Cluster-wide document read through the transfer service, and the extra grant a protected platform package needs (with run access). There are no per-document ACLs. |
| `konstapel-controller` (generated) | `evidenceattachments`: get, list, watch, update, patch; `status`: get, update, patch; `finalizers`: update | Validation, the destination-pin label, status and the retention finalizer |
| `konstapel-evidence-download` (the download service's own role) | `evidenceattachments`: get, list | Resolve a transfer's record by UID and its pinned destination. It writes nothing. |

`evidenceattachments/upload` and `/download` are authorization attributes
that the transfer service checks with SubjectAccessReview. They are not
CRD subresources, and the API server doesn't serve them. No other shipped role
grants anything on `evidenceattachments`. That includes the assessment
requester and exception editor (namespace roles), the compliance admin and
viewer, and the assessment operator. Only the controller writes status.

To check what a subject can do:

```sh
kubectl auth can-i create evidenceattachments --as=platform-registrar          # yes for registrars only
kubectl auth can-i create evidenceattachments --subresource=upload --as=u      # yes for uploaders only
kubectl auth can-i get evidenceattachments --subresource=download --as=d       # yes for downloaders only
kubectl auth can-i get evidenceattachments --as=system:serviceaccount:team-a:dev   # no
```

`TestAttachmentAuthorityMatrix` checks this matrix statically against every
shipped role. `TestLiveEvidenceAttachmentAPI` (acceptance group `admission`)
checks the same probes with SubjectAccessReview against a real API server.
The live test also checks:

- the published example's validation;
- strict field validation and immutability;
- forged-registrant replacement;
- controller association states for shared, foreign-statement, wrong-catalog,
  reporting-only-edit and recreated-binding cases;
- withdrawal.
