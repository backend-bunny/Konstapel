# Supporting evidence

Some controls in the selected baseline, such as datacenter physical security
(PE-3), can't be checked by workload policies. Platform operators can register
supporting documents for those controls as `EvidenceAttachment` records
(`compliance.erenius.io/v1alpha1`, cluster-scoped). An attachment is
supporting material. It has no verdict field, and it never changes technical
findings, expected checks, enforcement or risk acceptance.

**Status.** This is the `add-supporting-evidence-attachments` change, task
groups 1 to 3. The following are implemented:

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
- the `konstapel evidence` CLI (group 3).

Validity and availability status, and inclusion in assessment packages,
come in later task groups. The runtime chart's download service serves the
attachment routes with the default limits; chart values for the limits come
with the chart integration (task 7.1).

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
UID) on create. A value that names someone else is overwritten, and the
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
| `Valid` | `Valid` | The binding exists with the registered UID. It has resolved its current spec and profile revision. That revision's verified bundle has the registered catalog digest, and its Moderate baseline profile selects every control. Every statement is a `statement` or `item` part of its own control. |
| `Pending` | `BindingUnresolved` | The binding hasn't resolved its current spec or profile revision yet. Rechecked every minute and on binding changes. |
| `Pending` | `BaselineUnavailable` | The bundle content can't be read. The controller reads vendored content of its own digest, or a frozen copy of verified OCI content. Other content is never substituted. |
| `Mismatched` | `BindingNotFound` | No binding has that name. |
| `Mismatched` | `BindingReplaced` | The binding was recreated, so its UID changed. The association is never inherited. |
| `Mismatched` | `CatalogMismatch` | The binding now resolves a different catalog revision. |
| `Mismatched` | `ControlNotInBaseline` | A control isn't in the binding's selected baseline. |
| `Mismatched` | `StatementNotInControl` | A statement isn't one of its control's statement parts, for example `pe-2_smt.a` under `pe-3`, or a guidance part. |

`AssociationsValid` is `True` when every association is Valid, `False` when
any is Mismatched, and `Unknown` while any is Pending. A mismatch is final for
that record. To correct it, register a new record.

Some binding edits keep associations valid:

- reporting-only edits (`spec.assessment`);
- a new profile revision with the same catalog and controls.

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

On 2026-11-14 it passed against
`docker.io/rustfs/rustfs:1.0.3@sha256:9ca9559533b537d10482fe923288b676ad08f92a7069d9a17327fbae3cab688b`.
This makes no claim about AWS S3 or Object Lock.

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
5. checks once more that the record isn't withdrawn, then commits.

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

The service refuses to start with values outside these ranges. Uploads and
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

## Withdrawal and cleanup

Deleting a record withdraws it from new current evidence immediately
(`AssociationsValid=False/Withdrawn`). The
`compliance.erenius.io/evidence-attachment-retention` finalizer then keeps
the record, and with it the storage ownership, until no owned storage
remains:

| Record | On deletion |
| --- | --- |
| never pinned | released at once: nothing can be stored |
| pinned, no commitment | storage is read once more. A commitment found there (its status write was lost) is recorded and governs retention like any other. Otherwise every owned attempt and multipart upload is removed, then the record is released. |
| committed, before `expiresAt` | kept: `SourceRetained=True/RetentionActive`, `status.storage.cleanup.state: NotDue`. Withdrawal never shortens the commitment. |
| committed, at or after `expiresAt` | every owned version and delete marker is removed, the commit manifest last. Once storage confirms nothing owned remains, the record is released. |

A failed or refused deletion is never treated as cleanup. Causes include an
unreachable destination, Object Lock, a legal hold, or missing delete
permission. The record keeps its finalizer, its pin and its commitment.
`status.storage.cleanup` shows `DeletionFailed` or `RetentionBlocked` with
the storage message, the destination lists the record among its cleanup
blockers, and the controller retries every 5 minutes.

### A destination handed off to an operator

A destination handed off with `deletionPolicy: Orphan` is never contacted
again. Its attachments are not part of the orphan inventory yet (a tracked
follow-up of this change), so the handoff fails safe:

- transfers for its attachments answer 410;
- each pinned attachment keeps its finalizer, its pin and its commitment;
  cleanup reports `DeletionFailed` and is retried without contacting storage;
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

## Authority

All roles are ClusterRoles in `config/rbac/evidence-attachments.yaml`, shipped
in the runtime chart. None is aggregated into the built-in `admin`, `edit` or
`view` roles. Bind them with ClusterRoleBindings to platform subjects only.

| Role | Grants | Purpose |
| --- | --- | --- |
| `konstapel-evidence-attachment-registrar` | `evidenceattachments`: get, list, watch, create, delete; `status`: get | Register and withdraw records. There is no update or patch: the spec is immutable. |
| `konstapel-evidence-attachment-uploader` | `evidenceattachments`: get; `evidenceattachments/upload`: create | Upload a registered record's bytes through the transfer service |
| `konstapel-evidence-attachment-reader` | `evidenceattachments` and `status`: get, list, watch | Read metadata and status, never bytes |
| `konstapel-evidence-attachment-downloader` | `evidenceattachments`: get; `evidenceattachments/download`: get | Cluster-wide document read through the transfer service. There are no per-document ACLs. |
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
