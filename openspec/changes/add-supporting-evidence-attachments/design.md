# Design

## Context

See [proposal.md](proposal.md) and the
[attachment contract](specs/supporting-evidence-attachments/spec.md).

The repository has generated Konstapel APIs, authenticated assessment requester
attribution, collector scope/freshness contracts, and `internal/publication`.
`Publisher` is keyed by cluster/binding/run and cannot represent a shared source
document without inventing a run. File roles and summary fields are validated;
arbitrary files cannot simply be added to a package unnoticed.

The active S3 change owns backend configuration, commit/readback semantics,
authenticated download service, and retention execution. Its design deliberately
avoids cross-package deduplication. The coverage change supplies a versioned,
already-projected supporting-evidence input. This design connects those seams
while preserving platform-only document management in the first version.

## Goals / Non-Goals

**Goals:** Authenticated passive-document intake; durable immutable source bytes;
exact associations; validity independent of retention; confidential package
copies; a reproducible SeaweedFS development workflow.

**Non-Goals:** Team uploads, direct bucket credentials for users, fetching supplied
URLs, text extraction/OCR, scanner-result ingestion, control verdicts, approval
queues, new exception behavior, or automatic verification of a datacenter's
physical boundary. Source URLs and declared authors are claims, not identities
authenticated by Konstapel.

## Decisions

### 1. One protected record identifies immutable documentary evidence

Add cluster-scoped `EvidenceAttachment` in `compliance.erenius.io/v1alpha1` using
the repository's API generator and admission conventions. Its spec contains:

| Field group | Purpose |
| --- | --- |
| Document | Declared title, media type, expected byte length and SHA-256 |
| Source | Declared issuer/source description and optional informational URL |
| Validity | Required `validFrom` and `validUntil` timestamps |
| Associations | Exact local binding name/UID, catalog digest, control IDs and optional statement IDs |
| Scope description | Platform's explanation of the facility/system covered |
| Protected registration | Authenticated registering actor, not caller authority |

The CLI reads binding identities and resolved catalog information before creating
the record. Admission validates structure and immutability; the controller resolves
references and revalidates before making associations usable. A stale client cannot
silently bind to a replacement object. Statement references must belong to their control. References
can target selected physical/organizational controls without technical mappings.
The first version supports multiple local bindings explicitly; it does not infer
datacenter membership from workload labels or import evidence across clusters.

Keep evidence-defining spec fields immutable from creation. A corrected document,
period, catalog mapping, or added binding association creates a new identity and
reuploads bytes; the operator can withdraw the old record. This avoids an implicit
moving evidence revision. Ordinary descriptive Kubernetes metadata cannot change
scope or validity. Bindings keep their enforcement settings and revisions; there
is no attachment-reference edit to a ComplianceBinding spec.

Implementation (task group 1) fixes these interpretations:

- **Field names.** `spec.document` holds `title`, `mediaType`, `size` and
  `sha256`. `spec.source` holds `issuer` and an optional `url`.
  `spec.validity` holds `validFrom` and `validUntil`. `spec.scope` holds
  `description`. `spec.registeredBy` is the protected registrant. Each
  `spec.associations[]` entry holds `binding.{name,uid}`, `catalogDigest`, and
  `controls[].{id,statements}`.
- **API ceilings.** The API's absolute size ceiling is 1 GiB. The transfer
  service's configurable limit applies below it.
- **Catalog digest.** The catalog digest is the SHA-256 of the OSCAL catalog
  file in the bundle the binding's resolved profile revision pins.
- **Selected baseline.** Until the coverage owner's baseline reader exists,
  the selected baseline is that bundle's Moderate profile: an explicit
  `include-controls`/`with-ids` selection. `include-all` and `matching` fail
  closed as unavailable.
- **Statements.** A statement must be the control's own `statement` part or
  one of its nested `item` parts.
- **Content source.** The controller reads the vendored content of its own
  digest, or a frozen copy of verified OCI content. It never substitutes
  other content.
- **Status.** Status starts with per-association state and
  `AssociationsValid`. Temporal, content, withdrawal, and commitment fields
  are added additively by their task groups.
- **Retention finalizer.** The finalizer is released immediately while a
  record owns no stored bytes. Group 2 gates it on the recorded commitment.

Capture registration using protected admission consistent with assessment
requester attribution and the API-server-assigned creation timestamp; record the
actual upload principal separately at the transfer service. Only controller
credentials write status. Status carries conditions, resolved identity,
immutable commitment/retention receipt, observed
availability/validity, and cleanup state, never document bytes or credentials.
Do not grant privileges by aggregating into built-in `admin`, `edit`, or `view`.

### 2. Register through Kubernetes, transfer through the authenticated service

Add a small `konstapel evidence` command family with `upload`, `download`, and
status inspection. Registration metadata is declarative and reviewable; upload
accepts a record name/UID plus a local file. It does not run the C2P provider or
policy delivery. Do not encode files in CRDs or require operators to know S3 keys.

Extend the S3 owner's TLS service with UID-addressed attachment content routes.
Use Kubernetes TokenReview and SubjectAccessReview through its existing helpers.
Upload requires record read plus explicit `create` on the service authorization
attribute `evidenceattachments/upload`; download requires record read plus `get`
on `evidenceattachments/download`. These are service authorization attributes,
not automatically implemented CRD subresources. Registration, upload, metadata
read, and document read are distinct grants; namespace roles receive none.

Check identity, current authorization, immutable metadata, and deletion state
before accepting bytes. Staging is bounded to 32 MiB per document, a five-minute
transfer deadline, and two concurrent transfers per serving replica by default;
operator settings can lower or raise validated limits. Hash the stream and verify
size against the record, then commit only after S3 readback/checksum validation.
Do not trust an upload header or ETag as content proof. Interrupted attempts never
become available evidence.

Serve downloads as passive attachments with a safe filename, no MIME sniffing,
and private/non-cacheable responses. Do not inline HTML or execute/decompress
documents. Media type is descriptive; opaque machine-produced files can be stored
but produce no imported findings. Document inspection or source verification is
outside this feature. There is no presigned-URL shortcut around current RBAC.

### 3. Share S3 mechanics without pretending a document is an assessment run

Introduce an attachment-owned storage contract under `internal/attachments` for
commit/recover, inspect/open, and owned deletion. Reuse the S3 adapter's central
destination/credential configuration and tested low-level object operations.
If those helpers are not yet exposed, extract the small shared layer with the
S3 owner; do not duplicate credentials, SDK bootstrapping, or commit semantics.
Existing `publication.Publisher` continues to handle assessment packages only.

Use a separate owned attachment prefix keyed by cluster identity and attachment
UID, with attempt-specific objects and one fixed conditional commit manifest.
The manifest binds document digest/size, immutable registration/spec digest,
actual uploader, destination, stored version, and retention inputs. It excludes
itself from its content checksum. Verify bytes first, then conditionally create
the manifest; its server LastModified supplies commitment time. Unknown results
recover that same manifest. A concurrent loser cannot publish under another key
or overwrite the winner, and its abandoned data is cleaned independently.

Every ready serving replica can process authorized transfers; leader election
owns background validity and cleanup. Conditional storage and API resourceVersion
updates provide idempotency across replicas and restarts. Store the resolved
destination identity in the receipt; credential rotation can repair access to
that destination, but a new default must not relocate old documents silently.
Record attempt ownership durably and clean uncommitted attempts after 24 hours
by default. Keep useful failure metadata; never sweep arbitrary bucket prefixes.

### 4. Separate validity, availability, association, and retention

Use the half-open declared validity window `validFrom <= asOf < validUntil`,
rejecting missing dates or `validFrom >= validUntil`. A historical or future
document can be registered, but upload time is not evidence time. Reconciliation
schedules the next validity boundary rather than waiting for unrelated changes.
The platform asserts the period; even a checksum cannot prove that assertion.

Expose temporal state (not-yet-valid/current/expired), content state
(pending/available/unavailable), association state (valid/mismatched), and
withdrawal separately. There is no single `compliant` boolean. Catalog revision
changes, controls leaving the selected baseline, or binding UID replacement stop
current association. An unrelated policy parameter or assessment interval change
does not invalidate a facility document whose catalog/control/binding scope is
unchanged. Association with a binding intentionally covers that binding's
selected namespace scope in this cluster; it grants no team document access.

At first storage commitment, freeze positive central source retention with a
2160-hour default. Source expiry is `max(committedAt, validUntil) + retention`.
This deliberate default keeps a year-long document available for its declared
period even when individual assessment packages retain only 90 days. Date and
retention changes cannot alter a committed record; corrections use new records.
Withdrawal does not shorten the recorded storage commitment.

Deleting a record withdraws it from new current evidence immediately, while a
retention finalizer preserves the record and owned cleanup metadata. Retained
source downloads remain available to authorized platform readers until storage
expiry. After expiry, stop new source downloads and remove owned versions,
markers, commit manifests, and attempts using the S3 owner's supported semantics.
External Object Lock or deletion errors remain explicit; finalizers are removed
only after owned cleanup is confirmed. Do not use owner references to bindings
or namespaces, since their deletion must not lose document retention work.

### 5. Freeze independent copies into authorized assessment packages

The assessment producer reads attachment associations for the frozen run scope
and passes the coverage owner's projection model. Freeze record UID/spec digest,
catalog/control references, dates, source identity, and association state at run
start. Classify time validity at closure and record withdrawal/association changes
during capture. Required reads are bounded by the run's collection window.
Unavailable bytes or context produce a documentary limitation, not a technical
failure or a fabricated empty attachment list.

For platform Binding-scope packages, copy verified supporting files into a
`supporting-evidence/` directory, with an immutable context sidecar and relative
references. Include verified expired/future material only with its explicit
temporal state; do not describe it as current evidence. A missing copy must be
marked unavailable and cannot have a dangling included-file link. Required OSCAL
back-matter references point to authorized packaged copies; they do not create
control findings or embed external live storage dependencies.

Each package owns its bytes and follows its original per-binding retention.
Source and package copies can expire independently without reference-counted
deduplication. A package contains the needed attribution even if the original
EvidenceAttachment later disappears. Capture retries use the same staged bytes
or report capture loss through the assessment contract, never a newer document.

For Namespace-scope packages, emit only sanitized contextual availability,
validity, restricted-access markers, and opaque identity. Never copy the original
document, private title/source/scope descriptions, or a usable download URL.
This limitation is explicit: the namespace package describes the permitted
projection and does not claim to contain a complete copy of restricted evidence.

Extend the existing descriptor through its owner with explicit supporting-document
and context roles and a versioned protection marker derived from actual file
roles. The verifier rejects document bytes in namespace packages and verifies
all included files' size/digest/relative references. The package download service
requires platform document-read authorization in addition to existing run access
whenever protected document roles are present. This first version uses a dedicated
cluster-wide attachment-reader grant, not per-document ACLs. The additional check
uses recorded package protection, so historical downloads do not depend on the
source record still existing. Do not silently redact an immutable platform archive
at download time; deny the request if its reader lacks the additional grant.

### 6. Use SeaweedFS for local development, with measured compatibility

Provide a disposable SeaweedFS deployment exposing its S3 gateway, with a pinned
container version/digest, isolated local credentials, bucket, data volume, and
test-owned prefix. Pin and document the version when implementing the fixture;
this proposal does not claim a tested SeaweedFS release. Use the existing Devbox
and Docker/Task conventions, and route all controller/CLI traffic through the
same S3 adapter configured for production. Do not add a filesystem-only attachment
backend for tests or ship SeaweedFS in the Konstapel production Helm chart.

Verify conditional manifest creation, immutable commit timestamps, checksum or
readback verification, concurrent/lost-response recovery, multipart cleanup when
used, and owned deletion. Exercise supported versioning modes and explicitly
mark others unsupported; local SeaweedFS success proves neither AWS behavior nor
Object Lock support. A missing required semantic blocks readiness instead of
weakening the commit protocol. Explicit isolated local HTTP is permitted only
through the S3 owner's existing development configuration; normal TLS behavior
remains unchanged.

Keep start/stop/provision/fixture details in a shared development helper used by
the integration workflow. Prefer extending the S3 owner's helper once present.
Document direct Devbox commands and integrate existing acceptance workflows;
do not add one public Task task per helper. Cleanup removes only task-owned
containers, volumes, buckets/prefixes, credentials, and temporary files. Useful
sanitized compatibility/test reports can be retained as validation evidence.

## Risks / Trade-offs

- Documents are mistaken for proof or fresh scanner results → preserve declared
  source/period and a supporting-material-only model with no verdict field.
- Readers gain document bytes through an ordinary package route → explicit file
  roles, projection validation, and additional authorization at download time.
- Long document validity conflicts with short run retention → independent source
  retention through validity plus a fixed tail, and independent package copies.
- Uploads race or a serving replica dies → bounded S3 staging, one conditional
  manifest, durable receipts, and cleanup independent of any one process.
- SeaweedFS differs from a production endpoint → test required semantics and
  publish only the compatibility claims supported by each endpoint's results.
- Shared API/transport work overlaps active agents → consume existing owners'
  contracts and land any shared extension in one coordinated PR after rebasing.

## Migration Plan

Land the API/admission and attachment storage contract first with fixtures. Wire
the actual S3 service and SeaweedFS workflow when their owner implementations are
available. Integrate the coverage projection and scoped producer separately.
Extend generated CRDs/RBAC and the aligned CRD/controller Helm charts through
their existing generation/release workflows; preserve file and contract ownership.

Deploy descriptor verification and package-download authorization support before
enabling writers that include protected documents. Unknown protected package
versions must fail closed. An older server that ignores protection markers is
not a supported downgrade while protected packages remain accessible. Document
rollback as disabling new intake/associations while retaining a compatible
download/cleanup service until commitments expire. Never delete retained source
documents or CRDs as rollback cleanup. Full acceptance requires the real S3,
coverage, assessment-producer, and access-control integrations.

## Future Development

Application-team attachment submission remains outside this change's tasks.
A later change can add namespaced records, namespace ownership and UID isolation,
RBAC, quotas, upload limits, and explicit sharing rules. Per-document ACLs,
cross-cluster inheritance, structured external findings, and human assessment
verdicts require separate designs; no current upload grants those capabilities.
