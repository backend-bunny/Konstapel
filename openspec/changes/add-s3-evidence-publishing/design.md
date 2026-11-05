# Design

## Context

See [proposal.md](proposal.md) and the
[capability spec](specs/assessment-evidence/spec.md). The prototype currently
exports a validated local directory containing OSCAL, content, captures, and
provenance. The continuous-assessment change adds scoped packages and durable
run records. This change provides their first durable backend and download path.

Both cloud S3 and compatible self-hosted endpoints are intended targets, but
compatibility is verified behavior rather than a claim about every S3-like
service. Existing local prototype commands remain available.

## Goals / Non-Goals

**Goals:** Commit complete packages once, recover after interrupted operations,
authorize every download, and enforce immutable publication-time retention.

**Non-Goals:** Bucket provisioning, public access, alternate storage backends,
cross-package content deduplication, archive search, or overriding legal holds.
Konstapel manages its own retention without taking ownership of unrelated bucket
contents or the bucket's global lifecycle configuration.

## Decisions

### 1. Use central destination configuration and a narrow S3 adapter

Configure an endpoint, bucket, region, prefix, addressing style, and credential
source through platform-controlled deployment configuration. Use AWS SDK for Go
v2 behind the publication interface; pin its module versions at implementation.
Support the standard workload-identity credential chain and an explicit Secret
reference in the controller namespace for compatible services. TLS verification
is required outside explicitly isolated development fixtures; custom CA bundles
are supported. Application requests contain no destination or credential fields.

Record a stable destination identifier and its endpoint/bucket/prefix snapshot
with each publication; store only a protected credential reference. New default
destinations affect new publications, while old destinations remain addressable
for read/cleanup. Credential rotation is supported; removing an old credential
before cleanup produces a visible recoverable failure, not relocation of history.

Verify bucket access and the semantics required below before reporting backend
readiness. Document least-privilege operations for object upload/read, conditional
creation, version inspection/deletion, and multipart cleanup under the owned prefix.
Do not auto-create buckets or silently fall back to a local persistent volume.

### 2. Store a self-contained archive and a small commit manifest

Package the producer's validated directory as a deterministic archive with an
internal file inventory and SHA-256 digests. Reject path traversal, absolute paths,
symlinks, external local-file references, and unsafe scope. Reuse the established
OSCAL schema/reference checks for assessment packages. Diagnostic packages declare
their kind and missing export, with only the diagnostic files required by that
kind. No package relies on another package's lifetime or on a live exception object.

Use an opaque UID-based run prefix containing cluster identity, binding UID, and
run UID. Give that run one fixed commit-manifest key; retry attempts must not
choose independent commit keys. Store archives under attempt-specific child
prefixes, with the committed manifest selecting exactly one archive. Avoid
workload names or reasons in object keys.
Every file copy belongs to this package; this deliberately avoids reference-counted
cleanup across differently retained snapshots. Source and projected evidence stay
distinguishable, with required safe traceability inside the archive.

The producer owns evidence projection. The publisher independently validates the
descriptor, manifest, allowed file kinds, scope identities, and reference closure.
It never turns a cluster-wide package into a namespace package by changing labels.
Unstructured data that cannot be safely attributed must already be excluded and
reported unresolved; namespace publication fails if that boundary cannot be verified.

### 3. Make the commit manifest the publication boundary

Upload and verify the complete archive first. Use explicit SHA-256 validation;
ETag is not a portable content hash, especially with multipart upload. Verify the
server checksum when supported or read/hash the object when necessary. Persist
owned key/version/upload identifiers in the run record as they become known.

Then conditionally create the commit manifest with create-if-absent semantics.
It identifies run/scope, package kind, archive key and version, SHA-256, byte size,
effective retention, and the binding configuration revision used to select that
retention. Its successful creation is the publication commit. The manifest's
immutable server LastModified time is publishedAt; expiresAt is that time plus
the recorded duration. Recovery reads the same manifest/version and derives the
same dates rather than using the retry's clock. The backend compatibility suite
must verify these time and conditional-write semantics.

Choose effective retention from a consistent read of the binding when preparing
the first commit, after archive verification. Persist that commit intent so an
uncertain-response retry sends identical bytes. A binding edit concurrent with an
already prepared commit applies to subsequent publication intents. Record the
selection revision/time so this boundary is explicit. If the binding was deleted
after collection, use its last resolved retention recorded on the run; never
resolve a replacement binding with the same name.

An existing matching manifest is success on retry. Recover it before preparing
another publication intent. A mismatching archive or manifest is a conflict, not
permission to overwrite. Concurrent losing attempts cannot publish elsewhere;
clean up only their uncommitted archive data after checking the fixed commit
reference. Set Published only after
verifying the commit and archive and persisting the receipt in run status. This
recovers a lost response or restart between the S3 commit and Kubernetes update.
Storage and Kubernetes are not one transaction; the commit manifest supplies the
durable reconciliation point. Bucket listing order is not a publication signal.

### 4. Keep failures recoverable without inventing snapshots

Maintain explicit uploading, committed, failed, expired, deleting, and deleted
states separately from assessment completeness. Bound each network request and
the overall publication attempt with documented deployment limits. Cancellation
aborts owned multipart uploads where possible; reconciliation retries cleanup.
Preserve frozen package identity on every retry. If local capture bytes are lost
before durable staging, report CaptureLost through the producer contract rather
than recollecting newer evidence under the old identity.

Incomplete assessments are normal publishable packages. Invalid OSCAL can only
be represented by a clearly typed diagnostic package. An unreachable backend
leaves a visible failed/pending publication; it cannot satisfy the promise of
successful durable output. Bounded failure releases the binding's active slot.

Use a dedicated owned staging area for multipart/partial attempts and record its
run/attempt identity before upload. Reconcile abandoned uploads and uncommitted
objects without treating them as published evidence. A controller restart scans
its run records and known attempts before orphan cleanup. Never sweep an arbitrary
user-supplied prefix or delete an object whose ownership cannot be established.

### 5. Serve downloads through current Kubernetes RBAC

Provide a small TLS download service with two routes: a namespace request route
addressed by namespace/name/UID, and a platform run route addressed by run UID.
Authenticate Kubernetes bearer tokens with TokenReview, including the configured
audience, and authorize each request with SubjectAccessReview. Use dedicated RBAC
attributes `get` on `assessmentrequests/download` in the namespace and
`assessmentruns/download` at cluster scope, together with read permission on the
corresponding object. These are service authorization attributes; the endpoint
does not claim that a CRD automatically implements a downloadable API subresource.

Resolve the object, verify its UID and original namespace UID, and authorize the
resolved scope before accessing storage. Namespace routes can only resolve that
request's namespace-scoped package. A platform run remains platform-scoped even
when it happened to target a single namespace. Recheck current RBAC for each new
download; fail closed on authentication/authorization errors. Restrict TokenReview
and SubjectAccessReview permissions to this service account. Do not trust forwarded
user headers or accept arbitrary S3 URLs, keys, endpoints, or run IDs as authority.

Fetch into bounded temporary storage, validate size and archive checksum before
serving, then stream the verified archive to the authorized caller. Send private,
non-cacheable responses, an integrity digest, and recorded publication/expiry
metadata. Apply deployment limits to concurrent downloads and staging disk usage.
Reject expired, deleted, missing, corrupt, or uncommitted packages explicitly;
do not leak storage credentials or tokens in status/logs/errors. Revocation stops
new download requests; it cannot revoke bytes a caller has already received.

Proxying verified bytes costs service bandwidth, but keeps authorization current
and avoids long-lived bearer URLs in Kubernetes status. A future signed-URL path
would need its own expiry/revocation contract; it is not necessary for this version.

### 6. Freeze retention and reconcile deletion independently of bindings

Use the continuous-assessment field `spec.assessment.retention`, default 2160h.
Published packages keep their fixed expiry even if retention is shortened or
lengthened later. Both scheduled and namespaced on-demand publications follow
the binding's setting; request creators cannot override it. Expiry prevents new
downloads immediately when observed by the service, while storage cleanup is
asynchronous and explicitly reported.

Keep publication metadata in protected cluster-scoped AssessmentRun records with
a retention finalizer, without a binding/request garbage-collection owner
reference. A delete request before expiry stops neither retention nor cleanup;
the record remains until cleanup completes. Request or namespace deletion does
not make artifacts available to a newly created namespace with the same name.
After confirmed cleanup, remove bulky run details and permit record finalization;
keep a bounded operational tombstone where needed for request/latest-run status.

Delete only the owned package objects, commit manifest, and known attempt data.
For versioned buckets, a delete marker does not erase retained bytes: delete the
owned versions explicitly, inspect remaining owned versions, and clean up markers
created by Konstapel. Verify supported enabled/suspended/unversioned modes during
compatibility tests. Keep ownership metadata until storage deletion is confirmed.
Partial failures retain retry state. Object locks or missing permissions produce
DeletionFailed/RetentionBlocked; do not request bypass permissions automatically.

Changing the default endpoint or deleting a binding cannot erase the cleanup
record. External bucket lifecycle rules must not delete active evidence before
Konstapel's recorded expiry; early absence is Unavailable, not successful managed
retention. Konstapel does not rewrite those global rules. It controls deletion
within its own namespace while reporting interference or backend limitations.

### 7. Land the backend against a merged shared contract

The continuous-assessment change owns all assessment CRDs, binding settings,
package descriptors, and run/publication status fields. It lands that contract
first. This change owns the S3 adapter, package archive/commit logic, authenticated
download transport, retention reconciliation, backend configuration, and related
tests/docs. API changes discovered here are coordinated through that owner after
rebasing, not produced by competing schema generators.

Start archive/protocol fixtures and real-endpoint experiments independently using
the documented descriptor. Once the shared contract merges, wire publication and
retention into its run records; this does not require the full scheduler to be
finished. Final acceptance joins both implementations with namespace requests and
exception-enriched evidence. Tests must include a real S3-compatible service with
recorded image/version/configuration; mocks alone cannot prove storage semantics.
Cloud-specific compatibility is claimed only when tested separately.

## Risks / Trade-offs

- **S3 implementations vary:** gate readiness on required semantics and retain
  endpoint-specific compatibility evidence, including conditional creation/time.
- **Kubernetes/S3 commits can diverge:** recover from the immutable commit manifest
  and stable run identity, with uncertain responses covered by fault injection.
- **Retention metadata is lost through parent deletion:** retain independent
  run records/finalizers and test deletion of bindings, requests, and namespaces.
- **Versioning hides retained bytes:** verify and remove owned versions, preserve
  cleanup state, and expose lock/permission failures instead of claiming removal.
- **Downloads disclose another scope:** require current RBAC, UID-bound routing,
  package validation, and mixed-scope tests at producer and publisher boundaries.
- **Proxy downloads consume disk/bandwidth:** use bounded staging/concurrency and
  explicit errors; do not weaken integrity or authorization to avoid those bounds.

## Migration Plan

Deploy central destination configuration and backend readiness checks after the
shared API contract. Use a dedicated test prefix and two namespace roles to prove
publication, recovery, downloads, and short-duration cleanup. Preserve the local
prototype export path. Enable normal assessment scheduling only once the backend
is ready and request/download roles are installed.

Rollback by stopping new publications and downloads while keeping the cleanup
worker and retained run records. Do not delete the CRDs, old destination settings,
or required credentials before owned evidence is retired or deliberately migrated
through a separately authorized process. Teardown removes only task-owned objects,
test endpoints, and temporary files; preserve compatibility results for review.

## References

- [Continuous-assessment contract](../add-continuous-assessments/design.md)
- [Existing evidence package guide](../../../docs/integration/assessment-loop.md)
