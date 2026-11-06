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
Manage destination selection, retirement, and explicit orphan handoff without
losing historical ownership or affecting policy enforcement.

**Non-Goals:** Bucket provisioning, public access, alternate storage backends,
cross-package content deduplication, archive search, overriding legal holds,
moving existing packages, or automatically re-adopting orphaned evidence.
Konstapel manages its own retention without taking ownership of unrelated bucket
contents or the bucket's global lifecycle configuration.

## Decisions

### 1. Manage destinations through a cluster-scoped API and a narrow S3 adapter

Introduce the platform-managed `EvidenceDestination` CRD in
`compliance.erenius.io/v1alpha1`. Its S3 configuration contains endpoint, bucket,
region, prefix, addressing style, credential source, and trust references. Endpoint,
bucket, region, and prefix are immutable through API validation, including during
retirement. A new storage location requires a new resource and an explicit
reference switch; no edit moves existing evidence. Credentials and CA trust may
rotate while retaining the same location and UID. Use AWS SDK for Go v2 behind
the existing publication interface and retain the established backend fixtures.

Support workload identity and Secret references confined to the controller
namespace. Resolve trust references there as well; do not allow arbitrary
cross-namespace reads or application-supplied file paths. TLS verification is
required outside isolated development fixtures. Only platform administrators
manage destinations, credential/trust references, and the central default;
application roles cannot read credential material or alter destination status.

Keep one default destination reference in platform controller configuration,
with an optional `spec.assessment.destinationRef` override on ComplianceBinding.
Use name and UID in these references; reject UID mismatch rather than resolving
a replacement with the same name. An omitted binding override inherits the
default. AssessmentRequest has no storage selector and always inherits its
binding. Missing, unready, retiring, or mismatched selections produce a visible
evidence condition, with no fallback to another destination. Unaffected bindings
continue normally. Destination edits do not revise policies, recreate exceptions,
or change enforcement; keep evidence readiness separate from enforcement health.

Resolve and durably pin the selected destination when an AssessmentRun starts,
before its first storage write. Protected run metadata records name, UID, location
snapshot, and the configuration revision used for selection, but no credentials.
Use that pin for staging, publication, retries, downloads, and cleanup, including
after a controller restart. Credential/trust references are resolved through the
pinned UID so rotation works for historical packages. Later binding/default edits
affect subsequent runs only. Retention has a separate boundary: it is still chosen
at first commit preparation, as described in decision 3.

Establish destination protection before accepting pins. Selection and retirement
need a tested concurrency protocol: a pin accepted before retirement is durable
and counted even if the run status update is interrupted; a selection losing the
race cannot write to storage. Stale caches and concurrent controller replicas
must not admit new work after retirement or release the destination while an
accepted pin remains unrecorded. Do not rely on an eventually consistent count
alone as proof that finalization is safe.

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

Maintain explicit uploading, committed, failed, expired, deleting, deleted, and
orphaned dispositions separately from assessment completeness. Bound each network
request and the overall publication attempt with documented deployment limits.
Ordinary cancellation aborts owned multipart uploads where possible and retries
cleanup; cancellation during explicit orphan handoff must leave them untouched.
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
its run records and known attempts before abandoned-attempt cleanup. This automatic
recovery excludes destinations undergoing explicit orphan handoff and evidence
already marked Orphaned. Never sweep an arbitrary user-supplied prefix or delete
an object whose ownership cannot be established.

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
Reject expired, deleted, missing, corrupt, uncommitted, or Orphaned packages
explicitly; do not leak storage credentials or tokens in status/logs/errors. Revocation stops
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
the record remains until cleanup completes or the audited orphan handoff in
decision 8 is durable. Request or namespace deletion does not make artifacts
available to a newly created namespace with the same name.
After confirmed cleanup, remove bulky run details and permit record finalization;
keep a bounded operational tombstone where needed for request/latest-run status.

Delete only the owned package objects, commit manifest, and known attempt data.
For versioned buckets, a delete marker does not erase retained bytes: delete the
owned versions explicitly, inspect remaining owned versions, and clean up markers
created by Konstapel. Verify supported enabled/suspended/unversioned modes during
compatibility tests. Keep ownership metadata until storage deletion is confirmed
or ownership is explicitly handed off under decision 8; orphaning never counts
as confirmed storage deletion.
Partial failures retain retry state. Object locks or missing permissions produce
DeletionFailed/RetentionBlocked; do not request bypass permissions automatically.

Changing the default destination or deleting a binding cannot erase the cleanup
record. External bucket lifecycle rules must not delete active evidence before
Konstapel's recorded expiry; early absence is Unavailable, not successful managed
retention. Konstapel does not rewrite those global rules. It controls deletion
within its own namespace while reporting interference or backend limitations.

### 7. Retire destinations until their obligations finish

Use `spec.deletionPolicy: Retire` by default, with `Orphan` as the explicit
administrative alternative. Setting the policy alone does not delete a destination;
its deletion timestamp starts the chosen lifecycle. A terminating destination
stops accepting new runs. Under Retire, previously accepted pins may complete
publication, existing authorized downloads continue until expiry, and retention
and abandoned-attempt cleanup continue using the original UID and location.

A destination finalizer holds the resource while any accepted run, incomplete
upload, retained package, or pending cleanup needs it. Keep credentials and trust
rotatable while terminating. Reconcile independently of bindings and requests;
do not give runs garbage-collection ownership by the destination. Release the
finalizer only after outstanding obligations have been verified complete, or
after the explicit orphan handoff below. Backend outages and locks block normal
retirement visibly and remain retryable; elapsed time alone is not completion.

Expose observed generation, readiness/retirement conditions, outstanding run and
package counts, the latest known retained expiry, and cleanup blockers. Describe
unknown expiry for unfinished publications separately; it is not zero outstanding
work. Bindings whose selected destination is terminating report
`DestinationRetiring` for evidence work and do not silently inherit another
default. Policy enforcement and exception identity remain unchanged.

### 8. Make orphaning an explicit, durable administrative handoff

Platform administrators may choose Orphan before deletion or escalate a blocked
retirement to Orphan. Require a non-empty reason and capture the authenticated
actor and time through a trusted admission/administrative path. Do not infer the
actor from writable annotations, managedFields, or the controller service account.
Protect the accepted intent from later edits. Once orphan handoff starts, it is
irreversible; changing the policy cannot reactivate work or reclaim ownership.

First persist that intent and fence all destination work: new selections,
publication/recovery retries, downloads, retention, abandoned-attempt cleanup,
and backend probes. Both destination and run reconcilers, plus the download
service, must honor the fence across replicas and restarts. Stop issuing remote
operations, cancel and drain local in-flight operations with bounded waits, and
do not issue abort/delete requests as part of orphaning. Already-dispatched S3
requests can finish later or have unknown results; record these uncertainties
and known attempted keys/versions/upload IDs. Never claim that cancellation
reversed a remote write or deletion, or that retained bytes were removed.

Persist an independently durable, protected orphan inventory in the controller
namespace before releasing either destination or run retention finalizers. Use
records chunked within Kubernetes object limits, without owner references to
destinations, bindings, requests, namespaces of applications, or runs. This
inventory survives destination deletion and runs already pending deletion; an
Event, a soon-deleted status field, or a required write to the affected S3 backend
is insufficient. Retain the inventory until an explicit platform-administrator
removal after external handoff; do not garbage-collect it with package expiry.

The inventory contains an idempotent handoff identity, actor/time/reason,
destination UID and location snapshot, affected run and scope UIDs, original
publication references/checksums/expiry when present, owned attempt prefixes and
known object versions/upload IDs, and outstanding or uncertain operations. Mark
it incomplete if the remote state cannot be established. Include no credential
material or application evidence bytes. If persisting this recovery record fails,
keep the finalizers and the work fence; retry the handoff without restarting S3
work. Complete the inventory and mark surviving run records before finalization.

Mark affected records `Orphaned`, preserve their original receipt and expiry, and
make managed downloads unavailable. Preserve completed assessment results and
truthful prior publication state; an interrupted run must not become Published
just because it was orphaned. End interrupted publication and release its binding
active slot after the durable handoff. Already verified Deleted evidence stays Deleted.
Remaining objects, versions, and incomplete uploads become the operator's
responsibility even when storage is unreachable. The old expiry is historical
metadata, not a promise of future Konstapel deletion. Late storage responses may
add recovery information but cannot clear Orphaned or resume managed cleanup.

Recreating the same destination name, or pointing another destination at the
same bucket/prefix, does not adopt orphaned evidence. All sweep/recovery paths
must exclude that ownership inventory. Document export and external inspection
and cleanup using the inventory, including versioned and incomplete uploads and
uncertain remote outcomes. Manual finalizer stripping remains last-resort
recovery; it bypasses this handoff and cannot be described as successful cleanup.

### 9. Land the backend against a merged shared contract

The continuous-assessment change owns all assessment CRDs, binding settings,
package descriptors, and run/publication status fields. It lands that contract
first. This change owns EvidenceDestination and its generated CRD, validation,
RBAC/admission safeguards, controller, destination routing, S3 adapter, package
archive/commit logic, authenticated download transport, retention reconciliation,
orphan inventories, migration, and related tests/docs. Coordinate binding
destination references and protected run/publication/orphan status extensions
through the continuous-assessment owner after rebasing, not competing generators.
The Helm change consumes generated destination CRD/RBAC/admission resources in
its separate CRD and controller charts and covers installation/upgrade in its
required CI workflow; chart ownership and release alignment remain there.

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
- **Retirement races with selection:** test durable pin admission and finalization
  across stale caches, multiple replicas, and restarts, including interrupted updates.
- **Orphaning loses the last cleanup record:** persist an independent inventory
  before either finalizer releases, even when the run is already terminating.
- **In-flight S3 operations outlive orphan handoff:** retain uncertainty and
  attempted ownership in the inventory; do not claim remote rollback or deletion.

## Migration Plan

Deploy the destination CRD, admission/authorization safeguards, and shared
assessment contract before enabling CRD-based selection. Replace the legacy
`--evidence-destination=<file>` deployment path with an explicit default resource
reference; do not maintain two competing sources of default selection. Document
the field conversion, credential/trust references, immutable-location constraints,
and required upgrade ordering for controller and CRD charts.

Before switching, quiesce legacy writers and inventory retained receipts and
in-flight attempts. Create resources matching each verified historical location.
An administrator explicitly maps legacy destination IDs and protected snapshots
to the new resource UIDs, corroborating missing fields against preserved
configuration. Refuse ambiguous, missing, or conflicting location information;
never match on name alone or use the current default to fill historical gaps.
Persist the verified association in protected migration metadata and resume
attempts only against that association. Preserve existing archives, commit
manifests, keys, versions, checksums, publication time, and expiry byte-for-byte;
do not rewrite committed bytes to introduce a UID. Unresolved legacy records
remain visibly blocked with their ownership and finalizers intact, pending
explicit recovery or audited orphan handoff. Make mapping retries idempotent.

Use a dedicated test prefix and two namespace roles to prove publication,
recovery, downloads, short-duration cleanup, upgrade with existing evidence,
and retirement/orphaning. Preserve the local prototype export path. Enable normal
scheduling only when the selected destinations and request/download roles are ready.

Rollback by stopping new publications and downloads while keeping a compatible
cleanup worker and retained run records. Do not downgrade to a worker that ignores
destination UIDs or Orphaned fences. Do not delete CRDs, historical configuration,
inventories, or required credentials before managed evidence is retired or an
audited orphan handoff is durable. Package relocation is a separate future change.
Document normal retirement, blocked retirement, Orphan commands with a reason,
inventory export, operator responsibilities, and last-resort finalizer recovery.
Teardown removes only task-owned objects, test endpoints, and temporary files;
preserve compatibility and handoff results for review.

## References

- [Continuous-assessment contract](../add-continuous-assessments/design.md)
- [Existing evidence package guide](../../../docs/integration/assessment-loop.md)
