# Tasks

## Execution boundaries

Archive/protocol fixtures and isolated backend experiments can start now in the
existing Go module. Runtime integration uses the separately merged group 1
contract from `add-continuous-assessments`, not a second set of assessment APIs.
The complete scheduler is not required to implement and merge the adapter.
Full request/download acceptance requires the scheduler and scoped producer.

This change owns EvidenceDestination and its CRD/controller/admission safeguards,
S3 configuration/adapter, archive and commit logic, authenticated download
transport, retention execution, durable orphan inventories, migration, and their
tests/docs. Coordinate shared module/manager edits after rebasing. The
continuous-assessment owner owns binding fields, request/run CRDs, package
descriptors, and publication status schemas; coordinate the new destination and
orphan contracts there. The Helm owner consumes generated destination CRD, RBAC,
and admission resources and verifies chart installation/upgrade in required CI.
Planning artifact completion does not satisfy implementation prerequisites.

Checked tasks preserve the completed file-configured backend work. Groups 7–9
extend it with the agreed destination lifecycle; complete those dependencies and
the remaining recovery/documentation work before final integrated acceptance in
group 6. Do not treat earlier checks as coverage of the new API or orphan paths.

## 1. Establish backend configuration and compatibility fixtures

- [x] 1.1 Add the central S3 destination configuration and pin the Go SDK dependency; verify endpoint/bucket/region/prefix/addressing validation and that application requests cannot override destination fields.
- [x] 1.2 Support workload-identity credentials and protected controller-namespace Secret references with verified TLS/custom CA configuration; verify missing/rotated credentials and invalid trust fail visibly without leaking secrets or enabling public access.
- [x] 1.3 Create isolated real-endpoint fixtures using a recorded S3-compatible service version and unique test prefix; verify conditional creation, server timestamps, checksum/readback, and supported versioning modes before treating the backend as ready.
- [x] 1.4 Implement readiness checks against the required backend semantics through the shared publication interface; verify missing bucket/permissions or incompatible conditional-write behavior prevents ready publication rather than falling back to local storage.
- [x] 1.5 Document endpoint setup, minimum permissions, credential rotation, compatibility limits, and teardown; verify the commands use only test-owned prefixes/services and distinguish tested self-hosted behavior from untested cloud compatibility.

## 2. Validate packages and commit immutable publications

- [x] 2.1 Build deterministic archives and file inventories from the merged scoped descriptor; verify repeat packaging yields the same digest and traversal, symlinks, invalid OSCAL/references, and mismatched namespace scope are rejected.
- [x] 2.2 Implement archive upload and SHA-256 verification with checksum or readback support; verify multipart ETags are not treated as content hashes and corrupt/truncated bytes cannot produce Published status.
- [x] 2.3 Implement one fixed create-if-absent commit key per run and durable receipts with destination/key/version ownership; verify concurrent attempts with different staging prefixes publish only once and conflicting bytes, scope, or run identity cannot overwrite the winner.
- [x] 2.4 Resolve retention at first commit preparation and derive fixed publication/expiry times from the immutable commit object; verify retention edits, binding deletion/recreation, lost responses, and retry clocks preserve the documented selection boundary.
- [x] 2.5 Document assessment versus diagnostic packages and the commit protocol; verify complete/incomplete/diagnostic fixtures retain their original meaning and all required package references remain inspectable after download.

## 3. Recover interrupted operations and preserve ownership

- [x] 3.1 Wire upload/commit/failure reconciliation into the shared run status with bounded network/retry limits; verify storage failure remains separate from assessment outcomes and terminal failure releases the binding's active run slot.
- [x] 3.2 Add recovery after archive upload, commit-response loss, and Kubernetes receipt-update failure; verify recovery reconciles the original digest, publication time, expiry, and namespace scope instead of creating a second snapshot.
- [x] 3.3 Implement cancellation and orphan cleanup for owned multipart uploads and uncommitted objects; verify restart can identify its attempts and never deletes unrelated objects under a shared bucket/prefix.
- [x] 3.4 Route publication, retries, downloads, and cleanup through protected run-start destination UID/location pins and live credential/trust references; verify default/binding switches and rotation preserve historical access, UID mismatch never redirects history, and missing old credentials remain a visible retryable problem without fallback.
- [ ] 3.5 Document outage, CaptureLost, partial-upload, and destination-change recovery, including the distinction between automatic abandoned-attempt cleanup and explicit Orphan handoff; verify the fault-injection walkthrough preserves diagnostics and never resumes cleanup for intentionally orphaned evidence.

## 4. Authorize and verify full-package downloads

- [x] 4.1 Add TLS namespace-request and platform-run download routes with TokenReview and SubjectAccessReview; verify token audience, object read/download permissions, UID binding, and denial on authentication/authorization service failure.
- [x] 4.2 Resolve namespace downloads only through their request and original namespace UID; verify sibling namespaces, full-binding runs, recreated namespaces, deleted requests, guessed object keys, and forged identity headers cannot bypass authorization.
- [x] 4.3 Add current-authorization checks on each download and scoped errors/status without credentials or reusable download tokens; verify revoking RBAC prevents subsequent requests and logs/errors expose no sibling evidence or secrets.
- [x] 4.4 Fetch into bounded temporary storage, verify archive size/checksum, and serve private non-cacheable responses; verify corrupt, unavailable, expired, and uncommitted packages fail explicitly and concurrency/disk limits clean up temporary data.
- [x] 4.5 Document namespace/platform roles and the authenticated full OSCAL/evidence download workflow; verify real namespace credentials can download their complete package while the same credentials cannot retrieve a broader one.

## 5. Enforce fixed per-binding retention

- [x] 5.1 Implement expiry scheduling from immutable publication receipts for scheduled and manual packages; verify the 2160h default, shorter test durations, and retention edits affect only new publications while expired packages reject new downloads.
- [x] 5.2 Add retention finalization independent of binding/request ownership and restart recovery; verify deleting a binding, request, or namespace retains its cleanup record and original expiry until storage removal is confirmed.
- [x] 5.3 Delete owned archives, commit objects, attempt data, and applicable object versions/markers; verify enabled, suspended, and unversioned test modes remove owned retained bytes while separately retained packages and unrelated objects survive.
- [x] 5.4 Add truthful deletion/availability states and retry behavior for partial deletion, missing permissions, locks, early object loss, and corruption; verify failed cleanup preserves ownership metadata and never reports a remaining version as deleted.
- [x] 5.5 Document retention selection separately from run-start destination pinning, credential/CA rotation, normal and blocked destination retirement, external lifecycle interference, and recovery; verify short-duration tests demonstrate expiry and finalization without waiting 90 days.

## 6. Verify publication, access, and retention together

- [ ] 6.1 With continuous assessments integrated, run full-binding and namespace-scoped scheduled/manual cases against the real test backend using default and binding-specific destinations; verify complete/incomplete/diagnostic publications, full authorized downloads, immutable expiry, rotation, and run-start pinning through the actual run APIs.
- [ ] 6.2 Exercise lost responses, controller restart, RBAC revocation, binding/request deletion, retention edits, destination switches/retirement/orphaning, and cleanup failure end to end; verify recovery never changes historical bytes, leaks scope, changes enforcement/exception identity, or loses outstanding ownership records.
- [ ] 6.3 Retain the final backend/version matrix and CI acceptance evidence, run the preserved local prototype validation, and tear down task-owned endpoints/objects/temporary data; explicitly clean intentional orphan fixtures through the documented operator path and preserve sanitized inventory evidence while leaving unrelated infrastructure untouched.

## 7. Introduce the destination API and run-start selection

- [x] 7.1 Add the cluster-scoped compliance.erenius.io/v1alpha1 EvidenceDestination type, generated schema, status, and Retire default; verify API-server rejection of endpoint/bucket/region/prefix mutations and acceptance of valid credential/CA rotation during normal operation and retirement.
- [x] 7.2 Add platform-only destination management and protected status/credential/trust access; verify application identities cannot change destinations or read credential material and references outside the controller namespace are rejected.
- [x] 7.3 Coordinate name/UID references for one central default and an optional spec.assessment.destinationRef with the shared-contract owner; verify AssessmentRequests inherit selection, recreated names fail UID checks, invalid overrides never fall back, and selection conditions remain separate from enforcement health.
- [x] 7.4 Implement durable pin admission before run storage writes and the destination finalizer before pin acceptance; verify deletion races, stale caches, concurrent replicas, and interrupted run updates cannot lose an accepted obligation or admit work after retirement.

## 8. Retire destinations and support audited orphan handoff

- [x] 8.1 Reconcile normal destination retirement with existing pinned publications, authorized downloads, and cleanup; verify outstanding runs/uploads/packages hold the finalizer, blockers remain retryable, and status includes counts, latest known expiry, and unfinished work with unknown expiry.
- [x] 8.2 Implement authenticated Orphan intent with required reason and protected actor/time, including escalation from blocked Retire; verify caller-forged identities are rejected, selecting a policy alone does not delete storage, and started orphan handoff cannot be reversed.
- [x] 8.3 Fence publication, recovery, downloads, probes, and both destination/run cleanup workers during orphan handoff; verify bounded cancellation/draining, restart, late responses, and uncertain remote outcomes do not resume operations, abort uploads, or claim remote rollback/deletion.
- [x] 8.4 Persist an independent protected, chunked orphan inventory with audit identity, original receipts, known attempts/versions/upload IDs, and uncertain outcomes; verify idempotence, object-size limits, backend outages, and inventory persistence failures preserve the fence and finalizers without exposing credentials.
- [x] 8.5 Coordinate Orphaned disposition and finalizer release with the shared run/publication contract; verify records already pending deletion export ownership first, surviving records retain original references/checksums/expiry, prior Deleted records remain truthful, and interrupted publication ends and releases its binding slot without falsely claiming success.
- [x] 8.6 Exclude orphaned ownership from every automatic recovery/cleanup path, including a replacement destination at the same bucket/prefix; verify expiry, same-name recreation, and restart cannot adopt evidence or garbage-collect the independent inventory.
- [ ] 8.7 Document normal deletion, Orphan selection/escalation commands with a reason, inventory export, external recovery/cleanup, and last-resort finalizer stripping; verify the walkthrough explains unreachable storage, uncertain operations, retained versions/uploads, disabled managed downloads, and operator ownership of future retention.

## 9. Migrate legacy configuration and verify the lifecycle in CI

- [ ] 9.1 Document and implement upgrade ordering, legacy-writer quiescence, file-to-resource conversion, and explicit verified legacy-ID/location-to-UID mappings; verify migration retries preserve immutable archive/commit bytes, keys, versions, checksums, publication time, and expiry while ambiguous records remain blocked with ownership intact.
- [ ] 9.2 Add Go tests against a real Kubernetes API server for destination validation/RBAC, selection, retirement, and durable orphan audit; cover concurrency and restarts, already-deleting runs, forged actor metadata, missing inventory permissions, and prevention of enforcement/exception changes.
- [ ] 9.3 Wire Go lifecycle acceptance into the existing required CI workflows with a real S3-compatible service; verify live rotation, destination switches, versioned retirement, backend-unreachable orphaning, pending/uncertain operations, and upgrade of retained legacy evidence, with sanitized diagnostics and explicit test-owned cleanup on success or failure.
- [ ] 9.4 Coordinate generated destination CRD/RBAC/admission resources and migration prerequisites with the Helm owner; verify its separate, version-aligned charts install/upgrade them and its required CI covers those resources without duplicating assessment schema or chart ownership in this change.
