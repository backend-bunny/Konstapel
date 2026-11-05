# Tasks

## Execution boundaries

Archive/protocol fixtures and isolated backend experiments can start now in the
existing Go module. Runtime integration uses the separately merged group 1
contract from `add-continuous-assessments`, not a second set of assessment APIs.
The complete scheduler is not required to implement and merge the adapter.
Full request/download acceptance requires the scheduler and scoped producer.

This change owns S3 configuration/adapter, archive and commit logic, authenticated
download transport, retention execution, and their tests/docs. Coordinate shared
module/manager edits after rebasing. The continuous-assessment agent owns binding
fields, request/run CRDs, package descriptors, and publication status schemas.
Planning artifact completion does not satisfy implementation prerequisites.

## 1. Establish backend configuration and compatibility fixtures

- [ ] 1.1 Add the central S3 destination configuration and pin the Go SDK dependency; verify endpoint/bucket/region/prefix/addressing validation and that application requests cannot override destination fields.
- [ ] 1.2 Support workload-identity credentials and protected controller-namespace Secret references with verified TLS/custom CA configuration; verify missing/rotated credentials and invalid trust fail visibly without leaking secrets or enabling public access.
- [ ] 1.3 Create isolated real-endpoint fixtures using a recorded S3-compatible service version and unique test prefix; verify conditional creation, server timestamps, checksum/readback, and supported versioning modes before treating the backend as ready.
- [ ] 1.4 Implement readiness checks against the required backend semantics through the shared publication interface; verify missing bucket/permissions or incompatible conditional-write behavior prevents ready publication rather than falling back to local storage.
- [ ] 1.5 Document endpoint setup, minimum permissions, credential rotation, compatibility limits, and teardown; verify the commands use only test-owned prefixes/services and distinguish tested self-hosted behavior from untested cloud compatibility.

## 2. Validate packages and commit immutable publications

- [ ] 2.1 Build deterministic archives and file inventories from the merged scoped descriptor; verify repeat packaging yields the same digest and traversal, symlinks, invalid OSCAL/references, and mismatched namespace scope are rejected.
- [ ] 2.2 Implement archive upload and SHA-256 verification with checksum or readback support; verify multipart ETags are not treated as content hashes and corrupt/truncated bytes cannot produce Published status.
- [ ] 2.3 Implement one fixed create-if-absent commit key per run and durable receipts with destination/key/version ownership; verify concurrent attempts with different staging prefixes publish only once and conflicting bytes, scope, or run identity cannot overwrite the winner.
- [ ] 2.4 Resolve retention at first commit preparation and derive fixed publication/expiry times from the immutable commit object; verify retention edits, binding deletion/recreation, lost responses, and retry clocks preserve the documented selection boundary.
- [ ] 2.5 Document assessment versus diagnostic packages and the commit protocol; verify complete/incomplete/diagnostic fixtures retain their original meaning and all required package references remain inspectable after download.

## 3. Recover interrupted operations and preserve ownership

- [ ] 3.1 Wire upload/commit/failure reconciliation into the shared run status with bounded network/retry limits; verify storage failure remains separate from assessment outcomes and terminal failure releases the binding's active run slot.
- [ ] 3.2 Add recovery after archive upload, commit-response loss, and Kubernetes receipt-update failure; verify recovery reconciles the original digest, publication time, expiry, and namespace scope instead of creating a second snapshot.
- [ ] 3.3 Implement cancellation and orphan cleanup for owned multipart uploads and uncommitted objects; verify restart can identify its attempts and never deletes unrelated objects under a shared bucket/prefix.
- [ ] 3.4 Preserve historical destination snapshots and credential references across default endpoint changes; verify old artifacts can still be read/retired and missing old credentials remain a visible retryable problem.
- [ ] 3.5 Document outage, CaptureLost, partial-upload, and destination-change recovery; verify the fault-injection walkthrough retains useful diagnostics while cleaning its task-owned storage attempts.

## 4. Authorize and verify full-package downloads

- [ ] 4.1 Add TLS namespace-request and platform-run download routes with TokenReview and SubjectAccessReview; verify token audience, object read/download permissions, UID binding, and denial on authentication/authorization service failure.
- [ ] 4.2 Resolve namespace downloads only through their request and original namespace UID; verify sibling namespaces, full-binding runs, recreated namespaces, deleted requests, guessed object keys, and forged identity headers cannot bypass authorization.
- [ ] 4.3 Add current-authorization checks on each download and scoped errors/status without credentials or reusable download tokens; verify revoking RBAC prevents subsequent requests and logs/errors expose no sibling evidence or secrets.
- [ ] 4.4 Fetch into bounded temporary storage, verify archive size/checksum, and serve private non-cacheable responses; verify corrupt, unavailable, expired, and uncommitted packages fail explicitly and concurrency/disk limits clean up temporary data.
- [ ] 4.5 Document namespace/platform roles and the authenticated full OSCAL/evidence download workflow; verify real namespace credentials can download their complete package while the same credentials cannot retrieve a broader one.

## 5. Enforce fixed per-binding retention

- [ ] 5.1 Implement expiry scheduling from immutable publication receipts for scheduled and manual packages; verify the 2160h default, shorter test durations, and retention edits affect only new publications while expired packages reject new downloads.
- [ ] 5.2 Add retention finalization independent of binding/request ownership and restart recovery; verify deleting a binding, request, or namespace retains its cleanup record and original expiry until storage removal is confirmed.
- [ ] 5.3 Delete owned archives, commit objects, attempt data, and applicable object versions/markers; verify enabled, suspended, and unversioned test modes remove owned retained bytes while separately retained packages and unrelated objects survive.
- [ ] 5.4 Add truthful deletion/availability states and retry behavior for partial deletion, missing permissions, locks, early object loss, and corruption; verify failed cleanup preserves ownership metadata and never reports a remaining version as deleted.
- [ ] 5.5 Document retention selection, new-publication-only edits, endpoint/credential retirement, external lifecycle interference, and recovery; verify short-duration tests demonstrate the full expiry lifecycle without waiting 90 days.

## 6. Verify publication, access, and retention together

- [ ] 6.1 With continuous assessments integrated, run full-binding and namespace-scoped scheduled/manual cases against the real test backend; verify complete/incomplete/diagnostic publications, full authorized downloads, and immutable expiry through the actual run APIs.
- [ ] 6.2 Exercise lost responses, controller restart, RBAC revocation, binding/request deletion, retention edits, and cleanup failure end to end; verify recovery never changes historical bytes, leaks scope, or loses outstanding deletion work.
- [ ] 6.3 Retain the final backend/version matrix and acceptance evidence, run the preserved local prototype validation, and tear down task-owned endpoints/objects/temporary data; verify cleanup leaves unrelated storage and infrastructure untouched.
