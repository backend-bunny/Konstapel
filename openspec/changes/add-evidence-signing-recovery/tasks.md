# Tasks

## Execution boundaries

This change is an owner-approved follow-up (2026-11-18) to
`add-evidence-signing`. It is not a 0.3.0 requirement or release blocker.
It reuses the existing signing intent, `signingRequirement`, the publisher's
commit gate, the destination fence, the download server, and the existing
manager. Do not add a controller Deployment, image, Helm value, Secret
permission, or Taskfile task.

- Group 1 can start at once.
- Group 2 needs the group 1 API types.
- Group 3 needs group 2's status vocabulary.
- Group 5 needs groups 1 and 2 merged into the charts.
- Rebase before editing the shared publication records, generated RBAC, or
  the acceptance-group inventory. `add-controller-high-availability` is
  archived; its manager registration and recovery fixtures are now on `main`.

## 1. Request API, admission, and RBAC

- [x] 1.1 Add the cluster-scoped `EvidenceSigningRequest` types (immutable `spec.run` name/UID, required bounded `reason`, optional `expectedKeyFingerprint`, admission-recorded `requestedBy`, controller-owned status with the fixed phase/reason vocabulary) and the additive `AssessmentRun.status.signingRecovery`; verify the generated CRD rejects malformed references, empty or whitespace reasons, spec edits, terminal-status rewrites, and changes to a set `recovered` record, and that runs without recovery keep their exact status bytes.
  <!-- agent: tier=deep risk=high reason="Authorization, audit attribution, and protected recovery status" -->
- [x] 1.2 Add the requester MutatingAdmissionPolicy and ValidatingAdmissionPolicy (with bindings) following `evidence-attachment-registrant`, and the status-writer ValidatingAdmissionPolicy that reads the controller identity from the existing `konstapel-assessment-admission` ConfigMap; verify forged and missing attribution, non-controller status writes, and a missing or empty ConfigMap all fail closed.
  <!-- agent: tier=deep risk=high reason="Authorization, audit attribution, and protected recovery status" -->
- [x] 1.3 Add the non-aggregated `konstapel-evidence-signing-recoverer` and `konstapel-evidence-signing-recovery-reader` ClusterRoles and the controller role additions; verify with RBAC probes that namespace roles, `konstapel-compliance-admin` alone, and the reader cannot create requests, and that the recoverer cannot update, patch, or delete requests, write any status, read Secrets, or change destinations.
  <!-- agent: tier=deep risk=high reason="Authorization, audit attribution, and protected recovery status" -->
- [x] 1.4 Generate the CRD, roles, and admission policies into the existing CRD and runtime charts through the existing generation workflow; verify chart rendering, CRD chart lifecycle, and generated-file freshness checks, with no new Helm value.
  <!-- agent: tier=standard risk=medium reason="Generated chart wiring against established conventions" -->

## 2. Recovery controller and publication record

- [x] 2.1 Add the optional `retention.notAfter` to the signed commit and the receipt/status validation in the shared publication contract, the S3 publisher, and the fake; verify strict decoding, `expiresAt = notAfter`, rejection of `notAfter` after `publishedAt + duration`, a commit landing at or after `notAfter` reported Expired and deleted by retention, current-release readers failing closed on the new field, and adoption of a matching lost-response commit with its original time and later expiry unchanged.
  <!-- agent: tier=deep risk=high reason="Immutable publication records and retention integrity" -->
- [x] 2.2 Implement eligibility from an uncached run read and every terminal outcome (`RunNotFound`, `RunDeleting`, `NotRecoverable`, `Expired`, `Orphaned`, `EvidenceLost`, `Conflict`); verify each case issues no storage write, leaves the run unchanged, and is never re-evaluated after it ends.
  <!-- agent: tier=deep risk=high reason="Distributed recovery of retained evidence" -->
- [x] 2.3 Implement the per-run claim (resourceVersion-conditional `signingRecovery.active`), waiting requests, `AlreadyRecovered`, and stale-claim clearing, and register `SigningRecoveryReconciler` (2.2) with the manager, making the charts CRD contract tolerate controller-written request status; verify concurrent requests, conflicting claim writes, a request deleted while holding the claim, and leader changes converge on one claim holder without a storage write (the single signature and commit they lead to is verified with 2.4).
  <!-- agent: tier=deep risk=high reason="Concurrency and leader-change convergence" -->
- [x] 2.4 Run recovery through the existing `signingRequirement` and commit gate under the destination fence as `run <name> signature recovery`, including `expectedKeyFingerprint` confirmation for unpinned intents; verify that a stored signature is reused without reading a private key, that `KeyMismatch`, `KeyConfirmationRequired`, and the destination's current policy or rotation never change the key used or allow an unsigned commit, and that concurrent requests, a request deleted while holding the claim, and leader changes converge on one signature and one commit.
  <!-- agent: tier=deep risk=high reason="Cryptographic key identity and no-substitution guarantee" -->
- [x] 2.5 Bound each claimed attempt by `PublishTimeout` from the claim, ending with `SigningFailed` unless the run already records successful recovery; verify the run's retained failure record, expiry, and outstanding-package accounting are unchanged, and that a new request can then succeed.
  <!-- agent: tier=deep risk=medium reason="Recovery retry bounds and retained-evidence state" -->
- [x] 2.6 Record success in one run status update (committed publication, `Completed`, `Published` True, `signingRecovery.recovered`) and the existing sanitized namespace-request update; verify the summary, completeness, outcomes, export kind, window, and `publishedAt` truthfulness, coverage ordering by closure, and pair-verified downloads through the unchanged routes. Make AlreadyRecovered repair the remaining matching statuses before success; retry transient failures even past the attempt deadline, and never recreate or overwrite missing/recreated namespace requests.
  <!-- agent: tier=deep risk=high reason="Distributed recovery of retained evidence" -->

## 3. Observability

- [ ] 3.1 Add the `konstapel_evidence_signing_recovery_requests` gauge (labels `phase` and `reason` only, reconstructed from records after restart), the Events on requests and runs, and the update to the publication projection; verify bounded labels, restart reconstruction, and no double counting when a run moves from failed to published.
  <!-- agent: tier=standard risk=medium reason="Bounded metrics against the existing observability contract" -->

## 4. Documentation

- [ ] 4.1 Replace the "not implemented yet" note in `docs/integration/evidence-signing.md` with the recovery workflow, roles, request example, outcome table, expiry rule, mixed-version and rollback guidance, and worked examples (key restored, unpinned intent, late recovery, expired evidence); verify the example manifests and permission probes against the generated API.
  <!-- agent: tier=standard risk=low reason="Document an established contract" -->
- [ ] 4.2 Update the publication record and status tables, the RBAC and admission references, and the acceptance table; verify every outcome and status field in the docs matches the implemented vocabulary.
  <!-- agent: tier=standard risk=low reason="Document an established contract" -->

## 5. Acceptance and live recovery

- [x] 5.1 Add live recovery acceptance to the mandatory storage group on the RustFS S3 fixture with disposable keys: a missing key Secret causing `SigningFailed`, restoration, and recovery; verify offline with pinned Cosign and the original trusted key, rejection with another key, unchanged evidence fields, and authorized namespace and platform downloads.
  <!-- agent: tier=deep risk=high reason="Live cryptographic verification of recovered evidence" -->
  Evidence: `TestLiveSigningRecoveryWorkflow` (storage group; inventory check in `scripts/ci/test_acceptance.py`). The destination's per-run key signs its first package. The key Secret is then deleted, and a team request's run ends `SigningFailed` with an unpinned Required intent. Its archive is retained, and both routes answer 409. The key is restored re-encrypted under the recorded name. A recoverer with only the shipped recoverer and operator roles creates the request with `expectedKeyFingerprint`, and the shipped admission policies record the recoverer. The request ends `Recovered`, and the run is `Completed` with `signingRecovery.recovered`. Storage holds one signature and one commit. The package keeps its digest, the failure-record expiry (`retention.notAfter`) and `publishedAt` after the failure, and every evidence field is unchanged. The team request is `Completed` and names no administrator, Secret or reason. Namespace and platform downloads return the identical pair, which verifies with Cosign v3.1.3 (pinned in `devbox.json`) and the trusted key and is rejected with the other key. The offline Cosign helper is shared with `TestLiveSignedPublicationWorkflow`. Passed on a local disposable kind cluster (109s; teardown verified), with the sanitized evidence passing `stage-evidence.py`.
- [ ] 5.2 Add live fault cases to the mandatory recovery group: concurrent requests, leader loss after signature storage, crashes after the run and namespace-request status writes (including restart after the attempt deadline), lost commit response with differing failure/commit expiries, expiry during recovery, orphan handoff, lost or replaced staged archive, and key mismatch; verify exactly one signature and commit, the defined terminal outcomes, and no unsigned publication.
  <!-- agent: tier=deep risk=high reason="Distributed recovery and concurrency under real storage" -->
- [ ] 5.3 Add live admission and RBAC cases to the existing admission or storage group: forged requester, spec edits, user status writes, and each role's denials; verify with real Kubernetes credentials and keep the API server's denial responses as evidence.
  <!-- agent: tier=deep risk=high reason="Authorization and audit attribution" -->
- [ ] 5.4 Add a deterministic network-boundary test that allows only required Kubernetes/S3 fixture traffic and fails on unexpected outbound requests, including Fulcio, Rekor, and timestamp authorities; verify the recovered key-based bundle carries no certificate, log entry, or timestamp. Run in the normal cluster-free checks without starting a Sigstore stack.
  <!-- agent: tier=deep risk=medium reason="Cryptographic trust boundary of keyless infrastructure" -->

## 6. Final checks

- [ ] 6.1 Run `task check`, the generated CRD/RBAC/chart freshness checks, the affected acceptance groups, `openspec validate add-evidence-signing-recovery --strict`, `openspec validate --specs --strict`, and `python3 -I scripts/agents/select-task.py --check` through Devbox; keep sanitized evidence, and remove task-owned keys, Secrets, RustFS containers and volumes, clusters, and processes.
  <!-- agent: tier=standard risk=low reason="Run established validation and cleanup" -->
