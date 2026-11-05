# Tasks

API/storage-contract work can begin with explicit fixtures. Real intake depends
on the S3 owner's adapter and authenticated service; reporting depends on the
coverage projection contract and scoped assessment producer. Shared schema,
transport, and chart extensions go through their existing owners after rebasing.
These tasks implement platform-only attachments. Application-team self-service
is recorded under Future Development below, without implementation checkboxes.
The SeaweedFS fixture in group 6 can start alongside group 1 and supplies the real
local S3 endpoint for groups 2 and 3; it does not wait for package integration.

## 1. Attachment API and authority

- [ ] 1.1 Add cluster-scoped EvidenceAttachment types with immutable document metadata, required validity dates, exact binding/catalog/control associations, protected attribution, status, and retention finalization; verify generated CRDs reject malformed dates/digests, unsupported fields, and evidence-defining edits.
- [ ] 1.2 Protect registration attribution using existing admission conventions and validate references before activation; verify the authenticated actor cannot be forged, statement IDs belong to their controls, and binding recreation or wrong-catalog associations cannot become active.
- [ ] 1.3 Add dedicated platform registration/upload/read/download and controller roles without built-in role aggregation; verify namespace assessment/exception credentials cannot create, upload, associate, read private metadata, or withdraw attachments.
- [ ] 1.4 Document the platform API, immutable replacement workflow, associations, and authority matrix in `docs/supporting-evidence.md`; verify example manifests and permission probes against the generated API.

## 2. Source storage and commitment

- [ ] 2.1 Define the attachment storage/receipt contract separately from assessment RunRef/Publisher, consuming the S3 owner's destination and credential configuration; verify contract fixtures preserve document/spec identity, commitment, uploader, versions, and retention without fake assessment runs.
- [ ] 2.2 Implement staged upload, checksum/readback verification, and one conditional commit manifest through shared S3 primitives; verify identical retries, conflicting bytes, concurrent writers, lost responses, and restart recovery against a real S3-compatible endpoint.
- [ ] 2.3 Freeze source expiry as max(committedAt, validUntil) plus positive central retention with default 2160h; verify future/expired documents, policy changes to retention, withdrawal, and response loss cannot change the first commitment.
- [ ] 2.4 Track destination and attempt ownership durably, with bounded orphan cleanup; verify credential rotation, changed defaults, abandoned multipart/attempt data, and unrelated objects are handled without silent relocation or overbroad deletion.
- [ ] 2.5 Document source versus assessment-copy retention and the commit boundary; verify worked examples cover a year-long document with 90-day assessment retention and independent source/package expiry.

## 3. Authenticated transfer and CLI

- [ ] 3.1 Extend the existing authenticated TLS service with UID-addressed attachment upload/download routes and dedicated authorization attributes; verify current TokenReview/SubjectAccessReview decisions, record identity, deleted-record upload denial, and revocation behavior using real Kubernetes credentials.
- [ ] 3.2 Add bounded streaming with the documented 32 MiB, five-minute, and two-per-replica defaults plus validated overrides; verify size/hash mismatch, timeout, concurrency saturation, interrupted transfers, and safe non-inline download responses leave no falsely available document.
- [ ] 3.3 Add independent `konstapel evidence` CLI dispatch for registration/upload, download, and status inspection; verify kubeconfig/context handling, exact binding/record UIDs, actionable errors, and absence of C2P/provider/policy-delivery startup.
- [ ] 3.4 Document end-to-end platform commands and the distinction between authenticated submitter, uploader, and declared document source; verify a different authorized uploader is recorded truthfully and an informational URL is never fetched.

## 4. Association, validity, withdrawal, and cleanup

- [ ] 4.1 Reconcile temporal, content, association, and withdrawal states separately; verify exact validity boundaries, no-event expiry, unavailable bytes, removed baseline controls, binding recreation, and unchanged associations across reporting-only/policy-parameter edits.
- [ ] 4.2 Withdraw deleted records from new coverage while retaining source ownership until fixed expiry; verify restart/leader changes, retention-active finalization, expired source-download denial, and owned version/marker cleanup without changing historical packages.
- [ ] 4.3 Expose bounded failure and cleanup conditions for inaccessible destinations or retention locks; verify failed deletion is recoverable and does not lose ownership or delete unrelated data.
- [ ] 4.4 Document lifecycle and recovery with clock-controlled examples; verify re-upload does not implicitly renew validity and correction requires a new immutable record.

## 5. Coverage and assessment packages

- [ ] 5.1 Consume the coverage owner's supporting-evidence projection contract and freeze attachment scope/context per run; verify datacenter evidence can support several explicit bindings without changing technical counts, outcomes, risk acceptance, or policy revisions.
- [ ] 5.2 Add verified independent document copies, immutable context, checksummed inventory, and valid relative OSCAL back-matter references to platform packages through the producer owner; verify capture changes, storage failure, expired/future documents, source cleanup, and retry/capture-loss behavior.
- [ ] 5.3 Add explicit protected-document/context roles and versioned package protection through the publication owner; verify namespace packages reject document bytes and contain only sanitized validity/availability context without private metadata or usable links.
- [ ] 5.4 Require document-read permission as well as run/download permission for platform packages containing protected roles; verify a run reader cannot bypass attachment authorization, permission revocation is effective, and historical package access works without a live source record.
- [ ] 5.5 Document report interpretation and producer/reader compatibility rollout; verify old packages remain readable, unknown protected versions fail closed, and rollback retains compatible download/cleanup service for existing commitments.

## 6. SeaweedFS local development

- [ ] 6.1 Add or extend the S3 owner's disposable development helper with a pinned SeaweedFS container/S3 gateway, local credentials, bucket/prefix, and owned volume; verify start/stop commands use existing Devbox tooling and leave production Helm dependencies unchanged.
- [ ] 6.2 Run the shared conditional-create, commit-time, checksum/readback, concurrency/recovery, and cleanup compatibility suite against that SeaweedFS pin; record supported versioning modes and reject missing required semantics without claiming untested AWS or Object Lock support.
- [ ] 6.3 Document the local registration/upload/capture/download workflow and safe teardown in development and supporting-evidence guides; verify the production S3 adapter handles the fixture with no alternate filesystem backend or one-task-per-script expansion.

## 7. Integrated acceptance and release wiring

- [ ] 7.1 Integrate generated CRD/RBAC/admission and service settings into the existing aligned charts and controller startup through their owners; verify chart generation, permissions, serving readiness, and reader authorization are deployed before protected-document writers are enabled.
- [ ] 7.2 Run full attachment/coverage/assessment acceptance with real S3 service and namespace/platform credentials using SeaweedFS; verify upload, multi-binding association, validity, independently authorized downloads, namespace confidentiality, and independent source/package retention.
- [ ] 7.3 Exercise replica/leader loss, interrupted upload, lost commit response, unavailable source storage, withdrawal during capture, and denied cleanup across the integrated workflow; verify durable recovery, unchanged historical bytes, and truthful unavailable states.
- [ ] 7.4 Run appropriate existing Devbox/Task checks, generated-schema/package regressions, and strict OpenSpec validation; retain sanitized test/compatibility evidence and remove task-owned SeaweedFS containers/volumes, credentials, prefixes, clusters, and processes.

## Future Development

- Namespace-scoped self-service attachments for application teams: define ownership,
  Kubernetes RBAC, quotas, upload limits, namespace UID isolation, and sharing in a
  later change. Do not enable this through the platform-only tasks above.
- Per-document ACLs, cross-cluster inheritance, structured scanner-result ingestion,
  and human assessment verdicts require separate exploration and authorization.
