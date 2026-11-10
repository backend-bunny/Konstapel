# Tasks

Groups 1-4 can start from the merged prototype and targeting API contract.
Group 5 integrates after the targeting resolver/manager lands. Group 6 can build
on groups 1-3 independently of that manager. Group 7 requires the named owning
changes; prepare fixtures earlier without replacing their implementations.
All work follows the ownership boundaries in [design.md](design.md).

## 1. Bundle schema, content contract and packaging

- [x] 1.1 Add the versioned bundle descriptor schema and OCI layout documentation; verify valid official/organization fixtures and rejection of unsupported formats, duplicate identities/keys, unexpected layers, and name/inventory mismatches.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 1.2 Generalize content validation around the existing OSCAL/C2P conventions; test local reference closure, parameter validation, Moderate mappings and mixed declared OSCAL versions with external content access disabled, preserving the prototype regression suite.
  <!-- agent: tier=deep risk=medium reason="Cross-owner content resolution and bounded registry access" -->
- [ ] 1.3 Publish the resolved-content handle and verification-receipt contract, including cache leases and separate source/rendered/OCI digests; verify serialization fixtures and compatibility with the existing targeting contribution fields without changing its revision algorithm.
  <!-- agent: tier=deep risk=medium reason="Cross-owner content resolution and bounded registry access" -->
- [x] 1.4 Implement deterministic archive and OCI-manifest construction from a bundle definition; verify repeated builds from identical source/tool inputs produce identical digests, with no circular descriptor checksum or runtime dependency downloads.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.5 Package the existing privileged-container policy with its source, tests, licenses, provenance and NIST content; verify checksums, fixtures and the existing bounded AC-6 mapping against the unpacked release payload.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.6 Add the documented `bundles:package` workflow and integrate format/content checks into existing checks; verify the documented Devbox commands and confirm Taskfile exposes no individual signing, checksum or summary helper tasks.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 2. Central source configuration and registry transport

- [ ] 2.1 Define and document the versioned name-to-source configuration and its credential/CA/publisher references; test duplicate or missing sources, invalid repositories, invalid trust rules and payload-name mismatches while preserving the profile name/digest schema.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 2.2 Add pinned ORAS Go dependencies and a bounded digest/referrer retrieval adapter; test exact-subject selection, moved tags, unexpected descriptors, missing proofs, timeout/cancellation, referrer limits and concurrent request deduplication.
  <!-- agent: tier=deep risk=medium reason="Cross-owner content resolution and bounded registry access" -->
- [ ] 2.3 Implement namespace-local dockerconfigjson Secret credentials and custom CA handling; test rotation/token invalidation, missing configured Secrets, malformed credentials, helper rejection and prevention of credential disclosure or forwarding to unrelated origins.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 2.4 Add a disposable authenticated TLS OCI registry fixture supporting the chosen referrer layout; verify real anonymous/authenticated subject and proof retrieval, authentication failure, custom-CA trust and task-owned teardown with recorded versions.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 2.5 Document private registry setup, least-privilege Secret access and registry compatibility requirements; verify the setup against the fixture and state explicitly that Konstapel does not inherit node pull credentials.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 3. Signature and provenance verification

- [ ] 3.1 Add pinned Cosign/Sigstore Go verification dependencies and public-key rules; verify valid signatures and rejection of unsigned content, wrong keys, tampering, wrong subjects and bundle-provided trust settings using independently signed fixtures.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 3.2 Implement keyless verification with exact issuer/identity, trusted roots and signing-time evidence; test wrong identities/issuers, invalid or missing proofs, root changes and expired leaf certificates with valid versus invalid authenticated signing times.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 3.3 Verify required SLSA provenance against the OCI subject and configured publisher/builder/source constraints; test wrong digests, mixed unauthorized signer rules, missing attestations, source-revision/version/material mismatches and correct organization-key provenance.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 3.4 Persist bounded verification receipts and the material needed for rechecking under current trust; test reconstruction without accepting a receipt as its own authority and validate that credentials are excluded from the serialized result.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 3.5 Document both signing methods, official trust-root maintenance and publisher rotation; verify pinned Cosign CLI output is accepted by the Go verifier for both methods using isolated test roots/keys and no disabled verification checks.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 4. Safe materialization and bounded caching

- [ ] 4.1 Implement isolated extraction and file-inventory checks; test traversal, symlinks/hardlinks, special files, duplicate normalized paths, truncated blobs and decompression limits, proving existing verified entries and unrelated files stay unchanged.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 4.2 Implement atomic digest-cache promotion, capacity reservation and configurable limits; test concurrent staging, disk exhaustion, interruption and recovery within the documented payload/proof/cache defaults.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 4.3 Separate cached bytes from source/trust/compatibility acceptance revisions; test reuse during registry outages, invalidation after trust/key/source changes and rejection of a result invalidated concurrently with its verification.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 4.4 Implement leases for desired/applied content and active assessments, plus eviction of unreferenced entries; test exhausted capacity with active pins, lease release, corrupted reuse and safe restoration from persistent cache.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 4.5 Document cache lifetime and outage behavior; verify process restart and Pod/cache-loss cases distinguish usable proofs, missing content and stale applied policies without claiming default durable storage.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 5. Targeting and provider integration

- [ ] 5.1 After the targeting resolver/manager merges, connect central ConfigMap and referenced Secret/CA watches to affected profiles with appropriate namespace-local RBAC; test atomic invalid configuration, deletion, rotation, requeue and observed-generation status.
  <!-- agent: tier=deep risk=medium reason="Cross-owner content resolution and bounded registry access" -->
- [ ] 5.2 Connect resolved bundle content to the existing provider and contribution resolver; test unknown policies/parameters, provider allowlisting, unsupported workload scope/APIs, engine recovery and preservation of profile/binding governance without installing fixture resources.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 5.3 Integrate bundle failures with detailed profile conditions and the existing ContentUnavailable boundary; test initial failure, failed update, trust revocation and recovery while preserving applied ownership and prohibiting new use of rejected content.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 5.4 Verify profile digest upgrades and rollbacks through the existing replacement-readiness and revision contracts; test that semantic changes advance revisions while mirrors/credential rotation do not, and that an earlier exception cannot authorize a new revision when exception integration is available.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 5.5 Update targeting/provider documentation with configured official and organization sources; run the documented Audit example and retain existing local CLI/capture regression results without rewriting historical hashes.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 6. Independent release publication

- [ ] 6.1 Add bundle-specific versions, Git release-tag validation and a dedicated dispatch workflow using reviewed main-ancestor commits; test invalid names/versions/source commits and demonstrate that it requires no application or chart release.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 6.2 Freeze tested archives/manifests and implement serialized write-once publication with recoverable inputs; use registry failure injection to verify missing-upload recovery, conflicting version refusal and completion of missing proofs without replacing original bytes.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 6.3 Sign and attest the exact remote OCI digest through GitHub OIDC; validate provenance identifies actual content source, bundle inputs and tests separately from dispatch/workflow revision, and verify the resulting subject through the consumer's trust contract.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 6.4 Add bundle release notes and CI summaries with version, digest, compatibility, policies, licenses and verification instructions; test rendering/idempotent updates and ensure publication is not reported complete while required remote verification is missing.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 6.5 Document organization publication and mirroring with the same format and verifier; test copying a subject plus referrers to the private fixture registry, preserving its digest and original provenance, and rejection when required evidence is omitted.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 7. Integrate independently owned content, evidence and deployment

- [ ] 7.1 After Linux hardening content merges, assemble its complete bundle by build-time reference to owned sources; verify all shipped variants, tests and bounded mappings against that change's accepted inputs without copying source ownership or adding policies here.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 7.2 After the continuous-assessment descriptor contract merges, include applied bundle identity, content and verification context in frozen packages through its owner; verify evidence remains complete after runtime cache eviction and registry loss, with desired/applied differences preserved.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 7.3 After the Helm chart implementation merges, expose central configuration, Secret/CA references and bounded cache mounts through existing chart conventions; verify schema/render tests and installed runtime configuration without generating competing CRDs or exposing trust bypasses.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 8. End-to-end acceptance

- [ ] 8.1 Add the documented `bundles:acceptance` workflow over the existing registry and disposable Kyverno fixtures; verify official/organization content in Audit and Deny, valid/invalid signatures, credential rotation, warm-cache outage, cold-cache failure, trust revocation and recovery, cleaning up all task-owned resources.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 8.2 Exercise full upgrade/rollback with the merged targeting/exception/evidence integrations; retain evidence proving replacement readiness, fresh exception revisions, stable logical checks and OSCAL provenance for the exact applied bundle.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
- [ ] 8.3 Verify one official independently released OIDC-signed subject and its private mirror through the production verifier; retain release/registry/runtime versions, digest-based commands and results, and run the repository's applicable checks without treating unimplemented dependency integrations as complete.
  <!-- agent: tier=deep risk=high reason="Content trust, isolation, cache races, and release integrity" -->
