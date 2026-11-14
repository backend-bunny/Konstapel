# Tasks

## 1. Establish the signer and interoperability contract

- [x] 1.1 Add a focused Go signer interface and Secret-key adapter using maintained Sigstore/Cosign libraries, ECDSA P-256/SHA-256, standard Cosign key encoding, and SPKI fingerprints; verify valid keys, wrong passwords, mismatched public keys, unsupported algorithms, and sanitized failures with disposable-key tests.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 1.2 Produce a standard message-signature bundle for exact archive bytes and pin its supported library/schema version; verify Go-generated output using Devbox's pinned Cosign with networking disabled, including wrong-key, changed-byte, malformed-bundle, and double-hashing regressions.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 1.3 Document supported key fields, algorithm, bundle version, and the explicit no-transparency-log verification contract; execute the documented verification command in the interoperability tests and prove no public signing service or ambient identity is used.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.4 Integrate new Go dependencies through the existing module/image workflows; verify module locks, image smoke checks, SBOM/license inventory and attestation inputs while keeping runtime signing in Go without adding Cosign or a shell to the controller image.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 2. Add central destination configuration and Secret access

- [x] 2.1 Coordinate shared schema ownership with S3 publishing, then add Disabled/Required signing configuration and controller-namespace Secret reference validation to EvidenceDestination; regenerate CRDs and test defaults, missing/mismatched fields, cross-namespace references, and unsupported KMS/keyless backend requests.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 2.2 Resolve configured Secrets through bounded namespace-scoped reads and react to relevant rotation changes; verify application roles cannot access keys or override policy, controller permissions stay scoped, and key values never enter captured errors/logs/status.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 2.3 Add bounded signing readiness and public-key identity status separately from assessment outcomes; test missing/malformed keys, recovery, unrelated destinations, and historical reads/cleanup with the current signer unavailable.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 2.4 Document operator key generation/installation and destination setup using validated examples; exercise API admission and RBAC against the examples and state that keys and trust distribution are operator-managed.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 3. Extend durable signing and publication

- [x] 3.1 Version the shared signing-intent, commit/receipt, run status, and object-reference extensions with the S3 owner; verify legacy unsigned records remain readable and unsupported or malformed signed records cannot downgrade to unsigned.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 3.2 Freeze signing mode, destination revision, key source/fingerprint/public material, and archive digest at first publication-intent preparation; test concurrent preparation, enabled/disabled changes, same-name Secret replacement, and rotation without changing an existing intent.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 3.3 Sign and locally verify staged archives, persist recoverable signature artifacts, and require a verified pair before conditional commit; test missing keys, invalid signatures, interrupted writes, and prevention of unsigned success for Required intents.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 3.4 Recover signatures before loading private keys and converge concurrent attempts on one committed pair; test randomized signature bytes, leader/restart recovery, lost commit responses, and completion after private-key retirement without changing archive bytes, signature bytes, expiry, or run identity.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 3.5 Integrate bounded signing retries with existing run termination and staged-evidence recovery; test unavailable signer behavior, released active slots, explicit capture loss, and no recollection or reassignment of failures to compliance outcomes.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 3.6 Document the signing-intent boundary and publication failure/recovery states; verify worked examples cover a rotation, an in-flight Required-to-Disabled edit, and complete/incomplete/diagnostic archives without changing assessment meaning.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 4. Expose authorized verification material

- [x] 4.1 Add companion signature retrieval to the existing namespace-request and platform-run download paths using their current authorization rules; test team/sibling/full-binding boundaries, namespace UID replacement, expired/orphaned evidence, and explicit unsigned responses.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 4.2 Verify the archive/signature pair against protected receipt identity and retained public material before serving either artifact; test missing/tampered/swapped bundles, wrong keys and scope, and successful historical reads after current signing-Secret deletion.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 4.3 Document downloading both artifacts and verifying with a separately trusted public key, followed by existing file/scope checks; test the command sequence offline and demonstrate that a key supplied by an untrusted package cannot establish trust.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 5. Preserve rotation, retention, and migration behavior

- [x] 5.1 Make pending key dependencies inspectable and document versioned-Secret rotation; test old intents using the previous key, new intents using the next key, early private-key removal, same-key re-encryption, and verification after completed keys are retired.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 5.2 Extend integrity checks, attempts cleanup, retention deletion, and destination retirement to signature objects and owned versions; test cleanup without affecting unrelated artifacts or extending expiry and ensure mismatched material reports corrupt/unavailable evidence.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 5.3 Extend orphan fences and durable handoff inventories to signing/signature uploads and uncertain in-flight operations; test no new work after the fence, no late-response reactivation, and retained ownership records without private material.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 5.4 Document migration, rollback, historical public-key retention, and trust withdrawal after compromise; verify legacy unsigned fixtures keep original bytes/receipts and that required-signature verification never uses claimed timestamps to bypass withdrawn trust.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 5.5 Update shared status/observability and deployment documentation with the owning changes; verify bounded reason categories, signing versus evidence distinctions, and the configuration/permissions consumed by Helm without introducing separate controllers or unbounded metric labels.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 6. Verify real publication and required CI

- [x] 6.1 Add signing blackbox cases to the existing mandatory acceptance-group inventory, using real Kubernetes APIs, the isolated S3 backend, disposable Secrets, and pinned Cosign; verify local/CI selection requires these tests and teardown removes only test-owned keys and infrastructure.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 6.2 Run the complete signed-publication workflow for namespace and full-binding packages, including incomplete and diagnostic results, rotation, interruption/recovery, tampering, authorization, retention, and orphaning; verify downloaded artifacts offline and retain sanitized evidence with stdout/file progress logs.
  <!-- agent: tier=deep risk=high reason="Cryptographic trust, key isolation, and immutable publication" -->
- [x] 6.3 Run the pinned Devbox checks, relevant image workflows, and required acceptance groups on the final implementation; verify Kyverno/unsigned publication regressions remain green and supported HA recovery consumes the same signing contract before implementation is marked complete.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## Workflow follow-up

- Review against the evidence-signing spec and archive only after implementation
  and required CI acceptance are complete.
- Owner decision needed on the API shape: add an admin-initiated re-sign, as
  its own PR after group 5, for runs that ended with `SigningFailed` and
  retained their staged archive (design section 4, group 3 note), owned by
  this change's group 4/5 work. It reuses the run's recorded signing intent
  and pinned key, cannot change the archive, the run's identity, or its
  retention, and is authorized for platform administrators only. Until then,
  the retained archive is kept until its expiry and is not re-signed.
- Propose a separate follow-up for OpenBao/Vault Transit and AWS KMS keys. Keep
  their credentials, service behavior, key versions, and compatibility tests out
  of this change's implementation checklist.
- Explore Kubernetes service-account JWT authentication to Fulcio as a separate,
  optional keyless-signing change, following the design's deferred flow. Resolve
  issuer/audience trust, independent verifier identity constraints, retained
  certificate/time/log proof for offline verification, infrastructure ownership,
  and ephemeral-key recovery before implementation. This is future planning, not
  a v1 task or an automatic fallback when Secret signing fails.
