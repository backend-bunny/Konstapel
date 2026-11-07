# Proposal

## Why

Konstapel's evidence packages have checksums and protected publication receipts,
but an auditor who receives a package outside the cluster cannot independently
authenticate its publisher. Signing the frozen package lets that auditor verify
its integrity and origin against an explicitly trusted public key.

## What Changes

- Add centrally managed signing configuration to EvidenceDestination, inherited
  by its bindings and requests. Signing is disabled unless configured; when
  required, an unavailable or invalid signer blocks publication without unsigned
  fallback.
- Implement only operator-provided Kubernetes Secret keys in the controller
  namespace initially. Operators own generation, rotation, and public-key trust
  distribution; Konstapel does not generate or replace their keys.
- Sign the exact frozen assessment archive using a standard, Cosign-compatible
  blob-signature format. Include complete, incomplete, and diagnostic packages
  without changing their assessment meaning.
- Extend immutable publication, recovery, authorized downloads, and retention to
  cover the signature and verification material alongside the existing archive.
  Verification must work offline with a separately trusted public key.
- Pin signing intent and key identity for retries. Rotation applies to new
  publication intents; retained packages and signatures remain unchanged and can
  be verified using retained historical public keys.
- Keep the signer boundary replaceable. Defer OpenBao/Vault Transit, AWS KMS,
  keyless signing, public transparency-log integration, and trusted timestamping
  to later work. Record Kubernetes service-account JWT authentication to Fulcio
  as an optional future keyless approach, with explicit issuer trust and retained
  historical verification proof; it is not a v1 dependency or implementation task.
  This change signs produced evidence, not release artifacts or upstream scanner
  reports, and does not attest that a cluster is compliant.

## Capabilities

### New Capabilities

- `evidence-signing`: Destination-governed evidence signing, Secret-backed key
  handling, immutable signature publication, rotation, and offline verification.

### Modified Capabilities

None. The existing continuous-assessment completeness, scope, and immutable-history
contracts remain intact. This capability extends the publication contract being
implemented by `add-s3-evidence-publishing`; shared schema changes must be
coordinated with that owner.

## Impact

Implementation will extend EvidenceDestination and run/publication metadata,
generated CRDs and RBAC, the shared publication interface, S3 staging/commit and
cleanup, and the authorized download service. It will add a focused Go signing
adapter using maintained Sigstore/Cosign libraries and interoperability tests
against the pinned Cosign CLI. Runtime signing must not require adding a CLI or
shell to the controller image.

Coordinate with S3 publishing for receipt/commit versions and lifecycle ownership,
Helm distribution for configuration and permissions, high availability for retry
behavior, and observability for bounded status. Existing Kyverno and planned Trivy
assessments use the same signing boundary. Documentation and required CI acceptance
will cover key setup, rotation, signature retrieval, verification, and failures.
