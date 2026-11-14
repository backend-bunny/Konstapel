# evidence-signing Specification

## Purpose
Authenticate Konstapel's frozen evidence packages through centrally configured
signatures that remain independently verifiable after publication and key rotation.

This delta covers Secret-backed signing only. Kubernetes service-account JWT
authentication to Fulcio and remote OpenBao/Vault/KMS signers are deferred as
described in the design's Deferred Follow-up section. They introduce no v1
runtime dependency or implicit ambient-identity signing path.

## Requirements

### Requirement: Destination-controlled signing policy

EvidenceDestination SHALL support Disabled and Required signing modes, defaulting
to Disabled for compatibility. Required SHALL reference an operator-provided
signing Secret in the controller namespace. Application bindings and requests
SHALL inherit the selected destination's policy without a signing override.
Invalid combinations and unsupported signer kinds SHALL be rejected explicitly.

#### Scenario: Enable signing for a destination

- **WHEN** a platform administrator selects Required with a valid Secret reference
- **THEN** new publication intents using that destination require a signature
- **AND** application-team requests cannot disable signing or select another key

#### Scenario: Invalid configuration

- **WHEN** Required lacks a Secret reference, a reference selects another namespace, or a deferred KMS or keyless kind is requested
- **THEN** admission rejects the configuration with a field-specific explanation

#### Scenario: A workload identity token is available

- **WHEN** the controller has a Kubernetes service-account token but its Required signing Secret is unavailable
- **THEN** publication fails under the Secret-backed contract
- **AND** token availability does not enable Fulcio signing or an unsigned fallback

### Requirement: Signing keys remain operator-managed secrets

Konstapel SHALL read only the configured signing key through controller-namespace
Secret access. Operators SHALL own key generation, installation, and rotation.
Konstapel SHALL NOT generate, replace, or export private keys. Private key bytes
and passwords SHALL NOT appear in status, logs, metrics, evidence, or command
arguments. Application evidence access SHALL NOT grant signing-Secret access.

#### Scenario: Read a package as an application team

- **WHEN** authorized application credentials retrieve signed evidence
- **THEN** they receive the package and permitted public verification material
- **AND** they cannot read or modify its private signing key or destination configuration

#### Scenario: Key loading fails

- **WHEN** a Secret is unreadable, malformed, encrypted with an invalid password, or contains a mismatched public key
- **THEN** the signer reports a sanitized failure without revealing secret contents
- **AND** Konstapel does not generate a substitute key

### Requirement: Sign the complete frozen evidence archive

A signature SHALL authenticate the exact bytes of the frozen evidence archive,
including its descriptor, scoped source evidence, OSCAL or diagnostics, and any
packaged acceptance history. The signed descriptor SHALL bind cluster, run,
binding, scope, and content identities. A detached signature SHALL identify its
algorithm and public-key identity and SHALL NOT require modifying the signed archive.

#### Scenario: An archive or signature is substituted

- **WHEN** archive bytes change or a signature from another package is supplied
- **THEN** verification fails against the expected trusted key and archive digest
- **AND** a valid signature for another scope does not satisfy the requested scope

### Requirement: Standard key-based offline verification

Signed evidence SHALL use a documented Cosign-compatible blob-signature format
and supported algorithm. Verification SHALL work offline using the exact archive,
its retained verification material, and an independently trusted public key.
Kubernetes, S3, the private key, KMS, and public signing services SHALL NOT be
required after download. Unknown formats or algorithms SHALL fail explicitly.

#### Scenario: An auditor verifies a downloaded package

- **WHEN** an auditor uses the documented pinned Cosign workflow with a separately trusted public key and network access disabled
- **THEN** the unchanged archive verifies successfully
- **AND** a modified archive, wrong key, malformed bundle, or unsupported algorithm fails

### Requirement: Packaged key material does not establish trust

Public-key hints or public keys supplied with evidence SHALL identify verification
material only. They SHALL NOT become trusted automatically. Verification SHALL
require caller-selected trust and expected scope. Documentation SHALL distinguish
the signer identity from unverified producer claims and SHALL describe how platform
operators distribute and retain trusted public keys.

#### Scenario: An attacker replaces the package and its key

- **WHEN** a replacement package has a valid signature from an untrusted key included beside it
- **THEN** verification against the auditor's trusted key fails
- **AND** the supplied key cannot override the auditor's trust configuration

### Requirement: Signing intent is durable and bounded

Before a new publication commit, Konstapel SHALL durably record the effective
destination signing mode and revision, selected key source and fingerprint, and
archive identity. Retries SHALL preserve that intent. Once Required is selected,
configuration changes or key rotation SHALL NOT silently downgrade it or switch
its signer. Signing attempts SHALL use bounded retries and existing run recovery.

#### Scenario: Disable signing while a required publication is pending

- **WHEN** a destination changes to Disabled after a Required intent was recorded
- **THEN** that intent still requires its recorded key and signature
- **AND** later intents use the new policy without rewriting the earlier one

#### Scenario: Enable signing before an unprepared publication

- **WHEN** an archive is staged but no signing intent has been prepared and the destination is changed to Required
- **THEN** preparation selects Required from the current authoritative destination configuration
- **AND** staging alone cannot preserve an earlier unsigned default

### Requirement: Required signing gates successful publication

A Required publication SHALL become committed and downloadable only after the
archive and its matching signature material are durably stored and verified.
Missing keys, signing failure, invalid signatures, and partial uploads SHALL
remain publication failures or pending work, never unsigned success. Failure
SHALL NOT change evidence outcomes or cause recollection under the same run identity.

#### Scenario: The signer is unavailable

- **WHEN** the frozen package is ready but its required key cannot be used
- **THEN** publication reports the signing failure and preserves recoverable frozen evidence
- **AND** no successful commit or downloadable unsigned fallback is created

#### Scenario: Signature upload is interrupted

- **WHEN** the archive is stored but its verification material is not durable
- **THEN** the publication remains uncommitted and retryable under its original intent

### Requirement: Signing failures retain frozen evidence

A publication whose Required signing intent is not satisfied within the
bounded publication retries SHALL end with an explicit signing failure. Its
staged archive and any stored signature SHALL be retained with the run until
the run's recorded retention, counted from collection closure, expires. Loss
of the frozen package itself SHALL remain a capture loss.

#### Scenario: The signer never becomes available

- **WHEN** a Required publication's key stays unavailable past the publication timeout
- **THEN** the run fails with SigningFailed, releases its binding's slot, and keeps its evidence summary
- **AND** its staged archive is retained until the run's retention expiry and then deleted like a retained package

### Requirement: Retained signing failures share the package lifecycle

Retained evidence of a signing failure SHALL count as an outstanding package
of its destination. Abandoned-attempt cleanup and deletion of the run record
SHALL NOT remove it. Only retention deletion at its expiry or an orphan
handoff SHALL end Konstapel's ownership. The run's signing intent SHALL stay
recorded so an authorized recovery can re-sign the same archive.

#### Scenario: The run record is deleted after a signing failure

- **WHEN** a run that failed signing is deleted before its retention expires
- **THEN** the record is held and the staged archive is kept until that expiry
- **AND** the destination still counts it until then

### Requirement: Signature recovery preserves publication identity

Recoverable signature material SHALL be reused after retries or leader changes.
Concurrent attempts SHALL converge on one immutable committed archive/signature
pair with pinned checksums. Recovery SHALL verify the committed pair and preserve
its original retention and publication identity. A committed signature SHALL NOT
be regenerated or replaced merely because the active signing key changed.

#### Scenario: Lose the commit response

- **WHEN** storage commits signed evidence but the controller loses the response
- **THEN** recovery returns the same committed archive and verification material
- **AND** it does not require the old private key or move publication time and expiry

#### Scenario: Two attempts produce different signature bytes

- **WHEN** concurrent signing attempts satisfy the same recorded key and archive intent
- **THEN** one committed signature is selected under the existing conditional-commit protocol
- **AND** losing artifacts are cleaned up without overwriting the winner

### Requirement: Rotation preserves historical verification

Rotation SHALL affect new publication intents while existing intents retain their
recorded signing identity. Completed evidence SHALL remain verifiable using its
historical trusted public key after private-key retirement. Operators SHALL be
able to retain overlapping versioned Secrets until pending signing finishes.
Removing a needed old key SHALL fail pending signing visibly rather than substitute
a new key.

#### Scenario: Rotate while an older run still needs signing

- **WHEN** a destination switches to a new Secret while a pending intent references the previous key
- **THEN** the pending intent uses the previous key and a new intent uses the rotated key
- **AND** deleting the old Secret before signing finishes leaves an explicit failure

#### Scenario: Retire the private key after signing

- **WHEN** matching verification material is already durably recorded and the private key is removed
- **THEN** recovery, authorized downloads, and offline verification use retained public material
- **AND** existing archive and signature bytes remain unchanged

### Requirement: Verification time and trust limits remain explicit

Signatures SHALL establish integrity and possession of a trusted signing key.
They SHALL NOT assert source correctness, uncompromised controller execution,
compliance, or an independently trusted signing time. Routine rotation SHALL NOT
invalidate historical signatures. A verifier's withdrawal of trust SHALL prevent
trusted verification; self-reported timestamps SHALL NOT prove pre-compromise signing.

#### Scenario: The operator withdraws trust after key compromise

- **WHEN** the auditor removes a key from trusted verification configuration
- **THEN** packages signed by that key cannot pass that auditor's trusted verification
- **AND** a recorded package timestamp alone cannot establish that signing preceded compromise

### Requirement: Signature retrieval follows evidence authorization

Authorized download workflows SHALL expose the exact archive and its corresponding
verification material through the same namespace/run identity, RBAC, expiry, and
orphaning boundaries. Namespace packages SHALL never expose sibling evidence or
signatures for broader scopes. The existing archive representation SHALL remain
available; clients SHALL be able to retain both artifacts for offline verification.

#### Scenario: Retrieve a namespace signature

- **WHEN** a team authorized for its namespace request retrieves verification material
- **THEN** it receives only that committed package's material
- **AND** another namespace, a recreated namespace UID, or a full-binding run is denied

### Requirement: Downloads detect damaged signed evidence

For signed publications, download validation SHALL verify the archive/signature
association against protected publication metadata and retained public material
before serving evidence. Missing, mismatched, or invalid material SHALL report
unavailable or corrupt evidence. Current signing-key availability SHALL NOT be a
prerequisite for reading an otherwise valid retained package.

#### Scenario: A signature disappears before expiry

- **WHEN** a committed signed package's verification material is missing or corrupted
- **THEN** the managed download reports the integrity/availability failure
- **AND** it does not serve the archive as an unsigned replacement

### Requirement: Signing state is separate from assessment meaning

Status and verification output SHALL distinguish signing Disabled, signing pending
or failed, and recorded signed publication from evidence completeness and outcomes.
Complete, incomplete, violating, accepted-risk, and diagnostic packages SHALL use
the same configured signing policy. Signing SHALL NOT create a compliance pass,
repair missing evidence, renew freshness, or broaden scope.

#### Scenario: Sign an incomplete assessment or diagnostic

- **WHEN** a Required destination receives a valid incomplete or diagnostic package
- **THEN** it can be signed and published with its original limitations and outcomes
- **AND** the signature does not turn it into a complete or passing assessment

### Requirement: Signature artifacts share the evidence lifecycle

Verification material SHALL share the package's publication ownership, expiry,
retirement, and orphan handoff. Cleanup SHALL remove owned signature versions and
abandoned signing attempts along with their corresponding evidence, subject to
existing ownership and retention rules. Signing SHALL NOT bypass orphan fences or
extend a retained package's expiry.

#### Scenario: Retire or orphan a signed destination

- **WHEN** a destination is retired normally or handed off through Orphan
- **THEN** signatures follow the same finish/download/cleanup or fenced-handoff behavior as their archives
- **AND** ownership inventories account for signature artifacts and uncertain in-flight operations

### Requirement: Existing unsigned history remains explicit

Existing unsigned packages SHALL retain their original bytes, receipts, and
retention when signing is enabled. They SHALL be identified as unsigned and SHALL
NOT be silently re-signed or represented as historically signed. Versioned
publication formats SHALL distinguish legacy unsigned data from invalid or
missing required signatures. Unsupported signed formats SHALL fail explicitly.

#### Scenario: Enable signing after earlier publications

- **WHEN** an existing destination begins requiring signatures
- **THEN** new intents require signing while earlier unsigned publications remain identifiable and downloadable under their original contract
- **AND** an offline workflow requiring a trusted signature rejects those unsigned packages

### Requirement: Signing support has mandatory interoperability evidence

Required CI acceptance SHALL verify Secret-backed signing through real Kubernetes
and S3-compatible publication, authorized retrieval, rotation/recovery, and offline
Cosign verification. Tests SHALL reject tampering, wrong trust, and unsigned
fallback. Public signing services and production keys SHALL NOT be required.
New live tests SHALL belong to the existing mandatory acceptance-group inventory.

#### Scenario: Validate the complete signing workflow

- **WHEN** CI runs the signing acceptance cases with disposable keys and storage
- **THEN** the downloaded archive verifies with pinned Cosign offline
- **AND** damaged evidence, missing keys, unauthorized requests, and interrupted publication exercise their defined failures
