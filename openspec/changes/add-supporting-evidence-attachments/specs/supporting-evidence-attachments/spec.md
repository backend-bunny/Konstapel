# Spec Delta

## Purpose

Let platform operators retain and associate documentary evidence with selected
controls and binding scopes, preserving attribution, validity, confidentiality,
and historical copies without turning attachments into compliance verdicts.

## ADDED Requirements

### Requirement: Platform-managed evidence attachment records

Konstapel SHALL provide cluster-scoped EvidenceAttachment records in
`compliance.erenius.io/v1alpha1` and a platform file-submission workflow. Creating,
uploading, associating, or withdrawing attachments SHALL require dedicated
platform authority. Application-team submission SHALL remain outside the first
version, including for a binding that selects only that team's namespace.

#### Scenario: Platform submits a datacenter document

- **WHEN** an authorized platform operator registers and uploads the document
- **THEN** Konstapel tracks its immutable document identity, source metadata,
  validity, associations, and storage state

#### Scenario: Application credentials attempt submission

- **WHEN** a namespace application role attempts to create, upload, or associate
  a document
- **THEN** access is denied without widening the existing assessment-request or
  exception roles

### Requirement: Authenticated attribution is distinct from document claims

Each attachment SHALL record the authenticated registering actor and actual
uploader, submission time, document digest/size, and declared source. Caller
fields MUST NOT forge protected attribution. The original source URL SHALL be
optional informational provenance, never an instruction to fetch external data.
Successful intake SHALL attest storage/integrity only, not the truth of claims
or the authority of a named document author.

#### Scenario: A caller supplies another actor's identity

- **WHEN** a submitted manifest names a different registering user
- **THEN** protected attribution reflects the authenticated operation, and the
  declared document source remains distinguishable from that identity

### Requirement: Immutable content and retry-safe intake

Once committed, attachment content and its evidence-defining metadata SHALL be
immutable. Replacement documents or corrected validity/scope SHALL use new
attachment identities. Uploads SHALL verify expected size and SHA-256 before
availability. Retries SHALL converge on one committed document; conflicting or
partial bytes MUST NOT replace it or appear as available evidence.

#### Scenario: Upload response is lost

- **WHEN** a verified upload committed but its response was lost
- **THEN** retry returns the original commitment and dates for identical input
  without creating a different document under that identity

#### Scenario: Replacement bytes differ

- **WHEN** a caller uploads different bytes to a committed attachment
- **THEN** the operation fails with a conflict and preserves the original

### Requirement: Explicit catalog and binding associations

Associations SHALL identify catalog digests, valid control IDs and optional
statement IDs, and exact local binding identities. The same document SHALL be
usable for several explicitly named bindings. References SHALL be validated
against each binding's selected baseline; same-name replacements or catalog
changes MUST NOT silently inherit associations. A document's claimed physical
scope SHALL remain visible as a platform declaration.

#### Scenario: Shared facility evidence

- **WHEN** an operator associates one document with controls selected by two
  local bindings
- **THEN** each binding can show that supporting evidence while preserving the
  shared document identity and declared facility scope

#### Scenario: Binding recreation or catalog change

- **WHEN** a referenced binding is recreated or selects a different catalog
  revision
- **THEN** the old association does not apply automatically and current reports
  explain the mismatch without rewriting historical packages

### Requirement: Validity is explicit and independent of upload time

Every attachment SHALL require RFC3339 `validFrom` and `validUntil` with
`validFrom < validUntil`. At observation time T, temporal validity SHALL be
`validFrom <= T < validUntil`. Future and expired documents SHALL remain
identifiable. Uploading or copying the same document MUST NOT implicitly reset
its validity. These dates are declared documentary coverage, not technical
evaluation timestamps.

#### Scenario: End of the declared period

- **WHEN** the current time reaches `validUntil`
- **THEN** the current documentary context becomes expired without requiring an
  unrelated Kubernetes event
- **AND** historical snapshots retain their validity assessment at closure

#### Scenario: Old document is uploaded again

- **WHEN** the same document is submitted with its unchanged validity period
- **THEN** the new upload time cannot make expired evidence current

### Requirement: Storage uses configured S3 with verified ownership

Committed document bytes SHALL reside in the configured S3 backend with recorded
destination identity, owned keys/versions, size, checksum, and commitment time.
The controller SHALL select destinations and credentials centrally. CRDs MUST
NOT contain bulk files, credentials, or caller-selected storage locations.
Missing, corrupt, inaccessible, or uncommitted content SHALL be unavailable
rather than successfully attached.

#### Scenario: Upload or storage fails

- **WHEN** an upload is interrupted, its checksum differs, or S3 cannot confirm
  commitment
- **THEN** the record exposes pending/failure state and cannot provide available
  documentary evidence

### Requirement: Source-document retention preserves its validity window

Source-document expiry SHALL be fixed at first storage commitment as
`max(committedAt, validUntil) + retention`, using a positive central retention
duration defaulting to 2160h. Later setting changes or withdrawal MUST NOT shorten
that commitment. Assessment copies SHALL instead follow their own immutable
package retention. Documentary expiry MUST NOT itself delete retained bytes.

#### Scenario: Annual document and a shorter assessment retention

- **WHEN** a document remains valid beyond an assessment package's expiry
- **THEN** deleting that package does not delete the source document needed for
  later assessments

#### Scenario: A retained assessment outlives its source copy

- **WHEN** an authorized platform package retained its own document copy
- **THEN** source-document cleanup does not break that package's evidence

### Requirement: Document access is independently authorized

Document upload and download SHALL require current authentication and explicit
authorization separate from metadata/coverage access. Assessment-package access
containing document bytes SHALL also require document-read authority. Namespace
views SHALL expose only sanitized supporting context and MUST NOT include
platform document bytes, private source metadata, or usable storage/download
credentials. Authorization failure SHALL prevent disclosure.

#### Scenario: Reader can inspect a run but lacks document permission

- **WHEN** the reader requests a platform package containing protected attachments
- **THEN** the download is denied until document-read permission is also granted
  rather than returning the embedded documents through the run route

#### Scenario: A team reads inherited coverage

- **WHEN** its namespace assessment references platform supporting material
- **THEN** the package can show a sanitized availability/validity indication with
  restricted access, without the document, private title/source, or raw link

### Requirement: Documentary availability never changes technical conclusions

Attachment context SHALL preserve content availability, temporal validity,
association validity, withdrawal, and access restriction separately. It SHALL
contribute supporting material to coverage without changing expected technical
checks, findings, policy enforcement, or risk acceptance. Uploaded scanner output
SHALL remain opaque supporting material in this version, not imported findings.

#### Scenario: Valid physical-security evidence is available

- **WHEN** a current, associated document is committed
- **THEN** coverage can report documentary evidence available while retaining
  no automated assessment or control verdict for unsupported technical checks

### Requirement: Assessment capture freezes attachment context

Each run SHALL freeze relevant attachment identities, immutable metadata, and
associations for its scope, classify validity at closure, and record changes
during capture. Authorized platform packages SHALL contain verified independent
copies for documents represented as included evidence. Unavailable bytes or
changed context SHALL remain explicit; retries MUST NOT substitute newer
documents or broaden disclosure.

#### Scenario: Document is withdrawn during capture

- **WHEN** a captured attachment becomes withdrawn before the run closes
- **THEN** the package records the transition and does not describe it as
  unconditionally current supporting evidence

#### Scenario: Document storage is unavailable at capture

- **WHEN** a document cannot be retrieved and verified within the collection limit
- **THEN** the package records documentary unavailability without inventing
  bytes or changing independently observed technical results

### Requirement: Withdrawal and cleanup do not rewrite history

Deleting an attachment SHALL withdraw it from new current associations while a
durable cleanup record preserves retained ownership and expiry. Cleanup SHALL
remove only owned source objects and attempts, resume after restart, and report
retention locks or deletion failures. Existing immutable package copies SHALL
remain governed by their original retention and current download authorization.

#### Scenario: Record is deleted before retention expires

- **WHEN** an operator deletes a committed attachment
- **THEN** it stops contributing to new current coverage, while source bytes and
  cleanup metadata persist until the recorded retention permits deletion

### Requirement: Local development uses SeaweedFS through the S3 interface

The project SHALL document and provide a disposable SeaweedFS S3 environment for
local attachment development and integration checks, using recorded immutable
runtime pins and the production storage adapter. Tests SHALL verify the required
commit, checksum, readback, and cleanup semantics. Local compatibility MUST NOT
imply untested AWS, versioning, or Object Lock support.

#### Scenario: Run the local attachment workflow

- **WHEN** a developer starts the documented SeaweedFS fixture through the pinned
  development environment
- **THEN** registration, upload, authorized capture/download, expiry, and cleanup
  can be tested through its S3 endpoint, with task-owned resources removable

### Requirement: Attachment intake is bounded and stores passive files

Intake SHALL enforce configured size, concurrency, and time limits; verify bytes
before commitment; and clean abandoned attempts. Documents MUST NOT be executed,
rendered as trusted HTML, recursively fetched, or parsed into control verdicts.
Downloads SHALL use safe attachment disposition and avoid credential disclosure.

#### Scenario: Oversized or interrupted document transfer

- **WHEN** a transfer exceeds configured bounds or stops before commitment
- **THEN** it fails explicitly, leaves no available attachment, and retained
  staging is bounded and eligible for cleanup
