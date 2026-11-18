# Spec Delta

## ADDED Requirements

### Requirement: Signing recovery requests are dedicated and attributed

Konstapel SHALL provide a cluster-scoped EvidenceSigningRequest naming one
AssessmentRun by name and UID with a required reason. Its spec SHALL be
immutable. Admission SHALL record the authenticated requester and reject
forged attribution. Only the controller SHALL write its status, which SHALL
record progress, the terminal outcome, and the requester.

#### Scenario: Submit a recovery request with a forged requester

- **WHEN** an administrator creates a request whose requester names another user
- **THEN** the stored request records the authenticated administrator instead
- **AND** a request without a reason or with a malformed run reference is rejected

#### Scenario: Change a request after creation

- **WHEN** anyone edits the run reference, reason, or requester, or a non-controller identity writes status
- **THEN** admission or authorization rejects the change
- **AND** a terminal outcome recorded by the controller cannot be rewritten

### Requirement: Recovery authorization is separate and non-aggregated

Recovery SHALL need a dedicated ClusterRole that is not aggregated into
built-in roles and is not part of namespace or compliance-admin roles.
Requesting recovery SHALL NOT grant AssessmentRun status writes, signing
Secret access, or destination changes. A separate read-only role SHALL
expose requests and their status for audit. Requests SHALL outlive their run
without an owner reference; deletion SHALL require a separate administrator grant.

#### Scenario: A namespace team or general administrator requests recovery

- **WHEN** a holder of namespace assessment or exception roles, or of the compliance-admin role alone, creates a request
- **THEN** the API server denies it

#### Scenario: A recoverer tries to rewrite run status

- **WHEN** a holder of only the recoverer role patches an AssessmentRun status or reads a signing Secret
- **THEN** the API server denies it
- **AND** a holder of only the reader role can list requests but cannot create one

### Requirement: Recovery retries the retained archive under its original intent

A request SHALL only retry signing and publication of a run that ended
SigningFailed with a Required intent and retained evidence. It SHALL use the
staged archive whose digest the intent records, reuse a stored signature
that verifies under the intent's key, and otherwise sign with that key. It
SHALL NOT recollect evidence or change completeness, outcomes, or summary.

#### Scenario: Recover after the missing key Secret is restored

- **WHEN** the intent's key is installed again and an administrator requests recovery
- **THEN** the same archive is signed with the pinned key and committed with its signature
- **AND** the run's evidence summary, completeness, outcomes, and export kind are unchanged

#### Scenario: A verified signature is already stored

- **WHEN** a retained run already has a stored signature that verifies under its intent key
- **THEN** recovery commits that signature without reading any private key

#### Scenario: The destination policy changed after the failure

- **WHEN** the destination now has signing Disabled or a rotated key Secret
- **THEN** recovery still requires the run's original intent and key
- **AND** the evidence is never published unsigned or under the new key

### Requirement: Recovery never substitutes a signing key

Recovery SHALL accept only the key fingerprint the intent pinned. When no
key was pinned, it SHALL load only the intent's recorded Secret and require
the fingerprint stated in the request before pinning it. Any other key, a
conflicting commit, or a stored signature that does not verify SHALL end the
request without overwriting stored objects or the intent.

#### Scenario: The recorded Secret now holds another key

- **WHEN** the intent's Secret name holds a key whose fingerprint differs from the pinned one
- **THEN** the request fails with KeyMismatch and nothing is signed or committed

#### Scenario: The intent never pinned a key

- **WHEN** a request for such a run omits the expected fingerprint or states one the Secret does not hold
- **THEN** the request fails without pinning a key
- **AND** a request stating the Secret's actual fingerprint authorizes initial key selection, pins it once, and proceeds

### Requirement: Recovered publications keep their recorded expiry

A new recovery commit SHALL keep the signing-failure expiry and record its
actual commit time. Recovery SHALL NOT start at or after the failure expiry.
A new commit landing at or after that expiry SHALL never be served and SHALL
be deleted by retention. An existing matching commit SHALL instead retain
its original publication time and expiry, even if that expiry differs from
the failure record; adoption SHALL NOT rewrite the commit.

#### Scenario: Recover late in the retention period

- **WHEN** a run failed signing at closure with 90-day retention and is recovered on day 80
- **THEN** the publication is downloadable until day 90 from closure and then deleted
- **AND** its recorded publication time is day 80

#### Scenario: Request recovery after expiry

- **WHEN** a request is evaluated at or after the run's recorded expiry
- **THEN** it fails with Expired and nothing is signed, committed, or retained longer

#### Scenario: Adopt a commit whose response was lost

- **WHEN** recovery before the failure expiry finds a matching earlier commit with a later expiry
- **THEN** it adopts the commit's original publication time and expiry unchanged
- **AND** it does not create a new commit or recalculate retention

### Requirement: Concurrent recovery requests converge

At most one request SHALL hold a run's recovery at a time. Concurrent
requests, retries, and leader changes SHALL converge on one stored signature
and one commit. A request evaluated after a successful recovery SHALL succeed
idempotently, referencing that publication without further storage writes.

#### Scenario: Two administrators request recovery together

- **WHEN** two requests for the same run are created concurrently
- **THEN** exactly one signature object and one commit exist for the run
- **AND** both requests end successfully referencing the same publication

#### Scenario: The leader is lost during recovery

- **WHEN** the leader stops after storing the signature but before recording the commit
- **THEN** the successor resumes the same request and reuses the stored signature
- **AND** no second signature or commit is created

### Requirement: Recovery status converges across API writes

The recovered run SHALL be the durable source for idempotent status repair.
Before a recovery request succeeds, its matching namespace request SHALL
reflect Completed and the sanitized artifact reference. Transient status
write failures SHALL retry, including after the attempt deadline. Missing or
recreated namespace requests SHALL NOT be recreated or overwritten.

#### Scenario: Crash between success status writes

- **WHEN** the controller stops after updating the run or namespace request but before completing the recovery request
- **THEN** its successor repairs the remaining matching statuses from the recovered run, even after the attempt deadline
- **AND** it neither signs again nor rewrites the commit

### Requirement: Unrecoverable evidence ends explicitly

A request SHALL end with an explicit terminal outcome, reviving nothing,
when its run is missing, recreated, being deleted, not a retained signing
failure, expired, or orphaned, or its staged archive is lost or differs.
Failing within the bounded attempt window SHALL leave the run's retained
failure unchanged so that a new request can try again.

#### Scenario: Recover evidence of a deleted or recreated run

- **WHEN** the named run is being deleted or exists only with a different UID
- **THEN** the request fails with RunDeleting or RunNotFound and nothing is published

#### Scenario: Recover evidence after an orphan handoff or capture loss

- **WHEN** the run's destination was handed off, or its staged archive is missing or has another digest
- **THEN** the request fails with Orphaned or EvidenceLost and issues no storage write

#### Scenario: The key is still unavailable

- **WHEN** the intent's key cannot be loaded until the attempt deadline
- **THEN** the request fails with SigningFailed and the run keeps its original retained failure and expiry

### Requirement: Recovered publications follow the normal access contract

After recovery the run SHALL be Completed with a committed signed publication, and
downloads SHALL use the existing authorization, scope, expiry, orphan, and
pair-verification rules. A namespace request SHALL receive only the existing
sanitized status. The run SHALL record which request recovered it, and
metrics SHALL use only bounded phase and reason labels.

#### Scenario: Download a recovered namespace package

- **WHEN** the team authorized for the namespace request downloads after recovery
- **THEN** it receives the pair-verified archive and signature
- **AND** the request status names no administrator, Secret, or recovery reason

### Requirement: Signing recovery has mandatory acceptance evidence

Mandatory acceptance SHALL exercise recovery against a real API server and
the RustFS S3 fixture with disposable keys: offline Cosign verification of a
recovered package, concurrent requests, leader loss, expiry, orphaning, lost
archives, key mismatch, RBAC, and forged attribution. Deterministic tests
SHALL reject outbound requests beyond the required Kubernetes/S3 fixtures
and verify that recovery uses no keyless services or keyless bundle material.

#### Scenario: Validate recovery end to end

- **WHEN** CI runs the recovery acceptance cases
- **THEN** the recovered archive verifies offline with pinned Cosign and the original trusted key
- **AND** each defined failure ends with its terminal outcome and no unsigned publication
