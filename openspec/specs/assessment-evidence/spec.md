# assessment-evidence Specification

## Purpose
Retain complete assessment packages in S3-compatible storage, authorize scoped
downloads through Kubernetes RBAC, and expire evidence under binding retention.

## Requirements

### Requirement: Centrally configured S3 backend

Konstapel SHALL expose cluster-scoped, platform-managed EvidenceDestination
resources in compliance.erenius.io/v1alpha1 for S3-compatible endpoint, bucket,
region, and prefix configuration. Credential Secret references SHALL be limited
to the controller namespace. Missing credentials, unavailable storage, or
unsupported backend semantics SHALL prevent ready publication with an explicit
error. Application requests SHALL NOT choose storage or credentials.

#### Scenario: Publish to compatible self-hosted storage

- **WHEN** the configured endpoint satisfies the documented backend contract
- **THEN** Konstapel can publish and retrieve packages through that endpoint
- **AND** namespace users cannot override the endpoint or inspect storage credentials

#### Scenario: An application team attempts to manage a destination

- **WHEN** an application identity tries to create or alter a destination, its status, or its credential references
- **THEN** authorization denies the action
- **AND** cross-namespace credential references are rejected by the API

### Requirement: Binding selection inherits one central default

Konstapel SHALL use one platform-selected default destination with an optional
ComplianceBinding override. References SHALL identify name and UID.
AssessmentRequests SHALL inherit the binding selection. Missing, mismatched,
unready, or retiring selections SHALL fail visibly without fallback. Destination
changes SHALL NOT alter policy enforcement or exception identity.

#### Scenario: Resolve default and explicit destinations

- **WHEN** runs start for bindings with and without a destination override
- **THEN** the former select their explicit destination and the latter select the central default
- **AND** a namespace request cannot bypass either choice

#### Scenario: An explicitly selected destination is unavailable

- **WHEN** a binding's destination is missing, unready, or has a different UID
- **THEN** its evidence work reports the selection failure without using the default
- **AND** policy enforcement, exceptions, and other bindings' valid destinations continue unaffected

### Requirement: Destination location is immutable and access can rotate

The API SHALL reject changes to a destination's endpoint, bucket, region, or
prefix. Credentials and CA trust SHALL remain rotatable, including during
retirement. A new location SHALL require a new destination and explicit reference
changes. Historical evidence SHALL retain its original destination UID and
location; name reuse SHALL NOT redirect it.

#### Scenario: Change location or rotate credentials

- **WHEN** an administrator edits an existing destination
- **THEN** location changes are rejected while valid credential and CA trust rotation is accepted
- **AND** rotation preserves historical reads and cleanup at the same location

#### Scenario: Recreate a destination name

- **WHEN** a destination name is reused with a new UID
- **THEN** old references do not resolve to the new resource
- **AND** retained or orphaned evidence is not automatically adopted even at the same bucket and prefix

### Requirement: Runs pin destinations before storage work

Konstapel SHALL resolve and durably pin destination UID and location in protected
run metadata when an AssessmentRun starts, before storage writes. Publication,
retry, download, and cleanup SHALL use that pin across restarts. Selection SHALL
be coordinated with retirement so accepted pins remain accounted for and losing
selections cannot write. Subsequent reference edits SHALL affect subsequent runs.

#### Scenario: Switch destinations during a run

- **WHEN** a binding override or central default changes after a run starts
- **THEN** that run uploads, retries, downloads, and retires evidence at its pinned destination
- **AND** a later run selects the new destination without moving the old package
- **AND** retention is still selected separately at first commit preparation

#### Scenario: Selection races with destination deletion

- **WHEN** run startup overlaps deletion, an interrupted status update, or a stale controller cache
- **THEN** a previously accepted pin remains protected and accounted for through restart
- **AND** a selection that loses to retirement performs no storage writes

### Requirement: Destination deletion retires outstanding obligations

Destination deletion SHALL default to Retire: reject new runs, permit pinned
runs to finish, and maintain authorized downloads and cleanup until obligations
end. A finalizer SHALL hold the destination while runs, uploads, packages, or
cleanup remain. Bindings SHALL report DestinationRetiring for evidence work
without changing enforcement. Status SHALL expose outstanding counts, latest
known retained expiry, and cleanup blockers.

#### Scenario: Delete a destination with retained evidence

- **WHEN** an administrator deletes a destination under the default policy
- **THEN** new runs selecting it are refused without fallback while previously pinned runs may complete
- **AND** existing packages remain downloadable until expiry and are cleaned up normally
- **AND** the destination finalizer remains until outstanding obligations are verified complete

#### Scenario: Retirement is blocked

- **WHEN** cleanup cannot complete because of an outage, missing credentials, or an object lock
- **THEN** status exposes the blocker and retains the destination and cleanup records for retry
- **AND** unfinished publication with unknown expiry is not treated as an empty destination

### Requirement: Explicit orphaning transfers storage responsibility

Platform administrators SHALL be able to select Orphan deletion, including
during retirement. Once deletion uses Orphan, Konstapel SHALL fence new storage
work, downloads, and cleanup across all workers and restarts. Remaining objects,
versions, and incomplete uploads SHALL be left to the operator even if storage
is unreachable. Already-dispatched operations SHALL be reported truthfully;
orphaning SHALL NOT imply remote cancellation or successful deletion.

#### Scenario: Orphan a destination whose backend is unreachable

- **WHEN** an authenticated administrator requests Orphan deletion with a reason
- **THEN** handoff can complete without contacting the affected backend
- **AND** publication, probes, downloads, retention, and abandoned-attempt cleanup stop issuing remote operations
- **AND** surviving run records retain original references, checksums, and expiry with an Orphaned disposition
- **AND** interrupted publication is not falsely marked successful and previously verified Deleted records remain Deleted
- **AND** durable handoff ends interrupted publication and releases its binding's active run slot

#### Scenario: Orphaning races with an in-flight operation

- **WHEN** an upload, commit, or delete request was dispatched before the handoff fence
- **THEN** Konstapel cancels and drains local work with bounded waits and records known or uncertain remote outcomes
- **AND** late responses cannot clear Orphaned, start compensating cleanup, or reactivate the destination
- **AND** already delivered download bytes are not claimed to be revoked

### Requirement: Orphan audit and ownership survive finalization

Orphan handoff SHALL record an authenticated actor, time, required reason, and
independent durable ownership inventory before releasing destination or run
finalizers. The inventory SHALL survive destination and run deletion and contain
no credential material. Finalization SHALL remain blocked if it cannot be saved.
Only explicit administrative removal SHALL discard the inventory after handoff.

#### Scenario: A run is already pending deletion

- **WHEN** its destination is orphaned while the run has a deletion timestamp
- **THEN** an independent protected record preserves destination and run UIDs, location, original receipt and expiry, known attempts, and uncertain operations before either finalizer releases
- **AND** deleting the run or destination cannot garbage-collect that record
- **AND** backend unavailability is recorded as incomplete knowledge rather than an empty inventory

#### Scenario: Audit persistence fails

- **WHEN** the handoff inventory cannot be durably saved
- **THEN** persistence failure retains finalizers and the storage fence for retry

#### Scenario: A caller forges audit identity

- **WHEN** a caller supplies a claimed actor in writable metadata
- **THEN** that claim cannot replace the identity captured from the authenticated administrative request
- **AND** unauthenticated or unauthorized requests cannot initiate orphan handoff

#### Scenario: Recover ownership after handoff

- **WHEN** an operator follows the documented orphaning and inventory-export commands
- **THEN** it can inspect remaining keys, versions, incomplete uploads, and uncertain operations for external recovery or cleanup
- **AND** documentation explains that original expiry no longer schedules Konstapel cleanup and manual finalizer removal bypasses this audited path

### Requirement: Legacy destinations migrate without rewriting history

Migration from file configuration and receipts lacking destination UID SHALL use
explicit administrator-approved mappings verified against historical location
data. It SHALL preserve committed bytes, references, checksums, and expiry.
Ambiguous records SHALL retain ownership and finalizers with visible blockers;
name matching or current defaults SHALL NOT infer historical ownership.

#### Scenario: Upgrade with retained evidence and incomplete uploads

- **WHEN** legacy writers are quiesced and verified mappings to destination UIDs are recorded
- **THEN** reads, retries, and cleanup resume against the mapped original locations without rewriting archives or commit manifests
- **AND** repeating migration preserves the same mapping and historical identity

#### Scenario: A legacy location cannot be verified

- **WHEN** preserved configuration and receipts cannot establish an unambiguous original location
- **THEN** affected work remains blocked for explicit recovery or audited orphan handoff
- **AND** unrelated destinations can operate without adopting the unresolved evidence

### Requirement: Complete and identifiable evidence packages

Each package SHALL identify its run, binding UID, cluster, authorization scope,
content revisions, file inventory, and checksums. Assessment packages SHALL include
validated OSCAL and all required scoped evidence references, including applicable
acceptance snapshots. Diagnostic packages SHALL identify export failure without
claiming successful OSCAL output. Packages SHALL remain interpretable without
live workload or exception resources.

#### Scenario: Inspect a downloaded assessment

- **WHEN** an authorized user downloads a published assessment package
- **THEN** its required local references resolve and its file checksums validate
- **AND** expired or deleted live exceptions remain explainable from packaged context

### Requirement: Publication commits only complete immutable packages

Publication SHALL become successful only after the complete validated package
and its publication metadata are durable and verified. Published bytes and
publication identity SHALL be immutable until retention cleanup. Retried or
concurrent attempts for the same run SHALL reconcile one publication; conflicting
content SHALL fail without overwriting an existing artifact.

#### Scenario: Upload is interrupted

- **WHEN** an upload stops before package publication completes
- **THEN** the run is not reported as published or offered for download
- **AND** retry recovers or cleans up its own incomplete upload

#### Scenario: The response is lost after commit

- **WHEN** storage accepted the publication but its response was lost
- **THEN** reconciliation recognizes the existing matching publication
- **AND** it preserves the original publication time, expiry, and content

### Requirement: Publication does not change assessment meaning

Publication status SHALL remain separate from evidence completeness and check
outcomes. Incomplete assessments and diagnostic snapshots SHALL be publishable
with their limitations intact. A successful upload SHALL NOT turn failure,
accepted risk, missing evidence, or an export error into passing compliance.

#### Scenario: Upload a snapshot with missing evidence

- **WHEN** an incomplete snapshot is successfully published
- **THEN** status reports successful publication and incomplete evidence separately
- **AND** the downloaded package retains its original missing-evidence explanation

### Requirement: Full downloads respect current Kubernetes authorization

Full package downloads SHALL authenticate the caller and authorize the requested
namespace request or platform run using current Kubernetes RBAC. Namespace access
SHALL be bound to the request and namespace identities and SHALL NOT grant access
to full-binding or sibling-namespace packages. Storage references alone SHALL NOT
authorize a download. Credentials and unscoped download capabilities SHALL NOT be
exposed in request status.

#### Scenario: A team downloads its evidence

- **WHEN** a caller has the required namespace request download permission
- **THEN** it receives that request's complete scoped package, including OSCAL and evidence
- **AND** the same permission does not permit a full-binding download

#### Scenario: Permission is revoked or the namespace is recreated

- **WHEN** a new download request lacks current RBAC authorization or refers to a different namespace UID
- **THEN** access is denied even if the caller knows the previous artifact reference

### Requirement: Namespace isolation includes package contents

The publisher SHALL validate a package's declared scope before exposing it to a
namespace download path. Mixed-scope raw reports, diagnostic messages, embedded
resources, and evidence links SHALL NOT bypass that boundary. Unsafe scope or
unresolved references SHALL block disclosure and remain visible as a scoped
publication or access error without leaking the excluded content.

#### Scenario: A package accidentally includes cluster-wide source data

- **WHEN** namespace package validation finds another namespace's results or a link to a full-binding artifact
- **THEN** the package cannot be published as namespace-accessible evidence
- **AND** the failure response does not disclose the excluded results

### Requirement: Per-binding retention is fixed at publication

Konstapel SHALL apply the binding's configured retention, defaulting to 2160h
(90 days), to scheduled and on-demand packages. The first successful publication
SHALL record its effective retention and a fixed expiry measured from publication.
Later retention changes SHALL apply only to new publications and SHALL NOT
shorten or extend an already published package's expiry.

#### Scenario: Shorten retention after publication

- **WHEN** a binding changes retention from 90 days to 30 days
- **THEN** existing published packages retain their recorded expiry
- **AND** subsequent publications use the new duration

#### Scenario: Retry an old publication under changed settings

- **WHEN** an already committed publication is recovered after retention changes
- **THEN** its original expiry is preserved rather than recalculated from retry time

### Requirement: Konstapel manages expiry cleanup

At expiry, Konstapel SHALL stop serving new downloads and reconcile deletion of
the owned package and related publication objects unless orphan handoff has
fenced the destination. OSCAL, raw evidence, and packaged exception history SHALL
share package retention. Cleanup SHALL cover owned versions and abandoned uploads.
Unrelated, separately retained, or explicitly orphaned objects SHALL NOT be deleted.

#### Scenario: An assessment package expires

- **WHEN** the recorded expiry is reached
- **THEN** new downloads are refused and Konstapel removes the owned package through retryable cleanup
- **AND** another package using the same source content retains its independent expiry

#### Scenario: Orphaned evidence reaches its original expiry

- **WHEN** an orphaned package reaches the expiry preserved in its receipt
- **THEN** run and destination cleanup workers leave its storage untouched
- **AND** a restart or new destination at the same location does not resume its cleanup

### Requirement: Cleanup failures and availability remain truthful

Konstapel SHALL distinguish expired-but-not-deleted, deletion-failed, unavailable,
corrupt, orphaned, and accessible evidence. Failed cleanup SHALL retain ownership
and expiry records for retry unless explicitly orphaned. Delete acknowledgments
SHALL NOT imply removal of all owned versions. Missing or corrupt objects SHALL
NOT be reported available or replaced. Orphaned evidence SHALL be unavailable
through managed downloads and SHALL NOT be reported as successfully deleted.

#### Scenario: Storage refuses deletion

- **WHEN** permissions or an object retention lock prevent cleanup
- **THEN** status records the failure and retains the cleanup record for retry
- **AND** Konstapel does not bypass the lock or claim deletion succeeded

#### Scenario: A published object disappears early

- **WHEN** a download or reconciliation discovers the object is missing before expiry
- **THEN** availability becomes explicitly unavailable without rewriting the assessment result

### Requirement: Retention outlives binding and request records

Published-package retention and cleanup identities SHALL survive binding or
request deletion, controller restart, and changes to the default storage
destination. Historical packages SHALL retain their original destination and
expiry. Cleanup records SHALL remain until owned storage is removed or an explicit
audited orphan handoff durably transfers responsibility.

#### Scenario: Delete a binding with retained evidence

- **WHEN** a binding is removed before one of its packages expires
- **THEN** its historical package is retained until the recorded expiry
- **AND** cleanup remains scheduled independently of the deleted binding

### Requirement: Storage behavior has executable compatibility evidence

The backend SHALL provide documented compatibility tests for publication,
conditional creation, recovery, namespace authorization, integrity, and retention.
Tests SHALL cover destination admission, selection, retirement, orphaning,
migration, supported versioning modes, and a real S3-compatible service.
Untested endpoint behavior SHALL NOT be represented as verified compatibility.

#### Scenario: Validate a deployment backend

- **WHEN** the documented compatibility workflow runs against a supported test endpoint
- **THEN** it demonstrates idempotent publication, authorized retrieval, and complete owned-object cleanup
- **AND** it retains results and removes only its test-owned objects and infrastructure

#### Scenario: Verify destination lifecycle through Kubernetes APIs

- **WHEN** the lifecycle acceptance workflow runs against a real API server and S3-compatible service
- **THEN** it proves immutable locations, protected credentials, UID pinning, rotation, normal retirement, and audited orphaning through the actual run APIs
- **AND** it exercises concurrent deletion, controller restart, missing audit persistence, and legacy upgrade without losing ownership or changing enforcement
- **AND** CI retains sanitized diagnostics and tears down its test-owned resources, including intentional orphan fixtures through explicit operator cleanup
