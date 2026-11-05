# Spec Delta

## Purpose

Retain complete assessment packages in S3-compatible storage, authorize scoped
downloads through Kubernetes RBAC, and expire evidence under binding retention.

## ADDED Requirements

### Requirement: Centrally configured S3 backend

Konstapel SHALL support S3 as its first evidence backend, including configurable
compatible endpoints, bucket, region, and prefix. Configuration and credentials
SHALL be platform-controlled. Missing credentials, unsupported backend semantics,
or an unavailable bucket SHALL prevent ready publication with an explicit error.
Application requests SHALL NOT select arbitrary storage locations or credentials.

#### Scenario: Publish to compatible self-hosted storage

- **WHEN** the configured endpoint satisfies the documented backend contract
- **THEN** Konstapel can publish and retrieve packages through that endpoint
- **AND** namespace users cannot override the endpoint or inspect storage credentials

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
the owned package and related publication objects. OSCAL, raw evidence, and
packaged exception history SHALL share the package's retention. Cleanup SHALL
cover owned object versions and abandoned uploads where applicable. Unrelated
objects or separately retained packages SHALL NOT be deleted.

#### Scenario: An assessment package expires

- **WHEN** the recorded expiry is reached
- **THEN** new downloads are refused and Konstapel removes the owned package through retryable cleanup
- **AND** another package using the same source content retains its independent expiry

### Requirement: Cleanup failures and availability remain truthful

Konstapel SHALL distinguish expired-but-not-deleted, deletion-failed, unavailable,
corrupt, and accessible evidence. Failed cleanup SHALL retain ownership and expiry
records for retry. Delete acknowledgments alone SHALL NOT imply removal of all
owned retained versions. Missing or corrupt objects SHALL NOT be reported as
available or silently replaced with different evidence.

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
expiry. Cleanup records SHALL remain until owned storage is removed or a visible
administrative recovery action resolves the failure.

#### Scenario: Delete a binding with retained evidence

- **WHEN** a binding is removed before one of its packages expires
- **THEN** its historical package is retained until the recorded expiry
- **AND** cleanup remains scheduled independently of the deleted binding

### Requirement: Storage behavior has executable compatibility evidence

The backend SHALL provide documented compatibility tests for publication,
conditional creation, recovery, namespace authorization, integrity, and retention.
Tests SHALL cover the supported versioning modes and a real S3-compatible service.
Untested endpoint behavior SHALL NOT be represented as verified compatibility.

#### Scenario: Validate a deployment backend

- **WHEN** the documented compatibility workflow runs against a supported test endpoint
- **THEN** it demonstrates idempotent publication, authorized retrieval, and complete owned-object cleanup
- **AND** it retains results and removes only its test-owned objects and infrastructure
