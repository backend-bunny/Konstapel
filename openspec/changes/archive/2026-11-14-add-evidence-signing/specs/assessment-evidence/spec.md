# Spec Delta

## Purpose

Extend the EvidenceDestination contract, owned by the archived
add-s3-evidence-publishing change, with the destination's signing policy:
signing configuration is access, not location, and rotates like credentials.
Absent signing configuration leaves existing destinations unchanged.

## MODIFIED Requirements

### Requirement: Destination location is immutable and access can rotate

The API SHALL reject changes to a destination's endpoint, bucket, region, or
prefix. Credentials, CA trust, and the evidence signing policy and key reference
SHALL remain changeable, including during retirement. A new location SHALL
require a new destination and explicit reference changes. Historical evidence
SHALL retain its original destination UID and location; name reuse SHALL NOT
redirect it. A destination without signing configuration SHALL keep its
existing specification and status unchanged.

#### Scenario: Change location or rotate credentials

- **WHEN** an administrator edits an existing destination
- **THEN** location changes are rejected while valid credential, CA trust, and signing key rotation is accepted
- **AND** rotation preserves historical reads and cleanup at the same location

#### Scenario: Recreate a destination name

- **WHEN** a destination name is reused with a new UID
- **THEN** old references do not resolve to the new resource
- **AND** retained or orphaned evidence is not automatically adopted even at the same bucket and prefix

#### Scenario: Leave signing unconfigured

- **WHEN** an existing destination has no signing configuration
- **THEN** the API adds no signing field to it and the controller adds no signing status or condition
- **AND** its publication, readiness, retention, and retirement behave as before
