# Proposal

## Why

Controller-produced assessments need durable, inspectable evidence after the
live cluster changes. S3 publishing must preserve complete packages, enforce
namespace access, and retire evidence under Konstapel's per-binding retention.

## What Changes

- Add S3 as the first evidence backend through a cluster-scoped, platform-managed
  `EvidenceDestination` CRD in `compliance.erenius.io/v1alpha1`, supporting compatible
  self-hosted storage and protected controller-namespace credential references.
- Select one central default, with an optional ComplianceBinding override.
  Assessment requests inherit that selection. Pin the destination UID and immutable
  location when a run starts; keep credentials and CA trust rotatable without
  redirecting historical evidence or falling back to another destination.
- Publish immutable packages containing OSCAL, scoped source evidence, mappings,
  provenance, and applicable exception snapshots. Store small summaries and
  durable publication references in Kubernetes.
- Mark publication successful only after the entire package and its commit
  manifest are durable and verified; make retries recover the same publication.
- Provide authenticated full-package downloads authorized through Kubernetes
  RBAC for a namespace request or a platform full-binding run.
- Enforce per-ComplianceBinding retention, defaulting to 90 days from successful
  publication, for both scheduled and on-demand packages.
- Freeze each published package's expiry. Later retention changes apply only to
  new publications; binding/request deletion does not erase retained history.
- Reconcile cleanup, retain failed-deletion diagnostics, and distinguish expired,
  missing, corrupt, and unpublished evidence from accessible packages.
- Retire deleted destinations gracefully: reject new runs, finish pinned work,
  preserve downloads, and retain finalizers until outstanding cleanup completes.
- Allow an explicit, audited administrator `Orphan` deletion policy. Stop managed
  storage work, preserve remaining objects and recovery metadata, mark evidence
  `Orphaned`, and transfer responsibility to the operator without claiming deletion.
- Migrate legacy file configuration and receipts explicitly, preserving committed
  bytes and refusing to infer destination ownership from reused names.

## Capabilities

### New Capabilities

- `assessment-evidence`: Publish, authorize access to, and retire immutable
  assessment evidence packages through a durable storage backend.

### Modified Capabilities

None. The local output and validation workflow of `kyverno-assessment-loop`
remains supported; S3 publication consumes the new controller package contract.

## Impact

Adds an S3 client adapter, package commit/recovery logic, publication and retention
reconciliation, an authenticated download service, backend fixtures/integration
tests, the destination CRD/controller and admission safeguards, durable orphan
inventories, and operator documentation. It consumes the assessment settings, scoped
package descriptor, and run/publication status types owned by
`add-continuous-assessments` rather than defining a second assessment API.

Backend fixtures and S3 protocol tests can start independently. Runtime wiring
waits for the merged shared-contract phase; final namespace and lifecycle tests
use the continuous-assessment implementation. Shared assessment API files remain
owned by that change; destination resources belong here and chart integration is
coordinated with the Helm change. Destination changes affect evidence handling,
not policy enforcement or exception identity. Other storage backends, a public
bucket, bucket provisioning, legal hold management, package relocation, automatic
orphan re-adoption, and a general evidence search service are outside scope.
