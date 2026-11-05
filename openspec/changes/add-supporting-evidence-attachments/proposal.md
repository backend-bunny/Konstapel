# Proposal

## Why

Some selected controls, such as datacenter physical security, need evidence
Konstapel cannot obtain from workload policy checks. Platform operators need to
attach attributable documents to relevant controls and bindings while preserving
their validity, historical bytes, and access boundaries.

## What Changes

- Add platform-managed supporting-evidence records and an authenticated file
  intake/download workflow. Store immutable, checksummed copies in the configured
  S3 backend; original URLs are optional provenance, not storage dependencies.
- Associate documents explicitly with catalog/control/statement identities and
  one or more binding identities. Record source, authenticated submission,
  declared scope, and required validity start/end times.
- Separate documentary validity from storage retention. Reconciliation exposes
  pending, available, unavailable, expired, and withdrawn context without making
  document upload or re-upload a compliance pass or fresh technical evaluation.
- Integrate sanitized attachment context into control coverage. Include document
  copies only in authorized platform assessment packages, with independent
  package retention and explicit restrictions in namespace projections.
- Reuse the S3 change's storage configuration, authorization infrastructure, and
  tested object semantics through an attachment-specific storage boundary.
  Do not manufacture assessment runs to store source documents.
- Use SeaweedFS's S3 endpoint for disposable local development and integration
  fixtures, with recorded versions, compatibility checks, and teardown.

## Capabilities

### New Capabilities

- `supporting-evidence-attachments`: Register, retain, authorize, and attribute
  documentary evidence supporting controls without recording control verdicts.

### Modified Capabilities

None. This change integrates the active coverage, assessment, S3, and deployment
contracts. Their existing technical outcome and exception semantics remain intact.

## Impact

Adds a `compliance.erenius.io/v1alpha1` EvidenceAttachment API, generated
CRD/RBAC/admission, platform CLI and authenticated transfer routes, attachment
reconciliation/storage, producer projection, tests, and operator documentation.
Shared publication/authentication or chart extensions must integrate with their
owners after rebasing; no parallel schema generator or S3 configuration is added.

The first version stores supplied documents as supporting material. It does not
interpret uploaded scanner reports as technical findings, verify the truth of a
document's claims, run a human assessment/approval workflow, grant exceptions,
or change policy enforcement. Cross-cluster inheritance is future work.

## Future Development

Namespace-scoped self-service attachments for application teams are explicitly
deferred. A later change must define namespace ownership, RBAC, quotas, upload
limits, and safe sharing before adding team submission or document access.
No first-version implementation task enables this capability.
