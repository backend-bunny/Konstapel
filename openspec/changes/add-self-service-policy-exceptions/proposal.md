# Proposal

## Why

Application teams need to accept bounded risks for their own workloads without
a central approval queue, while the platform retains control over which policies
are non-negotiable. Engine exemptions must remain visible as risk acceptance in
assessment evidence, including when a native report records a pass or skip.

## What Changes

- Add namespaced, self-service `ComplianceException` records for a selected logical
  policy and workload scope, with a reason and required expiry.
- Enforce profile-defined `Forbidden` or `SelfService` eligibility and maximum
  lifetime; capture the authenticated submitting or renewing identity.
- Translate eligible records into managed `policies.kyverno.io/v1`
  `PolicyException` resources without a manual approval step.
- Protect the native exception path with permissions and admission validation
  so application teams cannot bypass non-exemptable policy settings.
- Gate enablement on verified engine expiry during Konstapel downtime; resolve
  the cached-policy expiry gap identified in the starting Kyverno 1.19.2 source.
- Handle explicit renewal, expiry, revocation, scope changes, and policy revisions
  without silently broadening or indefinitely extending acceptance.
- Attach immutable acceptance context and lifecycle history to evaluation
  evidence and OSCAL output, preserving raw outcomes and coverage limits.

## Capabilities

### New Capabilities

- `policy-exceptions`: Apply authorized, time-limited workload exceptions and
  retain their risk-acceptance meaning throughout engine and assessment workflows.

### Modified Capabilities

None. The new capability consumes the targeting contract and extends the
assessment pipeline through explicit exception context.

## Impact

Adds a namespaced alpha CRD, admission validation and identity capture, an
exception reconciler, native-engine governance, evidence enrichment, and tests.
It depends on the profile/binding contract from `add-compliance-targeting-api`
and the report/OSCAL boundary from `prove-kyverno-v1-assessment-loop`.

Exception fixtures and lifecycle cases can be prepared independently. API and
runtime integration must use the merged prerequisite contracts. The current
assessment-loop task file and profile/binding schemas remain owned by their
respective agents. This change does not add permanent exceptions, central
approvals, cross-namespace delegation, or a full audit-history storage service;
acceptance snapshots accompany retained assessment artifacts.
