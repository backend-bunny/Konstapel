# Proposal

## External-provider follow-up

The approved `add-external-assessment-providers` change consumes these shared
interfaces and adds separately Helm-installed provider services, OCI distribution,
a versioned remote protocol and an optional explicit scan-request capability.
This foundation remains in-tree and read-only: its collection, Generate and
GetResults paths never initiate scans. Completed work and current Kyverno behavior
remain unchanged. External registration and scan execution are follow-up scope,
not requirements to finish or archive this foundation. Coordinate capture and
evaluation compatibility at handoff; production Prowler/AWS scope remains separate.

## Why

C2P defines an executable plugin interface, but adding a Konstapel evidence source
still requires provider-specific changes across collection, captures, evaluation,
and export. Define and prove a small shared contract before implementing Trivy,
so Konstapel remains an OSCAL assessment controller consuming existing security
tooling rather than taking ownership of those tools.

## What Changes

- Define a code-registered, versioned assessment-provider descriptor: identity,
  supported checks/modes, parameter schemas, capture compatibility, required APIs,
  and read permissions. Bundles select installed providers, never executable code.
- Introduce narrow in-tree Go adapters for scoped inventory/collection and pure
  evaluation. Keep external access in collection and reuse the existing manager,
  scheduling, content resolution, publication, signing, retention, and downloads.
- Define provider-neutral capture/result boundaries, preserving source identity,
  freshness, completeness, raw outcomes, applicability, and scoped provenance.
- Connect current evaluation and offline C2P conversion to the same evaluator and
  frozen content. Preserve existing Kyverno behavior and retained capture readers.
- Add reusable conformance tests and a provider-authoring guide; prove the contract
  with the real Kyverno path and a test-only reporting adapter. A test adapter does
  not establish support for Trivy or any other external producer.
- Make this contract a prerequisite for Trivy runtime integration. Its producer
  compatibility research can proceed independently.
- Extend shared bundle content so signed bundles can define declarative checks
  for reporting-only providers, and connect bundle compatibility and binding
  resolution to the provider selection seam (owner decision 2026-11-27,
  group 6). This is one provider-neutral extension of the existing payload,
  consumed by Trivy and by registered external providers alike; it is not a
  second content format and does not depend on any real reporting provider.

No new runtime plugin marketplace, provider CRD, arbitrary bundle-selected binary,
scanner orchestration, remediation, mixed-provider binding, vulnerability-specific
exception API, or production Trivy/SPO integration is included. This is a separate
future change, not a newly imposed gate for the existing 0.3.0 release scope.

## Capabilities

### New Capabilities

- `assessment-providers`: Installed-provider registration, collection/evaluation
  boundaries, compatible capture/replay, and conformance required to add an
  assessment evidence source.

### Modified Capabilities

None. Existing targeting, assessment, evidence, and Kyverno guarantees remain in
force. This capability adds the provider contract; producer-specific extensions
remain with their own changes, including Trivy's existing targeting/assessment
deltas. It does not redefine their outcomes, authority, or publication lifecycle.

## Impact

Implementation will touch `internal/assessment`, `internal/collector`, provider
selection at targeting/content boundaries, the bundle payload and content
validation (`internal/bundle`, `internal/bundle/content`), manager capability/watch integration,
`cmd/konstapel-provider`, image provider manifests, and test fixtures. Add a focused
provider package only where needed; reuse existing shared types and interfaces.
The current C2P-Go v2 pin and plugin packaging remain authoritative. Document the
contract in `docs/assessment-providers.md` and link it from architecture/development
guides when implemented. No new public Taskfile wrappers or deployment services
are needed. Shared API/capture changes must coordinate with their owning features
and preserve supported packages; planning does not claim the contract exists yet.
