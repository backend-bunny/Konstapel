# Proposal

## Why

Adding an independently maintained evidence source should not require rebuilding
Konstapel or granting its controller the source's credentials. Extend the shared
provider contract with independently installed services and a versioned protocol,
including an optional request for fresh evidence.

## What Changes

- Add administrator-owned AssessmentProvider registrations for authenticated,
  compatible external endpoints; retain the existing built-in Kyverno path.
- Define a versioned service protocol for capabilities, bounded collection,
  optional durable scan requests, and deterministic evaluation of frozen inputs.
- Run external providers in separate pods installed by platform operators through
  provider Helm charts and signed, digest-pinned OCI images. Konstapel does not
  install, upgrade, or execute provider binaries.
- Keep scheduling, scope authorization, OSCAL publication, signing, retention,
  and downloads in Konstapel. Providers own source access and scan execution.
- Provide a Go authoring kit, language-neutral protocol, reference reporting
  service and synthetic scan-worker example, with executable conformance tests.
- Document a future Prowler provider using temporary CLI Jobs and dedicated cloud
  identity, without requiring Prowler's full application stack.

The shared in-tree contract remains a prerequisite, not replaced work. Production
Prowler/AWS targeting, Trivy integration, moving Kyverno delivery to a remote
service, local executable loading, arbitrary bundle-selected code, and remediation
are outside this change. This is not a 0.3.0 release gate.

## Capabilities

### New Capabilities

- `external-assessment-providers`: Administrator registration, authenticated
  service execution, optional scan requests, compatible replay, independent
  distribution, and the authoring/conformance contract.

### Modified Capabilities

None of the main specs are redefined. Existing assessment scope and lifecycle
guarantees apply. The active `add-assessment-provider-contract` plan is clarified
so its read-only collection interfaces remain distinct from this optional request
protocol; remote selection is an explicit extension of its installed catalog.

## Impact

Consumes `internal/provider` descriptors, limits and conformance; integrates with
collector/content ownership, manager lifecycle and the existing C2P adapter.
Adds generated API/RBAC/chart wiring for registration and a remote client,
versioned protocol definitions, reference provider assets, and authoring docs.
Provider charts/images release independently of Konstapel; core and CRD charts
keep their existing aligned release contract. Cloud subject authorization and real
scanner compatibility remain separate prerequisite work for a production Prowler
integration.
