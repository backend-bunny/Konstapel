# Spec Delta

## Purpose

Give operators independently managed CRD and controller installations through
aligned OCI Helm releases whose lifecycle, prerequisites, and provenance can be
verified before use.

## ADDED Requirements

### Requirement: Independent chart releases

Konstapel SHALL provide `konstapel-crds` and `konstapel` charts for separate Helm
releases, installed in that order. Only the CRD chart SHALL own Konstapel CRDs.
The controller chart SHALL NOT include the CRD chart, Kyverno, or cert-manager
as an automatically installed dependency.

#### Scenario: Install the controller after its CRDs

- **WHEN** an operator installs the two charts as separate releases
- **THEN** the CRD release owns the definitions and the controller release owns its deployment resources
- **AND** existing Kyverno and cert-manager installations remain independently managed

### Requirement: Generated API definitions remain authoritative

The CRD chart SHALL package the generated `compliance.erenius.io` definitions
implemented in its source release, initially using `v1alpha1`. Packaged schemas
SHALL preserve the API owners' validation, defaults, scopes, and subresources.
An unimplemented capability SHALL NOT be represented by a placeholder CRD or
advertised as available merely because its planning artifacts exist.

#### Scenario: Detect drift in a packaged schema

- **WHEN** a packaged definition differs semantically from its authoritative generated API
- **THEN** chart validation fails before publication
- **AND** chart-specific ownership metadata does not justify changes to schema behavior

### Requirement: Aligned versions on every release

Both charts SHALL use the application release version for chart `version` and
`appVersion`. Every supported chart release SHALL publish both charts, including
releases with unchanged CRD schemas. Independent installation SHALL NOT introduce
an independently numbered CRD release stream.

#### Scenario: Release an application fix without schema changes

- **WHEN** Konstapel releases version X.Y.Z with unchanged CRD definitions
- **THEN** both charts are published at X.Y.Z and identify the same source release
- **AND** the CRD chart retains those unchanged definitions

### Requirement: Uninstall preserves API objects

Uninstalling either chart SHALL preserve Konstapel CRDs and all existing custom
resources, including their UIDs, spec, status, and finalizers. Normal chart
operations SHALL NOT delete or recreate CRDs as cleanup. CRD deletion SHALL
require a separate explicit administrator action outside chart uninstall.

#### Scenario: Uninstall and reinstall the CRD release

- **WHEN** an operator uninstalls `konstapel-crds` with existing custom resources
- **THEN** the definitions and instances remain present with unchanged identities and data
- **AND** the documented reinstall using the same release identity can resume management without deleting them

### Requirement: Explicit compatible schema upgrades

The CRD chart SHALL support explicit in-place upgrades before controller
upgrades. Supported upgrade paths SHALL preserve existing objects and specify
the compatible controller/schema combinations during transition and rollback.
Destructive schema changes and automatic schema downgrades SHALL NOT be presented
as supported routine Helm operations.

#### Scenario: Upgrade CRDs while the previous controller runs

- **WHEN** an operator follows a documented supported upgrade path
- **THEN** existing objects remain valid and retain their data and UIDs while CRDs upgrade first
- **AND** the previous controller remains compatible for the documented transition
- **AND** controller rollback is offered only for a tested compatible schema combination

### Requirement: Capability-specific Kyverno prerequisites

Konstapel SHALL discover the served resource versions, resource scopes, required
operations, and its access permissions needed by enabled capabilities. Policy
delivery SHALL require `policies.kyverno.io/v1` ValidatingPolicy. Assessment SHALL
require `wgpolicyk8s.io/v1alpha2` PolicyReport and ClusterPolicyReport. Exceptions
SHALL additionally require native v1 PolicyException and their existing runtime
compatibility and governance gates.

#### Scenario: An API group exists but a required resource does not

- **WHEN** Kyverno discovery serves the group but omits a required resource or serves an unsupported version or scope
- **THEN** the affected capability reports the precise incompatibility
- **AND** Konstapel neither installs engine CRDs nor substitutes legacy policy APIs

#### Scenario: Discovery or use is forbidden

- **WHEN** the service account lacks discovery or resource-operation permission
- **THEN** the condition distinguishes denied access from an absent API
- **AND** API presence alone is not reported as sufficient readiness

#### Scenario: Exceptions are unavailable

- **WHEN** native PolicyException is absent or the tested expiry/governance requirements are unmet
- **THEN** exceptions cannot activate
- **AND** independent policy delivery and assessment capabilities remain available when their own prerequisites hold

### Requirement: Dependency recovery without process failure

Missing or unavailable Kyverno prerequisites SHALL leave Konstapel running with
bounded retries and diagnostic Conditions on affected resources. Recovery SHALL
resume dependent watches and reconciliation without a controller restart.
Dependency failures SHALL NOT delete existing managed policies, bypass exception
authorization, or manufacture passing assessment results.

#### Scenario: Install Kyverno after Konstapel starts

- **WHEN** the required Kyverno APIs and permissions become available after controller startup
- **THEN** affected Conditions and reconciliation recover automatically
- **AND** the process and configuration-admission endpoints remain available while capability-dependent requests still enforce their authorization and readiness gates

#### Scenario: Reporting becomes unavailable

- **WHEN** report access fails while policy delivery remains available
- **THEN** assessment status exposes unavailable or stale evidence
- **AND** existing enforcement remains in place and independently supported operations continue

### Requirement: Managed certificates by default

The controller chart SHALL default to separately installed cert-manager for TLS
issuance, renewal, and admission-webhook CA injection. Certificate resources
SHALL cover the actual configured service identities. Missing issuance, expired
certificates, or invalid trust SHALL remain visible and SHALL NOT cause fallback
to plaintext or disabled admission validation.

#### Scenario: Renew a serving certificate

- **WHEN** cert-manager rotates a webhook or enabled download-service certificate
- **THEN** the service consumes the new certificate and its configured trust remains valid
- **AND** any temporary unavailability does not permit unauthenticated downloads or bypass protected API admission

### Requirement: Operator-managed TLS alternative

Operators SHALL be able to supply existing namespace-local TLS Secrets and
explicit webhook CA trust instead of cert-manager. This mode SHALL render no
cert-manager resources and SHALL preserve caller-owned Secrets. Missing keys,
invalid service identity, expiry, or CA mismatch SHALL prevent the affected TLS
service from becoming ready; certificate and trust rotation remain operator duties.

#### Scenario: Install without cert-manager

- **WHEN** the operator selects external certificates with valid Secrets and CA trust
- **THEN** the webhooks and enabled download service operate without cert-manager APIs
- **AND** chart upgrades and uninstall do not replace or delete the supplied Secrets

### Requirement: Deploy the real controller with bounded privileges

The controller chart SHALL run the implemented controller entry point from a
digest-pinned image and use the owning features' RBAC and admission contracts.
Defaults SHALL retain non-root execution, a read-only root filesystem, bounded
writable working storage, and no privilege escalation. Service health SHALL
distinguish serving readiness from engine and assessment readiness.

#### Scenario: Verify the packaged runtime

- **WHEN** the packaged chart is installed with its default runtime settings
- **THEN** the controller reconciles real Konstapel resources and can execute its required C2P provider
- **AND** the release fails validation if the image only supplies the prototype CLI or requires broader privileges than declared

### Requirement: Package the supported replica availability defaults

The controller chart SHALL default to two replicas, preferred separation across
nodes, a minAvailable 1 PodDisruptionBudget, and rolling updates with zero
unavailable and one surge replica. Explicit single-replica development SHALL
omit the default PDB. Services and probes SHALL consume the controller
availability contract without requiring a replica to hold leadership.

#### Scenario: Render production and development settings

- **WHEN** the chart is rendered with defaults or single-replica development values
- **THEN** replicas, scheduling, disruption protection and rollout settings match the selected mode
- **AND** service selectors include all ready installation replicas across supported image revisions

#### Scenario: Validate the replicated runtime before publication

- **WHEN** a functional controller chart is prepared for publication
- **THEN** the real enabled features pass the controller availability acceptance cases
- **AND** chart rendering or fixture services alone cannot establish that release gate

### Requirement: Sign and attest each OCI chart digest

Both charts SHALL be published to distinct GHCR OCI repositories. Each OCI
manifest digest SHALL carry its own keyless Cosign signature and verifiable build
provenance identifying the source revision, chart name/version, and build inputs.
The controller chart's evidence SHALL identify its default image digest. Image
signatures or signatures of a chart archive alone SHALL NOT substitute for this.

#### Scenario: Verify a chart before installing it

- **WHEN** an operator follows the release's verification procedure
- **THEN** the signature and provenance are checked against the expected repository/workflow identity and OIDC issuer
- **AND** the verified OCI digest identifies the exact chart package subsequently installed
- **AND** verifying the controller chart does not implicitly verify the CRD chart

### Requirement: Reject unverifiable publication

Chart publication SHALL verify the remote artifacts' signatures, provenance,
source revision, versions, and packaged contents before reporting release
success. Pull-request validation SHALL have no production publish or signing
authority. A missing or mismatched signature, subject, issuer, source, or artifact
digest SHALL fail verification rather than produce successful release evidence.

#### Scenario: Reject substituted provenance

- **WHEN** a chart has valid cryptography but the wrong source revision, workflow identity, or subject digest
- **THEN** verification fails and the release is not reported as complete
- **AND** diagnostic evidence identifies the mismatch without exposing credentials

### Requirement: Immutable and recoverable chart publication

Published chart versions SHALL NOT be overwritten with different contents.
Retries SHALL reuse the frozen chart packages or verified original artifacts.
A release SHALL be reported complete only when both aligned chart digests and
their evidence are verified. Partial publication SHALL remain visible and
recoverable without replacing an already published chart.

#### Scenario: Resume after publishing only the CRD chart

- **WHEN** publication fails before the controller chart is fully verified
- **THEN** the existing CRD chart version and digest remain unchanged
- **AND** a retry verifies that artifact and completes the matching controller artifact and evidence
- **AND** different bytes proposed for either existing version are rejected

### Requirement: Operator installation and lifecycle evidence

Release notes and CI summaries SHALL include both chart references, digests,
versions, verification commands, and the default controller image digest.
Documentation SHALL explain ordered installation, external prerequisites, TLS
modes, supported upgrades, retained-CRD reinstall, and runtime-uninstall effects
on admission governance and evidence retention processing.

#### Scenario: Follow the documented lifecycle

- **WHEN** an operator runs the documented verification, installation, upgrade, uninstall, and reinstall workflow
- **THEN** each step has a test-backed expected result and preserves retained CRD objects
- **AND** documentation distinguishes preserving API data from continuing controller services, exception governance, or storage cleanup
