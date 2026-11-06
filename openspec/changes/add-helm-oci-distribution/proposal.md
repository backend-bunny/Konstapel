# Proposal

## Why

Konstapel needs a supported installation and upgrade path for its planned
controller, with CRD lifecycle managed independently of the running service.
Operators also need to verify the origin and exact contents of both Helm charts
with the same confidence as the existing signed container images.

## What Changes

- Publish separate `konstapel-crds` and `konstapel` Helm charts as OCI artifacts
  in GHCR. Install them as independent releases, CRDs first.
- Keep both chart versions aligned with `VERSION` and release-please, publishing
  both for every application release even when the CRD schemas are unchanged.
- Give each chart's OCI digest its own keyless Cosign signature and build
  provenance; verify published artifacts and include digests and verification
  commands in CI summaries and release notes.
- Package generated `compliance.erenius.io` CRDs in the CRD chart, support explicit
  upgrades, and preserve CRDs and their objects when either chart is uninstalled.
  Removing CRDs requires a separate administrator action.
- Keep Kyverno separately installed and managed. Discover required resource
  versions and permissions, report unavailable capabilities on affected
  resources, and recover without restarting Konstapel when prerequisites return.
- Use separately installed cert-manager by default for service certificates and
  webhook CA injection; support operator-managed TLS Secrets as an alternative.
- Install the controller with its generated RBAC, services, admission integration,
  probes, and a digest-pinned image. Keep engine readiness distinct from process
  health, configuration admission, and assessment completeness.
- Default to two controller replicas with preferred node separation, a
  minAvailable 1 disruption budget and zero-unavailable/one-surge rolling updates;
  provide single-replica development values without the default disruption budget.
  Consume the lifecycle and release gates from `add-controller-high-availability`.
- Exercise rendered charts and real install, upgrade, certificate rotation,
  dependency recovery, uninstall, and reinstall workflows before publication.
- Require Go black-box acceptance against the Helm-installed controller image
  in CI on relevant pull requests and pushes to `main`. Gate merges and chart
  publication on passing results for the tested source, chart archives, and
  image digest; retain diagnostics and clean up even when tests fail.

## Capabilities

### New Capabilities

- `helm-distribution`: Install, upgrade, and independently retain Konstapel CRDs
  through aligned, verifiable OCI Helm releases with external prerequisites.

### Modified Capabilities

None. The prototype's explicit-target CLI and disposable-cluster acceptance
workflow remain supported. This capability packages the planned controller and
adds its deployment contract.

## Impact

Adds `charts/konstapel-crds`, `charts/konstapel`, chart helpers/tests, installation
documentation, required CI acceptance, and chart publication integration with
the existing release and image workflows. Packages the merged controller entry
point in the existing image build and extends version checks and the small
public Task interface.
Controller integration consumes the manager, generated APIs/RBAC, admission
handlers, and download service owned by the existing changes.

Chart contracts, rendering fixtures, and publication helpers can start
independently. Functional release publication waits for the controller/API
implementation; optional exception and evidence features wait for their own
merged contracts and compatibility gates. This change does not author competing
CRD schemas, implement the controller's compliance logic, install Kyverno or
cert-manager, add multi-cluster management, or introduce independent chart
version streams.
