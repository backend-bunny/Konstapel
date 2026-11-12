# Proposal

## Why

Policy content currently ships with the assessment prototype, while the new
ComplianceProfile API already pins a bundle name and digest. Administrators need
to release and adopt official or organization-authored policies independently of
controller and Helm releases, with verifiable content and explicit publisher trust.

## What Changes

- Define a versioned Konstapel bundle payload using standard OCI distribution
  and the existing OSCAL/C2P mapping conventions. Each release is self-contained:
  policies, mappings, pinned NIST content, provenance, licenses, and tests.
- Publish independently versioned, signed OCI bundles with build provenance and
  immutable release identities. Bundle versions do not follow the aligned
  controller/CRD chart versions.
- Resolve the existing profile bundle name through centrally managed repository,
  credential, and trust configuration; pin the OCI manifest with its digest.
- Retrieve content and verification metadata in the controller using maintained
  OCI and Cosign/Sigstore libraries. Support private registries with Konstapel's
  own Kubernetes Secret credentials, plus keyless and public-key verification.
  Credentials reach a token service on another origin (Docker Hub, GitLab)
  only through an explicit per-source allowlist of exact HTTPS origins.
- Validate content, compatibility, and current trust before use; cache verified
  content by digest and preserve existing applied policies when updates fail.
- Carry the exact bundle and verification identity into resolved content and
  assessment snapshots without replacing the targeting revision contract.

## Capabilities

### New Capabilities

- `policy-bundle-distribution`: Author, publish, trust, retrieve, and resolve
  self-contained policy releases independently of the controller lifecycle.

### Modified Capabilities

None. The assessment-loop content and traceability requirements remain intact.
This extends the transport behind the in-flight targeting and bundle plans.

## Impact

Implementation will add a bundle schema, packager, OCI/trust adapter, cache, and
independent publishing workflow. It will integrate with `internal/assessment`,
the targeting resolver/manager, deployment configuration, and evidence snapshots.
The merged `api/v1alpha1.BundleReference` name/digest fields and
`internal/targeting` contribution/revision contract remain authoritative.

The change owns transport and packaging, not new policy semantics. It consumes
the existing privileged-container content and the Linux hardening content when
that change lands; controller and assessment integration follow their owning
changes. Helm configuration integrates after rebasing onto the chart work.

Out of scope: OPA support, additional controls, runtime bundle dependencies,
automatic profile upgrades, kubelet image-volume/loader-Job retrieval, bundled
executables, new bundle CRDs, and coupling bundle releases to application releases.
