# Spec Delta

## Purpose

Let administrators adopt verifiable, self-contained policy content from trusted
publishers independently of Konstapel controller and Helm chart releases.

## ADDED Requirements

### Requirement: Independently versioned immutable releases

Each bundle SHALL have its own logical name and release version. Published
versions SHALL identify immutable OCI manifest digests independently of
application and chart versions. Publishing a new bundle SHALL NOT change any
profile's pinned digest automatically.

#### Scenario: Release policy content independently

- **WHEN** a publisher releases a new compatible bundle version
- **THEN** it can be adopted without releasing a new controller or Helm chart
- **AND** existing profiles continue selecting their original digest until explicitly changed

#### Scenario: Retry an existing version

- **WHEN** publication finds that its version already exists
- **THEN** it verifies and completes the original publication or reports a conflict
- **AND** it never overwrites that version with different content

### Requirement: Standard distribution and versioned payload

Bundles SHALL use standard OCI distribution with a documented artifact type and
a versioned Konstapel payload schema. The payload SHALL identify its name,
version, logical policies, parameter schemas, compatibility, file inventory,
and OSCAL entry points. Unsupported formats and inconsistent identities SHALL
be rejected before content is used.

#### Scenario: Inspect and validate a release

- **WHEN** an operator inspects a supported bundle by digest
- **THEN** its payload layout and schema can be validated without running Konstapel's controller
- **AND** policy identities and mapped checks resolve without depending on generated engine names

#### Scenario: Reject ambiguous content

- **WHEN** a bundle has an unsupported schema, duplicate logical policy identity, missing inventory entry, or mismatching file checksum
- **THEN** resolution reports invalid content and does not apply it

### Requirement: Self-contained content closure

Each bundle SHALL contain all policies, mappings, pinned catalog/profile content,
and schemas required to validate and render its supported checks. Content
references SHALL resolve within the bundle without downloading other bundles
or following external content URLs. Provenance links SHALL remain inspectable
without being treated as runtime dependencies.

#### Scenario: Resolve without further content downloads

- **WHEN** a complete bundle and its verification material have been obtained
- **THEN** content validation and rendering succeed with external content access disabled
- **AND** the resulting checks use the catalog and profile carried by that exact bundle

#### Scenario: Reject an external content dependency

- **WHEN** a required mapping, schema, or policy reference can only resolve outside the bundle
- **THEN** resolution reports incomplete content instead of fetching a moving external input

### Requirement: Traceable policy sources and bounded mappings

Bundles SHALL preserve upstream revisions, source checksums, local modifications,
applicable licenses and notices, and relevant policy tests. Mappings SHALL use
the existing OSCAL/C2P conventions with verified NIST Moderate references and
explicit coverage limits. Publishing or signing content SHALL NOT imply full
control or baseline compliance.

#### Scenario: Package the existing privileged-container policy

- **WHEN** that policy is packaged as a separately released bundle
- **THEN** its original source and local rendering remain distinguishable
- **AND** its AC-6 mapping retains the existing partial-evidence boundary

### Requirement: Central source selection and explicit digest pins

The existing profile bundle name and digest SHALL resolve through centrally
managed source configuration. The digest SHALL identify the OCI manifest,
not a tag, archive checksum, or rendered policy hash. Unconfigured sources,
payload name mismatches, and content not matching the pin SHALL be unresolved.

#### Scenario: Select an organization-authored bundle

- **WHEN** an administrator configures its source and a profile selects its name and manifest digest
- **THEN** resolution uses that repository and its centrally assigned trust and credentials
- **AND** the organization follows the same payload validation rules as an official publisher

#### Scenario: Change a tag or registry location

- **WHEN** a remote tag moves or an administrator changes the source to a mirror
- **THEN** the profile still requests exactly its pinned manifest digest
- **AND** neither change silently selects another bundle or revision

### Requirement: Private registry access using controller credentials

Konstapel SHALL retrieve bundle content and verification metadata using its own
registry client and centrally referenced Kubernetes registry-credential Secrets.
It SHALL support anonymous repositories and authenticated private repositories,
verified TLS and configured custom CAs. Credentials SHALL NOT appear in profiles,
status, evidence, or logs, and SHALL NOT be forwarded to unrelated origins; a
token service on another origin is related only when the source explicitly lists
it.

#### Scenario: Pull and verify from a private registry

- **WHEN** a source references valid credentials in the controller namespace
- **THEN** both the pinned bundle and its required verification artifacts can be retrieved
- **AND** no kubelet credential access, image volume, or loader Job is required

#### Scenario: Rotate or remove credentials

- **WHEN** a referenced Secret changes or becomes unavailable
- **THEN** subsequent registry requests use the current credentials or report a recoverable authentication failure
- **AND** errors contain no credential values and no anonymous bypass is used for a required missing credential

#### Scenario: Token service on another origin

- **WHEN** a registry's bearer challenge names a token realm on another origin than the registry
- **THEN** the credential is sent there only if that exact https origin is listed for the source, validated when the configuration loads
- **AND** only as an unredirected token request scoped to the source's own repository, with no anonymous retry if the exchange fails
- **AND** an unlisted, malformed or redirecting realm, or a request for another scope, fails without sending the credential

### Requirement: Explicit keyless and public-key publisher trust

Bundle acceptance SHALL require a valid signature for the pinned OCI subject
under a centrally configured publisher rule. Keyless rules SHALL verify the
configured issuer, signing identity, trusted roots, and signing-time evidence.
Public-key rules SHALL verify against configured keys. Bundles and application
teams SHALL NOT supply their own trusted verifier configuration.

#### Scenario: Verify either supported signing method

- **WHEN** a bundle is signed by an allowed keyless identity or an allowed public key
- **THEN** its signature can satisfy the applicable source rule
- **AND** invalid signatures, a different issuer or identity, or an unconfigured key cannot satisfy that rule

#### Scenario: A trusted root does not authorize every publisher

- **WHEN** a keyless rule trusts the public-good or a configured custom root but its issuer or identity is empty, a wildcard, or a pattern
- **THEN** the rule is rejected as invalid configuration
- **AND** no signature verifies under it, whichever identity the root certified

#### Scenario: Validate an expired keyless leaf certificate correctly

- **WHEN** a keyless certificate has expired since a recorded valid signing event
- **THEN** verification checks its validity at the authenticated signing time using trusted evidence
- **AND** it neither rejects solely because of present-day leaf expiry nor bypasses signing-time validation

### Requirement: Build provenance bound to the OCI subject

Published bundles SHALL carry verifiable build provenance identifying the source
revision, builder, bundle version, and content inputs for the exact OCI manifest
digest. Acceptance SHALL verify required provenance under central trust rules.
Missing, mismatched, or untrusted attestations SHALL NOT count as verified
publication or resolved content.

#### Scenario: Reject provenance for different bytes

- **WHEN** an otherwise signed bundle carries provenance for another digest, builder, or source than its configured and declared identity permits
- **THEN** verification fails before the bundle is used

#### Scenario: Organization-key provenance without a GitHub workflow

- **WHEN** an organization publisher whose configured builder is not a GitHub Actions workflow signs with its key and attests provenance naming that builder, the configured source repository, and the builder's own revision
- **THEN** the provenance can satisfy the rule without any GitHub workflow record
- **AND** missing provenance, another subject, builder or source, or a workflow record in place of the builder record fails verification

#### Scenario: GitHub publisher provenance names its workflow

- **WHEN** a publisher rule names a GitHub Actions workflow builder
- **THEN** the provenance must carry a workflow record whose repository, path, and ref are that builder's
- **AND** provenance without it, or with another workflow, fails verification

#### Scenario: Retry publication from a newer workflow revision

- **WHEN** a publication retry runs from a workflow revision newer than the selected release source
- **THEN** provenance distinguishes the actual content source from the workflow execution revision
- **AND** the release becomes complete only after remote content, signature, and required provenance verify

### Requirement: Compatibility before adoption

Bundle resolution SHALL verify supported payload and OSCAL versions, controller
and provider compatibility, logical policies and parameters, and required engine
capabilities before adoption. Initial runtime policies SHALL use modern Kyverno
APIs and namespaced Linux workload scope. Unsupported content SHALL NOT trigger
automatic engine installation or a fallback to legacy APIs.

#### Scenario: Encounter an unsupported requirement

- **WHEN** a bundle needs an unavailable provider, unsupported OSCAL/schema version, missing engine API, or cluster-scoped workload targeting
- **THEN** the affected profile or binding reports the incompatibility and does not adopt that content
- **AND** the controller remains available to reconcile supported configuration

#### Scenario: Reject a non-Linux workload scope

- **WHEN** a bundle's OS scope is empty, repeated, names an operating system other than Linux, or mixes Linux with another
- **THEN** the bundle is reported invalid or incompatible and is not adopted
- **AND** no operating system other than Linux is presented as supported

#### Scenario: Recover an engine prerequisite

- **WHEN** a required engine capability becomes available again
- **THEN** affected bindings can recover using the same pinned, verified content without a bundle republish

### Requirement: Content cannot replace central enforcement governance

Bundles SHALL supply declarative policy content only. They SHALL NOT install
executables, choose arbitrary provider binaries, grant exceptions, or override
the resolved namespace scope, Audit/Deny mode, ownership, or exception eligibility.
Rendered content SHALL retain stable logical identities under the existing
targeting and exception contracts.

#### Scenario: Preserve platform choices while rendering

- **WHEN** a trusted bundle contains a selected policy and its upstream examples
- **THEN** rendering uses the profile and binding's resolved configuration
- **AND** fixtures or example exceptions are never installed as desired resources

### Requirement: Bounded verification and safe materialization

Downloads, verification metadata, extraction, and cache use SHALL have documented
configurable resource limits. Content SHALL be isolated until all required checks
pass. Unsafe paths, links, duplicate archive paths, special files, malformed
inputs, and size-limit violations SHALL be rejected without affecting existing
verified content or unrelated files.

#### Scenario: Receive an unsafe or oversized archive

- **WHEN** a bundle attempts path traversal, escapes through a link, contains conflicting paths, or exceeds configured limits
- **THEN** materialization fails within its bounds
- **AND** no files outside its owned staging area are modified or offered to the provider

### Requirement: Cached bytes retain current trust checks

Konstapel SHALL cache content by immutable digest and validate its integrity
before reuse. Acceptance SHALL remain associated with the current source and
trust configuration, not merely the presence of cached files. Changed trust,
keys, source rules, or controller/provider compatibility SHALL invalidate
affected acceptance decisions and trigger re-evaluation.

#### Scenario: Reuse verified content during an outage

- **WHEN** the registry is unavailable and intact cached content and verification evidence still satisfy current configuration
- **THEN** resolution can use the pinned cache entry without fetching a different version
- **AND** a cache miss or missing required verification evidence remains unresolved

#### Scenario: Revoke a cached bundle's publisher

- **WHEN** the administrator removes its only matching trust rule or key
- **THEN** affected profiles become unresolved and the cached content cannot authorize new adoption
- **AND** existing applied instances remain explicitly stale until centrally replaced or removed

#### Scenario: Restart without a usable cache

- **WHEN** the controller restarts after its local cache is lost and the registry cannot be reached
- **THEN** it reports content unavailability and preserves existing owned engine instances
- **AND** it does not claim successful resolution based on remembered status alone

### Requirement: Preserve applied policies through failed updates

Bundle updates SHALL use the existing targeting revision and replacement
readiness contract. Download, verification, compatibility, or cache failures
SHALL NOT delete the last applied owned policies, activate partial replacement
content, or fall back to an unrequested digest. Initial resolution failure SHALL
remain visibly unresolved without inventing a successful deployment.

#### Scenario: Fail and recover an upgrade

- **WHEN** a profile is changed to a bundle digest whose retrieval or validation fails
- **THEN** the last applied revision remains identifiable and the desired revision reports its failure
- **AND** a later successful retry adopts replacements through the normal readiness transition

#### Scenario: Roll back a bundle selection

- **WHEN** an administrator restores a previously used digest in a newer profile generation
- **THEN** the existing revision algorithm creates the appropriate new enforcement revision
- **AND** old policy exceptions do not automatically authorize the new revision

### Requirement: Resolution and evidence preserve artifact identity

Resolution results and assessment snapshots SHALL preserve the selected bundle
name, version, OCI digest, source, mapping identity, and verification context.
Desired and applied revisions SHALL remain distinguishable. Evidence packages
SHALL retain their required content and provenance independently of the runtime
cache or continued registry availability.

#### Scenario: Export evidence and later evict content

- **WHEN** an assessment snapshots the applied bundle and its runtime cache entry is later evicted
- **THEN** the retained assessment still identifies and contains the inputs required by its evidence contract
- **AND** signature validity is not reported as proof of workload compliance

### Requirement: Reproducible publication and portable verification

The publishing workflow SHALL package and test the exact content it publishes,
preserve recoverable publication inputs, and emit digest-based verification
instructions. Mirroring SHALL preserve the OCI subject and required signature
and provenance artifacts. A source's registry compatibility SHALL be established
by tested retrieval and verification behavior.

#### Scenario: Mirror a bundle to a private registry

- **WHEN** an administrator copies the immutable bundle and its verification artifacts and configures the destination source
- **THEN** the same profile digest resolves under its configured publisher trust
- **AND** provenance continues identifying the original source and publisher

#### Scenario: Lose verification artifacts during a mirror or partial publish

- **WHEN** the destination has the content but lacks a required signature or provenance artifact
- **THEN** it does not become a trusted resolved bundle until the missing evidence is restored and verified
