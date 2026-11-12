# Spec Delta

## ADDED Requirements

### Requirement: Packages of OCI bundle runs use only their frozen bundle

An assessment run of an OCI bundle SHALL freeze the exact verified bytes of
the bundle its capture was resolved against, together with its name, version,
digests, source and verification context, when the run starts. Export,
replay and package verification SHALL use only that frozen content, and the
package SHALL carry it with proofs that bind it to the recorded manifest
digest. Content that cannot be frozen, a frozen copy that is lost or altered,
a capture naming another bundle, or a bundle the producer cannot export
SHALL produce an explicit Diagnostic package that identifies the bundle.
Vendored or other content SHALL NOT be substituted, and packages of the
vendored bundle SHALL remain unchanged.

#### Scenario: Export after the live content became unusable

- **WHEN** a run's bundle is evicted from the cache, its registry is unreachable, or its publisher trust is revoked after the run started
- **THEN** the run's package is exported from the frozen bundle and names its identity and verification context
- **AND** the package verifies offline against the recorded manifest digest

#### Scenario: Bundle content differs from the vendored content

- **WHEN** the run's bundle maps a check to a different control or ships a different catalog than the vendored content
- **THEN** the exported OSCAL contains the bundle's mapping and the package contains the bundle's catalog

#### Scenario: Bundle content cannot be frozen

- **WHEN** the run's bundle is not configured, untrusted, incompatible, or missing from cache and registry until collection closes
- **THEN** the package is a Diagnostic with reason ContentUnavailable and the classified detail
- **AND** it contains no OSCAL assessment documents
