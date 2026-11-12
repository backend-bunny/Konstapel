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

### Requirement: Assessment content is the applied content of each contribution

An assessment run SHALL capture the exact verified content of every bundle
an assessed contribution was applied from (the bundle identified by its
delivered engine policy), keyed by manifest digest, including each bundle's
digests, OSCAL content, mappings and verification context. It SHALL record the
desired bundle (the profile's selection) separately and report every
desired/applied difference explicitly. Applied content SHALL be frozen when the
run starts, under a cache lease, and a frozen copy SHALL be the only source for
export and replay. Overlapping revisions of a policy applied from different
bundles SHALL be packaged and reported under their own bundle identities and
SHALL NOT be collapsed into one. If any applied bundle cannot be recovered and
verified under the trust contract in force, the package SHALL be an explicit
Diagnostic that identifies it; desired or vendored content SHALL NOT be
substituted. Engine policy annotations and reports identify content but SHALL
NOT replace it.

#### Scenario: Update while the previous revision remains applied

- **WHEN** the profile selects bundle B while the binding's engine policy applied from bundle A is still the one enforcing
- **THEN** the run packages and exports A's frozen content for that contribution and records B as desired with the differences `DesiredNotApplied` B and `AppliedNotDesired` A
- **AND** the package still verifies and exports A after A's cache entry is evicted, its registry is lost, or its publisher trust is revoked

#### Scenario: Applied content is unavailable

- **WHEN** the applied bundle cannot be resolved and frozen by the time collection closes (evicted with the registry unreachable, untrusted, or incompatible)
- **THEN** the package is a Diagnostic with reason ContentUnavailable naming the applied bundle, even when the desired bundle is available
- **AND** it contains no OSCAL assessment documents and no other bundle's content

#### Scenario: Overlapping old and new revisions

- **WHEN** engine policies applied from bundles A and B are both delivered during one run
- **THEN** both bundles are frozen and packaged, and each contribution's observations are reported in a result derived from, and naming, its own bundle
