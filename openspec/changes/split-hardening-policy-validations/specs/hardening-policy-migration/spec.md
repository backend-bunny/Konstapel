# Spec Delta

## Purpose

Permit official hardening bundle revisions to produce independent check evidence
while preserving enforcement, attribution and safe migration of existing users.

## ADDED Requirements

### Requirement: Hardening validations have independent producer outcomes

The new hardening revision SHALL represent drop-ALL, allowed capability additions,
Pod seccomp type and effective container seccomp profiles as separate modern
Kyverno policies with one validation each. Each original validation SHALL retain
its expected observation and independently attributable outcome. Missing source
results SHALL NOT be inferred as passes or removed from the denominator.

#### Scenario: One sibling check fails

- **WHEN** exactly one check in a split pair fails for a stable in-scope subject
- **THEN** the failing and passing checks each have explicit attributable evidence
- **AND** neither becomes Missing solely because its sibling failed

### Requirement: Split policies preserve security and applicability

Splitting SHALL preserve the original validation expressions, variables, matching,
operations, container coverage, Linux/Windows applicability and exception inputs.
The conjunction of each pair SHALL preserve the original unexcepted admission
decision in Audit and Deny. The change SHALL NOT introduce unrelated policy
tightening, exclusions or new exception authority.

#### Scenario: Compare original and split admission decisions

- **WHEN** both-pass, first-fail, second-fail and both-fail cases exercise each pair
- **THEN** Deny rejects exactly the original violating combinations and Audit admits otherwise-valid requests
- **AND** Pods, supported templates, init containers and ephemeral updates retain their original scope

#### Scenario: Explicit Windows workload

- **WHEN** a workload explicitly declares Windows
- **THEN** it remains outside Linux coverage rather than becoming a passing Linux result

### Requirement: Bundle revisions preserve provenance and mapping identity

New policies SHALL have explicit logical IDs and traceable mappings from old
policy/validation identities. Authored OSCAL mappings, inventories, checksums,
variant derivation and license material SHALL match the new revision. Shared
control mappings SHALL NOT multiply control credit. Published old digests and
their retained captures SHALL retain their original interpretation.

#### Scenario: Replay an old package after bundle upgrade

- **WHEN** a retained package uses the original multi-validation revision
- **THEN** replay uses its frozen content and original identities, preserving missing observations
- **AND** new mappings do not rewrite the historical result

#### Scenario: Replay a retained run without substituting current content

- **WHEN** a retained OCI assessment package is replayed after the split revision exists
- **THEN** replay reads only the package's frozen member content, never current vendored or OCI content
- **AND** a missing or unverifiable frozen member is a blocking diagnostic, not a fallback to other content

### Requirement: Migration preserves enforcement until replacements are ready

Migration SHALL explicitly update bundle pins and old-ID selections to the
replacement pairs. Old enforcing contributions SHALL remain until all required
replacements are ready; a partial replacement SHALL NOT create an enforcement
gap. Generated resources SHALL remain controller-owned. Old IDs SHALL NOT
silently resolve to only part of their original behavior.

#### Scenario: Only one replacement becomes ready

- **WHEN** an administrator migrates an enforcing old policy to its replacement pair
- **THEN** the documented migration retains the old enforcing contribution until both replacements are ready
- **AND** a failed migration can retain or restore the original pin without manual engine-policy edits

### Requirement: Exceptions do not silently transfer across split identities

Migration SHALL document eligibility and acceptance consequences for new policy
IDs and revisions. Original exception inputs SHALL retain their meaning, but
acceptances SHALL NOT automatically authorize newly identified contributions.
Non-negotiable settings and lifetime limits SHALL remain restrictive. Native
exception behavior SHALL not be claimed validated when upstream support is absent.

#### Scenario: An old acceptance exists during migration

- **WHEN** its policy is replaced by two new identities
- **THEN** new contributions require acceptance under the existing revision rules
- **AND** no automatic waiver broadens scope or exempts unrelated checks

### Requirement: Live acceptance verifies all split outcomes and export

Required CI SHALL exercise all four outcome combinations for both pairs against
the supported Kyverno pin using shipped rendered variants, including pre-existing
subjects and OSCAL export. Tests SHALL verify check counts, attribution, scope,
freshness and mapping correctness. Other causes of incomplete evidence SHALL
remain visible.

#### Scenario: Export a stable mixed-outcome assessment

- **WHEN** the split bundle assesses pre-existing subjects with each outcome combination
- **THEN** its frozen package contains independent attributable outcomes for every selected split check
- **AND** absent, stale or changed-subject evidence still fails attribution instead of becoming pass

### Requirement: New bundle artifacts are independently versioned

The migration SHALL prepare a new immutable bundle revision through the existing
signed OCI release pipeline, including provenance and documented digest selection.
Old version tags SHALL NOT be overwritten. Production publication SHALL require
the repository's separate release authorization and remote artifact verification.

#### Scenario: Prepare the replacement bundle

- **WHEN** implementation validation completes
- **THEN** release inputs identify the tested content and required new revision
- **AND** users can retain the old pin until they explicitly adopt a verified new artifact

### Requirement: Vendored content stays on the original revision

The split revision SHALL ship only as a separately versioned OCI bundle. The
vendored content and its digest SHALL remain unchanged, and users SHALL obtain
independent outcomes only by explicitly selecting the new OCI revision.

#### Scenario: Vendored content stays on the original revision

- **WHEN** the split OCI revision is prepared
- **THEN** the vendored content, its checksums and its digest are byte-unchanged
- **AND** a profile pinning the vendored digest keeps the original policy identities and their documented sibling gaps
