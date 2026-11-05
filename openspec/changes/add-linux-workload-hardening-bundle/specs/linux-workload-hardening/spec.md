# Spec Delta

## Purpose

Provide a versioned set of Linux workload configuration policies and bounded
NIST Moderate assessment evidence, with explicit scope and recorded exceptions.

## ADDED Requirements

### Requirement: Identifiable modern Kyverno bundle

Konstapel SHALL ship the four named candidate policies as
`policies.kyverno.io/v1` ValidatingPolicy resources with immutable source
provenance, license material, relevant tests, and source/rendered checksums.
Local variants SHALL be distinguished from upstream originals and SHALL retain
stable logical check identities across rendering and binding instances.

#### Scenario: Inspect the shipped bundle

- **WHEN** an operator selects the bundle
- **THEN** it includes disallow-privilege-escalation, disallow-capabilities-strict, require-run-as-nonroot, and restrict-seccomp-strict
- **AND** each source revision, local change, checksum, and logical check identity is inspectable
- **AND** no legacy Kyverno policy resource is required

### Requirement: Explicit Linux assessment scope

The bundle SHALL evaluate Linux workload configuration and exclude explicit
Windows workloads from these checks. An omitted Pod OS declaration SHALL be
evaluated using the bundle's documented Linux-rule convention. Out-of-scope
Windows results SHALL NOT be counted as passing Linux coverage or accepted risk.

#### Scenario: An explicit Windows workload is encountered

- **WHEN** a Pod or controller template declares Windows as its OS
- **THEN** these Linux checks do not deny it
- **AND** reporting identifies it as outside the bundle's assessment scope

#### Scenario: A workload omits its OS declaration

- **WHEN** a Pod or template has no OS declaration
- **THEN** the Linux configuration checks apply
- **AND** documentation makes clear that this convention does not attest the observed node OS

### Requirement: Enforce the defined Linux settings

In Deny mode, the bundle SHALL reject Linux workloads that omit or enable
allowPrivilegeEscalation, omit dropping ALL capabilities, add capabilities other
than NET_BIND_SERVICE, fail the non-root flag requirement, or lack an allowed
seccomp profile type. Valid exceptions SHALL be handled through the separate
exception capability and SHALL NOT exempt unrelated policies.

#### Scenario: A workload satisfies all four checks

- **WHEN** every applicable container has allowPrivilegeEscalation false, drops ALL, adds only permitted capabilities, satisfies non-root inheritance, and uses an allowed seccomp type
- **THEN** these four policies allow the request

#### Scenario: An init or ephemeral container violates a setting

- **WHEN** a regular, init, or ephemeral container violates an applicable setting without a valid exception
- **THEN** the corresponding Deny policy rejects the request for its own policy-specific reason

### Requirement: Non-root has no automatic user-namespace bypass

Every non-exempt Linux container SHALL set runAsNonRoot true or inherit true
from its Pod; explicit false at Pod level SHALL fail the check. Setting hostUsers
false SHALL NOT bypass this requirement. A workload unable to satisfy it SHALL
need a valid explicit exception when central policy configuration permits one.

#### Scenario: User namespaces are enabled without non-root configuration

- **WHEN** a Linux workload sets hostUsers false and omits or disables the required non-root flag
- **THEN** the non-root Deny policy rejects it in the absence of a valid exception

#### Scenario: A recorded exception permits the non-root deviation

- **WHEN** an eligible workload has an active self-service exception for the non-root check
- **THEN** that check permits the scoped deviation
- **AND** assessment output records the accepted risk
- **AND** other applicable policies retain their enforcement

### Requirement: Preserve exact capability and seccomp semantics

The capabilities policy SHALL require drop ALL and allow only NET_BIND_SERVICE
to be added by default. The seccomp policy SHALL allow RuntimeDefault or Localhost,
require each container to set or inherit an allowed type, and reject an invalid
Pod-level type. Reported coverage SHALL describe these configuration checks
without implying validation of effective privileges or Localhost profile contents.

#### Scenario: An allowed capability is added without dropping defaults

- **WHEN** a container adds NET_BIND_SERVICE but does not drop ALL
- **THEN** the capabilities policy rejects the unexcepted request

#### Scenario: No seccomp profile can be inherited

- **WHEN** a non-exempt container and its Pod both omit an allowed seccomp type
- **THEN** the seccomp policy rejects the request

### Requirement: Targeting and engine modes remain authoritative

Bundle policy instances SHALL follow centrally resolved namespace scope and
Audit/Deny settings. Namespace label changes and overlapping bindings SHALL
follow the targeting contract, and exception eligibility SHALL follow the
exception contract. The bundle SHALL NOT silently add namespace exclusions or
weaken the configured mode.

#### Scenario: Production enforcement overlaps cluster-wide audit

- **WHEN** the same check has matching Audit and Deny contributions
- **THEN** an unexcepted violation is denied by the Deny contribution
- **AND** resulting evidence identifies the binding and rendered policy revisions

### Requirement: Bounded Moderate mappings and independent checks

Each check SHALL have authored mappings to verified statements in pinned NIST
Moderate content, with rationale and partial-coverage limits. Distinct checks
SHALL remain distinguishable when mapped to a shared control. Multiple passes,
policy exceptions, or out-of-scope workloads SHALL NOT imply full-control or
Moderate-baseline satisfaction.

#### Scenario: Several checks map to AC-6

- **WHEN** privilege escalation, capabilities, and non-root results are converted to OSCAL
- **THEN** their independent check identities and outcomes are preserved
- **AND** the control remains one control with multiple pieces of bounded evidence

### Requirement: Validate changed artifacts and live behavior

Acceptance SHALL exercise the shipped rendered variants rather than relying on
upstream research results. It SHALL cover workload templates, applicable updates,
background observations, the changed user-namespace behavior, exception lifecycle,
and OSCAL output. Unsupported runtime prerequisites SHALL be reported explicitly
and SHALL NOT count as successful validation.

#### Scenario: Run the expanded bundle acceptance suite

- **WHEN** acceptance runs on the documented supported Linux test environment
- **THEN** policy-specific admission checks and pre-existing-resource background checks produce the expected results
- **AND** explicit exceptions and their expiry remain visible in assessment evidence
- **AND** rendered checksums and test dependencies identify exactly what was tested

#### Scenario: Runtime behavior has not been validated

- **WHEN** only configuration or CLI evaluation has been exercised
- **THEN** the evidence describes that limited validation
- **AND** it does not claim observed UID, capability sets, privilege transitions, or syscall filtering
