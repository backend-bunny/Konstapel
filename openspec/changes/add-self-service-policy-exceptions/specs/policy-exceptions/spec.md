# Spec Delta

## Purpose

Let application teams accept time-limited risks for authorized workloads while
preserving centrally defined policy boundaries and traceable assessment evidence.

## ADDED Requirements

### Requirement: Namespace-bounded self-service acceptance

An application team authorized to manage ComplianceException resources in a
namespace SHALL be able to exempt selected workloads in that namespace from an
eligible logical policy without manual approval. Exception scope SHALL use
standard workload label selectors and MUST NOT reach another namespace.

#### Scenario: An eligible team creates an exception

- **WHEN** an authorized namespace user submits a valid exception for an applicable SelfService policy
- **THEN** Konstapel validates and activates it automatically once engine readiness is established
- **AND** no platform approval queue is required

#### Scenario: Identical workload labels exist elsewhere

- **WHEN** an exception matches workload labels also present in another namespace
- **THEN** its effect remains confined to the exception's own namespace
- **AND** unauthorized cross-namespace exception creation is rejected

### Requirement: Mandatory reason and authenticated attribution

Each acceptance and renewal SHALL have a nonblank reason, authenticated actor,
acceptance time, policy identity, workload scope, and expiry. Actor identity SHALL
come from an authorized API operation rather than caller-supplied attribution.
The recorded identity SHALL distinguish the actual authenticated principal from
any separately claimed human or ticket reference.

#### Scenario: Record an API acceptance

- **WHEN** a team creates or explicitly renews an exception
- **THEN** its acceptance snapshot contains the reason and authenticated principal
- **AND** the caller cannot forge or overwrite protected attribution fields

#### Scenario: Reject an unexplained exception

- **WHEN** the supplied reason is empty or only whitespace
- **THEN** the API rejects the operation without granting an exemption

### Requirement: Effective eligibility cannot be weakened

Exception activation SHALL require every applicable contribution for the logical
policy to permit SelfService. Any Forbidden contribution, unresolved eligibility,
or missing policy mapping SHALL prevent activation. Workload users SHALL NOT be
able to change central eligibility through their exception permissions.

#### Scenario: A non-negotiable policy also has a permissive binding

- **WHEN** overlapping bindings include both Forbidden and SelfService settings for a policy
- **THEN** the exception is ineligible and normal policy enforcement continues
- **AND** the reported reason identifies the restrictive contribution

### Requirement: Bounded lifetime and explicit renewal

An exception SHALL have a future expiry within the shortest applicable central
maximum lifetime, measured from its acceptance or explicit renewal. Permanent
exceptions SHALL be rejected. Renewal SHALL revalidate current scope and policy
eligibility, record a new attributable acceptance, and require an explicit user
operation rather than automatic extension.

#### Scenario: A lifetime exceeds a central limit

- **WHEN** the requested expiry is absent, already elapsed, or beyond the effective maximum lifetime
- **THEN** the operation is rejected without creating or extending an exemption

#### Scenario: A team renews an expiring exception

- **WHEN** an authorized user explicitly renews with a valid expiry and reason
- **THEN** current eligibility is rechecked and a new acceptance snapshot is recorded
- **AND** the previous snapshot remains distinguishable from the renewal

### Requirement: Controlled native Kyverno exceptions

Konstapel SHALL realize active acceptances through managed
`policies.kyverno.io/v1` PolicyException resources with bounded namespace/workload
scope and expiry. Application teams SHALL NOT be able to bypass governance by
directly creating or modifying native exceptions in engine-enabled namespaces.
Native exceptions SHALL reference only the authorized managed policy instances.

#### Scenario: A workload user attempts a native bypass

- **WHEN** application credentials attempt to create, widen, or alter a native exception that could affect a managed policy
- **THEN** authorization or admission validation rejects the attempt
- **AND** the non-negotiable policy remains enforced

#### Scenario: A native exception has been rendered

- **WHEN** Konstapel activates a valid acceptance
- **THEN** its native exception references the acceptance identity and exact authorized policy instances
- **AND** its namespace condition and expiry cannot be broader than the acceptance

### Requirement: Expiry and revocation restore enforcement

Expired, deleted, revoked, or newly ineligible acceptances SHALL cease granting
exemptions and trigger cleanup of their native resources. Status SHALL distinguish
desired revocation from observed engine state and SHALL NOT claim completion
while stale native exceptions remain effective. Withdrawal SHALL NOT itself
delete or stop an existing workload.

#### Scenario: An exception expires

- **WHEN** its expiry is reached
- **THEN** new violating requests no longer receive that exception's permission
- **AND** background evidence and lifecycle status subsequently reflect its expiry
- **AND** previously admitted workloads are not automatically removed by Konstapel

#### Scenario: Central eligibility becomes Forbidden

- **WHEN** the controller observes a new restrictive configuration
- **THEN** affected acceptances stop being eligible and their native grants are withdrawn
- **AND** reconciliation reports pending withdrawal until the engine state is confirmed

#### Scenario: Konstapel is unavailable at expiry

- **WHEN** an active exception expires while the Konstapel controller is stopped
- **THEN** the engine stops granting it without needing a Konstapel-triggered policy update
- **AND** capability enablement is blocked on runtimes that cannot demonstrate this behavior

### Requirement: Acceptance does not silently expand

An acceptance SHALL bind to the resolved policy/configuration identities present
when it is made. A new policy revision, additional binding contribution, or wider
workload scope SHALL NOT inherit acceptance automatically. Renewal or a new
acceptance SHALL be required after revalidation, and unrelated policies SHALL
continue to apply.

#### Scenario: Policy content changes after acceptance

- **WHEN** a selected policy instance changes to a revision outside the recorded acceptance
- **THEN** the old acceptance does not exempt that new instance
- **AND** status explains the need for renewed acceptance

#### Scenario: Another policy still denies the workload

- **WHEN** an exception covers one policy but the workload violates another applicable Deny policy
- **THEN** the other policy still rejects the request

### Requirement: Evaluation and risk acceptance remain distinct

Assessment evidence SHALL retain the raw engine outcome and separately identify
whether an authorized acceptance applied at evaluation time. Accepted exemptions
MUST NOT be counted as ordinary unexcepted passes or full control satisfaction.
A skip or exception name without a resolvable acceptance SHALL NOT establish
accepted risk, and skipped evaluation SHALL NOT fabricate an underlying failure.

#### Scenario: Kyverno reports a skip caused by an active exception

- **WHEN** the report can be linked to a valid acceptance at evaluation time
- **THEN** output preserves the skip and records self-accepted risk with its reason and identity
- **AND** it does not invent a failing baseline evaluation that was never performed

#### Scenario: A report records pass with exception context

- **WHEN** an engine reports pass while an exception influenced its evaluation
- **THEN** output retains the raw pass and the exception context separately
- **AND** it does not count that result as evidence of an unexcepted passing check

#### Scenario: Exception attribution cannot be resolved

- **WHEN** the referenced acceptance or its evaluation-time validity is unavailable
- **THEN** output marks the attribution as unresolved rather than accepted or ordinarily compliant

### Requirement: Assessment artifacts retain acceptance history

Exported assessment artifacts SHALL retain an immutable snapshot or a resolvable
packaged reference containing acceptance identity, revision, actor, reason, scope,
policy revisions, and validity interval. Historical assessments SHALL remain
interpretable after live exception resources are renewed, expired, or deleted.

#### Scenario: Inspect evidence after expiry

- **WHEN** an operator opens a retained assessment artifact after the exception has expired or been removed
- **THEN** its recorded acceptance and evaluation-time validity can still be established
- **AND** current revocation does not rewrite the historical raw outcome
