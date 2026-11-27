# compliance-targeting Specification

## Purpose

Let platform administrators centrally configure compliance content and resolve
namespace-targeted bindings into predictable, traceable policy enforcement.

## Requirements

### Requirement: Centrally administered profiles and bindings

Konstapel SHALL provide cluster-scoped ComplianceProfile and ComplianceBinding
resources. Profiles SHALL identify immutable bundle content and logical policy
settings; bindings SHALL reference a profile and declare namespace scope and
Audit or Deny mode. Application exception permissions SHALL NOT grant write
access to these centrally administered resources.

#### Scenario: An administrator configures a binding

- **WHEN** an authorized administrator creates a profile and binding
- **THEN** the binding resolves to the referenced profile and pinned content
- **AND** application-team credentials cannot modify either resource through their exception role

### Requirement: Standard and explicit namespace selectors

A binding SHALL require a Kubernetes LabelSelector evaluated against Namespace
labels. An explicit empty selector SHALL match all namespaces. Missing, null,
or invalid selectors SHALL be rejected. MatchLabels and matchExpressions SHALL
use standard Kubernetes conjunction and operator semantics.

#### Scenario: Select a namespace group

- **WHEN** a binding selects `environment: production`
- **THEN** only namespaces with that label match
- **AND** selection concerns Namespace labels rather than workload labels

#### Scenario: Select every namespace

- **WHEN** a binding declares `namespaceSelector: {}`
- **THEN** all existing and subsequently created namespaces match

#### Scenario: Reject ambiguous or invalid scope

- **WHEN** a binding omits its selector, sets it to null, or uses an invalid expression
- **THEN** admission rejects the resource with a field-specific explanation

### Requirement: Dynamic membership

Namespace creation, deletion, and label changes SHALL trigger recomputation of
affected binding membership. Matching namespaces SHALL receive the binding's
policy contribution; namespaces leaving scope SHALL lose that contribution
without losing contributions from other matching bindings.

#### Scenario: A namespace enters and leaves a selected group

- **WHEN** its labels change to match a binding and later cease matching
- **THEN** its desired policy set includes and later removes that binding's contribution
- **AND** membership and readiness status converge to the current namespace state

### Requirement: Cumulative enforcement

Audit and Deny bindings SHALL coexist. If an applicable check fails under any
matching Deny contribution, admission SHALL be rejected unless a valid exception
permits that contribution. Audit contributions SHALL NOT relax Deny contributions.
Resolution SHALL be independent of resource listing or creation order.

#### Scenario: Audit everywhere and deny in production

- **GIVEN** an Audit binding selects all namespaces and a Deny binding selects production
- **WHEN** an unexcepted workload violates the selected policy
- **THEN** production admission is denied while an otherwise-valid non-production request is admitted and audited
- **AND** both binding contributions remain identifiable in evidence

#### Scenario: Different policy parameters overlap

- **WHEN** matching bindings configure different constraints for the same logical policy
- **THEN** each contribution is evaluated under its own configuration
- **AND** satisfying one does not override a failing Deny contribution from another

### Requirement: Central exception eligibility contract

Each selected policy SHALL declare Forbidden or SelfService exception eligibility,
defaulting to Forbidden. SelfService SHALL require a positive maximum lifetime.
For a logical policy in a namespace, any matching Forbidden contribution SHALL
make self-service exceptions ineligible; otherwise the shortest matching maximum
lifetime SHALL apply.

#### Scenario: Resolve restrictive eligibility across bindings

- **WHEN** one matching profile permits SelfService and another forbids exceptions for the same policy
- **THEN** effective self-service eligibility is Forbidden, irrespective of Audit or Deny mode

#### Scenario: Resolve lifetime limits

- **WHEN** all matching contributions permit SelfService with different maximum lifetimes
- **THEN** the effective lifetime limit is the shortest
- **AND** the resolution identifies the contributing profile and binding revisions

### Requirement: Owned and traceable policy contributions

Generated policy instances SHALL identify their owning binding, logical policy,
profile revision, bundle digest, namespace scope, and target cluster. Removing a
binding SHALL withdraw only its contributions. Konstapel SHALL reject conflicts
with unmanaged engine resources rather than adopting or overwriting them.

#### Scenario: Remove one overlapping binding

- **WHEN** a binding is deleted
- **THEN** its owned engine policies are removed
- **AND** policies contributed by surviving bindings remain effective

#### Scenario: An engine policy name is already unmanaged

- **WHEN** delivery encounters an existing resource it cannot establish ownership of
- **THEN** it reports a conflict and leaves that resource unchanged

### Requirement: Resolution status is distinct from enforcement

Status SHALL expose observed configuration generations, resolved content and
target counts, resolution errors, and engine readiness separately from assessment
outcomes. Missing profiles, unavailable content, or stale generations SHALL NOT
be reported as ready enforcement. Zero matched namespaces SHALL NOT imply a
passing compliance assessment.

#### Scenario: A reference is unresolved

- **WHEN** a binding references a missing profile or unavailable pinned bundle
- **THEN** its status identifies the unresolved reference
- **AND** no ready or compliant status is inferred

#### Scenario: No namespace matches

- **WHEN** a valid selector matches zero namespaces
- **THEN** status reports zero targets explicitly and does not infer a compliance pass

### Requirement: Namespace targeting has a bounded resource scope

This capability SHALL target namespaced workload policies in the local cluster.
Namespace selectors SHALL NOT implicitly select cluster-scoped workload resources.
Unsupported resource scope SHALL produce an explicit resolution error rather
than silently extending enforcement to the whole cluster.

#### Scenario: A bundle introduces a cluster-scoped check

- **WHEN** a selected policy requires cluster-scoped workload evaluation
- **THEN** resolution reports that unsupported targeting scope
- **AND** it does not treat an empty namespace selector as authorization for that check

### Requirement: Pending engine readiness exposes actionable conditions

A binding blocked on owned Kyverno policies SHALL expose the failing readiness
condition type, reason and message with policy attribution through EngineReady
or a directly linked diagnostic. Diagnostics SHALL be bounded, deterministic
and safe for status display. Missing or malformed conditions SHALL remain
explicitly unknown. Diagnostic enrichment SHALL NOT change readiness or
replacement-retention decisions.

#### Scenario: Kyverno lacks ephemeral-container permissions

- **WHEN** a selected policy reports RBACPermissionsGranted False with missing pods/ephemeralcontainers verbs
- **THEN** the binding remains EngineReady False and exposes the missing permission with the policy identity
- **AND** Resolved can remain True without implying ready enforcement or passing evidence

#### Scenario: Many policies fail readiness

- **WHEN** policy diagnostics exceed the status budget
- **THEN** a bounded deterministic summary preserves an actionable failure and indicates omitted diagnostics with a documented inspection command
- **AND** missing, malformed or control-character-containing source messages cannot cause a reconcile failure or misleading ready status

### Requirement: Kyverno permission prerequisites are operator managed

Official bundle installation guidance SHALL provide a production RBAC example
and tested permission matrix separating admission and reporting controllers,
supported modes and ephemeral-container operations. Grants SHALL be justified
and limited to required resources and verbs. Konstapel SHALL NOT install or
expand Kyverno permissions automatically.

#### Scenario: Install with an existing Kyverno release

- **WHEN** an operator follows the installation or bundle Audit walkthrough
- **THEN** the guide identifies prerequisite grants, aggregation labels, verification commands and installation-specific identity substitutions
- **AND** Audit is not presented as permission-free when reporting still requires grants

### Requirement: Permission repair recovers through normal reconciliation

Required live acceptance SHALL start without the additional Kyverno grants,
observe an actionable binding failure, then apply documented operator grants
and verify ready policies and attributable evidence without restarting Konstapel.
The test SHALL distinguish permission repair from evidence freshness and scope
failures, and clean only test-owned grants.

#### Scenario: Repair missing grants

- **WHEN** the administrator supplies the required permissions to the same Kyverno installation
- **THEN** affected bindings recover through ordinary reconciliation and reports become usable
- **AND** Konstapel did not modify another controller's RBAC or withdraw retained enforcement

#### Scenario: Engine does not re-evaluate permissions after repair

- **WHEN** a current policy owned by the binding still reports RBACPermissionsGranted False or Unknown because the engine does not re-evaluate RBAC changes
- **THEN** Konstapel writes only a dedicated readiness-recheck annotation to that policy, at most once per step of a bounded backoff, conditional on the version it read
- **AND** it never changes the policy spec, rendered identity, revision, enforcement epoch, ownership or other metadata, never writes ready, unowned, retained or held policies, and stops once the policy is ready
