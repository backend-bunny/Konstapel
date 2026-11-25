# Spec Delta

## ADDED Requirements

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
