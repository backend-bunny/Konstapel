# Proposal

## Why

Issue [#358](https://github.com/backend-bunny/Konstapel/issues/358) shows official
bundles resolving while engine delivery remains ReplacementPending because
Kyverno lacks ephemeral-container permissions. Acceptance installs these grants,
but production guidance and binding diagnostics do not make the prerequisite clear.

## What Changes

- Expose bounded, policy-attributed Kyverno readiness condition details through
  the binding's existing EngineReady diagnostic without changing readiness rules.
- Provide an operator-applied production RBAC example and documented permission
  matrix for admission/reporting, Audit/Deny and ephemeral-container updates.
- Test missing grants, actionable diagnostics and recovery after operator repair
  using a real supported Kyverno installation.
- Preserve external engine ownership: Konstapel never silently grants permissions
  to Kyverno or relaxes enforcement while diagnosing a failure.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `compliance-targeting`: Add actionable engine-prerequisite diagnostics,
  operator-owned prerequisite guidance and verified recovery.

## Impact

Touches internal/targeting/deliver.go, internal/controller/binding.go and their
tests; installation and bundle Audit guides; a production RBAC example; live
acceptance fixture setup. Reuse existing Conditions, limits and Task workflows.
No new CRD, automatic privilege grants, engine installation or legacy API fallback.
Issue observations are reported evidence, not proof recovery already succeeded.
