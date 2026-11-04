# Konstapel

Konstapel is a compliance controller written in Go. It brings compliance intent
into the reconciliation loop, connecting NIST SP 800-53 controls to technical
policies, observed system state, and assessment evidence.

The project builds on OSCAL Compass's **compliance-to-policy-go v2** tooling,
using OSCAL as the foundation for expressing compliance requirements and
preserving their connection to policy and assessment results. The intended
technical design is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Why it exists

Compliance requirements are often maintained separately from the systems they
describe. Documents capture intent, policies enforce selected requirements, and
evidence is assembled later. Those pieces drift apart as systems change.

Konstapel aims to keep that relationship explicit and continuously reconciled.
Operators should be able to understand which requirements apply, which policies
implement them, and what the available evidence says about their implementation.

## What we are building

A Kubernetes controller that turns an approved compliance scope into an ongoing
operational workflow:

1. Consume OSCAL content describing the applicable controls and their scope.
2. Use compliance-to-policy tooling to connect those controls to technical
   policies.
3. Reconcile the intended policy configuration through supported integrations.
4. Collect policy evaluation results and relate them to their source controls.
5. Expose coverage, findings, and evidence so people can assess the system and
   investigate changes.

Go is the implementation language for the controller. How it integrates with
compliance-to-policy will be established through technical validation, respecting
the tooling's supported interfaces and runtime requirements.

## Initial focus

The initial compliance framework is **NIST SP 800-53**, with Revision 5 as the
starting point. The first implementation should demonstrate a complete path
from a scoped set of controls to policies and traceable assessment evidence.

The initial baseline, control subset, policy engine, and deployment assumptions
remain to be selected. They should follow from a concrete use case and verified
tooling capabilities.

## Principles

- **Traceability:** preserve the relationship between controls, policies,
  evaluated resources, and evidence.
- **Honest coverage:** distinguish supported, unsupported, unevaluated, and
  failing requirements. Missing evidence must remain visible.
- **Continuous reconciliation:** respond to changes in compliance intent,
  policy configuration, and observed state.
- **Standards first:** build on OSCAL and OSCAL Compass capabilities, extending
  them where necessary.
- **Clear boundaries:** technical checks provide evidence for an assessment.
  Organizational, procedural, and human judgments remain part of compliance.

## What success looks like

For the initial supported scope, an operator can select the applicable controls,
see the policies associated with them, and inspect current findings with enough
context to trace each result back to its requirement. Changes in scope or system
state lead to updated results, with gaps and failures clearly reported.

Konstapel should make compliance work repeatable, inspectable, and useful in
day-to-day operations. It does not claim that passing automated checks establishes
compliance with all of NIST SP 800-53 or grants an authorization to operate.
