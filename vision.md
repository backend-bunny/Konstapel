# Konstapel

Konstapel is a compliance controller written in Go. It brings compliance intent
into the reconciliation loop, connecting controls to technical policies,
vulnerability findings, observed system state, and assessment evidence. NIST
SP 800-53 is the first framework; the design should support other frameworks
available as OSCAL catalogs without framework-specific evaluation logic.

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
   policies and assessment checks.
3. Reconcile the intended policy configuration through supported integrations.
4. Collect policy evaluation and scanner evidence and relate it to source controls.
5. Expose coverage, findings, and evidence so people can assess the system and
   investigate changes.

Go is the implementation language for the controller. C2P-Go v2 connects authored
mappings and provider results to OSCAL assessments; integrations must validate
their evidence semantics and preserve the tooling's runtime requirements.

## Initial focus

The initial compliance framework is **NIST SP 800-53**, with Revision 5 as the
starting point and **Moderate** as the initial baseline. Technical checks provide
partial evidence for selected controls, with unassessed obligations left visible.

The first policy engine is **Kyverno**, using `policies.kyverno.io/v1` resources.
Centrally managed profiles and bindings select namespaces and configure Audit or
Deny behavior; the policy engine performs enforcement. Initial deployment covers
Linux workloads in the controller's own cluster, with identities and evidence
boundaries designed to accommodate multiple clusters later. Windows is out of scope.

The planned next assessment integration is **Trivy Operator** for workload-image
vulnerabilities. It adds separate scan-coverage and vulnerability-exposure checks
through C2P, using dedicated Audit bindings. Trivy remains separately installed
and owns scanning and registry access; Konstapel reads its evidence. Vulnerability
admission blocking is deferred. See the
[Trivy assessment proposal](openspec/changes/add-trivy-vulnerability-assessment/proposal.md)
for the planned scope and implementation tasks.

## Principles

- **Traceability:** preserve the relationship between controls, policies,
  evaluated resources, and evidence.
- **Honest coverage:** distinguish supported, unsupported, unevaluated, and
  failing requirements. Missing, stale, or unattributable scan evidence must
  remain visible and cannot establish a clean result.
- **Governed self-service:** let application teams accept eligible risks with an
  authenticated reason and bounded expiry, within centrally controlled limits.
  Preserve findings and accepted risk separately; acceptance is not a pass.
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
