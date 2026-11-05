# Konstapel

Konstapel is a compliance controller being built in Go for Kubernetes, targeting
**NIST SP 800-53 Revision 5**. It builds on OSCAL Compass's
[compliance-to-policy-go v2](https://github.com/oscal-compass/compliance-to-policy-go)
to connect compliance requirements, technical policies, and assessment evidence.

The intended workflow is to:

1. Define the applicable controls through OSCAL content and authored
   control-to-policy mappings.
2. Generate and reconcile policies for a supported policy engine.
3. Collect evaluation results and produce traceable OSCAL Assessment Results.
4. Report coverage, findings, and missing or stale evidence as systems change.

## Project status

Konstapel is in the initial design phase. The repository currently contains the
project vision and architecture; controller implementation has not started.
The initial control scope and policy engine are still being selected.

## Documentation

- [Vision](vision.md): purpose, principles, and what success looks like.
- [Architecture](ARCHITECTURE.md): components, reconciliation flow, C2P-Go v2
  integration, and open design decisions.

## Assessment-loop prototype

The Go prototype delivers the shipped Kyverno v1 privileged-container check and
exports bounded AC-6 evidence through C2P v2. See the
[setup, acceptance and evidence guide](docs/integration/assessment-loop.md) and
[recorded validation results](docs/integration/validation-results.md).
