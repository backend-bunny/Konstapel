# Proposal

## Why

Konstapel needs a verified path from NIST SP 800-53 Rev. 5 Moderate requirements
to enforced Kubernetes policy and traceable OSCAL evidence. C2P-Go v2 includes a
Kyverno plugin, but its result adapter still depends on legacy policy types, so
support for `policies.kyverno.io/v1` must be established before expanding the
shipped policy bundle or committing to a controller API.

## What Changes

- Introduce a reproducible Go integration prototype for one target cluster,
  using pinned C2P-Go v2 and Kyverno dependencies.
- Vendor the official `disallow-privileged-containers` `ValidatingPolicy` and
  relevant upstream tests, retaining its source revision and license notices.
- Ship an authored OSCAL Component Definition linking this technical check to
  a verified requirement in the Moderate baseline, with explicit partial coverage.
- Configure policy delivery for audit or admission denial while leaving evaluation
  and enforcement to Kyverno. Exercise denial in the acceptance workflow.
- Adapt the C2P plugin boundary to accept the new policy API and its reports,
  preserving cluster, resource, policy, content revision, and observation identity.
- Demonstrate allowed and denied workload requests, background detection of an
  existing violation, and validated OSCAL Assessment Results. Missing evidence
  must remain distinguishable from a passing check.

## Capabilities

### New Capabilities

- `kyverno-assessment-loop`: Deliver configured Kyverno policies and turn their
  evaluation results into traceable, bounded OSCAL evidence for selected controls.

### Modified Capabilities

None. The project has no existing capability specifications.

## Impact

This introduces the first Go module, a minimal integration runner, a modern
Kyverno result adapter, vendored policy content, OSCAL mappings, and repeatable
tests. It depends on Kubernetes, Kyverno's `policies.kyverno.io/v1` API, the
C2P-Go v2 plugin interface, and versioned NIST OSCAL content.

The first target is the cluster in which Konstapel will run. Explicit target
identity and cluster-scoped clients preserve a path to future multi-cluster
operation. This milestone does not define production CRDs, deploy a full
controller, manage remote clusters, implement automatic workload remediation,
or provide complete Moderate coverage. It establishes the integration contract
those later changes can build on.
