# Proposal

## Why

Konstapel needs a centrally managed Kubernetes configuration model for applying
compliance content to namespace groups. Explicit selectors and deterministic
overlap semantics let platform teams introduce enforcement gradually while
preserving a clear record of which policies apply to each workload.

## What Changes

- Add cluster-scoped `ComplianceProfile` and `ComplianceBinding` resources.
- Reference pinned policy bundles and bounded NIST Moderate mappings from profiles;
  declare per-policy exception eligibility and maximum self-service lifetime.
- Select Namespaces using Kubernetes `LabelSelector` semantics, with an explicit
  empty selector selecting all namespaces and a missing selector rejected.
- Support simultaneous Audit and Deny bindings. A failing applicable Deny policy
  rejects admission regardless of overlapping Audit bindings.
- Resolve namespace creation, label changes, profile changes, and binding removal
  into desired engine policy instances with explicit ownership and provenance.
- Expose resolved scope and observed generations separately from engine readiness
  and assessment outcomes.

## Capabilities

### New Capabilities

- `compliance-targeting`: Centrally define compliance profiles and resolve
  namespace-targeted bindings into cumulative policy configuration.

### Modified Capabilities

None. The active assessment-loop change remains the owner of the initial adapter
and single-policy integration contract.

## Impact

Adds alpha CRDs, API validation, central administration RBAC, a targeting resolver,
namespace/profile/binding watches, policy lifecycle integration, and tests/docs.
It uses the cluster client, policy delivery, and evidence identity conventions
established by `prove-kyverno-v1-assessment-loop`.

API/schema fixtures and resolver cases can be prepared independently. Go work
uses the existing module once its foundation is available; live engine integration
requires the assessment-loop implementation. This change owns the shared profile
and binding contracts consumed by `add-self-service-policy-exceptions`.
Exception activation and the additional Linux policies belong to their separate
changes. Multi-cluster operation and cluster-scoped workload checks remain later
capabilities.
