# Proposal

## Why

Platform teams need to understand how proposed compliance configuration will
change namespace coverage, enforcement, and accepted risks before GitOps applies
it. A read-only preview can expose those effects using Konstapel's resolver
without promising that existing workloads will pass new policies.

## What Changes

- Add `konstapel preview` for locally rendered ComplianceProfile and
  ComplianceBinding manifests, using the selected cluster as the observed
  baseline. An optional previous rendered set declares explicit removals;
  unrelated cluster objects are preserved.
- Resolve proposed configuration with the controller's shared targeting and
  verified-content contracts, including every binding affected by a shared
  profile and overlapping contributions.
- Report namespace coverage, policies, parameters, bundle pins, Audit/Deny
  changes, exception eligibility, and acceptances needing renewal. Distinguish
  live desired configuration, observed applied policy state, and predictions.
- Include current evidence context and missing/stale evidence limitations without
  evaluating workloads or attributing old results to proposed policy revisions.
- Provide readable text and versioned JSON with observation times, input
  fingerprints, cluster/object identities, content digests, and completeness.
- Default to informational results. Return `2` for a completed preview with
  impacts only when `--fail-on-impact` is set; return `1` for invalid, failed, or
  incomplete previews, and `0` for other completed previews.
- Keep Kubernetes access read-only and use caller-authorized bundle access under
  the same source and verification rules as the controller.

## Capabilities

### New Capabilities

- `policy-change-preview`: Inspect proposed compliance configuration and its
  cluster-scoped targeting, enforcement, exception, and evidence implications
  before application, with explicit limits and CI exit behavior.

### Modified Capabilities

None. The preview consumes the targeting, bundle distribution, exception, and
assessment contracts without changing their behavior or the existing
`kyverno-assessment-loop` capability.

## Impact

Adds independent CLI dispatch, manifest/snapshot adapters, semantic comparison,
reporting, fixtures, and usage documentation. Reuses `internal/targeting` and its
content and expected-evidence contracts; exception and evidence integration
depends on their owning changes. OCI resolution depends on
`add-policy-bundle-distribution`; local vendored content remains supported.

No new CRDs, cluster mutation, policy engine, workload simulation, automatic
rollout/rollback, rendering system, risk acceptance, or compliance score is
introduced. Kubernetes admission and GitOps application remain authoritative.
The first release targets the existing Linux/Kyverno scope, with framework-neutral
impact categories. This change creates the implementation plan, not the CLI.
