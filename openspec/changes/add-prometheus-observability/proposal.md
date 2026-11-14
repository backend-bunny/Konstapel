# Proposal

## Why

Konstapel's planned Conditions and assessment records explain individual failures,
but operators need standard monitoring to detect broken enforcement coordination,
stale evidence and blocked publication or cleanup. The monitoring contract must
remain useful for future OSCAL frameworks while NIST SP 800-53 Moderate remains
the first supported content set.

## What Changes

- Expose standard Prometheus metrics through the controller's authenticated
  metrics endpoint, retaining controller-runtime and process instrumentation.
- Add framework-neutral operational signals and per-ComplianceBinding summaries
  for resolution, engine readiness, current evidence, historical assessments,
  publication and cleanup. Preserve unknown, stale, accepted-risk and
  out-of-scope states instead of reporting a compliance percentage.
- Define bounded labels, source timestamps, missing-data behavior, binding
  deletion/recreation handling and replica aggregation semantics.
- Offer independently configurable ServiceMonitor and PrometheusRule resources
  in the controller Helm chart, using an existing Prometheus Operator installation.
- Ship configurable starter alerts and runbooks for unresolved bindings,
  unavailable engine capabilities, overdue assessments, recurring publication
  failures and blocked retention cleanup.
- Verify metric semantics and alert behavior with projection fixtures, Prometheus
  rule tests and an authenticated scrape in the existing chart acceptance setup.

## Capabilities

### New Capabilities

- `prometheus-observability`: Monitor controller operations and binding assessment
  state with framework-neutral metrics and optional standard monitoring resources.

### Modified Capabilities

- `continuous-assessments`: status additionally records the oldest source
  evaluation of current evidence and closed runs, and the earliest outstanding
  scheduled obligation (design §4). These are additive observations through the
  owner; scheduling, enforcement and evidence semantics are unchanged.

Other assessment, targeting, evidence and chart behavior remains owned by its
respective capability; this change exposes observations of those contracts.

## Impact

Implementation adds instrumentation and metric projections around the existing
targeting contract and future assessment, bundle and storage controllers, plus
metrics TLS/RBAC and monitoring templates in the controller chart. It reuses the
existing controller-runtime and Prometheus client dependencies, promotes direct
dependencies when imported, and adds pinned rule-testing tooling through Devbox.

Metric definitions and rule fixtures can start independently. Runtime integration
follows the owning manager/status implementations; chart integration follows the
Helm change. No competing CRDs, manager, assessment scheduler or result-normalizer
are introduced. Out of scope: installing a monitoring stack, dashboards, tracing,
notification routing, automatic remediation, and adding support for another
compliance framework merely because its catalog exists.
