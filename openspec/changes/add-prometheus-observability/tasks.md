# Tasks

Groups 1 and 5 can start with fixtures before runtime integration. Group 2 waits
for each named producer, group 3 for the manager, and group 4 for the Helm chart.
Prepare interfaces and tests independently without implementing competing owners.
See [design.md](design.md) for the metric catalog, initial alert defaults and
integration boundaries.

## 1. Metric contract and pure projections

- [x] 1.1 Add the documented metric catalog with names, types, units, enum labels, source availability and reset semantics; verify exposition fixtures have no framework/control dimensions and equivalent alternative-catalog metadata produces the same contract.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.2 Define immutable owner-snapshot interfaces and readiness/enabled/validity projections; test unsynchronized startup, stalled producers, disabled domains, expired validity and known-zero versus missing-data behavior with an injected clock.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [x] 1.3 Implement per-binding current/latest-closed summary projections using the assessment owner's normalized fixtures; verify all display states, inventory totals, zero targets, incomplete/diagnostic runs and namespace-only requests without introducing a second report normalizer.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.4 Add UID-aware deletion/recreation and owner/replica filtering; test binding name reuse, leader loss/acquisition, source reconstruction and preservation of source/closure times across repeated scrapes.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [x] 1.5 Register custom collectors in the existing metrics registry and promote the Prometheus client dependency when imported; verify no duplicate upstream collectors, bounded series count as workload/history fixtures grow, and no credential or free-text label leakage.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 1.6 Document query examples, projection freshness, historical-view limitations and safe aggregation; verify those examples against fixtures and include projection/exposition checks in the existing test/check workflows.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 2. Instrument authoritative producers

- [ ] 2.1 After the targeting manager lands, wire binding Conditions, known target counts and capability state into snapshots; test stale observed generations, unavailable reporting with functioning delivery, periodic validity refresh and no source work caused by scraping.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 2.2 After continuous assessment state/scheduling lands, wire current evidence, latest full-binding closure and recorded due obligations through its owner; test source-time expiry, initial overdue runs, diagnostic failures, namespace requests, interval edits and missed-tick coalescing without changing enforcement or scheduler semantics.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [ ] 2.3 After bundle resolution lands, instrument bounded resolution attempts/durations and producer readiness; test failed verification, retries, recovery and process-counter reset without exposing repositories, digests, identities or credential details as labels.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 2.4 After evidence publishing/cleanup lands, wire attempts and durable backlog/oldest-expiry gauges; test successful incomplete publication, actionable versus historical failure, blocked deletion, restart reconstruction and cleanup surviving binding deletion.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [ ] 2.5 Extend each owning integration guide with its emitted signals and availability limits; verify documented state transitions against producer tests and keep unimplemented domains explicitly disabled instead of reporting healthy placeholders.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 3. Authenticated metrics serving

- [ ] 3.1 Integrate the manager's authenticated TLS metrics server with certificate reload and the existing controller-runtime filter; test authorized/unauthorized scrapes, invalid CA/server identity, rotated certificates and passive behavior during dependency outages.
  <!-- agent: tier=deep risk=high reason="Authenticated metrics and revocation during replica changes" -->
- [ ] 3.2 Add narrowly scoped reader RBAC for configured monitoring ServiceAccounts and reuse controller TokenReview/SubjectAccessReview permissions; test namespace roles cannot scrape and revoked access stops within the pinned authentication/authorization cache bounds.
  <!-- agent: tier=deep risk=high reason="Authenticated metrics and revocation during replica changes" -->
- [ ] 3.3 Document metrics access, token rotation, filter cache durations and Prometheus authorization options; verify the documented setup using a monitoring identity in another namespace and an Operator configuration that exercises its credential-access policy.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 4. Optional Helm monitoring integration

- [ ] 4.1 After the controller chart lands, add metrics Service/TLS configuration and independently optional ServiceMonitor/PrometheusRule values; test defaults, incompatible options, missing enabled APIs and rendering with both integrations disabled without monitoring CRDs.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 4.2 Add release-scoped ServiceMonitor selectors, named HTTPS port, verified CA/server-name, authorization and validated scrape timing; verify rendered resources against the selected Operator schema and cover both certificate-management modes.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 4.3 Add configurable rule-group/per-rule settings, safe release/namespace selectors and runbook annotations; verify actual rendered rule content changes with thresholds, holds, severity and enablement without altering workload or assessment settings.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 4.4 Document Prometheus namespace/label discovery, external scrape-job support and disabling/uninstalling integrations; test the rendering matrix and confirm neither Konstapel chart installs a monitoring stack or its CRDs.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 5. Starter alert rules and runbooks

- [ ] 5.1 Implement the seven starter rules from the design with source-availability gates and scoped replica aggregation; use Prometheus fixtures to verify default thresholds and detection of absent scrape targets or missing enabled-domain projections.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [ ] 5.2 Add rule cases for hourly/daily/initial scheduling, diagnostics, transient recovery, stale samples, process resets, replica transitions, two releases with identical binding names and cleanup after binding deletion; verify firing and resolution with `promtool test rules`.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 5.3 Write one actionable runbook per starter alert and framework-neutral outcome-query examples; verify links and commands against the owning status contracts and distinguish lost observability from actual operational recovery.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->
- [ ] 5.4 Pin rule-testing tooling in Devbox and validate the exact Helm-rendered rules with `promtool check rules` and the rule suite through existing checks; verify local/CI parity without adding a public task for each helper.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->

## 6. End-to-end monitoring acceptance

- [ ] 6.1 Extend the existing chart acceptance workflow with pinned Prometheus Operator/Prometheus fixtures; verify actual ServiceMonitor discovery, successful TLS/authenticated scraping, unauthorized denial and task-owned teardown, recording dependency versions.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [ ] 6.2 Exercise implemented producer failures/recovery through a real scrape and rule evaluator; verify per-binding evidence expiry, overdue scheduling, publication/cleanup alerts, configuration overrides and availability alerts without fabricated healthy data for missing integrations.
  <!-- agent: tier=deep risk=medium reason="Temporal projections and truthful replica aggregation" -->
- [ ] 6.3 Exercise restart/leader transition, certificate/token rotation and binding deletion/recreation in the integrated deployment; retain evidence of bounded authorization revocation, correct gauge/counter behavior and continued controller work, then run the repository's applicable checks.
  <!-- agent: tier=deep risk=high reason="Authenticated metrics and revocation during replica changes" -->
