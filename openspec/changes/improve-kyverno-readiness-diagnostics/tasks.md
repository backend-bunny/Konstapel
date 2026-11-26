# Tasks

## Execution boundaries

Planning follows the linked GitHub issue; implementation must preserve unrelated
work and coordinate shared controller/content fixtures with their owners. Use
pinned Devbox and existing Task workflows. Do not publish production artifacts
or mark the issue fixed merely because these planning artifacts are merged.

## 1. Readiness diagnostics

- [x] 1.1 Carry bounded typed Kyverno readiness details through DeliveryResult into EngineReady without changing readiness/retirement decisions; test False, Unknown, missing/malformed conditions and retained revisions.
  <!-- agent: tier=deep risk=medium -->
- [x] 1.2 Add deterministic formatting, deduplication, sanitization and truncation with inspection fallback; test many policies, oversized messages and control characters, and document the displayed diagnostic.
  <!-- agent: tier=standard risk=medium -->

## 2. Production prerequisite guidance

- [x] 2.1 Verify the supported Kyverno permission matrix by removing grants in a disposable fixture, including admission/reporting and Audit/Deny ephemeral updates; retain actual required verbs and reasons without expanding Konstapel RBAC.
  <!-- agent: tier=deep risk=high -->
- [ ] 2.2 Add the operator-applied least-privilege RBAC example and link installation/bundle Audit guidance; verify aggregation labels, installation-specific identities and documented auth-can-i commands against the pinned chart.
  <!-- agent: tier=standard risk=medium -->

## 3. Live recovery and handoff

- [ ] 3.1 Add a required acceptance case that starts without ephemeral grants, checks actionable binding diagnostics, applies the documented example and verifies readiness/report recovery without controller restart; confirm policy ownership and retained enforcement.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.2 Run pinned Devbox checks, affected acceptance and strict spec/task-routing validation; retain sanitized evidence, clean owned grants/clusters and document supported engine versions and remaining evidence limitations.
  <!-- agent: tier=standard risk=medium -->

