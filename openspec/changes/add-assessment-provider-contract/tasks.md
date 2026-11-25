# Tasks

## External-provider follow-up

The approved `add-external-assessment-providers` change consumes these shared
interfaces and adds separately Helm-installed provider services, OCI distribution,
a versioned remote protocol and an optional explicit scan-request capability.
This foundation remains in-tree and read-only: its collection, Generate and
GetResults paths never initiate scans. Completed work and current Kyverno behavior
remain unchanged. External registration and scan execution are follow-up scope,
not requirements to finish or archive this foundation. Coordinate capture and
evaluation compatibility at handoff; production Prowler/AWS scope remains separate.

## Execution boundaries

This change owns the shared provider interfaces, conformance harness and authoring
recipe, plus migration of existing Kyverno paths. It does not implement a real
Trivy provider or change exception APIs. Coordinate collector/content/schema and
manager changes with their existing owners; preserve their lifecycle guarantees.
The test-only reporting adapter must never be selectable in a production build.
Do not treat its fixtures as live producer compatibility evidence.

## 1. Register installed capabilities and define conformance inputs

- [x] 1.1 Add the minimal installed-provider descriptor/registry and selection checks using the current Kyverno provider identity; test duplicate/unknown identities, incompatible versions, unsupported modes, parameter validation and mixed-provider rejection without changing existing Kyverno policy delivery.
  <!-- agent: tier=deep risk=medium reason="Provider selection and backward-compatible capability contracts" -->
- [x] 1.2 Define versioned conformance inputs and expected results using current Kyverno fixtures plus a different test-only reporting subject shape; verify raw versus normalized outcomes, independent inventory and explicit unknowns without importing Kyverno policy-name or CEL-index assumptions into the reporting fixture.
  <!-- agent: tier=deep risk=medium reason="Cross-provider evidence and result semantics" -->
- [x] 1.3 Start docs/assessment-providers.md with the registration/capability contract and test-only boundary; verify examples against descriptor tests and document that bundle content cannot install executables or change provider permissions.
  <!-- agent: tier=standard risk=medium reason="Document and exercise the installed-provider contract" -->

## 2. Integrate scoped collection and provider availability

- [x] 2.1 Extract narrow inventory/collection adapters around existing Kyverno behavior, retaining host-owned scope and expected checks; verify missing reports, zero targets, replaced namespace/workload identities, shared evidence and unsupported subjects without changing existing attribution results.
  <!-- agent: tier=deep risk=high reason="Scope isolation and evidence attribution" -->
- [x] 2.2 Connect descriptor prerequisites to existing capability discovery and bounded watch activation; test absent/unsupported APIs, denied reads, recovery without restart and continued healthy-provider operation, with explicit nonapplicable enforcement for the test-only reporting shape.
  <!-- agent: tier=deep risk=medium reason="Manager lifecycle and independent provider availability" -->
- [x] 2.3 Enforce host deadlines, cancellation and collection resource limits across adapters; test oversized inputs, incomplete pagination/collection and leadership cancellation, and verify reporting adapters issue no scanner/report/workload writes using a recording API fixture.
  <!-- agent: tier=deep risk=high reason="Bounded external access and lifecycle cancellation" -->
  Note (owner decision 2026-11-24): the page size and request, object and byte limits are configurable through `--collection-*` controller flags and the chart's `controller.collection` values, defaulting to the host defaults and validated at startup and render; the deadline stays the binding's collectionTimeout (design.md, decision 2).
- [x] 2.4 Document the capability/permission matrix and collection limits beside the authoring recipe; verify API operations match fixtures and distinguish narrow Go readers from the service account's effective shared RBAC.
  <!-- agent: tier=standard risk=medium reason="Accurate permissions and collection documentation" -->

## 3. Preserve captures, content closure and confidentiality

- [ ] 3.1 Add the provider-discriminated capture boundary and explicit version checks through the collector owner; test supported legacy CaptureV2 fixtures, unknown providers/payloads, evaluator compatibility and reader-before-writer behavior without rewriting retained evidence or existing Kyverno identities.
  <!-- agent: tier=deep risk=high reason="Historical evidence and capture compatibility" -->
- [x] 3.2 Connect provider captures to existing RunContent and verified-content ownership; test applied A versus desired B, overlapping applied revisions, reporting-only frozen selection and unavailable content, retaining exact content for replay after cache eviction without vendored fallback or digest-only resolution identity.
  <!-- agent: tier=deep risk=high reason="Frozen content identity and immutable assessment history" -->
- [ ] 3.3 Add shared projection validation and provider-specific safe extraction before summaries/export; test mixed-namespace sources, unknown scope, diagnostics/references and protected supporting-evidence boundaries so no sibling findings, private metadata or credentials enter team output.
  <!-- agent: tier=deep risk=high reason="Namespace confidentiality across extensible payloads" -->
- [ ] 3.4 Document payload compatibility, content retention and rollback constraints with saved examples; verify an incompatible reader fails explicitly and supported legacy packages retain their original interpretation.
  <!-- agent: tier=standard risk=medium reason="Executable capture compatibility guidance" -->

## 4. Share evaluation and C2P conversion

- [ ] 4.1 Route current Kyverno evaluation and the test-only reporting shape through pure evaluators with explicit time inputs; test freshness boundaries, ambiguous provenance, duplicate associations, applicability and raw warning-to-unknown summary mapping without creating new outcome API fields or risk acceptance.
  <!-- agent: tier=deep risk=medium reason="Shared deterministic evaluation and outcome semantics" -->
- [ ] 4.2 Connect existing continuous export and Configure/Generate/GetResults dispatch to the same evaluator semantics and frozen inputs; verify normalized result equivalence, schema-valid OSCAL or explicit diagnostics, local-only Generate behavior and no live cluster/registry access during replay.
  <!-- agent: tier=deep risk=high reason="C2P compatibility and trustworthy offline export" -->
- [ ] 4.3 Exercise the reusable conformance harness against Kyverno and the test-only reporting adapter, including canceled collection, missing/stale evidence, unavailable content, replay after source removal and deliberate bad-result/projection mutations; verify the test-only adapter is absent from production registry, manifests, image and bundles.
  <!-- agent: tier=deep risk=high reason="Conformance isolation and meaningful negative coverage" -->
- [ ] 4.4 Complete the worked provider-authoring recipe and link architecture/development guidance; run its registration, fixture and replay commands through pinned Devbox using existing Task workflows, and clearly distinguish internal Go interfaces from versioned package contracts and real producer support.
  <!-- agent: tier=standard risk=medium reason="Reproducible provider authoring guidance" -->

## 5. Verify production migration and hand off to Trivy

- [ ] 5.1 Run applicable existing live acceptance against the Helm-installed Kyverno image after migration; verify policy delivery, current/scheduled/namespace assessments, C2P export, downloads and restart behavior retain existing contracts, and keep publication/signing/retention integrations green with sanitized evidence and task-owned cleanup.
  <!-- agent: tier=deep risk=high reason="Production provider migration across existing lifecycle boundaries" -->
- [ ] 5.2 Reconcile the Trivy integration plan against the implemented shared seams and separate its initial read-only assessment slice from vulnerability-specific governance follow-up; verify the plan names concrete interfaces, retains real producer compatibility gates and adds no parallel scheduler, publication path or provider registry.
  <!-- agent: tier=deep risk=medium reason="Bounded Trivy scope and cross-owner handoff" -->
- [ ] 5.3 Run pinned Devbox task check, applicable required CI and strict OpenSpec validation; verify the conformance checks are reached through existing test/check entry points, document remaining producer-specific gaps, and mark completion only after installed Kyverno acceptance passes without exposing the synthetic provider.
  <!-- agent: tier=standard risk=medium reason="Final verification and accurate support claims" -->
