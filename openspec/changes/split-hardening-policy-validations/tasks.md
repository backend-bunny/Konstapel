# Tasks

## Execution boundaries

Planning follows the linked GitHub issue; implementation must preserve unrelated
work and coordinate shared controller/content fixtures with their owners. Use
pinned Devbox and existing Task workflows. Do not publish production artifacts
or mark the issue fixed merely because these planning artifacts are merged.

## 1. Single-validation content and mappings

- [x] 1.1 Create the four named variants retaining exact original CEL, variables, matching and applicability; test expression equivalence for all outcome combinations plus init/ephemeral/template cases and preserve upstream originals.
  <!-- agent: tier=deep risk=medium -->
- [x] 1.2 Update inventories, component definitions and OSCAL/control mappings with old-validation-to-new-ID provenance; validate checksums, license/source records and the unchanged seven-check full-bundle denominator.
  <!-- agent: tier=deep risk=medium -->
- [ ] 1.3 Prepare independently versioned bundle inputs and update active examples/vendored selection coherently; verify old pinned artifacts and saved historical fixtures remain readable and document the identity mapping.
  <!-- agent: tier=standard risk=medium -->

## 2. Migration and exception compatibility

- [ ] 2.1 Implement and document the staged overlapping-binding migration using old and new digest fixtures; test one replacement not ready, complete cutover, rollback and unrelated bindings without an enforcement gap or manual engine-policy edits.
  <!-- agent: tier=deep risk=high -->
- [ ] 2.2 Verify eligibility/lifetime and exception-expression equivalence using available owner fixtures; document explicit reacceptance for new identities, Forbidden precedence and blocked native grant cases without transferring old acceptances automatically.
  <!-- agent: tier=deep risk=high -->
- [ ] 2.3 Reconcile remaining original hardening tasks and documentation with versioned policy families; preserve historical acceptance and upstream-blocked requirements, and verify old-ID selectors cannot silently resolve to a partial replacement.
  <!-- agent: tier=standard risk=medium -->

## 3. Producer outcomes and export

- [ ] 3.1 Add required live Kyverno matrix tests for both-pass, first-fail, second-fail and both-fail on each pair; assert Audit/Deny behavior and independently attributable background outcomes using shipped variants.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.2 Export stable mixed-outcome captures through C2P and inspect frozen packages; verify UID/revision/index attribution, exact expected-check counts, mappings and Windows applicability, while absent/stale/changed-subject evidence remains incomplete.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.3 Exercise the existing signed OCI fixture pipeline with new content and migration pins; verify provenance/digests and old-package replay without publishing production artifacts.
  <!-- agent: tier=deep risk=high -->

## 4. Final verification

- [ ] 4.1 Run pinned Devbox content/check workflows, affected live acceptance, strict OpenSpec and routing validation; record the engine matrix and sanitized evidence, clean owned resources and list production publication as a separately authorized follow-up.
  <!-- agent: tier=standard risk=medium -->

