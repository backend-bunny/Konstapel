# Tasks

## Execution boundaries

Planning follows the linked GitHub issue; implementation must preserve unrelated
work and coordinate shared controller/content fixtures with their owners. Use
pinned Devbox and existing Task workflows. Do not publish production artifacts
or mark the issue fixed merely because these planning artifacts are merged.
Owner decision 2026-11-27 (option a): the vendored bundle and its digest stay
unchanged; the split ships only as the separately versioned OCI bundle
konstapel-linux-hardening 0.2.0.

## 1. Single-validation content and mappings

- [x] 1.1 Create the four named variants retaining exact original CEL, variables, matching and applicability; test expression equivalence for all outcome combinations plus init/ephemeral/template cases and preserve upstream originals.
  <!-- agent: tier=deep risk=medium -->
- [x] 1.2 Update inventories, component definitions and OSCAL/control mappings with old-validation-to-new-ID provenance; validate checksums, license/source records and the unchanged seven-check full-bundle denominator.
  <!-- agent: tier=deep risk=medium -->
- [x] 1.3 Prepare the independently versioned OCI bundle inputs (konstapel-linux-hardening 0.2.0 through the existing bundle definition and package tooling) and update examples that demonstrate it, without changing vendored selection; test that the vendored digest is byte-unchanged and that old pinned 0.1.0 artifacts and saved historical fixtures remain readable, and document the identity mapping.
  <!-- agent: tier=standard risk=medium -->

## 2. Migration and exception compatibility

- [ ] 2.1 Implement and document the staged overlapping-binding migration from a vendored or OCI 0.1.0 pin to the OCI 0.2.0 digest using old and new digest fixtures; test one replacement not ready, complete cutover, rollback and unrelated bindings without an enforcement gap or manual engine-policy edits.
  <!-- agent: tier=deep risk=high -->
- [ ] 2.2 Verify eligibility/lifetime and exception-expression equivalence using available owner fixtures; document explicit reacceptance for new identities, Forbidden precedence and blocked native grant cases without transferring old acceptances automatically.
  <!-- agent: tier=deep risk=high -->
- [ ] 2.3 Reconcile remaining original hardening tasks and documentation with versioned policy families (vendored and OCI 0.1.0 keep the original families, OCI 0.2.0 ships the split); preserve historical acceptance and upstream-blocked requirements, and verify old-ID selectors cannot silently resolve to a partial replacement.
  <!-- agent: tier=standard risk=medium -->

## 3. Producer outcomes and export

- [ ] 3.1 Add required live Kyverno matrix tests for both-pass, first-fail, second-fail and both-fail on each pair; assert Audit/Deny behavior and independently attributable background outcomes using the variants the OCI 0.2.0 revision ships.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.2 Export stable mixed-outcome captures through C2P and inspect frozen packages; verify UID/revision/index attribution, exact expected-check counts, mappings and Windows applicability, while absent/stale/changed-subject evidence remains incomplete.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.3 Exercise the existing signed OCI fixture pipeline with new content and migration pins; verify provenance/digests and old-package replay without publishing production artifacts.
  <!-- agent: tier=deep risk=high -->

## 4. Final verification

- [ ] 4.1 Run pinned Devbox content/check workflows, affected live acceptance, strict OpenSpec and routing validation; confirm the vendored digest is unchanged, record the engine matrix and sanitized evidence, clean owned resources and list production publication as a separately authorized follow-up.
  <!-- agent: tier=standard risk=medium -->

