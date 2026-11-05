# Tasks

The pure coverage model and fixtures can start against merged targeting and
collector contracts. Production content, current-state/export, and accepted-risk
integration depend on their existing owners. Attachment ingestion is optional for
this change; group 4 lands the shared context contract that the attachment change
consumes. Keep runtime integration tasks open until their real inputs exist.

## 1. Baseline and mapping inventory

- [ ] 1.1 Add the coverage report/input model and schema-aware baseline reader using verified content handles; verify the pinned Moderate profile enumerates every selected control/enhancement independently of findings and mappings.
- [ ] 1.2 Validate supported profile semantics, schema versions, local import closure, catalog-qualified IDs, and statement membership; verify missing/unsupported imports, wrong-control statements, duplicate selection edges, and catalog revision mismatches produce explicit resolution limitations rather than guessed inventories.
- [ ] 1.3 Join authored rule/check mappings to selected profile policies, retaining descriptions and parameters; verify absent, unselected, partial, and unresolved automation states plus a small alternate-catalog fixture with non-NIST identifiers.
- [ ] 1.4 Document supported OSCAL resolution semantics and the meaning of coverage states in `docs/control-coverage.md`; verify examples match the Moderate inventory and do not equate policy parameters with unmapped OSCAL parameters.

## 2. Attributed technical evidence and findings

- [ ] 2.1 Consume frozen collector observations and expected keys without reevaluating freshness; verify current, missing, rejected, unresolved, conflicting, zero-target, and changed-scope fixtures preserve the collector's results.
- [ ] 2.2 Add statement/control joins and deduplication by exact observation and mapping identity; verify repeated reports, shared checks, overlapping binding contributions, and distinct configurations do not inflate independent evaluation counts.
- [ ] 2.3 Consume the exception owner's accepted-risk projection once implemented; verify raw outcomes remain traceable, arbitrary skips do not create acceptance, Linux applicability stays check-scoped, and documents cannot change enforcement or risk disposition.
- [ ] 2.4 Document per-control versus unique-observation counts and evidence/coverage distinctions; verify a fixture with all available AC-6 checks passing still reports partial technical coverage and unassessed baseline controls.

## 3. Versioned reports and assessment integration

- [ ] 3.1 Render deterministic `coverage.json` and `coverage.txt` from one model with scope, times, qualified IDs, input digests, source references, and limitations; verify equivalent content and stable ordering through complete/incomplete/no-automation golden fixtures.
- [ ] 3.2 Integrate the production assessment producer and package inventory through its owner, using summary roles and valid relative references; verify package checksum/reference validation and explicit coverage diagnostics without fabricated OSCAL findings.
- [ ] 3.3 Extend the current assessment summary through its owning API/publication types with bounded coverage state and observation references; verify generated schemas, round-trip fixtures, large-baseline status bounds, and unchanged technical EvidenceComplete semantics.
- [ ] 3.4 Wire current-summary freshness/scope requeues through the assessment owner; verify clock-driven expiry updates current state while retained report bytes and original closure-time interpretation remain unchanged.
- [ ] 3.5 Document how operators and teams inspect scoped coverage in assessment packages and current summaries; verify examples using the existing download workflow without adding a new dashboard or per-helper Task commands.

## 4. Supporting-evidence contract and safe projection

- [ ] 4.1 Define the versioned `SupportingEvidenceContext` projection with integration, availability, association, temporal, withdrawal, and access states; verify disabled, empty, unavailable, expired, future, and restricted fixtures never add technical passes or expected observations.
- [ ] 4.2 Apply namespace projection before both renderers and diagnostics, retaining baseline controls but only authorized findings and sanitized document context; verify private titles, sources, document bytes/links, and sibling evidence cannot leak through error paths.
- [ ] 4.3 Document the attachment consumer contract and example physical-control row; verify no-automation plus an available document remains supporting evidence without a control verdict, and validate consumer fixtures shared with the attachment change.

## 5. Integrated acceptance

- [ ] 5.1 Exercise real targeting/content, assessment, exception, and publication integrations for a full-binding run and a namespace request; verify every baseline control is represented, partial coverage survives export, and scoped downloaded packages pass validation.
- [ ] 5.2 Exercise unresolved content, missing evidence, input changes, expired context, and publication failures across report generation; verify findings remain attributable and failed/unavailable inputs never become successful complete coverage.
- [ ] 5.3 Run appropriate existing Devbox/Task checks, prototype regressions, and strict OpenSpec validation; record results and remove task-owned test resources, keeping dependent runtime tasks unfinished if only fake integrations were exercised.
