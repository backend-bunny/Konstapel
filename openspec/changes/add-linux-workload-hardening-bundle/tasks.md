# Tasks

## Execution boundaries

Groups 1-2 can start independently in the four new policy/fixture directories.
Group 3 packaging and C2P work require the merged content/evidence contracts from
`prove-kyverno-v1-assessment-loop`. Group 4 requires that environment plus merged
`add-compliance-targeting-api`. Group 5 requires merged
`add-self-service-policy-exceptions` and its verified engine expiry support.
All are implementation prerequisites, not satisfied by planning artifacts.

This agent owns new policy content/variants, mapping entries, fixtures, and bundle
documentation. Preserve the existing privileged policy and root module. Rebase
before changing shared manifests or the combined acceptance command; do not edit
the other agents' CRDs or task lists.

## 1. Vendor and identify the four policy sources

- [x] 1.1 Vendor the four named source directories at the design's pinned revision, including relevant hidden CLI/Chainsaw fixtures and license material; verify original policy checksums against the research and require only new-group v1 policy resources in the shipped bundle.
- [x] 1.2 Record source URLs, licenses/notices, checksums, and stable logical check/sub-validation identities in content metadata local to the new directories; verify each policy can be traced to its immutable source without duplicating the initial privileged check.
- [x] 1.3 Run the retained upstream CLI suites using the pinned CLI and preserve results; verify expected outcomes match and identify the added-capabilities helper separately from the combined shipped policy.
- [x] 1.4 Document source layout, update procedure, runtime annotations, and the difference between research results and implementation acceptance; verify all source/license references and rerun commands resolve to the vendored content.

## 2. Implement and test explicit Linux variants

- [x] 2.1 Add separately tracked local variants with consistent explicit-Windows exclusion and missing-OS Linux-rule convention for Pods/controller templates; verify CLI fixtures cover Pods, Deployments, CronJobs, and all source-supported template forms without changing upstream originals.
- [x] 2.2 Remove the non-root `hostUsers: false` bypass while preserving flag inheritance and explicit-false semantics; verify regular/init/ephemeral, Pod/template, null-list, user-namespace, and Windows cases against local expectations distinct from upstream results.
- [x] 2.3 Exercise allowPrivilegeEscalation false/true/missing across all applicable container forms; verify only explicit false passes for unexcepted Linux containers and no Pod-level inheritance is invented.
- [x] 2.4 Add the complete drop/add cross-product against the shipped combined capabilities policy; verify missing drop ALL, disallowed additions, case sensitivity, permitted NET_BIND_SERVICE, and each container form independently of the upstream helper.
- [x] 2.5 Add seccomp Pod/container inheritance and override fixtures; verify RuntimeDefault/Localhost acceptance, missing both rejection, and invalid Pod-level rejection across applicable container/template forms.
- [x] 2.6 Document local differences and coverage limits, including whole-policy exception scope and omitted-OS behavior; verify variant digests and CLI results identify exactly which modified expressions were tested and make no observed runtime claims.

## 3. Package bounded Moderate evidence

- [x] 3.1 After the first loop's format lands, package the four variants through its content/rendering contract and compose the expanded demonstration with the existing privileged check by reference; verify stable check identities and source/variant/rendered digests survive packaging.
- [x] 3.2 Author per-check Component Definition mappings and rationales for the design's AC-6/CM-6/CM-7 statements; verify each statement resolves in the pinned catalog and its control belongs to Moderate, with a failing invalid-reference fixture.
- [x] 3.3 Validate authored/generated OSCAL at its supported declared schema while preserving official NIST inputs; verify the OSCAL 1.2.3 source files remain unchanged and no older-model round trip is used to establish membership.
- [x] 3.4 Add saved-report conversion fixtures for distinct checks and repeated binding instances sharing controls; verify independent check results remain identifiable without multiplying control satisfaction or asserting full Moderate coverage.
- [x] 3.5 Document packaging, mappings, partial coverage, and artifact inspection commands; verify a saved output package resolves all selected content and evidence references.

## 4. Integrate targeting and prove live policy behavior

- [x] 4.1 Render bundle instances through merged profiles/bindings with explicit Audit/Deny and namespace selectors; verify rendered CLI cases and API schemas retain v1, background evaluation, revision provenance, and no hidden namespace exclusions.
- [x] 4.2 Add live admission cases for every check on Pods and supported controller templates, with applicable UPDATE/ephemeral-container cases; verify ready policies reject only the intended unexcepted violation by policy-specific reason and Audit admits the otherwise-valid request.
- [x] 4.3 Exercise the changed non-root user-namespace case in the documented Linux environment; verify `hostUsers: false` without the required flag is denied and record Kubernetes/runtime prerequisites or an explicit failing/unvalidated acceptance result if unavailable.
- [x] 4.4 Seed pre-existing violating and compliant subjects and collect background evidence through the first loop; verify raw outcomes, source times, UIDs, cluster/policy identities, and expected inventory while existing violations remain present and denied creates are not required report subjects.
- [x] 4.5 Add applicability handling and fixtures for explicit Windows and omitted OS; verify Windows cannot become passing Linux coverage or accepted risk merely because a raw evaluation skips or short-circuits.
- [x] 4.6 Document supported workload forms, live environment, exclusions, and Audit-to-Deny rollout; verify the documented steps distinguish admission/background configuration evidence from any separately executed container-runtime checks.

## 5. Integrate recorded exceptions and final assessment output

- [ ] 5.1 After exception integration lands, add eligible non-root and non-negotiable policy cases using real application credentials; verify only an authorized scoped exception permits the deviation, sibling namespaces/workloads remain constrained, and unrelated policies still deny.
- [ ] 5.2 Exercise renewal, expiry, revocation, and policy revision changes on the bundle; verify accepted revisions never silently expand, expired grants stop working on the compatible engine, and retained snapshots explain historical evaluations.
- [ ] 5.3 Export combined raw outcomes, applicability, and accepted-risk context through C2P to OSCAL; verify skip/pass influenced by exceptions is distinct from ordinary passing evidence and unresolved/missing/stale evidence cannot establish compliance.
- [ ] 5.4 Document the bundle exception walkthrough, whole-policy waiver consequences, and final report interpretation; verify a retained output package remains understandable after live exception cleanup.

## 6. Verify the complete expanded assessment

- [ ] 6.1 Run the combined acceptance command from clean state with the original privileged check and all four new checks; verify targeting, admission, background collection, exception lifecycle, and declared-schema OSCAL validation satisfy the capability scenarios together.
- [ ] 6.2 Run failure/cleanup paths for unsupported prerequisites, missing evidence, unexpected admission, and failed exception attribution; verify failures retain diagnostics and cleanup affects only owned resources without fabricating pass results.
- [ ] 6.3 Repeat the documented clean-state workflow on the final engine pin and retain the tested matrix, rendered digests, and acceptance artifacts; verify any engine update needed for expiry also passes the original loop and all rendered-policy regressions.
