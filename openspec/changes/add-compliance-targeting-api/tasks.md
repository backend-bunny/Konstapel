# Tasks

## Execution boundaries

API/schema examples and resolver fixtures may start independently. Group 1's Go
work and subsequent implementation use the merged module/toolchain from
`prove-kyverno-v1-assessment-loop`; groups 3 onward also require its delivery and
evidence boundaries. Do not mark prerequisites satisfied because their planning
artifacts exist. Rebase onto the implementation before editing shared files.

This agent owns profile/binding APIs and generated files, targeting resolution,
the initial controller manager, and scope/status integration. The exceptions
agent consumes the merged contract and owns its separate resource/controller;
the bundle agent owns new content. Do not rewrite the assessment-loop task list.

## 1. Define the central API and contract

- [ ] 1.1 Add profile/binding API examples and resolver input/output fixtures for selected namespaces, `{}`, missing/null selectors, overlapping modes, and eligibility; verify each example's expected result is tied to a spec scenario and document the independent fixture entry point.
- [ ] 1.2 After the foundation module lands, add `compliance.erenius.io/v1alpha1` cluster-scoped Go types, generated CRDs, and schema validation; verify API-server tests accept valid selectors and reject invalid selectors, absent mode, invalid eligibility, and missing/nonpositive SelfService lifetime.
- [ ] 1.3 Add platform administration RBAC and namespace-team negative authorization cases; verify application exception permissions cannot create/update/delete profiles or bindings.
- [ ] 1.4 Define the shared contribution/revision/eligibility result types using the foundation's content and cluster identities; verify serialization fixtures preserve binding/profile identities, content/configuration digests, mode, scope, and resolution errors.
- [ ] 1.5 Document the alpha API, explicit mode/selector rules, central scope-label ownership, exception defaults, and downstream contract; verify the examples validate against the generated CRDs and identify which files dependent agents may consume.

## 2. Resolve namespace contributions and eligibility

- [ ] 2.1 Implement the pure namespace resolver with standard Kubernetes selectors and stable ordering; verify matchLabels, all expression operators, `{}`, new namespaces, label changes, and namespace deletion against table-driven fixtures.
- [ ] 2.2 Resolve overlapping policy contributions independently, retaining differing parameters; verify randomized input order yields identical output and Audit cannot remove a matching Deny contribution.
- [ ] 2.3 Implement Forbidden precedence and shortest SelfService lifetime across all applicable contributions; verify restrictive Audit settings, missing profiles/content, unknown policy identities, and invalid mappings never authorize an exception.
- [ ] 2.4 Reject bundle checks with unsupported cluster-scoped workload matches and resolve no-target scope explicitly; verify empty selectors cannot extend such checks cluster-wide and zero targets does not produce a compliance pass.
- [ ] 2.5 Document resolver output, error states, and overlap examples; verify the documented examples match the executable fixtures and the exceptions handoff includes accepted revision identities.

## 3. Deliver versioned engine policy instances

- [ ] 3.1 Connect the resolver to the merged delivery boundary and render namespace selectors, explicit modes, and provenance into `policies.kyverno.io/v1` instances; verify schema/CLI fixtures preserve the original content, supported namespaced match set, and background evaluation.
- [ ] 3.2 Implement deterministic names and ownership from binding UID, logical policy, and configuration revision; verify changes and rollbacks produce new names using observed configuration generations, repeated delivery converges, and unmanaged collisions remain untouched.
- [ ] 3.3 Add readiness-gated replacement and cleanup of superseded owned revisions; verify fake-client/integration cases retain the previous revision on failed replacement and never remove another binding's contribution.
- [ ] 3.4 Exercise delivery in the disposable cluster with Audit-all and Deny-selected bindings; verify policy-specific denial in the selected namespace, allowed/audited admission elsewhere, and behavior after a Namespace label change.
- [ ] 3.5 Document policy naming, readiness/transition behavior, deletion, and rollback; verify the documented procedure restores a prior configuration without adopting the prototype's unmanaged resources.

## 4. Reconcile watches, status, and evidence scope

- [ ] 4.1 Add the controller-runtime manager in the existing module, profile/binding/Namespace watches, reference indexes, and owned-resource watches; verify reconciliation is idempotent and creation, deletion, updates, and restart re-listing converge without unrelated policy writes.
- [ ] 4.2 Implement bounded status with observed generations, resolved content revisions, target counts, errors, and separate engine Conditions; verify missing references, stale generations, replacement failures, and zero targets cannot appear as current ready/compliant enforcement.
- [ ] 4.3 Feed resolved contributions and namespace identities into expected-evidence inventory and provenance through the existing assessment boundary; verify overlapping instances retain distinct configuration context without multiplying control coverage and replaced namespace UIDs do not reuse old subjects.
- [ ] 4.4 Document deployment/RBAC, status interpretation, engine exclusions, and troubleshooting; verify the documented commands distinguish resolved scope, engine readiness, and assessment completeness on saved fixtures and the disposable cluster.

## 5. Verify integrated controller behavior

- [ ] 5.1 Run the complete targeting workflow through the foundation's engine/evidence path; verify namespace creation/relabel/deletion, profile updates, overlapping modes, and binding removal satisfy the capability scenarios while other contributions remain effective.
- [ ] 5.2 Exercise missing content, ownership conflicts, controller restart, engine unavailability, and failed replacement end to end; verify truthful status, retained owned enforcement where appropriate, and no fabricated complete assessment.
- [ ] 5.3 Run the documented workflow from clean test state and retain the version matrix, rendered identities, and output package; verify the merged shared contracts are usable by the exceptions and bundle changes without duplicating root module or API ownership.
