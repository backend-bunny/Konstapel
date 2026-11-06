# Tasks

## Execution boundaries

The lifecycle fixture matrix and engine expiry investigation can start
independently in isolated test files/environment. API/controller integration
requires merged `add-compliance-targeting-api` types, revision/eligibility
contracts, and manager; evidence integration requires the merged
`prove-kyverno-v1-assessment-loop` capture/export boundary. Rebase before touching
shared registration, manifests, or generated output. Planning completion does
not satisfy these implementation prerequisites.

This agent owns exception API files, admission/controller logic, native exception
governance, acceptance snapshots, and report enrichment. Do not edit the
profile/binding schemas or bootstrap another root module. Native exception
enablement is blocked until the runtime expiry and governance gates pass.

## 1. Establish lifecycle fixtures and engine compatibility

- [x] 1.1 Add an acceptance/renewal/revocation/report fixture matrix covering namespace and revision boundaries, eligibility, attribution, and expired/missing context; verify every policy-exceptions scenario has an explicit expected outcome and document how to run these independent fixtures.
- [x] 1.2 Reproduce short-lived native v1 exception expiry on Kyverno 1.19.2 with Konstapel stopped and without policy edits that force recompilation; retain requests, timestamps, and image pins, verifying admission before/after expiry across cached engine replicas.
- [ ] 1.3 Resolve the observed expiry gap by pinning a corrected upstream runtime or a narrowly scoped upstream/backported engine fix; verify the regression from 1.2 passes during Konstapel downtime and engine restarts, and keep feature enablement disabled if it cannot pass.
- [ ] 1.4 Verify native v1 fields, exception namespace settings, CEL namespace UID access, and report exception references against the chosen runtime; retain API/discovery fixtures and verify a recreated namespace or missing namespace identity never inherits an old grant.
- [ ] 1.5 Document the supported engine matrix, expiry fix/provenance if needed, enablement gate, and operational clock/propagation limits; verify the chosen runtime also passes the merged initial assessment-loop acceptance before changing its shared pin.

## 2. Add the self-service API and authenticated acceptance

- [x] 2.1 After targeting lands, add the namespaced `ComplianceException` API/CRD with immutable logical policy/selector, reason, expiry, and explicit acceptance revision; verify API-server cases reject missing/null scope, blank reasons, invalid renewals, and scope mutation while accepting explicit `{}` within one namespace.
- [x] 2.2 Implement admission identity/time and resolved-contribution capture with protected validation for creation/renewal and dry-run safety; verify forged fields cannot survive admission, later configuration cannot replace the accepted set, metadata-only edits do not renew, and GitOps identities remain distinct from claimed human attribution.
- [x] 2.3 Connect admission to current targeting eligibility and lifetime limits; verify Forbidden contributions, unresolved mappings, absent/past/over-limit expiry, and a shorter overlapping maximum reject acceptance.
- [x] 2.4 Add namespace self-service roles and controller-only status/snapshot writes; verify application credentials cannot write central profiles/bindings, another namespace's exception, protected snapshots, or status.
- [ ] 2.5 Document creation, explicit renewal/revocation, whole-policy scope, controller-versus-Pod labels, and authenticated actor semantics; verify the examples pass API validation and the documented negative authorization cases fail.

## 3. Persist acceptances and govern native grants

- [ ] 3.1 Persist immutable acceptance snapshots before grant delivery and expose their digest/reference; verify snapshots contain actor/reason, namespace UID, cluster identity, policy/configuration revisions, selector, and validity interval and survive restart without refreshing the accepted set.
- [ ] 3.2 Render managed v1 native exceptions with exact versioned policy refs, namespace name/UID and workload-selector conditions, `reportResult: skip`, and bounded `expiresAt`; verify selector operator/escaping cases, sibling isolation, absent namespace identity, and unchanged snapshots through rendering fixtures.
- [ ] 3.3 Install restricted exception-namespace RBAC and fail-closed native admission governance covering every served version; verify direct create/update/widen attempts by application roles and invalid controller-generated refs/expiry are rejected before enabling exceptions.
- [ ] 3.4 Implement deterministic ownership checks, safe retry behavior, and finalizer/orphan handling for central native objects; verify unmanaged collisions remain untouched and no invalid cross-namespace owner reference is used.
- [ ] 3.5 Document snapshot storage/retention, native governance deployment order, and failure recovery; verify native enablement is unavailable until the runtime and authorization checks pass and documented cleanup preserves retained assessment packages.

## 4. Reconcile activation, renewal, and withdrawal

- [ ] 4.1 Add exception/profile/binding/Namespace/engine watches and activation reconciliation that rechecks eligibility against the frozen accepted set; verify eligible requests activate automatically and changes between admission and delivery cannot broaden grants. Also enqueue the continuous-assessment reconciler (`internal/controller/assessment.go`) on exception changes so current assessment status reflects grant changes (handed off from `add-continuous-assessments` task 3.4).
- [ ] 4.2 Implement explicit renewal with a new immutable snapshot and bounded native transition; verify current eligibility/lifetime are rechecked, old/new acceptances remain distinguishable, stale concurrent renewals conflict, and no background action extends expiry.
- [ ] 4.3 Implement expiry scheduling, restart rescan, and withdrawal on deletion, revocation, central restrictions, or changed policy revisions; verify new revisions and extra binding contributions require renewed acceptance and existing workloads remain present. Compare accepted contributions by `Contribution.Revision` only, never by binding generation or observed generation (provenance); verify `spec.assessment` (interval, timeout, freshness, retention) edits leave valid grants intact while enforcement changes still require renewed acceptance.
- [ ] 4.4 Expose separate eligibility, desired grant/withdrawal, and observed engine Conditions; verify API deletion alone does not claim engine convergence and cache delay/unavailability remains pending or unknown.
- [ ] 4.5 Document lifecycle transitions, pending withdrawal, restart behavior, and operator rollback; verify a disposable-cluster walkthrough shows an active grant become withdrawn without deleting the workload or losing acceptance history.

## 5. Preserve accepted risk through assessment export

- [ ] 5.1 Extend capture packages with immutable acceptance snapshots and observed lifecycle context keyed to source evaluation identities/times; verify saved evidence still resolves after the live exception is renewed, deleted, or expired. Integrate acceptance snapshots, applicability, and independent check outcomes into controller v2 captures and `collector.Export`, so accepted risk is a separate disposition and failures and repeated binding contributions never inflate passing or control coverage (handed off from `add-continuous-assessments` task 5.3).
- [ ] 5.2 Implement separate raw-result and risk-disposition handling for exception-influenced skip/pass and unresolved references; verify skips do not fabricate baseline failures, influenced passes are excluded from ordinary passing totals, and missing/stale attribution stays unresolved.
- [ ] 5.3 Preserve acceptance identity/revision, actor, reason, scope, validity interval, and policy refs through the C2P provider and OSCAL export boundary; verify final generated OSCAL against its declared schema and inspect packaged evidence links rather than relying on intermediate metadata.
- [ ] 5.4 Add delayed-report, revoked-acceptance, multiple-exception, and missing-snapshot conversion regressions; verify evaluation time controls historical attribution and multiple references never inflate full-control/Moderate coverage.
- [ ] 5.5 Document accepted-risk interpretation, GitOps attribution, retained-history limits, and inspection commands; verify a saved output package can explain an expired/deleted acceptance without querying the cluster.

## 6. Verify integrated self-service behavior

- [ ] 6.1 Run a complete application-role workflow from rejection through eligible acceptance, exception-influenced reporting, and expiry; verify the exact policy/namespace/workload boundary and validated OSCAL output with retained acceptance history.
- [ ] 6.2 Exercise overlapping Forbidden settings, renewal after policy revision, native bypass attempts, namespace recreation, controller downtime, and multi-replica engine propagation end to end; verify no silent broadening and no false activation/withdrawal completion.
- [ ] 6.3 Run the documented clean-state acceptance and rollback procedures, retaining version pins and diagnostic artifacts; verify the original assessment loop still passes and the bundle agent can consume the merged exception/export contracts.
