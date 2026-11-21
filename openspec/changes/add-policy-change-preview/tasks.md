# Tasks

The comparison core can start against the merged targeting resolver. OCI,
exception, and enforcement-epoch/evidence integrations depend on their owning
changes as noted below; keep those tasks open until real integrations are
verified. This checklist implements only the preview capability, not the
dependencies' CRDs, trust systems, or collectors.

## 1. Manifest inputs and candidate configuration

- [x] 1.1 Add strict rendered profile/binding input decoding with repeatable files, one stdin stream, named cluster-scoped identities, and bounded input size; verify multi-document YAML/JSON, duplicate keys/identities, unknown fields, unsupported kinds/versions, and invalid selectors in parser tests.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.2 Build the candidate from live desired state plus proposed complete specifications and explicit before-minus-after removals; verify partial input preserves unrelated objects, an empty proposed stream removes only declared identities, and an already absent object creates no removal impact.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
- [x] 1.3 Apply shared defaults/validation and ignore exported server metadata/status as proposed authority; verify default-equivalent and reordered inputs compare equally, injected UID/readiness values are ignored, and deleting a referenced profile produces an attributable error.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 1.4 Document the rendered-input model, supported object scope, explicit removals, and lack of server-side-apply/admission prediction in `docs/policy-preview.md`; verify each example has a matching input fixture.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 2. Read-only cluster observation

- [x] 2.1 Add a direct kubeconfig/context snapshot reader for cluster identity, profiles, bindings, namespaces, and owned modern Kyverno policy state; verify shared-profile consumers outside the files, namespace UIDs, policy ownership, and pagination with a recording API test server.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 2.2 Add provenance and bounded rechecks of relevant configuration, namespace membership, applied-policy, acceptance (protected acceptance record, `status.acceptance` snapshot reference, frozen snapshot ConfigMaps), and bundle-source/trust ConfigMap projections; verify a concurrent change to each causes recapture or incomplete output and unrelated report timestamps do not force endless retry.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
  Narrowed to what is observable today. The separate acceptance-record, snapshot-reference, snapshot-content and source-ConfigMap drift cases were added with group 3; the unobservable projections are 2.5.
- [x] 2.3 Enforce the default 60-second total timeout, at most two recaptures, object/input limits, and cancellation; verify denied/missing required APIs, expired pagination, and exhausted limits never produce a successful empty or truncated snapshot.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 2.4 Document the get/list/discovery permission matrix and snapshot limits beside the command examples; verify recorded preview requests contain no Kubernetes mutation or write-shaped authorization/dry-run probe.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->
- [ ] 2.5 Add exception revocation and Secret-held trust material to the rechecked projections: revocation (`spec.revoked` and revocation records) once `add-self-service-policy-exceptions` 2.6/3.6 reach main, reported as `exception-revocation-unavailable` until then, and Secret-held trust material through the caller-authorized named Secret reads of 4.3, reported as `secret-not-read` until then; verify a concurrent revocation or Secret change causes recapture or incomplete output, and that no Secret is listed or its data reported.
  <!-- agent: tier=deep risk=medium reason="Snapshot consistency across exception revocation and caller-authorized Secret trust inputs owned by other changes" -->
  Secret half done with 4.3: referenced Secrets are read by name with the caller's identity in every capture and rechecked as a keyed digest of their referenced values (change → recapture, persistent change → `unstable`; denied → `secret-not-read`; nothing listed or reported). Revocation half open until the exception owner's 2.6/3.6 reach main.

## 3. Shared resolution and semantic comparison

- [x] 3.1 Add the baseline/candidate adapter around the versioned targeting resolver and verified content seam; verify shared profiles, cumulative Audit/Deny contributions, Forbidden precedence, shortest lifetime, unsupported policy scope, and unresolved overlap using targeting fixtures.
  <!-- agent: tier=deep risk=high reason="Caller authorization, bundle trust, and accepted-risk boundaries" -->
- [x] 3.2 Implement stable contribution/configuration comparisons and framework-neutral impact categories; verify added/removed namespaces, selectors, parameters, bundle pins, enforcement settings, zero-target changes, and metadata/order-only no-ops with report fixtures.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
- [x] 3.3 Separate observed identity from provisional resolver inputs and candidate fingerprints; verify new resources and rollback flag revision replacement without leaking provisional UIDs, generations, hashes, or engine names as real future values.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
- [x] 3.4 Correlate observed applied policies with desired contributions and stale scopes; verify retained old policies, pending replacement/temporary overlap, binding removal, and unresolved profile removal are distinguished from immediate withdrawal or new impacts.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
- [x] 3.5 Document impact categories and observed-versus-proposed interpretation; verify worked examples show remaining overlap and avoid workload-pass, eviction, or framework-coverage claims.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 4. Verified bundle resolution

- [x] 4.1 Adapt local vendored `ContentSource` for preview without provider or manager startup; verify checksum corruption fails and reports distinguish vendored checksum-manifest digests from OCI manifest digests.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
- [x] 4.2 After `add-policy-bundle-distribution` supplies its implementation, consume the source mapping, exact-digest resolver, current-trust verifier, and cache contract; verify signed public/private bundles, changed trust, cache reuse, digest mismatch, unavailable pins, and forbidden unsigned fallback.
  <!-- agent: tier=deep risk=high reason="Caller authorization, bundle trust, and accepted-risk boundaries" -->
- [x] 4.3 Wire caller-authorized registry credentials and narrowly referenced Secret reads through the shared source adapter; verify denied credentials produce incomplete output, no controller impersonation or secret listing occurs, and reports/diagnostics redact credential material.
  <!-- agent: tier=deep risk=high reason="Caller authorization, bundle trust, and accepted-risk boundaries" -->
- [x] 4.4 Document bundle-source selection, required caller access, digest meanings, and trust errors; verify the documented private-source workflow against the distribution owner's integration fixture.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->
  Verified by `internal/preview/content_test.go` (real stack, organization-key fixture, in-process TLS registry) and `TestLivePolicyPreviewPrivateBundle` (bundles group: disposable cluster, pinned registry, documented names and reader RBAC).

## 5. Exception and evidence integration

- [ ] 5.1 After `add-self-service-policy-exceptions` supplies acceptance readers, compare effective eligibility with authenticated records and frozen snapshots; verify renewal, newly Forbidden policy, shorter lifetime, added/removed contributions, namespace recreation, and refusal to infer acceptance from native skips.
  <!-- agent: tier=deep risk=high reason="Caller authorization, bundle trust, and accepted-risk boundaries" -->
- [x] 5.2 After `add-continuous-assessments` supplies the enforcement-epoch integration, consume its shared enforcement-input classification; verify reporting-only changes preserve acceptance while policy changes and rollbacks require a new enforcement revision.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
  The owner's classification exists only as CEL (the epoch admission policy and the CRD transition rule), so the preview keeps its Go equivalent, pinned to both (`TestEnforcementFieldsChangedMatchesTheAdmissionPolicy`, `TestEnforcementFieldsChangedMatchesTheCRDTransitionRule`), and computes revisions only with `EnforcementRevision` (design decision 8). `TestEnforcementEpochKeepsAcceptanceOnlyForReportingEdits` and `TestRollbackDoesNotReviveAnAcceptedRevision` apply each edit with the policy's own expression and check the accepted eligibility revisions.
- [x] 5.3 Consume `ExpectedEvidence` and the assessment owner's attribution/freshness read contract; verify old results are never attached to new revisions, missing/stale/unattributable evidence is informational, and unavailable required exception inputs instead make the preview incomplete.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
  `internal/preview/evidence.go`: subjects from `targeting.ExpectedEvidence`, evidence from each binding's `status.assessment.current` (read with the bindings, no new request or permission), judged at the end of the observation (design decision 8). Verified by `evidence_test.go` (owner precedence, churn without recapture, no attachment to new revisions, gaps informational, owner subjects), the `TestPreviewExitMatrix` evidence scenarios (missing, stale, unattributable, controller behind, new revision; an undetermined exception stays incomplete with current evidence) and the goldens. The `evidence` part gained `bindings` and `entries[].proposed` within report v1.
- [ ] 5.4 Document exception renewal consequences and evidence limitations with owner-backed examples; verify no preview path writes acceptance or schedules an assessment, and no example describes unavailable integration as shipped.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->

## 6. CLI output and CI contract

- [x] 6.1 Add independent `preview` dispatch and flags with no prototype/provider/controller startup; verify help, malformed flags, kubeconfig/context selection, unknown format, and preservation of existing command error behavior through command tests.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
  `cmd/konstapel/preview.go` over `preview.Run`; `TestPreviewFlags`, `TestPreviewKubeconfigSelection`, `TestPreviewStartsNothingElse` (startup hooks, source and dependency checks) and `TestExistingCommandsKeepTheirBehavior`. Flag defaults are design decision 7.
- [x] 6.2 Define JSON report v1 and render text from the same model with stable ordering, observations, typed digests, completeness, impacts, applied state, exceptions, evidence, and coded diagnostics; verify complete/incomplete golden reports and JSON stdout purity.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
  `internal/preview/report.go` and `render.go`; goldens in `cmd/konstapel/testdata/preview`. The `exceptions` and `evidence` parts define their v1 shape with `analysis: not-available` and stay empty until 5.1 and 5.3 supply their content; an observed exception in a changed namespace and policy makes the report incomplete (`exception-impact-undetermined`).
- [x] 6.3 Implement informational exit `0`, opt-in impact exit `2`, and failure/incomplete/output-error exit `1`; verify the full flag/outcome matrix, evidence-only and reporting-only changes, failure precedence after partial impacts, and broken-output handling at the process boundary.
  <!-- agent: tier=standard risk=medium reason="Bounded implementation or validation against explicit criteria" -->
  `TestPreviewExitMatrix` (every scenario with and without `--fail-on-impact`), `TestPreviewOutputErrors` and `TestPreviewProcessBoundary` (the real `main`: closed stdout, `/dev/full`, statuses 0 and 2).
- [x] 6.4 Add local and CI examples to `docs/policy-preview.md` and link them from the README/development guide when implemented; verify commands and saved JSON using the pinned Devbox environment without adding per-helper Taskfile wrappers.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->
  `TestDocumentedPreviewCommands` runs every documented command, the text excerpt, the jq expressions on the saved JSON and the field and flag tables under `task test`; no Taskfile change.

## 7. Integrated acceptance

- [ ] 7.1 Run the implemented preview with a get/list-only identity against a disposable cluster using the real targeting controller, Kyverno modern APIs, bundle resolver, and exception/assessment integrations; verify namespace expansion/removal, Audit-to-Deny, shared-profile pin changes, acceptance renewal, stale evidence, and the three exit outcomes while recording the absence of preview mutation requests.
  <!-- agent: tier=deep risk=medium reason="Consistent snapshots and cross-owner impact semantics" -->
- [ ] 7.2 Exercise live drift, inaccessible exception snapshots, denied private-bundle access, stale applied policies, and trust changes; verify incomplete versus informational outcomes and retain sanitized evidence of every integration gate without substituting fake-only acceptance.
  <!-- agent: tier=deep risk=high reason="Caller authorization, bundle trust, and accepted-risk boundaries" -->
- [ ] 7.3 Run the relevant existing Devbox/Task check and live acceptance workflows plus strict OpenSpec validation; verify all tasks against the implemented contracts, record results, and remove task-owned clusters, credentials, temporary artifacts, and background processes.
  <!-- agent: tier=standard risk=low reason="Document or check an established contract" -->
