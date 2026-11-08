# Tasks

## Execution boundaries

Group 1 and the isolated packaging/registry fixtures from group 5 can start now.
Keep fixture CRDs and test runtimes outside distributable chart content.
Groups 2–4 require the merged targeting APIs/manager and their generated files.
Exception, assessment, and download integration uses each feature's merged
contracts and tested gates; planning artifacts do not satisfy those prerequisites.
Do not publish a functional chart backed only by the prototype CLI.

This change owns charts, chart helpers/tests/docs, capability-monitor integration,
and the chart additions to release/version automation and controller image
packaging. It consumes API definitions,
generated RBAC, admission handlers and service interfaces from their owning changes.
Do not create another manager or API schema, alter another change's task list,
or enable production publication before the applicable runtime tests pass.
Coordinate shared manager and release-file edits after rebasing.

Consume `add-controller-high-availability` for the replicated runtime lifecycle
and acceptance contract. This Helm change owns its chart values, Deployment,
Service/PDB/anti-affinity resources and rendering tests; the availability change
owns manager lifecycle and cross-feature failure tests. Chart fixtures can start
independently, but release acceptance requires that integrated runtime.

Go black-box acceptance against the Helm-installed image and its public APIs is
part of this change. Local runs alone, in-process manager tests, rendering checks,
or upstream Chainsaw policy fixtures do not satisfy the required CI/release gate.
Keep the existing fast checks and feature-owned integration suites alongside it.

## 1. Establish chart inputs and independent fixtures

- [x] 1.1 Define the chart input contract for generated CRDs/RBAC, available capabilities, manager entry point, ports/probes, TLS, writable storage, image inputs and the availability owner's Lease/shutdown/replica lifecycle; verify every field is traced to a named implementation owner and unresolved inputs cannot be substituted with a fixture in a release.
- [x] 1.2 Add metadata and values-schema scaffolding for the two independent charts with fixture render cases; verify chart names, the `compliance.erenius.io` API contract, mutually exclusive TLS settings, and absence of CRD/Kyverno/cert-manager chart dependencies.
- [x] 1.3 Extend release-please and the existing version helper to update/check both charts' version and appVersion; verify an unchanged-schema release advances both charts and a deliberate version mismatch fails the check.
- [x] 1.4 Add packaging-input/publication-manifest fixtures recording source revision, chart versions, archive checksums and image digest; verify source/digest mismatches, missing artifacts and incompatible version pairs fail before registry writes.
- [x] 1.5 Document ownership, phase dependencies, fixture entry points and chart release/version rules; verify another agent can run the independent checks through Devbox without a controller, cluster, or production registry credentials.

## 2. Package authoritative CRDs and prove their lifecycle

- [x] 2.1 After API implementations land, generate the CRD chart from their canonical outputs with only reviewed packaging metadata; verify normalized schemas, defaults, validation, scopes and subresources match and placeholder or obsolete definitions cannot ship.
- [x] 2.2 Add retention metadata to every CRD and prohibit destructive chart cleanup paths; verify rendered output has no deletion/recreation hooks, unsafe owner references, purge option or finalizer-removal behavior.
- [x] 2.3 Exercise explicit CRD upgrades with the pinned Helm in kind; verify existing object UIDs/spec/status/finalizers survive unchanged-schema version bumps and supported additive changes, and document the tested previous-controller transition when a prior runtime exists.
- [x] 2.4 Exercise CRD-chart uninstall and same-identity reinstall with populated objects; verify definitions/data survive, retained ownership supports the documented reinstall, and conflicting release ownership is reported without adoption or deletion.
- [x] 2.5 Document CRDs-first installation, supported upgrade/rollback boundaries and retained-resource ownership; verify the commands reproduce the lifecycle fixtures and explain that explicit CRD deletion is outside Helm uninstall.

## 3. Wire the real controller, admission and TLS services

- [x] 3.1 Consume the merged manager entry point, extend the existing build/melange/apko packaging as needed, and wire its image/provider paths in the runtime chart; verify a real installed controller reconciles a profile/binding and invokes C2P with non-root, read-only-root and bounded writable-storage defaults while preserving the CLI/provider smoke tests.
- [x] 3.2 Render generated RBAC, ServiceAccounts, Services and implemented feature settings; verify schema/default fixtures grant only the owners' required permissions, reference no missing handlers, and expose no values that bypass exception governance or download authorization.
- [ ] 3.3 Add default cert-manager Certificates/Issuers, optional platform issuer references and CA-injection metadata; verify real issuance matches the release's service DNS identities and the chart neither installs nor manages cert-manager itself.
- [x] 3.4 Add operator-managed TLS Secret/CA configuration; verify installation without cert-manager, caller Secret preservation, and explicit failure for absent keys, expiry, wrong service identity or mismatched trust.
- [ ] 3.5 Wire serving probes and certificate reload through the owning runtime interfaces; verify leaf and CA rotation preserve protected admission/download behavior, invalid TLS is not reported ready, and Kyverno unavailability does not remove otherwise healthy webhook endpoints.
- [ ] 3.6 Document both TLS modes, trust rotation, runtime values and feature availability; verify the examples render and install without changing the existing CLI workflow or claiming unimplemented exception/download support.
- [x] 3.7 Render and document the availability defaults: two replicas, preferred hostname anti-affinity, minAvailable 1 PDB when replicas exceed one, zero-unavailable/one-surge rolling updates and 60s termination grace; verify default/development/override fixtures, stable release selectors including all ready serving pods, timing validation, explicit one-replica development without the default PDB, and no required node separation or leader-only routing.

## 4. Recover from external engine prerequisites

- [x] 4.1 Implement capability discovery and service-account authorization checks on the merged manager boundary; verify missing resources, wrong group/version/scope/verbs, denied discovery/use and transport errors produce distinct results for delivery, assessment and exceptions.
- [x] 4.2 Add bounded retries, discovery refresh and deferred/recoverable engine watches; verify starting without Kyverno and subsequently adding, removing and restoring its API resources recovers without process restart or an unbounded retry loop.
- [ ] 4.3 Feed capability results into existing Conditions and operation gates; verify unavailable reports cannot establish compliance, missing exception prerequisites cannot activate grants, and unrelated healthy capabilities continue without deleting managed policies.
- [x] 4.4 Exercise live permission loss/recovery and engine rollout with existing policies and configuration admission; verify truthful readiness, retained enforcement, recovered watches, and no downgrade to legacy Kyverno policy APIs or bypass of the exception expiry/governance gate.
- [x] 4.5 Document required API resources/permissions, tested capability versions and condition-based troubleshooting; verify the walkthrough distinguishes API presence, serving health, policy readiness and evidence completeness.

## 5. Publish and verify aligned OCI artifacts

- [ ] 5.1 Implement packaging from a clean release checkout and its verified published image digest, using an isolated chart copy; verify the exact tested archives have aligned metadata, recorded inputs, LICENSE/NOTICE, no secrets and the intended default image digest.
- [ ] 5.2 Implement serialized write-once chart publication with frozen archives and durable retry inputs; verify a local registry/fault fixture preserves existing versions, rejects conflicting bytes and resumes after the first chart or an attestation is published.
- [ ] 5.3 Add per-OCI-digest Cosign signing, provenance/packaging-input attestations and remote verification; verify source SHA versus dispatch SHA, issuer/workflow identity, subject type/digest, chart-layer checksum and image identity, including rejection of forged or mismatched fixtures.
- [ ] 5.4 Integrate reusable chart publishing after image publication and explicitly dispatch checks, including chart acceptance, for release-please PRs; verify ordinary main pushes cannot overwrite chart versions, PR jobs cannot publish/sign in production, and release success requires acceptance of the frozen inputs plus both verified chart subjects.
- [ ] 5.5 Extend idempotent release notes and CI summaries with both chart references/digests and verification/install commands; verify repeated updates preserve existing changelog/user text and installation consumes the archive matched to the verified OCI digest.
- [ ] 5.6 Document release and partial-publication recovery, expected trust identities and image/CRD provenance; verify retry uses the original artifacts and missing recovery inputs fail visibly rather than replacing the release's contents.

## 6. Verify the complete installation and release workflow

- [ ] 6.1 Wire shared chart checks into `task check` and expose only `charts:package` and `charts:acceptance` for the new recurring workflows; verify local and CI use Devbox and the same helpers, update the development command table, and keep signing/summary/digest helpers private.
- [ ] 6.2 Implement Go black-box tests for the documented two-chart lifecycle in kind, driving Helm, Kubernetes APIs and service endpoints against the exact packaged controller image; verify every shipped CRD's defaults/validation and protected status/RBAC boundaries, both TLS modes, default replicas, late Kyverno readiness, policy delivery, available assessment/exception/download features with a real S3 backend, upgrades and retained-CRD reinstall. Consume the availability owner's leader-failure/serving/recovery tests for release acceptance; no in-process manager or fake backend may substitute for the installed runtime.
- [ ] 6.3 Verify the trusted publication path for a release candidate pair and exercise incomplete/signature-failure recovery; retain both remote verification results and confirm neither chart is reported successfully released until both subjects and their original inputs match.
- [ ] 6.4 Retain sanitized test results, logs, events, Conditions, tested source/archive/image identities and the version matrix on success, failure and timeout; tear down task-owned test releases, retained test CRDs/instances, clusters, registry data and processes through explicit cleanup. Verify cleanup failures remain visible, unrelated infrastructure remains untouched, no kubeconfigs/tokens/private keys enter CI artifacts, and the existing prototype checks still pass.
- [ ] 6.5 Add a separate CI acceptance workflow using the same Devbox `charts:acceptance` task on relevant pull requests and main pushes, and configure its stable gate as a required merge check; verify runtime/API/chart/content/image/dependency/tool/test/release/CI changes and unknown paths execute acceptance, documentation-only exclusions are explicit, bot release PR dispatch works, and a failed live case blocks a PR despite green fast checks. Document bounded runner resources, isolated fixtures and serialization for shared runners.
- [ ] 6.6 Require the full applicable release acceptance matrix before chart publication and bind its result to the frozen source, archive checksums and verified image digest; verify missing/failed/cancelled/skipped results and stale or substituted inputs block publication, nightly/manual-only results cannot bypass required gates, and no artifacts are rebuilt or replaced between acceptance and publishing.
