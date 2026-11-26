# Documentation

Konstapel's Kubernetes API is alpha and implementation is ongoing. Guides below
describe implemented behavior and call out incomplete integration or compatibility
gates. OpenSpec planning completion does not mean a feature has shipped.

## Purpose and design

- [Vision](../vision.md): project purpose, initial scope, and principles.
- [Architecture](../ARCHITECTURE.md): controller responsibilities, C2P providers,
  evidence flow, and planned vulnerability assessment.
- [Durable specifications](../openspec/specs): accepted capability contracts.
- [Active changes](../openspec/changes): proposed behavior and implementation
  checklists; read each change's tasks for remaining work.

## Operate and assess

| Guide | Scope and status |
| --- | --- |
| [Targeting API](integration/targeting-api.md) | Implemented profiles, bindings, namespace selection, revision ownership, and Kyverno delivery. |
| [Assessment workflows](integration/assessment-workflows.md) | Implemented schedules, on-demand requests, results, and namespace downloads. |
| [Assessment contract](integration/assessment-contract.md) | Alpha APIs, scheduling, frozen captures, attribution, package/export contracts, and remaining integration boundaries. |
| [S3 evidence](integration/s3-evidence.md) | Implemented publishing, download and retention behavior; destination API, legacy-file migration, retirement, and orphaning details. |
| [Evidence signing](integration/evidence-signing.md) | Implemented: signing and offline verification contract (keys, bundle format, `cosign verify-blob` workflow), EvidenceDestination signing policy, key Secret setup and readiness, frozen signing intents and the signed-commit gate (Required destinations never publish unsigned), authorized signature downloads, key rotation and the signature lifecycle. Administrator re-signing of a `SigningFailed` run is deferred to `add-evidence-signing-recovery`. |
| [Linux hardening](integration/linux-hardening.md) | Shipped policy variants, partial mappings, live admission and background assessment coverage; exception integration waits for exceptions. |
| [Control coverage](control-coverage.md) | Implemented baseline inventory, authored technical coverage model, attributed technical evidence, `coverage.json`/`coverage.txt` in every package, bounded status summaries and supporting-evidence context. Accepted risk is not reported until exception integration exists. |
| [Supporting evidence](supporting-evidence.md) | Implemented platform-registered EvidenceAttachment records: API, authenticated registrant, association validation, upload, storage, download, lifecycle and package inclusion through the download service and `konstapel evidence`. |
| [Policy exceptions](integration/policy-exceptions.md) | API, authenticated admission, revocation intent (`spec.revoked`), acceptance snapshots and independent revocation records exist, with the documented create, revoke, renew and delete workflow. Revocation processing ships off and the chart cannot enable it; native grants and withdrawal remain blocked on an upstream Kyverno release. |
| [Helm charts](charts.md) | CRD and runtime charts, published as signed OCI artifacts: installation, both TLS modes and certificate rotation, values, feature availability and installed-image acceptance. Exception admission is not in the chart. |
| [Policy bundles](policy-bundles.md) | Payload contract, central sources, registry retrieval, signature and provenance verification, the content cache, controller and Helm wiring, and bundle releases; the first official bundle (`konstapel-privileged-containers` 0.1.0) is published. Remaining work is tracked in the `add-policy-bundle-distribution` change. |
| [Official bundle Audit walkthrough](integration/bundle-audit-walkthrough.md) | Copy-paste run on a disposable kind cluster: official sources, a profile pinning the released bundle by digest, an Audit binding, a privileged Pod admitted, and the assessment finding with matching bundle and content digests. Run by hand, not in CI. |
| [Assessment-loop prototype](integration/assessment-loop.md) | Standalone Kyverno/C2P runner and shared disposable-cluster acceptance commands. |
| [Policy change preview](policy-preview.md) | The read-only `konstapel preview` command: rendered inputs, cluster observation under the caller's kubeconfig, semantic comparison, verified bundle content, evidence context, JSON report v1 and text, exit statuses, and verified local and CI examples. Exception-acceptance consequences are not analyzed, and a preview that could affect an observed exception is incomplete. |
| [Trivy proposal](../openspec/changes/add-trivy-vulnerability-assessment/proposal.md) | Planned reporting-only image vulnerability assessment; no implemented Trivy provider yet. |

## Develop and release

- [Development](development.md): Devbox/direnv, Task workflows, parallel CI
  acceptance groups, log locations, and dependency ownership.
- [Assessment providers](assessment-providers.md): the installed-provider
  descriptor and registry, selection checks, the conformance harness, the
  test-only provider boundary and the
  [provider-authoring recipe](assessment-providers.md#authoring-a-provider)
  with its Devbox commands. Kyverno is the only supported provider.
- [Images](images.md): melange/apko, SBOMs, license notices, signing, and verification.
- [Releases](releases.md): release-please, required acceptance, and publication.
- [v0.3.0 readiness](release-readiness.md): what release 0.3.0 ships, the test
  behind each claim, upgrade and rollback constraints, and known limitations.
- [Contributor instructions](../AGENTS.md): branch/PR workflow and tooling rules.

Current tool pins live in [devbox.json](../devbox.json) and
[devbox.lock](../devbox.lock); current acceptance runtime inputs live in
[scripts/runtime.env](../scripts/runtime.env). Historical evidence records the
versions used for that run, not necessarily today's pins.

## Research and historical validation

- [Original assessment-loop validation](integration/validation-results.md) and
  [reconciled implementation record](integration/reconciliation.md).
- [Next-policy-bundle research](research/next-policy-bundle.md), followed by the
  implementation guide under Linux hardening above.
- Committed JSON records alongside the integration guides preserve observed
  versions, results, and artifact digests. Interpret them at their recorded scope
  and date; use current CI evidence for a new revision.
