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
| [Evidence signing](integration/evidence-signing.md) | Signing and offline verification contract for evidence archives (keys, bundle format, `cosign verify-blob` workflow); not yet wired into publication, so published packages are still unsigned. |
| [Linux hardening](integration/linux-hardening.md) | Shipped policy variants, partial mappings, and live admission coverage; background/applicability and exception integration still in progress. |
| [Policy exceptions](integration/policy-exceptions.md) | API, authenticated admission and acceptance snapshots exist; native grants remain disabled pending engine compatibility and lifecycle work. |
| [Helm charts](charts.md) | CRD and runtime charts: installation, both TLS modes and certificate rotation, values, feature availability and installed-image acceptance; not yet published, and exception admission is not in the chart. |
| [Policy bundles](policy-bundles.md) | Payload contract, central sources, registry retrieval, signature and provenance verification, the content cache, controller and Helm wiring, and bundle releases; the first official bundle (`konstapel-privileged-containers` 0.1.0) is published. Remaining work is tracked in the `add-policy-bundle-distribution` change. |
| [Official bundle Audit walkthrough](integration/bundle-audit-walkthrough.md) | Copy-paste run on a disposable kind cluster: official sources, a profile pinning the released bundle by digest, an Audit binding, a privileged Pod admitted, and the assessment finding with matching bundle and content digests. Run by hand, not in CI. |
| [Assessment-loop prototype](integration/assessment-loop.md) | Standalone Kyverno/C2P runner and shared disposable-cluster acceptance commands. |
| [Trivy proposal](../openspec/changes/add-trivy-vulnerability-assessment/proposal.md) | Planned reporting-only image vulnerability assessment; no implemented Trivy provider yet. |

## Develop and release

- [Development](development.md): Devbox/direnv, Task workflows, parallel CI
  acceptance groups, log locations, and dependency ownership.
- [Images](images.md): melange/apko, SBOMs, license notices, signing, and verification.
- [Releases](releases.md): release-please, required acceptance, and publication.
- [v0.1.0 readiness](release-readiness.md): what the first release ships, the
  test behind each claim, and known limitations.
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
