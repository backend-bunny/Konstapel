# v0.3.0 readiness

This page covers release 0.3.0: what it ships, the test behind each claim, and
what it leaves out. It is meant to be read on its own; you don't need the
OpenSpec task history to interpret it.

Each claim names the test that backs it. "Release" means the check runs in
the release workflow itself, against the frozen release artifacts
([Releases](releases.md)). Every other test is part of the required `checks`
and `acceptance` gates on every pull request and main push. Live tests run in
the acceptance group named in brackets ([`scripts/acceptance-groups.json`](../scripts/acceptance-groups.json)).

Each feature falls into one of three states:

- **Supported** features are implemented, documented and covered by the named
  tests.
- **Partial** features ship with the explicit limits listed beside them.
- **Disabled** features have code or API present, but it is off and can't be
  turned on through the chart.

For the earlier checklist, written for 0.1.0 and still current at 0.2.0, see
the [v0.2.0 tag's copy](https://github.com/backend-bunny/Konstapel/blob/v0.2.0/docs/release-readiness.md).
Every claim from it that still applies is carried forward below.

## What ships

| Artifact | Reference | Contents |
| --- | --- | --- |
| Controller image | `ghcr.io/backend-bunny/konstapel@sha256:…` (digest in the release notes) | `konstapel controller`, `konstapel download-server`, `konstapel evidence` and `konstapel preview`, the C2P provider and vendored content; signed, with SPDX SBOMs, source/notice attestations and build provenance ([Images](images.md)) |
| CRD chart | `oci://ghcr.io/backend-bunny/charts/konstapel-crds@sha256:…` | the seven `compliance.erenius.io/v1alpha1` CRDs (0.2.0's six plus `EvidenceAttachment`), kept on uninstall |
| Runtime chart | `oci://ghcr.io/backend-bunny/charts/konstapel@sha256:…` | controller and download server (two replicas each), RBAC, admission policies, TLS (cert-manager or operator Secret), optional metrics, ServiceMonitor and PrometheusRule; defaults to the released image digest |

Both charts carry version `0.3.0`, the same as `VERSION` and the image. Each
chart subject is signed, with a chart-inputs attestation and GitHub
provenance. The digests exist only after publication; until then this page
describes a candidate.

## Feature status

| Feature | State | Default | Limits and guide |
| --- | --- | --- | --- |
| Profiles, bindings, namespace targeting, Kyverno Audit/Deny delivery | Supported | on | [Targeting API](integration/targeting-api.md) |
| Continuous and on-demand assessments, OSCAL through C2P | Supported | on | Evidence is requested configuration, not runtime state ([limitations](#known-limitations)) |
| S3 publication, authorized downloads, retention | Supported | on (download service) | RustFS 1.0.3 is the only tested backend ([S3 evidence](integration/s3-evidence.md)) |
| Evidence signing (Cosign key, `EvidenceDestination.spec.signing`) | Supported | off per destination | Key Secrets only; `kms` and `keyless` are rejected. A run that ends `SigningFailed` can't be re-signed yet: administrator signing recovery is deferred ([evidence signing](integration/evidence-signing.md)) |
| Supporting-evidence attachments (`EvidenceAttachment`, `konstapel evidence`) | Supported, with limits | API on; uploads need the download service | Platform-registered only; no application-team attachments. Packages carry documents only while every download replica runs this release ([supporting evidence](supporting-evidence.md)) |
| Prometheus metrics, ServiceMonitor, PrometheusRule | Supported | off (`metrics.enabled`) | Authenticated TLS endpoint ([metrics](integration/metrics.md), [alert runbooks](integration/alert-runbooks.md)) |
| Control coverage (`coverage.json`/`coverage.txt`, status summaries) | Partial | on | Accepted risk is never reported, because no exception projection exists yet. Coverage describes partial, configuration-level evidence ([control coverage](control-coverage.md)) |
| Controller high availability (two replicas, Lease, per-replica serving) | Supported | on | Tested with two replicas and short failure windows, not sustained load ([availability](integration/availability.md)) |
| Verified OCI policy bundles | Supported | off (`bundles.sourcesConfigMap`) | [Policy bundles](policy-bundles.md) |
| Policy-change preview (`konstapel preview`) | Partial | client command | Read-only, using the caller's kubeconfig. It does not analyze exception consequences: a change that could affect an observed exception makes the report incomplete (exit 1) ([policy preview](policy-preview.md)) |
| Self-service exceptions: admission webhooks, native Kyverno grants | Disabled | off; the chart can't enable them | Waiting for an upstream Kyverno release ([policy exceptions](integration/policy-exceptions.md)) |
| Exception revocation processing (revocation records, finalizer release) | Disabled | off; `exceptions.revocationProcessing.enabled=true` fails the render | Needs the exception webhooks above ([charts](charts.md#exception-revocation-processing)) |
| Linux hardening bundle | Supported for admission and background assessment | profile-selected | Exception-dependent cases are not available ([Linux hardening](integration/linux-hardening.md)) |
| Trivy vulnerability assessment | Not in 0.3.0 | | [proposal](../openspec/changes/add-trivy-vulnerability-assessment/proposal.md) |

## Checklist

### Clean installation

| Claim | Evidence |
| --- | --- |
| The CRD chart installs every shipped CRD, and the runtime chart installs on Kubernetes ≥ 1.36 into `konstapel-system` | `TestLiveHelmInstall`, `TestLiveCRDChartLifecycle` (`charts`); release: `charts:acceptance` on the frozen archives |
| Every shipped CRD's defaults, validation (including the documented examples), status subresource, immutable fields and status RBAC hold through the installed release's roles and admission policies | `TestLiveHelmLateKyverno` (`charts`) |
| The runtime chart refuses another namespace, a missing digest, unsafe timing or PDB values, and enabling exception revocation processing, at render time | `internal/charttest` (including `TestRuntimeChartExceptionRevocationGated`), `scripts/charts/check.sh` fixtures |
| Two hardened replicas (non-root, read-only root, no capabilities) become ready, and one holds the Lease | `TestLiveHelmInstall`, `TestLiveHelmAvailability` (`availability`) |
| Both TLS modes work: cert-manager (chart CA or platform issuer) and an operator Secret | `TestLiveHelmInstall` steps 4–8 |
| Leaf and CA rotation reach every replica without a restart. Invalid or expired TLS makes a replica not ready, but never opens an unauthenticated download or bypasses fail-closed admission | `TestLiveHelmInstall` (download), `TestLiveReplicaAdmission` (webhook against the API server), `TestCertificatesReloadRotation`, `TestWebhookCARotation` |
| The documented examples render and install | `TestDocumentedExamples`; `TestLiveHelmInstall` uses `operator-tls.yaml` and `platform-issuer.yaml`, and `TestLiveHelmAvailability` uses `development.yaml` |

### Assessment, publication and download

| Claim | Evidence |
| --- | --- |
| Profiles and bindings deliver Kyverno policies in Audit or Deny, scoped by namespace selector | `TestLiveDelivery`, `TestLiveTargetingWorkflow`, `TestLiveEnforcementEpoch` (`admission`) |
| Scheduled and team-requested runs collect attributable evidence and export OSCAL through C2P | `TestLiveAssessmentRuns`, `TestLiveIntegratedAssessments` (`assessments`), `TestLiveEvidenceDownload` (`storage`) |
| Missing, stale or unattributable evidence makes a run `Incomplete`, never a pass | `TestLiveHardeningBackground` (Kyverno first-failure gap reported as missing), collector unit tests |
| The Linux hardening bundle assesses pre-existing workloads; explicit Windows workloads are not applicable rather than passing | `TestLiveHardeningBackground`, `TestWindowsWorkloadIsOutOfScopeNotPassing` |
| Packages are published write-once to S3 with receipts, retention and expiry | `TestLiveDestinationPins`, `TestLiveRetentionLifecycle` (`storage`), `TestPublisherRoundTrip` |
| Downloads are authorized per request (TokenReview and SubjectAccessReview) and served by any replica, with no leader needed | `TestLiveEvidenceDownload`, `TestLiveHelmInstall` (follower downloads, revocation, credential rotation, namespace-UID isolation) |

### New in 0.3.0

| Claim | Evidence |
| --- | --- |
| **Signing.** A destination with `signing.mode: Required` signs every package with its ECDSA P-256 Cosign key and never publishes unsigned. A signing failure keeps the evidence and ends the run `SigningFailed` | `TestLiveDestinationSigning`, `TestLiveSignedPublicationWorkflow` (`storage`), `publication_signing_test.go`, `publication_signing_lifecycle_test.go` |
| **Signing.** Signatures verify offline with the pinned Cosign (`cosign verify-blob`), and a signature is served beside its archive only after the pair verifies | `TestCosignInteroperability`, `TestDocumentedVersionsArePinned`; `TestLiveSignedEvidenceDownload` (`storage`) |
| **Signing.** A leader lost mid-signature recovers the same run and publication identity | `TestLiveHelmDurableRecovery` (`availability`, release) |
| **Attachments.** Platform registrants register documents against binding catalogs and baselines, upload and download them through the download service, and see them withdrawn and cleaned up only after retention | `TestLiveEvidenceAttachmentAPI` (`admission`); `TestLiveAttachmentStorage`, `TestLiveAttachmentTransfer`, `TestLiveAttachmentLifecycle` (`storage`); `TestLiveHelmSupportingEvidence` (`charts`) |
| **Attachments.** Packages carry the documents valid at closure, and protected packages are served only to callers with the document-read grant | `TestLiveSupportingEvidencePackages` (`storage`), `TestLiveSupportingEvidenceAcceptance` (`assessments`), `TestLiveSupportingEvidenceRecovery` (`recovery`) |
| **Metrics.** The metrics endpoint authenticates (TokenReview and SAR) and serves only to `metrics.readers`; a cut-off leader serves no metrics | `TestLiveObservability`, `TestLiveLeaderObservability` (`admission`), `TestLiveHelmMetrics` (`charts`) |
| **Metrics.** The ServiceMonitor and PrometheusRule work against a real Prometheus Operator, and every alert has a runbook | `TestLiveHelmMonitoring` (`monitoring`, release), promtool rule tests, `TestOwningGuidesDocumentSignals` |
| **Coverage.** Every package carries `coverage.json` and `coverage.txt`, listing every baseline control with its authored checks and attributed technical evidence. Run, request and binding status carry a bounded summary, and a tampered coverage file fails package validation | `internal/coverage` tests, `TestRunPackageCarriesCoverage`, `TestValidatePackageRejectsTamperedCoverage`, `TestLiveIntegratedAssessments` |
| **High availability.** Every replica serves admission and readiness on its own, independent of leadership | `TestServingRunnablesNeedNoLeadership`, `TestInformerSyncGatesReadiness`, `TestWebhookReadinessFollowsTLS`; `TestLiveReplicaAdmission`, `TestLiveHelmAvailability` |
| **Bundles.** Content is resolved by bundle name and digest, so an unavailable reference affects only its own consumers | bundle resolution unit tests; `TestLiveBundlesOfficial`, `TestLiveBundlesOrganization` (`bundles`), `TestLiveHelmBundles` (`charts`) |
| **Preview.** `konstapel preview` sends only GET requests under the caller's kubeconfig, with no watch, dry-run, impersonation or access-review probe, and reads only the Secrets that bundle sources reference | `TestReadOnlyTransportRefusesBeforeSending`, `TestReadOnlyTransportAllowsOnlyReferencedSecretGets`, `TestRESTConfigUsesOnlyKubeconfig`; `TestLivePolicyPreviewObservation` (`admission`, wire-recorded as the documented get/list-only reader), `TestLivePolicyPreviewPrivateBundle`, `TestLivePolicyPreviewCLI` (`bundles`: the built binary under a reader ServiceAccount token, every request recorded through a proxy, and resourceVersions of profiles, bindings, exceptions, engine policies and controller-namespace ConfigMaps/Secrets unchanged after each of 18 invocations) |
| **Preview.** Inaccessible inputs, persistent drift during observation, untrusted or unavailable content, and a change that could affect an observed exception make the report incomplete (exit 1). Evidence gaps are informational and never change the exit status | `TestObserveIncompleteWhenDriftPersists`, `TestObserveRequiredInputsFailClosed`, `TestObserveRecapturesOnRevocationChange`, `TestBundleContentRejectsUntrustedAndUnavailableContent`, `TestEvidenceGapsAreInformational`, `TestPreviewExitMatrix`, `TestPreviewProcessBoundary`; live through the binary in `TestLivePolicyPreviewCLI` (selector, mode, shared-profile pin and removal impacts exit 0, or 2 with `--fail-on-impact`; a denied snapshot read, denied bundle Secrets, persistent drift, a rotated publisher key and an exception in a changed namespace exit 1; stale applied policies and missing or unattributable evidence stay informational) |
| **Exceptions stay disabled.** No chart configuration grants the controller exception writes or serves exception webhooks. The controller refuses revocation processing without the webhooks and stops when it can't verify them; with processing off, nobody can release the revocation finalizer | `TestRuntimeChartExceptionRevocationGated`, `TestRuntimeChartCannotActivateNativeExceptions`, `TestRevocationProcessingDisabled`, `TestRevocationProcessingNeedsTheWebhooks`, `TestRevocationProcessingWaitsForAdmissionProtection`, `TestVerifyProtection`; `TestLiveRevocationHistory` (`assessments`, exception harness) |

### Recovery

| Claim | Evidence |
| --- | --- |
| Leader pod loss and node loss: another replica leads within about 20 s and reconciles | `TestLiveHelmAvailability` |
| Under admission and download traffic, graceful follower or leader replacement, an abrupt leader kill, leader API loss and node loss never admit a privileged pod, never serve a wrong package, and keep the engine policies' UIDs. A revoked download operator is refused by every replica at once | `TestLiveHelmFailoverTraffic` (`availability`; [measurements](integration/availability.md#failover-under-traffic)) |
| A bundle registry outage or trust rotation during a handover delivers from verified caches only, keeps the applied policies, and otherwise reports `ContentUnavailable` | `TestLiveHelmBundles` (`charts`) |
| Kyverno keeps enforcing, and downloads keep serving, while no controller runs | `TestLiveHelmAvailability`, `TestLiveHelmInstall` |
| A run staged in S3 is committed by another replica after the Lease holder's pod is removed, with the same run and publication identity and the exact staged bytes; nothing is committed twice | `TestLiveHelmDurableRecovery` (`availability`), `TestLiveLeaderHandoverRecovery`, `TestLiveLeaderHandoverLoss` |
| A capture lost before durable staging is reported as `CaptureLost`, never published; an S3 outage alone never causes it | `TestLiveHelmAvailability`, `TestLiveHelmDurableRecovery`, `TestLiveLeaderHandoverLoss` |
| Installed before Kyverno, both charts become ready, report the missing engine and establish no evidence; Kyverno installed later is used without a restart | `TestLiveHelmLateKyverno` (`charts`) |
| Kyverno API or permission loss is reported and recovers without a restart; unavailable policy reports never establish compliance | `TestLiveEngineCapabilityRecovery` (`capabilities`), `TestUnavailableReportsCannotEstablishCompliance`, `TestAssessmentCapabilityGate`, `TestDeliveryCapabilityReasons` |
| A Kyverno installation without the ephemeral-container grant is reported at the binding with the missing verbs and policy; after the documented grant, the same controller recovers readiness and attributable evidence, keeping policy UIDs, ownership, revisions and enforcement | `TestLiveKyvernoPermissionRecovery` (`capabilities`), `TestBindingRechecksPermissionFailureWithinBackoff`, `TestRecheckWritesOnlyTheAnnotationWithinTheBackoff` |

### Upgrade and uninstall

| Claim | Evidence |
| --- | --- |
| CRD chart upgrades (same-schema and additive) keep objects, UIDs and finalizers; uninstall keeps the CRDs and their objects; a same-identity reinstall takes them back; a different release is refused | `TestLiveCRDChartLifecycle` |
| Runtime upgrades roll without dropping below two ready controllers, and a blocked surge keeps serving | `TestLiveHelmAvailability` |
| Uninstalling the runtime chart leaves an operator-supplied TLS Secret, delivered policies and published packages in place, and a reinstall resumes on the same revisions | `TestLiveHelmInstall` |

### Artifact verification

| Claim | Evidence |
| --- | --- |
| The image is signed and attested, and is verified before release | the image publish workflow ([Images](images.md#verify)) |
| Chart archives are frozen (source commit, checksums, CRD content, image digest) before acceptance, and only accepted bytes are published, write-once | `test_chart_manifest.py`, `test_chart_publish.py`, `test_chart_release_inputs.py`; release: the `charts` workflow |
| Each chart subject is signed, with a chart-inputs attestation binding source, image, archive and acceptance. Verification pulls the subject by digest and compares bytes | `test_chart_publish.py` (key pairs); release: keyless verification in the `charts` workflow |
| Release acceptance runs every release-required group (`charts`, `monitoring`, `availability`) on the frozen archives and the released image digest. A missing, failed, skipped, stale or mismatched record is refused before any registry write | `test_chart_evidence.py`, `test_chart_publish.py`, `test_acceptance.py`; release: `task charts:acceptance` in the `charts` workflow |
| A partial publication resumes from the frozen release assets without re-packaging, and never overwrites an existing chart version | `test_chart_publish.py`; release: `charts` workflow dispatched with the tag ([Chart publication](releases.md#chart-publication)) |
| The release notes' install commands install exactly the verified bytes | `test_documented_install_commands_pull_the_frozen_archives` |

## Supported versions

These are the versions the acceptance suites run against
([`scripts/runtime.env`](../scripts/runtime.env), [`devbox.json`](../devbox.json)).
Other versions are untested, not known to be broken.

| Component | Tested |
| --- | --- |
| Kubernetes | 1.37.0 (kind node). The chart requires ≥ 1.36 for MutatingAdmissionPolicy |
| Kyverno | 1.19.2 (chart 3.9.2), `policies.kyverno.io/v1` ValidatingPolicy and `wgpolicyk8s.io/v1alpha2` reports |
| cert-manager (optional) | v1.21.3 |
| Prometheus Operator (optional) | v0.95.2, rules checked with Prometheus v3.16.0 promtool |
| Helm | 4.3.1 |
| Cosign (signature verification) | v3.1.3 |
| S3 | RustFS 1.0.3, all three versioning modes. AWS S3 and other services are untested ([S3 evidence](integration/s3-evidence.md#tested-compatibility)) |
| OCI registries (bundles) | distribution `registry` 3.1.2 (tag-schema fallback) and zot v2.1.23 (referrers API); official bundles are published to ghcr.io |

## Upgrading from 0.2.0

Upgrade the CRD chart first, then the runtime chart
([Helm charts](charts.md#crd-chart)). Every CRD change in 0.3.0 is additive:
the new `EvidenceAttachment` CRD, plus new optional spec and status fields
for signing, coverage, supporting evidence and `ComplianceException.spec.revoked`.
The storage version stays `v1alpha1`, and no existing field is removed or
narrowed.

**Upgrade probe.** The upgrade from the published 0.2.0 charts was run by
hand on a disposable kind cluster, not as an automated test. The 0.3.0
candidate was built from main `ab4d3df`: image
`sha256:c0ea8d948893cd1ec05ec3e50be84d65f8d60a71c5ebae416f78d3576b3b4809`,
with charts packaged by `scripts/charts/package.sh`. The setup was Kyverno
3.9.2, cert-manager TLS, two replicas each, and a Deny binding on the vendored
privileged-containers policy. The release commit changes only version
strings, so the released archives' bytes differ from the tested ones.

The upgrade ran CRD chart first, then runtime chart. Results:
- every existing CRD, profile, binding and destination kept its UID,
  generation and finalizers, with `storedVersions` still `v1alpha1`;
- the binding kept its enforcement epoch and configuration revision;
- the delivered Kyverno policy was not recreated (same UID and resourceVersion);
- both Deployments stayed at two ready replicas;
- no privileged pod was admitted during the rollout (0 of 324 samples);
- the logs showed no decode or conversion errors;
- the controller gained no exception-write grant.

Within one version, the rolling-upgrade and additive-CRD behavior above is
also covered by the automated tests.

On a single small node, Kyverno's reports controller at its chart-default
128Mi memory limit caused API-server pressure during the first attempt.
Size Kyverno for your cluster.

**Retained packages.** 0.3.0 extends the package and record formats rather
than replacing them. Packages it writes add `coverage.json`/`coverage.txt`,
a supporting-evidence context and, on signing destinations, a signed commit.
Unsigned commits keep the shape 0.2.0 writes and reads. Nothing rewrites a
closed run: runs that closed before the upgrade keep their original package
and status.

**Rollback constraints:**

- **Signing destinations.** Once a destination has signed history, don't
  roll the controller back to 0.2.0. The older release reports signed runs as
  conflicts and can't serve or retire them
  ([mixed versions and rollback](integration/evidence-signing.md#mixed-versions-and-rollback)).
- **Protected packages.** Don't roll the download service back below 0.3.0
  while packages with supporting documents are retained. An older download
  service doesn't read package protection and would serve those packages to
  anyone with run access ([protected-package readers](charts.md#protected-package-readers)).
- **Download rollout.** A platform run that closes while download replicas
  are mixed permanently lacks supporting documents (`ProtectedReadersUnverified`).
  Its technical evidence is unaffected. Time upgrades accordingly, or re-run
  ([supporting evidence](supporting-evidence.md)).
- **CRD chart.** Don't use `helm rollback` of the CRD release as routine
  recovery. A 0.2.0 schema would prune the new fields from stored objects.
- A runtime rollback to 0.2.0 with neither signing nor documents in use
  isn't tested across versions. The CRD changes are additive and unsigned
  records keep 0.2.0's shape, but treat it as an unsupported recovery path
  and keep the 0.3.0 CRDs.

## Known limitations

- **Self-service exceptions are disabled.** The `ComplianceException` CRD
  and the exception-editor role ship, but the chart serves no exception
  webhook, grants nothing, and can't enable revocation processing. Exceptions
  wait for an upstream Kyverno release that enforces PolicyException expiry
  during cached evaluation and supports namespace-UID matching
  ([policy exceptions](integration/policy-exceptions.md)). As a result:
  - coverage never reports accepted risk;
  - preview never analyzes exception consequences;
  - the hardening bundle has no exception workflow;
  - HA has no native-grant failover case.
- **Administrator signing recovery is deferred.** A run that ends
  `SigningFailed` keeps its evidence until expiry, but can't be re-signed or
  re-published. A new run produces signed evidence once the key is fixed. The
  recovery action is planned as a separate change
  (`add-evidence-signing-recovery`).
- **Preview limits.** The preview analyzes configuration, content and
  applied state. Exception consequences are `analysis: not-available`.
  Evidence context is informational. The built CLI is acceptance-tested
  live for configuration, content, trust, drift, access and applied-state
  cases. Exception consequences and acceptance renewal are not, because that
  integration doesn't exist in 0.3.0. Revocation observation through
  admission-recorded state is unit-tested only.
- **Evidence is configuration, not runtime.** Checks evaluate requested pod
  settings. They don't observe effective UIDs, capabilities or seccomp
  filtering.
- **Kyverno first-failure gap.** When one validation of a multi-validation
  check fails, Kyverno doesn't report the others. Those checks are recorded
  as missing and the run is `Incomplete`.
- **Partial NIST coverage.** Mappings describe partial, configuration-level
  evidence for NIST SP 800-53 Rev. 5 Moderate controls. No result claims
  full control satisfaction.
- **S3 backends.** Only RustFS 1.0.3 is tested. Archives are capped at
  512 MiB, and conditional create (`If-None-Match: *`) is required.
- **Staging is per pod.** Captures not yet staged in S3 are lost with their
  pod and reported as `CaptureLost`.
- **Failover measurements are not service levels.** Only two replicas, the
  listed failure cases and short windows are covered
  ([availability](integration/availability.md#failover-under-traffic)). The
  three-node `availability` group starves on a shared small host. CI and the
  release workflow are the gate.
- **Deferred dependency updates.** None of them changes behavior for users.
  - Devbox lock-file maintenance (a nixpkgs refresh with unchanged tool
    versions): with it, CI can't execute Go test binaries.
  - `golang.org/x/crypto` v0.58.0, `golang.org/x/net` v0.61.0 and
    `github.com/prometheus/common` v0.73.1: the pinned `go-licenses` is built
    with Go 1.26 and can't classify x/crypto's new Go 1.27-only `crypto/mldsa`
    import, so the image's license notices couldn't be generated. 0.3.0 ships
    x/crypto v0.57.0, x/net v0.59.0 and prometheus/common v0.72.0. No published
    advisory affects them.

## Publication-time gates

These checks can only pass during the real publication, after the
release-please PR is merged. 0.3.0 must not be announced until each one has
succeeded:

1. Image publication waits for full main-branch acceptance of the tagged
   commit, then signs and attests the image and verifies its evidence.
2. The `charts` workflow freezes both archives and the image digest, attaches
   them to the GitHub Release, and runs release acceptance (`charts`,
   `monitoring`, `availability`) on exactly those inputs.
3. Each chart subject gets keyless Cosign signing under the `charts` /
   `release-please` workflow identity, its chart-inputs attestation and
   GitHub provenance, and remote verification by digest with byte comparison.
4. The release notes list the image digest and both chart subjects, and their
   install commands pull the frozen archives.

If any step fails, the workflow stops before reporting the charts released.
Resume it with the tag, as described in [Releases](releases.md). Exercising
signature-failure and incomplete-publication recovery in production is still
an open release-trust task (`add-helm-oci-distribution` 6.3). The
write-once and resume logic is covered by the tests above.
