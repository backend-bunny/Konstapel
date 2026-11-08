# v0.1.0 readiness

What the first early-adopter release, v0.1.0, ships, how each claim is
tested, and what it does not do. Each row names the test that backs it;
"release" means the check runs in the release workflow itself
([Releases](releases.md)). Everything else is part of the required
`acceptance` check on every pull request and main push.

## What ships

| Artifact | Reference | Contents |
| --- | --- | --- |
| Controller image | `ghcr.io/backend-bunny/konstapel@sha256:…` (digest in the release notes) | `konstapel controller`, `konstapel download-server`, the C2P provider and vendored content; signed, with SPDX SBOMs, source/notice attestations and build provenance ([Images](images.md)) |
| CRD chart | `oci://ghcr.io/backend-bunny/charts/konstapel-crds@sha256:…` | the six `compliance.erenius.io/v1alpha1` CRDs, kept on uninstall |
| Runtime chart | `oci://ghcr.io/backend-bunny/charts/konstapel@sha256:…` | controller and download server (two replicas each), RBAC, admission policies, TLS (cert-manager or operator Secret); defaults to the released image digest |

Both charts carry version `0.1.0` and are signed, with a chart-inputs
attestation and GitHub provenance on each OCI subject.

## Checklist

### Clean installation

| Claim | Evidence |
| --- | --- |
| The CRD chart installs every shipped CRD, and the runtime chart installs on Kubernetes ≥ 1.36 into `konstapel-system` | `TestLiveHelmInstall`, `TestLiveCRDChartLifecycle` (`charts` group); release: `charts:acceptance` on the frozen archives |
| The runtime chart refuses another namespace, a missing digest, and unsafe timing or PDB values at render time | `internal/charttest`, `scripts/charts/check.sh` fixtures |
| Two hardened replicas (non-root, read-only root, no capabilities) become ready, and one holds the Lease | `TestLiveHelmInstall`, `TestLiveHelmAvailability` (`availability` group) |
| Both TLS modes work: cert-manager (chart CA or platform issuer) and an operator Secret | `TestLiveHelmInstall` steps 4–8 |
| The documented examples render and install | `TestDocumentedExamples`; `TestLiveHelmInstall` uses `operator-tls.yaml` and `platform-issuer.yaml`, and `TestLiveHelmAvailability` uses `development.yaml` |

### Supported versions

| Component | Tested |
| --- | --- |
| Kubernetes | 1.37.0 (kind node in `scripts/runtime.env`); the chart requires ≥ 1.36 for MutatingAdmissionPolicy |
| Kyverno | 1.19.2 (chart 3.9.2), `policies.kyverno.io/v1` ValidatingPolicy and `wgpolicyk8s.io/v1alpha2` reports |
| cert-manager (optional) | v1.21.3 |
| Helm | 4.3.1 |
| S3 | RustFS 1.0.3, all three versioning modes. AWS S3 and other services are untested ([S3 evidence](integration/s3-evidence.md#tested-compatibility)) |

### Assessment, publication and download

| Claim | Evidence |
| --- | --- |
| Profiles and bindings deliver Kyverno policies in Audit or Deny, scoped by namespace selector | `TestLiveDelivery`, `TestLiveTargetingWorkflow`, `TestLiveEnforcementEpoch` |
| Scheduled and team-requested runs collect attributable evidence and export OSCAL through C2P | `TestLiveAssessmentRuns`, `TestLiveIntegratedAssessments`, `TestLiveEvidenceDownload` |
| Missing, stale or unattributable evidence makes a run `Incomplete`, never a pass | `TestLiveHardeningBackground` (Kyverno first-failure gap reported as missing), collector unit tests |
| The Linux hardening bundle assesses pre-existing workloads, and explicit Windows workloads are not applicable rather than passing | `TestLiveHardeningBackground`, `TestWindowsWorkloadIsOutOfScopeNotPassing` |
| Packages are published write-once to S3 with receipts, retention and expiry | `TestLiveDestinationPins`, `TestLiveRetentionLifecycle`, `TestPublisherRoundTrip` |
| Downloads are authorized per request (TokenReview and SubjectAccessReview), served by any replica, with no leader needed | `TestLiveEvidenceDownload`, `TestLiveHelmInstall` (follower downloads, revocation, credential rotation, namespace-UID isolation) |

### Recovery

| Claim | Evidence |
| --- | --- |
| Leader pod loss and node loss: another replica leads within about 20 s and reconciles | `TestLiveHelmAvailability` |
| Kyverno keeps enforcing, and downloads keep serving, while no controller runs | `TestLiveHelmAvailability`, `TestLiveHelmInstall` |
| A run staged in S3 before its commit is committed by the other replica after the Lease holder's pod is removed, with the same run and publication identity and the exact staged bytes; a run committed before its Kubernetes receipt is recorded with its original commit, `publishedAt`, `expiresAt` and retention even if the binding's retention changed since; nothing is committed twice | `TestLiveHelmDurableRecovery` (`availability` group: installed image, two replicas, real S3 behind a test-owned fault proxy that holds, or forwards and withholds, the commit); also `TestLiveLeaderHandoverRecovery`, `TestLiveLeaderHandoverLoss` (in-process managers) |
| A capture lost before durable staging is reported as `CaptureLost`, never published, and an S3 outage alone never causes it: while S3 is held or unreachable, before and after the leader pod is removed, the run stays `Publishing` | `TestLiveHelmAvailability`, `TestLiveHelmDurableRecovery` (installed image), `TestLiveLeaderHandoverLoss` |
| The first scheduled run of a binding is neither duplicated nor orphaned when its status write loses to another writer, even with a lagging run cache or a replan more than one interval later (a defect the deployed recovery test found and this release fixes) | `TestLostFirstScheduleWriteAdoptsTheCreatedRun`, `TestLostFirstScheduleWriteAdoptedAfterAnInterval`, `TestLostFirstScheduleWriteAdoptedDespiteRunCacheLag`, `TestFirstScheduleAdoptsOnlyOwnUnfinishedScheduledRuns` |
| A delayed former leader can't withdraw the current policy revision | `TestDelayedFormerLeaderResolvesAgain` and delivery tests |
| Kyverno API or permission loss is reported, not crashed on, and recovers without a restart | `TestLiveEngineCapabilityRecovery` (`capabilities` group) |

### Upgrade and uninstall

| Claim | Evidence |
| --- | --- |
| CRD chart upgrades (same-schema and additive) keep objects, UIDs and finalizers; uninstall keeps the CRDs and their objects; a same-identity reinstall takes them back; a different release is refused | `TestLiveCRDChartLifecycle` |
| Runtime upgrades roll without dropping below two ready controllers, and a blocked surge keeps serving | `TestLiveHelmAvailability` |
| Uninstalling the runtime chart leaves an operator-supplied TLS Secret | `TestLiveHelmInstall` |
| Uninstalling the runtime chart stops delivery, assessment, downloads and retention cleanup, but leaves delivered policies and published packages in place | [Helm charts](charts.md) |

### Artifact verification

| Claim | Evidence |
| --- | --- |
| The image is signed and attested, and is verified before release | the image publish workflow ([Images](images.md#verify)) |
| Chart archives are frozen (source commit, checksums, CRD content, image digest) before acceptance, and only accepted bytes are published, write-once | `test_chart_manifest.py`, `test_chart_publish.py`, `test_chart_release_inputs.py`; release: the `charts` workflow |
| Each chart subject is signed, with a chart-inputs attestation binding source, image, archive and acceptance; verification pulls the subject by digest and compares bytes | `test_chart_publish.py` (key pairs); release: keyless verification in the `charts` workflow |
| Release acceptance covers every release-required group on the frozen artifacts: `charts` and `availability` each run on their own disposable cluster, install the frozen archives and pull the released image by digest on every node. Per-test results come from the real test logs, and a missing, failed, cancelled, skipped, stale or mismatched record is refused before any registry write | `test_chart_evidence.py`, `test_chart_publish.py`, `test_acceptance.py`; release: `task charts:acceptance` in the `charts` workflow |
| The release notes' install commands install exactly the verified bytes | `test_documented_install_commands_pull_the_frozen_archives` |

## Known limitations

- **Self-service exceptions are disabled.** The `ComplianceException` CRD and
  the exception-editor role ship, but no webhook is served and no exception is
  granted. They wait for an upstream Kyverno release
  ([Policy exceptions](integration/policy-exceptions.md)).
- **No metrics.** Prometheus observability isn't implemented; health is
  reported through Conditions and probes.
- **Evidence is configuration, not runtime.** Checks evaluate requested pod
  settings. They don't observe effective UIDs, capabilities or seccomp
  filtering.
- **Kyverno first-failure gap.** When one validation of a multi-validation
  check fails, Kyverno doesn't report the others. Those checks are recorded as
  missing and the run is `Incomplete`.
- **Partial NIST coverage.** Mappings describe partial, configuration-level
  evidence for NIST SP 800-53 Rev. 5 Moderate controls. No result claims full
  control satisfaction.
- **S3 backends.** Only RustFS 1.0.3 is tested. Archives are capped at 512 MiB,
  and conditional create (`If-None-Match: *`) is required.
- **Staging is per pod.** Captures not yet staged in S3 are lost with their
  pod and reported as `CaptureLost`.
- **Failover under traffic.** The recovery tests check state and bytes after
  a leader pod or node is lost (a new leader takes the Lease in about 20 s).
  They don't measure client request success during that gap or under
  sustained load.
- **Not in v0.1.0:** Trivy vulnerability assessment, evidence signing,
  policy-change previews, supporting attachments, independent policy-bundle
  distribution, and control-coverage reporting.
- **First-release checks.** Keyless signing of the charts under the release
  workflow identity, GitHub provenance for chart subjects, and the
  release-please integration can only run in the release itself. The
  `charts` workflow fails the release if any of them fails, and can be
  resumed with the tag.
