# Assessment-loop validation record

Historical validation of the original standalone prototype. For current
controller capabilities and implementation status, see the
[documentation index](../README.md); current pins live in
[`scripts/runtime.env`](../../scripts/runtime.env).

Date: 2026-11-05. Environment versions and observed controller image digests are
recorded in [versions.json](versions.json) and
[runtime-images.json](runtime-images.json). Supporting bundle research remains
separate; no additional policies were implemented.

## Executed offline checks

- Go 1.25.7 dependency resolution and builds with C2P
  `v2.0.0-rc.1.0.20260824132548-45bfc1a8947e`: passed.
- `go test ./...`: passed, including actual gRPC plugin startup, manifest checksum
  rejection, missing provider/configuration, scoped rendering, invalid NIST control
  references, both report scopes/reference layouts, namespace/cluster subject
  identity, pass/fail/warning/error/skip/unknown results, malformed layouts,
  stale/missing/replaced-UID and ambiguous evidence, collection errors, CLI failure
  on incomplete evidence, admission reason attribution and cleanup refusal guards.
- `go vet ./...`: passed.
- Vendored upstream CLI suite on Kyverno CLI 1.19.2: 44 expected-result checks
  matched, zero failed. Expected policy failures/skips are successful test checks.
- Source and schema SHA-256 verification: passed; source policy/fixtures unchanged.
- NIST catalog and Moderate profile at OSCAL 1.2.3 and authored mapping at 1.1.3:
  schema validation, explicit AC-6 baseline inclusion, ac-6_smt existence and the
  profile's catalog reference resolution passed.
- C2P-generated Assessment Plan, supporting test-context SSP and Assessment Results
  at OSCAL 1.1.3: schema/local-reference validation passed for fail, all-pass and
  missing-evidence cases. No all-pass case asserts full-control satisfaction.
- Saved synthetic fixture conversion and validation without a cluster: passed.
- OpenSpec strict validation: passed.

## Live development runs

The Go runner passed against a fresh kind cluster in
`/tmp/konstapel-full-acceptance-3/package`:

- Modern policy and report API discovery and Kyverno controller readiness.
- Explicit kubeconfig/context, cluster identity derived from kube-system UID,
  policy ownership and repeated delivery retaining policy UID.
- Compliant Pod and Deployment admission, privileged Pod/Deployment creation,
  Deployment template updates, init containers and ephemeral updates attributed
  to the exact Kyverno policy reason, and Audit admitting a privileged request.
- Fresh background pass/fail findings after the final Deny boundary, with the
  pre-existing privileged Pod retained under the same UID and no remediation.
- Validated OSCAL output with partial coverage and packaged provenance.

[admission-example.json](admission-example.json) and
[acceptance-example.json](acceptance-example.json) preserve that disposable
runner result. These are development-run evidence examples, not certification
of production behavior or a substitute for the complete acceptance record below.

Earlier failed development attempts are retained under temporary research paths:
missing ephemeral-container RBAC prevented policy readiness; the upstream BusyBox
image failed execution; a default ServiceAccount creation race caused a legitimate
API rejection; and host I/O contention caused API timeouts and reports-controller
leader-lease loss. Missing/stale evidence remained incomplete and made the run
fail. Changes addressed prerequisite setup, a pinned test-image overlay, the
ServiceAccount wait and test logging volume. No freshness check was relaxed.
The initial shell wrapper also used unsupported Chainsaw flags; it was corrected
to the installed CLI's `--kube-context` and explicit KUBECONFIG environment.

## Complete acceptance runs

Both documented `scripts/acceptance.sh` runs passed from clean state with the
final implementation. [acceptance-runs.json](acceptance-runs.json) records their
independent cluster identities, evaluation boundaries, source evaluations,
collection times, acceptance assertions and artifact SHA-256 digests.

| Run | Output retained locally | Background results | Chainsaw | Teardown |
| --- | --- | --- | --- | --- |
| 5 | `/tmp/konstapel-full-acceptance-5` | 2 pass, 2 expected fail; complete | 1 passed, 0 failed, 0 skipped | passed |
| 6 | `/tmp/konstapel-full-acceptance-6` | 2 pass, 2 expected fail; complete | 1 passed, 0 failed, 0 skipped | passed |

Each run created its own cluster, proved Deny/Audit admission and retention of the
pre-existing violation, exported schema/reference-valid OSCAL, replayed the saved
capture offline and removed the cluster before the next run. The temporary paths
contain full local diagnostics; they are not portable repository links. The
committed compact record preserves the result assertions and hashes without
kubeconfigs or controller logs. The version matrix is the pinned matrix in
[versions.json](versions.json); the capability scenario table below distinguishes
live verification from synthetic/offline tests. Final Go tests, vet, shell syntax,
diff whitespace and strict OpenSpec validation also passed.

The initial PR CI run exposed older-jq expression parsing in the build script.
Parenthesizing the manifest configuration expression fixes that compatibility
issue; the generated manifest, binaries and live acceptance behavior are unchanged.

## Limits

Only the recorded Linux amd64/Kubernetes/Kyverno combination is exercised. No
production cluster, remote cluster, Windows runtime, or minimum-version matrix
was tested. Cluster-scoped report and alternate resource-reference layouts are
synthetic conversion tests; the live policy targets namespaced workloads.
Exception behavior beyond the shipped upstream suites is not a general exception
management feature. Release signature verification was not performed.

Source timestamps plus stable captured UID/spec and a quiescent test run support
freshness here; the runtime reports do not attest a policy-spec digest. Continuous
production revision correlation, approved SSP authoring and complete AC-6 or
Moderate coverage remain outside this prototype. The emitted supporting SSP is
explicit disposable-test context, not an authorization artifact.

## Capability scenario evidence

| Specification scenario | Verification |
| --- | --- |
| Inspect shipped bundle | Source checksums/provenance/LICENSE; upstream CLI fixtures; rendering API assertions |
| Resolve check to requirement | `TestContentAndRendering`, authoritative NIST schema/membership/reference validation |
| Passing check retains coverage boundary | `TestPluginAndExport/pass`: partial metadata and no satisfied finding |
| Deliver enforcing policy | `TestContentAndRendering`; live generated policy, readiness and admission captures |
| Select Audit | Live Audit admission followed by restoring Deny |
| Required API unavailable | `TestDeliveryPrerequisitesAndOwnership/missing-api`; no legacy fallback |
| Accept compliant workload | Live Pod/Deployment admission and resulting UIDs |
| Reject privileged workload | Live Pod/Deployment creates, template and ephemeral updates; precise denial reasons |
| Discover pre-existing privileged Pod | Background fail, retained original UID, no remediation in acceptance.json |
| Convert both report scopes | `TestSubjectIdentity`, `TestCompletenessAndLayouts`, synthetic saved fixture |
| Preserve evaluation error | `TestReportNormalization`: warn/warning/error/skip/unknown cannot pass |
| Required observation absent | `TestIncompleteCLIAndCleanupGuard`: nonzero exit and validated diagnostic package |
| Earlier policy/resource state | `TestCompletenessAndLayouts`: stale timestamps, replaced UID, policy digest mismatch |
| Inspect assessment artifact | `ValidatePackage`: schema and local UUID/evidence references; live export and offline replay |
| Run complete repeatable workflow | Final clean acceptance runs, controller/image/version captures, Chainsaw and scoped teardown |

## Reconciled implementation

See [reconciliation.md](reconciliation.md) for the combined implementation's two
fresh acceptance runs, artifact hashes, provenance regressions and complete
failure/cleanup probes performed after PR #29.
