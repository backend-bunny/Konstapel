# Bounded Kyverno v1 assessment loop

This prototype uses Go and the pinned C2P v2 library/plugin protocol to deliver
one `policies.kyverno.io/v1` ValidatingPolicy and export partial AC-6 evidence.
It is not a controller, a production SSP, or a full-control/baseline assessment.
Additional policies in [the bundle research](../research/next-policy-bundle.md)
are outside this change.

## Prerequisites and pinned inputs

Use Linux amd64 and the [Devbox environment](../development.md), activated by
direnv or `devbox shell`. Docker with a running daemon is required for live tests.
Current tool versions are pinned in `devbox.json`/`devbox.lock`; current chart and
test-image pins live in `scripts/runtime.env`.
[versions.json](versions.json) records the original C2P pseudo-version/revision,
Kubernetes 1.36.1 node digest, Kyverno/CLI 1.19.2, chart 3.9.2 and checksum,
and the generated/source OSCAL versions. [runtime-images.json](runtime-images.json)
records observed Kyverno image digests from the original environment setup. The
current chart version and digest are fixed in `scripts/runtime.env`; runtime image
versions are supplied by that chart, and the acceptance package records resolved
image IDs for comparison with this file.
Go dependencies are pinned by go.mod/go.sum; no C2P internal packages or legacy
policy objects are used.

Build and run the offline checks from the repository root:

```sh
devbox run -- task check
```

The matching Kyverno CLI is included in the Devbox lock. Run its fixtures alone:

```sh
devbox run -- task policies:test
```

The chart archive is checksum-verified by `scripts/fetch-chart.sh`. No release
signature verification is implied by a recorded checksum or the Devbox lock.

## Disposable environment and full acceptance

The complete workflow creates a uniquely named `konstapel-assessment-*` kind
cluster and records its name/context in `target.json`. Set
`KONSTAPEL_CLUSTER_NAME` to choose a specific name. It refuses to reuse an
existing cluster with that name, verifies its kube-system UID before teardown,
and sets an explicit
kubeconfig/context on all calls, exports failure logs, and tears down the cluster
it created. It does not alter the ambient kubeconfig. Never point it at production.
Its output directory must be new; choose an absolute path:

```sh
task acceptance OUTPUT=/tmp/konstapel-acceptance-1
task acceptance OUTPUT=/tmp/konstapel-acceptance-2
```

Both runs start from a clean disposable environment. Command stdout and stderr
stream to the terminal and per-stage files. `progress.log` records timestamped
stage markers; `targeting/targeting-live.log` includes verbose Go test progress
during the longer expiry/recovery cases. Read `result.txt`, `runner.log`,
`chainsaw.log`, `environment/`, `package/`, and `kind-logs/`. The final result is
recorded after teardown; teardown failure also fails the run.
The exit status is authoritative: a missing observation or unexpected admission
outcome fails acceptance. Failure artifacts remain available. Kubeconfig is an
operational input in the run directory, not evidence that should be published.

To inspect prerequisites interactively, use these explicit commands instead:

```sh
scripts/environment.sh create /tmp/konstapel.kubeconfig /tmp/konstapel-environment
scripts/environment.sh smoke /tmp/konstapel.kubeconfig /tmp/konstapel-environment
scripts/environment.sh delete /tmp/konstapel.kubeconfig /tmp/konstapel-environment
```

Environment setup installs Kyverno with a 15-second background scan interval,
enables v1 exceptions only for `policy-exceptions`, reduces log verbosity to zero, applies the upstream
admission/reporting ephemeral-container RBAC fixture, checks API discovery,
waits for controllers and verifies RBAC aggregation. These are isolated test
settings, not production recommendations. The source's declared minimum is
Kyverno 1.19.1 / Kubernetes 1.30+; the tested combination is recorded separately.
The stale `kyverno.io/kyverno-version: 1.14.0` annotation does not override the
minimum. The selected policy readiness conditions are under
`status.conditionStatus.conditions`: `WebhookConfigured` and
`RBACPermissionsGranted` must both be true.

The Go acceptance runner creates an owned namespace permitting controlled
privileged fixtures, waits for its default ServiceAccount, and seeds a privileged
Pod **before** policy delivery. It checks repeated delivery retains the policy
UID, admits compliant Pod/Deployment requests, rejects privileged Pod and
Deployment creates, Deployment template updates, init containers, and ephemeral
updates for this policy's exact denial reason. Audit must admit an otherwise-valid
privileged Pod. It then restores Deny and establishes a new evaluation boundary.
Background results must include the still-existing original violation and passes
for compliant fixtures. Rejected creates are not in the expected-report inventory.

Acceptance then runs the upstream Chainsaw suite on a disposable copy. The sole
fixture overlay replaces `ghcr.io/kyverno/test-busybox:1.35` with the digest-pinned
BusyBox image in `scripts/runtime.env`: the upstream image returned `exec format error`
in the initial local test. Vendored originals, including their tests, stay
unchanged. Chainsaw exercises controller/init/ephemeral behavior and a scoped
image exception with sibling rejection. These cluster-wide fixtures and their
RBAC are used only inside the disposable cluster.

## Generation, delivery and ownership

The upstream policy and test files are unchanged under
`content/upstream/kyverno/disallow-privileged-containers/`, with Apache-2.0
LICENSE. `content/provenance.json` identifies upstream revisions and local
rendering; `content/SHA256SUMS` covers the source/schema bytes. Generation writes
a copy under `generated/upstream/` and a separate rendered policy and manifest.

```sh
bin/konstapel generate --output artifacts/generated
bin/konstapel generate --action Audit --output artifacts/audit
bin/konstapel deliver --kubeconfig /tmp/konstapel.kubeconfig --context kind-konstapel-assessment --output artifacts/delivery
```

Deny is the default, Audit the only alternative; unknown actions fail. Rendering
keeps v1, enables background evaluation, adds an owner label and a namespace
selector (default `konstapel-acceptance`). For standalone delivery create that
namespace first. `--namespace` and `--owner` are explicit rendering options.
Kyverno alone enforces admission. Application, readiness, admission decisions,
and completeness are separate phases. A pre-existing policy without the expected
owner label causes a conflict; no legacy fallback is installed. Cleanup checks
ownership and only removes namespace/policy resources created by the run.
Standalone delivery leaves its managed policy for explicit inspection/removal.

The policy matches core/v1 Pods and ReplicationControllers, apps/v1 Deployments,
DaemonSets, StatefulSets and ReplicaSets, batch/v1 Jobs and CronJobs, and UPDATE
of Pods' ephemeralcontainers subresource. It checks regular/init/ephemeral
containers in direct Pod specs and workload templates. Privileged true fails;
false or omitted passes. There is no Windows exemption. Exact images in matching
v1 exceptions can waive only matching containers; whole-policy exceptions may
skip evaluation. No sample exception is shipped into the acceptance namespace.
Exceptions are deviations, not equivalent compliance evidence.

This policy does not prove nonroot execution, absence of capabilities, seccomp,
RBAC least privilege, host isolation, or organizational authorization. It does
not cover arbitrary custom controller templates, node processes, static Pod
execution, or all admission subresources. PSA or other webhooks can reject
fixtures independently; only the selected policy's denial counts as its test.

To update sources: select immutable revisions, copy only this policy's directory
and required license/notices, preserve originals, update provenance and
checksums, inspect expression/exception/API changes, run the CLI/Go tests, and
run clean acceptance twice. Record new toolchain/chart/image/schema selections
with the update. Never substitute moving main-branch install URLs.

## Evidence format, freshness and offline conversion

`capture.json` version 1 holds the explicit context and cluster identity, policy
snapshot/UID/spec digest, mapping digest, independent expected resource inventory,
raw reports, source evaluation boundary, collection time and collection errors.
The cluster identifier is `kube-system:<namespace-UID>`; C2P subject identity
combines that cluster ID, API version, kind, namespace, name and resource UID.
Identical names across namespaces or clusters remain distinct.

The supported report schema is `wgpolicyk8s.io/v1alpha2` PolicyReport and
ClusterPolicyReport. A result can identify resources through report-level `scope`
or result-level `resources`. Matching results must carry a timestamp with
numeric `seconds` and optional `nanos`, resource UID, policy name and source `KyvernoValidatingPolicy`. Raw reports
remain available, including messages, rule identifiers and original result states.
Unsupported layouts and malformed matching results fail rather than disappearing.

Pass/fail/warn/ warning/error map to their corresponding C2P outcomes; skip and
unknown outcomes normalize to error while retaining their source state. Missing
or ambiguous current results produce explicit error subjects and incomplete
evidence. Report-level resources, report UID, result index, original reason and
evaluation time remain traceable from exported subject properties. Evaluation
times are never replaced with collection time. A missing result has no source
evaluation time (the C2P intermediate representation uses its zero value).

Completeness reconciles reports against admitted fixtures, independently of
report presence. Results before the evaluation boundary or after collection,
replaced UIDs, conflicting simultaneous results, collection errors, independently rechecked admitted-resource UIDs and changed
policy identity/revision cannot establish a current passing assessment. Polling
is bounded. A fresh fail is complete evidence of a failing technical check;
complete does not mean compliant. A missing or error result is never a pass.

Freshness is intentionally bounded to a controlled, quiescent test run. Kyverno
reports do not supply a cryptographic policy-spec revision attestation. The
runner captures policy UID/spec and checks they remain stable, waits for readiness
and checks source timestamps after the boundary. This does not solve production
continuous report-to-policy revision correlation; outside these assumptions,
association remains unknown. No remote-cluster management is implemented.

Replay a saved capture without cluster access:

```sh
bin/konstapel convert --capture /tmp/konstapel-acceptance-1/package/capture.json --output artifacts/replayed
bin/konstapel validate --output artifacts/replayed
jq '."assessment-results".metadata.props' artifacts/replayed/assessment-results.json
jq '{complete,missing,rejected,evaluations}' artifacts/replayed/evidence.json
```

Conversion writes diagnostic artifacts for incomplete evidence and exits nonzero.
Malformed captures fail before assessment export; the original capture must be
retained by its caller. Do not equate conversion failure with a passing check.

## OSCAL mapping and artifact inspection

The authored Component Definition maps the stable rule/check
`disallow-privileged-containers` to `ac-6` / `ac-6_smt`. Its validation component
is `konstapel-kyverno`, exactly matching the plugin manifest ID. Missing provider,
wrong checksum, invalid configuration, unsupported action or unresolved mapping
fails visibly. The plugin implements the public C2P v2 gRPC Provider interface;
the runner invokes C2P generation, aggregation and Assessment Results actions,
and the SDK's Component Definition-to-Assessment Plan transformation.

Official NIST catalog/Moderate profile bytes remain OSCAL 1.2.3. The mapping and
generated Assessment Plan, supporting test-context SSP and Assessment Results
use OSCAL 1.1.3, which C2P supports. Both source documents and the mapping validate
against their own vendored official schemas. Control/statement identity, explicit
Moderate inclusion and the profile's catalog reference are independently checked
without round-tripping NIST through older structs.

Export adds source/content links, digests and completeness at the boundary,
retains source timestamps, and omits C2P's invalid empty optional property lists.
The included SSP describes only disposable test context; it is not an approved
system security plan. Assessment results describe partial technical evidence;
passing checks never assert the whole AC-6 statement or Moderate baseline is
satisfied. C2P negative findings remain limited by this documented scope.

`assessment-results.json` imports the packaged `assessment-plan.json`, which
imports `system-security-plan.json`. The package contains source mapping, NIST
content and provenance, `capture.json`, `evidence.json`, and `run-manifest.json`.
`rendered-policy.json` and `content-manifest.json` retain the reconstructed
policy and source/render checksums. Provider conversion and export compare the
entire captured policy spec to that render; even a recomputed capture hash cannot
validate changed expressions, matching, or evaluation settings. JSON key order,
metadata and status are ignored. The pinned runtime adds no spec defaults;
additional spec fields fail closed until reviewed explicitly.

Source result references use captured report UID and result index. The validator
checks declared schemas, UUID references and all local evidence hrefs.

See [validation-results.md](validation-results.md) for executed checks and limits.

A synthetic saved fixture under `testdata/capture.json` exercises both report
scopes and both resource-reference layouts. It is an offline conversion fixture,
not a claim that those records were observed from a cluster. To inspect it:

```sh
bin/konstapel convert --capture testdata/capture.json --output artifacts/example
bin/konstapel validate --output artifacts/example
```

## Failure-path probes

```sh
scripts/test-failures.sh artifacts/failure-probes
```

This runs two fresh disposable clusters. Missing-evidence injection requires an
independently inventoried nonexistent Pod and bounds collection to three seconds.
The admission probe deliberately expects Audit behavior while Deny is installed.
Both must fail, preserve policy/report/workload snapshots and admission responses,
and remove only their own clusters. The `KONSTAPEL_TEST_MISSING_EVIDENCE` and
`KONSTAPEL_TEST_EXPECT_ACTION` environment variables are failure probes, not
options that relax acceptance. `acceptance-result.json` records the final exit
status after teardown. All-missing exports remain incomplete and omit fabricated
control-violation findings.
