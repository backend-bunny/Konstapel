# Development tooling

Konstapel uses Devbox for the pinned development environment, direnv for optional
automatic activation, Task for commands, and Renovate for dependency update PRs.
The initial supported development and acceptance platform is Linux amd64.

For Claude Code and Codex loops, see [agent task routing](agent-task-routing.md)
for per-task model selection, escalation, and the external harness contract.

## Enter the environment

Install [Devbox](https://www.jetify.com/docs/devbox/installing_devbox/) and,
optionally, [direnv](https://direnv.net/docs/installation.html) with its shell hook.
CI currently uses Devbox 0.19.0. The repository's `devbox.json` and generated
`devbox.lock` select the tools, including Go, Task, Kyverno CLI, Chainsaw, kind,
kubectl, Helm, shell utilities, and the Renovate configuration validator.
Image tools include melange, apko, cosign, Syft, go-licenses and bubblewrap;
see the [image guide](images.md) for build and attestation commands.

```sh
devbox install
direnv allow
task --list
task check
```

The checked-in `.envrc` loads Devbox and watches its configuration and lockfile.
Review `.envrc` changes before allowing them. Devbox and direnv must be available
outside this environment so they can activate it. Docker and its running daemon
are host prerequisites for cluster acceptance; Devbox does not start a daemon.

Without direnv, either enter `devbox shell` or run individual commands explicitly:

```sh
devbox run -- task check
```

`GOTOOLCHAIN=local` prevents Go from silently downloading a different compiler.
The Go version in `go.mod` and Devbox must agree. Use `devbox update` after
deliberately editing package versions and commit the regenerated lockfile with
the configuration. `devbox install` installs the existing locked environment.

## Commands

| Task | Behavior |
| --- | --- |
| `task build` | Build the runner and C2P provider, including the provider manifest. |
| `task test` | Run Go tests, including the real provider handshake and saved-evidence checks, the independent external-provider example module (tidiness, `gofmt`, `go vet`, its tests and the documented [quickstart](integration/external-provider-quickstart.md) commands, through `scripts/examples/external-provider.sh`), plus CI decision and shell logging regression tests, and evaluate the documented Prometheus queries and the Helm-rendered starter alerts (`promtool check rules`, `promtool test rules`) with the digest-pinned promtool image (`scripts/promtool.sh`). |
| `task lint` | Check Go formatting, `go vet`, generated API files, Helm chart metadata, versions and values-schema fixtures (`scripts/charts/check.sh`), and shell syntax. |
| `task content:check` | Verify vendored policy, OSCAL, and schema checksums. |
| `task policies:test` | Run the vendored Kyverno CLI fixtures and the CLI checks of rendered targeting policies. |
| `task deps:check` | Validate Renovate configuration, Devbox lock entries, Go version agreement, image digest format, agreement of the isolated Sigstore stack's Trillian images with the go.sum Trillian module, chart checksum, and chart/CLI version agreement. |
| `task check` | Run all the preceding checks and build, in the same order as CI. |
| `task acceptance OUTPUT=/absolute/fresh/path [GROUP=all]` | Run full acceptance by default, or one named CI group, in a disposable kind cluster and retain evidence. `GROUP=bundles` is the policy-bundle acceptance that the `add-policy-bundle-distribution` change calls `bundles:acceptance` ([bundle acceptance](policy-bundles.md#bundle-acceptance)); it is a group of this task, not a separate task. |
| `task test:failures OUTPUT=/absolute/fresh/path` | Exercise missing-evidence and unexpected-admission failure paths. |
| `task charts:package OUT=/fresh/path IMAGE_DIGEST=sha256:…` | From a clean checkout, package both charts with the runtime chart defaulting to that image digest, and freeze them with `publication.json` ([Helm charts](charts.md#release-packaging-and-publication)). |
| `task charts:acceptance OUTPUT=/fresh/path ARCHIVES=/path IMAGE=ghcr.io/backend-bunny/konstapel@sha256:…` | From a clean checkout, run every release-required acceptance group (`"release": true`: `charts`, `monitoring` and `availability`) in turn, each on its own disposable cluster, on those exact archives with every node pulling that image by digest. Writes `chart-acceptance.json` only if every required test passed, binding the per-test results to the frozen inputs. |
| `task bundles:package NAME=<bundle> OUT=/fresh/path` | From a clean checkout, build `bundles/<NAME>/definition.json` into a frozen OCI image layout plus `package.json` at that commit, and re-verify it. Identical commits give identical digests. Publication is not available yet ([policy bundles](policy-bundles.md)). |
| `task clean` | Remove generated binaries and Task cache; retain assessment evidence. |

After editing Go types in `api/`, run `devbox run -- scripts/generate.sh` to
regenerate deepcopy code and CRDs with the pinned `controller-gen`; `task lint`
fails when they are stale. See the [targeting API guide](integration/targeting-api.md)
and the [continuous assessment contract](integration/assessment-contract.md).
The same script regenerates the external provider protocol's Go code
(`pkg/providerapi`) from `proto/` with the pinned `protoc`, `protoc-gen-go`
and `protoc-gen-go-grpc`; `task lint` fails when it is stale, and
`task deps:check` fails when `protoc-gen-go` differs from the
`google.golang.org/protobuf` version in `go.mod`. After adding a wire fixture
under `proto/konstapel/provider/v1/testdata/wire/cases`, record its binary
encoding with
`devbox run -- go test ./pkg/providerkit -run TestWireFixtures -update-wire`,
which never rewrites an existing encoding. The generated tables of the
[protocol reference](integration/external-provider-protocol.md) are checked
by `TestProtocolReference`; after a deliberate protocol change, rewrite them
with `devbox run -- go test ./pkg/providerkit -run TestProtocolReference -update-protocol-doc`.
The example module `examples/external-provider/reporting` has its own
`go.mod`; when a dependency bump in the root `go.mod` makes it stale, run
`go mod tidy` in that directory.

`task check` needs no cluster. Its only Docker use is the pinned promtool image
(`KONSTAPEL_PROMTOOL_IMAGE` in `scripts/runtime.env`, Renovate-tracked and
format-checked by `task deps:check`). Devbox's `prometheus` package ships
promtool only in a separate output, which would change the `devbox.json`
package format. Without a Docker daemon that step prints a notice and is
skipped; CI requires it. Initial tool/module installation
and the checksum-verified chart download need network access. The pinned Devbox
Kyverno CLI replaces the previous manual release-archive download.

To author or change an assessment provider, follow the
[provider-authoring recipe](assessment-providers.md#authoring-a-provider). Its
registration, conformance-fixture and replay checks are package-level
`go test` runs through `devbox run --`, all included in `task test`; there is
no separate task.

To preview a compliance configuration change against a cluster, build the
binary (`task build`) and run `bin/konstapel preview` directly; there is no
Task wrapper. See the [local and CI examples](policy-preview.md#local-and-ci-use),
which `task test` verifies against a recording API server.

Task delegates orchestration to `scripts/`; scripts remain usable directly inside
the environment. The Taskfile exposes recurring workflows; helper scripts do not
each need a task. Follow the [tooling guidelines](../AGENTS.md#taskfile-scope) when
extending it. Build workflows check application version agreement internally.
Full acceptance requires a fresh output directory, selects its
own explicit kubeconfig/context, refuses existing clusters, and tears down its
owned cluster while preserving diagnostic evidence. See the
[assessment guide](integration/assessment-loop.md) for package inspection and
manual environment create/smoke/delete commands.

GitHub Actions installs the same Devbox lock and runs `devbox run -- task check`
in the `checks` job on every PR, main push, and manual test run. Live acceptance
is scoped as follows:

| Change or event | Full acceptance |
| --- | --- |
| PR containing only root README, vision, architecture, agent guidelines, changelog, license/notice files, OpenSpec Markdown, root `openspec/config.yaml`, or research Markdown | Skipped with an explicit reason |
| Any other PR path, including Go, dependencies, workflows, scripts, policies, charts, and integration documentation | Required |
| Unknown paths, incomplete history, or an empty diff | Required |
| Main push or manual test run | Required |

The exact prose allowlist lives in `scripts/ci/acceptance-scope.sh`. It inspects
the complete Git diff, including deletions and both sides of renames. Integration
documentation stays covered because live tests execute documented commands.
Per-change OpenSpec `.openspec.yaml` metadata and documentation outside the
allowlisted paths currently require acceptance too.
Only superseded PR runs are cancelled; main runs remain available for publication.

The `acceptance-live` matrix runs every group in `scripts/acceptance-groups.json`
concurrently, each on its own runner with its own disposable kind cluster and
test-owned S3 and registry services:

| Group | Coverage |
| --- | --- |
| `admission` | Runner admission/background evidence, Chainsaw, offline replay, targeting/delivery, and Linux hardening |
| `assessments` | Assessment status/runs, engine correlation, integrated assessments, integrated supporting evidence (one document for two bindings, independently authorized downloads, namespace confidentiality, independent source and package retention), and authenticated exception admission |
| `storage` | Destination/credential changes, downloads, retention, and orphaning, plus evidence signing: destination configuration and readiness, signed downloads, and the signed-publication workflow; supporting-evidence attachment storage, its authenticated transfers through the `konstapel evidence` CLI, and its lifecycle (expiry without an event, unavailable bytes, withdrawal across restarts, refused cleanup) |
| `recovery` | Kyverno outages and assessment/publication faults, supporting-evidence recovery (transfer replica loss, lost commit response, interrupted upload, unavailable source storage, withdrawal during capture, leader loss, denied cleanup), the signing-recovery claim of a retained `SigningFailed` run (racing requests, successor, deleted and terminal holders), and signing-recovery faults (concurrent requests, leader loss after signature storage, crashes after the run and namespace-request status writes with a restart after the attempt deadline, a lost commit response, expiry during the attempt, an orphan handoff in flight, a replaced or lost staged archive, key mismatch) |
| `capabilities` | Engine API and permission loss and recovery without a controller restart, and Kyverno's missing ephemeral-container grant: actionable binding diagnostics, the documented operator grant, and readiness recovery through bounded readiness rechecks with retained enforcement |
| `charts` | The CRD chart lifecycle and the Helm-installed controller image (both TLS modes, downloads, rotation, follower serving), OCI policy bundles from a disposable TLS registry (chart RBAC, watches, revocation, follower pins, also under rotated trust, upgrade and rollback), authenticated metrics scrapes, supporting evidence through the installed download service (chart attachment limits and retention, and protected packages written only while every download replica runs the controller's image), and the opt-in exception admission webhooks and revocation processing (fail-closed admission, cert-manager CA injection, readiness, enable/disable order, no exception writes by an over-granted controller without the flag); installs cert-manager and builds the image |
| `monitoring` | The Helm-installed controller scraped by a pinned real Prometheus Operator and Prometheus ([verified Operator setup](charts.md#verified-operator-setup)), with the starter alerts evaluated by that Prometheus through real failures and recoveries: rule overrides, publication and cleanup faults, evidence expiry, lost reporting access, no leader, leader loss, binding recreation, certificate and token rotation, and revocation ([integrated acceptance](integration/metrics.md#integrated-acceptance)); needs network access to `quay.io` and `docker.io`; installs cert-manager and the Operator, runs the test S3 service and fault proxy, and builds the image |
| `providers` | The example reporting provider's [reference chart](integration/external-provider-chart.md) Helm-installed with its image built from this checkout (`scripts/examples/reference-provider-image.sh`, loaded by digest): no registration, the worker's and evaluator's permissions by SubjectAccessReview and real token requests, no evaluator API token, evaluator egress denied by NetworkPolicy, an assessment through the worker, and worker, host-trust and evaluator TLS rotation without a restart; and the [signing fixture](integration/external-provider-chart.md#signing-fixture) (`scripts/examples/reference-provider-signing.sh`): that image and a chart pinning it signed and attested with disposable keys in disposable local registries, then verified as documented, with twelve fixtures that must be rejected, and the controller image's signature payload check (`scripts/image/verify-signature-payload.sh`), which must reject an attestation-only image that plain `cosign verify` accepts; builds that image (not the controller's) |
| `bundles` | OCI policy bundles on an in-process controller: the official keyless release read anonymously from `ghcr.io` and the organization-key fixture from a disposable TLS registry, each in Audit and Deny; unsigned, wrong-key and tampered bundles; warm-cache outage, cold-cache failure, credential rotation, trust revocation and recovery ([bundle acceptance](policy-bundles.md#bundle-acceptance)); needs network access to `ghcr.io` and fails without it; also the policy-change preview against the private source, including the built `konstapel preview` command as a reader-RBAC ServiceAccount ([policy preview](policy-preview.md#local-and-ci-use)) |
| `availability` | The Helm-installed image on a multi-node cluster (two workers): placement, PDB, rolling and capacity-blocked upgrades, co-location, development values, controller outage, leader pod and node loss, leader loss during an S3 outage, leader loss mid-signing, and failover under admission and download traffic (graceful replacement, abrupt kill, leader API loss with a grant revoked meanwhile, node loss); builds the image |

`scripts/acceptance-groups.json` defines the matrix and Go test selection. The
normal `task test` checks that every compiled `TestLive*` test is assigned exactly
once, and that every group states `"release": true` or `false`. Release groups
(`charts`, `monitoring`, `availability`) install the Helm charts and the controller image, so
[release acceptance](charts.md#release-packaging-and-publication) runs them
again on the frozen archives and the published image digest; `task test` fails
if a test that installs the charts or the image sits in a non-release group.
The other groups exercise in-process managers against a disposable cluster and
install no chart; a release relies on their main-branch pass for the tagged
commit (`scripts/ci/require-acceptance.py`). Tests stay sequential inside each cluster: failure probes stop shared
Kyverno deployments, managers watch cluster-wide resources, and tests configure
process-global assessment settings. Matrix fail-fast is disabled so every group
can finish and upload diagnostics even if another fails.

Every group also states `"timeoutMinutes"`, its run budget: about 1.5 times
the longest successful CI run of that group, rounded up to 5 minutes (at least
15). The `test` workflow passes it as `KONSTAPEL_ACCEPTANCE_TIMEOUT` and sets
the group's job timeout 20 minutes higher, for setup, the post-timeout
diagnostics and teardown, and the evidence upload. Release acceptance runs each
release group under the same budget, and the `charts` workflow's acceptance
job timeout covers their sum; `task test` checks both. Raise a budget when a
group's successful runs grow towards it.

The stable `acceptance` gate requires successful `checks` and every matrix group,
or an explicit allowlisted prose-only PR skip. `checks` and `acceptance` are the
required status checks on `main`; individual matrix jobs remain conditional.

Local `task acceptance OUTPUT=/absolute/fresh/path` still runs the entire suite
sequentially in one cluster. Reproduce one CI group with, for example,
`task acceptance GROUP=storage OUTPUT=/tmp/konstapel-storage-1`. A group result
only proves that group's coverage; `acceptance-result.json` records its name.

Admission CI enables unprivileged user namespaces with the same AppArmor sysctl
and `bwrap` smoke check used by
[container-dropshipping's setup action](https://github.com/backend-bunny/container-dropshipping/blob/2096015fe369a0cab0db589f037126a543e72666/.github/actions/setup-tools/action.yml). This
host prerequisite does not by itself prove a nested kind Pod can run. Full and
admission runs also prepare their disposable node with the additional unmasked
sysfs mount described in [kind #3436](https://github.com/kubernetes-sigs/kind/issues/3436).
The hardening test must then verify Pod runtime isolation; missing runtime
evidence fails the prepared acceptance run. The mount disappears with the node.

Acceptance streams stdout and stderr to the terminal/Actions log while retaining
per-stage log files. Timestamped stage markers also go to `progress.log`;
`targeting/targeting-live.log` includes verbose Go test progress. Expiry/recovery
tests can take several minutes. Before partitioning, full CI took about 26 minutes;
parallel jobs reduce elapsed time while repeating setup on each runner.
Piping logs through `tee` preserves failures. `acceptance-result.json` and
`result.txt` record the final outcome after teardown.

The test S3 service for local work is `scripts/s3-compat.sh` (the digest-pinned
RustFS of `scripts/runtime.env`). `devbox run -- bash scripts/s3-compat.sh OUTPUT`
runs the S3 compatibility suites in all three versioning modes and records the
RustFS version; `--serve OUTPUT` keeps it running with an attachment bucket and
a 0600 `dev.env` of random credentials until Ctrl-C. Each run removes its own
container and named volume, identified by label. See
[supporting evidence](supporting-evidence.md#local-development).

Every run records `version-matrix.json` before creating the cluster: the tested
source commit (and whether it had uncommitted changes), the chart source trees
or, in release acceptance, the frozen archives' SHA-256, the tool versions on
`PATH`, the `devbox.lock` checksum and every pin of `scripts/runtime.env`.
Before teardown, on success, failure, timeout or cancellation alike,
`scripts/acceptance-evidence.sh diagnostics` writes `diagnostics/`: Kubernetes
events, the Conditions of nodes, workloads, CRDs, APIServices and the Kyverno,
cert-manager and Prometheus Operator resources, the full status of Konstapel
resources (ComplianceBinding, AssessmentRun, EvidenceDestination, ...), Pod
container states and image IDs, Leases, Helm releases, test-owned containers
still present, and recent logs of every Pod outside the kind system namespaces.
It then adds the server and node versions, Helm charts and running image IDs
to the version matrix. It never reads Secrets, Pod specs or container
environments; a failed collection step is listed in `diagnostics/collect.log`
without changing the result. Resources a test already deleted in its own
cleanup are gone by then; their events are in the test log.
`acceptance-result.json` records the `outcome`: `passed`, `failed`,
`timed-out` or `interrupted`. `KONSTAPEL_ACCEPTANCE_TIMEOUT` (for example
`45m`; CI sets the group's `timeoutMinutes`) stops a hung run, including every process it
started, so diagnostics and teardown finish inside the job timeout. Once
cleanup starts it ignores further INT/TERM signals; only SIGKILL stops it.

CI uploads test-owned evidence as `acceptance-evidence-<group>` (release
acceptance: `chart-acceptance-evidence`) only through
`scripts/ci/stage-evidence.py`. It copies the output without kubeconfigs,
compiled test binaries, the rendered Kyverno manifest, node logs, symlinks or
special files, and scans every copied file, including archive members, for PEM
or base64-encoded private keys (Cosign keys too), kubeconfig client keys and
tokens, bearer/basic authorization, JWTs, cloud and S3 access keys or
credential assignments, registry auths and htpasswd entries, age and GitHub
tokens, Kubernetes Secret data and key-material file names. A finding fails the
job and nothing is uploaded; the step summary names the file, line and rule,
never the value. Run it locally with
`devbox run -- python3 scripts/ci/stage-evidence.py OUTPUT FRESH_DIR`.
The task tears down its cluster and test service on success or failure;
teardown errors fail the task and remain in its logs.
After teardown the task checks that the kind cluster is gone and that no
container a live test labelled `konstapel.acceptance=<cluster name>` (test S3,
fault proxy and registry services) remains; a leftover fails the run, is
listed in `teardown.log` and is then removed.
CI checks that execution did not modify dependency locks. The setup action caches
Nix packages and Go downloads/build outputs; it does not use a separate Go version
or download an independently selected Kyverno CLI. Go build caches are reused only
under the same `devbox.lock`. Go keys cached cgo output by compiler version, not
by Nix store path, and `runtime/cgo` records the C toolchain's glibc loader. A
cache from an older lock therefore links test binaries against a loader that a
fresh runner lacks, and they fail with `fork/exec …test: no such file or
directory`. Locally the same happens once Nix garbage-collects the previous
toolchain; run `devbox run -- go clean -cache` after such an update.

## Dependency ownership and Renovate

| Input | Source of truth |
| --- | --- |
| Development tools | `devbox.json` and `devbox.lock` |
| Go modules and required compiler version | `go.mod` and `go.sum`, with matching Devbox Go pin |
| Kyverno chart version/checksum and test images | `scripts/runtime.env` |
| GitHub Actions and CI Devbox version | `.github/`, with the matching Devbox schema version |
| Reviewed policy/NIST content and provenance | `content/` and its checksums |
| Previously observed validation versions | `docs/integration/versions.json` and other historical evidence |
| Image runtime APKs | `apko.yaml` and `apko.lock.json`, refreshed through reviewed PRs |
| Application releases | `VERSION`, `melange.yaml` and `CHANGELOG.md`, managed by release-please |

Renovate uses its Go, Devbox, and GitHub Actions managers plus custom extraction
for the runtime chart/checksum, digest-pinned images, and Devbox installer/schema
version. It groups Go modules, Go toolchain, development tools, and Actions
separately. C2P integration, Kyverno runtime, and Kubernetes test-environment
updates require release from the Dependency Dashboard before Renovate opens their
update PRs. All updates require review; automerge is disabled. Lockfile maintenance
runs weekly before 06:00 Monday, Europe/Stockholm.

The Bash pin currently needs manual updates: Renovate's Devbox manager rejects
versions such as `5.3p20` during extraction. Update that pin with `devbox update`
and commit the regenerated lockfile; the other tools use automated update PRs.

The cert-manager chart used by the `charts` acceptance group for the runtime
chart's default TLS mode is pinned the same way, by version and archive
checksum in `scripts/runtime.env`, and fetched by `scripts/fetch-chart.sh
cert-manager`; `task deps:check` verifies the pin. Renovate updates the
version and checksum together.

The Prometheus Operator release whose `ServiceMonitor` and `PrometheusRule`
CRDs the chart tests validate rendered objects against is pinned by
`KONSTAPEL_PROMETHEUS_OPERATOR_VERSION` and a checksum of the vendored CRDs
(`testdata/charts/prometheus-operator`) in `scripts/runtime.env`. Renovate
proposes the version; `scripts/fetch-operator-crds.sh --refresh` renews the
files and prints the checksum, and `task deps:check` fails until they agree.

Kyverno chart and CLI updates are grouped. `task deps:check` verifies the chart's
actual `appVersion` against the CLI pin and verifies the chart archive checksum.
Update failures must be resolved with compatible pins, not by disabling the
check. Runtime or C2P updates also require all `acceptance-live (<group>)` and
`acceptance` jobs before merge. A local `task acceptance` run provides useful
evidence but does not replace the required CI gate. The `checks` job
alone does not prove live compatibility.

### Renovate rules for the Sigstore test stack

The `KONSTAPEL_SIGSTORE_*_IMAGE` pins in `scripts/runtime.env` have extra rules
in `renovate.json`. Patch and minor updates of nginx, PostgreSQL 17, Fulcio, the
timestamp server and Rekor remain allowed.

- Rekor (`ghcr.io/sigstore/rekor/rekor-server`) is limited to `v1.x`; upstream
  publishes bogus `v99.x` test tags.
- PostgreSQL (`docker.io/library/postgres`) is limited to `17.x-alpine`. The
  stack keeps PGDATA on tmpfs and was verified on 17; PostgreSQL 18 changed the
  data directory layout. To raise the major, change the pin and the
  `allowedVersions` rule together and re-run the opt-in stack suite
  (`KONSTAPEL_SIGSTORE_STACK=1`, registry-compat).
- The Trillian log server and signer images have updates disabled. `deps:check`
  requires their tag to equal the `github.com/google/trillian` version in
  `go.sum`, because the suite loads that module's PostgreSQL schema. The module
  is transitive (not in `go.mod`), so Renovate cannot group it with the images.
  To bump: update the module version (for example `go get
  github.com/google/trillian@<v>` or via the dependency that requires it), set
  both image tags and digests to that version, run `task deps:check`, and run
  the opt-in stack suite.

### Temporary Go toolchain holds

Devbox's package index currently stops at Go 1.27.3. The Devbox `go-licenses`
used to be built with Go 1.26, and its wrapper sets `GOROOT` to that toolchain,
whose standard library lacks `crypto/mldsa`. Its lock entry now resolves to a
nixpkgs build made with Go 1.27.3, so go-licenses loads `crypto/mldsa`. Keep it
on a Go 1.27 build when updating `devbox.lock`: the `GOROOT` exported by the
`go-licenses` wrapper must name a Go 1.27 store path. Rules in `renovate.json`
still keep Renovate from opening PRs that have not yet passed `task check` and
`task image:build`:

- The `go.mod` directive and the `devbox.json` `go@` pin (one "Go toolchain"
  group) are held below 1.27.4.
- `golang.org/x/crypto` is held below 0.58.0 (`ssh/mldsa.go` imports
  `crypto/mldsa`), `github.com/sigstore/sigstore` below 1.11.0 (`pkg/cryptoutils`
  imports it), and `golang.org/x/net` below 0.61.0 and
  `github.com/prometheus/common` below 0.74.0 (they require x/crypto 0.58 or
  newer). The Go 1.26 build of go-licenses failed to load these packages, so
  `image:build` failed; with the Go 1.27.3 build it passes for x/crypto 0.58.0.
- `github.com/sigstore/sigstore-go` is held below 1.4.0, with its coupled
  `rekor` (up to 1.5.3), `rekor-tiles/v2` (below 2.4.0) and
  `timestamp-authority/v2` (below 2.2.0). sigstore-go 1.4.0 requires rekor
  1.5.5, which requires Trillian 1.8.0, while `task deps:check` pins both
  Trillian images to the version in `go.sum`.

The x/crypto, sigstore/sigstore, x/net and prometheus/common holds no longer
wait for Go 1.27.4: lift them with steps 2 and 4. The Go directive hold waits
for Devbox to index Go 1.27.4 (step 1), and the sigstore-go set for Trillian
1.8.0 (step 3):

1. Set `go@1.27.4` in `devbox.json`, regenerate `devbox.lock` with Devbox, and
   set the `go.mod` directive.
2. Bump the held set together: x/crypto 0.59.0 or newer, sigstore/sigstore
   1.11.x, prometheus/common 0.74.0, x/net 0.62.0 and its x/sys, x/term and
   x/text, then `go mod tidy`.
3. Bump sigstore-go 1.4.0 with rekor 1.5.5, rekor-tiles 2.4.0 and
   timestamp-authority 2.2.0, and move both Trillian images (tag and digest in
   `scripts/runtime.env`) to Trillian 1.8.0; run the opt-in Sigstore stack
   suite and the live acceptance groups.
4. Run `task check`, `task image:build` and `task image:test`, then remove the
   holds from `renovate.json` and this section.

Renovate excludes vendored content, historical evidence, and OpenSpec artifacts.
Refresh policies, mappings, and NIST content through their reviewed content-update
workflow, with new provenance/checksums and relevant assessments. Do not rewrite
old validation results to describe a newly selected dependency version.

The Renovate GitHub App (or an existing self-hosted Renovate installation) must
be enabled for this repository to open update PRs. The checked-in configuration
does not install the App or grant it repository permissions. An extraction-only
check can be run locally without publishing changes:

```sh
devbox run -- renovate --platform=local --dry-run=extract
```
