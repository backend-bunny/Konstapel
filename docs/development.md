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
| `task test` | Run Go tests, including the real provider handshake and saved-evidence checks, plus CI decision and shell logging regression tests. |
| `task lint` | Check Go formatting, `go vet`, generated API files, Helm chart metadata, versions and values-schema fixtures (`scripts/charts/check.sh`), and shell syntax. |
| `task content:check` | Verify vendored policy, OSCAL, and schema checksums. |
| `task policies:test` | Run the vendored Kyverno CLI fixtures and the CLI checks of rendered targeting policies. |
| `task deps:check` | Validate Renovate configuration, Devbox lock entries, Go version agreement, image digest format, agreement of the isolated Sigstore stack's Trillian images with the go.sum Trillian module, chart checksum, and chart/CLI version agreement. |
| `task check` | Run all the preceding checks and build, in the same order as CI. |
| `task acceptance OUTPUT=/absolute/fresh/path [GROUP=all]` | Run full acceptance by default, or one named CI group, in a disposable kind cluster and retain evidence. `GROUP=bundles` is the policy-bundle acceptance that the `add-policy-bundle-distribution` change calls `bundles:acceptance` ([bundle acceptance](policy-bundles.md#bundle-acceptance)); it is a group of this task, not a separate task. |
| `task test:failures OUTPUT=/absolute/fresh/path` | Exercise missing-evidence and unexpected-admission failure paths. |
| `task charts:package OUT=/fresh/path IMAGE_DIGEST=sha256:…` | From a clean checkout, package both charts with the runtime chart defaulting to that image digest, and freeze them with `publication.json` ([Helm charts](charts.md#release-packaging-and-publication)). |
| `task charts:acceptance OUTPUT=/fresh/path ARCHIVES=/path IMAGE=ghcr.io/backend-bunny/konstapel@sha256:…` | From a clean checkout, run every release-required acceptance group (`"release": true`: `charts` and `availability`) in turn, each on its own disposable cluster, on those exact archives with every node pulling that image by digest. Writes `chart-acceptance.json` only if every required test passed, binding the per-test results to the frozen inputs. |
| `task bundles:package NAME=<bundle> OUT=/fresh/path` | From a clean checkout, build `bundles/<NAME>/definition.json` into a frozen OCI image layout plus `package.json` at that commit, and re-verify it. Identical commits give identical digests. Publication is not available yet ([policy bundles](policy-bundles.md)). |
| `task clean` | Remove generated binaries and Task cache; retain assessment evidence. |

After editing Go types in `api/`, run `devbox run -- scripts/generate.sh` to
regenerate deepcopy code and CRDs with the pinned `controller-gen`; `task lint`
fails when they are stale. See the [targeting API guide](integration/targeting-api.md)
and the [continuous assessment contract](integration/assessment-contract.md).

`task check` needs no cluster or Docker daemon. Initial tool/module installation
and the checksum-verified chart download need network access. The pinned Devbox
Kyverno CLI replaces the previous manual release-archive download.

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
| `assessments` | Assessment status/runs, engine correlation, integrated assessments, and authenticated exception admission |
| `storage` | Destination/credential changes, downloads, retention, and orphaning, plus evidence signing: destination configuration and readiness, signed downloads, and the signed-publication workflow |
| `recovery` | Kyverno outages and assessment/publication faults |
| `capabilities` | Engine API and permission loss and recovery without a controller restart |
| `charts` | The CRD chart lifecycle and the Helm-installed controller image (both TLS modes, downloads, rotation, follower serving), and OCI policy bundles from a disposable TLS registry (chart RBAC, watches, revocation, follower pins, upgrade and rollback); installs cert-manager and builds the image |
| `bundles` | OCI policy bundles on an in-process controller: the official keyless release read anonymously from `ghcr.io` and the organization-key fixture from a disposable TLS registry, each in Audit and Deny; unsigned, wrong-key and tampered bundles; warm-cache outage, cold-cache failure, credential rotation, trust revocation and recovery ([bundle acceptance](policy-bundles.md#bundle-acceptance)); needs network access to `ghcr.io` and fails without it |
| `availability` | The Helm-installed image on a multi-node cluster (two workers): placement, PDB, rolling and capacity-blocked upgrades, co-location, development values, controller outage, leader pod and node loss, leader loss during an S3 outage, and leader loss mid-signing; builds the image |

`scripts/acceptance-groups.json` defines the matrix and Go test selection. The
normal `task test` checks that every compiled `TestLive*` test is assigned exactly
once, and that every group states `"release": true` or `false`. Release groups
(`charts`, `availability`) install the Helm charts and the controller image, so
[release acceptance](charts.md#release-packaging-and-publication) runs them
again on the frozen archives and the published image digest; `task test` fails
if a test that installs the charts or the image sits in a non-release group.
The other groups exercise in-process managers against a disposable cluster and
install no chart; a release relies on their main-branch pass for the tagged
commit (`scripts/ci/require-acceptance.py`). Tests stay sequential inside each cluster: failure probes stop shared
Kyverno deployments, managers watch cluster-wide resources, and tests configure
process-global assessment settings. Matrix fail-fast is disabled so every group
can finish and upload diagnostics even if another fails.

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

CI uploads test-owned evidence as `acceptance-evidence-<group>`, excluding kubeconfigs,
compiled test binaries, rendered chart manifests, and node logs. The task tears
down its cluster and test service on success or failure; teardown errors fail
the task and remain in its logs.
After teardown the task checks that the kind cluster is gone and that no
container a live test labelled `konstapel.acceptance=<cluster name>` (test S3,
fault proxy and registry services) remains; a leftover fails the run, is
listed in `teardown.log` and is then removed.
CI checks that execution did not modify dependency locks. The setup action caches
Nix packages and Go downloads/build outputs; it does not use a separate Go version
or download an independently selected Kyverno CLI.

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

Devbox's package index currently stops at Go 1.27.3, and the Devbox `go-licenses`
is built with Go 1.26, whose standard library lacks `crypto/mldsa`. Rules in
`renovate.json` keep Renovate from opening PRs that cannot pass `task check` or
`task image:build`:

- The `go.mod` directive and the `devbox.json` `go@` pin (one "Go toolchain"
  group) are held below 1.27.4.
- `golang.org/x/crypto` is held below 0.58.0 (`ssh/mldsa.go` imports
  `crypto/mldsa`), `github.com/sigstore/sigstore` below 1.11.0 (`pkg/cryptoutils`
  imports it), and `golang.org/x/net` below 0.61.0 and
  `github.com/prometheus/common` below 0.74.0 (they require x/crypto 0.58 or
  newer). go-licenses fails to load these packages, so `image:build` fails.
- `github.com/sigstore/sigstore-go` is held below 1.4.0, with its coupled
  `rekor` (up to 1.5.3), `rekor-tiles/v2` (below 2.4.0) and
  `timestamp-authority/v2` (below 2.2.0). sigstore-go 1.4.0 requires rekor
  1.5.5, which requires Trillian 1.8.0, while `task deps:check` pins both
  Trillian images to the version in `go.sum`.

To lift the holds, once Devbox indexes Go 1.27.4 (or ships a `go-licenses`
built with Go 1.27):

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
