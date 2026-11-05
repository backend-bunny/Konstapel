# Development tooling

Konstapel uses Devbox for the pinned development environment, direnv for optional
automatic activation, Task for commands, and Renovate for dependency update PRs.
The initial supported development and acceptance platform is Linux amd64.

## Enter the environment

Install [Devbox](https://www.jetify.com/docs/devbox/installing_devbox/) and,
optionally, [direnv](https://direnv.net/docs/installation.html) with its shell hook.
CI currently uses Devbox 0.18.4. The repository's `devbox.json` and generated
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
| `task test` | Run Go tests, including the real provider handshake and saved-evidence checks. |
| `task lint` | Check Go formatting, `go vet`, and shell syntax. |
| `task content:check` | Verify vendored policy, OSCAL, and schema checksums. |
| `task policies:test` | Run the vendored Kyverno CLI fixtures. |
| `task deps:validate` | Validate `renovate.json` with the pinned validator. |
| `task deps:check` | Check Devbox lock entries, Go version agreement, image digest format, chart checksum, and chart/CLI version agreement. |
| `task check` | Run all the preceding checks and build, in the same order as CI. |
| `task acceptance OUTPUT=/absolute/fresh/path` | Run full acceptance in a disposable kind cluster and retain evidence. |
| `task test:failures OUTPUT=/absolute/fresh/path` | Exercise missing-evidence and unexpected-admission failure paths. |
| `task clean` | Remove generated binaries and Task cache; retain assessment evidence. |

`task check` needs no cluster or Docker daemon. Initial tool/module installation
and the checksum-verified chart download need network access. The pinned Devbox
Kyverno CLI replaces the previous manual release-archive download.

Task delegates orchestration to `scripts/`; scripts remain usable directly inside
the environment. Full acceptance requires a fresh output directory, selects its
own explicit kubeconfig/context, refuses existing clusters, and tears down its
owned cluster while preserving diagnostic evidence. See the
[assessment guide](integration/assessment-loop.md) for package inspection and
manual environment create/smoke/delete commands.

GitHub Actions installs the same Devbox lock and runs `devbox run -- task check`.
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

Kyverno chart and CLI updates are grouped. `task deps:check` verifies the chart's
actual `appVersion` against the CLI pin and verifies the chart archive checksum.
Update failures must be resolved with compatible pins, not by disabling the
check. Runtime or C2P updates also require `task acceptance` and retained evidence
before merge; the regular CI job alone does not prove live compatibility.

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
