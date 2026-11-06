# Linux workload hardening bundle

This page tracks `add-linux-workload-hardening-bundle`. Group 1 is done: the
four upstream policies are vendored and their upstream test suites have been
re-run. The Konstapel variants of the four checks exist (tasks 2.1 and 2.2;
the remaining group 2 matrices are pending). None of them is part of the
served bundle yet. Packaging and NIST mappings (group 3), targeting and live
behavior (group 4), and exceptions (group 5) come later.

## Source layout

| Path | Content |
| --- | --- |
| `content/upstream/kyverno/<check>/` | The upstream directory, byte for byte: the policy, `artifacthub-pkg.yml`, and the hidden `.kyverno-test*` CLI suites and `.chainsaw-test` fixtures. |
| `content/upstream/kyverno/LICENSE` | The Apache-2.0 license, shared with the first loop's check (same upstream revision, identical bytes). There is no upstream NOTICE file. |
| `content/linux-hardening/sources.json` | Source URL, path, license, checksums (each also matching the research table), stable check and sub-validation identities, and declared test aids. |
| `content/SHA256SUMS` | Covers every vendored file and `sources.json`. `task content:check` verifies it. |
| `docs/integration/hardening-upstream-cli.json` | The upstream CLI results (task 1.3). |

The four checks come from [`kyverno/policies` at
`fac1ccda72ab53594921ca1c040ac90b80afadcd`](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/restricted),
the revision pinned by the [research](../research/next-policy-bundle.md):

| Check (logical identity) | Sub-validations (`cel.validationIndex`) |
| --- | --- |
| `disallow-privilege-escalation` | 0 `no-escalation` |
| `disallow-capabilities-strict` | 0 `drop-all`, 1 `add-net-bind-service-only` |
| `require-run-as-nonroot` | 0 `run-as-non-root` |
| `restrict-seccomp-strict` | 0 `pod-profile-type`, 1 `container-profile-type` |

A check's identity is its policy name, as for the first loop's
`disallow-privileged-containers`. A sub-validation ID is
`<check>.<name>`, keyed by the validation's index, which Kyverno reports as
`cel.validationIndex`. Binding instance names and enforcement revisions are
separate identities. The bundle composes `disallow-privileged-containers` by
reference and does not vendor it again.

`disallow-capabilities-strict/.kyverno-test/adding-capabilities-strict.yaml`
is an upstream **test aid**: a Pod-only policy that checks added capabilities
only. It is recorded in `sources.json` as a fixture aid. It is never shipped,
and its CLI results are counted separately.

All shipped policies, the test aid and the fixture exceptions are new-group
`policies.kyverno.io/v1`. `internal/hardening` tests enforce this.

### Runtime annotations

Every source policy carries these upstream annotations:
- `policies.kyverno.io/minversion: 1.19.1`
- `kyverno.io/kyverno-version: 1.14.0`
- `kyverno.io/kubernetes-version: "1.30+"`
- category `Pod Security Standards (Restricted) in ValidatingPolicy`, severity `medium`, subject `Pod`

They also set `validationActions: [Audit]` and enable background evaluation.

These annotations are upstream descriptions, not Konstapel's tested matrix.
Konstapel's runtime pins are in `scripts/runtime.env` and
`docs/integration/versions.json`. Rendering will set the enforcement mode
(Audit or Deny) per binding.

## Upstream CLI suites (task 1.3)

```sh
for c in disallow-privilege-escalation require-run-as-nonroot disallow-capabilities-strict restrict-seccomp-strict; do
  devbox run -- kyverno test content/upstream/kyverno/$c --require-tests --remove-color
done
```

`task policies:test` runs every vendored suite, including these.
[hardening-upstream-cli.json](hardening-upstream-cli.json) records the
2026-11-06 run with the pinned Devbox Kyverno CLI v1.19.2, one row per
result:

| Check | Matched | Failed | Suites |
| --- | ---: | ---: | --- |
| `disallow-privilege-escalation` | 50 | 0 | `.kyverno-test`, `-controllers`, `-exceptions` |
| `require-run-as-nonroot` | 113 | 0 | those three plus `.kyverno-test-regressions` |
| `disallow-capabilities-strict` | 156 (80 shipped policy, 76 helper) | 0 | `.kyverno-test`, `-controllers`, `-exceptions` |
| `restrict-seccomp-strict` | 78 | 0 | `.kyverno-test`, `-controllers`, `-exceptions` |

The totals match the research's independent run.

The capabilities total is **not deterministic** between CLI runs. Repeated
runs report 152–159 results, always with 0 failures. The shipped policy
always contributes exactly 80. The variation is only in extra
`Pass / Excluded` rows that the CLI emits for the Pod-only
`adding-capabilities-strict` test aid on controller resources: its 72
ordinary results are stable. Compare the shipped policy's per-policy counts,
not the suite total.

## Local variants

Konstapel ships its own variant of each check: `content/linux-hardening/variants/<check>.yaml`.
The vendored originals stay byte for byte under `content/upstream/kyverno/`.
`content/linux-hardening/variants.json` records each variant's checksum, its
source and source checksum, and every intentional change with the policy
paths it touches. Each variant carries two provenance annotations:
`compliance.erenius.io/variant-of` and `compliance.erenius.io/source-sha256`.
`internal/hardening` tests fail if a variant differs from its source anywhere
not declared in `variants.json`, or if a checksum drifts. The logical check
identity (`metadata.name`) is unchanged.

| Check | Expression changes |
| --- | --- |
| `disallow-privilege-escalation` | none |
| `disallow-capabilities-strict` | none |
| `restrict-seccomp-strict` | none |
| `require-run-as-nonroot` | **removes the `spec.hostUsers: false` bypass** and **adds the Windows guard**. The description and message say so. |

### OS convention

- **Explicit Windows is out of scope.** A Pod or template with
  `spec.os.name: windows` short-circuits every validation of all four checks,
  through the same `isWindowsPod` variable. The upstream non-root policy had
  no such guard. The engine then reports a raw `pass`. Assessment must record
  such a workload as outside Linux scope, never as passing Linux coverage or
  as accepted risk (task 4.5).
- **An omitted OS gets the Linux rules.** This is a convention about
  configuration. It does not attest which OS the node actually runs.
- **Templates:** `variables.podSpec` extracts the Pod spec from Pods,
  controller templates and CronJob job templates, so the convention applies
  to every matched form.

### Non-root without a user-namespace bypass

Every container must set `runAsNonRoot: true` or inherit it from the Pod.
Explicit `false` fails at either level. `hostUsers: false` no longer exempts
a Pod: a workload that cannot run as non-root needs a recorded,
centrally permitted exception. Null `initContainers` and `ephemeralContainers`
lists are treated as empty, as upstream does.

### CLI fixtures

| Fixture | Covers |
| --- | --- |
| `testdata/linux-hardening/forms/` (generated by `go test ./internal/hardening -run TestWorkloadFormsFixtures -update`) | All four variants against Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job and CronJob forms: a compliant spec plus one violation per check, each with an omitted, Linux and Windows OS. 448 results. Each check fails only its own violation, and never on Windows. |
| `testdata/linux-hardening/nonroot/variant/` | The non-root variant on 26 cases: regular, init and ephemeral containers; Pod-level and container inheritance; explicit false at each level; null lists; `hostUsers` true and false with and without the flag; Linux and Windows OS; Deployment, StatefulSet and CronJob templates. |
| `testdata/linux-hardening/nonroot/upstream/` | The **unmodified upstream** policy on the same resources, with upstream's results. It shows the 8 intentional differences: 5 `hostUsers: false` cases upstream passes and the variant fails, and 3 Windows cases upstream fails and the variant leaves out of scope. |

`task policies:test` runs them all. These are CLI results on the variant
sources. They are not rendered-instance, admission or runtime results.

## Research results versus implementation acceptance

The research and this run show that the **unmodified upstream** policies
agree with **upstream's own expectations** in the CLI. A matched check can be
an expected failure or skip. These runs do not test:
- the local variants: Windows scope, the removed `hostUsers: false` bypass,
  and the full capabilities matrix (group 2);
- rendered binding instances, live admission or background reports (group 4);
- exceptions or OSCAL export (groups 3 and 5).

Coverage claims come only from those later tests, run against rendered
policies with recorded digests.

## Updating the sources

1. Choose a new immutable `kyverno/policies` revision; never follow a moving
   branch or Artifact Hub install URL.
2. Fetch the four `pod-security-vpol/restricted/<check>` directories and
   `LICENSE` at that revision into a scratch directory, and check for a
   NOTICE file.
3. Replace `content/upstream/kyverno/<check>/` wholesale. Update `sourceRevision`,
   the URLs and checksums in `content/linux-hardening/sources.json`, and the
   checksums in `content/SHA256SUMS`. Record new validations as new
   sub-validation identities. Never renumber existing ones.
4. Re-run the CLI suites, regenerate `hardening-upstream-cli.json`, and review
   upstream changes before updating any local variant.
5. `devbox run -- task check`. The vendored bundle digest is the sha256 of
   `content/SHA256SUMS`, so targeting fixtures that pin it change as well.
