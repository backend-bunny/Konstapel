# Linux workload hardening bundle

This page tracks `add-linux-workload-hardening-bundle`. Group 1 is done: the
four upstream policies are vendored and their upstream test suites have been
re-run. They are **not** part of the served bundle yet. Local Linux variants
(group 2), packaging and NIST mappings (group 3), targeting and live behavior
(group 4), and exceptions (group 5) come later.

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
