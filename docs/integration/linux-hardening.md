# Linux workload hardening bundle

This page tracks `add-linux-workload-hardening-bundle`. Group 1 is done: the
four upstream policies are vendored and their upstream test suites have been
re-run. Group 2 is done: the Konstapel variants of the four checks exist and
are tested in the CLI. Since task 3.1, the controller's vendored bundle serves
them next to the first loop's privileged check (see "Serving"). Packaging and NIST mappings (group 3), targeting and live
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

| `testdata/linux-hardening/escalation/` | `allowPrivilegeEscalation` `false`, `true`, missing, and no securityContext, on regular, init and ephemeral containers in Pod, Deployment and CronJob forms (ephemeral on Pods only). Also a Pod-level value, which is not inherited, and Windows. 42 cases. |
| `testdata/linux-hardening/capabilities/` | The combined shipped policy on the full cross-product of `drop` {`ALL`, `all`, `NET_RAW`, `NET_RAW`+`ALL`, empty, unset} × `add` {unset, empty, `NET_BIND_SERVICE`, `net_bind_service`, `SYS_ADMIN`, `NET_BIND_SERVICE`+`SYS_ADMIN`} for every container class and form, plus no securityContext and Windows. 266 cases. |
| `testdata/linux-hardening/seccomp/` | Pod-level × container `seccompProfile.type` in {unset, `RuntimeDefault`, `Localhost`, `Unconfined`} for every container class and form, plus Windows. 119 cases. |

The escalation, capabilities and seccomp fixtures are generated by
`go test ./internal/hardening -run TestCheckMatrices -update`. Their expected
results come from a small Go model of the intended semantics in
`matrices_test.go`, written independently of the policy expressions:
- escalation: only an explicit `false` passes;
- capabilities: `drop` must contain the exact string `ALL`, and every addition
  must be exactly `NET_BIND_SERVICE`;
- seccomp: a Pod-level type must be allowed if set, and each container must
  set or inherit `RuntimeDefault` or `Localhost`.

The CLI must agree with the model on every case; a single flipped
expectation fails the suite.

`task policies:test` runs all of these.
[hardening-variant-cli.json](hardening-variant-cli.json) records each
suite's result together with the **sha256 of every variant tested**. A test
fails if a variant changes without the suites being re-run and the evidence
re-recorded.

## Coverage and limits

The CLI evidence above shows how the **variant sources** evaluate submitted
configuration. It does not show:

- **Rendered behavior.** Binding instances (Audit or Deny mode, namespace
  selector, provenance), live admission, `UPDATE` and ephemeral-container
  requests, and background reports are group 4.
- **Runtime behavior.** No check observes the effective UID, the effective
  capability set, privilege transitions, or the contents of a `Localhost`
  seccomp profile and the filtering it applies. A pass means the workload
  *requested* the setting.
- **Node OS.** An omitted `spec.os.name` gets the Linux rules by convention;
  this does not attest the OS of the node that runs the Pod. Explicit Windows
  workloads produce a raw `pass` but are outside the bundle's scope (task 4.5).
- **Fine-grained waivers.** Exceptions are whole-policy: an exception for
  `disallow-capabilities-strict` waives both its `drop-all` and
  `add-net-bind-service-only` validations for the selected workloads. The
  upstream `images` and `allowedValues` hooks remain in the expressions, but
  Konstapel never renders them in native exceptions (design §3–4).
- **Full controls.** The NIST mappings (group 3) describe partial,
  configuration-level evidence. No pass, alone or combined, establishes full
  control or Moderate-baseline satisfaction.

The only local *semantic* change is in `require-run-as-nonroot`: it removes
the `hostUsers: false` bypass and adds the Windows guard. The other three
variants keep the upstream expressions unchanged and add provenance
annotations only. `variants.json` and its test pin this down.

## Serving

The controller's vendored bundle (`konstapel-vendored`, pinned by the sha256
of `content/SHA256SUMS`) serves the checks in `assessment.ShippedPolicies`:

| Logical policy (profile `policies[].name`) | Served source |
| --- | --- |
| `disallow-privileged-containers` | the first loop's upstream policy, unchanged and referenced, not copied |
| `disallow-privilege-escalation`, `disallow-capabilities-strict`, `require-run-as-nonroot`, `restrict-seccomp-strict` | the Konstapel variant in `content/linux-hardening/variants/` |

A profile selects any of them by name. Each binding renders one engine
policy per selected check. Each rendered instance carries:
- the logical policy name, `compliance.erenius.io/source-digest` (the
  variant's sha256), the bundle digest and its own revision;
- the binding's Audit or Deny mode, background evaluation, and the source's
  unchanged workload rules, variables and validations.

`internal/hardening/serve_test.go` checks this for a whole-bundle profile
under an Audit and a Deny binding.

### Rendered bundle instances (task 4.1)

`testdata/linux-hardening/rendered/` holds the four checks rendered through a
`linux-hardening` profile with two bindings: `audit-all` (empty selector:
every namespace, Audit) and `deny-production` (`environment: production`,
Deny). These eight golden policies are the input of a generated Kyverno CLI
test. The workloads are, per namespace, one compliant Pod, one Pod per
violated check, and a CronJob template violating all four, for 96 expected
results. In each namespace a binding selects, each check fails only the
workloads violating it; elsewhere it is skipped.

`TestRenderedBundleInstances` checks every instance in Go:
- it is a `policies.kyverno.io/v1` `ValidatingPolicy` with background
  evaluation and exactly the binding's mode;
- it carries revision, logical-policy and source-digest provenance;
- its resource rules are unchanged from the variant;
- `matchConstraints` holds nothing besides those rules and the namespace
  selector, and no `matchConditions` are added, so there are no hidden
  exclusions;
- its namespace selector selects exactly the binding's namespaces. This
  covers the Kyverno 1.19 CLI limitation that a selector-excluded resource
  passes any expected result.

The rendered names and annotations derive from the bundle digest. After any
`content/` change, regenerate with
`go test ./internal/hardening -run TestRenderedBundleFixtures -update`,
together with the targeting goldens.

## NIST Moderate mappings

`content/linux-hardening/component-definition.json` (OSCAL 1.1.3, trestle
shape) maps each check to statements in the pinned NIST SP 800-53 rev5
catalog. It sits next to the first loop's `content/component-definition.json`
and does not copy it: the expanded demonstration composes the two, and each
check is mapped in exactly one document.

| Check | Statements | Evidence boundary |
| --- | --- | --- |
| `disallow-privilege-escalation` | `ac-6_smt`, `cm-6_smt.b` | One declared privilege and configuration restriction; no observed privilege transitions |
| `disallow-capabilities-strict` | `ac-6_smt`, `cm-7_smt.b`, `cm-6_smt.b` | Declared capability lists, not effective capability sets |
| `require-run-as-nonroot` | `ac-6_smt`, `cm-6_smt.b` | Requested non-root execution, not the observed UID |
| `restrict-seccomp-strict` | `cm-7_smt.b`, `cm-6_smt.b` | Selected profile type, not profile contents or observed filtering |

Each check is a separate `Rule_Id` on a shared statement. So
`ac-6_smt` collects three independent, bounded pieces of evidence for one
control, and multiple checks or binding instances never multiply satisfied
controls. Each rule's `Rule_Description` states its rationale and
partial-coverage limit. No check establishes full control or Moderate-baseline
satisfaction.

`internal/assessment` validates every shipped component definition
(`ValidateDefinition`; `Mappings` returns the per-check result):
- it is valid OSCAL 1.1.3, and its control source resolves to the shipped
  catalog;
- every control is in the catalog and explicitly included by the Moderate
  profile;
- every statement exists and belongs to its control;
- every statement names a rule; every rule is declared with a description,
  mapped, has a `Check_Id` in the `konstapel-kyverno` provider, and is a
  shipped policy;
- no rule appears in two documents.

The NIST catalog and profile are read as raw JSON at their declared OSCAL
1.2.3 schema and are never round-tripped through the older 1.1.3 model.
`SHA256SUMS` keeps them unchanged. `TestInvalidMappingsAreRejected` covers
the failing references: an unknown statement, a statement from another
control, an unknown control, a control outside Moderate, an undeclared rule,
a missing provider check, a wrong catalog source, a rule that is not a
shipped policy, and a check mapped twice.

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
   `content/SHA256SUMS`, so fixtures that pin it change as well. Regenerate
   them with `go test ./internal/targeting -run 'TestRenderMatchesGoldenCLIFixtures|TestExpectedEvidenceMatchesGolden' -update`
   and `go test ./internal/hardening -run TestRenderedBundleFixtures -update`.
   Then refresh the engine policy names in `testdata/targeting/rendered/kyverno-test.yaml`.
