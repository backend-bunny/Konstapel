# Assessment providers

An assessment provider is the in-tree code that turns one kind of external
evidence into Konstapel check outcomes. Kyverno (ValidatingPolicy delivery
and PolicyReport evidence) is the only installed provider. This guide covers
the provider contract from
[`add-assessment-provider-contract`](../openspec/changes/add-assessment-provider-contract/proposal.md).

**Status.** Group 1 of that change is implemented: the installed-provider
descriptor and registry, the selection checks, and the conformance harness
with its versioned fixtures. Nothing in this guide changes how existing
bindings, profiles, delivery, collection, evaluation or export behave:

- The bundle compatibility check (`content.Compatibility`, allowlist
  `konstapel-kyverno/v1`) and the targeting resolver still make the
  production decisions.
- The registry encodes those decisions, and tests keep the two in
  agreement.
- The registry does not yet gate the resolver.
- Collection adapters, capability wiring, the provider-aware capture
  boundary, shared evaluation and the full authoring recipe are later groups
  of the change.

No Trivy or other producer is supported. See
[What this contract does not establish](#what-this-contract-does-not-establish).

## Registration is code, not data

Providers are registered by compiling a descriptor into the binary.
`internal/provider/installed.Registry()` is the production registry: a fixed
list that today contains only `kyverno.Descriptor()`. There is no runtime
registration API, plugin directory, provider CRD or configuration flag.

Verified bundle content can only name a provider contract
(`compatibility.provider` in `bundle.json`, for example
`konstapel-kyverno/v1`) and check definitions of kinds that a provider owns.
Selection looks those names up in the registry. Bundle content therefore
cannot:

- install, download or select an executable, Go module, command path or
  plugin manifest. A contract is `name/vN` and nothing else. A value such as
  `./konstapel-provider` is an `InvalidSelection`, never a path.
- add a provider, a check kind, a mode or a parameter contract.
- change a provider's declared reads, the controller's RBAC or its
  capability requirements. These come from the descriptor in code, the Helm
  chart and `internal/capability`.

The C2P plugin binary `konstapel-provider` and its manifest are build
outputs (`scripts/build.sh`). They are not bundle content. The pinned C2P-Go v2
packaging stays authoritative.

## The descriptor

`provider.Descriptor` is the versioned capability contract of one installed
provider:

| Field | Meaning |
| --- | --- |
| `name`, `version` | Identity. The contract `name/v<version>` is what bundles select. A registry holds one version per name. Requesting another version of an installed provider is `IncompatibleVersion`, never adapted. |
| `evaluatorVersion` | Version of the evaluation semantics. It is separate from the contract version and the capture version. |
| `checks[]` | Check kinds (`group/version/Kind` of the check definition in content). Each kind belongs to exactly one installed provider. |
| `checks[].delivery` | `true` when the delivery owner renders engine resources for the kind (enforcement-capable). `false` is reporting-only: no engine policy, scanner job or workload write, and only `Audit`. |
| `checks[].modes` | Binding modes the kind accepts. `Deny` requires `delivery`. |
| `checks[].parameters` | `Content`: the bundle declares a schema per check and delivery decides whether it renders parameters. `Descriptor`: a schema in the descriptor. `None`: no parameters. |
| `capture` | Capture payload versions it `write`s and `read`s. `write` must be in `read`, so readers ship before writers. |
| `reads[]` | External evidence-source operations its collection performs. These are read-only (`get`, `list`, `watch`). |
| `testOnly` | A synthetic provider. Never in the production registry, and never a registry default. |

`provider.New` rejects these registries:

- an invalid descriptor
- a provider name registered twice
- a check kind claimed by two providers
- a write verb in `reads`
- a reporting-only kind that accepts `Deny`
- a descriptor schema that is not a self-contained object schema
- an unreadable capture writer
- a default that is missing or test-only

The installed Kyverno descriptor, as `TestDocumentedExamples` checks it
against `kyverno.Descriptor()`:

<!-- verified: kyverno-descriptor -->
```json
{
  "name": "konstapel-kyverno",
  "version": 1,
  "evaluatorVersion": 1,
  "checks": [
    {
      "kind": "policies.kyverno.io/v1/ValidatingPolicy",
      "delivery": true,
      "modes": ["Audit", "Deny"],
      "parameters": {"source": "Content"}
    }
  ],
  "capture": {"write": 2, "read": [1, 2]},
  "reads": [
    {
      "group": "wgpolicyk8s.io",
      "version": "v1alpha2",
      "resource": "policyreports",
      "verbs": ["get", "list", "watch"]
    }
  ]
}
```

Notes on the Kyverno entry:

- `capture.read` covers the prototype's single-policy capture (1) and the
  controller's CaptureV2 (2), exactly the versions `collector.CaptureVersion`
  accepts. The controller writes 2.
- `reads` lists only the evidence source, matching the access that
  `capability.Requirements[Assessment]` requires. The host owns namespace and
  workload listing for the expected inventory. ValidatingPolicy writes
  belong to delivery (`capability.Delivery`), not to evidence collection.
- `reads` document and bound the provider's own access. They are not a
  sandbox: adapters are trusted in-tree code, and the controller service
  account's RBAC is shared and broader. Do not read a descriptor as
  per-provider security isolation.
- Parameters keep today's behavior. A policy's bundle schema validates them,
  and delivery does not render parameters yet, so any non-empty parameters
  are rejected, never dropped.

The production registry's contracts:

<!-- verified: installed-contracts -->
```json
["konstapel-kyverno/v1"]
```

## Selection

`Registry.Select` checks one binding's request: one provider, one mode and
the profile's checks. It returns a `Plan` or every reason for rejecting the
selection. A rejected selection has no plan, so nothing is applied in part. A
rejection never affects another binding's selection. The check is pure: no
cluster, registry or file access.

- **Implied provider.** An empty provider means the registry default,
  `konstapel-kyverno/v1`. Every existing bundle names that contract
  explicitly, and both forms resolve identically.
  `TestDefaultSelectionMatchesTheResolver` checks the default selection
  against the targeting resolver over the resolver fixtures and an exhaustive
  mode × scope × parameter matrix.
- **One provider per binding.** Checks whose kinds belong to more than one
  provider, or to a provider other than the selected one, are
  `MixedProviders`. Overlapping bindings over the same namespace stay
  independent selections: a reporting Audit binding never weakens a Kyverno
  Deny binding.

Each reason maps to an existing ComplianceBinding condition reason
(`SelectionReason.BindingReason`). Surfacing selection errors therefore needs
no new API reason:

| Reason | Meaning | Binding reason |
| --- | --- | --- |
| `UnknownProvider` | No installed provider has that name. | `ContentUnavailable` (content `Incompatible`, as today) |
| `IncompatibleVersion` | The provider is installed at another contract version, or cannot read the capture version. | `ContentUnavailable` |
| `UnsupportedCheck` | No installed provider evaluates the check kind. | `UnsupportedScope` (as for an unsupported policy type today) |
| `MixedProviders` | The checks span providers, or belong to another provider. | `InvalidConfiguration` |
| `UnsupportedMode` | The kind does not accept the mode (`Deny` for reporting-only). | `InvalidConfiguration` |
| `InvalidParameters` | The parameters violate the check's contract. | `InvalidConfiguration` |
| `InvalidSelection` | No checks, a repeated check, an invalid mode or a malformed contract. | `InvalidConfiguration` |

Example: a `Deny` selection for `konstapel-kyverno/v1` with two checks. The
first is `disallow-privileged-containers` (a ValidatingPolicy) with the
parameters `{"allowPrivileged":true}`. The second is `image-vulnerabilities`
of kind `scanner.example.io/v1/ImageReport`. The selection is rejected:

<!-- verified: rejected-selection -->
```json
[
  {
    "reason": "InvalidParameters",
    "check": "disallow-privileged-containers",
    "message": "policy \"disallow-privileged-containers\" does not accept parameters"
  },
  {
    "reason": "UnsupportedCheck",
    "check": "image-vulnerabilities",
    "message": "no installed provider evaluates \"scanner.example.io/v1/ImageReport\""
  }
]
```

A selection that names a provider this build does not contain:

<!-- verified: unknown-provider -->
```json
[
  {
    "reason": "UnknownProvider",
    "message": "provider example-scanner/v1 is not installed (installed: konstapel-kyverno/v1)"
  }
]
```

`Registry.CheckCapture(contract, version)` answers whether a retained capture
can be read. It never falls back to another provider or version.

## Conformance

`internal/provider/conformance` is the shared harness. It imports no
Kyverno package. `TestHarnessHasNoKyvernoDependencies` checks this with
`go list -deps`. A case is a directory with two files:

- `case.json`, format `konstapel.provider-conformance/v1`. It holds the
  provider contract, an explicit `evaluationTime` and an opaque
  provider-specific `input`.
- `expected.json`. It holds the golden inventory and observations, plus the
  existing `EvidenceSummary` and `OutcomeCounts`.

The harness rejects unknown case versions and unknown fields. A provider
supplies an `Adapter` (`Inventory`, `Evaluate`, `WithoutEvidence`). Besides
the golden comparison, every case must satisfy these rules:

- The expected inventory comes from the frozen scope alone. It is unchanged
  when all evidence is removed. Without evidence, every observation is
  `Missing`, or `Unresolved` for scope it cannot attribute. Nothing passes.
- Every expected observation is evaluated exactly once. None is dropped,
  invented or duplicated.
- Only `Attributable` evidence has a raw outcome, a normalized outcome
  (`pass`, `fail`, `error`, `skip`, `unknown`) and an evaluation time no
  later than the evaluation time. `Missing`, `Rejected` and `Unresolved`
  carry no outcome.
- A raw outcome always normalizes the same way. Raw values without a summary
  field, such as a warning, count once as `unknown`, and the raw value is
  kept. `NotApplicable` is never a pass.
- Evaluation is deterministic for the same input and time.

`TestHarnessCatchesSemanticRegressions` mutates a working adapter in
specific ways. Each mutation must fail the harness: missing evidence that
passes, an inventory derived from evidence, a warning counted as a pass, an
outcome on rejected evidence, a report update time used as freshness,
duplicate credit, inconsistent normalization, nondeterminism, and others.

Cases live under `testdata/providers/conformance/v1/<provider>/`:

- `konstapel-kyverno/background-1.19.2`: the saved live Kyverno 1.19.2
  background evidence, evaluated unchanged by `collector.CaptureV2.Evaluate`.
  The result is 30 expected, 28 attributable, 2 missing, 24 pass and 4 fail.
- `konstapel-kyverno/synthetic-unknowns`: synthetic reports over that frozen
  scope, with a warn, conflicting results, untimed and future results, and a
  skip.
- `konstapel-reporttest/*`: the synthetic reporting shape described below.

`TestKyvernoHarnessSummaryMatchesCollector` checks that the harness summary
equals the controller's `collector.Tally` result for the Kyverno cases. The
current Kyverno evaluator closes at the capture window. Its adapter refuses
any other evaluation time rather than substituting the closure; explicit
time inputs are task 4.1.

The cases run in the normal test entry points (`task test`, `task check`).
After an intended semantic change, rewrite the golden results and review the
diff:

```sh
go test ./internal/provider/kyverno ./internal/provider/reporttest -run Conformance -update
```

## Test-only boundary

`internal/provider/reporttest` (`konstapel-reporttest/v1`) is a synthetic
reporting-only provider. It checks that the shared contract does not depend
on Kyverno:

- Its subjects are workload containers and the images they run.
- One posture report per image digest is shared evidence for every
  workload that runs that image.
- Its checks are named verdicts.
- Freshness comes from the report's evaluation time, never from its update
  time.
- Tag-only images are `Unresolved`.

It has no engine policy, validation index or PolicyReport. The following
guards keep it out of production builds:

- The production registry is a closed list and never contains a `testOnly`
  descriptor. A test-only descriptor cannot be a registry default.
- `TestTestOnlyProvidersAreNotLinkedIntoShippedBinaries` runs `go list -deps`
  over every main package under `cmd/` and over the registry packages. It
  fails if any of them links `reporttest` or the conformance harness.
- Linking `reporttest` into a non-test binary panics at startup
  (`testing.Testing()`). `TestLinkingIntoABinaryPanics` builds such a binary
  and checks the panic.

Build tags were not used: the cases must run in the plain `go test ./...`
behind `task check`.

The reporting provider and its fixtures prove plumbing only. They are not a
model of Trivy or of any real producer, and they are not producer
compatibility evidence.

## Internal interfaces and versioned contracts

These are versioned contracts:

- the bundle descriptor's `compatibility.provider` value
- the capture versions recorded in packages
- the conformance case format `konstapel.provider-conformance/v1`

The Go types (`provider.Descriptor`, `Registry`, `Selection`,
`conformance.Adapter`) are internal to this repository. They are not a stable
third-party SDK and may change with the remaining groups of the change.

## What this contract does not establish

- No new production provider. A provider is supported only after it passes
  shared conformance and its own live compatibility tests against the real
  producer, through its own change. Trivy integration is deferred by the
  owner and must prove digest/owner correlation, evaluation time, filtering
  and missing evidence against real reports.
- No runtime plugin loading, provider CRD, marketplace, scanner
  orchestration, mixed-provider binding, or new outcome or exception API.
