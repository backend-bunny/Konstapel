# Design

## External-provider follow-up

The approved `add-external-assessment-providers` change consumes these shared
interfaces and adds separately Helm-installed provider services, OCI distribution,
a versioned remote protocol and an optional explicit scan-request capability.
This foundation remains in-tree and read-only: its collection, Generate and
GetResults paths never initiate scans. Completed work and current Kyverno behavior
remain unchanged. External registration and scan execution are follow-up scope,
not requirements to finish or archive this foundation. Coordinate capture and
evaluation compatibility at handoff; production Prowler/AWS scope remains separate.

## Context

See proposal.md for motivation and scope. The existing seams are concrete:

- `internal/assessment/provider.go` implements the pinned C2P-Go v2
  `policy.Provider` interface (Configure/Generate/GetResults); the executable in
  `cmd/konstapel-provider` registers it through the existing gRPC plugin library.
- `internal/assessment/export.go` checks the existing provider ID. Meanwhile,
  `internal/collector/export.go` converts continuous captures through C2P without
  requiring that executable path. A new plugin binary alone reaches neither
  controller collection nor generic continuous export.
- `CaptureV2`, expected observations, and targeting content currently carry
  Kyverno policy identities, CEL validation indexes, and rendered-policy hashes.
- `collector.ExportRequest.Content` already supports frozen per-applied-bundle
  content. Reuse that ownership and its failure behavior; do not reintroduce a
  vendored catalog fallback or a digest-only identity for resolved content.
- Existing assessment, evidence, coverage, signing, attachments, and observability
  owners define the lifecycle and summary contracts. The approved warning-to-
  unknown summary mapping must retain warnings in raw evidence and OSCAL.
- Trivy's active design documents additional reporting-only identities and source
  semantics. Its real compatibility investigation is still required. This change
  establishes reusable interfaces, not proof that Trivy's reports are usable.

## Goals / Non-Goals

**Goals:** Make provider-specific collection and evaluation explicit; preserve
existing Kyverno behavior; let a second, read-only shape exercise those boundaries;
provide a practical authoring and conformance recipe before real Trivy integration.

**Non-Goals:** A stable third-party Go SDK, dynamic collector loading, arbitrary
external executables, a marketplace, a new provider CRD, mixed-provider bindings,
new scanners or runtime controls, provider-owned schedulers/storage, vulnerability
triage or exception APIs, or rewrites of existing outcome/status contracts.
The contract is not an additional release gate for the existing 0.3.0 scope.

## Decisions

### 1. Code-owned registration with explicit capabilities

Use a small installed registry, initially Kyverno only in production. Each entry
owns its provider/evaluation version, supported check identities and parameter
schemas, enforcement versus reporting modes, payload compatibility, prerequisites,
read operations, and implementation bindings. The bundle resolver validates the
verified descriptor against this catalog before starting work. No bundle can name
a Go module, command path, or arbitrary plugin manifest to execute.

Keep one provider per binding. Reuse existing selectors and independent overlapping
bindings. Reporting-only entries accept Audit; no engine-ready claim, synthetic
policy object, or exception grant is fabricated to fit the Kyverno path. Keep
engine delivery with its existing owner, outside evidence collection/evaluation.

Alternative: infer capabilities from policy YAML or let bundles install plugins.
That hides unsupported modes and expands the executable trust boundary. A provider
CRD adds configuration and lifecycle complexity without a need in the first version.

### 2. Narrow in-tree adapters, with host-owned scope and lifecycle

Introduce a focused provider package only where existing types do not provide the
seam. Prefer small Go interfaces over a broad base class. The proposed boundaries:

| Boundary | Inputs | Outputs / responsibilities |
| --- | --- | --- |
| Descriptor/validation | verified content, checks, parameters, requested mode | supported selection or explicit resolution error |
| Capability observation | bounded discovery/read-access probes | availability reason and supported source semantics |
| Expected inventory | host-frozen namespace/cluster scope, workload state, checks | independently derived expected subjects and associations |
| Collection | expected inventory, scoped readers, deadline/cancellation and limits | immutable source evidence, attribution, limitations, and source times |
| Evaluation | validated frozen payload, configuration, explicit evaluation time | deterministic outcomes, completeness, applicability, and disposition references |
| C2P conversion | those evaluated results and exact frozen mappings/content | provider results for the existing schema-validated OSCAL export |

Provider-specific subject types remain discriminated payloads; do not force image
findings into Kyverno policy-report fields. Keep shared identities, bounds, and
scope validation in host code. Both shared validation and the provider validate
payloads; unknown payloads are never accepted as empty evidence.

Adapters are trusted in-tree code, not a sandbox. Narrow reader interfaces and
permission tests reduce accidental authority, but effective RBAC belongs to the
controller service account. Do not claim per-provider security isolation from
Go interfaces when other features require broader permissions.

The host retains cache/watch setup, late API discovery, deadline enforcement,
leadership cancellation, scope changes, concurrency and scheduling. Use bounded
existing retry/capability mechanisms. Declared limits must cover objects, bytes,
and collection work; consume current host defaults rather than inventing a second
configuration API. One unavailable provider cannot block other bindings.

Owner decision (2026-11-24): the host's page size and request, object and byte
limits are configurable before 2.3 merges, as controller flags
(`--collection-page-size`, `--collection-max-requests`, `--collection-max-objects`,
`--collection-max-bytes`) exposed through the runtime chart's
`controller.collection` values. This is host configuration of the existing
controller, not a second configuration API: no bundle, profile, binding or
provider field sets a limit, and an adapter cannot widen one. Unset flags keep
the defaults. Startup validation refuses, never clamps, values out of range or
combinations that could not complete (a page above the object limit, fewer
requests than the object limit's pages, a byte budget below one maximal object or
one page); the chart schema and render apply the same rules. The deadline stays
each binding's `collectionTimeout`; there is no global deadline flag. The byte
budget must be sized with the controller memory limit (decoded objects take about
2.4 times their JSON size).

### 3. Shared immutable evaluation, without external plugin collection

Retain the C2P Configure/Generate/GetResults contract and pinned plugin packaging.
The in-tree evaluator is called by current controller assessment and by offline
C2P conversion. Configure validates local frozen inputs and version compatibility;
Generate produces local policy artifacts or a reporting evaluation plan;
GetResults converts the same evaluated snapshot. Kubernetes collection does not
move into an external plugin. Provider source reads cannot trigger scans or repair
upstream evidence.

Pass evaluation time explicitly. Current projections use the current assessment
boundary; closed runs and replay use their frozen closure boundary. Require equal
normalized semantic results for equal inputs. This does not require byte-identical
newly rendered OSCAL documents where permitted generated identifiers differ, and
never rewrites an already published package to replay it.

Alternative: let a C2P plugin fetch live evidence or implement its own evaluator.
That makes offline replay depend on external state and risks divergent controller
and exported results. Runtime sandboxing of arbitrary collectors is out of scope.

### 4. Versioned captures and exact content closure

Define the smallest versioned envelope needed for provider-discriminated subjects
and payloads, coordinating with the collector owner. Record provider and evaluator
contracts, check/configuration revisions, independent inventory, cluster and
namespace UIDs, source evidence/attribution, evaluation boundary, parameters,
and frozen content references. Treat provider contract version, payload version,
and the C2P protocol version as separate compatibility dimensions.

Retain supported CaptureV2 readers and frozen fixtures. New semantics that legacy
readers would silently ignore need an incompatible envelope/version boundary and
an explicit reader-before-writer rollout; do not append optional JSON fields and
assume older readers reject them. Select only installed compatible evaluators;
never fetch an old executable from a retained package. Unsupported replay is a
clear compatibility failure. Legacy packages keep their bytes and interpretation.

For enforcement, use `RunContent`'s applied contributions, preserving distinct
bundle name/digest, source/trust context, namespace, and revision associations.
Desired content remains separate. For reporting-only contributions, freeze the
resolved evaluation content without inventing an engine-applied state. Reuse
existing verified-content handles, leases, and per-member export. Retain material
needed for replay before cache eviction; absent content follows existing diagnostic
export behavior rather than substituting another catalog.

Do not change existing Kyverno enforcement epochs merely because plumbing moves.
Any new reporting-only check revision must include its semantics and compatible
provider version, with scope/timing changes handled under the assessment owner's
existing rules. The Trivy change owns enabling those identities for real Trivy.

### 5. Preserve results and enforce projection before export

Use existing outcome and completeness types where sufficient. Retain raw producer
states alongside normalization, and distinguish applicability, evidence quality,
and authorized disposition from pass/fail. No new outcome API field, automatic
risk acceptance, or whole-control verdict is introduced here. Warnings use the
approved summary `unknown` mapping once and remain warnings in raw/OSCAL output.

Namespace projection covers provider payloads, diagnostics and references, not
just top-level counts. The host checks returned scope; provider-specific extracts
must validate it before any export or summary exposure. Keep protected attachment
roles and access checks unchanged. Unknown scope fails closed for disclosure.
The external plugin receives already projected local inputs and no credentials.

### 6. Prove a reusable contract without shipping a second integration

Port the existing Kyverno path incrementally. Add a test-only reporting adapter
with a different subject/evidence shape to catch accidental policy-name/CEL-index
requirements. It must not be in production registration, image plugin manifests,
or distributable bundles. Its fixtures prove plumbing, not Trivy semantics.

The shared conformance harness covers validation, unavailable dependencies,
independent inventory, source times, duplicated/ambiguous associations, bounds,
cancellation, namespace leakage, deterministic evaluation, result normalization,
capture compatibility, and replay without network access. Fault fixtures should
make meaningful semantic regressions fail, not merely assert interface names.

Run the existing applicable Kyverno live acceptance against the Helm-installed
image after production migration, including collection/export/download and restart
coverage. Keep source-specific compatibility tests separate: a real Trivy adapter
must later prove digest/owner correlation, actual evaluation time, filtering and
missing evidence using real operator reports. Add those tests through its owner,
not by advertising the synthetic reporting adapter as support.

Alternative: define a large generic framework before using it. A Kyverno migration
and a deliberately different test-only shape provide a bounded design check while
avoiding a new production integration or generalized vulnerability data model.

### 7. Authoring guide and ownership

Add `docs/assessment-providers.md` with the interfaces, registration and packaging
recipe, capabilities/permission table, normalized versus raw outcomes, capture
versioning, conformance invocation and a worked test-only example. Link it from
architecture/development guides when the implementation exists. State clearly
which interfaces are internal and which package formats are versioned contracts.

The Trivy plan consumes these seams instead of creating parallel registries,
collectors, schedulers or exporters. Its source compatibility research can run
now; shared runtime integration waits for this contract. The first useful Trivy
slice is read-only collection/evaluation/export. Its broader vulnerability-risk
API backlog is not required by this contract and is not authorized by implementing
it. That governance work is now the separate
[add-vulnerability-risk-governance](../add-vulnerability-risk-governance/proposal.md)
change (owner decision 2026-11-27).

### 8. Shared reporting-only check content (group 6)

Owner decision 2026-11-27: the content extension that lets bundles define
checks for reporting-only providers belongs to these shared provider and bundle
seams, not to a producer change. Trivy (`add-trivy-vulnerability-assessment`)
and registered external providers (`add-external-assessment-providers` group 3)
both consume it; neither defines its own content format, and the extension does
not depend on either runtime. It is proven with the test-only reporting provider
in a test registry, which stays unselectable in production builds, so production
behavior is unchanged until a real reporting-only provider becomes selectable.

Today the content contract is Kyverno-only in three places: the bundle
specification's initial runtime policies are modern Kyverno policies,
`bundle.validateContent` accepts only the Kyverno provider contract, and the
targeting content loader accepts only `policies.kyverno.io/v1`
ValidatingPolicy documents. The extension reconciles those with the bundle
owner (`add-policy-bundle-distribution` while active, a durable delta if
archived) and adds declarative reporting-only check definitions to the same
versioned payload: a logical check identity, the descriptor's check kind,
parameters validated against that kind's descriptor schema, and OSCAL mappings
under the existing closure, inventory, checksum, signature and provenance
rules. A definition never carries an executable, engine resource, endpoint or
permission. Existing Kyverno bundles keep their format, logical identities and
policy revisions.

Binding resolution consults `Registry.Select`, which the contract left
unconnected to the targeting resolver. Wiring it in must keep
`TestDefaultSelectionMatchesTheResolver` and every Kyverno resolver result
unchanged and map `UnsupportedMode`, `MixedProviders` and unknown contracts to
existing binding reasons. Bundle compatibility (`content.Compatibility.Providers`)
is fed from the selectable contracts, `installed.Registry().Contracts()` and,
when the external extension is enabled, registered contracts through
`external.Catalog`, instead of a separate allowlist.

**Design consideration (undecided): compatibility revision churn.**
`content.Compatibility.Revision()` hashes the sorted provider allowlist, and
that revision is the `Compat` component of every bundle acceptance key
(`resolve.Key`). Any change in the allowlist therefore makes every bundle's
acceptance unreachable, so every bundle, including unrelated Kyverno bundles,
re-verifies and in-flight verifications end as stale. For the built-in registry
this happens only with a controller release, which already changes the
revision. A registry-fed allowlist that includes administrator registrations
would also churn on every registration create, delete, enable or readiness
change. Mitigation question for the owner: should the acceptance key carry only
the built-in contracts, with registered contracts checked at selection time and
kept out of the key; should the compatibility revision be scoped per bundle to
the contract it names; or should registration churn forcing re-acceptance be
accepted as intended? Task 6.3 does not start until this is answered.

## Risks / Trade-offs

- [Premature abstraction] → Require real Kyverno migration and a distinct test-only
  reporting shape; do not build general dynamic-loading or scanner lifecycle APIs.
- [Schema expansion breaks retained evidence] → Retain legacy fixtures, explicit
  version rejection, and reader-before-writer deployment checks.
- [Two evaluation paths diverge] → Compare controller and C2P normalized results
  from the same frozen inputs, including freshness and unknown outcomes.
- [A provider leaks mixed-scope raw data] → Project before export and verify payloads,
  diagnostics, references, and supporting-evidence boundaries in conformance tests.
- [Concurrent owners change content/status contracts] → Rebase each integration
  step and consume owner interfaces; preserve content leases and package roles.
- [A synthetic provider masks upstream limitations] → Keep it test-only and retain
  real producer compatibility as an independent acceptance gate.
- [Reporting-only content becomes a second format] → One versioned payload for
  every provider, extended with the bundle owner; Kyverno bundles unchanged.
- [A registry-fed allowlist forces re-acceptance] → Undecided; see Decision 8's
  compatibility revision consideration before wiring registrations into it.

## Migration Plan

1. Establish descriptors, version boundaries and conformance fixtures without
   enabling any new production provider or changing existing output.
2. Wrap existing Kyverno inventory/collection/evaluation and C2P conversion with
   the narrow interfaces; preserve scope, revisions, normalized outcomes and RBAC.
3. Add provider-aware readers before enabling any new capture writer. Validate
   historical packages and document which retained formats a rollback must read.
4. Exercise the test-only reporting adapter and offline replay; run applicable
   installed-image Kyverno acceptance before merging the production switch.
5. Publish the authoring guide and hand the implemented contract to the Trivy
   owner. Do not claim a supported Trivy provider until its separate change proves it.

Rollback can disable new provider selection but must not remove readers needed
by retained packages or reset their lifecycle. If compatible readers cannot be
retained in an older controller, refuse/document that rollback rather than
silently dropping evidence.
