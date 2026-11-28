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

**Package replay versus semantic re-evaluation (owner decision 2026-11-27).**
Retrieving and validating the evaluation stored at closure is distinct from
re-evaluating frozen inputs to reproduce equivalent semantic results, and the
first is not proof of the second. Continuous packages today support only the
first: replay (`collector.ReadSnapshot`, `Snapshot.Validate`,
`SnapshotProvider`) converts `evaluation.json` after checking it is an
evaluation of `capture.json`. The deterministic-evaluation requirement stays as
specified and is not yet met for packages (task 4.5). No package format is
added merely to regenerate identical serialized output.

*Proposal: package inputs for semantic re-evaluation (not implemented).* A
package lacks these inputs of `kyverno.Evaluate(EvaluationInput{Capture,
Boundaries, MaxEvidenceAge}, at)`:

- `Boundaries`: per frozen workload, the host continuity boundary used at
  closure (`collector.Boundary`: `workloadUID`, `stateSha256`, `since`). The
  controller reads them from its in-memory tracker; without them a result
  evaluated before the window start but after continuous observation began is
  attributable at closure and rejected on re-evaluation.
- `MaxEvidenceAge`: the binding's effective evidence-age limit at closure. The
  descriptor records only an opaque `bindingConfiguration` revision, and
  `nextExpiry` is a derived output that is absent when nothing is attributable.

Already present and not part of the proposal: the evaluation time
(`window.closed`), the capture and its scope changes and discontinuities, the
engine policies applicability reads, the content record, and the evaluator
version (implied for legacy version 2, recorded by the version 3 envelope).
These inputs change semantics that legacy readers would ignore, so they need
an explicit version boundary rather than optional JSON fields, and readers
ship before writers: a release that reads and re-evaluates the new form, while
still converting the stored evaluation of every retained form, must be
released before any controller writes it. Packages written earlier are never
rewritten and remain retrieve-and-validate only.

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

Owner decisions of 2026-11-27 settle three questions left open by the first
projection check:

- A namespace Diagnostic records a stable reason code and its fixed text. A
  content failure's own message stays on the platform-scoped run and binding
  package, and storage refuses a namespace diagnostic with any other text.
- A projection counts only its own extracts. It records no source-report
  count and no withheld results, which named sibling reports.
- Source results are attributed one by one against the frozen authorized
  namespace and the workloads frozen in it, never live lookups or the
  report's namespace. A result with a reference that cannot be resolved that
  way stays unresolved in every namespace view. Provenance names a source
  report only when the namespace may see it (a report in that namespace).
  Any other source is named by a sealed reference, a digest of the report UID
  and namespace UID that the platform can recompute. No extract copies its
  report.

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

**One content format (6.1, reconciled 2026-11-28).** The payload stays
`konstapel.policy.bundle/v1`, and its descriptor keeps its shape. Every
`policies` entry names one declarative document (role `policy`) with its
logical name, its C2P `checks` and its OSCAL mappings, exactly as today. The
document's `apiVersion` and `kind` are its check kind
(`<group>/<version>/<Kind>`), and `compatibility.provider` names the one
provider contract of the bundle. What the document must be follows from that
contract:

- `konstapel-kyverno/v1`: a `policies.kyverno.io/v1` ValidatingPolicy, the
  existing rule, byte for byte. Existing bundles are unchanged, so their
  digests, receipts, rendered policies, logical identities and policy
  revisions are too.
- Any other contract: a reporting-only check definition. Its only members are
  `apiVersion` (with a group other than `policies.kyverno.io`), `kind`,
  `metadata.name` (the logical name) and `spec.resources`. Any other member,
  at any level, is rejected, so a definition cannot carry an image, command,
  endpoint, service account, permission, engine rule or other executable
  configuration. Its `policies` entry declares no `parameterSchema`: a
  reporting-only kind's parameter contract is its descriptor's schema
  (`ParametersFromDescriptor`), and profile parameters are validated against
  that schema during selection. A definition fixes no parameter values.
- `spec.resources` lists the resources the check expects evidence for, as
  `{group, version, resource}` (empty group for core), at least one and each
  once. The host derives a run's frozen inventory from them (external
  Decision 9): which workloads a check expects comes from verified content,
  never from a provider report. Targeting reports a definition's scope from
  them with the same scope function as a policy's match rules: Namespaced
  only when every resource is a supported namespaced workload resource.
- The component definition's `validation` component is titled with the
  contract's provider name, as `konstapel-kyverno` is today, so the OSCAL
  closure, rule and check mapping rules apply unchanged.

An older controller refuses such a bundle: it accepts only the Kyverno
contract (`validateContent` and its compatibility check), so the extension
fails closed without a new format version.

Seam owners for each generalization:

| Generalization | Owner and code |
| --- | --- |
| Payload rules: document kinds per contract, the definition shape, `spec.resources`, no content parameter schema for definitions, provider-titled validation component, closure, inventory, checksums, signature and provenance | Bundle (`add-policy-bundle-distribution`): `internal/bundle` (`validateContent`), `internal/assessment` (mapping closure) |
| Reading a document's check kind and scope, giving it to the resolver, never rendering a non-delivery selection | Targeting: `internal/targeting`, its loader `internal/bundle/content.OCIContent` |
| Whether a kind is declared, its modes and parameters, one provider per binding, the reasons each maps to | Registry: `provider.Registry.Select` |
| Which contracts are selectable, and registration availability | Registry: `installed.Registry()`, `external.Catalog` |
| Which bundles may be adopted at all (acceptance key) | Resolver: `content.Compatibility` and `resolve.Key.Compat` |

Binding resolution consults `Registry.Select`, which the contract left
unconnected to the targeting resolver. Wiring it in must keep
`TestDefaultSelectionMatchesTheResolver` and every Kyverno resolver result
unchanged and map `UnsupportedMode`, `MixedProviders` and unknown contracts to
existing binding reasons. Bundle compatibility (`content.Compatibility.Providers`)
is fed from the selectable built-in contracts, `installed.Registry().Contracts()`,
instead of a separate allowlist. Registered contracts are selectable through
`external.Catalog` when the external extension is enabled, but they are judged
during selection, not in the acceptance key (below).

**Owner decision 2026-11-28: compatibility revision churn, option (a).**
Immutable bundle verification is separate from installed-provider
availability. `content.Compatibility.Revision()`, the `Compat` component of
every acceptance key (`resolve.Key`), covers only what is static for a
controller process: the rules version, the controller version, the sorted
built-in contracts, the supported OSCAL versions and OS, and whether
registered providers are enabled. Registration create, delete, enable,
disable and readiness changes never change it, so they never make an
acceptance unreachable and never reverify any bundle.

- With registered providers disabled, `Check` is unchanged and the revision
  is byte for byte today's value.
- With them enabled, `Check` accepts, at the bundle level, a contract that is
  not a built-in provider's name; it still rejects another version of a
  built-in provider. The contract is then validated during selection, before
  any execution: every binding resolution builds its catalog from the current
  registrations and calls `Catalog.Resolve`, so an unknown, disabled,
  ambiguous, unready or stale registration is a binding error
  (`ContentUnavailable`) and nothing selected earlier is reused.
- A registration change requeues the bindings whose content names that
  provider: the binding controller watches `AssessmentProvider` and maps a
  change to those bindings. A binding selected through a registration is also
  requeued within the catalog's maximum status age, so a status nobody
  refreshes cannot leave it reported as resolvable.
- Removing or disabling a registration therefore stops new selections at the
  next resolution. Work already frozen to a registration keeps its frozen
  identity and the existing drain and recovery rules (`Frozen.Check`,
  Decision 6 of the external change); nothing here changes them.
- Validation results that depend on a provider-supplied schema are never
  cached across schema revisions. Built-in kinds and schemas are compiled in,
  so the controller version in the revision covers them, and `Select` is a
  pure function evaluated on every resolution. A registered provider's kinds
  and schemas come from its endpoint's description, which is bound to the
  frozen release digest; they are checked against the run's definitions when
  work is dispatched to that frozen identity (external task 3.1), never
  reused for another release, and not recorded in the acceptance key.
- Content validation and cryptographic trust are unchanged. The rule and
  trust components of the key still change with the source rule and trust
  material, and `InvalidateSource` and `InvalidateDigest` keep their callers.

What the provider allowlist in the revision protects against today, and what
covers each after the decision:

| Protection today | After the decision |
| --- | --- |
| Content naming an uninstalled contract is never adopted | Built-in: unchanged (contracts in `Check` and the revision). Registered disabled: unchanged. Registered enabled: `Catalog.Resolve` during every selection; the content verifies but no binding resolves until the contract is selectable. |
| A controller upgrade or downgrade that changes the built-in contracts never reuses an acceptance | Unchanged: built-in contracts and the controller version stay in the revision, and acceptances are in memory only. |
| Toggling registered providers re-judges every bundle | The enabled flag is in the revision; changing it is a restart. |
| A verification in flight while the provider set changes ends stale | Built-in sets change only with a restart. Registrations no longer affect acceptances; selection runs after resolution on every reconcile and the watch requeues it. |
| A cached verdict never outlives the kinds and schemas it judged | Built-in: the controller version. Registered: checked against the frozen release's description at dispatch, never cached across releases. |
| Trust and rule changes revoke acceptances | Unchanged: separate key components and invalidation calls. |

Task 6.3 proves this with counts: a registration change does not reverify
or re-accept an unrelated Kyverno bundle (no new resolution attempt, the
acceptance store unchanged), while a binding on a registered contract becomes
unavailable when its registration is disabled or removed and recovers when it
returns.

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
- [A registry-fed allowlist forces re-acceptance] → Owner decision 2026-11-28
  (Decision 8): registered contracts are judged during selection and kept out
  of the acceptance key; registration changes requeue affected bindings only.

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
