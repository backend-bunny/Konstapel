# Spec Delta

## Purpose

Let Konstapel add assessment evidence sources through a bounded, versioned
provider contract while preserving trustworthy scope, outcomes, and offline replay.

## ADDED Requirements

### Requirement: Only installed compatible providers can be selected

Konstapel SHALL resolve checks against an explicit installed-provider catalog
identifying provider and evaluation-contract versions, supported checks, modes,
parameters, and capture versions. Unknown or incompatible selections SHALL fail
explicitly before collection or delivery. Bundle content SHALL NOT install or
select arbitrary executable code.

#### Scenario: An uninstalled provider is requested

- **WHEN** verified content names a provider or contract version not installed
- **THEN** its binding has an explicit resolution error
- **AND** no executable is downloaded or selected from bundle-controlled paths

#### Scenario: Unsupported parameters or mixed providers

- **WHEN** a binding selects invalid parameters or checks from multiple providers
- **THEN** resolution rejects that selection without partially applying it
- **AND** independently valid bindings continue normally

### Requirement: Reporting-only assessment has no enforcement side effects

Providers SHALL declare whether their checks support enforcement or only Audit
assessment. Reporting-only checks SHALL NOT generate engine policy resources,
scanner jobs, or workload mutations. Unsupported Deny requests SHALL be rejected.
A reporting-only binding SHALL NOT weaken overlapping enforcing contributions.

#### Scenario: Read-only assessment overlaps Kyverno Deny

- **WHEN** an Audit reporting binding and a Kyverno Deny binding select the same namespace
- **THEN** assessment reads evidence independently while Kyverno continues enforcing
- **AND** reporting-only readiness does not claim ready enforcement

### Requirement: Provider prerequisites are independently observable

Provider availability SHALL distinguish missing or unsupported APIs, denied
access, and unavailable dependencies from check outcomes and evidence
completeness. Unavailable optional providers SHALL NOT prevent healthy providers
from operating. Recovery SHALL occur without requiring a controller restart.

#### Scenario: An optional evidence source disappears and returns

- **WHEN** its API or required read permission is removed and later restored
- **THEN** affected bindings expose bounded, attributable availability diagnostics and recover
- **AND** other providers keep operating without their applied policies being deleted

### Requirement: Collection is scoped and bounded

Evidence collection SHALL use centrally resolved scope and independently derived
expected subjects/checks. It SHALL obey the existing collection deadline and
cancellation, with explicit resource limits. A reporting adapter SHALL use only
its documented read operations. Missing evidence SHALL NOT remove expected
subjects or establish a pass, including when there are no selected subjects.

#### Scenario: No reports arrive before the deadline

- **WHEN** expected subjects exist but the producer emits no usable evidence
- **THEN** the run closes with missing observations and explicit incompleteness
- **AND** collection does not trigger a scan, extend the deadline indefinitely, or fabricate success

#### Scenario: Collection is interrupted or exceeds a bound

- **WHEN** leadership cancellation, oversized inputs, or configured collection limits prevent completion
- **THEN** work stops within the existing lifecycle budget and the limitation is recorded
- **AND** truncated input is never presented as complete evidence

### Requirement: Evidence retains source attribution and provenance

Provider evidence SHALL retain cluster, namespace and subject identities, check
and contribution revisions, source identity, actual evaluation time, collection
time, and provenance limitations. Shared evidence SHALL preserve its distinct
subject associations without inflating independent evaluations. Unresolved
identity or freshness SHALL NOT establish a current pass.

#### Scenario: A fresh report object contains an old evaluation

- **WHEN** a producer copies evidence or refreshes report metadata without a new evaluation
- **THEN** the adapter retains the original evaluation time or an explicit unknown
- **AND** report creation/update time does not renew freshness

#### Scenario: Shared evidence has an ambiguous workload association

- **WHEN** one source record could refer to replaced or differently scoped subjects
- **THEN** unresolved associations remain explicit and cannot establish their outcomes
- **AND** valid associations keep their own identities without duplicate control credit

### Requirement: Provider captures preserve scope and content identity

Frozen captures SHALL identify the provider, evaluator contract, capture version,
parameters, expected inventory, evidence and attribution, evaluation boundary,
and exact verified content used. Enforcing contributions SHALL preserve applied
content separately from desired content. Unsupported or unavailable content
SHALL NOT be replaced with desired, vendored, or another provider's content.

#### Scenario: Desired content changes while older content is applied

- **WHEN** an enforcing contribution still uses bundle A while desired content is B
- **THEN** its captured results and export use A and retain B as distinct desired intent
- **AND** overlapping applied revisions retain separate content associations

#### Scenario: A reporting-only run's selected content changes

- **WHEN** the binding changes after the run freezes its resolved check configuration
- **THEN** the run uses its frozen content and revision, recording the change
- **AND** it does not fabricate an engine policy or an applied-policy identity

### Requirement: Evaluation is deterministic and shared with offline replay

Current assessment and offline C2P conversion SHALL use the same provider
evaluation semantics. Evaluation SHALL depend only on immutable inputs and an
explicit evaluation boundary, without live cluster, registry, scanner, or clock
access. Replay SHALL use the recorded compatible contract and frozen content;
unsupported compatibility SHALL fail explicitly rather than select new semantics.

#### Scenario: Replay after cache eviction and source removal

- **WHEN** retained evidence is replayed with its supported evaluator after the live source and content cache disappear
- **THEN** normalized check outcomes, attribution, and completeness match evaluation at the recorded closure boundary
- **AND** replay performs no external evidence retrieval

#### Scenario: Time advances between current state and replay

- **WHEN** current assessment evaluates evidence at a later time than a retained run's closure
- **THEN** current freshness can change while replay preserves the retained interpretation
- **AND** the replay process's current wall clock does not rewrite history

### Requirement: Provider results preserve independent assessment dimensions

Evaluation SHALL preserve raw source outcomes, normalized check outcomes,
completeness, applicability, and any authorized accepted-risk context separately.
Unknown outcomes SHALL NOT become passes. Projection into existing summaries
SHALL use documented mappings and preserve richer evidence; adding a provider
SHALL NOT silently add new summary states or invent risk acceptance.

#### Scenario: A provider produces a warning unsupported by summary counts

- **WHEN** the existing summary contract has no distinct warning field
- **THEN** its documented unknown mapping counts the warning once
- **AND** retained evidence and OSCAL preserve the warning without treating it as pass, fail, or accepted risk

#### Scenario: Complete evidence contains violations

- **WHEN** every expected observation is attributable but some checks fail
- **THEN** completeness and failure remain distinct
- **AND** no whole-control satisfaction is inferred from completeness or accepted-risk context

### Requirement: Provider evidence cannot bypass namespace confidentiality

Namespace-scoped packages SHALL project inventory, source extracts, diagnostics,
results, and references before export. Provider payloads with unresolvable scope
SHALL NOT be disclosed. Shared source objects SHALL NOT expose other namespaces'
subjects, findings, private supporting evidence, or credentials through any output.

#### Scenario: A source record spans two namespaces

- **WHEN** a team requests an assessment for only one namespace
- **THEN** all exported provider data contains only safely attributable authorized extracts
- **AND** extraction provenance remains traceable without copying the sibling's data

### Requirement: Existing lifecycle and capture compatibility remain intact

Providers SHALL reuse Konstapel's durable scheduling, namespace authorization,
publication, signing, retention, recovery, and download guarantees. Supported
legacy Kyverno captures SHALL remain readable without rewriting their bytes or
identities. Unknown provider payload versions SHALL fail explicitly rather than
appear as empty successful assessments.

#### Scenario: An older or incompatible reader encounters new evidence

- **WHEN** a package requires a provider or capture contract the reader does not support
- **THEN** the compatibility boundary rejects its interpretation explicitly
- **AND** the reader does not fall back to Kyverno or an empty result set

#### Scenario: A provider integration is interrupted during publication

- **WHEN** leadership changes after a provider's capture is frozen
- **THEN** existing recovery resumes that same capture or explicitly reports its loss
- **AND** it does not recollect evidence under the old run identity

### Requirement: Provider support is backed by conformance evidence

Each supported provider SHALL document its capabilities, source semantics,
permissions, limits, compatibility, and an authoring/integration recipe. It SHALL
pass shared conformance checks and producer-specific live compatibility tests.
Synthetic adapters SHALL NOT establish support for an external producer or count
as production-ready installed providers.

#### Scenario: A reporting adapter passes synthetic conformance

- **WHEN** a test-only reporting adapter demonstrates the shared contract
- **THEN** it remains excluded from production provider registration and shipped bundles
- **AND** Trivy or another real producer still requires its own live attribution and freshness evidence

#### Scenario: An existing provider migrates to the shared contract

- **WHEN** Kyverno is routed through the shared interfaces
- **THEN** its existing CLI, live controller, package, and replay checks remain green
- **AND** no new provider is advertised merely because generic plumbing exists

### Requirement: Bundles define reporting-only checks in the shared content format

Signed bundles SHALL be able to define declarative checks for a reporting-only
provider contract in the same versioned payload and under the same verification
as engine policy content. A check definition SHALL name a check kind and
parameters its provider's descriptor declares and SHALL NOT carry an executable,
engine resource, endpoint, or permission. One content format SHALL serve every
provider; engine policy content SHALL keep its format, identities and revisions.

#### Scenario: A verified bundle defines reporting-only checks

- **WHEN** a trusted bundle names a selectable reporting-only contract and defines checks of a kind its descriptor declares
- **THEN** resolution adopts the content and binding resolution selects that provider in Audit mode
- **AND** no engine resource is rendered and no executable is downloaded or selected from the bundle

#### Scenario: A check definition does not match the provider

- **WHEN** a reporting-only check names an undeclared check kind or parameters outside its descriptor schema
- **THEN** the bundle or affected binding reports invalid content without partially adopting it

### Requirement: Bundle compatibility follows provider selection

Bundle compatibility SHALL be judged against the provider contracts the host can
select, through the same provider selection that binding resolution uses,
whether the provider is built in or administrator-registered. No separate
provider allowlist SHALL decide content compatibility.

#### Scenario: The contract cannot be selected

- **WHEN** verified content names a reporting-only contract that is neither built in nor registered and selectable
- **THEN** resolution reports the incompatibility despite a valid signature
- **AND** independently compatible bundles and bindings continue normally

#### Scenario: Existing engine content is unaffected

- **WHEN** an existing Kyverno policy bundle is resolved after the extension
- **THEN** its verification result, rendered policies, logical identities and policy revisions are unchanged
