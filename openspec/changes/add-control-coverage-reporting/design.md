# Design

## Context

See [proposal.md](proposal.md) and
[control-coverage-reporting](specs/control-coverage-reporting/spec.md).

The merged targeting controller provides versioned contributions and expected
evidence subjects. `internal/collector` now freezes workload/check scope and
evaluates attribution, freshness, and watch continuity. Its observations join to
the frozen expected inventory; they are not a catalog inventory.

`internal/assessment/content.go` still contains the bounded AC-6 prototype mapping
validator, while `export.go` creates prototype-specific titles and context. The
bundle distribution and Linux policy changes own generalized content loading.
The official NIST catalog/profile uses OSCAL 1.2.3; authored C2P content and export
use 1.1.3. Decoding the catalog through an older export model must not silently
drop selection or statement semantics.

`internal/publication` and the shared assessment API already separate expected
technical evidence counts, outcomes, export state, and storage commitment.
Descriptors support summary files and enforce scope-safe package inventories.
The continuous-assessment change owns production scheduling, current status, and
scoped export; the S3 change owns retained package delivery. This change adds a
consumer of those contracts rather than another assessment controller.

## Goals / Non-Goals

**Goals:** Deterministic control inventories and traceable joins to existing
evidence, usable before document ingestion exists; one model for readable and
machine-readable reports; bounded status integration and honest failure states.

**Non-Goals:** A control approval system, manual applicability overrides, a new
OSCAL authoring tool, a dashboard/API server, control satisfaction percentages,
new scanners, or changes to engine enforcement. Production SSP authoring and
cross-cluster aggregation remain separate concerns.

## Decisions

### 1. Start with the selected OSCAL profile, independently of policy selection

Introduce `internal/coverage` with a validated baseline inventory input, not a
list built from findings. Use the content owner's verified handle to read the
declared catalog/profile and authored mappings. Preserve their raw digests and
schema versions; resolve imports only within the validated content closure.

The first supported input is the shipped Moderate profile. Implement and test
its explicit control selection and enhancement hierarchy through a schema-aware
reader. Declare the supported resolution semantics. Use established OSCAL
resolution facilities where they support the content; do not extend the
prototype's `ac-6` string search into a pretend general resolver. Unknown imports,
merge/modify semantics, invalid parameters, ambiguous entry points, or unsupported
schema versions produce `inventoryResolved: false`. Never fall back to every
catalog control or only the successfully mapped subset.

Index controls recursively under catalog groups, keeping selected enhancements
as distinct IDs with parent references. Qualified identity includes catalog
digest plus control/statement ID; retain profile and mapping digests alongside
it. Resolve statement membership within the referenced control, not against one
global bag of IDs. Deduplicate profile selection edges. Preserve resolved
parameter context, but do not mistake policy-engine parameters for OSCAL
organization-defined parameters without an authored mapping.

For each selected control, collect authored rule/check edges and their coverage
descriptions. Join selected policies through the existing logical identities;
available-but-unselected mappings remain visible. Missing automation means
`none`, mapped technical coverage is initially `partial`, and unresolved mapping
is `unknown`. This version never emits a `full` control-satisfaction claim.
The same model works for another validated OSCAL catalog without NIST-specific
IDs, labels, or family assumptions; a small alternate-catalog fixture tests that
property without promising an unimplemented production framework adapter.

### 2. Join evidence without changing its meaning

Consume the collector's frozen expected inventory, observations, stale scopes,
and accepted-risk projection from the exception owner. Join each observation by
its exact expected key, keeping cluster/namespace/workload state, contribution,
check index/digest, mapping, and enforcement revision. Follow the existing
mapping between C2P rule/check identity and rendered sub-validations; do not
assume rule ID, policy name, and validation index are interchangeable.

The source collector remains authoritative for freshness, rejected/conflicting
results, and continuity. Reporting can explain those states, but cannot promote
rejected observations to current findings. Missing mapped expected checks stay
missing. A control without a selected technical check has no automated assessment;
it does not invent an expected observation merely to mark it failed.

Deduplicate identical mapping edges and repeated references to the same observed
result. Preserve distinct contributions/configurations. A check can support more
than one statement/control, so include references to the same observation rather
than claiming multiple independent evaluations. Any aggregate observation count
uses unique expected keys within its declared scope; counts across control rows
are not additive. There is no aggregate count of satisfied controls.

Keep raw outcomes, accepted-risk disposition, and workload applicability separate.
An exception snapshot explains a skip/waiver; neither an arbitrary native skip
nor a supporting document establishes acceptance. Linux scope and zero workloads
affect technical subjects, not the applicability of an entire baseline control.

### 3. Publish one versioned model as package files and bounded status

Coverage report v1 contains:

| Field | Contents |
| --- | --- |
| `schemaVersion`, `asOf`, `scope` | Format, closure/observation time, cluster/binding/namespace identities |
| `inputs` | Catalog/profile/bundle/mapping digests and consumed contract versions |
| `inventory` | Resolution state and selected control count, independent of evidence |
| `technicalEvidence` | Existing expected/attributable/missing/rejected/unresolved summary |
| `controls` | IDs/titles, hierarchy, statements, mapped/selected checks, coverage limits, evidence references and risk dispositions |
| `supportingEvidence` | Integration state and scoped documentary context |
| `limitations` | Coded source, resolution, freshness, or projection limitations |

Sort controls by qualified ID, statements by ID, and references by stable source
identity. Report times come from captured inputs, never from rendering time.
Write `coverage.json` and `coverage.txt` through the assessment producer; both
derive from the same model and appear as checksummed summary files in the package
descriptor. Text headings identify the selected baseline and observation window,
with clear partial-coverage and no-automation explanations.

This uses the existing package download workflow; no new dashboard or direct
cluster query CLI is needed initially. Add bounded aggregate coverage state and
an observation time/reference to the current assessment summary through its
owner. Do not put the full Moderate catalog or per-workload observations in CRD
status. Current-summary expiry uses the assessment owner's requeue mechanism;
historical package views remain frozen. Reading an old report is not a new run.

Keep technical `EvidenceComplete` semantics unchanged. A resolved inventory can
contain many unassessed controls; an attachment outage affects documentary
context, not the collector's expected-check denominator. Export/mapping failures
produce explicit coverage diagnostics and use the established diagnostic-package
path when valid OSCAL cannot be produced. Do not fabricate OSCAL findings to make
coverage rows fit a pass/fail export field.

### 4. Define the attachment projection before its implementation

Coverage owns a narrow versioned `SupportingEvidenceContext` input. It records
whether the integration is disabled, available, or unavailable, and a collection
of already authorized projections qualified by catalog/control/statement and
binding/scope identity. Each entry has an opaque source identity, observation
time, content availability, association validity, declared validFrom/validUntil,
withdrawal/change indicators, and access disposition. It has no outcome or
control-verdict field.

`add-supporting-evidence-attachments` owns acquisition, authenticated attribution,
storage, validity computation, and safe projection. When it is absent, coverage
still works with `disabled` context; when enabled but unavailable, report a
limitation rather than a trustworthy empty list. An expired document, a missing
file, an invalid association, and restricted read access remain different axes.
Technical evidence continues independently.

Document counts are not automated coverage or compliance scores. An upload may
be relevant to a control with no technical mapping. Package links are emitted
only for actual authorized copies; namespace reports contain only the sanitized
context the attachment owner permits, with no private title, source URL, or
document link. Projection happens before rendering, including diagnostics.

### 5. Keep ownership and integration work explicit

| Owner | Integration boundary |
| --- | --- |
| This change | Baseline/control inventory, coverage model and rendering, supporting-context input contract |
| Targeting and bundle changes | Verified content handles, selected policies, rule/check mappings and contributions |
| Continuous assessments | Frozen/current evidence, summary/API extensions, producer/export and package descriptors |
| Exception change | Attributable accepted-risk projection |
| Supporting attachments | Document context, scope/access projection and included copies |
| S3 publishing | Storage and authorized package transport |

Land the model and pure fixtures first. Extend shared types and golden fixtures
through their existing owner files, rebasing before edits; do not fork the
publication schema or add a separate collector. The attachment change consumes
this model once available but can develop its API and storage against explicit
fixtures in parallel. Full runtime claims require actual producer/exception
integration; pure fixtures alone do not establish operational coverage.

## Risks / Trade-offs

- A baseline resolver silently loses controls → strict declared semantics,
  schema-version tests, pinned Moderate inventory, and diagnostic failure.
- Readers interpret a document or green check as full compliance → separate
  dimensions, authored coverage limits, and no aggregate satisfaction field.
- Large catalogs grow API objects → detailed package files and bounded status.
- Overlapping mappings inflate summaries → unique observation identities and
  explicit non-additive control rows.
- Private metadata leaks through diagnostics → authorize/project before both
  renderers and test mixed-scope/error fixtures.

## Migration Plan

Introduce report v1 additively without rewriting retained packages. Preserve the
prototype path and its acceptance fixtures. Add report generation to production
assessment/current-state paths only after their contracts are available, updating
shared schemas and documentation together. Old packages without coverage remain
readable and are identified as lacking this report, not retroactively assessed.
Attachment integration is additive and can be disabled independently. There is
no enforcement migration or new policy rollout in this change.
