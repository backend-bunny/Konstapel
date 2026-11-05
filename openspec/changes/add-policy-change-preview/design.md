# Design

## Context

See [proposal.md](proposal.md) and the
[preview contract](specs/policy-change-preview/spec.md).

The current binary dispatches `controller` independently, but its prototype
assessment commands load OSCAL input and start an external C2P provider.
`internal/controller` now supplies a controller-runtime manager and live policy
delivery. Neither startup path is appropriate for a read-only preview.

`internal/targeting` already provides pure `Resolve`, a versioned contribution
contract, `EnforcementRevision`, verified `ContentSource`, and `ExpectedEvidence`.
Its local source verifies vendored checksums; its digest identifies the checksum
manifest rather than an OCI manifest. Failed resolution or replacement can leave
older Kyverno policies applied. Profile deletion does not mean binding deletion.

OCI distribution, authenticated exception acceptance, and continuous collection
are owned by active changes. The current binding revision uses API generation;
the assessment change owns its migration to a protected enforcement epoch so
reporting-only edits do not invalidate acceptance. Preview must consume that
contract rather than implement a competing revision algorithm.

## Goals / Non-Goals

**Goals:** A deterministic comparison core with explicit input provenance,
read-only adapters, conservative completeness, and identical local/CI semantics.
Keep observable configuration changes distinct from reconciliation progress and
from evidence about previously evaluated workloads.

**Non-Goals:** Running Helm/Kustomize, emulating server-side apply or admission,
predicting future namespace labels/workload behavior, downloading archived S3
evidence, creating acceptance snapshots, or operating controller reconciliation.
Namespace objects, ComplianceExceptions, central bundle-source configuration, and
arbitrary engine policies are not proposed-manifest inputs in this version.

## Decisions

### 1. An independent CLI with fully rendered desired specifications

Add early `preview` dispatch beside `controller` with its own flag set. Do not
start the manager, provider subprocess, delivery code, metrics server, or leader
election. Keep the comparison reusable under `internal/preview`; keep CLI I/O and
process exit handling in `cmd/konstapel`.

Example workflows, to be documented as available only once implemented:

```sh
konstapel preview -f proposed.yaml --context staging
konstapel preview --before previous.yaml -f proposed.yaml \
  --context production --format json --fail-on-impact > preview.json
```

Use repeatable `-f`/`--file` and `--before` paths containing multi-document
YAML/JSON. Allow stdin as `-` for at most one input stream, so two sets cannot
silently consume the same stream. Require at least one proposed input path;
explicitly empty streams allow declared deletion of the previous set. Accept only
the supported cluster-scoped profile/binding API, named objects, and empty
metadata.namespace. Reject duplicate keys/documents, unknown spec fields,
generateName, unsupported versions, and unrelated kinds. Do not silently filter
a whole application's manifests; callers render the compliance set explicitly.
Ignore exported status and server-managed metadata, including protected
enforcement-epoch annotations, as candidate authority.

Treat each supplied spec as its complete proposed value, with shared defaults and
validation. Preserve live objects outside the declared set. `before minus after`
by group/kind/name supplies removals; `after` supplies upserts. The before set is
deletion scope and provenance, not the current-state baseline. A previous object
already absent in the cluster creates no additional removal impact. A profile
removed while a surviving binding references it is an invalid candidate.

This choice avoids implicit pruning and allows small local previews and full
rendered CI diffs with one model. It does not reproduce field ownership, merge
patches, GitOps prune settings, or admission mutations. State those assumptions
in every report. Replacing an object by deleting/recreating the same name is not
expressible by two ordinary desired sets and is outside this first interface.

### 2. Capture a bounded, attributable cluster observation

Use ordinary kubeconfig/context selection and direct clients without controller
caches. Read all profiles, bindings, and namespaces needed to include shared
references and overlap; namespace UID and labels are essential. Record the
`kube-system` namespace UID cluster identity used by the controller. Read managed
`policies.kyverno.io/v1` policy objects, relevant status, source configuration,
and the exception/assessment read models through their owners' contracts.
Do not infer ownership from a name prefix alone or inspect arbitrary workload
contents to claim admission predictions.

Use paginated collection reads and record collection resourceVersions plus
object UID/resourceVersion/generation. Recheck the relevant configuration,
membership, source/trust, applied-policy, and acceptance projections before
finishing. A change to an irrelevant reporting timestamp alone need not invalidate
configuration comparison. Retry the entire dependent capture at most twice
within a default 60-second total `--timeout`. Record observation start/end and
individual evidence capture/evaluation times. Kubernetes provides no transaction
across these APIs: bounded rechecks detect drift, not atomicity.

Bound input documents, collected objects, and bundle extraction using explicit
limits, initially 16 MiB of total manifest input and 100,000 collected objects;
content verification keeps the bundle owner's limits. Hitting a limit, exhausted
pagination/retries, cancellation, or a timeout is an incomplete preview with
partial diagnostics. Never silently truncate a successful report. Do not resolve
only objects present in the proposed files, because it misses shared consumers
and restrictive overlap.

### 3. Share resolution, compare logical effects, label hypothetical identity

Feed baseline and candidate snapshots through the same targeting validation,
content lookup, and `Resolve` contract used by reconciliation. Retain every
contribution and effective eligibility. Use stable comparison keys consisting of
cluster, observed namespace UID where applicable, binding identity/name, and
logical policy identity. Configuration-level rows also exist when no namespace
currently matches. Include bundle/source/configuration digest and parameter
changes, selectors, modes, effective eligibility, and maximum lifetime.

Keep observed and proposed identity fields separate. Unchanged live objects can
carry their observed identities. For new or spec-changed objects, a private
resolver adapter can use deterministic provisional identity/epoch values to
resolve topology, but these values and derived policy names/revision hashes must
never escape as observed or guaranteed future values. Report `revisionEffect`
(`unchanged`, `replacement-required`, or `new`) and pending server identity
instead. Fingerprint normalized candidate configuration separately from the
controller's enforcement revision. The fingerprint is not an acceptance token.

Use the targeting/assessment owner's shared enforcement-input classification for
whether a revision changes; preserve generation-driven effects across all
policies of an updated shared profile. A rollback from the live spec rotates
revisions even if those values match historical configuration. Once the
enforcement-epoch integration is present, reporting-only edits appear as
informational configuration differences, with no policy impact or renewal.
Do not paper over a missing epoch contract with a preview-only approximation;
that integration is a completion prerequisite.

Read observed policy state separately. Correlate managed objects through their
ownership and recorded revision metadata; keep unresolved/stale scopes and
pending replacements explicit. Show removed desired contributions as requested
withdrawals, not proof of immediate engine convergence. Baseline problems that
prevent determining an affected contribution make that part of the preview
incomplete; a known reconciliation lag can be reported without pretending that
it is a new desired configuration impact. Do not hide uncertainty by treating an
unreadable or unresolved policy set as empty.

### 4. Classify policy impacts separately from evidence and operating state

Report impact entries with stable category, subject identity, before/after
values, responsible inputs/contributions, and explanatory reasons. Categories
cover policy/configuration, namespace scope, enforcement, and exception changes.
They describe direction without assigning a compliance percentage or suggesting
that all tightening is good or all relaxation is bad.

Changed selectors/settings count even with no current targets. Policy source or
bundle pin changes count even if rendered rules look identical. Metadata/order
changes, reporting-only settings, evidence age, and preexisting reconciliation
lag alone do not increment `impactCount`. Keep object/configuration changes and
affected namespace lists related so summary counts are not mistaken for a count
of failed workloads or covered NIST controls.

Use effective eligibility plus the exception owner's authenticated records and
frozen acceptance snapshots to classify renewal required, newly forbidden,
lifetime changed, scope removed, or unchanged. Include all accepted contributors;
an added contributor is not covered by an earlier acceptance. Restriction takes
precedence even from an Audit binding. Removal does not authorize new scope.
Namespace recreation is a different subject. Report the reason and affected
record identities, not copied authentication groups, free-text risk reasons, or
credential material that a CI log does not need. Never create a new acceptance
revision or infer acceptance from a native skip result.

Use `ExpectedEvidence` for observed resolved subjects and stale scopes, and the
assessment owner's evidence attribution/freshness rules for captured context.
Display source evaluation times and matched observed revisions. Candidate
revisions needing replacement are `not-evaluated`; old passes remain historical.
There is no workload evaluation, raw-report conversion job, S3 archive retrieval,
or assessment trigger. Missing/stale/unattributable evidence or an uninstalled
assessment capability is an explicit informational limitation. A required
exception inventory or protected snapshot that cannot be obtained is instead an
impact-analysis failure: do not claim zero affected acceptances.

### 5. Reuse bundle trust under the caller's authority

Resolve profile bundle names through the controller's configured source mapping
in its namespace, using the distribution owner's reader/verifier/cache contract.
The caller selects the Konstapel namespace consistently with controller setup.
Do not allow proposed manifests to replace source/trust configuration. Resolve
the exact digest and verify current trust, including cached content. Preserve
whether a digest is a vendored checksum-manifest digest or an OCI manifest digest
in the report; never label one as the other.

Use standard caller-authorized registry credentials for the mapped repository,
or referenced Secret credentials only if the caller has explicit Kubernetes read
access and uses the shared source credential path. Reading a source mapping does
not authorize impersonating the controller. Get only named referenced secrets;
do not list all secrets or print tokens, secret data, auth-bearing URLs, or raw
registry errors containing credentials. Local verified vendored content remains
usable through `ContentSource`; there is no unsigned fallback for OCI failures.

The Kubernetes access contract is get/list/discovery only; avoid write-shaped
authorization probes and server-side dry-run. Document required resources and
optional named secret reads instead of shipping broad administrative credentials.
Cluster-wide visibility is necessary for complete overlap analysis. Denied reads
of required impact inputs, unavailable required APIs, unknown contract versions,
or failed trust are incomplete results. In particular, a missing exception integration cannot be
reported as a successful full preview with no affected exceptions. A core-only
prototype can be developed and tested before that integration but is not the
completed capability. Missing evidence context has the distinct treatment above.

### 6. A versioned result with deliberate exit semantics

Use a report version independent of targeting's `ContractVersion`; record the
consumed contract versions in provenance. Define JSON v1 around:

| Field | Meaning |
| --- | --- |
| `schemaVersion`, `complete`, `impactCount` | Consumer contract and completion outcome |
| `observation` | Cluster, context, start/end, input/collection/object revisions |
| `inputs`, `content` | Input fingerprints and typed verified content digests |
| `changes` | Ordered changes with observed/proposed sides and impact classification |
| `appliedState` | Observed managed policy revisions, readiness, stale scopes |
| `exceptions`, `evidence` | Acceptance consequences and attributed evidence context |
| `limitations`, `errors` | Coded informational bounds versus incomplete analysis |

Sort by subject identity and category, with deterministic values for the same
captured inputs. Times describe capture, not rendering time; do not include random
IDs. Text renders the same model. Keep JSON stdout free of progress messages;
diagnostics go to stderr. Once a valid JSON invocation is parsed, operational
failures should produce an incomplete report if output is writable. Syntax/flag
errors can produce stderr only; output failure still exits `1`.

| Outcome | Default | `--fail-on-impact` |
| --- | --- | --- |
| Complete, no policy impacts | 0 | 0 |
| Complete, policy impacts | 0 | 2 |
| Invalid, failed, incomplete, or unwritable report | 1 | 1 |

Missing/stale evidence alone follows the complete rows. Centralize status
selection at the command boundary so `main` does not collapse the impact outcome
into its existing generic error exit `1`. Existing commands retain their current
exit behavior. Avoid adding one Taskfile wrapper per command; use existing check
workflows and direct Devbox commands in documentation.

## Risks / Trade-offs

- Cross-resource races and later GitOps changes → bounded recapture, explicit
  observations/assumptions, and no apply-time guarantee.
- Wider cluster visibility than an application service account has → document
  reader permissions; fail incomplete when overlap or acceptance cannot be read.
- Resolver revision inputs are still evolving → consume owners' contracts and
  golden fixtures; never expose provisional hashes as acceptance identities.
- Missing runtime integrations could produce a deceptively successful demo →
  keep integration tasks open and test failure on unavailable required APIs.
- Fast-changing report status can cause excessive retries → recheck relevant
  semantic projections and capture evidence separately with its own time bounds.
- Large/private bundles and clusters → bounded reads, verified caches, explicit
  failure diagnostics, and no silent partial success or secret-bearing reports.

## Migration Plan

This is an additive CLI command; existing controller configuration and GitOps
application need no migration. Build the core and fixtures against the merged
targeting API first. Integrate OCI through `add-policy-bundle-distribution`,
acceptance through `add-self-service-policy-exceptions`, and enforcement epochs
and attributed evidence through `add-continuous-assessments`. Those changes own
their APIs, CRDs, security, and compatibility gates.

Complete release acceptance against the actual integrated implementations,
including read-only credentials, before documenting the full preview as shipped.
Do not mark dependent tasks complete using fake providers alone. Add local and CI
examples with informational mode first; users opt into `--fail-on-impact` in
their own pipelines. Removing the CLI invocation is sufficient rollback because
preview creates no cluster state. No public Taskfile expansion is required.
