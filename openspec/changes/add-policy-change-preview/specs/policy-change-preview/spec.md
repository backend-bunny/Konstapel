# Spec Delta

## Purpose

Let platform teams inspect how proposed compliance configuration affects the
observed cluster before application, including namespace scope, enforcement,
accepted risks, and evidence limitations, without changing cluster state.

## ADDED Requirements

### Requirement: Read-only configuration preview

Konstapel SHALL provide `konstapel preview` using rendered ComplianceProfile and
ComplianceBinding manifests and a selected cluster. The command MUST NOT mutate
Kubernetes resources, trigger assessments, accept risk, or start policy delivery.
It SHALL describe configuration effects without simulating workload admission.

#### Scenario: Preview before GitOps application

- **WHEN** an operator previews proposed manifests against a cluster
- **THEN** the command reads the necessary cluster state and reports proposed
  effects without submitting any Kubernetes create, update, patch, or delete
  operation, including server-side dry-run writes
- **AND** applying the configuration remains a separate Kubernetes/GitOps action

#### Scenario: A proposed Deny policy has no workload evaluation

- **WHEN** a proposal introduces a Deny contribution
- **THEN** the preview identifies its configured enforcement scope without
  claiming that particular workloads will pass, fail, or be evicted

### Requirement: Explicit rendered input and removal scope

The command SHALL accept repeatable `-f`/`--file` inputs and an optional repeatable
`--before` rendered set. Proposed objects SHALL replace the corresponding live
desired specifications in the preview. Only identities present in `--before`
and absent from the proposed set SHALL be treated as removals. Every other live
object SHALL remain in the candidate configuration.

#### Scenario: Preview a subset of configuration

- **WHEN** the proposed set contains one binding and no previous set is supplied
- **THEN** every other live profile and binding is retained, including those that
  overlap the supplied binding

#### Scenario: Explicit removal from a previous rendered set

- **WHEN** a binding occurs in `--before` and is absent from the proposed set
- **THEN** the preview models removal of that binding and its contributions
- **AND** uses live cluster state as the baseline rather than treating the
  previous file as an authoritative description of current enforcement

#### Scenario: A whole declared set is removed

- **WHEN** the proposed input is an explicitly supplied empty document stream
  and the previous set contains profiles and bindings
- **THEN** only those previous identities are removed in the candidate

### Requirement: Validate inputs without impersonating API admission

Inputs MUST contain supported `compliance.erenius.io` profile or binding objects
with explicit names and valid specifications. Duplicate identities, unsupported
kinds/versions/fields, missing selectors, and invalid configuration SHALL fail
the preview. Server-managed metadata and status MUST NOT establish proposed
identity, acceptance, or readiness. Preview validation SHALL NOT claim to prove
API authorization, admission acceptance, or field ownership at apply time.

#### Scenario: Invalid or ambiguous input

- **WHEN** input has duplicate bindings, a Namespace, a Secret, an unknown spec
  field, or a missing namespace selector
- **THEN** the preview is incomplete and identifies the invalid input
- **AND** it does not silently skip the document or assume a missing selector is
  the explicit empty selector that selects all namespaces

#### Scenario: Exported live objects contain status

- **WHEN** a proposed manifest contains a UID, resourceVersion, generation,
  managedFields, or status copied from a cluster
- **THEN** these values do not create proposed server identities or readiness
  claims, and observed provenance comes from the selected cluster

### Requirement: Consistent targeting and overlapping contributions

Preview targeting, parameters, policy validity, and exception eligibility SHALL
follow the same versioned contracts as the controller. It MUST include every
binding referencing a changed profile and every relevant overlapping
contribution, including bindings absent from the files. Audit SHALL NOT override
Deny; effective exception eligibility and lifetime SHALL retain the controller's
Forbidden precedence and shortest applicable lifetime.

#### Scenario: Shared profile update

- **WHEN** a changed profile is referenced by multiple live bindings
- **THEN** the report includes the affected contributions and namespaces of each
  referencing binding, even if none of those bindings occurs in the input

#### Scenario: Audit overlaps Deny and Forbidden

- **WHEN** a proposed Audit/SelfService binding overlaps an unchanged
  Deny/Forbidden contribution for the same logical policy
- **THEN** the preview retains the Deny contribution and Forbidden eligibility
  rather than claiming that the proposal permits the workload or an exception

### Requirement: Framework-neutral semantic impact reporting

The report SHALL describe added, removed, or changed policy contributions,
namespace membership, selectors, parameters, bundle pins, enforcement modes,
and exception rules, including effective overlap consequences. Changed
enforcement revisions SHALL be impacts even if policy values match an earlier
revision. Formatting and metadata-only changes SHALL NOT be impacts. Categories
MUST NOT imply a framework-specific compliance score.

#### Scenario: Namespace selector changes

- **WHEN** a selector adds one observed namespace and removes another
- **THEN** the report identifies both namespace instances by name and UID, their
  affected bindings and policies, and remaining overlapping contributions

#### Scenario: No semantic change

- **WHEN** the proposed specifications differ only in YAML ordering or ordinary
  descriptive metadata
- **THEN** the completed preview has no policy impacts

#### Scenario: New bundle digest or zero current targets

- **WHEN** a bundle pin or enforcement setting changes on a binding that currently
  selects no namespaces
- **THEN** the configuration change is still an impact, with zero observed target
  namespaces and no compliance-pass claim

### Requirement: Separate desired effects from observed engine state

The preview SHALL distinguish live desired configuration, observed managed
Kyverno policy state, and proposed desired effects. Unresolved bindings, pending
replacement, stale observed generations, and retained old policies SHALL be
reported explicitly. It MUST NOT equate a profile removal or a successful
preview with immediate withdrawal, convergence, or absence of enforcement.

#### Scenario: A profile is deleted while a binding remains

- **WHEN** the candidate removes a profile still referenced by a binding
- **THEN** the preview reports unresolved proposed configuration and an incomplete
  result, identifying that previously applied policies may remain enforcing

#### Scenario: A replacement has not converged

- **WHEN** current policy replacement is pending or old managed policies remain
- **THEN** their observed revisions and readiness limitations appear separately
  from proposed effects, including possible temporary overlap
- **AND** unknown applied state is not represented as an empty policy set

### Requirement: Honest proposed identities and revision effects

Observed identities and revisions SHALL retain their provenance. Future UIDs,
generations, enforcement epochs, and generated engine names MUST NOT be presented
as assigned server values. The preview SHALL identify changes requiring new
enforcement revisions without promising their final values. Reporting-only
binding changes SHALL follow the shared enforcement-epoch contract and MUST NOT
invalidate policy acceptance merely because API generation changes.

#### Scenario: New profile and binding

- **WHEN** both objects exist only in proposed files
- **THEN** the preview can report their policy and namespace effects but labels
  their server identities and final revisions as pending application

#### Scenario: Rollback and reporting settings

- **WHEN** a proposal restores earlier policy settings while separately changing
  an assessment interval
- **THEN** the rollback is identified as requiring a new enforcement revision
  without reviving old acceptances, and the interval change alone does not
  require renewal

### Requirement: Exception impact follows recorded acceptance

The preview SHALL compare effective eligibility and affected acceptance records
using their namespace identities and frozen contribution revisions. It SHALL
identify acceptances requiring renewal, newly forbidden exceptions, changed
lifetime limits, and removed scope. It MUST NOT grant, renew, or infer acceptance
from a native exception or report result alone.

#### Scenario: Additional contribution invalidates acceptance

- **WHEN** a proposal adds a contribution or changes an accepted enforcement
  revision in an exception's namespace
- **THEN** the preview identifies the recorded acceptance requiring renewal and
  the responsible contribution changes
- **AND** a new Forbidden contribution is reported as preventing self-service
  renewal under the proposed configuration

#### Scenario: Scope shrinks or a namespace was recreated

- **WHEN** an accepted contribution is removed, or a namespace now has a
  different UID from a historical acceptance
- **THEN** the report distinguishes removed scope or an unrelated namespace
  instance from a new grant and does not extend the old acceptance

### Requirement: Evidence is context rather than proposed evaluation

The preview SHALL identify relevant available, missing, stale, or unattributable
evidence using source evaluation time and recorded scope/revision identities.
Existing results MUST NOT be attributed to new policy revisions. Evidence gaps
alone SHALL be informational limitations, not policy impacts or proof that the
configuration preview failed, provided the required impact inputs were read.

#### Scenario: Old evidence for a changed policy

- **WHEN** an existing report passed an earlier policy revision
- **THEN** it is shown only as historical context and the proposed revision is
  reported as not evaluated

#### Scenario: No recent evidence is available

- **WHEN** required configuration and exception inputs are available but
  assessment data is missing, stale, or the assessment capability is unavailable
- **THEN** the report states that evidence limitation without inventing a result,
  scheduling an assessment, or treating the gap alone as a policy impact

### Requirement: Caller-authorized and verified content resolution

The preview SHALL use the selected cluster's bundle-source and verification
rules, resolving exact pinned content under caller-authorized access. Cached
content MUST satisfy current trust requirements. The command MUST NOT bypass
verification, use arbitrary manifest-provided registry credentials, expose
credentials in output, or assume access to the controller's service account.

#### Scenario: Controller credentials are inaccessible to the caller

- **WHEN** a required private bundle cannot be resolved with the caller's
  authorized credentials under the configured source rules
- **THEN** the preview reports an actionable content-access error and is
  incomplete, without impersonating the controller or changing its sources

#### Scenario: Content verification fails

- **WHEN** content has a digest mismatch, fails configured signature verification,
  or was cached under trust that is no longer accepted
- **THEN** that content cannot support a completed preview

### Requirement: Snapshot provenance and bounded observation

The preview SHALL report cluster identity, observation start/end times, object
UIDs/resourceVersions, namespace instances, input fingerprints, resolved content
digests with their digest kind, and relevant contract versions. Reads and retries
SHALL be bounded. Detected relevant changes that prevent a stable comparison
SHALL make the result incomplete. A preview MUST NOT claim an atomic
cross-resource snapshot or an apply-time guarantee.

#### Scenario: Configuration changes while being read

- **WHEN** relevant objects or namespace membership change during observation
  and remain unstable after bounded retries
- **THEN** the preview reports the affected inputs and an incomplete comparison
  instead of presenting a completed result assembled from incompatible states

#### Scenario: Cluster changes after preview

- **WHEN** GitOps applies the manifests after the recorded observation window
- **THEN** the saved report remains a description of that earlier observation,
  with no claim that its effects are guaranteed at application time

### Requirement: Versioned and deterministic reports

The command SHALL default to human-readable text and support `--format json`. JSON SHALL
have a versioned schema with explicit completeness, impact count, observations,
changes, evidence context, limitations, and errors. Both formats SHALL preserve
the same meaning and stable ordering for the same captured inputs. JSON stdout
MUST contain only the report; operational diagnostics SHALL use stderr.

#### Scenario: CI consumes a report

- **WHEN** CI requests JSON for a completed or incomplete comparison
- **THEN** it can distinguish policy impacts, informational evidence limitations,
  and fatal errors without interpreting human prose or mixed log lines

### Requirement: Informational default and opt-in impact exit code

A completed preview SHALL exit `0` by default. With `--fail-on-impact`, it SHALL
exit `2` if at least one policy, scope, enforcement, or exception impact exists,
and `0` otherwise. Invalid inputs, failed execution, incomplete required impact
analysis, or report-output failure SHALL exit `1` regardless of impacts or the
flag. Reporting-only changes and evidence limitations alone SHALL NOT trigger
exit `2`.

#### Scenario: Informational and gated invocations

- **WHEN** a complete preview finds impacts
- **THEN** the default invocation exits `0`, while the same preview with
  `--fail-on-impact` exits `2`, and both provide the impact report

#### Scenario: No impacts with the flag enabled

- **WHEN** a complete preview finds no impacts and `--fail-on-impact` is enabled
- **THEN** it exits `0`, including when evidence limitations are present

#### Scenario: Failure takes precedence over impacts

- **WHEN** an impact is found but required namespace, exception, or content
  inputs cannot be read, required capabilities are unavailable, or an operational
  limit prevents complete comparison
- **THEN** the preview reports incomplete analysis and exits `1`, even with
  `--fail-on-impact`, without treating inaccessible records as empty
