# Spec Delta

## Purpose

Let application teams accept time-limited risks for authorized workloads while
preserving centrally defined policy boundaries and traceable assessment evidence.

## ADDED Requirements

### Requirement: Namespace-bounded self-service acceptance

An application team authorized to manage ComplianceException resources in a
namespace SHALL be able to exempt selected workloads in that namespace from an
eligible logical policy without manual approval. Exception scope SHALL use
standard workload label selectors and MUST NOT reach another namespace.

#### Scenario: An eligible team creates an exception

- **WHEN** an authorized namespace user submits a valid exception for an applicable SelfService policy
- **THEN** Konstapel validates and activates it automatically once engine readiness is established
- **AND** no platform approval queue is required

#### Scenario: Identical workload labels exist elsewhere

- **WHEN** an exception matches workload labels also present in another namespace
- **THEN** its effect remains confined to the exception's own namespace
- **AND** unauthorized cross-namespace exception creation is rejected

### Requirement: Mandatory reason and authenticated attribution

Each acceptance and renewal SHALL have a nonblank reason, authenticated actor,
acceptance time, policy identity, workload scope, and expiry. Actor identity SHALL
come from an authorized API operation rather than caller-supplied attribution.
The recorded identity SHALL distinguish the actual authenticated principal from
any separately claimed human or ticket reference.

#### Scenario: Record an API acceptance

- **WHEN** a team creates or explicitly renews an exception
- **THEN** its acceptance snapshot contains the reason and authenticated principal
- **AND** the caller cannot forge or overwrite protected attribution fields

#### Scenario: Reject an unexplained exception

- **WHEN** the supplied reason is empty or only whitespace
- **THEN** the API rejects the operation without granting an exemption

### Requirement: Effective eligibility cannot be weakened

Exception activation SHALL require every applicable contribution for the logical
policy to permit SelfService. Any Forbidden contribution, unresolved eligibility,
or missing policy mapping SHALL prevent activation. Workload users SHALL NOT be
able to change central eligibility through their exception permissions.

#### Scenario: A non-negotiable policy also has a permissive binding

- **WHEN** overlapping bindings include both Forbidden and SelfService settings for a policy
- **THEN** the exception is ineligible and normal policy enforcement continues
- **AND** the reported reason identifies the restrictive contribution

### Requirement: Bounded lifetime and explicit renewal

Creation and renewal SHALL require a future expiry within the shortest applicable
central maximum lifetime, measured from that acceptance or renewal. Permanent
exceptions SHALL be rejected. Renewal SHALL revalidate current scope and policy
eligibility, record a new attributable acceptance, and require an explicit user
operation rather than automatic extension.

#### Scenario: A lifetime exceeds a central limit

- **WHEN** the requested expiry is absent, already elapsed, or beyond the effective maximum lifetime
- **THEN** the operation is rejected without creating or extending an exemption

#### Scenario: A team renews an expiring exception

- **WHEN** an authorized user explicitly renews with a valid expiry and reason
- **THEN** current eligibility is rechecked and a new acceptance snapshot is recorded
- **AND** the previous snapshot remains distinguishable from the renewal

#### Scenario: Explicitly renew a revoked exception

- **WHEN** a team sets revoked false while incrementing acceptanceRevision by exactly one with a current reason and valid future expiry
- **THEN** admission rechecks current eligibility and lifetime and records a distinct acceptance
- **AND** the prior revision stays revoked and its revocation history is preserved before its protected intent is cleared
- **AND** renewal cannot cancel outstanding withdrawal for that earlier revision

### Requirement: Explicit revocation retains the exception resource

ComplianceException SHALL expose spec.revoked defaulting to false. An authorized
namespace editor SHALL revoke the current acceptance by setting it true without
changing acceptanceRevision, reason, or expiresAt. Revocation SHALL retain the
resource, request native withdrawal, and require no fresh eligibility or future
expiry. A revoked revision SHALL NOT be reactivated without a new validated
acceptance revision or resource.

#### Scenario: A team revokes an exception

- **WHEN** an authorized namespace editor sets revoked true for the current acceptance revision
- **THEN** the API retains the ComplianceException and original acceptance fields while requesting withdrawal
- **AND** no native exception write or manual approval is required
- **AND** existing workloads remain present

#### Scenario: Revoke an expired or currently ineligible acceptance

- **WHEN** a team revokes after expiry or while the policy is Forbidden, unmapped, or cannot currently be resolved
- **THEN** admission validates authority and the revocation transition without resolving fresh eligibility or demanding a future expiry
- **AND** the operation cannot create or extend an exemption

#### Scenario: A same-revision re-apply clears revocation

- **WHEN** an update sets revoked false or omits it so it defaults to false without incrementing acceptanceRevision
- **THEN** the API rejects reactivation of the revoked revision
- **AND** metadata edits and controller reconciliation cannot reactivate it either

#### Scenario: Create or renew into a revoked state

- **WHEN** a create or revision-incrementing renewal sets revoked true
- **THEN** the API rejects the operation because a new acceptance starts unrevoked
- **AND** revocation must refer to an existing acceptance revision

#### Scenario: Revocation races renewal

- **WHEN** documented client workflows read an exception UID, resourceVersion, and acceptanceRevision and patch with those preconditions
- **THEN** the API rejects a stale request after a concurrent change instead of silently targeting a newer acceptance
- **AND** the client must re-read and deliberately retry rather than blindly refreshing preconditions

### Requirement: Revocation records authenticated intent

On the first false-to-true transition, admission SHALL record exception UID,
acceptance revision, authenticated actor, and request time in protected revocation
metadata. It SHALL preserve the original acceptance record. Repeated revocation
SHALL preserve the first actor/time. Caller-forged attribution or unauthorized
changes SHALL be rejected or replaced with authenticated values. Dry runs SHALL
have no durable side effects.

#### Scenario: Revoke through GitOps and repeat the request

- **WHEN** a GitOps service account revokes an acceptance and later re-applies revoked true at that revision
- **THEN** the first authenticated service account identity and revocation time are retained separately from any claimed human identity
- **AND** the accepting actor, risk reason, expiry, and immutable acceptance snapshot are unchanged

#### Scenario: Forge identity or remove history protection

- **WHEN** a caller supplies false revocation attribution or changes an existing protected record
- **THEN** admission replaces supplied attribution on a genuine revoke with authenticated values and rejects alteration outside that operation
- **AND** application credentials cannot write controller-owned status, lifecycle records, or remove protected finalization safeguards

#### Scenario: Revoke outside the team's namespace

- **WHEN** application credentials attempt to revoke an exception outside their delegated namespace
- **THEN** authorization rejects the operation
- **AND** the other namespace's exception and history remain unchanged

### Requirement: Revocation history survives renewal and deletion

Konstapel SHALL preserve revocation intent and observed withdrawal context
independently of the live exception and its namespace. Renewal SHALL NOT erase
intent before its independent record is durable; deletion finalization SHALL
also preserve it. Storage failure SHALL retain the intent and protection while
native withdrawal continues. Historical acceptance snapshots and retained
assessments SHALL NOT be rewritten by revocation.

#### Scenario: Revoke and immediately delete or renew

- **WHEN** revocation is followed by deletion or renewal before the controller copies its protected intent
- **THEN** renewal cannot erase that intent and finalization cannot remove its last durable copy
- **AND** independent immutable lifecycle records retain the exception UID, revision, authenticated revoking actor/time, and acceptance reference
- **AND** restart or namespace deletion cannot garbage-collect the retained records

#### Scenario: Persisting revocation history fails

- **WHEN** the controller cannot save the independent lifecycle record
- **THEN** the protected intent and finalization safeguards remain for retry
- **AND** Konstapel still attempts native withdrawal without claiming history persistence or engine convergence succeeded

### Requirement: Controlled native Kyverno exceptions

Konstapel SHALL realize active acceptances through managed
`policies.kyverno.io/v1` PolicyException resources with bounded namespace/workload
scope and expiry. Application teams SHALL NOT be able to bypass governance by
directly creating or modifying native exceptions in engine-enabled namespaces.
Native exceptions SHALL reference only the authorized managed policy instances.

#### Scenario: A workload user attempts a native bypass

- **WHEN** application credentials attempt to create, widen, or alter a native exception that could affect a managed policy
- **THEN** authorization or admission validation rejects the attempt
- **AND** the non-negotiable policy remains enforced

#### Scenario: A native exception has been rendered

- **WHEN** Konstapel activates a valid acceptance
- **THEN** its native exception references the acceptance identity and exact authorized policy instances
- **AND** its namespace condition and expiry cannot be broader than the acceptance

### Requirement: Expiry and revocation restore enforcement

Expired, deleted, revoked, or newly ineligible acceptances SHALL cease granting
exemptions and trigger cleanup of their native resources. Status SHALL distinguish
desired revocation from observed engine state and SHALL NOT claim completion
while stale native exceptions remain effective. Withdrawal SHALL NOT itself
delete or stop an existing workload.

#### Scenario: An exception expires

- **WHEN** its expiry is reached
- **THEN** new violating requests no longer receive that exception's permission
- **AND** background evidence and lifecycle status subsequently reflect its expiry
- **AND** previously admitted workloads are not automatically removed by Konstapel

#### Scenario: Central eligibility becomes Forbidden

- **WHEN** the controller observes a new restrictive configuration
- **THEN** affected acceptances stop being eligible and their native grants are withdrawn
- **AND** reconciliation reports pending withdrawal until the engine state is confirmed

#### Scenario: Revocation has been recorded but the engine has not converged

- **WHEN** revoked is true and native grants remain effective or their withdrawal cannot be confirmed
- **THEN** status distinguishes the requested withdrawal from pending or unknown engine state
- **AND** API update/delete success alone does not establish completion
- **AND** restart or a late native-create response cannot restore the desired grant for that revoked revision

#### Scenario: Reconciliation is unavailable during revocation

- **WHEN** the API admission path records revocation while the reconciler is stopped
- **THEN** withdrawal remains unconfirmed and delivered native grants may persist until reconciliation resumes or independently enforced expiry
- **AND** documentation does not promise immediate engine withdrawal during that outage

#### Scenario: Delete instead of revoke

- **WHEN** a team deletes the ComplianceException
- **THEN** finalization withdraws outstanding native grants and preserves acceptance and revocation history before removing the resource
- **AND** a revocation request alone retains the resource for inspection

#### Scenario: Konstapel is unavailable at expiry

- **WHEN** an active exception expires while the Konstapel controller is stopped
- **THEN** the engine stops granting it without needing a Konstapel-triggered policy update
- **AND** capability enablement is blocked on runtimes that cannot demonstrate this behavior

### Requirement: Acceptance does not silently expand

An acceptance SHALL bind to the resolved policy/configuration identities present
when it is made. A new policy revision, additional binding contribution, or wider
workload scope SHALL NOT inherit acceptance automatically. Renewal or a new
acceptance SHALL be required after revalidation, and unrelated policies SHALL
continue to apply.

#### Scenario: Policy content changes after acceptance

- **WHEN** a selected policy instance changes to a revision outside the recorded acceptance
- **THEN** the old acceptance does not exempt that new instance
- **AND** status explains the need for renewed acceptance

#### Scenario: Another policy still denies the workload

- **WHEN** an exception covers one policy but the workload violates another applicable Deny policy
- **THEN** the other policy still rejects the request

### Requirement: Evaluation and risk acceptance remain distinct

Assessment evidence SHALL retain the raw engine outcome and separately identify
whether an authorized acceptance applied at evaluation time. Accepted exemptions
MUST NOT be counted as ordinary unexcepted passes or full control satisfaction.
A skip or exception name without a resolvable acceptance SHALL NOT establish
accepted risk, and skipped evaluation SHALL NOT fabricate an underlying failure.

#### Scenario: Kyverno reports a skip caused by an active exception

- **WHEN** the report can be linked to a valid acceptance at evaluation time
- **THEN** output preserves the skip and records self-accepted risk with its reason and identity
- **AND** it does not invent a failing baseline evaluation that was never performed

#### Scenario: A report records pass with exception context

- **WHEN** an engine reports pass while an exception influenced its evaluation
- **THEN** output retains the raw pass and the exception context separately
- **AND** it does not count that result as evidence of an unexcepted passing check

#### Scenario: Exception attribution cannot be resolved

- **WHEN** the referenced acceptance or its evaluation-time validity is unavailable
- **THEN** output marks the attribution as unresolved rather than accepted or ordinarily compliant

### Requirement: Assessment artifacts retain acceptance history

Exported assessment artifacts SHALL retain an immutable snapshot or a resolvable
packaged reference containing acceptance identity, revision, actor, reason, scope,
policy revisions, and validity interval. Historical assessments SHALL remain
interpretable after live exception resources are renewed, expired, or deleted.

#### Scenario: Inspect evidence around a revocation

- **WHEN** an assessment captures evidence referencing a revoked acceptance
- **THEN** its packaged lifecycle context distinguishes authenticated revocation request time from observed engine withdrawal
- **AND** a delayed report from before revocation can retain its original accepted-risk attribution
- **AND** a stale native exception reference after revocation does not by itself establish authorized acceptance at evaluation time
- **AND** missing or ambiguous lifecycle context remains unresolved without rewriting raw outcomes or earlier retained assessments

#### Scenario: Inspect evidence after expiry

- **WHEN** an operator opens a retained assessment artifact after the exception has expired or been removed
- **THEN** its recorded acceptance and evaluation-time validity can still be established
- **AND** current revocation does not rewrite the historical raw outcome
