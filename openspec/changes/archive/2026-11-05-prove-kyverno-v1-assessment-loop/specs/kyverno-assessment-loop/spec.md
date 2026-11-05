# Spec Delta

## Purpose

Connect configured Kyverno policy enforcement to traceable OSCAL assessment
evidence for selected NIST SP 800-53 Rev. 5 Moderate requirements, starting with
the prohibition of privileged containers on one target cluster.

## ADDED Requirements

### Requirement: Reproducible shipped policy content

Konstapel SHALL ship the `disallow-privileged-containers` policy as a
`policies.kyverno.io/v1` `ValidatingPolicy`, together with relevant upstream tests,
license notices, source repository, immutable revision, and content checksums.
Local modifications SHALL be identified separately from the upstream source.

#### Scenario: Inspect the shipped policy bundle

- **WHEN** an operator inspects the shipped policy bundle
- **THEN** its source revision, license, checksums, and any local changes are identifiable
- **AND** the policy uses `policies.kyverno.io/v1` without requiring a legacy `kyverno.io/v1` policy
- **AND** tests for permitted and prohibited workloads accompany the policy

### Requirement: Explicit and bounded Moderate mapping

The shipped OSCAL mapping SHALL associate the check with control `ac-6` and
statement `ac-6_smt` in pinned NIST content whose Moderate profile includes that
control. It SHALL describe the check as partial technical evidence for least
privilege. Passing this check MUST NOT imply satisfaction of all of AC-6 or the
Moderate baseline.

#### Scenario: Resolve the check to its requirement

- **WHEN** the mapping is loaded
- **THEN** its control and statement references resolve against the identified NIST catalog
- **AND** the selected Moderate profile includes `ac-6`
- **AND** the mapping explains the privileged-container check and the limits of its coverage

#### Scenario: A passing check retains its coverage boundary

- **WHEN** all observed resources pass the privileged-container check
- **THEN** the output describes a passing technical check with partial control coverage
- **AND** it does not mark the entire AC-6 control or Moderate baseline as satisfied

### Requirement: Configurable policy delivery

Konstapel SHALL deliver the policy to one explicitly identified target cluster,
with configurable `Deny` or `Audit` validation actions and background evaluation
enabled. `Deny` SHALL be the default for this enforcement workflow. Unsupported
actions or a missing required policy API SHALL produce a clear error without
falling back to the legacy API.

#### Scenario: Deliver an enforcing policy

- **WHEN** an operator runs the workflow with its default configuration
- **THEN** the resulting `ValidatingPolicy` requests `Deny` and background evaluation
- **AND** the workflow distinguishes successful application from policy readiness and check outcomes

#### Scenario: Select audit behavior

- **WHEN** the operator selects `Audit`
- **THEN** Kyverno is configured to report violations without denying admission through this policy

#### Scenario: Required API is unavailable

- **WHEN** the target cluster does not serve the required policy API
- **THEN** the workflow reports the unsupported prerequisite
- **AND** it does not install a `Policy` or `ClusterPolicy` as a substitute

### Requirement: Kyverno performs admission enforcement

For a ready policy in `Deny` mode, Kyverno SHALL accept compliant workload
requests and reject requests violating the shipped check. The initial workflow
SHALL demonstrate this behavior for Pods and Deployment pod templates, including
applicable update requests and init or ephemeral containers. Konstapel SHALL
attribute the decision to Kyverno and the applied policy.

#### Scenario: Accept a compliant workload

- **WHEN** a compliant Pod or Deployment is submitted to the test cluster
- **THEN** the request succeeds
- **AND** the workflow can associate the resulting resource with its target cluster

#### Scenario: Reject a privileged workload

- **WHEN** a Pod creation, Deployment creation or pod-template update, or Pod ephemeral-container update introduces a privileged container
- **THEN** Kyverno rejects the request because of the enforcing policy
- **AND** the rejection is distinguished from unrelated API or infrastructure failures

### Requirement: Existing violations remain observable

Konstapel SHALL collect background findings for resources that already violate
the policy when it is enabled. The initial workflow SHALL report those findings
without automatically stopping, deleting, or modifying those workloads.

#### Scenario: Discover a pre-existing privileged Pod

- **GIVEN** a privileged Pod exists before the policy is enabled
- **WHEN** the ready policy evaluates existing resources in the background
- **THEN** the workflow observes a failing check for that Pod
- **AND** the Pod retains its identity and is not removed or remediated by Konstapel

### Requirement: Preserve evaluation identity and outcomes

Assessment conversion SHALL accept relevant namespaced and cluster-scoped
Kyverno reports and preserve check outcomes, reasons, source evaluation times,
policy identity, target-cluster identity, and resource identity including UID.
Non-passing or unrecognized outcomes MUST NOT be converted to passes.

#### Scenario: Convert namespaced and cluster-scoped report fixtures

- **WHEN** supported report fixtures contain matching results for the configured check
- **THEN** results from both report scopes are represented in the conversion
- **AND** each result retains its resource, policy, cluster, evaluation time, and reason
- **AND** identical resource names in different namespaces or clusters remain distinct

#### Scenario: Preserve an evaluation error

- **WHEN** a matching report contains an error, skip, warning, or unrecognized result
- **THEN** conversion preserves the original state or explicitly describes its non-passing normalization
- **AND** the assessment does not describe that result as a passing check

### Requirement: Missing and stale evidence remain explicit

The workflow SHALL identify expected test resources and checks independently of
the reports received. Missing evidence, collection errors, and results whose
freshness or association with the intended policy cannot be established SHALL
remain incomplete or unknown. A successful policy application or an empty result
set MUST NOT count as a passing assessment.

#### Scenario: A required observation is absent

- **WHEN** collection finishes without a current result for an expected resource and check
- **THEN** the output identifies the missing observation and incomplete assessment
- **AND** the acceptance workflow fails its evidence-completeness check

#### Scenario: Reports belong to an earlier policy or resource state

- **WHEN** available reports predate the required evaluation boundary or refer to a replaced resource UID
- **THEN** those reports do not establish the current check outcome
- **AND** the workflow waits within a bounded interval for suitable evidence or reports incompleteness

### Requirement: Traceable OSCAL assessment output

The workflow SHALL emit OSCAL Assessment Results conforming to their declared
schema version. The evidence SHALL retain the mapping to the selected control
and identify the target cluster, policy and mapping revisions, raw reports, and
collection context. Collection time SHALL be distinguishable from the source
evaluation time, and internal evidence references SHALL be consistent.

#### Scenario: Inspect an assessment artifact

- **WHEN** the workflow exports observations from compliant and pre-existing violating resources
- **THEN** the OSCAL document passes validation against its declared schema
- **AND** each observation can be traced through the check mapping to `ac-6`
- **AND** its resource, cluster, source report, and content revisions can be identified
- **AND** partial coverage and incomplete evidence remain visible

### Requirement: Repeatable integration acceptance workflow

The project SHALL provide a documented acceptance workflow for an explicitly
selected disposable cluster using recorded dependency versions. It SHALL verify
admission and background evaluation separately, retain useful failure evidence,
and clean up only resources created for the test. A denied creation SHALL NOT
require a PolicyReport for a resource that never existed.

#### Scenario: Run the complete workflow

- **WHEN** the documented acceptance workflow is executed
- **THEN** it demonstrates policy delivery, a permitted request, a policy-specific denial, and background pass/fail observations
- **AND** it produces validated OSCAL output with the bounded Moderate mapping
- **AND** missing required evidence or an unexpected admission result makes the run fail
- **AND** repeating the workflow does not leave conflicting test policies or workloads
