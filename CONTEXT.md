# Konstapel

Konstapel continuously assesses a Kubernetes cluster against compliance frameworks, using Kyverno as its evidence source and emitting OSCAL Assessment Results. This document fixes the vocabulary, because `control`, `component`, `subject`, and `result` each mean something different in OSCAL, in Kyverno, and in Kubernetes, and conflating them is the main source of confusion in this domain.

## Language

### The assessment model

**Check**:
A named assertion about a class of subject, such as `no-privileged-containers`. Konstapel owns the name; it is not derived from Kyverno. The check is the primary entity in this model — controls are views over checks, never the reverse.
_Avoid_: rule, policy, test, control

**Policy**:
A Kyverno object that implements one or more checks. Renameable and splittable without affecting any check's identity.
_Avoid_: check, rule

**Observation**:
What one check said about one subject at one point in time. Carries Kyverno's five-state outcome (`pass`, `fail`, `warn`, `error`, `skip`).
_Avoid_: result, finding, verdict

**Determination**:
Whether a control is satisfied for a canonical subject: `satisfied`, `not-satisfied`, or `undetermined`. Derived from observations, never observed directly.
_Avoid_: result, verdict, status, finding

**Undetermined**:
A determination state meaning the evidence does not support a verdict — a check was skipped, errored, or never reported. Distinct from both `satisfied` and `not-satisfied`, and not expressible in OSCAL.
_Avoid_: unknown, error, n/a, not-applicable

### Subjects

**Reported resource**:
The Kubernetes object Kyverno emitted a result against. Observations attach here. Kyverno's autogen means one workload violation surfaces against many reported resources.
_Avoid_: subject, resource, target

**Canonical subject**:
The stable object a determination is made about — the owning workload where one exists (Deployment, StatefulSet, DaemonSet, CronJob), otherwise the reported resource itself. Identified by `kind`+`namespace`+`name`, from which the OSCAL `subject-uuid` is derived as a UUIDv5.
_Avoid_: subject, workload, owner

### Frameworks and mapping

**Control**:
A requirement defined by a framework, such as CCM `I_S-04`. Satisfied by one or more checks, only ever through a mapping.
_Avoid_: requirement, rule, policy

**Framework**:
A named body of controls, such as CCM v4.1.0 or NIST SP 800-53 rev5. A view over checks. A framework is never defined in terms of another framework.
_Avoid_: standard, catalog, baseline, regime

**Mapping**:
An authored, human-ratified set of check→control edges. The only path by which a check satisfies a control. There is deliberately no control→control edge, which makes inheriting a verdict across a framework crosswalk unrepresentable rather than merely discouraged.
_Avoid_: crosswalk, binding, link

**Crosswalk**:
A published correspondence between two frameworks' controls, such as CSA's CCM→800-53 file. An **authoring aid** used to narrow the search space when writing a mapping. Never evaluated at runtime and never a source of satisfaction.
_Avoid_: mapping

### Coverage

**Expected coverage**:
The set of check × canonical-subject pairs Konstapel expected to observe in an assessment run. Reconciled against what was actually received, because Kyverno degrades to silence rather than to errors.
_Avoid_: scope, plan, inventory

**Shortfall**:
The difference between expected coverage and received observations. Shortfall makes affected controls `undetermined`; it never leaves them reading as satisfied.
_Avoid_: gap, miss, drift

## Rules that follow from the language

- **A check satisfies a control only through a mapping edge.** There is no other path, and no control→control edge exists.
- **Determination is computed**: any `fail` → `not-satisfied`; else any unevaluated check → `undetermined`; else `satisfied`. A confirmed failure outranks missing evidence.
- **Absence is never satisfaction.** A missing observation makes a determination `undetermined`, never `satisfied`.
- **Check identity is independent of Kyverno.** Renaming, splitting, or migrating a policy between the legacy and CEL generations does not change any check's identity.
