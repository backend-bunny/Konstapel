# Next policy bundle research

Research date: 2026-11-05. Scope: the five requested candidates, exclusively
`policies.kyverno.io/v1` `ValidatingPolicy` resources and their v1
`PolicyException` examples. This is a research recommendation, not an approved
control implementation or a change to the assessment-loop plan.

## Recommendation and ranking

Recommend a Linux workload-hardening bundle containing the four Restricted
candidates, introduced in the order below after the assessment loop is proven.
Treat approved image registries as a separate, configuration-dependent follow-up.
The ranking weighs bounded behavior, usefulness alongside the existing privileged
container check, operational prerequisites, and quality of available evidence;
it does not count policies as independent satisfaction of NIST controls.

| Rank | Candidate | Reason and release condition |
| --- | --- | --- |
| 1 | `disallow-privilege-escalation` | Small explicit requirement, directly complements the privileged-container check, and has a straightforward partial AC-6 rationale. Validate Linux runtime behavior with privilege and capability restrictions in place. |
| 2 | `disallow-capabilities-strict` | Restricts another concrete source of process privilege. Requires workload capability inventory; preserve `drop: ALL` even with fine-grained exceptions. Extend tests against the shipped combined policy because the upstream suite also tests a helper policy. |
| 3 | `require-run-as-nonroot` | Valuable process-identity restriction, but image user compatibility and the unconditional `hostUsers: false` exemption require an explicit scope decision. It checks intent, not observed UID. |
| 4 | `restrict-seccomp-strict` | Useful syscall-filter configuration evidence, but profile type alone says little about effective syscall restrictions. Validate runtime support and any Localhost profiles on every applicable node. |
| 5 | `restrict-image-registries` | Useful approved-source restriction after operators define registry ownership and an allowlist. Sample prefixes are unusable defaults, and allowed registries do not establish authorized software, provenance, or integrity. |

Use the four hardening checks as complementary evidence for bounded parts of
AC-6, CM-6, and CM-7. Do not call this a complete Kubernetes Restricted profile,
NIST Moderate bundle, or full-control compliance assessment. All recommendations
and NIST mappings below are proposed; upstream behavior and test outcomes are
identified separately.

## Immutable sources, license, and evidence method

All five candidates were downloaded and inspected at the same immutable
[`kyverno/policies` revision `fac1ccda72ab53594921ca1c040ac90b80afadcd`](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd),
aligning with the existing design's research pin. This is a reproducible research
snapshot, not a claim that it is the latest or that every sample is deployable.
Do not follow the moving `main` install URLs in Artifact Hub metadata.

The repository's pinned [LICENSE](https://github.com/kyverno/policies/blob/fac1ccda72ab53594921ca1c040ac90b80afadcd/LICENSE)
is Apache-2.0 and applies to the selected policies and fixtures. No NOTICE file
was found in this snapshot. Future vendoring should retain the license and
applicable attribution/notices and identify modifications. Artifact Hub package
version `1.0.0` and creation dates do not replace a source revision or checksum.

Each directory link below includes the actual policy, Artifact Hub description,
CLI manifests/fixtures, and Chainsaw manifests/fixtures. Hidden test directories
are part of the source tree.

| Candidate and immutable directory | Policy YAML SHA-256 |
| --- | --- |
| [disallow-privilege-escalation](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/restricted/disallow-privilege-escalation) | `8298294ae338afca75bd016a327d9b64343344d3f10421134ca6e2351c0589ea` |
| [require-run-as-nonroot](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/restricted/require-run-as-nonroot) | `5276cb3c4f3d782604334d40cb40e659ee5d9ffefb190b9d52ab880e74bbb3b8` |
| [disallow-capabilities-strict](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/restricted/disallow-capabilities-strict) | `30d3ffefc63a00badbf7e5805f0c14709ac8c146b11260415b92e768a5fd4830` |
| [restrict-seccomp-strict](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/restricted/restrict-seccomp-strict) | `fd22b77d67e01e17e4f0083f605736adce25f4a4486e90879a3350a9e918b0ac` |
| [restrict-image-registries](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/best-practices-vpol/restrict-image-registries) | `70b046af34e53957db096fab6ee9f4d622c3a66bee80bb99493f6bd714e83347` |

### Executed checks

Downloaded the [Kyverno CLI 1.19.2 Linux x86-64 release archive](https://github.com/kyverno/kyverno/releases/download/v1.19.2/kyverno-cli_v1.19.2_linux_x86_64.tar.gz).
`kyverno version` reported `1.19.2`, commit
`e63308f1e16c05cd009ac4864be6ec25c66b49be`, build time
`2026-10-20T22:13:49Z`. Downloaded archive SHA-256:
`357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a`.
This records the downloaded bytes; independent release signature verification
was not performed.

Executed the following command separately for each candidate's entire directory,
with unmodified upstream policies, fixtures, and exceptions:

```sh
kyverno test "$UPSTREAM_CANDIDATE_DIRECTORY" --require-tests --remove-color
```

| Candidate | CLI expected-result checks matched | Failed | Discovered CLI suites |
| --- | ---: | ---: | --- |
| `disallow-privilege-escalation` | 50 | 0 | `.kyverno-test`, `.kyverno-test-controllers`, `.kyverno-test-exceptions` |
| `require-run-as-nonroot` | 113 | 0 | Those three plus `.kyverno-test-regressions` |
| `disallow-capabilities-strict` | 156 | 0 | `.kyverno-test`, `.kyverno-test-controllers`, `.kyverno-test-exceptions` |
| `restrict-seccomp-strict` | 78 | 0 | `.kyverno-test`, `.kyverno-test-controllers`, `.kyverno-test-exceptions` |
| `restrict-image-registries` | 19 | 0 | `.kyverno-test`, `.kyverno-test-scope` |

A matched check can be an expected policy failure or skip. These numbers mean
agreement with test expectations, not that all resources were compliant.
The capabilities total includes the upstream v1 `adding-capabilities-strict`
helper, which checks only added capabilities and has Pod-only match rules;
it is a test aid, not a sixth bundle candidate or the shipped combined policy.

Also executed SHA-256 calculation, a `jq -e` assertion that every control in the
mapping table is explicitly included by the Moderate profile, and an assertion
that every mapped statement exists in its resolved catalog. Both assertions
returned `true`. Read the original catalog statement prose and the profile's
back-matter catalog reference as well.

**Not executed:** Chainsaw, Kubernetes admission/update requests, background
report collection, container execution, node/runtime checks, C2P conversion,
OSCAL schema validation, or a Kubernetes/Kyverno compatibility matrix. No live
cluster was changed. Logs and downloaded tools were temporary research inputs;
this document is the sole repository deliverable. Re-run tests and retain raw
artifacts with the implementation rather than treating this narrative as its
acceptance record.

## Shared behavior and prerequisites from source

All five source policies default to `validationActions: [Audit]` and enable
background evaluation. Their expressions identify violations; the stock policies
do not deny admission. Enforcement requires an explicit rendered `[Deny]` mode
and a ready Kyverno policy. Background evaluation does not remediate existing
resources or prove their running processes satisfy the configuration.

Every candidate explicitly matches CREATE and UPDATE for core/v1 Pods and
ReplicationControllers, apps/v1 Deployments, DaemonSets, StatefulSets and
ReplicaSets, and batch/v1 Jobs and CronJobs. Every candidate also explicitly
matches UPDATE of core/v1 `pods/ephemeralcontainers`. The expressions inspect
regular, init, and ephemeral containers, including templates selected from
controllers and CronJob job templates. This is explicit matching, not a claim
of legacy ClusterPolicy autogeneration. The four Restricted controller suites
contain negative fixtures for all seven controller kinds; the registry suite
also contains negative fixtures for all seven.

There is no source namespace selector: matching is cluster-wide unless rendering
or engine configuration narrows it. DELETE, other subresources, custom workload
kinds, node processes, and arbitrary software installation are outside the
explicit match set. Static Pod execution is not established by admission checks
on API objects. Engine-wide exclusions, webhook configuration, other admission
controllers, and resource mutation can affect effective coverage and must be
recorded. Background behavior and report granularity for these kinds/subresources
remain live-validation questions.

All five declare `policies.kyverno.io/minversion: 1.19.1`. The four Restricted
policies also retain `kyverno.io/kyverno-version: 1.14.0`; that older descriptive
annotation must not override the declared minimum. Their Kubernetes annotation
is `1.30+`; the registry policy's is `1.30`. These are **confirmed source
annotations**, not executed minimum-version compatibility results. CLI 1.19.2
passed locally; no Kubernetes version was tested. Use the assessment loop's
Kyverno/CLI 1.19.2 target initially, pin the actual Kubernetes/chart/images, and
verify the served v1 CRDs, CEL optional access, exception support, runtime support,
and admission/report controllers on that combination before shipping.

Fine-grained exception fixtures use `policies.kyverno.io/v1` `PolicyException`,
`spec.policyRefs` naming the ValidatingPolicy, and match conditions constrained
by namespace and resource identity. Source expressions consume
`exceptions.allowedImages` and, for capabilities/seccomp, `exceptions.allowedValues`.
The Restricted suites also contain exceptions without images/values, expected
to skip the whole policy. Those expectations matched in the CLI run; live
exception enablement, namespace restrictions, propagation, and reporting remain
unverified. Do not ship sample exceptions. Any approved exception needs bounded
scope, authorization, reason, owner, review/expiry, and evidence that distinguishes
waived checks from unexceptional compliance. A partial exception can produce a
policy pass while allowing a prohibited value.

## Candidate assessments

### 1. disallow-privilege-escalation

**Inspected behavior:** each container must explicitly set
`securityContext.allowPrivilegeEscalation: false`. Missing values default to
`true` in the expression and fail. Pod-level security context supplies no
inheritance for this field. `spec.os.name: windows` bypasses the validation;
missing OS is checked normally. An exact image entry in a matching exception
waives this container check, leaving other containers checked. A whole-policy
exception is expected to skip.

**Tests:** CLI fixtures cover compliant/noncompliant Pods, Deployments, CronJobs,
container classes, Windows cases, all controller kinds, and partial/wrong/sibling/
whole exceptions. Inspected Chainsaw tests switch to Deny, wait for readiness,
assert policy-specific Pod/controller rejection, then test a live ephemeral
update rejection, an image exception, and a non-exempt sibling rejection. These
Chainsaw steps were not executed.

**Proposed mappings:** primary `ac-6` / `ac-6_smt`; secondary
`cm-6` / `cm-6_smt.b`. Blocking configured privilege escalation supports limiting
workload-process privilege and implementing one secure configuration setting.
Partial coverage: it does not determine necessary/authorized access, inspect
RBAC, prohibit initial root identity or privileged containers, or observe kernel
privilege transitions. Configuration alone is not proof of effective
`no_new_privs`; validate it with runtime tests alongside privileged-container and
capability restrictions. It supplies no evidence for all AC-6 requirements or
CM-6 documentation, deviation approval, and organizational change control.

**Required configuration and remaining validation:** set false on every Linux
container class; choose scope, Audit/Deny rollout and exception governance.
Validate omitted/true/false cases, Windows bypass, template and ephemeral UPDATE
handling, effective runtime behavior, and reports for existing violations.

### 2. disallow-capabilities-strict

**Inspected behavior:** two validations require each Linux container's
`capabilities.drop` list to contain exact `ALL`, and permit only exact
`NET_BIND_SERVICE` entries in `capabilities.add` by default. Missing drop fails;
missing add is empty and passes. There is no Pod-level capabilities inheritance.
Explicit Windows Pods bypass both expressions. Matching `allowedValues` permits
additional exact capability names; matching image exceptions bypass the added
capabilities check only. Neither fine-grained mechanism waives `drop: ALL`.
Whole-policy exceptions can skip both validations.

**Tests:** executed CLI cases include the combined policy's drop requirements,
selected added-capability cases, controller coverage and exceptions, plus the
separate helper's added-capability matrix. Inspected Chainsaw covers Deny,
readiness, Pod/controller rejection, ephemeral rejection, matching image exception,
and sibling rejection. Live execution and a full add/drop cross-product against
the actual combined policy remain outstanding.

**Proposed mappings:** primary `ac-6` / `ac-6_smt`; secondary
`cm-7` / `cm-7_smt.b` and `cm-6` / `cm-6_smt.b`. Dropping defaults and restricting
re-added capabilities bounds process privilege and selected kernel functions.
Partial coverage: `NET_BIND_SERVICE` is allowed without proving each workload
needs it; exceptions can add powerful capabilities. This checks declared lists,
not effective capability sets or all privileged execution paths, host privileges,
authorization, or the full list of restricted system functions. It does not
establish the organization-defined CM-7 restrictions by itself.

**Required configuration and remaining validation:** inventory necessary
capabilities; explicitly drop ALL; allow NET_BIND_SERVICE only where operationally
justified, and approve any exception values. Test both combined validations,
image exceptions that still fail missing drop, case sensitivity, all container
classes, Windows handling, effective runtime capability sets, and report identities
for the two validations under one policy.

### 3. require-run-as-nonroot

**Inspected behavior:** absent Pod-level `runAsNonRoot` does not itself fail, but
each non-exempt container must set true or inherit Pod-level true. Pod-level
false fails even if every container explicitly sets true or has an image exception.
Container-level false overrides inherited true and fails unless that container's
image is exempt. Missing/null init and ephemeral lists are explicitly normalized
to empty lists. **`spec.hostUsers: false` bypasses the entire expression**, including
explicit false at either security-context level. There is no Windows bypass.
No `runAsUser` value or image metadata is inspected.

The source description calls the user-namespace exemption consistent with PSS
v1.35 and later and notes older Pod Security Admission differs. Confirmed here:
the CEL exemption is unconditional on Kubernetes version. Its equivalence to PSS
and effective user-namespace isolation were not independently runtime-tested.
The `1.30+` annotation does not imply PSA parity, available feature gates, or
support from the selected container runtime.

**Tests:** executed CLI cases cover inheritance, overrides, explicit Pod false,
user-namespace exemptions on Pods/templates, container classes, controller kinds,
and exceptions. The dedicated regression suite checks null container lists and
root configurations including Windows. Inspected Chainsaw tests Deny/readiness,
Pod/controllers and ephemeral image-exception/sibling behavior; it does not
establish root-image startup or user-namespace isolation.

**Proposed mappings:** primary `ac-6` / `ac-6_smt`; secondary
`cm-6` / `cm-6_smt.b`. Requiring a nonroot process intent reduces default privilege
for application processes. Partial coverage: a true flag does not report actual
UID, supplementary groups, file permissions, or necessary authorizations. A
root image may pass admission with true and then fail startup. Exempt
user-namespace Pods can run namespace-root; describe those as outside this
nonroot check's coverage, with isolation evidence needed separately. Avoid an
AC-6(2) claim: this policy does not check users' nonsecurity duties or their use
of nonprivileged accounts/roles.

**Required configuration and remaining validation:** choose and document whether
to accept the upstream hostUsers exemption or propose a separately reviewed
rendered variant; validate feature gates, nodes and runtime before relying on it.
Select compatible nonroot images and explicit/container-inherited true settings.
Test startup and observed UID, conflicting `runAsUser: 0`, OS behavior, null lists,
all container classes, exceptions with Pod-level false, and pre-existing-resource
reports. Record any variant as changed upstream behavior with new tests/digests.

### 4. restrict-seccomp-strict

**Inspected behavior:** Pod profile type can be absent or one of RuntimeDefault/
Localhost. Each container must set an allowed type or inherit an allowed Pod
type; no type at either level fails. An invalid Pod-level type fails even if all
containers explicitly specify valid types. Windows bypasses both validations.
Exact exception tokens `seccomp.type:<value>` allow that profile type at Pod or
container level. Exact image exceptions waive type restrictions only on containers
with an explicit type: they do not waive a missing type or an invalid Pod type.
Localhost is permitted despite the error message saying custom profiles are
disallowed. The CEL does not inspect `localhostProfile`, profile contents,
existence, or effective syscall filtering.

**Tests:** CLI tests cover type selection/inheritance, missing/invalid types,
Windows, container classes, controllers, and exception/sibling/whole-skip cases.
Inspected Chainsaw tests Deny/readiness, Pods/controllers, and ephemeral image
exceptions. No executed test checked local profile files or runtime enforcement.

**Proposed mappings:** primary `cm-7` / `cm-7_smt.b`; secondary
`cm-6` / `cm-6_smt.b`. Requiring a filter profile type supports restriction of
selected syscall functionality and implementation of a secure setting. This is
conditional evidence: RuntimeDefault differs by runtime, and Localhost could
allow nearly everything. Partial coverage excludes profile quality, prohibited
function definitions, node deployment and integrity, effective filter attachment,
and functions outside seccomp. Do not infer software integrity or a complete
sandbox from the allowed type.

**Required configuration and remaining validation:** prefer RuntimeDefault as an
initial operational standard, without claiming the unmodified policy requires
it exclusively. If Localhost is used, define approved contents and deployment
on every applicable node; assess those separately. Test inheritance/override
cases, invalid Pod types with otherwise good containers, precise exception
semantics, Windows, runtime profile attachment and a prohibited syscall, and
background reports.

### 5. restrict-image-registries

**Inspected behavior:** every regular/init/ephemeral image string must start
with literal `eu.foo.io/` or `bar.io/`, or equal an image in a matching exception.
No Windows bypass, registry lookup, parser, image normalization, signature,
digest, vulnerability, or provenance check is present. Unqualified references
and strings without the accepted prefixes fail. The trailing slash prevents a
simple `bar.io.evil/` lookalike from matching, but the logic is case-sensitive
and does not automatically accept a port-qualified registry. Any repository,
tag or digest under an allowed prefix is permitted. This is the basic
`best-practices-vpol` candidate, not `advanced-restrict-image-registries`.

**Tests:** executed CLI fixtures cover missing/unknown registries, mixed
containers, positive and negative image exceptions, all seven controller kinds,
and identical names in different namespaces (scope suite). Inspected Chainsaw
checks Deny/readiness, Pod rejections and ephemeral debug rejection, with RBAC
for admission and reports. Its debug step accepts any command failure as a
successful negative test; an RBAC, API, or target error could satisfy it. Add
policy-specific denial assertions before using it as enforcement evidence.
The suite's forced namespace-wide Pod cleanup also requires isolation before
live reuse. Neither behavior was executed here.

**Proposed mappings:** primary `cm-11` / `cm-11_smt.b`, conditional on treating
container image deployment by users as governed software installation; secondary
`cm-6` / `cm-6_smt.b`. Enforcing an organization-approved image-source list can
implement one installation policy and one configuration setting. Partial
coverage excludes software installed later inside containers, node software,
all user installation channels, and installation approval procedures.

Optional future mapping: `cm-7.5` / `cm-7.5_smt.b` (CM-7(5), Authorized Software),
**not recommended as direct coverage with this policy alone**. A registry
allowlist is coarser than a list of authorized programs: approval of registry
custody must not imply approval of every stored image. Consider this only with
separate evidence that approved registry contents correspond to authorized
software and that other execution paths are controlled. It does not check list
identification/review, actual execution, or integrity. Do not map it directly to
SI-7 or SR-11 based on the sample description's security claims.

**Required configuration and remaining validation:** replace both fictional
prefixes with an explicitly approved allowlist, define registry ownership,
repository boundaries, ports/mirrors and unqualified-name handling, and record
source/rendered revisions. Test altered prefixes, hostname lookalikes, ports,
case, tags/digests, all controller/container classes, exception scope/siblings,
actual pulls/mirrors, and exact admission denial reasons. Document mutable-tag,
registry-compromise and post-start installation gaps. Sample configuration must
never silently become an operational default.

## Proposed NIST mappings and verified Moderate inclusion

NIST sources were downloaded at immutable
[`usnistgov/oscal-content` revision `f0de6d8d8c059d374f15e0ae07508d82e370fc1d`](https://github.com/usnistgov/oscal-content/tree/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json):

- [Original Rev. 5 catalog](https://github.com/usnistgov/oscal-content/blob/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json), content version `5.2.0`, OSCAL `1.2.3`.
- [Moderate profile](https://github.com/usnistgov/oscal-content/blob/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json).
- [Resolved Moderate catalog](https://github.com/usnistgov/oscal-content/blob/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json).

The profile imports a back-matter resource with UUID
`84cbf061-eb87-4ec1-8112-1f529232e907`; its JSON link resolves to the original
catalog above. This is a reference-resource UUID, not the catalog UUID.
Inclusion was checked against `imports[].include-controls[].with-ids`, rather
than inferred from the base control or a secondary mapping website. Statements
were checked in both original prose and the resolved Moderate catalog.

| Proposed control / exact OSCAL statement | Moderate inclusion (confirmed) | Statement meaning and proposed use |
| --- | --- | --- |
| AC-6 / `ac-6_smt` | Explicit `ac-6`; statement present | Employ least privilege for users/processes, allowing only necessary authorized access. Primary for escalation, capabilities, nonroot. |
| CM-6(b) / `cm-6_smt.b` | Explicit `cm-6`; statement present | “Implement the configuration settings.” Secondary bounded setting evidence for all five, after organizational settings are established. |
| CM-7(b) / `cm-7_smt.b` | Explicit `cm-7`; statement present | Prohibit/restrict organization-defined functions, ports, protocols, software and/or services. Capabilities and seccomp cover selected process/kernel functions only. |
| CM-11(b) / `cm-11_smt.b` | Explicit `cm-11`; statement present | Enforce software installation policies through organization-defined methods. Primary for registries only when workload deployment falls within that policy. |
| CM-7(5)(b) / `cm-7.5_smt.b` | Explicit enhancement `cm-7.5`; statement present | Deny-all, permit-by-exception execution of authorized software. Optional registry mapping requiring additional authorization/execution evidence; defer direct claim. |

Moderate membership and statement identity are confirmed source facts.
Policy-to-statement relationships are authored proposals requiring assessment
review; NIST and Kyverno do not certify these mappings. Organization-defined
parameters and tailoring remain decisions for the compliance owner. Parameter
selection, establishing/documenting settings, deviation approvals, and review
frequencies are not measured by these CEL checks. Audit observations may support
assessment of settings; CM-11 enforcement claims require Deny plus actual
admission evidence and a defined installation-policy scope.

Preserve partial-coverage rationale in future machine-readable mappings and
assessment context. A shared control with several checks is not several fully
satisfied controls. Do not convert pass, policy delivery, exception skip, missing
evidence, or stale reports into full-control or Moderate-baseline satisfaction.
Keep official OSCAL 1.2.3 source content identifiable; compatibility with C2P's
planned OSCAL 1.1.3 models remains the assessment-loop agent's validation task.

## Validation gates before adopting the recommendation

1. Resolve operational scope: Linux/Windows, user namespaces, approved settings,
   registry configuration and exceptions. Record each source and rendered digest,
   mode and scope; preserve upstream fixtures and applicable license material.
2. Verify the pinned Kyverno/Kubernetes combination, v1 CRDs and readiness,
   exception configuration, ephemeral-container admission/report RBAC, engine
   exclusions and interaction with Pod Security Admission. Separate upstream
   annotations, CLI results, and live compatibility evidence.
3. Re-run CLI fixtures against the rendered artifacts. Add only meaningful gaps:
   combined capability matrix, exception edge cases, registry parser/prefix
   boundaries, OS/user-namespace behavior, and any changed scope or expression.
4. Run adapted Chainsaw tests in a disposable isolated cluster, with exact
   policy-denial reasons. Exercise CREATE, normal applicable UPDATE, controller
   templates, and ephemeral subresource UPDATE. Distinguish policy rejection
   from other admission, RBAC, startup or scheduling failures.
5. Seed violations before policy installation and observe background evidence
   without remediation. Verify report scopes, validation identity, resource UID,
   timestamp/freshness and exception outcomes. Denied creates need admission
   evidence and need not generate persisted-resource background reports.
6. Add runtime observations where configuration is insufficient: effective
   privilege transitions, capability sets, UID/user-namespace isolation, seccomp
   attachment/filter behavior, and image-source resolution. A passing CEL check
   does not substitute for these observations.
7. Have the assessment owner review proposed mappings, resolve relevant
   organization-defined parameters, and validate report-to-OSCAL conversion,
   source links, independent check identities and partial coverage after the
   assessment-loop implementation establishes that path.

Implementation, vendoring, mapping artifacts and the existing OpenSpec change
remain with the assessment-loop agent. This research changes only this document.
