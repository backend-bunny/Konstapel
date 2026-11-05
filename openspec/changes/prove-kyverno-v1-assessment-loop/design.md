# Design

## Context

See [proposal.md](proposal.md) for the motivation and
[the capability specification](specs/kyverno-assessment-loop/spec.md) for the
behavior contract. The repository currently contains documentation and OpenSpec
planning files, with no Go module or runtime implementation.

The agreed direction is Go, C2P-Go v2, NIST SP 800-53 Rev. 5 Moderate, and Kyverno
as the first policy engine. Konstapel ships the policy content and mappings;
Kyverno performs enforcement. Initial operation targets its own cluster, with
cluster identity kept explicit for future multi-cluster support. Only
`policies.kyverno.io/v1` policy resources are in scope.

Research identified these concrete constraints:

- The selected upstream policy declares Kyverno 1.19.1 as its minimum and uses
  CEL features, workload-template matching, and policy exceptions.
- C2P-Go v2's existing Kyverno generator copies policy directories, but its result
  adapter loads legacy policy types, only searches the namespaced report list,
  and assigns the current time to source evaluations.
- The researched C2P revision uses Go 1.25.7 and OSCAL 1.1.3 model types. The
  current NIST reference snapshot declares OSCAL 1.2.3. Their compatibility must
  be handled explicitly rather than by relabeling or silently rewriting content.

## Goals / Non-Goals

**Goals:**

- Establish a repeatable integration contract through a minimal Go runner and
  a C2P-compatible Kyverno provider executable.
- Separate policy delivery, observation collection, and evidence conversion so
  those parts can later be called from a controller reconciler.
- Preserve raw evidence and source identities so conversion can be tested
  independently of cluster availability.

**Non-Goals:**

- Define the production Kubernetes API, controller scheduling, or evidence store.
- Build a general OSCAL authoring or profile-resolution service.
- Implement cluster registration, fleet aggregation, or automatic remediation.

## Decisions

### 1. Prove the loop with a small runner before defining CRDs

Use a Go executable to coordinate loading content, invoking C2P, delivering one
policy, collecting reports, and exporting results. Exercise the C2P v2 external
plugin protocol in the prototype, including plugin startup and failures.

The runner takes an explicit target configuration and output directory. Its
cluster client is supplied to the delivery and collection components; those
components do not independently select a kubeconfig context. The same boundary
can later accept an in-cluster client.

A full controller scaffold would couple the experiment to unresolved API and
ownership decisions. A shell-only demonstration would leave the Go and plugin
integration unproven. The small runner establishes that integration directly.

### 2. Pin content and preserve upstream files

Use these starting revisions:

| Input | Starting revision or version |
| --- | --- |
| C2P-Go v2 | `45bfc1a8947e8b56b7e11391e13f8c1f2136cfaa` |
| `kyverno/policies` | `fac1ccda72ab53594921ca1c040ac90b80afadcd` |
| Kyverno runtime and CLI | `1.19.2` |
| NIST `oscal-content` | `f0de6d8d8c059d374f15e0ae07508d82e370fc1d` |

Record the resolved Go pseudo-version, toolchain, Kubernetes test version, chart
version, image digests, OSCAL schemas, and source checksums during environment
setup. Commit those selections with the implementation so reruns do not follow
moving branches or floating image tags.

Keep the vendored policy and applicable upstream fixtures identifiable as their
original sources. Put mode selection, test-namespace scoping, and other local
configuration in a separate rendering layer. Copy the Apache-2.0 license and
applicable notices; identify any modified upstream files. The content manifest
records both the source checksum and the rendered policy checksum.

Vendoring a selected policy with tests makes review and offline inspection
possible. Downloading the latest policy on each reconciliation would prevent
repeatable behavior. Copying the whole policy library would expand the first
milestone beyond the chosen check.

### 3. Map one check to a bounded part of AC-6

Use `ac-6` (Least Privilege) and its statement `ac-6_smt`. Both identifiers exist
in the researched NIST catalog, and the Moderate profile explicitly includes
`ac-6`. The mapping rationale is that prohibiting privileged containers reduces
unnecessary privileges for workload processes. This check provides partial
technical evidence; it does not assess authorization, all process privileges,
organizational procedures, or the rest of the control.

Author a Component Definition using C2P's rule/check conventions. Keep the
logical rule and check identity stable and explicitly relate them to the applied
policy identity. Include the rationale and partial-coverage statement in both
the shipped mapping and the assessment context.

Preserve the official NIST catalog and profile at their declared version. Verify
the selected control and statement against those source documents, including
the profile's referenced catalog. Author C2P input and generated assessment
artifacts using its supported OSCAL 1.1.3 model, and validate each document
against its own declared schema. Do not round-trip the full 1.2.3 catalog through
older model structs. Only the selected mapping and scope are supplied to C2P.

The output includes the Assessment Plan and any supporting context required by
the chosen OSCAL models, with meaningful references. A passing technical
observation does not become a full-control satisfaction claim. Absence of a
negative finding also does not establish compliance.

This explicit mapping is preferable to treating Kubernetes Pod Security
Standards as equivalent to the NIST Moderate baseline.

### 4. Let Kyverno own enforcement and configure its supported behavior

Render `validationActions: [Deny]` by default, allow explicit `[Audit]`, and retain
background evaluation. Validate prerequisites and wait for the applicable policy
readiness conditions before testing admission. Report delivery, readiness,
admission outcomes, and assessment completeness separately.

The prototype manages its own test policy and fails on a conflicting resource
it does not own. It scopes integration fixtures to a dedicated test namespace.
It does not delete or mutate existing violating workloads as remediation.

Admission denial and background assessment are separate evidence channels. A
rejected resource creation has no persisted resource UID and need not produce
a PolicyReport. Verify rejection using the actual Kubernetes API response and
policy-specific reason. Use admitted, existing resources for background evidence.

Implementing a second admission webhook inside Konstapel would duplicate the
policy engine's responsibility and is not part of this design.

### 5. Adapt the C2P provider boundary for modern Kyverno reports

Implement a focused provider executable using C2P v2's public plugin interfaces.
Reuse the upstream generation approach for the vendored policy; implement report
conversion without importing C2P's internal packages or requiring legacy policy
objects. Register the provider consistently with the Component Definition's
validation component so C2P cannot silently skip it.

The runner captures the current `ValidatingPolicy`, raw PolicyReports and
ClusterPolicyReports, expected fixture inventory, and run metadata. The provider
consumes that captured input and produces C2P observations. Decode the actual
report API/schema served by the pinned runtime, with fixtures for both report
scopes and explicit handling of unsupported layouts.

Preserve source result, reason, evaluation timestamp, and resource UID. Normalize
unsupported result states to a documented non-passing state while retaining the
original value. Handle report-level resource scope as well as result-level
resource references according to the observed schema. Search both report lists;
do not reproduce the existing adapter's omission of cluster-scoped results.

Use an explicit cluster identity, derived for the prototype from the
`kube-system` namespace UID, and a composite cluster/resource identity when
passing subjects into C2P. Retain the original Kubernetes UID separately. This
prevents collisions when the same conversion code later receives multiple
clusters' observations without introducing remote-cluster management now.

A dedicated provider keeps the experimental dependency boundary small. A full
C2P fork would increase maintenance scope, while pretending the new resources
are legacy policies would obscure compatibility gaps.

### 6. Treat completeness and freshness as inputs to assessment

Build the expected check/resource inventory from the selected mapping and the
test resources actually admitted to the cluster, independently of report
contents. Denied creations are not expected background subjects.

Associate observations with the current resource UID, applied policy identity,
and the stable policy/configuration revision for the run. Establish an evaluation
boundary after policy readiness and relevant fixture changes. Require suitable
source timestamps and matching identities; if the report cannot establish that
association, keep the observation incomplete. Poll for evidence within a bounded
timeout instead of converting an empty result set into success.

Write raw captures and a run manifest alongside the OSCAL output. The manifest
records cluster identity, expected observations, missing or rejected evidence,
source and rendered content digests, and collection time. Link that context from
the assessment artifact and preserve available source evaluation times separately.
Verify the C2P export retains the required metadata; add it at the export boundary
when the core transformation does not carry a field through.

This prototype uses controlled, quiescent test runs. A production solution for
continuous report-to-policy revision correlation will require a later design;
the prototype must report ambiguity rather than infer freshness from collection
time alone.

### 7. Validate admission and assessment in a disposable cluster

Use a pinned kind-based test environment with Kyverno, the necessary reporting
permissions, and a namespace whose admission configuration permits the controlled
privileged fixture. Seed one privileged Pod before installing the test policy.

Then deliver the rendered policy, wait for readiness, admit a compliant workload,
and reject privileged Pod/Deployment requests and applicable updates. Retain the
relevant upstream CLI and Chainsaw tests for workload templates, init containers,
and ephemeral-container updates. Background reports must show the existing
violation and the compliant resource, with the original violating Pod still
present.

Convert the captured results through the C2P provider and validate the generated
OSCAL artifacts, source references, partial coverage, and result identities.
Exercise missing, stale, malformed, and non-passing report fixtures separately.
An acceptance run succeeds only when all required phases and evidence checks
pass; evidence files remain available for diagnosing failures.

## Risks / Trade-offs

- **Experimental C2P APIs and older Kyverno adapter assumptions:** pin the core,
  exercise the public plugin boundary, and keep adapter behavior covered by
  report fixtures and a live integration test.
- **Different OSCAL versions:** validate official source documents and generated
  artifacts separately; preserve source content and fail on unresolved mappings
  or unsupported semantics instead of silently dropping fields.
- **Sample annotations are not runtime proof:** use the declared minimum as a
  prerequisite and verify the selected Kyverno/CLI/Kubernetes combination.
- **Asynchronous reporting or stale observations:** use bounded polling, resource
  identity, explicit evaluation boundaries, and incomplete outcomes.
- **An unrelated admission failure is mistaken for policy enforcement:** check
  policy readiness and the exact denial reason, and ensure the fixture namespace
  permits the pre-policy test resources.
- **One check appears to establish full compliance:** retain partial-coverage
  language in machine-readable assessment context and test the absence of a
  full-control or baseline satisfaction claim.

## Migration Plan

There is no deployed implementation or stored state to migrate. Introduce the
prototype and pinned content as the first implementation. Run acceptance in a
disposable cluster and clean up only the test-owned policy and fixtures. Retain
run artifacts for review. A failed experiment is rolled back by removing its
test resources or deleting the disposable cluster; it does not require changes
to a production cluster.

## References

- [Selected policy and upstream tests](https://github.com/kyverno/policies/tree/fac1ccda72ab53594921ca1c040ac90b80afadcd/pod-security-vpol/baseline/disallow-privileged-containers)
- [C2P Kyverno result adapter](https://github.com/oscal-compass/compliance-to-policy-go/blob/45bfc1a8947e8b56b7e11391e13f8c1f2136cfaa/cmd/kyverno-plugin/server/result2oscal.go)
- [C2P report conversion and OSCAL model](https://github.com/oscal-compass/compliance-to-policy-go/blob/45bfc1a8947e8b56b7e11391e13f8c1f2136cfaa/framework/actions/report.go)
- [NIST catalog and Moderate profile](https://github.com/usnistgov/oscal-content/tree/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json)
