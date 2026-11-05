# Tasks

## 1. Establish the pinned integration environment

- [ ] 1.1 Create the Go module and minimal integration runner, pin C2P-Go v2 to the design's revision, and record the required toolchain; verify dependency resolution and that the runner builds.
- [ ] 1.2 Define a disposable kind environment with Kyverno 1.19.2 and matching CLI, recording Kubernetes, chart, tool, and image versions or digests; verify API discovery serves `policies.kyverno.io/v1` and the required reporting resources.
- [ ] 1.3 Document environment creation, explicit context selection, prerequisites, and teardown; verify the documented smoke workflow reaches ready Kyverno controllers and affects only the selected disposable cluster.

## 2. Ship the first policy and bounded OSCAL mapping

- [ ] 2.1 Vendor `disallow-privileged-containers` and relevant upstream CLI/Chainsaw fixtures from the design's pinned revision, with license, notices, provenance, and checksums; verify the manifest digest and new policy API against the source.
- [ ] 2.2 Retain the pinned NIST catalog/profile as authoritative inputs and author the C2P Component Definition and scoped assessment context for `ac-6` / `ac-6_smt`; verify profile membership, reference resolution, and the partial-coverage rationale without rewriting the NIST documents into an older OSCAL version.
- [ ] 2.3 Add validation for the mapping and its declared schema, including an invalid-control reference case, and run the vendored policy's CLI cases; verify bad references fail and permitted/prohibited workload fixtures yield the expected check results.
- [ ] 2.4 Document the policy's supported resource forms, runtime requirements, configuration overlays, source update procedure, and coverage limits; verify every provenance reference and example matches the shipped files.

## 3. Generate and deliver configured modern Kyverno policies

- [ ] 3.1 Implement and register the focused C2P v2 provider executable, including its manifest and configuration; verify a real plugin handshake succeeds and a missing or misconfigured provider produces a visible error instead of skipped work.
- [ ] 3.2 Implement policy generation and a separate rendering layer for `Deny`/`Audit` and the test namespace; verify rendered manifests retain `policies.kyverno.io/v1`, enable background evaluation, default to `Deny`, reject unsupported actions, and leave the upstream copy unchanged.
- [ ] 3.3 Implement explicit target identity/client selection, test-policy ownership checks, application, and bounded readiness waiting; verify missing APIs and conflicting resources fail clearly and repeated delivery converges on the same owned policy.
- [ ] 3.4 Add the live admission checks and usage instructions for delivery; verify compliant Pod/Deployment requests succeed, privileged creates and applicable updates are denied for the expected policy reason, and `Audit` permits the same otherwise-valid request. Include init and ephemeral-container cases using the upstream fixtures.

## 4. Collect and normalize trustworthy policy evidence

- [ ] 4.1 Capture policy state, target identity, expected admitted-resource inventory, raw report snapshots, and collection context; verify a pre-existing privileged Pod remains present and produces a background failure while a compliant resource produces a pass.
- [ ] 4.2 Implement modern report-to-C2P conversion for namespaced and cluster-scoped reports without loading legacy policy objects; verify fixtures preserve policy identity, source timestamps, reasons, resource UIDs, and distinct subjects for matching names across namespaces or cluster identities.
- [ ] 4.3 Add explicit normalization for pass, fail, warning, error, skip, and unknown outcomes and reject unsupported report layouts; verify no non-passing or malformed input is converted to a pass and source outcomes remain inspectable.
- [ ] 4.4 Implement expected-observation reconciliation, source freshness/identity checks, bounded polling, and incomplete outcomes; verify missing reports, stale timestamps, replaced resource UIDs, and collection failures cannot produce a complete passing assessment.
- [ ] 4.5 Document the captured evidence format, cluster identity scheme, supported report schema, and freshness limits; verify saved fixtures can be converted without a live cluster and collection times remain distinct from evaluation times.

## 5. Export bounded and traceable OSCAL assessments

- [ ] 5.1 Connect the provider results to C2P's Assessment Plan and Assessment Results workflow, supplying the supporting context required by the OSCAL model; verify a saved pass/fail capture produces assessment artifacts referencing the selected check and control.
- [ ] 5.2 Preserve or add source links, cluster/resource identities, content revisions, raw evidence references, partial coverage, and completeness metadata at the export boundary; verify each generated observation can be traced back to its captured result and the artifact package contains the referenced local evidence.
- [ ] 5.3 Validate generated OSCAL against its declared schema and check internal references; add regressions for all-pass and missing-evidence inputs, verifying neither asserts full AC-6/Moderate satisfaction and incomplete inputs remain explicitly incomplete.
- [ ] 5.4 Document artifact inspection and schema-validation commands, including the distinction between official NIST content and generated OSCAL versions; verify the commands work against a saved output package.

## 6. Verify the complete acceptance workflow

- [ ] 6.1 Connect the existing environment, delivery, collection, and export steps into one documented acceptance command; verify it seeds the existing violation, proves admission behavior, observes background pass/fail results, and emits validated OSCAL with the expected partial mapping.
- [ ] 6.2 Exercise the complete workflow's failure and cleanup paths; verify missing required evidence and unexpected admission outcomes return failure, preserve diagnostic artifacts, and clean up only test-owned resources without requiring reports for rejected creations.
- [ ] 6.3 Run the documented workflow twice from clean test state and record the tested version matrix and acceptance results; verify both runs pass without conflicting leftovers and the implementation's evidence supports every scenario in the capability specification.
