# Design

## Context

See proposal.md. The shared provider contract is already being implemented:
internal/provider defines descriptors, selection, bounded Sources and collection;
internal/provider/installed registers Kyverno, and conformance/reporttest provides
a nonproduction reporting shape. Its capture/evaluator migration is still active.
The C2P executable uses Configure/Generate/GetResults over its own plugin library.
Neither that protocol nor OCI distribution supplies remote scan orchestration.

OpenBao downloads OCI-distributed executables and runs local processes. Here,
external providers run in separate pods to keep their resources and source
credentials separate from the Konstapel controller. The platform installs them.

## Goals / Non-Goals

**Goals:** independently authored/released providers, a small stable wire contract,
optional fresh-evidence requests, and executable authoring/conformance guidance.

**Non-Goals:** general workflow orchestration, automatic plugin installation,
arbitrary local processes, replacing existing Kyverno delivery, production AWS
scanning, or moving publication/signing/retention into providers. No new release
gate for 0.3.0. This change proves the protocol with reference fixtures.

## Decisions

### 1. Extend the shared contract without rewriting its current migration

Complete the relevant shared capture, scope and evaluator seams first. Preserve
existing compiled providers. Add an explicit external-registration selection
path; do not disguise remote services as executable paths supplied by content.
Built-in name collisions fail. One provider per binding remains the rule.

The foundation's collection interface stays read-only. A separate optional scan
request capability precedes collection; it is not engine delivery, does not imply
Deny support and never appears as a side effect of Generate or GetResults.
Remote scan execution is new behavior owned here, not retroactively part of the
foundation's completed tasks. At implementation handoff reconcile the then-current
assessment-providers spec with this extension before enabling it; preserve every
existing read-only scenario and historical capture guarantee.

### 2. Registration and platform installation

Add cluster-scoped compliance.erenius.io/v1alpha1 AssessmentProvider using existing
generation and CRD chart conventions. Spec identifies a Kubernetes Service
(namespace/name/port), server trust/name, expected provider name and immutable
release digest, protocol/evaluator/payload compatibility, allowed capabilities,
and whether new requests are enabled. Status holds observed generation,
bounded Conditions and observed compatible identity. No credentials in status.

The Service reference avoids arbitrary URL fetching; authenticate the expected
server before sending evidence. Administrator-only registration roles are
non-aggregated. Controller permissions read registrations and explicitly named
transport credentials; providers have separate service accounts and source
permissions. No provider grants are copied onto the controller.

A provider Helm chart deploys its service or operator, TLS configuration, service
account and scoped RBAC. Platform operators verify and install signed OCI images
pinned by digest. Reuse the project's artifact verification conventions; the
controller does not act as Helm, a container runtime, or a plugin downloader.
Registration identity is a claim checked against administrator configuration,
not cryptographic proof of the running container: deployment/image verification
is the installation boundary. Do not claim endpoint self-reporting is attestation.

### 3. Wire protocol and credentials

Use a versioned protobuf/gRPC service over mutual TLS with explicit peer names
and configured trust. Certificate issuance remains platform-owned; document
cert-manager and operator-provided material using existing chart conventions.
Handle rotation and missing/expired credentials without insecure fallbacks.
Provider authorizes the controller identity; no cloud credentials travel in RPC.

Publish protocol definitions and a small Go client/server kit outside internal/
so independently maintained implementations can use it. Other languages can
generate clients from the protocol. Do not export internal controller types as
a stable SDK. Protocol major, provider descriptor, evaluation semantics and
capture payload versions are distinct compatibility dimensions.

Operations:
- Describe: identity, capabilities, schema/version compatibility and limits.
- Collect: bounded scoped evidence/inventory exchange without source mutations.
- Start/Get/Cancel: optional asynchronous scan operations.
- ReadResult/Acknowledge: bounded immutable result transfer and durable handoff.
- Evaluate: pure evaluation from a projected frozen input envelope.

Use bounded streams/chunks, checksums, deadlines, request limits and cancellation;
never arbitrary provider-returned download URLs or local file paths. Share the
existing collection defaults where applicable, and negotiate only stricter limits.
Separate scan execution budgets from the existing collection window; the enclosing
assessment deadline is authoritative. This change does not silently lengthen runs.

### 4. Optional scans and distributed ownership

A logical scan key includes run UID, registration UID/revision and frozen input
digest. Provider durably records it before launching work; deterministic workload
identity and reconciliation adopt existing work after response loss. A repeated
key with different inputs conflicts. Retries can have bounded, explicitly recorded
attempts; do not promise exactly-once cloud API calls across crashes.

Konstapel schedules assessments, polls operation status and requests cancellation
on termination. Provider owns execution/retry mechanics, target credentials,
concurrency and rate limits. A controller leadership handover resumes the durable
operation rather than creating a replacement. A closed run rejects late results.
Cancellation uncertainty and orphaned execution remain observable and bounded.

Start requires explicit registration permission and a frozen request that opts in;
ordinary existing-evidence bindings do not start scans. No user-controlled command,
image, role ARN or service account is accepted as execution configuration.
Existing namespace targeting remains the only production scope in this change.
Cloud accounts/regions/ARNs need their own authorized target contract before a
real AWS provider is enabled, not synthetic namespace identities.

### 5. Frozen results, evaluation and C2P

Transfer only authorized scope; source-specific extraction happens in the
provider, with host validation before summaries, package export or diagnostics.
Independent inventory and producer coverage metadata prevent empty/partial
results from becoming success. Preserve raw outcomes and source evaluation times.

Provider retains bounded staging until acknowledgement of durable host capture,
or explicit handoff expiry. A failed transfer can resume the same immutable bytes.
Persist enough digest/identity state to avoid acknowledging only an in-memory
buffer. Host RunContent, storage, signing and retention remain authoritative.

Evaluate shares semantics with the provider's C2P-facing adapter. The reference
deployment separates a source-reading worker from a credential-free evaluator
with denied source egress, rather than claiming an RPC method is a sandbox.
The C2P bridge uses prepared projected inputs and invokes the compatible evaluator;
it never starts scans or forwards source credentials. C2P does not acquire native
OCI discovery through this change.

Offline replay means no source or registry dependency: an operator must already
have installed a compatible evaluator, reachable locally within the deployment.
The external service is still an execution dependency; this is not an air-gapped
single-file executable promise. Record implementation digest and semantic versions.
Never download historical executables from a package. Keep compatible evaluator
deployments available for retained formats or return explicit replay-unavailable.
Previously published packages remain immutable.

### 6. Upgrade, disable and uninstallation

Freeze registration UID, configuration revision and implementation identity per
operation. Endpoint upgrades must retain advertised compatible behavior or reject
old operations explicitly. An incompatible release uses a separate registration/
endpoint; no in-flight migration by silently changing versions.

Disabling registration blocks new starts but permits bounded reconciliation,
cancellation and result handoff for existing work. Drain before removing the
provider chart. Lost services yield explicit incomplete/unavailable evidence;
Konstapel does not recreate the service. Retained packages survive uninstall.
Rollback must preserve required capture readers and compatible evaluators.

### 7. Reference providers and future Prowler shape

Deliver a reporting service and a synthetic scan provider that creates temporary
Jobs. Examples exercise the same public protocol, use separate identities, and
are explicitly test/demo artifacts absent from default production registration.
They establish an authoring recipe, not support for any real scanner.

A future Prowler provider is a small operator plus temporary pinned CLI Jobs:
approved AWS target -> scan request -> Job -> machine-readable results -> durable
capture. It needs no Prowler UI, API database or queue stack. AWS workload identity
belongs to scan Jobs, with centrally approved roles/targets. Measure resource and
API usage before setting defaults. Model denied regions/checks and scan execution
errors separately from findings; clean Jobs only after capture acknowledgement.
Actual AWS target APIs, IAM policies, report-version correlation, OSCAL mappings
and live account acceptance belong to a separately proposed Prowler integration.

Kyverno/Trivy evidence adapters need not create Jobs or introduce another operator.
Their deployment can be a simple provider service; engine/scanner lifecycle stays
with its existing owner. Remote Kyverno enforcement is not included here.

### 8. Authoring documentation is a deliverable

Extend docs/assessment-providers.md with links to a dedicated external-provider
guide and versioned protocol reference. Include a quickstart from an independent
directory/module, capability tables, authentication setup, schemas, error taxonomy,
limits, idempotency/cancellation, results handoff, replay compatibility and C2P.
Provide OCI build/sign/SBOM/provenance instructions, chart installation and digest
verification, upgrade/drain/uninstall procedures, and permission troubleshooting.

Run the documented commands in CI against the reference examples. Conformance
must cover malformed inputs, scope leakage, incompatible versions, credential
rotation, canceled/duplicate operations, lost responses, partial results, bounded
transfer and deterministic replay. Required installed-image acceptance proves the
real controller consumes the protocol; a unit-only mock is insufficient.

## Risks / Trade-offs

- More services and TLS configuration -> reference chart and diagnosed readiness.
- Provider compromise -> separate identities, source scope, transport authorization
  and output validation; signatures establish publisher identity, not correctness.
- In-flight upgrades -> immutable operation identities and compatible draining.
- Scanner creep -> optional bounded request capability; no general command runner.
- Premature cloud abstraction -> synthetic scan example; real cloud scope deferred.
- Replay depends on retained evaluator support -> documented compatibility matrix
  and explicit unavailable results, never silent reinterpretation.

## Migration Plan

1. Finish shared contract seams; add protocol and reference kit without changing
   the default Kyverno path.
2. Ship registration readers, client and authenticated reference charts.
3. Prove reporting capture/export and optional scan recovery in required CI.
4. Publish executable authoring documentation and compatibility matrix.
5. Enable external providers only through explicit administrator installation.
   Disabling the extension preserves existing built-in assessments and packages.

## References

- https://openbao.org/docs/plugins/plugin-installation/ (OCI binary distribution)
- https://github.com/prowler-cloud/prowler/blob/master/Dockerfile (standalone CLI)
- https://github.com/prowler-cloud/prowler/tree/master/contrib/k8s/helm/prowler-app
  (full application chart; not required by the proposed CLI Job architecture)
