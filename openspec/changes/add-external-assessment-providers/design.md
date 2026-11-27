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
generation and CRD chart conventions. Spec identifies a source endpoint and,
when evaluation is allowed, a separate evaluator endpoint (Decision 11), each a
Kubernetes Service (namespace/name/port) with its own server trust/name, the
expected provider name and immutable release digest, protocol/evaluator/payload compatibility, allowed capabilities,
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
- Collect: bounded evidence for a host-frozen inventory, without source
  mutations; the result is an attribution envelope (Decision 9).
- Start/Get/Cancel: optional asynchronous scan operations.
- ReadResult/Acknowledge: bounded immutable result transfer and durable handoff.
- Evaluate: pure evaluation from a projected frozen input envelope, served at
  the registration's evaluator endpoint (Decision 11).

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

Check content for a registered reporting contract uses the shared
reporting-only check definitions owned by `add-assessment-provider-contract`
group 6 (owner decision 2026-11-27): the same signed bundle payload, verification
and closure as every other provider, with compatibility judged against the
selectable contracts through the same `Registry.Select` gating the targeting
resolver uses, the external `Catalog` contributing registered contracts. This
change defines no content format or allowlist of its own. Because
`content.Compatibility.Revision()` covers the provider allowlist and is part of
every bundle acceptance key, feeding registrations into it would force
re-acceptance of every bundle on registration changes; how to avoid that is an
open question recorded in that change's Decision 8, and registered contracts are
not fed into the allowlist before it is answered.

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
The host reaches that evaluator directly at the registration's evaluator
endpoint, never through the worker (Decision 11).
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

### 9. Host-frozen inventory and attribution: protocol revision 2

Owner decisions 6b and 6c (2026-11-27). Revision 1 left inventory, attribution
and the result format to the provider: `CollectRequest.inventory` was opaque
provider input and a staged result an opaque JSON object, so the host could
not tell which subject or check evidence belonged to, or what was missing. An
earlier 3.1 attempt stopped on that gap.

**Inventory.** The host derives the inventory and freezes it before dispatch;
the provider never defines it. For the supported Kubernetes scope it lists the
scope's namespace identities and the workload instances in them. Each subject
has its stable UID, its namespace UID, its resource (`group/version/resource`,
empty group for core), its name, a host revision of the state checks can read
(the spec, labels and annotations digest, never `resourceVersion`) and the
names of the checks expected for it. The expected (subject, check) pairs are
the collection's denominator. Only these fields are projected: no labels,
specs, images or owners cross the boundary. A provider that needs more reads
its own source under its own authority. Namespaces alone are insufficient,
because a namespace-only scope can neither attribute workload evidence nor
detect a missing workload.

The host builds the inventory at run start from targeting, the listed
workloads and the reporting-only check definitions of the shared content
extension (provider-contract group 6), which say which resources a check
applies to. That derivation is wiring (task 3.1); the collection seam takes
the inventory as input. The inventory travels in the Collect request, so one
message bound applies. An inventory larger than the negotiated bounds is not
dispatched: the collection is explicitly incomplete, never truncated. A
chunked inventory upload would be a later additive revision. Cloud accounts,
regions and other non-Kubernetes targets need their own target contract and
are out of scope here.

**Supplements.** A provider may report subjects it discovers itself, such as
containers or images of a workload, only when the inventory allows
supplements, and only under a frozen workload subject (the scope rule). A
supplement never changes the denominator (the completeness rule). A frozen
expectation is attributable only through evidence attributed to that frozen
subject. A supplement's own expectations (its parent's checks) are reported
separately, and their evidence or gaps never make a frozen expectation
complete or passing. Reports never define their own denominator.

**Attribution envelope.** At revision 2 a staged result is a `CollectionResult`
document, the proto3 JSON mapping of that message. It lists evidence items and
the supplements and subject limitations the provider reports. Each evidence
item has an id, its (subject, check) attributions, the source observation time
and `details`. `details` is a JSON object (`google.protobuf.Struct`) and the
only opaque, source-specific part; the payload version versions it. The
document is the result's bytes, so its size and digest are verified and its
transfer resumes like any result, and the capture keeps exactly those bytes.
The kit checks its structure strictly on both sides: unknown fields, bounds,
unique ids and valid times.

The host validates attribution against its frozen inventory before anything
is used:

- evidence is accepted only when every attribution names an inventory subject
  (or an accepted supplement) and a check expected for it. An item that mixes
  in-scope and out-of-scope attributions is withheld whole, because its
  details can carry the other subject's data;
- out-of-scope subjects, unexpected checks, disallowed or orphaned supplements
  and malformed items become bounded diagnostics, never evidence;
- an expectation without accepted evidence is missing, with the provider's
  limitation when it gave one, and never a pass;
- diagnostics name item locations and reasons, never provider-supplied
  identifiers or details, because they reach operator status.

Collection computes no outcomes. Evaluation (3.3) receives the captured
document and the frozen inventory.

**Why revision 2.** The owner allowed additive revision-1 fields only if
negotiation made the new contract mandatory for this path and older peers
demonstrably rejected unsupported use. Tests against main's generated v1 code
and kit (0ddcaa5) as the old peer showed:

- unknown fields: a revision-1 `CollectRequest` carrying a new field 6 decodes
  without error, the kit server serves it, and the handler never sees the
  field. A revision-1 host accepts a `ResultReference` carrying a new field 8
  and drops it. Additive revision-1 fields are silently ignored;
- the revision check: a revision-1 kit server refuses a revision-2 request with
  `UNSUPPORTED_PROTOCOL_VERSION` before any handler runs;
- `CheckCompatibility`: a revision-1 host refuses a provider serving only
  revision 2. It accepts one serving revisions 1 and 2, at revision 1.

So the inventory and the envelope are revision 2 of `konstapel.provider.v1`:
additive messages in the same package, made mandatory by the revision. The kit
speaks and serves revision 2 only, and a kit server refuses a description that
lists another revision, so no revision-1 host can collect without an
inventory. Collect requires an inventory. Revision-1 peers fail explicitly as
`UnsupportedProtocolVersion` in both directions. No release speaks revision 1
(0.3.0 has no `pkg/providerkit`), so no dual-revision window is kept. The
opaque revision-1 `CollectRequest.inventory` field is removed and reserved.

### 10. Frozen registration identity in the capture envelope

Owner decision 6d. A capture of a registered provider records what is needed
to interpret it: the registration name, UID and configuration revision, the
release digest (the implementation), and the protocol and its revision. The
envelope already records the provider contract, payload version and evaluator
version. Evaluator endpoint configuration is configuration, not identity, and
is not recorded.

The identity is a `registration` member of the version 3 envelope, not a new
version 4, because:

- released readers reject every version 3 document. 0.1.0 to 0.3.0 have no
  envelope reader: `CaptureVersion` accepts 1 and 2, `CaptureV2.Validate`
  requires 2 and `assessment.Reconcile` requires 1. Running 0.3.0's readers on
  a version 3 document with the member confirmed it;
- no retained version 3 artifact depends on the current shape. No production
  code writes an envelope (Kyverno writes version 2; only tests build
  envelopes), and no saved testdata capture is version 3;
- unreleased readers reject the member. Main's envelope decoding is strict, so
  `ReadCapture` fails with `ErrUnsupportedCapture` (`unknown field
  "registration"`). The published main commit builds read it the same way and
  write no envelope.

Inside the member every field is required. Only readers that support
registered providers accept it: the built-in registry refuses any capture
carrying it, and a registered contract is never read without it. A capture
read against another registration UID, revision or release fails explicitly.

### 11. Separate evaluator endpoint

Owner decision 2026-11-27. Evaluation uses its own explicit endpoint with its
own authenticated identity, so evaluator isolation can be tested without
trusting a worker to forward evaluation.

- API: an additive `spec.evaluatorEndpoint` (a Service, `serverName` and
  `serverTrust`, shaped like `endpoint`) is required exactly when
  `capabilities` include Evaluate and is forbidden otherwise. `spec.endpoint`
  becomes the source endpoint, required exactly when Collect or Scan is
  allowed. An Evaluate-only registration, such as replay after the worker is
  gone, therefore names only an evaluator. The two endpoints must name
  different Services and different server names. Both follow 2.1's
  conventions: they are mutable, each change is a new revision that only new
  work uses, and work freezes the revision's endpoints.
- Probing describes each endpoint against its own expectation. The source
  endpoint serves the allowed Collect and Scan and writes the payload version.
  The evaluator serves Evaluate and reads the payload version. Both report the
  same provider contract, evaluator version and release digest. Either failing
  makes Available or Compatible False with the endpoint named. Ready and
  selection need both.
- The host sends Collect, Scan, ReadResult and Acknowledge only to the source
  endpoint, and Evaluate only to the evaluator endpoint.
- The evaluator workload holds no source credential and has no source network
  access; the worker keeps collection and scans. In the reference chart the
  worker stops serving and forwarding Evaluate. The evaluator authorizes the
  host identity directly, admits the host namespaces, and still has no token
  and no egress. Live acceptance calls the evaluator as the host.
- Registration checks identities, not isolation: two Services can select the
  same pods. The platform's separate deployment is the isolation boundary, as
  it is for release digests.

### 12. Self-contained collection seam

Owner decision 6d. `external.Collect(ctx, dialer, frozen, inventory, limits,
deadline)` is merged, tested, before it is wired into assessment runs:

1. `Frozen.Continue` checks the current registration before anything is
   dispatched.
2. Bounds: the deadline is the earlier of the argument and the limits'
   timeout. Result bytes, subjects and evidence items use the stricter of the
   host's limits and the provider's advertised ones; an inventory beyond them
   is not dispatched.
3. One authenticated connection: Describe (checking the frozen
   implementation), Collect, then ReadResult, within the same deadline. The
   returned collection is the single result seam that 3.2 extends with durable
   capture, Acknowledge and resume; the seam itself never acknowledges.
4. Every failure (registration gone, unavailable or incompatible endpoint,
   deadline, malformed or oversized result, digest mismatch, expired result,
   provider gone mid-transfer) is an explicit incomplete collection with one
   bounded limitation and no evidence. When the host context ends (leadership
   loss, shutdown) the seam returns an error, and nothing is recorded.
5. Attribution validation (Decision 9) yields accepted evidence, missing
   expectations and diagnostics.
6. The capture is the version 3 envelope with the registration (Decision 10)
   and the staged bytes verbatim, read back through the frozen identity before
   it is returned.

No run calls the seam yet. Task 3.1 stays open until it is wired; end-to-end
collection, attribution in reports and export are not complete.

## Risks / Trade-offs

- More services and TLS configuration -> reference chart and diagnosed readiness.
- Provider compromise -> separate identities, source scope, transport authorization
  and output validation; signatures establish publisher identity, not correctness.
- In-flight upgrades -> immutable operation identities and compatible draining.
- Scanner creep -> optional bounded request capability; no general command runner.
- Premature cloud abstraction -> synthetic scan example; real cloud scope deferred.
- Replay depends on retained evaluator support -> documented compatibility matrix
  and explicit unavailable results, never silent reinterpretation.
- Inventory and attribution volume -> negotiated bounds and explicit incomplete
  collections; a larger scope needs a later chunked revision, never truncation.
- Endpoint separation is configuration -> live isolation acceptance on the
  reference deployment; registration claims no attestation.

## Migration Plan

1. Finish shared contract seams; add protocol and reference kit without changing
   the default Kyverno path.
   Protocol revision 2, the capture registration identity and the unwired
   collection seam land before run wiring; revision-1 peers fail explicitly.
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
