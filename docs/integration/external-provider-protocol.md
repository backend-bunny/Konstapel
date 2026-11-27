# External provider protocol reference

This is the reference for `konstapel.provider.v1`, the wire contract between
Konstapel (the *host*) and an independently installed assessment provider
service. It comes from the
[`add-external-assessment-providers`](../../openspec/changes/add-external-assessment-providers/proposal.md)
change. To build a provider that speaks it, follow the
[reporting quickstart](external-provider-quickstart.md).

**Status.** The protocol definition, the public Go types and the Go
authoring kit are implemented and tested. The administrator-owned
`AssessmentProvider` registration API exists
([assessment providers](../assessment-providers.md#registration-is-code-not-data)),
and a controller configured for external providers probes registrations and
selects them ([registration, selection and status](#registration-selection-and-status)).
No assessment uses an external provider yet. The host's collection seam
(`external.Collect`, [collection seam](#host-collection-seam)) is
implemented and tested but no run calls it; run wiring, result capture,
evaluation replay and Helm distribution of providers are later tasks of the
change. Nothing on this page installs a provider. Konstapel's
only supported provider is still the in-tree Kyverno provider
([assessment providers](../assessment-providers.md)).

## Sources of truth

| Artifact | Role |
| --- | --- |
| [`proto/konstapel/provider/v1/provider.proto`](../../proto/konstapel/provider/v1/provider.proto) | The language-neutral contract. Generate a client or server for any language from it. Its comments are normative. |
| [`pkg/providerapi/v1`](../../pkg/providerapi/v1) | Go code generated from the proto (`providerv1`). |
| [`pkg/providerkit`](../../pkg/providerkit) | The Go authoring kit. `Server` enforces the protocol around a provider's handlers, `Client` is the host side, and `NewServerTLS`/`NewClientTLS`/`NewClientTLSFrom`, `ServerOptions`/`DialOptions` and `TransportLimits` configure the transport. |
| [`proto/konstapel/provider/v1/testdata/wire`](../../proto/konstapel/provider/v1/testdata/wire) | Wire fixtures. Each case is one message as protojson and as its binary encoding, plus the outcome a conforming implementation must reach. Use them to test an implementation in another language. |

The tables on this page marked *generated* are produced from the proto
descriptor, the proto comments and the kit's constants by
`TestProtocolReference` in `pkg/providerkit`, which `task test` runs. If the
protocol and this page disagree, that test fails. After a deliberate protocol
change, regenerate them with
`devbox run -- go test ./pkg/providerkit -run TestProtocolReference -update-protocol-doc`.

`pkg/providerapi/v1` and `pkg/providerkit` import nothing from Konstapel's
`internal/` or `api/` packages. They are the only Go surface a provider
builds on. The controller's internal provider types are not a stable SDK.

## Service

A provider serves the `AssessmentProvider` service. It implements `Describe`
plus the RPCs of each capability it declares. Every other RPC fails with
`ERROR_REASON_UNSUPPORTED_CAPABILITY`.

<!-- BEGIN GENERATED: rpcs -->
| RPC | Shape | Capability | Request | Response |
| --- | --- | --- | --- | --- |
| `Describe` | unary | none (always served) | `DescribeRequest` | `DescribeResponse` |
| `Collect` | unary | `CAPABILITY_COLLECT` | `CollectRequest` | `CollectResponse` |
| `Start` | unary | `CAPABILITY_SCAN` | `StartRequest` | `StartResponse` |
| `Get` | unary | `CAPABILITY_SCAN` | `GetRequest` | `GetResponse` |
| `Cancel` | unary | `CAPABILITY_SCAN` | `CancelRequest` | `CancelResponse` |
| `ReadResult` | server stream | `CAPABILITY_COLLECT` or `CAPABILITY_SCAN` | `ReadResultRequest` | `ReadResultResponse` |
| `Acknowledge` | unary | `CAPABILITY_COLLECT` or `CAPABILITY_SCAN` | `AcknowledgeRequest` | `AcknowledgeResponse` |
| `Evaluate` | bidirectional stream | `CAPABILITY_EVALUATE` | `EvaluateRequest` | `EvaluateResponse` |
<!-- END GENERATED: rpcs -->

### Capabilities

*Generated.* A provider declares at least one capability. The host uses one
only when the provider declares it and the host's expectation (later, the
provider registration) allows it. The kit's `Client` sends no request
outside both.

<!-- BEGIN GENERATED: capabilities -->
| Value | Number | Meaning |
| --- | --- | --- |
| `CAPABILITY_COLLECT` | 1 | Collect, ReadResult and Acknowledge: read-only collection of existing evidence. |
| `CAPABILITY_SCAN` | 2 | Start, Get, Cancel, ReadResult and Acknowledge: explicitly requested fresh evidence. A host uses it only when the provider registration allows it and the frozen request opts in. |
| `CAPABILITY_EVALUATE` | 3 | Evaluate: pure evaluation of frozen payloads. |
<!-- END GENERATED: capabilities -->

### Describe

`DescribeRequest` carries only the request header.
`DescribeResponse` returns:

- `provider`: the provider's name, a lowercase DNS label of at most 63
  characters, and its contract version (at least 1);
- `protocol_versions`: the revisions of major version 1 it serves;
- `evaluator_version`: its evaluation semantics (at least 1);
- `payload`: the payload version it writes, and the versions it reads.
  `read` always includes `write`, because readers ship before writers;
- `capabilities` (at least one) and `checks` (at least one check kind
  `<group>/<version>/<Kind>`, each with an optional self-contained JSON
  Schema of its parameters). External providers deliver no engine
  resources, so their checks accept only Audit mode;
- `limits`: its bounds ([Limits](#limits-and-negotiation));
- `implementation`: a self-reported build identity, such as an image
  digest, at most 1024 bytes. It is a diagnostic claim, not attestation.
  Artifact verification happens when the platform installs the provider.

Describe reads no evidence and has no side effect. The host describes an
endpoint before any other call, checks the description
([check order](#check-order)), and keeps the negotiated limits for
later calls. An incompatible description blocks every other call.

### Collect

`CollectRequest` names the host-frozen `scope`: the cluster and the
namespace instances (name and UID) that the expected inventory covers. It
carries the host-frozen `inventory` (required since revision 2), the
`payload_version` the host will store (which must be the provider's
`payload.write`), and the collection `deadline`.

#### Inventory

The host derives the inventory and freezes it before dispatch. The provider
never defines it. Each `InventorySubject` is one namespace or workload
instance of the scope:

| Field | Meaning |
| --- | --- |
| `uid` | The object's `metadata.uid`, its stable instance identity. Unique in the inventory. |
| `namespace_uid` | The UID of the scope namespace the subject is in. A namespace subject is its own namespace. |
| `resource` | `<group>/<version>/<resource>`, with an empty group for core: `/v1/namespaces` for a namespace subject, for example `apps/v1/deployments` for a workload. |
| `name` | The object's name, at most 253 bytes. A namespace subject has the scope's name for its UID. |
| `revision` | The host's revision of the state checks can read: for a workload, a digest of its spec, labels and annotations, never its `resourceVersion`. Evidence about another state is not this subject's. |
| `checks` | The names of the run's checks expected for the subject: at least one, at most 256, each once. |

The expected (subject, check) pairs are the collection's denominator. A
result can neither add to them, narrow them nor replace them. The inventory
projects identities, revisions and expectations only, never labels, specs,
images or other object data. A provider that needs more reads its own
source under its own authority.

`supplements` says whether the provider may report subjects it discovers
itself. It is never defaulted: `SUPPLEMENTS_UNSPECIFIED` is
`ERROR_REASON_INVALID_REQUEST`.

- `SUPPLEMENTS_NONE`: only inventory subjects.
- `SUPPLEMENTS_WITHIN_WORKLOADS`: parts of an inventory workload, such as
  its containers or images, may be reported as supplements of that
  workload. A supplement adds observations of its own (its parent's checks).
  It never changes the inventory's expectations, and evidence attributed to
  it never completes one.

The provider (`providerkit.CheckInventory`) refuses an inventory without
subjects, with a subject outside the scope's namespaces, a repeated UID or
check, a malformed resource, or a missing name, revision or check. More
subjects than the negotiated `max_subjects` is `ERROR_REASON_LIMIT_EXCEEDED`.
The kit's `Client` refuses such an inventory before sending it, and never
truncates one. Cloud accounts and other non-Kubernetes targets need their
own target contract and are not part of this protocol.

#### Result

The provider reads existing evidence for that inventory. It never mutates a
source and never starts a scan. It stages the result as one immutable
payload and returns its `ResultReference`:

- `result_id`: an opaque identifier of at most 1024 bytes;
- `provider` and `payload_version`: what wrote the payload. Both must match
  the request;
- `size_bytes` and `sha256` (`sha256:` plus 64 lowercase hex digits): the
  exact payload length and digest;
- `expires_at`: the end of the handoff window
  ([ReadResult and Acknowledge](#resumable-readresult-and-acknowledge));
- `limitations`: at most 64 strings of at most 1024 bytes, naming what could
  not be collected or assessed. A limitation is never a finding and never a
  pass.

The staged payload is a `CollectionResult`, the host-readable attribution
envelope, as its proto3 JSON mapping: one UTF-8 JSON object without
surrounding whitespace, so the host's capture keeps exactly the staged
bytes.

- `evidence`: the evidence items. Each has an `id` unique in the result, at
  least one `attributions` entry (a `subject`, the UID of an inventory
  subject or the id of a supplement, and a `check` expected for it, each pair
  once), the `observed` time at which the source evaluated or observed it,
  and `details`.
- `supplements`: the subjects the provider discovered, each with an `id`
  unique in the result, the `parent` inventory workload UID, a `kind` and a
  `name`. Allowed only when the inventory allows supplements.
- `limitations`: what the provider could not collect for a `subject`
  (optionally one `check`), with a `message`. Never a finding and never a
  pass.

`details` (a JSON object, `google.protobuf.Struct`) is the only
source-specific part. Its format is the provider's payload version, and the
host never interprets it. A reader rejects unknown fields, so a field added
later needs a new revision. `providerkit.ParseCollectionResult` checks the
structure and bounds: at most `max_evidence` items and limitations, at most
`max_subjects` supplements, at most 1024 attributions per item, and bounded
text.

Evidence must be attributable to the inventory only. The host validates
attribution before anything is used
([collection seam](#host-collection-seam)). The inventory and every other
input never select credentials, identities, commands or images. The
deadline is the enclosing assessment's, and a provider never extends it.

### Start, Get and Cancel

These RPCs make up the optional scan capability, for fresh evidence the host
explicitly requested.

- `Start` carries a `ScanKey`, the scope, the frozen administrator-approved
  `input` (one JSON object), the `payload_version` and the deadline. The key
  is the scan's idempotency identity: `run_uid`, `registration_uid`,
  `registration_revision` (at least 1) and `input_digest`, which must equal
  the SHA-256 of `input`. The client checks the digest before sending and the
  server checks it again (`ERROR_REASON_DIGEST_MISMATCH`). The provider
  durably records the key before it starts any work. A repeated key with the
  same digest returns the original operation, which is how a host recovers
  a lost start response. The same run and registration with another digest
  fails with `ERROR_REASON_OPERATION_CONFLICT`.
- `Get` returns an operation's current record.
- `Cancel` requests cancellation and returns the record after the request.
  It is idempotent.

An `Operation` has an `operation_id`, its `key`, a `state`, `attempt` and
`max_attempts` (1 ≤ attempt ≤ max_attempts), an optional bounded `message`
and timestamps. `result` is set exactly when the state is
`OPERATION_STATE_SUCCEEDED`, and is then read like a collection result.
Unknown operations fail with `ERROR_REASON_NOT_FOUND`.

<!-- BEGIN GENERATED: operation-states -->
| Value | Number | Meaning |
| --- | --- | --- |
| `OPERATION_STATE_PENDING` | 1 | Recorded under its key; work has not started yet. |
| `OPERATION_STATE_RUNNING` | 2 | Work is running in the current attempt. |
| `OPERATION_STATE_SUCCEEDED` | 3 | Completed with a result. Completion does not imply complete evidence: the result's limitations say what was not assessed. |
| `OPERATION_STATE_FAILED` | 4 | Failed without a result. An execution error, never a finding. |
| `OPERATION_STATE_CANCELING` | 5 | Cancellation was requested and work may still be stopping. |
| `OPERATION_STATE_CANCELED` | 6 | Cancellation completed without a result. |
| `OPERATION_STATE_UNCERTAIN` | 7 | The provider cannot establish whether work still runs. It stays explicit; the host never starts an untracked replacement. |
<!-- END GENERATED: operation-states -->

Scan execution itself is specified by later tasks of the change. This
includes durable reference operation state, polling, retry attempts and
draining. The wire shape above is fixed now.

### Resumable ReadResult and Acknowledge

`ReadResult` streams a staged result's bytes. The request names the
`result_id` and a byte `offset`. Each `ReadResultResponse` is one chunk with
its `offset` and non-empty `data` of at most the negotiated
`max_chunk_bytes`. Chunks are contiguous from the requested offset, and the
stream ends after the last byte. An offset beyond the result is
`ERROR_REASON_INVALID_REQUEST`.

Results are immutable, so an interrupted transfer resumes with the same
bytes. The kit's `Client.ResumeResult(ctx, ref, have)` asks for
`offset = len(have)`. On an interrupted stream it returns the bytes received
so far together with the error, so the caller can resume again. On any
protocol violation, such as a gap, an overlong or empty chunk, or more bytes
than `size_bytes`, it returns no bytes. A complete transfer is accepted
only when its length and SHA-256 match the reference and it is a
well-formed `CollectionResult`. `Client.ReadCollection` also returns the
decoded result. Before sending, the kit's `Server` also checks that the
staged bytes match their reference and are a well-formed `CollectionResult`.

`Acknowledge` sends the `result_id` with the `size_bytes` and `sha256` of
the bytes the host captured. The provider verifies them against the result
(`ERROR_REASON_DIGEST_MISMATCH` otherwise) and then may release its staging.
The host acknowledges only after its capture is durable. The provider keeps
the result until then, or until `expires_at`. After that, reading it fails
with `ERROR_REASON_RESULT_EXPIRED`, which means lost evidence and is never an
empty result. Provider staging is a bounded handoff, not a second
publication or retention system: Konstapel's capture, storage, signing and
retention stay authoritative.

### Evaluate streaming

`Evaluate` is a bidirectional stream with two phases:

1. The host sends one `EvaluateRequest.start` (an `EvaluateStart`), then the
   payload as contiguous `payload_chunk` messages of at most
   `max_chunk_bytes` each, then closes its side.
2. The provider verifies that the received payload matches the start's
   `payload_size_bytes` and `payload_sha256` and is one JSON object. It then
   evaluates and streams `ObservationBatch` messages, ending with exactly one
   `EvaluationSummary`.

`EvaluateStart` carries the request header, the capture's
`evaluator_version` (which must be the provider's) and `payload_version`
(which must be one it reads), the payload size and digest, an explicit
`evaluation_time`, the frozen `scope`, the run's frozen content set
(`ContentReference`: bundle and `sha256:` manifest digest) and its `checks`.
Each `CheckDefinition` has a kind the provider declared, a unique name, the
verified definition (one JSON object) and optional parameters (one JSON
object). The whole `EvaluateStart` must fit in one gRPC message
([limits](#limits-and-negotiation)). Content larger than the message bound
fails with gRPC code `ResourceExhausted` before it reaches the provider.

Evaluation reads only its input: no source, clock or registry. It starts no
scan. Each `Observation` has a provider-defined `subject` and `check`, a
pair unique within the evaluation, and an evidence `state`:

<!-- BEGIN GENERATED: evidence-states -->
| Value | Number | Meaning |
| --- | --- | --- |
| `EVIDENCE_STATE_ATTRIBUTABLE` | 1 | Usable evidence attributed to the observation: raw, outcome and evaluated are set. |
| `EVIDENCE_STATE_MISSING` | 2 | No evidence for the observation. |
| `EVIDENCE_STATE_REJECTED` | 3 | Evidence exists but none is usable (stale, untimed, after the evaluation time). |
| `EVIDENCE_STATE_UNRESOLVED` | 4 | Evidence cannot be attributed (ambiguous, conflicting, scope change). |
<!-- END GENERATED: evidence-states -->

Only attributable observations carry `raw` (the producer's own outcome,
verbatim, at most 1024 bytes), `outcome` (normalized: `OUTCOME_PASS`,
`OUTCOME_FAIL`, `OUTCOME_ERROR`, `OUTCOME_SKIP` or `OUTCOME_UNKNOWN`), the
optional `not_applicable` flag (which never counts as a pass) and the
source `evaluated` time. The summary repeats the provider identity and
evaluator version, which must match `Describe`. It also gives the
`observation_count`, which must equal the observations sent, and
`stale_scopes`, the number of scopes whose expected checks are unknown. Any
stale scope makes the evidence incomplete. Observations beyond
`max_observations`, or anything sent after the summary, fail the
evaluation.

## Request header and versions

Every request opens with a `RequestHeader`. It holds `protocol_version` (the
revision of major version 1 the caller speaks; this definition is revision
2, `providerkit.ProtocolVersion`) and `provider` (the contract the caller
expects to reach). For `Evaluate`, the header is in `EvaluateStart`.

### Revision 2

Revision 2 added the inventory, the `CollectionResult` envelope and the
`max_subjects` and `max_evidence` limits, and removed revision 1's opaque
`CollectRequest.inventory` bytes (field 3, now reserved). The messages are
additive, but a revision 1 peer would silently ignore them: protobuf keeps
unknown fields, and revision 1 readers never see them
(`TestRevision1ReadersSilentlyIgnoreRevision2Fields` decodes revision 2
messages with revision 1's saved descriptor). The revision is therefore what
makes them mandatory:

- the kit speaks and serves revision 2 only. `NewServer` refuses a
  description that lists any other revision, because it would accept that
  revision's requests: a revision 1 host would collect without an inventory;
- a revision 2 provider refuses a revision 1 request with
  `UNSUPPORTED_PROTOCOL_VERSION` before any handler runs, as a revision 1
  provider refuses a revision 2 request;
- a revision 2 host refuses a provider that does not serve revision 2.

No Konstapel release speaks revision 1, so no dual-revision window is kept
(`TestOtherRevisionsAreRejectedInBothDirections`).

Four versions are separate compatibility dimensions. None implies another,
and none is negotiated downward, defaulted or adapted:

| Dimension | Where | Meaning |
| --- | --- | --- |
| Protocol version | The package name is the major version (`konstapel.provider.v1`; a breaking change is a new package). `RequestHeader.protocol_version` and `DescribeResponse.protocol_versions` carry the revision | This wire contract |
| Provider contract version | `ProviderContract.version`, selected by bundles as `<name>/v<version>` | The provider's capability contract: the host's provider descriptor version |
| Payload version | `PayloadCompatibility`, `ResultReference.payload_version`, `*.payload_version` | The evidence payload format. The host records it as a capture's `payloadVersion` |
| Evaluator version | `DescribeResponse.evaluator_version`, `EvaluateStart.evaluator_version` | Evaluation semantics. The host records it as a capture's `evaluatorVersion` and replays a capture only with the same evaluator version |

These are the descriptor, `capture` and `evaluatorVersion` versions of the
[provider contract](../assessment-providers.md#versioned-contracts), not
parallel ones. The protocol revision is the fourth dimension.

### Check order

Each dimension fails with its own reason, and the first mismatch is
returned.

The provider checks each request in this order (`providerkit.CheckHeader`
and `Server`):

1. the header: protocol revision (`UNSUPPORTED_PROTOCOL_VERSION`), then
   provider name (`PROVIDER_MISMATCH`), then contract version
   (`UNSUPPORTED_CONTRACT_VERSION`);
2. the capability the RPC needs (`UNSUPPORTED_CAPABILITY`);
3. for `Collect` and `Start`, that `payload_version` is the written version
   (`UNSUPPORTED_PAYLOAD_VERSION`). For `Evaluate`, the evaluator version
   (`UNSUPPORTED_EVALUATOR_VERSION`), then that the payload version is one
   it reads (`UNSUPPORTED_PAYLOAD_VERSION`), then the payload size bound
   (`LIMIT_EXCEEDED`);
4. the remaining fields (`INVALID_REQUEST`, or `DIGEST_MISMATCH` for a scan
   key's input digest).

The host checks a description in this order (`providerkit.CheckCompatibility`):

1. its own expectation and the description's well-formedness
   (`INVALID_REQUEST`, `INVALID_RESPONSE`);
2. protocol revision, provider name, contract version and evaluator
   version, each with its reason;
3. payload version: with collection or scans allowed, the provider must
   write the stored version. In every case it must read that version;
4. every allowed capability must be served (`UNSUPPORTED_CAPABILITY`).

The kit's `Client.Evaluate` also refuses, before sending anything, a capture
whose evaluator version the endpoint does not serve or whose payload version
it does not read.

## Errors

A failed call returns a gRPC status whose details carry exactly one
`ErrorDetail` with an `ErrorReason`. Clients branch on the reason, never on
the message text. The gRPC code only keeps generic gRPC tooling meaningful
(`providerkit.Code`).

*Generated:*

<!-- BEGIN GENERATED: error-reasons -->
| Reason | Number | gRPC code | Meaning |
| --- | --- | --- | --- |
| `ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION` | 1 | `FailedPrecondition` | The request's protocol_version is not one the provider serves. |
| `ERROR_REASON_PROVIDER_MISMATCH` | 2 | `FailedPrecondition` | The request names another provider than the one serving it. |
| `ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION` | 3 | `FailedPrecondition` | The request's provider contract version is not the provider's. |
| `ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION` | 4 | `FailedPrecondition` | The payload version is not one the provider writes (Collect, Start) or reads (Evaluate). |
| `ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION` | 5 | `FailedPrecondition` | The evaluator version is not the provider's evaluator version. |
| `ERROR_REASON_UNSUPPORTED_CAPABILITY` | 6 | `Unimplemented` | The provider does not declare the capability the operation needs. |
| `ERROR_REASON_INVALID_REQUEST` | 7 | `InvalidArgument` | The request is malformed: a missing or invalid field. |
| `ERROR_REASON_LIMIT_EXCEEDED` | 8 | `ResourceExhausted` | The request or response would exceed a negotiated limit. |
| `ERROR_REASON_OPERATION_CONFLICT` | 9 | `AlreadyExists` | A scan key was repeated with a different input digest. |
| `ERROR_REASON_NOT_FOUND` | 10 | `NotFound` | The operation or result is unknown to the provider. |
| `ERROR_REASON_RESULT_EXPIRED` | 11 | `FailedPrecondition` | The result's handoff window ended before it was acknowledged. The evidence is lost; it is never an empty result. |
| `ERROR_REASON_DIGEST_MISMATCH` | 12 | `InvalidArgument` | A size or SHA-256 digest does not match the bytes it describes. |
| `ERROR_REASON_UNAVAILABLE` | 13 | `Unavailable` | The provider failed for a reason of its own (source unavailable, internal error). Availability, not a finding. |
| `ERROR_REASON_INVALID_RESPONSE` | 14 | `Internal` | A provider response violates this protocol (detected by the host). |
<!-- END GENERATED: error-reasons -->

How the kit maps errors:

- A `Server` handler returns `providerkit.Errorf(reason, …)` to choose a
  reason. Any other error is the provider's own failure and is served as
  `ERROR_REASON_UNAVAILABLE`. A context cancellation or deadline keeps gRPC
  code `Canceled` or `DeadlineExceeded`, with no detail.
- `Client` returns a `*providerkit.Error` both for a provider's status and
  for checks it makes itself before or instead of sending, such as an
  incompatible description or a response that violates the protocol
  (`ERROR_REASON_INVALID_RESPONSE`). Test a reason with
  `providerkit.ReasonOf(err)` or
  `errors.Is(err, &providerkit.Error{Reason: r})`.
- A status without exactly one `ErrorDetail`, such as a transport failure, a
  failed handshake or gRPC's own message-size error, has reason
  `ERROR_REASON_UNSPECIFIED`. Its message keeps the gRPC code. If the
  caller's context ended, the context error is returned as is.

## Limits and negotiation

A provider advertises `Limits` in its description. Zero means the provider
sets no bound stricter than the host's. The host applies the stricter of
each of its own bounds and the provider's (`providerkit.NegotiateLimits`).
An advertised limit never raises a host bound. A provider's `Server` uses
the stricter of the kit defaults and its own limits (`Server.Limits`), and
its transport should carry the same (`TransportLimits{Protocol:
srv.Limits()}`). Exceeding a protocol bound is `ERROR_REASON_LIMIT_EXCEEDED`.

*Generated defaults:*

<!-- BEGIN GENERATED: limits -->
| Bound | Default | Configured by / applies to |
| --- | --- | --- |
| `Limits.max_result_bytes` | 512 MiB | `DefaultMaxResultBytes`: one staged result, and one evaluated payload |
| `Limits.max_chunk_bytes` | 1 MiB | `DefaultMaxChunkBytes`: the data of one `ReadResultResponse` or `EvaluateRequest.payload_chunk`, and the encoded observations of one `ObservationBatch` |
| `Limits.max_observations` | 100000 | `DefaultMaxObservations`: the observations of one evaluation |
| `Limits.max_subjects` | 100000 | `DefaultMaxSubjects`: the subjects of one inventory, and separately the supplements of one result |
| `Limits.max_evidence` | 100000 | `DefaultMaxEvidence`: the evidence items of one result, and separately its subject limitations |
| gRPC message, either direction | 4 MiB | `TransportLimits.MaxMessageBytes` (`DefaultMaxMessageBytes`); at least 64 KiB and one chunk plus its envelope |
| Received bytes of one call | largest bounded transfer plus one message | `TransportLimits.MaxStreamBytes`: a full result or payload in chunks, or a full evaluation's observations |
| Concurrent calls per connection | 100 | `TransportLimits.MaxConcurrentStreams` (`DefaultMaxConcurrentStreams`), server side |
| TLS handshake and HTTP/2 preface | 10s | `TransportLimits.HandshakeTimeout` (`DefaultHandshakeTimeout`) |
| Call metadata | 16 KiB | Fixed header-list bound, both sides |
| Limitations per result | 64 | `MaxLimitations` |
| Identifier, limitation, operation message or raw outcome | 1024 bytes | `MaxTextBytes` |
| Inventory subject name | 253 bytes | `MaxNameBytes`, a Kubernetes object name |
| Expected checks per inventory subject | 256 | `MaxSubjectChecks` |
| Attributions per evidence item | 1024 | `MaxAttributions` |
| One mounted TLS file | 1 MiB | Fixed; at most 512 certificates |
| TLS file reload interval | 10s | `DefaultReloadInterval` (`MutualTLS.Watch`) |
<!-- END GENERATED: limits -->

Size caps to keep in mind:

- Results and payloads travel in chunks, so their bound is
  `max_result_bytes`, not the message size.
- Unary requests and responses, `EvaluateStart` (with its content and check
  definitions), and each observation batch must each fit in one message of
  at most `MaxMessageBytes`. A larger message fails with gRPC code
  `ResourceExhausted` and no `ErrorDetail`. An oversized request never
  reaches a handler, and the client refuses to send one.
- The received bytes of a whole call are bounded by `MaxStreamBytes`.
  Exceeding it is `ERROR_REASON_LIMIT_EXCEEDED` and cancels the call.

## Transport and identity

Calls run over mutual TLS 1.3, configured with
`providerkit.NewServerTLS(files, authorizedHosts)` plus `ServerOptions` on
the provider, and `providerkit.NewClientTLS(files, serverName)` plus
`DialOptions` on the host. `providerkit.SecretFiles(dir)` names `tls.crt`,
`tls.key` and `ca.crt` in a mounted `kubernetes.io/tls` Secret, as
cert-manager writes them. Its `ca.crt` is the peer's trust only when one
issuer signs both sides. Otherwise set `TLSFiles.Trust` to the peer's CA
bundle. The platform issues certificates. No credential is ever carried in
a message.

A host whose trust bundle is not a mounted file uses
`providerkit.NewClientTLSFrom(source, serverName)`. A `TLSSource` returns
the certificate, key and trust bundle as bytes (`TLSMaterial`) at every
load. `TLSFiles` is itself a source. Material from any source passes exactly
the checks mounted files pass, including the 1 MiB bound per part, and a
failed or rejected load keeps the last valid material in use. The Konstapel
controller uses it to combine its own mounted client certificate with a
registration's `serverTrust` ConfigMap.

Identity rules:

- A peer is authorized only when its certificate chains to the configured
  trust bundle, is valid now, carries the extended key usage of its role
  (server or client authentication, or none) and names an authorized peer
  exactly as a DNS subject alternative name. Names compare case-insensitively.
  Wildcards, common names, URIs and IP addresses never match.
- The host authorizes exactly one name, the provider's server name, whatever
  address it dials. The dialed address never changes the expected name. The
  provider authorizes the host identities its deployment configures.
- The host sends no call and no client certificate before the server is
  authorized. No call reaches a provider handler before the host is
  authorized. Each call is authorized again against the current material.
  Plaintext and TLS below 1.3 are refused, and there is no session
  resumption.
- Mutual TLS and the identity check are transport authentication. They do
  not attest which image is running. That is checked when the platform
  verifies and installs the provider.

Rotation behavior:

- `MutualTLS.Reload`, or `Watch` every `DefaultReloadInterval`, re-reads the
  files or source. Changed material is used only after it passes the checks of the
  initial load. Until then, the last valid material stays in use and
  `MutualTLS.Ready()` reports the problem. There is no insecure fallback.
- New connections use the current material. An established connection is
  closed as soon as the current material no longer authorizes its peer,
  whether after a trust rotation or when a certificate in its chain expires.
  Its calls fail, and the client reconnects with the current material.

Deadlines:

- Every call carries a deadline. The client kit refuses a call without one
  (`ERROR_REASON_INVALID_REQUEST`) before sending anything, and the provider
  refuses one in its tap handle, before reading messages. The host's
  deadline and cancellation reach the handler's context.
- `Collect` and `Start` also carry an explicit `deadline` field, the
  enclosing assessment's. A provider never extends it.

Health and probes: the tap handle applies to every service on the protocol
port. A gRPC health service there would also require authenticated callers
with deadlines, which kubelet probes are not. Serve liveness and readiness
on a separate port, for example plain HTTP reporting `MutualTLS.Ready()`, as
the [quickstart](external-provider-quickstart.md) does.

## Registration, selection and status

This section describes how the Konstapel controller uses `AssessmentProvider`
registrations (`api/v1alpha1/assessmentprovider_types.go`,
`internal/provider/external`). It is host behavior, not part of the wire
contract.

External providers are off by default. The controller probes and selects
registrations only when `--external-provider-client-cert-dir` names a
directory with `tls.crt` and `tls.key`, the controller's own client
certificate, as a mounted `kubernetes.io/tls` Secret. The certificate must
allow client authentication and name the host identity providers authorize.
Without the flag, the controller neither watches nor contacts registrations,
and every contract that is not built in is `UnknownProvider`, exactly as
before. With the flag, invalid credentials fail startup. The runtime chart sets
the flag and mounts the Secret only with `externalProviders.enabled`.
[External assessment providers](../charts.md#external-assessment-providers)
covers the certificates, trust ConfigMaps, roles to bind and the platform
installation boundary. The controller never installs or downloads a
provider. Content and assessment runs do not use registrations yet.

### Probing

Every registration is probed when it changes and then every minute. A probe
reads the `serverTrust` ConfigMap key in the controller namespace and the
controller's credentials, dials `<service>.<namespace>.svc:<port>`,
authenticates the server as `serverName` over mutual TLS 1.3 and sends
`Describe` with a 10 second deadline. Nothing else is sent. The description
must match the registration in every dimension, and its `implementation`
must equal `spec.provider.releaseDigest`. A matching `implementation` is the
endpoint's own claim, not attestation. A rotated trust ConfigMap or client
certificate is used from the next probe, without a restart. Up to four
probes run at once, and each probe is bounded, so a slow endpoint never
delays another registration. A registration that names a built-in provider,
which the API rejects anyway, is never contacted.

The probe writes `status.observedGeneration`, three conditions and, only
while the endpoint is compatible, `status.identity`, whose `observedAt` is
refreshed on every probe. Condition messages name endpoints, server names,
versions and errors, never certificate contents or keys.

| Condition | `True` when | Reasons when not `True` |
| --- | --- | --- |
| `Available` | The Service accepted a connection, the server authenticated as `serverName`, the controller was accepted, and `Describe` answered. | `TrustUnavailable`, `ClientCredentialsUnavailable`, `EndpointUnavailable`, `AuthenticationFailed`; `NotChecked` (`Unknown`) for a built-in name |
| `Compatible` | The description matches the registration: provider, release, protocol revision, contract, evaluator, payload and allowed capabilities. | `ProviderMismatch`, `ReleaseMismatch`, `UnsupportedProtocolVersion`, `UnsupportedContractVersion`, `UnsupportedEvaluatorVersion`, `UnsupportedPayloadVersion`, `UnsupportedCapability`, `InvalidDescription`, `BuiltInProvider`; `NotChecked` (`Unknown`) while unavailable |
| `Ready` | New work may select the registration. | `Unavailable`, `Incompatible`, `NewRequestsDisabled`, `AmbiguousRegistration` |

The `True` reasons are `Available`, `Compatible` and `Ready`.

### Selection

New work resolves a provider contract (`name/vN`) in this order. No rule
falls back to another registration, release, version or provider.

1. An empty contract is the built-in default, and a malformed one is
   `InvalidSelection`.
2. A built-in provider name resolves only to the built-in provider. Its
   other versions are `IncompatibleVersion`. Registrations are not consulted,
   so a built-in provider is never shadowed.
3. With external providers off, or with no registration of the name, the
   contract is `UnknownProvider`. Registrations of the name at other contract
   versions only are `IncompatibleVersion`.
4. Registrations with `newRequests: Disabled`, or being deleted, are never
   selected. If none of the contract's registrations is enabled, the result
   is `ProviderDisabled`.
5. More than one enabled registration of the contract is
   `AmbiguousProvider`, whatever their order, age or health. Each of them
   reports `Ready=False` with `AmbiguousRegistration`.
6. The one enabled registration must allow every capability the work needs
   (`UnsupportedCapability`). Its status must show `Ready=True` for its
   current generation, with a compatible identity observed serving those
   capabilities within the last five minutes (`ProviderUnavailable`).

These are `SelectionError` reasons of the shared host
(`internal/provider`). A binding reports each of the four
registration-specific reasons as `ContentUnavailable`. One provider's
registrations never affect the selection of another provider or of a
built-in one.

A release upgrade is a new registration, because `releaseDigest` is
immutable. To avoid an ambiguous window, create the new registration with
`newRequests: Disabled`, wait for `Available` and `Compatible`, then disable
the old registration and enable the new one. New work selects the new
release once it is `Ready`.

### Frozen registration identity

A selection freezes the selected registration: its name, UID,
configuration revision (`metadata.generation`), provider contract, release
digest, protocol revision, evaluator and payload versions, allowed
capabilities, and that revision's endpoint (Service, `serverName` and
`serverTrust` ConfigMap name and key). The record contains no credentials.
Work frozen to it keeps that configuration:

- A later revision, such as a moved Service, other capabilities or
  `newRequests: Disabled`, is used only by new work. Disabled lets frozen
  work drain.
- The trust ConfigMap's contents are read at every connection, so trust
  rotation applies to frozen work too. The ConfigMap name and key stay
  frozen.
- Frozen work ends with an explicit reason when the registration is deleted
  (`RegistrationRemoved`) or replaced under the same name
  (`RegistrationReplaced`), or when an immutable field no longer matches
  (`RegistrationChanged`, which the API already prevents). It also ends when
  it needs a capability its revision did not allow (`CapabilityNotFrozen`),
  or when the endpoint no longer reports the frozen release or compatibility
  (`ImplementationChanged`). It is never reinterpreted.

A capture of frozen work records the identity needed to interpret it: the
envelope's `registration` (name, UID, revision, release digest, protocol and
protocol revision) beside its provider contract, payload version and
evaluator version
([captures](../assessment-providers.md#captures)).

## Host collection seam

`external.Collect(ctx, dialer, frozen, inventory, limits, deadline)` in
`internal/provider/external` is the host's whole read-only collection from
one registered provider
([design Decision 12](../../openspec/changes/add-external-assessment-providers/design.md#12-self-contained-collection-seam)).
It is tested over real mutual TLS endpoints (`externaltest`), but no
assessment run calls it yet: wiring it into runs, captures and reports is
the open task 3.1. In order, it:

1. calls `Frozen.Continue` with the registration as the dialer's
   `Registration` reader sees it now. Removed, replaced or changed
   registrations and capabilities the frozen revision does not allow end the
   collection before anything is dispatched;
2. bounds the collection by the earlier of `deadline` and the limits'
   timeout, and applies the stricter of the host's limits (result bytes from
   the byte budget; subjects, evidence items and supplements from the object
   budget) and the provider's advertised ones. An inventory beyond them is
   never dispatched or truncated;
3. on one authenticated connection, describes the endpoint (checked against
   the frozen identity and release), sends Collect with the inventory, and
   reads the result back with `ReadCollection`. It never acknowledges:
   acknowledgement follows durable capture (task 3.2), so the provider keeps
   the result until then or until `expires_at`;
4. attributes the result against the inventory (`external.Attribute`). An
   item is evidence only when every one of its attributions names an
   inventory subject, or an accepted supplement, and a check expected for it.
   An item that also names anything else is withheld whole. Supplements are
   accepted only when the inventory allows them and only under an inventory
   workload, and never complete a frozen expectation. Every expectation
   without accepted evidence is missing, with the provider's limitation for
   it when it gave one, and never a pass. Withheld items and limitations
   become at most 64 diagnostics. Each names the item's location and the
   reason, never a provider-supplied identifier or detail;
5. writes the capture: a version 3 envelope recording the frozen
   registration, with the staged bytes as its payload unchanged
   (`collector.EncodeEnvelope`). It reads the capture back through
   `Frozen.CaptureReaders`, which read only captures of that registration
   UID, revision and release.

Every other outcome is an incomplete collection with no payload, capture
or evidence: its one limitation names a stop reason (`registration`,
`unavailable`, `incompatible`, `deadline`, `limit`, `malformed`,
`digest-mismatch`, `result-lost` or `refused`) and a bounded message. When
the host's own context ends (leadership loss or shutdown), `Collect` returns
the context's error, and nothing may be recorded.

## What is not specified here

- Permissions, chart configuration of the controller's client certificate
  and Helm installation of providers, which are later tasks of the change.
- Remote collection, capture and replay integration in the controller, scan
  dispatch and the reference scan worker.
- Any real producer. No external provider is supported yet.
