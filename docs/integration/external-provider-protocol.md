# External provider protocol reference

This is the reference for `konstapel.provider.v1`, the wire contract between
Konstapel (the *host*) and an independently installed assessment provider
service. It comes from the
[`add-external-assessment-providers`](../../openspec/changes/add-external-assessment-providers/proposal.md)
change. To build a provider that speaks it, follow the
[reporting quickstart](external-provider-quickstart.md).

**Status.** The protocol definition, the public Go types and the Go
authoring kit are implemented and tested. The controller cannot use an
external provider yet: provider registration (an administrator-owned
`AssessmentProvider` resource), selection, remote collection, result
capture, evaluation replay and Helm distribution of providers are later
tasks of the change. Nothing on this page installs, registers or selects a
provider. Konstapel's only supported provider is still the in-tree Kyverno
provider ([assessment providers](../assessment-providers.md)).

## Sources of truth

| Artifact | Role |
| --- | --- |
| [`proto/konstapel/provider/v1/provider.proto`](../../proto/konstapel/provider/v1/provider.proto) | The language-neutral contract. Generate a client or server for any language from it. Its comments are normative. |
| [`pkg/providerapi/v1`](../../pkg/providerapi/v1) | Go code generated from the proto (`providerv1`). |
| [`pkg/providerkit`](../../pkg/providerkit) | The Go authoring kit. `Server` enforces the protocol around a provider's handlers, `Client` is the host side, and `NewServerTLS`/`NewClientTLS`, `ServerOptions`/`DialOptions` and `TransportLimits` configure the transport. |
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
also has optional provider-specific `inventory` (one UTF-8 JSON object),
the `payload_version` the host will store (which must be the provider's
`payload.write`), and the collection `deadline`.

The provider reads existing evidence for that scope. It never mutates a
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

The payload is one UTF-8 JSON object in the provider's payload format.
Evidence must be attributable to the request's scope only. The host rejects
or projects anything else before disclosure. `inventory` and every other
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
only when its length and SHA-256 match the reference and it is one JSON
object. Before sending, the kit's `Server` also checks that the staged
bytes match their reference.

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
1, `providerkit.ProtocolVersion`) and `provider` (the contract the caller
expects to reach). For `Evaluate`, the header is in `EvaluateStart`.

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
| gRPC message, either direction | 4 MiB | `TransportLimits.MaxMessageBytes` (`DefaultMaxMessageBytes`); at least 64 KiB and one chunk plus its envelope |
| Received bytes of one call | largest bounded transfer plus one message | `TransportLimits.MaxStreamBytes`: a full result or payload in chunks, or a full evaluation's observations |
| Concurrent calls per connection | 100 | `TransportLimits.MaxConcurrentStreams` (`DefaultMaxConcurrentStreams`), server side |
| TLS handshake and HTTP/2 preface | 10s | `TransportLimits.HandshakeTimeout` (`DefaultHandshakeTimeout`) |
| Call metadata | 16 KiB | Fixed header-list bound, both sides |
| Limitations per result | 64 | `MaxLimitations` |
| Identifier, limitation, operation message or raw outcome | 1024 bytes | `MaxTextBytes` |
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
  files. Changed material is used only after it passes the checks of the
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

## What is not specified here

- Provider registration (`AssessmentProvider`), selection, permissions and
  Helm installation, which are later tasks of the change.
- Remote collection, capture and replay integration in the controller, scan
  dispatch and the reference scan worker.
- Any real producer. No external provider is supported yet.
