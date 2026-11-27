# Tasks

## Execution boundaries

Consumes add-assessment-provider-contract; coordinate with its active owner and
finish required capture/evaluator seams before production integration. Do not
rewrite completed foundation tasks or change its read-only adapters into scanners.
No production Prowler, AWS target API, Trivy migration, remote Kyverno delivery,
release/tag publication or new public Task wrapper is authorized by this change.
Each group includes its tests and documentation; final tasks prove integration.

## 1. Protocol and authoring kit

- [x] 1.1 Publish versioned protobuf contracts and public Go client/server types for Describe, Collect, Start/Get/Cancel, ReadResult/Acknowledge and Evaluate; verify wire fixtures reject unsupported versions and distinguish capability, payload and evaluator versions.
  <!-- agent: tier=deep risk=medium -->
- [x] 1.2 Implement mutual TLS peer authorization, credential rotation and bounded RPC transport; test wrong identities, expired trust, oversized streams, cancellation and no credential/payload transmission before authentication.
  <!-- agent: tier=deep risk=high -->
- [x] 1.3 Write the protocol reference and an independent-module reporting quickstart; verify it builds without internal imports and runs the documented client/server commands.
  <!-- agent: tier=standard risk=medium -->

## 2. Administrator registration and selection

- [x] 2.1 Add AssessmentProvider API, generated CRD and non-aggregated RBAC with endpoint/identity/compatibility validation; test namespace-user denials, invalid references, built-in collisions and controller-only status.
  <!-- agent: tier=deep risk=high -->
- [x] 2.2 Integrate registered-provider selection, frozen registration identity and capability Conditions with the shared host; test unknown/incompatible selection, disabled new starts, changed registrations and healthy-provider independence.
  <!-- agent: tier=deep risk=high -->
- [x] 2.3 Add core chart registration-client configuration and document TLS, permissions and platform installation; verify default charts retain built-in behavior without installing external providers or granting source permissions.
  <!-- agent: tier=standard risk=medium -->
- [x] 2.4 Add a separate evaluator endpoint (design Decision 11, owner decision 2026-11-27): `spec.evaluatorEndpoint` required exactly with Evaluate, `spec.endpoint` required exactly with Collect or Scan, with distinct Services and server names; probe and select each endpoint against its own expectation, send Evaluate only to the evaluator endpoint, and change the reference chart so the worker no longer forwards evaluation and the evaluator authorizes the host; test API validation, frozen revisions, per-endpoint availability and compatibility, and live denied source access from the evaluator called as the host.
  <!-- agent: tier=deep risk=high reason="Registration authorization and evaluator isolation boundary" -->
  Evidence: `spec.evaluatorEndpoint` (`*ProviderEndpoint`) and an optional `spec.endpoint`, with CEL rules: each endpoint is required exactly with its capabilities, and the evaluator endpoint has another `serverName` and another Service (`TestAssessmentProviderCreateValidation`, `TestAssessmentProviderUpdateValidation`, live `TestLiveAssessmentProviderAPI`). `Frozen` freezes both endpoints. `Compatibility(role)`, `Connect` and `ConnectEvaluator` give each endpoint a client limited to its own capabilities, and `Probe` describes both, naming a failing one (`TestProbeDescribesEachEndpoint`, `TestProbeFailsOnTheEvaluatorEndpoint`, `TestEachEndpointCarriesOnlyItsOperations`, `TestEvaluateOnlyRegistration`, `TestFrozenEvaluatorEndpoint`, controller probe tests). In the reference chart the worker serves Collect only, without forwarding or an evaluator client. The evaluator authorizes `evaluator.authorizedHosts` from `evaluator.hostNamespaces` only (`internal/charttest`, example `TestSplitAssessment` and `TestWorkerServesNoEvaluation`). `TestLiveReferenceProviderChart` calls both endpoints as the host and proves that each refuses the other's capability and that the evaluator has no token and no egress.

## 3. Remote evidence and replay

Bundle check definitions for registered reporting contracts, resolver gating
through `Registry.Select` and `content.Compatibility` fed from the selectable
contracts are the shared, provider-neutral extension of
[add-assessment-provider-contract](../add-assessment-provider-contract/tasks.md)
group 6 (owner decision 2026-11-27). Group 3 consumes it and defines no content
format, check-definition schema or provider allowlist of its own; feeding
registrations into the allowlist waits for that change's compatibility revision
decision (its design Decision 8).

- [ ] 3.1 Integrate remote read-only collection with host scope, inventory and limits; test mixed-scope payloads/diagnostics, missing subjects, malformed results and deadline closure without scans.
  <!-- agent: tier=deep risk=high -->
  Note (owner decision 2026-11-27): 3.1.1 to 3.1.3 deliver its prerequisites and a tested seam that no run calls. 3.1 stays open until the host derives the frozen inventory from targeting, listed workloads and the shared check definitions, assessment runs call the seam, and its evidence, diagnostics and limitations reach captures and reports. End-to-end collection, attribution and export are not complete before then.
- [x] 3.1.1 Define protocol revision 2 of `konstapel.provider.v1` (design Decision 9): a host-frozen inventory in Collect and the `CollectionResult` attribution envelope as the staged result. Prove the revision-1 reader behavior first (unknown fields, the revision check, `CheckCompatibility`), make the kit and host speak revision 2 only, and update the wire fixtures, protocol reference, quickstart and reference provider; test unsupported revisions, missing or out-of-scope inventory and malformed documents.
  <!-- agent: tier=deep risk=high reason="Wire contract compatibility and scope attribution" -->
  Evidence: proven before the change against main 0ddcaa5's generated code and kit: a revision 1 reader decodes a new field and its handler never sees it, a revision 1 server refuses revision 2 with `UNSUPPORTED_PROTOCOL_VERSION`, and `CheckCompatibility` refuses a revision-2-only provider but accepts revisions 1 and 2. The proto adds `Inventory`, `CollectionResult` and `max_subjects`/`max_evidence`, reserves field 3, and is revision 2. `providerkit.ProtocolVersion` is 2, `NewServer` refuses descriptions listing any other revision, and `CheckInventory`/`ParseCollectionResult` check both sides. Tests: `TestRevision1ReadersSilentlyIgnoreRevision2Fields` (revision 1's saved descriptor, `testdata/revision1`), `TestOtherRevisionsAreRejectedInBothDirections`, `TestCheckInventory`, `TestParseCollectionResult`, and wire fixtures moved to revision 2 with new inventory cases. The protocol reference, quickstart, reference provider (staged `CollectionResult`, evaluation from it) and the live `refAssess` are updated.
- [x] 3.1.2 Record the frozen registration identity in the version 3 capture envelope (design Decision 10), after verifying that no released or retained version 3 artifact depends on its shape and that incompatible readers reject it; test built-in readers rejecting it, registered captures without it, mismatched registration identities and the documented compatibility examples.
  <!-- agent: tier=deep risk=high reason="Retained capture compatibility" -->
  Evidence: verified before the change: 0.3.0's readers (run at the v0.3.0 tag) refuse a version 3 document with the member, no production code writes an envelope, no saved capture is version 3, and main's strict reader refuses it as an unknown field. `collector.CaptureEnvelope` and `CaptureHeader` gain the optional `registration` (`CaptureRegistration`, every field required). `ReadCapture` accepts it only through `RegistrationReaders`, and `EncodeEnvelope` keeps payload bytes exactly. Tests: `TestRegisteredCaptureIdentity` and `TestEarlierReadersRefuseRegisteredCaptures`; the documented examples are updated (`TestDocumentedExamples`).
- [x] 3.1.3 Add the self-contained `external.Collect` seam and host attribution validation, not wired into runs (design Decision 12): Continue before dispatch, then Collect and ReadResult on one connection behind one result seam for 3.2, the stricter of host and negotiated limits, deadline and transfer failures as explicit incomplete limitations, and out-of-scope or missing subjects as diagnostics; test over mutual TLS `externaltest` servers.
  <!-- agent: tier=deep risk=high reason="Evidence scope, bounded transfer and failure semantics" -->
  Evidence: `external.Collect`, `external.Attribute` and `Frozen.CaptureReaders` in `internal/provider/external`; no run calls them. The tests run over mutual TLS `externaltest` servers. `TestCollectAttributesAgainstTheFrozenInventory` covers mixed-scope and unexpected-check items, missing subjects, bounded diagnostics without provider identifiers, no Acknowledge, and the capture read back only for its registration. `TestCollectSupplementRules`, `TestCollectContinuesTheFrozenRegistrationFirst`, `TestCollectBounds` (host and provider subject, byte and evidence bounds, nothing dispatched) and `TestCollectFailuresAreIncomplete` (malformed, digest mismatch, expired, refused, deadline, timeout, provider gone mid-transfer, unavailable, another release) cover the rest, with `TestCollectHostContextEnds`.
- [ ] 3.2 Implement immutable bounded result transfer and durable-capture acknowledgement; test interrupted transfer, checksum mismatch, result expiry, host restart and cleanup only after acknowledged capture or documented expiry.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.3 Connect external evaluation and the C2P bridge to projected frozen captures and exact RunContent, whose reporting-only check definitions come from the shared content extension (provider-contract task 6.2); test warning preservation, applied-versus-desired content, compatible replay without source access and explicit unavailable evaluator failures.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.4 Document evidence formats, C2P setup and offline replay dependencies; run the replay walkthrough with source access denied and verify unsupported historical versions fail explicitly.
  <!-- agent: tier=standard risk=medium -->

## 4. Optional scan requests and reference worker

- [ ] 4.1 Add explicitly authorized scan dispatch outside collection/evaluation; test capability denial, frozen approved targets, immutable operation keys and rejection of arbitrary images, commands or credentials.
  <!-- agent: tier=deep risk=high -->
- [ ] 4.2 Implement durable reference operation state and a synthetic Job worker; test lost start responses, concurrent retries, conflicting inputs and provider/controller leader changes without duplicate logical scans.
  <!-- agent: tier=deep risk=high -->
- [ ] 4.3 Implement bounded polling, cancellation, retry attempts and draining; test uncertain termination, operation timeout, late results, provider removal and completion after controller handover without changing closed captures.
  <!-- agent: tier=deep risk=high -->
- [ ] 4.4 Document the synthetic scan walkthrough and future Prowler CLI Job architecture; execute the example and label AWS scope, IAM, report compatibility and live Prowler acceptance as separate follow-up prerequisites.
  <!-- agent: tier=standard risk=medium -->

## 5. Independent distribution and compatibility

- [x] 5.1 Provide reference provider charts with dedicated identities, source-worker/evaluator separation and digest-pinned images; verify rendered permissions and live denied source access from the evaluator, TLS rotation and default absence from production registration.
  <!-- agent: tier=deep risk=high -->
- [x] 5.2 Add reference OCI image/chart signing, SBOM/provenance and verification instructions using existing build conventions; test valid and mismatched digest/publisher fixtures without publishing production artifacts.
  <!-- agent: tier=deep risk=high -->
- [ ] 5.3 Exercise provider upgrade, disable/drain, uninstall and retained evaluator compatibility; test in-flight identity pinning and explicit failures when compatible replay support is removed, and document rollback limits.
  <!-- agent: tier=deep risk=high -->

## 6. Conformance and installed acceptance

- [ ] 6.1 Extend the reusable conformance suite for remote reporting and scan providers; verify negative scope, malformed protocol, credential, duplicate-operation, bounded-transfer and deterministic-evaluation cases fail when deliberately broken.
  <!-- agent: tier=deep risk=high -->
- [ ] 6.2 Run required CI acceptance against the Helm-installed controller and reference provider charts; prove reporting and scan request to capture, OSCAL export, authorized download and failover paths using disposable Jobs.
  <!-- agent: tier=deep risk=high -->
- [ ] 6.3 Run the complete provider-authoring guide from an independent example directory in CI; verify build, install, register, assess, replay and uninstall commands, and link the guide from architecture/development documentation.
  <!-- agent: tier=standard risk=medium -->
- [ ] 6.4 Run pinned Devbox checks, affected live acceptance, strict OpenSpec and task-routing validation; reconcile prerequisite specs without marking deferred real providers supported, retain sanitized evidence and clean all task-owned infrastructure.
  <!-- agent: tier=standard risk=medium -->

