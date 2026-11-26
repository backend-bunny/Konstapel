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

## 3. Remote evidence and replay

- [ ] 3.1 Integrate remote read-only collection with host scope, inventory and limits; test mixed-scope payloads/diagnostics, missing subjects, malformed results and deadline closure without scans.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.2 Implement immutable bounded result transfer and durable-capture acknowledgement; test interrupted transfer, checksum mismatch, result expiry, host restart and cleanup only after acknowledged capture or documented expiry.
  <!-- agent: tier=deep risk=high -->
- [ ] 3.3 Connect external evaluation and the C2P bridge to projected frozen captures and exact RunContent; test warning preservation, applied-versus-desired content, compatible replay without source access and explicit unavailable evaluator failures.
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

- [ ] 5.1 Provide reference provider charts with dedicated identities, source-worker/evaluator separation and digest-pinned images; verify rendered permissions and live denied source access from the evaluator, TLS rotation and default absence from production registration.
  <!-- agent: tier=deep risk=high -->
- [ ] 5.2 Add reference OCI image/chart signing, SBOM/provenance and verification instructions using existing build conventions; test valid and mismatched digest/publisher fixtures without publishing production artifacts.
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

