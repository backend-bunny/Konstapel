# Design

## Context

See [proposal.md](proposal.md) and the
[helm-distribution contract](specs/helm-distribution/spec.md). The repository
currently ships an assessment CLI and C2P provider, not a controller image or
Helm charts. `scripts/environment.sh` installs Kyverno only in a disposable
test cluster. `internal/assessment/target.go` already discovers policy/report
resources and waits for policy RBAC/webhook conditions, but its synchronous CLI
preflight is not the desired controller startup behavior.

Release-please uses one `VERSION`, with checks in `scripts/check-version.sh`.
The publishing workflow builds melange/apko images, signs their OCI digests with
keyless Cosign, attests provenance, and retains verification output. Devbox
already pins Helm 4.3.1, Cosign, Go, and cluster-test tools. Reuse those boundaries
and tooling; chart publication needs its own subjects and tests.

## Goals / Non-Goals

**Goals:** Make independently installed CRD and runtime releases a tested
operational contract; bind both release artifacts to their actual source and
runtime inputs; retain configuration through uninstall; support external engine
and certificate lifecycle without coupling engine availability to admission
service health.

**Non-Goals:** New compliance APIs, another controller manager, a bundled Kyverno
or cert-manager installation, automatic CRD deletion or destructive migration,
independent chart version streams, preview chart publication on every main
commit, an OLM distribution, or a custom certificate authority implementation.
Exceptions, assessment scheduling, and S3 downloads retain their existing
feature ownership and enablement gates.

## Decisions

### 1. Establish the integration contract before packaging runtime resources

The chart change owns `charts/`, chart scripts/tests, installation docs, and the
extensions to release/version automation and packaging of the merged controller
entry point in the existing image build. Publish a small reviewed input
contract identifying generated CRD/RBAC paths, available capabilities, manager
entry point, ports, probe semantics, certificate/working-directory configuration,
and image inputs. Resolve these from merged code before filling runtime templates.

| Existing change | Authoritative inputs consumed here |
| --- | --- |
| `add-compliance-targeting-api` | Initial manager, profile/binding APIs, generated CRDs/RBAC, targeting Conditions and policy delivery |
| `add-self-service-policy-exceptions` | Exception API, admission/governance handlers, compatible-engine matrix and expiry gate |
| `add-continuous-assessments` | Request/run APIs, admission epoch handling, scheduler and assessment readiness |
| `add-s3-evidence-publishing` | Download service, TLS interface, destination/credential configuration and authorization |

Chart metadata, rendering fixtures, version checks, and registry/publication
helpers can be developed before those implementations. Keep fixture schemas and
test images visibly separate from distributable chart content. Functional chart
publication requires the real targeting manager and generated APIs; optional
features appear only after their contracts are implemented and tested. A chart
must never turn the prototype CLI into a Deployment that merely crash-loops.

After the targeting manager lands, implement the capability monitor and its
manager integration as a separate commit phase on that boundary. Coordinate
shared registration, API-generated outputs, and release files after rebasing.
Do not create duplicate Go API types, hand-maintain chart copies of schemas, or
rewrite the other changes' task lists.

### 2. Give CRDs one owner and preserve them through chart removal

Use `charts/konstapel-crds` and `charts/konstapel`, with OCI repositories
`ghcr.io/backend-bunny/charts/konstapel-crds` and
`ghcr.io/backend-bunny/charts/konstapel`. These are independent Helm releases;
the runtime chart has no dependency on the CRD chart. Use one centrally managed
CRD release per cluster. The first runtime installation is also cluster-wide;
multiple competing controller installations are outside the initial support matrix.

Render generated CRDs as ordinary templates in the CRD chart so explicit Helm
upgrades apply schema changes. Helm's special `crds/` bootstrap directory does
not provide the required upgrade behavior. Preserve schema/default/validation
semantics and allow only reviewed packaging metadata changes. Chart validation
compares normalized output with the owning API generator's results.

Apply `helm.sh/resource-policy: keep` to every rendered CRD. Provide no chart
value or uninstall hook that deletes a CRD, recreates it for an upgrade, removes
custom-resource finalizers, or purges instances. The pinned Helm implementation
must pass real retention tests; an annotation alone is not evidence of safety.
No owner reference may cause a retained CRD to disappear with a release-owned
namespaced resource.

Retained CRDs retain Helm ownership metadata. Document reinstall with the same
release name and namespace, and test it against existing object UIDs and data.
Conflicting release identities require deliberate operator reconciliation, not
blanket adoption or deletion. The controller chart does not package user
profiles/bindings or native Kyverno policies as Helm-owned resources.

Upgrade CRDs first, then the runtime. Initially support additive compatible
schema evolution, validating existing objects and the previous controller against
the new schemas during the supported transition. Removal, narrowing, storage-version
changes, and conversion-webhook migrations need a separately designed migration
before that release can ship. Do not recommend `helm rollback` of the CRD release
as routine recovery; controller rollback is limited to tested schema combinations.

### 3. Align chart versions while keeping installation independent

Extend release-please's existing single package to update both Chart.yaml
`version` and `appVersion` fields from `VERSION`. Extend the existing version
helper to reject drift across application, melange, and both charts. Both charts
publish for every application version once chart distribution is introduced;
unchanged schemas still receive a new chart version and source provenance.

Separate installation does not promise arbitrary version skew. Publish a tested
version pair and an explicit upgrade transition matrix. Once charts ship,
chart-only changes that require a new distribution must use a release-producing
Conventional Commit type; they cannot replace an existing version's bytes.

Keep existing main-commit image publication. Publish versioned charts from the
release workflow and validated manual retries of existing releases, not every
main push under an unchanged application version. PRs render/package/test without
production registry writes or signing authority. This avoids collisions while
preserving the repository's current image development workflow.

### 4. Monitor external capabilities without crashing the manager

Add a capability monitor using Kubernetes discovery and authorization checks.
Check group/version, resource name/kind, scope, discovery verbs, and the service
account operations required by the owning implementation. A forbidden discovery
request is different from an absent API; both differ from a transport failure.
Use bounded request timeouts and retry backoff, and refresh cached discovery after
NoMatch or endpoint loss.

| Capability | Required external API resources |
| --- | --- |
| Policy delivery | Cluster-scoped `policies.kyverno.io/v1` ValidatingPolicy |
| Assessment | Namespaced PolicyReport and cluster-scoped ClusterPolicyReport in `wgpolicyk8s.io/v1alpha2` |
| Exceptions | Namespaced `policies.kyverno.io/v1` PolicyException, plus the exception feature's schema, governance and tested expiry prerequisites |

Register or resume dependent watches when their APIs are available. Avoid
unconditional startup of Kyverno informers that can make manager initialization
fail before it reports a missing dependency. Recover watches after API removal
and recreation, re-list current objects, and keep the existing continuity rules
for evidence gaps. Own Konstapel CRDs are installed first as a chart prerequisite;
the late-dependency behavior specifically covers the external engine.

Feed structured capability results into the existing feature Conditions rather
than adding another status CRD. Stable reasons include missing API, unsupported
resource shape, access denied, and dependency unavailable. Do not tie `/livez`
or the admission-serving part of `/readyz` to Kyverno discovery. A missing engine
must not remove the service endpoints needed to reject unauthorized configuration
or serve independently available evidence downloads. Failure of the actual
admission server or its certificate is a serving-readiness failure.

Gate only dependent operations. Missing reports make assessment unavailable;
they do not remove applied policies. Missing exception support prevents new grants
and keeps withdrawal/lifecycle diagnostics truthful without suppressing otherwise
supported delivery. Retain existing policies on dependency outages and recover
without reinstalling either chart. Discovery is not an enforcement proof: continue
using owned policy readiness Conditions and the existing evidence/expiry tests.
Version compatibility comes from the tested capability matrix, not equality with
the development cluster's Kyverno version string.

### 5. Delegate TLS lifecycle with an explicit external-certificate mode

Default to cert-manager APIs, supplied by the platform before chart installation.
Create namespaced Certificate/Issuer resources and webhook CA-injection metadata
for the actual release service names. The default issuer arrangement uses a
release-local CA through cert-manager; allow a supplied Issuer/ClusterIssuer
reference for platform PKI. Keep these resources in the controller chart; the
initial single-version CRD chart is independent of serving certificates.

Issue webhook and enabled download-service certificates for their configured DNS
identities. Default download exposure is an internal Service; external exposure
and any extra DNS names require explicit values. Wire serving-certificate reload
through the owning runtime contracts and test issuance and rotation, including
CA trust changes. Preserve admission failure policies and download authorization
through incomplete issuance or trust propagation. Never toggle validation off
to make installation or renewal appear successful.

External-certificate mode references existing Secrets in the controller namespace
with `tls.crt` and `tls.key`, plus explicit CA trust for webhook configuration.
Render no cert-manager objects in this mode and never claim ownership of those
Secrets. Validate mutually exclusive options, required keys and service identity;
runtime checks handle expiry and actual trust. Operators own certificate and CA
rotation, including updating supplied trust values. Chart packages contain no
private keys, tokens, or generated credentials. Backend S3 trust/credentials stay
under the publishing feature's independent configuration.

Keep TLS services unavailable when certificate prerequisites are invalid while
preserving diagnostics. This is different from tolerating absent Kyverno: the
controller cannot truthfully advertise a healthy TLS endpoint without a usable
certificate. Scope webhooks to the owning features' protected APIs and operations;
do not introduce a Konstapel workload-admission engine.

### 6. Package the real runtime with explicit health and storage settings

Consume generated RBAC and handler registration from the API owners. Chart values
configure image digest, resource limits, scheduling, probes, service identities,
TLS mode, bounded writable storage and implemented feature settings. Validate
these with values.schema.json. Do not expose switches that bypass central scope,
native exception governance, download authentication, or retention ownership.

The current image runs as UID 65532 with no shell. Preserve non-root operation,
read-only root, dropped capabilities and disabled privilege escalation. Mount
bounded writable directories for the manager/provider and any implemented
staging requirements; the controller's existing capture/recovery contract decides
whether storage must survive restart. Probes and hooks cannot assume a shell
exists inside the application image. Keep C2P executable/content paths aligned
with the image build. Do not claim multi-replica availability until leader and
admission behavior from the owning implementations passes its tests.

If the merged manager introduces another binary or command mode, extend the
existing build/melange/apko packaging to ship and exercise that entry point.
This change owns that packaging integration, while the targeting change owns
the manager implementation. Preserve the assessment CLI and provider smoke tests;
do not assume adding a Deployment makes the existing prototype image a controller.

Build a tested image from the release source and verify its published digest
before preparing the final controller chart. Inject that digest into an isolated
packaging copy, recording it as a build input; do not edit source files during
publication or default to a mutable tag. Final package tests consume that exact
archive and digest. A release cannot succeed by testing a development-values
render and publishing different defaults.

### 7. Extend the existing release pipeline with immutable chart subjects

Add a reusable chart-publishing workflow called after image publication. Preserve
the existing GITHUB_TOKEN/OIDC model, least job permissions, pinned actions,
release-target validation and serialization. Dispatch chart checks for bot-created
release PRs, just as current test/image workflows are explicitly dispatched.

Before any push, freeze both chart archives and a publication manifest containing
the source commit/tag, chart metadata, archive checksums, generated-CRD content
identity, default image digest, and relevant build-tool inputs. Retain these
inputs for retry. The image's existing build does not promise reproducible bytes;
do not rebuild it during chart retry and silently substitute a different digest.

Push the exact tested archives to the two OCI repositories, resolve the resulting
manifest digests from the registry, and verify their chart-layer checksums against
the frozen archives. Sign each OCI subject with Cosign and attach build provenance
plus the packaging-input record needed to establish the actual checked-out source
and image selection. In manual retries, distinguish the release checkout SHA
from the newer workflow-dispatch SHA; provenance must not misidentify the source.
Reuse the existing GitHub provenance mechanism where it represents those inputs
correctly, with an explicit supplementary attestation where needed.

Verification trusts the expected GitHub repository, release workflow identities,
OIDC issuer, immutable source revision and OCI subject. Verify the referenced
image under the existing image trust policy as well. A valid signature by an
unrelated identity, or provenance for the archive hash instead of the OCI subject,
does not satisfy the chart contract. Retain verification output with bounded
logs and timeouts as the image pipeline already does.

Treat chart version tags as write-once in the serialized publisher. If a version
exists, verify that it is the expected original artifact; never overwrite
different contents. Registry pushes are not atomic across two repositories:
represent partial completion explicitly and retry missing pushes/attestations
using retained packages or verified original artifacts. If original inputs cannot
be recovered, fail with a diagnostic instead of rebuilding a replacement for that
version. Only report the release pair complete after both remote subjects verify.
Limit production registry write permission to the trusted release path.

Extend the existing idempotent release-notes update with separate chart markers,
preserving generated changelog text and user notes. Show both chart versions,
digests, source revision, image digest and copyable verification/install commands
in release notes and CI summaries. Verification must lead to installation of the
same bytes: fetch the verified OCI subject, check its chart-content layer digest,
and install the resulting local archive. Never verify one digest and then install
an unchecked tag. Include the project's LICENSE/NOTICE in chart packages and
preserve any third-party template notices introduced during implementation.

### 8. Keep local and CI validation behind a small workflow interface

Use Devbox's pinned Helm and Cosign. Put orchestration in chart helper scripts.
Integrate chart lint/render/schema/version checks into `task check`; add public
`charts:package` and `charts:acceptance` workflows only for those distinct recurring
outcomes. Signing, digest lookup, summary rendering and individual test helpers
remain private commands. Declare any additional required tool in Devbox rather
than installing a second toolchain in CI.

Use rendering fixtures first, then a disposable kind environment with explicitly
recorded Helm, Kubernetes, Kyverno and cert-manager versions. Cover both TLS modes,
late engine discovery, revoked permissions and API recovery, actual controller/C2P
operation, CRD upgrades and same-schema version bumps, uninstall retention and
same-identity reinstall. Test the certificate and exception behavior only when
their real feature implementations are present; fixture success is not a release
claim for an absent feature. Registry fixtures exercise mismatched subjects,
tampered packages, partial publication and retry without production credentials.

## Risks / Trade-offs

- **Retained CRDs become unmanaged after uninstall:** document and test same-release
  reinstallation, and preserve ownership rather than adopting unknown definitions.
- **Helm retention and schema upgrades are version-sensitive:** test the pinned
  client against real custom resources and make lifecycle failures release-blocking.
- **External APIs can disappear after startup:** re-establish discovery/watches
  with bounded retries and preserve truthful status and existing enforcement.
- **TLS bootstrap can interrupt admission:** separate serving and engine readiness,
  preserve failure policies, and exercise issuance, CA changes and Secret rotation.
- **Runtime uninstall stops governance and cleanup:** retaining CRDs preserves
  data but does not continue admission handlers, assessments or S3 retention work.
  The uninstall runbook must use the exception/storage owners' withdrawal and
  retained-artifact procedures before removing needed services or credentials.
- **Two OCI artifacts cannot publish atomically:** freeze inputs, expose partial
  completion, and verify both digests before announcing a successful release pair.
- **Concurrent feature work can conflict in generated/release files:** land the
  input contract first and integrate only the merged owners' implementations.

## Migration Plan

1. Land the chart input contract and fixture/publication helpers independently.
   Keep production chart publication disabled until a real controller is packaged.
2. Consume the merged APIs and manager, generate chart resources, and validate
   the runtime, certificate and capability-recovery contracts.
3. Publish the first verified chart pair through release-please. Verify both
   OCI subjects and their packaged image before installation.
4. Install the CRD release, then the controller with cert-manager or supplied TLS.
   Kyverno can already exist or arrive later; validate an Audit binding before
   using Deny according to the targeting workflow.
5. For upgrades, validate the documented transition, upgrade CRDs first, then the
   controller. Roll back only the controller to a tested compatible version;
   retain newer schemas and records during that recovery.
6. For uninstall, follow the feature-specific withdrawal/retention procedures,
   remove runtime resources when safe, and optionally uninstall the CRD release.
   CRDs and instances remain. Any eventual CRD deletion is a separate explicit
   administrator operation after the required data and obligations are handled.
