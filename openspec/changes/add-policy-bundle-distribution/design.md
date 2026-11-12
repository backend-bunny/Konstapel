# Design

## Context

See [proposal.md](proposal.md) for motivation and the
[capability spec](specs/policy-bundle-distribution/spec.md) for behavior.
`internal/assessment/content.go` and `provider.go` currently read a fixed
privileged-container policy, Component Definition, and NIST content from a local
root. `content/provenance.json` and `content/SHA256SUMS` identify those inputs;
there is no OCI bundle resolver or publisher.

PR #50 introduced `api/v1alpha1.BundleReference` with `name` and `digest`, and the
shared `internal/targeting` contribution/revision contract. The targeting resolver
and production manager remain unfinished. The Linux hardening change owns four
additional policy variants. The chart plan owns aligned application/CRD chart
publication; those versions are deliberately independent of bundle releases.

## Goals / Non-Goals

**Goals:** Resolve immutable, trusted content through ordinary reconciliation;
keep source configuration separate from enforcement; publish portable content
that another organization can author with the same validation tools.

**Non-Goals:** A universal cross-engine bundle standard, runtime dependency
resolution, arbitrary provider/plugin installation, automatic version selection,
new bundle CRDs, or persistent-cache high availability. Self-contained content
does not promise cold-start operation without a registry or verification evidence.

## Decisions

### 1. Preserve the name/digest API and resolve sources centrally

Keep `ComplianceProfile.spec.bundle` unchanged. Its name is the logical bundle
name and its digest is the SHA-256 of a single OCI manifest. A platform-managed,
versioned configuration document maps each name to one exact OCI repository,
optional registry Secret/custom CA references, and publisher/provenance rules.
Reject duplicate names, embedded tags/digests in repository configuration, and
missing sources; require the payload name to match the profile name.

Load this configuration from a named ConfigMap in the controller namespace and
watch that object and explicitly referenced Secrets/CA objects. Validate updates
as an atomic configuration revision. Invalid or removed configuration makes
affected resolution unavailable; it cannot silently retain old trust as current.
Keep sensitive data out of the ConfigMap and restrict source/trust writes to
platform administrators. Grant only the namespace-local read permissions the
loader actually needs; do not introduce cluster-wide Secret access.
The bundle Role grants these reads by name, but RBAC is additive: the
controller ServiceAccount is shared by every feature, and its generated Role
already allows Secret and ConfigMap `get` by any name in the controller
namespace for CR-named S3 credentials, CA trust and runtime-named snapshots.
The bundle Role's effective addition is therefore the named `list`/`watch` of
the sources ConfigMap; narrowing the shared `get` would be a separate contract
change (docs/charts.md, "Controller ServiceAccount boundary").

A mirror replaces the configured repository while retaining the expected name,
digest, and original publisher/source constraints. Multiple registries and bundle
families are supported through separate entries. Automatic mirror failover and
ambiguous prefix-based source selection are deferred.

An OCI reference field on every profile would duplicate source and trust settings
and require another alpha schema change. Central name resolution uses the merged
contract and gives administrators one place to rotate credentials or mirror a
repository. These central edits trigger re-resolution, but do not change content
semantics or manufacture profile generations.

### 2. Define a small versioned payload over standard OCI distribution

Use an OCI 1.1 image manifest with artifact type
`application/vnd.konstapel.policy.bundle.v1+json`, an OCI empty config descriptor,
and one deterministic gzip-compressed tar layer. Use
`application/vnd.oci.image.layer.v1.tar+gzip` for the filesystem layer. Reject
indexes and unexpected layer layouts in this version. The payload schema is a
Konstapel contract; OCI and OSCAL supply the standardized outer distribution and
compliance document formats, not a pre-existing C2P OCI bundle standard.

The archive has this conceptual layout; concrete policy paths are recorded in
the descriptor rather than inferred by filename:

```text
bundle.json
content/
  component-definition.json
  upstream/                 # preserved policy and NIST source material
  policies/                 # explicitly identified local variants, if any
  schemas/                  # pinned OSCAL and parameter schemas
  provenance.json
  SHA256SUMS
tests/                      # declarative policy cases
LICENSE
NOTICE
licenses/                   # applicable third-party terms and notices
```

The versioned JSON descriptor identifies name, SemVer release version, immutable
source repository/revision, logical policy/check inventory, provider contract,
parameter-schema paths, workload/OS scope, compatibility requirements, and OSCAL
entry points. Konstapel supports Linux workloads only: the only compatible OS
scope is exactly `["linux"]`. An empty, repeated or unrecognized scope is an
invalid descriptor; `windows` is recognized solely so that content naming it,
alone or mixed with `linux`, is reported Incompatible and never adopted. This
implies no Windows support. Its file inventory records relative paths, roles, sizes, and SHA-256
digests for all regular payload files except `bundle.json` itself. The enclosing
OCI digest authenticates the descriptor; do not create a circular self-checksum.
Retain the existing content checksums as provenance and validate them as well.

Preserve C2P Rule_Id/Check_Id mappings and upstream-relative references where
possible. Include the NIST catalog/Moderate profile and each declared OSCAL schema
version, preserving official 1.2.3 documents alongside C2P-compatible 1.1.3 authored
documents. Validate structural schemas plus semantic reference closure: IDs,
Moderate membership, provider/check correspondence, and coverage boundaries.
Informational source URLs are permitted; imports, schema references, and other
required content must resolve inside the archive without network access.

Composition occurs at build time. The hardening bundle can reuse the existing
privileged policy's source paths without maintaining another source copy; its
published archive contains the complete selected set. A small definition under
`bundles/<name>/` selects existing content and records that bundle's version and
compatibility. It does not replace the policy owners' source manifests or invent
another rule identity scheme.

### 3. Validate declarative content against installed capabilities

Reject unknown schema versions, duplicate identities or JSON/YAML keys, invalid
parameters, unresolved checks, and mismatches between descriptor claims and
actual policy resources. Only supported declarative `policies.kyverno.io/v1`
ValidatingPolicy inputs targeting namespaced Linux workloads enter the initial
provider path. Preserve the established omitted-OS convention and partial
Moderate claims. Test fixtures, original source copies, licenses, and notices
are data and are not automatically applied.

The descriptor declares controller and Kyverno version constraints, required
GVKs/features, OSCAL versions, and the installed provider contract identifier.
Publish a tested compatibility matrix; version ranges alone do not prove engine
capabilities or exception governance. Engine discovery/readiness remains owned
by the targeting/chart integration, and absence can recover without refetching
otherwise valid content. Distinguish content compatibility from live engine
readiness in the resolution result.

Bundle data cannot choose an arbitrary C2P executable. Resolve provider IDs only
through Konstapel's installed allowlist. Do not run packaged scripts or plugins,
install additional Kubernetes resources, or introduce alternate exception paths.
Rendering consumes the existing contribution contract for selector, mode,
parameters, ownership and exception eligibility; it records rendered hashes
separately from source, archive, and OCI hashes.

### 4. Retrieve content and verification artifacts through one bounded adapter

Use ORAS Go v2 for OCI graph retrieval and maintained Cosign/Sigstore Go libraries
for verification, pinned to releases compatible with the repository's Go
toolchain. Keep transport, verification and local content validation separable
for testing. Reuse standard registry challenge/token handling; do not implement
an authentication protocol or shell out to a CLI inside the controller image.

Support anonymous access or a configured `kubernetes.io/dockerconfigjson` Secret
in the controller namespace. Read credentials only for the configured registry,
refresh on Secret updates, and discard cached authentication tokens on rotation.
A configured-but-missing Secret is an error, not a request for anonymous fallback.
Do not execute credential helper programs named by untrusted JSON. Require TLS
verification with system or configured CAs; insecure HTTP belongs only to
explicit isolated test fixtures. Preserve standard authenticated registry token
flows without forwarding credentials across unrelated redirects or repositories.

Docker Hub aliases (`docker.io`, `index.docker.io`, `registry.hub.docker.com`,
`registry.docker.io`, `hub.docker.com`) are rejected in `repository` at
configuration load, and by the adapter through the same validation, with an
error naming `registry-1.docker.io`, the `auths` entry and `tokenRealms`.
Identities and credential lookups are never rewritten; alias support may follow
as an explicit tested compatibility feature.

Credentials go to the source's registry origin and, only when the central source
lists it, to a bearer token realm on another origin (Docker Hub's
`auth.docker.io`, GitLab.com's `gitlab.com`). The per-source `tokenRealms`
allowlist holds exact `https://host[:port]` origins, validated when the
configuration loads: no paths, wildcards, userinfo, IP addresses or localhost,
and not the registry's own origin, whose realm behaves as before. A challenge
naming any other realm gets no credential. A request to a listed realm carries
the credential only as a token request whose every scope is the source's own
repository with the actions the operation needs (pull to retrieve, pull and push
for the publisher), is never redirected, and a refusal or timeout fails the
attempt rather than retrying anonymously. The adapter enforces this beneath the
standard ORAS token flow instead of replacing it; realm addresses ORAS already
blocks stay blocked. A per-registry allowlist was chosen over trusting any
public realm because the registry, not the operator, names the realm in its
challenge.

The same adapter retrieves the subject and required signature/provenance
referrers from the configured repository, in the OCI referrers layout written by
the pinned Cosign publisher. It lists referrers through the OCI 1.1 referrers
API first; when a registry does not serve that API, it reads the OCI referrers
tag schema index (the image index tagged `sha256-<subject hex>`, OCI
distribution spec "backwards compatibility"), which is how registries without
the API, including the reference registry and GitHub Container Registry, keep
referrers. Either listing is an unauthenticated, mutable hint: every listed
entry is fetched by digest and must pass the same exact-subject checks, and the
tag index is bounded, digest-checked against its declared descriptor and parsed
strictly. A registry with neither yields no referrers, so required proofs are
reported missing. Validate this against a real registry. Do not claim arbitrary
OCI registries work solely because they accept a manifest. Cosign's legacy
`.sig`/`.att` signature tags and separate signature repositories are not part of
this version.

Start with documented deployment defaults: 4 concurrent resolutions, 30-second
individual network timeouts, a 2-minute resolution attempt, and jittered retry
backoff from 5 seconds to 5 minutes. Bound referrer count and downloaded proof
bytes as well as payload bytes; use 64 referrers and 16 MiB verification metadata
as initial limits. Deduplicate concurrent requests for the same source/digest;
cancel obsolete work and check configuration revisions again before publishing
a result. Downloads must not block unrelated reconciles or health endpoints.

Kubelet image volumes were considered. Their Pod-start lifecycle would require
controller restarts or loader Jobs and an additional content-transfer protocol,
while signature retrieval would still need attention. Direct retrieval keeps
dynamic profile selection and both content/evidence authentication in one path.
Konstapel explicitly requires its own registry access; node pull credentials are
not inherited. Cloud-specific credential-provider integrations are deferred.

### 5. Verify publisher identity and build provenance for the pinned subject

Require both a subject signature and an in-toto SLSA provenance v1 attestation
for the exact requested OCI manifest digest. A source rule defines acceptable
signers, builders and source repositories. Verify the attested source revision,
bundle name/version, and declared materials against the descriptor. The same
configured publisher rule must authorize the signature and provenance; signature
presence, archive-hash attestations, or arbitrary signed builder claims do not
satisfy it. Do not claim a SLSA assurance level from merely emitting the predicate.

Support alternative publisher rules of two types:

- Keyless: exact OIDC issuer and certificate identity, trusted Sigstore roots,
  and authenticated signing-time/transparency evidence. Official releases use
  the dedicated GitHub bundle workflow identity. Check leaf validity at verified
  signing time, including relevant transparency checks, rather than requiring
  the short-lived signing certificate to be unexpired when consumed later.
- Public key: an explicitly referenced public key and fingerprint, with signed
  provenance verified under that publisher rule. Organizations can use this
  mode without a public transparency service. Private keys never enter Konstapel.

A trusted root authorizes no publisher by itself. The embedded Sigstore
public-good root stays the default for public keyless verification and a rule
may reference its own root instead (replacing it, never falling back), but every
keyless rule must name one exact, non-empty issuer and identity; empty values,
wildcards, regular-expression characters, surrounding space or pattern fields are
configuration errors at parse time and again in the verifier.

Provenance is required for every publisher, but a GitHub workflow record is not.
The provenance predicate holds exactly one build record, selected by the rule's
exact builder and kept apart from the source revision:

- GitHub publishers: a builder of the form
  `https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>` requires the
  workflow record (repository, path, ref, commit), whose repository, path and ref
  must equal the builder's. A keyless rule with the GitHub Actions issuer must
  name such a builder, so GitHub publishers keep issuer, identity, builder and
  workflow constraints.
- Organization builders (any other builder id, typically an organization's own
  pipeline signing with its key): the builder record `{"revision": <string>}`
  is required and a workflow record is refused, because nothing could check it.
  The rule's exact builder and source repository constrain them.

Both, neither, or the wrong record fails verification; the release tool writes
the form the rule's builder requires (`-builder-revision` for organization
builders) and refuses to sign otherwise. The selection is derived from the
already-configured builder, so the rule revision and existing configurations are
unchanged. Binding the workflow record to the Fulcio certificate's GitHub
workflow claims is not done; the record's commit is recorded, not authenticated.

Trust roots, keys and builder/source constraints come only from central
configuration, never from fields that the fetched artifact asks the verifier to
trust. Provide documented public Sigstore trust-root configuration for official
releases and an operator-controlled update path. Missing necessary proof or an
unavailable required trust input fails resolution; there is no verification-off
switch. Signature/provenance metadata is attached to the subject, not embedded
recursively in the payload whose digest it signs.

Verification is tested with isolated test roots and keys and signed fixtures:
pinned Cosign CLI output for public-key mode, and sigstore-go's virtual Sigstore
and a test CA for keyless checks. Real keyless Cosign output is covered by
checked-in proofs from GitHub Actions and the first official bundle release
against the public-good root, plus an opt-in network test (`publicinterop` build
tag) that retrieves that release anonymously and verifies it under the official
source configuration, refusing other identities. A full isolated Sigstore stack
(Fulcio, Rekor) is not deployed; consequently Cosign CLI keyless output under
isolated roots remains unverified and task 3.5 stays open for that gap.

Record verification time, source/trust revision, signer identity or key
fingerprint, trusted-root identity, proof/attestation hashes and predicate
identity in a receipt. Retain the evidence needed to recheck that receipt locally
when possible. OCI hostname is a retrieval location, not proof of publisher
identity: mirroring preserves original source/signer claims.

### 6. Cache immutable bytes and separately evaluate current acceptance

Stage content in an owned directory, verify manifest/blob digests, then extract
with explicit path and resource limits. Reject absolute or escaping paths,
symlinks, hardlinks, special files, duplicate normalized paths, and decompression
overruns. Initial configurable limits are 64 MiB compressed payload, 256 MiB
unpacked payload, 4096 regular files, and a 1 GiB cache including staging and
verification material. Reserve capacity before concurrent writes; failure is
observable and leaves accepted entries intact. Do not execute content while
validating it.

Promote only fully validated content atomically. Store immutable raw OCI/content
bytes by digest, with integrity checks on reuse and after restart. Acceptance is
separate and keyed by name/digest, source rules, trust/key/root revision, and
controller/provider compatibility. A cache hit is not permanent authorization.
Watch config/key changes to invalidate affected receipts and enqueue profiles;
before adoption ensure no concurrent revision has invalidated the result.
Credential rotation invalidates transport tokens but need not invalidate
cryptographic trust in already verified content.

Pin entries referenced by desired profiles, last applied contributions, or
active assessment snapshots. Use bounded least-recently-used eviction for
unreferenced entries; if active pins exceed capacity, fail new resolution rather
than silently evicting content still needed. Release pins when owners finish or
advance. The default cache is bounded `emptyDir`, with optional operator-provided
persistent storage using the same integrity/revalidation rules. Do not promise
survival of a Pod replacement or node loss with the default cache.

During a registry outage, intact content and complete proof that still satisfy
current trust can be reused. Lost cache, missing proof, new trust requirements,
or incompatibility remain unresolved. After a restart, reconstruct applied
ownership through the targeting contract; cached status alone cannot authorize
content. Preserve existing engine instances without pretending that missing
content has resolved. Cache retention is independent of S3 evidence retention.

### 7. Integrate resolution without changing enforcement identity

Expose a resolved-content handle with name/version, manifest digest, checked
paths, logical policy metadata, compatibility result, verification receipt, and
an explicit cache lease. Adapt the assessment content/provider boundary to
consume validated roots and generalized mappings while preserving existing
prototype commands and capture formats. Do not hard-code another single-policy
path in the OCI resolver.

The targeting change retains ownership of the resolver, manager, policy names
and `targeting.EnforcementRevision`. Its `BundleDigest` is the selected manifest
digest for the new transport; mapping/rendered hashes remain separate. A source
mirror or credential rotation alone does not create a new semantic revision.
A profile digest edit or rollback uses the existing generation/revision scheme,
including its exception invalidation and create-before-retire readiness behavior.
Do not rewrite historical prototype digests or increment the contract version
without an actual coordinated algorithm change.

Set profile `Resolved` conditions with observed generations and useful bounded
reasons for missing source, authentication, verification, malformed content,
incompatibility or cache exhaustion. Map unavailable content into the existing
targeting `ContentUnavailable` boundary while retaining detailed profile reasons.
Bindings distinguish desired resolution from their last applied revision and
engine readiness. Network/config changes requeue affected profiles; they do not
require profile edits merely to retry.

On failed update or trust revocation, retain already applied owned policies and
report them stale/unresolved; do not newly install or reapply rejected content.
Unresolved eligibility cannot grant a new exception. Revocation is not automatic
policy deletion: an administrator must explicitly replace or remove centrally
managed configuration to withdraw enforcement. Engine evaluation may continue,
but current trusted resolution or compliance is never inferred from its presence.

The assessment producer consumes the applied content handle and verification
receipt, copying required content into its frozen package before releasing its
cache lease. Reports retain desired/applied differences and coverage limits.
Coordinate descriptor additions through the continuous-assessment owner; do not
create another evidence archive, run CRD, or retention mechanism here.

### 8. Publish bundles through an independent release path

Publish official bundles to `ghcr.io/backend-bunny/bundles/<name>` with their own
SemVer tags. Keep each version in its bundle definition and use Git release tags
`bundle/<name>/vX.Y.Z`, separate from application `vX.Y.Z` tags. The initial
dedicated workflow is dispatched on `main` with a bundle name and immutable
reviewed source commit. Require ancestry on `main` and a version declared in that
checkout; create or verify the matching bundle tag. It does not invoke the image
or chart publishers or depend on a release-please application release. Preserve
existing application release automation; automated bundle version proposals can
be added later without changing artifact semantics.

Build deterministically from pinned inputs: sorted paths, fixed ownership/modes,
source-derived timestamps, stable JSON, deterministic gzip headers, and recorded
tool versions. The local descriptor never includes the final OCI digest. Verify
checksums, all content/reference rules, and the selected policy fixtures before
freezing the archive and OCI manifest. Official policy compatibility claims also
require the owning content's live acceptance evidence for those exact source and
variant inputs; a packaging-only test does not establish runtime enforcement.

Use pinned Devbox tooling and a GITHUB_TOKEN/OIDC workflow with least permissions
and serialized publication. Push the frozen bytes, read back and verify the
remote subject, sign that digest, attach build provenance, and verify using the
same consumer contract. Bind provenance to the actual source checkout, bundle
definition/materials, tests, and build tools; record the dispatch/workflow SHA
separately when a retry packages an older source revision. Adapt the existing
attestation helpers only when they can represent those facts correctly.

Versions are write-once within the publisher. Retain frozen inputs and a
publication record so a partial upload, signature or attestation failure retries
the same bytes. An existing identical subject can have missing evidence completed;
different bytes are a conflict. If recovery cannot establish the original inputs,
fail rather than replace a release. Limit production registry writes to the
trusted publisher, and do not advertise a GitHub release as complete before its
remote subject and required evidence verify.

Release notes and CI summaries identify bundle version, digest, source revision,
compatibility, policy inventory, licenses, test evidence and copyable Cosign
verification commands for the exact digest. Document copying the subject and its
referrers without rewriting the manifest. A mirrored repository's central trust
entry must still allow the original publisher, builder and source.

### 9. Divide implementation at existing ownership boundaries

This change owns the bundle schema/packager, independent release workflow,
transport/verification/cache module, central source configuration and integration
adapter. It can build format, signing and private-registry fixtures immediately.
Publish the resolved-content handle before integrating the unfinished targeting
resolver/manager; coordinate through that owner rather than implementing a second
manager or editing competing generated API outputs.

The existing privileged policy is the first packaging fixture and release input.
Integrate the four Linux variants only after their owning content change merges;
do not mark them shipped or validated because a bundle transport test passes.
Shared assessment/provider edits need a rebase onto their latest owner work.
Evidence integration waits for the assessment descriptor contract, not the full
S3 service. Chart values, named configuration objects, Secret references and
cache mounts integrate after the Helm chart implementation lands; this change
does not generate competing charts.

Put validation into the existing `task check`/content workflows and keep helper
commands behind their callers. Add only two distinct recurring public workflows,
`bundles:package` and `bundles:acceptance`; signing, referrer lookup, summary
rendering and publication helpers are not separate public tasks. Document the
interface and pin any added CLI tools in Devbox. Go libraries remain in go.mod.

Acceptance uses an authenticated TLS OCI registry with referrers and recorded
versions, plus the existing disposable Kyverno cluster for profile integration.
Cover both signing methods, actual publisher-to-consumer interoperability,
mirroring, credential/key rotation, malformed payloads, bounded retries, cache
loss/corruption, trust revocation, failed upgrades, and new-generation rollback.
Use isolated test roots/keys and signing-time fixtures for keyless failure tests;
do not disable production verification to make local tests pass. Verify one
official OIDC-published subject through the production trust path before claiming
official release acceptance. Clean up only task-owned registry/cluster resources.

## Risks / Trade-offs

- **Another registry credential consumer:** use standard Secrets and maintained
  libraries, document least-privilege pulls, and test rotation/redaction.
- **Signatures outlive changing trust:** separate immutable bytes from acceptance,
  re-evaluate policy revisions, and make stale applied enforcement explicit.
- **Registry referrer interoperability varies:** test the selected layout and
  private mirror end to end; missing proofs cannot silently weaken verification.
- **Self-contained catalogs duplicate bytes:** accept the storage cost for one
  reproducible content identity and dependency-free rendering.
- **Ephemeral cache loss during an outage:** preserve installed policies and
  report unavailability; optional durable storage does not bypass integrity checks.
- **A signed policy still has semantic effects:** require existing content review,
  scope/governance validation and bounded NIST mappings before publication.
- **Multiple agents touch shared integration files:** land the handle first,
  rebase on owning changes, and keep revision/API ownership explicit.

## Migration Plan

Introduce the schema, packager and transport tests using the existing local
content first. Publish a verified independent bundle release and configure its
repository, current trust roots/rules and optional credentials. Once targeting
integration lands, select its manifest digest in an Audit profile/binding, then
exercise Deny, failed upgrades, credential/key rotation and rollback. Old sample
digests without a published subject are fixtures, not resolvable releases.

Roll back content through an explicit profile digest change, retaining a
compatible controller/provider and the old artifact/proofs. Keep the existing
policy replacement and exception-revision boundaries. For a controller downgrade
that cannot consume a newer bundle schema, select supported content first.
Deleting registry or cache content must not silently remove enforcement, and
published assessment packages remain independent of runtime caches. Leave the
prototype's local workflows and historical captures usable.
