# Policy bundles

A policy bundle is the versioned, signed unit in which Konstapel distributes
policy content: Kyverno policies, their tests, and the OSCAL/C2P mappings to
NIST controls. A profile references a bundle by name and digest; the controller
resolves it centrally and verifies it before use.

> **Status.** This page documents the payload contract implemented in
> [`internal/bundle`](../internal/bundle) and how to build a bundle locally.
> Publishing a release, signing, and runtime resolution by the controller are
> tracked in the `add-policy-bundle-distribution` OpenSpec change and are **not
> available yet**: no official bundle has been released, and a locally built
> bundle cannot yet be consumed by a profile. Until those land, the only
> supported way to deliver policies is the existing prototype workflow in
> [development](development.md). This page gains release and mirroring
> instructions as each group lands.

## OCI layout

A bundle is one OCI 1.1 **image manifest** (never an index):

| Field | Value |
| --- | --- |
| `artifactType` | `application/vnd.konstapel.policy.bundle.v1+json` |
| `config` | the OCI empty descriptor (`application/vnd.oci.empty.v1+json`, `sha256:44136f…aff8a`, size 2) |
| `layers` | exactly one layer, `application/vnd.oci.image.layer.v1.tar+gzip` |

Any other manifest shape, extra layer or different layer type is rejected in
format v1. Signatures and attestations are separate OCI referrers on the
manifest digest, never layers.

## Archive layout

```text
bundle.json                  # descriptor (below)
content/
  component-definition.json  # OSCAL component definition
  upstream/                  # preserved policy and NIST source material
  policies/                  # locally authored policy variants, if any
  schemas/                   # OSCAL and parameter schemas
  provenance.json
  SHA256SUMS
tests/                       # declarative policy cases
LICENSE
NOTICE
licenses/                    # third-party terms and notices
```

Only `content/`, `tests/`, `licenses/`, `LICENSE` and `NOTICE` are valid payload
locations. Paths are clean and relative; the policy paths are recorded in the
descriptor, never inferred from filenames.

## Descriptor (`bundle.json`)

```json
{
  "format": "konstapel.policy.bundle/v1",
  "name": "acme-baseline",
  "version": "1.2.3",
  "source": {"repository": "https://github.com/acme/policies", "revision": "<40-hex commit>"},
  "policies": [{
    "name": "disallow-privileged",
    "path": "content/policies/disallow-privileged.yaml",
    "parameterSchema": "content/schemas/disallow-privileged.json",
    "checks": [{"ruleID": "no-privileged", "checkID": "check-no-privileged"}]
  }],
  "scope": {"workloads": ["Pod", "Deployment"], "os": ["linux"]},
  "compatibility": {"provider": "kyverno/v1", "konstapel": "0.1.0"},
  "oscal": [{"path": "content/component-definition.json", "version": "1.1.3"}],
  "files": [
    {"path": "content/policies/disallow-privileged.yaml", "role": "policy", "size": 812, "sha256": "<hex>"}
  ]
}
```

- `name` is a DNS label and `version` is SemVer; the release is immutable.
- `source.revision` is the full commit the content was built from.
- `policies[].checks` carry the C2P `Rule_Id`/`Check_Id` pairs unchanged. Rule
  and check IDs are unique across the bundle.
- `files` inventories **every** regular payload file except `bundle.json` with
  role, size and SHA-256. Roles: `component-definition`, `upstream`, `policy`,
  `schema`, `provenance`, `checksums`, `test`, `license`. Exactly one
  `provenance` and one `checksums` file and a `LICENSE` are required.
- The descriptor has no checksum of itself: the OCI digest authenticates it.
- Policy, schema and OSCAL entry-point paths must appear in `files` with the
  matching role, and the payload must match the inventory exactly. Unknown
  fields, unsupported formats, duplicate identities or keys, missing or extra
  files and digest mismatches are all rejected.

An organization bundle uses the same format and the same verifier as an
official one; it differs only in who publishes and signs it.

## Deterministic builds

`bundle.Build` turns a definition (descriptor fields plus a list of
`from`/`to`/`role` includes read from a source tree) into the archive layer and
OCI manifest. Building is reproducible: identical definition, source bytes and
source-commit time give byte-identical output and therefore identical digests.
Entries are sorted, owned by uid/gid 0 with mode `0644`, stamped with the source
commit time, and gzip headers carry no name or time. Nothing is downloaded at
build time, and the descriptor never records the layer or manifest digest.
Before returning, the builder re-reads its own output and verifies the manifest
shape, the descriptor and every inventoried file.

`bundle.Unpack` is the matching reader for untrusted archives: it accepts only
regular files in valid payload locations, rejects duplicates, and enforces file
count and size limits before the descriptor and inventory are verified.

`bundles:package` (below) drives this; registry publication is not available yet (see [Release a bundle](#release-a-bundle)).

## Bundle definitions

A bundle is defined by a small JSON file at `bundles/<name>/definition.json`.
It holds the descriptor fields (name, version, source repository, policy and
check inventory, scope, compatibility, OSCAL entry points) and an `include` list
that selects existing repository files into archive paths:

```json
{"from": "content/component-definition.json", "to": "content/component-definition.json", "role": "component-definition"}
```

The definition selects content that other owners maintain; it does not copy or
replace it, and it does not rename any C2P `Rule_Id`/`Check_Id`. It cannot name
its own commit: the build supplies `source.revision` and the commit time.
`{"generate": "sha256sums", "to": "content/SHA256SUMS", "role": "checksums"}`
makes the builder write a `sha256sum -c` compatible list of every `content/`
file. Upstream test fixtures stay beside the policy they exercise, so their
relative paths keep working when the archive is unpacked and tested.

### First bundle: `konstapel-privileged-containers`

`bundles/konstapel-privileged-containers/definition.json` packages the existing
Kyverno `disallow-privileged-containers` policy with its upstream tests,
licenses, provenance, the pinned NIST catalog and Moderate profile, the OSCAL
1.1.3 and 1.2.3 schemas, and the existing bounded AC-6 component definition
(partial technical evidence only; it does not claim AC-6 or Moderate
satisfaction). Tests build it from this repository and check, on the unpacked
payload: the packaged checksums verify and agree with `content/SHA256SUMS`, the
AC-6 mapping and descriptor inventory correspond, and the upstream Kyverno
fixtures pass. The bundle is defined but **not published**.

## Content validation

`bundle.ValidateContent` checks an unpacked payload's declarative content. It
reads only the payload (no network or registry access), never applies or runs
anything in it, and runs during `bundles:package` and `task check`. It checks:

- Only the installed provider contract (`konstapel-kyverno/v1`) is accepted;
  bundle data cannot name another executable.
- Every declared OSCAL entry point exists, validates against the pinned schema
  for its declared version, and states that version itself. Mixed versions are
  normal: authored component definitions must be C2P-compatible OSCAL 1.1.3,
  and the official NIST catalog and Moderate profile keep 1.2.3. Each declared
  version's schema must be in the archive and self-contained (no external
  `$ref`).
- Every import and control `source` resolves inside the archive. Informational
  `links`/`rlinks` URLs are allowed and never fetched.
- No JSON key (descriptor, OSCAL, parameter schemas) and no YAML key repeats.
- The existing prototype validation runs on the payload unchanged: schema
  validity, catalog and Moderate-profile consistency, controls restricted to
  the Moderate baseline, statements that belong to their controls, every rule
  described, mapped and given a matching `Check_Id`, and every rule backed by a
  policy in the bundle. A bundle must therefore carry the NIST catalog and
  profile and the schemas at their `content/` paths.
- The descriptor's logical checks equal the rules the component definitions map
  (`checkID` equals `ruleID`, the C2P convention the provider matches on), and
  each policy is a `policies.kyverno.io/v1` `ValidatingPolicy` whose
  `metadata.name` is the name the descriptor gives it.

`bundle.ValidateParameters` validates a profile's parameters for one policy
against its declared parameter schema. The schema must describe an object and
be self-contained, and a policy that declares no schema accepts no parameters.

## Resolved-content handle and verification receipt

This is the contract a resolver will publish and that rendering and the
assessment producer will consume (`bundle.ResolvedContent`, `bundle.Receipt`,
`bundle.Lease`). Only the contract exists today: nothing resolves, signs or
caches a bundle yet, and the [signature verifier](#signature-verification) is
not wired into a resolver. Serialized examples are pinned in
`testdata/bundles/contract/` and a drift fails the tests.

Four identities stay separate and are never interchangeable:

| Digest | Meaning |
| --- | --- |
| `revision` | the source commit the content was built from |
| `content` | digest of the canonical file inventory, independent of packaging |
| `archive` | the deterministic layer digest |
| `oci` | the manifest digest: the signed identity and the only one targeting uses |

Rendered engine-policy hashes are recorded per policy by the renderer
(`policies[].rendered`), separately from all four.

- **Targeting compatibility.** `BundleDigest()` is the OCI digest and fills
  `targeting.Contribution.BundleDigest`; the handle's name and policy names fill
  `BundleName` and `Policy`. `targeting.EnforcementRevision` is unchanged and a
  test pins its value. A mirror, re-verification, credential rotation, lease
  change, engine state or rendered hash cannot change it; a new manifest digest
  does.
- **Content versus engine.** `compatibility.content` is the verdict on the
  content alone; `compatibility.engine` (`unknown`, `ready`, `unavailable`) is
  reported separately, starts `unknown`, and neither implies the other.
- **Receipt.** Records the verified subject (name, version, manifest digest),
  where it was retrieved from (a location, not publisher identity), the source
  rule and trust input revisions, the signer (keyless issuer and identity, or a
  public-key fingerprint), the SLSA provenance v1 claims checked against the
  descriptor (build type, source repository and revision, builder, content
  digest, workflow revision), and the manifest, bundle and statement digests of
  the retained signature and attestation. It is evidence that verification
  happened under named trust inputs, not a standing authorization: a change to
  those inputs invalidates it, and it is only ever compared against a fresh
  verification ([receipts and recheck](#receipts-and-recheck)). Version 2 of
  the handle and receipt introduced the per-proof digests and the full
  provenance claims; version 1 was never persisted and is not accepted.
- **Lease.** An explicit pin on the cache entry by a holder (`profile`,
  `applied` or `assessment`), released when that holder finishes or advances.
- The handle carries no credentials and no payload bytes.

## Central source configuration

A `ComplianceProfile` keeps its existing `spec.bundle` of `name` and `digest`.
Where a name's bytes come from, and whom to trust for them, is configured once,
centrally, in a versioned document (`bundle.Sources`) stored under the
`sources.yaml` key of a ConfigMap in the controller's namespace. Only platform
administrators write it. Examples that the tests parse are in
`testdata/bundles/sources/` (an official keyless release, and an organization
mirror with a registry credential, custom CA and public key).

```yaml
version: 1
sources:
  - name: konstapel-privileged-containers   # the profile's bundle name, exact match only
    repository: ghcr.io/backend-bunny/bundles/konstapel-privileged-containers
    credentialSecret: {name: registry-creds}     # optional dockerconfigjson Secret
    ca: {kind: ConfigMap, name: registry-ca, key: ca.crt}   # optional extra trusted roots
    publisher:
      type: keyless                              # or public-key
      issuer: https://token.actions.githubusercontent.com
      identity: https://github.com/<org>/<repo>/.github/workflows/bundle-release.yml@refs/heads/main
      provenance:
        sourceRepository: https://github.com/<org>/<repo>
        builder: https://github.com/<org>/<repo>/.github/workflows/bundle-release.yml@refs/heads/main
```

- **One entry per name, exact selection.** Duplicate names are rejected; there
  is no prefix matching and no default registry, so an unconfigured name is
  unresolved. Several registries and bundle families are separate entries.
- **`repository` is `host[:port]/path`** in lowercase OCI form. A scheme, tag or
  embedded digest is rejected: the profile's digest alone selects the content,
  and TLS is always verified. A mirror replaces `repository` and nothing else;
  the pinned digest and the publisher rule are unchanged.
- **References, not secrets.** Credentials, the CA, trust roots and public keys
  are references to objects in the controller's namespace; a reference has no
  namespace field. Inline key material or credentials are rejected.
- **Publisher rule.** Keyless fixes the exact OIDC issuer and signing identity
  (an optional `trustRoot` reference replaces the built-in Sigstore public-good
  root); public-key fixes a referenced key and its SHA-256 fingerprint.
  Provenance fixes the exact source repository and builder either way. No
  wildcards or patterns are accepted, and nothing the bundle itself carries can
  change the rule.
- **Strict and atomic.** Unknown fields, repeated keys, unsupported versions and
  any invalid entry reject the whole revision; nothing is partially accepted.
  `BundleSource.CheckPayload` requires the fetched payload's name to equal the
  requested name.

This is the configuration contract and its validation. The registry adapter
and the signature verifier below use it as libraries; nothing in the controller
reads the ConfigMap or watches Secrets yet.

## Registry retrieval

[`internal/bundle/registry`](../internal/bundle/registry) retrieves one pinned
bundle and the proofs attached to it, using ORAS Go (`oras.land/oras-go/v2`
v2.7.0) for the OCI distribution protocol and its standard registry
challenge/token handling. It is **not yet wired into the controller**: nothing
calls it at runtime, and it is not linked into the shipped binaries. Its unit
tests use an in-process fake registry serving real `bundle.Build` bytes; the
compatibility suite (`scripts/registry-compat.sh`, see
[Real-registry compatibility](#real-registry-compatibility)) runs it against
two pinned real registries over TLS, one per way of listing referrers.

`Client.Fetch(ctx, source, digest)` takes a configured `BundleSource` and the
profile's pinned manifest digest and returns the manifest, the layer and the
proofs, or a typed error. Its contract:

- **By digest only.** The manifest is requested as
  `/v2/<path>/manifests/sha256:<hex>`; no tag is ever resolved to select
  content, so a moved tag has no effect. (The only tag read is the referrers
  tag schema index below, as an untrusted listing.) The manifest bytes' SHA-256 must equal the pinned digest (a
  `Docker-Content-Digest` header is not trusted), and every blob and referrer is
  checked against its descriptor's digest *and* size.
- **Bundle shape.** Indexes, non-OCI manifests and any manifest rejected by
  `bundle.ValidateManifest` (artifact type, empty config, exactly one tar+gzip
  layer) fail with `ErrUnexpectedDescriptor`. The empty config is not
  downloaded.
- **Referrers API, then the referrers tag schema.** Proofs are listed with
  `GET /v2/<path>/referrers/<digest>`. When the registry does not serve it (404
  other than `NAME_UNKNOWN`, 405, 501, or a body that is not an image index),
  the OCI referrers tag schema index is read instead:
  `GET /v2/<path>/manifests/sha256-<hex>`, where `<hex>` is the pinned
  digest's hex. A 404 there means the subject has no referrers.
  `Result.ReferrersSource` records `api`, `tag-schema` or `none`. Cosign's
  legacy `.sig`/`.att` tags and separate signature repositories are never
  read. There is no `ErrReferrersUnsupported`: an unserved API is not an error,
  and a subject with no listing simply has no proofs.
- **The tag index is untrusted.** Anyone who can push to the repository can
  move the tag, so the index is only a hint. It must be served as an image
  index of at most 4 MiB; its body is charged to the metadata budget, must
  match the size and digest the registry declares for it, and must parse as
  JSON with `schemaVersion` 2, the image index `mediaType` and a `manifests`
  list. Violations fail the retrieval (`ErrUnexpectedDescriptor`,
  `ErrIntegrity`, `ErrLimitExceeded`). Its entries then go through exactly
  the checks of an API listing below.
- **Exact subject.** Every listed entry counts toward the 64-referrer limit
  (duplicates included). A listed referrer becomes a proof only if its downloaded,
  digest-checked manifest names the pinned digest (and its size) as `subject`,
  repeats the listed artifact type, carries a recognized predicate type and has
  exactly one Sigstore bundle layer. Anything else (another subject, an
  unrelated artifact or predicate type, a non-manifest entry, a duplicate entry,
  an unexpected layout) is not an error:
  it is reported in `Result.Skipped` with a reason and never used. Integrity and
  limit failures, by contrast, fail the whole retrieval.
- **Proofs are reported, not trusted.** `Result.Missing` and
  `Result.RequireProofs(RequiredProofs...)` name the required kinds
  (`signature`, `provenance`) that were not found (`ErrMissingProofs`).
  Signature and provenance verification are the later verifier's job; the
  predicate-type annotation used for classification is unauthenticated, so the
  verifier must check the signed statement itself.

### Referrer layout

The recognized layout is what the pinned Cosign (v3.1.3, `devbox.json`) writes
by default ("new bundle format", OCI referrers). It was determined from the
Cosign v3.1.3 source (`pkg/oci/remote/write.go`: `WriteReferrer`,
`WriteAttestationNewBundleFormat`; `cmd/cosign/cli/sign/sign.go`;
`pkg/types/predicate.go`) and sigstore-go v1.2.2 `bundle.MediaTypeString("0.3")`.
`cosign sign` and `cosign attest --type slsaprovenance1` each push one image
manifest to the bundle's own repository:

| Field | Value |
| --- | --- |
| `mediaType` | `application/vnd.oci.image.manifest.v1+json` |
| `artifactType` | `application/vnd.dev.sigstore.bundle.v0.3+json` (both kinds) |
| `config` | the OCI empty descriptor (`application/vnd.oci.empty.v1+json`, `{}`) |
| `layers` | exactly one, media type `application/vnd.dev.sigstore.bundle.v0.3+json`: the Sigstore bundle JSON |
| `subject` | the pinned bundle manifest (media type, digest, size) |
| annotation `dev.sigstore.bundle.predicateType` | `https://sigstore.dev/cosign/sign/v1` → signature; `https://slsa.dev/provenance/v1` → provenance |

Cosign also sets `dev.sigstore.bundle.content: dsse-envelope` and
`org.opencontainers.image.created`; they are not used for selection. On a
registry without the referrers API, the referrers are listed in the
`sha256-<hex>` tag schema index that the pushing client maintains (Cosign and
ORAS Go both do); GitHub Container Registry, for example, answers the referrers
API with `404 MANIFEST_UNKNOWN` and serves this index. Legacy
`.sig`/`.att` tags, the older bundle media type spellings and other predicate
types (for example SLSA v0.2) are not recognized.

### Limits and defaults

`registry.DefaultLimits()`; every field is configurable, and exceeding a size or
count limit is an error, never a truncation:

| Limit | Default |
| --- | --- |
| Concurrent retrievals (all sources) | 4 |
| Each HTTP exchange, including its body and token requests | 30 s |
| One retrieval attempt, after it obtains a slot | 2 min |
| Retry backoff (`RetryPolicy.Delay`, jittered) | 5 s to 5 min |
| Subject manifest, each referrers page and the referrers tag index | 4 MiB |
| Referrers listed for the subject (any type) | 64 |
| Verification metadata: listing bodies (API pages or the tag index), referrer manifests and proof layers | 16 MiB in total |
| Compressed bundle layer | 64 MiB |

Declared sizes are checked before a download starts, and reads stop one byte
past the declared size whatever `Content-Length` says. `RetryPolicy.Delay`
draws uniformly from `[ceiling/2, ceiling]` where the ceiling doubles from
10 s per attempt up to 5 min, never below 5 s; the random source is injected.
The retry loop belongs to the resolver. `Classify` sorts errors into
*canceled* (the caller left), *permanent* for this configuration and digest
(`ErrIntegrity`, `ErrUnexpectedDescriptor`, `ErrLimitExceeded`,
`ErrInvalidRequest`) and *retryable* (timeouts,
transport errors, `ErrNotFound`, `ErrUnauthorized`, `ErrUnavailable`,
`ErrCredentials`, `ErrTrustConfig`, `ErrCredentialScope`: a Secret, CA object
or registry configuration can be fixed).

### Concurrency and cancellation

Concurrent `Fetch` calls for the same source, credential reference and digest
share one retrieval; different digests or credentials never do. A finished
retrieval is not cached (caching is a later group). The work runs on its own
goroutine, so a reconciler or health handler bounds only its own wait with
`ctx`. A caller that cancels gets its context error immediately while the
shared work continues for the remaining callers; the work is canceled when its
last caller leaves.

### Transport and credentials seam

`Options.Transport` (an `http.RoundTripper`, defaulting to a clone of
`http.DefaultTransport` with system roots) or, instead, `Options.Transports`
(a `TransportProvider` asked for one transport per source and attempt, so a
custom CA is trusted only for its own source) carries the TLS trust; a
transport with `InsecureSkipVerify` is rejected, and a `TransportProvider`
error fails the attempt with `ErrTrustConfig` before any request. Plain HTTP is
possible only with `Options.TestOnlyPlainHTTP`, used by in-process fixtures.
Redirects are limited to five and may not leave HTTPS (`ErrInsecureRedirect`).
Credential material is confined to the source's registry origin
(scheme, host and port): a request that would carry an `Authorization` header
or a body (an OAuth2 token request) to another origin, such as a bearer token
`realm` on another host or port, is not sent and fails with
`ErrCredentialScope`; an anonymous token request to such a realm is allowed.
On a redirect the `Authorization` header is dropped unless the target is the
registry's origin *and* a path of the source's repository (`/v2/<path>/...`
without dot segments or escapes), so neither another host nor another
repository on the same registry receives it. A consequence: registries whose
token service lives on another host (Docker Hub's `auth.docker.io`,
GitLab.com's `gitlab.com/jwt/auth`) cannot be used with credentials yet.
`Options.Credentials` is a `CredentialProvider` that is asked only for the
source's own registry host, never for a token realm or another origin. When a
source references a credential Secret, the credential is obtained before any
request and an error or empty credential fails with `ErrCredentials`, so a
public registry is never read anonymously instead. Token caches are kept per
source and credential reference; `Client.ResetTokens` discards one after a
rotation. Credential values never appear in returned errors: values the
attempt sent, including any echoed back by the registry, are replaced with
`[REDACTED]`, and `Credential` formats as redacted. A registry that challenges
for authentication when no usable credential is available (none for an
anonymous source, or a username without a password) fails with
`ErrUnauthorized`, like a refused credential.

### Real-registry compatibility

`scripts/registry-compat.sh OUTPUT_DIR` (through Devbox; `OUTPUT_DIR` must not
exist) runs `TestRegistryCompat` (build tag `registrycompat`) against
disposable, test-owned containers of two digest-pinned registries from
`scripts/runtime.env`, all over TLS with a throwaway CA and loopback ports:

| Instance | Image | Referrers listing |
| --- | --- | --- |
| anonymous and htpasswd-protected, plus an anonymous one with another CA | `KONSTAPEL_REGISTRY_IMAGE` (distribution registry 3.1.2) | no `/referrers/` API (404): tag schema |
| anonymous | `KONSTAPEL_REGISTRY_API_IMAGE` (Zot v2.1.23) | OCI 1.1 referrers API |

Random credentials are generated per run. The Go test starts and removes its
containers itself; the script also removes anything still carrying the run's
label and fails if a container remains. Evidence, in
`OUTPUT_DIR/registry-compat.json` and `registry-images.json`, records both
registries' versions and image digests, the Docker, ORAS Go and Go versions, and
every case. It verifies:

- each registry really behaves as claimed before retrieval is judged: the
  distribution registry answers `/referrers/` with 404 and holds a
  `sha256-<hex>` index listing the referrers that ORAS Go's pushes created,
  while Zot answers `/referrers/` with an image index listing them;
- retrieval reports `ReferrersSource` `tag-schema` against the distribution
  registry and `api` against Zot, finds the signature and the provenance, and
  skips the unrelated SBOM-style referrer;
- anonymous retrieval with the custom CA, and authenticated retrieval with
  credentials;
- a wrong password is `ErrUnauthorized` and never echoed; no credential against
  the protected registry is `ErrUnauthorized`; a configured but empty
  credential is `ErrCredentials` without any anonymous request;
- an untrusted CA fails TLS verification;
- a moved tag does not change what the digest returns;
- a bundle with no referrers reports `none`, zero proofs and
  `ErrMissingProofs` from `RequireProofs`;
- an unknown digest is `ErrNotFound`;
- through `kubeaccess` with an in-memory object reader: anonymous retrieval
  with a ConfigMap CA added to the real system roots; a wrong password in the
  dockerconfigjson Secret is `ErrUnauthorized` and never echoed, and the same
  `Client` succeeds after the Secret is rotated and invalidated; a missing
  Secret is `ErrCredentials` although the registry is anonymous; an invalid
  CA object is `ErrTrustConfig`; and the CA ConfigMap of one registry does not
  trust a third registry instance with its own unrelated CA, which succeeds
  with its own CA object.

Why two registries: the first run of this suite found that neither the
reference registry nor `ghcr.io` (the planned official registry) serves the
referrers API, although `ghcr.io` stores referrers under the tag-schema tag
(`cosign tree` reads them that way). The fallback exists because of that
finding, and Zot keeps the API path covered by a real server.

Not covered: bearer-token (token service) authentication, which neither image
offers without a separate token server, and `ghcr.io` itself (only its tag
schema format was checked, by read-only anonymous requests). The suite is run on
demand; it is not part of `task check` or CI, and `task bundles:acceptance`
(task 8.1) will compose it. It is deliberately not a Taskfile task.

## Registry credentials and custom CAs

[`internal/bundle/registry/kubeaccess`](../internal/bundle/registry/kubeaccess)
turns a source's `credentialSecret` and `ca` references into what the
retrieval adapter consumes: `Provider` implements both
`registry.CredentialProvider` and `registry.TransportProvider`, and
`kubeaccess.NewClient(provider, opts)` builds a `registry.Client` bound to it.
It is **not wired into the controller yet** (task 5.1 adds the watches and
calls) and, like the adapter, is not linked into the shipped binaries. Node
or kubelet pull credentials are never used, and nothing is pulled through image
volumes, loader Jobs or a `docker`/helper process.

### Object access

The provider reads through a narrow `ObjectReader`: `Get(kind, name)` of one
`Secret` or `ConfigMap` in the controller's own namespace, fixed when the reader
is built. References have no namespace field, so no other namespace can be
named. There is no list, watch or cluster-wide access. `NewClientReader` adapts
a controller-runtime `client.Reader`; use the manager's uncached `APIReader`,
because a cached client would need `list`/`watch` on every Secret in the
namespace. `MemoryReader` is the in-memory reader for tests and fixtures.

RBAC for the later chart task: a namespaced `Role` in the controller namespace
with only

```yaml
- apiGroups: [""]
  resources: [secrets]
  verbs: [get]
  resourceNames: [<every configured credentialSecret and Secret-held ca>]
- apiGroups: [""]
  resources: [configmaps]
  verbs: [get]
  resourceNames: [<every ConfigMap-held ca>]
```

`resourceNames` is possible because every object is fetched by name. Change
notification (task 5.1) needs `watch` as well; `resourceNames` cannot restrict
`list`, and restricts `watch` only for single-object watches selected by
`metadata.name`, so how the watches are granted is decided by that wiring
task, not here.

### Credential Secret

The Secret must have type `kubernetes.io/dockerconfigjson`; its data key is
`.dockerconfigjson` unless the reference names another key. The document is
parsed strictly, and every failure is a non-secret error wrapping
`registry.ErrCredentials` (`kubeaccess.ErrMalformedCredentials` or
`kubeaccess.ErrNoCredentialForHost`):

- At most 1 MiB, valid UTF-8, one JSON object, at most 8 levels deep, and no
  repeated key anywhere (a duplicate could hide a credential from review).
- The only top-level field is `auths`. `credsStore` and `credHelpers` are
  rejected and their programs are never executed; `HttpHeaders` and `proxies`
  are rejected too, as is any other field (a Secret created by
  `kubectl create secret docker-registry` has only `auths`).
- Every entry is validated, not only the one used. Entry fields are `auth`,
  `username`, `password`, `identitytoken`, `registrytoken`, and the ignored
  legacy `email` and `serveraddress`; values are strings without control
  characters. An entry holds exactly one credential form: `username` with
  `password`; `auth` (strict, padded base64 of `user:password`, non-empty user
  and password), which must agree with `username`/`password` if both are
  present; `identitytoken` (optionally with the account name Docker stores
  next to it, but no password); or `registrytoken`.

**Host matching.** The entry is chosen by exact equality with the registry
host of the source's `repository` (`host[:port]`). An `auths` key may be written
as `host`, `host:port`, `https://host[:port]`, `https://host[:port]/` or
`https://host[:port]/v1/`; nothing else is normalized. Comparison is exact:
no case folding (repository hosts are lowercase, so `GHCR.IO` does not match
`ghcr.io`), no wildcard, prefix or suffix matching (`evil-ghcr.io` and
`sub.ghcr.io` do not match `ghcr.io`), and the port is part of the host: an
entry for `registry.example` does not match a repository on
`registry.example:5000`, and `registry.example:443` does not match
`registry.example`. Two keys that name the same host are rejected as
ambiguous; no matching entry is an error, never a fallback to another entry
or to anonymous access. The provider only answers for the source's own
registry host; the adapter never asks it for a token realm or another origin.

A source without `credentialSecret` is anonymous. A configured but missing
Secret, a missing key, a wrong type, a malformed document or a missing entry
fails before any request is sent.

### Rotation and invalidation

An object read is reused for at most `Options.CacheFor` (30 seconds by
default, at most 5 minutes; negative disables reuse). The watcher that will be
wired in task 5.1 calls `Provider.Invalidate(kind, name)` on every change or
deletion of a referenced object (or `InvalidateAll` after a watch restarts), so
the next retrieval re-reads at once; an invalidation that races with a read
forces another read. Resolution is serialized per source, so a slower, older
read can never replace a newer credential.

The provider remembers a SHA-256 fingerprint of the credential each source
last resolved to (never logged or returned). When it changes, or the Secret
becomes unusable, it calls `Client.ResetTokens(source)` *before* returning, so
bearer tokens and cached Basic state obtained with the old credential are
discarded and the next requests authenticate with the current credential. The
adapter asks for the credential at the start of every retrieval, before it
takes the token cache, so a retrieval that starts after a rotation is observed
never uses a token of the old credential (one already in flight finishes with
what it had). A removed or emptied Secret is a recoverable `ErrCredentials`:
never the old credential, never anonymous. A provider that is not bound to a
client (`Bind`, done by `kubeaccess.NewClient`) refuses to release
credentials, because it could not reset tokens.

### Custom CA

`ca` references a ConfigMap (`data` or `binaryData`) or Secret key, default
`ca.crt`, holding PEM certificates. The bundle is parsed strictly
(`kubeaccess.ErrMalformedCA`, wrapping `registry.ErrTrustConfig`): only
`CERTIFICATE` blocks without PEM headers and whitespace between them, at least
one and at most 512 certificates, at most 1 MiB; a private key, any other block
type, text outside blocks or a malformed block is rejected. The certificates are
trust anchors and need not be CA certificates.

Each source with a CA gets its own transport whose roots are the **system
roots plus** the referenced certificates; extra roots are never used alone,
and if the system roots cannot be loaded the source is unavailable. Another
source never shares that pool, so one source's CA does not vouch for another
source's registry. The transport requires TLS 1.2 or later, never skips
verification, and keeps `http.DefaultTransport`'s other settings, including
`HTTPS_PROXY`/`NO_PROXY` from the environment (a CONNECT proxy sees no
credentials: TLS is end to end). When the bundle's content changes the
transport is rebuilt and the old one's idle connections are closed. A missing,
emptied or invalid CA object makes the source unavailable
(`ErrTrustConfig`), never a silent fall back to system roots only. Sources
without `ca` share one transport with the system roots.

### Verification

Unit tests use an in-process TLS registry with Basic and bearer-token
authentication and throwaway CAs: strict parsing and every rejection above,
exact host matching and its near misses, missing Secret/key/entry with no
request reaching the registry, rotation (the old credential until the change
is observed, then the new; `ResetTokens` exactly when the credential changes
or is removed), a cached bearer token dropped after rotation although the
registry would still accept it, a realm on another port, a redirect to another
host and a redirect to another repository receiving no credential, redaction
in every `fmt` verb, `slog` and JSON, CA rejections, CA rotation closing idle
connections, per-source trust, and concurrent rotation under `-race`. The
[real-registry suite](#real-registry-compatibility) repeats the essential cases
against real registries.

## Private registry setup

How to point a bundle name at a private registry. Everything here is the
configuration contract plus tested examples: nothing in the controller reads
these objects yet (task 5.1 wires them in), so the steps cannot be followed end
to end today. The manifests below are the files in
`testdata/bundles/private-registry/`; `TestPrivateRegistryExamples` parses them
with the real code (the source configuration, the credential document, the CA
bundle) and checks they agree with each other, including the Role, and
`TestPrivateRegistryGuideEmbedsTheExamples` fails if this page and those files
differ.

### What the registry must provide

| Requirement | Detail |
| --- | --- |
| TLS | Always verified, against the system roots plus the CA you configure. Plain HTTP and skipping verification are not possible. |
| Access | Anonymous, or Basic credentials from a `kubernetes.io/dockerconfigjson` Secret. A bearer token service works when its token `realm` is on the registry's own origin (same scheme, host and port). With credentials configured, a realm on another origin (Docker Hub's `auth.docker.io`, GitLab.com's `gitlab.com/jwt/auth`) fails with `ErrCredentialScope`: credentials are never sent to another origin. Anonymous retrieval from a public repository may use any realm. |
| Pull account | Read-only, limited to the bundle repositories. |
| Referrers | The OCI 1.1 referrers API, or the referrers tag schema (`sha256-<hex>` index tag). Signatures and provenance must be Sigstore bundle v0.3 referrers (see [Referrer layout](#referrer-layout)). Cosign's legacy `.sig`/`.att` tags and separate signature repositories are not read. |

A registry that merely accepts a manifest is not thereby compatible. The
[compatibility suite](#real-registry-compatibility) ran against the Distribution
registry 3.1.2 (tag schema, Basic auth, custom CA) and Zot v2.1.23 (referrers
API); `ghcr.io`'s tag-schema format was checked with read-only anonymous
requests. Other registries are unverified: run the suite's checks against yours
before relying on it. Bearer-token services were only tested against an
in-process fake.

### Steps

All objects live in the controller's namespace (`konstapel-system` here);
references carry no namespace.

1. **Trust the registry's CA** (skip if its certificate chains to the system
   roots). The roots are added to the system roots, never replacing them, and
   apply only to sources that reference this object. Private keys and other PEM
   blocks are rejected.

```yaml
# Extra trusted roots for the private registry's TLS (added to the system roots).
# This certificate is an example only: replace it with your registry's CA.
apiVersion: v1
kind: ConfigMap
metadata:
  name: acme-registry-ca
  namespace: konstapel-system
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIBpzCCAU2gAwIBAgIUWqGwlbtMZve0onmxo6HS/dwykRIwCgYIKoZIzj0EAwIw
    KDEmMCQGA1UEAwwdRXhhbXBsZSByZWdpc3RyeSBDQSAocmVwbGFjZSkwIBcNMjYx
    MTEwMTUzMzQxWhgPMjEyNjEwMTcxNTMzNDFaMCgxJjAkBgNVBAMMHUV4YW1wbGUg
    cmVnaXN0cnkgQ0EgKHJlcGxhY2UpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
    pz2SE5mzCPElOcOo8r767xkHfEFlkRBmQ5iH4hc1xyv/aBotNXuqn5oo0XL+7gPz
    VEYDcnJDK66izey3J1Swi6NTMFEwHQYDVR0OBBYEFFdsJYCijhBWAJqCUiMAl8cV
    RTWPMB8GA1UdIwQYMBaAFFdsJYCijhBWAJqCUiMAl8cVRTWPMA8GA1UdEwEB/wQF
    MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAPk+Gda2j/jmYMIk65a3FvXBDDiiA4Gk
    wMvLpd1F44QnAiAmxNU4U/Jh/bHpqWi7OWWjuErPHkBHaAppl2Ixb8BAUw==
    -----END CERTIFICATE-----
```

2. **Store the pull credential.** Create the Secret as below, or with
   `kubectl create secret docker-registry acme-registry --docker-server=registry.acme.internal:5000 --docker-username=... --docker-password=...`,
   which writes the same document. The entry key must be exactly the host of
   the source's repository, including the port. Use a read-only account, and a
   Secret of its own: it is not an `imagePullSecret`.

```yaml
# Registry credential, in the controller's namespace. Created like this, or with
# kubectl create secret docker-registry (which writes the same document).
# "reader:change-me" is a placeholder: use a read-only registry account.
apiVersion: v1
kind: Secret
metadata:
  name: acme-registry
  namespace: konstapel-system
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {"auths":{"registry.acme.internal:5000":{"auth":"cmVhZGVyOmNoYW5nZS1tZQ=="}}}
```

3. **Store the public key** for a public-key publisher rule, for example
   `kubectl create secret generic acme-bundle-signing-key --from-file=cosign.pub`.
   (Signature verification is a later task; the reference is validated now and
   the Secret is read then.)
4. **Configure the source.** The ConfigMap holds only references and rules, no
   secret material; inline keys or credentials are rejected. Writing it is a
   platform-administrator action.

```yaml
# Central bundle source configuration (see "Central source configuration").
apiVersion: v1
kind: ConfigMap
metadata:
  name: konstapel-bundle-sources
  namespace: konstapel-system
data:
  sources.yaml: |
    version: 1
    sources:
      - name: acme-baseline
        repository: registry.acme.internal:5000/security/bundles/acme-baseline
        credentialSecret:
          name: acme-registry
        ca:
          kind: ConfigMap
          name: acme-registry-ca
        publisher:
          type: public-key
          publicKey:
            kind: Secret
            name: acme-bundle-signing-key
            key: cosign.pub
          keyFingerprint: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          provenance:
            sourceRepository: https://git.acme.internal/security/policies
            builder: https://git.acme.internal/ci/bundle-builder@refs/heads/main
```

5. **Grant read access.** The controller's ServiceAccount needs only `get`, by
   name, on the objects above, and on the configuration ConfigMap itself. Bind
   this Role to that ServiceAccount (the chart task defines it). The Role must
   list every object the configuration references, including a Secret-held CA
   or trust root when you use one.

```yaml
# Least-privilege read access: get, by name, in the controller's namespace only.
# resourceNames lists every object the sources configuration references.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: konstapel-bundle-sources
  namespace: konstapel-system
rules:
  - apiGroups: [""]
    resources: [configmaps]
    verbs: [get]
    resourceNames: [acme-registry-ca, konstapel-bundle-sources]
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
    resourceNames: [acme-bundle-signing-key, acme-registry]
```

### Least privilege

- A namespaced Role with `get` and `resourceNames` only: no `list`, no `watch`
  from this loader, no ClusterRole, no other namespace. Change notification
  (task 5.1) will need watches, which `resourceNames` restricts only for
  single-object watches; that wiring decides how they are granted.
- One credential Secret per registry, scoped to the bundle repositories, so a
  leaked or rotated credential has a small blast radius.
- Credentials are offered only for the source's own registry host, never to a
  token realm, redirect target or repository outside the configured one, and
  never appear in errors, logs or evidence.
- A configured Secret that is missing, malformed, has no entry for the host, or
  names a credential helper makes retrieval fail (`ErrCredentials`). There is no
  anonymous fallback.

### Node and kubelet credentials are not used

Konstapel does **not** inherit node pull credentials. It never reads
kubelet or container-runtime credential configuration, any Pod's
`imagePullSecrets`, a ServiceAccount's pull secrets, or a cloud provider's
credential helper, and it never runs a credential helper program. A registry
that your nodes can pull from is therefore not accessible to Konstapel until you
configure a `credentialSecret` as above. Cloud-specific credential providers are
not supported.

### Rotating credentials and CAs

Update the Secret or ConfigMap in place. The loader caches an object for at most
30 seconds (configurable up to five minutes) unless the watcher in task 5.1
invalidates it sooner. When the credential for a source changes, the tokens
cached for the old one are discarded before the next request, so a rotated
credential is used immediately and an old token is never reused. Deleting or
emptying the Secret makes retrieval fail with `ErrCredentials` (recoverable
when it returns). A changed CA rebuilds that source's trust and closes its idle
connections; an invalid or removed CA fails with `ErrTrustConfig` and never falls
back to the system roots alone.

### What has and has not been verified

Verified: the parsing and agreement of the examples above (unit test), and, in
the real-registry suite, Secret-backed credentials, a wrong password then a
rotated Secret on the same client, a missing Secret, a ConfigMap-backed CA on top
of the system roots, an invalid CA, and one source's CA not trusting another
registry. Not verified: a running controller reading these objects, the Role
against a real API server, and bearer-token services other than the in-process
fake.

## Signature verification

[`internal/bundle/verify`](../internal/bundle/verify) checks that the proofs the
registry adapter retrieved were signed by the publisher the source rule names,
for exactly the pinned manifest digest. It uses sigstore-go
(`github.com/sigstore/sigstore-go` v1.3.0) and verifies **offline**: it never
contacts a transparency log, Fulcio, a timestamp authority or a TUF repository.
Like the adapter it is **not yet wired into the controller** and is not linked
into the shipped binaries.

`Verifier.VerifyProofs(ctx, source, result)` verifies the required signature
and SLSA provenance of one `registry.Result` and returns both, or a typed
error; `Verify` and `VerifyProof` check one kind or one proof. Trust inputs are
read once per call, so the signature and the attestation are always judged
under the same rule, key or root snapshot: a signature valid under one rule can
never be combined with an attestation valid under another. Within one kind,
candidates come from the unauthenticated predicate-type annotation, in listing
order, and the first that verifies is used; none at all is
`registry.ErrMissingProofs`, only failing candidates is `ErrNoValidProof`
(which also matches each candidate's own error).

### What is checked

- **Trust only from central configuration.** Keys, trusted roots, issuers and
  identities come from the source's `publisher` rule and the Secret or
  ConfigMap it references, read by name in the controller namespace
  (`kubeaccess.ObjectReader`). Material in the proof (a key hint, certificates,
  log or timestamp data) is evidence checked against that trust, never an
  anchor: a key hint naming another key is ignored, a certificate chain in a
  proof is refused, and a certificate, log entry or timestamp from an instance
  outside the configured root fails. The rule is validated again and patterns
  in an identity are refused. A missing, unreadable, oversized or malformed
  trust object fails with `ErrTrustConfig`; there is no fallback to another rule
  or to the public-good root once a `trustRoot` is referenced, and no
  verification-off switch.
- **Proof format.** A Sigstore bundle v0.3 (`application/vnd.dev.sigstore.bundle.v0.3+json`),
  at most 4 MiB, valid UTF-8 JSON with no duplicate or unknown keys, whose
  bytes match the digest retrieval recorded, holding a DSSE envelope with
  exactly one signature over an in-toto statement (`ErrMalformedProof`,
  `ErrProofTooLarge`). This is what the pinned Cosign writes for both `cosign
  sign` and `cosign attest`; a `cosign sign` proof is **not** a signature over
  the manifest digest itself but a DSSE-signed in-toto statement with
  predicate type `https://sigstore.dev/cosign/sign/v1` whose subject is the
  manifest digest.
- **Subject binding from the signed statement.** The statement (in-toto
  Statement v1, or v0.1 as `cosign attest` writes it) is parsed strictly from
  the signed payload: exact key names, no unknown or duplicate keys, a JSON
  object predicate (`ErrStatement`). It must name exactly one subject whose
  digest set is exactly one lowercase `sha256` equal to the pinned digest
  (`ErrSubject`), and its predicate type must be the one the requested kind
  needs (`ErrPredicateType`); the registry annotation is only used to choose
  candidates. A subject `name` is ignored: it is a registry location (absent in
  Cosign's signature statement, changed by a mirror), not identity.
  sigstore-go checks the digest binding again in the final, authoritative call.
- **Public-key rules.** The referenced value must be exactly one PEM `PUBLIC
  KEY` block holding an ECDSA P-256 key, the type `cosign generate-key-pair`
  creates; other key types are refused (`ErrUnsupportedKey`) rather than
  verified with a guessed hash, and private keys are rejected. The SHA-256 of
  the key's DER SubjectPublicKeyInfo must equal `keyFingerprint` (with or
  without the `sha256:` prefix), even if the signature verifies under the key
  (`ErrKeyFingerprint`). The DSSE signature is verified as ECDSA P-256 with
  SHA-256 under that key only; a proof carrying a certificate instead of a key
  fails (`ErrSigner`). Transparency log entries or timestamps in such a proof
  are not verified or reported: a public-key rule configures no log or
  timestamp authority, so `SigningTime` is zero and no evidence is claimed.
- **Keyless rules.** The proof must carry one signing certificate (ECDSA P-256
  or P-384; others are `ErrAlgorithm`) with exactly one subject alternative
  name equal to `identity` and the Fulcio OIDC issuer extension equal to
  `issuer`, both compared as exact strings (`ErrSigner`; a prefix, suffix or
  case variant fails). A key-signed proof fails (`ErrSigner`). The trusted
  root is the referenced object (a Sigstore `trusted_root.json`, at most 1 MiB,
  parsed strictly, with at least one certificate authority and one
  transparency log) or, when the rule references none, the embedded Sigstore
  public-good root (`internal/bundle/verify/publicgood`, with its provenance and
  refresh procedure; its SHA-256 is pinned in the code).
- **Signing time and transparency.** The minimum for a keyless proof is at
  least one transparency log entry that verifies under a log in the root
  (inclusion proof, as bundle v0.3 requires, and/or a signed entry timestamp;
  `ErrTransparency`), and at least one authenticated signing time: a log's
  integrated time with a verified signed entry timestamp, or an RFC 3161
  timestamp from an authority in the root (`ErrSigningTime`). When the root
  lists certificate transparency logs, as the public-good root does, an
  embedded SCT that verifies under one of them is also required. The leaf
  must be valid, and chain to the root, at **every** authenticated time, and no
  time may lie more than five minutes after the verifier's clock. The present
  time plays no part: a short-lived certificate that expired after a valid
  signing event verifies, while one whose only times are missing,
  unauthenticated, from an authority outside the root, or outside its validity
  fails. A log's unsigned integrated time (inclusion proof only) is not used.
- **Root changes.** Each call reads the current root. A proof valid only under
  a replaced root is rejected, and the result names the root used.

### Result

A `VerifiedProof` carries the proof kind established by the signed predicate
type, the subject, the signer (`bundle.Signer`: issuer and identity, or key
fingerprint), the trusted root's SHA-256 and source (keyless), the earliest
authenticated signing time and every time evidence with its authority, the
evidence kinds, the verification time from an injectable clock, the referrer
manifest, bundle and signed-statement digests, and the verified statement
including its raw predicate. It holds public identifiers and digests only, no
key material or credentials. `Proofs.Provenance.Statement` is the seam for the
provenance stage: it can check builder, source repository, revision, version
and materials on the already verified statement without verifying again.

### Not done yet

- The provenance policy, receipts and recheck are described in
  [Provenance verification](#provenance-verification).
- Signing and trust-root maintenance documentation, publisher rotation and
  CLI-output interoperability for both methods (3.5); caching and controller
  wiring.
- Public-key rules accept one ECDSA P-256 key; keyless certificates whose only
  identity is an otherName SAN are not accepted.

### What has and has not been verified

Verified, by table-driven unit tests without network access (any HTTP request
fails the run):

- Public key: real proofs made by the pinned Cosign v3.1.3 CLI with generated
  test keys against a disposable registry (`testdata/cosign/README.md`):
  valid signature and provenance; wrong key, rotated key, fingerprint
  mismatch, unreferenced key, unacceptable key objects; tampered payload and
  signature, unsigned and doubly signed envelopes, truncated, garbled,
  duplicate-key, unknown-field, oversized and older-format proofs; wrong
  subject, wrong predicate type and mislabelled proofs; key hints and a
  substituted certificate ignored or refused; strict statement shape.
- Keyless: isolated Sigstore instances (sigstore-go's `VirtualSigstore` and a
  test CA) for valid proofs with each kind of time evidence, wrong and
  near-miss identities and issuers, several SANs, missing or foreign log
  entries and timestamps, leaves expired after valid signing times versus
  signing times outside validity, unauthenticated or from a foreign authority,
  future times, swapped and mixed roots, foreign chains, missing SCTs,
  Ed25519 leaves and malformed or missing roots.
- Real Cosign v3 CI output: the signature and provenance of
  `ghcr.io/backend-bunny/konstapel:0.1.0` verify offline against the embedded
  public-good root under the publishing workflow's identity, two days after
  their certificates expired (`testdata/ghcr/README.md`).

Not verified: a keyless proof made by the Cosign CLI with an isolated Fulcio
and Rekor (3.5), a private Sigstore deployment's real trusted root, and use
from a running controller.

## Provenance verification

[`internal/bundle/verify`](../internal/bundle/verify) also applies the
provenance policy and produces receipts and recheck material. Like the
signature verifier it is **not wired into the controller** and is not linked
into the shipped binaries.

`Verifier.Accept(ctx, source, result)` is the whole acceptance check of one
retrieved subject: `VerifyProofs` (signature and SLSA provenance under the
publisher rule, one trust snapshot), the layer against the pinned manifest and
the payload against its own inventory (`ErrContent`), then
`CheckProvenance(source, descriptor, pinned, proofs)`. It returns the verified
claims (`VerifiedProvenance`), a `bundle.Receipt` and a `RecheckBundle`.
`CheckProvenance` reads only the statement `VerifyProofs` already verified; it
never parses unverified bytes.

### Bundle provenance v1

The provenance attestation must be an in-toto statement for exactly the pinned
manifest digest, with predicate type `https://slsa.dev/provenance/v1`, whose
predicate follows this contract. Field names are SLSA provenance v1's; SLSA
leaves the content of the parameters and dependencies to each build type, and
`cosign attest --type slsaprovenance1 --predicate <file>` signs whatever
predicate the publisher supplies, so the content below is Konstapel's own
contract. The bundle release workflow must produce exactly this (task 6.3);
an organization publishing with its own key must too.

```json
{
  "buildDefinition": {
    "buildType": "https://github.com/backend-bunny/Konstapel/blob/main/docs/policy-bundles.md#bundle-provenance-v1",
    "externalParameters": {
      "bundle": {"name": "konstapel-privileged-containers", "version": "0.1.0"},
      "source": {"repository": "https://github.com/backend-bunny/Konstapel", "commit": "e30d50760b498cbb17012742c7789a414a1e1d6b"}
    },
    "internalParameters": {
      "workflow": {
        "repository": "https://github.com/backend-bunny/Konstapel",
        "path": ".github/workflows/bundle-release.yml",
        "ref": "refs/heads/main",
        "commit": "591d6fea5e6517bffc906540cec1e94c3def738a"
      }
    },
    "resolvedDependencies": [
      {"name": "source", "uri": "git+https://github.com/backend-bunny/Konstapel",
       "digest": {"gitCommit": "e30d50760b498cbb17012742c7789a414a1e1d6b"}},
      {"name": "bundle-definition",
       "uri": "git+https://github.com/backend-bunny/Konstapel@e30d50760b498cbb17012742c7789a414a1e1d6b#bundles/konstapel-privileged-containers/definition.json",
       "digest": {"sha256": "29f6f901e9818c6186416417122e66aa083e75f352a97e4ed4436b919327eb0b"}},
      {"name": "bundle-content", "uri": "bundle-content:konstapel-privileged-containers@0.1.0",
       "digest": {"sha256": "791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8"}},
      {"name": "test", "uri": "bundle-file:content/upstream/kyverno/disallow-privileged-containers/.kyverno-test/kyverno-test.yaml",
       "digest": {"sha256": "f9a80e78f7fd92059a57e1e4640298ad5c99eaf65ce3a42624b16b5be2441160"}},
      {"name": "tool", "uri": "pkg:golang/go@1.27.3"},
      {"name": "tool", "uri": "pkg:github/sigstore/cosign@v3.1.3"}
    ]
  },
  "runDetails": {
    "builder": {"id": "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"},
    "metadata": {"invocationId": "https://github.com/backend-bunny/Konstapel/actions/runs/<run>/attempts/<n>"}
  }
}
```

(The digests are those of the official bundle built from `e30d507`; the full
conforming predicate is
`internal/bundle/verify/testdata/provenance/valid.predicate.json`.)

| Field | Meaning |
| --- | --- |
| `buildDefinition.buildType` | exactly the URI above |
| `externalParameters.bundle` | the requested release: bundle `name` and SemVer `version` |
| `externalParameters.source` | the requested content source: `repository` (https URL) and full 40-character `commit` |
| `internalParameters.workflow` | the pipeline that ran: `repository`, `path`, full `commit`, optional `ref`. Recorded separately from the content source: a retry from a newer workflow revision packaging an older source commit stays distinguishable. It is never used in place of the source commit. |
| `resolvedDependencies` `source` | exactly one: `git+<repository>`, digest exactly `{"gitCommit": <commit>}` |
| `resolvedDependencies` `bundle-definition` | exactly one: `git+<repository>@<commit>#bundles/<name>/definition.json`, digest exactly `{"sha256": …}` of that file |
| `resolvedDependencies` `bundle-content` | exactly one: `bundle-content:<name>@<version>`, digest exactly `{"sha256": …}` of the payload's canonical inventory (`Descriptor.ContentDigest()`, the handle's `digests.content`) |
| `resolvedDependencies` `test` | zero or more payload test files the release ran: `bundle-file:<archive path>`, digest exactly `{"sha256": …}` |
| `resolvedDependencies` `tool` | at least one build tool, `uri` free-form (a purl is recommended), optional `{"sha256": …}` |
| `runDetails.builder.id` | the builder identity; optional `version` (object of strings) |
| `runDetails.metadata` | optional `invocationId`, `startedOn`, `finishedOn` (RFC 3339) |

Parsing is strict: the predicate is at most 1 MiB of valid UTF-8 JSON without
duplicate keys; every object has exactly the fields above with exact-case names
(no unknown fields, no `byproducts`); every value has its exact JSON type, with
no null, number-for-string or other coercion; strings are non-empty, at most
2048 bytes and free of control characters; there are at most 1024
`resolvedDependencies`, each with a `name` and `uri` and no other field but
`digest`, never repeated; unknown material names are refused. A violation is
`ErrProvenanceContract`.

**Why the content digest is the checkable material.** The consumer can only
check a material against what it holds. `bundle-content` binds the attestation
to the canonical file inventory (sorted path, role, size and sha256 of every
payload file), which the verifier recomputes from the descriptor after checking
every file against the unpacked payload. It is independent of tar/gzip
packaging, the builder knows it before the archive exists, and it is already
the handle's `content` identity. The bundle definition is not shipped in the
payload, so its digest is recorded, with its URI required to name the attested
repository, commit and bundle; the release workflow is where it is checked.

### What is checked

In addition to everything in [Signature verification](#signature-verification):

- **Same publisher for both proofs.** `VerifyProofs` verifies the signature
  and the attestation under one rule and one snapshot of its key or root, so a
  signature by key A cannot be combined with provenance by key B, an identity X
  signature with an identity Y attestation, or public-key proofs with a keyless
  rule. `CheckProvenance` checks it again: both proofs must report the same
  signer, trusted root and subject, and be a signature and a provenance
  attestation (`ErrMixedSigner`). Missing either proof is
  `registry.ErrMissingProofs`.
- **Subject.** Both statements name exactly the pinned manifest digest
  (`ErrSubject`, already enforced by the signature verifier).
- **Builder.** `runDetails.builder.id` equals `publisher.provenance.builder`
  exactly (`ErrProvenanceBuilder`).
- **Source.** The attested repository equals `publisher.provenance.sourceRepository`
  exactly, and the descriptor's `source.repository` must equal it too. No
  normalization is applied: a trailing `.git` or `/`, another case or a
  `git+` prefix in the rule are different repositories. The `source` material
  is `git+` plus that repository and records the same commit as
  `externalParameters.source.commit`, and that commit equals the descriptor's
  `source.revision` (`ErrProvenanceSource`). The workflow commit is never
  consulted: provenance whose only matching commit is the workflow revision
  fails.
- **Release identity.** The descriptor's name equals the source's name (the
  profile's bundle name), and the attested name and version equal the
  descriptor's (`ErrProvenanceRelease`).
- **Materials.** The `bundle-content` digest equals the payload's content
  digest and its URI names this bundle and version; the `bundle-definition` URI
  names this repository, commit and bundle; every `test` material is a payload
  file with role `test` and the same sha256 (`ErrProvenanceMaterial`).

The result, `VerifiedProvenance`, carries the builder, build type, source
repository and revision, bundle name and version, content digest, definition,
test and tool materials, workflow and invocation ID: public identifiers and
digests only.

**Limit: generic GitHub provenance is refused.** Provenance written by GitHub's
attestation actions or by a `cosign attest` of the generic Actions workflow
build type (`https://actions.github.io/buildtypes/workflow/v1`, as on the
application image's real CI proofs in `internal/bundle/verify/testdata/ghcr`)
records the workflow and its trigger commit, not the bundle, its source commit
or its content, and fails with `ErrProvenanceContract`. No bundle published
today carries conforming provenance; until the release workflow produces it
(6.3), only publishers that attest the contract themselves can be accepted.

### Receipts and recheck

`Accept` builds the receipt from the verification results only:

| Receipt field | Value |
| --- | --- |
| `subject` | descriptor name and version, pinned manifest digest |
| `retrievedFrom` | the retrieval's repository (a location only) |
| `sourceRule` | `RuleRevision(source)` (below) |
| `trustRevision` | keyless: sha256 of the trusted root bytes used; public key: the key fingerprint |
| `trustRoot` | keyless: where the root came from (`embedded:sigstore-public-good` or `ConfigMap/<name>[<key>]`); public key: `Secret/<name>[<key>]` or `ConfigMap/…` |
| `signer` | the verified signer |
| `proofs.signature`, `proofs.attestation` | referrer manifest, Sigstore bundle and signed statement digests |
| `provenance` | predicate type, build type, repository, revision, builder, content digest, workflow |
| `verifiedAt` | the verifier's injectable clock |

**Rule revision.** `RuleRevision` is `sha256:` plus the SHA-256 of the JSON
encoding of, in this order, `domain` (`konstapel.bundle.source-rule/v1`), the
source `name`, and the publisher's `type`, `issuer`, `identity`, `trustRoot`
and `publicKey` references (`<Kind>/<name>[<key>]` with the default data key
filled in, empty when absent), `keyFingerprint` (with its `sha256:` prefix,
empty for keyless), `sourceRepository` and `builder`. The repository (a mirror
changes only the retrieval location), `credentialSecret` and `ca` (transport
only) are excluded, so a mirror or credential rotation does not change it.

**Recheck material.** `RecheckBundle` (version 1) holds the receipt, the
subject manifest and, for the signature and the attestation, the referrer
manifest and Sigstore bundle exactly as retrieved (the bundle contains the
signed statement). It holds no credentials and no payload; the bundle layer is
cached separately by digest (group 4). Bounds: at most 64 KiB per retained
manifest, 4 MiB per Sigstore bundle, and 16 MiB for the whole serialized
material (the registry adapter's metadata budget). `Encode` is deterministic;
`DecodeRecheckBundle` rejects oversized input, invalid UTF-8, duplicate,
unknown or case-variant keys, trailing data, any version but 1, and anything
that is not byte-for-byte the canonical encoding. `Check` (run on decode and
before every recheck) requires every retained byte to hash to the digest the
receipt names (subject manifest, referrer manifests, bundles, statements), each
referrer to name the subject and exactly its retained bundle, and a valid
receipt (`ErrRecheckBundle`).

**Recheck under current trust.** `Verifier.Recheck(ctx, source, material,
layer)` takes the source rule as configured **now** and the cached layer. The
receipt is never authority: the subject digest comes from the retained
manifest bytes, the layer must be the one that manifest names, and the
signature, attestation, signer, trust and provenance are verified again from
scratch by `Accept` with the current rule and the objects it references now.
Only then is the fresh receipt compared with the stored one:

| Outcome | Meaning |
| --- | --- |
| `valid` | verifies under current trust with exactly the stored claims (time and location aside) |
| `changed` | verifies, but `Differences` names receipt fields that differ (an edited receipt, a moved key reference, a changed root); use `Current` |
| `invalid` | does not satisfy current trust (`Reason`): another key, identity, builder or source repository required, root replaced or its authority no longer valid at the signing time, source removed (`RecheckSource`) |
| error | the current trust input is unreadable or inconsistent (`ErrTrustConfig`), the material is malformed or fails its digests (`ErrRecheckBundle`), or the layer is not the subject's (`ErrContent`) |

Time: the verifier's clock only stamps the new receipt and bounds signing
times in the future; certificate validity is judged at the authenticated
signing times in the retained evidence, so a recheck long after a short-lived
certificate expired still verifies while the root still trusts it.

### Not done yet

- Signing and trust-root maintenance documentation and CLI interoperability
  for both methods (3.5).
- Persisting `RecheckBundle`s, the content cache and leases, and invalidating
  on configuration changes (group 4); controller wiring (group 5).
- A release workflow that produces conforming provenance (6.3).

### What has and has not been verified

Verified by unit tests without network access (verification makes no request;
the credential test's fetch goes to an in-process loopback registry through
an explicit transport):

- Real `cosign attest --key` output of the pinned Cosign v3.1.3 for the real
  official bundle (`testdata/provenance/README.md`): conforming organization-key
  provenance is accepted; wrong builder, source repository, source commit,
  version and name, the workflow revision attested as the source, forged
  content and test digests, missing materials, provenance for another digest,
  missing proofs, and mixed keys are rejected.
- Contract strictness with runtime-signed predicates; the real GitHub CI
  provenance is refused with `ErrProvenanceContract`; keyless mixed identities.
- Receipt fields, rule revision stability, recheck encoding and integrity,
  forged receipts, evidence that does not verify behind a consistent receipt,
  changed rules, removed sources, unreadable trust inputs, keyless root swaps,
  an authority that expired before the signing time and rechecks after leaf
  expiry, and the absence of planted registry credentials from the receipt and
  recheck material after an authenticated fetch.

Not verified: provenance produced by the release workflow (it produces none
yet), keyless provenance made by the Cosign CLI, and use from a running
controller.

## Create and package a bundle

1. Add `bundles/<name>/definition.json` (the name is a DNS label and must equal
   the directory). Start from `bundles/konstapel-privileged-containers/` and
   edit the policies, checks, scope, compatibility and `include` list. Every
   included source must already be in the repository; keep upstream licenses,
   provenance, the NIST catalog and profile, and the OSCAL schemas in the
   bundle, and keep `Rule_Id`/`Check_Id` values from the existing C2P mapping.
2. Commit it. Packaging reads the committed tree and records `HEAD` as the
   source, so it refuses a dirty tracked tree.
3. Package it:

   ```sh
   devbox run -- task bundles:package NAME=<name> OUT=/fresh/dir
   ```

   `OUT` must not exist. It receives an OCI image layout (`oci-layout`,
   `index.json`, `blobs/sha256/…`) holding the exact manifest and layer bytes
   that would be pushed, and `package.json` recording name, version, source
   revision and time, both digests and the Go version. The layout is verified
   after writing: blob digests and sizes, manifest shape, descriptor, and every
   inventoried file. Packaging the same commit again gives the same digests.
4. `task check` builds and verifies every `bundles/*/definition.json`, so a
   malformed definition fails there rather than at release time.

The produced layout can be inspected with any OCI tool. It is not signed and
not published, and Konstapel cannot yet consume it.

## Release a bundle

Bundles are released independently of the application, the controller image
and the Helm charts. A bundle release needs no release-please release, does
not read the application `VERSION` file and never runs the image or chart
publishers.

- **Version.** The `version` in `bundles/<name>/definition.json` is the bundle's
  own SemVer, written bare (`1.2.0`, not `v1.2.0`). Pre-release versions such as
  `1.2.0-rc.1` are allowed. Build metadata (`1.2.0+x`) is rejected because SemVer
  ignores it for precedence and OCI tags cannot contain `+`. Bump the version in
  a reviewed PR before releasing changed content.
- **Tag.** The release is marked by the Git tag `bundle/<name>/v<version>`, for
  example `bundle/konstapel-privileged-containers/v0.1.0`. Application releases
  use bare `vX.Y.Z` tags, so the namespaces never overlap. A bundle tag is
  created once and is never moved or deleted.
- **Source.** The release is built from one reviewed commit: a full 40-character
  SHA that is an ancestor of `origin/main`. The version is read from that commit,
  not from the current tip of `main`, so an older reviewed commit can be
  released or retried later.

To release, dispatch the `bundle-release` workflow on `main` (Actions → bundle-release → Run workflow, or
`gh workflow run bundle-release.yml --ref main -f bundle=<name> -f commit=<sha>`).
Runs for the same bundle are serialized and never cancelled. The workflow:

1. validates the request with `cmd/bundlerelease verify` (read-only token): the
   name is a DNS label with a `bundles/<name>/definition.json` at that commit
   whose `name` matches the directory, the commit is on reviewed `main`
   history, the version is valid, and any fetched tag for that version marks
   the same commit;
2. packages exactly that commit with `scripts/bundles/package.sh` from a
   detached worktree, re-verifies the frozen OCI layout and `package.json`
   against the request, and uploads it as the workflow artifact
   `bundle-<name>-<version>`;
3. in a separate job, the only one with `contents: write`, re-validates and
   runs `cmd/bundlerelease tag`: it pushes the tag when absent (never forced)
   or verifies that the existing tag marks exactly that commit. A tag at any
   other commit, or a ref blocking the `bundle/<name>/` namespace, fails the
   run. Rerunning a successful release is therefore harmless.

The same checks run locally against any full-history checkout:

```sh
devbox run -- go run ./cmd/bundlerelease verify -name <name> -commit <sha>
```

`cmd/bundlerelease` is a build tool; it is not part of the controller image.

**Not implemented yet.** The workflow does not push to
`ghcr.io/backend-bunny/bundles/<name>`, sign or attest anything (its provenance
must follow [Bundle provenance v1](#bundle-provenance-v1)), run the
policy fixtures against the frozen bytes, or write release notes. A bundle tag
therefore means "this version is this reviewed commit", not "this version is
published". The uploaded artifact is retained for 14 days and is not yet a
durable publication record. Write-once publication with recoverable frozen
inputs, OIDC signing and provenance, and release notes/summaries extend the
`package` job's frozen layout in later work (tasks 6.2 to 6.4 of
`add-policy-bundle-distribution`).
