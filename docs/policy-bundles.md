# Policy bundles

A policy bundle is the versioned, signed unit in which Konstapel distributes
policy content: Kyverno policies, their tests, and the OSCAL/C2P mappings to
NIST controls. A profile references a bundle by name and digest; the controller
resolves it centrally and verifies it before use.

> **Status.** This page documents the payload contract implemented in
> [`internal/bundle`](../internal/bundle) and how to build a bundle locally.
> The release workflow can publish a bundle write-once to the registry, but
> signing, provenance and runtime resolution by the controller are tracked in
> the `add-policy-bundle-distribution` OpenSpec change and are **not available
> yet**: no official bundle has been released (a published bundle stays
> incomplete until it is signed), and a locally built bundle cannot yet be
> consumed by a profile. Until those land, the only
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
- `scope.os` is a non-empty list of distinct names. Konstapel supports Linux
  workloads only: `["linux"]` is the only compatible scope. `windows` is
  recognized only so that content naming it, alone or with `linux`, is
  reported Incompatible and never adopted (see [Compatibility](#compatibility));
  an empty, repeated or other value is an invalid descriptor.
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

`bundles:package` (below) drives this; the release workflow freezes and publishes the result (see [Release a bundle](#release-a-bundle)).

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
  `applied` or `assessment`), released when that holder finishes or advances
  ([leases and eviction](#leases-and-eviction)).
- The handle carries no credentials and no payload bytes.

## Central source configuration

A `ComplianceProfile` keeps its existing `spec.bundle` of `name` and `digest`.
Where a name's bytes come from, and whom to trust for them, is configured once,
centrally, in a versioned document (`bundle.Sources`) stored under the
`sources.yaml` key of a ConfigMap in the controller's namespace. Only platform
administrators write it. The official configuration is checked in as
[`bundles/official-sources.yaml`](../bundles/official-sources.yaml): the rules for
every bundle this repository releases, which the release workflow signs for and
verifies against (see [Release a bundle](#release-a-bundle)) and which an
operator stores as `sources.yaml` to consume official bundles. An organization
example that the tests parse, a mirror with a registry credential, custom CA and
public key, is in `testdata/bundles/sources/organization.yaml`.

```yaml
version: 1
sources:
  - name: konstapel-privileged-containers   # the profile's bundle name, exact match only
    repository: ghcr.io/backend-bunny/bundles/konstapel-privileged-containers
    credentialSecret: {name: registry-creds}     # optional dockerconfigjson Secret
    ca: {kind: ConfigMap, name: registry-ca, key: ca.crt}   # optional extra trusted roots
    tokenRealms: [https://auth.example]          # optional token services on another origin
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
- **`tokenRealms` lists exact https origins** of bearer token services on
  another origin than the registry that may receive the source's credential,
  as token requests for this repository only; see
  [Token realms on another origin](#token-realms-on-another-origin).
- **References, not secrets.** Credentials, the CA, trust roots and public keys
  are references to objects in the controller's namespace; a reference has no
  namespace field. Inline key material or credentials are rejected.
- **Publisher rule.** Keyless fixes the exact OIDC issuer and signing identity
  (an optional `trustRoot` reference replaces the built-in Sigstore public-good
  root); public-key fixes a referenced key and its SHA-256 fingerprint.
  Provenance is required for every publisher and fixes the exact source
  repository and builder either way; the builder also decides which build
  record the provenance carries (see [Bundle provenance v1](#bundle-provenance-v1)).
  A keyless rule's issuer and identity are required, non-empty exact values,
  and a keyless rule with the GitHub Actions issuer must name a GitHub Actions
  workflow builder. No wildcards or patterns are accepted (and there is no
  pattern field), and nothing the bundle itself carries can change the rule.
- **Strict and atomic.** Unknown fields, repeated keys, unsupported versions and
  any invalid entry reject the whole revision; nothing is partially accepted.
  `BundleSource.CheckPayload` requires the fetched payload's name to equal the
  requested name.

This is the configuration contract and its validation. The registry adapter
and the signature verifier below use it as libraries.
[Central configuration and watches](#central-configuration-and-watches)
describes the component that reads the ConfigMap at run time; the controller
uses it when bundle sources are enabled (see
[Controller wiring](#controller-wiring)).

## Registry retrieval

[`internal/bundle/registry`](../internal/bundle/registry) retrieves one pinned
bundle and the proofs attached to it, using ORAS Go (`oras.land/oras-go/v2`
v2.7.0) for the OCI distribution protocol and its standard registry
challenge/token handling. The controller uses it when bundle sources are enabled
(see [Controller wiring](#controller-wiring)); it is linked into the controller
image since that change. Its unit
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
(scheme, host and port) and the token realm origins listed in the source's
`tokenRealms`: a request that would carry an `Authorization` header or a body
(an OAuth2 token request) to any other origin, such as an unlisted bearer
token `realm` on another host or port, is not sent and fails with
`ErrCredentialScope`; an anonymous token request to such a realm is allowed.
A listed realm receives the credential only as an unredirected token request
for the source's repository (see
[Token realms on another origin](#token-realms-on-another-origin)).
On a redirect the `Authorization` header is dropped unless the target is the
registry's origin *and* a path of the source's repository (`/v2/<path>/...`
without dot segments or escapes), so neither another host nor another
repository on the same registry receives it. Registries whose token service
lives on another host (Docker Hub's `auth.docker.io`, GitLab.com's
`gitlab.com/jwt/auth`) need that origin in `tokenRealms`.
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
| anonymous, and one requiring htpasswd credentials to write but allowing anonymous reads (a public `ghcr.io` package's access model) | `KONSTAPEL_REGISTRY_API_IMAGE` (Zot v2.1.23) | OCI 1.1 referrers API |

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
- write-once publication (`internal/bundle/publish`, see
  [Release a bundle](#release-a-bundle)) to the anonymous distribution
  registry (the publisher maintains the tag schema index) and to the
  write-authenticated Zot: the first run creates with the version tag as the
  last write and no deletes, reads back anonymously and reports both proofs
  missing; a rerun writes nothing; other bytes under the version are refused
  without a write; a proof step adds the signature and provenance without any
  write to the subject, after which the consumer adapter finds both proofs and
  skips the record; through a fault-injecting TLS proxy in front of each, a
  failed manifest push and then a failed tag push are each completed by the
  next run with only the missing pieces; against the htpasswd distribution
  registry the anonymous read-back fails with `ErrReadBack` (as a private
  package does) while an authenticated read-back succeeds; a wrong password is
  `ErrUnauthorized` and never echoed;
- release signing with the pinned Cosign CLI in key mode (`internal/bundle/sign`
  through `publish.Completer`, offline, a fresh test key, outbound HTTP(S) to a
  closed port) on both the distribution registry, where Cosign maintains the
  tag schema index itself as on `ghcr.io`, and Zot: publication followed by a
  signature and a SLSA provenance attestation of the digest; the consumer
  adapter lists both referrers; `release.VerifyRelease` (what `bundlerelease
  verify-release` runs) accepts the release anonymously under a test
  public-key rule with the source and workflow commits recorded apart, and
  refuses a rule naming another builder; a rerun signs and writes nothing; with
  only the signature present only the attestation is made; another subject
  than the record's is refused; and a signed release that anonymous consumers
  cannot read is not accepted;
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
The controller uses it when bundle sources are enabled (see
[Controller wiring](#controller-wiring)). Node
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

The runtime chart grants this access in a namespaced `Role`, `get` by name on
exactly the objects listed in its `bundles.referencedSecrets` and
`bundles.referencedConfigMaps` values (see
[RBAC and informers](#rbac-and-informers) and
[Helm charts](charts.md#oci-policy-bundles)). `resourceNames` is possible because every object is fetched by name.
Referenced objects are never listed or watched: changes are noticed by
re-reading them by name (see
[Central configuration and watches](#central-configuration-and-watches)).

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
default, at most 5 minutes; negative disables reuse). The source watcher
(`internal/bundle/sources`) calls `Provider.Invalidate(kind, name)` on every
change or deletion of a referenced object it observes (or `InvalidateAll` after a watch restarts), so
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

### Token realms on another origin

Many registries hand out bearer tokens from a service on another origin than
the registry API: the registry answers `401` with
`WWW-Authenticate: Bearer realm="https://<token service>/...",service=...,scope=...`.
By default a source's credential goes only to its registry's own origin, so
such a realm gets an anonymous token request at most, and a source with a
credential fails with `ErrCredentialScope`. `tokenRealms` names, per source,
the token service origins that may receive the credential:

```yaml
  - name: acme-dockerhub
    repository: registry-1.docker.io/acme/policy-bundles
    credentialSecret: {name: dockerhub-reader}
    tokenRealms: [https://auth.docker.io]
    publisher: ...
```

- **Exact origins, checked at load.** Each entry is `https://host[:port]`:
  lowercase DNS host, no path (not even `/`), query, fragment, userinfo,
  wildcard, IP address or `localhost`, port 1-65535 (`:443` is the same as no
  port). At most 4 per source, no duplicates, and not the registry's own
  origin (a same-origin realm needs no entry and behaves as before). An
  invalid entry rejects the whole configuration revision; the adapter checks
  the list again and fails with `ErrInvalidRequest` before any request.
- **Exact match at run time.** The realm the registry names is compared with
  the list by scheme, host and port only; `x.auth.example`, `auth.example.`,
  another port, `http://` or a realm with userinfo do not match and get no
  credential (`ErrCredentialScope`, nothing is sent to them). ORAS's own realm
  checks (no `http` realm for an `https` registry, no loopback, link-local or
  similar realm addresses) still apply first.
- **Token requests for this repository only.** A request to a listed realm
  carries the credential only as a token request: `GET` with Basic credentials
  (distribution token) or a form `POST` with the refresh token or password
  (OAuth2). Every `scope` it asks for, in the URL query or the form, must be
  `repository:<the source's repository path>:<actions>` with `pull` only when
  retrieving (`pull` and `push` for the publisher's write session), and at
  least one is required. A challenge or realm URL that asks for another
  repository, a prefix or parent of it, `*` actions, `push` while reading or
  `registry:catalog:*` makes the attempt fail with `ErrCredentialScope`
  before anything is sent.
- **No redirects of credentialed token requests.** A listed realm that
  redirects such a request, to any URL including its own origin, fails the
  attempt with `ErrCredentialScope`; the redirect is not followed, so the
  credential and the token request never reach a third party and are never
  replayed as an anonymous request. Registry redirects are unchanged: the
  `Authorization` header (the registry token) is dropped unless the target is
  the registry's origin and the source's repository, so a token service or
  blob store reached by a redirect never receives it.
- **No weaker fallback.** A realm that refuses the credential, times out or
  fails makes the retrieval fail (`ErrUnauthorized`, a timeout or
  `ErrCredentialScope`); it is never retried anonymously, and with a
  configured credential the registry is never read anonymously instead. The
  credential provider is still asked only for the registry host, never for a
  realm, and every value sent, including to a realm, is redacted from errors.

**Observed challenges.** On 2026-11-12 an unauthenticated, read-only `GET`
(no credentials) of each registry's `/v2/` and of one public repository's
manifest answered:

| Registry | `repository` host | Challenge | `tokenRealms` |
| --- | --- | --- | --- |
| Docker Hub | `registry-1.docker.io` | `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"` (manifest: plus `scope="repository:library/alpine:pull"`) | `https://auth.docker.io` |
| GitLab.com | `registry.gitlab.com` | `Bearer realm="https://gitlab.com/jwt/auth",service="container_registry"` (manifest: plus `scope="repository:gitlab-org/gitlab-runner:pull"`) | `https://gitlab.com` |

`internal/bundle/registry/realm_test.go` records these headers verbatim and
replays them against local stand-ins named like the real hosts (nothing leaves
the machine): without the entry the credential stays home, with it the
retrieval succeeds and the credential reaches only the realm.
`testdata/bundles/sources/token-realms.yaml` is a parsed example of both
sources. For Docker Hub, use `registry-1.docker.io/<namespace>/<repository>`
as `repository`, not `docker.io/...` (the API host is `registry-1.docker.io`,
and a `docker.io` repository with a credential fails with
`ErrCredentialScope`), and give the credential Secret an `auths` entry for
`registry-1.docker.io` (the `https://index.docker.io/v1/` key Docker writes
does not match). A self-managed GitLab uses its own registry host and realm
origin; read them from its `/v2/` challenge.

**Not validated.** No Docker Hub or GitLab credentials were available: no
authenticated token exchange or pull against either service was performed,
so it is not shown that their token services accept the request forms above
(Basic `GET`, or OAuth2 `POST` for an identity token) for every credential
type, nor that their tokens then work for referrers or the referrers tag
schema there. Only the challenge text was observed; the realm path and
service value may change without notice, but only the origin is configured.

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
connections, per-source trust, and concurrent rotation under `-race`. Token
realms are tested over real TLS between named in-process hosts
(`realm_test.go`): listed and unlisted realms, the near misses above,
malformed and multiple challenges, scope tampering, token-service and registry
redirects (also with a transport that does not record the redirect chain),
refusal and timeout without an anonymous retry, and, on every recorded
request, that the credential reached only the listed realm and the registry
token only the registry. The
[real-registry suite](#real-registry-compatibility) repeats the essential cases
against real registries.

## Private registry setup

How to point a bundle name at a private registry. The manifests below are the
files in `testdata/bundles/private-registry/` and the chart values in
`docs/examples/charts/oci-bundles.yaml`; `TestPrivateRegistryExamples` parses
them with the real code (the source configuration, the credential document,
the CA bundle) and checks they agree with each other, including the chart
values' grants, and `TestPrivateRegistryGuideEmbedsTheExamples` fails if this
page and those files differ. `TestLiveHelmBundles` installs the chart with
those values and objects of the same names against a disposable registry (see
[Helm installation and live acceptance](#helm-installation-and-live-acceptance)).

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

5. **Enable it in the chart.** Install or upgrade the runtime chart with the
   sources ConfigMap's name and every object it references. The chart then
   passes the `--bundle-*` flags, mounts the cache and binds a Role granting
   `get` on exactly those names, plus `get`, `list` and `watch` on the sources
   ConfigMap alone ([Helm charts](charts.md#oci-policy-bundles)). List every
   reference, including a Secret-held CA or trust root when you use one, and
   upgrade the release when the references change.

```yaml
# Verified OCI policy bundles from a private registry (docs/policy-bundles.md,
# "Private registry setup"). Create the objects first in konstapel-system:
# the sources ConfigMap (data key sources.yaml) and every Secret and
# ConfigMap it references. The chart creates none of them; it grants the
# controller get on exactly these names, plus get, list and watch on the
# sources ConfigMap alone. List every reference here: an unlisted one is
# Forbidden and makes its source unavailable.
bundles:
  sourcesConfigMap: konstapel-bundle-sources
  referencedSecrets: [acme-registry, acme-bundle-signing-key]
  referencedConfigMaps: [acme-registry-ca]
```

### Least privilege

- A namespaced Role with `get` and `resourceNames` only: no `list`, no `watch`
  from this loader, no ClusterRole, no other namespace. Only the sources
  ConfigMap itself is watched, through a single-object (field-selected)
  watch; see [the exact grants](#rbac-and-informers). The controller's
  generated Role also grants `get` on every Secret and ConfigMap in its
  namespace for other features, so today a reference the chart values omit
  is still readable ([Helm charts](charts.md#oci-policy-bundles)).
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
30 seconds (configurable up to five minutes) unless the source watcher
invalidates it sooner; the watcher itself re-reads referenced objects every
30 seconds by default (see [rotation latency](#rbac-and-informers)). When the credential for a source changes, the tokens
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
registry. In a cluster, `TestLiveHelmBundles` runs the Helm-installed
controller with these values against a disposable htpasswd/TLS registry: the
dockerconfigjson Secret, the ConfigMap CA and the public-key Secret are read by
name, and a rotated credential is used by the pods that start after it. Not
verified: bearer-token services other than the in-process fake.

## Signature verification

[`internal/bundle/verify`](../internal/bundle/verify) checks that the proofs the
registry adapter retrieved were signed by the publisher the source rule names,
for exactly the pinned manifest digest. It uses sigstore-go
(`github.com/sigstore/sigstore-go` v1.3.0) and verifies **offline**: it never
contacts a transparency log, Fulcio, a timestamp authority or a TUF repository.
Like the adapter it is used by the controller when bundle sources are enabled
(see [Controller wiring](#controller-wiring)).

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
- **A root is not a publisher.** Trusting a root (the public-good one or a
  referenced one) only says which certificate authorities, logs and timestamp
  authorities are genuine; it authorizes nobody. Every keyless rule names one
  exact issuer and one exact identity, validated when the configuration is
  parsed and again by the verifier: an empty or missing value, a wildcard or
  regular-expression character (`*?[]{}()|^$\`), or surrounding space is
  `ErrTrustConfig`, so a rule can never match every identity a root certifies.
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
- Signing, trust-root maintenance and publisher rotation are documented in
  [Signing, trust roots and rotation](#signing-trust-roots-and-rotation). A
  keyless proof made by the Cosign CLI under an isolated Sigstore stack has
  not been verified (task 3.5 stays open, see that section).
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
  their certificates expired (`testdata/ghcr/README.md`). The same proofs fail
  under rules whose identity is empty, `*`, `.*`, a regular expression or a
  prefix glob, whose issuer is empty or a wildcard, and under a GitHub rule
  with an empty or non-workflow builder (`ErrTrustConfig`).
- The first official bundle release (`konstapel-privileged-containers` 0.1.0,
  `sha256:1a2ca25a…`), signed keylessly by the bundle release workflow: its
  real proofs, kept in `internal/bundle/release/testdata/official`, verify
  offline through the production verifier and release check under
  `bundles/official-sources.yaml`, and fail under another workflow identity,
  ref, fork, issuer, builder or source repository; referencing a root object
  replaces the embedded root, with no fallback when it is missing.
- Public-good interoperability (network, opt-in): `devbox run -- go test -tags
  publicinterop -count=1 -run '^TestOfficialReleasePublicGood'
  ./internal/bundle/release/` retrieves that release anonymously from
  `ghcr.io` through the consumer's registry adapter and verifies it the same
  way, with the same negatives. Run on 2026-11-12: passed (referrers through
  the tag schema).

Not verified: a keyless proof made by the Cosign CLI with an isolated Fulcio
and Rekor (3.5), a private Sigstore deployment's real trusted root (custom
roots are tested with sigstore-go's virtual instance and with the public-good
root referenced as an object), and use from a running controller.

## Provenance verification

[`internal/bundle/verify`](../internal/bundle/verify) also applies the
provenance policy and produces receipts and recheck material. Like the
signature verifier it is used by the controller when bundle sources are
enabled (see [Controller wiring](#controller-wiring)).

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
contract. Provenance is required for every publisher. It holds exactly one
**build record**, chosen by the rule's builder, and kept apart from the source
commit:

- a **GitHub Actions workflow builder**, a builder id of the form
  `https://github.com/<owner>/<repo>/.github/workflows/<file>.yml@<ref>` (the
  form of the workflow's keyless identity), requires the **workflow record**
  `internalParameters.workflow`, whose repository, path and ref must be the
  builder's;
- **any other builder**, such as an organization's own pipeline signing with
  its key, requires the **builder record** `internalParameters.builder`, with
  the builder's own `revision`, and refuses a workflow record it could not be
  checked against. No GitHub workflow is needed.

The bundle release workflow produces the workflow form
(`publish.BuildProvenance`, see [Release a bundle](#release-a-bundle)); an
organization publishing with its own key produces whichever form its builder
requires, and can generate it with `bundlerelease provenance` (see
[Signing, trust roots and rotation](#signing-trust-roots-and-rotation)).

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

(The digests are those of the official bundle built from `e30d507`; full
conforming predicates are `internal/bundle/verify/testdata/release/valid.predicate.json`
for the workflow record and `internal/bundle/verify/testdata/provenance/valid.predicate.json`
for the builder record.) An organization builder replaces `internalParameters`
and the builder id, and nothing else:

```json
"internalParameters": {"builder": {"revision": "591d6fea5e6517bffc906540cec1e94c3def738a"}},
…
"runDetails": {"builder": {"id": "https://ci.example.test/konstapel/bundle-release@refs/heads/main"}}
```

| Field | Meaning |
| --- | --- |
| `buildDefinition.buildType` | exactly the URI above |
| `externalParameters.bundle` | the requested release: bundle `name` and SemVer `version` |
| `externalParameters.source` | the requested content source: `repository` (https URL) and full 40-character `commit` |
| `internalParameters` | exactly one build record, never both. `workflow` (GitHub Actions workflow builders): `repository`, `path`, full `commit`, and `ref` (optional in the syntax, required in effect because it must equal the builder's ref). `builder` (any other builder): `revision`, the builder's own revision as a non-empty string. Either is recorded separately from the content source: a retry from a newer pipeline revision packaging an older source commit stays distinguishable. Neither is ever used in place of the source commit. |
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
- **Build record.** For a GitHub Actions workflow builder the workflow record
  is required and its repository, path and ref must be the builder's; for any
  other builder the builder record is required and a workflow record is
  refused (`ErrProvenanceBuilder`). Both records, or neither, is
  `ErrProvenanceContract`. The workflow commit and builder revision are
  recorded, not checked against anything: the certificate's own workflow
  claims are not compared with them.
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
test and tool materials, the workflow or builder revision and invocation ID:
public identifiers and digests only.

**Limit: generic GitHub provenance is refused.** Provenance written by GitHub's
attestation actions or by a `cosign attest` of the generic Actions workflow
build type (`https://actions.github.io/buildtypes/workflow/v1`, as on the
application image's real CI proofs in `internal/bundle/verify/testdata/ghcr`)
records the workflow and its trigger commit, not the bundle, its source commit
or its content, and fails with `ErrProvenanceContract`. Official bundles get
conforming provenance from the bundle release workflow, as the first release
(`konstapel-privileged-containers` 0.1.0) shows.

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
| `provenance` | predicate type, build type, repository, revision, builder, content digest, and either `workflow` or `builderRevision` |
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
cached separately by digest ([content cache](#safe-materialization-and-the-content-cache)). Bounds: at most 64 KiB per retained
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

- Keyless interoperability with the Cosign CLI under isolated test roots
  (3.5; see [Signing, trust roots and rotation](#signing-trust-roots-and-rotation)).
- Controller wiring (group 5): retained `RecheckBundle`s, acceptance records
  and their invalidation, and cache leases now exist in the
  [content cache and resolver](#safe-materialization-and-the-content-cache),
  but nothing watches configuration or calls them yet.

### What has and has not been verified

Verified by unit tests without network access (verification makes no request;
the credential test's fetch goes to an in-process loopback registry through
an explicit transport):

- Real `cosign attest --key` output of the pinned Cosign v3.1.3 for the real
  official bundle (`testdata/provenance/README.md`): conforming organization-key
  provenance with the builder record is accepted; wrong builder, source
  repository, source commit, version and name, the builder revision attested
  as the source, a GitHub workflow record instead of the builder record, a rule
  naming a GitHub workflow builder, forged content and test digests, missing
  materials, provenance for another digest, missing proofs, and mixed keys are
  rejected.
- Contract strictness with runtime-signed predicates, including both, neither
  or malformed build records and workflow records of another repository, path
  or ref, or without a ref; the real GitHub CI provenance is refused with
  `ErrProvenanceContract`; keyless mixed identities.
- The official release's real keyless provenance (workflow record) is accepted
  under `bundles/official-sources.yaml`, offline and against `ghcr.io` (see
  [Signature verification](#signature-verification)).
- Receipt fields, rule revision stability, recheck encoding and integrity,
  forged receipts, evidence that does not verify behind a consistent receipt,
  changed rules, removed sources, unreadable trust inputs, keyless root swaps,
  an authority that expired before the signing time and rechecks after leaf
  expiry, and the absence of planted registry credentials from the receipt and
  recheck material after an authenticated fetch.

Also verified: the release tool's own generator output (`publish.BuildProvenance`
through `bundlerelease provenance`), signed by the pinned Cosign CLI with a
test key for a release that packages an older source commit (e30d507) from a
newer workflow revision (834c259), is accepted with both commits recorded apart
(`testdata/release/README.md`), and generator output for a confused source and
workflow commit, another builder, other tests and tampered records is refused.
Its builder-record output for an organization builder, signed at run time, is
accepted only under a rule naming that builder, and the generator refuses to
write a workflow record for such a builder, a builder record for a GitHub
workflow builder, or a workflow that is not the builder's. In the
registry-compatibility suite the pinned Cosign CLI in key mode signs both forms
through `bundlerelease`'s publication path, and verify-release accepts each
only under its own rule.

Not verified: keyless provenance made by the Cosign CLI against isolated test
roots, and use from a running controller.

## Signing, trust roots and rotation

A runbook for the two publisher rules, for maintaining the embedded official
trust root, and for rotating a publisher. The verifier it relies on is described
in [Signature verification](#signature-verification) and
[Provenance verification](#provenance-verification). Nothing here is performed by
the controller yet. Official releases are signed by the bundle release workflow
(see [Release a bundle](#release-a-bundle)); the commands below are what an
organization runs by hand.

### The two signing methods

| | Public key (organizations, offline) | Keyless (official releases) |
| --- | --- | --- |
| Rule fields | `publisher.type: public-key`, `publicKey` reference, `keyFingerprint` | `publisher.type: keyless`, exact `issuer` and `identity`, optional `trustRoot` reference |
| Trust anchor | the referenced public key, checked against the configured fingerprint | the trusted root (the embedded Sigstore public-good root unless the rule references its own) |
| Needs | a key pair you keep private; no Sigstore service | an OIDC identity (GitHub Actions for official releases) and the Sigstore services |
| Evidence the verifier requires | the signature | a transparency-log entry and an authenticated signing time, plus a certificate transparency timestamp when the root lists CT logs; the leaf certificate only has to be valid at that signing time |
| Provenance | required; signed by the same key; builder record unless the builder is a GitHub Actions workflow | required; signed by the same identity; workflow record of the builder's workflow for GitHub publishers |

Both proofs, the signature and the SLSA provenance attestation, are made over
the **manifest digest** (never a tag) and are stored as Sigstore bundle v0.3
referrers. The provenance predicate must follow
[Bundle provenance v1](#bundle-provenance-v1).

**Public key.** These are the commands the test fixtures were made with
(`internal/bundle/verify/testdata/cosign/generate.sh`, Cosign v3.1.3), minus the
flags that point at a plain-HTTP test registry:

```sh
cosign generate-key-pair            # keep cosign.key private; cosign.pub is public
ref=<registry>/<repository>@sha256:<manifest digest>
cosign sign   --key cosign.key --tlog-upload=false --use-signing-config=false "$ref"
cosign attest --key cosign.key --tlog-upload=false --use-signing-config=false \
  --type slsaprovenance1 --predicate predicate.json "$ref"
# The fingerprint for the rule: SHA-256 of the key's DER SubjectPublicKeyInfo.
sed '/-----/d' cosign.pub | base64 -d | sha256sum
kubectl -n <controller namespace> create secret generic acme-bundle-signing-key --from-file=cosign.pub
```

Only ECDSA P-256 keys (Cosign's default) are accepted. `--tlog-upload=false`
keeps the key mode independent of any public service; the verifier neither
requires nor claims transparency evidence in this mode. See
[the private registry guide](#private-registry-setup) for the Secret, the rule
and the Role that lets the controller read the key.

**Generating the predicate.** `bundlerelease provenance` writes the
conforming predicate for a frozen package (`scripts/bundles/package.sh`, then
`bundlerelease freeze`), with the builder taken from the publisher rule and the
build record it requires recorded separately from the source commit. For an
organization builder that is not a GitHub Actions workflow, pass the builder's
own revision (any printable string, such as the pipeline definition's commit);
`-workflow-*` flags are refused:

```sh
devbox run -- go run ./cmd/bundlerelease provenance -package /path/to/bundle \
  -sources /path/to/sources.yaml -out predicate.json \
  -builder-revision <your pipeline revision>
```

For a GitHub Actions workflow builder outside GitHub Actions, pass the run's
workflow instead (`-workflow-repository https://github.com/<owner>/<repo>
-workflow-path .github/workflows/<file>.yml -workflow-ref <ref>
-workflow-commit <40 hex>`); repository, path and ref must be the builder's,
and `-builder-revision` is refused. Inside GitHub Actions the run's environment
is recorded.

`bundlerelease publish -signing key -key /abs/cosign.key -registry <prefix>`
(with the same build-record flag; password in `COSIGN_PASSWORD`, registry credential in
`BUNDLE_REGISTRY_USERNAME`/`BUNDLE_REGISTRY_PASSWORD`) does the publication,
signature and attestation in one step for a repository that follows this
repository's release layout, and `bundlerelease verify-release -sources
<file> -public-key-file cosign.pub` checks the result as a consumer would.

**Keyless.** Official releases are signed by the `publish` job of the bundle
release workflow, the only job with `id-token: write`, as the workflow's own
OIDC identity
`https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`), the identity and builder
that `bundles/official-sources.yaml` fixes. `bundlerelease` runs exactly
`cosign sign --yes <repository>@sha256:<digest>` and `cosign attest --yes --type
slsaprovenance1 --predicate <file> <repository>@sha256:<digest>`, the invocation
the application image's verified CI proofs were made with, with Cosign's
default public-good signing configuration (Fulcio, Rekor and its timestamping).
Before it signs, it checks that the run's identity
(`$GITHUB_SERVER_URL/$GITHUB_WORKFLOW_REF`) equals the rule's identity and the
rule's builder, so a run that could only produce proofs the rule rejects
refuses to sign.

### Maintaining the official trust root

The verifier embeds the Sigstore public-good trusted root
(`internal/bundle/verify/publicgood/`) and never fetches or refreshes it. A rule
that references its own `trustRoot` object replaces it entirely and never falls
back to it, which is also how a private Sigstore deployment is supported.

**Custom roots.** A keyless rule's `trustRoot` references a ConfigMap or
Secret key in the controller namespace holding a Sigstore `trusted_root.json`
(at most 1 MiB, with at least one certificate authority and one transparency
log). The operator owns that object: refresh it from the private instance's
own TUF repository or its operator, never from the bundle. To rotate a
private instance's CA, log or timestamp authority without an outage, publish
a root that lists the old and the new authority, each with its validity
window, before signing with the new one, and drop the old entry once nothing
pinned depends on it; receipts made under the old root bytes then recheck as
`changed`, and those whose authority left the root as `invalid`. A referenced
root that is missing or unreadable fails closed; there is no fallback to the
embedded root. A root, embedded or custom, never authorizes a publisher by
itself: the rule's exact issuer and identity do.

The embedded copy only changes through a reviewed pull request:

1. In a scratch directory, fetch it with the pinned Cosign, which verifies the
   TUF metadata chain from the root embedded in Cosign:
   `HOME=$(mktemp -d) TUF_ROOT=$HOME/.sigstore/root devbox run -- cosign initialize`
   and take `trusted_root.json` from the TUF cache.
2. Check the file against the signed targets metadata independently of Cosign.
   The hash must equal the `trusted_root.json` entry in the current
   `targets.json`, reached through the live `timestamp.json` and `snapshot.json`
   of `https://tuf-repo-cdn.sigstore.dev`:

   ```sh
   cdn=https://tuf-repo-cdn.sigstore.dev
   sv=$(curl -s $cdn/timestamp.json | jq -r '.signed.meta["snapshot.json"].version')
   tv=$(curl -s $cdn/$sv.snapshot.json | jq -r '.signed.meta["targets.json"].version')
   curl -s $cdn/$tv.targets.json | jq -r '.signed.targets["trusted_root.json"].hashes.sha256'
   sha256sum trusted_root.json
   ```

3. Replace the file, update `PublicGoodTrustRootSHA256` in
   `internal/bundle/verify/trust.go` and the table in the directory's README
   (TUF versions, hash, contents), and run the verifier tests: the real-proof test
   must still verify. A hash that does not match the constant is refused at run
   time with `ErrTrustConfig`.

When to refresh: when Sigstore rotates a certificate authority, log, or
timestamp authority, and in any case before the TUF root it was taken from
expires (root v16 expires 2027-04-22). The two failure directions differ. A
root that is too old fails closed for new Sigstore instances, so new proofs stop
verifying. But a key withdrawn upstream stays trusted here until the next
refresh, so treat a Sigstore key-compromise announcement as a trigger to refresh
at once, and let operators who need faster control pin their own `trustRoot`
object (and rotate it themselves). The embedded root is trusted for the
public-good instance only; it says nothing about which identities are allowed.
That is always the rule's exact issuer and identity.

### Rotating a publisher

A source has exactly one publisher rule, so there is no overlap window. Changing
the rule changes its revision, which makes earlier receipts fail a recheck and
makes every pinned digest unresolved until a proof that satisfies the **new** rule
exists. Rotate in this order:

1. **Re-sign first.** For every digest that profiles still pin, attach a new
   signature and provenance with the new key (or identity). Referrers are
   additive: the old proofs stay in the registry and are simply never selected,
   because the rule decides the signer. The provenance must be re-issued too,
   since both proofs have to come from the same signer.
2. Check each digest against the new rule (the verifier tests show the shape: the
   same manifest verifies under the new key or identity and fails under the old).
3. **Switch the central rule** (new `keyFingerprint` and key Secret, or new
   `identity` and `provenance.builder`) in the sources ConfigMap. A builder
   change that crosses between a GitHub Actions workflow and another builder
   also changes the build record the provenance must carry, so the re-issued
   provenance has to use the new builder's form.
4. Retire the old key or workflow identity once nothing pins an unsigned digest.

The same order applies to a keyless identity change such as renaming the release
workflow or moving it to another branch (`identity` and `provenance.builder` both
change), and to a source repository move (`provenance.sourceRepository`).
Pointing the source at a mirror is not a rotation: `repository` is only a
location, and it does not change the rule revision.

Revoking a publisher in an emergency is the same edit without step 1: change or
remove the rule, and affected resolution becomes unavailable. Policies that are
already applied stay in place and are reported as stale, never silently
withdrawn (see the targeting design); removing enforcement is an explicit
administrator action.

### What has and has not been verified

Coverage of the two methods (task 3.5):

| Path | Isolated, deterministic | Real public instance |
| --- | --- | --- |
| Public key | pinned Cosign v3.1.3 CLI output with generated test keys, offline, against a disposable registry (`testdata/cosign`, `testdata/provenance`, `testdata/release`), and the CLI driven by `bundlerelease` in the registry-compatibility suite; no verification check disabled | not applicable |
| Keyless | sigstore-go's virtual Sigstore and a test CA as isolated roots, with Go-made proofs (`keyless_test.go`); no check disabled | pinned Cosign CLI output from GitHub Actions against the public-good root: the application image proofs and the official bundle release, offline, and the opt-in live test against `ghcr.io` |

Verified also: the embedded root's hash against the live signed TUF targets
metadata (checked independently on 2026-11-11, targets v14), and real Cosign
output verifying after its leaf certificates expired.

Not verified, and why task 3.5 stays open: **Cosign CLI output made against
isolated keyless test roots.** The Cosign CLI only signs keylessly through a
Fulcio and a Rekor (and optionally a timestamp authority), so that path needs
an isolated Sigstore stack, which was deliberately not deployed: the CLI's
keyless output format is covered by the real public-good proofs, and the
verifier's checks against an isolated root are covered with Go-made proofs.
The remaining gap is exactly the combination of the two. Also not verified: the
rotation steps end to end (only their building blocks are tested), and anything
that runs in the controller.

## Organization publication and mirroring

An organization publishes its own bundles, or mirrors the official ones into a
private registry, with the same format and the same verifier as the official
release. Nothing here is a second trust path.

### Publish your own bundle

Build with `bundle.Build` and package like the official bundles, then run
`bundlerelease publish` against your repository (`-registry HOST/PREFIX`,
credential in `BUNDLE_REGISTRY_USERNAME` and `BUNDLE_REGISTRY_PASSWORD`) with
`-signing key` (your Cosign key) or `-signing keyless` (your CI identity) and
`-sources FILE` naming your publisher rule. Consumers reference the bundle
through a `BundleSource` whose publisher rule pins your key fingerprint or
issuer and identity, and the provenance source repository and builder. See
[Signing, trust roots and rotation](#signing-trust-roots-and-rotation).

### Mirror a published bundle

```sh
BUNDLE_REGISTRY_USERNAME=... BUNDLE_REGISTRY_PASSWORD=... \
  bundlerelease mirror -from ghcr.io/backend-bunny/konstapel/bundles/NAME \
    -to registry.example.org/mirror/NAME -digest sha256:HEX
```

The source is read anonymously; the destination is written with the
credential. The copy is by digest and never rewrites bytes: the subject
manifest, its layer, and the signature and provenance referrers keep their
digests, so the original publisher's signature and provenance verify at the
mirror. Point a `BundleSource` at the mirror with the same `publisher` rule
and a different `repository`; the rule revision excludes the repository, so
only the location changes. A mirror is never a source of trust.

The command refuses, before any write, a source that lacks the required
signature or provenance referrers (`ErrMissingProofs`), and after the copy
reads the destination back and fails if it does not return identical content
and proofs. Publication-record referrers and tags are not copied; the
consumer verifies by digest. A subject copied by other tools without its
referrers is refused by verification (`ErrMissingProofs`).

### What has and has not been verified

The registry compatibility suite (`scripts/registry-compat.sh`) copies a
signed bundle from a distribution registry to a Zot with htpasswd writes:
digests and proofs are identical, verification passes anonymously under the
same rule with only the repository changed, a source without proofs is not
mirrored and leaves nothing at the destination, and a subject-only copy fails
verification. Mirroring from registries that require credentials for reading
is not supported by the command.

## Safe materialization and the content cache

Package `internal/bundle/cache` turns the digest-verified manifest and layer
bytes from the [registry adapter](#registry-retrieval) into an extracted,
verified, immutable tree on local disk that rendering and the assessment
producer will read, retains the verification evidence beside it, and pins
entries with leases. Package `internal/bundle/resolve` composes retrieval,
the cache, the [verifier](#receipts-and-recheck) and in-memory acceptance
records into one resolution of a pinned digest. The controller builds both when
bundle sources are enabled (see [Controller wiring](#controller-wiring)); the
chart does not mount a cache volume yet.

A cache entry is never an authorization. It proves only that the stored bytes
are the ones the manifest digest names and that they passed the archive policy,
the inventory check and the content check when stored. Trust, source rules and
compatibility are evaluated separately, as an
[acceptance](#acceptance-is-separate-from-cached-bytes) under the revisions
current when the content is used.

### Layout

| Path under the cache root | Contents |
| --- | --- |
| `blobs/sha256/<hex>` | the raw manifest and layer bytes, named by their digests |
| `content/sha256/<manifest hex>/tree/` | the extracted payload, `bundle.json` included |
| `content/sha256/<manifest hex>/record.json` | the integrity record |
| `proofs/sha256/<manifest hex>` | the retained verification evidence (a header with its SHA-256, then the canonical `RecheckBundle`) |
| `staging/<random>/` | in-flight work; never read as content |
| `.lock` | the owner lock |

Entries are addressed by the OCI manifest digest, the same identity targeting
uses. A layer shared by two manifests is stored once. The integrity record
holds the manifest and layer digests and sizes, the canonical inventory
(`content`) digest, the digest of `bundle.json`, name, version, file count and
unpacked size. It contains no time, so identical content always yields an
identical record. Files are created read-only (`0444`, never executable,
setuid, setgid or sticky). Directories are `0755` beneath a `0700` root.
Archive modes, owners, times and extended attributes are ignored.

### Limits and defaults

`cache.DefaultLimits()`. Every value is configurable, and `Limits.Validate`
rejects non-positive values, values beyond what a filesystem can hold
(a component above 255 bytes, a path above 3072 bytes), a descriptor limit
above the unpacked limit, and a capacity that cannot hold one maximal entry
while it stages.

| Limit | Default |
| --- | --- |
| Manifest | 4 MiB |
| Compressed layer, as stored and as read | 64 MiB |
| Unpacked payload (sum of file sizes) | 256 MiB |
| Regular files, `bundle.json` included; implied directories are bounded by the same number | 4096 |
| `bundle.json` | 4 MiB |
| Path / path component / depth | 1024 bytes / 255 bytes / 32 components |
| Retained verification evidence per entry (`MaxProofBytes`, at most `verify.MaxRecheckBytes`) | 16 MiB |
| Cache capacity, including staging, blobs, records and retained evidence | 1 GiB |

Decompressed tar metadata (headers, PAX records, padding) is bounded at 16 KiB
per entry on top of the unpacked limit. Capacity is charged in whole 4 KiB
blocks per file and directory, at least one block each, to approximate disk
allocation. With the defaults, one maximal entry plus its staging and its
retained evidence needs about 372 MiB, and `Validate` requires the capacity to
hold at least that.

### Archive policy

Extraction streams the layer and stops at the first violation, before reading
or writing the bytes it governs. It rejects the following:

- **Paths.** Absolute paths, `..`, `.`, empty components and trailing
  slashes, meaning anything that is not exactly its `path.Clean` form. Also
  backslashes, NUL, control characters, DEL and any non-ASCII byte. Paths
  outside `content/`, `tests/`, `licenses/`, `LICENSE`, `NOTICE` and
  `bundle.json` are rejected using the shared `bundle.ValidPayloadPath` rule.
  Over-long paths, over-long components and over-deep paths are rejected too.
- **Entry types.** Symlinks, hardlinks, character and block devices, FIFOs,
  directory entries (directories are implied by file paths and created by the
  cache), contiguous files, PAX global headers and any other non-regular type.
  tar cannot carry sockets.
- **Collisions.** Any two paths that would collide on a case-insensitive
  filesystem. This covers exact duplicates, case variants of a file or of
  any directory component, and a path used both as a file and as a directory.
  Unicode is not admitted at all, so normalization collisions (NFC/NFD, the
  Kelvin sign) are impossible by construction rather than detected by
  tables.
- **Malformed streams.** Data that is not gzip, a truncated or corrupt gzip
  stream, a bad CRC or length, a second gzip member, bytes after the gzip
  stream, anything other than zero padding after the tar end-of-archive marker,
  truncated entries, and entry sizes that lie in either direction. A missing
  end-of-archive marker is tolerated, because the inventory check enforces
  completeness.
- **Limits.** Any limit above. The compressed limit is enforced on bytes read.
  The unpacked limit and the file limit are checked against each header
  before its data is read.
- **Inventory.** A missing or invalid `bundle.json`. An inventoried file that
  is missing, resized or has another digest. Any file that `bundle.json`
  does not inventory.
- **Pairing.** A manifest that is not the bundle shape (`bundle.ValidateManifest`)
  or a layer that is not exactly the digest and size the manifest names.

### Storing an entry

`Cache.Put(ctx, manifest, layer)` runs these steps in order:

1. Check the manifest and pair the layer with it.
2. Run a first pass over the in-memory layer. It applies the whole archive
   policy and the inventory check and writes nothing. A rejected archive
   therefore never touches the disk.
3. Reserve the entry's exact charge plus its staging overhead against capacity
   under a mutex. If it does not fit, return `ErrCapacity` having written
   nothing.
4. Create `staging/<random>/` with 128 random bits, never a name derived from
   the archive. Write and fsync both blobs. Extract in a second pass under the
   same policy: every file is created with `O_CREATE|O_EXCL` inside an
   `os.Root` confined to the cache root, written exactly its declared size,
   then fsynced and closed. Directories are synced deepest first.
5. Verify the staged tree on disk against the inventory derived from the
   layer. This is the on-disk equivalent of `Descriptor.VerifyPayload`, and it
   also rejects links, special files, unexpected directories and writable or
   executable modes. Each file is opened and compared with its `Lstat` result.
6. Run the content check on the staged tree, by default
   `bundle.ValidateContentDir`. This is `bundle.ValidateContent` reading the
   tree in place: it only reads and parses, and it executes and applies
   nothing.
7. Write and sync the record and the staging directories.
8. Promote under a commit lock. If an intact entry for the digest already
   exists, discard the staged copy and return the existing entry, never
   replacing it. Otherwise rename the blobs into `blobs/sha256/` (keeping an
   intact existing blob and atomically replacing a corrupt one with the
   verified copy), sync that directory, and rename the entry directory into
   `content/sha256/`. That rename is the commit point. Finally sync `content/`.

Every failure removes the staging directory and releases the reservation on
every exit path, including a panic. Existing entries and anything outside the
cache's own staging are left unchanged. Concurrent `Put`s of one digest
coalesce: one stages and the others wait. If the first caller gives up, the
next one tries. Concurrent `Put`s of different digests are admitted only while
their reservations fit. An `ENOSPC`/`EDQUOT` while staging returns `ErrNoSpace`
after the same rollback.

### Reuse, integrity and recovery

`Cache.Get(ctx, digest)` (and `Verify`) re-verifies an entry from its path
digest down on every call, with no trust in the record. It checks that:

- the manifest blob hashes to the digest and has the bundle shape;
- the layer blob hashes to the digest the manifest names and passes the
  archive policy as it is re-read;
- the record is byte-for-byte the record those bytes produce;
- the tree is exactly the inventory re-derived from the layer.

A mismatch returns `ErrCorrupt`. The entry is first renamed out of
`content/`, so it disappears atomically, and is then deleted. A corrupt entry
is never returned. `Entry.Layer()` and `Entry.Manifest()` re-read the blobs
and check their digests. The layer is the input `Verifier.Recheck` takes.
Verification detects at-rest corruption. It does not defend against another
writer modifying the tree while it is in use: the cache root belongs to the
controller alone. Limits apply on reuse too, so lowering them makes larger
stored entries unusable.

`Open` takes an exclusive `flock` on `.lock`, so a second owner, in-process or
not, gets `ErrInUse`. Because of the lock, Open can treat all of `staging/` as
abandoned and removes it. It also removes entries whose record or blobs are
missing or inconsistent, unreferenced blobs, and unexpected names inside
`blobs/`, `content/` and `staging/`, and reports all of it in `Recovery()`.
Payload trees are re-hashed lazily on reuse, not at Open. Nothing else in the
root, such as a volume's `lost+found`, is touched. An interruption at any
step of `Put` therefore leaves either no entry or a complete one, plus
staging debris that the next Open removes.

### Retained verification evidence

`Cache.PutProofs(ctx, digest, recheckBundle)` stores the `RecheckBundle` of a
stored entry ([receipts and recheck](#receipts-and-recheck)), replacing any
earlier one. It refuses, before writing anything, material that fails
`RecheckBundle.Check`, is for another subject, or exceeds `MaxProofBytes`.
Its charge (whole blocks of the file) is reserved first, evicting other
unleased entries if needed but never the entry itself; the file is written in
staging, fsynced and renamed over the old one under the commit lock, so either
the old or the new material is in place after a crash.

`Cache.Proofs(digest)` re-reads the file on every call and checks its size, the
SHA-256 recorded when it was written (in memory, and in the file header after a
restart), the strict canonical decoding (`verify.DecodeRecheckBundle`, which
also checks every retained digest) and that it is for exactly this digest.
Material that fails is removed and `ErrCorrupt` returned; the entry itself is
kept, and `ErrNoProofs` follows until verified material is stored again. The
material is removed with its entry on every removal path, and `Open` removes
material whose entry is gone or whose header is malformed (`Recovery().Proofs`).
It is evidence for a recheck under current trust, never a decision: a
well-formed file carrying other valid material for the subject is served after
a restart (only the header hash remains to compare with), and the recheck then
judges it like any other evidence.

### Capacity

The charge covers stored blobs, entries, retained evidence and in-flight
reservations, and `Stats()` reports it: capacity, used and reserved bytes,
the number of leases, and per entry its charge (including its evidence, and
its layer blob unless shared), the evidence charge, its leases and its last
use. Reservation is the single admission point and entry removal a single
internal path (detach from the index, then remove the files, then release the
charge).

### Leases and eviction

`Cache.Acquire(digest, holder, owner)` pins a stored entry and returns a
`bundle.Lease` with a random 128-bit ID; `Release(lease)` ends it. Holders are
`profile` (a desired profile references it), `applied` (the last applied
contribution uses it) and `assessment` (an active assessment snapshot needs
it). Several owners can lease one entry, each with its own lease. Only the
exact lease returned can be released: an unknown, already released or altered
lease (another owner, holder, digest or time under a known ID) is `ErrLease`
and releases nothing. `PutLeased` stores content and leases it atomically, so
it cannot be evicted between the two. Leases live in memory only; after a
restart there are none, and owners re-acquire them from their own state.

When a reservation does not fit, the cache evicts unleased entries in
least-recently-used order (`Get` and `Acquire` count as use; ties go to the
smaller digest). It first computes the shortest such prefix whose removal frees
enough, counting a shared layer blob only when every entry using it is a
victim. Only if that prefix suffices are the victims detached from the index
and removed, under the commit lock, so no lease can be taken on a chosen
victim. Otherwise the reservation fails with `ErrCapacity` having evicted and
written nothing. Leased entries are never evicted: when leases pin too much of
the capacity, new content fails rather than displacing content that is still
needed. Eviction never touches staging, `OnRemove` reports each removed digest
(the resolver drops its acceptances), and `Get` of an entry evicted while it
was being read is `ErrNotFound`, never a corrupt read. An entry's files stay
valid only while a lease is held.

A leased entry is removed only when it is found corrupt. Its holders then get
`ErrCorrupt` from `Get`, never the bytes, until they release it or the verified
bytes are stored again under the same digest (the leases then pin the new
copy).

### Acceptance is separate from cached bytes

An acceptance (`resolve.Acceptance`) is a derived, in-memory decision that a
cached digest may be used. It is keyed by every revision it depends on:

| Key component | Source | Unchanged by |
| --- | --- | --- |
| `Name`, `Digest` | the request | |
| `Rule` | `verify.RuleRevision` of the source as configured now | a mirror (repository), credential Secret or CA change |
| `Trust` | `Revisions.Trust`: the revision of the root or key object the rule references | credential or CA rotation |
| `Compat` | `Revisions.Compatibility`: the controller and provider contract | |

The current revisions are read on every lookup, so a decision under changed
revisions is never found. `Acceptances.InvalidateSource`, `InvalidateDigest`,
`Invalidate(predicate)` and `InvalidateAll` also drop decisions explicitly.
Nothing is persisted: after a restart no acceptance exists until one is
recomputed from retained evidence or a fresh verification.

**Concurrent changes.** A resolution captures invalidation generations
(global, per source and per digest) before it reads the revisions. It records
its acceptance only if those generations and the revisions are unchanged, and
checks both again immediately before adoption; otherwise it fails with
`ErrStale`, records and adopts nothing, and releases its lease. Whoever changes
configuration must first make `Revisions` return the new value and then
invalidate, so a resolution either sees the new revisions or is refused.
`Resolver.Confirm(handle)` repeats the check for a caller about to apply an
earlier result.

### Resolution and registry outages

`Resolver.Resolve(ctx, {Name, Digest, Holder, Owner})` takes the source
configured now for `Name`, leases the cached entry if there is one (and checks
its integrity), then:

1. an acceptance under the current revisions: the cached content is served,
   with no registry request and no verification;
2. otherwise, cached content with retained evidence: `Verifier.Recheck` under
   the current rule and trust material, offline, then the compatibility check.
   The receipt in the evidence is never used; the handle carries the
   recomputed one, and changed claims replace the stored evidence;
3. otherwise retrieval by digest through the registry adapter, full
   verification (`Verifier.Accept`), the compatibility check, `PutLeased` and
   `PutProofs`.

It returns a `bundle.ResolvedContent` with a new lease that the caller
releases (`Resolver.Release`), or an error wrapping `ErrUnresolved` with no
lease held. There are no retries: the caller re-runs resolution.

| Situation, registry unavailable | Result |
| --- | --- |
| intact content, complete evidence that satisfies current trust | resolved offline (path 1 or 2) |
| content lost (not cached, or found corrupt) | `ErrContentUnavailable` |
| content cached, evidence missing or corrupt | `ErrProofUnavailable` |
| evidence no longer satisfies the rule (another key, builder or source repository required) | `ErrUntrusted` |
| referenced key or root unreadable or replaced by other material | `ErrUntrusted` (no retrieval is tried) |
| source removed | `ErrConfig` |
| content incompatible with the controller or provider | `ErrIncompatible` |
| configuration changed during resolution | `ErrStale` |
| capacity pinned by leases | `ErrCapacity` |

With the registry reachable, missing or insufficient evidence is replaced by
fresh evidence when that satisfies current trust.

### Restart and persistent storage

The same rules apply to the default `emptyDir` and to an operator-provided
persistent directory. After a restart `Open` recovers as described above,
entries and evidence are re-verified on use and anything corrupt is removed and
never served, and no acceptance or lease exists: acceptances are recomputed
from retained evidence under the configuration current then, and leases are
re-acquired by their owners. Reopening with a lower capacity keeps every entry;
the next admission evicts unleased entries as needed, or fails with
`ErrCapacity` if leases pin too much.

### Cache lifetime and outage behavior

What an operator can rely on. The cache is a performance and availability aid
for bundle content, never a source of trust and never durable storage.

**What survives what.** The default cache directory is a bounded `emptyDir`
(not mounted by the chart yet; see below). An `emptyDir` lives as long as its
Pod, so:

| Event | Cached content and retained evidence | Acceptances and leases |
| --- | --- | --- |
| Container restart inside the same Pod | survive, and are re-verified on use | lost: recomputed from the retained evidence under the current configuration, re-acquired by their owners |
| Pod replacement, node loss, eviction, rollout | lost with the `emptyDir`: the next start has an empty cache | lost, as above |
| Operator-provided persistent volume | survive all of the above, with the same integrity rules (anything corrupt is removed and never served) | lost, as above |
| Lowering the capacity on reopen | every entry is kept; the next admission evicts unleased entries or fails with `ErrCapacity` | lost, as above |

Nothing in the default configuration promises that cached bytes survive a Pod
replacement, and nothing here should be read as durable storage. A persistent
volume is an operator choice that only changes how often content has to be
fetched again; it never changes what is trusted.

**What a cache hit means.** Cached bytes are never authorization. Serving them
needs an acceptance under the current source rule, trust material (root or
key) and compatibility revision, recomputed offline from the retained evidence
when none is held (`Verifier.Recheck`; the stored receipt is data to compare
against, not authority). Rotating registry credentials or pointing the source at
a mirror changes none of those revisions, so it invalidates nothing. A changed
rule, key, root or provider contract does, and the next resolution either
re-verifies or fails.

**What operators see, and what to do.** Every failure is `ErrUnresolved`
without a lease held; the controller (group 5) turns them into status
conditions. Applied policies are never removed because resolution failed.

| Result | Meaning | Action |
| --- | --- | --- |
| `ErrContentUnavailable` | not cached (a fresh or wiped cache, or an entry found corrupt) and not retrievable now | restore access to the registry; the content is fetched again and verified |
| `ErrProofUnavailable` | content cached but the retained verification evidence is missing or corrupt, and the registry cannot supply it | restore registry access; fresh evidence replaces it |
| `ErrUntrusted` | the evidence no longer satisfies the current rule, key or root (rotated, replaced, or unreadable) | publish proofs that satisfy the current rule, or correct the configuration |
| `ErrIncompatible` | the content does not match the controller or provider contract | use a compatible bundle version or upgrade |
| `ErrConfig` | no source is configured for the bundle name | configure it, or restore the removed entry |
| `ErrStale` | the configuration changed while resolving | none: resolve again |
| `ErrCapacity` | leased (pinned) content leaves no room | raise the capacity or use a persistent volume; leases are released when owners advance |

**Registry outages.** With the registry down, a bundle resolves only if its
content and complete evidence are still cached and still satisfy the current
trust configuration. A wiped cache, missing evidence, or changed trust stays
unresolved; there is no stale success and no verification is skipped.

**Applied policies.** Resolution decides whether content may be newly used, not
whether already applied policies keep running. When content becomes unresolved,
policies already applied stay in place and are reported as stale or unresolved
with the applied and desired revisions kept apart; content that failed to
resolve is never newly installed or reapplied, and an exception cannot newly
authorize anything meanwhile. After a process or cache loss the controller
reconstructs applied ownership through the targeting contract; cached status
alone never authorizes content. That reporting is the controller's (group 5) and
is not implemented yet.

**Sizing.** The defaults (1 GiB total, 64 MiB compressed and 256 MiB unpacked
per entry, 16 MiB of retained evidence per entry) exist to bound hostile
content; the official bundle is well under 1 MiB compressed. Size the volume
for the bundles you configure plus the worst-case reservation of one entry
(about 372 MiB at the defaults), which is the minimum the configuration
validation accepts.

**How the cases are tested.** `TestOutage` in `internal/bundle/resolve` runs
each scenario above with and without a process restart, against a registry that
is down and records whether it was called: reuse after restart (offline recheck,
no registry request), a lost cache (the whole directory removed, as on Pod
replacement) giving `ErrContentUnavailable`, missing and corrupt evidence giving
`ErrProofUnavailable`, corrupt content, rotated-out or replaced keys and a
changed builder giving `ErrUntrusted`, a removed source, an incompatible
provider, and recovery when the registry returns. The cache package tests cover
corruption and capacity after restart. The stale-applied-policy reporting is
verified with the controller wiring, so task 4.5 is not ticked.

### Not done yet

- The cache volume itself: the default bounded `emptyDir` (which does not
  survive Pod replacement) and the optional operator-provided persistent volume
  are described above, but neither is mounted by the chart yet; and the
  controller's reporting of stale applied policies (task 4.5 stays unticked
  until it is verified with the controller wiring).
- Controller wiring (group 5): configuration and Secret/ConfigMap watches
  feeding `Revisions` and the invalidation calls, installing the compatibility
  check and the content source ([using resolved bundles as a content
  source](#using-resolved-bundles-as-a-content-source)), re-acquiring leases
  from applied ownership after a restart, status conditions, retries, and the
  chart's cache volume.

### What has and has not been verified

Verified by unit tests on a real temporary directory with `-race`. A
failure-injecting filesystem wrapper simulates `ENOSPC`, a process crash at
every mutating step of a `Put`, and a panic. The tests cover:

- every rejection class above, each checked to leave a snapshot of the cache
  root, a sibling directory and a symlink unchanged and to perform no write;
- the official bundle round trip, equal to `bundle.Unpack`;
- inventory mismatches;
- promotion atomicity seen by a polling observer, and commit ordering;
- the destination-exists race, coalescing, and exact admission under
  concurrent capacity pressure;
- corruption of every stored component, with and without a restart, and
  recovery;
- retained evidence: round trip, replacement and restart, refusal without
  writing, corruption of every part of the file with and without a restart,
  reservation before writing (refused with zero writes and zero evictions,
  never evicting its own entry), removal with its entry, `ENOSPC` while
  writing it, concurrent replacement, and a crash at every mutating step of
  `PutProofs`;
- leases (several owners, double, foreign and altered releases), exact LRU
  victim order and tie-break, refusal with zero evictions and writes when
  leases pin the capacity, all-or-nothing eviction after reopening with a lower
  capacity, eviction racing a `Get` at a deterministic point (`ErrNotFound` for
  an unleased entry, untouched when leased), a leased entry found corrupt, and
  a concurrent put/evict/lease stress test, with the accounting recounted from
  disk afterwards.

The resolver is tested with the real Cosign organization-key fixtures of the
official bundle ([provenance verification](#provenance-verification)), a fake
registry and real temporary directories: the three resolution paths, every
acceptance key component (each change misses, a mirror or credential or CA
change hits), every outage row above with and without a restart, an edited
receipt (replaced by the recomputed one) and a consistent receipt over
another key's evidence (no acceptance), invalidation and revision changes
injected exactly between verification and recording and between recording
and adoption on both the retrieval and the recheck path (`ErrStale`, nothing
recorded, no lease left), and a concurrent resolve/invalidate stress test.

Not verified: behaviour on a real full disk or quota (only injected), a real
power loss (fsync ordering is checked from the operation log, not by cutting
power), filesystems other than the test host's, keyless trust-root swaps
through the resolver (the verifier's own tests cover them), and anything in
the controller.

## Using resolved bundles as a content source

`internal/bundle/content.OCIContent` implements `targeting.ContentSource`, the
seam the profile, binding and exception-admission code already consume through
`LocalContent`. It owns no transport, trust or caching: `resolve.Resolver`
decides whether the pinned digest may be used now, the content cache supplies
the integrity-checked bytes, and targeting keeps rendering, names and
revisions. The controller serves it through a router that keeps the vendored
bundle on `LocalContent` (see [Controller wiring](#controller-wiring)).

### Mapping

`Content(ctx, {Name, Digest})` resolves exactly that name and OCI manifest
digest. A handle or cache entry for any other name or digest is
`DigestMismatch`: content is never substituted.

| `targeting.Content` field | Value |
| --- | --- |
| `Bundle.Name` | the reference's name (the configured source name, equal to the descriptor's `name`) |
| `Bundle.Digest` | the OCI manifest digest, the only bundle identity `EnforcementRevision` uses; a mirror or credential change cannot alter it |
| `Bundle.Policies[]` | one entry per descriptor `policies[]` entry, by its logical `name` (what profiles reference), with the scope `targeting.PolicyScopeOf` assigns; `Parameters` stays `false` |
| `Policies[name].Manifest` | the policy file named by `policies[].path`, read from the verified cache tree and parsed by `targeting.ParsePolicyManifest`, the same parser `LocalContent` uses |
| `Policies[name].SourceDigest` | `sha256:` and the descriptor's recorded sha256 of that file (the bytes are re-hashed against it on every read) |
| `Policies[name].ParametersValidated`, `ParameterSchema` | `true`, and the bytes of the policy's `parameterSchema` file (`nil` when it declares none) |

For the official bundle the result equals `LocalContent`'s for the vendored
copy of the same policy file: same name, parsed manifest, source digest and
scope. Only `Bundle.Name` and `Bundle.Digest` differ, so profile and binding
governance (rendered names derived from the revision, owner labels and
references, exception settings, mode, namespace selector, untouched rules) is
unchanged; the revision moves only with the manifest digest.

### What is data and what is a policy

Only files that a descriptor `policies[]` entry names, and whose inventory role
is `policy`, are read as policies. Everything else is data and is never
returned, rendered or applied: upstream Kyverno and Chainsaw test fixtures
(the official bundle carries Pods, RBAC and a PolicyException under
`.chainsaw-test/` and `.kyverno-test*/`), `tests/`, OSCAL documents, schemas,
licenses, and a `policy`-role file that no `policies[]` entry names. A profile
naming such a file gets `UnknownPolicy`.

Scope is reported per policy, so one unsupported policy does not reject the
bundle's others: `Namespaced` for a `policies.kyverno.io/v1` ValidatingPolicy
whose every matched resource is a known namespaced workload resource,
`Cluster` for one that matches cluster-scoped or unknown resources, and
`Unsupported` (`targeting.ScopeUnsupported`) for another API or kind. The
targeting resolver and the profile reconciler report both non-namespaced scopes
as `UnsupportedScope`, and the renderer refuses them.

### Compatibility

`content.Compatibility{Controller, Providers}` implements the resolver's
`Compatible` check (`Check`) and its compatibility revision (`Revision`).
All rules must hold; each failure is one reason in the verdict:

- `compatibility.provider` is in the installed provider allowlist, by default
  exactly `konstapel-kyverno/v1`. A bundle names a provider contract, never an
  executable, and cannot add one.
- `compatibility.konstapel`, a minimum release, is at most the running
  controller's version under SemVer 2.0.0 precedence, ignoring build metadata.
  A pre-release precedes its release: controller `0.2.0-rc.1` accepts
  minimums up to `0.2.0-rc.1` (and every `0.1.x`) but not `0.2.0`. A
  controller version that is not SemVer is a configuration error.
- every declared OSCAL version is supported: `1.1.3` (authored component
  definitions) and `1.2.3` (the NIST documents).
- `scope.os` is exactly `linux`: Konstapel supports only namespaced Linux
  workloads, so a bundle that also or only claims another OS is incompatible
  (an empty, repeated or unrecognized scope is already an invalid descriptor;
  see [Descriptor](#descriptor-bundlejson)).

`Revision` hashes a rules version, the controller version, the sorted and
deduplicated allowlist and the supported OSCAL versions and OS. It changes when
the allowlist or controller version changes and not otherwise, which drops
acceptances recorded under the old contract.

### Parameters

The renderer does not render profile parameters, so `BundlePolicy.Parameters`
stays `false` for OCI content exactly as for `LocalContent`, and the targeting
resolver keeps rejecting any non-empty parameters with `InvalidConfiguration`
rather than dropping them. `content.ValidateParameters(src, policy, raw)`
checks parameters against the declared contract with
`bundle.ValidatePolicyParameters`, which has `bundle.ValidateParameters`'
semantics: a policy without a schema accepts no parameters, otherwise they must
be a JSON object valid against the schema (duplicate keys are rejected; the
schema decides whether unknown properties are allowed). It returns `nil` for a
source with `ParametersValidated == false` (`LocalContent`), whose parameters
stay governed by the resolver's gate alone. The explicit flag, rather than a
`nil` schema, keeps "declares no parameters" distinct from "declares no
contract". The controller uses it to give the rejection a precise reason.

### Errors

Every resolution outcome and every unusable content is a
`*targeting.ContentError` that `errors.Is(err, targeting.ErrContentUnavailable)`,
so existing callers report `ContentUnavailable` unchanged, and that carries a
class for detailed status:

| Class | From |
| --- | --- |
| `Config` | `resolve.ErrConfig`: no source configured, or its trust revision unreadable |
| `ContentUnavailable` | `resolve.ErrContentUnavailable`, or bytes no longer matching their verified digest |
| `ProofUnavailable` | `resolve.ErrProofUnavailable` |
| `Untrusted` | `resolve.ErrUntrusted` |
| `Incompatible` | `resolve.ErrIncompatible`, with the verdict's reasons |
| `Stale` | `resolve.ErrStale`: retry |
| `Capacity` | `resolve.ErrCapacity` |
| `Unresolved` | any other `resolve.ErrUnresolved`, such as a malformed digest |
| `DigestMismatch` | a handle or entry that is not exactly the pinned name and digest |
| `Malformed` | a policy path that is not an inventoried `policy` file, or a policy that is not YAML |

`Detail` is bounded (512 bytes) and credential-free by construction: it holds
the reference, the class sentinel's fixed text and the fixed texts of known
registry, verification and cache sentinels found in the cause, never a raw
cause message. `Unwrap` returns only the class sentinel (for example
`resolve.ErrUntrusted`). A cancelled or expired caller context is returned as
such and is not `ErrContentUnavailable`; a registry's own timeout is an outage
(`ContentUnavailable`). Errors that are not resolution outcomes, such as a
closed cache, are returned unclassified so the reconcile fails and retries.

### Leases and pins

`Content` takes a short-lived `profile` lease (owner `content-read/<n>`),
reads and parses the files, and releases the lease before returning, on every
path including errors, cancellation and a panic. The result is a deep copy that
references no cache file, so callers hold nothing. Content that must stay
available across reconciles is pinned with `Pin(ctx, ref, holder, owner)` for
`bundle.HolderProfile` (a desired profile), `HolderApplied` (the last applied
contribution) or `HolderAssessment` (an active assessment). A pin is resolved
exactly as `Content` is and fails the same way; `Pin.Handle` is the resolved
handle with its receipt, and `Pin.Release` is idempotent. Pins live in memory
only: after a restart none exists and each owner re-establishes its pins from
its own state. A pin keeps bytes; it never authorizes later use, which every
`Content` call re-decides.

Each `Content` call re-verifies the cache entry twice (once in the resolver,
once to read the files), which costs a full layer scan. The controller's router
memoizes results guarded by `Resolver.Confirm` (see
[Memo](#memo-and-the-adoption-guard)).

### What is wired next

Done: `internal/bundle/sources.Watcher` implements `Revisions` from the central
ConfigMap and the referenced objects, the profile and binding reconcilers map
`ContentError` classes to detailed conditions and requeues and accept
`content.ValidateParameters`, and the controller builds the whole stack behind
a flag (see [Controller wiring](#controller-wiring)), and the runtime chart
enables it with live acceptance (see
[Helm installation and live acceptance](#helm-installation-and-live-acceptance)).

### What has and has not been verified

Unit tests in `internal/bundle/content` (`-race`, repeated, also with
`-cpu 1`) use the real Cosign organization-key fixtures of the official bundle,
the real resolver and cache on temporary directories and a fake registry that
can be taken down. They cover the equality with `LocalContent`, the targeting
resolver and renderer path (governance unchanged, revision from the manifest
digest, unchanged by a mirror and credential change and advanced by another
manifest digest), per-policy scopes, unknown policies, fixtures and unnamed
`policy`-role files never served, every compatibility rule and the revision,
incompatibility through the resolver and its recovery, parameters, offline
reuse after a restart, a wiped cache with the registry down and its recovery,
a rotated-out key and its restoration, a removed source, every error class
(planted credentials never appear), context cancellation before and during
resolution, zero leases after success, failure, cancellation, a panic and
concurrent calls, and pins for each holder. Crafted bundles (unsupported
scopes, fixtures, parameter schemas, a second digest) cannot carry real
signatures, so they are stored in a real cache and served by a stand-in
resolver that takes real leases. Ten safeguards were removed one at a time to
confirm a test fails for each. Nothing here runs in a cluster or in the
controller yet.

### Linking into the controller image

Linking this package into `cmd/konstapel` adds 44 Go modules to the shipped
image (sigstore-go, rekor, go-tuf, certificate-transparency-go, go-openapi,
oras-go, go-containerregistry, OpenTelemetry and others) and about 7.3 MiB
(+8.9%) to the unstripped linux/amd64 controller binary (85,478,075 to
93,120,541 bytes with the resolver, verifier, registry client, cache and
adapter reachable), measured with a throwaway command that was not committed.

`scripts/image/go-notices.py` would then fail: `go-licenses save` aborts with
an unknown license for `github.com/in-toto/in-toto-golang` v0.11.0,
`github.com/in-toto/attestation` v1.2.0 and
`github.com/cyberphone/json-canonicalization`
v0.0.0-20241213102144-19d51d7fe467. Each module ships a root `LICENSE`, but
that file is the Apache-2.0 standard notice ("Licensed under the Apache
License, Version 2.0 ...", 559 to 600 bytes), not the license text, and the
classifier does not identify the notice. It is a classification problem, not a
missing license. Every other added module is identified (Apache-2.0, MIT,
BSD-2-Clause or BSD-3-Clause).

This is now implemented in `scripts/image/go-notices.py` (see
[Container images](images.md#published-evidence) for how to review a version
bump): an override table keyed by exact module path and version gives the SPDX
identifier (`Apache-2.0`), the sha256 of the module's own `LICENSE` and the
reason. Exactly those modules are passed to `go-licenses` with `--ignore`; their
`LICENSE` is copied from the module archive after the archive's `h1:` hash is
recomputed and compared with `go.sum`, it must match the recorded sha256, the
full Apache-2.0 text (`scripts/image/licenses/Apache-2.0.txt`, itself pinned)
is shipped beside it as `LICENSE-Apache-2.0.txt`, and the bundled-sources
entry records the override (`licenseOverride`). A version bump or a changed
file fails the build until the entry is reviewed, a module that only shares an
override's path prefix fails too (`--ignore` matches prefixes), and the script
itself fails on any other module whose license `go-licenses report` lists as
unknown or not at all (`go-licenses report` exits 0 in that case).

The reviewed `LICENSE` hashes (each `h1:` matched `go.sum`):

| Module | Version | `LICENSE` sha256 |
| --- | --- | --- |
| `github.com/in-toto/in-toto-golang` | v0.11.0 | `b5c26c8a2ad6dd7cac6646e470a32ee42d23c36124caac4e66c989b6545b2a44` |
| `github.com/in-toto/attestation` | v1.2.0 | `b3a6ac899861c2c28a1abd5c7ea8733fefaed6938d730e099c42671386032aeb` |
| `github.com/cyberphone/json-canonicalization` | v0.0.0-20241213102144-19d51d7fe467 | `6821faaddedf2d78c95bb6d98b127e9e616097afd2f6bcc34389f000d13ab12d` |

With the controller wiring linked, the unstripped linux/amd64 `konstapel`
binary grew from 85,312,889 to 93,263,248 bytes (+7.6 MiB, +9.3%; 114 to 158
module dependencies), and the local `task image:build` image archive from
69,913,088 to 73,686,528 bytes (+3.6 MiB compressed, +5.4%). The local image
build and `task image:test` pass; the notices list the three modules as
`Apache-2.0` with both files, and the Syft SBOM concludes `Apache-2.0` for the
in-toto modules (it adds a `LicenseRef` for json-canonicalization from its own
scan, and declares `NOASSERTION` for all three, as for other modules it finds
no declared license for).

## Controller wiring

`konstapel controller` builds the bundle machinery only when
`--bundle-sources-configmap` is set. **It is off by default**: without the
flag no cache directory is created, no informer, watcher, trigger or pinner
runs, no Secret or ConfigMap is read and no extra RBAC is used, and the
vendored bundle is served by `LocalContent` exactly as before.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--bundle-sources-configmap` | empty (off) | Name of the [central sources ConfigMap](#central-source-configuration) in the controller namespace (`POD_NAMESPACE`). Setting it enables OCI bundle content. |
| `--bundle-cache-dir` | none; required when enabled | Absolute, writable directory for the [content cache](#safe-materialization-and-the-content-cache), owned by this process only. |
| `--bundle-cache-capacity` | `1Gi` (the cache default) | Cache capacity as a Kubernetes quantity; it must hold at least one maximal entry. |
| `--bundle-refresh-interval` | `30s` | How often referenced Secrets and ConfigMaps are re-read; at most `5m`. |

The namespace comes from `POD_NAMESPACE`, as for the other namespaced
features. Startup fails with a clear error when the feature is enabled without
a namespace or cache directory, with a relative directory, an invalid name,
capacity or interval, and when any of the other bundle flags is given without
`--bundle-sources-configmap`. It also fails when the cache cannot be opened:
an unwritable directory, or another process holding its `.lock`.

The controller's version is set at build time from `VERSION`
(`-ldflags -X main.version`, `scripts/build.sh`) and used for the
[compatibility check](#compatibility). A development build without it reports
`dev`, which is not SemVer: startup still succeeds and logs the problem, every
OCI bundle is then a `Config` content error, and the vendored bundle is
unaffected.

### Router

One `stack.Router` instance is `Options.Content` for every consumer: the
profile, binding and assessment reconcilers and the exception admission
webhooks.

- The vendored bundle name (`konstapel-vendored`) is always served by
  `LocalContent`, with or without the feature. Its digest is the sha256 of
  `content/SHA256SUMS`. That name is reserved for the image's own content: a
  source of that name in the ConfigMap is never consulted, so a profile naming
  the vendored bundle keeps working unchanged and its digest is never
  confused with an OCI manifest digest.
- Every other name is resolved by `OCIContent` (the OCI manifest digest) when
  the feature is enabled. When it is not, the result is a
  `*targeting.ContentError` of class `Config` ("no source is configured: OCI
  bundle sources are not enabled in this controller") that still
  `Is(ErrContentUnavailable)`: profiles report `ContentUnavailable` as before,
  now with the class in the message, and are not retried on a timer.

### Construction

When enabled, the controller builds, in this order: a
`kubeaccess.ClientReader` over the manager's **uncached** API reader restricted
to the controller namespace (objects are read by name with `get`); a
`kubeaccess.Provider` (refresh interval as its object cache bound) and the
registry client from `kubeaccess.NewClient`, with the provider as transport and
credential source; `verify.New` over the same reader; `resolve.NewAcceptances`;
`content.Compatibility{Controller: <version>}` with the default provider
allowlist; the `sources.Watcher` reading the ConfigMap from a dedicated cache
(`sources.ConfigMapCacheOptions`: that namespace, field selector
`metadata.name=<name>`) with `ConfigMapHandler` on its informer; then the cache
(`cache.Open`, with `OnRemove` dropping the removed digest's acceptances), the
resolver (`Revisions` = the Watcher, `Compatible` = the compatibility check)
and `OCIContent`. The cache is opened last, so a configuration error creates
nothing on disk. Both reconcilers get `ValidateParameters` (it is a no-op for
`LocalContent`, so it is set whether or not the feature is on).

### Runnables and leader election

| Runnable | Runs on | Why |
| --- | --- | --- |
| ConfigMap cache | every replica | the Watcher needs it everywhere (a cache built with per-object options does not declare this itself, so it is wrapped) |
| Watcher | every replica, after the ConfigMap cache synced | admission webhooks resolve content on every replica; until the first sync the configuration is "not loaded yet" and only OCI content is unavailable |
| Trigger | the leader | it feeds the profile controller (`EnqueueRequestForObject`) and the binding controller (the profile-to-bindings map) through `source.Channel`, besides their existing watches |
| Pinner | every replica | each replica has its own cache and serves webhooks, so it pins what it may serve |

If the ConfigMap cannot be listed (the RBAC is missing), the Watcher never
starts and OCI content stays a `Config` error; nothing else waits for it.

### Pins

The Pinner keeps cache leases for what cluster state needs, so that content is
not evicted while it is desired, applied or assessed. Each pass computes the
set from cluster objects and applies set semantics per holder and owner: it
acquires missing pins (`OCIContent.Pin`, which resolves under the current
acceptance) and releases stale ones.

| Holder | Owner | From |
| --- | --- | --- |
| `profile` | `profile/<name>` | every ComplianceProfile's `spec.bundle` |
| `applied` | `binding/<binding>` | the `bundle` and `bundle-digest` annotations of the engine policies Konstapel manages (read uncached by label). Binding status records only the last resolved profile digest, not what is applied, so the applied policies are the authority. An engine API that is not served means nothing is applied. |
| `assessment` | `run/<name>` | for every AssessmentRun that may still snapshot (no phase yet, `Pending`, `Collecting`, `Exporting`), its binding's profile `spec.bundle` |

The vendored bundle is never pinned (it is not in the cache). A holder whose
state cannot be read in a pass keeps its pins; a pin that fails (registry down,
no source) is retried on the next pass. Passes run at startup, on every
profile, binding and AssessmentRun event (which only kicks a coalescing
channel) and every minute, in the Pinner's own goroutine: reconciles never
wait for it. Leases live in memory, so a restarted process re-pins from cluster
state on its first pass; with retained evidence this works with the registry
down. Stopping releases every pin. A pin keeps bytes only; every use is still
decided by `Content`.

### Memo and the adoption guard

**Adoption guard (TOCTOU).** Between the binding reconciler's read of content
for rendering and its apply, trust can be revoked, the source removed or the
entry evicted. The router implements `Confirm(ref)`: `Resolver.Confirm`, an
in-memory check that an acceptance for exactly that name and digest exists
under the revisions current now (nil for the vendored bundle). The binding
reconciler adds it to `Delivery.Current`, the snapshot check `Delivery.Sync`
runs before its first write and again before any delete, so a withdrawn
acceptance stops the Sync as a stale snapshot: nothing new is written,
nothing is deleted, applied policies stay, and the binding resolves again
after a second. What remains is the time between that check and the API
write, the same window the snapshot check itself has.

**Memo.** The admission webhook and every reconcile call `Content`, which
costs two full layer scans (about a second for the official bundle). The
router memoizes successful OCI results per name and digest (at most 16
entries, deep-copied on store and on every hit) and serves an entry only if
`Confirm` passes at that moment; otherwise the entry is dropped and `Content`
runs. Every invalidation (a source, rule, trust or compatibility change, the
configuration becoming unavailable, an entry removed by eviction or found
corrupt through `OnRemove`) removes or re-keys the acceptance, so the memo
cannot serve content past an invalidation, and content for a digest is fully
determined by its verified bytes. One difference remains by design: a memo hit
does not re-hash the files on disk, so on-disk corruption is noticed on the
next miss rather than on that call; the memo only ever serves the copy read
from verified bytes. Failed and cancelled calls are never memoized or served.

### What has and has not been verified

Unit tests (`-race`, repeated, also with `-cpu 1`, no sleeps for ordering) in
`internal/bundle/stack`, `internal/controller` and `cmd/konstapel` cover the
flags and their combinations, options validation, construction failures
(nothing on disk for a disabled or invalid configuration, a held lock, an
unwritable directory), a development version, the router (vendored content and
errors identical to `LocalContent`, OCI routing, the disabled `Config` error,
the memo and its bound, deep copies, cancellation), the `OnRemove` wiring, the
wiring added to the manager (runnables, leader semantics, the dedicated
ConfigMap cache options, the Trigger feeding both channels, the Watcher waiting
for its cache, parameter validators), the binding's adoption guard, the Pinner
(set semantics, unknown holders, retries, restart, events, release on stop),
pins against a real cache under capacity pressure, and the cluster-state pin
set. End-to-end tests run the real stack (the Watcher over a fake API server,
the real verifier and cache, the Cosign-signed fixture bundle behind a fake
registry) under the real profile and binding reconcilers: an OCI profile
resolves and renders, trust revocation keeps the applied policy and reports
`ContentUnavailable`, recovery creates no duplicate, a revocation between the
render and the write is refused, and pins survive a restart with the registry
down. The cluster, the chart, the real registry client from the controller and
the field-selected watch against a real API server are covered by
[live acceptance](#helm-installation-and-live-acceptance).

## Central configuration and watches

[`internal/bundle/sources`](../internal/bundle/sources) is the run-time holder of
the [central source configuration](#central-source-configuration). Its
`Watcher` implements the resolver's `Revisions` and keeps them current; the
profile and binding reconcilers report the outcome. It is built from injected
readers; the controller builds it when bundle sources are enabled (see
[Controller wiring](#controller-wiring)).

### Atomic revisions

Each `Sync` reads the sources ConfigMap and parses it with
`bundle.ParseConfigMapData` as one revision. `State.Revision` increases by one
whenever what is served changes: availability, the parsed document, or the
reason it is unavailable. An identical re-read (an informer resync) changes
nothing.

The configuration is **unavailable as a whole** before the first `Sync`, when
the ConfigMap is missing or deleted, when `sources.yaml` is missing, when any
other `data` key or any `binaryData` is present, and when the document is
invalid in any way (an unsupported `version`, an invalid entry, inline key
material). While it is unavailable, `Source` fails with
`sources.ErrUnavailable` for every name and `Trust` fails too: the previous
revision is **never** served in its place. `State.Reason` explains it
(bounded to 512 bytes; the ConfigMap holds no secrets, and a document with key
material or credentials is rejected with a fixed message) and
`State.LastGoodRevision` names the last good revision, for diagnostics only.
Fixing the ConfigMap makes the next `Sync` serve the new revision.

A failure to *read* the ConfigMap other than its absence (the informer cache
not synced, a cancelled context) is not a configuration change: that `Sync`
fails, changes nothing and is retried at the next trigger. The informer
reports a deletion as a deletion.

### Trust revision

`Trust(src)` is `<publisher type>:` followed by
`verify.Verifier.TrustRevision`, computed by the last `Sync` from the objects
the publisher rule references, read and parsed exactly as verification reads
them:

- keyless: the `sha256:` of the trusted root's bytes; without a `trustRoot`
  reference, the pinned digest of the embedded public-good root;
- public key: the key's fingerprint (`sha256:` of its DER
  SubjectPublicKeyInfo), the same value a receipt records as
  `TrustRevision`. A re-encoding of the same key (whitespace, line breaks)
  keeps the token; any other key changes it.

Credentials, CAs and the repository never contribute. A missing object or
key, an unreadable object (including a transient read error), malformed or
oversized material, an unsupported key type or a key whose fingerprint is not
the rule's makes `Trust` fail (`sources.ErrTrustUnavailable`), so resolution of
that source is unavailable (`Config`); no earlier token is served. `Trust` also
fails for a source that is not the one configured now under its name (its
`verify.RuleRevision` differs). `Compatibility` is the injected
`content.Compatibility.Revision`.

### What changes invalidate

`Sync` builds the complete new state, publishes it (`Source`, `Trust` and
`Compatibility` answer from it at once) and only then invalidates, which is
the resolver's protocol: a verification that read the old revisions is refused
(`ErrStale`) at record or adoption time, and one that begins after
publication reads the new ones.

| Change | Acceptances | Transport (`Provider.Invalidate`) | Profiles requeued |
| --- | --- | --- | --- |
| Configuration becomes unavailable, or available again | all (`InvalidateAll`) | every previously referenced object | every bundle name in the old and the new revision |
| Source added or removed | that source (`InvalidateSource`) | its objects | that name |
| Publisher rule changed (issuer, identity, key or root reference, fingerprint, provenance) | that source | changed references | that name |
| Referenced key or root content changed, removed or unreadable (trust revision changed or unavailable) | that source | that object | every name referencing it |
| Same key re-encoded | none | that object | names referencing it |
| `repository` only (a mirror) | none | none | that name |
| Credential or CA reference changed | none | old and new objects | that name |
| Credential Secret rotated or deleted, CA changed or deleted | none | that object | every name referencing it |
| Anything else (unrelated objects, an unchanged re-read) | none | none | none |

A rotated credential resets the registry tokens through the provider and
keeps every acceptance: verified content is still reused offline. A deleted
credential makes the next retrieval fail with `ErrCredentials`, but content
whose acceptance or retained evidence still satisfies current trust is served
without the registry. A CA change rebuilds that source's transport.

### Events

The `Watcher` records the affected bundle names. Its `Trigger` (a
leader-elected runnable) lists the `ComplianceProfile`s whose
`spec.bundle.name` is affected (`sources.ProfilesFor`) and sends one
`GenericEvent` per profile to each output channel: one for the profile
controller (`handler.EnqueueRequestForObject`) and one for the binding
controller (the existing profile-to-bindings map function). Unrelated
objects and profiles of other bundles produce nothing. Names affected while no
trigger runs (a non-leader replica) are kept, at most one entry per bundle
name, and sent when it starts. The `Watcher` itself runs on every replica,
because admission webhooks resolve content on every replica.

`Predicate()` admits the sources ConfigMap and, in the controller namespace
only, exactly the Secrets and ConfigMaps (by kind) the current configuration
references; it consults the current configuration on every event.
`ConfigMapHandler()` is the informer handler for the sources ConfigMap: it only
asks for a `Sync`, so the informer is never blocked.

### RBAC and informers

Informers need `list` and `watch`, and RBAC `resourceNames` restricts those only
for requests that carry a `metadata.name` field selector. So:

- **The sources ConfigMap** is the only watched object, through a dedicated
  cache that holds just that object (`sources.ConfigMapCacheOptions(namespace,
  name)`: ConfigMaps of the controller namespace with the field selector
  `metadata.name=<name>`). Its `list` and `watch` carry the selector, so they
  can be granted by name. Changes are noticed at once.
- **Referenced Secrets and ConfigMaps** (credentials, CAs, public keys, trusted
  roots) are never listed or watched. `Sync` reads each by name with `get`,
  through an uncached reader (`kubeaccess.NewClientReader` over the manager's
  API reader), at most once per `Sync`. `Sync` runs on every ConfigMap event and
  every `Options.Interval`: `kubeaccess.DefaultCacheFor` (30 s) by default, at
  most `kubeaccess.MaxCacheFor` (5 min). **A rotation, revocation or removal
  of a referenced object is therefore noticed within one interval**, and the
  transport provider's own object cache uses the same bound. Until then a
  previously accepted digest can still be served under the old key; any new
  verification reads the objects directly.

Per-object field-selected watchers for referenced objects would notice changes
sooner, but the referenced set changes with the configuration, controller-runtime
cannot stop a watch it started, and the chart's `resourceNames` must be static
anyway; polling by name keeps the grant to `get` and the design to one cache.

The grants the chart adds (`konstapel-controller-bundles`, rendered only when
`bundles.sourcesConfigMap` is set), in the controller namespace only, in a
namespaced `Role`; no `ClusterRole` and no namespace-wide Secret access:

```yaml
- apiGroups: [""]
  resources: [configmaps]
  verbs: [get, list, watch]
  resourceNames: [<sources ConfigMap name, default konstapel-bundle-sources>]
- apiGroups: [""]
  resources: [configmaps]
  verbs: [get]
  resourceNames: [<every ConfigMap-held ca, publicKey and trustRoot>]
- apiGroups: [""]
  resources: [secrets]
  verbs: [get]
  resourceNames: [<every credentialSecret and Secret-held ca, publicKey and trustRoot>]
```

Because `resourceNames` are static, the referenced names come from chart
values (`bundles.referencedSecrets`, `bundles.referencedConfigMaps`); an empty
list renders no rule rather than an unrestricted one. RBAC is additive: the
generated `konstapel-controller` Role already grants `get` on every Secret and
ConfigMap in the controller namespace for other features (S3 credentials, CA
trust, snapshots and inventories whose names come from CR specs or are derived
at runtime; see
[Controller ServiceAccount boundary](charts.md#controller-serviceaccount-boundary)),
so today the bundle Role's effective new privilege is the named `list`/`watch`
of the sources ConfigMap, and a reference missing from the values is still readable rather than
`Forbidden`. If those broader rules are narrowed, a missing reference becomes
`Forbidden`, which makes its source unavailable (never a fallback).

Against a real API server (`TestLiveHelmBundles`), acting as the controller's
ServiceAccount: the field-selected `watch` of the sources ConfigMap is allowed
with the chart's RoleBinding and forbidden once that RoleBinding is deleted
(no other grant allows it); an unselected ConfigMap watch, a field-selected
watch of another ConfigMap or of a Secret, a Secret `list`, a ConfigMap
`update` and the same watch in another namespace are all forbidden. The same
step asserts the controller's effective Secret/ConfigMap boundary: a Secret no
bundle value lists is readable (the generated Role), while an unselected
ConfigMap `list`, Secret `watch`, writes and deletes of either kind, and reads
in other namespaces are forbidden.

### Conditions and requeue

A profile whose content is unavailable keeps the existing boundary:
`Resolved=False` with reason `ContentUnavailable` and `observedGeneration` set.
For a classified error the message is
`bundle content unavailable (<Class>): <detail>`, where the detail is the
`ContentError`'s bounded, credential-free detail; the whole message is bounded
(1024 bytes). Recovery sets `Resolved=True` with reason `Resolved` again.
`LocalContent` errors are reported exactly as before. Bindings report the same
message on their `Resolved` condition, including when content resolved for the
snapshot but not when it was read for rendering.

| Class | Retried after |
| --- | --- |
| `Stale` | 1 s |
| `ContentUnavailable`, `ProofUnavailable`, `Capacity`, `Unresolved` | 1 min |
| `Untrusted` | 5 min (fresh evidence from the registry can fix it) |
| `Config`, `Incompatible`, `DigestMismatch`, `Malformed`, unclassified | not on a timer |

Configuration, trust and object changes re-trigger the affected profiles and
bindings through events, and profile edits through their generation, so no
class loops; a binding uses the shorter of this and its own engine requeue.

On failed update or trust revocation a binding retains the policies it
applied, reports `EngineReady=False/StaleRevision` ("last applied policies
kept"), renders and applies nothing from the rejected content (it does not
reapply a policy that disappears meanwhile), and exception eligibility is
`Forbidden` while it is unresolved. Recovery delivers the current revision
through the normal create-before-retire path without duplicates. If the
binding's applied policies cannot be listed while content is unavailable, the
reconcile fails and retries rather than holding nothing (holding nothing would
let delivery remove applied policies).

With `ValidateParameters` set (`content.ValidateParameters`), parameters of
content that declares a parameter contract are rejected with
`InvalidConfiguration` and a precise message on the profile and the binding
(an unknown property, a wrong type, parameters for a policy without a schema,
or valid parameters that the renderer does not render yet). Content without a
contract (`LocalContent`) keeps the resolver's generic rejection on bindings
and no parameter check on profiles.

### What the manager wiring adds

Done; see [Controller wiring](#controller-wiring). The runtime chart adds the
RBAC above and the cache volume; see
[Helm installation and live acceptance](#helm-installation-and-live-acceptance).

### What has and has not been verified

Unit tests (`-race`, repeated, also with `-cpu 1`, no sleeps for ordering)
cover atomic configuration (invalid update after a good one, deletion, extra,
missing and `binaryData` keys, version 2, recovery, revision numbering), the
trust token (key and root bytes, re-encoding, credential/CA/mirror
independence, every unusable-material case), the full invalidation matrix
including transport invalidations and acceptance survival, the
publish-before-invalidate ordering at a deterministic hook, the real resolver,
cache and verifier with the signed fixture bundle (a rule change during a
retrieval is `ErrStale` and records nothing; credential rotation and deletion
and a mirror keep acceptance and offline reuse; trust revocation is
`Untrusted`; a missing key is `Config`; recovery), predicates and the informer
handler, the trigger, per-class conditions and requeues with planted secrets,
and the binding scenarios above. Thirteen safeguards were removed one at a
time to confirm a test fails for each. Not verified: anything in a cluster,
the field-selected watch against a real API server, and the RBAC above.

## Helm installation and live acceptance

The runtime chart enables OCI bundle content with `bundles.sourcesConfigMap`
(off by default, which renders exactly the chart without it). It then adds the
four `--bundle-*` flags, a per-pod `emptyDir` cache of
`bundles.cache.sizeLimit` at `/var/lib/konstapel/bundles`, `POD_NAMESPACE`
from the downward API (already set for other features), and the
`konstapel-controller-bundles` Role and RoleBinding described in
[RBAC and informers](#rbac-and-informers). The chart never renders the sources
ConfigMap or the objects it references: a platform administrator creates them
([Private registry setup](#private-registry-setup)) and lists the referenced
names in the values ([Helm charts](charts.md#oci-policy-bundles)).

**Cache directory modes.** A pod `fsGroup` makes the `emptyDir` a setgid
directory, and Linux copies that bit to every directory created beneath it.
The cache sets each directory's mode explicitly after creating it, so its own
check that no stored file or directory carries a setuid, setgid or sticky bit
still holds there (`TestPutUnderSetgidRoot`). Live acceptance found this:
before the fix, every OCI bundle in the chart failed to store.

**Live acceptance.** `TestLiveHelmBundles` (the `charts` acceptance group, so
it also runs in release acceptance on the frozen archives) installs the chart
with `docs/examples/charts/oci-bundles.yaml` on two replicas of the image
built from the checkout. A disposable distribution registry
(`KONSTAPEL_REGISTRY_IMAGE`: TLS from a throwaway CA, htpasswd users, no
referrers API, so the tag-schema fallback) on the kind network serves the
checked-in Cosign organization-key fixture (the official bundle's content,
`internal/bundle/verify/testdata/provenance`) under a primary and a mirror
repository; the test pushes it with the retrieval adapter's session and the
mirror tool. It verifies, in order:

1. RBAC against the API server as the controller's ServiceAccount (see
   [RBAC and informers](#rbac-and-informers)), including that the
   field-selected watch fails without the chart's RoleBinding.
2. Each replica's Watcher loads the configuration through that watch (its
   logged revision), and both observe a later change.
3. An Audit binding over a profile pinning the fixture digest is delivered
   from the verified bundle (policy annotated with that digest).
4. A mirror (repository change) is seen by both replicas and changes nothing
   applied: same policy UID, same binding revision.
5. Invalid configuration (`version: 2`) and a deleted ConfigMap report
   `ContentUnavailable (Config)` on the profile, the binding keeps its policy
   (`EngineReady=False/StaleRevision`), and both recover with the same
   revision.
6. Trust revocation (the key Secret and rule moved to another key) reports
   `ContentUnavailable (Untrusted)`; the applied policy stays; a new binding of
   the same profile stays unresolved with no policies; after restoring trust
   both resolve.
7. Follower pins: with the registry paused, the leader is removed (scaled
   away, so no fresh pod races for the Lease) and the former follower, which
   reconciled nothing and serves no webhook, delivers a new binding from the
   content its own Pinner fetched and verified.
8. Controller upgrade (a changed value rolls both pods) after rotating the
   credential Secret to another registry user: the new pods fetch with the
   new credential (seen in the registry log) and the applied revision is
   unchanged.
9. `helm rollback` during a registry outage: the replaced pods cannot fetch,
   the profile reports `ContentUnavailable (ContentUnavailable)`, the binding
   keeps its policy, and after the registry returns the same revision
   resolves again.

Hand-broken checks: a chart Role without `watch` fails step 1, an image whose
Pinner runs only on the leader fails step 7, and the image without the cache
mode fix fails step 3.

**Not covered live:** exception admission webhooks (the chart serves none,
so no admission path on a non-leader exists to test); a profile digest
upgrade to a different, semantically changed signed bundle (only one signed
subject exists as a fixture; the revision advance by another manifest digest
is unit-tested in `internal/bundle/content`); keyless signatures in the
cluster (the fixture is public-key signed); bearer-token registries; and
assessment export, which still reads the image's vendored `content/` tree
(`AssessmentRunReconciler` passes `Runtime.ContentRoot` to
`collector.Export`), so OSCAL for a run of an OCI-bundle binding is built from
vendored catalog and mapping files rather than the bundle's own.

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
Runs for the same bundle are serialized (one concurrency group per bundle) and
never cancelled. The workflow has four jobs:

1. **package** (`contents: read`) validates the request with
   `cmd/bundlerelease verify`: the name is a DNS label with a
   `bundles/<name>/definition.json` at that commit whose `name` matches the
   directory, the commit is on reviewed `main` history, the version is valid,
   and any fetched tag for that version marks the same commit. It packages
   exactly that commit with `scripts/bundles/package.sh` from a detached
   worktree, then **freezes** it (`bundlerelease freeze`, below): the bundle's
   declarative policy fixtures run against the unpacked frozen layer and a
   publication record bound to those bytes is written next to the layout. It
   re-verifies the layout, `package.json` and the record against the request
   and uploads them as the workflow artifact `bundle-<name>-<version>`.
2. **tag** (`contents: write`, the only job that may write to the repository)
   re-validates and runs `cmd/bundlerelease tag`: it pushes the tag when absent
   (never forced) or verifies that the existing tag marks exactly that commit.
   A tag at any other commit, or a ref blocking the `bundle/<name>/` namespace,
   fails the run.
3. **publish** (`contents: read`, `packages: write`, `id-token: write`; the
   only job that may write to the registry or request an OIDC token) runs after
   the tag job, so a registry version is only ever published for a version
   whose Git tag marks the source commit. It downloads the artifact,
   re-verifies it, requires the release tag at the source commit, and runs
   `cmd/bundlerelease publish -signing keyless`: write-once publication to
   `ghcr.io/backend-bunny/bundles/<name>:<version>`, an anonymous read-back
   (below), then [signing](#signing-and-provenance-of-the-published-digest) of
   exactly the published digest for the proofs still missing. It writes a
   bounded record of the run (`publication.json`: outcome, digests, pushed and
   existing pieces, read-back, missing and added proofs, and the workflow
   repository, ref, commit, run and attempt, recorded separately from the
   source commit) and the publication record in effect (`record.json`). A
   separate step then runs `cmd/bundlerelease verify-release` on the published
   digest, with no credential in its environment; only it reports
   `status=complete`. Both write to the step summary and to the artifact
   `bundle-<name>-<version>-publication-<attempt>` (`verification.json` holds
   the receipt).

   Signing happens in this job because proofs are registry writes too: a
   separate signing job would also need `packages: write` and would leave an
   unsigned publication reported between jobs. GitHub exposes the OIDC request
   variables to every step of a job with `id-token: write`; besides the tool,
   the only steps in this job are the pinned first-party checkout,
   upload/download-artifact actions and the repository's own setup action.
4. **release-notes** (`contents: write`, no packages, no OIDC) runs only after
   publish succeeded, that is after `verify-release` reported the release
   complete. It downloads the frozen package and the verification record of the
   same run attempt, renders the notes and creates or updates the GitHub release
   for the bundle tag ([below](#release-notes-and-the-github-release)).

The same checks run locally against any full-history checkout:

```sh
devbox run -- go run ./cmd/bundlerelease verify -name <name> -commit <sha>
```

`cmd/bundlerelease` is a build tool; it is not part of the controller image,
and the packages it uses for publication, signing and release verification
(`internal/bundle/publish`, `internal/bundle/sign`, `internal/bundle/release`)
are not linked into the shipped binaries; the controller links only the
consumer side (`internal/bundle/registry`, `internal/bundle/verify` and the
packages in [Controller wiring](#controller-wiring)). `internal/bundle/sign` is the only code that executes Cosign.

### Signing and provenance of the published digest

After the anonymous read-back, `publish` hands the subject (repository,
digest, size and the publication record in effect) to `publish.Completer`
with the proof kinds the consumer adapter reported missing:

1. **Rule first.** The publisher rule for the bundle is read from
   `bundles/official-sources.yaml` in the workflow's main checkout, never from
   the packaged source or the artifact. Signing is refused unless the rule
   names the repository being published, allows the record's source
   repository, and, for keyless, its issuer is GitHub's and its identity is
   both this run's certificate identity (`$GITHUB_SERVER_URL/$GITHUB_WORKFLOW_REF`)
   and its provenance builder (`ErrSigningRule`).
2. **The subject is re-read.** The completer fetches the digest anonymously
   through the consumer's adapter and requires the manifest and layer to be
   exactly the bytes the publication record is bound to; another digest, other
   bytes or an unbound record is `ErrProofSubject`, and nothing is signed.
3. **Only missing kinds.** Kinds the adapter now finds are skipped, so a rerun
   never makes a second signature or attestation.
4. **Provenance** follows [Bundle provenance v1](#bundle-provenance-v1) and is
   built from the record alone (`publish.BuildProvenance`): bundle name and
   version, source repository and commit, the definition digest read from Git
   at the source commit, the content digest, the fixtures `freeze` ran as
   `test` materials, and the record's tools plus the Cosign version as `tool`
   materials. The workflow repository, path, ref and commit (`GITHUB_SHA`, the
   revision that runs, which a retry may make newer than the source commit) go
   to `internalParameters.workflow` and the run to `runDetails.metadata`;
   `runDetails.builder.id` is the rule's builder.
5. **Signature, then attestation, by digest.** `cosign sign` and `cosign attest
   --type slsaprovenance1` run on `<repository>@sha256:<digest>`, never a tag
   (see [Signing, trust roots and rotation](#signing-trust-roots-and-rotation)
   for the exact invocations). Cosign is executed without a shell; it inherits
   only an allowlist of environment variables (the OIDC request variables for
   keyless, `COSIGN_PASSWORD` for key mode, proxy and certificate settings),
   gets the registry token only through a private temporary Docker config
   removed after each call, and its output is bounded and redacted.

`publish` then reads back again and reports the added proofs, but never
`complete`: `bundlerelease verify-release` does.

### Verifying a release

`verify-release` verifies a published digest exactly as a consumer of the
official source would, so a maintainer can run the same check by hand against
any published digest:

```sh
devbox run -- go run ./cmd/bundlerelease verify-release -name <name> -digest sha256:<hex>
# optionally: -record publication-record.json -out verification.json
```

It selects the rule for `<name>` from `bundles/official-sources.yaml` (or
`-sources`; `-public-key-file` and `-trust-root-file` supply what a non-official
rule references), retrieves the digest **anonymously** with
`registry.Client.Fetch` (a source requiring a credential is refused), and runs
`Verifier.Accept`: the signature and provenance under that one rule with the
embedded Sigstore public-good root, the layer against the manifest, the
payload against its inventory, `CheckProvenance` against the unpacked
descriptor, then `bundle.ValidateContent`. With `-record` the provenance must
also attest exactly that record's source, definition, content and tests
(`ErrReleaseRecord`). It prints the digests, signer, signing time, trusted root
and its revision, rule revision, source and workflow commits, builder and proof
digests, and `status=complete`; any failure prints `status=incomplete:
verification failed` and fails.

### Freezing: tests and the publication record

`bundlerelease freeze` (`publish.Freeze`) verifies the layout end to end
(`bundle.VerifyLayout`: blob digests and sizes, manifest shape, descriptor and
every inventoried file; packaging already ran `ValidateContent`), unpacks the
**frozen layer** into a temporary directory, and runs `kyverno test
--require-tests` (the pinned Devbox CLI) in every payload directory that holds
a `kyverno-test.yaml` with role `test`. Each run must report at least one
passed and zero failed tests; a bundle without such fixtures is refused. Only
then does it write `publication-record.json`, which is never replaced:

```json
{"format":"konstapel.policy.bundle.publication/v1","name":"konstapel-privileged-containers","version":"0.1.0",
 "source":{"repository":"https://github.com/backend-bunny/Konstapel","commit":"<40 hex>"},
 "definition":{"path":"bundles/konstapel-privileged-containers/definition.json","sha256":"<hex>"},
 "manifestDigest":"sha256:…","layerDigest":"sha256:…","contentDigest":"sha256:…",
 "tools":[{"name":"go","version":"go1.27.3"},{"name":"kyverno","version":"v1.19.2"}],
 "tests":{"runner":"kyverno test --require-tests","result":"passed",
          "files":[{"path":"content/upstream/kyverno/disallow-privileged-containers/.kyverno-test/kyverno-test.yaml","sha256":"<hex>"}]}}
```

The record holds only frozen facts (no run identifiers), in one canonical
serialization, so identical frozen inputs always give byte-identical records.
`contentDigest` is `Descriptor.ContentDigest()`, the provenance contract's
`bundle-content` material; the definition digest is read from Git at the source
commit; the test files are the provenance `test` materials. Loading a frozen
bundle (`publish.Load`) refuses a missing, non-canonical or unbound record: the
name, version, source, all three digests and each test file (present, role
`test`, same sha256) must match the verified bytes.

The Chainsaw tests in the payload need a cluster and are **not** run here. The
fixtures establish that the packaged policy evaluates its declarative cases;
they are not live acceptance evidence. An official compatibility claim also
needs the owning content's live acceptance evidence for these exact source and
variant inputs, which this workflow does not produce or claim.

### Write-once publication

`publish.Publish` pushes with ORAS Go through the same transport, TLS,
credential scope, redirect rules and redaction as the consumer's adapter
(`registry.Client.Open`). The writer's source always references a credential,
so it never writes anonymously; the token reaches the tool only through the
publish step's environment (`BUNDLE_REGISTRY_USERNAME`,
`BUNDLE_REGISTRY_PASSWORD`), is removed from the environment once read, never
appears on a command line, and is redacted from every error, including one a
registry echoes back. Within a process, publishers of one repository and tag
are serialized; across runs, the workflow's concurrency group serializes them.

Order, checked by the tests against every request sent:

1. the empty config blob and the layer blob, each only if `HEAD` does not find
   it;
2. the bundle manifest **by digest**, only if absent;
3. the publication record as an OCI referrer of the manifest (artifact type
   `application/vnd.konstapel.policy.bundle.publication.v1+json`, empty
   config, one layer holding the record, `subject` = the manifest), unless a
   valid record bound to the subject is already listed. On registries without
   the referrers API (such as `ghcr.io`) the publisher also maintains the
   `sha256-<hex>` referrers tag schema index, adding its entry; a superseded
   index is kept, never deleted;
4. **last**, the version tag, after re-reading it immediately before the push.

A tag therefore never names a subject that lacks a blob or its record. The
version tag means "this version is these bytes" and is written once; it does
not mean "complete". Then the tag is read again with the writer's credential
and must name the frozen digest, and the publication is read back
**anonymously**: the tag, then `registry.Client.Fetch` by digest (the consumer
adapter), whose manifest and layer must equal the frozen bytes and whose
referrer listing must include the record. A registry that has not yet made a
push visible is retried with backoff (six attempts by default); other bytes,
an integrity failure or a refused anonymous read fail at once. The result lists
the required proofs (`signature`, `provenance`) that the consumer adapter did
not find; the [signer](#signing-and-provenance-of-the-published-digest) adds
exactly those and the subject is read back again. `publish.Publish` sets
`Complete` when read-back verified and no proof is missing, but the command
reports that only as `proofs attached; unverified until verify-release passes`:
a release is **complete** only when `verify-release` accepts it. Missing proofs
without `-signing` fail the command (`-defer-proofs`, for publishers who sign
separately, makes it succeed as `incomplete`). A read-back failure fails the
step.

Nothing is ever deleted, re-uploaded or replaced: existing blobs and manifests
are left as they are, and the only tag ever moved is the referrers tag schema
index, which the OCI distribution specification defines as a client-maintained
listing (entries are only added). The one exception to "never push an existing
manifest again" is a record manifest that exists but is missing from that
listing (an index update that failed after the manifest was stored): it is
pushed again, byte-identical under the same digest, so the listing includes it
(`relisted`).

**Conflicts.** A version tag that names other bytes is compared before anything
is written. Different content (another descriptor: version, source commit,
policies or file inventory) is `ErrConflict`: nothing is written and the tag is
never moved or deleted. A tag created by another publisher between the first
check and the push is caught by the re-check (identical bytes are accepted,
others are `ErrConflict` without a write). A tag moved by someone else right
after this run pushed it is reported as `ErrConflict` and is not moved back:
resolve that by hand. OCI registries offer no conditional tag update, so this
last window can only be detected, not prevented; the per-bundle concurrency
group and the `packages: write` permission held only by this job keep other
writers out.

**Errors.** `ErrConflict` (other bytes under the version), `ErrIncompleteRemote`
(a registry request or the proof step failed; rerun with the same frozen
inputs; wraps the registry's class, a timeout or a cancellation),
`ErrReadBack` (the remote does not read back as frozen, or not anonymously; not
complete) and `ErrFrozenInputs` (the frozen layout or record is invalid or
unbound, or recovery cannot establish the original inputs). The outcome of a
successful run is `created` (this run wrote the version tag), `completed` (the
tag already named the subject and only missing pieces or proofs were added) or
`already-published` (nothing was written).

### Retries and partial publication

Where the frozen inputs live: the frozen bytes are content-addressed, so once a
subject is in the registry the registry itself is their durable copy, and the
publication record referrer keeps the facts (source, definition, content
digest, tools, tests) that a later run needs to attest or recover exactly those
bytes. Until the version tag exists, nothing is published; the frozen inputs
are the run's artifact (14 days) and, after that, the reviewed source commit.

- **Re-run failed jobs** of the same run reuses that run's artifact, so it
  pushes exactly the same bytes, and runs the original workflow revision.
- **A new dispatch** for the same version packages the same commit again.
  Packaging is deterministic, so with the same tools the digest is the same and
  the run continues where the last one stopped. If a toolchain change produced
  different bytes for the same content (identical descriptor and inventory) and
  the tag already names the original subject, the original bytes and their
  record are adopted from the registry (`recovered`) and nothing local is
  pushed. Without a bound record, the original inputs cannot be established and
  the run fails with `ErrFrozenInputs` rather than replacing anything.

| Found in the registry | A run |
| --- | --- |
| nothing | pushes everything, tag last: `created` |
| some blobs (an upload failed or the connection dropped) | pushes only the missing blobs, then the manifest, record and tag: `created` |
| blobs and manifest, no record or tag | pushes the record and the tag: `created` |
| record manifest stored but not in the tag schema listing | pushes it again, identical, to repair the listing, then the tag |
| tag at the frozen digest, record missing | adds the record: `completed` |
| tag at the frozen digest, everything present, proofs missing | writes nothing to the subject; signs and attests only the missing kinds (a signature from a run that failed before attesting is kept, and only the attestation is added) |
| everything present, both proofs present | writes and signs nothing; `verify-release` decides completeness |
| tag at other bytes with other content | `ErrConflict`, nothing written |
| tag at the same release repackaged by other tools, with its record | adopts the remote bytes: `already-published`, `recovered` |
| the same without a record bound to it | `ErrFrozenInputs`, nothing written |
| anonymous read-back refused or mismatching | `ErrReadBack`; the run fails and is not complete |

An untagged manifest left by an earlier failed run of different bytes (only
possible with a toolchain change after the artifact expired) was never
published; it stays in the registry untagged and is not deleted.

### One-time owner steps on `ghcr.io`

The workflow can push a package with its job token, but it cannot change a
package's visibility or access, and there is no way to create the package
before its first push. The first push to `ghcr.io/backend-bunny/bundles/<name>`
creates the package with the organization's default visibility, which is
private; a private package refuses the anonymous read-back, so **the first
release run of every new bundle name fails at read-back by design** and is not
reported complete. An organization owner (or package admin) then, once per
bundle name:

1. Checks that the organization allows public packages (Organization settings
   → Packages → package creation: public).
2. Opens the package (organization → Packages → `bundles/<name>`) → Package
   settings:
   - under **Manage Actions access**, makes sure `backend-bunny/Konstapel` is
     listed with the **Write** role (needed for later runs to push new
     versions or proofs), and connects the repository if it is not linked;
   - under **Danger Zone → Change visibility**, makes the package **Public**.
     GitHub does not let a public package become private again.
3. Re-runs the failed `publish` job (Re-run failed jobs). The subject is
   already there, so the run writes nothing to it; the anonymous read-back now
   passes, the job signs and attests the digest (the first run stopped before
   signing) and `verify-release` reports the release complete.

Before the first release of a new bundle name, a maintainer also adds its rule
to `bundles/official-sources.yaml` in a reviewed pull request (a test requires
an entry for every `bundles/<name>/`); without it the publish job refuses to
sign. No other owner step is needed for signing: `id-token: write` is granted
by the workflow itself, keyless signing needs no secret, and the proofs are
pushed with the same job token and package Write role as the bundle.

Never delete a package version or tag to "fix" a run: versions are write-once
and consumers pin digests.

### Release notes and the GitHub release

`bundlerelease release-notes` renders the notes of a release and, with
`-announce`, makes the GitHub release for its tag match them. The notes are a
pure function of two inputs of the same run: the frozen package (descriptor and
publication record) and the verification record `verify-release` wrote
(`verification.json`). They contain the bundle name and version; the registry,
the manifest digest and the exact `spec.bundle` pin; the source repository and
commit and, separately, the release workflow's revision; the content and
archive digests; the builder, signer, signing time and trust root; the declared
compatibility (provider contract, minimum Konstapel, OSCAL versions, workload
kinds, operating systems) with the statement that this is not a claim about a
particular cluster; the policy inventory with rule and check IDs; the fixtures
that passed against the frozen bytes with their digests; the license and notice
files; the build tools; and copyable verification commands for the exact digest:

```sh
cosign verify "$ref" --certificate-identity '<workflow identity>' --certificate-oidc-issuer '<issuer>'
cosign verify-attestation "$ref" --type slsaprovenance1 --certificate-identity '<workflow identity>' --certificate-oidc-issuer '<issuer>'
```

The two Cosign commands were run with the pinned Cosign v3.1.3 against the real
signed `ghcr.io/backend-bunny/konstapel` image under its workflow identity
(they pass; a different identity fails). Cosign checks who signed, not what the
provenance says, so the notes also give the `verify-release` command, which
checks the attested builder, source, name, version and materials as well.

- **Not announced unless complete.** Rendering refuses a verification whose
  status is not `complete` (`ErrNotComplete`), a missing record, and any
  disagreement between the receipt, the publication record and the frozen
  descriptor on digest, name, version, content digest, source commit or
  repository (`ErrNotesInput`), a public-key signer (`ErrNotesUnsupported`: the
  notes describe keyless official releases, organizations publish by hand), and
  values that would not survive being pasted into a shell command. The workflow
  job also runs only after publish succeeded.
- **Idempotent.** The output contains no clock: re-verifying later (a new
  verification time) renders the same bytes. `EnsureRelease` creates the release
  when absent, updates it only when its title, notes or pre-release flag differ,
  and does nothing when they match, so a retry or a re-run writes nothing. A
  draft release is refused, never edited or published.
- **Never the latest release.** Creation uses `--verify-tag` (the tag must
  already exist; the release never creates it) and `--latest=false`, so a bundle
  release cannot take the "latest" marker from the application's releases.
  Versions with a pre-release part are marked as pre-releases.
- **Credentials.** The token reaches only the announce step, through
  `GH_TOKEN`, and the tool drops everything else from the GitHub CLI's
  environment. The notes travel in a private temporary file, never on the
  command line, and errors never include the token.
- The notes are also appended to the run's step summary.

### First official release: `konstapel-privileged-containers` 0.1.0

Released on 2026-11-12 from commit `863f4853151bb342a46eefa57c31cb2d46e17cff`
by the `bundle-release` workflow (dispatched on `main` with the bundle name
and the full commit; no application, image or chart release was involved).
The tag is `bundle/konstapel-privileged-containers/v0.1.0`; the GitHub release
carries the rendered notes.

| | |
| --- | --- |
| Repository | `ghcr.io/backend-bunny/bundles/konstapel-privileged-containers` |
| Manifest digest | `sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8` |
| Content digest | `sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8` |
| Signer | `https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main` (issuer `https://token.actions.githubusercontent.com`) |
| Trust root | embedded public-good root, revision `sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |

Checked anonymously after the release, from a machine with no registry
credentials, with the pinned Cosign v3.1.3 and the production verifier:

```sh
ref=ghcr.io/backend-bunny/bundles/konstapel-privileged-containers@sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
id=https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main
iss=https://token.actions.githubusercontent.com
cosign verify "$ref" --certificate-identity "$id" --certificate-oidc-issuer "$iss"
cosign verify-attestation "$ref" --type slsaprovenance1 --certificate-identity "$id" --certificate-oidc-issuer "$iss"
bundlerelease verify-release -name konstapel-privileged-containers -digest sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
```

Both Cosign commands pass; the same signature checked against another
identity is refused. `cosign tree` lists the signature, the provenance and the
publication record as referrers. `verify-release` reports status `complete`
with referrers retrieved through the OCI tag-schema fallback (ghcr.io does not
serve the referrers API), source and workflow commit both
`863f4853151bb342a46eefa57c31cb2d46e17cff`, and the source rule revision
`sha256:0812f19fc13d0ff42bba7420c2111c81ca9a87dbe11740be79c7e56f5184dcd8`.
The first dispatch with an abbreviated commit was refused by validation before
any tag or upload, as designed.

Still outstanding for this release: a private mirror of this exact subject
verified through the production verifier, and live runtime acceptance
(`bundles:acceptance`).

### What has and has not been verified

Verified locally: every publication safeguard above against an in-process
registry with fault injection (failed, dropped, throttled and hung requests;
partial states; concurrent and moved tags; eventual and mismatching read-back;
private packages; echoed credentials; racing publishers) in both referrer
listing modes, and the happy path, idempotent rerun, conflict refusal, proof
completion, recovery through a fault-injecting TLS proxy and the anonymous
read-back failure against the real registries of the
[compatibility suite](#real-registry-compatibility). The real `kyverno test`
runs the official bundle's fixtures against the frozen layer.

Signing and release verification, verified locally:

- `publish.Completer` against the in-process registry: only missing kinds,
  signature before attestation, by digest; a rerun after a failed attestation
  adds only the attestation; nothing is signed twice; another digest, another
  repository's bytes, a tampered record, a wrong size, a tag and a repository
  with a tag are refused before anything is signed.
- The real Cosign CLI in key mode against both real registries (see
  [Real-registry compatibility](#real-registry-compatibility)), followed by
  `release.VerifyRelease`: publish, sign, attest, anonymous verification under
  a test rule, recovery of a missing attestation, refusal of another subject,
  and refusal of a release anonymous consumers cannot read.
- The provenance generator's output signed by Cosign and accepted by the
  verifier, with an older source commit and a newer workflow commit recorded
  apart, and refused for wrong builders, tests, records and a confused source
  (`internal/bundle/verify/testdata/release`).
- The Cosign wrapper with a fake executable: exact argv (digest only, fixed
  flags, key reference never key material), the environment allowlist (no
  `COSIGN_REPOSITORY`, `GITHUB_TOKEN` or registry token; OIDC variables only
  for keyless, the key password only for key mode), the temporary Docker
  config (mode 0600, removed), redaction of tokens and passwords from errors
  and logs, timeouts, and refusals before anything runs.
- Keyless argument construction, the run identity derived from GitHub's
  environment, the pre-signing rule check, the equality of
  `bundles/official-sources.yaml` with the workflow's identity and builder,
  and that `verify-release`'s check refuses real keyless Cosign proofs made by
  another workflow of this repository (`publish.yml`) under the official rule.
- The workflow's structure (permissions per job, `id-token` only on the
  publish job, step order, no secrets on command lines, independence from the
  application release workflows).

Not verified, because only a real GitHub run can: keyless signing itself (the
OIDC token exchange, a Fulcio certificate whose identity is the workflow on
`main`, Rekor and timestamp evidence from the public-good instance) and
`verify-release` accepting those proofs with the embedded root; the workflow on
GitHub (it has not been dispatched); the `ghcr.io` package creation,
permissions and visibility steps above; Cosign's writes to `ghcr.io` with the
job token; artifact download across re-run attempts; any write to `ghcr.io`;
and the GitHub CLI creating or editing the release with the job token
(including `--verify-tag` and `--latest=false` behaving as documented). Keyless proofs made by this repository's other workflow with the
same Cosign version verify offline (`internal/bundle/verify/testdata/ghcr`),
which is the closest local evidence.

**Not implemented yet.** Organization publication and mirroring (6.5), and live
acceptance evidence for official compatibility claims. No official bundle has
been released yet.
