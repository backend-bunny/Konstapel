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
  `applied` or `assessment`), released when that holder finishes or advances.
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
- Signing, trust-root maintenance and publisher rotation are documented in
  [Signing, trust roots and rotation](#signing-trust-roots-and-rotation);
  keyless interoperability with the Cosign CLI under an isolated Sigstore stack
  (3.5), caching and controller wiring are not done.
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
contract. The bundle release workflow produces exactly this
(`publish.BuildProvenance`, see [Release a bundle](#release-a-bundle)); an
organization publishing with its own key must too, and can generate it with
`bundlerelease provenance` (see [Signing, trust roots and rotation](#signing-trust-roots-and-rotation)).

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
or its content, and fails with `ErrProvenanceContract`. Official bundles get
conforming provenance from the bundle release workflow; no official bundle has
been released with it yet (the workflow has not been dispatched).

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
- Provenance from a real run of the release workflow (it is implemented, but
  has not been dispatched; see [Release a bundle](#release-a-bundle)).

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

Also verified: the release tool's own generator output (`publish.BuildProvenance`
through `bundlerelease provenance`), signed by the pinned Cosign CLI with a
test key for a release that packages an older source commit (e30d507) from a
newer workflow revision (834c259), is accepted with both commits recorded apart
(`testdata/release/README.md`), and generator output for a confused source and
workflow commit, another builder, other tests and tampered records is refused.

Not verified: provenance from a real run of the release workflow (it has not
been dispatched), keyless provenance made by the Cosign CLI, and use from a
running controller.

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
| Provenance | same rule: the attestation must be signed by the same key | same rule: the same identity |

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
pipeline that ran recorded separately from the source commit:

```sh
devbox run -- go run ./cmd/bundlerelease provenance -package /path/to/bundle \
  -sources /path/to/sources.yaml -out predicate.json \
  -workflow-repository https://git.example.com/acme/policies \
  -workflow-path ci/release.yml -workflow-ref refs/heads/main -workflow-commit <40 hex>
```

`bundlerelease publish -signing key -key /abs/cosign.key -registry <prefix>`
(password in `COSIGN_PASSWORD`, registry credential in
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
   `identity` and `provenance.builder`) in the sources ConfigMap.
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

Verified: the public-key flow end to end with the pinned Cosign v3.1.3 CLI
(real signatures and provenance against a disposable registry, accepted by the Go
verifier, and the rotated-key and swapped-root cases); the embedded root's hash
against the live signed TUF targets metadata (checked independently on
2026-11-11, targets v14); and real Cosign v3 output from GitHub Actions
(`ghcr.io/backend-bunny/konstapel:0.1.0`) accepted offline against the embedded
root, including after its leaf certificates expired.

Not verified: a keyless proof made by the Cosign CLI against an isolated
Fulcio, Rekor and timestamp authority (the keyless tests use sigstore-go's
virtual Sigstore instead, and the real CI proof covers the public instance), the
rotation steps end to end (only their building blocks are tested), and anything
that runs in the controller. Because of the first item, task 3.5 is not ticked.

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
never cancelled. The workflow has three jobs:

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

The same checks run locally against any full-history checkout:

```sh
devbox run -- go run ./cmd/bundlerelease verify -name <name> -commit <sha>
```

`cmd/bundlerelease` is a build tool; it is not part of the controller image,
and the packages it uses for publication, signing and release verification
(`internal/bundle/publish`, `internal/bundle/sign`, `internal/bundle/release`,
`internal/bundle/registry`, `internal/bundle/verify`) are not linked into the
shipped binaries. `internal/bundle/sign` is the only code that executes Cosign.

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
job token; artifact download across re-run attempts; and any write to
`ghcr.io`. Keyless proofs made by this repository's other workflow with the
same Cosign version verify offline (`internal/bundle/verify/testdata/ghcr`),
which is the closest local evidence.

**Not implemented yet.** Release notes and summaries (6.4), organization
publication and mirroring (6.5), and live acceptance evidence for official
compatibility claims. No official bundle has been released yet.
