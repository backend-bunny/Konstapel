# Policy bundles

A policy bundle is the versioned, signed unit in which Konstapel distributes
policy content: Kyverno policies, their tests, and the OSCAL/C2P mappings to
NIST controls. A profile references a bundle by name and digest; the controller
resolves it centrally and verifies it before use.

> **Status.** This page documents the payload contract implemented in
> [`internal/bundle`](../internal/bundle). Building an archive
> (`bundles:package`), publishing a release, and runtime resolution are tracked
> in the `add-policy-bundle-distribution` OpenSpec change and are **not
> available yet**: no official bundle has been released, and no bundle can be
> built with a Konstapel command today. Until those land, the only supported
> way to deliver policies is the existing prototype workflow in
> [development](development.md). This page will gain build, release and
> mirroring instructions as each group lands.

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

The command-line workflow (`bundles:package`) that drives this, and the
publication path, are not available yet.

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
