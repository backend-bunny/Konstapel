# konstapel-privileged-containers 0.1.0

A Konstapel policy bundle release. It is versioned and published independently of the Konstapel application, image and charts, and contains no controller code.

**Status: complete.** The published bytes were retrieved anonymously by digest, and their signature, build provenance and content were verified under the official publisher rule for this bundle (rule revision `sha256:1111111111111111111111111111111111111111111111111111111111111111`).

## Identity

| | |
| --- | --- |
| Registry | `ghcr.io/backend-bunny/bundles/konstapel-privileged-containers` |
| Manifest digest | `sha256:fac58c648281fc47cce010cc201c18b60a35b6dfdd1b8e0773c5a73c28a2785e` |
| Pin in a profile | `spec.bundle.name` `konstapel-privileged-containers` and `spec.bundle.digest` `sha256:fac58c648281fc47cce010cc201c18b60a35b6dfdd1b8e0773c5a73c28a2785e` |
| Version tag | `0.1.0` |
| Source | https://github.com/backend-bunny/Konstapel at commit `0123456789abcdef0123456789abcdef01234567` |
| Release workflow (recorded separately from the source) | https://github.com/backend-bunny/Konstapel `.github/workflows/bundle-release.yml` at commit `89abcdef0123456789abcdef0123456789abcdef` |
| Content digest | `sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8` |
| Archive (layer) digest | `sha256:72856b1957288d28acae04db0f6344f879f52ac97c06e7f050a313a8b187716d` |
| Bundle definition | `bundles/konstapel-privileged-containers/definition.json`, sha256 `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |
| Builder | https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main |
| Signer | https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main (issuer https://token.actions.githubusercontent.com) |
| Signing time | 2026-11-12T08:59:12Z |
| Trust root | embedded Sigstore public-good root (revision `sha256:2222222222222222222222222222222222222222222222222222222222222222`) |

## Compatibility

- Provider contract: `konstapel-kyverno/v1`
- Minimum Konstapel release: `0.1.0`
- OSCAL documents: `1.1.3` (content/component-definition.json), `1.2.3` (content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json), `1.2.3` (content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json)
- Workload kinds: `CronJob`, `DaemonSet`, `Deployment`, `Job`, `Pod`, `ReplicaSet`, `ReplicationController`, `StatefulSet`
- Operating systems: `linux`

This is the bundle's declared contract. It does not claim enforcement on a particular cluster: live acceptance evidence for these exact inputs is separate, and the controller's own compatibility checks still apply.

## Policies

| Policy | Rule and check IDs | Source file |
| --- | --- | --- |
| `disallow-privileged-containers` | `disallow-privileged-containers` | `content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml` |

## Tests

Declarative policy fixtures ran against the unpacked, frozen bytes with `kyverno test --require-tests` before publication: **pass**, 14 fixture files.

<details><summary>Fixture files and SHA-256 digests</summary>

| File | SHA-256 |
| --- | --- |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/chainsaw-test.yaml` | `136e1c4b98da423a834fa319a3f1d5528c5b16ea7b3d16bf0606f83287ea58f9` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/ephemeral-rbac.yaml` | `c30b4ff1ea908fdab199863715c755d4bb90fcf082f0f07ec0ff9800dd7d4fe6` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/pod-bad.yaml` | `6b2438745d86020967e81b2a1e6a4a89d088ce212309d63bdd23ade1554b3e9a` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/pod-good.yaml` | `7c2a72511aff660799caca6d1029671fe568671c97d82d8d9247bb0e5e817917` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/podcontroller-bad.yaml` | `e4ff2eea66681d9034756b7f80c9147e9a2fed93ab2cae46541f5974e6c1d723` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/podcontroller-good.yaml` | `c1422826802552cb30842c8cb765d20c61d3e9c9b5003d19d0fa0beab0026078` |
| `content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/policy-ready.yaml` | `51f12242bc2e7f4a06d18b0a80faf12f5cd4b2833a4b0016b9656eaa5b0d9d70` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test-controllers/kyverno-test.yaml` | `37c23b3c28896a228ca9123673ba3dd94516553b7ac3f32dc696facf9f97da4b` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test-controllers/resources.yaml` | `0441e9380910694cefddcd474bb86f9c8288ade74700bf301cca7fdb826facbb` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test-exceptions/exception-resources.yaml` | `336e28b37d7a6db477e9b572983cf6f473c483c4620ef4598e0bc338cd896291` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test-exceptions/exceptions.yaml` | `9731fe76e5cc132bbfd6840c9eccf98a17199981be2e94fcbd07f1ce4d67cab5` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test-exceptions/kyverno-test.yaml` | `370548252e6653026472595f71870e009175b68f761a1997636b208d0d92b999` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test/kyverno-test.yaml` | `f9a80e78f7fd92059a57e1e4640298ad5c99eaf65ce3a42624b16b5be2441160` |
| `content/upstream/kyverno/disallow-privileged-containers/.kyverno-test/resource.yaml` | `c9b4d86200c140adf569119c10d2b22567c7a40be2b01751ff19a7a0fa650d62` |

</details>

## Licenses

The archive carries its license and notice texts; they are part of the signed content:

- `LICENSE`
- `NOTICE`
- `content/upstream/kyverno/LICENSE`
- `content/upstream/nist/LICENSE.md`
- `licenses/kyverno-LICENSE`
- `licenses/nist-LICENSE.md`

## Build tools

- cosign v3.1.3
- go go1.27.4
- kyverno 1.17.2

## Verify it yourself

Both commands check the exact digest and fail if the signer is not exactly this workflow identity:

```sh
ref=ghcr.io/backend-bunny/bundles/konstapel-privileged-containers@sha256:fac58c648281fc47cce010cc201c18b60a35b6dfdd1b8e0773c5a73c28a2785e
cosign verify "$ref" \
  --certificate-identity 'https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
cosign verify-attestation "$ref" --type slsaprovenance1 \
  --certificate-identity 'https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Cosign checks the signatures and who made them; it does not check what the provenance says. The Konstapel verifier (run it from a checkout of this repository at or after the source commit) also checks the attested builder, source repository and commit, bundle name and version, the content and test materials, and that the archive matches its manifest:

```sh
devbox run -- go run ./cmd/bundlerelease verify-release -name konstapel-privileged-containers -digest sha256:fac58c648281fc47cce010cc201c18b60a35b6dfdd1b8e0773c5a73c28a2785e
```

Referrers were listed through the OCI referrers tag schema (`sha256-<hex>` index tag).
