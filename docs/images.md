# Container images

Konstapel uses melange to build an APK and apko to assemble a non-root Linux
amd64 image. The current image packages the assessment prototype: the runner,
C2P provider and manifest, reviewed policy/OSCAL content, CA certificates, and
kubectl. It has no shell or package manager. A production controller is still
planned separately.

## Build and test

Enter the [development environment](development.md), then run:

```sh
task image:build
task image:test
task image:publish-dry-run
```

melange uses bubblewrap and requires unprivileged user namespaces. The setup
action enables these on disposable Ubuntu CI runners. Docker is required only
for container smoke tests and the publish digest lookup. Builds download APKs,
Go modules, upstream source archives and license metadata; keep network access
available. Caches live under `.cache/image`.

The build exports the working tree, verifies Go module checksums, collects
licenses and vendors dependencies into a temporary directory. melange compiles
the two commands with CGO disabled and module network access disabled. Its
Wolfi Go package follows the major/minor version from `go.mod`; Wolfi's compiler
patch version can differ from the locally pinned Devbox compiler. Exact build
environment packages are recorded in `out/image/build-dependencies.json.x86_64`,
and the compiler version is included in the image. This is not a fully locked
or independently reproduced build environment.

Each build generates a temporary APK signing key and deletes the private key
after signing. Only the public key reaches apko. The committed `apko.lock.json`
pins the Wolfi runtime packages and their checksums. The freshly built local
APK is merged into a temporary build lock; configuration and package-set drift
fail the build. Image trust comes from the published digest's keyless signature.

Tests exercise real policy generation and the provider handshake, saved-evidence
conversion, kubectl availability, non-root UID 65532, a read-only root filesystem,
no network, dropped capabilities, and embedded C2P dependencies in the SBOM.
Test containers and the temporary Docker image are removed afterwards. Build
artifacts and evidence remain under `out/image`; `task clean` preserves them.

The default working directory is `/usr/share/konstapel`. Supply an explicit
writable output path. For example, using a published digest:

```sh
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp \
  ghcr.io/backend-bunny/konstapel@sha256:... generate --output /tmp/generated
```

Live operations also need an explicitly mounted kubeconfig, an explicit context,
and network access. No ambient cluster credentials are bundled in the image.

## Published evidence

Pull requests build and test with read-only repository permissions. Pushes to
`main` run checks, rebuild and test, then publish
`ghcr.io/backend-bunny/konstapel:sha-<full-commit>`. Manual publishing is restricted
to `main`. There is no mutable `latest` tag or release-version promise yet.

Every published digest receives:

- A keyless cosign signature using the GitHub Actions OIDC identity.
- Two SPDX SBOM attestations: apko's APK/source inventory and Syft's image scan,
  including Go modules embedded in Konstapel and kubectl.
- A source manifest linking APKs to recipes and pinned upstream sources, and
  Konstapel's linked Go modules to checksum-verified module archives.
- A license notices attestation containing deduplicated full texts. It includes
  Konstapel's `LICENSE`/`NOTICE`, Go module license files, Go's license, shipped
  policy/NIST licenses, APK source notices, and notices from vendored Go sources
  in upstream APK archives. Original Konstapel dependency texts also ship under
  `/usr/share/doc/konstapel`, alongside source files collected by `go-licenses`.
- GitHub build provenance bound to the published digest.

`go-licenses` identifies licenses in the packages used by the two commands;
ambiguous multiple matches retain their texts and `NOASSERTION` rather than
inventing a combined license expression. Syft also searches module sources for
license metadata. Unknown fields remain visible. Missing collected Go license
texts, unpinned sources, or a package with no notice or canonical license text
fail the build. Canonical-only APK notices are explicitly reported in the build
log and `out/image/notices.md`.

The OCI license label describes Konstapel's own Apache-2.0 code. It does not
relicense the bundled dependencies or NIST content. See [LICENSE](../LICENSE),
[NOTICE](../NOTICE), and the published per-package evidence.

## Verify

Both image workflows show expandable dependency/license inventories, pinned
sources and license notices in the GitHub Actions job summary. The publishing
summary also reports verification status and provides commands containing the
actual published digest. Downloadable evidence remains available as an artifact.

Use the digest printed in the publishing job summary:

```sh
IMAGE=ghcr.io/backend-bunny/konstapel@sha256:...
IDENTITY=https://github.com/backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/main
cosign verify "$IMAGE" --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "$IMAGE" \
  --type https://github.com/backend-bunny/Konstapel/notices/v1 \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$IMAGE" --repo backend-bunny/Konstapel
```

The publish workflow runs these verification checks itself, including the source
manifest attestation. Signing and OIDC attestations require GitHub Actions and
are not emulated by a local dry run.

## Dependency refresh

Renovate updates Devbox tools, Go modules and GitHub Actions. Runtime APK locks
use a separate Monday workflow, matching container-dropshipping: it runs
`task image:lock`, tests, and opens or updates `chore/image-lock-refresh`.
It explicitly dispatches both PR check workflows because `GITHUB_TOKEN` pushes
do not trigger them. The repository must allow GitHub Actions to create PRs.
Merging the reviewed refresh PR publishes the updated image.

For a manual refresh, run `task image:lock` and `task image:test`, review the
`apko.lock.json` diff and resulting evidence, then include the lock in a PR.
The lock refresh never publishes directly.

## Tooling provenance

The scripts are adapted from these Apache-2.0 sources:

- `scripts/image/lockfile.py` and the build/publish pattern:
  [talos-nyckelpiga](https://github.com/backend-bunny/talos-nyckelpiga/tree/3505994c1009ac01f5f0cc526b82468c94e3ab4c).
- `scripts/image/sources.py` and `scripts/image/notices.py`:
  [container-dropshipping](https://github.com/backend-bunny/container-dropshipping/tree/fb70fff1db04661077001c7bee1253921897b93a).
  Konstapel adds notices shipped by Go modules and harvests upstream vendored Go
  notices as well as the source archive's root notices.
- `scripts/image/licenses/GO-LICENSE` is the unmodified
  [Go license at go1.25.12](https://github.com/golang/go/blob/go1.25.12/LICENSE).
