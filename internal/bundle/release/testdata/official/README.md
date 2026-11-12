# The first official bundle release (public data)

`ghcr.io/backend-bunny/bundles/konstapel-privileged-containers@sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8`
(version 0.1.0, source commit `863f4853151bb342a46eefa57c31cb2d46e17cff`), as
the bundle release workflow published it and the pinned Cosign CLI (v3.1.3)
signed and attested it keylessly on 2026-11-12, as
`https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`) against the Sigstore
public-good instance. Fetched read-only and anonymously on 2026-11-12 with a
pull token from
`https://ghcr.io/token?scope=repository:backend-bunny/bundles/konstapel-privileged-containers:pull`,
the subject and layer by digest, the referrers through the tag schema index
(`sha256-1a2ca25a...`), each saved unchanged:

| File | Digest |
| --- | --- |
| `subject-manifest.json` | `sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8` |
| `subject-layer.tar.gz` | `sha256:82a3f787a42544e3f84f38b008d84880db59881b5721302653872741ee2e1da5` |
| `signature.manifest.json` (`cosign sign`) | `sha256:0d2484523fc82bec88b3e5c3cf35b0aaa3d4a3b764134a8bb14559fcc776a2c5` |
| `signature.bundle.json` | `sha256:1e6200ab594499daba95f7ed3fecfcf8267a0c49f55bb51a05c29145a332d3e9` |
| `provenance.manifest.json` (`cosign attest`, Bundle provenance v1 with the workflow record) | `sha256:5141de7e7f35faf2fe54c8fa0c5f43514a534fc18c2a07053d842aa054961190` |
| `provenance.bundle.json` | `sha256:6ad9ec8671f6d9d23e570f34c7175122826759efdb70ee2e7ec7df4fd45f6a8a` |

The index also lists the release's publication-record referrer, which is not
needed for verification and not copied. `official_test.go` verifies these
bytes offline through `CheckRelease` (`verify.Verifier.Accept` and the content
checks) under `bundles/official-sources.yaml` and the embedded public-good
root, and refuses rules naming another identity, ref, fork, issuer, builder or
source repository. `official_publicinterop_test.go` (build tag
`publicinterop`, network) does the same against the live registry.
