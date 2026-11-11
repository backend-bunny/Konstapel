# Real Cosign v3 CI proofs (public data)

The signature and SLSA provenance referrers of the public image
`ghcr.io/backend-bunny/konstapel:0.1.0`
(`sha256:20711e1fbda7982615945cf775fbcc4d245fea428900c5dca4fa701eded20407`), as
the release workflow's Cosign v3 wrote them, fetched read-only and anonymously
on 2026-11-11 with a pull token from
`https://ghcr.io/token?scope=repository:backend-bunny/konstapel:pull`, through
the referrers tag schema index (`sha256-20711e1f...`), by digest:

| File | Digest |
| --- | --- |
| `signature.manifest.json` | `sha256:b41f0b439292f33f9700316d0c4135c8d1e4733edce33e95287fcb4820755c40` |
| `signature.bundle.json` | `sha256:92c8ac99ca23802aaf13beeac8192b5832cba7af2ed0559c74b179197729dfbb` |
| `provenance.manifest.json` | `sha256:e04d91e5d2aca8f389f30823b27d4fac5a2435f79da98ce4dccdd318fd59a722` |
| `provenance.bundle.json` | `sha256:71c0ec1ba072739b377c94b13e7da1ac53c7cff78303f0bee780a55a1c44725f` |

Both were signed keylessly by
`https://github.com/backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`) on 2026-11-09; their
leaf certificates expired ten minutes later. The tests verify them offline
against the embedded public-good trusted root (`../../publicgood/`). The image
is an application image, not a policy bundle; only the Sigstore layer format and
statement binding are exercised.
