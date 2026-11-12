# Provenance-policy fixtures (test-only)

These files were produced by the pinned Cosign CLI, v3.1.3 (`devbox.json`), with
`generate.sh` in this directory, on 2026-11-12 (regenerated with fresh keys for
the organization builder record; the subject is unchanged):

```sh
# The official bundle packaged from a clean checkout of e30d507 (the same
# subject as ../cosign), attested by an organization builder whose own
# revision (591d6fe) is newer than the source:
git worktree add --detach /tmp/kb-prov/src-e30 e30d507
(cd /tmp/kb-prov/src-e30 && devbox run -- scripts/bundles/package.sh konstapel-privileged-containers /tmp/kb-prov/layout-e30)
devbox run -- internal/bundle/verify/testdata/provenance/generate.sh \
  /tmp/kb-prov/layout-e30 591d6fea5e6517bffc906540cec1e94c3def738a /tmp/kb-prov/out
# then copied here: everything except org.key and other.key (deleted)
```

`generate.sh` starts a disposable `registry` container (the pinned
`KONSTAPEL_REGISTRY_IMAGE`, loopback port, label `konstapel.test=<run>`, removed
on exit), pushes the frozen layout unchanged plus a second subject (the same
layer under a manifest with one extra annotation), writes a predicate following
the Konstapel bundle provenance contract (`docs/policy-bundles.md`, "Bundle
provenance v1") for an organization builder that is not a GitHub Actions
workflow, so with the builder record `internalParameters.builder.revision`
and no workflow record, from the frozen payload's `bundle.json`, the definition at the
source commit and `package.json`, derives one negative predicate per violation,
creates two fresh ECDSA P-256 key pairs (`org`, `other`, empty password), and
runs `cosign sign --key` and `cosign attest --key --type slsaprovenance1
--predicate`, each with `--tlog-upload=false --use-signing-config=false
--allow-http-registry`. No transparency log, timestamp authority, Fulcio or
OIDC provider was used, and outbound HTTP(S) was routed to a closed local port.
Each referrer was read back through the OCI referrers tag schema index and its
manifest and Sigstore bundle layer saved unchanged.

| File | Content |
| --- | --- |
| `subject-manifest.json`, `subject-layer.tar.gz` | the official bundle `konstapel-privileged-containers@0.1.0` built from e30d507 (manifest `sha256:2d574a6f…`) |
| `other-subject-manifest.json` | a second subject over the same layer |
| `org.pub`, `other.pub` | the public keys |
| `facts.txt` | subjects, builder revision, key fingerprints, test builder id |
| `sign-org`, `sign-other` (`.manifest.json`, `.bundle.json`) | `cosign sign` by each key |
| `valid.predicate.json` | the conforming predicate |
| `prov-valid` | `valid` attested by `org` |
| `prov-valid-other` | `valid` attested by `other` (mixed-signer cases) |
| `prov-other-subject` | `valid` attested by `org` for the second subject |
| `prov-wrong-builder`, `prov-wrong-source-repo`, `prov-wrong-source-commit`, `prov-wrong-version`, `prov-wrong-name` | one attested fact changed |
| `prov-dispatch-as-source` | the builder revision attested as the source commit |
| `prov-workflow-record` | a GitHub workflow record instead of the builder record |
| `prov-forged-content`, `prov-forged-test` | a material digest that contradicts the payload |
| `prov-no-resolved-dependencies`, `prov-no-source-material` | required materials missing |
| `*.predicate.json` | the predicate each `prov-*` attests |

The private keys were discarded and are not in the repository. The keys, the
builder id `https://ci.example.test/konstapel/bundle-release@refs/heads/main`
and every other identity here are test material that must never be trusted
anywhere. The official release workflow produces the workflow-record form
instead (`../release`, and the real release in
`internal/bundle/release/testdata/official`).
