# Release-provenance fixtures (test-only)

The provenance predicate written by the release tool's own generator
(`bundlerelease provenance`, which calls `publish.BuildProvenance`, the code the
release workflow's signer uses), signed and attested with the pinned Cosign CLI,
v3.1.3 (`devbox.json`), with `generate.sh` in this directory, on 2026-11-11:

```sh
# The official bundle packaged from e30d507 (the same subject as ../provenance
# and ../cosign) and frozen by the release tool, released by a newer workflow
# revision 834c259: a retry that packages an older source commit.
git worktree add --detach /tmp/kb/source e30d50760b498cbb17012742c7789a414a1e1d6b
devbox run -- bash /tmp/kb/source/scripts/bundles/package.sh konstapel-privileged-containers /tmp/kb/bundle
devbox run -- go run ./cmd/bundlerelease freeze -name konstapel-privileged-containers \
  -commit e30d50760b498cbb17012742c7789a414a1e1d6b -package /tmp/kb/bundle
flock /tmp/konstapel-live-cluster.lock devbox run -- internal/bundle/verify/testdata/release/generate.sh \
  /tmp/kb/bundle 834c259212c1f11d41faf42b81f361a7f7107e53 /tmp/kb/out
# then copied here: everything except org.key, subject-layer.tar.gz and
# subject-manifest.json, which are byte-identical to ../provenance's.
```

`generate.sh` starts a disposable `registry` container (the pinned
`KONSTAPEL_REGISTRY_IMAGE`, loopback port, label `konstapel.test=<run>`, removed
on exit), pushes the frozen layout unchanged, creates a fresh ECDSA P-256 key
pair (`org`, empty password) and a public-key rule for it (`rule.yaml`, builder
= the release workflow identity), runs `bundlerelease provenance` with that rule
(`valid.predicate.json`) and with a rule naming another builder
(`wrong-builder.predicate.json`), then `cosign sign --key` and `cosign attest
--key --type slsaprovenance1 --predicate` for each, with `--tlog-upload=false
--use-signing-config=false --allow-http-registry`. No transparency log,
timestamp authority, Fulcio or OIDC provider was used, and outbound HTTP(S) was
routed to a closed local port. Each referrer was read back through the
referrers tag schema index and saved unchanged.

| File | Contents |
| --- | --- |
| `publication-record.json` | the record `bundlerelease freeze` wrote (source e30d507, three fixtures, go and kyverno) |
| `valid.predicate.json`, `wrong-builder.predicate.json` | the generator's output |
| `sign.*`, `prov-valid.*`, `prov-wrong-builder.*` | referrer manifests and Sigstore bundles |
| `org.pub`, `rule.yaml`, `facts.txt` | test key, the rule, subject, workflow commit, fingerprint, builders, Cosign version |

`release_test.go` regenerates the predicate from `publication-record.json` and
`facts.txt` with `publish.BuildProvenance` and requires it to equal both the
file and the predicate inside the signed statement, then accepts the subject
with `Verifier.Accept` (`VerifyProofs` and `CheckProvenance`), and requires the
attested source commit (e30d507) and workflow commit (834c259) to be recorded
apart. The key is test-only and its private half was deleted.

`wrong-builder.predicate.json` was written by the generator before it required
a GitHub Actions workflow builder's workflow record to name that workflow: it
records `bundle-release.yml` under the builder `other.yml`. The generator now
refuses that input; the signed fixture is kept as real Cosign output the
verifier must refuse (`ErrProvenanceBuilder`).
