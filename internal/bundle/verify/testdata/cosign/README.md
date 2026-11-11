# Public-key verification fixtures (test-only)

These files were produced by the pinned Cosign CLI, v3.1.3 (`devbox.json`), with
`generate.sh` in this directory, on 2026-11-11:

```sh
# From a clean checkout of main at e30d507:
devbox run -- scripts/bundles/package.sh konstapel-privileged-containers /tmp/kb-fx/layout
devbox run -- internal/bundle/verify/testdata/cosign/generate.sh /tmp/kb-fx/layout /tmp/kb-fx/out
# then copied here: everything except key-a.key and key-b.key
```

`generate.sh` starts a disposable `registry` container (the pinned
`KONSTAPEL_REGISTRY_IMAGE`, loopback port, label `konstapel.test=<run>`, removed
on exit), pushes the frozen bundle layout unchanged, creates two fresh ECDSA
P-256 key pairs with `cosign generate-key-pair` (empty password), and runs:

- `cosign sign --key key-a.key` and `cosign sign --key key-b.key` on the bundle
  manifest digest, and
- `cosign attest --key key-a.key --type slsaprovenance1 --predicate
  provenance-predicate.json` on the same digest,

each with `--tlog-upload=false --use-signing-config=false --allow-http-registry`.
No transparency log, timestamp authority, Fulcio or OIDC provider was used, and
outbound HTTP(S) was routed to a closed local port so nothing could reach the
Sigstore public-good services. Each referrer was then read back through the OCI
referrers tag schema index, and its manifest and Sigstore bundle layer saved
unchanged.

| File | Content |
| --- | --- |
| `subject-manifest.json` | the signed bundle manifest; its SHA-256 is the subject digest |
| `sign-key-{a,b}.manifest.json`, `.bundle.json` | `cosign sign` referrer manifest and Sigstore bundle v0.3 (DSSE, in-toto Statement v1, predicate type `https://sigstore.dev/cosign/sign/v1`) |
| `provenance-key-a.manifest.json`, `.bundle.json` | `cosign attest` referrer (DSSE, in-toto Statement v0.1, predicate type `https://slsa.dev/provenance/v1`) |
| `provenance-predicate.json` | the made-up SLSA predicate that was attested |
| `key-{a,b}.pub` | the public keys |
| `fingerprints.txt` | subject digest and SHA-256 of each key's DER SubjectPublicKeyInfo |

The private keys were discarded and are not in the repository; these keys,
the predicate, and every identity in them are test material that must never be
trusted anywhere. Negative cases (tampering, other subjects, statements Cosign
would not write) are derived from these files, or signed in the tests with
keys generated at run time.
