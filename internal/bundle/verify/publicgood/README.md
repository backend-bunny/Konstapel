# Embedded Sigstore public-good trusted root

`trusted_root.json` is the default trusted root for keyless publisher rules
that do not reference their own (`publisher.trustRoot`). It is used offline
only: the verifier never fetches or refreshes it at run time.

## Provenance

Obtained on 2026-11-11 with the pinned Cosign CLI (v3.1.3, `devbox.json`),
which verifies the Sigstore TUF repository from the TUF root embedded in Cosign:

```sh
HOME=$(mktemp -d) TUF_ROOT=$HOME/.sigstore/root devbox run -- cosign initialize
cp "$HOME/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json" .
```

| Item | Value |
| --- | --- |
| TUF repository | `https://tuf-repo-cdn.sigstore.dev` |
| TUF metadata | root v16 (expires 2027-04-22), targets v14, snapshot v166, timestamp v831 |
| Target | `trusted_root.json`, length 6787 |
| SHA-256 | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` (equals the targets metadata hash) |
| Content | Fulcio CAs (2021-03, 2022-04), Rekor logs `rekor.sigstore.dev` and `log2025-1.rekor.sigstore.dev`, CT logs `ctfe.sigstore.dev/test` and `/2022`, TSA `timestamp.sigstore.dev` |

The SHA-256 is pinned in `verify.PublicGoodTrustRootSHA256`; a changed file
that does not match it is refused (`ErrTrustConfig`).

## Refreshing

Repeat the commands above, check that the downloaded file's SHA-256 equals the
`trusted_root.json` hash in the verified `targets.json`, replace the file, update
`PublicGoodTrustRootSHA256` and this table, and run the tests (the real-proof
test must still verify). An embedded root only becomes stale in the safe
direction for new keys (proofs from new Sigstore instances fail closed); a key
withdrawn from the public-good root stays trusted here until the next refresh,
which is why operators can pin their own root object and why refreshing
belongs to the release process (task 3.5 documents its maintenance).
