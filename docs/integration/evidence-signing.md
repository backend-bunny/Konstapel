# Evidence signing

`add-evidence-signing` lets an auditor who receives an evidence package outside
the cluster check that it was published by a key they trust. This guide covers
the parts implemented so far: the signing and verification contract that the
controller's publication path will use. Destination configuration, signing
during publication, signature downloads, and rotation are **not implemented
yet**; until they are, every published package is unsigned. Remaining work is
tracked in the change's [tasks](../../openspec/changes/add-evidence-signing/tasks.md).

## What is signed

The signature covers the exact bytes of the frozen `package.tar.gz` that S3
publication stores ([S3 evidence](s3-evidence.md)). Its `descriptor.json`
binds the cluster, run, binding, namespace scope, revisions, and file
inventory, so the signature authenticates all of them. The signature is a
separate file, `package.sigstore.json`; the archive and its digest are
unchanged, and existing archive readers keep working.

A valid signature shows that the archive is unchanged since a holder of the
trusted key signed it. It does not show that the cluster is compliant, that
scanner or producer claims are true, that the controller was uncompromised, or
when signing happened: there is no trusted timestamp and no transparency log.
After a key compromise, removing that key from your trusted keys is the only
remedy; a date recorded in a package cannot prove it was signed earlier.

## Keys

Konstapel signs only with operator-provided keys. It never generates, replaces,
or exports a private key, and runs no signing service. Operators distribute the
trusted public key to auditors themselves, separately from evidence.

| Item | Supported value |
| --- | --- |
| Algorithm | ECDSA P-256 with SHA-256 (`ecdsa-sha2-256-nistp256`, the default of `cosign generate-key-pair`) |
| Private key | Cosign's encrypted PEM (`ENCRYPTED SIGSTORE PRIVATE KEY`, or the older `ENCRYPTED COSIGN PRIVATE KEY`) holding a PKCS #8 key |
| Public key | One PEM `PUBLIC KEY` block (PKIX), which must be the private key's public key |
| Key identity | `sha256:` and the hex SHA-256 of the DER SubjectPublicKeyInfo; never a Secret name or file name |

The signing Secret has exactly the entries that
`cosign generate-key-pair k8s://<namespace>/<name>` writes:

| Entry | Content |
| --- | --- |
| `cosign.key` | The encrypted private key |
| `cosign.pub` | The matching public key |
| `cosign.password` | The password, byte for byte (no trailing newline); required even when empty |

Other key types (RSA, other curves, Ed25519), unencrypted private keys, and a
public key that does not match fail explicitly and are never converted. Key
loading errors name the failed check but never contain key bytes or the
password. Decryption accepts only Cosign's three fixed scrypt parameter sets
and refuses others, which bounds its memory use (64 MiB for keys the pinned
Cosign writes, at most 128 MiB).

## Signature format

`package.sigstore.json` is a Sigstore bundle v0.3
(`application/vnd.dev.sigstore.bundle.v0.3+json`) containing a message
signature: the SHA-256 of the archive bytes and an ASN.1 ECDSA signature over
that digest. Its verification material is only a public-key hint (the base64
SHA-256 of the DER key), the same content `cosign sign-blob --bundle` writes for
a key without a transparency log. It has no certificate, transparency-log
entry, or timestamp. The hint only names a key; it never makes a key trusted.

Konstapel writes the bundle in one canonical JSON form and checks it against
the recorded archive digest and public key before relying on it. Bundles with
another media type, digest algorithm, a DSSE envelope, a certificate, or
log/timestamp material are refused rather than interpreted.

The format was validated with the pinned tools and libraries below. Signing
uses these Go libraries in the controller; it does not run Cosign, and the
controller image contains no Cosign binary or shell. Cosign is only the
auditor's and the tests' verification tool.

| Component | Version |
| --- | --- |
| Cosign CLI (Devbox) | v3.1.3 |
| `github.com/sigstore/sigstore-go` | v1.3.0 |
| `github.com/sigstore/sigstore` | v1.10.8 |
| `github.com/secure-systems-lab/go-securesystemslib` | v0.11.0 |

`internal/evidencesign` tests check this table against `devbox.json` and
`go.mod`, and run the verification below with the pinned Cosign on every
`task test`.

## Verify a downloaded package

Verification needs only the archive, its bundle, and a public key you trust
obtained independently of the package. It works offline: no Kubernetes, S3,
private key, or signing service. Do not use a public key that arrived with the
package; anyone can sign a replacement package with their own key.

Verify a downloaded package offline:

```sh
cosign verify-blob --key trusted.pub --bundle package.sigstore.json --insecure-ignore-tlog=true package.tar.gz
```

The command prints `Verified OK` and exits 0 only when the archive bytes, the
bundle, and `trusted.pub` all match. `--insecure-ignore-tlog=true` is required
because this format deliberately has no transparency-log entry; with `--key`
and that flag, Cosign checks the signature and key without contacting any
service, and prints a warning about skipping the log. The flag does not
disable signature checking. Then inspect the archive as usual: extract it with
bounded tools and check `descriptor.json`, its file digests, and that its
scope is the one you expected ([package kinds](s3-evidence.md#package-kinds)). A valid
signature for a different run or namespace is still the wrong package.
