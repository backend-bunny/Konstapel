# Evidence signing

`add-evidence-signing` lets an auditor who receives an evidence package outside
the cluster check that it was published by a key they trust. This guide covers
the parts implemented so far:
- the signing and verification contract that the publication path will use;
- the destination's signing policy, its key Secret, and the controller's
  signing readiness status.

Signing during publication, signature downloads, and the rotation and
retention behavior around them are **not implemented yet**. Until they are,
every published package is unsigned, even on a destination with
`mode: Required`. Remaining work is tracked in the change's
[tasks](../../openspec/changes/add-evidence-signing/tasks.md).

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

## Set up signing for a destination

Signing is a property of an EvidenceDestination, set by a platform
administrator (`konstapel-compliance-admin`). Every binding and request that
publishes to the destination inherits it; nothing in a binding, profile,
request or run can select another key or disable signing.

| `spec.signing` | Meaning |
| --- | --- |
| absent | Disabled. Existing destinations are unchanged and get no signing status. |
| `mode: Disabled` (the default when `signing` is set) | New publications are unsigned. `secretRef` must not be set. |
| `mode: Required` | New publications need a verified signature from the key in `secretRef`; there is no unsigned fallback. |

`secretRef` names a Secret in the controller namespace only; a `namespace` on
it is rejected. `kms` and `keyless` are rejected with an explicit message:
remote keys and Fulcio keyless signing are not supported. A change to the
policy or the reference applies to publications prepared afterwards.

Konstapel never creates, rotates, or deletes signing keys; the key pair, its
password, and the trusted public key are yours to generate, store, and
distribute. Create a versioned key pair as a Secret in the controller
namespace (Cosign makes it immutable and writes `cosign.pub` to the current
directory):

Create the signing key Secret:

```sh
cosign generate-key-pair k8s://konstapel-system/konstapel-evidence-signing-2026-11
```

Cosign prompts for the password, or reads `COSIGN_PASSWORD`. Give `cosign.pub`
to auditors through a channel they already trust, never inside an evidence
package. Then reference the Secret from the destination, as in
[`docs/examples/evidence-signing/destination.yaml`](../examples/evidence-signing/destination.yaml):

```yaml
spec:
  signing:
    mode: Required
    secretRef: {name: konstapel-evidence-signing-2026-11}
```

To rotate, create the next Secret under a new name, distribute its public key,
and change `secretRef`. Editing a Secret in place, or deleting a key that
pending publications still need, is not the supported workflow; the
publication rules for rotation are not implemented yet.

### Signing readiness

The controller reports what it observes about the policy and key on the
destination, separately from storage readiness:

```sh
kubectl get evidencedestination primary -o jsonpath='{.status.signing}{"\n"}{.status.conditions[?(@.type=="SigningReady")]}{"\n"}'
```

`status.signing` has the mode, the Secret name, and the loaded key's
`keyFingerprint` and `algorithm`. Compare the fingerprint with the public key
you distributed:

Compute a public key's fingerprint:

```sh
printf 'sha256:%s\n' "$(grep -v -- '-----' cosign.pub | base64 -d | sha256sum | cut -d' ' -f1)"
```

The `SigningReady` condition is present only when `spec.signing` is set:

| Status | Reason | Meaning |
| --- | --- | --- |
| True | `SigningDisabled` | Signing is disabled. |
| True | `KeyLoaded` | The key decrypts with its password and matches `cosign.pub`. |
| False | `SecretNotFound` | The Secret does not exist in the controller namespace. |
| False | `SecretUnreadable` | The controller cannot read it (for example `Forbidden`). |
| False | `KeyUnavailable` | An entry is missing or too large; `cosign.password` must exist, even if empty. |
| False | `KeyMalformed` | An entry is not the expected PEM or key encoding. |
| False | `KeyPasswordInvalid` | The key does not decrypt with `cosign.password`. A trailing newline counts. |
| False | `KeyMismatch` | `cosign.pub` is not the private key's public key. |
| False | `UnsupportedKey` | The key isn't an encrypted ECDSA P-256 Cosign key. |

Messages name the failed check and never contain key bytes or the password.
The condition is advisory: it never changes `Ready`, downloads, retention, or
retirement, and publication will reread the destination and the Secret itself
before it relies on a key. The controller does not watch Secrets. It re-reads
the key when the destination changes, every 30 seconds while `SigningReady` is
False, and every 5 minutes otherwise. An unchanged Secret (same UID and
resourceVersion) is not decrypted again.

### Who can read signing keys

Only the controller reads the signing Secret: one `get` by name in the
controller namespace per evaluation, never a list or a watch, and the private
key and password bytes are cleared after use. Application teams, assessment
operators and requesters, and compliance viewers cannot read Secrets in the
controller namespace or change destinations.

There is no grant specific to signing keys. The controller's existing Secret
`get` in `konstapel-system` covers any Secret name, because names come from
EvidenceDestination specs ([controller ServiceAccount
boundary](../charts.md#controller-serviceaccount-boundary)). The download
server's `konstapel-evidence-download-credentials` Role has the same `get` on
any Secret in the namespace; it does not read signing keys, but its identity
could. Anyone who can read Secrets in the controller namespace can read the
signing key. Protect that namespace, and encrypt Secrets at rest.

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
log/timestamp material are refused rather than interpreted. Konstapel's own
checks accept only bundles that Konstapel wrote: a bundle produced elsewhere,
such as by `cosign sign-blob` (the same content with different JSON spacing),
is never stored or served as a package signature. Auditors verify with Cosign,
which accepts both.

The format was validated with the pinned tools and libraries below. Signing
uses these Go libraries in the controller; it does not run Cosign, and the
controller image contains no Cosign binary or shell. Cosign is only the
auditor's and the tests' verification tool.

| Component | Version |
| --- | --- |
| Cosign CLI (Devbox) | v3.1.3 |
| `github.com/sigstore/sigstore-go` | v1.3.0 |
| `github.com/sigstore/sigstore` | v1.10.8 |
| `github.com/secure-systems-lab/go-securesystemslib` | v0.11.1 |

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
