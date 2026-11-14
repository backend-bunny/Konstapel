# Evidence signing

`add-evidence-signing` lets an auditor who receives an evidence package outside
the cluster check that it was published by a key they trust. This guide covers
the parts implemented so far:
- the signing and verification contract;
- the destination's signing policy, its key Secret, and the controller's
  signing readiness status;
- [signed publication](#signed-publication): the frozen signing intent, signing
  and storing the signature, and the commit gate that never publishes unsigned
  evidence under `mode: Required`.

**Not implemented yet:**
- signature downloads, and verification of the archive/signature pair before a
  download is served;
- rotation and retention around signatures: inspectable key dependencies,
  integrity checks, orphan fences, and inventories;
- a trigger to retry signing for a run that ended with `SigningFailed`. Its
  evidence is retained, see [failure and recovery
  states](#publication-failure-and-recovery-states).

Until signature downloads exist, the authorized download path serves a signed
package's archive alone, as before. Remaining work is tracked in the change's
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
pending publications still need, is not the supported workflow. A run's
signing intent pins the Secret name and key it was prepared with (see
[signed publication](#signed-publication)), so a run waiting to be signed
still needs its old key. Rotation status is not implemented yet.

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

## Signed publication

Signing happens between staging and commit, inside the existing publication
retries. The steps are:

1. **Freeze the intent.** After the archive is staged and verified, and before
   any commit attempt, the controller reads the run's pinned destination
   (uncached, by name, and checked against the pinned UID). It records the run's
   `status.signingIntent`: the mode, the destination UID and generation, the
   archive SHA-256, and for `Required` the Secret name and the pinned public
   key (fingerprint, algorithm, PEM, and the Secret's UID and resourceVersion
   as provenance). The intent is written once and never removed. Its mode,
   destination, Secret, and archive never change. Its key is set once: if the
   key could not be loaded at preparation, the `Required` intent is recorded
   without a key, and the first successful load pins it. Later edits to the
   destination, including switching to `Disabled` or to another Secret,
   affect only runs prepared later. A run whose intent is `Disabled` stays
   unsigned even if the destination later requires signing.
2. **Recover before signing.** If the run's `package.sigstore.json` is already
   stored and verifies for this archive under the pinned key, it is used as
   is. No private key is read, so a restarted or new leader finishes even
   after the key Secret was deleted.
3. **Sign and store once.** Otherwise the controller loads the intent's Secret,
   requires its key to be the pinned key (a different key under the same
   Secret name is refused; the same key re-encrypted with another password is
   accepted), signs the archive digest, and verifies the result. It stores
   the bundle with a conditional create. If another attempt stored a bundle
   first, that bundle is used and verified again. ECDSA signatures differ on
   every attempt, but only one is ever stored.
4. **Commit gate.** The publisher reads the stored bundle back and verifies
   it for the staged archive under the intent's key. Only then does it
   create the commit, a `SignedPublicationCommit` that references both
   objects. Without a stored, verifying bundle nothing is committed. An
   existing commit that does not match the intent is a conflict and is never
   accepted:
   - an unsigned commit under `Required`;
   - a signed commit under `Disabled`;
   - a commit signed by another key.

While the intent cannot be satisfied (the key is missing, unreadable, or
different, or the stored signature is invalid), the run's `Published`
condition is False with reason `SigningPending`, and publication retries.
After the publish timeout (5 minutes after collection closed) the run fails
with `SigningFailed`; see below for what happens to its evidence. Signing
problems are never reported as compliance results.

A signed run's `status.publication.signature` names the stored bundle (key,
version, SHA-256, size, media type, algorithm, key fingerprint). Unsigned
runs have no `signature`, and their commit, receipt, and publication status
are byte for byte what earlier releases wrote.

### Publication failure and recovery states

The signing intent boundary separates two phases. Before the intent is
recorded, the destination's current policy applies. After it is recorded,
only the intent counts: edits, rotation, and key deletion change nothing for
that run except whether its intent can still be satisfied.

| Run state | `Published` condition | Evidence |
| --- | --- | --- |
| Signing pending | False, `SigningPending` (retrying every poll) | Staged archive kept; nothing committed |
| Signed | True, `Committed`; `status.publication.signature` set | Archive and signature committed together |
| Signing failed | False, `SigningFailed` (after the publish timeout) | Staged archive retained, see below |
| Capture lost | False, `CaptureLost` | The frozen package itself was lost; a later run assesses current state |

A signing failure never costs evidence:
- **Retained, not discarded.** The staged archive, and the stored signature if
  there is one, is not treated as an abandoned attempt.
- **Recorded.** `status.publication` has phase `Failed`, failure reason
  `SigningFailed`, the archive digest, the destination, and `expiresAt`.
  `expiresAt` is the run's own retention (recorded at collection closure)
  counted from closure.
- **Held like a committed package.** Deleting the run record waits for that
  expiry. The destination counts the archive as an outstanding package.
  Expiry deletes it with the usual retryable cleanup, and an orphan handoff
  hands it to the operator.
- **Evidence unchanged.** Completeness and outcomes stay as they were. Nothing
  is recollected under the run's identity. The binding's slot is released,
  so later runs are scheduled normally.
- **Recoverable.** The intent stays recorded so an authorized recovery can
  later re-sign the same archive. That recovery trigger is not implemented
  yet.

If the staged archive itself is lost while signing is pending, the run ends
with `CaptureLost` instead.

**Worked examples.**
- **Rotation.** Run A was prepared under `signing-2026-11`. Its signature
  upload failed. The destination then moved to `signing-2027-05`. Run A is
  still signed with the 2026 key, because its intent pinned it. Runs prepared
  afterwards use the 2027 key. If the 2026 Secret is deleted before run A's
  signature is stored, run A waits in `SigningPending` and then fails with
  `SigningFailed`, with its evidence retained. If its signature was already
  stored, run A completes without the key.
- **In-flight Required→Disabled.** Run B's intent is Required, but its key is
  missing. An administrator switches the destination to Disabled. Run B stays
  Required: it is signed once its key is installed, or ends `SigningFailed`.
  It is never published unsigned. Runs prepared after the edit are unsigned.
- **Complete, incomplete, and diagnostic packages.** All three are signed the
  same way. The run's evidence completeness, outcome counts, and export kind
  (`Assessment` or `Diagnostic`) are identical to an unsigned publication of
  the same package; a signature never makes an incomplete or diagnostic
  package complete.

### Mixed versions and rollback

Releases before evidence signing read `commit.json` leniently, but require
its top-level `run` to match. A signed commit keeps the run under `subject`,
so an older controller that meets one, after a rollback or during a rolling
upgrade, reports a conflict for that run. It does not publish or serve it as
unsigned. Its retries fail with `PublicationFailed`, and it never overwrites
the commit. Destinations without signing, or with `mode: Disabled`, write
exactly the records older releases read, so mixed versions and HA failover
behave as before. Once a destination has signed history, do not roll back to
a release without signing support: the older release cannot serve or retire
those runs correctly. This release reads unknown commit kinds, versions,
fields, and signature formats as unsupported records, never as unsigned.

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
