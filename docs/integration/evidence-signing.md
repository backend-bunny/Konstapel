# Evidence signing

`add-evidence-signing` lets an auditor who receives an evidence package outside
the cluster check that it was published by a key they trust. This guide covers
the parts implemented so far:
- the signing and verification contract;
- the destination's signing policy, its key Secret, and the controller's
  signing readiness status;
- [signed publication](#signed-publication): the frozen signing intent, signing
  and storing the signature, and the commit gate that never publishes unsigned
  evidence under `mode: Required`;
- [signature downloads](#download-a-signed-package): authorized download of the
  signature beside the archive, served only after the pair verifies;
- [key rotation](#rotate-a-signing-key), [the signature
  lifecycle](#signature-lifecycle), [migration, rollback, and trust
  withdrawal](#migration-rollback-and-trust-withdrawal), and the [status and
  deployment contract](#status-observability-and-deployment).

**Not implemented yet:** a trigger to re-sign a run that ended with
`SigningFailed`. Its evidence is retained (see [failure and recovery
states](#publication-failure-and-recovery-states)). The re-sign is planned
as its own platform-administrator action, and its API shape still needs an
owner decision.

Remaining work is tracked in the change's
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

To change keys later, see [rotate a signing key](#rotate-a-signing-key).

### Rotate a signing key

Use versioned, immutable Secrets: each key pair gets a new Secret name, as
`cosign generate-key-pair k8s://` creates them. To rotate:

1. Create the next Secret, for example
   `cosign generate-key-pair k8s://konstapel-system/konstapel-evidence-signing-2027-05`.
2. Give its `cosign.pub` to auditors and add it to their trusted keys. Keep the
   previous public key trusted as well: it verifies everything signed before.
3. Change the destination's `secretRef` to the new name. Runs prepared from
   now on use the new key.
4. Wait until the old key is no longer a dependency, then delete the old
   Secret.

Each run waiting to be signed pinned its Secret name, and usually its key,
when its signing intent was recorded. The destination lists what those
runs still need, whatever its current `spec.signing` says:

```sh
kubectl get evidencedestination primary -o jsonpath='{.status.pendingSigningKeys}'
```

Each entry has `secretName`, the pinned `keyFingerprint` (empty if the intent
was recorded while the key was unavailable), and the number of `runs`. The
list holds at most 16 entries and disappears when no run is waiting. If you
delete a Secret that is still listed, or replace its key under the same name,
those runs cannot be signed: they wait with `SigningPending` and then end with
`SigningFailed`, with their evidence retained. Nothing is published unsigned,
and no other key is substituted. Re-encrypting the same private key with a
new password is safe, because the key, not its encoding, is pinned.

A run whose signature is already stored or committed needs no private key.
Retiring a key never affects verification, downloads, or retention of
packages already signed: those use the public key retained in each run's
status.

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

### Signature lifecycle

The signature object, `package.sigstore.json` under the run's storage prefix,
belongs to its run's publication. It shares every rule that applies to the
archive:

| When | What happens to the signature |
| --- | --- |
| Integrity check (daily while retained) | The committed signature version is read back. Missing → `Unavailable`, `ObjectMissing`; different bytes → `Unavailable`, `IntegrityFailed`. The message names the signature. The receipt, expiry, and assessment summary never change. |
| Attempt cleanup (run ended without a commit) | Removed with the abandoned attempts, every version. A committed signature is kept. A `SigningFailed` run keeps its staged archive and any stored signature until its retention expires. |
| Retention expiry | Deleted with the archive and commit: every owned version under the run's prefix. Nothing outside the prefix is touched. |
| Destination retirement | The destination waits for these runs like any retained package; deleting the destination never removes them early. |
| Orphan handoff | Signing and signature uploads are fenced like any storage work. No upload starts after the fence. One in flight is cancelled, and if it does not stop in time the handoff records `run <name> signature upload` as an uncertain operation; its late response never commits. The handoff inventory records each run's signing intent (mode, Secret name, pinned public key and fingerprint) and its signature reference. It holds public material only. |

### Migration, rollback, and trust withdrawal

**Migration.**
- Upgrade the controllers first, with signing absent or `Disabled`. Until
  then the records they write are byte for byte what earlier releases wrote.
- Then enable `Required` on one destination, check `SigningReady`, publish a
  test package, and verify it offline. Then roll out to the other
  destinations.
- Packages published before signing remain unsigned and identifiable: they
  have no `status.publication.signature`, their signature route answers 404
  with `X-Konstapel-Signing: unsigned`, and an offline workflow that requires
  a signature rejects them. They are never re-signed or presented as signed,
  and their bytes, receipts, and expiry do not change.

**Rollback.** See [mixed versions and rollback](#mixed-versions-and-rollback).
- Setting a destination back to `Disabled` affects only runs prepared later.
  Runs already prepared under `Required` still need their key or their stored
  signature.
- Do not roll a controller back to a release without signing support while
  signed history exists.

**Historical public keys.**
- Each signed run keeps the public key it was signed with
  (`status.signingIntent.key.publicKey`). Konstapel uses that copy for its own
  download checks, and the orphan inventory keeps it as well.
- Auditors must keep their own trusted copies of every public key they rely
  on. A key served with a package, or read from cluster status, is not a
  trust anchor.

**Trust withdrawal after a compromise.**
- Remove the compromised key from every auditor's trusted keys. Packages
  signed with it then fail trusted verification, including ones signed
  before the compromise.
- Evidence signatures carry no trusted timestamp or transparency-log proof,
  and verification takes no time input. Konstapel's own checks refuse
  bundles that carry such claims. A date inside a package, or its
  publication time, cannot show that it was signed before the compromise.
- Rotate to a new key as above. Decide separately, outside Konstapel, whether
  to collect affected evidence again under new runs. Existing runs are never
  re-signed with another key.

### Status, observability, and deployment

Signing reports through the existing resources, with fixed vocabularies:

| Where | Field | Values |
| --- | --- | --- |
| EvidenceDestination | `status.signing`, `SigningReady` condition | the reasons in [signing readiness](#signing-readiness) |
| EvidenceDestination | `status.pendingSigningKeys` | Secret name, key fingerprint, run count (at most 16 entries) |
| AssessmentRun | `Published` condition | `SigningPending`, `SigningFailed` (beside the existing publication reasons) |
| AssessmentRun | `status.signingIntent`, `status.publication.signature` | mode `Disabled`/`Required`; public key identity; signature reference |
| AssessmentRun | `status.publication.failure.reason` | `ObjectMissing`, `IntegrityFailed`, `SigningFailed` |

These describe signing only. Evidence completeness, outcomes, and the export
kind are reported separately and never changed by signing.

Signing runs in the existing controller and destination reconcilers, and the
existing download server serves signatures. Signing adds no controller, Helm
value, image, or metric. Its permissions are the controller's existing
Secret `get` in the controller namespace and the download server's existing
reads ([who can read signing keys](#who-can-read-signing-keys)). Any metric
derived from these fields must label only by these fixed reasons and modes,
never by run, key, Secret, or package.

### Acceptance

Signing is covered by the mandatory acceptance groups, against a real API
server, the test-owned S3 service, disposable key Secrets, and the pinned
Cosign:

| Test | Group | Covers |
| --- | --- | --- |
| `TestLiveDestinationSigning` | storage | the documented key setup and destination example, admission, RBAC, and readiness |
| `TestLiveSignedEvidenceDownload` | storage | the documented download and verification commands, signature authorization, key retirement, and a replaced signature object |
| `TestLiveSignedPublicationWorkflow` | storage | full-binding and namespace packages, incomplete and diagnostic packages, rotation with a pending key dependency and a re-encrypted key, retention deletion of the signature, and an orphan handoff with its inventory. Every pair is verified offline with the trusted key and rejected with the other key. Bundles, public keys, digests, and Cosign output are kept as evidence. |
| `TestLiveHelmDurableRecovery` | availability | on the Helm-installed image, the leader is removed while its signature upload is held, and again after the signature was stored with its response lost and the private key deleted. The successor finishes the same signed publication, uploading the signature only once. |

`scripts/ci/test_acceptance.py` fails if any of these leaves its group.
Each test removes only the Secrets and objects it created.

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

## Download a signed package

The download service ([S3 evidence downloads](s3-evidence.md#downloads)) serves
each package's signature from a companion route beside the archive route:

| Archive | Signature |
| --- | --- |
| `GET /v1/namespaces/<ns>/assessmentrequests/<name>/download?uid=<request uid>` | `GET /v1/namespaces/<ns>/assessmentrequests/<name>/signature?uid=<request uid>` |
| `GET /v1/assessmentruns/<run uid>/download` | `GET /v1/assessmentruns/<run uid>/signature` |

A signature route checks exactly what its archive route checks, in the same
order:
- the same TokenReview audience;
- the same SubjectAccessReviews (`get` on `.../download`, and on the
  request or run itself);
- the same request UID, namespace UID, and scope checks;
- the same expiry (410), orphan (410), and pinned-destination rules.

There is no separate permission and no other path to the signature.

For a signed publication, the server downloads and checks both artifacts
before it sends a byte of either:
1. **The archive** has its recorded size and SHA-256.
2. **The records agree.**
   - The run's protected receipt (`status.publication.signature`) and the
     stored commit name the same signature object, digest, size, and key.
   - The run's frozen signing intent pinned that same key, for that same
     archive.
3. **The stored bundle** has the recorded digest and size, and it verifies for
   the archive under the public key retained in the intent.

The current signing Secret, the private key, and the destination's signing
readiness are never consulted. Historical packages stay downloadable after
their key is retired. If anything fails, neither artifact is served:
- a missing signature is 503, and the archive is never served as an unsigned
  replacement;
- a mismatched or invalid one is 502.

Both responses carry `X-Konstapel-Signing: signed`, the key fingerprint
(`X-Konstapel-Signing-Key`), and the signature digest. They never name the
key's Secret. An unsigned publication's archive is served as before, with
`X-Konstapel-Signing: unsigned`, and its signature route answers 404 with the
same header: the package has no signature.

The verification above only proves that storage still matches what
Konstapel recorded. Trust comes from your own check with a key you
already trust.

Download and verify a signed package:

```sh
TOKEN=$(kubectl create token ci-reader -n dev --audience konstapel-download)
REQUEST_UID=$(kubectl get assessmentrequest nightly -n dev -o jsonpath='{.metadata.uid}')
curl --fail --cacert ca.crt -H "Authorization: Bearer $TOKEN" -o package.tar.gz "https://download.example.internal/v1/namespaces/dev/assessmentrequests/nightly/download?uid=$REQUEST_UID"
curl --fail --cacert ca.crt -H "Authorization: Bearer $TOKEN" -o package.sigstore.json "https://download.example.internal/v1/namespaces/dev/assessmentrequests/nightly/signature?uid=$REQUEST_UID"
cosign verify-blob --key trusted.pub --bundle package.sigstore.json --insecure-ignore-tlog=true package.tar.gz
```

`trusted.pub` is the public key your platform gave you through a channel you
already trust, as in [set up signing](#set-up-signing-for-a-destination). It is
not anything served with the package. A platform operator does the same with
the run routes.

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
