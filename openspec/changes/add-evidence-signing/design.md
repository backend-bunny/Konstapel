# Design

## Context

See [proposal.md](proposal.md) for motivation and agreed scope. The current
`internal/publication` contract separates frozen package staging from publication.
`internal/s3store/publisher.go` validates the descriptor, builds a deterministic
archive, uploads it under a run-owned attempt, and conditionally creates one
commit manifest. The commit selects an archive digest/version and fixed retention.
Its server LastModified establishes publication time; retries recover that commit.

`internal/download/server.go` authorizes each request and verifies the archive
against protected run metadata before returning its exact bytes. Neither this
path nor the package descriptor currently provides a publisher signature.
EvidenceDestination already owns central storage references, controller-namespace
Secret access, retirement, and orphan fences, making it the signing-policy owner.

Devbox pins Cosign 3.1.3. Its inspected `sign-blob` and `verify-blob` interfaces
support key-based Sigstore bundles and explicit public-key verification. That
interface inspection is not an interoperability test; implementation must prove
the selected bundle/library version works offline with the pinned CLI. Image and
OCI release signatures use separate build-time identities and do not authenticate
these runtime assessment archives.

## Goals / Non-Goals

**Goals:** Standard archive authenticity with offline public-key verification;
portable Secret-backed signing; immutable retries and rotation; reuse of current
publication, access, retention, and HA contracts.

**Non-Goals:** A new storage backend or controller manager; cryptographic algorithm
invention; automatic key issuance/rotation; retroactive signing of old packages;
upstream scanner attestation; proof of compliance or trusted execution; KMS,
keyless identity, transparency logs, or trusted timestamps in this first version.

## Decisions

### 1. Put signing policy on EvidenceDestination

Add `spec.signing.mode: Disabled | Required`, default Disabled, with a
`secretRef.name` required only for Required. References resolve only in the
controller namespace using the existing reference conventions. Reject a signer
reference with Disabled, absent references with Required, unsupported signer
kinds, and explicit cross-namespace selection. Do not add binding/request overrides
or credentials to policy bundles. Legacy file destinations remain unsigned until
explicitly migrated to a configured EvidenceDestination.

Add a bounded signing-readiness condition and observed key fingerprint. Required
signer failure prevents readiness for new publications but does not disable
historical downloads, retention, policy enforcement, or unrelated destinations.
Readiness is advisory; the publication path revalidates the authoritative policy
and actual Secret before recording its intent. Secret changes are picked up by
bounded re-reads rather than a Secret watch, and an observation is never
treated as signing authorization.

Implemented (group 2): `spec.signing` is optional and has no default, so
destinations without it keep their exact spec and status. Inside it, `mode`
defaults to Disabled, and `secretRef` reuses the controller-namespace reference
type, whose `namespace` field is rejected. CEL rules reject Required without a
reference and a reference with Disabled. `kms` and `keyless` are schemaless
placeholder fields that are always rejected, so these requests fail with an
explicit message instead of being pruned silently. Status adds `signing`
(mode, Secret name, key fingerprint, algorithm) and a `SigningReady` condition
with a fixed reason set. Both appear only when `spec.signing` is set, and
neither touches `Ready`.

The controller reads the Secret with its existing uncached, namespace-scoped
`get` by name. It does not add a Secret watch, because that would need Secret
`list`/`watch` in the controller namespace, broader than today's boundary. A
change to the destination reconciles immediately. While SigningReady is
False, the key is re-read every 30 seconds, otherwise with the 5-minute
destination probe. An unchanged Secret (same UID and resourceVersion) is not
decrypted again; the memo holds only public results. Private key and password
bytes from the read are cleared after loading. Readiness stays advisory;
publication intent preparation (group 3) rereads the policy and the Secret.

Alternative: putting key references on each binding duplicates security settings
and allows storage peers to diverge without a clear central ownership boundary.

### 2. Use operator-provided Cosign keys through Go libraries

V1 supports ECDSA P-256 with SHA-256, using the standard Cosign key encoding and
Sigstore message-signature bundle representation. The Secret contains
`cosign.key`, `cosign.pub`, and `cosign.password`; require the password entry even
when its value is empty. Load/decrypt with maintained library code, derive the
public key, and require equality with the supplied public key. Unsupported key
types fail explicitly. Identify the key by SHA-256 of DER SubjectPublicKeyInfo,
not by Secret name, certificate subject text, or an arbitrary caller key ID.

Use a small signer interface that returns public identity and a verified signature
for the supplied archive digest under a fixed algorithm. Implement only a
Secret-backed adapter. The artifact digest must represent the archive bytes as
Cosign expects, not the textual hex digest accidentally hashed again. Use a
standard Sigstore bundle version supported by the pinned verifier; pin and test
the exact library/schema compatibility in implementation.

Implemented contract (`internal/evidencesign`, group 1): the signer interface
takes a raw 32-byte archive SHA-256 (never hex text) and returns the bundle,
its digest, media type, algorithm `ecdsa-sha2-256-nistp256`, and key fingerprint
`sha256:<hex of DER SPKI>`. The Secret adapter decrypts with the same
securesystemslib `encrypted` package Cosign uses (both `ENCRYPTED SIGSTORE` and
`ENCRYPTED COSIGN` PEM types), takes the password byte for byte, and signs via
sigstore's ECDSA signer over that digest. The bundle is Sigstore bundle v0.3
(`messageSignature` plus Cosign's public-key hint, base64 SHA-256 of the DER
key) with no certificate, log entry, or timestamp. Konstapel writes one
canonical JSON form; its internal verifier accepts only that form, requires
the hint to name the caller's trusted key, then verifies with sigstore-go.
Cosign-written bundles differ only in protojson spacing and are an auditor
concern, not a stored input. Pinned and interoperability-tested with Devbox
Cosign v3.1.3, sigstore-go v1.3.0, sigstore v1.10.8, and securesystemslib
v0.11.0; these were already controller dependencies, so no module was added.

Use direct controller-namespace Secret reads with bounded memory lifetime; avoid
cluster-wide private-key caches and persistent private-key copies. Grant only
necessary namespace-scoped read access (by-name `get`, no Secret list or watch),
and keep key/password values out of logs, errors, traces, status, disk staging,
metrics, and subprocess arguments. The controller does not execute Cosign, fetch
an arbitrary key URL, use ambient signing identity, or add a signing CLI to its
image. Devbox Cosign is an operator/test verification tool.

Operators generate and install keys and distribute trusted public keys separately.
Reading a Kubernetes Secret is part of the controller's existing trust boundary;
encryption at rest and access control remain platform responsibilities.

Alternative: mandatory external signing would add a service dependency to v1.
Invoking a CLI at runtime would expand the image and complicate credential handling.

### 3. Sign the frozen archive and keep verification material detached

Sign the exact deterministic `package.tar.gz` already produced by staging. Its
descriptor binds run, binding, cluster, namespace scope, revisions, and the file
inventory. Validate scope and file closure before signing. Complete, incomplete,
and diagnostic packages follow the same path; evidence meanings never influence
whether the required signature is produced.

Store `package.sigstore.json` beside the archive as a run-owned object, with its
digest, size, version, algorithm, and key fingerprint recorded in the publication
commit and protected receipt. Retain the public key needed for internal validation
in bounded public verification metadata bound to that receipt. The standard
bundle's key hint is an identifier, not an external trust root. Keep the existing
archive's byte representation and descriptor digest unchanged.

This avoids a self-reference: a signature of an archive cannot be inserted into
that same archive without changing its digest. It also preserves existing archive
readers. Clients download the archive and companion bundle together as two files.
The signature covers the archive's embedded identities and recorded assessment
timestamps; it does not independently attest the storage server's commit time,
retention, or the real-world truth of producer/scanner claims. Transport headers
and publication receipts remain distinct from cryptographically signed content.

Alternative: wrapping the archive and signature in a new outer archive would
change the existing download representation and require every reader to unwrap
another format. Signing only OSCAL would omit raw evidence and acceptance history.

### 4. Freeze signing intent before committing publication

Keep destination selection pinned at run startup as today. For that pinned
destination, select signing policy from an authoritative read when preparing the
first durable publication intent, after the archive is staged and verified.
Persist mode, destination UID/configuration revision, key reference, public-key
fingerprint/material, algorithm, and archive digest. Record observed Secret
UID/resourceVersion as provenance, never private bytes. Protect intent with the
same concurrency and ownership discipline as destination and retention records.

Once intent exists, changing Required to Disabled or rotating the current key
does not alter it. A disabled intent prepared earlier remains explicitly unsigned;
an archive merely staged earlier uses the policy current at preparation. A failed
key load cannot manufacture a disabled intent. Configuration-only changes do not
rotate engine policies or accepted-risk identities.

For Required, sign and locally verify the frozen archive, durably store verified
signature material, then conditionally commit references to both objects. The
commit is the only success boundary. Keep one durable winning signing record per
intent so retries reuse recorded signature bytes; do not assume ECDSA is
deterministic. Concurrent valid attempts select one immutable pair, and losers
remain owned cleanup work. A conflicting key, archive, or policy identity is an
error, not permission to overwrite or publish under another run key.

Recover durable signatures before loading private keys. Once the signature is
stored and verified, completing a commit or recovering a lost response needs only
public material. Before that point, the Secret must still yield the pinned
cryptographic key; missing or changed keys produce bounded publication failure.
Re-encrypting the same private key does not change its identity. A substituted key
under the same Secret name cannot satisfy an old intent.

Reuse existing timeout, retry, and terminal-run rules so signing outages do not
hold a binding's active slot indefinitely. Preserve staged evidence for authorized
recovery; if capture is actually lost use CaptureLost. Never recollect newer
observations under the same frozen identity or report signing failure as compliance
failure. Retention and publishedAt continue using the existing commit rules.

Implemented (group 3, pending owner confirmation): a `SigningFailed` run keeps
its staged archive and any stored signature, tied to its own lifecycle.
`status.publication` records phase `Failed`, the failure, the archive digest,
and `expiresAt` = closure + the run's recorded retention. Terminal
abandoned-attempt cleanup skips it. Deleting the run record waits for
`expiresAt` (retention finalizer). The destination counts it as an
outstanding package. At expiry the publisher's retention deletion removes the
run's objects, and an orphan handoff hands it off like any retained package.
The archived S3 contract does not cover this case: its abandoned-attempt
cleanup applies to uncommitted attempts in general. The evidence-signing
delta states the rule. A trigger to re-sign a retained failure is a
follow-up.

Alternative: signing after commit creates downloadable unsigned windows. Reading
the latest key on every retry makes publication history depend on retry timing.

### 4a. Durable record names and versions (group 3 proposal)

The names follow the existing patterns. Kubernetes status is additive
`compliance.erenius.io/v1alpha1` fields. S3 records are JSON documents carrying
`apiVersion` and `kind`, like the commit manifest (`PublicationCommit`) and the
package descriptor. Each new field is optional with `omitempty`, so an
unsigned publication writes exactly the bytes it writes today: the commit
manifest, the receipt, the publication status, and its
`AssessmentRun.status.publication` form, checked against goldens captured
before the change. The only addition to an unsigned run is
`status.signingIntent` with `mode: Disabled`. It records that the run was
prepared unsigned, so a later Required policy cannot apply retroactively.
Runs prepared before this change have no intent and stay unsigned.

| Record | Unsigned (unchanged) | Signed (new) |
| --- | --- | --- |
| S3 commit `<run>/commit.json` | `kind: PublicationCommit` with top-level `run`, digests, archive reference, and retention | `kind: SignedPublicationCommit`, same `apiVersion`. `publicationID` and `retention` stay top-level; `subject` holds run, descriptor, archive key/version, package digest, and size; `signature` holds `format: sigstore-bundle-v0.3`, media type, object key/version, SHA-256, size, algorithm, key fingerprint, and public key PEM. |
| S3 signature `<run>/package.sigstore.json` | absent | The canonical bundle, created once with `If-None-Match: *` and SHA-256 verified like the archive. The first durable writer wins. |
| `AssessmentRun.status.signingIntent` | `mode: Disabled` plus destination UID/generation and the archive digest | `mode: Required` plus `secretRef.name`. `key` {fingerprint, algorithm, publicKey PEM, secretUID, secretResourceVersion, pinnedAt} is set once at the first successful key load. |
| `AssessmentRun.status.publication.signature` | absent | {key, versionID, sha256, size, mediaType, algorithm, keyFingerprint} copied from the signed commit |
| `publication.Receipt` / `Status` | unchanged | optional `Signature` reference |
| owned-object role | `archive`, `manifest`, `staging` | adds `signature` |

The signed commit moves the run identity into `subject`. Releases before this
change require a top-level `run` in `commit.json`, so they treat a signed
commit as another run's record (a conflict) and fail, instead of reading it as
an unsigned publication. New readers decode both kinds strictly: unknown
fields, unknown kinds or `apiVersion`s, and unknown signature formats return
`ErrUnsupportedRecord`, which is never treated as unsigned.

`signingIntent` is written once, with a resourceVersion-conditional status
update, at the first preparation: after the archive is staged and verified,
and before any commit attempt. It is read from an uncached destination `get`
whose UID must equal the run's pin. CEL transition rules on the status forbid
removing it or changing its mode, destination, Secret reference, or archive
digest; `key` may only go from unset to set. A Required intent prepared while
its key is unavailable is still recorded without `key`, so an admin switching
to Disabled cannot downgrade it. The first successful load pins the key, and a
later load with another fingerprint is `KeyMismatch`, which is also how a
replaced same-name Secret is caught.

Commit gate (the S3 publisher and the fake implement it identically):
- **Required intent.** `Publish` requires a signature reference. It reads the
  stored signature object back and verifies it with `evidencesign.Verify`
  against the package digest and the intent's public key before the
  conditional commit; a missing or invalid signature returns
  `ErrSignatureRequired`.
- **Existing commits.** An unsigned commit under a Required intent, a signed
  commit under a Disabled intent, and a signed commit with another
  fingerprint all return `ErrConflict`. None is accepted or downgraded.
- **Run status.** While retrying, the run's Published condition says
  `SigningPending`. After the existing PublishTimeout the run fails with
  `SigningFailed`. Evidence completeness and outcomes are untouched, and the
  staged package is kept.

The signing step looks for the stored signature object before loading any
private key. A stored bundle that verifies under the intent key is reused
as is. Otherwise the step loads the intent's Secret, checks the fingerprint,
signs, stores the bundle conditionally, and re-reads the winner.

### 5. Rotate keys without rewriting history

Document versioned, preferably immutable Secrets as the normal rotation workflow:
create the next key Secret, distribute its trusted public key, then update the
destination reference. Existing intents keep their old reference/fingerprint;
new intents use the new key. Keep old private keys until no pending intent needs
them; status must make those dependencies inspectable. In-place replacement with
another key is allowed but can strand old intents and must be documented as such.

Retain public key material in publication records for internal consistency checks
and maintain operator-controlled public-key trust outside evidence for auditors.
Historical verification does not require the old Secret or private key. Ordinary
rotation does not revoke trust in previous signatures or re-sign them.

Compromise handling is separate: an auditor can remove the compromised key from
trusted verification inputs. V1 supplies no trusted timestamp or transparency
proof, so a package's claimed date cannot prove it was signed before compromise.
Do not silently grandfather signatures using that date or market this as trusted
time, tamper-proof storage, or proof of an uncompromised controller.

Alternative: retaining old private keys forever is unnecessary for verification;
discarding old public keys loses the ability to independently authenticate history.

### 6. Extend authorized downloads and explicit verification

Preserve current `/download` routes and returned archive bytes. Add companion
`/signature` routes for the same namespace-request and platform-run identities,
including the existing namespace request UID parameter. Reuse exactly the same
TokenReview/SubjectAccessReview permissions and scope, expiry, destination, and
orphan checks; no public bucket URL or separate weaker access path is introduced.

For signed publications, validate both objects' digests and association against
the protected receipt, then cryptographically verify using its pinned public
material before serving either artifact. This checks internal continuity; an
auditor still chooses its own trusted key. Current destination signing readiness
or private-key access must not gate historical reads. Return an explicit unsigned
response for legacy/Disabled publications requesting a signature, and an error
for missing material from a publication recorded as signed. Include bounded
signing mode/key-fingerprint metadata without exposing key-source Secret details
in namespace responses.

Document a workflow using a separately trusted public key and the pinned Cosign
`verify-blob --key ... --bundle ...` command. The first format has no transparency
entry; explicitly document the pinned verifier's `--insecure-ignore-tlog` setting
for this key-based, no-log contract while retaining signature and key checks.
Test with networking disabled rather than treating a CLI help example as proof.
Do not use arbitrary bundle-provided keys as trust or disable cryptographic checks.
After signature verification, existing bounded extraction, descriptor/file checks,
and expected-scope inspection still apply. No new custom crypto or verification
protocol is required.

Implemented (group 4): the companion routes are
`/v1/namespaces/<ns>/assessmentrequests/<name>/signature?uid=` and
`/v1/assessmentruns/<uid>/signature`. They ask exactly the SubjectAccessReviews
of the matching `/download` route, so no new RBAC verb or subresource is
added. For a signed publication, each route first downloads and checks the
archive, then the pair: the receipt, the stored commit, and the run's signing
intent must name the same signature object and key, and the stored bundle
must have the recorded digest and verify under the intent's retained public
key. Only then is either artifact served. A missing bundle is 503 and an
invalid one 502, and the archive is never served as unsigned. The signature
route answers an unsigned publication with 404 and `X-Konstapel-Signing:
unsigned`. Responses carry the key fingerprint, never the Secret name. The
download server reads no Secrets for this.

Alternative: requiring a live controller or current key Secret for verification
defeats evidence portability. Public keys arriving with an untrusted package alone
cannot authenticate its source.

### 7. Preserve shared lifecycle and versioned compatibility

Extend the shared publication interface, commit/receipt schema, object inventory,
and protected run status with bounded signing metadata. Version new signed records
explicitly. Old unsigned records remain readable as unsigned, and unsupported
signed schemas must fail rather than be parsed as legacy unsigned data. Existing
producer archives need no signature-specific rewrite. Migration enables signing
for future intents; it never changes historical bytes, expiry, or authenticity.

S3 retirement, normal cleanup, attempts cleanup, integrity inspection, and orphan
handoff must include signature objects and all owned versions. The orphan fence
covers signing work and signature uploads as well as archive work. Retain audit
inventory without secret bytes. Snapshot publication availability stays separate
from assessment completeness, engine readiness, and signing configuration readiness.

Coordinate these changes with `add-s3-evidence-publishing`, including its legacy
destination migration; rebase before shared API, descriptor, or schema edits. If
that change archives first, express any required changes to its durable spec as
additional deltas before implementation. Helm/RBAC, HA recovery, and observability
consume the same contracts; do not introduce another manager or retention worker.
Metrics use bounded outcomes/reasons, not per-key, run, or package labels.

### 8. Require interoperability and live publication tests

Use disposable generated keys only in test-owned temporary storage. Unit tests
cover key parsing, wrong password/key, malformed bundles, byte tampering, unsigned
downgrade attempts, mode validation, and exact digest semantics. Interoperability
tests use the pinned Cosign binary for signatures produced by Go and exercise
offline verification without any signing service.

Add real API/S3 tests to the existing mandatory acceptance-group manifest, normally
the storage group, and reuse its isolated backend/cluster. Test Required and
Disabled destinations, namespace authorization, complete/incomplete/diagnostic
archives, rotation during publication, removed keys, interrupted signature writes,
lost commit responses, concurrent attempts, tampering, retirement, orphaning,
and legacy unsigned reads. Coordinate HA-specific cases with the availability
owner. Keep stage logs on stdout and in artifacts, redact private material, and
clean up keys, Secrets, clusters, and test-owned objects. Do not add a Taskfile
wrapper for every helper. Packaging validation must cover any new Go crypto
dependencies and preserve the image's existing SBOM/license/attestation workflows.

## Risks / Trade-offs

- Secret-backed keys share the controller's access boundary → restricted namespace
  access, no private material in evidence, operator-managed rotation; remote keys
  remain an explicit follow-up.
- Cosign bundle defaults may assume online services → pin a key-based no-log
  contract and prove it with network-disabled interoperability tests.
- Lost or replaced keys strand unsigned pending intents → versioned Secrets,
  visible dependencies, bounded failure, and reuse of durable signature material.
- Signature and archive are separate objects → atomic publication references both,
  and downloads verify the committed pair before exposing bytes.
- Historical authenticity depends on verifier trust → retain and distribute public
  keys independently; document compromise and trusted-time limitations.

## Migration Plan

1. Extend shared APIs/receipts and deploy compatible readers while signing remains
   Disabled. Keep current unsigned packages and download representation unchanged.
2. Operators provision a Secret and distribute its public key. Enable Required on
   one destination, inspect readiness, publish a test package, and verify offline.
3. Roll out to other destinations. Rotate using overlapping Secrets and retained
   public trust. Old unsigned evidence stays labelled unsigned.
4. Rollback can disable new signing intents, but existing Required intents still
   need their pinned signer or durable signature. Keep compatible readers and CRD
   fields while signed history exists; do not downgrade a reader that would ignore
   signed metadata or lose signature cleanup obligations.

## Deferred Follow-up

### Remote signing keys

Add remotely owned signing keys through OpenBao/Vault Transit and AWS KMS in a
separate change. Reuse the signer and artifact/verification contracts; design
provider authentication, immutable remote key versions, timeouts, rotation, and
service-outage acceptance there. Kubernetes workload identity may authenticate
access to those services, but the persistent remote key still signs the evidence;
this is distinct from Fulcio-based keyless signing.

### Kubernetes identity and keyless signing

Explore an optional Sigstore keyless signer in a separate change, especially for
organisations that already operate compatible signing infrastructure. Keep
Secret-backed signing as the portable v1 implementation; deploying Fulcio or
trusting a public signing service is not a prerequisite for Konstapel.

The prospective flow is:

1. Mount a short-lived, projected Kubernetes service-account token with the
   audience expected by the configured Fulcio service, normally `sigstore`.
2. Generate an ephemeral signing key in memory and present the token plus proof
   of possession of that key to Fulcio.
3. Fulcio validates the token's issuer, audience, expiry, and signature through
   the trusted issuer's discovery/JWKS, then issues a short-lived certificate
   binding the public key to the workload identity.
4. Sign the frozen archive with the ephemeral private key and durably retain the
   signature, certificate chain, and verification proof before committing the
   publication. Discard the ephemeral private key after use; never retain the
   bearer token with the evidence.

The JWT authenticates the certificate request; it is not the evidence-signing
key. Neither the API server's service-account signing keys nor its token-issuance
API become a general-purpose evidence signer. Use maintained Sigstore libraries
through the signer boundary rather than a runtime CLI or custom JWT crypto.

Fulcio must explicitly trust the cluster's issuer and be able to validate its
tokens. Public Sigstore does not automatically trust arbitrary self-hosted
clusters. Upstream Fulcio configuration includes EKS, AKS, and GKE issuer
patterns; validate compatibility for the actual deployment. A self-hosted cluster
needs a suitable Fulcio trust configuration or federation into a supported trusted
issuer, not merely a token with the right audience. Verifiers must independently
trust the certificate authority and constrain both the identity issuer and the
expected namespace/service-account identity; names alone are not unique across
clusters.

Long-lived evidence needs retained certificate and trusted-time verification
material that establishes signing within the certificate's validity period,
such as authenticated transparency-log evidence or a trusted timestamp. Specify
and test the chosen Sigstore bundle and offline trust inputs in that follow-up;
certificate expiry alone must not make valid historical evidence unverifiable.
Define service ownership, trust-root distribution/rotation, log visibility, and
outage behaviour before selecting public or private infrastructure. Publishing
to a public transparency log must be an explicit operator decision, accounting
for disclosure of signing identity and artifact digest metadata.

That change must adapt durable signing intent and restart recovery to ephemeral
keys and certificate renewal; v1's pinned persistent-key contract cannot simply
be assumed to work unchanged. Preserve exact frozen bytes, Required publication
gating, reuse of durable signatures, and immutable committed history. No implicit
fallback to a Secret key or unsigned publication is allowed. Token projection,
Fulcio integration, remote signers, and their service-dependent tests remain
outside this change's implementation checklist.

References: [Fulcio OIDC and Kubernetes token requirements](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md#kubernetes)
and [upstream issuer configuration](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml).
