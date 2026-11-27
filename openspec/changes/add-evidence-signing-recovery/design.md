# Design

## Context

See [proposal.md](proposal.md). The design was approved by the owner on
2026-11-18. It is a follow-up to `add-evidence-signing` and is not a 0.3.0
requirement.

The current state, from `add-evidence-signing` (archived 2026-11-14) and the
code at `e9f9b2c`:

- `AssessmentRun.status.signingIntent` is written once, before any commit. It
  records mode, destination UID and generation, `secretName`, the archive
  digest, and, after the first successful key load, a pinned `key`
  (fingerprint, algorithm, public key PEM, Secret UID/resourceVersion). CEL
  transition rules make it append-only.
- `signingRequirement` (`internal/controller/publication_signing.go`) reads
  any stored `package.sigstore.json` first and verifies it under the pinned
  public key without loading a private key. Otherwise it loads the intent's
  Secret, rejects any other fingerprint, signs the raw archive digest, and
  stores the canonical Sigstore bundle v0.3 with `If-None-Match: *` (first
  durable writer wins). Signing and upload run under the destination fence.
- The S3 publisher's commit gate commits a `SignedPublicationCommit` only
  after it re-reads and verifies the stored bundle. A conflicting commit is
  `ErrConflict`, never permission to overwrite or downgrade.
- After `PublishTimeout`, `retainAfterSigningFailure` ends the run `Failed`
  with `SigningFailed` and records `status.publication` with phase `Failed`,
  the archive digest, the pinned destination, `expiresAt` = closure + recorded
  retention, and cleanup `NotDue`. The run's retention finalizer, destination
  outstanding-package accounting, retention deletion, and orphan handoff
  treat the staged archive like a retained package.
- Downloads (`/download`, `/signature`) serve only `Completed` runs with a
  committed publication, after verifying the archive/signature pair against
  the receipt, the commit, and the run's intent.
- The S3 commit fixes `expiresAt = publishedAt + retention`, and
  `publication.Receipt` validation enforces that equality.

## Goals / Non-Goals

**Goals:** an administrator-only, attributable, auditable trigger that
finishes the publication of one retained `SigningFailed` run with the exact
staged archive and the exact original signing intent; safe convergence of
concurrent requests and leader changes; explicit terminal outcomes.

**Non-Goals:** recollecting evidence; changing completeness, outcomes,
export kind, or the run summary; extending or reviving retention; signing
with any key other than the intent's; re-signing committed or legacy unsigned
packages; automatic recovery without a request; KMS, keyless, transparency
logs, or trusted time; a new Deployment, image, Secret permission, or Helm
value.

## Decisions

### 1. A cluster-scoped request resource

Add `EvidenceSigningRequest` (`compliance.erenius.io/v1alpha1`,
cluster-scoped, plural `evidencesigningrequests`, status subresource), using
the existing API generator and CRD/chart generation.

| Field | Rules |
| --- | --- |
| `spec.run.name` | Required DNS subdomain name of an AssessmentRun. |
| `spec.run.uid` | Required UID of that run. A recreated run with the same name never matches. |
| `spec.reason` | Required, 1 to 1024 characters, not only whitespace. Free text for the audit trail. |
| `spec.expectedKeyFingerprint` | Optional `sha256:<64 hex>`. Required by the controller only when the run's intent has no pinned key (decision 4). |
| `spec.requestedBy` | `{username, uid}` written by admission (decision 2). |

The whole spec is immutable after creation (`self == oldSelf`). Status is
controller-owned:

| Status field | Content |
| --- | --- |
| `phase` | `Pending`, `Running`, `Succeeded`, `Failed`. The last two are terminal. |
| `reason`, `message` | Fixed reason vocabulary (decision 6); message bounded to the existing status message limit, never key or Secret bytes. |
| `requestedBy` | Copied from the admission-recorded spec at acceptance. |
| `run` | The observed run name and UID. |
| `keyFingerprint` | The intent key used or confirmed. Never the Secret name. |
| `publication` | On success: publication ID, package SHA-256, signature SHA-256, `publishedAt`, `expiresAt`. |
| `acceptedAt`, `startedAt`, `completedAt` | Controller times. |
| `conditions` | `Complete` (True on either terminal phase). |

CEL transition rules on status: once `phase` is terminal, status cannot
change; `requestedBy` and `run` can only go from unset to set.

On the run, add an additive, controller-owned `status.signingRecovery`:

- `active`: `{name, uid, claimedAt, deadline}` of the request currently
  holding the run (decision 5);
- `recovered`: `{name, uid, requestedBy, at}`, set once on success.

CEL makes `recovered` write-once. Runs without recovery keep their exact
status bytes.

Alternatives rejected:

- Letting administrators patch run status needs a broad status grant. It also
  leaves no dedicated record and bypasses a single enforcement point.
- An annotation on the run gives no requester attribution, reason, or
  per-attempt outcome.
- A namespaced request does not fit the cluster-scoped run and would suggest
  application-team self-service.

### 2. Admission and validation

- **CRD schema.** Required fields, formats, lengths, spec immutability, and
  the status transition rules above. Unknown fields are pruned only where the
  generator already does so; `expectedKeyFingerprint` has a strict pattern.
- **Requester attribution.** This copies `evidence-attachment-registrant`. A
  `MutatingAdmissionPolicy` on CREATE overwrites `spec.requestedBy` with
  `request.userInfo.username` and `uid`. A `ValidatingAdmissionPolicy` on
  CREATE fails closed unless the stored value equals the API server's user
  info. Both use `failurePolicy: Fail` and ship with bindings. Spec
  immutability keeps the requester from being rewritten later.
- **Controller-only status.** RBAC grants `evidencesigningrequests/status`
  writes only to the controller. As defence in depth, a
  `ValidatingAdmissionPolicy` on `evidencesigningrequests/status` UPDATE
  denies any identity other than the controller's ServiceAccount. It reads
  that identity from the existing `konstapel-assessment-admission` ConfigMap,
  the same way `assessment-run-scope` does, and fails closed when the
  ConfigMap is missing.
- **Run lookup.** Admission does not look up the run. VAP cannot fetch
  arbitrary objects. The controller checks the run and reports `RunNotFound`.

No webhook is added. The charts generate these policies like the existing
attachment and orphan policies.

### 3. Dedicated, non-aggregated roles

Follow `config/rbac/evidence-attachments.yaml`: generated ClusterRoles,
labelled `app.kubernetes.io/part-of: konstapel`, bound only by
ClusterRoleBinding to platform subjects, never aggregated into `admin`,
`edit`, or `view`, and never part of namespace roles.

| ClusterRole | Rules |
| --- | --- |
| `konstapel-evidence-signing-recoverer` | `evidencesigningrequests`: `get, list, watch, create`; `evidencesigningrequests/status`: `get` |
| `konstapel-evidence-signing-recovery-reader` | `evidencesigningrequests`, `evidencesigningrequests/status`: `get, list, watch` |

- Neither role grants `update`, `patch`, `delete`, or any status write.
  Neither grants AssessmentRun status writes, Secret access, or destination
  access. A recoverer finds failed runs through the existing
  `konstapel-assessment-operator` grant, which reads runs and their status.
- `konstapel-compliance-admin` does not gain these permissions. Recovery is a
  separate grant.
- **Controller role additions:** `evidencesigningrequests`: `get, list,
  watch`; `evidencesigningrequests/status`: `get, update, patch`. The
  controller already holds the run status, Secret `get`, and destination
  permissions it needs.
- **Retention of requests.** Requests are kept as the audit record. They have
  no owner reference to the run and are not garbage-collected with it.
  Deleting them needs a cluster-administrator grant outside these roles
  as an explicit administrator action.

### 4. Recovery reuses the original intent and nothing else

Eligibility is checked from an uncached read of the run. A request proceeds
only if all of these hold:

- the run exists with `spec.run.uid` and has no deletion timestamp;
- `retainedSigningFailure(run)` is true: phase `Failed`, publication failure
  `SigningFailed`, no commit;
- the intent's mode is `Required`;
- cleanup state is `NotDue`, and now is before `status.publication.expiresAt`;
- the pinned destination still exists with the pinned UID, and the destination
  has no accepted orphan handoff or fence.

The procedure, under the destination fence as
`run <name> signature recovery`:

1. `Publisher.Recover` returns the durable staging. A missing archive or a
   digest other than `signingIntent.archiveSHA256` is `EvidenceLost`.
   Nothing is re-staged or recollected.
2. If a signature is stored, verify it under the pinned public key and reuse
   it. No private key is loaded.
3. Otherwise, load the intent's Secret by its recorded name. Require the
   pinned fingerprint. If the intent has no pinned key, require it to equal
   `spec.expectedKeyFingerprint` (absent: `KeyConfirmationRequired`), then pin
   it with the existing write-once update. This authorizes initial key selection;
   it does not prove a previously established key identity. Sign, store with
   first-writer-wins,
   and re-read and verify the winner. This is the existing
   `signingRequirement` path.
4. Commit through the existing gate with the intent's `publication.Signing`
   and the run's recorded retention, bounded by the recorded expiry
   (decision 7).

The current destination signing policy, the current key in other Secrets, and
key rotation are ignored. A Secret holding any other fingerprint is
`KeyMismatch`. A conflicting existing commit (unsigned, other fingerprint,
other archive) is `Conflict`. Neither is ever overwritten.

### 5. One claim per run; requests converge

- **Claim.** A request claims a run by writing `status.signingRecovery.active`
  with a resourceVersion-conditional status update. A losing writer re-reads
  the run.
- **Waiting.** While another request holds the claim, the request stays
  `Pending` with reason `Waiting`.
- **Release.** On success the holder sets `recovered` and clears `active` in
  the same update that commits the run status. On a terminal failure it only
  clears `active`; waiting requests may then claim and try.
- **Late requests.** A request evaluated after `recovered` is set succeeds
  with `AlreadyRecovered` and references the same commit and signature. It
  does no storage write. Before completing, it reconciles the namespace
  AssessmentRequest projection and its own request status from the recovered run.
  This also applies to the original holder resuming after its run update.
- **Successors.** The holder's claim survives leader changes. A successor
  resumes the claimed request. Stored signatures and the conditional commit
  make retried and overlapping attempts converge on one immutable pair, as
  the existing HA and recovery contracts already require.
- **Stale claims.** A claim whose request is gone, or is already terminal, is
  cleared after a fresh read.

### 6. Bounded attempts and terminal outcomes

A claimed request retries within a deadline of claim time plus the existing
`PublishTimeout`, polling at the existing interval, with reason `Signing` or
`Committing`. At the deadline, unless durable recovery already succeeded, it fails with
`SigningFailed`. The run stays a
retained `SigningFailed` run with its original failure record, and a new
request can try again.

| Phase | Reasons |
| --- | --- |
| Pending | `Accepted`, `Waiting` |
| Running | `Signing`, `Committing` |
| Succeeded | `Recovered`, `AlreadyRecovered` |
| Failed | `RunNotFound` (absent or UID differs), `RunDeleting`, `NotRecoverable` (not a retained `SigningFailed` run with a Required intent), `Expired`, `Orphaned`, `EvidenceLost`, `KeyConfirmationRequired`, `KeyMismatch`, `SigningFailed`, `Conflict` |

Terminal requests are never re-evaluated. Nothing in this table changes the
run's evidence summary, completeness, outcomes, or export kind.

### 7. The recovered publication keeps its recorded expiry

A normal commit fixes `expiresAt = publishedAt + retention`. Applied to a
late commit, that would extend retention beyond the expiry recorded at the
signing failure. The recovered commit therefore records an explicit bound:

- **Record.** The `SignedPublicationCommit` gains an optional
  `retention.notAfter`. It is set only by recovery, to the run's recorded
  `status.publication.expiresAt`.
- **Readers.** When `notAfter` is present, the receipt's `expiresAt` is
  `notAfter`, and validation requires `notAfter <= publishedAt + duration`.
  Otherwise the existing equality holds.
- **Late commit.** A commit whose server time is at or after `notAfter` is
  `Expired` at once. It is never served, and retention deletion removes it.
  The request ends `Expired`.
- **Mixed versions.** Strict decoders already reject unknown fields as
  `ErrUnsupportedRecord`, never as unsigned. A reader without this field
  fails closed. Upgrade the controller and download server (one image)
  before creating requests.
- **Existing commit.** A matching commit that already exists (a commit whose
  response was lost before `SigningFailed`) is adopted unchanged with its own
  recorded expiry. A committed record is never rewritten.

`publishedAt` remains the storage commit time, so it truthfully shows that
publication happened late. The window, evaluation times, and summary keep
their original values, so freshness is not renewed.

### 8. Effect on the run, request, and downloads

On success, the controller makes one status update to the run:

- the committed `status.publication`, with the signature reference;
- `phase: Completed`, the `Published` condition True with reason
  `Committed`, and a message naming the recovery request;
- `signingRecovery.recovered`.

Evidence fields are untouched. A namespace run's AssessmentRequest gets the
existing sanitized `finishRequest` update (Completed, artifact reference),
with no requester details. These are separate API writes, not a transaction.
The recovered run is the durable source of truth: retries must finish the
namespace projection before marking the EvidenceSigningRequest successful.
Transient write failures requeue, including on the AlreadyRecovered path;
a missing or recreated namespace request is never recreated or overwritten.
A durable recovered record takes precedence over attempt timeout and the
retained-failure eligibility check when finishing these status writes.
Downloads then work unchanged, including pair
verification. Coverage views select runs by window closure, so an older
recovered run never displaces a newer published run.

### 9. Observability

- Recovery emits no Kubernetes Events (owner decision, 2026-11-27). This
  is a choice about the controller's Event recorder and permissions:
  Konstapel grants the controller Event writes only in its own namespace.
  EvidenceSigningRequests and AssessmentRuns are cluster-scoped, so their
  Events would need such writes outside it. Recovery is observed through
  the durable request and run status, the metrics below, and logs.
- Add one durable gauge, `konstapel_evidence_signing_recovery_requests`,
  labelled only by `phase` and `reason` (fixed vocabularies) and
  reconstructed from request records after restart, following
  `prometheus-observability`.
- The publication projection counts a retained `SigningFailed` run in
  `konstapel_publication_failed` until recovery publishes it or its expiry
  passes (owner decision, 2026-11-27). After expiry it is cleanup backlog.
  `konstapel_publication_retained_signing_failures` counts these runs, so
  the publication-failing alert subtracts them and fires only for runs that
  are retrying. Recovery moves a run from failed to published in one record
  update, without double counting.
- Logs carry run and request names but no key material.

### 10. Testing

- **Unit tests:** CRD/CEL and admission policy fixtures, eligibility, the
  claim protocol under conflicts, the fake publisher's `notAfter` handling,
  and every terminal reason.
- **Live acceptance:** in the mandatory groups, on the existing RustFS S3
  fixture, with disposable keys and pinned Cosign offline verification.
  Covers successful recovery, concurrent requests, leader loss, expiry, the
  orphan fence, a lost archive, key mismatch, RBAC denials, and forged
  attribution.
- **Network boundary:** a deterministic test rejects unexpected outbound
  requests while allowing only the required Kubernetes and S3 fixture traffic.
  It fails on attempts to contact Fulcio, Rekor, timestamp authorities, or
  other external services, and checks that the recovered key-based v0.3 bundle
  contains no certificate, log entry, or timestamp. No Sigstore stack is needed.
- **Status crash points:** live recovery injects interruption after the run
  status write and after the namespace request write, before recovery-request
  completion. Each restart converges all surviving matching records without
  re-signing or rewriting the commit, even after the attempt deadline.

## Risks / Trade-offs

- **A short remaining retention makes recovery pointless.** The bound is
  enforced, and the request reports `Expired` instead of extending retention.
- **An administrator might install a different key under the recorded Secret
  name for an unpinned intent.** `expectedKeyFingerprint` makes that choice
  explicit and attributed; it is still that Secret's key under the original
  intent.
- **A `Failed` → `Completed` run transition could surprise consumers.** Only
  the publication phase gates coverage and downloads, and closure-time
  ordering is unchanged. The transition is documented and tested.
- **Request records accumulate.** Recovery is a rare administrator action,
  and the records are the audit trail.
- **An adopted pre-existing commit keeps an expiry later than the failure
  record.** That expiry was fixed by the earlier commit and is not an
  extension by recovery. It is documented.

## Migration Plan

1. Ship the CRD, roles, admission policies, controller reconciler, and reader
   support for `retention.notAfter` in one release, with the charts.
2. Existing retained `SigningFailed` runs become recoverable after upgrade,
   until their recorded expiry. Nothing changes for any run without a request.
3. Rollback: retire unprocessed requests first. A release without
   `notAfter` support fails closed on recovered commits. Do not roll back
   while recovered publications are retained, as with signed history today.

## Confirmed decisions

The owner confirmed these review recommendations on 2026-11-18:

1. Successful recovery moves the run and its matching namespace request to
   `Completed`, preserving assessment results and original assessment times.
2. Unpinned intents are recoverable with explicit `expectedKeyFingerprint`.
   This authorizes initial key selection, not restoration of a known old key.
3. Recovery requests outlive their run without an owner reference. Deletion
   requires an explicit cluster-administrator action outside the recovery roles.
