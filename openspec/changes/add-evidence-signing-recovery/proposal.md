# Proposal

## Why

A run whose Required signing intent is not satisfied within the publication
timeout ends with `SigningFailed`. Its staged archive, any stored signature,
and its signing intent are retained until the run's retention expiry so that
"an authorized recovery can re-sign the same archive"
(`evidence-signing`, *Retained signing failures share the package lifecycle*).
No such recovery exists yet: once the key problem is fixed, an administrator
cannot finish the publication, and the retained evidence simply expires.

Letting administrators edit run status would be the wrong tool. It needs a
broad grant to rewrite protected status, leaves no dedicated audit record, and
gives no single place to enforce "same archive, same intent, same key".

## Status: owner-approved follow-up, not a 0.3.0 requirement

- The owner approved this design on 2026-11-18. The artifacts follow that
  decision and do not reopen it.
- This is a follow-up to `add-evidence-signing`. It is **not** a 0.3.0
  requirement or release blocker. Evidence signing is already part of the
  0.3.0 release line without a recovery trigger; until this change ships,
  retained `SigningFailed` evidence stays retained and expires as documented.

## What Changes

- Add an administrator-only, cluster-scoped `EvidenceSigningRequest` in
  `compliance.erenius.io/v1alpha1`. Its immutable spec names one
  AssessmentRun by name and UID and carries a required reason. Admission
  records the authenticated requester; status is controller-owned only.
- The controller retries signing and publication of the run's **existing**
  retained archive under its **original** signing intent. It reuses a stored
  signature, otherwise signs with the intent's pinned key, and commits through
  the existing gated, conditional publication protocol.
- Recovery never recollects evidence, changes completeness or outcomes,
  extends expiry, or substitutes a key. The recovered publication keeps the
  expiry recorded at the signing failure (closure plus recorded retention).
- Concurrent requests for one run converge on one signature and one commit.
  Expired, deleted, orphaned, lost, or otherwise unrecoverable evidence ends
  the request with an explicit terminal outcome; nothing is revived.
- Add two non-aggregated ClusterRoles (requester and audit reader), admission
  policies for requester attribution, CRD validation, controller RBAC, chart
  wiring, documentation, and live acceptance against the RustFS fixture.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `evidence-signing`: adds the recovery request API, its authorization and
  attribution, the recovery contract, convergence, terminal outcomes, and
  acceptance evidence.
- `assessment-evidence`: the per-binding retention requirement states that a
  publication recovered after a signing failure keeps the expiry recorded at
  that failure instead of measuring a new one from the recovered commit.

## Impact

- API: new `EvidenceSigningRequest` CRD (generated CRD, deep-copy, CEL rules)
  and an additive, controller-owned `AssessmentRun.status.signingRecovery`.
- Storage: a recovered signed commit records the fixed expiry bound. It is a
  versioned, strictly decoded record field; readers without it fail closed.
- RBAC/admission: two new ClusterRoles, one MutatingAdmissionPolicy and one
  ValidatingAdmissionPolicy (with bindings), and controller role additions,
  generated into the existing charts.
- Controller: a recovery reconciler in the existing manager, under leader
  election and the destination orphan fence. No new Deployment, image,
  Secret access, or Helm value.
- Download server: unchanged routes and pair verification; a recovered run
  becomes downloadable like any committed signed run.
- Docs and tests: `docs/integration/evidence-signing.md`, acceptance-group
  inventory, and an opt-in check against the isolated Sigstore test stack.

Out of scope: re-signing committed or legacy unsigned packages, signing with
any key other than the intent's, KMS/keyless signers, automatic recovery
without an administrator request, and extending or reviving retention.
