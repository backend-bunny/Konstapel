# Self-service policy exceptions

Status: **not enabled.** This page tracks the work under the
`add-self-service-policy-exceptions` change. Native Kyverno exception support
stays disabled for Konstapel until the engine expiry gate below passes (design
§5).

## ComplianceException API

`ComplianceException` (`compliance.erenius.io/v1alpha1`, namespaced, short
name `cexc`) records one acceptance of risk for one logical policy in its own
namespace. The CRD itself enforces these rules
(`api/v1alpha1/complianceexception_types.go`):

| Field | Rule |
| --- | --- |
| `spec.policy` | Logical policy name, as in `ComplianceProfile` `spec.policies[].name`. Immutable. |
| `spec.workloadSelector` | Required standard label selector. Missing or `null` is rejected. `{}` selects every applicable workload in the namespace. Immutable. |
| `spec.reason` | Required. Blank or whitespace-only values are rejected. |
| `spec.expiresAt` | Required RFC 3339 time. |
| `spec.acceptanceRevision` | `1` at creation. A renewal increments it by exactly one. |
| `spec.revoked` | Optional, default `false`. `true` revokes the current acceptance revision ([Revocation](#revocation)). A new acceptance starts with `false`, and only a renewal sets it back to `false`. |

`reason` and `expiresAt` can change only together with a renewal (the
revision +1). Metadata edits do not renew, and a revision never skips or goes
back. Revocation changes neither field. A selector has no namespace field, so
scope cannot reach another namespace. Widening the scope means creating a new
resource. Resources stored before `spec.revoked` existed read as `false`, so
the field neither revokes nor renews them.

Admission (below) records authenticated attribution for acceptances and
revocations, and enforces eligibility and lifetime limits. Status is
controller-only (see Access control). The resource has no effect on workloads
yet: native exception enablement is blocked (see the engine gates below), so
Konstapel grants nothing for it.

## Access control

| Identity | Access |
| --- | --- |
| Application team: ClusterRole `konstapel-exception-editor` (`config/rbac/exception-editor.yaml`), bound with a **RoleBinding in the team's namespace** | get, list, watch, create, update, patch and delete on `complianceexceptions` in that namespace; read-only status. Nothing else. |
| Konstapel controller: generated `konstapel-controller` ClusterRole | Reads exceptions; the only identity that writes `complianceexceptions/status`. It cannot create, update, patch or delete an exception. |
| Konstapel controller, only with [revocation processing](#revocation-processing): gated ClusterRole `konstapel-controller-exception-revocation` (`config/rbac/controller/exception-revocation.yaml`) | `update`/`patch` on `complianceexceptions`, only to release the revocation finalizer once the revocation is recorded independently ([Revocation records](#revocation-records)); `create` on `selfsubjectreviews` to learn its identity; `get` on the two `konstapel-exception-acceptance` webhook configurations. The validating webhook rejects any other change it sends, so it cannot accept, renew, revoke or reactivate one. Not part of the default installation, and the chart refuses to render it. |
| Platform administrators: `konstapel-compliance-admin` | Central profiles and bindings. Does not write exceptions on a team's behalf. |

The editor role is not aggregated into the built-in `admin`/`edit` roles:
namespace edit rights alone do not grant authority to accept risk. It grants
nothing outside `complianceexceptions`. In particular it gives no access to
profiles, bindings, the protected `konstapel-system` namespace where
acceptance snapshots are stored, or native Kyverno
`PolicyException`s. The protected acceptance and revocation records are
enforced by admission, not RBAC (see below).

`api/v1alpha1/exception_rbac_test.go` checks every shipped role. The live
admission test confirms these as denied for a team member:
- creating an exception in another team's namespace
- writing exception status
- creating profiles or bindings
- writing in `konstapel-system`
- creating a native `PolicyException`

It also confirms that the controller identity can write status. Without the
gated grant, `TestLiveRevocationHistory` confirms the controller identity
cannot release the finalizer or edit an exception (RBAC).

## Acceptance admission

Two Konstapel webhooks (`config/webhook/exceptions.yaml`) authenticate every
acceptance. The controller serves both on every replica when it is started with
`--webhook-cert-dir` (a directory holding `tls.crt` and `tls.key`;
`--webhook-port`, default 9443). The deployment provides the
`konstapel-system/konstapel-webhook` Service and the `caBundle`: by default
cert-manager, otherwise an operator-managed CA (add-helm-oci-distribution).
Both webhooks use `failurePolicy: Fail` and `sideEffects: None`.

On **creation** and on an **explicit renewal** (`spec.acceptanceRevision` + 1),
the mutating webhook writes the protected annotation
`compliance.erenius.io/acceptance`. Any value the caller supplied is
overwritten. The annotation holds:

| Field | Source |
| --- | --- |
| `revision` | `spec.acceptanceRevision` |
| `acceptedAt` | the webhook's clock, in UTC seconds |
| `actor` | the request's authenticated `userInfo`: username, UID, groups |
| `claim` | the caller-owned `compliance.erenius.io/claimed-by` annotation, unverified |
| `cluster`, `namespace` | the cluster identity, and the namespace name and UID |
| `policy` | `spec.policy` |
| `eligibility` | the targeting resolver's effective eligibility for the policy in this namespace: the complete contribution set with each `Contribution.Revision`, the shortest `maxLifetime`, and any resolution errors. Always present: an acceptance that no binding applies to is rejected. |

The webhook resolves against live profiles and bindings through the API
server, not a cache. If the namespace or the configuration cannot be read,
the operation is rejected.

The validating webhook rejects any record that does not belong to the
operation:

- On an acceptance, the record must name the authenticated caller (username,
  UID and groups), the requested revision, this cluster, namespace, policy and
  claim, and a time within two minutes of the webhook's clock.
- On any other update, such as a label edit or a GitOps re-apply, the record
  must be unchanged. A metadata edit therefore never renews, and configuration
  that changes after acceptance never replaces the accepted set. Only a
  renewal records a new set.

A GitOps controller's service account is the authenticated actor. A commit
author or ticket belongs in `claimed-by`, which is kept as an unverified
claim. Dry-run requests get the record they would store, and admission only
reads the cluster.

### Eligibility and lifetime checks

An acceptance (creation or renewal) is admitted only if every check below
passes. The time used is the acceptance time, so a renewal is measured from
the renewal, not from the original acceptance:

| Reason | Rejected when |
| --- | --- |
| `UnknownPolicy` | No binding applies the policy in this namespace. |
| `Unresolved` | A binding that targets the namespace failed to resolve, for example `ContentUnavailable` or an unknown policy. Unresolved configuration never grants permission. |
| `Forbidden` | Any applicable contribution is `Forbidden`, even in `Audit` mode or alongside a permissive binding. The message names the restricting ComplianceBinding(s). |
| `ExpiryElapsed` | `expiresAt` is not after the acceptance time. |
| `LifetimeExceeded` | `expiresAt` is later than the acceptance time plus the **shortest** `maxLifetime` across every applicable contribution. |

The admission message starts with the reason, for example
`Forbidden: policy "disallow-privileged-containers" does not permit
self-service exceptions in namespace "shop-prod"; restricted by
ComplianceBinding "pci"`. The validating webhook re-checks these rules
against the stored record. Metadata edits are not acceptances and are not
re-checked. Withdrawal after central eligibility changes is the controller's
job (task 4.3).

`TestLiveExceptionAdmission` (`internal/controller`, `live` tag) runs these
webhooks against a real API server. The manager runs in-process with a test
CA, and requests are made as impersonated users (alice, bob, an Argo CD
service account). It checks forged attribution, dry run, GitOps claims,
renewal, an over-limit expiry, a `Forbidden` overlap on creation and renewal,
a metadata edit after the binding is deleted, a tampered record, and a renewal
once no binding applies. `TestLiveExceptionRevocation` covers
[revocation](#revocation) and the [documented workflows](#working-with-an-exception),
and `TestLiveReplicaAdmission` covers revocation through either replica and
across failover. The assessments group of `task acceptance` runs all three.
Run them against a cluster created by `scripts/environment.sh`:

```sh
devbox run -- scripts/exception-admission-live.sh konstapel-assessment-<name> /tmp/konstapel-exc-adm
```

The script runs the compiled test in a container on the kind network, so the
API server can reach the webhook even when a host firewall blocks
container-to-host traffic.

## Revocation

A team revokes an acceptance by setting `spec.revoked: true` at the current
`acceptanceRevision`, with `reason` and `expiresAt` unchanged. The resource
stays, with its acceptance record and snapshots, and no approval or native
Kyverno write is involved. The CRD rules and both webhooks allow only these
transitions:

| Operation | Request | Result |
| --- | --- | --- |
| Create | revision 1, `revoked` omitted or `false` | An acceptance (above). |
| Create | `revoked: true` | Rejected: `InvalidRevocationTransition`. |
| Revoke | same revision, `false` to `true` | Admitted. Admission adds the revocation record and finalizer; eligibility and expiry are not checked. |
| Repeat revoke | same revision, `true` to `true` | Admitted. The first record is kept. |
| Reactivate | same revision, `true` to `false`, including an update that omits `revoked` | Rejected: `RenewalRequired`. |
| Renew | revision + 1, `revoked` stays `false` | An acceptance (above). |
| Renew a revoked revision | revision + 1, `true` to `false` | An acceptance (above), once the revocation is recorded independently; until then `RevocationHistoryPending` ([Revocation records](#revocation-records)). The renewal removes the revocation annotation from the resource. Without [revocation processing](#revocation-processing) it is always rejected. |
| Renew and revoke together | revision + 1 with `revoked: true` | Rejected: `InvalidRevocationTransition`. |

Admission messages start with the reason, as acceptance denials do. Metadata
edits and controller reconciliation cannot change `revoked`.

### Revocation record

On the `false` to `true` update, the mutating webhook writes the protected
annotation `compliance.erenius.io/revocation`. Any value the caller supplied
is overwritten. The annotation holds:

| Field | Source |
| --- | --- |
| `exceptionUID` | the UID of the stored resource |
| `revision` | the revoked `spec.acceptanceRevision` |
| `requestedAt` | the webhook's clock at the request, in UTC seconds. It records when revocation was requested, not when an engine stopped granting. |
| `actor` | the request's authenticated `userInfo`: username, UID, groups |
| `claim` | the `compliance.erenius.io/claimed-by` value in the revoking request, unverified |

In the same write it adds the finalizer
`compliance.erenius.io/revocation-history`. The record sits next to the
acceptance record and changes nothing in it: the accepting actor, reason,
expiry and snapshot stay as accepted. With
[revocation processing](#revocation-processing), the controller then copies
the record into an independent [revocation record](#revocation-records) and
releases the finalizer. Without it, which is the default, the finalizer stays.

The validating webhook checks that the record belongs to the request: the
authenticated caller, the stored UID, the current revision, the claim, a time
within two minutes of its clock, and the finalizer. On every other create or
update, the record and the finalizer must be exactly as stored:

- a creation carries neither;
- no edit adds, rewrites or removes either, except as below;
- a repeated revocation keeps the first actor and time;
- a GitOps re-apply that drops the annotation is rejected, like one that drops
  the acceptance record.

Two operations may remove them, and only after the independent record is
durable and matches the annotation: the controller identity releases the
finalizer, and a renewal of the revoked revision removes the annotation
(once the finalizer is gone).

Revocation reads nothing from the cluster once the webhook knows the
controller identity (with revocation processing; without it there is none
to know). It resolves no eligibility and
does not need a future `expiresAt`, so an expired acceptance, a policy that
is now `Forbidden` and one whose configuration cannot be resolved can all be
revoked. It still needs the webhooks: while admission is unavailable the
update fails (`failurePolicy: Fail`) and nothing is recorded. A dry run
returns the record and finalizer it would store, and stores nothing.

A GitOps service account that revokes is the recorded actor. A commit author
or ticket belongs in `claimed-by`, which is kept as an unverified claim.

### Revocation processing

Revocation processing writes the [revocation records](#revocation-records)
and releases the `compliance.erenius.io/revocation-history` finalizer
(task 3.6). It is **off by default**, and the runtime chart cannot turn it
on yet.

Releasing the finalizer means the controller must be allowed to update
exceptions. Only the validating exception webhook keeps that grant from
being a general exception write: it confines the controller identity to
releasing the finalizer, and only once the record is durable. So the grant,
the identity lookup and the processing belong together, and they are safe
only while the exception webhooks are registered and fail closed. The chart
ships the `ComplianceException` CRD and the editor role, but it doesn't
deploy the exception webhooks, so it can't provide that protection. Its one
switch, `exceptions.revocationProcessing.enabled`, defaults to `false`, and
`true` fails the render ([charts](../charts.md#exception-revocation-processing)).

**While processing is off**, a revocation is still admitted and recorded on
the resource with its finalizer ([Revocation record](#revocation-record)).
Nothing else happens:

- No independent record is written, and the controller has no grant to
  release the finalizer.
- The exception's `RevocationRecorded` condition is `False` with reason
  `RevocationProcessingDisabled`, and its message says why.
- Deleting the exception is accepted, but it stays `Terminating`, and so
  does a namespace that contains it.
- A renewal of the revoked revision is rejected with
  `RevocationHistoryPending`. Create a new `ComplianceException` for a new
  acceptance.

The annotation stays the only copy of the revocation. Nothing is lost, and
enabling processing later records every held revocation and releases it.

**To enable it** outside the chart (the non-chart test harness does this,
and so can an operator who deploys the webhooks themselves), keep this order,
so that the grant never becomes usable before its protection exists:

1. Serve the webhooks: run every controller replica with `--webhook-cert-dir`
   and provide the `konstapel-system/konstapel-webhook` Service and
   `caBundle` ([Acceptance admission](#acceptance-admission)).
2. Register both webhooks from `config/webhook/exceptions.yaml` with
   `failurePolicy: Fail`, without selectors or match conditions.
3. Bind the ClusterRole `konstapel-controller-exception-revocation`
   (`config/rbac/controller/exception-revocation.yaml`) to the controller
   ServiceAccount with a ClusterRoleBinding.
4. Restart every replica with `--exception-revocation-processing`. Every
   replica runs the same flags, because each one serves the webhooks.

The controller refuses to start with the flag but without
`--webhook-cert-dir`. Before each attempt to record or release, it reads both
`konstapel-exception-acceptance` webhook configurations and checks that each
exists, is not being deleted, uses `failurePolicy: Fail`, intercepts `CREATE`
and `UPDATE` of `compliance.erenius.io/v1alpha1` `complianceexceptions`, and
has no namespace or object selector and no match conditions. If any check
fails, or the configurations can't be read, it records and releases nothing.
The condition is then `RevocationProtectionUnverified`, its message names
the problem, and the check is retried every 15 seconds.

With the flag, each replica's webhook learns the controller identity with a
`SelfSubjectReview` at startup. The replica stays unready until it knows the
identity. A request that reaches it before then is denied with
`ControllerIdentityUnknown`, from any identity, until a lookup succeeds:
the webhook can't tell the controller from anyone else, so it never lets the
controller's request through as an application's.

**To disable it**, reverse the order, so that the grant never outlives its
protection:

1. Restart every replica without `--exception-revocation-processing`. It then
   writes no record and releases nothing. Revoked exceptions it hasn't
   processed report `RevocationProcessingDisabled`. Ones already recorded
   keep `Recorded`, and their records stay.
2. Delete the `konstapel-controller-exception-revocation` ClusterRoleBinding,
   and the ClusterRole if you like.
3. Only then remove the webhooks, if at all.

If the webhooks are removed while processing is still on, the controller
stops at its next check (`RevocationProtectionUnverified`). The grant is
still bound, though, and nothing confines it until step 2. The check runs
just before each attempt, so a webhook removed between the check and the
release is noticed only on the next attempt. The controller also can't check
that the registered endpoint is its own. An endpoint that doesn't answer
fails closed, and `TestLiveRevocationHistory` shows every write, the
controller's release included, denied while no webhook serves. Binding the
gated ClusterRole without the flag gives the controller the grant without
the webhook's restriction of its identity, because the webhook restricts it
only with the flag. Bind the two together.

### Revocation records

The annotation is the only copy of a revocation until the controller
persists it independently (task 3.6) with
[revocation processing](#revocation-processing) enabled. For every revoked
acceptance revision, the controller writes an immutable `ConfigMap` in the
protected namespace
(`konstapel-system`), next to the acceptance snapshots. It is named
`revocation-<exception UID>-<revision>`, so each revoked revision has its own
record and a recreated exception never reuses one. Its `revocation.json`
(record `version: 1`) holds:

- the exception name, namespace and UID, and the revoked acceptance revision;
- the namespace name and UID, the cluster identity and the policy, from that
  revision's acceptance record;
- `revocation`: the protected annotation exactly as admission wrote it (the
  authenticated revoking actor, `requestedAt` and the unverified claim);
- `acceptance`: the `{revision, snapshot, digest}` of the revoked revision's
  acceptance snapshot, which is referenced, never rewritten. When no usable
  acceptance record exists, `acceptanceUnavailable` says why instead.

Everything comes from the stored resource. Nothing is resolved from the
cluster, so an expired, `Forbidden` or unresolvable acceptance gets the same
record, and every replica or leader builds the same one. The labels match the
snapshots' (`app.kubernetes.io/component=revocation-record`,
`compliance.erenius.io/exception-uid`, `compliance.erenius.io/namespace-uid`,
`compliance.erenius.io/acceptance-revision`,
`compliance.erenius.io/policy-hash`), and the
`compliance.erenius.io/record-digest` annotation is verified on every read.
Records have no owner reference: deleting the exception or its namespace does
not remove them. Their retention is documented with task 3.5.

The record says when revocation was **requested**. It is not evidence that an
engine stopped granting; observed withdrawal is group 4 (below).

#### Order of operations

1. The controller verifies that the exception webhooks fail closed
   ([Revocation processing](#revocation-processing)). It then writes the
   record, or finds an existing one and checks that it holds exactly this
   revocation. An existing object is never overwritten.
2. Only then does it release the finalizer, with an optimistic lock. The
   validating webhook allows the release only from the controller identity,
   which it learns with a `SelfSubjectReview` at startup, and only after it
   has read the record back from the API server and found it matching. It
   restricts the controller only with revocation processing on. Without it,
   no identity may release the finalizer. For
   a deleted exception, the controller also writes the revoked revision's
   acceptance snapshot first, so an acceptance that was revoked and deleted
   before the controller ever ran keeps its snapshot too.
3. A renewal of the revoked revision is admitted only once the finalizer is
   gone and the record matches. It is then validated and attributed like any
   renewal, and it removes the annotation. The record of the earlier revision
   stays.

The exception's `RevocationRecorded` condition reports the record of the
current revision. It is absent while the current revision is not revoked.

| Reason | Meaning | Finalizer |
| --- | --- | --- |
| `Recorded` (`True`) | The record exists and matches. The message names it and its digest. | Released |
| `RevocationHistoryPending` | The record could not be written yet, for example because the protected namespace is not writable. Retried every 5 seconds. | Kept |
| `RevocationRecordConflict` | Another object has the record's name and does not hold this revocation. It is never overwritten. Rechecked every minute; an operator must remove it. | Kept |
| `RevocationInvalid` | `spec.revoked` is true but the protected record is missing or belongs to another revision. Nothing can be recorded. | Kept |
| `RevocationProcessingDisabled` | [Revocation processing](#revocation-processing) is off, which is the default. Nothing is recorded or released. Not retried: enabling processing restarts the controller, which then records it. | Kept |
| `RevocationProtectionUnverified` | Processing is on, but the exception webhooks couldn't be verified to fail closed. The message names the problem. Rechecked every 15 seconds. | Kept |

The finalizer is also kept while the revoked revision's acceptance snapshot
cannot be written (a transient error, or `SnapshotConflict`): the acceptance
record on the resource is then its last copy.

While the finalizer is kept, deleting the exception is accepted but the
resource stays `Terminating`, record intact, and so does a namespace that
contains it. A renewal of the revoked revision is rejected with
`RevocationHistoryPending`. Create a new `ComplianceException` if you cannot
wait: it has a new UID and is validated as a new acceptance.

Recovery needs no manual step. A record whose create response was lost is
found and verified on the next attempt and not written again. A controller
that stops after writing the record and before releasing the finalizer is
replaced by the next leader, which verifies the same record and releases. A
revocation admitted while no replica leads is recorded by whichever replica
is elected next. `TestLiveRevocationHistory` exercises each of these against
a real API server with the controller running as its service account and the
shipped roles: first the default roles with processing off, then the gated
grant with processing on. It also covers the validating webhook removed and
restored, a conflicting object at a record's name, an unavailable webhook,
and an identity lookup that fails. `TestLiveReplicaAdmission` covers
failover, and with `TestLiveExceptionRevocation` it runs the managers with
processing on.

An operator who removes the webhooks and then the finalizer by hand, before
the record exists, erases the only copy of that revocation.

### What revocation does not do yet

- **It withdraws nothing.** No native grant exists while engine enablement
  is blocked. Withdrawing native grants, and status that separates the
  requested withdrawal from observed engine state, are group 4 (tasks 4.1,
  4.3, 4.4). `spec.revoked: true` is accepted intent. It is not evidence
  that any engine has stopped granting, and once grants exist, a revocation
  recorded while the controller is stopped stays unconfirmed until
  reconciliation resumes. Persisting the revocation record never waits for,
  or holds up, withdrawal.
- **Observed withdrawal is not recorded.** The revocation record holds the
  request. A durable record of when withdrawal was observed comes with
  group 4.

## Working with an exception

The examples are in
[`docs/examples/policy-exceptions`](../examples/policy-exceptions).
`TestComplianceExceptionDocsExample` validates them against the CRD, and
`TestLiveExceptionRevocation` applies them to a real API server, substituting
only the namespace, a current `expiresAt` and the values that were read.

### Scope

An exception waives one whole logical policy (`spec.policy`) for the objects
its `workloadSelector` matches, in its own namespace. There are no
per-container, per-image or per-value waivers. The selector matches each
evaluated object's own labels, and Konstapel does not follow owner
references. A Deployment and the Pods it creates are distinct objects, so when
both are evaluated, label the Deployment and its Pod template. A selector also
covers matching workloads created later, but only in the same namespace
instance.

### Create

```sh
kubectl apply -f docs/examples/policy-exceptions/exception.yaml
```

[`exception.yaml`](../examples/policy-exceptions/exception.yaml) is revision
1 and omits `revoked`. Set `expiresAt` within the shortest applicable
`maxLifetime` from the time of the request. Admission records the
authenticated caller as the accepting actor; `claimed-by` stays an
unverified claim.

### Revoke

Read the exception and review it, then send a JSON patch that tests the UID,
`resourceVersion` and `acceptanceRevision` you reviewed before it sets
`revoked` ([`revoke.json`](../examples/policy-exceptions/revoke.json)):

```sh
kubectl -n team-a get complianceexception priv-debug \
  -o jsonpath='{.metadata.uid} {.metadata.resourceVersion} {.spec.acceptanceRevision} {.spec.revoked}{"\n"}'
# 4b8f0d6e-2c1a-4e7b-9f3d-5a6c7b8d9e01 48213 1 false
kubectl -n team-a patch complianceexception priv-debug --type=json -p '[
  {"op": "test", "path": "/metadata/uid", "value": "4b8f0d6e-2c1a-4e7b-9f3d-5a6c7b8d9e01"},
  {"op": "test", "path": "/metadata/resourceVersion", "value": "48213"},
  {"op": "test", "path": "/spec/acceptanceRevision", "value": 1},
  {"op": "add", "path": "/spec/revoked", "value": true}
]'
```

If anything changed after you read it, such as a renewal, an edit or a
controller status write, a `test` fails. The API server then rejects the
patch as invalid (HTTP 422, `the server rejected our request due to an error
in our request`) and changes nothing. Re-read, check
that you still mean to revoke that revision, and retry with the new values.
Do not refresh the values automatically.

Admission sees only the resulting object, so it cannot tell whether a request
carried these tests. A plain `kubectl patch -p '{"spec":{"revoked":true}}'`
revokes whichever revision is current when it arrives. Repeating the patch
with current values is safe: the first record stays.

With GitOps, commit `revoked: true` and leave `acceptanceRevision`, `reason`
and `expiresAt` unchanged. The GitOps service account is the recorded actor.
Keep `revoked: true` in the source afterwards: applying `false`, or a manifest
without the field over one that set it, is rejected.

### Renew

[`renew.json`](../examples/policy-exceptions/renew.json) tests the same three
values plus `spec.revoked: false`, then sets `acceptanceRevision` to the read
value plus one and replaces `reason` and `expiresAt`. The `revoked` test makes
the renewal fail rather than renew over a revocation you have not seen.
Admission re-checks eligibility and lifetime from the time of the renewal and
records the renewing actor; the controller writes a new snapshot and keeps
the earlier ones.

To renew a **revoked** revision, use
[`renew-revoked.json`](../examples/policy-exceptions/renew-revoked.json). It
tests `spec.revoked: true` instead, and sets it to `false` with the revision
increment. Wait until the exception's `RevocationRecorded` condition is `True`
and the `compliance.erenius.io/revocation-history` finalizer is gone; before
that, admission rejects the renewal with `RevocationHistoryPending`, as it
always does without [revocation processing](#revocation-processing). The
renewal is a new acceptance: eligibility and lifetime are checked again, it
starts unrevoked, and it removes the revocation annotation from the
resource. The revoked revision stays revoked, and its independent record and
snapshot stay.

### Delete

Deletion removes the resource, and revocation keeps it. `kubectl delete`
sends no preconditions, so it deletes whatever resource has that name when
the request arrives. API clients can send `DeleteOptions.preconditions` with
the `uid` and `resourceVersion` they reviewed; the API server rejects stale
values with `409 Conflict`. An exception is removed at once, unless it is
revoked and its revocation is not yet recorded independently. It then stays
`Terminating` until the controller has written the record (above), and
without [revocation processing](#revocation-processing) it stays that way. Deletion
removes neither its snapshots nor its revocation records, and it does not
delete or stop a workload.
Withdrawing native grants on deletion is part of the lifecycle work in groups
3 and 4.

### Rejected requests

`TestLiveExceptionRevocation` confirms each of these, and
`TestLiveRevocationHistory` the controller-identity and history cases:

| Request | Result |
| --- | --- |
| An editor bound in another namespace revokes the exception | `Forbidden` (RBAC) |
| An identity without the editor role revokes it | `Forbidden` (RBAC) |
| A team member revokes an exception in another namespace | `Forbidden` (RBAC) |
| Anyone rewrites or removes the revocation annotation or re-adds the finalizer | `ProtectedField` |
| A team member writes in `konstapel-system` (revocation records included) | `Forbidden` (RBAC) |
| A stale `test`, or a delete with stale preconditions | `422` or `409`; nothing changes |
| A team member removes the finalizer | `ProtectedField` |
| The controller identity removes the finalizer before the record is durable and matches | `RevocationHistoryPending` |
| The controller identity sets `revoked`, renews, or edits labels or annotations | `ProtectedField` |
| The controller identity updates or deletes a record `ConfigMap` | `Forbidden` (RBAC: `get`/`create` only); an administrator's rewrite fails because it is immutable |

## Acceptance snapshots

For every acceptance revision, the controller persists an immutable snapshot
before anything is granted. The snapshot is a `ConfigMap` with
`immutable: true` in the controller namespace (`konstapel-system`). It is
named `acceptance-<exception UID>-<revision>`, so a recreated exception never
reuses a name. Its `acceptance.json` (snapshot `version: 1`) holds:

- the exception name, namespace and UID, and the acceptance revision;
- the namespace name and UID, and the cluster identity;
- the policy, workload selector and reason;
- the authenticated actor and the unverified claim;
- `acceptedAt` and `expiresAt` (the validity interval);
- the accepted contribution/revision set.

It is copied from the admission record and the spec at that revision. The
controller never re-resolves targeting, so a restart or later configuration
cannot change what was accepted.

The exception's `status.acceptance` holds `{revision, snapshot, digest}`, and
the condition `AcceptanceRecorded` is `True` (`Recorded`). It is `False` in
these cases:

| Reason | Meaning |
| --- | --- |
| `AcceptanceMissing` | No admission record exists. |
| `AcceptanceInvalid` | The admission record cannot be used. |
| `AcceptancePending` | The record does not yet match the spec revision. |
| `SnapshotConflict` | A ConfigMap with the snapshot's name exists but is not an identical immutable Konstapel snapshot. It is never overwritten. |

A renewal creates a new snapshot and keeps the earlier ones, so each
acceptance stays distinguishable.

Snapshot labels support selection without listing every ConfigMap:
`app.kubernetes.io/component=acceptance-snapshot`,
`compliance.erenius.io/exception-uid`, `compliance.erenius.io/namespace-uid`,
`compliance.erenius.io/acceptance-revision`, and
`compliance.erenius.io/policy-hash`. Each accepted contribution revision also
gets a label `revision.compliance.erenius.io/<first 40 hex of the
revision>=true`. The `compliance.erenius.io/snapshot-digest` annotation is
verified on every read.

The controller may only `get` and `create` ConfigMaps in its namespace;
application roles have no access there. Snapshots, like
[revocation records](#revocation-records), have no owner reference, because
they outlive the exception for retained evidence. Their retention is
documented with task 3.5.

## Lifecycle fixture matrix

[`testdata/exceptions/lifecycle-matrix.yaml`](../../testdata/exceptions/lifecycle-matrix.yaml)
gives every `policy-exceptions` scenario at least one case with an explicit
expected outcome. The cases cover acceptance, renewal, revocation, native
bypass and report disposition, across the namespace, revision, eligibility,
attribution, lifetime and expired/missing-context boundaries. The
[fixture README](../../testdata/exceptions/README.md) documents the format.
The fixtures need no cluster:

```sh
devbox run -- go test ./internal/exception/ -run LifecycleMatrix
```

## Engine expiry gate (Kyverno 1.19.2)

`scripts/exception-expiry.sh` reproduces native `policies.kyverno.io/v1`
`PolicyException` expiry on the pinned runtime. Konstapel is not installed
during the run, and no policy is edited after the exception exists:

```sh
devbox run -- scripts/exception-expiry.sh /tmp/konstapel-exc-expiry
```

The script creates and always deletes its own kind cluster
(`konstapel-assessment-exc` by default). It runs these steps:

1. Scales the admission controller to two replicas.
2. Applies a `Deny` copy of the vendored `disallow-privileged-containers`
   policy.
3. Sends server-side dry-run requests for a privileged Pod and records each
   request's phase, timestamp, outcome and message in `requests.jsonl`.

The phases:

| Phase | What happens | Requests |
| --- | --- | --- |
| `before-exception` | Policy enforced, no exception | 10 consecutive denials |
| `created-expired` | An exception whose `expiresAt` is already past | 10 |
| `active` | A 120 s exception, matched by namespace and label | 20 consecutive admissions |
| `after-expiry`, `after-expiry-75s` | 15–135 s after `expiresAt`, no events | 50 |
| `after-restart` | Admission controller restarted | 20 |

`result.json` summarises the run. The script exits 0 whenever the
observation is complete, whatever the outcome.

### Observed result

[exception-expiry.json](exception-expiry.json) records the 2026-11-06 run:
Kyverno 1.19.2 (chart 3.9.2, image digests recorded), Kubernetes 1.37.0 kind
node, two admission replicas.

| Phase | Outcome |
| --- | --- |
| before-exception | 10/10 denied |
| created-expired | 10/10 denied: an exception that is already expired never grants |
| active | 20/20 admitted |
| after-expiry (+15 s … +135 s) | **50/50 admitted**: the cached grant outlives `expiresAt` |
| after-restart | 20/20 denied: recompilation drops the expired exception |

This confirms the source finding in the design. Kyverno filters expired
exceptions only when it compiles a policy, and a compiled ValidatingPolicy
keeps evaluating a grant after it expires. With Konstapel stopped, nothing
recompiles the policy, so the exemption lasts until some unrelated event
does. That breaks the spec scenario *Konstapel is unavailable at expiry*.

Requests go through the API server to the Kyverno Service, which balances
across both replicas. The probe cannot attribute a single request to a
replica, because Kyverno 1.19.2 does not log admitted requests at the
verbosity the chart uses. However, all 50 post-expiry requests were admitted.
If one replica enforced expiry, it would have denied about half of them, so
both replicas held the stale grant.

### Upstream status and gate

- Upstream issue [kyverno#18150](https://github.com/kyverno/kyverno/issues/18150)
  reports the same defect.
- The fix [kyverno#18152](https://github.com/kyverno/kyverno/pull/18152)
  rechecks expiry during cached evaluation for vpol/mpol/gpol/dpol and image
  verification. It merged to `main` on 2026-11-03 (commit `a015b2d`), after
  v1.20.0-rc.1.
- As of 2026-11-06, no release contains the fix, and it has not been
  backported to `release-1.19` or `release-1.20`.

Native exception enablement therefore remains blocked. To lift the gate,
take one of these runtimes and re-run this probe:

- a released runtime that contains the fix
- a narrowly backported engine build with recorded provenance (task 1.3)

The probe must show `after-expiry` denied with Konstapel stopped. Do not work
around the gap with a Konstapel workload webhook (design §5).

## Engine namespace-identity gate (Kyverno 1.19.2)

Design §4 binds a native grant to a namespace *instance*: its name **and** UID.
That way a namespace deleted and recreated under the same name never inherits
an old grant. `scripts/exception-namespace-uid.sh` checks whether the pinned
runtime can express this in `PolicyException` match conditions:

```sh
flock /tmp/konstapel-live-cluster.lock devbox run -- scripts/exception-namespace-uid.sh /tmp/konstapel-exc-nsuid
```

The [2026-11-06 result](exception-namespace-uid.json) on Kyverno 1.19.2:

| Condition | Exception accepted | Admission | Background |
| --- | --- | --- | --- |
| `namespaceObject.metadata.uid == …` | no: `undefined field 'uid'` | (policy enforced) | `fail` |
| `namespaceObject.metadata.UID == …` | yes | **denied**: `no such key: UID` (evaluation error, fails closed) | `error` |
| `namespaceObject.metadata.name == …` only | yes | admitted | `skip` |

The Kubernetes CEL Namespace type that Kyverno uses for exception conditions
declares the field `UID`. The namespace value at evaluation carries the JSON
field `uid`. So a UID condition is either rejected or never matches, and only
the namespace name can be matched.

**Native exception enablement therefore stays blocked on this too.** A
name-only grant would let a recreated namespace inherit it, which the spec
forbids. Lifting this gate needs one of:
- a runtime that resolves namespace UIDs in exception conditions;
- a narrowly scoped engine fix;
- an agreed alternative design for namespace identity.

Re-run this probe whenever the engine pin changes, together with the expiry
probe.
