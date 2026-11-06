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

`reason` and `expiresAt` can change only together with a renewal (the
revision +1). Metadata edits do not renew, and a revision never skips or goes
back. A selector has no namespace field, so scope cannot reach another
namespace. Widening the scope means creating a new resource.

Authenticated attribution is recorded by admission (below). Time and
eligibility checks (future expiry, maximum lifetime, `Forbidden`
contributions) come with task 2.3. Status is controller-only (task 2.4), and
revocation arrives with the withdrawal lifecycle (group 4). Until then the
resource has no effect: Konstapel grants nothing for it.

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
| `eligibility` | the targeting resolver's effective eligibility for the policy in this namespace: the complete contribution set with each `Contribution.Revision`, the shortest `maxLifetime`, and any resolution errors. `null` when no binding applies the policy here. |

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

Admission records the set; it does not reject on it yet. Rejecting
`Forbidden` or unresolved contributions and enforcing lifetime limits is task
2.3, so a recorded `Forbidden` set grants nothing.

`TestLiveExceptionAdmission` (`internal/controller`, `live` tag) runs these
webhooks against a real API server. The manager runs in-process with a test
CA, and requests are made as impersonated users (alice, bob, an Argo CD
service account). It checks forged attribution, dry run, a metadata edit after
the binding is deleted, a tampered record, renewal, and GitOps claims. Run it
against a cluster created by `scripts/environment.sh`:

```sh
devbox run -- scripts/exception-admission-live.sh konstapel-assessment-<name> /tmp/konstapel-exc-adm
```

The script runs the compiled test in a container on the kind network, so the
API server can reach the webhook even when a host firewall blocks
container-to-host traffic.

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
