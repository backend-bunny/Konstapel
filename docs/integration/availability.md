# Controller availability

`add-controller-high-availability` owns the controller's replica lifecycle and
the cross-feature availability tests. [Helm charts](../charts.md)
(`add-helm-oci-distribution`) owns the Deployment, Services, PDB, scheduling and
values that use this contract. This page is the integration contract between
the two. It names only interfaces that exist in merged code; everything else is
marked unavailable.

## Entry points

| Process | Command | Leadership | Status |
| --- | --- | --- | --- |
| Controller | `konstapel controller` (`cmd/konstapel/controller.go`, `controller.NewManager`) | Elected: reconcilers, the capability trigger and deferred engine watches run only on the Lease holder | available |
| Exception admission webhooks | the controller's webhook server (`--webhook-cert-dir`, port 9443) | none: served on every replica | **unavailable**: add-self-service-policy-exceptions waits on an upstream Kyverno release |
| Evidence downloads | `konstapel download-server` (`--listen :8443`) | none: a separate stateless process reading run status and the pinned destination | available; the chart renders it as its own two-replica Deployment |
| Probes | `GET /healthz`, `/readyz` on `--health-probe-bind-address` (`:8081`) | independent of leadership and engine health | available. The controller's `/readyz` fails while it shuts down. The download server answers `/healthz` and `/readyz` over HTTPS on `:8443`, and its `/readyz` fails while its TLS is invalid. The rest of the serving-readiness wiring is task 3.1. |

## Leader election

| Setting | Value | Flag |
| --- | --- | --- |
| Lease | `coordination.k8s.io/v1` Lease `konstapel-controller-leader-election` in the controller namespace (`--leader-election-namespace`, default `POD_NAMESPACE`) | — |
| Election | on in every mode, including one replica | `--leader-elect` (default `true`; only in-process tests turn it off) |
| Lease duration / renew deadline / retry period | `15s` / `10s` / `2s` | `--leader-election-lease-duration`, `--leader-election-renew-deadline`, `--leader-election-retry-period` |
| Release on cancel | off: the Lease expires instead of being released while shutdown may still be draining | — |
| RBAC | Lease get/list/watch/create/update/patch/delete in `konstapel-system` only (generated Role) | — |

- **Shared Lease.** Every replica and every supported runtime revision of an
  installation uses the same Lease. Its name has no pod name, image or chart
  version, and each process gets its own holder identity.
- **Timing checks.** Startup fails unless every timing is positive and
  lease > renew > 1.2 × retry (client-go's jitter). Invalid timings never fall
  back to running without election.
- **No Lease access.** A candidate without Lease permissions is never elected
  and never reconciles. The timings aren't a recovery SLA: takeover after a
  graceful leader stop took about 20s in `TestLiveLeaderElection`, because the
  Lease expires rather than being released.

## What runs where

Every replica starts the same process. What each part does depends on
leadership:

| Part | Runs on | Why |
| --- | --- | --- |
| Profile, binding, assessment, run, destination and exception controllers | leader only | they write managed resources, status and storage |
| Capability trigger and deferred engine watches | leader only | they re-queue reconciliation |
| Informer caches and field indexes | every replica | a follower that takes over starts from a warm, synchronized view |
| Probes (`/healthz`, `/readyz`) | every replica | they report serving health, not leadership |
| Exception admission webhooks (when served) | every replica | they read through the API reader and write nothing |
| Startup reads (`kube-system` identity, evidence runtime, staging directory) | every replica | local initialization only; no cluster writes |

controller-runtime (v0.25) starts and syncs the caches before it joins the
election. Each controller also waits for its own watches to sync before its
workers start. A new leader therefore never acts on a partial view.
`TestBackgroundWorkersNeedLeadership` pins the leader-only setting for the
two custom runnables. `TestLiveLeaderElection` gives each candidate its own
user agent and edits a binding while both run. The test then checks the field
managers of the binding, its profile, its engine policies, the Lease and every
Event: the follower's agent appears on none of them, and the leader's does.

## Serving readiness versus leadership

Readiness answers "can this pod serve requests now?", never "is this pod the
leader?". Both controller replicas, leader and follower, become ready.
Services and probes therefore select every ready replica, and none of them
needs to know which one holds the Lease.

| Process | Ready when | Not ready when | Independent of |
| --- | --- | --- | --- |
| Controller (`:8081/readyz`) | the manager is running | it is shutting down (termination signal or leadership loss) | leadership, Kyverno health (reported in binding Conditions), S3 |
| Download server (`:8443/readyz`, HTTPS) | its mounted certificate is valid and verified | the mounted TLS is invalid, the served certificate has expired, or it is shutting down | the controller, leadership, S3 (a backend outage fails only the affected downloads with `503`) |

To see who leads, read the Lease, not readiness:

```sh
kubectl -n konstapel-system get lease konstapel-controller-leader-election \
  -o jsonpath='{.spec.holderIdentity}{"\n"}'
```

`TestLiveHelmInstall` checks this on the installed chart. Both controller pods
become ready while exactly one holds the Lease. Both download pods serve
through the `konstapel-download` Service, which has no session affinity. Each
download pod also serves directly with no controller running at all (see
[Downloads without the leader](#downloads-without-the-leader)).

### Client retry

- **Downloads.** Retry the same URL with a fresh token. Any ready replica
  answers, and there is no session state to resume. Answers:
  - `503` and `429` are temporary: retry after the `Retry-After` header (30s).
  - `401` and `403` mean authenticate or authorize again; retrying doesn't
    help.
  - `409` means not published yet.
  - `410` means expired or handed off.

  An interrupted transfer restarts from the beginning, because there are no
  range requests.
- **Kubernetes API writes** (bindings, profiles, requests). Clients talk to
  the API server, not to Konstapel, so leadership changes don't affect them.
  A new leader reconciles everything from the current state after the Lease
  changes hands, which took about 20s in tests.
- **Exception admission webhooks.** They aren't served yet (see below). Once
  they are, every ready replica will serve them, and the API server retries
  them according to the webhook's failure policy.

## Shutdown and leadership loss

| Setting | Default | Flag |
| --- | --- | --- |
| Controller shutdown budget | `45s`: runnables must stop by then, and the process exits even if one doesn't | `konstapel controller --shutdown-timeout` |
| Download drain | `20s`: accepted downloads may finish, then remaining connections are closed | `konstapel download-server --shutdown-drain` |
| Pod termination grace | `60s` (Helm), leaving headroom above both | — |

- **Readiness.** From the termination signal on, `/readyz` fails (the
  `shutdown` check) while the controller drains, so the replica leaves service
  endpoints first. `/healthz` is unaffected.
- **Interrupted downloads.** A long download can't hold termination open. Its
  client retries the whole download with fresh authorization, because there
  are no resumable ranges. There are no shell `preStop` hooks: the image has no
  shell.
- **Leadership loss.** When the Lease is lost, controller-runtime cancels
  every leader-only runnable (reconcilers, the capability trigger, deferred
  engine watches) and the manager exits with `leader election lost`. It doesn't
  linger as an unelected process; the pod restarts and becomes a candidate
  again.
- **No child processes.** The controller runs no C2P child processes. Only the
  `konstapel` CLI starts the provider plugin, so there are no children to
  terminate.
- **Interrupted work.** Durable recovery handles interrupted work: frozen
  captures and staged packages are recovered on the next leader, and loss
  before durable staging is `CaptureLost` (see the assessment contract).

`TestLiveBoundedShutdown` checks three things:
1. readiness fails once termination begins;
2. a runnable that ignores cancellation can't hold the process past a 3s
   budget;
3. when another holder takes the Lease, the leader's work is cancelled within
   5s and the manager exits with `leader election lost`.

## Delayed former leaders

Leader election isn't fencing. A paused process, or a request already in
flight, can outlive its leadership. Each write therefore carries its own guard:

| Write | Guard against a stale attempt |
| --- | --- |
| Binding and profile status | `Update` with the read `resourceVersion`; a newer object is a conflict, and the next reconcile reads it |
| Engine policy create, repair | names are derived from the enforcement revision and never reused; repair is an `Update` with the read `resourceVersion` on a policy the binding owns at the same revision |
| Engine policy delete (superseded revisions) | before the first write, and again after listing owned policies, the binding and profile are re-read from the API server and must still have the snapshot's UID and generation. A changed snapshot aborts the Sync, and the binding resolves again. Each delete carries the listed object's UID and `resourceVersion` as preconditions. |
| Assessment run publication | deterministic run identities and conditional immutable S3 commits: matching bytes recover the original commit, and different bytes under the same identity are a conflict (`internal/s3store` `TestStagePublishAndRecover`, `TestConflictingContentNeverOverwrites`) |

The order is what makes this safe. A policy delivered for a newer snapshot
can only exist after that snapshot was committed. If it appears in the owned
list, the check that follows sees the newer generation, and no delete is sent.
A stale attempt can at most recreate a superseded revision. The current
leader's owned-policy watch then retires it again once the replacement is
ready. The current revision is never withdrawn.

Tests:
- `TestDelayedFormerLeaderResolvesAgain` runs a reconciler whose cache still
  holds the old binding and profile after another reconciler delivered a
  newer profile generation. The current policy and the newer status stay
  untouched.
- `TestDelayedFormerLeaderCannotWithdrawTheNewRevision` covers a stale
  snapshot, and one that turns stale during the attempt.
- `TestDeleteRequiresTheListedObject` changes a policy between listing and
  delete; the result is a conflict, not a deletion.

## Recovery on leadership acquisition

Staging is durable in S3, not in the pod. A run's package is staged as an
attempt under the run's prefix before it is committed, and a new leader
recovers it with `Publisher.Recover`. It never needs the former leader's
staging directory.
- **Run identity.** Run names are deterministic and each binding has at most
  one active run, so a new leader continues the same run instead of starting
  another.
- **Unreachable S3.** If S3 is unreachable while the new leader recovers, the
  run stays `Publishing`. That is uncertain backend access, not `CaptureLost`,
  and the run is retried until S3 answers.
- **Committing.** The new leader commits exactly the bytes the former leader
  staged.

`TestLiveLeaderHandoverRecovery` (`recovery` group) checks this. Leader A
stages a run's package in S3 and stalls before the commit. S3 is paused and A
is stopped. Candidate B, with its own empty staging directory, takes over.
For 30 seconds the single run stays `Publishing` and is never `CaptureLost`.
After S3 returns, B commits the same run with A's publication ID and package
SHA-256.

### Where a lost leader's work ends up

| The leader was lost | The successor finds | Outcome |
| --- | --- | --- |
| before the capture was durably staged (it existed only in that pod's staging directory) | no attempt in S3: `Recover` returns `ErrCaptureLost` | the run fails with `export: CaptureLost` and nothing is committed; the next run is a new identity and publishes normally |
| after staging, before the commit | the staged attempt | the same run commits the staged bytes (above) |
| after the commit, before the Kubernetes receipt | the existing commit | the run records the original commit: same publication ID, archive, `publishedAt` and `expiresAt`. The retention is the one the commit was made with, even if the binding's retention changed since. Nothing is committed twice. |
| while S3 is unreachable | nothing certain | the run stays `Publishing` and retries; this is never `CaptureLost` |

`TestLiveLeaderHandoverLoss` (`recovery` group) checks the first and third
rows across leaders:
- In the lost-receipt case, the binding's retention changes from 600s to
  120s before the successor takes over. The recorded expiry is still the
  committed 600s.
- In the lost-capture case, the test also checks that S3 holds no staging for
  the lost run, and that a following run publishes.

These in-process tests use managers in the test process. On the
Helm-installed image, `TestLiveHelmDurableRecovery` (`availability` group)
checks the second and third rows and the last one with two installed
replicas, and `TestLiveHelmAvailability` the first
([Deployed availability](#deployed-availability-multi-node-acceptance)).

## Per-pod budgets

Each replica has its own bounded storage and concurrency. Nothing is shared
between pods, and nothing is needed from a lost pod.

| Process | Budget | Default (chart value) | When exceeded |
| --- | --- | --- | --- |
| Controller (leader) | concurrently executing runs across all bindings | 4 | further runs wait their turn; one active run per binding |
| Controller | staging volume (`emptyDir`) for frozen captures and packages awaiting publication | 2Gi (`controller.stagingSizeLimit`) | the kubelet evicts the pod; captures not yet staged in S3 become `CaptureLost` on the next leader |
| Controller | one package archive | 512 MiB (`s3store.MaxArchiveBytes`) | publication is refused for that run |
| Controller | publication retries after collection closes | 5 min | the run fails with the publication error, and nothing partial is committed |
| Download server | concurrent downloads | 4 (`download.maxConcurrent`) | `429` with `Retry-After: 30` |
| Download server | bytes buffered for verification across downloads | 2 GiB (`download.maxTempBytes`) inside a 3Gi volume (`download.tempSizeLimit`) | `503` with `Retry-After: 30` |
| Both | shutdown | 45 s controller budget and 20 s download drain within a 60 s grace ([Shutdown and leadership loss](#shutdown-and-leadership-loss)) | the process exits; interrupted work is recovered or reported |

Two replicas of each Deployment use at most twice these budgets.

## Replica-local state after pod loss

A new pod, or a new leader, starts with nothing remembered locally. It
rebuilds what it can from durable state, and states what it can't:

| Local state | After loss | Never assumed from memory |
| --- | --- | --- |
| Policy content | read from the image and **re-verified on every resolution** against `SHA256SUMS`, whose own digest is the pinned bundle digest | a file that fails verification makes the binding `Resolved=False` (`ContentUnavailable`): applied policies stay, no other digest is chosen, and the binding isn't reported current |
| Informer caches | re-listed from the API server and synced before the leader acts ([What runs where](#what-runs-where)) | — |
| Engine capability | rediscovered on the first reconcile and every poll | an absent engine is reported, not inferred from earlier status |
| An in-progress capture | resumed from the run's frozen scope | results evaluated before the restart don't count, because watch continuity isn't proven; missing evidence leaves the run `Incomplete` |
| Staged packages | recovered from S3 attempts | a capture that existed only in the lost pod's staging volume becomes `CaptureLost` |
| Grants, publications, cleanup obligations | live in the API (runs, finalizers, receipts) and in S3, never only in the pod | — |

Tests:
- `TestSuccessorWithUnverifiableContentKeepsPolicies` gives a successor a
  tampered content copy: it reports `ContentUnavailable`, keeps the former
  leader's policy, and keeps the recorded bundle digest.
- `TestUnavailableContentKeepsAppliedPolicies` covers a digest this replica
  doesn't serve.
- `TestLocalContentRejectsTamperedFiles` covers tampered content files.
- `TestRestartResumesSameCaptureWithoutContinuity` covers continuity lost
  during collection.
- `TestLiveEngineCapabilityRecovery` covers capability rediscovery.

## Failure walkthrough

What survives each failure, and what is cleaned up. Committed artifacts are
never rewritten or deleted before their recorded expiry. Cleanup removes only
attempt data that the run itself owns.

| Failure | Committed package | Incomplete attempt data | Retention obligation |
| --- | --- | --- | --- |
| Leader pod deleted mid-collection | none yet | the capture is lost with the pod; the run ends `CaptureLost`, nothing is uploaded | none for that run |
| Leader lost after staging, before commit | committed later by the next leader with the original bytes and identity | staged attempts other than the committed one are removed once the run is terminal (`AttemptsCleaned`) | from the commit, with the retention selected at commit |
| Leader lost after commit, before the receipt | unchanged; the next leader records the original receipt | as above | the original `expiresAt`, even if the binding's retention changed since |
| S3 unreachable | unchanged | kept until S3 answers; the run stays `Publishing` and isn't `CaptureLost` | unchanged; expiry deletion retries |
| A response lost on publish or delete | unchanged; a retry returns the matching commit instead of committing twice | as above | a lost delete response is retried until no owned version remains |
| Controller outage (no replica) | unchanged and still downloadable | untouched until a controller runs | expiry deletion is delayed, never skipped; the run's retention finalizer keeps it until its package is deleted |

**How attempt cleanup stays safe.** `CleanupAttempts` runs only for terminal
runs, and only below that run's own prefix (cluster, binding UID, run UID). It
removes uncommitted staged attempts and incomplete multipart uploads, but it
never touches the commit or the committed archive, and it leaves anything
whose ownership it can't establish. A failure is recorded on the run
(`AttemptsCleaned=False`, `CleanupPending`) and retried, and a new leader
re-lists terminal runs and resumes.

Tests:
- `TestPublisherRoundTrip` (`internal/s3store`, real S3, all versioning
  modes) removes an interrupted attempt and a real incomplete multipart
  upload. It checks that an unrelated object in the same bucket survives,
  and that the committed package is undamaged.
- `TestLiveLeaderHandoverRecovery` and `TestLiveLeaderHandoverLoss` cover
  the staged, receipt-lost and capture-lost rows across leaders.
- `TestLiveHelmAvailability` covers capture loss with the installed image,
  and `TestLiveHelmDurableRecovery` the staged and receipt-lost rows
  ([Deployed availability](#deployed-availability-multi-node-acceptance)).
- `TestLiveEvidenceRecovery` and `TestLiveRetentionLifecycle` cover expiry
  deletion blocked by a legal hold and resumed, and a binding deleted during
  an S3 outage.
- `TestLostDeleteResponseIsRetriedToDeleted` (unit) loses a delete response.
  The finalizer stays, and the retry after backoff records the `Deleted`
  tombstone. `TestLostPublishResponseKeepsOriginalReceipt` covers a lost
  publish response, which keeps the original receipt and commits only once.

## Downloads without the leader

The download server is its own Deployment (`konstapel-download`, two
replicas). It isn't elected and doesn't talk to the controller. Each request
is handled the same way on any replica:
1. It authenticates the token (TokenReview, audience `konstapel-download`)
   and authorizes it (SubjectAccessReview), every time, with no cache.
2. It resolves the run from the API: the run UID, or the request UID plus the
   UID of the namespace the request was admitted in.
3. It reads the pinned EvidenceDestination and its current credential Secret.
4. It fetches the package from S3 and checks it against the run's receipt
   before streaming it.

No replica keeps local files between requests, and the Service has no session
affinity. A client that loses a connection retries the same URL, and any
ready replica answers it.

| Condition on retry | Answer from every replica |
| --- | --- |
| Still authorized, package available | `200` and the same package (same SHA-256 as the receipt) |
| Grant revoked, or the request or its namespace was recreated | `403`, the same answer as for a missing object |
| Wrong token audience | `401` |
| The destination's credential Secret is missing | `503` until the Secret exists again |
| S3 unreachable | `503`, within the S3 client's bound of three attempts of 30 seconds each |
| Package expired or handed off | `410` |

`TestLiveHelmInstall` (`charts` group) checks this with no controller pod
running at all. It scales `konstapel-controller` to zero after a team request
and a scheduled run are published, then calls each download pod directly
through its own port-forward. It checks:
- both packages match their receipts on each pod;
- revoking and restoring the operator's and the team's grants takes effect
  on each pod;
- a wrong audience is rejected;
- a missing credential Secret, and then a rotated one, take effect without a
  restart;
- a paused S3 container gives `503` on each pod, and serving resumes once S3
  is back;
- after the team namespace is recreated with the same names, neither the old
  nor the new request UID reaches the old evidence, while the platform
  operator still can;
- no pod logged the S3 secret, a private key or a token.

The certificate rotations in the same test (operator Secret and cert-manager)
also check every pod.

## Deployed availability (multi-node acceptance)

The `availability` acceptance group runs on a kind cluster with one control
plane and two workers (`KONSTAPEL_CLUSTER_WORKERS=2`). The workers are
labelled `konstapel.dev/pool=workload`, and Kyverno is pinned to the control
plane, so losing a worker removes Konstapel replicas but not the engine.
`TestLiveHelmAvailability` installs both charts with the packaged image
(operator TLS) and checks, in order:

| Case | What must hold |
| --- | --- |
| Placement | both controller and both download replicas ready, on different workers (preferred anti-affinity); one Lease holder |
| Disruption budget | one voluntary eviction proceeds; a second, before its replacement is ready, is refused (`429`) |
| Rolling upgrade | a pod-template change replaces both controllers while at least two stay ready |
| Constrained surge | with every worker cordoned, the surge pod stays `Pending`; both old replicas keep serving and the rollout is visibly incomplete until capacity returns |
| Preferred separation | with one worker cordoned, a replaced replica co-locates with the other and becomes ready (separation is never required) |
| Development values | `docs/examples/charts/development.yaml`: one replica, no controller PodDisruptionBudget, and a drain of the single replica proceeds |
| Controller outage | with the controller scaled to zero, Kyverno keeps enforcing the delivered policies and downloads keep serving |
| Leader pod loss | a force-deleted leader is replaced: the other replica takes the Lease (about 16–20 s in tests) and reconciles a new binding generation |
| Leader loss during an S3 outage | after capture, with S3 paused, the leader pod is force-deleted. The run stays `Publishing` (uncertain access, never `CaptureLost`) while S3 is down. The capture lived only in that pod's staging volume, so once S3 returns the run ends as a truthful `CaptureLost`, and the next run publishes under a new identity |
| Node loss | the leader's worker container is stopped. The replica on the other worker takes the Lease (about 19–21 s) and reconciles, and the download replica there serves the package |

`TestLiveHelmDurableRecovery` (same group, same packaged image and charts)
proves recovery of work that the leader had already made durable in S3. A
test-owned fault proxy (`internal/s3fault`, built from the checkout and run
in a disposable container on the kind network) sits between the pods and the
test S3 service. It forwards requests with their signed `Host` header
unchanged and interrupts one run's conditional commit
(`PUT …/<run UID>/commit.json` with `If-None-Match: *`). The controller is
not changed or replaced. Each case removes the pod that holds the Lease at
that moment (force delete, grace 0) and waits until its container has
stopped on the node; the other installed replica, with its own empty staging
volume, takes over. The workers stay cordoned until it holds the Lease, so the
Deployment's replacement pod cannot race it:

| Case | What must hold |
| --- | --- |
| Staged, not committed | the proxy holds the leader's commit and never forwards it. Read directly from S3, the run has exactly one staged attempt whose archive matches its recorded SHA-256, and no commit. The binding's retention changes from 600s to 900s, S3 is blackholed, and the leader pod is removed. While the successor's S3 requests are held, the single run stays `Publishing` for 30 s and is never `CaptureLost`. After release the successor commits the same run (same name, UID and publication ID) with the leader's staged archive object: the staged, committed, receipt and downloaded SHA-256 are equal, the commit is forwarded once, and the retention and expiry are the binding's at the commit (900s), not the 600s recorded at closure |
| Committed, receipt lost | the proxy forwards the leader's commit, which lands in S3, withholds the response and blackholes every later request. The binding's retention changes from 600s to 120s and the leader pod is removed. The run stays `Publishing`, never `CaptureLost`, while S3 is unreachable. After release the successor records the original commit: publication ID, archive key, manifest version, package SHA-256, `publishedAt` (the commit object's server time) and `expiresAt` (`publishedAt` + the committed 600s). The commit reached S3 once, the commit object has one version, and the downloaded package matches |

A background watch over each run fails on any other UID, `Failed` or
`CaptureLost`; the phases seen are recorded (`Collecting`, `Publishing`,
`Completed`). The proxy's log and the recorded steps are kept with the test
evidence (`<output>/targeting/TestLiveHelmDurableRecovery*.json` and
`…-s3fault.log`).

## Lifecycle matrix

`testdata/availability/lifecycle-matrix.json` maps every requirement in the
`controller-availability` specification to:
- its lifecycle boundary (startup, leadership, serving, termination, recovery,
  release);
- the expected observable result;
- the implementing owner;
- whether a merged test verifies it (`verified`) or it is still `pending`.

`internal/availabilitytest` fails if a requirement is missing, stale or
incomplete.

## Checks

```sh
devbox run -- go test ./internal/availabilitytest/ ./internal/controller/ -run 'LifecycleMatrix|ElectionTimings'
devbox run -- task acceptance OUTPUT=/absolute/fresh/path GROUP=admission   # includes TestLiveLeaderElection
```

`TestLiveLeaderElection` starts two in-process candidates against the
disposable cluster and checks four things:
1. exactly one becomes leader and stays leader;
2. after the leader stops, the other takes over once the Lease expires and
   reconciles a new binding generation;
3. a candidate whose identity is bound to the controller ClusterRole, but not
   the Lease Role, is never elected and leaves a binding edit unreconciled;
4. granting the Lease Role lets it lead.

## Not yet available

- Serving readiness for the controller's admission webhooks, which wait for
  exception admission (task 3.1). The download server's readiness already
  follows its TLS state.
- Multi-replica recovery and node-loss acceptance (group 5).
