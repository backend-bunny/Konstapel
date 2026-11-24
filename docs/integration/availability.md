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
| Exception admission webhooks | the controller's webhook server (`--webhook-cert-dir`, port 9443) | none: served on every replica | acceptance admission is implemented and served by every replica when `--webhook-cert-dir` is set; the chart doesn't deploy it, because native exception enablement (add-self-service-policy-exceptions) waits on an upstream Kyverno release |
| Evidence downloads | `konstapel download-server` (`--listen :8443`) | none: a separate stateless process reading run status and the pinned destination | available; the chart renders it as its own two-replica Deployment |
| Probes | `GET /healthz`, `/readyz` on `--health-probe-bind-address` (`:8081`) | independent of leadership and engine health | available; see [Serving readiness versus leadership](#serving-readiness-versus-leadership). The download server answers `/healthz` and `/readyz` over HTTPS on `:8443`. |

## Leader election

| Setting | Value | Flag |
| --- | --- | --- |
| Lease | `coordination.k8s.io/v1` Lease `konstapel-controller-leader-election` in the controller namespace (`--leader-election-namespace`, default `POD_NAMESPACE`) | — |
| Election | on in every mode, including one replica | `--leader-elect` (default `true`; only in-process tests turn it off) |
| Lease duration / renew deadline / retry period | `15s` / `10s` / `2s` | `--leader-election-lease-duration`, `--leader-election-renew-deadline`, `--leader-election-retry-period` |
| Release on cancel | off: the Lease expires instead of being released while shutdown may still be draining | — |
| RBAC | Lease `get`/`update` of `konstapel-controller-leader-election` and Lease `create` (not restrictable by name), in `konstapel-system` only (generated Role); see [Controller ServiceAccount boundary](../charts.md#controller-serviceaccount-boundary) | — |

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
| Webhook and metrics certificate reloaders, informer readiness gate | every replica | they keep this replica's serving prerequisites current |
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
| Controller (`:8081/readyz`) | its informer caches finished their initial sync (`informers`), and, when webhooks are served, the webhook server answers TLS with a verified, unexpired certificate (`webhook`) | it is starting and the caches have not synced; a webhook certificate rotation was rejected or the served certificate expired; it is shutting down (termination signal or leadership loss) | leadership, Kyverno health (reported in binding Conditions), bundle sources (OCI content is unavailable per binding; exception admission denies the affected namespace's acceptances as `Unresolved`), S3 |
| Download server (`:8443/readyz`, HTTPS) | its mounted certificate is valid and verified | the mounted TLS is invalid, the served certificate has expired, or it is shutting down | the controller, leadership, S3 (a backend outage fails only the affected downloads with `503`) |

Liveness and startup (`/healthz`) check only that the process serves; they
never depend on the API server, an external service or leadership.

controller-runtime starts the probe server before the caches, so until 3.1 a
starting replica answered `/readyz` before its view had synced. The
`informers` check latches once the initial sync completes: informers relist
on their own afterwards, and an informer the leader adds later for an absent
engine API never takes a serving replica out of its Service.

The webhook certificate (`tls.crt`, `tls.key` in `--webhook-cert-dir`) is
handled like the metrics and download certificates. It must be valid at
startup, or the controller exits. Every 10s it is re-read; a rotation is
served only once it verifies. Until then the last good certificate keeps
serving and `/readyz` fails, so the replica leaves its Service while
`/healthz` keeps it alive.

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
- **Exception admission webhooks.** Every ready replica serves them with the
  same checks, and none forwards to the leader. Both webhooks fail closed
  (`failurePolicy: Fail`): a request that reaches no replica is rejected and
  the client retries it. Admission reads profiles, bindings and namespaces
  through the API server on every request, so a central restriction applies
  on every replica at once, also while no replica leads. The leader only
  persists acceptance snapshots afterwards, exactly as admitted.

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
  engine watches, metric owner projections, which are cleared) and the
  manager exits with `leader election lost`. It doesn't
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

## Metrics across leadership changes

The [metrics](metrics.md) owner projections (binding summaries, capabilities,
the storage backlog and domain readiness) are leader-scoped; operation
counters are process-local on every replica. `NewManager` registers the
Hub's leadership term (`observability.Leadership`) and one refresher per
enabled domain as leader-only runnables, so they follow the same Lease as
the reconcilers:

| Transition | What a replica exposes |
| --- | --- |
| Follower, or a candidate that cannot take the Lease | readiness 0 for every domain, the enabled flags and its own counters; no binding, capability or backlog series |
| Elected | nothing until each refresher has waited for the manager's cache to synchronize and published from it; a domain is ready only with the state it summarizes |
| Lease lost (another holder, renewal failed) | the leader context is cancelled: every owner projection is cleared, a write still in flight for the old term is refused (`ErrNotLeading`), and the manager exits with `leader election lost` |
| Graceful stop | the same clearing when the leader context ends |
| Restart | a fresh process with counters at zero (`resets()` in PromQL) and nothing remembered; it owns projections only after it is elected again |

`TestLiveLeaderObservability` (`admission` group) checks this in-process
with the real Lease and two managers, each with its own Hub, sampled every
25 ms. Before the leader loses the Lease, the follower exposes no owner
series. When another holder takes the Lease, the former leader's Hub is
cleared, a write for its old term is refused, and nothing reappears. At no
sample do both Hubs expose owner projections. The successor never exposes a
ready domain without that domain's binding or backlog series. Its binding
series are equal to the former leader's, rebuilt from the API. Its Hub
clears again when it stops. Through Prometheus on the Helm-installed chart,
`TestLiveHelmMonitoring` covers a killed leader and a release with no
leader ([integrated acceptance](metrics.md#integrated-acceptance)).

### Inspecting the Lease

```sh
kubectl -n konstapel-system get lease konstapel-controller-leader-election \
  -o custom-columns=HOLDER:.spec.holderIdentity,RENEWED:.spec.renewTime,ACQUIRED:.spec.acquireTime,TRANSITIONS:.spec.leaseTransitions,DURATION:.spec.leaseDurationSeconds
kubectl -n konstapel-system get events --field-selector reason=LeaderElection
```

- **Holder.** `holderIdentity` is `<pod name>_<random>`; the part before
  `_` is the pod that leads. Each process has its own suffix, so a
  restarted pod shows a new identity.
- **Liveness.** `renewTime` advances every couple of seconds while the
  holder is healthy. A `renewTime` older than `leaseDurationSeconds` (15s)
  means the Lease has expired and is free to take.
- **Changes.** `leaseTransitions` counts takeovers. Expect one more per
  leader loss, upgrade step or node failure; steady growth without such
  events means leaders keep losing renewal (API latency, CPU starvation).
- **Metrics.** Exactly one pod should report `konstapel_observation_ready 1`
  per enabled domain, and it should be the holder. A ready pod that isn't
  the holder is a stale target: check its scrape.

### Permission failures

The chart's Role grants Lease `get`/`update` of
`konstapel-controller-leader-election` and Lease `create` in
`konstapel-system`, and Event `create`/`patch` ([Leader election](#leader-election)).
Without them:

- A candidate that can't read or update the Lease is never elected and
  never reconciles. Election is never skipped.
- A leader that loses access can't renew: its log shows
  `leases.coordination.k8s.io "konstapel-controller-leader-election" is forbidden`,
  then `leader election lost`, and the pod restarts. It keeps serving probes
  and metrics, but owns nothing, so `KonstapelObservationUnavailable` fires
  for every enabled domain ([runbook](alert-runbooks.md#konstapelobservationunavailable)).
  Applied engine policies stay in place.
- Check the ServiceAccount's grants:

  ```sh
  for verb in get update; do
    kubectl auth can-i "$verb" leases/konstapel-controller-leader-election -n konstapel-system \
      --as=system:serviceaccount:konstapel-system:konstapel-controller
  done
  kubectl auth can-i create leases -n konstapel-system \
    --as=system:serviceaccount:konstapel-system:konstapel-controller
  ```

  All three must answer `yes`. Restoring the Role lets the next candidate
  take the Lease after it expires.

### Measured recovery

These are test measurements, not service levels. Takeover waits for the
Lease to expire (15s by default; nothing releases it early), then for the
successor's refreshers to republish. Cache sync, API latency and host load
add to both.

| Case | Setting | Measured |
| --- | --- | --- |
| Lease stolen from a running leader (`TestLiveLeaderObservability`, 6s test Lease) | in-process, two managers | in two runs, the former leader cleared and exited about 4.2s after the Lease was taken (its 4s renew deadline); the successor was elected 7.6–8.8s after, and all its domains were ready about 8.6s after its election |
| Graceful leader stop (`TestLiveLeaderElection`, 15s Lease) | in-process | follower took over after about 20s |
| Leader pod killed (`TestLiveHelmMonitoring`) | Helm, Prometheus scrape every 15s | Lease taken after 14s, successor the only owner after 20s |
| Leader pod or worker node lost (`TestLiveHelmAvailability`) | Helm, two workers | Lease taken by the other pod 18.0–18.4s after the leader pod was force-deleted or its worker node lost, in two CI runs |
| Graceful leader removal, abrupt leader kill, node loss under traffic (`TestLiveHelmFailoverTraffic`) | Helm, two workers | Lease taken 17–23s after the graceful removal or kill and 18–21s after node loss; the gracefully removed leader exited in 1–13s ([Failover under traffic](#failover-under-traffic)) |
| Leader cut off from the API server under traffic (`TestLiveHelmFailoverTraffic`) | Helm, two workers | Lease taken 18.1s after the cut (one CI run); the cut-off process had exited by then; ready again as a follower 10.0s after the API returned |
| Lease access removed, then restored (`TestLiveHelmMonitoring`) | Helm | leader restarted 12s after losing access; `KonstapelObservationUnavailable` firing 90s after (1m hold); one owner 9s after access returned |

Alerts that need an owner domain can't fire while no replica owns it, and
one that was firing resolves without recovering. A condition that persists
through the gap fires again only after its full hold. Under the default
holds (`KonstapelObservationUnavailable`: 5m), a normal takeover never fires
it.

## Delayed former leaders

Leader election isn't fencing. A paused process, or a request already in
flight, can outlive its leadership. Each write therefore carries its own guard:

| Write | Guard against a stale attempt |
| --- | --- |
| Binding and profile status | `Update` with the read `resourceVersion`; a newer object is a conflict, and the next reconcile reads it |
| Engine policy create, repair | names are derived from the enforcement revision and never reused; repair is an `Update` with the read `resourceVersion` on a policy the binding owns at the same revision |
| Engine policy delete (superseded revisions) | before the first write, and again after listing owned policies, the binding and profile are re-read from the API server and must still have the snapshot's UID and generation. A changed snapshot aborts the Sync, and the binding resolves again. Each delete carries the listed object's UID and `resourceVersion` as preconditions. |
| Assessment run publication | deterministic run identities and conditional immutable S3 commits: matching bytes recover the original commit, and different bytes under the same identity are a conflict (`internal/s3store` `TestStagePublishAndRecover`, `TestConflictingContentNeverOverwrites`; across clients, [Publication fault fixtures](#publication-fault-fixtures)) |

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

### Publication fault fixtures

`publicationtest.RunPublicationFaults` (`internal/publication/publicationtest/faults.go`)
runs the same four cases against any `Publisher` store. Each case uses fresh
clients: another replica, or a restarted process.

| Case | Fault | What must hold |
| --- | --- | --- |
| `lost-stage-response` | the stager's last staging write lands, but the stager gets an error (`ErrUnavailable`) and is never used again | another client recovers the bytes under the run's identity; restaging the same bytes returns the same staging; they commit once |
| `lost-publish-response` | the commit lands, but the publisher gets an error (`ErrUnavailable`) | a second client with a shorter retention, and a third with another, both get the original receipt: publication ID, commit, `publishedAt`, retention and `expiresAt` = `publishedAt` + the committed retention. Different bytes under the identity are `ErrConflict` |
| `same-run-conflicting-bytes` | two clients stage different packages for one run | at most one commits; every other stage or publish of the other bytes, from any client, is `ErrConflict`; the served archive stays the committed one |
| `separate-client-recovery` | the stager is gone; four successors with different retentions race | each recovers the staging and all four get one receipt; a run that was never staged is `ErrCaptureLost` (not an outage) and has no publication |

Every case then reads the commit through a fresh client: `Inspect` and the
archive served by `Open` must match the receipt. Where the store can count
commit writes, exactly one must have been accepted.

A run is labelled with what its store can prove:

| Store | Kind | Run by |
| --- | --- | --- |
| `fake.Publisher` (every client is the one in-memory fake) | `shared-fake-store`: the contract's semantics only | `TestPublicationFaults` in `internal/publication/fake` (`task check`) |
| `s3store.Publisher` against an in-memory S3 server, in three versioning modes | `shared-fake-store`: the S3 publisher's handling, not real storage | `TestPublicationFaults` in `internal/s3store` (`task check`) |
| `s3store.Publisher` against the pinned RustFS service, in three versioning modes | `durable-backend`: the only durable-backend acceptance | `TestLivePublicationFaults` (`recovery` group) |

For S3, each client is a new SDK client with its own HTTP transport
(`internal/s3store/s3storetest`), as a separate replica builds one. A lost
response is dropped on that client only (`s3fault.LostResponses`), after
the service has processed the request: retries inside the same call lose
their responses too. A `durable-backend` claim is refused unless its clients
are independent publishers (`CheckClients`).

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
| Lease under the chart Role | any earlier Lease is deleted before install, and a controller creates it under the chart's grants (Lease `get`/`update` by name, `create`); for longer than a lease duration the holder keeps it and renews it while the other replica contends; `LeaderElection` Events are written; impersonated requests and SubjectAccessReviews of the ServiceAccount allow exactly those grants and refuse Lease `list`/`watch`/`patch`/`delete`, other Leases and other namespaces; no controller log, current or previous, shows a refused Lease request (also after the rolling upgrade, restart and leader loss below) |
| Disruption budget | one voluntary eviction proceeds; a second, before its replacement is ready, is refused (`429`) |
| Rolling upgrade | a pod-template change replaces both controllers while at least two stay ready; a new replica takes the Lease the gracefully stopped one did not release |
| Constrained surge | with every worker cordoned, the surge pod stays `Pending`; both old replicas keep serving and the rollout is visibly incomplete until capacity returns |
| Preferred separation | with one worker cordoned, a replaced replica co-locates with the other and becomes ready (separation is never required) |
| Development values | `docs/examples/charts/development.yaml`: one replica, no controller PodDisruptionBudget, and a drain of the single replica proceeds |
| Controller outage | with the controller scaled to zero, Kyverno keeps enforcing the delivered policies and downloads keep serving; scaled back to two, a new process takes over the stale Lease (a new holder, one more transition) and renews it under contention |
| Leader pod loss | a force-deleted leader is replaced: the other replica takes the Lease (about 16–20 s in tests; exactly one more transition) and reconciles a new binding generation |
| Leader loss during an S3 outage | after capture, with S3 paused, the leader pod is force-deleted. The run stays `Publishing` (uncertain access, never `CaptureLost`) while S3 is down. The capture lived only in that pod's staging volume, so once S3 returns the run ends as a truthful `CaptureLost`, and the next run publishes under a new identity |

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

### Failover under traffic

`TestLiveHelmFailoverTraffic` (same group, last: it stops a worker) installs
both charts again, with authenticated metrics over operator TLS, and keeps
client traffic running while it replaces replicas. Each event is judged by
what clients, S3 and metrics show, not by who holds the Lease.

| Traffic | What must hold for every request |
| --- | --- |
| Admission | every second, a privileged dry-run pod in the `Deny`-bound namespace is denied by one of the delivered engine policies (named in the denial), and every fifth second a compliant pod is admitted. A privileged pod admitted or a compliant one denied fails; other probe errors are recorded and may not last 30s |
| Downloads | every second, an authorized download through a test-owned `NodePort` Service with the chart Service's selector, on the control-plane node: kube-proxy sends each new connection to a ready endpoint, as the chart Service does. Transport errors, `503` and `429` are retried and recorded as transient; every request must return the receipt's package (same SHA-256) within 90s, and any other answer fails |

| Event | What must hold |
| --- | --- |
| Graceful follower replacement | the follower is deleted with its normal grace and is gone within the 45s shutdown budget (+10s; never `SIGKILL`ed). The leader keeps the Lease (same holder, acquisition time and transition count) and publishes a run started during the replacement; the replacement becomes ready |
| Graceful leader replacement, commit held | the leader has staged a run's package in S3 and the fault proxy holds its commit. The leader is deleted gracefully and is gone within the budget; its held commit ends with the process and is never forwarded. Another replica takes the Lease (one more transition, within 60s), its commit of the same run is held too, and the run stays `Publishing` with its UID. Released, it commits the same run (UID, publication ID) with the exact staged archive, once |
| Abrupt leader failure during collection | the leader is force-deleted while a run is `Collecting`. The capture lived only in that pod's staging volume: the run ends `Failed` with `CaptureLost`, S3 has no commit for it, and the next run publishes under a new identity |
| Leader API loss, commit held | the leader has staged a run and the fault proxy holds its commit. Then the leader's node drops every packet from that pod to the API server endpoints (an `iptables` rule in the node's `FORWARD` chain, so open connections stall as in a partition); S3 stays reachable. The other replica takes the Lease (one more transition, within 60s). The cut-off process exits on the lost leadership without forwarding its commit, the pod is not ready while it cannot reach the API, and no scrape of its metrics is answered (a scrape could not be authenticated anyway; in CI the restarted process served no metrics at all while cut off), so it serves nothing it remembered. Meanwhile a second operator's `ClusterRoleBinding` is deleted: every download replica refuses that operator (`403`) and still serves the first. The successor commits the same run once with the staged archive. With the rule removed, the former leader becomes ready as a follower: the Lease stays with the successor, which alone exposes owner metrics. The held run is the only new run, and the first run's receipt (publication ID, digest, `publishedAt`, `expiresAt`) is unchanged |
| Node loss, commit held | with the replicas on different workers, the leader's worker container is stopped while its commit is held. The replica on the other worker takes the Lease and commits the same staged run once; the download replica there serves the package directly |

After every event:
- the binding's engine policies have the same names, UIDs and specs as
  before (kept, never recreated), also after a reporting-only binding edit
  (the assessment interval) that the current leader must reconcile within
  90s;
- the Lease holder exposes the binding's owner metrics equal to the binding
  now (creation time, target namespaces, the edited interval) and is ready in
  every enabled domain, while every other ready replica exposes no owner
  series and no ready domain at any scrape.

Finally the new leader rotates the binding to `Audit` after the node loss.
The test records placement, Lease timings, termination times, run and
publication IDs, and per event the download attempts, transient failures
(first and last), slowest request and admission results
(`<output>/targeting/TestLiveHelmFailoverTraffic.json`).

Native exception acceptances aren't part of it: the chart deploys no
admission webhooks yet. `TestLiveReplicaAdmission` covers acceptance
identities across failover with in-process replicas
([checks](#checks)).

Measured in local and CI runs (test measurements, not service levels; host load
moves them):
- graceful removal took 1.0–13.1s for the leader and 0.5–9.4s for the
  follower, every exit `0`, never `SIGKILL`;
- the Lease was taken 17–23s after a graceful leader removal or an abrupt
  leader kill, and 18–21s after node loss;
- reporting-only edits were reconciled in about 2–5s after each event;
- downloads saw no transient failure during graceful replacements or the
  abrupt kill. After node loss, kube-proxy kept sending part of the new
  connections to the stopped node's endpoint for 32–41s: 8–10 attempts timed
  out on connect, each request succeeded on retry, the slowest after 7–15s;
- no privileged pod was admitted and every compliant pod was. Under heavy host
  load, single admission probes failed while Kyverno's webhook was briefly
  unreachable (fail closed, never admitted);
- leader API loss (one CI run): the successor took the Lease 18.1s after the
  cut, and the cut-off process had exited by then (its restart was seen
  18.1s after the cut). The revoked operator was refused by both download
  replicas on the first attempt, and the former leader was ready as a
  follower 10.0s after the API was reachable again. Downloads saw no
  transient failure and no admission probe failed during the event.

On a shared 4-CPU, 7 GiB development host the three-node cluster can starve
(I/O wait above 50%, swap in use): the kind API server restarted and the
leader lost its Lease before any fault was injected. Run the `availability`
group on an otherwise idle host or rely on CI.

### Handovers during outages, trust changes and revocation

Each case below changes a dependency or an authorization while leadership
moves, and is checked by what clients, stored objects and metrics show:

| During a handover | Test (group) | What must hold |
| --- | --- | --- |
| The leader loses the API server | `TestLiveHelmFailoverTraffic` leader API loss (availability) | see [Failover under traffic](#failover-under-traffic): the cut-off leader stops, commits nothing, is unready and serves no metrics; Kyverno keeps enforcing; the successor recovers the run with its staged bytes; nothing is fabricated |
| No replica can use the Lease | `TestLiveHelmMonitoring` no leader (monitoring) | the leader restarts; no owner series and no ready domain anywhere; `KonstapelObservationUnavailable` fires; one owner after access returns ([integrated acceptance](metrics.md#integrated-acceptance)) |
| S3 unreachable or held | `TestLiveHelmDurableRecovery`, `TestLiveHelmAvailability` S3 outage, `TestLiveHelmFailoverTraffic` held commits (availability); `TestLiveLeaderHandoverRecovery` (recovery) | the run stays `Publishing`, never `CaptureLost`, while access is uncertain; the successor commits the staged bytes once or records the original commit and expiry |
| Registry down | `TestLiveHelmBundles` follower pins and rollback (charts) | a successor with a verified cache delivers from it; replicas with an empty cache report `ContentUnavailable` and keep the applied policies |
| Bundle trust rotated to a key that did not sign the content, registry down | `TestLiveHelmBundles` follower pins (charts) | the successor holds the bytes and their proofs but delivers nothing for a new binding (unresolved, `ContentUnavailable`); the applied policy keeps its UID and digest; rotated back, the same successor delivers from its cache |
| Signing key deleted while the leader is lost | `TestLiveHelmDurableRecovery` signing (availability) | the successor recovers the stored signature without any private key and commits it; the signature is uploaded once and both artifacts verify offline |
| A download grant revoked | `TestLiveHelmFailoverTraffic` leader API loss (availability) | every download replica refuses the revoked operator at once; others keep access |
| A central exception restriction while no replica leads | `TestLiveReplicaAdmission` (assessments) | the surviving replica denies at once; earlier acceptances, revisions and snapshots are unchanged by failover |
| An exception revoked while no replica leads, or a leader stopped between persisting its revocation record and releasing the finalizer | `TestLiveReplicaAdmission`, `TestLiveRevocationHistory` (assessments) | with [revocation processing](policy-exceptions.md#revocation-processing) on (off by default), the next leader writes the [revocation record](policy-exceptions.md#revocation-records) exactly as admitted, or verifies the one already written without rewriting it, and only then releases the finalizer; nothing is renewed or reactivated |

Native exception grants are not delivered yet, so their handover stays open as add-self-service-policy-exceptions task 6.4 (formerly availability task 3.6). Native exception support is not HA-validated until that task passes. It gates exception features, not two-replica availability.

## Supported versions

The matrix is what the acceptance groups install and test; other versions are
untested, not known to fail. Inputs live in `scripts/runtime.env`,
`devbox.json` and the charts, and Renovate moves them.

| Component | Tested | Source |
| --- | --- | --- |
| Kubernetes | 1.37.0 (`kindest/node`); the runtime chart requires `kubeVersion >=1.36.0-0` (MutatingAdmissionPolicy) | `KONSTAPEL_NODE_IMAGE`, `charts/konstapel/Chart.yaml` |
| Cluster shape | `availability` group: one control plane and two workers (Kyverno pinned to the control plane); other groups: one node | `KONSTAPEL_CLUSTER_WORKERS` |
| kind / kubectl | 0.33.0 / 1.37.2 | `devbox.json` |
| Helm | 4.3.1 | `devbox.json` |
| Kyverno | chart 3.9.2 (`policies.kyverno.io/v1`, `wgpolicyk8s.io/v1alpha2`); CLI 1.19.2 | `runtime.env`, `devbox.json` |
| cert-manager (optional TLS mode) | v1.21.3 | `runtime.env` |
| S3-compatible backend | RustFS 1.0.3. Other services, including AWS S3, are untested | `KONSTAPEL_S3_IMAGE` |
| OCI registry for bundles | registry 3.1.2 (tag-schema fallback) and zot v2.1.23 (referrers API) | `runtime.env` |
| Prometheus Operator / promtool | v0.95.2 / v3.16.0 (monitoring group) | `runtime.env` |

- **Replicas.** Two controller and two download replicas is the tested default
  (`replicaCount: 2`, PodDisruptionBudget `minAvailable: 1`, rolling update
  `maxUnavailable: 0` and `maxSurge: 1`, preferred hostname anti-affinity,
  60s grace with a 45s shutdown budget). One replica is the development
  setting and gives no redundant service. More than two replicas are untested.
- **Rolling pairs.** The old and new revisions of a supported rolling upgrade
  share the Lease, the CRD schemas and the storage contracts, so they can lead
  and follow each other. Increasing replicas cannot make an incompatible pair
  safe.
- **Not recorded.** The kube-proxy mode and container runtime of the kind
  nodes, and real multi-zone clusters, are not recorded in the evidence and are
  untested.

## Operations runbook

Measured values are in [Measured recovery](#measured-recovery) and
[Failover under traffic](#failover-under-traffic). They are test results, not
service levels.

### Leadership

- One replica holds the Lease and runs reconcilers, assessment, publication
  and cleanup. Takeover waits for the old Lease to expire (15s; it is never
  released early), then for the successor to resync its caches: about 17-23s
  in the Helm tests, longer under load.
- Expect one more `leaseTransitions` per leader loss, upgrade step or node
  failure ([Inspecting the Lease](#inspecting-the-lease)). Steady growth
  without such events means renewals fail (API latency or CPU starvation).
- Check that exactly one pod reports `konstapel_observation_ready 1` per
  enabled domain and that it is the holder. Followers report ready 0 and no
  owner series; that is correct. A leader that cannot reach the API exits and
  restarts rather than serving remembered state.
- While no replica leads, Kyverno keeps enforcing the delivered policies,
  downloads keep serving from every ready download replica, and no new run or
  reconcile starts. Alerts needing an owner domain cannot fire
  ([alert runbooks](alert-runbooks.md)).

### Rolling upgrades and node maintenance

- Upgrade the CRD chart first, then the runtime chart (`helm upgrade`, see
  [Helm charts](../charts.md)). Each Deployment replaces pods one surge at a
  time and never drops below two ready replicas; the new pod must be ready
  before an old one is retired. A gracefully stopped leader does not release
  the Lease, so the next holder appears after it expires.
- If surge capacity is missing the surge pod stays `Pending`, both old
  replicas keep serving and the rollout stays visibly incomplete
  (`kubectl rollout status`) until capacity returns. Preferred anti-affinity
  lets replicas co-locate when only one node fits; that is not node redundancy.
- Voluntary evictions go one at a time: the PodDisruptionBudget refuses (`429`)
  a second one until the replacement is ready. Drain nodes sequentially.
- **`ProtectedReadersUnverified`.** The controller writes protected supporting
  evidence only while every download replica runs its own image. During the
  download rollout, or while one Deployment declares another image, runs that
  close report supporting evidence unavailable with this reason; the package
  carries no supporting context, technical evidence is unaffected. The next run
  after the rollout is complete carries it again
  ([protected-package readers](../charts.md#protected-package-readers)). The
  runs that closed during the rollout stay that way permanently: the closed
  run's report, package and status are never rewritten, so schedule download
  rollouts away from platform runs whose documents matter
  ([supporting evidence](../supporting-evidence.md)). Otherwise no action
  beyond finishing or reverting the rollout.
- **Downgrades.** Supported rollback is to a previously tested chart and image
  pair, or scaling to one replica, accepting reduced availability. Never
  disable election, authentication or retention recovery. Rolling the download
  service back below the supporting-evidence version while protected packages
  are retained is unsupported ([supporting evidence](../supporting-evidence.md)).
  Running the controller and download server from different images is
  unsupported outside a rollout.

### Failure modes

| Situation | What happens | Check |
| --- | --- | --- |
| Leader loses the API server | the leader exits on the lost Lease without forwarding held writes; it is unready and serves no metrics while cut off; the other replica takes over; the former leader returns as a follower. Kyverno keeps enforcing | Lease holder and transitions; `konstapel_observation_ready`; `KonstapelObservationUnavailable` if no replica can lead ([Permission failures](#permission-failures)) |
| Leader pod or node lost mid-run | before staging the run ends `Failed` with `CaptureLost` and the next run publishes under a new identity; after staging, the successor commits the same run with the staged bytes; after commit but before the receipt it records the original commit and expiry | `konstapel_publication_pending`, `konstapel_publication_failed`; the run's `Published` condition ([Failure walkthrough](#failure-walkthrough)) |
| S3 unreachable or held | runs stay `Publishing`, never `CaptureLost`, while access is uncertain; downloads of affected packages return `503` and clients retry. Nothing is fabricated | `KonstapelPublicationFailing`, `konstapel_operation_attempts_total{operation="evidence_publication",result="failure"}`, `konstapel_publication_failed` |
| Registry down | a replica with a verified cache keeps delivering from it; one with an empty cache reports `ContentUnavailable` and keeps applied policies | `KonstapelBindingUnresolved`, `konstapel_binding_condition{condition="Resolved"}` |
| Bundle trust rotated to a key that did not sign the content | nothing new is delivered (`ContentUnavailable`); the applied policy keeps its UID and digest; rotating back delivers from the cache | same as above; correct the trust configuration |
| Download authorization revoked | every download replica refuses the operator (`403`) at once, others keep access; no session affinity or leader proxy | download `403` responses |
| Kyverno API or permission loss | reported in binding conditions, no crash, recovers without restart | `KonstapelEngineUnavailable` |
| Evidence ages out with no new run | the current view turns stale; it is never shown healthy | `konstapel_binding_current_evidence_expiry_timestamp_seconds`, `KonstapelAssessmentOverdue` |
| Packages past expiry cannot be deleted | retention blocks deletion | `KonstapelCleanupBlocked`, `konstapel_cleanup_blocked` |

Per-pod staging is not shared: a capture that was never staged in S3 is lost
with its pod and reported as `CaptureLost`. Retries repeat the whole download
with fresh authorization; there is no resumable download.

### Alerts and metrics

Use the families in [metrics](metrics.md) and the starter alerts in
[alert runbooks](alert-runbooks.md): `KonstapelMetricsUnavailable`,
`KonstapelObservationUnavailable`, `KonstapelBindingUnresolved`,
`KonstapelEngineUnavailable`, `KonstapelAssessmentOverdue`,
`KonstapelPublicationFailing`, `KonstapelCleanupBlocked`. During a takeover,
a condition that persists through the gap fires again only after its full hold,
and the default `KonstapelObservationUnavailable` hold (5m) is not reached by a
normal takeover.

### Shared hosts

The three-node `availability` group needs an otherwise idle host. On a shared
4-CPU, 7 GiB development host it starved (I/O wait above 50%, swap in use): the
kind API server restarted and the leader lost its Lease before any fault was
injected. A local failure there is not evidence of a defect, and a passing CI
run is the gate. Run one live cluster at a time.

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
devbox run -- go test ./internal/publication/... ./internal/s3store/ -run 'PublicationFaults|DurableClaim'
devbox run -- task acceptance OUTPUT=/absolute/fresh/path GROUP=admission   # includes TestLiveLeaderElection, TestLiveLeaderObservability
devbox run -- task acceptance OUTPUT=/absolute/fresh/path GROUP=recovery    # includes TestLivePublicationFaults (RustFS)
```

Serving on every replica (tasks 3.1 and 3.2):

```sh
devbox run -- go test ./internal/controller/ -run 'ServingRunnables|InformerSync|WebhookReadiness|WebhookTLS'
devbox run -- task acceptance OUTPUT=/absolute/fresh/path GROUP=assessments # includes TestLiveReplicaAdmission
```

`TestLiveReplicaAdmission` runs two elected in-process replicas that each
serve the exception webhooks. The API server reaches them through a TCP
switch in the test, so every step names the replica that answered. It checks
that:
1. both replicas become ready while one leads, and the follower serves
   acceptance and dry runs attributed to the authenticated caller;
2. a central restriction (profile eligibility `Forbidden`) denies creation,
   renewal and dry run immediately on the leader and on the follower, and
   lifting it accepts again at once;
3. a namespace whose binding's OCI content is unavailable gets `Unresolved`
   denials while the replica stays ready and other namespaces are accepted;
4. renewal through the follower records a new revision by the renewing
   caller; a skipped revision or a rewritten record is rejected;
5. after the leader stops, the survivor serves acceptance, restriction and
   dry run while no replica leads (the evidence records that it answered
   before its election); the new leader snapshots those acceptances
   as admitted; failover changes no earlier acceptance, expiry, revision or
   snapshot; a replacement replica follows, becomes ready and serves renewal;
6. an expired webhook certificate rotation on the follower makes it unready
   but live while the leader keeps serving; a valid rotation restores it.

Native exception grants aren't delivered yet (add-self-service-policy-exceptions
groups 3 and 4), so step 5 covers acceptance records and snapshots only.

`TestLiveLeaderElection` starts two in-process candidates against the
disposable cluster and checks four things:
1. exactly one becomes leader and stays leader;
2. after the leader stops, the other takes over once the Lease expires and
   reconciles a new binding generation;
3. a candidate whose identity is bound to the controller ClusterRole, but not
   the Lease Role, is never elected and leaves a binding edit unreconciled;
4. granting the Lease Role lets it lead.

## Not yet available

- Chart deployment of the exception admission webhooks, and native exception
  grants, which wait for an upstream Kyverno release
  (add-self-service-policy-exceptions).
- HA validation of native exception grants: native exception support is not
  HA-validated until add-self-service-policy-exceptions task 6.4 (failover and
  leadership changes against delivered grants) passes.
