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
| Evidence downloads | `konstapel download-server` (`--listen :8443`) | none: a separate stateless process reading run status and the pinned destination | available; the chart Deployment is pending |
| Probes | `GET /healthz`, `/readyz` on `--health-probe-bind-address` (`:8081`) | independent of leadership and engine health | available (ping checks; serving-readiness wiring is task 3.1) |

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

- Serving readiness, which needs TLS and synchronized state (task 3.1).
- Bounded shutdown: 45s application budget, 20s HTTP drain, 60s grace (task
  4.4).
- Child-process cancellation on leadership loss (task 2.3).
- Multi-replica recovery and node-loss acceptance (group 5).
