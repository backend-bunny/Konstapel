# Alert runbooks

These runbooks belong to the starter alerts that the runtime chart renders
with `metrics.prometheusRule.enabled` ([Monitoring
integration](../charts.md#monitoring-integration)). Each alert links here
through its `runbook_url` annotation. The metrics they read are in the
[metrics guide](metrics.md).

All starter alerts default to `severity: warning`. Thresholds, windows, holds,
severity and enablement are chart values under
`metrics.prometheusRule.groups.<group>.rules.<Alert>`.

| Alert | Group | Fires when | Default hold |
| --- | --- | --- | --- |
| [KonstapelMetricsUnavailable](#konstapelmetricsunavailable) | `konstapel-availability` | no target of the release, or no target with a successful scrape | 5m |
| [KonstapelObservationUnavailable](#konstapelobservationunavailable) | `konstapel-availability` | an enabled domain has no fresh, ready projection on exactly one replica | 5m |
| [KonstapelBindingUnresolved](#konstapelbindingunresolved) | `konstapel-operations` | a binding's `Resolved` is false or unknown | 10m |
| [KonstapelEngineUnavailable](#konstapelengineunavailable) | `konstapel-operations` | a capability the controller uses is false or unknown | 10m |
| [KonstapelAssessmentOverdue](#konstapelassessmentoverdue) | `konstapel-operations` | time is past the scheduled due time + collection timeout + `threshold` (600s) | 5m |
| [KonstapelPublicationFailing](#konstapelpublicationfailing) | `konstapel-operations` | a run is currently retrying publication and at least `threshold` (3) attempts failed in `window` (15m) | 2m |
| [KonstapelCleanupBlocked](#konstapelcleanupblocked) | `konstapel-operations` | storage refuses an expiry deletion, or pending cleanup is `threshold` (3600s) past the oldest expiry | 15m |

## How the rules read metrics

- **Scope.** Every selector carries the release's exact scope matchers
  (`job`, `namespace` and, with the chart's ServiceMonitor,
  `app_kubernetes_io_instance`), and every aggregation keeps those labels.
  Two releases, even with identically named bindings, never mix.
- **One owner per domain.** Binding and backlog gauges come from the elected
  leader only. A rule reads them only from the single replica whose domain
  projection is ready and younger than `metrics.prometheusRule.maxProjectionAge`
  (default 4m). With no such replica, or with several (for example a
  lingering former leader), the rule reads nothing. It aggregates with
  `max`, never summing across replicas. Failed publication attempts are per
  process and reset on restart: they are counted with `increase`, then
  summed across replicas.
- **Missing data is not health.** When the release is not scraped, or a
  domain has no single fresh owner, the operational alerts cannot fire, and
  a firing one **resolves**. That resolution is *not* recovery. The
  availability alerts report the gap instead: `KonstapelMetricsUnavailable`
  for scraping, `KonstapelObservationUnavailable` for each domain. Before you
  treat a resolved alert as fixed, check that neither is firing and confirm
  recovery in the owning status (each runbook's recovery check).
- **A failover can restart holds.** A clean Lease handover keeps a pending
  alert's hold. If the old and new leader briefly overlap, or neither
  publishes for a scrape, the domain has no single owner; a pending
  operational alert then starts its hold again, so it can fire up to one
  hold later. Its condition is never counted twice.
- **Nothing here is a compliance statement.** The starter alerts report
  Konstapel's operation. None reports a framework score, a violation count,
  or that workloads pass. For outcome alerts, see
  [Outcome queries for custom alerts](#outcome-queries-for-custom-alerts).

Never silence these alerts by disabling verification, deleting retained
records or AssessmentRuns, removing finalizers, relaxing a binding's mode,
or granting exceptions. Disable or tune a rule through its chart values
instead.

The commands below assume the chart's `konstapel-system` namespace and use
the status fields that the owning contracts define:
[targeting](targeting-api.md#reading-status),
[assessments](assessment-contract.md) and
[evidence storage](s3-evidence.md). Replace `BINDING` and `RUN` with real
names. AssessmentRuns carry their binding's UID in the
`compliance.erenius.io/binding-uid` label, also after the binding is gone.

## KonstapelMetricsUnavailable

**Meaning.** For 5 minutes, Prometheus has had no target for this release,
or none of its targets was scraped successfully. A ServiceMonitor that
selects nothing leaves no `up` series at all; the rule covers that case
explicitly. One failing replica while another is scraped does not fire;
`KonstapelObservationUnavailable` reports it if that replica was the leader.

**Impact.** No other Konstapel alert can fire. This alert says nothing about
enforcement, assessments or evidence, which keep running.

**Diagnose.**

```sh
# Are the controller pods running, and is the metrics Service backed?
kubectl -n konstapel-system get pods -l app.kubernetes.io/component=controller
kubectl -n konstapel-system get endpointslices -l kubernetes.io/service-name=konstapel-controller-metrics
# Does the ServiceMonitor exist with your Prometheus's selector labels?
kubectl -n konstapel-system get servicemonitor konstapel-controller --show-labels
# May Prometheus's ServiceAccount scrape? (use its namespace and name)
kubectl auth can-i get /metrics --as=system:serviceaccount:monitoring:prometheus
```

Then look at the target on Prometheus's Targets page:

- **No target:** Prometheus's `serviceMonitorSelector` or
  `serviceMonitorNamespaceSelector` does not admit the ServiceMonitor, or
  `metrics.enabled` is off. An external scrape job must put the labels of
  `metrics.prometheusRule.scope.matchers` on its series.
- **401 or 403:** the reader ServiceAccount is not in `metrics.readers` (or
  not bound to `konstapel-metrics-reader`), or its token is invalid.
  Revocation and grants take effect within the cache bounds in
  [Controller metrics](../charts.md#controller-metrics).
- **TLS errors:** the CA or server name does not match the served
  certificate. See the ServiceMonitor's TLS settings in
  [Monitoring integration](../charts.md#monitoring-integration). Never set
  `insecureSkipVerify`.

**Recovery check.** The target is `UP` and `up` is 1 for at least one pod.
Then check `KonstapelObservationUnavailable`: a successful scrape does not
mean that the controller has rebuilt its projections.

## KonstapelObservationUnavailable

**Meaning.** For 5 minutes, the enabled domain (`targeting`, `assessment`,
`bundle_resolution` or `evidence_storage`) has had no projection that is
ready and fresh on exactly one replica. The causes:

- No replica leads, or the new leader has not yet synchronized its cache and
  republished. A controller that cannot renew or take the Lease (for example
  its Role lost access to `leases`) exits with `leader election lost`,
  restarts, and keeps serving metrics without owning anything, so every
  enabled domain fires while `up` stays 1.
- The owner withdrew its projection because it cannot read its state (watch
  or cache failure), or stopped refreshing it. The exporter reports
  `ready 0` once the projection is 2 minutes old.
- Several replicas appear ready, for example a former leader whose last
  samples linger without staleness markers. Ownership is ambiguous, so
  nothing is read.

A disabled domain (`konstapel_observation_enabled 0`) never fires. An enabled
domain fires even before its first data.

**Impact.** That domain's operational alerts cannot fire, and any of them
that was firing has resolved without recovering.

**Diagnose.**

```sh
# Who holds the Lease?
kubectl -n konstapel-system get lease konstapel-controller-leader-election -o jsonpath='{.spec.holderIdentity}{"\n"}'
# Did the controller restart, or report watch or cache errors?
kubectl -n konstapel-system get pods -l app.kubernetes.io/component=controller
kubectl -n konstapel-system logs deploy/konstapel-controller --since=15m
```

In Prometheus, compare the replicas (add your scope matchers):

```promql
konstapel_observation_ready{domain="assessment"}
```

```promql
time() - konstapel_observation_updated_timestamp_seconds{domain="assessment"}
```

Exactly one pod should report `1`, with an age under 2 minutes. A leader at
`0` with a growing age is a stalled owner: its logs name the read that fails.
Two pods at `1` means that one target's samples are stale; check that both
targets are scraped.

**Recovery check.** One replica reports ready with a fresh projection. Then
look at the domain's own alerts below: a condition that persisted through
the gap fires again only after its full hold.

## KonstapelBindingUnresolved

**Meaning.** For 10 minutes, a binding's `Resolved` condition has been
`False`, or unknown (missing, or not observed for the binding's current
generation). This reflects the binding's configuration, not its workloads.

**Impact.** Previously applied enforcement stays in force. Changes to the
binding or profile are not delivered. Exceptions are blocked in the
binding's targets. Assessment evidence is incomplete (stale scope), never a
pass.

**Diagnose.**

```sh
kubectl get compliancebinding BINDING -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
kubectl get compliancebinding BINDING -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.profile.name}{"\n"}'
```

The `Resolved` reason (`ProfileNotFound`, `ContentUnavailable`,
`UnknownPolicy`, `UnsupportedScope`, `InvalidConfiguration` or
`InvalidSelector`) names the fix; see
[Troubleshooting](targeting-api.md#troubleshooting). For bundle content
(`ContentUnavailable`), check the profile's condition and
[Policy bundles](../policy-bundles.md).

**Recovery check.** `Resolved=True` with `observedGeneration` equal to
`metadata.generation`, then `EngineReady=True` once delivery catches up. The
alert resolves when the binding resolves, or when the targeting domain stops
being observable. Only the first is recovery.

## KonstapelEngineUnavailable

**Meaning.** For 10 minutes, a Kyverno capability that Konstapel uses has
been unavailable. `capability` is `policy_delivery` (ValidatingPolicy) or
`assessment` (PolicyReports). `false` means the API is missing or the
controller's access is denied. `unknown` means the dependency could not be
asked (API server or aggregation failure, timeout).

**Impact.** For `policy_delivery`, new or changed bindings are not
delivered, while existing policies stay in force. For `assessment`, reports
cannot be read, so evidence becomes incomplete while delivery may still
work. Neither implies a workload result.

**Diagnose.**

```sh
kubectl get compliancebindings
kubectl get compliancebinding BINDING -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
kubectl api-resources --api-group=policies.kyverno.io
kubectl api-resources --api-group=wgpolicyk8s.io
kubectl auth can-i list policyreports --all-namespaces --as=system:serviceaccount:konstapel-system:konstapel-controller
```

The `EngineReady` reasons (`EngineAPINotServed`, `EngineResourceMissing`,
`EngineResourceUnsupported`, `EngineAccessDenied`, `EngineUnavailable`) and
their fixes are in [Reading status](targeting-api.md#reading-status). The
required APIs are listed in
[External engine capabilities](../charts.md#external-engine-capabilities).
Restore Kyverno or the controller's generated RBAC; do not grant broader
permissions than the generated role.

**Recovery check.** The capability is `true` in
`konstapel_capability_condition`, and affected bindings report
`EngineReady=True`. The controller retries by itself; no restart is needed.

## KonstapelAssessmentOverdue

**Meaning.** For 5 minutes, a binding's scheduled assessment obligation has
been unmet 600s (`threshold`) after its due time plus the binding's
collection timeout. The due time is `schedule.outstandingSince`, the
earliest scheduled time not yet met by a scheduled run that closed with an
assessment export, or else the next scheduled time. Each binding follows its
own interval. A binding that has never been assessed is due at its initial
time.

These do **not** meet the obligation: diagnostic exports, lost captures,
deleted or manual runs, and namespace requests. They can advance the latest
closure (`konstapel_binding_last_closed_timestamp_seconds`) but not the due
time. A run whose publication fails afterwards does meet it;
`KonstapelPublicationFailing` reports that failure separately.

**Impact.** The binding's assessment evidence is older than its schedule
promises. Current evidence may also have expired; see the stale-evidence
query below.

**Diagnose.**

```sh
kubectl get compliancebinding BINDING -o jsonpath='{.status.assessment.schedule.outstandingSince} {.status.assessment.schedule.nextDue} {.status.assessment.schedule.activeRun.name}{"\n"}'
kubectl get compliancebinding BINDING -o jsonpath='{.status.assessment.destination.ready} {.status.assessment.destination.reason}: {.status.assessment.destination.message}{"\n"}'
kubectl get assessmentruns -l compliance.erenius.io/binding-uid=$(kubectl get compliancebinding BINDING -o jsonpath='{.metadata.uid}') \
  -o custom-columns='NAME:.metadata.name,PHASE:.status.phase,EVIDENCE:.status.summary.evidence.completeness,CLOSED:.status.window.closed'
kubectl get assessmentrun RUN -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
```

- No active run, and the destination is not ready: scheduling waits for a
  usable evidence destination ([evidence storage](s3-evidence.md)).
- An active run is stuck `Pending` or `Collecting`: check its conditions and
  the engine capabilities (`KonstapelEngineUnavailable`).
- Runs close with a diagnostic export or `CaptureLost`: each gives the cause
  in its conditions. They do not meet the obligation, so the alert stays.

**Recovery check.** A scheduled run closes with an assessment export.
`schedule.outstandingSince` then clears or moves to a later time. Missed
times stay recorded in `schedule.gaps` and `missedTotal`; they are not
claimed as assessed.

## KonstapelPublicationFailing

**Meaning.** For 2 minutes, at least one closed run has been retrying
publication of its evidence package, and at least 3 (`threshold`)
publication attempts failed in the last 15m (`window`), summed across
replicas. The backlog gauge counts `Publishing` runs whose `Published`
condition is `False` with reason `Retrying`, or `SigningPending` while
required signing is unmet.

A failing run retries only until the publish timeout, 5 minutes after its
collection closed. It then becomes `Failed` with `PublicationFailed` (or
`SigningFailed`), a historical failure, and the alert resolves. That is why
the default hold is shorter than the timeout. The resolution is not
recovery: check the next runs.

**Impact.** The run's assessment summary stands; publication success and
evidence completeness are reported independently. The evidence package is
not committed to storage and cannot be downloaded.

**Diagnose.**

```sh
kubectl get assessmentruns -o custom-columns='NAME:.metadata.name,BINDING:.spec.bindingRef.name,PHASE:.status.phase,PUBLISHED:.status.conditions[?(@.type=="Published")].reason,DEST:.status.destination.name'
kubectl get assessmentrun RUN -o jsonpath='{.status.conditions[?(@.type=="Published")].message}{"\n"}{.status.publication.failure.reason}: {.status.publication.failure.message}{"\n"}'
```

The message names the failing storage operation or signing step: missing
credentials, a refused write, an unreachable endpoint, or an unusable
signing key ([evidence signing](evidence-signing.md)). Fix the destination
or its credentials ([evidence storage](s3-evidence.md)). Never disable
signing that the destination requires.

**Recovery check.** New runs reach `Completed` with
`status.publication.publishedAt` recorded. Runs that already failed stay
`Failed`: their evidence was not published and is not re-exported under the
old identity.

## KonstapelCleanupBlocked

**Meaning.** For 15 minutes, either storage has refused an expiry deletion
(`cleanup.state: RetentionBlocked`: an object lock, a legal hold or a
missing delete permission), or deletions not yet confirmed have outlasted
the oldest recorded expiry by more than 3600s (`threshold`). The latter
includes `DeletionFailed`, which retries with backoff of up to an hour.

These records outlive their bindings: deleting a binding never ends
retention, so the alert can concern runs of a deleted binding. The gauges
carry no binding name.

**Impact.** Expired evidence stays in storage. New downloads of it are
refused after expiry. Nothing about current assessments changes.

**Diagnose.**

```sh
kubectl get assessmentruns -o custom-columns='NAME:.metadata.name,BINDING:.spec.bindingRef.name,EXPIRES:.status.publication.expiresAt,CLEANUP:.status.publication.cleanup.state,ATTEMPTS:.status.publication.cleanup.attempts'
kubectl get assessmentrun RUN -o jsonpath='{.status.publication.cleanup.message}{"\n"}{.status.destination.name} {.status.destination.bucket}/{.status.destination.prefix}{"\n"}'
```

- `RetentionBlocked`: remove the object lock or legal hold, or grant the
  delete permissions listed in [evidence storage](s3-evidence.md), on the
  run's prefix. The next retry (within an hour) deletes the package.
- `DeletionFailed`: check `cleanup.message` and the storage backend's
  health. Retries continue by themselves.

Do not remove a run's finalizer or delete the run to clear the alert. That
releases the record without deleting the stored evidence.

**Recovery check.** The runs report `cleanup.state: Deleted` and
`publication.phase: Deleted`, and `konstapel_cleanup_blocked` and
`konstapel_cleanup_pending` return to 0.

## Outcome queries for custom alerts

The starter alerts never page on outcome counts. These framework-neutral
queries let you build your own. Each reads check-instance states of the
[binding summaries](metrics.md#binding-summaries), which mirror the
assessment owner's normalized status:

| State | Binding status field (current view) |
| --- | --- |
| `pass`, `fail`, `error`, `skip` | `status.assessment.current.outcomes` |
| `accepted_risk` | `status.assessment.current.outcomes.acceptedRisk` |
| `out_of_scope` | `status.assessment.current.outcomes.notApplicable` |
| `unknown` (includes engine warnings) | `status.assessment.current.outcomes.unknown` |
| `missing`, `rejected`, `unresolved` | `status.assessment.current.evidence` |

```sh
kubectl get compliancebinding BINDING -o jsonpath='{.status.assessment.current.outcomes}{"\n"}{.status.assessment.current.evidence}{"\n"}{.status.assessment.current.nextExpiry}{"\n"}'
```

The counts are check instances, not satisfied controls; never turn them into
a percentage. In alerts, join them to the domain's owner as the starter rules
do, so that missing observability is not read as zero.

Failing checks in a binding's current evidence:

```promql
max by (job, binding) (konstapel_binding_assessment_checks{view="current", state="fail"}) > 0
```

Accepted risks, which are never passes:

```promql
max by (job, binding) (konstapel_binding_assessment_checks{view="current", state="accepted_risk"})
```

Checks without a usable result. `unknown` includes engine warnings, so it
is not only missing evidence:

```promql
sum by (job, binding) (
  max by (job, binding, state) (
    konstapel_binding_assessment_checks{view="current", state=~"unknown|missing|rejected|unresolved"}
  )
)
```

Stale current evidence. There is no `stale` state: the freshness gauge keeps
the owner's expiry time, and the current view is `unknown` from then until
the owner evaluates again:

```promql
time() >= max by (job, binding) (konstapel_binding_current_evidence_expiry_timestamp_seconds)
```

A known current summary whose evidence is incomplete. A summary can be
available without its evidence being complete:

```promql
max by (job, binding) (konstapel_binding_assessment_complete{view="current"}) == 0
```

A custom rule in chart values, for example failing checks held for an hour:

```yaml
metrics:
  prometheusRule:
    groups:
      my-outcomes:
        rules:
          MyBindingHasFailingChecks:
            expr: |-
              max by (__scope_labels__, binding) (
                konstapel_binding_assessment_checks{__scope__, view="current", state="fail"}
                and on (__scope_labels__, instance) __owner(assessment)__
              ) > __threshold__
            threshold: 0
            for: 1h
            runbookURL: https://runbooks.example.org/failing-checks
```

`task test` evaluates every `promql` block on this page, like those in the
[metrics guide](metrics.md#query-examples), and checks every `kubectl`
status path against the CRDs.
