# Kyverno permissions for official bundles

Konstapel delivers its policies to a Kyverno installation that you install and
manage. On the pinned Kyverno release, the policies in the official bundles
need one grant that the Kyverno chart doesn't include. You apply it as the
Kyverno administrator. Konstapel never installs, changes or checks Kyverno's
RBAC, and its own charts contain no Kyverno grant
(`TestPermissionMatrixGrantsAreKyvernoOwned`).

Without the grant, Kyverno keeps enforcing and reporting, but every delivered
policy reports `RBACPermissionsGranted=False`. The binding then stays
`EngineReady=False` `ReplacementPending`, and its message names the missing
verbs (see [readiness diagnostics](targeting-api.md#readiness-diagnostics)).
This happens in `Audit` mode as well as in `Deny`: Audit is not
permission-free.

## What to grant

Verified for Kyverno chart 3.9.2 (Kyverno v1.19.2) only. The
[permission matrix](kyverno-permission-matrix.json) has the live evidence and
the reasons.

| Controller | Resource | Verbs | Why |
| --- | --- | --- | --- |
| reports controller | `pods/ephemeralcontainers` | `get`, `list`, `watch` | Kyverno's readiness check (`RBACPermissionsGranted`) asks for these verbs on every resource a policy with background evaluation matches. Konstapel always enables background evaluation, and the delivered policies match the ephemeral-containers subresource. |
| admission controller | none | | Admission reads the object from the request. With no grant on the subresource, Deny still rejected privileged ephemeral containers and Audit still recorded them. |

The chart already binds Kubernetes' `view` role to the reports controller,
which covers Pods and workload controllers. Keep that binding: without it the
reports controller can't scan, and readiness fails on Pods too.

The example is
[`docs/examples/kyverno/reports-controller-ephemeralcontainers.yaml`](../examples/kyverno/reports-controller-ephemeralcontainers.yaml):
one ClusterRole with exactly those verbs, carrying the chart's aggregation
label `rbac.kyverno.io/aggregate-to-reports-controller: "true"`. The chart's
reports-controller ClusterRole aggregates every role with that label, so the
example needs no binding. There is no `update`, `patch` or wildcard, and no
role for the admission controller or for Konstapel.
`TestKyvernoRBACExampleMatchesMatrix` keeps the example equal to the matrix.

The upstream Kyverno test fixture that the acceptance environment applies
(`scripts/environment.sh`) grants more than this: it also gives the admission
controller `get`, `list`, `watch` and `update`. The matrix found none of that
required.

## Your installation's identities

Identities depend on how Kyverno was installed. With the 3.9.2 chart:

| What | Chart default | Changes with |
| --- | --- | --- |
| Namespace | `kyverno` | the Helm release namespace |
| Reports-controller service account | `kyverno-reports-controller` | `nameOverride` (`<nameOverride>-reports-controller`) or `reportsController.rbac.serviceAccount.name`; not the release name |
| Aggregating ClusterRole | `kyverno:reports-controller` | the release name and `fullnameOverride` (`<fullname>:reports-controller`, for example `policy-kyverno:reports-controller` for release `policy`) |
| Aggregation label | `rbac.kyverno.io/aggregate-to-reports-controller: "true"` | nothing in the chart; the role's second selector includes the release name, so don't rely on it |

The defaults were observed on a cluster; the variations come from
`helm template` of the pinned chart with another release name, namespace and
`nameOverride`.

With `reportsController.rbac.create=false` the chart creates neither the
service account, the aggregating ClusterRole nor the `view` binding: you
manage the reports controller's RBAC yourself. Bind the example's
ClusterRole (the aggregation label is then inert) to the service account
named in `reportsController.rbac.serviceAccount.name`, next to your `view`
grant. This variant was checked with `helm template` only, not on a cluster.

Look them up instead of assuming. Set `NS` to Kyverno's namespace:

```sh
NS=kyverno
# The reports controller's service account
SA=$(kubectl get deployment -n "$NS" -l app.kubernetes.io/component=reports-controller \
  -o jsonpath='{.items[0].spec.template.spec.serviceAccountName}')
echo "$SA"
# The aggregating ClusterRole and its selectors
kubectl get clusterrole -o json | jq -r '.items[] | select(.aggregationRule != null and (.metadata.name | endswith(":reports-controller")))
  | "\(.metadata.name) \(.aggregationRule.clusterRoleSelectors | map(.matchLabels) | tojson)"'
```

On the pinned chart, installed as `scripts/environment.sh` installs it:

```text
kyverno-reports-controller
kyverno:reports-controller [{"rbac.kyverno.io/aggregate-to-reports-controller":"true"},{"app.kubernetes.io/component":"reports-controller","app.kubernetes.io/instance":"kyverno","app.kubernetes.io/part-of":"kyverno"}]
```

If the first selector differs, change the example's label to match it.

## Apply and verify

```sh
kubectl apply -f docs/examples/kyverno/reports-controller-ephemeralcontainers.yaml
for verb in get list watch update patch; do
  echo "$verb $(kubectl auth can-i "$verb" pods --subresource=ephemeralcontainers --as="system:serviceaccount:$NS:$SA")"
done
```

Aggregation takes a moment. Once it has settled, the output is:

```text
get yes
list yes
watch yes
update no
patch no
```

`kubectl auth can-i` exits non-zero for `no`; that is expected here. Before
the grant (chart RBAC only) all five are `no`. The same loop with
`--as=system:serviceaccount:$NS:kyverno-admission-controller` prints `no`
for every verb after the grant: the example doesn't touch the admission
controller.

These outputs were observed on a disposable kind cluster with the pinned
chart, starting from the chart's own RBAC (the acceptance fixture removed);
see [Recorded verification](#recorded-verification).

To remove the grant, delete the same file. Kyverno reports the delivered
policies not ready again only when it next recomputes their conditions; see
[remaining limitations](#remaining-limitations).

## After applying the grant

Kyverno 1.19.2 doesn't recompute `RBACPermissionsGranted` when RBAC changes.
It computes the condition when a policy is created or updated. Its informer
resync doesn't help, because the policy-status handlers skip updates with an
unchanged `resourceVersion`: in the matrix's `resyncRepair` probe, every
policy still reported `False` 20 minutes after the grant. Earlier Kyverno
releases re-ran the check every 10 seconds through the webhook watchdog. That
was removed as a SubjectAccessReview storm
([kyverno/kyverno#17058](https://github.com/kyverno/kyverno/issues/17058)),
and nothing else triggers it.

Konstapel therefore rechecks its own policies. While a current policy
reports `RBACPermissionsGranted` `False` or `Unknown`, the controller writes
one annotation on it:

```yaml
compliance.erenius.io/readiness-recheck: "3@2026-11-27T13:17:08Z" # attempt@time
```

Kyverno recomputes the conditions on that metadata-only update. Once the
grant is in place, the next recheck makes the policy ready, and the binding
becomes `EngineReady=True` through ordinary reconciliation. You don't need to
restart Konstapel or Kyverno.

The recheck is bounded:

- **Schedule.** The first recheck comes 30 seconds after the policy was
  created. The next ones follow 1, 2, 4 and 8 minutes after the previous
  one, then every 15 minutes while the failure lasts. After you apply the
  grant, recovery therefore waits for the next recheck: under a minute
  shortly after delivery, at most 15 minutes for a policy that has been
  failing for longer. When the previous recheck is more than 30 minutes old
  (the policy was ready in between, or the controller wasn't running), the
  schedule starts again.
- **Scope.** Only the binding's current policies are rechecked: they carry
  Konstapel's ownership labels and a controller reference to the binding,
  and have the desired revision. Ready policies, other owners' policies,
  retained earlier revisions and held policies are never written. Neither
  are other readiness failures: `WebhookConfigured`, or a condition Kyverno
  hasn't reported.
- **Metadata only.** The write is a merge patch of that one annotation,
  conditional on the `resourceVersion` the controller has just read. The
  spec, generation, revision, enforcement epoch, labels, owner reference and
  other annotations stay as they are. The policy keeps its name and UID and
  enforces throughout. After an update conflict, the controller reads the
  policy again and decides again (at most three times per reconcile), so it
  never overwrites a newer write.
- **Stops when ready.** A ready policy is never rechecked, so a working
  installation gets no writes.
- **Cost of a grant that never comes.** Each failing policy gets one
  annotation write every 15 minutes. Each write makes Kyverno run its
  permission check again: three SubjectAccessReviews (`get`, `list`,
  `watch`) per resource the policy matches.
- Each recheck is logged at info level ("asked the engine to recheck policy
  readiness after a permission failure", with the policy and attempt).

To recheck at once instead of waiting, remove the annotation. That update
alone makes Kyverno recompute the conditions, and the schedule starts again:

```sh
kubectl annotate validatingpolicies -l compliance.erenius.io/binding-uid=<binding UID> \
  compliance.erenius.io/readiness-recheck-
```

Konstapel still never changes RBAC. It can't tell whether a grant is
present until Kyverno says so.

`EngineReady=True` means only that Kyverno accepted the policies. Whether
evidence is complete is a separate question (`status.assessment.current`,
see [Helm charts](../charts.md#external-engine-capabilities)).

### Remaining limitations

- **Removing a grant isn't noticed.** A ready policy is never rechecked, and
  Kyverno keeps reporting `RBACPermissionsGranted=True` until the policy
  changes for another reason, such as a new revision. The binding then stays
  `EngineReady=True` while the grant is missing. Kyverno keeps enforcing and
  reporting either way (see the matrix's `enforcementWhileNotReady`). The
  acceptance case records this as `removalVisible: false`.
- **One condition.** Only `RBACPermissionsGranted` is rechecked.
- **One version.** That a metadata-only update makes Kyverno recompute the
  condition was verified on Kyverno 1.19.2 only. Kyverno 1.20.0 has the same
  handlers by source inspection; it was not tested.
- **Upstream report pending.** An issue report to Kyverno about
  `RBACPermissionsGranted` not being recomputed after RBAC changes is
  pending; there is no link yet.

## Other Kyverno versions

The matrix and these commands hold for chart 3.9.2 only. After a Kyverno
upgrade, or for a bundle that matches another subresource, rerun the probe
(`flock /tmp/konstapel-live-cluster.lock devbox run --
scripts/kyverno-permission-matrix.sh OUTPUT`); the tests fail when the
delivered policies' matched subresources change.

The readiness recheck is verified for Kyverno v1.19.2 (chart 3.9.2) only.
`TestLiveKyvernoPermissionRecovery` runs against the pinned chart, so a
Kyverno upgrade is checked by the `capabilities` acceptance group. It fails
when a recheck no longer makes a repaired policy ready, and also when Kyverno
notices the grant by itself. The second case means the recheck may no longer
be needed.

## Recorded verification

On 2026-11-26, on a disposable kind cluster (`scripts/environment.sh`, kind
node `v1.37.0`, Kyverno chart 3.9.2), with the acceptance fixture deleted so
only the chart's RBAC remained, the commands on this page printed the outputs
shown: the reports-controller service account `kyverno-reports-controller`,
the `kyverno:reports-controller` selectors, all five verbs `no` before the
grant, `get`/`list`/`watch` `yes` and `update`/`patch` `no` after it, and
`no` for the admission controller. The aggregated `kyverno:reports-controller`
ClusterRole then contained exactly the example's rule. Deleting the example
returned all five verbs to `no`. No CI workflow repeats this run;
`TestKyvernoRBACExampleMatchesMatrix` keeps the example and this page tied to
the matrix. That the grant makes the delivered policies ready is the matrix's
`reports-read-only` scenario, which applied an identical aggregated role.

On 2026-11-27 the readiness recheck was verified on the same setup (kind node
`v1.37.0`, Kyverno chart 3.9.2, chart RBAC only):

- **Before any product change**, Audit and Deny copies of the bundle policy
  reported `RBACPermissionsGranted=False`. An annotation-only patch while the
  grant was still missing left them `False`. After the example was applied
  and `auth can-i` printed `yes`, they stayed `False` for 120 seconds
  untouched. Patching only `compliance.erenius.io/readiness-recheck` made
  them `True` within two seconds, with the same spec, UID and generation, and
  Deny still rejected a privileged Pod. Removing the grant again left them
  `True` for the following 60 seconds. In a separate run, the
  remove-the-annotation command above made the one policy it selected
  `True` at once, and left an unselected policy `False`.
- **Acceptance**: `TestLiveKyvernoPermissionRecovery` (the `capabilities`
  group, run by CI for every pull request). An Audit and a Deny binding
  reported the missing `get`, `list` and `watch` on
  `pods/ephemeralcontainers` with their policy names, and Deny kept
  enforcing. After a profile change, the earlier revisions stayed applied.
  The first recheck, 30 seconds after the replacements were created, left
  them `False` without the grant. 54 seconds after the example was applied,
  the second recheck made both bindings ready, without a restart and with
  the same policy UIDs, revisions and owners. The earlier revisions were
  removed only then. No further recheck was written in the following two
  minutes. The Audit binding's evidence was `Complete` with one attributable
  failure. After the grant was removed again, both bindings stayed ready
  (`removalVisible: false`).

