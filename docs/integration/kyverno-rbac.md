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

To remove the grant, delete the same file. That makes every delivered policy
not ready again once Kyverno recomputes its conditions.

## After applying the grant

Kyverno 1.19.2 does not recompute `RBACPermissionsGranted` when RBAC
changes. The matrix observed the conditions stay stale until the
ValidatingPolicy object itself changed, and its informer resync did not help
within 20 minutes. Konstapel leaves an unchanged policy untouched, so a
binding that reported the missing grant does not become `EngineReady=True`
by ordinary reconciliation alone. This is a known limitation. How recovery
should happen is not settled yet and is covered separately by the
`improve-kyverno-readiness-diagnostics` change (tasks 3.1 and 3.2); this
page doesn't prescribe a procedure. In the matrix runs, a policy that was
created or changed while the grant was in place reported
`RBACPermissionsGranted=True`.

`EngineReady=True` means only that Kyverno accepted the policies. Whether
evidence is complete is a separate question (`status.assessment.current`,
see [Helm charts](../charts.md#external-engine-capabilities)).

## Other Kyverno versions

The matrix and these commands hold for chart 3.9.2 only. After a Kyverno
upgrade, or for a bundle that matches another subresource, rerun the probe
(`flock /tmp/konstapel-live-cluster.lock devbox run --
scripts/kyverno-permission-matrix.sh OUTPUT`); the tests fail when the
delivered policies' matched subresources change.

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
