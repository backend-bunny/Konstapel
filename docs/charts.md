# Helm charts

Konstapel will be distributed as two independent Helm charts published to
GHCR as OCI artifacts (add-helm-oci-distribution):

| Chart | OCI repository | Contents |
| --- | --- | --- |
| `charts/konstapel-crds` | `ghcr.io/backend-bunny/charts/konstapel-crds` | The generated `compliance.erenius.io` CRDs, retained on uninstall |
| `charts/konstapel` | `ghcr.io/backend-bunny/charts/konstapel` | The controller and its services, RBAC, admission and certificates |

Install the CRD chart first, as its own release. The runtime chart does not
depend on it, and neither chart depends on or installs Kyverno or
cert-manager.

**Status.** The CRD chart packages the generated definitions and has been
lifecycle-tested in kind (groups 1–2). The runtime chart installs the
controller and the download server from a digest-pinned image. It supports
both TLS modes and is tested installed in kind (group 3). The
ComplianceException admission webhooks and revocation processing are in the
chart, off by default ([Exception admission webhooks](#exception-admission-webhooks));
native exception grants are not, and nothing is published (groups 5–6). Every
remaining piece is listed with its owner and prerequisite under Phases.

## Feature availability

What an installed runtime chart provides today. The `konstapel` CLI workflow
in the [assessment-loop guide](integration/assessment-loop.md) is unchanged
and doesn't need the charts.

| Feature | In the chart | Needs |
| --- | --- | --- |
| Policy delivery (`ComplianceProfile`, `ComplianceBinding`) | yes | Kyverno serving `policies.kyverno.io/v1` ValidatingPolicy; see [External engine capabilities](#external-engine-capabilities) |
| Continuous assessments (`AssessmentRun`, `AssessmentRequest`) | yes | Kyverno PolicyReports (`wgpolicyk8s.io/v1alpha2`) |
| Verified OCI policy bundles | yes, with `bundles.sourcesConfigMap` (off by default) | the sources ConfigMap and the Secrets/ConfigMaps it references, created by you; see [OCI policy bundles](#oci-policy-bundles) |
| Evidence publishing to S3 | yes | an `EvidenceDestination` and its credential Secret, created by you; the chart has no storage values |
| Evidence downloads | yes, with `download.enabled` (default) | a TLS certificate (either TLS mode) and published runs |
| Evidence signing | yes; no chart values | `spec.signing` on an `EvidenceDestination` and its key Secret, created by you; it runs in the installed controller and download server with their existing permissions ([evidence signing](integration/evidence-signing.md#status-observability-and-deployment)) |
| Supporting-evidence attachments (`EvidenceAttachment`) | API, roles, registrant admission, association validation, destination pinning, recorded commitments and retention-gated cleanup; uploads and downloads on the download service (`download.enabled`) with its limits and source retention as `download.attachments` values; platform packages carry supporting evidence only while every download replica runs the controller's image ([Protected-package readers](#protected-package-readers)) | platform subjects bound to the `konstapel-evidence-attachment-*` roles and a default `EvidenceDestination` ([supporting evidence](supporting-evidence.md)) |
| Authenticated controller metrics | yes, with `metrics.enabled` (off by default) | a TLS certificate (either TLS mode) and a monitoring ServiceAccount allowed through `metrics.readers`; see [Controller metrics](#controller-metrics). Optional ServiceMonitor and PrometheusRule (each off by default, needing the Operator's CRDs): [Monitoring integration](#monitoring-integration) |
| Exception admission (`ComplianceException` webhooks: authenticated acceptance and revocation records) | yes, with `exceptions.webhooks.enabled` (off by default) | a TLS certificate (either TLS mode); every exception create and update then fails closed unless a ready controller replica admits it. See [Exception admission webhooks](#exception-admission-webhooks). It grants nothing: native Kyverno exceptions stay off, behind their own upstream gate |
| Exception revocation processing (revocation records, finalizer release) | yes, with `exceptions.revocationProcessing.enabled` (off by default) | `exceptions.webhooks.enabled`, which confines the controller's exception writes; the render refuses it alone. See [Exception revocation processing](#exception-revocation-processing) |
| External assessment provider client (`AssessmentProvider` probing and status) | yes, with `externalProviders.enabled` (off by default) | a client certificate Secret, trust ConfigMaps and providers, all installed by you; registration roles bound by you. No run uses an external provider yet. See [External assessment providers](#external-assessment-providers) |
| Native Kyverno exception grants (`PolicyException`) | **no** | add-self-service-policy-exceptions, waiting for an upstream Kyverno release. Neither switch above enables them. |

## Chart input contract

Every runtime value the charts will use is traced to the change that owns it
in merged code. An input marked **pending** has no merged owner yet. A
release can't substitute a fixture or a guess for it.

| Input | Source in merged code | Owner | Status |
| --- | --- | --- | --- |
| CRDs | `config/crd/bases/*.yaml`, generated by `scripts/generate.sh` (controller-gen). The chart copies them unchanged, apart from reviewed packaging metadata. | targeting, continuous-assessments, s3-evidence-publishing, self-service-policy-exceptions (API types in `api/v1alpha1`) | resolved; packaged (CRD chart) |
| Controller RBAC | `config/rbac/controller/role.yaml` (generated ClusterRole and the `konstapel-system` Role from `+kubebuilder:rbac` markers) | the API/controller owners | resolved |
| Role catalog | `config/rbac/{compliance-admin,compliance-viewer,assessment-operator,assessment-requester,exception-editor,evidence-download,evidence-attachments,controller-assessments}.yaml` | the feature owners | resolved |
| Admission policies | `config/admission/*.yaml` (Mutating/ValidatingAdmissionPolicies; MutatingAdmissionPolicy needs Kubernetes ≥ 1.36, hence `kubeVersion: >=1.36.0-0`) | continuous-assessments, s3-evidence-publishing, supporting-evidence-attachments | resolved |
| Manager entry point | `konstapel controller`: `--content-root` (`/usr/share/konstapel/content`), `--evidence-staging-dir` (`/var/lib/konstapel/staging`), `--leader-elect` (true), `--leader-election-namespace` (`POD_NAMESPACE`), `--metrics-bind-address` (`0`; with `metrics.enabled`, `:8443` plus `--metrics-cert-dir` and `--metrics-server-name`), `--health-probe-bind-address` (`:8081`), `--webhook-cert-dir`, `--webhook-port` (9443), and `POD_NAMESPACE` | targeting (manager), continuous-assessments, s3-evidence-publishing | resolved |
| Probes | `GET /healthz` and `/readyz` on the probe address. `/readyz` requires this replica's informer sync and, when webhooks are served, a verified unexpired webhook certificate on a started server; it fails while the manager shuts down. Leadership and engine health are not readiness inputs: they are reported in Conditions. | targeting, add-controller-high-availability | resolved |
| Admission webhooks | ComplianceException webhooks (`config/webhook/exceptions.yaml`), served only when `--webhook-cert-dir` is set (`tls.crt`/`tls.key`); revocation processing `--exception-revocation-processing` with the gated `config/rbac/controller/exception-revocation.yaml` | self-service-policy-exceptions | resolved; values `exceptions.webhooks` and `exceptions.revocationProcessing`, off by default. Native exception grants stay pending: that change waits for an upstream Kyverno release |
| Download service | `konstapel download-server`: `--listen` (`:8443`), `--tls-cert-file`, `--tls-private-key-file`, `--audience` (`konstapel-download`), `--temp-dir`, `--max-concurrent`, `--max-temp-bytes`, `--tls-ca-file`, `--tls-server-name`, `--shutdown-drain`, and the attachment limits `--attachment-max-bytes`, `--attachment-timeout`, `--attachment-max-concurrent` and `--attachment-retention` (chart values `download.attachments`); HTTPS probes `/healthz` and `/readyz` (certificate valid, reloaded from the mounted files); RBAC `config/rbac/evidence-download.yaml` | s3-evidence-publishing, supporting-evidence-attachments | resolved |
| Evidence destinations | EvidenceDestination resources, the default ConfigMap `konstapel-system/konstapel-evidence-destination`, and credential Secrets in the controller namespace. There are no chart values for locations or credentials. | s3-evidence-publishing | resolved |
| Writable storage | the evidence staging directory (it must survive restarts for capture recovery) and the download temp directory (bounded by `--max-temp-bytes`) | continuous-assessments, s3-evidence-publishing | resolved |
| Image | `ghcr.io/backend-bunny/konstapel`; entrypoint `/usr/bin/konstapel`; user 65532, no shell; work dir `/usr/share/konstapel`; C2P provider at `/usr/share/konstapel/bin/konstapel-provider` (`apko.yaml`, `melange.yaml`). The chart pins a digest and never a mutable tag. | image packaging (`docs/images.md`) | resolved; the release digest is injected by group 5 |
| Lease and replica lifecycle | Lease `konstapel-controller-leader-election` with validated 15s/10s/2s timings (`--leader-election-*`), see [Controller availability](integration/availability.md); shutdown budgets `--shutdown-timeout` (45s) and download `--shutdown-drain` (20s) within 60s grace, with readiness failing while draining; per-replica serving readiness independent of leadership | add-controller-high-availability | resolved |
| TLS for services | cert-manager Certificates/Issuers (default) or an operator-managed Secret, reloaded in place on rotation | this change (group 3) | resolved for the download server, metrics and the exception webhooks (cert-manager `inject-ca-from`, or the operator's `caBundle`); the runtime reloads webhook TLS (leaf and CA rotation tested) |
| OCI policy bundles | `konstapel controller` `--bundle-sources-configmap` (off when empty), `--bundle-cache-dir`, `--bundle-cache-capacity`, `--bundle-refresh-interval` and `POD_NAMESPACE`; the operator-created sources ConfigMap and the Secrets/ConfigMaps it references, read by name in the controller namespace ([Controller wiring](policy-bundles.md#controller-wiring), [RBAC and informers](policy-bundles.md#rbac-and-informers)) | add-policy-bundle-distribution | resolved; values `bundles.*`, off by default |
| External provider client | `konstapel controller` `--external-provider-client-cert-dir` (off when empty; `tls.crt`/`tls.key` checked at startup and re-read per probe); probe interval, timeout and status age are Go defaults without flags; registrations and their `serverTrust` ConfigMaps read with the existing controller grants ([registration, selection and status](integration/external-provider-protocol.md#registration-selection-and-status)) | add-external-assessment-providers | resolved; values `externalProviders.*`, off by default |
| Capability monitor | Kyverno API discovery and authorization checks on the manager boundary | this change (group 4) on the targeting manager | resolved for delivery and assessments; the exceptions gate is pending |

## CRD chart

`charts/konstapel-crds/templates` is generated. `scripts/generate.sh` copies
each file in `config/crd/bases` through `scripts/charts/crds.sh`, adding only
the `helm.sh/resource-policy: keep` annotation and the
`app.kubernetes.io/name: konstapel-crds` and `part-of: konstapel` labels.
`scripts/generate.sh --check` (in `task lint`) fails if the chart is behind
the API types. `internal/charttest` renders the chart with the pinned Helm and
requires:
- exactly the generated set of CRDs, so nothing placeholder or obsolete;
- identical specs;
- no other metadata;
- no hooks, Jobs, owner references or finalizers in either chart.

The templates are ordinary templates, not Helm's `crds/` directory, so an
explicit `helm upgrade` applies schema changes. The chart has no values: no
setting can turn off retention, purge instances, or remove finalizers.

**Install, upgrade, uninstall.** The CRD chart is one cluster-wide release.
Install it before the runtime chart, and upgrade it before upgrading the
runtime:

```sh
helm install konstapel-crds oci://ghcr.io/backend-bunny/charts/konstapel-crds \
  --version <version> --namespace konstapel-system --create-namespace
helm upgrade konstapel-crds oci://ghcr.io/backend-bunny/charts/konstapel-crds \
  --version <newer version> --namespace konstapel-system
```

- **CRDs applied without Helm.** Clusters that applied `config/crd/bases`
  directly can hand the CRDs to the chart once. Only do this for definitions
  that no other release owns. Those definitions already have other field
  managers, and Helm applies server-side by default, which would only *share*
  their fields: the next schema change would fail with a conflict. So install
  the adopting release with client-side apply. Later `helm upgrade` runs keep
  using it, because `--server-side` defaults to `auto`, which follows the
  previous release. Also pass `--server-side=false` if you ever reinstall this
  release. A release installed fresh by Helm uses server-side apply
  throughout.

  ```sh
  helm install konstapel-crds oci://ghcr.io/backend-bunny/charts/konstapel-crds \
    --version <version> --namespace konstapel-system --create-namespace \
    --take-ownership --server-side=false
  ```
- **Supported upgrades.** Only additive, compatible schema changes are
  supported: new optional fields, for example. Removing or narrowing a field,
  changing the storage version, or adding conversion webhooks needs its own
  migration before such a release can ship. Don't use `helm rollback` of the
  CRD release as routine recovery. Releases ship the CRD and runtime charts
  at the same version, and only that pair is tested together. Upgrading
  from an earlier release, together with its rollback constraints, is covered in
  [v0.3.0 readiness](release-readiness.md#upgrading-from-020).
- **Uninstall keeps the CRDs.** `helm uninstall konstapel-crds` keeps every
  CRD and all of their objects, because of the keep policy. Deleting a CRD,
  which deletes every object of that kind, is a separate administrator action
  outside Helm:

  ```sh
  kubectl delete crd <name>.compliance.erenius.io   # destroys all its objects
  ```
- **Reinstall.** The retained CRDs keep Helm's ownership metadata for the
  release name and namespace. To take them back, reinstall with the **same**
  release name and namespace. A release with another name or namespace is
  refused with an ownership error and changes nothing. Resolving that is a
  deliberate operator decision, not something to retry with
  `--take-ownership`.

`TestLiveCRDChartLifecycle` (`charts` acceptance group) checks this with the
pinned Helm in kind. It installs the chart, adopting the CRDs with the
documented client-side steps when earlier tests applied them directly, and creates an EvidenceDestination with spec,
status and a finalizer. Through each of these steps, every CRD UID and the
object's UID, spec, status and finalizers stay unchanged:
1. an unchanged-schema version bump;
2. an additive schema change, which is applied;
3. uninstall;
4. a refused install under another release name;
5. a same-identity reinstall, which restores the chart's schema.

## External engine capabilities

Kyverno is installed and managed separately. The controller's capability
monitor (`internal/capability`) checks, for each capability:
- that the required API resources are served with the right group, version,
  resource, kind, scope and discovery verbs;
- that the controller's service account may perform the operations the
  implementation uses (SelfSubjectAccessReviews).

Each request is bounded at 10 seconds, and results are reused for one poll
interval.

| Capability | Required API resources | Access reviewed |
| --- | --- | --- |
| Policy delivery | `policies.kyverno.io/v1` `validatingpolicies` (ValidatingPolicy, cluster-scoped) | get, list, watch, create, update, patch, delete |
| Assessment | `wgpolicyk8s.io/v1alpha2` `policyreports` (namespaced) and `clusterpolicyreports` (cluster-scoped) | get, list, watch on `policyreports` (the collector reads namespaced reports) |
| Exceptions | `policies.kyverno.io/v1` `policyexceptions` (namespaced) | none yet: native exceptions are add-self-service-policy-exceptions's, which has its own expiry and governance gates |

The assessment row is not a separate list. It is the installed Kyverno
assessment provider's declared reads and prerequisites; see
[assessment provider availability](assessment-providers.md#availability).

The results are distinct. `APINotServed`, `ResourceMissing`,
`UnsupportedResource` (kind, scope or verbs), `AccessDenied` (forbidden
discovery or operation) and `DependencyUnavailable` (transport, timeout) are
never conflated. Results go into existing status, not a new resource:
- **Policy delivery** sets the binding's `EngineReady` reason
  (`EngineAPINotServed`, `EngineResourceMissing`,
  `EngineResourceUnsupported`, `EngineAccessDenied`, `EngineUnavailable`).
  Applied policies stay in place.
- **Assessment** adds `policy reports unavailable: <reason>` to
  `status.assessment.current.limitations`. Evidence is then incomplete, never
  compliant, and scheduled snapshots are disabled until reports return.
  Delivery is unaffected.

Each engine watch registers once its own capability is available. After that,
its informer re-lists and re-watches by itself when the API is removed and
restored, so the controller never restarts for a late or returning engine.

A Ready binding is otherwise not requeued, so a capability trigger rechecks
every capability each poll interval. When any result changes, it
re-reconciles every binding for delivery and assessment. This covers an
engine that is installed, removed, or loses or regains permissions.
`/healthz` and `/readyz` don't depend on Kyverno.

**Kyverno's own permissions.** The policies of the official bundles need
one grant on Kyverno's reports controller that the Kyverno chart doesn't
include: `get`, `list` and `watch` on `pods/ephemeralcontainers`. Without it
every delivered policy reports `RBACPermissionsGranted=False` and bindings
stay `ReplacementPending`, in `Audit` as well as `Deny`. Neither Konstapel
chart grants it: apply the operator example, after checking your
installation's identities, as described in
[Kyverno permissions for official bundles](integration/kyverno-rbac.md).

**Tested versions.** The matrix above is tested against Kyverno chart
`3.9.2` (`scripts/runtime.env`), which serves `policies.kyverno.io/v1` and
`wgpolicyk8s.io/v1alpha2`. Compatibility comes from these API shapes, not from
the Kyverno version string. Konstapel never installs engine CRDs and never
falls back to legacy Kyverno policy APIs.

**Troubleshooting.** These are four different questions. Answer them in this
order:
1. **Is the API present and usable?** Check the binding's `EngineReady`
   reason:
   - `EngineAPINotServed` or `EngineResourceMissing`: install, or reinstall,
     Kyverno with the APIs above.
   - `EngineResourceUnsupported`: run a Kyverno release from the tested matrix.
   - `EngineAccessDenied`: restore the controller's generated RBAC
     (`config/rbac/controller/role.yaml`).
   - `EngineUnavailable`: check API server and aggregation health.

   Each of these clears by itself once fixed. There's no restart.
2. **Is Konstapel serving?** `/healthz` and `/readyz` (probe port 8081) report
   the process. They stay healthy without Kyverno, so the endpoints for
   configuration admission and evidence downloads stay available.
3. **Are the policies ready?** `EngineReady=True` (`Ready`) means every
   desired policy is applied at the current revision and Kyverno reports it
   ready. `ReplacementPending` means the engine has not accepted the policies
   yet. Its message names the failing Kyverno readiness condition for each
   policy, for example `RBACPermissionsGranted=False` (see
   [readiness diagnostics](integration/targeting-api.md#readiness-diagnostics)
   and, for missing `pods/ephemeralcontainers` verbs,
   [Kyverno permissions](integration/kyverno-rbac.md)).
   During an engine outage, already applied policies stay in place and keep
   enforcing.
4. **Is the evidence complete?** That's `status.assessment.current`.
   `policy reports unavailable: <reason>` means no evidence can be attributed:
   completeness is never `Complete`, and scheduled snapshots stop until
   reports are readable again.

```sh
kubectl get compliancebinding <name> -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
kubectl get compliancebinding <name> -o jsonpath='{.status.assessment.current.evidence.completeness}{"\n"}{range .status.assessment.current.limitations[*]}{@}{"\n"}{end}'
```

`TestLiveEngineCapabilityRecovery` (the `capabilities` acceptance group, on
its own cluster) runs the controller under the generated RBAC and checks
these steps:
1. It starts while the ValidatingPolicy API is not served
   (`EngineResourceMissing`), and recovers to delivery and enforcement when the
   API returns.
2. It loses its engine and report permissions (`EngineAccessDenied`, with
   reports unavailable) while the applied policy keeps enforcing, and recovers
   when they're restored.
3. A Kyverno rollout keeps the policy.
4. The API is removed and restored while the controller runs, and the policy
   is re-delivered.

None of these restarts the controller. The controller serves its probes and
the admission webhook like a chart pod, and through every step `/readyz`
(informer sync and the webhook's verified certificate) passes and the webhook
answers TLS: Kyverno is not a serving prerequisite, so its absence never
removes the replica from its Service.

Missing reports never establish compliance.
`TestUnavailableReportsCannotEstablishCompliance` puts a passing,
attributable PolicyReport in place and makes the assessment capability
unavailable for each reason (`APINotServed`, `ResourceMissing`,
`UnsupportedResource`, `AccessDenied`, `DependencyUnavailable`). Current
evidence counts no pass, an active run keeps collecting and closes
`Incomplete`, and delivery still reconciles without touching the applied
policy. With reports readable again the same report counts.

The exceptions capability gates nothing yet because there is nothing to gate:
the native grant path of add-self-service-policy-exceptions isn't merged.
`TestRuntimeChartCannotActivateNativeExceptions` checks that no supported
chart configuration, the exception webhooks and revocation processing
included, grants any subject access to native `PolicyException` objects.
Without `exceptions.webhooks.enabled` it also checks that no admission
webhook is registered and the controller serves none; with it, only the two
ComplianceException webhooks, which intercept `complianceexceptions` alone.
When that path lands, its activation consumes the exceptions capability
result.

**Installing before Kyverno.** `TestLiveHelmLateKyverno` (`charts` group)
checks the same behavior on the installed charts and the packaged image, with
no in-process controller. It uninstalls the disposable cluster's Kyverno
release, so neither `policies.kyverno.io` nor `wgpolicyk8s.io` is served.
Kyverno's uninstall can leave the cleanup controller's `kyverno-cleanup-` and
`kyverno-ttl-` webhook configurations behind, calling Services it removed.
The test deletes each configuration that existed before its uninstall (same
UID), is Kyverno-named and calls only missing Services, keeps everything
else, and requires that none remains (`TestKyvernoLeftoverSelection` covers
the selection). It then installs both charts as documented:
1. Every controller and download replica becomes ready without Kyverno.
2. A Deny binding reports `EngineAPINotServed` (or `EngineResourceMissing`).
   Its current evidence lists `no engine policies or reports can be read`,
   counts nothing attributable and is not `Complete`. The download server
   still refuses an unauthenticated request with 401.
3. Kyverno is installed with its original chart and values. The binding
   becomes `EngineReady=True`, its policy enforces and the limitation clears.
   Neither chart is upgraded or reinstalled (both stay at revision 1), and no
   pod is replaced or restarted.

While Kyverno is absent, the same test also checks the installed release's
API contract for every CRD in the CRD chart. It fails if the chart ships a
CRD that the contract doesn't cover. Each check is a real API request,
authenticated as a user bound to one of the runtime chart's roles, or as the
chart's ServiceAccounts:
- **Defaults and admission fields.** A minimal object gets its schema
  defaults: profile exception eligibility `Forbidden`; binding assessment
  `24h`/`5m`/`2h`/`2160h`; destination `Retire`, `path` addressing and the
  credential keys. The runtime chart's admission policies set a binding's
  `enforcementEpoch`, a request's `requester` and an attachment's
  `registeredBy` from the caller. A supplied epoch is overwritten, and an
  enforcement change advances it.
- **Invalid specs.** Invalid specs are rejected with their documented
  reasons, and so are the invalid examples under
  `testdata/targeting/examples/invalid`. The valid examples (including
  `docs/examples/evidence-signing` and `docs/examples/supporting-evidence`)
  are accepted.
- **Status and protected fields.** Status sent on create or through the main
  resource isn't stored, and immutable fields refuse changes.
- **RBAC.** Only `konstapel-controller` may write any `/status`. Each role
  reads only its documented kinds' status, and a user with no Konstapel role
  reads none. The controller can't create profiles, bindings or destinations,
  and neither a viewer nor an attachment registrar can create a profile. Only the controller may create
  Namespace-scope runs, which `konstapel-assessment-run-scope` enforces
  through the chart's ConfigMap.

## Runtime chart

Install into `konstapel-system`: the shipped RBAC, admission policies and the
controller's code all use that namespace. The `konstapel-controller`
ServiceAccount is the one the admission policies authorize. The chart
renders:

- **Controller Deployment.** `konstapel controller` from the digest-pinned
  image, with `--leader-elect=true` (always on, even with one replica) and
  `--shutdown-timeout` from `controller.shutdownTimeoutSeconds` (45s), and
  the four `--collection-*` evidence collection limits from
  `controller.collection`, always rendered (their defaults are the
  controller's own).
  - **Rollout and placement:** two replicas, rolling update with
    `maxUnavailable: 0` and `maxSurge: 1`, and preferred (never required)
    hostname anti-affinity at weight 100. `controller.affinity` replaces that
    default.
  - **Termination:** 60s grace.
  - **Security:** non-root (65532), read-only root filesystem, no privilege
    escalation, all capabilities dropped, `RuntimeDefault` seccomp.
  - **Probes:** startup and liveness on `/healthz`, readiness on `/readyz`
    (port 8081). Neither depends on Kyverno or leadership.
  - **Storage:** a size-limited `emptyDir` for staging, so each pod has its
    own bounded scratch space and nothing is shared.
  - **Selector:** stable across revisions (name, instance, component). No
    version or template hash.
- **OCI policy bundles** (off by default). With `bundles.sourcesConfigMap`
  set, the controller also gets the four `--bundle-*` flags, a per-pod
  size-limited `emptyDir` for the content cache at
  `/var/lib/konstapel/bundles`, and a `konstapel-controller-bundles` Role and
  RoleBinding; see [OCI policy bundles](#oci-policy-bundles). With it empty
  (the default) the render is unchanged.
- **External provider client** (off by default). With
  `externalProviders.enabled`, the controller also gets
  `--external-provider-client-cert-dir` and a read-only mount of
  `externalProviders.clientCertSecretName`, and nothing else; see
  [External assessment providers](#external-assessment-providers). Disabled
  (the default), the render is unchanged.
- **PodDisruptionBudget.** `minAvailable: 1` with the same selector, only when
  `replicaCount > 1`. Development values (`replicaCount: 1`) omit it.
- **RBAC.** The ServiceAccount; ClusterRoleBindings to `konstapel-controller`
  and `konstapel-controller-assessments`; a RoleBinding to the Role in
  `konstapel-system` for the leader-election Lease, Events, Secrets and
  ConfigMaps. See
  [Controller ServiceAccount boundary](#controller-serviceaccount-boundary)
  for what that adds up to.
- **Copied manifests.** `scripts/charts/runtime.sh` copies these unchanged as
  `templates/generated-*.yaml`, and `scripts/generate.sh --check` keeps them
  current:
  - the generated controller roles (`config/rbac/controller/role.yaml`);
  - the role catalog (`config/rbac/*.yaml`: compliance admin and viewer,
    assessment operator and requester, exception editor, evidence download,
    evidence attachment registrar, uploader, reader and downloader);
  - the admission policies (`config/admission/*.yaml`, with their parameter
    ConfigMap).

**Rejected at render time:**
- a namespace other than `konstapel-system`;
- a missing `image.digest`;
- `controller.shutdownTimeoutSeconds` that isn't below
  `terminationGracePeriodSeconds`;
- `download.shutdownDrainSeconds` that isn't below
  `terminationGracePeriodSeconds`;
- `podDisruptionBudget.minAvailable` that isn't below `replicaCount`, or
  below `download.replicaCount` when the download server runs more than one
  replica.
- `download.attachments.maxBytes` above `download.maxTempBytes`, or a
  `download.attachments.timeout` above `1h`.
- `controller.collection.pageSize` above `maxObjects`, `maxRequests` below
  the pages `maxObjects` takes at `pageSize`, or `maxBytes` below one page of
  4096-byte objects; the schema rejects each value out of its range.
- `bundles.referencedSecrets` or `bundles.referencedConfigMaps` without
  `bundles.sourcesConfigMap`; a `bundles.cache.sizeLimit` that isn't larger
  than `bundles.cache.capacity`; a `bundles.refreshInterval` above `5m`; the
  sources ConfigMap listed among `bundles.referencedConfigMaps`.
- `externalProviders.enabled` without `externalProviders.clientCertSecretName`,
  or the name without `enabled`.

**Download server and TLS.** With `download.enabled` (the default), the chart
also renders the evidence download server:
- a `konstapel-download` ServiceAccount bound to the shipped download roles;
- a Deployment with two replicas and the same rollout, placement and
  hardening as the controller;
- the `konstapel-download` Service (port 443, every ready replica, no session
  affinity);
- a PodDisruptionBudget.

The server reads its certificate from a Secret holding `tls.crt`, `tls.key`
and `ca.crt`. It refuses to start, and so never becomes ready, if any of these
holds:
- the key pair is missing or mismatched;
- the certificate is expired or not yet valid;
- the certificate doesn't cover `konstapel-download.<namespace>.svc`;
- the certificate doesn't chain to `ca.crt`.

The flags are `--tls-ca-file` and `--tls-server-name`. `download.attachments`
sets the supporting-evidence limits (`--attachment-max-bytes`,
`--attachment-timeout`, `--attachment-max-concurrent`) and source retention
(`--attachment-retention`); see the [values contract](#values-contract).

### Protected-package readers

A platform package whose supporting context names a document is protected:
the download service serves it only to callers who also hold the
cluster-wide document-read grant. Download services older than this feature
don't read package descriptors and would serve it to anyone with run
access. The controller therefore writes supporting evidence into a package
only after checking the readers, each time a platform run with supporting
entries closes:

- With `download.enabled`, the chart starts the controller with
  `--protected-package-readers=konstapel-download` and its own pod name
  (`POD_NAME`). The check passes only while the `konstapel-download`
  Deployment's template and every unfinished Pod its selector matches,
  terminating ones included, run the controller's own image in their
  `download` container. Both come from `image`, so an installation or upgrade
  passes once the download rollout is complete.
- With `download.enabled=false` the chart passes `none`: no Konstapel
  service serves packages.
- Run outside the chart without the flag, the controller never writes
  protected packages.

While the check fails, during a download rollout, after an image was changed
on one Deployment only, or when the controller can't read its own Pod or the
Deployment, the run's supporting evidence is reported unavailable with
reason `ProtectedReadersUnverified`. The package then carries no supporting
context and no document copy, its coverage shows a blocking limitation, and
its technical evidence is unaffected. The answer is frozen with the run's
closure and is permanent for that run: verifying the readers later never
rewrites a closed run ([supporting evidence](supporting-evidence.md)). The check uses the controller's existing read access to Pods and
Deployments; the chart adds no permission. It doesn't follow a download
service deployed outside the chart. Rolling the download service back below
this version while protected packages are retained remains unsupported.

`TestLiveHelmSupportingEvidence` (the `charts` group) installs both charts
with non-default `download.attachments` values and checks them on every
ready download replica. A document above the chart's upload limit is refused
with 413, and one uploaded through the installed Service by the shipped
uploader role is committed with the chart's retention. While the download
Deployment declares another image (its surge replica never starts, so the
current replicas keep serving), a platform run's package carries no
supporting evidence and reports `ProtectedReadersUnverified`. Once the
rollout is back on the controller's image, the next platform run's package
holds the verified copy, and a platform operator reads it only with the
shipped `konstapel-evidence-attachment-downloader` role.

`tls.mode` chooses
where the Secret comes from:

| `tls.mode` | Secret | Requires |
| --- | --- | --- |
| `certManager` (default) | `konstapel-download-tls`, from a `Certificate` for the Service's DNS names. The issuer is the chart's self-signed CA (`Issuer` → CA `Certificate` → CA `Issuer`), or your `tls.certManager.issuerRef` (`Issuer` or `ClusterIssuer`) | cert-manager installed separately; the chart never installs or manages it |
| `secret` | yours, named by `tls.secret.name` | nothing else; the chart only mounts it and never creates, changes or deletes it |

Install examples. Each values file is rendered by `internal/charttest`, and
`TestLiveHelmInstall` installs the default mode, the operator Secret and the
platform issuer:

```sh
# Default: cert-manager (installed separately) with the chart's own CA.
helm install konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <version> \
  --namespace konstapel-system

# Operator-managed TLS (docs/examples/charts/operator-tls.yaml).
kubectl -n konstapel-system create secret generic operator-download-tls \
  --from-file=tls.crt --from-file=tls.key --from-file=ca.crt
helm install konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <version> \
  --namespace konstapel-system -f docs/examples/charts/operator-tls.yaml

# Your cert-manager issuer instead of the chart CA (docs/examples/charts/platform-issuer.yaml).
helm upgrade --install konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <version> \
  --namespace konstapel-system -f docs/examples/charts/platform-issuer.yaml
```

For a single-node development cluster,
`docs/examples/charts/development.yaml` runs one replica of each Deployment
without PodDisruptionBudgets. Leader election stays on.

**Upgrade.** Upgrade the CRD chart first ([CRD chart](#crd-chart)), then the
runtime chart to the same version, with the values you installed with:

```sh
helm upgrade konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <newer version> \
  --namespace konstapel-system --reuse-values
```

The rollout keeps two ready controllers and download servers, and Kyverno
keeps enforcing the delivered policies throughout. A release's rollback
constraints are listed in [release readiness](release-readiness.md#upgrading-from-020).

Clients trust the server through that CA (`ca.crt`) and use the
`konstapel-download.konstapel-system.svc` name.

**Certificate rotation.** The server re-reads the mounted Secret every 10
seconds. The kubelet usually updates a mounted Secret within a minute, so a
rotation reaches the pods without a restart:
- A new leaf, key or `ca.crt` is served on new connections once it passes the
  same checks as at startup.
- If the new files fail those checks, the server keeps serving its last good
  certificate and `/readyz` fails. The pod leaves the Service until a valid
  Secret arrives, and the log names the failed check.
- `/readyz` also fails once the served certificate expires, even without a
  rotation.
- Downloads always require an authorized token, so a TLS problem never opens
  an unauthenticated path.

The probes use HTTPS on the serving port. Startup and liveness use `/healthz`
and readiness uses `/readyz`. Neither path needs a token or returns data.

Who rotates depends on `tls.mode`:
- **`certManager`:** cert-manager renews the leaf before it expires. Replacing
  the chart CA (for example by deleting the `konstapel-ca` Secret) changes
  `ca.crt` in `konstapel-download-tls` once the leaf is reissued. Clients must
  then trust the new `ca.crt`.
- **`secret`:** the operator updates the Secret in place. To change CAs without
  breaking clients, first give clients a bundle trusting both CAs, then
  replace `tls.crt`, `tls.key` and `ca.crt` together, then drop the old CA from
  client trust.

**Installed-image acceptance.** The `charts` acceptance group builds the
controller image from the checkout (`scripts/image/build.sh`). It loads the
image into the disposable kind node and names it by its manifest digest, then
runs `TestLiveHelmInstall`, which uses only the cluster API and Helm:
1. It installs both charts with the pinned Helm, the runtime chart pinned to
   that digest with `pullPolicy: Never`.
2. Both replicas become ready with the hardened pod spec, and one of them
   holds the Lease.
3. The installed controller delivers a Deny binding, and a privileged Pod is
   denied.
4. A scheduled run is collected, exported to OSCAL with C2P, and published
   from inside the pod to a test-owned S3 service on the kind network. This
   proves the read-only root and the chart's bounded writable volumes are
   enough.
5. The test installs with `docs/examples/charts/operator-tls.yaml` and a test CA. A platform operator
   downloads the package through the installed download server (port-forwarded
   Service, TLS trusted only through that CA), and its SHA-256 matches the
   receipt.
   It then rotates the operator's Secret to a new CA and leaf. Every replica
   serves the new certificate without restarting, and a download that trusts
   only the new CA matches the receipt. Next it installs a certificate for the
   wrong name: every replica stops being ready but keeps rejecting
   unauthenticated downloads. Restoring a valid Secret makes them ready again,
   still without restarts.
6. After uninstall, the operator's Secret still exists.
7. The test reinstalls in the default `certManager` mode. The `charts` group
   installs cert-manager first, separately and pinned in
   `scripts/runtime.env`. cert-manager issues `konstapel-download-tls` from the
   chart's `konstapel-ca` for the Service's three DNS names, and a download that
   trusts only that Secret's `ca.crt` matches the receipt.
8. The test deletes the `konstapel-ca` and `konstapel-download-tls` Secrets.
   cert-manager reissues the CA and then the leaf. Every replica serves the
   new leaf without restarting, trusted through the new `ca.crt`.
9. The test creates a platform CA `ClusterIssuer` named `platform-ca` and
   upgrades with `docs/examples/charts/platform-issuer.yaml`. The chart CA
   issuers are removed, and cert-manager reissues the download certificate
   from the platform CA. Every replica serves it without restarting, and a
   download that trusts the platform CA matches the receipt.

```sh
devbox run -- task acceptance OUTPUT=/absolute/fresh/path GROUP=charts
```

The schema also rejects unknown values. Without
`exceptions.webhooks.enabled` (the default) no webhook Service or
configuration is rendered.
`internal/charttest` checks the defaults, the development case, the download
server and all three TLS shapes, that every binding refers to a shipped role,
the controller ServiceAccount's exact effective Secret and ConfigMap rules,
and the refusals.

### Controller ServiceAccount boundary

One ServiceAccount, `konstapel-system/konstapel-controller`, runs every
controller feature, so its permissions are the union of everything bound to
it. There is no per-feature identity: a defect in one feature's code runs
with all of these grants. The bindings are:

| Binding | Role | Scope | Source |
| --- | --- | --- | --- |
| ClusterRoleBinding `konstapel-controller` | ClusterRole `konstapel-controller` | cluster | `+kubebuilder:rbac` markers in `internal/controller`, generated to `config/rbac/controller/role.yaml` |
| ClusterRoleBinding `konstapel-controller-assessments` | ClusterRole `konstapel-controller-assessments` | cluster | `config/rbac/controller-assessments.yaml` |
| RoleBinding `konstapel-controller` | Role `konstapel-controller` | `konstapel-system` | the same markers (`namespace=konstapel-system`) |
| RoleBinding `konstapel-controller-bundles` (only with `bundles.sourcesConfigMap`) | Role `konstapel-controller-bundles` | `konstapel-system` | `templates/bundles.yaml` |
| ClusterRoleBinding `konstapel-controller-metrics-auth` (only with `metrics.enabled`) | ClusterRole `konstapel-controller-metrics-auth` | cluster | `templates/metrics.yaml` |

`externalProviders.enabled` adds no binding: its client certificate is a
mounted Secret, and the registrations and `serverTrust` ConfigMaps it reads
are covered by the grants below.

Neither ClusterRole grants Secrets or ConfigMaps, so all such access is in
`konstapel-system`. The effective Secret and ConfigMap access, and the
implemented feature behind each grant:

| Grant (in `konstapel-system`) | Feature and object | Why not narrower |
| --- | --- | --- |
| Secret `get`, any name | EvidenceDestination `spec.s3.credentialSecret` (S3 static credentials, read uncached on each client build, `internal/s3store.LoadCredentials`); EvidenceDestination `spec.signing.secretRef` (evidence signing key pair, read uncached by the destination reconciler, [evidence signing](integration/evidence-signing.md#who-can-read-signing-keys)) | The name is chosen in the CR, so it cannot be a static `resourceNames` entry. |
| ConfigMap `get`, any name | Central default destination (`konstapel-evidence-destination`, fixed); EvidenceDestination `spec.s3.caTrust` (user-named); preserved legacy configuration (`spec.legacy`, user-named); exception acceptance snapshots and orphan-inventory chunks and headers (names derived from exception UIDs and revisions, and destination UIDs) read back by name | Same: user-chosen or runtime-derived names. All reads are uncached `get`s through the manager's API reader. |
| ConfigMap `create` | Exception acceptance snapshots and orphan-inventory chunks (immutable; never updated or deleted) | The API server cannot restrict `create` by name. |
| Bundles Role: ConfigMap `get`/`list`/`watch` on `bundles.sourcesConfigMap`; `get` on each `bundles.referencedConfigMaps` and `bundles.referencedSecrets` entry | [OCI policy bundles](#oci-policy-bundles) | Already by name. |

The download server's own ServiceAccount is bound to the Role
`konstapel-evidence-download-credentials`, which also allows Secret and
ConfigMap `get` by any name in `konstapel-system`. That covers evidence
signing keys too, although the download server never reads them.

Nothing has `list`, `watch`, `update`, `patch`, `delete` or
`deletecollection` on Secrets, nor on ConfigMaps other than the named,
field-selected watch of the bundle sources ConfigMap; no rule uses a
wildcard; nothing reaches Secrets or ConfigMaps in another namespace. The
orphan inventory used to declare ConfigMap `list`, which no code path used;
it was removed.

The same Role grants the leader-election Lease and Events, also only in
`konstapel-system`. The grants are what the pinned client-go `LeaseLock`
behind controller-runtime's election issues; no other code reads or writes
Leases:

| Grant (in `konstapel-system`) | Election use | Why not narrower |
| --- | --- | --- |
| Lease `get` and `update`, name `konstapel-controller-leader-election` | Every candidate reads the Lease each retry period; the holder renews it with `update`; a candidate takes over an expired Lease with `update`; release on cancel (off) would also be an `update` | Already by name. |
| Lease `create` | The first candidate creates the Lease when it is missing (fresh install, or after it was deleted) | The API server cannot restrict `create` by name. |
| Event `create`/`patch` | The election records `LeaderElection` Events about the Lease (`became leader`, `stopped leading`); repeats are patched | Event names are generated. |

Nothing can `list`, `watch`, `patch`, `delete` or `deletecollection`
Leases, nor `get` or `update` any other Lease or a Lease in another
namespace. Before this was narrowed the Role granted Lease
`get`/`list`/`watch`/`create`/`update`/`patch`/`delete` on every Lease in
the namespace. `create` by any name lets a defect create other Leases in
`konstapel-system`, but not read, renew or take over them.

What this does not give you:
- **Any Secret in `konstapel-system` is readable by name.** That includes
  objects no feature references, such as the download server's TLS Secret or
  a registry credential missing from the bundle values. Keep only Konstapel's
  own objects in this namespace.
- **The bundle Role's `get` rules add nothing today.** The generated Role
  already grants `get` on every Secret and ConfigMap here, so the bundle
  Role's only new privilege is the named `list`/`watch` of the sources
  ConfigMap, and a reference missing from the bundle values is still read
  rather than `Forbidden`. The rules record what bundles need and become
  operative if the generated grants are narrowed.
- **Narrowing is a contract change.** Restricting Secret `get` to names
  would require listing every `credentialSecret` in chart values, as the
  bundle values do; that is not implemented.

Checks: `TestRuntimeChartControllerSecretConfigMapAccess`
(`internal/charttest`) computes the union of every rule bound to the
ServiceAccount from the rendered chart, with and without bundles, and
asserts it exactly, along with allowed and denied requests;
`TestRuntimeChartControllerLeaseAccess` does the same for Leases.
`scripts/generate.sh --check` (in `task check`) fails when the markers and
`config/rbac/controller/role.yaml` or its chart copy disagree.
`TestLiveHelmBundles` (charts acceptance group) asserts the same allowed and
denied requests against a real API server, through impersonation of the
ServiceAccount and SubjectAccessReview. `TestLiveHelmAvailability`
(availability group) does so for Leases, and runs the election under these
grants through Lease creation on a fresh install, renewal while a second
replica contends, takeover after a rolling replacement, a restart from zero
replicas and abrupt leader loss, failing on any refused Lease request in a
controller log.

**Metrics reviews (only with `metrics.enabled`).** The controller
ServiceAccount gains exactly two cluster-scoped grants, `create` on
`authentication.k8s.io/tokenreviews` and `create` on
`authorization.k8s.io/subjectaccessreviews`. Each one is a request that
returns an answer and stores nothing:

- With TokenReview it can learn whether any token it is shown is valid, and
  for whom (user, groups, audiences).
- With SubjectAccessReview it can ask whether any user or ServiceAccount may
  perform any action. A defect could use this to map other identities'
  permissions.

Neither grant reads, writes or impersonates anything. They are cluster
resources, so they cannot be limited to a namespace or a name, and RBAC
cannot restrict which questions a review asks. The metrics filter only asks
whether the presenting identity may `get` the non-resource URL `/metrics`.
With metrics disabled, nothing is bound.
`TestRuntimeChartMetricsEnabled` asserts that these two grants are all that
`metrics.enabled` adds.

**No exception writes by default.** The ServiceAccount reads
`complianceexceptions` and writes their status, nothing more: no rendered
configuration without `exceptions.revocationProcessing.enabled`, the exception
webhooks alone included, grants `create`, `update`, `patch` or `delete` on
exceptions, `create` on `selfsubjectreviews`, or reads of webhook
configurations. Those are the gated grant of
[exception revocation processing](#exception-revocation-processing), and
`create`, `delete` and `deletecollection` are never granted.

### Exception admission webhooks

`exceptions.webhooks.enabled` (false by default) deploys the
`ComplianceException` acceptance webhooks of add-self-service-policy-exceptions
([acceptance admission](integration/policy-exceptions.md#acceptance-admission)):

- The two `konstapel-exception-acceptance` configurations (mutating
  `record.acceptance.compliance.erenius.io`, validating
  `verify.acceptance.compliance.erenius.io`). `scripts/charts/runtime.sh`
  copies them unchanged from `config/webhook/exceptions.yaml`:
  `failurePolicy: Fail`, `CREATE` and `UPDATE` of
  `compliance.erenius.io/v1alpha1` `complianceexceptions`, and no namespace
  selector, object selector or match conditions. The chart adds only its
  labels and the CA. No value changes the failure policy, rules, selectors
  or timeout, and the schema rejects any attempt.
- The `konstapel-webhook` Service (port 443 to container port 9443,
  `webhook`), selecting every controller replica.
- `--webhook-cert-dir=/etc/konstapel/webhook-tls` and `--webhook-port=9443`
  on every controller replica, with the certificate Secret mounted read-only.

That is all it enables. The controller gets no new permission: admission
reads through its existing grants. Native Kyverno exceptions stay off, behind
their own upstream gate ([external engine capabilities](#external-engine-capabilities)).
Revocation processing stays off unless its own switch is set.

**Fail closed.** While the webhooks are enabled, every create and update of
a `ComplianceException` is denied unless a ready controller replica admits
it. That applies to everyone, cluster administrators included. It covers the
first rollout, a time when no replica is ready (all down, or every
certificate invalid), and a `caBundle` that doesn't verify the served
certificate. Deletion isn't intercepted. Run two replicas (the default) in
production.

**TLS.**

- `tls.mode=certManager`: the chart issues `konstapel-webhook-tls` from the
  download server's issuer (the chart CA or `tls.certManager.issuerRef`) for
  `konstapel-webhook`, `konstapel-webhook.konstapel-system` and
  `konstapel-webhook.konstapel-system.svc`. It annotates both configurations
  with `cert-manager.io/inject-ca-from: konstapel-system/konstapel-webhook`,
  so cert-manager's CA injector, part of a default cert-manager
  installation, writes the issuing CA (the Secret's `ca.crt`) into their
  `caBundle`. The issuer must provide `ca.crt`. With one that doesn't, the
  webhooks fail closed.
- `tls.mode=secret`: set `exceptions.webhooks.tls.secretName`, a
  `kubernetes.io/tls` Secret with `tls.crt`, `tls.key` and `ca.crt` covering
  the Service name, and `exceptions.webhooks.tls.caBundle`, the PEM CA the
  API server trusts, which the chart writes into both `caBundle`s. Both are
  required in this mode and rejected in `certManager` mode. The chart never
  creates, changes or deletes your Secret.

The controller verifies the certificate at start and re-reads it while
serving ([Phases](#phases) describes the tested rotation). To move to a new CA
in `secret` mode, first upgrade with a `caBundle` holding both CAs, then
rotate the Secret, then drop the old CA. In `certManager` mode the injector
and the controller's reload run independently. A leaf from a new chart CA
can be served before the injector updates `caBundle`, and admission then
fails closed, never open, until it does.

**Readiness.** Each replica's `/readyz` includes the `webhook` check: a
verified, unexpired certificate on a started webhook server. With revocation
processing it also includes `controller-identity`. Only ready replicas are
endpoints of `konstapel-webhook`.

**Enable and disable.** Enable with
`docs/examples/charts/exception-webhooks.yaml`:

```sh
helm upgrade konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <version> \
  --namespace konstapel-system --reuse-values -f docs/examples/charts/exception-webhooks.yaml
```

To disable, turn [revocation processing](#exception-revocation-processing)
off first, then upgrade with `exceptions.webhooks.enabled=false`. cert-manager
keeps the `konstapel-webhook-tls` Secret when the chart removes its
Certificate, so delete it if you no longer need it. Without the webhooks,
nothing authenticates acceptances or protects their records
([policy exceptions](integration/policy-exceptions.md#acceptance-admission)).

### Exception revocation processing

Revocation processing (add-self-service-policy-exceptions task 3.6) writes
independent revocation records and releases the revocation finalizer of a
revoked `ComplianceException`. It needs a grant that lets the controller
update exceptions: ClusterRole `konstapel-controller-exception-revocation`
(`config/rbac/controller/exception-revocation.yaml`), with `update`/`patch`
on `complianceexceptions`, `create` on `selfsubjectreviews`, and `get` on the
two `konstapel-exception-acceptance` webhook configurations. Only the
fail-closed exception webhooks confine that grant, to releasing the
finalizer once the record is durable.

`exceptions.revocationProcessing.enabled` is the one switch for that
ClusterRole (copied unchanged by `scripts/charts/runtime.sh`), its
ClusterRoleBinding `konstapel-controller-exception-revocation`, the identity
lookup and the controller's `--exception-revocation-processing`:

- `false` (the default) renders none of them, with or without the webhooks.
  The controller's default roles are unchanged.
- `true` without `exceptions.webhooks.enabled` fails the render before
  anything is applied. The grant can never come from the chart without its
  protection in the same release.
- `true` with the webhooks adds exactly the gated ClusterRole's grants, its
  binding and the flag on every replica.

**Order.** The grant is safe only while the webhooks are registered and fail
closed. Enable it in two upgrades:

1. `-f docs/examples/charts/exception-webhooks.yaml`: the webhooks, with
   processing off. Let the rollout finish (`--wait`).
2. `-f docs/examples/charts/exception-revocation.yaml`: the gated
   ClusterRole, its binding and the flag. The webhooks already exist when
   the binding is created.

Disable in reverse: upgrade with `exceptions.revocationProcessing.enabled=false`
while the webhooks stay, which deletes the binding and rolls out the
replicas without the flag. Only then turn the webhooks off. Before
`helm uninstall`, turn processing off the same way.

**What Helm guarantees.** Helm 4.3, the pinned version, applies resources in
a fixed kind order (`InstallOrder` in Helm's
`pkg/release/v1/util/kind_sorter.go`). It finishes each kind's requests
before it starts the next: ClusterRole, ClusterRoleBinding, and so on through
Service and Deployment, then MutatingWebhookConfiguration and
ValidatingWebhookConfiguration, then kinds Helm doesn't know, such as
cert-manager's. Only hooks could order resources differently, and the charts
have none (`TestChartsHaveNoHooksOrCleanupJobs`). So:

| Operation | What Helm does | Effect on the grant |
| --- | --- | --- |
| Two-step enable, step 2 | creates the binding; the webhooks exist from step 1 | never bound without registered webhooks |
| Two-step disable, step 1 | deletes the binding; the webhooks stay | gone before the protection |
| Both on in one upgrade | creates the binding before the webhook configurations | bound without protection until Helm reaches the webhooks, a few requests later |
| Both off in one upgrade | deletes the removed binding before the webhook configurations, in the old release's `InstallOrder` | gone before the protection |
| `helm uninstall` with both on | deletes in `UninstallOrder`: webhook configurations first, then the Service and Deployment, then the binding | outlives the protection until Helm reaches the binding |

`TestLiveHelmExceptionWebhooks` observes the first four on the installed
chart, ordered by etcd revision. The uninstall order comes from Helm's
source. RBAC changes also take a moment to reach the API server's
authorizer.

The controller itself writes no exception in any of these windows:

- Replicas without the flag start no revocation writer (see the runtime
  enforcement below).
- Replicas with the flag check both registered configurations before each
  attempt. They record and release nothing until the check passes, and the
  condition reads `RevocationProtectionUnverified` meanwhile
  ([policy exceptions](integration/policy-exceptions.md#revocation-processing)).
- Registered webhooks fail closed while unserved and before their CA is
  injected.

Helm can't stop another identity that can act as the controller
ServiceAccount from using a bound grant during such a window. That includes
anyone who can create its tokens or Pods in `konstapel-system`, or
impersonate it. This is why the two-step order exists, and why processing
goes off before uninstall. The check runs just before each attempt, so a
webhook removed between the check and the release is noticed at the next
attempt.

**Runtime enforcement of the flag.** Without `--exception-revocation-processing`,
the controller's exception reconciler is built without a revocation writer.
Before anything is sent, its client refuses every `ComplianceException` write
other than status, and every revocation record. A ServiceAccount
over-granted by hand (the gated role, or any `update`/`patch` on exceptions
bound without the flag) therefore still sees no exception write from the
controller. `TestRevocationDisabledSendsNoExceptionWrite` checks this in
unit tests, `TestLiveRevocationHistory` on the manager's own transport, and
`TestLiveHelmExceptionWebhooks` through the API server's request counts on
the installed chart. This isn't an authorization control. It can't revoke a
grant bound by hand, and without the flag the validating webhook doesn't
restrict the controller identity, so anything else using that ServiceAccount
could use such a grant. RBAC and the admission webhooks remain the controls,
so don't bind the gated role yourself.

With processing off, revoked exceptions keep their finalizer. Their
`RevocationRecorded` condition reports `RevocationProcessingDisabled`, and a
deleted one stays `Terminating`. Enabling processing later records and
releases every held revocation. The controller's own check of the webhook
configuration, the non-chart order and these effects are documented in
[policy exceptions](integration/policy-exceptions.md#revocation-processing).

**Tests.**

- `internal/charttest`:
  - `TestRuntimeChartExceptionWebhooks` renders both TLS modes and the
    platform issuer. The rendered configurations pass the controller's
    `VerifyProtection` and equal `config/webhook/exceptions.yaml` apart from
    labels and CA. It also checks the Service, the replicas' flags, port and
    mount, and the certificate.
  - `TestRuntimeChartExceptionWebhooksOffByDefault` checks that the default
    render has none of it. The default render is byte-identical to the chart
    before this feature.
  - `TestRuntimeChartExceptionRevocationGated` checks that only both switches
    grant an exception write or the identity lookup, and then exactly the
    gated ClusterRole.
  - The `testdata/charts/konstapel/*exception*.yaml` fixtures check the
    refusals and the schema.
- `TestLiveHelmExceptionWebhooks` (the `charts` group) runs the cert-manager
  mode on the packaged image, in order:
  1. A default install has nothing of the feature.
  2. The webhooks are enabled. They pass `VerifyProtection`, the injected CA
     verifies the served certificate for the Service name, every ready
     replica reports the `webhook` check and is an endpoint, an acceptance
     records the caller, and a revocation is held.
  3. The ServiceAccount is over-granted `update`/`patch` on exceptions with
     processing off. Across a new revocation, a deletion and a restart, the
     API server counts no exception write but the test's own.
  4. With no ready replica, creates and updates are denied for everyone.
  5. Processing is enabled. The binding is created after the webhooks, the
     held revocations are recorded and released, a new one runs end to end,
     the controller identity can't edit, and a removed validating webhook
     stops processing.
  6. Processing is disabled. The binding goes while the webhooks stay.
  7. The webhooks are disabled.
  8. Both are enabled in one upgrade, then disabled in one, with the orders
     in the table above. Nothing is recorded before the webhooks are
     registered.

### Controller metrics

With `metrics.enabled`, every controller replica serves Prometheus metrics
over HTTPS at `konstapel-controller-metrics.<namespace>.svc:443` (port name
`https`, container port 8443). The contract is in the
[metrics guide](integration/metrics.md). There is no plaintext mode and no
self-signed fallback:

- **Certificate.** In `certManager` mode the chart issues
  `konstapel-controller-metrics-tls` from the same issuer as the download
  server. In `secret` mode, set `metrics.tls.secretName`.
- **Verified at start.** The controller refuses to start unless the
  certificate chains to `ca.crt`, is valid now and covers the Service name.
- **Reloaded while serving.** A rotated Secret is served within about a
  minute, without a restart. A rotation that fails verification is rejected,
  and the last valid certificate keeps serving.
- **Authentication and authorization.** Each scrape is authenticated with a
  TokenReview and authorized with a SubjectAccessReview for `get` on
  `/metrics`, by controller-runtime's filter.
- **Who may scrape.** The `konstapel-metrics-reader` ClusterRole grants only
  that `get`. `metrics.readers` binds it to the ServiceAccounts you list;
  with an empty list, bind it yourself.
- **Namespace roles cannot scrape.** The exception editor and assessment
  requester roles do not include `/metrics`: these are platform-wide
  summaries, not a namespace self-service API.

**Revocation is bounded, not immediate.** The pinned controller-runtime
v0.25.2 filter caches decisions:

| Cached decision | How long |
| --- | --- |
| Token authentication | 1 minute |
| Allowed authorization | 5 minutes |
| Denied authorization | 30 seconds |

Each replica caches separately. Removing a reader's binding, or deleting its
ServiceAccount, therefore stops its scrapes within about 5 minutes; the
token's own expiry also applies. A token the API server rejects is refused,
reported as `500 invalid bearer token`. If the API server cannot be reached,
any request without a cached answer is refused: failures close, never open.
Check these bounds again when upgrading controller-runtime.

`TestLiveHelmMetrics` (the `charts` group) installs the chart with
cert-manager TLS and a reader in another namespace, and checks:

- the reader scrapes;
- a namespace ServiceAccount gets 403 and an anonymous client 401;
- another service name or CA fails the TLS handshake;
- a certificate reissued by cert-manager is served without a pod restart;
- deleting the reader binding stops scraping within the 5-minute bound.

`TestLiveHelmMonitoring` (the `monitoring` group) repeats the reader and
revocation checks as a real Prometheus, while a replica is replaced (see
[Verified Operator setup](#verified-operator-setup)).

Credential access, rotation and reader identities for the monitoring system
are in [Monitoring integration](#monitoring-integration), which also covers
the optional ServiceMonitor and PrometheusRule.

### Monitoring integration

Both integrations are off by default, independent of each other, and need
`metrics.enabled`. Neither chart installs Prometheus, the Prometheus Operator
or their CRDs, and neither declares a dependency on them. Konstapel's own
chart tests (`internal/charttest`) validate every rendered object against the
CRD schemas of the Operator version pinned by
`KONSTAPEL_PROMETHEUS_OPERATOR_VERSION` in `scripts/runtime.env` (vendored in
`testdata/charts/prometheus-operator`; `task deps:check` verifies the
checksum, and `scripts/fetch-operator-crds.sh --refresh` renews the files
after Renovate bumps the version). The objects use `monitoring.coreos.com/v1`.

| Values | Result |
| --- | --- |
| `metrics.enabled=false` (default) | no metrics Service, RBAC or monitoring object; the integration values are refused if enabled |
| `metrics.enabled=true` | metrics Service and RBAC only; scrape it from any Prometheus, for example with an external scrape job |
| `+ metrics.serviceMonitor.enabled` | a ServiceMonitor `konstapel-controller`; needs the `ServiceMonitor` API |
| `+ metrics.prometheusRule.enabled` | a PrometheusRule `konstapel-controller` with the seven [starter alerts](integration/alert-runbooks.md) and any rules you add; needs the `PrometheusRule` API. With every group or rule disabled, nothing renders (no empty PrometheusRule) |

Rendering rules:

- The cluster must serve each enabled resource. `helm install` checks the live
  cluster; an offline `helm template` (and tools that render without a cluster)
  need `--api-versions monitoring.coreos.com/v1/ServiceMonitor` and
  `--api-versions monitoring.coreos.com/v1/PrometheusRule`. A missing API,
  or an integration without `metrics.enabled`, fails the render with a message
  naming the value. With both integrations disabled, no API is needed.
- `metrics.serviceMonitor.interval` (default `30s`, at most `2m`) and
  `scrapeTimeout` (default `10s`, shorter than the interval) are whole
  seconds or minutes. Zero, unitless or longer values are refused.
- `insecureSkipVerify` is not a value; unknown values fail schema validation.

**ServiceMonitor.** It selects only this release's `konstapel-controller-metrics`
Service: `matchLabels` of `app.kubernetes.io/name`, `app.kubernetes.io/instance`
(the release name) and `app.kubernetes.io/component=controller-metrics`, with
`namespaceSelector.matchNames` the release namespace. It scrapes the named port
`https` over HTTPS at `/metrics` and copies the release onto each target
(`app_kubernetes_io_instance`). Verification:

- **Server name:** `konstapel-controller-metrics.<namespace>.svc`
  (`metrics.serviceMonitor.serverName` to change it, if you front the Service).
- **CA:** `ca.crt` of the certificate Secret in the release namespace, read
  by the Operator as a Secret reference (no file access). That is
  `konstapel-controller-metrics-tls` in `certManager` mode and
  `metrics.tls.secretName` in `secret` mode. Set exactly one of
  `metrics.serviceMonitor.tls.ca.secret`, `.configMap` or `.file` when your
  issuer does not put the CA in `ca.crt`.
- **Authorization:** `authorization.mode: serviceAccountToken` (default) sets
  `bearerTokenFile` to the Prometheus Pod's own mounted ServiceAccount token.
  It stays the default although the field is deprecated upstream: it needs no
  long-lived token, and the kubelet rotates it. The ServiceMonitor API offers
  no non-deprecated file option, and an Operator that denies file access from
  ServiceMonitors rejects it. Use
  `mode: secret` with a Secret holding a token for the reader ServiceAccount
  in the release namespace, which the Operator reads. You create and rotate
  that Secret; the chart never creates a long-lived token.

**Reader access.** Prometheus's ServiceAccount, which need not live in the
release namespace, must be listed in `metrics.readers` (or bound to
`konstapel-metrics-reader` by you). ServiceAccount tokens are projected and
rotated by the kubelet; a file-based token follows rotation, a Secret
token follows whatever rotation you run. The controller accepts a rotated
token within the cache bounds in [Controller metrics](#controller-metrics).
To rotate a Secret token without a gap, put the new token into the Secret,
wait until the Operator and the kubelet have delivered it to Prometheus (the
acceptance waits 150 seconds; the Secret mode took about 100 to 150 seconds
to take effect there), then revoke the old token. The controller refuses a
revoked token once its 1-minute authentication cache expires. Acceptance
binds the token to a Secret (TokenRequest `boundObjectRef`), so deleting
that Secret revokes it; the kubelet's rotation of projected tokens (about an
hour) is not shortened there.

**Discovery is not guaranteed by the object.** Prometheus selects
ServiceMonitors by its `serviceMonitorSelector` (labels; put them in
`metrics.serviceMonitor.labels`, for example
`release: kube-prometheus-stack`) and `serviceMonitorNamespaceSelector`
(which must admit `konstapel-system`). The same two settings exist for rules
(`ruleSelector`, `ruleNamespaceSelector`; `metrics.prometheusRule.labels`).
Check the Prometheus object's selectors and its Targets page; creating the
object does not prove discovery. Labels under `app.kubernetes.io/` cannot be
set through these values: the chart owns them.

**External scrape jobs.** Without a ServiceMonitor (VictoriaMetrics, a
hand-written scrape config, a different Operator), scrape
`https://konstapel-controller-metrics.<namespace>.svc:443/metrics` with a
bearer token of a listed reader, the CA from the certificate Secret and the
server name above. Rules still work: set `metrics.prometheusRule.scope.matchers`
to labels your job puts on its series (exact values only, no regular
expressions), for example `{job: konstapel, cluster: prod}`. Without
a ServiceMonitor and without matchers, the scope is
`job="konstapel-controller-metrics", namespace="<namespace>"`; with one it
also adds the release instance label.

**Rules.** `metrics.prometheusRule.groups` is a map of group name to
`{enabled, interval, rules}`, and `rules` a map of alert name to `{enabled,
expr, for, threshold, window, severity, labels, annotations, runbookURL}`.
Maps merge across values files, so one value tunes one rule
(`--set metrics.prometheusRule.groups.<group>.rules.<Alert>.for=15m`). In
`expr`:

| Placeholder | Expands to |
| --- | --- |
| `__scope__` | the scope matchers |
| `__scope_labels__` | their label names, for `by (...)` and `on (...)` |
| `__threshold__`, `__window__` | the rule's `threshold` and `window` (a rule using one must set it) |
| `__owner(<domain>)__` | the one scrape target whose `<domain>` projection is ready and younger than `metrics.prometheusRule.maxProjectionAge` (default `4m`; at least 2m plus the scrape interval); nothing when no target or several do. Join gauges to it with `and on (__scope_labels__, instance)` |
| `__owners__` | the same for every domain, keeping the `domain` label |

`severity` is `info`, `warning` (default) or `critical`; a `severity` or
`alertname` label is refused. The `runbook_url` annotation is `runbookURL`,
or `runbookBaseURL/<Alert>` for rules without one. Scope matchers may not
name `instance` or a Konstapel metric label. Tuning rules changes only the
PrometheusRule: workload, RBAC and assessment settings render identically.

**Starter alerts.** The default groups `konstapel-availability`
(`KonstapelMetricsUnavailable`, `KonstapelObservationUnavailable`) and
`konstapel-operations` (`KonstapelBindingUnresolved`,
`KonstapelEngineUnavailable`, `KonstapelAssessmentOverdue`,
`KonstapelPublicationFailing`, `KonstapelCleanupBlocked`) are described,
with their defaults and what to do, in the
[alert runbooks](integration/alert-runbooks.md). Each sets its own
`runbookURL` there; set it per rule to point at your own copy. Disable a
group with `metrics.prometheusRule.groups.<group>.enabled=false`, or one
alert with `....rules.<Alert>.enabled=false`. With every group disabled the
chart renders no PrometheusRule. When one ruler evaluates several
clusters, put the cluster label into `scope.matchers` so that each
release's alerts read only its own series.

**Disabling and uninstalling.** Set the integration's `enabled` to `false` and
upgrade: Helm deletes only the ServiceMonitor or PrometheusRule it owns.
Metrics keep being served and the reader bindings stay; `metrics.enabled=false`
removes those too (the integrations must be disabled first, or in the same
upgrade). `helm uninstall` removes all of them. Prometheus keeps the series
it already stored under its own retention. The Operator, its CRDs and your
Prometheus are never touched.

`internal/charttest` covers the defaults, incompatible options, each missing
API, rendering with both integrations disabled and no monitoring CRDs, both
certificate modes, other release names, the schema of every rendered object,
and that threshold, window, hold, severity, runbook, scope, projection age
and enablement change the rendered rule content. It also keeps
`testdata/observability/rules/*.rules.yml` identical to the `spec.groups`
of the PrometheusRule an enabled default install renders (two release
names), and generates the promtool rule tests from `*.cases.yaml`. `task
test` runs `promtool check rules` and `promtool test rules` on those files
with the pinned promtool image. A live scrape through a real Operator is the end-to-end
monitoring acceptance, described next.

#### Verified Operator setup

`TestLiveHelmMonitoring` (the `monitoring` group) runs the setup above against a
real Prometheus Operator, so the documented values are exercised rather than
only rendered. `scripts/acceptance.sh` installs the Operator from its pinned
release bundle (`scripts/fetch-operator-crds.sh --bundle`: `bundle.yaml`
checked against `KONSTAPEL_PROMETHEUS_OPERATOR_BUNDLE_SHA256`, with the
operator and config-reloader images replaced by their digest-pinned
`KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE` and
`KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE`). The Prometheus it manages runs
`KONSTAPEL_PROMTOOL_IMAGE`, the same pinned image as the rule tests.
`task deps:check` keeps those pins on one Operator release. The test then:

1. installs the chart with `metrics.readers` naming a ServiceAccount in another
   namespace and `metrics.serviceMonitor.labels` / `metrics.prometheusRule.labels`
   set to `release: monitoring-acceptance`;
2. creates a `Prometheus` in that other namespace, running as the listed reader
   ServiceAccount, with `serviceMonitorSelector`, `ruleSelector` and both
   namespace selectors limited to that label and the release namespace;
3. waits for every controller replica to be an active target of
   `serviceMonitor/<namespace>/konstapel-controller/0`, healthy over verified
   TLS with the Pod's own token, labelled with the release, and queries a
   Konstapel metric through the Prometheus HTTP API;
4. checks that the seven starter alerts are loaded and evaluating healthily;
5. checks denial: an identity without the reader binding gets
   `403 Forbidden`, a wrong `serverName` fails with an `x509` error, and a
   ServiceMonitor or PrometheusRule without the selector label is never
   discovered or loaded;
6. sets the Prometheus `arbitraryFSAccessThroughSMs.deny: true` (the Operator's
   policy on file access from ServiceMonitors): the default
   `serviceAccountToken` mode, which uses `bearerTokenFile`, is rejected and its
   targets vanish; `helm upgrade` to `authorization.mode=secret` with a token
   Secret in the release namespace brings them back up;
7. runs the [integrated acceptance](integration/metrics.md#integrated-acceptance)
   on the same release and Prometheus: tuned rules through `helm upgrade`,
   real producer failures and recoveries evaluated by the starter alerts,
   binding recreation, leader loss and restart, certificate and token
   rotation, and finally deletes the `konstapel-metrics-reader` binding while
   a replica is replaced, measuring how long until every Prometheus target
   reports `403`, and restores it;
8. deletes the Prometheus and fails if any of its Pods remain. The disposable
   cluster, and with it the Operator, is removed by the acceptance teardown;
   the test S3 service and fault proxy containers are removed by the test.

Local measurements (one run, kind, 15s scrape interval): all replicas up 9s
after the Prometheus API answered; the file-access policy rejected the default
mode 66s after it was set and the Secret mode scraped again 153s after the
`helm upgrade`; scrapes failed with `403` 313s (CI: 315s) after the binding was deleted,
which is the 5-minute allow cache plus a scrape interval, as documented in
[Controller metrics](#controller-metrics). In the integrated run, which replaces
a replica during the revocation, every target was refused after 135s: the new
replica has no cached answer, and the other's cached answer was older. Expect
up to about 5 minutes and 30 seconds, never longer.

The dependency versions of every run (Operator, config-reloader, Prometheus
and controller images, the running Prometheus version) are recorded in
`TestLiveHelmMonitoring.json` of the group's evidence. Pinned for this
change: Prometheus Operator v0.95.2 and Prometheus v3.16.0.

### OCI policy bundles

Profiles can pin verified OCI bundles from configured registries
([Policy bundles](policy-bundles.md)). The chart only wires the controller;
you create the configuration:

1. In `konstapel-system`, create the sources ConfigMap (data key
   `sources.yaml`, see [Central source configuration](policy-bundles.md#central-source-configuration))
   and every Secret and ConfigMap it references: registry credentials, custom
   CAs, public keys and trusted roots
   ([Private registry setup](policy-bundles.md#private-registry-setup)). The
   chart never renders or changes them.
2. Install or upgrade with `bundles.sourcesConfigMap` naming that ConfigMap
   and every referenced object listed by kind
   (`docs/examples/charts/oci-bundles.yaml`):

```sh
helm upgrade --install konstapel oci://ghcr.io/backend-bunny/charts/konstapel --version <version> \
  --namespace konstapel-system -f docs/examples/charts/oci-bundles.yaml
```

The `konstapel-controller-bundles` Role grants, in `konstapel-system` only:

| Objects | Verbs | Why |
| --- | --- | --- |
| ConfigMap `bundles.sourcesConfigMap` | `get`, `list`, `watch` | the single-object, field-selected (`metadata.name=<name>`) watch of the configuration; the API server authorizes such a `list`/`watch` by `resourceNames` |
| ConfigMaps in `bundles.referencedConfigMaps` | `get` | read by name every refresh interval |
| Secrets in `bundles.referencedSecrets` | `get` | read by name every refresh interval |

A rule whose list is empty is not rendered (an empty `resourceNames` would
grant every object of the kind), and names are validated, so no rule is a
wildcard. List every reference `sources.yaml` makes, and upgrade the
release when you add one.

RBAC is additive, and the bundle Role is not the only grant: the
controller's generated `konstapel-controller` Role (from
`+kubebuilder:rbac` markers for evidence destinations, exceptions and the
orphan inventory) already grants `get` on every Secret and ConfigMap in
`konstapel-system` (see
[Controller ServiceAccount boundary](#controller-serviceaccount-boundary)).
So today the bundle Role's effective new privilege is the named,
field-selected `list`/`watch` of the sources ConfigMap, and a reference
missing from these lists is still readable rather than `Forbidden`. Its `get` rules record exactly what bundles need and become the
operative grant if those broader rules are narrowed. `TestLiveHelmBundles`
checks the watch against the API server: allowed with the bundle RoleBinding,
forbidden without it, and forbidden unselected, for other ConfigMaps, for
Secrets and in other namespaces.

Each replica has its own cache (`bundles.cache.capacity`, default `1Gi`, in
an `emptyDir` of `bundles.cache.sizeLimit`, default `1536Mi`). A replaced pod
starts empty and fetches again; while the registry is unreachable, its
profiles report `ContentUnavailable` and bindings keep the policies they
applied. `bundles.refreshInterval` (`30s`, at most `5m`) bounds how late a
rotated or revoked referenced object is noticed. `TestLiveHelmBundles`
installs these values against a disposable TLS registry (see
[Policy bundles](policy-bundles.md#helm-installation-and-live-acceptance)).

### External assessment providers

`AssessmentProvider` registrations
([registration, selection and status](integration/external-provider-protocol.md#registration-selection-and-status))
need the controller's mutual TLS client. The chart wires that client only
with `externalProviders.enabled` (off by default). Content and assessment
runs cannot use an external provider yet: with the client enabled, the
controller probes registrations and reports their conditions, and nothing
else uses them (`add-external-assessment-providers` group 3).

With `externalProviders.enabled: false` (the default), the render is
byte-identical to a chart without this section. The controller has no
`--external-provider-client-cert-dir`, so it neither watches nor contacts
registrations, and every provider contract that is not built in resolves to
`UnknownProvider`. Enabling it adds exactly three things to the controller
Deployment (`docs/examples/charts/external-providers.yaml`):

- the flag `--external-provider-client-cert-dir=/etc/konstapel/external-provider-client-tls`;
- a read-only mount at that path;
- a `secret` volume of `externalProviders.clientCertSecretName`.

No other object changes. In particular:

- **No provider is installed.** The chart renders no provider Deployment,
  Service, image or chart, and the controller does not download or start
  one. Providers have their own charts; the
  [reference provider chart](integration/external-provider-chart.md) of the
  example reporting provider shows the shape (separate source-worker and
  evaluator identities, mutual TLS from rotated Secrets, a digest-pinned
  image) and is a test/demo artifact that no Konstapel chart refers to.
- **No registration role is bound.** The chart ships
  `konstapel-assessment-provider-admin` and
  `konstapel-assessment-provider-viewer` but binds neither.
- **The controller gains no grants.** The Secret is mounted by the kubelet,
  not read through the API. The controller's existing grants already cover
  registrations (read, plus status writes) and the `serverTrust` ConfigMaps it
  reads by name in `konstapel-system`
  ([Controller ServiceAccount boundary](#controller-serviceaccount-boundary)).
  No provider's source permissions are copied to the controller.

The render refuses `enabled` without `clientCertSecretName`, and
`clientCertSecretName` without `enabled`. The schema rejects names that are
not DNS subdomain names.

**TLS setup.** Each side authenticates the other over TLS 1.3. A peer
matches only through an exact DNS subject alternative name. Wildcards,
common names, URIs and IP addresses never match
([transport and identity](integration/external-provider-protocol.md#transport-and-identity)).
The platform issues every certificate. You need three pieces:

1. **The controller's client certificate.** A `kubernetes.io/tls` Secret in
   `konstapel-system` with `tls.crt` and `tls.key`. Its extended key usage
   must be client authentication, or it must have none. Its DNS SAN is the
   controller identity that providers authorize. Pick a stable name, such as
   `konstapel-controller.konstapel-system.svc`. It is an identity, not an
   address the provider dials. A cert-manager Certificate from a
   platform-owned issuer is one way to produce it:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata:
     name: konstapel-external-provider-client
     namespace: konstapel-system
   spec:
     secretName: konstapel-external-provider-client-tls
     dnsNames: [konstapel-controller.konstapel-system.svc]
     usages: [client auth, digital signature]
     issuerRef: {name: platform-ca, kind: ClusterIssuer}
   ```

   The chart's own `konstapel-ca` Issuer is internal to the release, so don't
   make providers trust it. The controller checks the certificate at startup
   and refuses to start if it is missing, invalid or expired. Without the
   Secret, the pod does not start. The certificate is re-read on every probe
   and connection, so a rotation needs no restart. Until rotated material
   passes the same checks, the last valid material stays in use.
2. **The provider's server trust.** A ConfigMap in `konstapel-system` that
   holds the PEM roots of the provider's serving-certificate issuer, under
   `ca.crt` or the key the registration names. Reference it as the
   registration's `spec.endpoint.serverTrust`. These roots alone verify the
   provider, and system roots are never used. It is read on every
   connection, so you can rotate it in place.
3. **The provider's serving certificate.** Its extended key usage must be
   server authentication, or it must have none. Its DNS SAN must equal the
   registration's `spec.endpoint.serverName` exactly. The controller dials
   `<service>.<namespace>.svc:<port>` from `spec.endpoint.service`, but it
   authenticates only `serverName`. The provider trusts the issuer of
   step 1 and authorizes its DNS name. How the provider is configured is up
   to its own chart.

A registration whose trust is wrong reports `Available=False` with reason
`TrustUnavailable` or `AuthenticationFailed`. One with an unusable client
certificate reports `ClientCredentialsUnavailable`. In each case nothing is
sent.

**Who to bind.** Bind each role yourself with a ClusterRoleBinding, to
platform subjects only:

- `konstapel-assessment-provider-admin` for administrators who create,
  change and delete registrations;
- `konstapel-assessment-provider-viewer` for auditors.

Neither role is aggregated into `admin`, `edit` or `view`, or into
`konstapel-compliance-admin` and `konstapel-compliance-viewer`. Neither
reads Secrets or ConfigMaps. Only the controller writes status. Whoever
creates the trust ConfigMaps in `konstapel-system` needs that permission
separately.

```sh
kubectl create clusterrolebinding platform-assessment-provider-admins \
  --clusterrole=konstapel-assessment-provider-admin --group=platform-admins
```

**Platform installation boundary.** A provider is a separate workload, and
platform operators install it with its own Helm chart. That chart deploys
the provider's Service, its TLS configuration, its own ServiceAccount and
its scoped source permissions. Install signed images and charts pinned by
digest, and verify their signatures and provenance before installing, as
for Konstapel's own artifacts ([images](images.md)); the reference
provider's guide shows the procedure
([Verify and install](integration/external-provider-chart.md#verify-and-install)).
Konstapel is not Helm,
a container runtime or a plugin downloader. It only dials the registered
Service. A registration's `releaseDigest` must match what the endpoint
reports, but that is the endpoint's own claim and not attestation.
Verifying the deployment is the installation boundary.

**Enabling.**

1. Create the client Secret (step 1) and install the provider.
2. Upgrade with `-f docs/examples/charts/external-providers.yaml`, or set
   `externalProviders.enabled=true` and `externalProviders.clientCertSecretName`.
3. Create the trust ConfigMap and the registration. Wait for `Available`,
   `Compatible` and `Ready`.

**Upgrading a provider release.** `releaseDigest` is immutable, so a new
release is a new registration. Don't enable it next to the old one: two
enabled registrations of a contract are `AmbiguousProvider`. Use this
sequence instead:

1. Create the new registration with `newRequests: Disabled`.
2. Wait for `Available=True` and `Compatible=True`.
3. Set `newRequests: Disabled` on the old registration, then
   `newRequests: Enabled` on the new one.

New work selects the new release once it is `Ready`. Drain old work before
you remove the old provider chart.

**Disabling.** Upgrade with `externalProviders.enabled=false`. The
controller stops probing, and non-built-in contracts resolve to
`UnknownProvider`. Registration status is no longer updated. Registrations,
trust ConfigMaps, the client Secret and the provider workloads stay until
you remove them.

**Probe timing is not configurable.** Each registration is probed when it
changes and then every minute, with a 10 second deadline. New work relies
only on a compatible observation less than five minutes old. These are the
controller's Go defaults (`internal/controller`, `ExternalProviders`).
The design asks for no tuning, so they have no flags or chart values.

Checks: `TestRuntimeChartExternalProvidersOffByDefault` and
`TestRuntimeChartExternalProvidersEnabled` (`internal/charttest`) compare
the renders document by document, RBAC included, with and without bundles,
metrics, operator TLS and webhooks.
`TestRuntimeChartAssessmentProviderRegistration` asserts in every
configuration, the enabled client included, that no binding reaches a
registration role. The `testdata/charts/konstapel/*external-providers*`
fixtures cover the render refusals.

## Uninstalling the runtime chart

`helm uninstall konstapel -n konstapel-system` removes the controller, the
download server and their RBAC, Services, admission policies and
certificates. The CRD chart, every custom resource and anything outside the
cluster stay. In detail:

| Stops | Stays |
| --- | --- |
| reconciling profiles and bindings: new or changed bindings deliver nothing | the delivered Kyverno policies: they are owned by their bindings, so **Kyverno keeps enforcing the last delivered revisions** |
| scheduled and requested assessment runs | completed runs and their status, and the packages already published to S3 |
| downloads (the download Service goes away) | the S3 objects; operators can still read them with storage credentials |
| retention cleanup: expired packages are **not** deleted until a controller runs again | the runs' retention finalizer, which keeps a run until its package is deleted |
| the admission policies that protect run and destination status | `ComplianceException` objects and their acceptance and revocation records |
| with `exceptions.webhooks.enabled`, exception admission: the webhook configurations are removed first, so acceptances are no longer authenticated or protected | revoked exceptions keep the revocation finalizer, and deleted ones stay `Terminating` until a controller with revocation processing runs again |
| releasing deleted `EvidenceAttachment` records and expiring their source documents | records pending deletion keep their retention finalizer, storage pin and commitment until a controller runs again; their documents stay in S3 |

With revocation processing enabled, first upgrade with
`exceptions.revocationProcessing.enabled=false`: `helm uninstall` deletes the
webhook configurations before the gated binding
([what Helm guarantees](#exception-revocation-processing)).

To remove Konstapel completely, keep the controller running while you remove
its work:
1. delete the bindings, so their Kyverno policies are garbage-collected;
2. let retention delete what has expired, or hand storage off as described
   in [S3 evidence](integration/s3-evidence.md);
3. uninstall the runtime chart, then the CRD chart;
4. delete the CRDs explicitly if their data should go too.

Reinstalling the runtime chart resumes all of the above from the retained
objects.
`TestLiveHelmInstall` checks this: after `helm uninstall konstapel`, the
binding's delivered policies are unchanged and Kyverno still denies, and the
reinstalled runtime becomes ready on the same policy revisions and serves the
earlier run's package.

## Values contract

`charts/konstapel/values.schema.json` rejects unknown values. There are no
switches that bypass scope, exception governance, download authorization or
retention.

- **`image`:**
  - `repository`
  - `digest`: `sha256:<64 hex>`. It is empty only in source charts; release packaging fills it in.
  - `pullPolicy`
- **`replicaCount`:** controller replicas, at least 1, default 2. 1 is for development and omits the controller PodDisruptionBudget.
- **`podDisruptionBudget`:** `enabled` (true) and `minAvailable` (1), which must be below each replica count. Rendered only for Deployments with more than one replica.
- **`controller`:**
  - `shutdownTimeoutSeconds` (45): must be below `terminationGracePeriodSeconds` (60), which the download server shares.
  - `stagingSizeLimit` (2Gi): the per-pod evidence staging volume.
  - `collection`: evidence collection limits per collection of one binding ([collection limits](assessment-providers.md#configuring-the-limits)). The defaults are the controller's own, and the render refuses what the controller would refuse at startup. A collection that meets one is `Incomplete`. The deadline is not a value: it stays each binding's `spec.assessment.collectionTimeout`.
    - `pageSize` (500, `--collection-page-size`): objects per list request, 1 to 10000 and at most `maxObjects`.
    - `maxRequests` (20000, `--collection-max-requests`): list requests, 1 to 1000000 and at least `maxObjects` / `pageSize`, rounded up.
    - `maxObjects` (100000, `--collection-max-objects`): objects read, 1 to 10000000.
    - `maxBytes` (536870912, 512 MiB, `--collection-max-bytes`): bytes of object JSON read, 1572864 (1.5 MiB) to 68719476736 (64 GiB) and at least `pageSize` × 4096. Decoded objects take about 2.4 times this in controller memory: raise `resources.limits.memory` together with `maxBytes` or `maxObjects`.
  - `resources`, `affinity` (empty means preferred hostname anti-affinity; a value replaces it), `nodeSelector`, `tolerations`.
- **`tls.mode`:** exactly one of the following.
  - `certManager` (default), optionally with `certManager.issuerRef {name, kind: Issuer|ClusterIssuer}`.
  - `secret` with `secret.name`. Setting both, or `secret` without a name, is rejected.
- **`download`:**
  - `enabled` (true), `replicaCount` (2).
  - `audience` (`konstapel-download`): the token audience callers request.
  - `maxConcurrent` (4), `maxTempBytes` (2 GiB) and `tempSizeLimit` (3Gi): download concurrency and per-pod scratch space.
  - `shutdownDrainSeconds` (20): must be below the grace period.
  - `attachments`: supporting-evidence transfers ([supporting evidence](supporting-evidence.md#uploading-and-downloading)). The defaults are the server's own, and the render refuses what the server would refuse at startup.
    - `maxBytes` (33554432, 32 MiB): the largest registered document accepted for upload, 1 byte to 1 GiB and at most `maxTempBytes`.
    - `timeout` (5m): one transfer's deadline, receiving and storing included; whole seconds or minutes, 1s to 1h.
    - `maxConcurrent` (2): uploads and downloads together per replica, 1 to 64.
    - `retention` (2160h): central source retention frozen into each new commitment; whole seconds, minutes or hours. Changing it applies to new commitments only.
  - `resources`.

- **`metrics`:** authenticated controller metrics, off by default.
  - `enabled` (false).
  - `readers`: monitoring ServiceAccounts `{namespace, name}` bound to `konstapel-metrics-reader`. Explicit names only. Set only with `enabled`.
  - `tls.secretName`: required with `tls.mode=secret`; a `kubernetes.io/tls` Secret for `konstapel-controller-metrics.<namespace>.svc`.
  - `serviceMonitor`, `prometheusRule`: independent optional Prometheus Operator objects, off by default; each needs `enabled` metrics and its API. Timing, CA, authorization, scope matchers and rule groups: [Monitoring integration](#monitoring-integration).
- **`exceptions`:** off by default; neither switch enables native exception grants.
  - `webhooks.enabled` (false): the [exception admission webhooks](#exception-admission-webhooks), failing closed.
  - `webhooks.tls.secretName` and `webhooks.tls.caBundle` (PEM): both required with `tls.mode=secret`, both rejected with `certManager`.
  - `revocationProcessing.enabled` (false): [exception revocation processing](#exception-revocation-processing). `true` needs `webhooks.enabled`; enable it in a later upgrade than the webhooks, and disable it first.
- **`bundles`:** verified OCI policy bundles, off while `sourcesConfigMap` is empty (the default).
  - `sourcesConfigMap`: the operator-created sources ConfigMap in `konstapel-system`.
  - `cache.capacity` (1Gi) and `cache.sizeLimit` (1536Mi, must be larger): the per-pod content cache and its `emptyDir`.
  - `refreshInterval` (30s, at most 5m): re-read interval for referenced objects.
  - `referencedSecrets`, `referencedConfigMaps`: the names `sources.yaml` references; the controller may `get` only these. Set only with `sourcesConfigMap`.
- **`externalProviders`:** the controller's client for registered external assessment providers, off by default ([External assessment providers](#external-assessment-providers)). It installs no provider, binds no registration role and grants nothing.
  - `enabled` (false): mount the client certificate and pass `--external-provider-client-cert-dir`.
  - `clientCertSecretName`: required with `enabled`, rejected without it; a `kubernetes.io/tls` Secret (`tls.crt`, `tls.key`) in `konstapel-system` that you create and rotate.

There are no values for evidence locations, credentials (only the names of
bundle credential Secrets and the external provider client Secret), external
provider installation or registration, provider probe timing, Kyverno or cert-manager installation, or native
exception enablement.

The CRD chart accepts no values. Its definitions are generated, and retention
can't be turned off.

## Versions

Both charts carry the application version as `version` and `appVersion`. The
lines are marked `x-release-please-version`, and release-please updates them
as extra files of the single `konstapel` package. Every application release
therefore produces a new version of both charts, even when no schema changed.
`scripts/check-version.sh`, which runs in every build, rejects any difference
between `VERSION`, `melange.yaml` and either chart.
`scripts/ci/test_chart_versions.py` checks this with a simulated release and
deliberate mismatches. Chart-only changes that need a new distribution use a
release-producing Conventional Commit type (`feat`, `fix`, `perf`, `deps`,
`build`). A published version's bytes are never replaced.

## Publication manifest

Before anything is pushed, release packaging freezes both chart archives
and a manifest. Every publication attempt and retry verifies that manifest,
and stops before any registry write on a mismatch.
`scripts/charts/manifest.py` does both:

```sh
python3 scripts/charts/manifest.py freeze --archives out/charts --source <commit SHA> --tag v<version> \
  --image-digest sha256:<verified image digest> --tool helm=<version> --out out/charts/publication.json
python3 scripts/charts/manifest.py verify --archives out/charts --manifest out/charts/publication.json \
  --source <commit SHA> --image-digest sha256:<digest>
```

**What it records:**
- the source commit and tag;
- each chart's name, version, `appVersion`, archive file name and SHA-256;
- a content identity of the CRD chart's templates;
- the runtime chart's default image digest;
- the packaging tool versions.

**What it rejects:**
- a non-SHA source, a malformed tag, or an image reference that isn't a
  digest;
- a missing, extra or duplicate chart archive;
- changed archive bytes or CRD content;
- a source or image digest other than the frozen one;
- a runtime chart that doesn't default to that digest;
- chart versions that aren't the aligned pair for the tag.

An existing manifest is never overwritten. `scripts/ci/test_chart_manifest.py`
packages real archives with the pinned Helm and exercises each rejection.

## Release packaging and publication

A release publishes the charts that passed acceptance, unchanged. Nothing is
rebuilt or re-rendered between acceptance and the registry.

1. **Package.** `task charts:package OUT=… IMAGE_DIGEST=sha256:…`
   (`scripts/charts/package.sh`) needs a clean checkout, because
   `publication.json` records `HEAD` as the source. It works on an isolated
   copy of both charts, sets the runtime chart's default `image.digest` to
   the verified published image, adds `LICENSE` and `NOTICE`, lints, packages,
   and refuses archives containing key material or registry credentials. It
   then freezes the archives with the [publication manifest](#publication-manifest).
   The output directory must not exist: frozen inputs are never replaced.
2. **Accept those bytes.** `task charts:acceptance OUTPUT=… ARCHIVES=… IMAGE=ghcr.io/backend-bunny/konstapel@sha256:…`
   (`scripts/charts/acceptance.sh`) needs a clean checkout of the frozen
   source. It verifies the manifest against `HEAD` and the image digest, then
   runs every **release-required group**: those marked `"release": true` in
   `scripts/acceptance-groups.json` as committed at `HEAD`, today `charts`
   (CRD chart lifecycle, installed controller, both TLS modes, downloads),
   `monitoring` (the installed controller under a real Prometheus Operator
   and Prometheus, with its starter alerts through real failures) and
   `availability` (multi-node placement, disruption budgets, upgrades,
   leader, pod and node loss, and recovery). Each group runs through
   `scripts/acceptance.sh` on its own fresh disposable cluster, one after
   another, in `OUTPUT/groups/<group>/`, bounded by the group's
   `timeoutMinutes` at `HEAD`. A group that exceeds it is stopped, collects
   diagnostics, tears down and fails (`timed-out`); later groups do not run
   and no record is written:
   - every kind node pulls the image by its registry digest (`crictl pull`)
     instead of building one (`image-ref.txt` records it);
   - the tests install the frozen `.tgz` files, and the runtime chart's own
     default digest, with no image override.

   A failed group stops the run. `scripts/charts/evidence.py` then derives
   each test's result from the group's real `go test -v` log: a test passes
   only if its own top-level `--- PASS:` line appears exactly once, with no
   `FAIL` or `SKIP` for it or its subtests. A failed, skipped, missing or
   duplicated result, a failed package, a panic, an unexpected test, a
   nonzero exit status, or a cluster that ran another image fails the gate.
   Only if every required group fully passed does it write
   `chart-acceptance.json` (`konstapel.dev/chart-acceptance/v2`): the source
   commit and tag, both archive checksums, the CRD content identity, the
   image, and for each group its tests and their results, its exit status
   and the SHA-256 of its log, result and image reference, plus the kind,
   node, Kyverno, cert-manager and S3 versions.

   The other groups (`admission`, `assessments`, `storage`, `capabilities`,
   `recovery`) run in-process managers against a disposable cluster and
   install no chart or image, so the release does not repeat them; it
   requires their full main-branch pass for the tagged commit instead
   (`scripts/ci/require-acceptance.py`). `task test` keeps the split honest:
   every group must state `release`, release groups are exactly the groups
   that install the image, and a live test that installs the charts or the
   image must belong to one.
3. **Publish write-once.** `scripts/charts/publish.py --archives … --acceptance chart-acceptance.json --registry oci://ghcr.io/backend-bunny/charts --out release.json`
   checks two things before any registry write: the frozen manifest, and an
   acceptance record that passed for exactly those inputs. It reads the
   required groups and tests from `scripts/acceptance-groups.json` at the
   frozen source commit (`git show`), never from the record, and refuses a
   record that is missing, unreadable, of another `apiVersion`, for another
   source, tag, image, archive, chart version or CRD content, that lacks a
   required group or has an extra one, or whose group did not pass, exited
   nonzero, lacks its evidence digests, or lists other tests than the frozen
   source or any result other than `pass`. Then, CRD chart first:
   - If the version doesn't exist, the frozen archive is pushed.
   - If it exists, its chart layer must be byte-identical to the frozen
     archive. A released version is never replaced, and different content
     stops the publication.
   - The OCI manifest is read back by digest, and its single chart layer must
     carry the frozen archive's digest.

   `release.json` records both OCI subjects, and is written only when both
   verify. A retry after a partial publication runs the same steps and
   pushes only what is missing.

`scripts/ci/test_chart_publish.py` runs the publisher against an in-process
OCI registry (`scripts/ci/oci_fake.py`) with the pinned Helm. It covers:
- publication and read-back;
- republishing as a no-op;
- refusal, before any write, of a changed archive and of every class of bad
  acceptance evidence above (missing, partial, failed, cancelled, skipped,
  stale or for other inputs), with the requirements taken from the frozen
  source commit;
- a failed second push that a retry resumes;
- an existing version with other bytes, which is never replaced.

`scripts/ci/test_chart_evidence.py` covers deriving results from `go test -v`
logs, reading the required groups from a commit rather than the working
tree, and writing no record unless every required group fully passed.

Signing, attestations, remote verification and the release workflow are
described in [Releases](releases.md#chart-publication).

## Checks you can run

`task check` runs `scripts/charts/check.sh` through `task lint`. It needs no
controller, cluster, registry or credentials:

```sh
devbox run -- sh scripts/charts/check.sh
devbox run -- python3 -m unittest scripts/ci/test_chart_versions.py
```

`scripts/charts/check.sh` checks:
- each chart's name, `apiVersion: v2` and the `compliance.erenius.io/v1alpha1`
  contract annotation;
- that no dependencies are declared or vendored (`dependencies`, `Chart.lock`,
  `charts/`);
- `helm lint --strict`;
- every values fixture under `testdata/charts/<chart>/`. The first line,
  `# expect: ok` or `# expect: <error text>`, states whether the render must
  succeed, or which schema error it must fail with. An optional second line,
  `# api-versions: a,b`, supplies cluster APIs (the Operator's) to the render.

Fixtures stay outside `charts/` so they are never packaged.

## Phases

| Group | Work | Prerequisite |
| --- | --- | --- |
| 1 | Input contract, metadata, values schema, version alignment, packaging-input manifest fixtures (done) | none |
| 2 | Package the generated CRDs with `helm.sh/resource-policy: keep`; upgrade, uninstall and reinstall lifecycle in kind (done) | the merged APIs (available) |
| 3 | Deployment, Services, RBAC, cert-manager or operator TLS, probes and availability defaults (controller and download Deployments, RBAC, availability defaults, both TLS modes, download, metrics and webhook certificate reload, serving readiness, documented examples and installed-image acceptance done; the exception webhooks with their CA injection, and gated revocation processing, done and off by default) | the merged manager (available); the replica lifecycle (add-controller-high-availability, Lease and shutdown merged) |
| 4 | Capability discovery and recovery without restart (done except the exceptions gate, which waits for add-self-service-policy-exceptions's native path) | the merged manager |
| 5 | Package, sign, attest and publish the OCI charts from the verified image digest (packaging, frozen-input acceptance, write-once publisher, signing/verification tooling, release workflow, release notes and recovery done; the keyless signing identity and release-please integration are exercised by the first release) | groups 2 and 3 tested |
| 6 | `charts:package` and `charts:acceptance` tasks (done), Go black-box acceptance of the installed charts, the required CI gate (the `charts` group within the required `acceptance` check) and release gating (done) | groups 2–5 |

The exception webhooks render only with `exceptions.webhooks.enabled`
([Exception admission webhooks](#exception-admission-webhooks)). Native
exception grants stay out of the chart until add-self-service-policy-exceptions
passes its gates; their activation then consumes the exceptions capability.
On the runtime side, every replica serves the webhook,
re-reads its certificate, and leaves its Service while the mounted
certificate is invalid or expired. `TestLiveReplicaAdmission` rotates the
webhook CA against the real API server. A leaf from a CA that the webhook
configurations don't trust yet fails admission closed and stores nothing.
Trusting the old and new CA, then only the new one, admits through both
rotated replicas with the caller's attribution. A replica left on the
retired CA is refused, never bypassed. The chart's CA injection must
therefore reach the `caBundle` before a leaf from a new CA is served. In
`secret` mode the documented bundle order guarantees that. In `certManager`
mode the injector usually wins, but a chart CA rotation can briefly fail
admission closed ([TLS](#exception-admission-webhooks)).
