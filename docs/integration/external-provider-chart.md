# Reference provider chart: the example reporting provider

[`examples/external-provider/reporting/chart`](../../examples/external-provider/reporting/chart)
installs the synthetic `example-reporting` provider of the
[quickstart](external-provider-quickstart.md) as a platform operator would
install an external provider: two deployments under separate identities,
mutual TLS from Secrets you rotate, and an image pinned by digest
(`add-external-assessment-providers` 5.1).

**Scope.** It is a test/demo artifact and an authoring recipe, not a
supported provider. Its source is the Namespace labels of the cluster it
runs in, and its one check is `reporting.example.test/v1/RequiredLabel`.
No default Konstapel installation refers to it: the runtime and CRD charts,
their values examples, the bundles, the compiled-in provider registry, the
controller binaries and the controller image carry no reference to it, and
installing it registers nothing. Content and assessment runs cannot use any
external provider yet ([charts](../charts.md#external-assessment-providers));
how bundle content defines checks for external providers, host-readable
attribution and the inventory format are `add-external-assessment-providers`
group 3. Image signing, SBOMs, provenance and their verification for the
reference image are task 5.2; upgrade, drain and uninstall are 5.3.

## Layout

| Object | Name (release `ref`) | What it is |
| --- | --- | --- |
| ServiceAccount | `ref-example-reporting-worker` | The source worker's identity; its token is mounted. |
| ClusterRole and ClusterRoleBinding | `ref-example-reporting-worker-<namespace>-source` | `get` on `namespaces`, bound to the worker only. The chart's only permission. |
| Deployment and Service | `ref-example-reporting-worker` | `reporting-provider -role worker -source kubernetes`: the endpoint you register. One replica, because staged results live in its memory. |
| ServiceAccount | `ref-example-reporting-evaluator` | The evaluator's identity: `automountServiceAccountToken: false`, bound to no role. |
| Deployment and Service | `ref-example-reporting-evaluator` | `reporting-provider -role evaluator`: Evaluate only. |
| NetworkPolicy | `ref-example-reporting-evaluator` | Ingress to the protocol port from the worker only (and `evaluator.hostNamespaces`); no egress at all. |
| NetworkPolicy | `ref-example-reporting-worker` | Ingress to the protocol port from `worker.hostNamespaces` (default `konstapel-system`). |

The chart renders no `AssessmentProvider`, no TLS Secret, no hook and no
Job. Both deployments run the same image as UID 65532 with a read-only root
filesystem, no privilege escalation, all capabilities dropped and the
`RuntimeDefault` seccomp profile. Probes are plain HTTP `/healthz` and
`/readyz` on `ports.health` (8081), never on the protocol port (8443), which
admits only authenticated calls with a deadline; neither Service exposes the
probe port.

## Source worker and evaluator

The worker is the only process with source access. For each Collect it gets
each scope Namespace from the Kubernetes API with its own ServiceAccount
token (re-read per request, so the kubelet's token rotation applies) and
the API server CA. A Namespace that does not exist is a limitation; any
other failure, a denied request included, fails the collection and stages
nothing.

The worker never evaluates. Its Evaluate forwards the host's frozen input,
unchanged and within the host's deadline, to the evaluator over a second
mutual TLS connection, and returns the evaluator's observations after its
own kit server checks them again. It refuses an evaluator that does not
report the worker's own release digest, and reports an unreachable
evaluator as `ERROR_REASON_UNAVAILABLE`.

The evaluator serves only `CAPABILITY_EVALUATE` and holds no source handler.
It has no Kubernetes API token, no RBAC, and its NetworkPolicy denies all
egress, so the separation does not rest on an RPC method: the process that
evaluates cannot reach a source. By default it authorizes one client, the
worker's identity, so the host cannot call it directly. For replay without
the worker (for example after the source is gone), list the controller's
identity in `evaluator.authorizedHosts` and its namespace in
`evaluator.hostNamespaces`, and register the evaluator Service with only the
`Evaluate` capability. It describes the same provider, versions and release.

NetworkPolicy needs a CNI that enforces it. The live acceptance proves the
policy on kind's default CNI. The worker's egress (API server, DNS and the
evaluator) is not restricted by the chart, because the API server's address
is cluster-specific.

## Install

1. **Image.** Build it from this checkout with
   `devbox run -- scripts/examples/reference-provider-image.sh /absolute/fresh/dir`.
   The script builds it like the controller image ([images](../images.md)):
   it exports the working tree, verifies and vendors the example module's Go
   modules, compiles in melange's sandbox without module network access,
   tests the package, and assembles a non-root apko image holding the one
   static binary, with no shell, package manager or Wolfi runtime package.
   It writes `image.tar` (tag `localhost/konstapel-example-reporting:build-amd64`)
   and its SBOMs. Load it into your cluster's nodes or a registry you
   control, and take its manifest digest. The reference image is not
   published.
2. **Certificates.** Create three `kubernetes.io/tls` Secrets in the release
   namespace, each with `tls.crt`, `tls.key` and `ca.crt`. Each leaf has one
   exact DNS SAN ([transport and identity](external-provider-protocol.md#transport-and-identity)):

   | Value (default name) | Certificate | Its `ca.crt` verifies |
   | --- | --- | --- |
   | `tls.workerSecretName` (`<fullname>-worker-tls`) | worker serving (server auth), SAN = the `serverName` you register, for example `ref-example-reporting-worker.<namespace>.svc` | the host's client certificate |
   | `tls.workerClientSecretName` (`<fullname>-worker-client-tls`) | worker client (client auth), SAN = `worker.clientName` (default `<fullname>-worker.<namespace>.svc`) | the evaluator's serving certificate |
   | `tls.evaluatorSecretName` (`<fullname>-evaluator-tls`) | evaluator serving (server auth), SAN = `evaluator.serverName` (default `<fullname>-evaluator.<namespace>.svc`) | the worker's client certificate |

   With cert-manager and a platform issuer, for example:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: {name: ref-example-reporting-evaluator, namespace: providers}
   spec:
     secretName: ref-example-reporting-evaluator-tls
     dnsNames: [ref-example-reporting-evaluator.providers.svc]
     usages: [server auth, digital signature]
     issuerRef: {name: platform-ca, kind: ClusterIssuer}
   ```

   cert-manager writes `ca.crt` for CA issuers. The chart mounts each Secret
   read-only as a whole volume (never `subPath`), and each process re-reads
   its files every 10 seconds, so a renewed certificate or rotated trust is
   used without a restart once the kubelet updates the volume; connections
   the new trust no longer authorizes are closed.
3. **Install** into its own namespace:

   ```sh
   helm install ref examples/external-provider/reporting/chart --namespace providers \
     --set image.repository=<repository> --set image.digest=sha256:<digest> \
     --set 'worker.authorizedHosts[0]=konstapel-controller.konstapel-system.svc'
   ```

   `image.digest` and `worker.authorizedHosts` are required, and the schema
   rejects tags, other digest algorithms, wildcard names and unknown values.
   Both deployments report `image.digest` as their implementation.
4. **Register** (a Konstapel administrator, with the non-aggregated
   `konstapel-assessment-provider-admin` role): an `AssessmentProvider`
   naming provider `example-reporting`, `releaseDigest` = `image.digest`,
   the worker Service and its port, the worker's `serverName`, a
   `serverTrust` ConfigMap holding the worker serving certificate's CA, and
   compatibility `konstapel.provider.v1`, contract 1, evaluator 1, payload 1
   with capabilities `Collect` and `Evaluate`
   ([registration, selection and status](external-provider-protocol.md#registration-selection-and-status)).
   The registration is a claim checked against what the endpoint reports.
   Verifying and installing the digest-pinned image is the installation
   boundary, not proof from the endpoint.

## Tests

- `internal/charttest` (`task test`) renders the chart in several
  configurations and checks the permissions above: exactly one rule, `get`
  `namespaces`, bound only to the worker; no token, binding or source flag
  for the evaluator; the digest-pinned image reported as the
  implementation; probes on the health port; whole read-only Secret mounts;
  the evaluator's deny-all egress; no `AssessmentProvider` or
  `compliance.erenius.io` object. It also checks strict lint and that unsafe
  values fail. `TestChartsRegisterNoReferenceProvider`,
  `internal/provider/installed` and `scripts/image/test.sh` check that no
  Konstapel chart, values example, bundle, binary or controller image names
  the example provider, and that its contract resolves to no installed
  provider.
- The example module's tests (`scripts/examples/external-provider.sh`,
  `task test`) run the worker and evaluator in process: the split assessment,
  the evaluator's refusal of collection and the worker's refusal of an
  evaluator of another release or an unreachable one, and the Kubernetes
  source against a fake API server.
- `TestLiveReferenceProviderChart` (acceptance group `providers`,
  `task acceptance GROUP=providers OUTPUT=/absolute/fresh/path`) builds the
  image, loads it by digest into the disposable kind cluster, installs the
  chart and checks: no registration exists; SubjectAccessReview and real
  requests with tokens issued for each ServiceAccount (the worker may only
  get Namespaces, the evaluator nothing); the evaluator Pod has no API token;
  an ephemeral probe in the evaluator's network namespace cannot connect to
  the API server, while the same probe from the worker can; a Describe,
  Collect over live Namespaces, ReadResult, Acknowledge and Evaluate through
  the worker; the host's own identity refused by the evaluator; and, without
  a restart, a rotated worker serving certificate, host trust rotated to
  another CA (the old identity and its established connection refused, the
  new one accepted) and a rotated evaluator certificate still used by the
  worker.
