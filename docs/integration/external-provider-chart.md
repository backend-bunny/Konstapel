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
external provider yet ([charts](../charts.md#external-assessment-providers)).
The inventory and attribution format is protocol revision 2
([inventory](external-provider-protocol.md#inventory)), and run wiring and
bundle check content are `add-external-assessment-providers` group 3. How a provider release is signed, with SBOMs and provenance, and
how operators verify it before installing is in
[Release proofs](#release-proofs) and [Verify and install](#verify-and-install);
the reference image and chart are signed only in disposable local
registries. Upgrade, drain and uninstall are 5.3.

## Layout

| Object | Name (release `ref`) | What it is |
| --- | --- | --- |
| ServiceAccount | `ref-example-reporting-worker` | The source worker's identity; its token is mounted. |
| ClusterRole and ClusterRoleBinding | `ref-example-reporting-worker-<namespace>-source` | `get` on `namespaces`, bound to the worker only. The chart's only permission. |
| Deployment and Service | `ref-example-reporting-worker` | `reporting-provider -role worker -source kubernetes`: Collect only, the source endpoint you register (`spec.endpoint`). One replica, because staged results live in its memory. |
| ServiceAccount | `ref-example-reporting-evaluator` | The evaluator's identity: `automountServiceAccountToken: false`, bound to no role. |
| Deployment and Service | `ref-example-reporting-evaluator` | `reporting-provider -role evaluator`: Evaluate only, the evaluator endpoint you register (`spec.evaluatorEndpoint`). |
| NetworkPolicy | `ref-example-reporting-evaluator` | Ingress to the protocol port from `evaluator.hostNamespaces` (default `konstapel-system`) only, not from the worker; no egress at all. |
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

The worker never evaluates, and forwards nothing: it serves only
`CAPABILITY_COLLECT` (with ReadResult and Acknowledge) and has no client
identity for the evaluator.

The evaluator is a separate endpoint with its own authenticated identity
(design Decision 11). The host calls it directly at the registration's
`spec.evaluatorEndpoint`, never through the worker, so evaluator isolation
does not depend on trusting the worker to forward evaluation. It serves only
`CAPABILITY_EVALUATE` and holds no source handler. It has no Kubernetes API
token and no RBAC, and its NetworkPolicy denies all egress, so the separation
does not rest on an RPC method: the process that evaluates cannot reach a
source. It authorizes exactly `evaluator.authorizedHosts` (required, the
controller's identity), admits only `evaluator.hostNamespaces` (default
`konstapel-system`), and describes the same provider, versions and release
as the worker. Replay after the worker is gone uses the same endpoint: an
`Evaluate`-only registration names only `spec.evaluatorEndpoint`.

NetworkPolicy needs a CNI that enforces it. The live acceptance proves the
policy on kind's default CNI. The worker's egress (API server and DNS) is
not restricted by the chart, because the API server's address is
cluster-specific.

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
   published. A provider published by someone else is verified first:
   follow [Verify and install](#verify-and-install) instead of steps 1 and 3.
2. **Certificates.** Create two `kubernetes.io/tls` Secrets in the release
   namespace, each with `tls.crt`, `tls.key` and `ca.crt`. Each leaf has one
   exact DNS SAN ([transport and identity](external-provider-protocol.md#transport-and-identity)):

   | Value (default name) | Certificate | Its `ca.crt` verifies |
   | --- | --- | --- |
   | `tls.workerSecretName` (`<fullname>-worker-tls`) | worker serving (server auth), SAN = the `spec.endpoint.serverName` you register, for example `ref-example-reporting-worker.<namespace>.svc` | the host's client certificate |
   | `tls.evaluatorSecretName` (`<fullname>-evaluator-tls`) | evaluator serving (server auth), SAN = `evaluator.serverName` (default `<fullname>-evaluator.<namespace>.svc`), the `spec.evaluatorEndpoint.serverName` you register | the host's client certificate |

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
     --set 'worker.authorizedHosts[0]=konstapel-controller.konstapel-system.svc' \
     --set 'evaluator.authorizedHosts[0]=konstapel-controller.konstapel-system.svc'
   ```

   `image.digest`, `worker.authorizedHosts` and `evaluator.authorizedHosts`
   are required. The schema and the chart reject tags, other digest
   algorithms, wildcard names, unknown values, an evaluator without host
   namespaces, and an evaluator `serverName` equal to the worker's. Both
   deployments report `image.digest` as their implementation.
4. **Register** (a Konstapel administrator, with the non-aggregated
   `konstapel-assessment-provider-admin` role) an `AssessmentProvider`
   naming the two endpoints separately
   ([registration, selection and status](external-provider-protocol.md#registration-selection-and-status)):

   ```yaml
   apiVersion: compliance.erenius.io/v1alpha1
   kind: AssessmentProvider
   metadata: {name: example-reporting}
   spec:
     provider: {name: example-reporting, releaseDigest: "sha256:<image.digest>"}
     endpoint:            # the worker: Collect
       service: {namespace: providers, name: ref-example-reporting-worker, port: 8443}
       serverName: ref-example-reporting-worker.providers.svc
       serverTrust: {name: example-reporting-ca}
     evaluatorEndpoint:   # the evaluator: Evaluate
       service: {namespace: providers, name: ref-example-reporting-evaluator, port: 8443}
       serverName: ref-example-reporting-evaluator.providers.svc
       serverTrust: {name: example-reporting-ca}
     compatibility: {protocol: konstapel.provider.v1, contractVersion: 1, evaluatorVersion: 1, payloadVersion: 1}
     capabilities: [Collect, Evaluate]
   ```

   Each `serverTrust` ConfigMap in the controller namespace holds the CA of
   that endpoint's serving certificate.
   The registration is a claim checked against what the endpoint reports.
   Verifying and installing the digest-pinned image is the installation
   boundary, not proof from the endpoint.

## Release proofs

A provider release is two OCI subjects, each named by its manifest digest:
the image and the chart. The publisher signs and attests both by digest,
never by tag, with the tools and formats of Konstapel's own release
([images](../images.md#published-evidence), [releases](../releases.md#chart-publication)):

| Subject | Proofs (Cosign v3 Sigstore bundles, attached as OCI referrers) |
| --- | --- |
| image | a `cosign sign` signature; apko's SPDX SBOM (`sbom-x86_64.spdx.json`) and Syft's image scan (`sbom-complete.spdx.json`, which lists the binary's Go modules) as `cosign attest --type spdxjson`; SLSA provenance v1 |
| chart | a `cosign sign` signature; SLSA provenance v1. Its default `image.repository` and `image.digest` are the signed image, set at packaging as Konstapel's release pins its runtime chart's image |

`scripts/examples/reference-provider-image.sh` writes both SBOMs. A real
publisher signs keylessly from its release workflow, as Konstapel's
publishing workflow does: `cosign sign --yes "$IMAGE"` and
`cosign attest --yes --type spdxjson --predicate <sbom> "$IMAGE"` with the
workflow's GitHub OIDC identity, then provenance for the digest
(Konstapel uses `actions/attest-build-provenance` with `push-to-registry`).
It packages the chart with `image.digest` set to the published image
digest, pushes it with `helm push`, signs and attests the chart digest the
same way, and documents three things for operators: the exact signing
identity and OIDC issuer, the provenance builder ID, and the chart digest of
each release.

A signature establishes who published a digest, not that the provider is
correct or safe. Konstapel does not check these proofs: it is not Helm, a
container runtime or a plugin downloader. Verifying them before installing
is the installation boundary, and an `AssessmentProvider`'s `releaseDigest`
is a claim compared with what the endpoint reports, not attestation.

### Reference provenance v1

The provenance the [signing fixture](#signing-fixture) attests is SLSA
provenance v1 (`https://slsa.dev/provenance/v1`, `cosign attest --type
slsaprovenance1`) with this build type
(`https://github.com/backend-bunny/Konstapel/blob/main/docs/integration/external-provider-chart.md#reference-provenance-v1`):

- `buildDefinition.externalParameters`: `artifact` (`image` or `chart`),
  `source` (repository and commit) and, for the image, `recipe` (the
  melange/apko directory), or, for the chart, `chart` (path, name, version)
  and `image` (the repository and digest the chart pins).
- `buildDefinition.resolvedDependencies`: the source commit (`gitCommit`),
  and the SHA-256 of `melange.yaml` and `apko.yaml` at that commit, or the
  pinned image's digest for the chart.
- `runDetails.builder.id`: the builder, which the verification compares;
  `metadata.invocationId` is the run; `byproducts` are the SHA-256 of the
  two SBOMs and the build-environment log, or of the chart archive.

The fixture's builder is the test name
`https://ci.example.test/konstapel/reference-provider-signing`. Provenance
generated by GitHub's attestation action has GitHub's own build type and
fields; only the builder comparison below applies to both.

## Verify and install

Run this in Bash (`set -euo pipefail`) in a fresh directory with the pinned
Cosign, Helm and jq, and stop at the first failure. Set the publisher's
documented trust, its builder ID and the chart digest of the release. For a
keyless publisher releasing from GitHub Actions:

```sh
TRUST=(--certificate-identity https://github.com/<owner>/<repository>/.github/workflows/<release>.yml@refs/heads/main
  --certificate-oidc-issuer https://token.actions.githubusercontent.com)
PULL=()
BUILDER=<the provenance builder ID the publisher documents>
CHART=<registry>/<path>/example-reporting-provider@sha256:<chart digest>
```

Use the exact identity, not a pattern that admits other workflows. Then
verify the chart, find the image it runs, and verify that image:

```sh
cosign verify "${TRUST[@]}" "$CHART" > chart-signature.json
jq -e --arg digest "${CHART#*@}" 'type == "array" and any(.[]; .critical.type == "https://sigstore.dev/cosign/sign/v1" and .critical.image."docker-manifest-digest" == $digest)' chart-signature.json
cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$CHART" > chart-provenance.jsonl
jq -se --arg builder "$BUILDER" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == $builder)' chart-provenance.jsonl
mkdir chart
helm pull "oci://$CHART" "${PULL[@]}" --destination chart
IMAGE=$(helm template ref chart/*.tgz --set 'worker.authorizedHosts[0]=probe.example.test' --set 'evaluator.authorizedHosts[0]=probe.example.test' | sed -n 's/^ *image: //p' | sort -u)
[[ $IMAGE =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]
cosign verify "${TRUST[@]}" "$IMAGE" > image-signature.json
jq -e --arg digest "${IMAGE#*@}" 'type == "array" and any(.[]; .critical.type == "https://sigstore.dev/cosign/sign/v1" and .critical.image."docker-manifest-digest" == $digest)' image-signature.json
cosign verify-attestation "${TRUST[@]}" --type spdxjson "$IMAGE" > image-sbom.jsonl
cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$IMAGE" > image-provenance.jsonl
jq -se --arg builder "$BUILDER" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == $builder)' image-provenance.jsonl
```

What each step establishes:

- `cosign verify` accepts only proofs signed under `TRUST` whose signed
  statement names exactly that digest, so proofs copied from another digest
  fail. Cosign v3 also counts the publisher's attestations as signatures,
  so `jq` then requires the `cosign sign` signature itself: a verified
  payload of type `https://sigstore.dev/cosign/sign/v1` whose subject is
  exactly the verified digest (the controller image's
  [check](../images.md#verify) is the same filter).
- `cosign verify-attestation` requires an SBOM and a provenance attestation
  under the same trust, again for exactly that digest, and `jq` requires the
  documented builder.
- The chart is pulled by its verified digest. `helm template` reports the
  one image both deployments run. It must be a digest reference, and that
  digest is verified next: a signed chart pinning an unsigned or foreign
  image fails there.

If the publisher attests provenance with GitHub artifact attestations, as
Konstapel's controller does, also run `gh attestation verify "oci://$IMAGE"
--repo <owner>/<repository>`, the controller's documented check
([images](../images.md#verify)). This procedure has not been run against
GitHub-generated provenance.

Install the verified archive with the verified image, and register that
digest:

```sh
helm install ref chart/*.tgz --namespace providers \
  --set image.repository="${IMAGE%@*}" --set image.digest="${IMAGE#*@}" \
  --set 'worker.authorizedHosts[0]=konstapel-controller.konstapel-system.svc' \
  --set 'evaluator.authorizedHosts[0]=konstapel-controller.konstapel-system.svc'
echo "releaseDigest: ${IMAGE#*@}"
```

Create the TLS Secrets of [Install](#install) step 2 first, and register as
in step 4 with `releaseDigest` set to the printed digest. A mirror is fine
if it serves the same digests; verify against the mirror's references.

### Signing fixture

`scripts/examples/reference-provider-signing.sh IMAGE_DIR OUTPUT_DIR` signs
the image that `reference-provider-image.sh` built, unchanged, and a chart
pinning it, and runs the procedure above, every line of which it quotes from
this page (it fails if this page stops quoting one). The acceptance group
`providers` runs it after building the image. It publishes nothing: each of
two disposable registries, the pinned distribution registry (no referrers
API, so Cosign keeps the OCI tag schema index, as on `ghcr.io`) and Zot (OCI
1.1 referrers API), runs on a loopback port over plain HTTP, labelled for the
run and removed afterwards. Cosign signs in key mode with two key pairs
generated for the run, in a private temporary directory that is deleted;
nothing is uploaded to a transparency log, no OIDC token is used, and
outbound HTTP(S) other than loopback goes to a closed port. The keyed trust
and plain-HTTP pull of the fixture are:

```sh
TRUST=(--key publisher.pub --insecure-ignore-tlog=true --allow-http-registry)
PULL=(--plain-http)
```

These flags are for the disposable fixture only. A publisher signing with a
key of its own should also upload to a transparency log, so that verifiers
need no `--insecure-ignore-tlog`.

On each registry the run must end exactly as listed, at the listed step:

| Case | Fixture | Outcome |
| --- | --- | --- |
| `valid-release` | the chart, the image it pins, both SBOMs and both provenances, by the publisher | accepted; the image it reports is the tested image's digest |
| `image-other-publisher` | an image signed and attested only by another key | rejected at the image signature |
| `image-untrusted-key` | the valid image, verified under a key the publisher does not use | rejected at the image signature |
| `image-unsigned` | an image digest with no proofs | rejected at the image signature |
| `image-attestations-only` | the publisher's attestations, no signature | rejected at the signature kind check |
| `image-signature-only` | a signature, no SBOM or provenance | rejected at the SBOM |
| `image-other-builder` | signed and attested by the publisher, provenance from another builder | rejected at the builder check |
| `image-copied-proofs` | the valid image's signature and attestations attached to another digest | rejected at the image signature |
| `image-copied-attestations` | its own signature, the valid image's attestations | rejected at the SBOM |
| `chart-pins-unsigned-image` | a signed chart with provenance whose default image is an unsigned digest | rejected at the image signature |
| `chart-unsigned` | a chart with no proofs | rejected at the chart signature |
| `chart-signature-only` | a signed chart without provenance | rejected at the chart provenance |
| `chart-other-publisher` | a chart signed and attested by another key | rejected at the chart signature |
| `controller-check-valid` | the valid image, through the controller image's signature check ([images](../images.md#verify), `scripts/image/verify-signature-payload.sh`) | accepted |
| `controller-check-attestations-only` | the attestation-only image, through that check | `cosign verify` accepts it; rejected at the payload check |
| `controller-check-other-subject` | the valid image's verified payloads, required to name another digest | rejected at the payload check |

Each fixture is another digest of the same image (one more manifest
annotation) or another chart version. `OUTPUT_DIR/reference-provider-signing.json`
records every case, its outcome, the step it ended at and the tool and
registry versions; per registry, the accepted release's signatures and
provenance statements, a summary of its SBOM statements and the release
digests; the predicates; and the SHA-256 of both public keys. No private key
is written there. To run it outside acceptance (Docker required):

```sh
devbox run -- scripts/examples/reference-provider-image.sh /absolute/fresh/image
devbox run -- scripts/examples/reference-provider-signing.sh /absolute/fresh/image /absolute/fresh/signing
```

Keyless signing is not exercised by this fixture. Konstapel's policy
bundle suite runs a disposable Sigstore instance for that
([isolated keyless Sigstore stack](../policy-bundles.md#isolated-keyless-sigstore-stack)); the identity flags above are
Cosign's documented keyless verification.

## Tests

- `internal/charttest` (`task test`) renders the chart in several
  configurations and checks the permissions above: exactly one rule, `get`
  `namespaces`, bound only to the worker; no token, binding or source flag
  for the evaluator; the digest-pinned image reported as the
  implementation; probes on the health port; whole read-only Secret mounts;
  the evaluator's deny-all egress and host-only ingress; no
  worker-to-evaluator client; no `AssessmentProvider` or
  `compliance.erenius.io` object. It also checks strict lint and that unsafe
  values fail. `TestChartsRegisterNoReferenceProvider`,
  `internal/provider/installed` and `scripts/image/test.sh` check that no
  Konstapel chart, values example, bundle, binary or controller image names
  the example provider, and that its contract resolves to no installed
  provider.
- The example module's tests (`scripts/examples/external-provider.sh`,
  `task test`) run the worker and evaluator in process: the split assessment
  (collection at the worker, evaluation at the evaluator, each called by the
  host), the evaluator's refusal of collection, the worker's refusal of
  evaluation, and the Kubernetes source against a fake API server.
- The [signing fixture](#signing-fixture) (acceptance group `providers`)
  signs the built image and a chart pinning it in two disposable registries
  and runs the documented verification on the valid release and twelve
  fixtures that must be rejected, and the controller image's signature check
  on the valid image and two fixtures it must reject.
- `TestLiveReferenceProviderChart` (acceptance group `providers`,
  `task acceptance GROUP=providers OUTPUT=/absolute/fresh/path`) builds the
  image, loads it by digest into the disposable kind cluster, installs the
  chart and checks: no registration exists; SubjectAccessReview and real
  requests with tokens issued for each ServiceAccount (the worker may only
  get Namespaces, the evaluator nothing); the evaluator Pod has no API token;
  an ephemeral probe in the evaluator's network namespace cannot connect to
  the API server, while the same probe from the worker can; a Describe,
  Collect over live Namespaces, ReadResult and Acknowledge at the worker and
  Evaluate at the evaluator, both called as the host; the worker's refusal
  of evaluation and the evaluator's refusal of collection; and, without a
  restart, a rotated worker serving certificate, host trust rotated to
  another CA (the old identity and its established connection refused, the
  new one accepted) and a rotated evaluator certificate served to the host.
