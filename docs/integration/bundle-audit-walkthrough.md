# Walkthrough: audit with the official signed bundle

One complete, reproducible path through OCI policy bundles on a disposable
cluster: configure the registry and trust, resolve the released
`konstapel-privileged-containers` 0.1.0 bundle by digest, pin it in a
`ComplianceProfile`, apply it to selected namespaces with an `Audit`
`ComplianceBinding`, admit a privileged Pod, and read the finding in an
assessment package whose bundle and content identity match the release.

> **How this is checked.** This page is run by hand; no CI workflow runs it.
> The commands and outputs below are from a run against the image and charts
> built from this repository's `main`, on the date in
> [Recorded run](#recorded-run). Output that varies between runs (UIDs,
> times, generated names and policy names, the controller image digest) is
> shown as observed in that run. The charts are installed from
> this checkout because they are not published yet
> ([Helm charts](../charts.md)).

What it uses:

| | |
| --- | --- |
| Bundle | `ghcr.io/backend-bunny/bundles/konstapel-privileged-containers@sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8` ([first official release](../policy-bundles.md#first-official-release-konstapel-privileged-containers-010)) |
| Content digest | `sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8` |
| Trust | [`bundles/official-sources.yaml`](../../bundles/official-sources.yaml): anonymous pulls, keyless signature by this repository's `bundle-release` workflow on `main` |
| Cluster | kind and Kyverno as pinned in [`scripts/runtime.env`](../../scripts/runtime.env), created by `scripts/environment.sh` (the acceptance environment) |
| Controller | the image built from the checkout (`task image:build`), loaded into the kind node and pinned by digest; one replica ([development values](../examples/charts/development.yaml)), download server off |
| Evidence storage | the pinned RustFS test service (`KONSTAPEL_S3_IMAGE`) on the kind network, as an `EvidenceDestination` with `developmentFixture: true` (plain HTTP, test-only) |

## Prerequisites

Docker, network access to `ghcr.io` and Docker Hub, and the repository's Devbox
environment. Run every command from the repository root inside `devbox shell`
(or with direnv), in one `bash` session: later steps use variables set by
earlier ones. `$W` must not exist yet; it collects the run's logs, verification
output and the downloaded package. Stop at the first command that fails.

```sh
source scripts/runtime.env
export KONSTAPEL_CLUSTER_NAME=konstapel-assessment-walkthrough
W=$PWD/out/walkthrough
mkdir "$W"
BUNDLE=konstapel-privileged-containers
REF=ghcr.io/backend-bunny/bundles/$BUNDLE
DIGEST=sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
CONTENT=sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8
```

## 1. Verify the release independently

Before trusting the digest in a cluster, check it the way the
[release notes](../policy-bundles.md#verifying-a-release) describe: Cosign
against the exact keyless identity, and the production verifier under the
checked-in official rule. Both read anonymously.

```sh
ID=https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main
ISS=https://token.actions.githubusercontent.com
cosign verify "$REF@$DIGEST" --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" > "$W/cosign-verify.json"
cosign verify-attestation "$REF@$DIGEST" --type slsaprovenance1 \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" > "$W/cosign-attestation.json"
go run ./cmd/bundlerelease verify-release -name "$BUNDLE" -digest "$DIGEST" | tee "$W/verify-release.txt"
```

Expected (Cosign's stderr ends with `The code-signing certificate was verified
using trusted certificate authority certificates` for each command):

```text
name=konstapel-privileged-containers
version=0.1.0
repository=ghcr.io/backend-bunny/bundles/konstapel-privileged-containers
digest=sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
signer=https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main (issuer https://token.actions.githubusercontent.com)
signingTime=2026-11-12T15:23:03Z
trustRoot=embedded:sigstore-public-good
trustRevision=sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66
sourceRule=sha256:0812f19fc13d0ff42bba7420c2111c81ca9a87dbe11740be79c7e56f5184dcd8
sourceRepository=https://github.com/backend-bunny/Konstapel
sourceCommit=863f4853151bb342a46eefa57c31cb2d46e17cff
workflowCommit=863f4853151bb342a46eefa57c31cb2d46e17cff
builder=https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main
content=sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8
signature=sha256:0d2484523fc82bec88b3e5c3cf35b0aaa3d4a3b764134a8bb14559fcc776a2c5
attestation=sha256:5141de7e7f35faf2fe54c8fa0c5f43514a534fc18c2a07053d842aa054961190
status=complete
```

`digest` and `content` are the two identities the assessment package must
carry at the end.

## 2. Create the disposable cluster

`scripts/environment.sh` creates the kind cluster from the pinned node image
and installs the pinned Kyverno chart (background scans every 15 seconds). It
refuses an existing cluster of the same name.

```sh
scripts/environment.sh create "$W/kubeconfig" "$W/environment" > "$W/environment.log" 2>&1
export KUBECONFIG=$W/kubeconfig
kubectl get --raw /apis/policies.kyverno.io/v1 | jq -r '.resources[].name' | grep -x validatingpolicies
```

```text
validatingpolicies
```

## 3. Build and load the controller image

Build the image from the checkout and load it into the node. kind records a
digest only for its import alias, so tag the image by that manifest digest
under its real repository; the chart then runs it by `repository@digest`
with `pullPolicy: Never`, as the live acceptance does.

```sh
task image:build > "$W/image-build.log" 2>&1
kind load image-archive out/image/image.tar --name "$KONSTAPEL_CLUSTER_NAME"
NODE=$KONSTAPEL_CLUSTER_NAME-control-plane
for _ in $(seq 30); do
  IMAGE_DIGEST=$(docker exec "$NODE" crictl inspecti -o json ghcr.io/backend-bunny/konstapel:build-amd64 2>/dev/null \
    | jq -r '.status.repoDigests[0] // empty' | sed 's/.*@//') && [ -n "$IMAGE_DIGEST" ] && break
  sleep 2
done
docker exec "$NODE" ctr -n k8s.io images tag ghcr.io/backend-bunny/konstapel:build-amd64 \
  "ghcr.io/backend-bunny/konstapel@$IMAGE_DIGEST" >/dev/null
echo "$IMAGE_DIGEST"
```

```text
sha256:a76245895fd5536e4e4d92a91420153b4b3ff111c7b9aaddad07da77915c9eec
```

Your digest differs: it identifies your local build, and later output that
names the controller image shows the same value.

## 4. Start the test evidence store

Assessment packages are published to S3. This starts the pinned S3-compatible
test service on the kind network (reachable from pods by container name and
from this shell on a loopback port) and creates the bucket. Konstapel never
creates buckets.

```sh
S3=konstapel-walkthrough-s3
S3_KEY=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
S3_SECRET=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
docker run -d --name "$S3" --network kind -p 127.0.0.1::9000 \
  -e RUSTFS_ACCESS_KEY="$S3_KEY" -e RUSTFS_SECRET_KEY="$S3_SECRET" "$KONSTAPEL_S3_IMAGE" /data >/dev/null
S3_LOCAL=http://$(docker port "$S3" 9000/tcp | head -1)
s3() { curl -fsS --aws-sigv4 aws:amz:us-east-1:s3 --user "$S3_KEY:$S3_SECRET" "$@"; }
# The service needs a few seconds to start; retry until the bucket exists.
until s3 -X PUT "$S3_LOCAL/konstapel-evidence" -o /dev/null 2>/dev/null; do sleep 2; done
```

## 5. Configure the registry source and trust

The sources ConfigMap is the central registry and trust configuration
([Central source configuration](../policy-bundles.md#central-source-configuration)).
For official bundles it is the checked-in `bundles/official-sources.yaml`
unchanged: anonymous pulls, so no credential Secret, CA or key to reference.
The chart never creates this ConfigMap.

```sh
kubectl create namespace konstapel-system
kubectl -n konstapel-system create configmap konstapel-bundle-sources \
  --from-file=sources.yaml=bundles/official-sources.yaml
```

## 6. Install the charts with bundles enabled

`bundles.sourcesConfigMap` turns on OCI bundle sources (the `--bundle-*`
flags, the per-pod cache and the bundle Role;
[OCI policy bundles](../charts.md#oci-policy-bundles)). The download server is
turned off because this walkthrough reads the package from the test bucket;
see [Downloads](s3-evidence.md#downloads) for the authorized download path.

```sh
helm install konstapel-crds charts/konstapel-crds --namespace konstapel-system --wait
kubectl wait --for=condition=Established crd --all --timeout=60s >/dev/null
helm install konstapel charts/konstapel --namespace konstapel-system --wait --timeout 5m \
  -f docs/examples/charts/development.yaml \
  --set download.enabled=false \
  --set bundles.sourcesConfigMap=konstapel-bundle-sources \
  --set image.digest="$IMAGE_DIGEST" --set image.pullPolicy=Never > "$W/helm-install.log"
kubectl -n konstapel-system get deploy konstapel-controller \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}{.spec.template.spec.containers[0].args}{"\n"}'
```

```text
ghcr.io/backend-bunny/konstapel@sha256:a76245895fd5536e4e4d92a91420153b4b3ff111c7b9aaddad07da77915c9eec
["controller","--leader-elect=true","--health-probe-bind-address=:8081","--metrics-bind-address=0","--evidence-staging-dir=/var/lib/konstapel/staging","--shutdown-timeout=45s","--bundle-sources-configmap=konstapel-bundle-sources","--bundle-cache-dir=/var/lib/konstapel/bundles","--bundle-cache-capacity=1Gi","--bundle-refresh-interval=30s"]
```

## 7. Create the evidence destination

```sh
kubectl -n konstapel-system create secret generic walkthrough-s3 \
  --from-literal=accessKeyID="$S3_KEY" --from-literal=secretAccessKey="$S3_SECRET"
kubectl apply -f - <<EOF
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceDestination
metadata: {name: walkthrough}
spec:
  s3:
    endpoint: http://$S3:9000
    bucket: konstapel-evidence
    region: us-east-1
    prefix: walkthrough
    addressing: path
    developmentFixture: true
    credentialSecret: {name: walkthrough-s3}
EOF
kubectl wait evidencedestination/walkthrough --for=condition=Ready --timeout=3m
DEST_UID=$(kubectl get evidencedestination walkthrough -o jsonpath='{.metadata.uid}')
```

## 8. Pin the bundle and bind it in Audit mode

The profile pins the bundle by name and manifest digest and selects its one
policy. The binding applies it, in `Audit`, to namespaces labelled
`walkthrough.konstapel.dev/audit: "true"`, and publishes its scheduled
assessments to the destination above.

```sh
kubectl apply -f - <<EOF
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata: {name: official-privileged}
spec:
  bundle:
    name: $BUNDLE
    digest: $DIGEST
  policies:
    - name: disallow-privileged-containers
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata: {name: official-privileged-audit}
spec:
  profileRef: {name: official-privileged}
  namespaceSelector:
    matchLabels: {walkthrough.konstapel.dev/audit: "true"}
  mode: Audit
EOF
kubectl wait complianceprofile/official-privileged --for=condition=Resolved --timeout=5m
kubectl wait compliancebinding/official-privileged-audit --for=condition=EngineReady --timeout=5m
kubectl get compliancebinding official-privileged-audit \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'
kubectl get validatingpolicies -l compliance.erenius.io/binding-uid="$(kubectl get compliancebinding official-privileged-audit -o jsonpath='{.metadata.uid}')" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}  bundle={.metadata.annotations.compliance\.erenius\.io/bundle}{"\n"}  digest={.metadata.annotations.compliance\.erenius\.io/bundle-digest}{"\n"}  actions={.spec.validationActions}{"\n"}{end}'
```

```text
complianceprofile.compliance.erenius.io/official-privileged created
compliancebinding.compliance.erenius.io/official-privileged-audit created
complianceprofile.compliance.erenius.io/official-privileged condition met
compliancebinding.compliance.erenius.io/official-privileged-audit condition met
Resolved=True Resolved
EngineReady=True Ready
konstapel-disallow-privileged-containers-377207027577b0fd
  bundle=konstapel-privileged-containers
  digest=sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
  actions=["Audit"]
```

The profile resolved only after the controller fetched the digest from
`ghcr.io`, verified its keyless signature and provenance under the official
rule, and validated the content; the engine policy names the bundle and digest
it was rendered from.

## 9. Submit a violating workload

A namespace the binding selects, and a privileged Pod in it. `Audit` admits
the Pod; the violation is recorded, not blocked.

```sh
kubectl create namespace walkthrough-team
kubectl label namespace walkthrough-team walkthrough.konstapel.dev/audit=true
kubectl -n walkthrough-team run privileged --image="$KONSTAPEL_WORKLOAD_IMAGE" --restart=Never \
  --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"privileged","image":"'"$KONSTAPEL_WORKLOAD_IMAGE"'","command":["sleep","3600"],"securityContext":{"privileged":true}}]}}'
kubectl -n walkthrough-team wait pod/privileged --for=condition=Ready --timeout=3m
```

```text
namespace/walkthrough-team created
namespace/walkthrough-team labeled
pod/privileged created
pod/privileged condition met
```

## 10. Run the assessment

Enabling the binding's assessment schedules its first run immediately. The
run freezes the binding's scope and the verified bundle, collects Kyverno's
reports until evidence is complete (or `collectionTimeout`), exports OSCAL
from the frozen bundle and publishes the package.

```sh
kubectl patch compliancebinding official-privileged-audit --type merge -p \
  '{"spec":{"assessment":{"interval":"24h","collectionTimeout":"3m","destinationRef":{"name":"walkthrough","uid":"'"$DEST_UID"'"}}}}'
until RUN=$(kubectl get compliancebinding official-privileged-audit -o jsonpath='{.status.assessment.latestRun.name}') && [ -n "$RUN" ]; do sleep 3; done
kubectl wait assessmentrun/"$RUN" --for=jsonpath='{.status.publication.phase}'=Committed --timeout=10m
kubectl get assessmentrun "$RUN"
kubectl get assessmentrun "$RUN" -o jsonpath='{.status.summary}' | jq .
kubectl -n konstapel-system get pods -l app.kubernetes.io/component=controller \
  -o jsonpath='{range .items[*]}{.metadata.name} restarts={.status.containerStatuses[0].restartCount}{"\n"}{end}'
```

```text
compliancebinding.compliance.erenius.io/official-privileged-audit patched
assessmentrun.compliance.erenius.io/official-privileged-audit-s-396360a16ba7882c condition met
NAME                                           BINDING                     SCOPE     PHASE       EVIDENCE   PUBLICATION
official-privileged-audit-s-396360a16ba7882c   official-privileged-audit   Binding   Completed   Complete   Committed
{
  "evidence": {
    "attributable": 1,
    "completeness": "Complete",
    "expected": 1,
    "missing": 0,
    "rejected": 0,
    "unresolved": 0
  },
  "export": "Assessment",
  "outcomes": {
    "acceptedRisk": 0,
    "error": 0,
    "fail": 1,
    "notApplicable": 0,
    "pass": 0,
    "skip": 0,
    "unknown": 0
  }
}
konstapel-controller-797957476b-sdxqz restarts=0
```

**If the run is `Incomplete`.** Expect `Complete` with one attributable
`fail`. A controller restart or leader change during collection makes earlier
observations non-continuous (`scopeChanges` in the package's `capture.json`
records a `WatchDiscontinuity`), and the Pod's report, evaluated before that
point, is then `rejected` with the reason `not after the observed-state
boundary` in `evaluation.json`. In the run where we saw this, Kyverno had
not re-stamped the unchanged Pod's report by the end of collection, so fresh
evidence needs a fresh evaluation. Check the controller's restart count
above; to repeat the step, recreate the Pod (step
9, after `kubectl -n walkthrough-team delete pod privileged`), wait for its
report (`kubectl -n walkthrough-team get policyreports`), and request a run:
`kubectl create -f - <<<'{"apiVersion":"compliance.erenius.io/v1alpha1","kind":"AssessmentRun","metadata":{"generateName":"official-privileged-audit-manual-"},"spec":{"bindingRef":{"name":"official-privileged-audit"},"scope":"Binding"}}'`.
We saw this once, on a host also running the full `task check` suite at the
time; the controller's logs were not retained.

## 11. Read the finding and the bundle identity

Fetch the committed archive, check it against the run's receipt, and read the
descriptor and the OSCAL assessment results.

```sh
KEY=$(kubectl get assessmentrun "$RUN" -o jsonpath='{.status.publication.commit.archiveKey}')
s3 "$S3_LOCAL/konstapel-evidence/$KEY" -o "$W/package.tar.gz"
echo "$(kubectl get assessmentrun "$RUN" -o jsonpath='{.status.publication.packageSha256}')  $W/package.tar.gz" | sha256sum -c
mkdir "$W/package" && tar -xzf "$W/package.tar.gz" -C "$W/package"
jq '.revisions.content' "$W/package/descriptor.json"
jq -e --arg d "$DIGEST" --arg c "$CONTENT" --arg b "$BUNDLE" \
  '.revisions.content | (.applied | length) == 1 and (.applied[0] | .bundle == $b and .manifestDigest == $d and .contentDigest == $c and .frozen)
   and .desired.manifestDigest == $d and (.differences // [] | length) == 0' "$W/package/descriptor.json"
echo "sha256:$(sha256sum < "$W/package/bundles/${DIGEST#sha256:}/bundle/manifest.json" | cut -d' ' -f1)"
```

The run assessed the policy applied from the bundle the profile selects, so
`applied` holds that one bundle, packaged under `bundles/<hex digest>/`,
`desired` names the same bundle, and there are no `differences`. (The output
below was recorded before `revisions.content` gained `applied`, `desired`
and `differences`; it is shown in the current shape with the recorded
values.)

```text
/…/out/walkthrough/package.tar.gz: OK
{
  "applied": [
    {
      "bundle": "konstapel-privileged-containers",
      "manifestDigest": "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8",
      "frozen": true,
      "path": "bundles/1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8",
      "version": "0.1.0",
      "contentDigest": "sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8",
      "archiveDigest": "sha256:82a3f787a42544e3f84f38b008d84880db59881b5721302653872741ee2e1da5",
      "sourceRevision": "863f4853151bb342a46eefa57c31cb2d46e17cff",
      "sourceRule": "sha256:0812f19fc13d0ff42bba7420c2111c81ca9a87dbe11740be79c7e56f5184dcd8",
      "trustRevision": "sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
      "verifiedAt": "2026-11-12T19:08:25.382557553Z"
    }
  ],
  "desired": {
    "bundle": "konstapel-privileged-containers",
    "manifestDigest": "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8",
    "frozen": false
  }
}
true
sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8
```

```sh
jq '.["assessment-results"] | {
  bundle: ([.metadata.props[] | select(.name | startswith("bundle-")) | {(.name): .value}] | add),
  finding: .results[0].findings[0].target,
  observation: (.results[0].observations[0].props | map({(.name): .value}) | add)}' "$W/package/assessment-results.json"
# Each evaluated observation's outcome and its resource's UID (the key's fourth field)
jq -r '.observations[] | "\(.outcome) \(.key | split("\u0000")[3])"' "$W/package/evaluation.json"
kubectl -n walkthrough-team get pod privileged -o jsonpath='{.metadata.uid}{"\n"}'
```

```text
{
  "bundle": {
    "bundle-name": "konstapel-privileged-containers",
    "bundle-version": "0.1.0",
    "bundle-digest": "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8",
    "bundle-content-digest": "sha256:791b6e4a006101c5dd676e3c005bd4452d14892554d7c7f336171eace33457c8"
  },
  "finding": {
    "status": {
      "state": "not-satisfied"
    },
    "target-id": "ac-6_smt",
    "type": "statement-id"
  },
  "observation": {
    "assessment-rule-id": "disallow-privileged-containers",
    "assessment-check-id": "disallow-privileged-containers"
  }
}
fail a0a53315-dd92-4fea-a920-8b782caf74ae
a0a53315-dd92-4fea-a920-8b782caf74ae
```

The package names the bundle by the same manifest digest and content digest
that `verify-release` reported in step 1, and the finding (the privileged Pod
admitted in step 9) is evaluated against that frozen bundle.

## 12. Tear down

```sh
scripts/environment.sh delete "$W/kubeconfig" "$W/environment"
docker rm -f "$S3"
```

`$W` keeps the logs, verification output and the downloaded package.

## Recorded run

2026-11-12, on Linux with Docker, from `main` at `566c831` plus this page.
Every command block on this page was extracted from the Markdown and run in
order, unmodified, in one `bash -euo pipefail` session from a fresh `$W`
(Kyverno chart 3.9.2, kind node `v1.37.0`, Cosign 3.1.3, Helm 4.3.1), and
the outputs above are from that run. It also ran the manual `AssessmentRun`
from the troubleshooting note, which completed with `Complete` evidence. An
earlier run, on a host also running `task check`, ended `Incomplete` for the
reason described under step 10.

Not covered here: `Deny` mode, a private or mirrored organization source
(see [Private registry setup](../policy-bundles.md#private-registry-setup)),
credential or trust rotation, and digest upgrades or rollbacks.
`TestLiveHelmBundles` covers mirrors, credential rotation, trust revocation
and rollback against a test registry
([Helm installation and live acceptance](../policy-bundles.md#helm-installation-and-live-acceptance));
`Deny` with an OCI bundle and digest upgrades are not yet exercised live.
