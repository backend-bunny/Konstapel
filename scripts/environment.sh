#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command=${1:?usage: environment.sh create|smoke|delete KUBECONFIG OUTPUT}
kubeconfig=${2:?explicit kubeconfig path required}
out=${3:?output directory required}
name=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment}
[[ "$name" =~ ^konstapel-assessment(-[a-z0-9-]+)?$ ]] || { echo "Invalid disposable cluster name" >&2; exit 1; }
context=kind-$name
k=(kubectl --request-timeout=15s --kubeconfig "$kubeconfig" --context "$context")
mkdir -p "$out" tools
case "$command" in
create)
  if kind get clusters 2>/dev/null | rg -qx "$name"; then
    echo "Refusing to reuse or delete existing cluster $name" >&2; exit 1
  fi
  chart=tools/kyverno-3.9.2.tgz
  if [[ ! -f $chart ]]; then curl -fLsS https://kyverno.github.io/kyverno/kyverno-3.9.2.tgz -o "$chart"; fi
  echo "f6fe7184544d5e2ee33a77808c09e67aa603ce6560cc197038fde31d727c861e  $chart" | sha256sum -c -
  kind create cluster --name "$name" --kubeconfig "$kubeconfig" --image kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5 --wait 120s
  "${k[@]}" get namespace kube-system -o jsonpath='{.metadata.uid}' > "$out/cluster-uid"
  # This kubeconfig file belongs only to this disposable cluster; never edit the ambient config.
  helm upgrade --install kyverno "$chart" --kubeconfig "$kubeconfig" --kube-context "$context" -n kyverno --create-namespace --set features.backgroundScan.backgroundScanInterval=15s --set features.logging.verbosity=0 --set features.policyExceptions.enabled=true --set features.policyExceptions.namespace=policy-exceptions --wait --timeout 10m > "$out/helm-install.log" 2>&1
  "${k[@]}" apply -f content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/ephemeral-rbac.yaml
  "$0" smoke "$kubeconfig" "$out"
  ;;
smoke)
  "${k[@]}" rollout status deployment -n kyverno --timeout=180s
  "${k[@]}" get --raw /apis/policies.kyverno.io/v1 > "$out/policy-api.json"
  "${k[@]}" get --raw /apis/wgpolicyk8s.io/v1alpha2 > "$out/report-api.json"
  jq -e 'any(.resources[]; .name=="validatingpolicies")' "$out/policy-api.json"
  jq -e 'any(.resources[]; .name=="policyreports") and any(.resources[]; .name=="clusterpolicyreports")' "$out/report-api.json"
  for account in admission reports; do
    verbs='get list watch'; if [[ $account == admission ]]; then verbs="$verbs update"; fi
    for verb in $verbs; do
      ready=false
      for attempt in {1..30}; do
        if "${k[@]}" auth can-i "$verb" pods --subresource=ephemeralcontainers --as="system:serviceaccount:kyverno:kyverno-$account-controller" | rg -qx yes; then ready=true; break; fi
        sleep 1
      done
      if [[ $ready != true ]]; then echo "missing $account $verb ephemeral permissions" >&2; exit 1; fi
    done
  done
  "${k[@]}" get ns kube-system -o json > "$out/target.json"
  "${k[@]}" get pods -n kyverno -o json | jq '[.items[] | {name:.metadata.name,containers:[(.status.initContainerStatuses[]?,.status.containerStatuses[]?)|{image,imageID,ready}]}]' > "$out/runtime-images.json"
  "${k[@]}" version -o json > "$out/kubernetes-version.json"
  helm get manifest kyverno -n kyverno --kubeconfig "$kubeconfig" --kube-context "$context" > "$out/helm-manifest.yaml"
  ;;
delete)
  # Refuse a replaced cluster, even if its kind name was reused.
  test -s "$out/cluster-uid"
  current=$("${k[@]}" get namespace kube-system -o jsonpath='{.metadata.uid}')
  test "$current" = "$(cat "$out/cluster-uid")" || { echo 'Cluster identity changed; refusing teardown' >&2; exit 1; }
  kind delete cluster --name "$name" --kubeconfig "$kubeconfig"
  ;;
*) echo "unknown environment operation: $command" >&2; exit 1;;
esac
