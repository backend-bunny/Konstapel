#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
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
  chart=$(scripts/fetch-chart.sh)
  # KONSTAPEL_CLUSTER_WORKERS adds worker nodes labelled for Konstapel
  # (konstapel.dev/pool=workload); Kyverno then stays on the control plane,
  # so node-loss tests remove Konstapel replicas without removing the engine.
  workers=${KONSTAPEL_CLUSTER_WORKERS:-0}
  [[ $workers =~ ^[0-9]$ ]] || { echo "KONSTAPEL_CLUSTER_WORKERS must be 0-9" >&2; exit 1; }
  config=$out/kind-config.yaml
  { echo 'kind: Cluster'; echo 'apiVersion: kind.x-k8s.io/v1alpha4'; echo 'nodes:'; echo '- role: control-plane'
    for _ in $(seq 1 "$workers"); do echo '- role: worker'; echo '  labels:'; echo '    konstapel.dev/pool: workload'; done; } > "$config"
  kind create cluster --name "$name" --kubeconfig "$kubeconfig" --image "$KONSTAPEL_NODE_IMAGE" --config "$config" --wait 180s
  kyverno_placement=()
  if (( workers > 0 )); then
    cp=$name-control-plane
    for c in admissionController backgroundController reportsController cleanupController; do
      kyverno_placement+=(--set "$c.nodeSelector.kubernetes\.io/hostname=$cp"
        --set "$c.tolerations[0].key=node-role.kubernetes.io/control-plane" --set "$c.tolerations[0].operator=Exists" --set "$c.tolerations[0].effect=NoSchedule")
    done
  fi
  "${k[@]}" get namespace kube-system -o jsonpath='{.metadata.uid}' > "$out/cluster-uid"
  # This kubeconfig file belongs only to this disposable cluster; never edit the ambient config.
  helm upgrade --install kyverno "$chart" --kubeconfig "$kubeconfig" --kube-context "$context" -n kyverno --create-namespace --set features.backgroundScan.backgroundScanInterval=15s --set features.logging.verbosity=0 --set features.policyExceptions.enabled=true --set features.policyExceptions.namespace=policy-exceptions "${kyverno_placement[@]}" --wait --timeout 10m 2>&1 | tee "$out/helm-install.log"
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
