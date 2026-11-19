#!/usr/bin/env bash
# Evidence that scripts/acceptance.sh retains for every run, whatever its outcome:
#   acceptance-evidence.sh versions OUTPUT GROUP
#     Writes OUTPUT/version-matrix.json before the cluster exists: the tested
#     source revision and chart identities (source trees, or the frozen
#     archives' checksums in release acceptance), the tool versions actually on
#     PATH, the devbox.lock checksum and the pins of scripts/runtime.env.
#   acceptance-evidence.sh diagnostics KUBECONFIG CONTEXT OUTPUT
#     Before teardown, writes OUTPUT/diagnostics/: Kubernetes events, the
#     status Conditions of workloads, nodes, CRDs, APIServices and the Kyverno,
#     cert-manager, Prometheus Operator and Konstapel (full status) resources,
#     Pod container states with their image IDs, Leases, Helm releases, the
#     test-owned containers still present, and recent logs of every Pod outside
#     the kind system namespaces. It then adds what the cluster ran (server and
#     node versions, Helm charts, running image IDs, controller image) to
#     version-matrix.json.
# Best effort: a failed collection is reported in diagnostics/collect.log and
# never changes the acceptance result. Nothing here reads Secrets, Pod specs or
# container environments; CI scans what it uploads (scripts/ci/stage-evidence.py).
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env

versions() {
  local out=${1:?usage: acceptance-evidence.sh versions OUTPUT GROUP} group=${2:?group required}
  local commit dirty=false tools pins charts
  commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
  [[ -z $(git status --porcelain --untracked-files=no 2>/dev/null) ]] || dirty=true
  version_of() { "$@" 2>/dev/null | head -n 1 | tr -d '\r' || true; }
  tools=$(jq -n \
    --arg go "$(version_of go env GOVERSION)" \
    --arg kind "$(version_of kind version)" \
    --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion // empty')" \
    --arg helm "$(version_of helm version --template '{{.Version}}')" \
    --arg chainsaw "$(chainsaw version 2>/dev/null | sed -n 's/^Version: //p' | head -n 1)" \
    --arg docker "$(version_of docker version --format '{{.Server.Version}}')" \
    --arg devboxLockSha256 "$(sha256sum devbox.lock 2>/dev/null | cut -d' ' -f1)" \
    '{go:$go, kind:$kind, kubectl:$kubectl, helm:$helm, chainsaw:$chainsaw, dockerServer:$docker, devboxLockSha256:$devboxLockSha256}
     | with_entries(.value |= (if . == "" then null else . end))')
  # Every pin, exactly as scripts/runtime.env declares it.
  pins=$(grep -E '^KONSTAPEL_[A-Z0-9_]+=' scripts/runtime.env | jq -Rn '[inputs | capture("^(?<key>[^=]+)=(?<value>.*)$")] | from_entries')
  if [[ -n ${KONSTAPEL_LIVE_CHART_ARCHIVES:-} ]]; then
    charts=$(cd "$KONSTAPEL_LIVE_CHART_ARCHIVES" && sha256sum -- *.tgz 2>/dev/null | jq -Rn '{source:"frozen archives", archives:[inputs | capture("^(?<sha256>[0-9a-f]{64})  (?<file>.+)$")]}')
  else
    charts=$(for chart in konstapel-crds konstapel; do
      jq -n --arg name "$chart" --arg tree "$(git rev-parse "HEAD:charts/$chart" 2>/dev/null)" \
        --arg version "$(sed -n 's/^version: *\([^ #]*\).*/\1/p' "charts/$chart/Chart.yaml" | head -n 1)" \
        '{name:$name, version:$version, gitTree:$tree}'
    done | jq -s '{source:"checkout", charts:.}')
  fi
  jq -n --arg group "$group" --arg commit "$commit" --argjson dirty "$dirty" --argjson tools "$tools" \
    --argjson pins "$pins" --argjson charts "$charts" \
    --arg cluster "${KONSTAPEL_CLUSTER_NAME:-}" --arg controllerImage "${KONSTAPEL_ACCEPTANCE_IMAGE:-}" \
    '{group:$group, source:{commit:$commit, uncommittedChanges:$dirty}, cluster:{name:$cluster},
      charts:$charts, controllerImage:(if $controllerImage == "" then null else $controllerImage end),
      tools:$tools, pins:$pins}' > "$out/version-matrix.json"
  echo "Recorded the version matrix in $out/version-matrix.json"
}

diagnostics() {
  local kubeconfig=${1:?usage: acceptance-evidence.sh diagnostics KUBECONFIG CONTEXT OUTPUT} context=${2:?context required} out=${3:?output required}
  local dir=$out/diagnostics
  mkdir -p "$dir/logs"
  local k=(kubectl --request-timeout=20s --kubeconfig "$kubeconfig" --context "$context")
  local log=$dir/collect.log failures=0
  : > "$log"
  # Runs one collection step; a failure is logged and counted, never fatal.
  step() {
    local name=$1; shift
    if "$@" 2>>"$log"; then echo "ok: $name" >> "$log"; else echo "failed: $name" >> "$log"; failures=$((failures + 1)); fi
  }
  events() {
    "${k[@]}" get events -A -o json | jq '[.items[] | {namespace:.metadata.namespace, type, reason, message,
      object:{kind:.involvedObject.kind, namespace:.involvedObject.namespace, name:.involvedObject.name},
      source:(.reportingComponent // .source.component), count:(.count // .series.count),
      first:(.firstTimestamp // .eventTime), last:(.lastTimestamp // .series.lastObservedTime // .eventTime)}]
      | sort_by(.last // "")' > "$dir/events.json" &&
    jq -r '.[] | [.last, .type, .namespace, "\(.object.kind)/\(.object.name)", .reason, (.message // "" | gsub("\n"; " "))] | map(. // "-" | tostring) | join("\t")' \
      "$dir/events.json" > "$dir/events.txt"
  }
  pods() {
    "${k[@]}" get pods -A -o json | jq '[.items[] | {namespace:.metadata.namespace, name:.metadata.name, uid:.metadata.uid,
      node:.spec.nodeName, phase:.status.phase, reason:.status.reason, message:.status.message, deletionTimestamp:.metadata.deletionTimestamp,
      conditions:.status.conditions,
      containers:[(.status.initContainerStatuses[]?, .status.containerStatuses[]?) | {name, image, imageID, ready, restartCount, state, lastState}]}]' > "$dir/pods.json"
  }
  # Conditions of the resources acceptance exercises; Konstapel's own
  # resources keep their whole status (Conditions, summaries, pins, runs).
  conditions() {
    local resources
    resources=$("${k[@]}" api-resources --verbs=list -o name | grep -E '^(nodes|deployments\.apps|statefulsets\.apps|daemonsets\.apps|jobs\.batch|customresourcedefinitions\.apiextensions\.k8s\.io|apiservices\.apiregistration\.k8s\.io)$|\.(compliance\.erenius\.io|kyverno\.io|cert-manager\.io|monitoring\.coreos\.com)$') || return 1
    for resource in $resources; do
      "${k[@]}" get "$resource" -A -o json | jq --arg resource "$resource" '[.items[] | {resource:$resource, kind, namespace:.metadata.namespace, name:.metadata.name,
        generation:.metadata.generation, deletionTimestamp:.metadata.deletionTimestamp, observedGeneration:.status.observedGeneration}
        + (if ($resource | endswith(".compliance.erenius.io")) then {status} else {conditions:.status.conditions} end)]' \
        || echo "failed: get $resource" >> "$log"
    done | jq -s 'add // []' > "$dir/conditions.json"
  }
  leases() {
    "${k[@]}" get leases.coordination.k8s.io -A -o json | jq '[.items[] | {namespace:.metadata.namespace, name:.metadata.name,
      holder:.spec.holderIdentity, renewTime:.spec.renewTime, transitions:.spec.leaseTransitions}]' > "$dir/leases.json"
  }
  releases() {
    helm list -A -o json --kubeconfig "$kubeconfig" --kube-context "$context" > "$dir/helm-releases.json"
  }
  containers() {
    # Name, image and state only: docker inspect would expose container environments.
    docker ps -a --filter "label=konstapel.acceptance=${KONSTAPEL_CLUSTER_NAME:-}" --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}' > "$dir/test-containers.txt"
  }
  logs() {
    local namespace name restarted
    jq -r '.[] | select(.namespace | IN("kube-system","kube-public","kube-node-lease","local-path-storage") | not)
      | [.namespace, .name, ([.containers[].restartCount // 0] | add // 0)] | @tsv' "$dir/pods.json" |
    while IFS=$'\t' read -r namespace name restarted; do
      "${k[@]}" logs -n "$namespace" "$name" --all-containers --prefix --timestamps --tail=5000 > "$dir/logs/$namespace.$name.log" 2>&1 || true
      if (( restarted > 0 )); then
        "${k[@]}" logs -n "$namespace" "$name" --all-containers --prefix --timestamps --tail=5000 --previous > "$dir/logs/$namespace.$name.previous.log" 2>&1 || true
      fi
    done
  }
  cluster_versions() {
    local matrix=$out/version-matrix.json cluster
    cluster=$(jq -n --argjson server "$("${k[@]}" version -o json | jq '.serverVersion | {gitVersion, platform}')" \
      --argjson nodes "$("${k[@]}" get nodes -o json | jq '[.items[] | {name:.metadata.name} + (.status.nodeInfo | {kubeletVersion, containerRuntimeVersion, osImage, kernelVersion, architecture})]')" \
      --argjson releases "$(jq '[.[] | {namespace, name, chart, app_version, revision, status}]' "$dir/helm-releases.json" 2>/dev/null || echo null)" \
      --argjson images "$(jq '[.[].containers[] | {image, imageID}] | unique' "$dir/pods.json" 2>/dev/null || echo null)" \
      --arg controllerImage "$(cat "$out/image-ref.txt" 2>/dev/null)" \
      '{kubernetes:$server, nodes:$nodes, helmReleases:$releases, runningImages:$images,
        controllerImage:(if $controllerImage == "" then null else $controllerImage end)}')
    if [[ -s $matrix ]]; then
      jq --argjson cluster "$cluster" '.cluster += ($cluster | del(.controllerImage)) | .controllerImage = (.controllerImage // $cluster.controllerImage)' "$matrix" > "$matrix.tmp" && mv "$matrix.tmp" "$matrix"
    else
      jq -n --argjson cluster "$cluster" '{cluster:($cluster | del(.controllerImage)), controllerImage:$cluster.controllerImage}' > "$matrix"
    fi
  }
  if [[ ! -s $kubeconfig ]]; then
    echo "no kubeconfig at $kubeconfig: the cluster was not created; nothing to collect" | tee -a "$log"
    return 0
  fi
  step events events
  step pods pods
  step conditions conditions
  step leases leases
  step helm-releases releases
  step test-containers containers
  step logs logs
  step cluster-versions cluster_versions
  echo "Collected cluster diagnostics in $dir ($failures failed step(s); see collect.log)"
}

command=${1:?usage: acceptance-evidence.sh versions|diagnostics ...}
shift
case "$command" in
versions) versions "$@" ;;
diagnostics) diagnostics "$@" ;;
*) echo "unknown evidence operation: $command" >&2; exit 1 ;;
esac
