#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: scripts/acceptance.sh ABSOLUTE_OUTPUT_DIRECTORY [GROUP]}
group=${2:-all}
if [[ $group != all ]]; then
  jq -e --arg group "$group" 'has($group)' scripts/acceptance-groups.json >/dev/null || {
    echo "Unknown acceptance group: $group" >&2; exit 1;
  }
fi
includes() {
  [[ $group == all ]] || jq -e --arg group "$group" --arg stage "$1" '.[$group][$stage] == true' scripts/acceptance-groups.json >/dev/null
}
# KONSTAPEL_ACCEPTANCE_TIMEOUT (sleep(1) duration, e.g. 100m) bounds the run
# so diagnostics and teardown still fit inside an outer CI job timeout.
deadline=${KONSTAPEL_ACCEPTANCE_TIMEOUT:-}
[[ -z $deadline || $deadline =~ ^[1-9][0-9]*[smh]?$ ]] || { echo 'KONSTAPEL_ACCEPTANCE_TIMEOUT must be a duration such as 100m' >&2; exit 1; }
out=$(realpath -m "$out")
if [[ -e $out ]]; then echo 'Acceptance output must be a fresh directory' >&2; exit 1; fi
mkdir -p "$out"
kubeconfig=$out/kubeconfig
export KONSTAPEL_CLUSTER_NAME=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment-${RANDOM}-${RANDOM}}
# A group may ask for worker nodes (multi-node availability cases).
if [[ $group != all ]]; then
  export KONSTAPEL_CLUSTER_WORKERS=$(jq -r --arg group "$group" '.[$group].workers // 0' scripts/acceptance-groups.json)
fi
context=kind-$KONSTAPEL_CLUSTER_NAME
jq -n --arg name "$KONSTAPEL_CLUSTER_NAME" --arg context "$context" '{name:$name,context:$context}' > "$out/target.json"
created=false
interrupted=
watchdog=
stage() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$out/progress.log"
}
cleanup() {
  code=$?
  trap - EXIT
  # Diagnostics and teardown run to completion even when CI cancels again
  # (INT, then TERM); only SIGKILL stops them. Bounded steps use timeout -k.
  trap '' INT TERM USR1
  [[ -z $watchdog ]] || kill "$watchdog" 2>/dev/null || true
  # The stopped stage may fail before the watchdog's signal arrives.
  if [[ -e $out/deadline-exceeded.txt ]]; then interrupted=timed-out; code=124; fi
  if [[ $created == true ]]; then
    stage 'Collecting cluster diagnostics and tearing down the disposable environment' || true
    # Events, Conditions, Pod states/logs and running images before teardown.
    timeout -k 10s 5m scripts/acceptance-evidence.sh diagnostics "$kubeconfig" "$context" "$out" 2>&1 | tee "$out/diagnostics.log" ||
      echo 'Cluster diagnostics incomplete; see diagnostics.log' | tee -a "$out/progress.log"
    kind export logs --name "$KONSTAPEL_CLUSTER_NAME" "$out/kind-logs" 2>&1 | tee "$out/kind-export.log" || true
    scripts/environment.sh delete "$kubeconfig" "$out/environment" 2>&1 | tee "$out/teardown.log" || { [[ $code != 0 ]] || code=1; }
    # Prove the teardown: the cluster and every container a live test
    # labelled for it (liveContainerLabel) are gone. A leftover fails the run
    # and is then removed.
    clean=true
    if kind get clusters 2>/dev/null | rg -Fxq "$KONSTAPEL_CLUSTER_NAME"; then
      echo "leftover kind cluster: $KONSTAPEL_CLUSTER_NAME" | tee -a "$out/teardown.log"; clean=false
    fi
    if ! leftover=$(docker ps -aq --filter "label=konstapel.acceptance=$KONSTAPEL_CLUSTER_NAME"); then
      echo 'cannot list test-owned containers' | tee -a "$out/teardown.log"; clean=false; leftover=
    fi
    if [[ -n $leftover ]]; then
      echo "leftover test-owned containers: $(echo $leftover)" | tee -a "$out/teardown.log"; clean=false
      docker rm -f $leftover >/dev/null 2>&1 || true
    fi
    if [[ $clean == true ]]; then
      echo "teardown verified: no cluster $KONSTAPEL_CLUSTER_NAME and no container labelled for it" | tee -a "$out/teardown.log"
    elif [[ $code == 0 ]]; then
      code=1
    fi
  fi
  if [[ $code == 0 ]]; then outcome=passed; elif [[ -n $interrupted ]]; then outcome=$interrupted; else outcome=failed; fi
  jq -n --arg group "$group" --argjson exitCode "$code" --arg outcome "$outcome" '{group:$group,passed:($exitCode==0),exitCode:$exitCode,outcome:$outcome}' > "$out/acceptance-result.json"
  if [[ $code == 0 ]]; then
    printf 'Acceptance passed (group: %s); all selected checks and teardown succeeded.\n' "$group" | tee "$out/result.txt"
  else
    printf 'Acceptance failed (exit %s, %s); diagnostics: %s\n' "$code" "$outcome" "$out" | tee "$out/result.txt"
  fi
  # Kubeconfig is operational input, not exported OSCAL evidence.
  exit "$code"
}
trap cleanup EXIT
trap 'interrupted=interrupted; exit 130' INT
trap 'interrupted=interrupted; exit 143' TERM
trap 'interrupted=timed-out; exit 124' USR1
stage "Acceptance group: $group; logs and evidence: $out"
if [[ -n $deadline ]]; then
  # On expiry, stop every process this run started (the shell waits for its
  # foreground stage before handling a signal), then let cleanup collect
  # diagnostics and tear down.
  main=$$
  (
    trap 'kill "$sleeper" 2>/dev/null; exit 0' TERM
    sleep "$deadline" & sleeper=$!
    wait "$sleeper" || exit 0
    echo "Acceptance exceeded KONSTAPEL_ACCEPTANCE_TIMEOUT=$deadline; stopping it to collect diagnostics and tear down" |
      tee "$out/deadline-exceeded.txt" | tee -a "$out/progress.log" >&2
    self=$BASHPID
    stopping=$(ps -e -o pid=,ppid= | awk -v root="$main" -v self="$self" '
      { parent[$1] = $2 } END {
        do { added = 0; for (p in parent) if (!(p in seen) && p != self && (parent[p] == root || parent[p] in seen)) { seen[p] = 1; added = 1 } } while (added)
        for (p in seen) print p }')
    [[ -z $stopping ]] || kill -TERM $stopping 2>/dev/null
    kill -USR1 "$main"
  ) &
  watchdog=$!
fi
# load_image ARCHIVE REPOSITORY LOG loads ARCHIVE (tag REPOSITORY:build-amd64)
# into every disposable node and sets loaded=REPOSITORY@<manifest digest>.
# The node records a digest only for kind's import alias; the image is named
# by that digest under its real repository so a chart's repository@digest
# reference resolves locally (pullPolicy Never).
load_image() {
  local archive=$1 repository=$2 log=$3 node="$KONSTAPEL_CLUSTER_NAME-control-plane" imported= attempt each
  kind load image-archive "$archive" --name "$KONSTAPEL_CLUSTER_NAME" 2>&1 | tee "$log"
  # containerd can register an archive import a moment after kind returns:
  # wait for it, and load once more if it never appears.
  for attempt in $(seq 1 30); do
    if imported=$(docker exec "$node" crictl inspecti -o json "$repository:build-amd64" 2>/dev/null | jq -er '.status.repoDigests[0]'); then
      break
    fi
    if (( attempt == 15 )); then
      kind load image-archive "$archive" --name "$KONSTAPEL_CLUSTER_NAME" 2>&1 | tee -a "$log"
    fi
    sleep 2
  done
  [[ -n $imported ]] || { echo "the loaded image $repository never appeared on $node" | tee -a "$log"; exit 1; }
  loaded=$repository@${imported##*@}
  for each in $(kind get nodes --name "$KONSTAPEL_CLUSTER_NAME"); do
    docker exec "$each" ctr -n k8s.io images tag "$repository:build-amd64" "$loaded" 2>&1 | tee -a "$log"
  done
}
# The version matrix exists even when the cluster never comes up.
scripts/acceptance-evidence.sh versions "$out" "$group" 2>&1 | tee "$out/versions.log" ||
  stage 'Recording the version matrix failed; see versions.log'
if includes core; then
  stage 'Building acceptance binaries'
  scripts/build.sh 2>&1 | tee "$out/build.log"
fi
# Refuse an existing named cluster before setting the cleanup guard.
if kind get clusters 2>/dev/null | rg -Fxq "$KONSTAPEL_CLUSTER_NAME"; then echo 'Disposable cluster already exists; inspect and remove it explicitly first' >&2; exit 1; fi
created=true
stage 'Creating the disposable kind cluster and installing Kyverno'
scripts/environment.sh create "$kubeconfig" "$out/environment" 2>&1 | tee "$out/environment.log"
if includes core; then
  stage 'Preparing the disposable kind node for user-namespaced Pods'
  # kind masks parts of /sys. An additional unmasked sysfs mount lets the
  # kernel permit sysfs mounts in child user namespaces (kind issue #3436).
  # Only the node we just created is changed; cluster teardown removes it.
  docker exec "$KONSTAPEL_CLUSTER_NAME-control-plane" sh -ec '
    mkdir -p /run/konstapel-userns-sys
    mount -t sysfs sysfs /run/konstapel-userns-sys
    echo "Prepared unmasked sysfs for user-namespaced Pods"
  ' 2>&1 | tee "$out/userns-setup.log"
  export KONSTAPEL_LIVE_REQUIRE_USERNS=true
  stage 'Testing admission and background findings, then validating the evidence package'
  ./bin/konstapel acceptance --kubeconfig "$kubeconfig" --context "$context" --output "$out/package" --timeout 180s 2>&1 | tee "$out/runner.log"
  ./bin/konstapel validate --output "$out/package" 2>&1 | tee "$out/validate.log"
  # Upstream Chainsaw fixtures remain unmodified in content. Apply only an image
  # overlay in the disposable test copy because the upstream busybox failed startup.
  cp -a content/upstream/kyverno/disallow-privileged-containers "$out/chainsaw-policy"
  find "$out/chainsaw-policy" -type f -name '*.yaml' -exec sed -i "s|ghcr.io/kyverno/test-busybox:1.35|$KONSTAPEL_WORKLOAD_IMAGE|g" {} +
  stage 'Running the upstream Chainsaw admission fixtures'
  KUBECONFIG="$kubeconfig" chainsaw test --kube-context "$context" --exec-timeout 180s --apply-timeout 30s --assert-timeout 120s --cleanup-timeout 60s --test-dir "$out/chainsaw-policy/.chainsaw-test" 2>&1 | tee "$out/chainsaw.log"
  # Re-run schema and reference validation from the saved evidence, without cluster access.
  stage 'Replaying saved evidence and validating schema/reference closure'
  ./bin/konstapel convert --capture "$out/package/capture.json" --output "$out/reconverted" 2>&1 | tee "$out/reconvert.log"
  ./bin/konstapel validate --output "$out/reconverted" 2>&1 | tee "$out/revalidate.log"
fi
if includes certManager; then
  # The runtime chart's default TLS mode needs cert-manager, installed
  # separately as an operator would; the chart never installs it.
  stage 'Installing the pinned cert-manager'
  helm upgrade --install cert-manager "$(scripts/fetch-chart.sh cert-manager)" --kubeconfig "$kubeconfig" --kube-context "$context" \
    -n cert-manager --create-namespace --set crds.enabled=true --wait --timeout 10m 2>&1 | tee "$out/cert-manager-install.log"
  export KONSTAPEL_LIVE_CERT_MANAGER=true
fi
if includes prometheusOperator; then
  # A real Prometheus Operator for the monitoring acceptance, installed from
  # its pinned release bundle as a platform team would. It is not a chart
  # dependency; the disposable cluster's deletion removes it, and the test
  # deletes the Prometheus it creates.
  stage 'Installing the pinned Prometheus Operator'
  kubectl --kubeconfig "$kubeconfig" --context "$context" apply --server-side --force-conflicts \
    -f "$(scripts/fetch-operator-crds.sh --bundle)" 2>&1 | tee "$out/prometheus-operator-install.log"
  kubectl --kubeconfig "$kubeconfig" --context "$context" -n default rollout status deployment/prometheus-operator --timeout 5m \
    2>&1 | tee -a "$out/prometheus-operator-install.log"
  export KONSTAPEL_LIVE_PROMETHEUS_OPERATOR=true
fi
if includes image && [[ -n ${KONSTAPEL_ACCEPTANCE_IMAGE:-} ]]; then
  # Release acceptance: the node pulls the published image by its registry
  # digest, so the cluster runs exactly the bytes that will be released.
  [[ $KONSTAPEL_ACCEPTANCE_IMAGE =~ ^ghcr\.io/backend-bunny/konstapel@sha256:[0-9a-f]{64}$ ]] || {
    echo "KONSTAPEL_ACCEPTANCE_IMAGE must be ghcr.io/backend-bunny/konstapel@sha256:<digest>" >&2; exit 1; }
  stage 'Pulling the published controller image by digest into the disposable cluster'
  for node in $(kind get nodes --name "$KONSTAPEL_CLUSTER_NAME"); do
    docker exec "$node" crictl pull "$KONSTAPEL_ACCEPTANCE_IMAGE" 2>&1 | tee -a "$out/image-load.log"
  done
  export KONSTAPEL_LIVE_IMAGE=$KONSTAPEL_ACCEPTANCE_IMAGE
  echo "$KONSTAPEL_LIVE_IMAGE" | tee "$out/image-ref.txt"
elif includes image; then
  # The Helm-installed controller runs the image built from this checkout,
  # loaded into the disposable node and referenced by its digest.
  stage 'Building the controller image and loading it into the disposable cluster'
  scripts/image/build.sh 2>&1 | tee "$out/image-build.log"
  load_image out/image/image.tar ghcr.io/backend-bunny/konstapel "$out/image-load.log"
  KONSTAPEL_LIVE_IMAGE=$loaded
  export KONSTAPEL_LIVE_IMAGE
  echo "$KONSTAPEL_LIVE_IMAGE" | tee "$out/image-ref.txt"
fi
if includes referenceProviderImage; then
  # The example reporting provider's reference chart runs its image built
  # from this checkout (test/demo only, never published), by digest.
  stage 'Building the example reporting provider image and loading it into the disposable cluster'
  scripts/examples/reference-provider-image.sh "$out/reference-provider-image" 2>&1 | tee "$out/reference-provider-image.log"
  load_image "$out/reference-provider-image/image.tar" localhost/konstapel-example-reporting "$out/reference-provider-image-load.log"
  export KONSTAPEL_LIVE_REFERENCE_PROVIDER_IMAGE=$loaded
  echo "$KONSTAPEL_LIVE_REFERENCE_PROVIDER_IMAGE" | tee "$out/reference-provider-image-ref.txt"
fi
# Targeting delivery: Audit/Deny bindings, relabelling, ready-gated replacement,
# withdrawal, and non-adoption of a prototype-style unmanaged policy.
stage 'Running live targeting, controller, storage and hardening tests (expiry/recovery cases take several minutes)'
scripts/targeting-live.sh "$kubeconfig" "$context" "$out/targeting" "$group"
# Exception acceptance admission: authenticated attribution, eligibility and
# lifetime limits against the real API server.
if includes exceptionAdmission; then
  stage 'Testing authenticated exception admission'
  scripts/exception-admission-live.sh "$KONSTAPEL_CLUSTER_NAME" "$out/exceptions"
fi
