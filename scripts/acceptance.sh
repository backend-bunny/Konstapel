#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: scripts/acceptance.sh ABSOLUTE_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
if [[ -e $out ]]; then echo 'Acceptance output must be a fresh directory' >&2; exit 1; fi
mkdir -p "$out"
kubeconfig=$out/kubeconfig
export KONSTAPEL_CLUSTER_NAME=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment-${RANDOM}-${RANDOM}}
context=kind-$KONSTAPEL_CLUSTER_NAME
jq -n --arg name "$KONSTAPEL_CLUSTER_NAME" --arg context "$context" '{name:$name,context:$context}' > "$out/target.json"
created=false
stage() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$out/progress.log"
}
cleanup() {
  code=$?
  trap - EXIT
  if [[ $created == true ]]; then
    stage 'Collecting cluster diagnostics and tearing down the disposable environment' || true
    kind export logs --name "$KONSTAPEL_CLUSTER_NAME" "$out/kind-logs" 2>&1 | tee "$out/kind-export.log" || true
    scripts/environment.sh delete "$kubeconfig" "$out/environment" 2>&1 | tee "$out/teardown.log" || { [[ $code != 0 ]] || code=1; }
  fi
  jq -n --argjson exitCode "$code" '{passed:($exitCode==0),exitCode:$exitCode}' > "$out/acceptance-result.json"
  if [[ $code == 0 ]]; then
    printf '%s\n' 'Acceptance passed; admission, background findings, schema/reference validation, offline replay, targeting delivery and exception admission verified.' | tee "$out/result.txt"
  else
    printf 'Acceptance failed (exit %s); diagnostics: %s\n' "$code" "$out" | tee "$out/result.txt"
  fi
  # Kubeconfig is operational input, not exported OSCAL evidence.
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage "Building acceptance binaries; logs and evidence: $out"
scripts/build.sh 2>&1 | tee "$out/build.log"
# Refuse an existing named cluster before setting the cleanup guard.
if kind get clusters 2>/dev/null | rg -Fxq "$KONSTAPEL_CLUSTER_NAME"; then echo 'Disposable cluster already exists; inspect and remove it explicitly first' >&2; exit 1; fi
created=true
stage 'Creating the disposable kind cluster and installing Kyverno'
scripts/environment.sh create "$kubeconfig" "$out/environment" 2>&1 | tee "$out/environment.log"
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
# Targeting delivery: Audit/Deny bindings, relabelling, ready-gated replacement,
# withdrawal, and non-adoption of a prototype-style unmanaged policy.
stage 'Running live targeting, controller, storage and hardening tests (expiry/recovery cases take several minutes)'
scripts/targeting-live.sh "$kubeconfig" "$context" "$out/targeting"
# Exception acceptance admission: authenticated attribution, eligibility and
# lifetime limits against the real API server.
stage 'Testing authenticated exception admission'
scripts/exception-admission-live.sh "$KONSTAPEL_CLUSTER_NAME" "$out/exceptions"
