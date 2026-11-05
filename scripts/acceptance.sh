#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: scripts/acceptance.sh ABSOLUTE_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
if [[ -e $out ]]; then echo 'Acceptance output must be a fresh directory' >&2; exit 1; fi
mkdir -p "$out"
kubeconfig=$out/kubeconfig
created=false
cleanup() {
  code=$?
  if [[ $created == true ]]; then
    kind export logs --name konstapel-assessment "$out/kind-logs" > "$out/kind-export.log" 2>&1 || true
    scripts/environment.sh delete "$kubeconfig" "$out" > "$out/teardown.log" 2>&1 || { [[ $code != 0 ]] || code=1; }
  fi
  # Kubeconfig is operational input, not exported OSCAL evidence.
  exit "$code"
}
trap cleanup EXIT
scripts/build.sh
# Refuse an existing named cluster before setting the cleanup guard.
if kind get clusters 2>/dev/null | rg -qx konstapel-assessment; then echo 'Disposable cluster already exists; inspect and remove it explicitly first' >&2; exit 1; fi
created=true
scripts/environment.sh create "$kubeconfig" "$out/environment"
./bin/konstapel acceptance --kubeconfig "$kubeconfig" --context kind-konstapel-assessment --output "$out/package" --timeout 180s > "$out/runner.log" 2>&1
./bin/konstapel validate --output "$out/package"
# Upstream Chainsaw fixtures remain unmodified in content. Apply only an image
# overlay in the disposable test copy because the upstream busybox failed startup.
cp -a content/upstream/kyverno/disallow-privileged-containers "$out/chainsaw-policy"
find "$out/chainsaw-policy" -type f -name '*.yaml' -exec sed -i 's|ghcr.io/kyverno/test-busybox:1.35|docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec|g' {} +
KUBECONFIG="$kubeconfig" chainsaw test --kube-context kind-konstapel-assessment --exec-timeout 180s --apply-timeout 30s --assert-timeout 120s --cleanup-timeout 60s --test-dir "$out/chainsaw-policy/.chainsaw-test" > "$out/chainsaw.log" 2>&1
# Re-run schema and reference validation from the saved evidence, without cluster access.
./bin/konstapel convert --capture "$out/package/capture.json" --output "$out/reconverted" > "$out/reconvert.log" 2>&1
./bin/konstapel validate --output "$out/reconverted"
printf '%s\n' 'Acceptance passed; admission, background findings, schema/reference validation and offline replay verified.' | tee "$out/result.txt"
