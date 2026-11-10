#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env

for image in "$KONSTAPEL_NODE_IMAGE" "$KONSTAPEL_WORKLOAD_IMAGE" "$KONSTAPEL_S3_IMAGE" "$KONSTAPEL_REGISTRY_IMAGE" "$KONSTAPEL_REGISTRY_API_IMAGE"; do
  if [[ ! $image =~ ^[^[:space:]@]+:[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]]; then
    echo "Runtime image must include a tag and complete SHA-256 digest: $image" >&2
    exit 1
  fi
done

# Fail when an update drifts the development toolchain away from go.mod.
expected_go=$(jq -r '.packages[] | select(startswith("go@")) | ltrimstr("go@")' devbox.json)
module_go=$(go mod edit -json | jq -r '.Go')
actual_go=$(go env GOVERSION)
if [[ $expected_go != "$module_go" || $actual_go != "go$expected_go" ]]; then
  echo "Go versions differ: Devbox=$expected_go go.mod=$module_go running=$actual_go" >&2
  exit 1
fi
jq -e --slurpfile config devbox.json '
  . as $lock | all($config[0].packages[];
    . as $pkg | ($lock.packages[$pkg].version == ($pkg | split("@") | last))
      and ($lock.packages[$pkg].resolved | type == "string"))
' devbox.lock >/dev/null

# The chart supplies the engine version; the CLI must evaluate that same version.
chart=$(scripts/fetch-chart.sh)
expected_kyverno=$(jq -r '.packages[] | select(startswith("kyverno@")) | ltrimstr("kyverno@")' devbox.json)
chart_kyverno=$(helm show chart "$chart" | sed -n 's/^appVersion: *//p')
chart_kyverno=${chart_kyverno//\"/}
chart_kyverno=${chart_kyverno//\'/}
if [[ ${chart_kyverno#v} != "$expected_kyverno" ]]; then
  echo "Kyverno versions differ: Devbox CLI=$expected_kyverno chart=$chart_kyverno" >&2
  exit 1
fi
# The cert-manager pin must resolve to the checksummed archive.
scripts/fetch-chart.sh cert-manager >/dev/null
printf 'Dependency pins agree: Go %s, Kyverno %s, chart %s\n' "$expected_go" "$expected_kyverno" "$KONSTAPEL_KYVERNO_CHART_VERSION"
