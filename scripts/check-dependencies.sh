#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env

sigstore_images=("$KONSTAPEL_SIGSTORE_FULCIO_IMAGE" "$KONSTAPEL_SIGSTORE_REKOR_IMAGE" "$KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE"
  "$KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE" "$KONSTAPEL_SIGSTORE_DB_IMAGE" "$KONSTAPEL_SIGSTORE_TSA_IMAGE" "$KONSTAPEL_SIGSTORE_OIDC_IMAGE")
for image in "$KONSTAPEL_NODE_IMAGE" "$KONSTAPEL_WORKLOAD_IMAGE" "$KONSTAPEL_S3_IMAGE" "$KONSTAPEL_REGISTRY_IMAGE" "$KONSTAPEL_REGISTRY_API_IMAGE" "$KONSTAPEL_PROMTOOL_IMAGE" "${sigstore_images[@]}"; do
  if [[ ! $image =~ ^[^[:space:]@]+:[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]]; then
    echo "Runtime image must include a tag and complete SHA-256 digest: $image" >&2
    exit 1
  fi
done

# The isolated Sigstore suite loads the PostgreSQL schema of the Trillian
# module go.sum pins; both Trillian images must run that same version.
trillian=$(go list -mod=readonly -m -f '{{.Version}}' github.com/google/trillian)
for image in "$KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE" "$KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE"; do
  if [[ $image != *":$trillian@sha256:"* ]]; then
    echo "Trillian image $image must match github.com/google/trillian $trillian (go.sum)" >&2
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
# The vendored Prometheus Operator CRDs must match their pin.
scripts/fetch-operator-crds.sh
# The cert-manager pin must resolve to the checksummed archive.
scripts/fetch-chart.sh cert-manager >/dev/null
printf 'Dependency pins agree: Go %s, Kyverno %s, chart %s\n' "$expected_go" "$expected_kyverno" "$KONSTAPEL_KYVERNO_CHART_VERSION"
