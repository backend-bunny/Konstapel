#!/usr/bin/env bash
# Fetch a pinned test chart and verify its archive checksum:
# scripts/fetch-chart.sh [kyverno|cert-manager] (default kyverno). Prints the
# cached archive path.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
case ${1:-kyverno} in
  kyverno)
    name=kyverno version=$KONSTAPEL_KYVERNO_CHART_VERSION sha=$KONSTAPEL_KYVERNO_CHART_SHA256
    url="https://kyverno.github.io/kyverno/kyverno-${version}.tgz" ;;
  cert-manager)
    name=cert-manager version=$KONSTAPEL_CERT_MANAGER_CHART_VERSION sha=$KONSTAPEL_CERT_MANAGER_CHART_SHA256
    url="https://charts.jetstack.io/charts/cert-manager-${version}.tgz" ;;
  *) echo "unknown chart $1" >&2; exit 1 ;;
esac
mkdir -p tools
chart="tools/${name}-${version}-${sha}.tgz"
if [[ ! -f $chart ]]; then
  download=$(mktemp "tools/${name}-download.XXXXXX")
  trap 'rm -f "$download"' EXIT
  curl -fLsS --retry 3 "$url" -o "$download"
  printf '%s  %s\n' "$sha" "$download" | sha256sum --check --status
  mv "$download" "$chart"
fi
printf '%s  %s\n' "$sha" "$chart" | sha256sum --check --status
printf '%s\n' "$chart"
