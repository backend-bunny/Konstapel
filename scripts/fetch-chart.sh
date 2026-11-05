#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
mkdir -p tools
chart="tools/kyverno-${KONSTAPEL_KYVERNO_CHART_VERSION}-${KONSTAPEL_KYVERNO_CHART_SHA256}.tgz"
if [[ ! -f $chart ]]; then
  download=$(mktemp tools/kyverno-download.XXXXXX)
  trap 'rm -f "$download"' EXIT
  curl -fLsS --retry 3 "https://kyverno.github.io/kyverno/kyverno-${KONSTAPEL_KYVERNO_CHART_VERSION}.tgz" -o "$download"
  printf '%s  %s\n' "$KONSTAPEL_KYVERNO_CHART_SHA256" "$download" | sha256sum --check --status
  mv "$download" "$chart"
fi
printf '%s  %s\n' "$KONSTAPEL_KYVERNO_CHART_SHA256" "$chart" | sha256sum --check --status
printf '%s\n' "$chart"
