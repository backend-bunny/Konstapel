#!/usr/bin/env bash
# Verify the vendored Prometheus Operator CRDs (testdata/charts/prometheus-operator)
# that chart tests validate rendered ServiceMonitor and PrometheusRule objects
# against. Default: check the files against the pin in scripts/runtime.env.
# With --refresh: download the CRDs of KONSTAPEL_PROMETHEUS_OPERATOR_VERSION from
# the upstream release tag, replace the vendored files and print the new
# checksum to put in runtime.env (Renovate bumps the version; this refreshes
# the files that go with it).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
dir=testdata/charts/prometheus-operator
files=(monitoring.coreos.com_prometheusrules.yaml monitoring.coreos.com_servicemonitors.yaml)
digest() { (cd "$1" && cat "${files[@]}" | sha256sum | cut -d' ' -f1); }
if [[ ${1:-} == --refresh ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  for f in "${files[@]}"; do
    curl -fLsS --retry 3 "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${KONSTAPEL_PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/$f" -o "$tmp/$f"
  done
  cp "$tmp"/*.yaml "$dir/"
  echo "KONSTAPEL_PROMETHEUS_OPERATOR_CRDS_SHA256=$(digest "$dir")"
  exit 0
fi
actual=$(digest "$dir")
if [[ $actual != "$KONSTAPEL_PROMETHEUS_OPERATOR_CRDS_SHA256" ]]; then
  echo "Prometheus Operator CRDs in $dir do not match KONSTAPEL_PROMETHEUS_OPERATOR_VERSION=$KONSTAPEL_PROMETHEUS_OPERATOR_VERSION (checksum $actual); run scripts/fetch-operator-crds.sh --refresh" >&2
  exit 1
fi
for f in "${files[@]}"; do
  grep -q "operator.prometheus.io/version: ${KONSTAPEL_PROMETHEUS_OPERATOR_VERSION#v}\$" "$dir/$f" || { echo "$f is not the CRD of Operator $KONSTAPEL_PROMETHEUS_OPERATOR_VERSION" >&2; exit 1; }
done
