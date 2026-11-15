#!/usr/bin/env bash
# Verify the vendored Prometheus Operator CRDs (testdata/charts/prometheus-operator)
# that chart tests validate rendered ServiceMonitor and PrometheusRule objects
# against. Default: check the files against the pin in scripts/runtime.env.
# With --refresh: download the CRDs of KONSTAPEL_PROMETHEUS_OPERATOR_VERSION from
# the upstream release tag, replace the vendored files and print the new
# checksum to put in runtime.env (Renovate bumps the version; this refreshes
# the files that go with it).
# With --bundle: download the release's bundle.yaml (cached in tools/), verify
# KONSTAPEL_PROMETHEUS_OPERATOR_BUNDLE_SHA256, substitute the digest-pinned
# operator and config-reloader images and print the path of the manifest the
# charts acceptance group applies.
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
if [[ ${1:-} == --bundle ]]; then
  for image in "$KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE" "$KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE"; do
    [[ $image == *":${KONSTAPEL_PROMETHEUS_OPERATOR_VERSION}@sha256:"* ]] || {
      echo "$image is not Operator $KONSTAPEL_PROMETHEUS_OPERATOR_VERSION by digest" >&2; exit 1; }
  done
  mkdir -p tools
  bundle="tools/prometheus-operator-bundle-${KONSTAPEL_PROMETHEUS_OPERATOR_VERSION}-${KONSTAPEL_PROMETHEUS_OPERATOR_BUNDLE_SHA256}.yaml"
  if [[ ! -f $bundle ]]; then
    download=$(mktemp tools/prometheus-operator-bundle-download.XXXXXX)
    trap 'rm -f "$download"' EXIT
    curl -fLsS --retry 3 "https://github.com/prometheus-operator/prometheus-operator/releases/download/${KONSTAPEL_PROMETHEUS_OPERATOR_VERSION}/bundle.yaml" -o "$download"
    printf '%s  %s\n' "$KONSTAPEL_PROMETHEUS_OPERATOR_BUNDLE_SHA256" "$download" | sha256sum --check --status
    mv "$download" "$bundle"
  fi
  printf '%s  %s\n' "$KONSTAPEL_PROMETHEUS_OPERATOR_BUNDLE_SHA256" "$bundle" | sha256sum --check --status
  pinned="${bundle%.yaml}-pinned.yaml"
  # Each image appears exactly once in the pinned release; anything else means
  # the bundle changed shape and the substitution must be reviewed.
  operator_tag=${KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE%@*}
  reloader_tag=${KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE%@*}
  for tag in "$operator_tag" "$reloader_tag"; do
    [[ $(grep -c -F -- "$tag" "$bundle") == 1 ]] || { echo "$tag must appear exactly once in $bundle" >&2; exit 1; }
  done
  sed -e "s|${operator_tag}\$|${KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE}|" -e "s|${reloader_tag}\$|${KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE}|" "$bundle" > "$pinned"
  grep -q -F -- "$KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE" "$pinned" && grep -q -F -- "$KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE" "$pinned" || {
    echo "image substitution failed" >&2; exit 1; }
  printf '%s\n' "$pinned"
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
