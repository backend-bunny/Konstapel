#!/usr/bin/env bash
# Cluster-free chart checks run by `task check`: metadata and the
# compliance.erenius.io API contract, version alignment, the absence of chart
# dependencies, strict lint, and values-schema render fixtures from
# testdata/charts/<chart>/*.yaml (first line "# expect: ok" or
# "# expect: <error text>"). Needs no cluster, registry, or credentials.
set -euo pipefail
cd "$(dirname "$0")/../.."
sh scripts/check-version.sh >/dev/null
failures=0
fail() { echo "FAIL $*" >&2; failures=$((failures + 1)); }
for chart in konstapel-crds konstapel; do
  dir=charts/$chart
  meta=$(helm show chart "$dir")
  [[ $(awk '$1 == "name:" {print $2}' <<<"$meta") == "$chart" ]] || fail "$chart: Chart.yaml name"
  grep -qx 'apiVersion: v2' <<<"$meta" || fail "$chart: apiVersion must be v2"
  grep -q 'compliance.erenius.io/api-versions: compliance.erenius.io/v1alpha1' <<<"$meta" || fail "$chart: API contract annotation"
  # Kyverno, cert-manager and the CRD chart are installed independently.
  if grep -q '^dependencies:' <<<"$meta" || [[ -e $dir/Chart.lock || -e $dir/charts ]]; then
    fail "$chart: charts must not declare or vendor dependencies"
  fi
  # A release renders into konstapel-system with a pinned digest (packaging
  # supplies it); testdata/charts/<chart>/base.values supplies one here.
  base=()
  [[ -f testdata/charts/$chart/base.values ]] && base=(-f "testdata/charts/$chart/base.values")
  helm lint --strict "$dir" --namespace konstapel-system "${base[@]}" >/dev/null || fail "$chart: helm lint --strict"
  for values in testdata/charts/"$chart"/*.yaml; do
    expect=$(sed -n '1s/^# expect: //p' "$values")
    [[ -n $expect ]] || { fail "$values: first line must be '# expect: ...'"; continue; }
    if out=$(helm template fixture "$dir" --namespace konstapel-system "${base[@]}" -f "$values" 2>&1); then
      [[ $expect == ok ]] || fail "$values: rendered, expected an error containing '$expect'"
    else
      [[ $expect != ok ]] || { fail "$values: $out"; continue; }
      grep -qiF -- "$expect" <<<"$out" || fail "$values: error does not mention '$expect': $out"
    fi
  done
done
if ((failures > 0)); then
  exit 1
fi
echo "charts ok"
