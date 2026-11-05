#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
base=${1:-artifacts/failure-probes}
test ! -e "$base" || { echo "Output already exists: $base" >&2; exit 1; }
mkdir -p "$base"
for probe in missing admission; do
  output="$base/$probe"
  if [[ $probe == missing ]]; then
    if KONSTAPEL_TEST_MISSING_EVIDENCE=1 scripts/acceptance.sh "$output" > "$base/$probe.log" 2>&1; then
      echo 'Missing-evidence probe unexpectedly passed' >&2; exit 1
    fi
    jq -e '(.complete | not) and (.missing | any(contains("missing-resource")))' "$output/package/evidence.json"
    test -s "$output/package/capture.json"
  else
    if KONSTAPEL_TEST_EXPECT_ACTION=Audit scripts/acceptance.sh "$output" > "$base/$probe.log" 2>&1; then
      echo 'Unexpected-admission probe incorrectly passed' >&2; exit 1
    fi
    rg -q 'unexpected rejection' "$output/package/failure.json"
    jq -e 'any(.[]; .expectedDenial == false and (.error | contains("denied")))' "$output/package/admission.json"
  fi
  jq -e '.passed == false and .exitCode != 0' "$output/acceptance-result.json"
  test -s "$output/package/final-policies.json"
  test -s "$output/package/final-reports.json"
  name=$(jq -r '.name' "$output/target.json")
  if kind get clusters | rg -Fxq "$name"; then
    echo "Probe $probe left an owned cluster behind" >&2; exit 1
  fi
  echo "Failure probe $probe: expected failure, diagnostics retained, cluster removed"
done
