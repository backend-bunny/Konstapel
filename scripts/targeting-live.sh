#!/usr/bin/env bash
# Live targeting delivery acceptance against an existing disposable cluster
# with Kyverno installed (task 3.4 of add-compliance-targeting-api).
# scripts/acceptance.sh calls this on the cluster it owns.
set -euo pipefail
cd "$(dirname "$0")/.."
kubeconfig=${1:?usage: targeting-live.sh KUBECONFIG CONTEXT OUTPUT}
context=${2:?explicit context required}
out=${3:?output directory required}
mkdir -p "$out"
KONSTAPEL_LIVE_KUBECONFIG=$kubeconfig KONSTAPEL_LIVE_CONTEXT=$context KONSTAPEL_LIVE_OUTPUT=$out \
  go test -mod=readonly -tags live -count=1 -timeout 25m -run '^TestLiveDelivery$' -v ./internal/targeting/ \
  > "$out/targeting-live.log" 2>&1 || { tail -40 "$out/targeting-live.log" >&2; exit 1; }
