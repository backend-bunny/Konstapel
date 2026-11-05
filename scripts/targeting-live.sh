#!/usr/bin/env bash
# Live targeting acceptance against an existing disposable cluster with Kyverno
# installed: delivery (task 3.4) and the in-process manager (tasks 4.1/4.2) of
# add-compliance-targeting-api. The two tests use separate resources and run
# one after the other.
# scripts/acceptance.sh calls this on the cluster it owns.
set -euo pipefail
cd "$(dirname "$0")/.."
kubeconfig=${1:?usage: targeting-live.sh KUBECONFIG CONTEXT OUTPUT}
context=${2:?explicit context required}
out=${3:?output directory required}
mkdir -p "$out"
KONSTAPEL_LIVE_KUBECONFIG=$kubeconfig KONSTAPEL_LIVE_CONTEXT=$context KONSTAPEL_LIVE_OUTPUT=$out \
  go test -mod=readonly -tags live -count=1 -p 1 -timeout 25m -run '^(TestLiveDelivery|TestLiveManager)$' -v ./internal/targeting/ ./internal/controller/ \
  > "$out/targeting-live.log" 2>&1 || { tail -40 "$out/targeting-live.log" >&2; exit 1; }
