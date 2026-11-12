#!/usr/bin/env bash
# Live targeting acceptance against an existing disposable cluster with Kyverno
# installed. Tests share cluster-scoped resources and run sequentially.
# scripts/acceptance.sh calls this on the cluster it owns.
set -euo pipefail
cd "$(dirname "$0")/.."
kubeconfig=${1:?usage: targeting-live.sh KUBECONFIG CONTEXT OUTPUT}
context=${2:?explicit context required}
out=${3:?output directory required}
group=${4:-all}
# Shared by local full runs and isolated CI groups. Unknown/empty groups fail
# before go test, which otherwise reports success when no tests match.
tests=$(jq -er --arg group "$group" '
  (if $group == "all" then [.[].goTests[]] else .[$group].goTests end)
  | select(length > 0) | "^(" + join("|") + ")$"
' scripts/acceptance-groups.json)
mkdir -p "$out"
# The evidence download test runs the pinned test-owned S3 service; the Helm
# bundle test runs the pinned registry.
source scripts/runtime.env
KONSTAPEL_S3_IMAGE=$KONSTAPEL_S3_IMAGE KONSTAPEL_REGISTRY_IMAGE=$KONSTAPEL_REGISTRY_IMAGE KONSTAPEL_WORKLOAD_IMAGE=$KONSTAPEL_WORKLOAD_IMAGE KONSTAPEL_LIVE_KUBECONFIG=$kubeconfig KONSTAPEL_LIVE_CONTEXT=$context KONSTAPEL_LIVE_OUTPUT=$out \
  go test -mod=readonly -tags live -count=1 -p 1 -timeout 40m -run "$tests" -v ./internal/targeting/ ./internal/controller/ \
  2>&1 | tee "$out/targeting-live.log"
