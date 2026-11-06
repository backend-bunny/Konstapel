#!/usr/bin/env bash
# Live ComplianceException admission check (add-self-service-policy-exceptions
# task 2.2) against an existing disposable cluster from scripts/environment.sh.
#
# The webhook is served by an in-process manager inside the test. The test
# binary runs in a container on the kind network, so the API server reaches
# it without host firewall exceptions.
#
# Usage: scripts/exception-admission-live.sh CLUSTER_NAME OUTPUT
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
name=${1:?usage: exception-admission-live.sh CLUSTER_NAME OUTPUT}
out=$(realpath -m "${2:?output directory required}")
[[ "$name" =~ ^konstapel-assessment(-[a-z0-9-]+)?$ ]] || { echo 'Invalid disposable cluster name' >&2; exit 1; }
mkdir -p "$out/live"
kind get kubeconfig --internal --name "$name" > "$out/kubeconfig-internal"
CGO_ENABLED=0 go test -mod=readonly -tags live -c -o "$out/controller.test" ./internal/controller/
status=0
docker run --rm --network kind --user "$(id -u):$(id -g)" \
  -v "$PWD:/src:ro" -v "$out:/out" -w /src/internal/controller \
  -e KONSTAPEL_LIVE_KUBECONFIG=/out/kubeconfig-internal -e KONSTAPEL_LIVE_CONTEXT="kind-$name" -e KONSTAPEL_LIVE_OUTPUT=/out/live \
  -e HOME=/tmp "$KONSTAPEL_WORKLOAD_IMAGE" \
  sh -c 'KONSTAPEL_LIVE_WEBHOOK_HOST=$(hostname -i) exec /out/controller.test -test.run "^TestLiveExceptionAdmission$" -test.v -test.count=1 -test.timeout 15m' \
  > "$out/exception-admission-live.log" 2>&1 || status=$?
rm -f "$out/kubeconfig-internal" "$out/controller.test"
if [[ $status != 0 ]]; then tail -40 "$out/exception-admission-live.log" >&2; fi
exit "$status"
