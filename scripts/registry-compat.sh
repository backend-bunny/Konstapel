#!/usr/bin/env bash
# Run the bundle retrieval compatibility suite against disposable, test-owned
# instances of the pinned OCI registry (KONSTAPEL_REGISTRY_IMAGE in runtime.env):
# one anonymous and one htpasswd-authenticated, both over TLS with a throwaway CA.
# Usage: scripts/registry-compat.sh OUTPUT_DIR
# The Go test creates the CA, certificates, random credentials and containers
# (loopback ports only) and removes them itself; this script additionally removes
# anything still carrying its run label, then fails if a container remains.
# OUTPUT_DIR must not exist. Results go to OUTPUT_DIR/registry-compat.json.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: registry-compat.sh OUTPUT_DIR}
[[ ! -e $out ]] || { echo "$out exists; evidence is never overwritten" >&2; exit 1; }
mkdir -p "$out"
run=konstapel-registry-compat-$RANDOM$RANDOM
cleanup() { docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker image inspect "$KONSTAPEL_REGISTRY_IMAGE" >/dev/null 2>&1 || docker pull -q "$KONSTAPEL_REGISTRY_IMAGE" >/dev/null
docker image inspect "$KONSTAPEL_REGISTRY_IMAGE" --format '{{json .RepoDigests}}' > "$out/registry-image.json"
KONSTAPEL_REGISTRY_IMAGE=$KONSTAPEL_REGISTRY_IMAGE KONSTAPEL_REGISTRY_RUN=$run KONSTAPEL_REGISTRY_OUTPUT=$out \
  go test -mod=readonly -tags registrycompat -count=1 -run '^TestRegistryCompat' -v ./internal/bundle/registry/ > "$out/registry-compat.log" 2>&1 \
  || { tail -60 "$out/registry-compat.log" >&2; exit 1; }
cleanup
if [[ -n $(docker ps -aq --filter "label=konstapel.test=$run") ]]; then
  echo "registry containers for $run were not removed" >&2
  exit 1
fi
echo "Registry compatibility suite passed against $KONSTAPEL_REGISTRY_IMAGE; results in $out/registry-compat.json; all test containers removed"
