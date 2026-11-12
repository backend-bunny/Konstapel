#!/usr/bin/env bash
# Run the bundle retrieval compatibility suite against disposable, test-owned
# instances of two pinned OCI registries (runtime.env): KONSTAPEL_REGISTRY_IMAGE
# (no referrers API: exercises the tag-schema fallback), one anonymous and one
# htpasswd-authenticated instance, and KONSTAPEL_REGISTRY_API_IMAGE (serves the
# OCI 1.1 referrers API) anonymous and, as a write-authenticated publisher
# target with anonymous reads, htpasswd-protected, all over TLS with a
# throwaway CA. Besides retrieval it runs the write-once publication cases of
# internal/bundle/publish (happy path, idempotent rerun, conflict, proof
# completion, recovery through a fault-injecting proxy, anonymous read-back
# failure), and release signing and verification: the pinned Cosign CLI in
# key mode (offline, test key) signs and attests the published digest for only
# the missing proof kinds, and bundlerelease's verify-release check accepts it
# anonymously under a test publisher rule. With KONSTAPEL_NETWORK_INTEROP=1 it
# also reads the official keyless release anonymously from ghcr.io (never
# writes there), mirrors it into the private registries and verifies the
# mirror under bundles/official-sources.yaml; without it those cases are
# recorded as skipped and the suite needs no access beyond the image pulls.
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
for image in "$KONSTAPEL_REGISTRY_IMAGE" "$KONSTAPEL_REGISTRY_API_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
done
{ docker image inspect "$KONSTAPEL_REGISTRY_IMAGE" --format '{{json .RepoDigests}}'
  docker image inspect "$KONSTAPEL_REGISTRY_API_IMAGE" --format '{{json .RepoDigests}}'; } > "$out/registry-images.json"
KONSTAPEL_REGISTRY_IMAGE=$KONSTAPEL_REGISTRY_IMAGE KONSTAPEL_REGISTRY_API_IMAGE=$KONSTAPEL_REGISTRY_API_IMAGE KONSTAPEL_REGISTRY_RUN=$run KONSTAPEL_REGISTRY_OUTPUT=$out \
  go test -mod=readonly -tags registrycompat -count=1 -run '^TestRegistryCompat' -v ./internal/bundle/registry/ > "$out/registry-compat.log" 2>&1 \
  || { tail -60 "$out/registry-compat.log" >&2; exit 1; }
cleanup
if [[ -n $(docker ps -aq --filter "label=konstapel.test=$run") ]]; then
  echo "registry containers for $run were not removed" >&2
  exit 1
fi
echo "Registry compatibility suite passed against $KONSTAPEL_REGISTRY_IMAGE and $KONSTAPEL_REGISTRY_API_IMAGE; results in $out/registry-compat.json; all test containers removed"
