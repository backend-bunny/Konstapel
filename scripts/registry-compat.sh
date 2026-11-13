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
# With KONSTAPEL_SIGSTORE_STACK=1 it also starts a disposable Sigstore
# instance from the pinned KONSTAPEL_SIGSTORE_* images (Fulcio, Rekor v1 on
# Trillian and PostgreSQL, a timestamp authority, and two test OIDC issuers)
# and signs keylessly with the pinned Cosign through it; the production
# verifier checks the result under the generated test root, including an
# expired certificate, which waits for real expiry (about 12 minutes more).
# KONSTAPEL_SIGSTORE_STACK=fast skips only the expiry cases.
# Usage: scripts/registry-compat.sh OUTPUT_DIR
# The Go test creates the CAs, certificates, keys, tokens, random credentials,
# network and containers (loopback ports only) and removes them itself; this
# script additionally removes anything still carrying its run label, then fails
# if a container or network remains or a Docker volume was left behind.
# OUTPUT_DIR must not exist. Results go to OUTPUT_DIR/registry-compat.json
# (and sigstore-stack.json for the Sigstore instance).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: registry-compat.sh OUTPUT_DIR}
[[ ! -e $out ]] || { echo "$out exists; evidence is never overwritten" >&2; exit 1; }
mkdir -p "$out"
run=konstapel-registry-compat-$RANDOM$RANDOM
stack=${KONSTAPEL_SIGSTORE_STACK:-}
[[ -z $stack || $stack == 1 || $stack == fast ]] || { echo "KONSTAPEL_SIGSTORE_STACK must be 1 or fast" >&2; exit 1; }
volumes_before=$(docker volume ls -q | sort)
cleanup() {
  docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -fv >/dev/null 2>&1 || true
  docker network ls -q --filter "label=konstapel.test=$run" | xargs -r docker network rm >/dev/null 2>&1 || true
}
trap cleanup EXIT
images=("$KONSTAPEL_REGISTRY_IMAGE" "$KONSTAPEL_REGISTRY_API_IMAGE")
if [[ -n $stack ]]; then
  images+=("$KONSTAPEL_SIGSTORE_FULCIO_IMAGE" "$KONSTAPEL_SIGSTORE_REKOR_IMAGE" "$KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE"
    "$KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE" "$KONSTAPEL_SIGSTORE_DB_IMAGE" "$KONSTAPEL_SIGSTORE_TSA_IMAGE" "$KONSTAPEL_SIGSTORE_OIDC_IMAGE")
  # The Trillian schema comes from the go.sum-verified module.
  go mod download github.com/google/trillian
fi
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
done
for image in "${images[@]}"; do
  docker image inspect "$image" --format '{{json .RepoDigests}}'
done > "$out/registry-images.json"
export KONSTAPEL_SIGSTORE_FULCIO_IMAGE KONSTAPEL_SIGSTORE_REKOR_IMAGE KONSTAPEL_SIGSTORE_TRILLIAN_SERVER_IMAGE \
  KONSTAPEL_SIGSTORE_TRILLIAN_SIGNER_IMAGE KONSTAPEL_SIGSTORE_DB_IMAGE KONSTAPEL_SIGSTORE_TSA_IMAGE KONSTAPEL_SIGSTORE_OIDC_IMAGE
KONSTAPEL_SIGSTORE_STACK=$stack KONSTAPEL_REGISTRY_IMAGE=$KONSTAPEL_REGISTRY_IMAGE KONSTAPEL_REGISTRY_API_IMAGE=$KONSTAPEL_REGISTRY_API_IMAGE KONSTAPEL_REGISTRY_RUN=$run KONSTAPEL_REGISTRY_OUTPUT=$out \
  go test -mod=readonly -tags registrycompat -count=1 -timeout 45m -run '^TestRegistryCompat' -v ./internal/bundle/registry/ > "$out/registry-compat.log" 2>&1 \
  || { tail -60 "$out/registry-compat.log" >&2; exit 1; }
cleanup
leftover=$(docker ps -aq --filter "label=konstapel.test=$run"; docker network ls -q --filter "label=konstapel.test=$run")
new_volumes=$(comm -13 <(printf '%s\n' "$volumes_before") <(docker volume ls -q | sort) | sed '/^$/d')
if [[ -n $leftover || -n $new_volumes ]]; then
  echo "test resources for $run were not removed: containers/networks: ${leftover:-none}; new volumes: ${new_volumes:-none}" >&2
  exit 1
fi
echo "Registry compatibility suite passed against $KONSTAPEL_REGISTRY_IMAGE and $KONSTAPEL_REGISTRY_API_IMAGE${stack:+ and the disposable Sigstore instance ($stack)}; results in $out; all test containers, networks and volumes removed"
