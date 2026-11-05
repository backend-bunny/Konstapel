#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/image/lib.sh
sh scripts/check-version.sh
mode=${1:-build}
[[ $mode == build || $mode == lock ]] || { echo 'Usage: build.sh [build|lock]' >&2; exit 1; }
if [[ $mode == build && ! -f apko.lock.json ]]; then
  echo 'Missing image lock; run task image:lock' >&2
  exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rm -rf out/image
mkdir -p out/image
build_package "$tmp"
fresh_lock "$tmp/fresh.lock.json"
if [[ $mode == lock ]]; then
  python3 scripts/image/lockfile.py strip "$tmp/fresh.lock.json" apko.lock.json
fi
python3 scripts/image/lockfile.py merge apko.lock.json "$tmp/fresh.lock.json" apko.yaml out/image/build.lock.json
apko build apko.yaml "$IMAGE:build" out/image/image.tar --arch x86_64 \
  --lockfile out/image/build.lock.json --keyring-append out/image/melange.rsa.pub \
  --sbom-path out/image --annotations "org.opencontainers.image.version:$(cat VERSION)"
python3 scripts/image/sources.py render out/image/sbom-x86_64.spdx.json out/image/image.tar out/image/sources.json out/image/sources.md
python3 scripts/image/notices.py render out/image/sources.json out/image/image.tar .cache/image/notices out/image/notices.json out/image/notices.md
# apko records APKs and their source relationships. Syft also finds Go modules
# embedded in both Konstapel commands.
SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
  syft scan "docker-archive:out/image/image.tar" -o spdx-json=out/image/sbom-complete.spdx.json
git rev-parse HEAD > out/image/commit
sha256sum out/image/image.tar out/image/build.lock.json packages/x86_64/*.apk > out/image/build.sha256
