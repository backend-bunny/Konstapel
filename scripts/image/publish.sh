#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/image/lib.sh
sh scripts/check-version.sh "${RELEASE_TAG:-}"
test "$(cat out/image/commit)" = "$(git rev-parse HEAD)"
sha256sum --check --status out/image/build.sha256
cmp out/image/build.sha256 out/image/tested.sha256
for artifact in sources.json notices.json sbom-x86_64.spdx.json sbom-complete.spdx.json; do
  test -s "out/image/$artifact"
done
ref="$IMAGE:sha-$(git rev-parse HEAD)"
refs=("$ref")
if [[ -n ${RELEASE_TAG:-} ]]; then
  test "$(git rev-parse "$RELEASE_TAG^{commit}")" = "$(git rev-parse HEAD)"
  refs+=("$IMAGE:${RELEASE_TAG#v}")
fi
if [[ ${1:-} == --dry-run ]]; then
  printf 'Would publish %s\n' "${refs[@]}"
  exit 0
fi
if [[ -n $(git status --porcelain) ]]; then
  echo 'Publish requires a clean checkout of the commit that was built and tested' >&2
  exit 1
fi
apko publish apko.yaml "${refs[@]}" --arch x86_64 --lockfile out/image/build.lock.json \
  --keyring-append out/image/melange.rsa.pub --sbom=false --image-refs out/image/image-refs \
  --annotations "org.opencontainers.image.version:$(cat VERSION)"
docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' |
  jq -er '.digest | select(test("^sha256:[a-f0-9]{64}$"))' > out/image/digest
printf 'Published %s@%s\n' "$IMAGE" "$(cat out/image/digest)"
