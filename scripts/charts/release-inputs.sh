#!/usr/bin/env bash
# Frozen chart inputs for a release: scripts/charts/release-inputs.sh OUT TAG sha256:IMAGE_DIGEST
# The first run packages the charts (charts:package) and attaches both
# archives and publication.json to the GitHub Release, write-once. Every
# retry downloads those assets and verifies them against this checkout and
# the image digest instead of packaging again, so a partially published
# release resumes with its original bytes. Attached inputs that are
# incomplete are discarded only while neither chart version exists in the
# registry; otherwise the run stops with a diagnostic.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?usage: release-inputs.sh OUT TAG DIGEST}
tag=${2:?usage: release-inputs.sh OUT TAG DIGEST}
digest=${3:?usage: release-inputs.sh OUT TAG DIGEST}
version=${tag#v}
registry=${CHARTS:-oci://ghcr.io/backend-bunny/charts}
assets=(konstapel-crds-$version.tgz konstapel-$version.tgz publication.json)
attached=$(gh release view "$tag" --json assets --jq '.assets[].name')
present=0
for a in "${assets[@]}"; do
  if grep -Fxq "$a" <<<"$attached"; then present=$((present + 1)); fi
done
published() {
  for chart in konstapel-crds konstapel; do
    if helm show chart "$registry/$chart" --version "$version" >/dev/null 2>&1; then return 0; fi
  done
  return 1
}
if (( present == ${#assets[@]} )); then
  mkdir -p "$out"
  for a in "${assets[@]}"; do gh release download "$tag" --pattern "$a" --dir "$out"; done
  python3 scripts/charts/manifest.py verify --archives "$out" --manifest "$out/publication.json" --source "$(git rev-parse HEAD)" --image-digest "$digest"
  echo "Reusing the frozen chart inputs attached to $tag"
  exit 0
fi
if (( present > 0 )); then
  if published; then
    echo "$tag has incomplete frozen chart inputs but a chart version is already published; restore the original assets instead of repackaging" >&2
    exit 1
  fi
  for a in "${assets[@]}"; do
    if grep -Fxq "$a" <<<"$attached"; then gh release delete-asset "$tag" "$a" --yes; fi
  done
  echo "Discarded incomplete, unpublished chart inputs on $tag"
elif published; then
  echo "$tag has no frozen chart inputs but a chart version is already published; refusing to repackage it" >&2
  exit 1
fi
scripts/charts/package.sh "$out" "$digest"
gh release upload "$tag" "$out/konstapel-crds-$version.tgz" "$out/konstapel-$version.tgz" "$out/publication.json"
echo "Froze and attached chart inputs to $tag"
