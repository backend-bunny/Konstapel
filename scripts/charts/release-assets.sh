#!/usr/bin/env bash
# Attach the chart release record to the GitHub Release, write-once:
#   scripts/charts/release-assets.sh TAG charts-release.json
# A retry that produced the same record is a no-op; a different record for
# the same release is an error.
set -euo pipefail
tag=${1:?usage: release-assets.sh TAG FILE}
file=${2:?usage: release-assets.sh TAG FILE}
name=charts-release.json
[[ $(basename "$file") == "$name" ]] || { echo "expected a file named $name" >&2; exit 1; }
if gh release view "$tag" --json assets --jq '.assets[].name' | grep -Fxq "$name"; then
  existing=$(mktemp -d)
  gh release download "$tag" --pattern "$name" --dir "$existing"
  # Only the publication state may differ between runs (pushed vs existing).
  if ! diff <(jq -S 'del(.charts[].state)' "$existing/$name") <(jq -S 'del(.charts[].state)' "$file") >/dev/null; then
    echo "$tag already records different chart subjects in $name" >&2
    exit 1
  fi
  echo "$name already attached to $tag"
  exit 0
fi
gh release upload "$tag" "$file"
