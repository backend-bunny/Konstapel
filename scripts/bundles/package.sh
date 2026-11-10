#!/usr/bin/env bash
# Build and freeze a policy bundle from a clean checkout:
#   scripts/bundles/package.sh NAME OUT_DIR
# NAME selects bundles/NAME/definition.json. The source revision and time are
# taken from HEAD, so the same commit always yields the same digests. OUT_DIR
# receives an OCI image layout (the exact bytes publication will push) and
# package.json, and must not exist: frozen inputs are never replaced.
# Bundles are versioned in their definition, independently of the application
# VERSION, charts and release-please, so none of those are read here.
set -euo pipefail
cd "$(dirname "$0")/../.."
name=${1:?usage: package.sh NAME OUT_DIR}
out=${2:?usage: package.sh NAME OUT_DIR}
[[ $name =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || { echo "invalid bundle name: $name" >&2; exit 1; }
[[ -f bundles/$name/definition.json ]] || { echo "no bundle definition at bundles/$name/definition.json" >&2; exit 1; }
[[ ! -e $out ]] || { echo "$out exists; frozen bundle inputs are never replaced" >&2; exit 1; }
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo 'Bundle packaging requires a clean checkout: the package records HEAD as the source' >&2
  exit 1
fi
sha256sum --check --quiet content/SHA256SUMS
go run -mod=readonly ./cmd/bundlepack \
  -root . -name "$name" -out "$out" \
  -revision "$(git rev-parse HEAD)" -time "$(git show -s --format=%cI HEAD)"
