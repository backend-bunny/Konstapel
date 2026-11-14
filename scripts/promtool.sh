#!/usr/bin/env bash
# Run the pinned promtool (KONSTAPEL_PROMTOOL_IMAGE) on files of this
# repository, mounted read-only at /work with no network.
# Usage: scripts/promtool.sh test rules testdata/observability/queries.test.yml
# Devbox's prometheus package only ships promtool in a separate output, so the
# tool is pinned by image digest instead. Without a Docker daemon the run is
# skipped with a notice, except in CI (CI=true), where it is required.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
if ! docker info >/dev/null 2>&1; then
  if [[ ${CI:-} == true ]]; then
    echo "promtool: a Docker daemon is required in CI" >&2
    exit 1
  fi
  echo "promtool: skipped (no Docker daemon): $*" >&2
  exit 0
fi
exec docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" -w /work \
  --entrypoint /bin/promtool "$KONSTAPEL_PROMTOOL_IMAGE" "$@"
