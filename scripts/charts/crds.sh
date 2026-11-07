#!/usr/bin/env bash
# Write the CRD chart's templates from generated CRDs: scripts/charts/crds.sh
# SOURCE_DIR OUT_DIR. Each definition is copied unchanged except for reviewed
# packaging metadata: the retention policy and chart labels. No templating,
# hooks, or other resources are added. scripts/generate.sh runs this and,
# with --check, verifies the chart is current.
set -euo pipefail
src=${1:?usage: crds.sh SOURCE_DIR OUT_DIR}
out=${2:?usage: crds.sh SOURCE_DIR OUT_DIR}
mkdir -p "$out"
find "$out" -maxdepth 1 -name '*.yaml' -delete
for f in "$src"/*.yaml; do
  awk '
    BEGIN { done = 0 }
    !done && $0 == "  annotations:" {
      print
      print "    helm.sh/resource-policy: keep"
      next
    }
    !done && /^  name: / {
      print "  labels:"
      print "    app.kubernetes.io/name: konstapel-crds"
      print "    app.kubernetes.io/part-of: konstapel"
      print
      done = 1
      next
    }
    { print }
  ' "$f" > "$out/$(basename "$f")"
  grep -q '^    helm.sh/resource-policy: keep$' "$out/$(basename "$f")" || { echo "$f: no metadata.annotations to extend" >&2; exit 1; }
done
