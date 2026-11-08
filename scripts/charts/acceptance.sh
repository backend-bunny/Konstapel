#!/usr/bin/env bash
# Release acceptance of frozen chart inputs:
#   scripts/charts/acceptance.sh OUTPUT ARCHIVES_DIR ghcr.io/backend-bunny/konstapel@sha256:<digest>
# Verifies the publication manifest in ARCHIVES_DIR against this checkout and
# the image digest, then runs the charts acceptance group with the cluster
# pulling that exact image and Helm installing exactly those archives. On
# success it writes OUTPUT/chart-acceptance.json, binding the passing result
# to the source commit, both archive checksums, the CRD content identity, the
# image digest and the runtime versions. The publisher refuses to publish
# without a binding that matches its frozen manifest.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?usage: acceptance.sh OUTPUT ARCHIVES_DIR IMAGE@DIGEST}
archives=$(realpath "${2:?usage: acceptance.sh OUTPUT ARCHIVES_DIR IMAGE@DIGEST}")
image=${3:?usage: acceptance.sh OUTPUT ARCHIVES_DIR IMAGE@DIGEST}
[[ $image =~ ^ghcr\.io/backend-bunny/konstapel@(sha256:[0-9a-f]{64})$ ]] || { echo "image must be ghcr.io/backend-bunny/konstapel@sha256:<digest>" >&2; exit 1; }
digest=${BASH_REMATCH[1]}
source=$(git rev-parse HEAD)
python3 scripts/charts/manifest.py verify --archives "$archives" --manifest "$archives/publication.json" --source "$source" --image-digest "$digest"
out=$(realpath -m "$out")
KONSTAPEL_ACCEPTANCE_IMAGE=$image KONSTAPEL_LIVE_CHART_ARCHIVES=$archives scripts/acceptance.sh "$out" charts
# Reached only when every selected test and the teardown passed.
source scripts/runtime.env
jq -n --arg source "$source" --arg image "$image" --slurpfile manifest "$archives/publication.json" \
  --arg kind "$(kind version | awk '{print $2}')" --arg node "$KONSTAPEL_NODE_IMAGE" --arg kyverno "$KONSTAPEL_KYVERNO_CHART_VERSION" \
  --arg certManager "$KONSTAPEL_CERT_MANAGER_CHART_VERSION" --arg s3 "$KONSTAPEL_S3_IMAGE" \
  --argjson tests "$(jq -c '.charts.goTests' scripts/acceptance-groups.json)" '{
    apiVersion: "konstapel.dev/chart-acceptance/v1",
    passed: true,
    source: {commit: $source, tag: $manifest[0].source.tag},
    image: $image,
    crdContent: $manifest[0].crdContent,
    charts: ($manifest[0].charts | map_values({version, sha256})),
    tests: $tests,
    runtime: {kind: $kind, nodeImage: $node, kyvernoChart: $kyverno, certManagerChart: $certManager, s3: $s3}
  }' > "$out/chart-acceptance.json"
cat "$out/chart-acceptance.json"
