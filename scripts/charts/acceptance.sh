#!/usr/bin/env bash
# Release acceptance of frozen chart inputs:
#   scripts/charts/acceptance.sh OUTPUT ARCHIVES_DIR ghcr.io/backend-bunny/konstapel@sha256:<digest>
# Verifies the publication manifest in ARCHIVES_DIR against this clean
# checkout and the image digest. It then runs every release-required
# acceptance group ("release": true in the committed
# scripts/acceptance-groups.json), one after another, each through
# scripts/acceptance.sh on its own fresh disposable cluster and in
# OUTPUT/groups/GROUP. Every node pulls that exact image by digest and Helm
# installs exactly those archives. scripts/charts/evidence.py then derives
# each test's result from the group's go test log and writes
# OUTPUT/chart-acceptance.json only if every required group fully passed,
# binding the results to the source commit, both archive checksums, the CRD
# content identity, the image digest and the runtime versions. The publisher
# refuses to publish without a binding that matches its frozen manifest.
set -euo pipefail
cd "$(dirname "$0")/../.."
usage='usage: acceptance.sh OUTPUT ARCHIVES_DIR IMAGE@DIGEST'
out=${1:?$usage}
archives=$(realpath "${2:?$usage}")
image=${3:?$usage}
[[ $image =~ ^ghcr\.io/backend-bunny/konstapel@(sha256:[0-9a-f]{64})$ ]] || { echo "image must be ghcr.io/backend-bunny/konstapel@sha256:<digest>" >&2; exit 1; }
digest=${BASH_REMATCH[1]}
# The tests, group selection and helpers that run must be the frozen source.
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo 'Release acceptance requires a clean checkout: the record binds HEAD as the tested source' >&2
  exit 1
fi
source=$(git rev-parse HEAD)
python3 scripts/charts/manifest.py verify --archives "$archives" --manifest "$archives/publication.json" --source "$source" --image-digest "$digest"
out=$(realpath -m "$out")
[[ ! -e $out ]] || { echo 'Acceptance output must be a fresh directory' >&2; exit 1; }
groups=$(python3 scripts/charts/evidence.py groups --source "$source")
mkdir -p "$out/groups"
for group in $groups; do
  printf '[%s] Release acceptance group %s on %s\n' "$(date -u +%H:%M:%S)" "$group" "$image"
  if ! KONSTAPEL_ACCEPTANCE_IMAGE=$image KONSTAPEL_LIVE_CHART_ARCHIVES=$archives scripts/acceptance.sh "$out/groups/$group" "$group"; then
    # Later groups are not run; the record step reports them as missing.
    echo "Release acceptance group $group failed" >&2
    break
  fi
done
source scripts/runtime.env
runtime=$(jq -cn --arg kind "$(kind version | awk '{print $2}')" --arg node "$KONSTAPEL_NODE_IMAGE" --arg kyverno "$KONSTAPEL_KYVERNO_CHART_VERSION" \
  --arg certManager "$KONSTAPEL_CERT_MANAGER_CHART_VERSION" --arg s3 "$KONSTAPEL_S3_IMAGE" \
  '{kind: $kind, nodeImage: $node, kyvernoChart: $kyverno, certManagerChart: $certManager, s3: $s3}')
# Fails, writing no record, unless every required group fully passed.
python3 scripts/charts/evidence.py record --archives "$archives" --groups-dir "$out/groups" --image "$image" \
  --source "$source" --runtime "$runtime" --out "$out/chart-acceptance.json"
cat "$out/chart-acceptance.json"
