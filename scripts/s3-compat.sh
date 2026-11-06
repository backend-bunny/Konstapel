#!/usr/bin/env bash
# Run the S3 compatibility suite against a disposable, test-owned instance of
# the pinned S3-compatible service (KONSTAPEL_S3_IMAGE in runtime.env).
# Usage: scripts/s3-compat.sh OUTPUT_DIR
# The container uses random credentials and a loopback port, and is always
# removed. Results are written to OUTPUT_DIR/s3-compat.json.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: s3-compat.sh OUTPUT_DIR}
mkdir -p "$out"
name=konstapel-s3-compat-$RANDOM$RANDOM
access=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" -p 127.0.0.1::9000 \
  -e RUSTFS_ACCESS_KEY="$access" -e RUSTFS_SECRET_KEY="$secret" \
  "$KONSTAPEL_S3_IMAGE" /data >/dev/null
port=$(docker port "$name" 9000/tcp | head -1 | sed 's/.*://')
endpoint=http://127.0.0.1:$port
for _ in $(seq 60); do
  if curl -s -o /dev/null "$endpoint/"; then break; fi
  sleep 1
done
docker image inspect "$KONSTAPEL_S3_IMAGE" --format '{{json .RepoDigests}}' > "$out/s3-image.json"
KONSTAPEL_S3_ENDPOINT=$endpoint KONSTAPEL_S3_ACCESS_KEY=$access KONSTAPEL_S3_SECRET_KEY=$secret \
KONSTAPEL_S3_OUTPUT=$out KONSTAPEL_S3_IMAGE=$KONSTAPEL_S3_IMAGE \
  go test -mod=readonly -tags s3compat -count=1 -run '^(TestCompatibility|TestPublisherRoundTrip)$' -v ./internal/s3store/ > "$out/s3-compat.log" 2>&1 \
  || { tail -40 "$out/s3-compat.log" >&2; exit 1; }
echo "S3 compatibility suite passed against $KONSTAPEL_S3_IMAGE; results in $out/s3-compat.json"
