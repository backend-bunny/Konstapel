#!/usr/bin/env bash
# Run the S3 compatibility suite against a disposable, test-owned instance of
# the pinned S3-compatible service (KONSTAPEL_S3_IMAGE in runtime.env).
# Usage: scripts/s3-compat.sh OUTPUT_DIR          run the compatibility suites
#        scripts/s3-compat.sh --serve OUTPUT_DIR  start the same service for local
#                                                 attachment development
# The container uses random credentials, a loopback port and its own named data
# volume; both are always removed (only when they carry this run's label).
# Results are written to OUTPUT_DIR/s3-compat.json, attachment-compat.json and
# s3-version.txt. --serve also creates the attachment bucket and writes
# OUTPUT_DIR/dev.env (mode 0600; never commit it), then waits for Ctrl-C or EOF
# on stdin before tearing everything down.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
serve=0
if [ "${1:-}" = --serve ]; then serve=1; shift; fi
out=${1:?usage: s3-compat.sh [--serve] OUTPUT_DIR}
mkdir -p "$out"
name=konstapel-s3-compat-$RANDOM$RANDOM
label=konstapel.s3-compat=$name
access=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
cleanup() {
  if [ -n "$(docker ps -aq --filter "label=$label" --filter "name=^$name\$")" ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  if [ -n "$(docker volume ls -q --filter "label=$label" --filter "name=^$name\$")" ]; then
    docker volume rm -f "$name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
docker volume create --label "$label" "$name" >/dev/null
docker run -d --name "$name" --label "$label" -v "$name":/data -p 127.0.0.1::9000 \
  -e RUSTFS_ACCESS_KEY="$access" -e RUSTFS_SECRET_KEY="$secret" \
  "$KONSTAPEL_S3_IMAGE" /data >/dev/null
port=$(docker port "$name" 9000/tcp | head -1 | sed 's/.*://')
endpoint=http://127.0.0.1:$port
for _ in $(seq 60); do
  if curl -s -o /dev/null "$endpoint/"; then break; fi
  sleep 1
done
docker image inspect "$KONSTAPEL_S3_IMAGE" --format '{{json .RepoDigests}}' > "$out/s3-image.json"
docker exec "$name" rustfs --version 2>&1 | head -1 > "$out/s3-version.txt" || true
if [ "$serve" = 1 ]; then
  bucket=konstapel-attachments
  curl -sf --aws-sigv4 "aws:amz:us-east-1:s3" --user "$access:$secret" -X PUT "$endpoint/$bucket" >/dev/null
  umask 077
  cat > "$out/dev.env" <<ENVEOF
KONSTAPEL_S3_ENDPOINT=$endpoint
KONSTAPEL_S3_BUCKET=$bucket
KONSTAPEL_S3_PREFIX=konstapel-dev
KONSTAPEL_S3_ACCESS_KEY=$access
KONSTAPEL_S3_SECRET_KEY=$secret
ENVEOF
  echo "$(cat "$out/s3-version.txt") ready; settings in $out/dev.env. Ctrl-C or EOF removes the container and volume."
  cat >/dev/null || true
  exit 0
fi
KONSTAPEL_S3_ENDPOINT=$endpoint KONSTAPEL_S3_ACCESS_KEY=$access KONSTAPEL_S3_SECRET_KEY=$secret \
KONSTAPEL_S3_OUTPUT=$out KONSTAPEL_S3_IMAGE=$KONSTAPEL_S3_IMAGE KONSTAPEL_S3_VERSION="$(cat "$out/s3-version.txt")" \
  go test -mod=readonly -tags s3compat -count=1 -run '^(TestCompatibility|TestPublisherRoundTrip|TestSignedPublisherRoundTrip|TestAttachmentStoreCompatibility)$' -v ./internal/s3store/ > "$out/s3-compat.log" 2>&1 \
  || { tail -40 "$out/s3-compat.log" >&2; exit 1; }
for f in s3-compat.json attachment-compat.json; do
  [ -s "$out/$f" ] || { echo "missing $out/$f" >&2; exit 1; }
done
echo "S3 compatibility suite passed against $KONSTAPEL_S3_IMAGE ($(cat "$out/s3-version.txt")); results in $out"
