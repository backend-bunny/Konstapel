#!/usr/bin/env bash
# Check the independent external-provider example module and run its
# documented quickstart (docs/integration/external-provider-quickstart.md):
# build the binaries, generate throwaway certificates, start the provider,
# wait for readiness, run the host, and confirm a wrong server identity is
# refused. Called by `task test`; needs no cluster or network beyond the Go
# module cache. Private keys only ever live in a temporary directory.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
example="$root/examples/external-provider/reporting"
doc="$root/docs/integration/external-provider-quickstart.md"
cd "$example"

# The module must be tidy and formatted, and build without network fetches.
if ! go mod tidy -diff >/dev/null; then
  echo "examples/external-provider/reporting/go.mod or go.sum is stale; run 'go mod tidy' there" >&2
  go mod tidy -diff >&2 || true
  exit 1
fi
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  printf 'Run gofmt on examples/external-provider/reporting:\n%s\n' "$unformatted" >&2
  exit 1
fi
go vet -mod=readonly ./...
go test -mod=readonly -count=1 ./...

# Every command below is quoted verbatim in the quickstart, so the guide and
# this run cannot drift apart.
documented=(
  'go build -mod=readonly -o "$work/" ./cmd/...'
  '"$work/quickstart-certs" -out "$work/tls"'
  '"$work/reporting-provider" -tls-dir "$work/tls/server" &'
  'curl -fsS --retry 30 --retry-delay 1 --retry-all-errors http://127.0.0.1:18444/readyz'
  '"$work/reporting-host" -tls-dir "$work/tls/host"'
  '"$work/reporting-host" -tls-dir "$work/tls/host" -server-name other.provider.example.test'
)
for line in "${documented[@]}"; do
  if ! grep -qF -- "$line" "$doc"; then
    echo "quickstart no longer documents: $line" >&2
    exit 1
  fi
done

work=$(mktemp -d)
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

go build -mod=readonly -o "$work/" ./cmd/...
"$work/quickstart-certs" -out "$work/tls"
"$work/reporting-provider" -tls-dir "$work/tls/server" &
server_pid=$!
curl -fsS --retry 30 --retry-delay 1 --retry-all-errors http://127.0.0.1:18444/readyz
"$work/reporting-host" -tls-dir "$work/tls/host"
if "$work/reporting-host" -tls-dir "$work/tls/host" -server-name other.provider.example.test; then
  echo "the host reached a provider whose certificate does not name the expected server" >&2
  exit 1
fi
echo "external provider quickstart: ok"
