#!/usr/bin/env bash
# Regenerate deepcopy code, CRDs, and RBAC from the Go API types.
# With --check, fail if the checked-in generated files are out of date.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

generate() {
	local crd_dir=$1
	controller-gen object paths=./api/...
	controller-gen crd paths=./api/... output:crd:artifacts:config="$crd_dir"
}

if [ "${1:-}" = "--check" ]; then
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cp -r api "$tmp/api.orig"
	generate "$tmp/crd"
	status=0
	if ! diff -r "$tmp/api.orig" api >/dev/null; then
		echo "Generated Go files in api/ are out of date; run scripts/generate.sh" >&2
		rm -rf api && cp -r "$tmp/api.orig" api
		status=1
	fi
	if ! diff -r "$tmp/crd" config/crd/bases; then
		echo "CRDs in config/crd/bases are out of date; run scripts/generate.sh" >&2
		status=1
	fi
	exit "$status"
fi

generate config/crd/bases
