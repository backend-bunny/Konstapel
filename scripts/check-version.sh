#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
version=$(cat VERSION)
jq -en --arg version "$version" '$version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")' >/dev/null
package_version=$(sed -n 's/^  version: "\([^"]*\)".*/\1/p' melange.yaml)
if [ "$version" != "$package_version" ]; then
  echo "Version mismatch: VERSION=$version melange.yaml=$package_version" >&2
  exit 1
fi
if [ -n "${1:-}" ] && [ "$1" != "v$version" ]; then
  echo "Tag $1 does not match VERSION (expected v$version)" >&2
  exit 1
fi
printf 'version %s\n' "$version"
