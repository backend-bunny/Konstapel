#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sh scripts/check-version.sh
version=$(cat VERSION)
mkdir -p bin
go build -o bin/konstapel ./cmd/konstapel
go build -o bin/konstapel-provider ./cmd/konstapel-provider
jq -n --arg version "$version" --arg hash "$(sha256sum bin/konstapel-provider | cut -d ' ' -f1)" '{metadata:{id:"konstapel-kyverno",description:"Bounded modern Kyverno evidence provider",version:$version,types:["pvp"]},executablePath:"konstapel-provider",sha256:$hash,configuration:((["root","output","namespace","owner"] | map({name:.,required:true})) + (["action","capture"]|map({name:.,required:false})))}' > bin/c2p-konstapel-kyverno-manifest.json
