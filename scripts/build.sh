#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
go build -o bin/konstapel ./cmd/konstapel
go build -o bin/konstapel-provider ./cmd/konstapel-provider
jq -n --arg hash "$(sha256sum bin/konstapel-provider | cut -d ' ' -f1)" '{metadata:{id:"konstapel-kyverno",description:"Bounded modern Kyverno evidence provider",version:"0.1.0",types:["pvp"]},executablePath:"konstapel-provider",sha256:$hash,configuration:(["root","output","namespace","owner"] | map({name:.,required:true})) + (["action","capture"]|map({name:.,required:false}))}' > bin/c2p-konstapel-kyverno-manifest.json
