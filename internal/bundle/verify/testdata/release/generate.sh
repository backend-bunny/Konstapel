#!/usr/bin/env bash
# Regenerate the release-provenance fixtures in this directory: the predicate
# written by the release tool's own generator (bundlerelease provenance,
# publish.BuildProvenance), signed and attested with the pinned Cosign CLI
# (devbox.json) and a fresh test key against a disposable local registry.
#   devbox run -- internal/bundle/verify/testdata/release/generate.sh LAYOUT WORKFLOW_COMMIT OUT_DIR
# LAYOUT is a frozen bundle layout (scripts/bundles/package.sh, then
# bundlerelease freeze, so it carries publication-record.json). WORKFLOW_COMMIT
# is the (newer) workflow revision that "runs" the release, recorded apart
# from the layout's (older) source commit. OUT_DIR must not exist; review its
# contents and copy them here by hand (everything except *.key).
#
# Same isolation as ../cosign/generate.sh: an ECDSA P-256 test key pair with an
# empty password, a registry container on a loopback port labelled
# konstapel.test=<run> and removed on exit, no transparency log upload, no
# timestamp authority, no signing configuration, and outbound HTTP(S) routed
# to a closed port.
set -euo pipefail
cd "$(dirname "$0")/../../../../.."
source scripts/runtime.env
layout=${1:?usage: generate.sh LAYOUT WORKFLOW_COMMIT OUT_DIR}
workflow_commit=${2:?usage: generate.sh LAYOUT WORKFLOW_COMMIT OUT_DIR}
out=${3:?usage: generate.sh LAYOUT WORKFLOW_COMMIT OUT_DIR}
[[ $workflow_commit =~ ^[0-9a-f]{40}$ ]] || { echo "workflow commit must be a full SHA" >&2; exit 1; }
[[ -f $layout/publication-record.json ]] || { echo "$layout is not frozen (no publication-record.json)" >&2; exit 1; }
[[ ! -e $out ]] || { echo "$out exists" >&2; exit 1; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
layout=$(cd "$layout" && pwd)
run=konstapel-release-fixtures-$RANDOM$RANDOM
cleanup() { docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Build the tool first, with the real environment (module cache).
go build -mod=readonly -o "$out/.bundlerelease" ./cmd/bundlerelease

docker run -d --label "konstapel.test=$run" -p 127.0.0.1::5000 "$KONSTAPEL_REGISTRY_IMAGE" >/dev/null
port=$(docker port "$(docker ps -q --filter "label=konstapel.test=$run")" 5000/tcp | head -1 | sed 's/.*://')
reg=127.0.0.1:$port
repo=fixtures/konstapel-privileged-containers
for _ in $(seq 50); do curl -fsS "http://$reg/v2/" >/dev/null 2>&1 && break; sleep 0.2; done

push_blob() {
  local d=$1 file=$2 loc sep
  loc=$(curl -fsS -X POST -D - -o /dev/null "http://$reg/v2/$repo/blobs/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
  case $loc in http*) ;; *) loc=http://$reg$loc ;; esac
  sep='?'; [[ $loc == *\?* ]] && sep='&'
  curl -fsS -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@$file" "$loc${sep}digest=$d" >/dev/null
}
subject=$(jq -r '.manifests[0].digest' "$layout/index.json")
for blob in "$layout"/blobs/sha256/*; do
  d=sha256:$(basename "$blob")
  [[ $d == "$subject" ]] || push_blob "$d" "$blob"
done
curl -fsS -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary "@$layout/blobs/sha256/${subject#sha256:}" "http://$reg/v2/$repo/manifests/$subject" >/dev/null
cp "$layout/blobs/sha256/${subject#sha256:}" "$out/subject-manifest.json"
layer=$(jq -r '.layers[0].digest' "$out/subject-manifest.json")
cp "$layout/blobs/sha256/${layer#sha256:}" "$out/subject-layer.tar.gz"
cp "$layout/publication-record.json" "$out/publication-record.json"

export COSIGN_PASSWORD='' COSIGN_YES=true
export HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost
export TUF_ROOT=$out/.tuf-unused HOME=$out/.home
unset GITHUB_ACTIONS
mkdir -p "$HOME"
(cd "$out" && cosign generate-key-pair --output-key-prefix org >/dev/null)
fp=$(sed '/-----/d' "$out/org.pub" | base64 -d | sha256sum | cut -d' ' -f1)

builder=https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main
other_builder=https://github.com/backend-bunny/Konstapel/.github/workflows/other.yml@refs/heads/main
rule() { # BUILDER
  cat <<RULE
version: 1
sources:
  - name: konstapel-privileged-containers
    repository: registry.example.test/fixtures/konstapel-privileged-containers
    publisher:
      type: public-key
      publicKey: {kind: Secret, name: org-signing-key}
      keyFingerprint: sha256:$fp
      provenance:
        sourceRepository: https://github.com/backend-bunny/Konstapel
        builder: $1
RULE
}
rule "$builder" > "$out/rule.yaml"
rule "$other_builder" > "$out/.other-rule.yaml"
wf=(-workflow-repository https://github.com/backend-bunny/Konstapel -workflow-path .github/workflows/bundle-release.yml
  -workflow-ref refs/heads/main -workflow-commit "$workflow_commit")
"$out/.bundlerelease" provenance -package "$layout" -sources "$out/rule.yaml" "${wf[@]}" -out "$out/valid.predicate.json"
"$out/.bundlerelease" provenance -package "$layout" -sources "$out/.other-rule.yaml" "${wf[@]}" -out "$out/wrong-builder.predicate.json"

common=(--allow-http-registry --tlog-upload=false --use-signing-config=false --key "$out/org.key")
ref=$reg/$repo@$subject
seen=""
listed() { curl -fsS -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/$repo/manifests/sha256-${subject#sha256:}" 2>/dev/null | jq -r '.manifests[].digest' | sort; }
save() {
  local now new m l
  now=$(listed)
  new=$(comm -13 <(printf '%s\n' $seen | sort) <(printf '%s\n' $now) | grep . || true)
  [[ $(wc -l <<<"$new") == 1 && -n $new ]] || { echo "expected exactly one new referrer for $1" >&2; exit 1; }
  m=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/$repo/manifests/$new")
  l=$(jq -r '.layers[0].digest' <<<"$m")
  printf '%s' "$m" > "$out/$1.manifest.json"
  curl -fsS -o "$out/$1.bundle.json" "http://$reg/v2/$repo/blobs/$l"
  seen=$now
}
cosign sign "${common[@]}" "$ref"
save sign
cosign attest "${common[@]}" --type slsaprovenance1 --predicate "$out/valid.predicate.json" "$ref"
save prov-valid
cosign attest "${common[@]}" --type slsaprovenance1 --predicate "$out/wrong-builder.predicate.json" "$ref"
save prov-wrong-builder

printf 'subject %s\nworkflow %s\norg sha256:%s\nbuilder %s\nother-builder %s\ncosign %s\n' \
  "$subject" "$workflow_commit" "$fp" "$builder" "$other_builder" "$(cosign version --json | jq -r .gitVersion)" > "$out/facts.txt"
rm -rf "$out/.home" "$out/.tuf-unused" "$out/.bundlerelease" "$out/.other-rule.yaml"
cleanup
[[ -z $(docker ps -aq --filter "label=konstapel.test=$run") ]] || { echo "registry container for $run not removed" >&2; exit 1; }
echo "fixtures written to $out; registry removed"
