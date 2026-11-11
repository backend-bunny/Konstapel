#!/usr/bin/env bash
# Regenerate the public-key verification fixtures in this directory with the
# pinned Cosign CLI (devbox.json) against a disposable local registry.
#   devbox run -- internal/bundle/verify/testdata/cosign/generate.sh LAYOUT OUT_DIR
# LAYOUT is a frozen bundle OCI layout from scripts/bundles/package.sh. OUT_DIR
# must not exist; review its contents and copy them here by hand.
#
# Everything is test-only: two fresh ECDSA P-256 key pairs with an empty
# password, a registry container on a loopback port (labelled
# konstapel.test=<run> and removed on exit), no transparency log upload, no
# timestamp authority and no signing configuration. Outbound HTTP(S) other
# than to the loopback registry is routed to a closed port, so a mistake can
# not reach the Sigstore public-good services.
set -euo pipefail
cd "$(dirname "$0")/../../../../.."
source scripts/runtime.env
layout=${1:?usage: generate.sh LAYOUT OUT_DIR}
out=${2:?usage: generate.sh LAYOUT OUT_DIR}
[[ ! -e $out ]] || { echo "$out exists" >&2; exit 1; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
run=konstapel-verify-fixtures-$RANDOM$RANDOM
cleanup() { docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --label "konstapel.test=$run" -p 127.0.0.1::5000 "$KONSTAPEL_REGISTRY_IMAGE" >/dev/null
port=$(docker port "$(docker ps -q --filter "label=konstapel.test=$run")" 5000/tcp | head -1 | sed 's/.*://')
reg=127.0.0.1:$port
repo=fixtures/konstapel-privileged-containers
for _ in $(seq 50); do curl -fsS "http://$reg/v2/" >/dev/null 2>&1 && break; sleep 0.2; done

# Push the frozen layout's blobs and manifest unchanged.
manifest_digest=$(jq -r '.manifests[0].digest' "$layout/index.json")
for blob in "$layout"/blobs/sha256/*; do
  d=sha256:$(basename "$blob")
  [[ $d == "$manifest_digest" ]] && continue
  loc=$(curl -fsS -X POST -D - -o /dev/null "http://$reg/v2/$repo/blobs/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
  case $loc in http*) ;; *) loc=http://$reg$loc ;; esac
  sep='?'; [[ $loc == *\?* ]] && sep='&'
  curl -fsS -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@$blob" "$loc${sep}digest=$d" >/dev/null
done
curl -fsS -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary "@$layout/blobs/sha256/${manifest_digest#sha256:}" "http://$reg/v2/$repo/manifests/$manifest_digest" >/dev/null
cp "$layout/blobs/sha256/${manifest_digest#sha256:}" "$out/subject-manifest.json"

export COSIGN_PASSWORD='' COSIGN_YES=true
export HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost
export TUF_ROOT=$out/.tuf-unused HOME=$out/.home
mkdir -p "$HOME"
(cd "$out" && cosign generate-key-pair --output-key-prefix key-a >/dev/null && cosign generate-key-pair --output-key-prefix key-b >/dev/null)

common=(--allow-http-registry --tlog-upload=false --use-signing-config=false)
ref=$reg/$repo@$manifest_digest
tagindex="http://$reg/v2/$repo/manifests/sha256-${manifest_digest#sha256:}"
listed() { curl -fsS -H 'Accept: application/vnd.oci.image.index.v1+json' "$tagindex" 2>/dev/null | jq -r '.manifests[].digest' | sort; }
# save NAME: store the one referrer added since the last call (manifest and
# its Sigstore bundle layer) as NAME.manifest.json and NAME.bundle.json.
seen=""
save() {
  local now new m layer
  now=$(listed)
  new=$(comm -13 <(printf '%s\n' $seen | sort) <(printf '%s\n' $now) | grep . || true)
  [[ $(wc -l <<<"$new") == 1 && -n $new ]] || { echo "expected exactly one new referrer for $1" >&2; exit 1; }
  m=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/$repo/manifests/$new")
  layer=$(jq -r '.layers[0].digest' <<<"$m")
  printf '%s' "$m" > "$out/$1.manifest.json"
  curl -fsS -o "$out/$1.bundle.json" "http://$reg/v2/$repo/blobs/$layer"
  seen=$now
}
cosign sign "${common[@]}" --key "$out/key-a.key" "$ref"
save sign-key-a
cosign sign "${common[@]}" --key "$out/key-b.key" "$ref"
save sign-key-b
cat > "$out/provenance-predicate.json" <<'PRED'
{"buildDefinition":{"buildType":"https://konstapel.example/test-build/v1","externalParameters":{"source":"https://git.example.test/policies","bundle":"konstapel-privileged-containers","version":"0.1.0"},"resolvedDependencies":[{"uri":"git+https://git.example.test/policies","digest":{"gitCommit":"0000000000000000000000000000000000000001"}}]},"runDetails":{"builder":{"id":"https://ci.example.test/bundle-builder@refs/heads/main"},"metadata":{"invocationId":"test-only"}}}
PRED
cosign attest "${common[@]}" --key "$out/key-a.key" --type slsaprovenance1 --predicate "$out/provenance-predicate.json" "$ref"
save provenance-key-a
# Fingerprint: SHA-256 of the DER SubjectPublicKeyInfo inside the PEM.
keyid() { sed '/-----/d' "$out/$1.pub" | base64 -d | sha256sum | cut -d' ' -f1; }
printf 'subject %s\nkey-a sha256:%s\nkey-b sha256:%s\n' "$manifest_digest" "$(keyid key-a)" "$(keyid key-b)" > "$out/fingerprints.txt"
rm -rf "$out/.home" "$out/.tuf-unused"
cleanup
[[ -z $(docker ps -aq --filter "label=konstapel.test=$run") ]] || { echo "registry container for $run not removed" >&2; exit 1; }
echo "fixtures written to $out; registry removed"
