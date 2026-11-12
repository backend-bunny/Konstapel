#!/usr/bin/env bash
# Regenerate the provenance-policy fixtures in this directory with the pinned
# Cosign CLI (devbox.json) against a disposable local registry.
#   devbox run -- internal/bundle/verify/testdata/provenance/generate.sh LAYOUT BUILDER_REVISION OUT_DIR
# LAYOUT is a frozen bundle OCI layout from scripts/bundles/package.sh;
# BUILDER_REVISION is the organization builder's own revision (a full commit
# here, newer than the source), recorded separately from the layout's source
# commit. OUT_DIR must not exist; review its contents and copy them here by
# hand (everything except *.key).
#
# Same isolation as ../cosign/generate.sh: fresh ECDSA P-256 test key pairs
# with an empty password, a registry container on a loopback port labelled
# konstapel.test=<run> and removed on exit, no transparency log upload, no
# timestamp authority, no signing configuration, and outbound HTTP(S) routed
# to a closed port.
set -euo pipefail
cd "$(dirname "$0")/../../../../.."
source scripts/runtime.env
layout=${1:?usage: generate.sh LAYOUT BUILDER_REVISION OUT_DIR}
builder_revision=${2:?usage: generate.sh LAYOUT BUILDER_REVISION OUT_DIR}
out=${3:?usage: generate.sh LAYOUT BUILDER_REVISION OUT_DIR}
[[ $builder_revision =~ ^[0-9a-f]{40}$ ]] || { echo "builder revision must be a full SHA" >&2; exit 1; }
[[ ! -e $out ]] || { echo "$out exists" >&2; exit 1; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
run=konstapel-provenance-fixtures-$RANDOM$RANDOM
cleanup() { docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT

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
push_manifest() {
  curl -fsS -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
    --data-binary "@$2" "http://$reg/v2/$repo/manifests/$1" >/dev/null
}

# The frozen layout, unchanged.
subject=$(jq -r '.manifests[0].digest' "$layout/index.json")
for blob in "$layout"/blobs/sha256/*; do
  d=sha256:$(basename "$blob")
  [[ $d == "$subject" ]] || push_blob "$d" "$blob"
done
push_manifest "$subject" "$layout/blobs/sha256/${subject#sha256:}"
cp "$layout/blobs/sha256/${subject#sha256:}" "$out/subject-manifest.json"
layer=$(jq -r '.layers[0].digest' "$out/subject-manifest.json")
cp "$layout/blobs/sha256/${layer#sha256:}" "$out/subject-layer.tar.gz"
# A second subject: the same layer under a manifest with one extra annotation,
# so its digest differs.
jq -c '.annotations = {"org.example.test/variant": "other"}' "$out/subject-manifest.json" > "$out/other-subject-manifest.json"
other=sha256:$(sha256sum "$out/other-subject-manifest.json" | cut -d' ' -f1)
push_manifest "$other" "$out/other-subject-manifest.json"

# Facts the valid predicate attests, read from the frozen payload and the
# source repository.
work=$(mktemp -d)
tar -xzf "$out/subject-layer.tar.gz" -C "$work" bundle.json
desc=$work/bundle.json
name=$(jq -r .name "$desc")
version=$(jq -r .version "$desc")
src_repo=$(jq -r .source.repository "$desc")
src_commit=$(jq -r .source.revision "$desc")
# Descriptor.ContentDigest: SHA-256 of the compact JSON of the inventory
# sorted by path (Go's json.Marshal of []bundle.File).
content=$(jq -cj '[.files | sort_by(.path)[] | {path, role, size, sha256}]' "$desc" | sha256sum | cut -d' ' -f1)
definition=$(git show "$src_commit:bundles/$name/definition.json" | sha256sum | cut -d' ' -f1)
go_version=$(jq -r .tools.go "$layout/package.json")
rm -rf "$work"
# An organization builder that is not a GitHub Actions workflow: its
# provenance carries the builder record (internalParameters.builder), never a
# workflow record.
builder=https://ci.example.test/konstapel/bundle-release@refs/heads/main

jq -n --arg name "$name" --arg version "$version" --arg repo "$src_repo" --arg commit "$src_commit" \
  --arg content "$content" --arg definition "$definition" --arg rev "$builder_revision" --arg builder "$builder" \
  --arg go "${go_version#go}" --argjson tests "$(jq -c '[.files[] | select(.role == "test") | {name: "test", uri: ("bundle-file:" + .path), digest: {sha256: .sha256}}]' <(tar -xzOf "$out/subject-layer.tar.gz" bundle.json))" '
{
  buildDefinition: {
    buildType: "https://github.com/backend-bunny/Konstapel/blob/main/docs/policy-bundles.md#bundle-provenance-v1",
    externalParameters: {bundle: {name: $name, version: $version}, source: {repository: $repo, commit: $commit}},
    internalParameters: {builder: {revision: $rev}},
    resolvedDependencies: ([
      {name: "source", uri: ("git+" + $repo), digest: {gitCommit: $commit}},
      {name: "bundle-definition", uri: ("git+" + $repo + "@" + $commit + "#bundles/" + $name + "/definition.json"), digest: {sha256: $definition}},
      {name: "bundle-content", uri: ("bundle-content:" + $name + "@" + $version), digest: {sha256: $content}}
    ] + $tests + [
      {name: "tool", uri: ("pkg:golang/go@" + $go)},
      {name: "tool", uri: "pkg:github/sigstore/cosign@v3.1.3"}
    ])
  },
  runDetails: {builder: {id: $builder}, metadata: {invocationId: "test-only"}}
}' > "$out/valid.predicate.json"

# Negative predicates: one contract violation each. dispatch-as-source attests
# the builder revision as the content source; workflow-record carries a GitHub
# workflow record instead of the builder record.
neg() { jq "$2" "$out/valid.predicate.json" > "$out/$1.predicate.json"; }
srcdep='.buildDefinition.resolvedDependencies |= map(if .name == "source" then '
neg wrong-builder '.runDetails.builder.id = "https://ci.example.test/other-builder@refs/heads/main"'
neg wrong-source-repo '.buildDefinition.externalParameters.source.repository = "https://github.com/example-fork/Konstapel" | '"$srcdep"'.uri = "git+https://github.com/example-fork/Konstapel" else . end)'
neg wrong-source-commit '.buildDefinition.externalParameters.source.commit = "0123456789abcdef0123456789abcdef01234567" | '"$srcdep"'.digest.gitCommit = "0123456789abcdef0123456789abcdef01234567" else . end)'
jq --arg rev "$builder_revision" '.buildDefinition.externalParameters.source.commit = $rev | '"$srcdep"'.digest.gitCommit = $rev else . end)' "$out/valid.predicate.json" > "$out/dispatch-as-source.predicate.json"
jq --arg rev "$builder_revision" '.buildDefinition.internalParameters = {workflow: {repository: "https://github.com/backend-bunny/Konstapel", path: ".github/workflows/bundle-release.yml", ref: "refs/heads/main", commit: $rev}}' "$out/valid.predicate.json" > "$out/workflow-record.predicate.json"
neg wrong-version '.buildDefinition.externalParameters.bundle.version = "0.1.1"'
neg wrong-name '.buildDefinition.externalParameters.bundle.name = "konstapel-other-bundle"'
neg forged-content '.buildDefinition.resolvedDependencies |= map(if .name == "bundle-content" then .digest.sha256 = ("0" * 64) else . end)'
jq '(.buildDefinition.resolvedDependencies | map(.name == "test") | index(true)) as $i | .buildDefinition.resolvedDependencies[$i].digest.sha256 = ("1" * 64)' "$out/valid.predicate.json" > "$out/forged-test.predicate.json"
neg no-resolved-dependencies '.buildDefinition.resolvedDependencies = []'
neg no-source-material '.buildDefinition.resolvedDependencies |= map(select(.name != "source"))'

export COSIGN_PASSWORD='' COSIGN_YES=true
export HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost
export TUF_ROOT=$out/.tuf-unused HOME=$out/.home
mkdir -p "$HOME"
(cd "$out" && cosign generate-key-pair --output-key-prefix org >/dev/null && cosign generate-key-pair --output-key-prefix other >/dev/null)

common=(--allow-http-registry --tlog-upload=false --use-signing-config=false)
declare -A seen
listed() {
  curl -fsS -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/$repo/manifests/sha256-${1#sha256:}" 2>/dev/null |
    jq -r '.manifests[].digest' | sort
}
# save SUBJECT NAME: store the one referrer added to SUBJECT since the last
# call as NAME.manifest.json and NAME.bundle.json.
save() {
  local now new m layer
  now=$(listed "$1")
  new=$(comm -13 <(printf '%s\n' ${seen[$1]:-} | sort) <(printf '%s\n' $now) | grep . || true)
  [[ $(wc -l <<<"$new") == 1 && -n $new ]] || { echo "expected exactly one new referrer for $2" >&2; exit 1; }
  m=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/$repo/manifests/$new")
  layer=$(jq -r '.layers[0].digest' <<<"$m")
  printf '%s' "$m" > "$out/$2.manifest.json"
  curl -fsS -o "$out/$2.bundle.json" "http://$reg/v2/$repo/blobs/$layer"
  seen[$1]=$now
}
attest() { # KEY PREDICATE SUBJECT NAME
  cosign attest "${common[@]}" --key "$out/$1.key" --type slsaprovenance1 --predicate "$out/$2.predicate.json" "$reg/$repo@$3"
  save "$3" "$4"
}

cosign sign "${common[@]}" --key "$out/org.key" "$reg/$repo@$subject"
save "$subject" sign-org
cosign sign "${common[@]}" --key "$out/other.key" "$reg/$repo@$subject"
save "$subject" sign-other
attest org valid "$subject" prov-valid
attest other valid "$subject" prov-valid-other
attest org valid "$other" prov-other-subject
for n in wrong-builder wrong-source-repo wrong-source-commit dispatch-as-source workflow-record wrong-version wrong-name \
  forged-content forged-test no-resolved-dependencies no-source-material; do
  attest org "$n" "$subject" "prov-$n"
done

keyid() { sed '/-----/d' "$out/$1.pub" | base64 -d | sha256sum | cut -d' ' -f1; }
printf 'subject %s\nother-subject %s\nbuilder-revision %s\norg sha256:%s\nother sha256:%s\nbuilder %s\n' \
  "$subject" "$other" "$builder_revision" "$(keyid org)" "$(keyid other)" "$builder" > "$out/facts.txt"
rm -rf "$out/.home" "$out/.tuf-unused"
cleanup
[[ -z $(docker ps -aq --filter "label=konstapel.test=$run") ]] || { echo "registry container for $run not removed" >&2; exit 1; }
echo "fixtures written to $out; registry removed"
