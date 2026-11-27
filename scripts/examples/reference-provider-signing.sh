#!/usr/bin/env bash
# Reference provider signing, SBOMs and provenance (add-external-assessment-
# providers 5.2). Publishes the example reporting provider's image and its
# reference chart to disposable local registries the way a provider release
# would be published, with the controller release's tools and formats: a
# Cosign signature, apko's and Syft's SPDX SBOMs as `cosign attest --type
# spdxjson` attestations, and SLSA provenance v1 (`--type slsaprovenance1`)
# for the image and the chart, whose default image.digest is the signed
# image's digest. It then runs the operator verification procedure of
# docs/integration/external-provider-chart.md ("Verify and install") on the
# valid release and on fixtures that must be rejected: proofs by another
# key, a key the operator does not trust, no proofs, attestations without a
# signature, a signature without attestations, provenance from another
# builder, proofs copied from another digest, a signed chart pinning an
# unsigned image, and charts that are unsigned, lack provenance or were
# signed by another key. It also runs the controller image's signature check
# (docs/images.md "Verify", scripts/image/verify-signature-payload.sh) on the
# valid image, on the attestation-only image, which plain `cosign verify`
# accepts and that check must reject, and on the valid image's verified
# payloads checked against another digest. Each case must end exactly as
# expected, at the expected step.
#
# Usage: reference-provider-signing.sh IMAGE_DIR OUTPUT_DIR
# IMAGE_DIR is what scripts/examples/reference-provider-image.sh wrote; its
# image is pushed unchanged, so the signed digest is the built and tested
# image manifest. OUTPUT_DIR must not exist. It receives
# reference-provider-signing.json (every case and its outcome), the
# verification output of the valid release, the predicates and the public
# keys' fingerprints. scripts/acceptance.sh runs this in the providers group.
#
# Nothing is published. The registries are the pinned KONSTAPEL_REGISTRY_IMAGE
# (no referrers API, so Cosign maintains the OCI tag schema index, as on
# ghcr.io) and KONSTAPEL_REGISTRY_API_IMAGE (Zot, OCI 1.1 referrers API),
# each a container on a loopback port over plain HTTP, labelled
# konstapel.test=<run> (and konstapel.acceptance=<cluster> under acceptance)
# and removed on exit. Cosign signs in key mode with two fresh ECDSA P-256
# key pairs (empty password) generated in a private temporary directory that
# is removed on exit and never written to OUTPUT_DIR. No transparency log,
# signing configuration, Fulcio or OIDC token is used. Cosign and Helm run
# with a clean environment, a private HOME, DOCKER_CONFIG and TMPDIR, and
# their outbound HTTP(S) other than to loopback goes to a closed port, so no
# ambient credential is used and nothing reaches a public service.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
source scripts/runtime.env
usage='usage: reference-provider-signing.sh IMAGE_DIR OUTPUT_DIR'
images=${1:?$usage}
out=${2:?$usage}
images=$(realpath -e "$images")
out=$(realpath -m "$out")
[[ ! -e $out ]] || { echo "$out exists; evidence is never overwritten" >&2; exit 1; }
for f in image.tar sbom-x86_64.spdx.json sbom-complete.spdx.json commit build.sha256; do
  [[ -s $images/$f ]] || { echo "$images/$f is missing: run scripts/examples/reference-provider-image.sh first" >&2; exit 1; }
done
sha256sum --check --status "$images/build.sha256" || { echo "$images/image.tar does not match its build.sha256" >&2; exit 1; }
commit=$(cat "$images/commit")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "$images/commit is not a commit" >&2; exit 1; }
doc=docs/integration/external-provider-chart.md
chart_src=examples/external-provider/reporting/chart
recipe=examples/external-provider/reporting/image
source_repo=https://github.com/backend-bunny/Konstapel
# The test builder: a reserved .test name, so these proofs are never mistaken
# for a real publisher's.
BUILDER=https://ci.example.test/konstapel/reference-provider-signing
other_builder=https://ci.example.test/konstapel/another-builder
build_type="$source_repo/blob/main/$doc#reference-provenance-v1"
sign_kind=https://sigstore.dev/cosign/sign/v1

# The verification procedure. Every line is quoted verbatim in the guide, so
# the documentation and this run cannot drift apart.
documented=(
  'cosign verify "${TRUST[@]}" "$CHART" > chart-signature.json'
  "jq -e --arg digest \"\${CHART#*@}\" 'type == \"array\" and any(.[]; .critical.type == \"https://sigstore.dev/cosign/sign/v1\" and .critical.image.\"docker-manifest-digest\" == \$digest)' chart-signature.json"
  'cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$CHART" > chart-provenance.jsonl'
  "jq -se --arg builder \"\$BUILDER\" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == \$builder)' chart-provenance.jsonl"
  'mkdir chart'
  'helm pull "oci://$CHART" "${PULL[@]}" --destination chart'
  "IMAGE=\$(helm template ref chart/*.tgz --set 'worker.authorizedHosts[0]=probe.example.test' --set 'evaluator.authorizedHosts[0]=probe.example.test' | sed -n 's/^ *image: //p' | sort -u)"
  '[[ $IMAGE =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]'
  'cosign verify "${TRUST[@]}" "$IMAGE" > image-signature.json'
  "jq -e --arg digest \"\${IMAGE#*@}\" 'type == \"array\" and any(.[]; .critical.type == \"https://sigstore.dev/cosign/sign/v1\" and .critical.image.\"docker-manifest-digest\" == \$digest)' image-signature.json"
  'cosign verify-attestation "${TRUST[@]}" --type spdxjson "$IMAGE" > image-sbom.jsonl'
  'cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$IMAGE" > image-provenance.jsonl'
  "jq -se --arg builder \"\$BUILDER\" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == \$builder)' image-provenance.jsonl"
  'TRUST=(--key publisher.pub --insecure-ignore-tlog=true --allow-http-registry)'
  'PULL=(--plain-http)'
)
for line in "${documented[@]}"; do
  if ! grep -qF -- "$line" "$doc"; then
    echo "$doc no longer documents: $line" >&2
    exit 1
  fi
done

run=konstapel-reference-signing-$RANDOM$RANDOM
for image in "$KONSTAPEL_REGISTRY_IMAGE" "$KONSTAPEL_REGISTRY_API_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
done
labels=(--label "konstapel.test=$run")
[[ -z ${KONSTAPEL_CLUSTER_NAME:-} ]] || labels+=(--label "konstapel.acceptance=$KONSTAPEL_CLUSTER_NAME")
work=$(mktemp -d)
chmod 700 "$work"
cleanup() {
  docker ps -aq --filter "label=konstapel.test=$run" | xargs -r docker rm -fv >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$out" "$work/home" "$work/docker" "$work/tmp" "$work/tuf-unused" "$work/keys" "$work/image"

# Cosign and Helm get only this environment.
tools_env=(env -i "PATH=$PATH" "HOME=$work/home" "DOCKER_CONFIG=$work/docker" "TMPDIR=$work/tmp" "TUF_ROOT=$work/tuf-unused"
  COSIGN_PASSWORD= HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost
  https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 no_proxy=127.0.0.1,localhost)
cosign() { "${tools_env[@]}" cosign "$@"; }
helm() { "${tools_env[@]}" helm "$@"; }
# Key-mode signing as the bundle fixtures do: no transparency log or signing
# configuration, plain HTTP only to the loopback registry.
signing=(--yes --tlog-upload=false --use-signing-config=false --allow-http-registry)

quiet() { "$@" > "$work/tmp/quiet.log" 2>&1 || { cat "$work/tmp/quiet.log" >&2; return 1; }; }
(cd "$work/keys" && quiet cosign generate-key-pair --output-key-prefix publisher && quiet cosign generate-key-pair --output-key-prefix other)
fingerprint() { sed '/-----/d' "$1" | base64 -d | sha256sum | cut -d' ' -f1; }
jq -n --arg publisher "sha256:$(fingerprint "$work/keys/publisher.pub")" --arg other "sha256:$(fingerprint "$work/keys/other.pub")" \
  '{publisher:$publisher,other:$other,note:"SHA-256 of each public key DER SubjectPublicKeyInfo; the private keys were generated for this run and deleted"}' \
  > "$out/keys.json"

# The image exactly as built and tested: apko's OCI manifest, config and layer.
tar -xf "$images/image.tar" -C "$work/image"
base_manifest=$(jq -er '.manifests | if length == 1 then .[0].digest else error("one image manifest expected") end' "$work/image/index.json")
base_file=$work/image/$base_manifest
[[ sha256:$(sha256sum "$base_file" | cut -d' ' -f1) == "$base_manifest" ]] || { echo "image.tar: manifest $base_manifest does not match its bytes" >&2; exit 1; }
blob_file() { if [[ -f $work/image/$1 ]]; then echo "$work/image/$1"; else echo "$work/image/${1#sha256:}.tar.gz"; fi; }
for d in $(jq -r '.config.digest, .layers[].digest' "$base_file"); do
  [[ sha256:$(sha256sum "$(blob_file "$d")" | cut -d' ' -f1) == "$d" ]] || { echo "image.tar: blob $d does not match its bytes" >&2; exit 1; }
done

sha() { sha256sum "$1" | cut -d' ' -f1; }
deplog=$images/build-dependencies.json.x86_64
[[ -s $deplog ]] || deplog=$images/build-dependencies.json
# committed PATH: the SHA-256 of PATH at the image's source commit.
committed() {
  git cat-file -e "$commit:$1" 2>/dev/null || { echo "$1 is not in the image's source commit $commit" >&2; return 1; }
  git show "$commit:$1" | sha256sum | cut -d' ' -f1
}
melange_sum=$(committed "$recipe/melange.yaml")
apko_sum=$(committed "$recipe/apko.yaml")
# SLSA provenance v1 predicates ("Reference provenance v1" in the guide).
image_predicate() { # BUILDER OUT
  jq -n --arg buildType "$build_type" --arg repo "$source_repo" --arg commit "$commit" --arg builder "$1" --arg run "$run" \
    --arg melange "$melange_sum" --arg apko "$apko_sum" \
    --arg spdx "$(sha "$images/sbom-x86_64.spdx.json")" --arg syft "$(sha "$images/sbom-complete.spdx.json")" \
    --arg deps "$(sha "$deplog")" --arg depsName "$(basename "$deplog")" --arg recipe "$recipe" '
    {buildDefinition:{buildType:$buildType,
      externalParameters:{artifact:"image",source:{repository:$repo,commit:$commit},recipe:$recipe},
      resolvedDependencies:[
        {name:"source",uri:("git+"+$repo+"@"+$commit),digest:{gitCommit:$commit}},
        {name:"melange.yaml",uri:("git+"+$repo+"@"+$commit+"#"+$recipe+"/melange.yaml"),digest:{sha256:$melange}},
        {name:"apko.yaml",uri:("git+"+$repo+"@"+$commit+"#"+$recipe+"/apko.yaml"),digest:{sha256:$apko}}]},
     runDetails:{builder:{id:$builder},metadata:{invocationId:$run},
      byproducts:[{name:"sbom-x86_64.spdx.json",digest:{sha256:$spdx}},{name:"sbom-complete.spdx.json",digest:{sha256:$syft}},
        {name:$depsName,digest:{sha256:$deps}}]}}' > "$2"
}
chart_predicate() { # ARCHIVE IMAGE OUT
  local version=${1##*/example-reporting-provider-}
  jq -n --arg buildType "$build_type" --arg repo "$source_repo" --arg commit "$commit" --arg builder "$BUILDER" --arg run "$run" \
    --arg chart "$chart_src" --arg version "${version%.tgz}" --arg image "$2" --arg archive "$(sha "$1")" --arg file "$(basename "$1")" '
    ($image | split("@")) as [$repository, $digest] |
    {buildDefinition:{buildType:$buildType,
      externalParameters:{artifact:"chart",source:{repository:$repo,commit:$commit},
        chart:{path:$chart,name:"example-reporting-provider",version:$version},image:{repository:$repository,digest:$digest}},
      resolvedDependencies:[
        {name:"source",uri:("git+"+$repo+"@"+$commit+"#"+$chart),digest:{gitCommit:$commit}},
        {name:"image",uri:("oci://"+$repository),digest:{sha256:($digest | ltrimstr("sha256:"))}}]},
     runDetails:{builder:{id:$builder},metadata:{invocationId:$run},byproducts:[{name:$file,digest:{sha256:$archive}}]}}' > "$3"
}
image_predicate "$BUILDER" "$work/image-provenance.json"
image_predicate "$other_builder" "$work/image-provenance-other-builder.json"

# Registry access over loopback HTTP (curl talks only to $reg).
start_registry() { # KIND; sets reg
  local kind=$1 name=$run-$1 port
  case $kind in
    distribution) docker run -d --name "$name" "${labels[@]}" -p 127.0.0.1::5000 "$KONSTAPEL_REGISTRY_IMAGE" >/dev/null ;;
    zot)
      mkdir -p "$work/zot"
      printf '%s\n' '{"distSpecVersion":"1.1.0","storage":{"rootDirectory":"/var/lib/zot"},"http":{"address":"0.0.0.0","port":"5000"},"log":{"level":"error"}}' > "$work/zot/config.json"
      chmod 755 "$work/zot"
      chmod 644 "$work/zot/config.json"
      docker run -d --name "$name" "${labels[@]}" -p 127.0.0.1::5000 -v "$work/zot:/etc/konstapel-zot:ro" \
        "$KONSTAPEL_REGISTRY_API_IMAGE" serve /etc/konstapel-zot/config.json >/dev/null ;;
  esac
  port=$(docker port "$name" 5000/tcp | head -1 | sed 's/.*://')
  reg=127.0.0.1:$port
  for _ in $(seq 150); do
    curl -fsS "http://$reg/v2/" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  docker logs "$name" >&2 || true
  echo "registry $name is not serving" >&2
  return 1
}
push_blob() { # REPO FILE DIGEST
  local loc sep
  curl -fsS -o /dev/null -I "http://$reg/v2/$1/blobs/$3" 2>/dev/null && return 0
  loc=$(curl -fsS -X POST -D - -o /dev/null "http://$reg/v2/$1/blobs/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
  case $loc in http*) ;; *) loc=http://$reg$loc ;; esac
  sep='?'
  [[ $loc != *\?* ]] || sep='&'
  curl -fsS -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@$2" "$loc${sep}digest=$3" >/dev/null
}
push_manifest() { # REPO FILE MEDIA_TYPE [TAG]; prints the digest the registry stored
  local d got
  d=sha256:$(sha "$2")
  got=$(curl -fsS -X PUT -H "Content-Type: $3" --data-binary "@$2" -D - -o /dev/null "http://$reg/v2/$1/manifests/${4:-$d}" |
    tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
  [[ $got == "$d" ]] || { echo "the registry stored $2 as '$got', not $d" >&2; return 1; }
  echo "$d"
}
# image_variant NAME: the tested image under another manifest digest (one
# more annotation; the same config and layer). "valid" is the tested image.
image_variant() {
  local file=$work/variants/$1.json
  mkdir -p "$work/variants"
  if [[ $1 == valid ]]; then
    cp "$base_file" "$file"
  else
    jq -c --arg c "$1" '.annotations["konstapel.fixture"] = $c' "$base_file" > "$file"
  fi
  push_manifest "$image_repo" "$file" application/vnd.oci.image.manifest.v1+json
}
# referrers REPO DIGEST: the subject's referrers as an image index, from the
# referrers API or else the tag schema index (an empty index if neither).
referrers() {
  local tmp=$work/tmp/referrers.json code
  code=$(curl -sS -o "$tmp" -w '%{http_code}' -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/$1/referrers/$2")
  if [[ $code == 200 ]]; then cat "$tmp"; return 0; fi
  code=$(curl -sS -o "$tmp" -w '%{http_code}' -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/$1/manifests/sha256-${2#sha256:}")
  if [[ $code == 200 ]]; then cat "$tmp"; else echo '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'; fi
}
# copy_proofs REPO FROM TO all|attestations: attach FROM's proof manifests,
# unchanged but for their subject, to TO, as an attacker with write access
# to the repository could. Without a referrers API the tag schema index is
# updated too.
copy_proofs() {
  local repo=$1 from=$2 to=$3 mode=$4 size m pt file nd entries='[]' before after
  before=$(referrers "$repo" "$to" | jq '.manifests | length')
  size=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/$repo/manifests/$to" | wc -c)
  for r in $(referrers "$repo" "$from" | jq -r '.manifests[].digest'); do
    m=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/$repo/manifests/$r")
    pt=$(jq -r '.annotations["dev.sigstore.bundle.predicateType"] // ""' <<<"$m")
    [[ $mode == all || $pt != "$sign_kind" ]] || continue
    file=$work/tmp/copied-${r#sha256:}.json
    jq -c --arg d "$to" --argjson s "$size" '.subject.digest = $d | .subject.size = $s' <<<"$m" > "$file"
    nd=$(push_manifest "$repo" "$file" application/vnd.oci.image.manifest.v1+json)
    entries=$(jq -c --arg d "$nd" --argjson s "$(wc -c < "$file")" --slurpfile f "$file" \
      '. + [{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$d,size:$s,artifactType:$f[0].artifactType,annotations:$f[0].annotations}]' <<<"$entries")
  done
  [[ $entries != '[]' ]] || { echo "no proofs to copy from $from" >&2; return 1; }
  if [[ $(curl -sS -o /dev/null -w '%{http_code}' "http://$reg/v2/$repo/referrers/$to") != 200 ]]; then
    referrers "$repo" "$to" | jq -c --argjson add "$entries" '.manifests += $add' > "$work/tmp/tag-index.json"
    push_manifest "$repo" "$work/tmp/tag-index.json" application/vnd.oci.image.index.v1+json "sha256-${to#sha256:}" >/dev/null
  fi
  # The copies are listed where Cosign looks, so a rejection is Cosign's.
  after=$(referrers "$repo" "$to" | jq '.manifests | length')
  [[ $after == $((before + $(jq length <<<"$entries"))) ]] || { echo "copied proofs for $to are not listed ($before before, $after after)" >&2; return 1; }
}
sign() { quiet cosign sign "${signing[@]}" --key "$work/keys/$1.key" "$2"; }
attest() { quiet cosign attest "${signing[@]}" --key "$work/keys/$1.key" --type "$2" --predicate "$3" "$4"; }
attest_image() { # KEY REF [PROVENANCE]
  attest "$1" spdxjson "$images/sbom-x86_64.spdx.json" "$2"
  attest "$1" spdxjson "$images/sbom-complete.spdx.json" "$2"
  attest "$1" slsaprovenance1 "${3:-$work/image-provenance.json}" "$2"
}
# package_chart NAME VERSION IMAGE: the reference chart with its default
# image set to IMAGE (repository@digest), as release packaging pins the
# controller chart's image; prints the archive.
package_chart() {
  local dir=$work/charts/$registry/$1 values
  mkdir -p "$dir"
  cp -a "$chart_src" "$dir/src"
  cp LICENSE NOTICE "$dir/src/"
  values=$dir/src/values.yaml
  [[ $(grep -c '^  digest: ""$' "$values") == 1 && $(grep -c '^  repository: localhost/konstapel-example-reporting$' "$values") == 1 ]] ||
    { echo "$chart_src/values.yaml: expected one default image repository and one empty digest" >&2; return 1; }
  sed -i -e "s|^  digest: \"\"\$|  digest: \"${3#*@}\"|" -e "s|^  repository: localhost/konstapel-example-reporting\$|  repository: ${3%@*}|" "$values"
  helm lint --strict "$dir/src" --set 'worker.authorizedHosts[0]=probe.example.test' --set 'evaluator.authorizedHosts[0]=probe.example.test' >/dev/null
  helm package "$dir/src" --version "$2" --destination "$dir" >/dev/null
  echo "$dir/example-reporting-provider-$2.tgz"
}
push_chart() { # ARCHIVE; prints repository@digest
  local d
  d=$(helm push "$1" "oci://$reg/charts" --plain-http 2>&1 | sed -n 's/^Digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p')
  [[ -n $d ]] || { echo "helm push $1 reported no digest" >&2; return 1; }
  echo "$reg/charts/example-reporting-provider@$d"
}

# The documented procedure (see $doc). Each step announces itself, so a
# rejection is attributed to the step that refused it.
step() { echo "step: $1"; }
verify_image() { # IMAGE
  local IMAGE=$1
  step image-signature
  cosign verify "${TRUST[@]}" "$IMAGE" > image-signature.json
  step image-signature-kind
  jq -e --arg digest "${IMAGE#*@}" 'type == "array" and any(.[]; .critical.type == "https://sigstore.dev/cosign/sign/v1" and .critical.image."docker-manifest-digest" == $digest)' image-signature.json
  step image-sbom
  cosign verify-attestation "${TRUST[@]}" --type spdxjson "$IMAGE" > image-sbom.jsonl
  step image-provenance
  cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$IMAGE" > image-provenance.jsonl
  step image-provenance-builder
  jq -se --arg builder "$BUILDER" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == $builder)' image-provenance.jsonl
  step accepted
}
verify_release() { # CHART; prints the verified image
  local CHART=$1 IMAGE
  step chart-signature
  cosign verify "${TRUST[@]}" "$CHART" > chart-signature.json
  step chart-signature-kind
  jq -e --arg digest "${CHART#*@}" 'type == "array" and any(.[]; .critical.type == "https://sigstore.dev/cosign/sign/v1" and .critical.image."docker-manifest-digest" == $digest)' chart-signature.json
  step chart-provenance
  cosign verify-attestation "${TRUST[@]}" --type slsaprovenance1 "$CHART" > chart-provenance.jsonl
  step chart-provenance-builder
  jq -se --arg builder "$BUILDER" 'any(.[].payload | @base64d | fromjson; .predicate.runDetails.builder.id == $builder)' chart-provenance.jsonl
  step chart-pull
  mkdir chart
  helm pull "oci://$CHART" "${PULL[@]}" --destination chart
  step chart-image
  IMAGE=$(helm template ref chart/*.tgz --set 'worker.authorizedHosts[0]=probe.example.test' --set 'evaluator.authorizedHosts[0]=probe.example.test' | sed -n 's/^ *image: //p' | sort -u)
  [[ $IMAGE =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]
  echo "image: $IMAGE"
  verify_image "$IMAGE"
}

# The controller image's signature check: `cosign verify` under the trust,
# then the payload check of scripts/image/verify-signature-payload.sh for
# SUBJECT (default IMAGE). Cosign v3's `cosign verify` alone also accepts
# the publisher's attestations as signatures; this pins that behaviour.
verify_controller_signature() { # IMAGE [SUBJECT]
  step controller-signature
  cosign verify "${TRUST[@]}" "$1" > signature.json
  step controller-signature-payload
  "$root/scripts/image/verify-signature-payload.sh" signature.json "${2:-$1}"
  step accepted
}

results=$work/results.jsonl
failures=0
# expect CASE accept|reject STEP DESCRIPTION COMMAND...: run COMMAND in a
# fresh directory whose publisher.pub is the key the operator trusts (the
# publisher's, or $trusted) and record whether it ended at STEP as expected.
expect() {
  local name=$1 want=$2 at=$3 what=$4 dir=$work/cases/$registry/$1 code got last passed
  shift 4
  mkdir -p "$dir"
  cp "$work/keys/${trusted:-publisher}.pub" "$dir/publisher.pub"
  set +e
  (set -e; cd "$dir"; "$@") > "$dir/log" 2>&1
  code=$?
  set -e
  if [[ $code == 0 ]]; then got=accept; else got=reject; fi
  last=$(sed -n 's/^step: //p' "$dir/log" | tail -1)
  passed=false
  [[ $got != "$want" || $last != "$at" ]] || passed=true
  [[ $passed == true ]] || failures=$((failures + 1))
  jq -nc --arg registry "$registry" --arg case "$name" --arg description "$what" --arg expected "$want" --arg outcome "$got" \
    --arg expectedStep "$at" --arg step "$last" --argjson passed "$passed" --arg detail "$(grep -v '^step: ' "$dir/log" | tail -c 400)" \
    '{registry:$registry,case:$case,description:$description,expected:$expected,outcome:$outcome,expectedStep:$expectedStep,step:$step,passed:$passed,detail:$detail}' >> "$results"
  printf '%-12s %-34s expected %s at %s, got %s at %s%s\n' "$registry" "$name" "$want" "$at" "$got" "$last" "$([[ $passed == true ]] || echo '  <-- FAILED')"
}
# The fixture's trust and pull options, as documented.
TRUST=(--key publisher.pub --insecure-ignore-tlog=true --allow-http-registry)
PULL=(--plain-http)

for registry in distribution zot; do
  start_registry "$registry"
  image_repo=reference/example-reporting
  for d in $(jq -r '.config.digest, .layers[].digest' "$base_file"); do push_blob "$image_repo" "$(blob_file "$d")" "$d"; done

  # The release: the tested image, signed, with both SBOMs and provenance,
  # and a chart pinning it, signed, with provenance.
  valid=$(image_variant valid)
  [[ $valid == "$base_manifest" ]] || { echo "$registry stored the tested image as $valid, not $base_manifest" >&2; exit 1; }
  image=$reg/$image_repo@$valid
  sign publisher "$image"
  attest_image publisher "$image"
  archive=$(package_chart valid 0.1.0 "$image")
  chart=$(push_chart "$archive")
  chart_predicate "$archive" "$image" "$work/chart-provenance.json"
  sign publisher "$chart"
  attest publisher slsaprovenance1 "$work/chart-provenance.json" "$chart"

  # Image fixtures, each another digest of the same image.
  other=$reg/$image_repo@$(image_variant other-publisher)
  sign other "$other"
  attest_image other "$other"
  unsigned=$reg/$image_repo@$(image_variant unsigned)
  attestations_only=$reg/$image_repo@$(image_variant attestations-only)
  attest_image publisher "$attestations_only"
  signature_only=$reg/$image_repo@$(image_variant signature-only)
  sign publisher "$signature_only"
  other_builder_image=$reg/$image_repo@$(image_variant other-builder)
  sign publisher "$other_builder_image"
  attest_image publisher "$other_builder_image" "$work/image-provenance-other-builder.json"
  copied=$(image_variant copied-proofs)
  copy_proofs "$image_repo" "$valid" "$copied" all
  copied_attestations=$(image_variant copied-attestations)
  sign publisher "$reg/$image_repo@$copied_attestations"
  copy_proofs "$image_repo" "$valid" "$copied_attestations" attestations

  # Chart fixtures: each a distinct archive (version) signed as stated.
  pins_unsigned_archive=$(package_chart pins-unsigned 0.1.0-fixture.pins-unsigned-image "$unsigned")
  pins_unsigned=$(push_chart "$pins_unsigned_archive")
  chart_predicate "$pins_unsigned_archive" "$unsigned" "$work/chart-provenance-pins-unsigned.json"
  sign publisher "$pins_unsigned"
  attest publisher slsaprovenance1 "$work/chart-provenance-pins-unsigned.json" "$pins_unsigned"
  chart_unsigned=$(push_chart "$(package_chart unsigned 0.1.0-fixture.unsigned "$image")")
  chart_signature_only=$(push_chart "$(package_chart signature-only 0.1.0-fixture.signature-only "$image")")
  sign publisher "$chart_signature_only"
  chart_other_archive=$(package_chart other-publisher 0.1.0-fixture.other-publisher "$image")
  chart_other=$(push_chart "$chart_other_archive")
  chart_predicate "$chart_other_archive" "$image" "$work/chart-provenance-other.json"
  sign other "$chart_other"
  attest other slsaprovenance1 "$work/chart-provenance-other.json" "$chart_other"

  expect valid-release accept accepted "the signed chart, the image it pins, its SBOMs and provenance" verify_release "$chart"
  expect image-other-publisher reject image-signature "an image signed and attested only by another key" verify_image "$other"
  trusted=other expect image-untrusted-key reject image-signature "the valid image verified under a key the publisher does not use" verify_image "$image"
  expect image-unsigned reject image-signature "an image digest with no proofs" verify_image "$unsigned"
  expect image-attestations-only reject image-signature-kind "attestations by the publisher but no signature" verify_image "$attestations_only"
  expect image-signature-only reject image-sbom "a signature but no SBOM or provenance" verify_image "$signature_only"
  expect image-other-builder reject image-provenance-builder "signed and attested by the publisher, provenance from another builder" verify_image "$other_builder_image"
  expect image-copied-proofs reject image-signature "the valid image's proofs attached to another digest" verify_image "$reg/$image_repo@$copied"
  expect image-copied-attestations reject image-sbom "its own signature, attestations copied from the valid image" verify_image "$reg/$image_repo@$copied_attestations"
  expect chart-pins-unsigned-image reject image-signature "a signed chart with provenance pinning an unsigned image digest" verify_release "$pins_unsigned"
  expect chart-unsigned reject chart-signature "a chart with no proofs" verify_release "$chart_unsigned"
  expect chart-signature-only reject chart-provenance "a signed chart without provenance" verify_release "$chart_signature_only"
  expect chart-other-publisher reject chart-signature "a chart signed and attested by another key" verify_release "$chart_other"
  expect controller-check-valid accept accepted "the controller image signature check on the valid image" verify_controller_signature "$image"
  expect controller-check-attestations-only reject controller-signature-payload "attestations by the publisher but no signature: plain cosign verify accepts, the payload check rejects" verify_controller_signature "$attestations_only"
  expect controller-check-other-subject reject controller-signature-payload "the valid image's verified payloads required for another digest" verify_controller_signature "$image" "$attestations_only"

  # The accepted release's evidence: what was verified and the image the
  # chart runs (its digest is the registration's releaseDigest).
  v=$work/cases/$registry/valid-release
  r=$out/$registry
  mkdir -p "$r"
  if [[ -s $v/image-provenance.jsonl ]]; then
    [[ $(sed -n 's/^image: //p' "$v/log") == "$image" ]] || { echo "$registry: the chart ran $(sed -n 's/^image: //p' "$v/log"), not $image" >&2; failures=$((failures + 1)); }
    cp "$v/chart-signature.json" "$v/image-signature.json" "$r/"
    for f in chart-provenance image-provenance image-sbom; do
      jq -c '.payload | @base64d | fromjson' "$v/$f.jsonl" > "$r/$f.statements.jsonl"
    done
    # The SBOM statements without their (large) documents.
    jq -c '{predicateType, subject, predicate: {spdxVersion: .predicate.spdxVersion, name: .predicate.name, packages: (.predicate.packages | length)}}' \
      "$r/image-sbom.statements.jsonl" > "$r/image-sbom.summary.jsonl"
    rm "$r/image-sbom.statements.jsonl"
  fi
  jq -n --arg registry "$registry" --arg image "$image" --arg chart "$chart" --arg archive "sha256:$(sha "$archive")" \
    --arg referrers "$( [[ $(curl -sS -o /dev/null -w '%{http_code}' "http://$reg/v2/$image_repo/referrers/$valid") == 200 ]] && echo api || echo tag-schema)" \
    '{registry:$registry,image:$image,chart:$chart,chartArchive:$archive,referrersListing:$referrers,releaseDigest:($image | split("@")[1])}' > "$r/release.json"
  docker rm -fv "$run-$registry" >/dev/null
done

cp "$work/image-provenance.json" "$out/image-provenance.predicate.json"
cp "$work/chart-provenance.json" "$out/chart-provenance.predicate.json"
for registry in distribution zot; do cp "$work/cases/$registry/valid-release/log" "$out/$registry/valid-release.log"; done
versions=$(jq -n --arg cosign "$(cosign version --json 2>/dev/null | jq -r .gitVersion)" --arg helm "$(helm version --template '{{.Version}}')" \
  --arg distribution "$KONSTAPEL_REGISTRY_IMAGE" --arg zot "$KONSTAPEL_REGISTRY_API_IMAGE" '{cosign:$cosign,helm:$helm,registries:{distribution:$distribution,zot:$zot}}')
jq -s --arg commit "$commit" --arg builder "$BUILDER" --argjson versions "$versions" --argjson failures "$failures" \
  '{source:{commit:$commit},builder:$builder,tools:$versions,passed:($failures == 0 and length > 0 and all(.[]; .passed)),cases:.}' "$results" \
  > "$out/reference-provider-signing.json"
cleanup
trap - EXIT
leftover=$(docker ps -aq --filter "label=konstapel.test=$run")
[[ -z $leftover ]] || { echo "registry containers of $run were not removed: $leftover" >&2; exit 1; }
if [[ $(jq -r .passed "$out/reference-provider-signing.json") != true ]]; then
  echo "reference provider signing: $failures case(s) did not end as expected; see $out/reference-provider-signing.json" >&2
  exit 1
fi
echo "reference provider signing: $(jq '.cases | length' "$out/reference-provider-signing.json") cases as expected on both registries; evidence in $out; registries and keys removed"
