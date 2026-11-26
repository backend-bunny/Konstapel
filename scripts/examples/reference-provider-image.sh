#!/usr/bin/env bash
# Build the example reporting provider's image (add-external-assessment-
# providers 5.1) from examples/external-provider/reporting/image the way
# scripts/image/build.sh builds the controller's: export the working tree,
# verify and vendor the example module's Go modules (the public Konstapel
# packages it replaces included), compile in melange's sandbox with module
# network access off, test the package, and assemble a non-root apko image.
#
# Usage: reference-provider-image.sh FRESH_OUTPUT_DIRECTORY
# Writes image.tar (docker archive, tag $REFERENCE_IMAGE:build-amd64; it
# also holds the OCI image manifest), the image SBOMs the controller's
# build makes (apko's SPDX inventory sbom-x86_64.spdx.json and Syft's image
# scan sbom-complete.spdx.json, which finds the binary's Go modules), the
# build-environment log and the source commit. Test/demo only: nothing is
# pushed, signed or published here, and no registration or chart refers to
# it by default; scripts/examples/reference-provider-signing.sh signs and
# attests it in disposable local registries (5.2). Needs bubblewrap with
# unprivileged user namespaces and network access to Wolfi, like
# task image:build.
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/image/lib.sh
REFERENCE_IMAGE=localhost/konstapel-example-reporting
out=${1:?usage: reference-provider-image.sh FRESH_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
if [[ -e $out ]]; then echo 'Output must be a fresh directory' >&2; exit 1; fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out" "$tmp/key" .cache/image/go .cache/image/apk
export_source "$tmp/repo"
module=$tmp/repo/examples/external-provider/reporting
cp LICENSE NOTICE "$module/"
(
  cd "$module"
  go mod download
  go mod verify
  go mod vendor
)
go_series=$(cd "$module" && go mod edit -json | jq -r '.Go | split(".")[0:2] | join(".")')
(cd "$tmp/key" && melange keygen)
melange build "$module/image/melange.yaml" --arch x86_64 --runner "$MELANGE_RUNNER" --package-append "go-$go_series" \
  --source-dir "$module" --cache-dir .cache/image/go --apk-cache-dir .cache/image/apk \
  --git-repo-url https://github.com/backend-bunny/Konstapel --git-commit "$KONSTAPEL_SOURCE_COMMIT" --namespace backend-bunny \
  --license Apache-2.0 --signing-key "$tmp/key/melange.rsa" --out-dir "$tmp/packages" \
  --dependency-log "$out/build-dependencies.json"
melange test "$module/image/melange.yaml" --arch x86_64 --runner "$MELANGE_RUNNER" \
  --repository-append "$tmp/packages" --keyring-append "$tmp/key/melange.rsa.pub" \
  --repository-append https://packages.wolfi.dev/os \
  --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
# apko resolves "@local ./packages" from its working directory.
(
  cd "$tmp"
  apko build "$module/image/apko.yaml" "$REFERENCE_IMAGE:build" "$out/image.tar" --arch x86_64 \
    --keyring-append "$tmp/key/melange.rsa.pub" --sbom-path "$out"
)
rm -rf "$tmp/key"
# As for the controller: apko records the APK and its sources, Syft also
# finds the Go modules embedded in the binary.
SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
  syft scan "docker-archive:$out/image.tar" -o spdx-json="$out/sbom-complete.spdx.json"
git rev-parse HEAD > "$out/commit"
sha256sum "$out/image.tar" > "$out/build.sha256"
echo "built $REFERENCE_IMAGE:build-amd64 into $out/image.tar"
