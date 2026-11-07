# Shared image build functions; callers run from the repository root.
IMAGE=ghcr.io/backend-bunny/konstapel
MELANGE_RUNNER=${MELANGE_RUNNER:-bubblewrap}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export KONSTAPEL_SOURCE_COMMIT=$(git rev-parse HEAD)

export_source() {
  local dest=$1 file
  mkdir -p "$dest"
  git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' file; do
      [[ ! -f $file && ! -L $file ]] || printf '%s\0' "$file"
    done | tar --null --files-from=- -cf - | tar -xf - -C "$dest"
}

build_package() {
  local tmp=$1 go_series
  go_series=$(go mod edit -json | jq -r '.Go | split(".")[0:2] | join(".")')
  mkdir -p "$tmp/key" .cache/image/go .cache/image/apk
  rm -rf packages
  (cd "$tmp/key" && melange keygen)
  export_source "$tmp/src"
  (
    cd "$tmp/src"
    go mod download
    go mod verify
    # License collection needs module-cache paths, so run before vendoring.
    python3 scripts/image/go-notices.py image-notices
    go mod vendor
  )
  melange build melange.yaml --arch x86_64 --runner "$MELANGE_RUNNER" --package-append "go-$go_series" \
    --source-dir "$tmp/src" --cache-dir .cache/image/go --apk-cache-dir .cache/image/apk \
    --git-repo-url https://github.com/backend-bunny/Konstapel --git-commit "$KONSTAPEL_SOURCE_COMMIT" --namespace backend-bunny \
    --license Apache-2.0 --signing-key "$tmp/key/melange.rsa" --out-dir packages \
    --generate-provenance --dependency-log out/image/build-dependencies.json
  cp "$tmp/key/melange.rsa.pub" out/image/melange.rsa.pub
  rm -rf "$tmp/key"
  melange test melange.yaml --arch x86_64 --runner "$MELANGE_RUNNER" \
    --repository-append ./packages --keyring-append out/image/melange.rsa.pub \
    --repository-append https://packages.wolfi.dev/os \
    --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
}

fresh_lock() {
  apko lock apko.yaml --arch x86_64 --keyring-append out/image/melange.rsa.pub --output "$1"
}
