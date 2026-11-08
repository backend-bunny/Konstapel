#!/usr/bin/env bash
# Package both charts for publication from a clean checkout and the verified
# published image digest, then freeze them:
#   scripts/charts/package.sh OUT_DIR sha256:<image digest>
# The charts are copied to an isolated directory, the runtime chart's default
# image digest is set there (source charts never carry one), and LICENSE and
# NOTICE are added to each package. OUT_DIR receives the two archives and
# publication.json, the manifest every later step verifies. OUT_DIR must not
# exist: frozen inputs are never replaced.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?usage: package.sh OUT_DIR sha256:DIGEST}
digest=${2:?usage: package.sh OUT_DIR sha256:DIGEST}
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "image digest must be sha256:<64 hex>, got $digest" >&2; exit 1; }
[[ ! -e $out ]] || { echo "$out exists; frozen chart inputs are never replaced" >&2; exit 1; }
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo 'Chart packaging requires a clean checkout: the manifest records HEAD as the source' >&2
  exit 1
fi
version=$(cat VERSION)
sh scripts/check-version.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -a charts/konstapel-crds charts/konstapel "$work/"
for chart in konstapel-crds konstapel; do
  cp LICENSE NOTICE "$work/$chart/"
done
# Exactly one empty digest line under image: in the source chart.
values=$work/konstapel/values.yaml
[[ $(grep -c '^  digest: ""$' "$values") == 1 ]] || { echo "charts/konstapel/values.yaml: expected one empty image digest" >&2; exit 1; }
sed -i "s|^  digest: \"\"\$|  digest: \"$digest\"|" "$values"
mkdir -p "$out"
for chart in konstapel-crds konstapel; do
  helm lint --strict --namespace konstapel-system "$work/$chart" >/dev/null
  helm package "$work/$chart" --destination "$out" >/dev/null
done
# Packages carry no key material or credentials.
for archive in "$out"/*.tgz; do
  if tar -xzOf "$archive" | grep -aEq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----|aws_secret_access_key|"auths"[[:space:]]*:'; then
    echo "$archive contains key material or credentials" >&2
    exit 1
  fi
done
python3 scripts/charts/manifest.py freeze --archives "$out" --source "$(git rev-parse HEAD)" --tag "v$version" \
  --image-digest "$digest" --tool "helm=$(helm version --template '{{.Version}}')" --out "$out/publication.json"
printf 'Packaged %s\n' "$out"/*.tgz
