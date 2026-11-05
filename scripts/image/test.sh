#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/image/lib.sh
docker load -i out/image/image.tar
# Name the exact locally loaded image ID, so cleanup never removes another tag.
id=$(docker image inspect "$IMAGE:build-amd64" --format '{{.Id}}')
trap 'docker image rm "$id" >/dev/null 2>&1 || true' EXIT
test "$(docker image inspect "$id" --format '{{.Config.User}}')" = 65532
options=(--rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev)
docker run "${options[@]}" "$id" generate --output /tmp/generated
docker run "${options[@]}" -v "$PWD/testdata:/evidence:ro" "$id" convert --capture /evidence/capture.json --output /tmp/converted
python3 - <<'PY'
import json
from pathlib import Path
from scripts.image.sources import image_files
files = dict(image_files('out/image/image.tar', lambda p: p in ('bin/sh', 'usr/bin/sh', 'sbin/apk', 'usr/bin/apk', 'usr/bin/kubectl', 'bin/kubectl', 'usr/share/konstapel/NOTICE')))
assert 'usr/share/konstapel/NOTICE' in files, 'NOTICE missing from image'
assert not any(p in files for p in ('bin/sh', 'usr/bin/sh', 'sbin/apk', 'usr/bin/apk', 'usr/bin/kubectl', 'bin/kubectl')), 'Unexpected shell/package manager/kubectl'
sbom = json.loads(Path('out/image/sbom-complete.spdx.json').read_text())
assert any(p['name'] == 'github.com/oscal-compass/compliance-to-policy-go/v2' for p in sbom['packages']), 'C2P module missing from SBOM'
PY
cp out/image/build.sha256 out/image/tested.sha256
