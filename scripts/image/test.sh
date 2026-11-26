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
files = dict(image_files('out/image/image.tar', lambda p: p in ('bin/sh', 'usr/bin/sh', 'sbin/apk', 'usr/bin/apk', 'usr/share/konstapel/NOTICE') or Path(p).name.startswith('kubectl')))
assert 'usr/share/konstapel/NOTICE' in files, 'NOTICE missing from image'
assert not any(p in files for p in ('bin/sh', 'usr/bin/sh', 'sbin/apk', 'usr/bin/apk')), 'Unexpected shell/package manager'
assert not any(Path(p).name.startswith('kubectl') for p in files), 'Unexpected kubectl binary (including versioned names)'
sbom = json.loads(Path('out/image/sbom-complete.spdx.json').read_text())
assert not any(p['name'].startswith('kubectl') for p in sbom['packages']), 'kubectl package remains in SBOM'
assert any(p['name'] == 'github.com/oscal-compass/compliance-to-policy-go/v2' for p in sbom['packages']), 'C2P module missing from SBOM'
# The test-only reporting provider and the conformance harness never ship
# (add-assessment-provider-contract 4.3): no Konstapel file in the image,
# binaries, plugin manifest or content, carries their package paths or
# identities (internal/provider/installed checks the same markers before
# the image is built).
markers = [b'internal/provider/reporttest', b'internal/provider/conformance', b'konstapel-reporttest', b'reporttest.konstapel.io']
payload = dict(image_files('out/image/image.tar', lambda p: p.startswith('usr/share/konstapel/')))
for name in ('usr/share/konstapel/bin/konstapel', 'usr/share/konstapel/bin/konstapel-provider', 'usr/share/konstapel/bin/c2p-konstapel-kyverno-manifest.json'):
    assert name in payload, f'{name} missing from image'
assert json.loads(payload['usr/share/konstapel/bin/c2p-konstapel-kyverno-manifest.json'])['metadata']['id'] == 'konstapel-kyverno', 'unexpected C2P plugin manifest'
leaks = sorted({(p, m.decode()) for p, data in payload.items() for m in markers if m in data})
assert not leaks, f'test-only provider shipped in the image: {leaks}'
PY
cp out/image/build.sha256 out/image/tested.sha256
