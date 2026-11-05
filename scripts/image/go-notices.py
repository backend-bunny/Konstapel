#!/usr/bin/env python3
"""Record the source and license texts for modules linked by the two commands."""
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run(*args):
    return subprocess.check_output(args, text=True)


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        obj, end = decoder.raw_decode(text.lstrip())
        yield obj
        text = text.lstrip()[end:]


def escape(value):
    return ''.join('!' + c.lower() if c.isupper() else c for c in value)


def main(output):
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64')
    os.environ.update(env)
    modules = {}
    for pkg in objects(run('go', 'list', '-mod=readonly', '-deps', '-json', './cmd/...')):
        if module := pkg.get('Module'):
            if module.get('Replace'):
                raise SystemExit('Module replacements need explicit source attribution before image builds')
            modules[module['Path']] = module
    report = run('go-licenses', 'report', './cmd/...')
    (out / 'go-licenses.csv').write_text(report)
    subprocess.run(['go-licenses', 'save', './cmd/...', '--save_path', str(out / 'licenses')], check=True)
    licenses = {path: set() for path in modules}
    for library, _, license_id in csv.reader(report.splitlines()):
        match = max((m for m in modules if library == m or library.startswith(m + '/')), key=len)
        licenses[match].add(license_id)
    entries = []
    for path, module in sorted(modules.items()):
        if module.get('Main'):
            version = os.environ['KONSTAPEL_SOURCE_COMMIT']
            source, checksum = 'https://github.com/backend-bunny/Konstapel', ''
            ref = version
        else:
            version = module['Version']
            data = json.loads(run('go', 'mod', 'download', '-json', path + '@' + version))
            if data.get('Error') or not data.get('Sum') or not data.get('Zip'):
                raise SystemExit(f'No verified module source: {path}@{version}')
            source = f'https://proxy.golang.org/{escape(path)}/@v/{escape(version)}.zip'
            checksum = 'sha256:' + hashlib.sha256(Path(data['Zip']).read_bytes()).hexdigest()
            ref = data['Sum']
        files = []
        root = out / 'licenses' / path
        for file in sorted(root.rglob('*')):
            if file.is_file() and re.match(r'(?i)^(licen[cs]e|notice|copying|copyright|unlicense)', file.name):
                files.append('usr/share/doc/konstapel/' + file.relative_to(out).as_posix())
        if not files:
            raise SystemExit(f'No license text collected for {path}')
        detected = sorted(licenses[path])
        entries.append(dict(name=path, version=version, purl=f'pkg:golang/{path}@{version}',
                            source=source, ref=ref, checksum=checksum,
                            license=detected[0] if len(detected) == 1 else 'NOASSERTION',
                            detectedLicenses=detected, noticeFiles=files))
    # Keep the shipped content's own attribution, independent of the code license.
    provenance = json.loads(Path('content/provenance.json').read_text())
    for name, repo, revision, license_id, file in [
        ('kyverno-policy-content', provenance['policyRepository'], provenance['policyRevision'],
         provenance['policyLicense'], 'content/upstream/kyverno/LICENSE'),
        ('nist-oscal-content', provenance['nistRepository'], provenance['nistRevision'],
         'CC0-1.0', 'content/upstream/nist/LICENSE.md'),
    ]:
        entries.append(dict(name=name, version=revision, source=repo, ref=revision,
                            license=license_id, noticeFiles=['usr/share/konstapel/' + file]))
    (out / 'bundled-sources.json').write_text(json.dumps(entries, indent=2) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
