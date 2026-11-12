#!/usr/bin/env python3
"""Record the source and license texts for modules linked by the two commands.

Every linked module must have a license that go-licenses identifies, except
the exact module versions in LICENSE_OVERRIDES: their root LICENSE is only the
short Apache-2.0 notice, which the classifier does not identify. For those,
and only those, go-licenses is told to skip the module, the notice is copied
from the checksum-verified module archive and must match its pinned sha256,
and the full Apache-2.0 text is shipped beside it. Any other module whose
license is unknown fails the build, and so does a listed module at another
version or with another LICENSE file, until the override is reviewed.
"""
import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile


# Exact module@version -> reviewed license facts. Review a version bump by
# reading the new module's LICENSE (and any NOTICE) in its module archive,
# then updating the version and the sha256 here (docs/images.md).
LICENSE_OVERRIDES = {
    ('github.com/in-toto/in-toto-golang', 'v0.11.0'): dict(
        license='Apache-2.0', file='LICENSE',
        sha256='b5c26c8a2ad6dd7cac6646e470a32ee42d23c36124caac4e66c989b6545b2a44',
        reason='root LICENSE is the standard Apache-2.0 notice (560 bytes), not the license text; '
               'go-licenses cannot classify it'),
    ('github.com/in-toto/attestation', 'v1.2.0'): dict(
        license='Apache-2.0', file='LICENSE',
        sha256='b3a6ac899861c2c28a1abd5c7ea8733fefaed6938d730e099c42671386032aeb',
        reason='root LICENSE is the standard Apache-2.0 notice (559 bytes), not the license text; '
               'go-licenses cannot classify it'),
    ('github.com/cyberphone/json-canonicalization', 'v0.0.0-20241213102144-19d51d7fe467'): dict(
        license='Apache-2.0', file='LICENSE',
        sha256='6821faaddedf2d78c95bb6d98b127e9e616097afd2f6bcc34389f000d13ab12d',
        reason='root LICENSE is the standard Apache-2.0 notice (600 bytes), not the license text; '
               'go-licenses cannot classify it'),
}

# The full Apache License 2.0 text (apache.org LICENSE-2.0.txt), shipped with
# every override whose notice refers to it.
LICENSE_TEXTS = {
    'Apache-2.0': ('scripts/image/licenses/Apache-2.0.txt',
                   'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'),
}

UNKNOWN = {'', 'Unknown'}


def run(*args):
    return subprocess.check_output(args, text=True)


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        obj, end = decoder.raw_decode(text.lstrip())
        yield obj
        text = text.lstrip()[end:]


def shipped_commands(build_script='scripts/build.sh'):
    """The commands the image ships: exactly those scripts/build.sh builds.

    Build-only tools under cmd/ (bundle packaging and release) are not in the
    image, so their dependencies must neither be scanned nor attributed here.
    """
    commands = re.findall(r'^go build (?:-ldflags "[^"\n]*" )?-o bin/\S+ (\./cmd/\S+)$',
                          Path(build_script).read_text(), re.M)
    if not commands:
        raise SystemExit('No shipped commands found in scripts/build.sh')
    return commands


def escape(value):
    return ''.join('!' + c.lower() if c.isupper() else c for c in value)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def zip_h1(path):
    """The go.sum h1: hash of a module zip (golang.org/x/mod/sumdb/dirhash Hash1)."""
    with zipfile.ZipFile(path) as z:
        names = sorted(z.namelist())
        summary = ''.join(f'{sha256(z.read(n))}  {n}\n' for n in names)
    return 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def gosum_h1(gosum, path, version):
    for line in gosum.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == path and fields[1] == version:
            return fields[2]
    raise SystemExit(f'{path}@{version} is not in go.sum')


def applicable_overrides(modules, overrides=LICENSE_OVERRIDES):
    """The overrides for the linked modules, keyed by path.

    A linked module whose path has an override at another version fails: the
    new version's license files have not been reviewed. go-licenses' --ignore
    matches package path prefixes, so a linked module that merely shares a
    prefix with an override path also fails rather than being skipped.
    """
    by_path = {}
    for (path, version), o in overrides.items():
        by_path.setdefault(path, {})[version] = o
    out = {}
    for path, module in modules.items():
        versions = by_path.get(path)
        if versions is not None:
            if module.get('Version') not in versions:
                raise SystemExit(f'License override for {path} is reviewed for {", ".join(sorted(versions))}, '
                                 f'but {module.get("Version")} is linked: review its license and update '
                                 'LICENSE_OVERRIDES in scripts/image/go-notices.py')
            out[path] = versions[module['Version']]
            continue
        for other in by_path:
            if path.startswith(other):
                raise SystemExit(f'{path} shares the prefix of the license override {other}; '
                                 'go-licenses --ignore would skip it')
    return out


def owner(library, modules):
    return max((m for m in modules if library == m or library.startswith(m + '/')), key=len)


def classify(report, modules, overrides):
    """Licenses per module from the go-licenses report.

    Every linked module must be identified, except the overridden ones. An
    unknown license fails here, independently of go-licenses' own exit code
    (go-licenses report exits 0 for an unknown license).
    """
    licenses = {path: set() for path in modules}
    for row in csv.reader(report.splitlines()):
        if not row:
            continue
        library, license_id = row[0], row[-1]
        licenses[owner(library, modules)].add(license_id)
    unknown = []
    for path, module in sorted(modules.items()):
        if module.get('Main') or path in overrides:
            continue
        found = licenses[path]
        if not found or found & UNKNOWN:
            unknown.append(f'{path}@{module.get("Version")}')
    if unknown:
        raise SystemExit('Unknown license for linked modules: ' + ', '.join(unknown))
    return licenses


def write_override(out, path, version, override, zip_path, gosum, root='.'):
    """Copy a reviewed module's notice from its verified archive and ship the full text."""
    expected = gosum_h1(gosum, path, version)
    actual = zip_h1(zip_path)
    if actual != expected:
        raise SystemExit(f'Module archive of {path}@{version} does not match go.sum ({actual} != {expected})')
    with zipfile.ZipFile(zip_path) as z:
        try:
            notice = z.read(f'{path}@{version}/{override["file"]}')
        except KeyError:
            raise SystemExit(f'{path}@{version} has no {override["file"]}; review its license override')
    if sha256(notice) != override['sha256']:
        raise SystemExit(f'{override["file"]} of {path}@{version} changed (sha256 {sha256(notice)}, '
                         f'reviewed {override["sha256"]}): review its license override')
    text_path, text_sum = LICENSE_TEXTS[override['license']]
    text = (Path(root) / text_path).read_bytes()
    if sha256(text) != text_sum:
        raise SystemExit(f'{text_path} is not the reviewed {override["license"]} text')
    dest = Path(out) / 'licenses' / path
    dest.mkdir(parents=True, exist_ok=True)
    (dest / override['file']).write_bytes(notice)
    full = dest / f'LICENSE-{override["license"]}.txt'
    full.write_bytes(text)
    return dict(license=override['license'], reason=override['reason'],
                file=override['file'], sha256=override['sha256'], fullText=full.name)


def main(output):
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64')
    os.environ.update(env)
    modules = {}
    shipped = shipped_commands()
    for pkg in objects(run('go', 'list', '-mod=readonly', '-deps', '-json', *shipped)):
        if module := pkg.get('Module'):
            if module.get('Replace'):
                raise SystemExit('Module replacements need explicit source attribution before image builds')
            modules[module['Path']] = module
    overrides = applicable_overrides(modules)
    ignore = [arg for path in sorted(overrides) for arg in ('--ignore', path)]
    report = run('go-licenses', 'report', *shipped, *ignore)
    (out / 'go-licenses.csv').write_text(report)
    licenses = classify(report, modules, overrides)
    subprocess.run(['go-licenses', 'save', *shipped, *ignore, '--save_path', str(out / 'licenses')], check=True)
    gosum = Path('go.sum').read_text()
    entries = []
    for path, module in sorted(modules.items()):
        override = None
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
            checksum = 'sha256:' + sha256(Path(data['Zip']).read_bytes())
            ref = data['Sum']
            if path in overrides:
                override = write_override(out, path, version, overrides[path], data['Zip'], gosum)
        files = []
        root = out / 'licenses' / path
        for file in sorted(root.rglob('*')):
            if file.is_file() and re.match(r'(?i)^(licen[cs]e|notice|copying|copyright|unlicense)', file.name):
                files.append('usr/share/doc/konstapel/' + file.relative_to(out).as_posix())
        if not files:
            raise SystemExit(f'No license text collected for {path}')
        detected = sorted(licenses[path] - UNKNOWN)
        entry = dict(name=path, version=version, purl=f'pkg:golang/{path}@{version}',
                     source=source, ref=ref, checksum=checksum,
                     license=detected[0] if len(detected) == 1 else 'NOASSERTION',
                     detectedLicenses=detected, noticeFiles=files)
        if override:
            entry['license'] = override['license']
            entry['licenseOverride'] = override
        entries.append(entry)
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
