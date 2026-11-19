"""Stage acceptance evidence for upload, failing closed on credentials.

    stage-evidence.py SOURCE DEST [--report FILE]

Copies the regular files of the acceptance output SOURCE into the fresh
directory DEST, leaving out what is never evidence (kubeconfigs, compiled
test binaries, the rendered Kyverno manifest, kind node logs), symlinks and
special files. Every copied file is scanned, including the members of gzip,
tar and zip archives, for credentials: PEM and base64-encoded private keys,
kubeconfig client keys and tokens, bearer/basic authorization, JWTs, cloud
and S3 access keys or credential assignments, registry auths and htpasswd
entries, age and GitHub tokens, Kubernetes Secret data, and files whose names
denote key material.

Any finding removes DEST and exits 1, so CI uploads nothing rather than a
credential (fail closed). Findings name the file, line and rule, never the
matched text. On success DEST/evidence-scan.json lists what was scanned and
left out. Run it directly (devbox run -- python3 scripts/ci/stage-evidence.py);
it is a CI helper behind the acceptance upload steps, not a Task workflow.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import zipfile

# Left out of the upload entirely (not scanned): operational inputs and bulk
# node logs, matched against each path component's name.
EXCLUDED = ("kubeconfig*", "*.test", "helm-manifest.yaml", "kind-logs")
# File names that denote key material regardless of content.
SENSITIVE_NAMES = (
    "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.age", "id_rsa*", "id_ecdsa*", "id_ed25519*",
    "htpasswd", ".htpasswd", ".netrc", ".dockerconfigjson", ".git-credentials", "dev.env", "*.kubeconfig",
)
# Bound decompression so a corrupt or hostile archive cannot exhaust the runner.
MAX_EXPANDED = 512 * 1024 * 1024
MAX_DEPTH = 3

# Values that only stand in for a credential.
PLACEHOLDER = re.compile(
    r"""^(?:<[^>]*>|\*+|x{3,}|\.{3}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{.*\}\}|%[sv]|"""
    r"""(?i:redacted|\[redacted\]|masked|hidden|none|null|nil|true|false|changeme|example\w*|placeholder|unset|empty|required|optional))$""")

TEXT_RULES = [
    ("pem-private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("kubeconfig-client-key", re.compile(rb"""client-key-data["']?\s*[:=]\s*["']?[A-Za-z0-9+/=]{16,}""")),
    ("bearer-token", re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")),
    ("url-credentials", re.compile(rb"\b[a-z][a-z0-9+.-]*://[^\s/:@'\"<>]+:[^\s/@'\"<>]{3,}@[^\s/'\"<>]")),
    ("cloud-access-key-id", re.compile(rb"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("registry-auth", re.compile(rb"""["']auth["']\s*:\s*["'][A-Za-z0-9+/]{8,}={0,2}["']""")),
    ("htpasswd-entry", re.compile(rb"(?m)^[^\s:#]+:(?:\$(?:2[abxy]?|apr1|5|6)\$[./A-Za-z0-9$]{20,}|\{SHA\}[A-Za-z0-9+/]{27}=)")),
    ("age-secret-key", re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{50,}")),
    ("github-token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
]

# Credential assignments whose value is checked against PLACEHOLDER: env
# style (RUSTFS_SECRET_KEY=..., AWS_SECRET_ACCESS_KEY: ...), JSON/YAML fields
# (secretAccessKey, accessKeyID, password, token, ...) and CLI flags.
ASSIGNMENTS = [
    ("kubeconfig-credential", re.compile(rb"""(?m)^\s*(?:token|password)\s*:\s*["']?(?P<value>[^\s"'#]{8,})""")),
    ("credential-variable", re.compile(
        rb"""\b[A-Z0-9_]*(?:SECRET_ACCESS_KEY|SECRET_KEY|ACCESS_KEY(?:_ID)?|SESSION_TOKEN|PASSWORD|PASSWD|PASSPHRASE|API_KEY|"""
        rb"""PRIVATE_KEY|CLIENT_SECRET|_TOKEN|_SECRET)\b["']?\s*[=:]\s*["']?(?P<value>[^\s"'`,;}\]\)]{8,})""")),
    # JSON/YAML fields, log key=value pairs and Go %+v struct dumps.
    ("credential-field", re.compile(
        rb"""(?i)(?<![A-Za-z0-9_.-])["']?(?:secretAccessKey|secretKey|accessKeyID|accessKey|sessionToken|password|passphrase|token|"""
        rb"""clientSecret|privateKey|apiKey|secret_access_key|access_key_id|session_token)["']?\s*[:=]\s*["']?(?P<value>[^"'\s{}\[\](),;]{8,})""")),
    ("credential-flag", re.compile(
        rb"""(?i)--(?:password|passphrase|token|secret-key|access-key|secret-access-key|client-secret|registry-password)(?:=|\s+)["']?(?P<value>[^\s"'-][^\s"']{7,})""")),
]

# "Basic <base64>" counts only when it decodes to printable user:password.
BASIC = re.compile(rb"\b[Bb]asic\s+(?P<value>[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
PEM_B64 = re.compile(rb"LS0tLS1CRUdJT[A-Za-z0-9+/]{20,}={0,2}")
YAML_SECRET = re.compile(rb"(?m)^kind:\s*[\"']?Secret[\"']?\s*$")
YAML_DATA = re.compile(rb"(?m)^(?:data|stringData):[ \t]*\r?\n[ \t]+[^\s#][^:\n]*:[ \t]*\S")


def excluded(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED)


def line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def scan_text(data: bytes) -> list[tuple[int, str]]:
    """Return (line, rule) for each credential found in raw bytes."""
    found = []
    for rule, pattern in TEXT_RULES:
        found += [(line_of(data, m.start()), rule) for m in pattern.finditer(data)]
    for rule, pattern in ASSIGNMENTS:
        for m in pattern.finditer(data):
            value = m.group("value").decode("latin-1")
            if not PLACEHOLDER.match(value):
                found.append((line_of(data, m.start()), rule))
    for m in BASIC.finditer(data):
        value = m.group("value")
        try:
            decoded = base64.b64decode(value + b"=" * (-len(value) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if b":" in decoded and all(32 <= c < 127 for c in decoded):
            found.append((line_of(data, m.start()), "basic-authorization"))
    for m in PEM_B64.finditer(data):
        chunk = m.group(0)
        try:
            decoded = base64.b64decode(chunk[: len(chunk) - len(chunk) % 4] or b"", validate=False)
        except (binascii.Error, ValueError):
            continue
        if b"PRIVATE KEY" in decoded:
            found.append((line_of(data, m.start()), "encoded-private-key"))
    found += [(line, "kubernetes-secret-data") for line in kubernetes_secrets(data)]
    return found


def kubernetes_secrets(data: bytes) -> list[int]:
    """Lines of Kubernetes Secret objects that carry data, in JSON or YAML."""
    lines = []
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        try:
            document = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            document = None
        if document is not None:
            def walk(node):
                if isinstance(node, dict):
                    if node.get("kind") == "Secret" and (node.get("data") or node.get("stringData")):
                        lines.append(1)
                    for value in node.values():
                        walk(value)
                elif isinstance(node, list):
                    for value in node:
                        walk(value)
            walk(document)
            return lines
    offset = 0
    for document in re.split(rb"(?m)^---[ \t]*$", data):
        if YAML_SECRET.search(document) and YAML_DATA.search(document):
            lines.append(line_of(data, offset + YAML_SECRET.search(document).start()))
        offset += len(document) + 3
    return lines


def expand(data: bytes):
    """Yield (member suffix, bytes) for the archive members inside data, if any."""
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                inner = stream.read(MAX_EXPANDED + 1)
        except (OSError, EOFError) as error:
            raise ValueError(f"unreadable gzip: {error}") from None
        if len(inner) > MAX_EXPANDED:
            raise ValueError("gzip expands beyond the scan bound")
        yield "", inner
        return
    if len(data) > 262 and data[257:262] == b"ustar":
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                total = 0
                for member in archive:
                    if not member.isfile():
                        continue
                    total += member.size
                    if total > MAX_EXPANDED:
                        raise ValueError("tar expands beyond the scan bound")
                    yield "!" + member.name, archive.extractfile(member).read()
        except tarfile.TarError as error:
            raise ValueError(f"unreadable tar: {error}") from None
        return
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                total = 0
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    total += info.file_size
                    if total > MAX_EXPANDED:
                        raise ValueError("zip expands beyond the scan bound")
                    yield "!" + info.filename, archive.read(info)
        except zipfile.BadZipFile as error:
            raise ValueError(f"unreadable zip: {error}") from None


def scan_bytes(name: str, data: bytes, depth: int = 0) -> list[tuple[str, int, str]]:
    findings = [(name, 0, "sensitive-filename")] if any(
        fnmatch.fnmatch(part, pattern) for part in re.split(r"[/!]", name) for pattern in SENSITIVE_NAMES) else []
    try:
        members = list(expand(data))
    except ValueError as error:
        # An archive that cannot be inspected cannot be shown to be clean.
        return findings + [(name, 0, f"unscannable-archive ({error})")]
    if not members:
        # Archives are scanned through their members, everything else as is.
        findings += [(name, line, rule) for line, rule in scan_text(data)]
    for suffix, inner in members:
        if depth >= MAX_DEPTH:
            return findings + [(name, 0, "unscannable-archive (nesting too deep)")]
        findings += scan_bytes(name + suffix, inner, depth + 1)
    return findings


def scan_dir(root: Path) -> list[tuple[str, int, str]]:
    """Scan every regular file below root, as staged (no exclusions)."""
    findings = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        findings += scan_bytes(path.relative_to(root).as_posix(), path.read_bytes())
    return findings


def stage(source: Path, dest: Path) -> dict:
    """Copy evidence from source to dest; return the inventory of what was left out."""
    inventory = {"excluded": [], "skipped": [], "files": 0}
    for directory, subdirs, files in os.walk(source, followlinks=False):
        here = Path(directory)
        rel = here.relative_to(source)
        for name in sorted(subdirs):
            child = here / name
            if excluded(name) or child.is_symlink():
                inventory["excluded" if excluded(name) else "skipped"].append((rel / name).as_posix() + "/")
        subdirs[:] = sorted(n for n in subdirs if not excluded(n) and not (here / n).is_symlink())
        for name in sorted(files):
            path = here / name
            relative = (rel / name).as_posix()
            if excluded(name):
                inventory["excluded"].append(relative)
                continue
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                inventory["skipped"].append(relative)
                continue
            target = dest / rel / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            inventory["files"] += 1
    return inventory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("dest", type=Path)
    parser.add_argument("--report", type=Path, help="also write findings (never values) to this file outside DEST")
    args = parser.parse_args(argv)
    source, dest = args.source.resolve(), args.dest.resolve()
    if not source.is_dir():
        print(f"no evidence directory at {source}", file=sys.stderr)
        return 1
    if dest.exists():
        print(f"{dest} must not exist: staging needs a fresh directory", file=sys.stderr)
        return 1
    if dest == source or source in dest.parents or dest in source.parents:
        print("source and destination must be separate trees", file=sys.stderr)
        return 1
    dest.mkdir(parents=True)
    inventory = stage(source, dest)
    findings = scan_dir(dest)
    lines = [f"{name}:{line}: {rule}" if line else f"{name}: {rule}" for name, line, rule in findings]
    if args.report:
        args.report.write_text("".join(f"{line}\n" for line in lines))
    if findings:
        shutil.rmtree(dest)
        print(f"Refusing to stage evidence: {len(findings)} credential finding(s); nothing will be uploaded.", file=sys.stderr)
        for line in lines:
            print(f"  {line}", file=sys.stderr)
        return 1
    summary = {"source": str(source), "scannedFiles": inventory["files"], "findings": 0,
               "excluded": inventory["excluded"], "skipped": inventory["skipped"],
               "excludedPatterns": list(EXCLUDED),
               "rules": sorted({r for r, _ in TEXT_RULES} | {r for r, _ in ASSIGNMENTS}
                               | {"basic-authorization", "encoded-private-key", "kubernetes-secret-data", "sensitive-filename"})}
    (dest / "evidence-scan.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Staged {inventory['files']} evidence files in {dest}; no credentials found "
          f"({len(inventory['excluded'])} excluded, {len(inventory['skipped'])} skipped).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
