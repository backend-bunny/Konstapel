#!/usr/bin/env python3
"""Freeze and verify the chart publication manifest.

Before anything is pushed, release packaging freezes both chart archives and
this manifest; the publisher, and every retry, verifies it and stops before
any registry write on a mismatch:

  manifest.py freeze --archives DIR --source SHA --tag vX.Y.Z \
      --image-digest sha256:... [--tool helm=VERSION ...] --out MANIFEST
  manifest.py verify --archives DIR --manifest MANIFEST \
      [--source SHA] [--image-digest sha256:...]

The manifest records the source commit and tag, both charts' name, version and
appVersion, each archive's SHA-256, the CRD content identity (a digest over the
CRD chart's templates), the runtime chart's default image digest, and the
packaging tool versions. Verification fails on a missing or extra archive,
changed archive bytes, a source or image digest other than the frozen one, a
runtime chart whose default image is not that digest, and chart versions that
do not form the aligned pair for the tag.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

CHARTS = ("konstapel-crds", "konstapel")
SCHEMA = "konstapel.dev/chart-publication/v1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class Mismatch(Exception):
    pass


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def scalar(text: str, key: str, indent: str = "") -> str:
    """A top-level (or indented) YAML scalar, without quotes or comments."""
    m = re.search(rf"(?m)^{indent}{re.escape(key)}:\s*(.*)$", text)
    if not m:
        return ""
    value = m.group(1).split(" #", 1)[0].strip()
    return value.strip('"').strip("'")


def read_archive(path: Path) -> dict:
    """Chart metadata and content identities from a packaged chart."""
    with tarfile.open(path, "r:gz") as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        roots = {name.split("/", 1)[0] for name in members}
        if len(roots) != 1:
            raise Mismatch(f"{path.name}: not a single packaged chart")
        root = roots.pop()

        def text(rel: str) -> str:
            m = members.get(f"{root}/{rel}")
            return tar.extractfile(m).read().decode() if m else ""

        chart = text("Chart.yaml")
        templates = sorted(n for n in members if n.startswith(f"{root}/templates/"))
        identity = hashlib.sha256()
        for name in templates:
            identity.update(name.split("/", 1)[1].encode() + b"\0")
            identity.update(tar.extractfile(members[name]).read() + b"\0")
        values = text("values.yaml")
    image = re.search(r"(?ms)^image:\n(.*?)(?=^\S|\Z)", values)
    return {
        "name": scalar(chart, "name"),
        "version": scalar(chart, "version"),
        "appVersion": scalar(chart, "appVersion"),
        "archive": path.name,
        "sha256": sha256(path.read_bytes()),
        "templates": "sha256:" + identity.hexdigest(),
        "imageDigest": scalar(image.group(1), "digest", r"\s+") if image else "",
    }


def collect(archives: Path) -> dict:
    found = {}
    for path in sorted(archives.glob("*.tgz")):
        meta = read_archive(path)
        if meta["name"] not in CHARTS:
            raise Mismatch(f"{path.name}: unexpected chart {meta['name']!r}")
        if meta["name"] in found:
            raise Mismatch(f"two archives for chart {meta['name']}")
        found[meta["name"]] = meta
    missing = [c for c in CHARTS if c not in found]
    if missing:
        raise Mismatch(f"missing chart archive(s): {', '.join(missing)}")
    return found


def check_pair(charts: dict, tag: str, image_digest: str) -> None:
    version = tag[1:]
    for name in CHARTS:
        c = charts[name]
        if c["version"] != version or c["appVersion"] != version:
            raise Mismatch(f"{name} {c['version']} (appVersion {c['appVersion']}) is not the aligned pair for {tag}")
    if charts["konstapel"]["imageDigest"] != image_digest:
        raise Mismatch(f"konstapel chart's default image digest {charts['konstapel']['imageDigest'] or '(empty)'} is not {image_digest}")


def freeze(args) -> dict:
    if not SHA.match(args.source):
        raise Mismatch(f"source {args.source!r} is not a full commit SHA")
    if not TAG.match(args.tag):
        raise Mismatch(f"tag {args.tag!r} is not vMAJOR.MINOR.PATCH")
    if not DIGEST.match(args.image_digest):
        raise Mismatch(f"image digest {args.image_digest!r} is not sha256:<64 hex>")
    charts = collect(Path(args.archives))
    check_pair(charts, args.tag, args.image_digest)
    tools = dict(t.split("=", 1) for t in args.tool or [])
    return {
        "apiVersion": SCHEMA,
        "source": {"commit": args.source, "tag": args.tag},
        "image": {"digest": args.image_digest},
        "crdContent": charts["konstapel-crds"]["templates"],
        "charts": {n: {k: charts[n][k] for k in ("version", "appVersion", "archive", "sha256")} for n in CHARTS},
        "tools": tools,
    }


def verify(args) -> None:
    manifest = json.loads(Path(args.manifest).read_text())
    if manifest.get("apiVersion") != SCHEMA:
        raise Mismatch(f"unknown manifest {manifest.get('apiVersion')!r}")
    if args.source and args.source != manifest["source"]["commit"]:
        raise Mismatch(f"source {args.source} is not the frozen source {manifest['source']['commit']}")
    if args.image_digest and args.image_digest != manifest["image"]["digest"]:
        raise Mismatch(f"image digest {args.image_digest} is not the frozen digest {manifest['image']['digest']}")
    charts = collect(Path(args.archives))
    for name in CHARTS:
        want, got = manifest["charts"][name], charts[name]
        if got["sha256"] != want["sha256"] or got["archive"] != want["archive"]:
            raise Mismatch(f"{name}: archive {got['archive']} {got['sha256']} differs from frozen {want['archive']} {want['sha256']}")
    if charts["konstapel-crds"]["templates"] != manifest["crdContent"]:
        raise Mismatch("CRD content differs from the frozen CRD content identity")
    check_pair(charts, manifest["source"]["tag"], manifest["image"]["digest"])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--archives", required=True)
    f.add_argument("--source", required=True)
    f.add_argument("--tag", required=True)
    f.add_argument("--image-digest", required=True)
    f.add_argument("--tool", action="append", help="NAME=VERSION of a packaging tool")
    f.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--archives", required=True)
    v.add_argument("--manifest", required=True)
    v.add_argument("--source")
    v.add_argument("--image-digest")
    args = p.parse_args(argv)
    try:
        if args.command == "freeze":
            out = Path(args.out)
            if out.exists():
                raise Mismatch(f"{out} exists; a frozen manifest is never replaced")
            out.write_text(json.dumps(freeze(args), indent=2, sort_keys=True) + "\n")
        else:
            verify(args)
    except Mismatch as e:
        print(f"chart publication manifest: {e}", file=sys.stderr)
        return 1
    print(f"chart publication manifest: {args.command} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
