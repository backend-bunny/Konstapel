#!/usr/bin/env python3
"""Publish frozen chart archives to an OCI registry, write-once.

  publish.py --archives DIR --acceptance CHART_ACCEPTANCE_JSON \
      --registry oci://ghcr.io/backend-bunny/charts --out RESULT_JSON [--plain-http]

Before any registry write it verifies DIR/publication.json (the frozen
manifest) against the archives and this checkout, and requires a passing
chart-acceptance record bound to exactly that source, those archive
checksums, the CRD content and the image digest.

Each chart version is write-once. For each chart, the CRD chart first:
  - if the version already exists, its chart layer must be byte-identical to
    the frozen archive; it is never replaced, and different bytes stop the
    publication;
  - otherwise the frozen archive is pushed.
Then the OCI manifest is read back by digest and its single chart-content
layer must have the frozen archive's digest. A retry after a partial
publication (one chart pushed, or signing failed) runs the same steps and
pushes only what is missing. RESULT_JSON records both OCI subjects; it is
written only when both verify.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest as frozen  # noqa: E402

CHART_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
CHART_CONFIG = "application/vnd.cncf.helm.config.v1+json"
MANIFEST_TYPES = "application/vnd.oci.image.manifest.v1+json"
ACCEPTANCE = "konstapel.dev/chart-acceptance/v1"


class Refused(Exception):
    pass


def run(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise Refused(f"{' '.join(args[:3])}: {p.stderr.strip() or p.stdout.strip()}")
    return p


def git_head() -> str:
    return run("git", "rev-parse", "HEAD").stdout.strip()


def check_acceptance(manifest: dict, record: dict) -> None:
    """The acceptance record must be a pass for exactly the frozen inputs."""
    if record.get("apiVersion") != ACCEPTANCE or record.get("passed") is not True:
        raise Refused("chart acceptance did not pass")
    want_image = "ghcr.io/backend-bunny/konstapel@" + manifest["image"]["digest"]
    checks = [
        ("source commit", record.get("source", {}).get("commit"), manifest["source"]["commit"]),
        ("tag", record.get("source", {}).get("tag"), manifest["source"]["tag"]),
        ("image", record.get("image"), want_image),
        ("CRD content", record.get("crdContent"), manifest["crdContent"]),
    ]
    for name in frozen.CHARTS:
        got = record.get("charts", {}).get(name, {})
        checks.append((f"{name} archive", got.get("sha256"), manifest["charts"][name]["sha256"]))
        checks.append((f"{name} version", got.get("version"), manifest["charts"][name]["version"]))
    for what, got, want in checks:
        if got != want:
            raise Refused(f"chart acceptance tested {what} {got!r}, frozen {want!r}")


class Registry:
    """Minimal OCI distribution reads (manifests by tag or digest)."""

    def __init__(self, ref: str, plain_http: bool):
        if not ref.startswith("oci://"):
            raise Refused(f"registry {ref!r} must be oci://HOST/PATH")
        self.oci = ref.rstrip("/")
        host, _, self.path = ref[len("oci://"):].partition("/")
        self.base = ("http://" if plain_http else "https://") + host
        self.host = host
        self.plain = plain_http

    def _token(self, repo: str, challenge: str) -> str:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        url = f"{params['realm']}?service={params.get('service', '')}&scope=repository:{repo}:pull"
        req = urllib.request.Request(url)
        user, password = os.environ.get("REGISTRY_USER"), os.environ.get("REGISTRY_PASSWORD")
        if user and password:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.load(r)
        return body.get("token") or body.get("access_token")

    def manifest(self, name: str, ref: str):
        repo = f"{self.path}/{name}" if self.path else name
        url = f"{self.base}/v2/{repo}/manifests/{ref}"
        headers = {"Accept": MANIFEST_TYPES}
        for _ in range(2):
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    raw = r.read()
                    return json.loads(raw), "sha256:" + hashlib.sha256(raw).hexdigest()
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None, None
                if e.code == 401 and "Authorization" not in headers:
                    headers["Authorization"] = "Bearer " + self._token(repo, e.headers.get("WWW-Authenticate", ""))
                    continue
                raise Refused(f"read {repo}:{ref}: HTTP {e.code}")
        raise Refused(f"read {repo}:{ref}: unauthorized")


def chart_layer(m: dict) -> str:
    layers = [l for l in m.get("layers", []) if l.get("mediaType") == CHART_LAYER]
    if m.get("config", {}).get("mediaType") != CHART_CONFIG or len(layers) != 1 or len(m.get("layers", [])) != 1:
        raise Refused("OCI manifest is not a single Helm chart")
    return layers[0]["digest"]


def publish(args) -> dict:
    archives = Path(args.archives)
    manifest_path = archives / "publication.json"
    manifest = json.loads(manifest_path.read_text())
    try:
        frozen.verify(argparse.Namespace(archives=str(archives), manifest=str(manifest_path), source=git_head(), image_digest=None))
    except frozen.Mismatch as e:
        raise Refused(f"frozen inputs: {e}")
    check_acceptance(manifest, json.loads(Path(args.acceptance).read_text()))
    reg = Registry(args.registry, args.plain_http)
    plain = ["--plain-http"] if args.plain_http else []
    result = {"apiVersion": "konstapel.dev/chart-release/v1", "source": manifest["source"], "image": manifest["image"], "charts": {}}
    for name in frozen.CHARTS:
        chart = manifest["charts"][name]
        archive = archives / chart["archive"]
        version = chart["version"]
        existing, digest = reg.manifest(name, version)
        if existing is not None:
            if chart_layer(existing) != chart["sha256"]:
                raise Refused(f"{name} {version} already exists with different content ({chart_layer(existing)}); a released version is never replaced")
            state = "existing"
        else:
            run("helm", "push", str(archive), reg.oci, *plain)
            existing, digest = reg.manifest(name, version)
            if existing is None:
                raise Refused(f"{name} {version} not found after push")
            state = "pushed"
        by_digest, again = reg.manifest(name, digest)
        if by_digest is None or again != digest or chart_layer(by_digest) != chart["sha256"]:
            raise Refused(f"{name}@{digest} does not carry the frozen archive {chart['sha256']}")
        result["charts"][name] = {"version": version, "reference": f"{reg.oci[len('oci://'):]}/{name}", "digest": digest,
                                  "archiveSha256": chart["sha256"], "state": state}
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--archives", required=True)
    p.add_argument("--acceptance", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--plain-http", action="store_true", help="test registries only")
    args = p.parse_args(argv)
    try:
        result = publish(args)
    except Refused as e:
        print(f"chart publication: {e}", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    for name, c in result["charts"].items():
        print(f"{c['state']}: {c['reference']}:{c['version']}@{c['digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
