"""The frozen chart publication manifest rejects every substitution before
any registry write (add-helm-oci-distribution 1.4). Archives are packaged
with the pinned Helm from isolated copies of the repository's charts."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("manifest", ROOT / "scripts/charts/manifest.py")
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)

VERSION = (ROOT / "VERSION").read_text().strip()
TAG = "v" + VERSION
SOURCE = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32


def package(out: Path, chart: str, version=None, digest=DIGEST, extra=None) -> Path:
    """helm package an isolated copy of a chart, as release packaging does."""
    work = Path(tempfile.mkdtemp())
    try:
        src = work / chart
        shutil.copytree(ROOT / "charts" / chart, src)
        if version:
            meta = src / "Chart.yaml"
            meta.write_text(re.sub(r"(?m)^version: \S+", f"version: {version}", meta.read_text()))
        if chart == "konstapel":
            values = src / "values.yaml"
            values.write_text(values.read_text().replace('digest: ""', f'digest: "{digest}"', 1))
        if extra:
            (src / "templates" / "extra.yaml").write_text(extra)
        subprocess.run(["helm", "package", str(src), "--destination", str(out)], check=True, capture_output=True)
    finally:
        shutil.rmtree(work)
    return next(out.glob(f"{chart}-*.tgz"))


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.archives = self.dir / "archives"
        self.archives.mkdir()
        package(self.archives, "konstapel-crds")
        package(self.archives, "konstapel")
        self.manifest = self.dir / "manifest.json"

    def run_tool(self, *args) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = manifest.main(list(args))
        return code, err.getvalue()

    def freeze(self, digest=DIGEST, out=None):
        return self.run_tool("freeze", "--archives", str(self.archives), "--source", SOURCE, "--tag", TAG,
                             "--image-digest", digest, "--tool", "helm=pinned", "--out", str(out or self.manifest))

    def verify(self, *extra):
        return self.run_tool("verify", "--archives", str(self.archives), "--manifest", str(self.manifest), *extra)

    def assertRejected(self, result, text):
        code, err = result
        self.assertNotEqual(code, 0)
        self.assertIn(text, err)

    def test_frozen_inputs_verify(self):
        self.assertEqual(self.freeze()[0], 0)
        m = json.loads(self.manifest.read_text())
        self.assertEqual(m["source"], {"commit": SOURCE, "tag": TAG})
        self.assertEqual(m["image"]["digest"], DIGEST)
        self.assertEqual(set(m["charts"]), {"konstapel-crds", "konstapel"})
        for c in m["charts"].values():
            self.assertEqual((c["version"], c["appVersion"]), (VERSION, VERSION))
            self.assertRegex(c["sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(m["crdContent"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(self.verify("--source", SOURCE, "--image-digest", DIGEST)[0], 0)

    def test_frozen_manifest_is_never_replaced(self):
        self.assertEqual(self.freeze()[0], 0)
        self.assertRejected(self.freeze(), "never replaced")

    def test_source_and_digest_substitution_rejected(self):
        self.freeze()
        self.assertRejected(self.verify("--source", "f" * 40), "not the frozen source")
        self.assertRejected(self.verify("--image-digest", OTHER), "not the frozen digest")

    def test_runtime_chart_must_default_to_the_frozen_image(self):
        self.assertRejected(self.freeze(digest=OTHER), "default image digest")

    def test_missing_or_extra_archives_rejected(self):
        self.freeze()
        crds = next(self.archives.glob("konstapel-crds-*.tgz"))
        moved = crds.rename(self.dir / crds.name)
        self.assertRejected(self.verify(), "missing chart archive")
        moved.rename(crds)
        package(self.archives, "konstapel-crds", version="9.9.9")
        self.assertRejected(self.verify(), "two archives")

    def test_changed_bytes_rejected(self):
        self.freeze()
        for old in self.archives.glob("konstapel-crds-*.tgz"):
            old.unlink()
        package(self.archives, "konstapel-crds", extra="# changed\n")
        self.assertRejected(self.verify(), "differs from frozen")

    def test_incompatible_version_pair_rejected_before_freezing(self):
        for old in self.archives.glob("konstapel-*.tgz"):
            if not old.name.startswith("konstapel-crds"):
                old.unlink()
        package(self.archives, "konstapel", version="0.0.99")
        self.assertRejected(self.freeze(), "not the aligned pair")
        self.assertFalse(self.manifest.exists())

    def test_malformed_inputs_rejected(self):
        self.assertRejected(self.run_tool("freeze", "--archives", str(self.archives), "--source", "main", "--tag", TAG,
                                          "--image-digest", DIGEST, "--out", str(self.manifest)), "full commit SHA")
        self.assertRejected(self.run_tool("freeze", "--archives", str(self.archives), "--source", SOURCE, "--tag", TAG,
                                          "--image-digest", "latest", "--out", str(self.manifest)), "sha256")


if __name__ == "__main__":
    unittest.main()
