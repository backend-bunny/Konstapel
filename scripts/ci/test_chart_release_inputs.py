"""Frozen chart inputs for a release are created once and reused on every
retry (add-helm-oci-distribution 5.2, 5.6). `gh` and `helm show` are stubbed:
the GitHub Release is a directory of assets and the registry is a set of
published chart names. Each case runs scripts/charts/release-inputs.sh in a
clean clone of this repository, as the release workflow's checkout is."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text().strip()
TAG = "v" + VERSION
DIGEST = "sha256:" + "ab" * 32
ASSETS = {f"konstapel-crds-{VERSION}.tgz", f"konstapel-{VERSION}.tgz", "publication.json"}

GH = r'''#!/usr/bin/env bash
set -euo pipefail
rel=$FAKE_RELEASE
case "$1 $2" in
  "release view") ls "$rel" | while read -r a; do echo "$a"; done ;;
  "release download") cp "$rel/$5" "$7/" ;;
  "release upload") shift 3; for f in "$@"; do [[ -e $rel/$(basename "$f") ]] && { echo "asset exists" >&2; exit 1; }; cp "$f" "$rel/"; done ;;
  "release delete-asset") rm "$rel/$4"; echo "deleted $4" >> "$FAKE_LOG" ;;
  *) echo "unexpected gh $*" >&2; exit 2 ;;
esac
echo "gh $1 $2" >> "$FAKE_LOG"
'''

HELM = r'''#!/usr/bin/env bash
if [[ $1 == show ]]; then
  chart=${3##*/}
  grep -Fxq "$chart" "$FAKE_PUBLISHED" && exit 0
  exit 1
fi
exec "$REAL_HELM" "$@"
'''


class ReleaseInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp())
        cls.clone = cls.base / "repo"
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(cls.clone)], check=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["git", "checkout", "--quiet", head], cwd=cls.clone, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.base))
        self.release = self.dir / "release"
        self.release.mkdir()
        self.published = self.dir / "published"
        self.published.write_text("")
        self.log = self.dir / "log"
        self.log.write_text("")
        bin_ = self.dir / "bin"
        bin_.mkdir()
        (bin_ / "gh").write_text(GH)
        (bin_ / "helm").write_text(HELM)
        for f in bin_.iterdir():
            f.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", FAKE_RELEASE=str(self.release), FAKE_LOG=str(self.log),
                        FAKE_PUBLISHED=str(self.published), REAL_HELM=shutil.which("helm"))
        self.runs = 0

    def run_inputs(self):
        self.runs += 1
        out = self.dir / f"out{self.runs}"
        return subprocess.run(["bash", "scripts/charts/release-inputs.sh", str(out), TAG, DIGEST], cwd=self.clone,
                              env=self.env, capture_output=True, text=True), out

    def test_first_run_freezes_and_attaches_and_retries_reuse_them(self):
        p, out = self.run_inputs()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual({a.name for a in self.release.iterdir()}, ASSETS)
        frozen = json.loads((self.release / "publication.json").read_text())
        self.assertEqual(frozen["image"]["digest"], DIGEST)
        p, again = self.run_inputs()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Reusing", p.stdout)
        for a in ASSETS:
            self.assertEqual((again / a).read_bytes(), (self.release / a).read_bytes())

    def test_retry_with_changed_assets_fails(self):
        self.assertEqual(self.run_inputs()[0].returncode, 0)
        archive = self.release / f"konstapel-{VERSION}.tgz"
        archive.write_bytes(archive.read_bytes() + b"\0")
        p, _ = self.run_inputs()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("differs from frozen", p.stderr)

    def test_retry_for_another_image_fails(self):
        self.assertEqual(self.run_inputs()[0].returncode, 0)
        p = subprocess.run(["bash", "scripts/charts/release-inputs.sh", str(self.dir / "other"), TAG, "sha256:" + "cd" * 32],
                           cwd=self.clone, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not the frozen digest", p.stderr)

    def test_incomplete_unpublished_inputs_are_frozen_again(self):
        (self.release / "publication.json").write_text("{}")
        p, _ = self.run_inputs()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("deleted publication.json", self.log.read_text())
        self.assertEqual({a.name for a in self.release.iterdir()}, ASSETS)

    def test_incomplete_inputs_after_publication_stop(self):
        self.assertEqual(self.run_inputs()[0].returncode, 0)
        (self.release / f"konstapel-{VERSION}.tgz").unlink()
        self.published.write_text("konstapel-crds\n")
        before = {a.name for a in self.release.iterdir()}
        p, _ = self.run_inputs()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("restore the original assets", p.stderr)
        self.assertEqual({a.name for a in self.release.iterdir()}, before, "assets changed after publication")

    def test_missing_inputs_after_publication_are_never_rebuilt(self):
        self.published.write_text("konstapel\n")
        p, _ = self.run_inputs()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refusing to repackage", p.stderr)
        self.assertEqual(list(self.release.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
