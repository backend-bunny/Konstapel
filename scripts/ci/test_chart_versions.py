"""Chart versions follow VERSION through release-please's generic updater."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHARTS = ["charts/konstapel-crds/Chart.yaml", "charts/konstapel/Chart.yaml"]
SEMVER = re.compile(r"\d+\.\d+\.\d+")


def release_please_bump(root: Path, version: str) -> None:
    """Apply what release-please does for a release: VERSION, then every
    extra-file line marked x-release-please-version (generic updater)."""
    config = json.loads((root / "release-please-config.json").read_text())
    package = config["packages"]["."]
    (root / package["version-file"]).write_text(version + "\n")
    for extra in package["extra-files"]:
        path = root / extra["path"]
        lines = [SEMVER.sub(version, l, count=1) if "x-release-please-version" in l else l
                 for l in path.read_text().splitlines(keepends=True)]
        path.write_text("".join(lines))


class ChartVersionTests(unittest.TestCase):
    def copy(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for rel in ["VERSION", "melange.yaml", "release-please-config.json", "scripts/check-version.sh", *CHARTS]:
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / rel, tmp / rel)
        return tmp

    def check(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "scripts/check-version.sh"], cwd=root, capture_output=True, text=True)

    def test_both_charts_are_release_please_extra_files(self):
        config = json.loads((ROOT / "release-please-config.json").read_text())
        paths = {e["path"] for e in config["packages"]["."]["extra-files"]}
        self.assertTrue(set(CHARTS) <= paths)
        for chart in CHARTS:
            text = (ROOT / chart).read_text()
            for field in ("version:", "appVersion:"):
                line = next(l for l in text.splitlines() if l.startswith(field))
                self.assertIn("x-release-please-version", line, f"{chart} {field}")

    def test_release_advances_both_charts_without_schema_changes(self):
        root = self.copy()
        self.assertEqual(self.check(root).returncode, 0)
        release_please_bump(root, "9.8.7")
        result = self.check(root)
        self.assertEqual(result.returncode, 0, result.stderr)
        for chart in CHARTS:
            text = (root / chart).read_text()
            self.assertRegex(text, r'(?m)^version: 9\.8\.7 ')
            self.assertRegex(text, r'(?m)^appVersion: "9\.8\.7" ')

    def test_version_mismatch_fails(self):
        for chart, field in [(c, f) for c in CHARTS for f in ("version", "appVersion")]:
            with self.subTest(chart=chart, field=field):
                root = self.copy()
                path = root / chart
                text = path.read_text()
                text = re.sub(rf'(?m)^({field}: "?)\d+\.\d+\.\d+', r"\g<1>0.0.99", text)
                path.write_text(text)
                result = self.check(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Version mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
