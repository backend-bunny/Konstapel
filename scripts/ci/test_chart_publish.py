"""Write-once chart publication against a fake OCI registry
(add-helm-oci-distribution 5.2): frozen inputs and a matching acceptance
record are required before any write; existing versions are never
replaced; a retry after partial publication pushes only what is missing."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/charts"))
sys.path.insert(0, str(ROOT / "scripts/ci"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


manifest = load("manifest", ROOT / "scripts/charts/manifest.py")
publish = load("publish", ROOT / "scripts/charts/publish.py")
fixtures = load("test_chart_manifest", ROOT / "scripts/ci/test_chart_manifest.py")
from oci_fake import FakeRegistry  # noqa: E402

HEAD = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
DIGEST = fixtures.DIGEST


def acceptance_for(m: dict, **override) -> dict:
    record = {
        "apiVersion": "konstapel.dev/chart-acceptance/v1",
        "passed": True,
        "source": dict(m["source"]),
        "image": "ghcr.io/backend-bunny/konstapel@" + m["image"]["digest"],
        "crdContent": m["crdContent"],
        "charts": {n: {"version": c["version"], "sha256": c["sha256"]} for n, c in m["charts"].items()},
    }
    record.update(override)
    return record


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.archives = self.dir / "archives"
        self.archives.mkdir()
        fixtures.package(self.archives, "konstapel-crds")
        fixtures.package(self.archives, "konstapel")
        self.assertEqual(self.quiet(manifest.main, ["freeze", "--archives", str(self.archives), "--source", HEAD, "--tag", fixtures.TAG,
                                                     "--image-digest", DIGEST, "--out", str(self.archives / "publication.json")])[0], 0)
        self.frozen = json.loads((self.archives / "publication.json").read_text())
        self.registry = FakeRegistry()
        self.addCleanup(self.registry.close)
        self.acceptance = self.dir / "chart-acceptance.json"
        self.write_acceptance(acceptance_for(self.frozen))

    def quiet(self, fn, args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = fn(args)
        return code, err.getvalue()

    def write_acceptance(self, record):
        self.acceptance.write_text(json.dumps(record))

    def publish(self, out="result.json"):
        return self.quiet(publish.main, ["--archives", str(self.archives), "--acceptance", str(self.acceptance),
                                         "--registry", f"oci://{self.registry.host}/charts", "--out", str(self.dir / out), "--plain-http"])

    def result(self, out="result.json"):
        return json.loads((self.dir / out).read_text())

    def test_publishes_both_subjects_with_the_frozen_layers(self):
        code, err = self.publish()
        self.assertEqual(code, 0, err)
        r = self.result()
        self.assertEqual(r["source"]["commit"], HEAD)
        for name, c in r["charts"].items():
            self.assertEqual(c["state"], "pushed")
            self.assertRegex(c["digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(c["archiveSha256"], self.frozen["charts"][name]["sha256"])
            media, raw = self.registry.manifests[(f"charts/{name}", c["digest"])]
            layer = json.loads(raw)["layers"][0]["digest"]
            self.assertEqual(layer, self.frozen["charts"][name]["sha256"])

    def test_republishing_is_a_no_op(self):
        self.assertEqual(self.publish()[0], 0)
        writes = len(self.registry.manifest_writes())
        code, err = self.publish("again.json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.registry.manifest_writes()), writes, "a released version was written again")
        again = self.result("again.json")
        self.assertEqual({c["state"] for c in again["charts"].values()}, {"existing"})
        self.assertEqual({n: c["digest"] for n, c in again["charts"].items()}, {n: c["digest"] for n, c in self.result()["charts"].items()})

    def assertRefusedBeforeWrites(self, text):
        code, err = self.publish()
        self.assertNotEqual(code, 0)
        self.assertIn(text, err)
        self.assertEqual(self.registry.writes, [], "a refused publication wrote to the registry")
        self.assertFalse((self.dir / "result.json").exists())

    def test_requires_passing_acceptance(self):
        self.write_acceptance(acceptance_for(self.frozen, passed=False))
        self.assertRefusedBeforeWrites("did not pass")
        self.acceptance.unlink()
        with self.assertRaises(FileNotFoundError):
            self.publish()
        self.assertEqual(self.registry.writes, [])

    def test_acceptance_of_other_inputs_is_refused(self):
        other = "sha256:" + "ee" * 32
        cases = {
            "image": acceptance_for(self.frozen, image="ghcr.io/backend-bunny/konstapel@" + other),
            "source commit": acceptance_for(self.frozen, source={"commit": "f" * 40, "tag": fixtures.TAG}),
            "CRD content": acceptance_for(self.frozen, crdContent=other),
        }
        charts = acceptance_for(self.frozen)
        charts["charts"]["konstapel"]["sha256"] = other
        cases["konstapel archive"] = charts
        for what, record in cases.items():
            with self.subTest(what):
                self.write_acceptance(record)
                self.assertRefusedBeforeWrites(f"tested {what}")

    def test_changed_archive_is_refused(self):
        for old in self.archives.glob("konstapel-crds-*.tgz"):
            old.unlink()
        fixtures.package(self.archives, "konstapel-crds", extra="# changed\n")
        self.assertRefusedBeforeWrites("differs from frozen")

    def test_partial_publication_resumes(self):
        self.registry.fail_manifest_put.add("charts/konstapel")
        code, err = self.publish()
        self.assertNotEqual(code, 0)
        self.assertFalse((self.dir / "result.json").exists(), "a partial publication reported success")
        self.assertIn(("charts/konstapel-crds", fixtures.VERSION), self.registry.tags)
        self.assertNotIn(("charts/konstapel", fixtures.VERSION), self.registry.tags)
        self.registry.fail_manifest_put.clear()
        code, err = self.publish()
        self.assertEqual(code, 0, err)
        states = {n: c["state"] for n, c in self.result()["charts"].items()}
        self.assertEqual(states, {"konstapel-crds": "existing", "konstapel": "pushed"})

    def test_existing_version_with_other_content_is_never_replaced(self):
        other = self.dir / "other"
        other.mkdir()
        conflicting = fixtures.package(other, "konstapel-crds", extra="# other bytes\n")
        subprocess.run(["helm", "push", str(conflicting), f"oci://{self.registry.host}/charts", "--plain-http"], check=True, capture_output=True)
        before = dict(self.registry.tags)
        writes = len(self.registry.manifest_writes())
        code, err = self.publish()
        self.assertNotEqual(code, 0)
        self.assertIn("never replaced", err)
        self.assertEqual(self.registry.tags, before)
        self.assertEqual(len(self.registry.manifest_writes()), writes)


if __name__ == "__main__":
    unittest.main()
