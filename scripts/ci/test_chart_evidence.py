"""Release acceptance evidence (add-helm-oci-distribution 6.6): which groups
the frozen source requires, how each test's result is derived from its real
`go test -v` log, and that a chart-acceptance record is written only when
every required group fully passed."""

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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


evidence = load("evidence", ROOT / "scripts/charts/evidence.py")
manifest = load("manifest", ROOT / "scripts/charts/manifest.py")
fixtures = load("test_chart_manifest", ROOT / "scripts/ci/test_chart_manifest.py")

HEAD = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
IMAGE = "ghcr.io/backend-bunny/konstapel@" + fixtures.DIGEST
TESTS = ["TestLiveA", "TestLiveB"]


def go_log(*results, packages=("ok  \tgithub.com/backend-bunny/Konstapel/internal/targeting\t0.02s [no tests to run]",
                               "ok  \tgithub.com/backend-bunny/Konstapel/internal/controller\t301.5s")):
    """A go test -v log in the shape targeting-live.sh records."""
    lines = ["testing: warning: no tests to run", "PASS", packages[0]]
    for name, verdict, *subs in results:
        lines += [f"=== RUN   {name}", f"    {name.lower()}_live_test.go:12: progress"]
        for sub, sv in subs:
            lines += [f"=== RUN   {name}/{sub}", f"    --- {sv}: {name}/{sub} (1.00s)"]
        lines.append(f"--- {verdict}: {name} (12.34s)")
    lines += ["PASS" if all(r[1] == "PASS" for r in results) else "FAIL", *packages[1:]]
    return "\n".join(lines) + "\n"


class ParseLogTests(unittest.TestCase):
    def parse(self, text, tests=TESTS):
        return evidence.parse_log(text, tests)

    def test_every_test_passing_is_a_pass(self):
        results, problems = self.parse(go_log(("TestLiveA", "PASS", ("sub", "PASS")), ("TestLiveB", "PASS")))
        self.assertEqual(results, {"TestLiveA": "pass", "TestLiveB": "pass"})
        self.assertEqual(problems, [])

    def test_failed_skipped_or_absent_tests_do_not_pass(self):
        cases = {
            "fail": go_log(("TestLiveA", "FAIL"), ("TestLiveB", "PASS")),
            "skip": go_log(("TestLiveA", "SKIP"), ("TestLiveB", "PASS")),
            "subtest skip": go_log(("TestLiveA", "PASS", ("x", "SKIP")), ("TestLiveB", "PASS")),
            "subtest fail": go_log(("TestLiveA", "PASS", ("x", "FAIL")), ("TestLiveB", "PASS")),
            "missing": go_log(("TestLiveB", "PASS")),
            "ambiguous": go_log(("TestLiveA", "PASS"), ("TestLiveA", "PASS"), ("TestLiveB", "PASS")),
        }
        want = {"fail": "fail", "skip": "skip", "subtest skip": "skip", "subtest fail": "fail", "missing": "missing", "ambiguous": "ambiguous"}
        for what, text in cases.items():
            with self.subTest(what):
                results, _ = self.parse(text)
                self.assertEqual(results["TestLiveA"], want[what])
                self.assertEqual(results["TestLiveB"], "pass")

    def test_pass_line_must_be_the_tests_own_top_level_result(self):
        # Indented or quoted text that merely mentions a pass does not count.
        text = go_log(("TestLiveB", "PASS")) + "    log.go:1: --- PASS: TestLiveA (1.00s)\n" + "    --- PASS: TestLiveA (1.00s)\n"
        results, _ = self.parse(text)
        self.assertEqual(results["TestLiveA"], "missing")
        results, _ = self.parse(go_log(("TestLiveA/sub", "PASS"), ("TestLiveB", "PASS")))
        self.assertEqual(results["TestLiveA"], "missing")

    def test_untrustworthy_logs_are_reported(self):
        good = go_log(("TestLiveA", "PASS"), ("TestLiveB", "PASS"))
        cases = {
            "unexpected test": go_log(("TestLiveA", "PASS"), ("TestLiveB", "PASS"), ("TestLiveC", "PASS")),
            "failed package": good + "FAIL\tgithub.com/backend-bunny/Konstapel/internal/controller\t1.0s\n",
            "build failure": good + "FAIL\tgithub.com/backend-bunny/Konstapel/internal/controller [build failed]\n",
            "panic": good + "panic: test timed out after 25m0s\n",
            "no package result": good.replace("ok  \t", "??  \t"),
            "empty log": "",
        }
        for what, text in cases.items():
            with self.subTest(what):
                _, problems = self.parse(text)
                self.assertTrue(problems, f"{what} was accepted")


class FrozenGroupTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo)
        for args in (["init", "-q"], ["config", "user.name", "t"], ["config", "user.email", "t@example.invalid"]):
            subprocess.run(["git", *args], cwd=self.repo, check=True)

    def commit(self, groups):
        path = self.repo / evidence.GROUPS_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(groups))
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "x"], cwd=self.repo, check=True)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()

    @staticmethod
    def group(release, tests=("TestLiveA",), image=True):
        g = {"goTests": list(tests), "release": release}
        if image is not None:
            g["image"] = image
        return g

    def test_requirements_are_read_from_the_commit_not_the_working_tree(self):
        commit = self.commit({"charts": self.group(True), "storage": self.group(False, ["TestLiveS"], None)})
        (self.repo / evidence.GROUPS_FILE).write_text(json.dumps({"charts": self.group(True, ["TestLiveOther"])}))
        self.assertEqual(evidence.frozen_groups(commit, self.repo), {"charts": ["TestLiveA"]})

    def test_unknown_commits_and_missing_files_fail_closed(self):
        commit = self.commit({"charts": self.group(True)})
        for bad in ("f" * 40, "HEAD", commit[:12], None):
            with self.subTest(commit=bad), self.assertRaises(evidence.Rejected):
                evidence.frozen_groups(bad, self.repo)
        (self.repo / evidence.GROUPS_FILE).unlink()
        subprocess.run(["git", "commit", "-qam", "rm"], cwd=self.repo, check=True)
        gone = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()
        with self.assertRaisesRegex(evidence.Rejected, "cannot read"):
            evidence.frozen_groups(gone, self.repo)

    def test_every_group_must_be_classified(self):
        bad = {
            "missing marker": {"charts": self.group(True), "storage": {"goTests": ["TestLiveS"]}},
            "non-boolean marker": {"charts": self.group("true")},
            "no release group": {"storage": self.group(False)},
            "release group without the published image": {"charts": self.group(True, image=None)},
            "release group without tests": {"charts": self.group(True, tests=())},
            "release group with a non-live test": {"charts": self.group(True, tests=("TestUnit",))},
            "release group listing a test twice": {"charts": self.group(True, tests=("TestLiveA", "TestLiveA"))},
            "not an object": [],
        }
        for what, groups in bad.items():
            with self.subTest(what), self.assertRaises(evidence.Rejected):
                evidence.release_groups(groups)


class RecordTests(unittest.TestCase):
    """The record builder against group output laid out as scripts/acceptance.sh
    writes it, for the release groups committed at HEAD."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.archives = self.dir / "archives"
        self.archives.mkdir()
        fixtures.package(self.archives, "konstapel-crds")
        fixtures.package(self.archives, "konstapel")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(manifest.main(["freeze", "--archives", str(self.archives), "--source", HEAD, "--tag", fixtures.TAG,
                                            "--image-digest", fixtures.DIGEST, "--out", str(self.archives / "publication.json")]), 0)
        self.frozen = json.loads((self.archives / "publication.json").read_text())
        self.required = evidence.frozen_groups(HEAD)
        self.groups = self.dir / "groups"
        for group, tests in self.required.items():
            self.write_group(group, go_log(*[(t, "PASS") for t in tests]))

    def write_group(self, group, log, exit_code=0, image=IMAGE):
        d = self.groups / group
        (d / "targeting").mkdir(parents=True, exist_ok=True)
        (d / evidence.LOG).write_text(log)
        (d / evidence.RESULT).write_text(json.dumps({"group": group, "passed": exit_code == 0, "exitCode": exit_code}))
        (d / evidence.IMAGE_REF).write_text(image + "\n")

    def record(self):
        out = self.dir / "chart-acceptance.json"
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = evidence.main(["record", "--archives", str(self.archives), "--groups-dir", str(self.groups), "--image", IMAGE,
                                  "--source", HEAD, "--runtime", '{"kind":"v0"}', "--out", str(out)])
        return code, err.getvalue(), (json.loads(out.read_text()) if out.exists() else None)

    def test_full_pass_writes_a_record_the_publisher_accepts(self):
        code, err, record = self.record()
        self.assertEqual(code, 0, err)
        self.assertEqual(record["apiVersion"], evidence.ACCEPTANCE)
        self.assertEqual(set(record["groups"]), set(self.required))
        for group, tests in self.required.items():
            g = record["groups"][group]
            self.assertEqual([t["name"] for t in g["tests"]], tests)
            self.assertEqual(g["files"][evidence.LOG], evidence.sha256_file(self.groups / group / evidence.LOG))
        evidence.check(self.frozen, record, self.required)
        # Records are never replaced.
        self.assertEqual(self.record()[0], 1)

    def assertNoRecord(self, text):
        code, err, record = self.record()
        self.assertNotEqual(code, 0)
        self.assertIsNone(record, "a record was written for a release acceptance that did not pass")
        self.assertIn(text, err)

    def test_any_incomplete_group_writes_no_record(self):
        last = list(self.required)[-1]
        tests = self.required[last]
        passing = go_log(*[(t, "PASS") for t in tests])
        cases = {
            "skipped test with exit 0": (lambda: self.write_group(last, go_log(*[(t, "PASS") for t in tests[:-1]], (tests[-1], "SKIP"))), "skip"),
            "failed test": (lambda: self.write_group(last, go_log(*[(t, "PASS") for t in tests[:-1]], (tests[-1], "FAIL")), 1), "fail"),
            "passing log with failing exit": (lambda: self.write_group(last, passing, 1), "exited 1"),
            "cancelled": (lambda: self.write_group(last, passing.splitlines()[0], 130), "exited 130"),
            "group never ran": (lambda: shutil.rmtree(self.groups / last), "group did not run"),
            "no result file": (lambda: (self.groups / last / evidence.RESULT).unlink(), "missing"),
            "no log": (lambda: (self.groups / last / evidence.LOG).unlink(), "missing"),
            "result for another group": (lambda: (self.groups / last / evidence.RESULT).write_text(json.dumps({"group": "charts-x", "passed": True, "exitCode": 0})), "names group"),
            "another image ran": (lambda: self.write_group(last, passing, image="ghcr.io/backend-bunny/konstapel@sha256:" + "ee" * 32), "cluster ran"),
            "locally built image ran": (lambda: (self.groups / last / evidence.IMAGE_REF).unlink(), "missing"),
        }
        for what, (damage, text) in cases.items():
            with self.subTest(what):
                for group, t in self.required.items():
                    shutil.rmtree(self.groups / group, ignore_errors=True)
                    self.write_group(group, go_log(*[(x, "PASS") for x in t]))
                damage()
                self.assertNoRecord(text)

    def test_manifest_from_another_source_writes_no_record(self):
        frozen = dict(self.frozen, source={"commit": "f" * 40, "tag": fixtures.TAG})
        (self.archives / "publication.json").write_text(json.dumps(frozen))
        self.assertNoRecord("frozen manifest source")


if __name__ == "__main__":
    unittest.main()
