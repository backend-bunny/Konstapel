"""Exercise CI decisions with real Git diffs and mocked GitHub responses."""

import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("require_acceptance", HERE / "require-acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.name", "CI tests")
        self.git("config", "user.email", "ci@example.invalid")
        self.write("README.md")
        self.write("internal/controller.go")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def write(self, name, content="initial\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def classify(self, event="pull_request", base=None, head=None):
        env = dict(os.environ, GITHUB_EVENT_NAME=event, PR_BASE_SHA=base or self.base,
                   PR_HEAD_SHA=head or self.git("rev-parse", "HEAD"))
        result = subprocess.run(["bash", str(HERE / "acceptance-scope.sh")], cwd=self.repo,
                                env=env, text=True, capture_output=True, check=True)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())["required"]

    def test_only_known_prose_skips(self):
        for name in ("README.md", "openspec/changes/example/specs/feature/spec.md", "docs/research/notes.md"):
            self.write(name, "updated\n")
        self.commit()
        self.assertEqual(self.classify(), "false")
        for event in ("push", "workflow_dispatch", "unknown"):
            self.assertEqual(self.classify(event), "true")

    def test_integration_docs_and_unknown_paths_run(self):
        for name in ("docs/integration/targeting-api.md", "future/runtime.yaml", "go.sum", ".github/workflows/test.yml"):
            with self.subTest(path=name):
                self.git("reset", "--hard", self.base)
                self.write(name)
                self.commit()
                self.assertEqual(self.classify(), "true")

    def test_code_renamed_into_prose_is_not_skipped(self):
        (self.repo / "internal/controller.go").rename(self.repo / "ARCHITECTURE.md")
        self.commit()
        self.assertEqual(self.classify(), "true")

    def test_deleted_code_runs(self):
        (self.repo / "internal/controller.go").unlink()
        self.commit()
        self.assertEqual(self.classify(), "true")

    def test_large_diff_does_not_hide_runtime_changes(self):
        for number in range(350):
            self.write(f"docs/research/{number}.md")
        self.write("internal/new.go")
        self.commit()
        self.assertEqual(self.classify(), "true")

    def test_newline_filename_cannot_hide_unknown_path(self):
        self.write("unknown\nREADME.md")
        self.commit()
        self.assertEqual(self.classify(), "true")

    def test_missing_history_and_empty_diff_run(self):
        self.assertEqual(self.classify(), "true")
        self.assertEqual(self.classify(base="f" * 40), "true")
        self.assertEqual(self.classify(head="invalid"), "true")


class GateTests(unittest.TestCase):
    def run_gate(self, **overrides):
        env = dict(os.environ, SCOPE_RESULT="success", CHECKS_RESULT="success", LIVE_RESULT="success",
                   ACCEPTANCE_REQUIRED="true", GITHUB_EVENT_NAME="pull_request")
        env.update(overrides)
        return subprocess.run(["bash", str(HERE / "acceptance-gate.sh")], env=env,
                              text=True, capture_output=True).returncode

    def test_full_success_and_explicit_prose_skip(self):
        self.assertEqual(self.run_gate(), 0)
        self.assertEqual(self.run_gate(ACCEPTANCE_REQUIRED="false", LIVE_RESULT="skipped"), 0)

    def test_missing_failed_cancelled_or_skipped_required_work_fails(self):
        for field in ("SCOPE_RESULT", "CHECKS_RESULT", "LIVE_RESULT"):
            for value in ("failure", "cancelled", "skipped", ""):
                with self.subTest(field=field, value=value):
                    self.assertNotEqual(self.run_gate(**{field: value}), 0)
        self.assertNotEqual(self.run_gate(ACCEPTANCE_REQUIRED=""), 0)

    def test_main_and_manual_cannot_use_prose_skip(self):
        for event in ("push", "workflow_dispatch"):
            self.assertNotEqual(self.run_gate(ACCEPTANCE_REQUIRED="false", LIVE_RESULT="skipped",
                                             GITHUB_EVENT_NAME=event), 0)


class PublicationTests(unittest.TestCase):
    repository = "backend-bunny/Konstapel"
    commit = "a" * 40

    def run_record(self, **overrides):
        run = dict(id=100, path=acceptance.WORKFLOW, head_sha=self.commit, head_branch="main",
                   event="push", head_repository={"full_name": self.repository}, status="completed",
                   conclusion="success", run_attempt=1, html_url="https://example.invalid/run/100")
        run.update(overrides)
        return run

    def test_only_trusted_exact_commit_runs_match(self):
        self.assertTrue(acceptance.matches_source(self.run_record(), self.repository, self.commit))
        for override in ({"head_sha": "b" * 40}, {"head_branch": "feature"}, {"event": "pull_request"},
                         {"path": ".github/workflows/image.yml"}, {"head_repository": None},
                         {"head_repository": {"full_name": "fork/Konstapel"}}):
            self.assertFalse(acceptance.matches_source(self.run_record(**override), self.repository, self.commit))

    def test_newer_failure_does_not_fall_back_to_old_success(self):
        failed = self.run_record(id=101, conclusion="failure")
        self.assertEqual(acceptance.select_run([self.run_record(), failed], self.repository, self.commit), failed)

    def test_full_jobs_required_even_when_gate_passed(self):
        jobs = [{"name": name, "conclusion": "success"} for name in acceptance.REQUIRED_JOBS]
        acceptance.verify_jobs(jobs)
        for conclusion in ("skipped", "failure", "cancelled", None):
            bad = copy.deepcopy(jobs)
            bad[1]["conclusion"] = conclusion
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_jobs(bad)
        for bad in (jobs[:1], jobs + [jobs[1]]):
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_jobs(bad)

    def test_success_is_bound_to_attempt_and_rechecked(self):
        run = self.run_record()
        jobs = [{"name": name, "conclusion": "success"} for name in acceptance.REQUIRED_JOBS]
        with patch.object(acceptance, "api", side_effect=[run, [{"jobs": jobs}], run]) as api:
            acceptance.wait_for_acceptance(self.repository, self.commit, 100, 0, 1)
        self.assertIn("/attempts/1/jobs", api.call_args_list[1].args[0])

    def test_rerun_race_does_not_authorize_publish(self):
        run = self.run_record()
        jobs = [{"name": name, "conclusion": "success"} for name in acceptance.REQUIRED_JOBS]
        rerun = self.run_record(run_attempt=2, status="in_progress", conclusion=None)
        with patch.object(acceptance, "api", side_effect=[run, [{"jobs": jobs}], rerun]):
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.wait_for_acceptance(self.repository, self.commit, 100, 0, 1)

    def test_failed_or_missing_evidence_blocks_publish(self):
        for responses in ([self.run_record(conclusion="failure")], [[{"workflow_runs": []}]]):
            with patch.object(acceptance, "api", side_effect=responses):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.wait_for_acceptance(self.repository, self.commit,
                                                   100 if isinstance(responses[0], dict) else None, 0, 1)


if __name__ == "__main__":
    unittest.main()
