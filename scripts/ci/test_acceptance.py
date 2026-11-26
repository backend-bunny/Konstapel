"""Exercise CI decisions with real Git diffs and mocked GitHub responses."""

import copy
from collections import Counter
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("require_acceptance", HERE / "require-acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class GroupCoverageTests(unittest.TestCase):
    def test_every_compiled_live_test_runs_in_exactly_one_group(self):
        # -list compiles/discovers tests without starting a cluster. Fail when a
        # new live test is unassigned, or a stale/duplicate selection is present.
        output = subprocess.check_output(
            ["go", "test", "-mod=readonly", "-tags", "live", "-list", "^TestLive",
             "./internal/targeting/", "./internal/controller/"],
            cwd=HERE.parents[1], text=True, timeout=180,
        )
        discovered = Counter(re.findall(r"^TestLive\w+$", output, re.MULTILINE))
        assigned = Counter(test for group in acceptance.GROUPS.values() for test in group["goTests"])
        # The exceptionAdmission stage runs the tests its script selects.
        script = (HERE.parents[1] / "scripts" / "exception-admission-live.sh").read_text()
        selected = re.search(r'-test\.run "\^\(?([\w|]+)\)?\$"', script)
        self.assertIsNotNone(selected)
        for group in acceptance.GROUPS.values():
            if group["exceptionAdmission"]:
                for test in selected.group(1).split("|"):
                    assigned[test] += 1
        self.assertTrue(discovered)
        self.assertEqual(assigned, discovered)
        self.assertTrue(all(count == 1 for count in assigned.values()))
        self.assertEqual(sum(group["core"] for group in acceptance.GROUPS.values()), 1)


class SigningAcceptanceTests(unittest.TestCase):
    """add-evidence-signing 6.1: the signing blackbox cases are part of the
    mandatory acceptance inventory. They run in groups CI always requires
    (the acceptance gate requires every group), on real Kubernetes APIs with
    the test S3 service; leader loss mid-signing runs in the release group
    that installs the image."""

    REQUIRED = {
        "TestLiveDestinationSigning": "storage",
        "TestLiveSignedEvidenceDownload": "storage",
        "TestLiveSignedPublicationWorkflow": "storage",
        "TestLiveHelmDurableRecovery": "availability",
    }

    def test_signing_cases_are_in_required_groups(self):
        for test, group in self.REQUIRED.items():
            with self.subTest(test=test):
                self.assertIn(test, acceptance.GROUPS[group]["goTests"])

    def test_the_durable_recovery_case_exercises_signing(self):
        text = (HERE.parents[1] / "internal/controller/helm_availability_durable_live_test.go").read_text()
        self.assertIn("l.signedHandover(", text)


class SigningRecoveryAcceptanceTests(unittest.TestCase):
    """add-evidence-signing-recovery 5.1: live recovery of a SigningFailed run
    after its key Secret is restored, verified offline with the pinned Cosign,
    runs in the mandatory storage group on the test S3 service."""

    REQUIRED = {
        "TestLiveSigningRecoveryWorkflow": "storage",
    }

    def test_recovery_cases_are_in_required_groups(self):
        for test, group in self.REQUIRED.items():
            with self.subTest(test=test):
                self.assertIn(test, acceptance.GROUPS[group]["goTests"])

    def test_the_workflow_verifies_offline_with_cosign(self):
        text = (HERE.parents[1] / "internal/controller/signing_recovery_workflow_live_test.go").read_text()
        self.assertIn("verifyOfflinePair(", text)
        self.assertIn("pinnedCosign(", text)


class AttachmentAcceptanceTests(unittest.TestCase):
    """add-supporting-evidence-attachments: the attachment API, storage,
    authenticated transfer and lifecycle cases run in groups CI always
    requires, on real Kubernetes APIs (admission) and with the test S3
    service (storage)."""

    REQUIRED = {
        "TestLiveEvidenceAttachmentAPI": "admission",
        "TestLiveAttachmentStorage": "storage",
        "TestLiveAttachmentTransfer": "storage",
        "TestLiveAttachmentLifecycle": "storage",
    }

    def test_attachment_cases_are_in_required_groups(self):
        for test, group in self.REQUIRED.items():
            with self.subTest(test=test):
                self.assertIn(test, acceptance.GROUPS[group]["goTests"])


class ReleaseGroupTests(unittest.TestCase):
    """Release acceptance (scripts/charts/acceptance.sh) runs exactly the
    groups marked "release": true against the frozen chart archives and the
    released image digest. Every group must be classified consciously, and a
    test that installs the charts or the controller image cannot sit in a
    group that release acceptance skips."""

    CHART_USE = re.compile(r"\b(chartArchive|chartDir|imageValues)\(|KONSTAPEL_LIVE_IMAGE")

    def release(self):
        spec = importlib.util.spec_from_file_location("evidence", HERE.parent / "charts/evidence.py")
        evidence = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(evidence)
        return evidence.release_groups(acceptance.GROUPS)

    def test_every_group_is_classified_and_release_groups_install_the_image(self):
        for name, group in acceptance.GROUPS.items():
            with self.subTest(group=name):
                self.assertIsInstance(group.get("release"), bool)
                self.assertEqual(group["release"], group.get("image") is True,
                                 "a group that installs the controller image must run in release acceptance, and only those")
        self.assertLessEqual({"charts", "availability"}, set(self.release()))

    def test_tests_that_install_charts_or_the_image_run_in_release_acceptance(self):
        release = {test for tests in self.release().values() for test in tests}
        found = set()
        for path in sorted((HERE.parents[1] / "internal").rglob("*_live_test.go")):
            text = path.read_text()
            if path.name == "chartsource_live_test.go" or not self.CHART_USE.search(text):
                continue
            for test in re.findall(r"(?m)^func (TestLive\w+)\(", text):
                found.add(test)
                with self.subTest(test=test, file=path.name):
                    self.assertIn(test, release)
        self.assertTrue(found, "no chart-installing live tests found")


def job(workflow, name):
    """The text of one job of a workflow file (no YAML parser in Devbox)."""
    text = (HERE.parents[1] / ".github/workflows" / workflow).read_text()
    found = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text)
    assert found, f"{workflow} has no job {name}"
    return found.group(1)


class AcceptanceBudgetTests(unittest.TestCase):
    """Every group's run is bounded by its "timeoutMinutes" (scripts/acceptance.sh
    KONSTAPEL_ACCEPTANCE_TIMEOUT: watchdog, exit 124, diagnostics, teardown), and
    each enclosing job leaves room for setup and the post-timeout cleanup, so
    a hung group fails with evidence instead of being killed by the runner."""

    # Measured on successful runs (2026-11-24): release setup about 1 minute
    # and the evidence steps seconds; PR jobs spend at most about 3 minutes
    # outside the run (image build included). After expiry, diagnostics alone
    # may take 5 minutes, then node logs and teardown.
    RELEASE_SETUP_AND_EVIDENCE = 15
    PR_SETUP_AND_EVIDENCE = 5
    POST_TIMEOUT_CLEANUP = 15

    def release_budgets(self):
        spec = importlib.util.spec_from_file_location("evidence", HERE.parent / "charts/evidence.py")
        evidence = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(evidence)
        return evidence.release_budgets(acceptance.GROUPS)

    def test_every_group_has_a_budget(self):
        for name, group in acceptance.GROUPS.items():
            with self.subTest(group=name):
                self.assertIs(type(group.get("timeoutMinutes")), int)
                self.assertGreaterEqual(group["timeoutMinutes"], 15)
        self.assertEqual(set(self.release_budgets()), {n for n, g in acceptance.GROUPS.items() if g["release"]})

    def test_release_job_timeout_covers_the_sequential_budgets(self):
        acceptance_job = job("charts.yml", "acceptance")
        minutes = re.search(r"(?m)^    timeout-minutes: (\d+)$", acceptance_job)
        self.assertIsNotNone(minutes, "the release acceptance job needs a literal timeout")
        # Groups run one after another and a failed group stops the run, so at
        # most one group overruns its budget by the post-timeout cleanup.
        need = sum(self.release_budgets().values()) + self.RELEASE_SETUP_AND_EVIDENCE + self.POST_TIMEOUT_CLEANUP
        self.assertGreaterEqual(int(minutes.group(1)), need)
        # The arithmetic comment must not drift from the budgets.
        for group, budget in self.release_budgets().items():
            self.assertIn(f"{group} {budget}", acceptance_job)
        self.assertIn(f"= {sum(self.release_budgets().values())}", acceptance_job)
        # The budget is applied by the script, not duplicated in YAML.
        self.assertNotIn("KONSTAPEL_ACCEPTANCE_TIMEOUT", acceptance_job)
        script = (HERE.parent / "charts/acceptance.sh").read_text()
        self.assertIn("KONSTAPEL_ACCEPTANCE_TIMEOUT=${minutes}m", script)

    def test_release_timeout_keeps_evidence_and_blocks_publication(self):
        acceptance_job = job("charts.yml", "acceptance")
        steps = re.split(r"(?m)^      - ", acceptance_job)[1:]
        named = {re.match(r"(?:name: |uses: )(.*)", st).group(1): st for st in steps}
        for step in ("Release acceptance summary", "Stage sanitized evidence"):
            self.assertRegex(named[step], r"(?m)^        if: always\(\)$")
        uploads = [st for st in steps if st.startswith("uses: actions/upload-artifact@")]
        evidence_upload = next(st for st in uploads if "name: chart-acceptance-evidence" in st)
        self.assertIn("if: always() && steps.stage-evidence.outcome == 'success'", evidence_upload)
        # The record is uploaded only when every earlier step, including the
        # acceptance run, succeeded, and it must exist.
        record_upload = next(st for st in uploads if "name: chart-acceptance\n" in st)
        self.assertNotIn("if:", record_upload)
        self.assertIn("if-no-files-found: error", record_upload)
        publish = job("charts.yml", "publish")
        self.assertRegex(publish, r"(?m)^    needs: \[freeze, acceptance\]$")
        self.assertNotRegex(publish, r"(?m)^    if:", "publish must not run after a failed or timed-out acceptance")
        self.assertNotIn("continue-on-error", (HERE.parents[1] / ".github/workflows/charts.yml").read_text())

    def test_pr_acceptance_derives_each_groups_budget_and_job_timeout(self):
        scope = job("test.yml", "acceptance-scope")
        self.assertIn("echo \"budgets=$(jq -c 'map_values(.timeoutMinutes)' scripts/acceptance-groups.json)\"", scope)
        overhead = re.search(r"job-timeouts=\$\(jq -c 'map_values\(\.timeoutMinutes \+ (\d+)\)'", scope)
        self.assertIsNotNone(overhead)
        self.assertGreaterEqual(int(overhead.group(1)), self.PR_SETUP_AND_EVIDENCE + self.POST_TIMEOUT_CLEANUP)
        live = job("test.yml", "acceptance-live")
        self.assertIn("timeout-minutes: ${{ fromJSON(needs.acceptance-scope.outputs.job-timeouts)[matrix.group] }}", live)
        self.assertIn("KONSTAPEL_ACCEPTANCE_TIMEOUT: ${{ fromJSON(needs.acceptance-scope.outputs.budgets)[matrix.group] }}m", live)


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
        for index, job in enumerate(jobs):
            with self.subTest(job=job["name"]):
                for conclusion in ("skipped", "failure", "cancelled", None):
                    bad = copy.deepcopy(jobs)
                    bad[index]["conclusion"] = conclusion
                    with self.assertRaises(acceptance.AcceptanceError):
                        acceptance.verify_jobs(bad)
                for bad in (jobs[:index] + jobs[index + 1:], jobs + [job]):
                    with self.assertRaises(acceptance.AcceptanceError):
                        acceptance.verify_jobs(bad)

    def test_old_single_job_cannot_stand_in_for_missing_groups(self):
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.verify_jobs([{"name": name, "conclusion": "success"}
                                    for name in ("checks", "acceptance-live", "acceptance")])

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
