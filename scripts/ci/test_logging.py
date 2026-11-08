"""Run the real shell wrappers with fake tools; no Docker or cluster required."""

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class LoggingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        (self.repo / "scripts").mkdir()
        (self.repo / "bin").mkdir()
        shutil.copy(ROOT / "scripts/runtime.env", self.repo / "scripts/runtime.env")
        shutil.copy(ROOT / "scripts/acceptance-groups.json", self.repo / "scripts/acceptance-groups.json")
        self.out = self.repo / "output"
        self.env = dict(os.environ, PATH=f"{self.repo / 'bin'}:{os.environ['PATH']}",
                        KONSTAPEL_CLUSTER_NAME="konstapel-assessment-log-test")
        self.stub("bin/kind", 'if [[ $1 == export ]]; then echo diagnostics; fi; if [[ $1 == get && $2 == nodes ]]; then echo stub-control-plane; fi')

    def stub(self, name, body):
        path = self.repo / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body + "\n")
        path.chmod(0o755)

    def run_script(self, name, *args, **env):
        shutil.copy(ROOT / "scripts" / name, self.repo / "scripts" / name)
        return subprocess.run(["bash", str(self.repo / "scripts" / name), *map(str, args)],
                              cwd=self.repo, env=dict(self.env, **env), text=True,
                              capture_output=True, timeout=15)

    def setup_acceptance(self):
        fixture = self.repo / "content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test"
        fixture.mkdir(parents=True)
        self.stub("scripts/build.sh", "echo build")
        self.stub("scripts/environment.sh", 'echo "environment-$1"; if [[ $1 == delete ]]; then exit "${DELETE_EXIT:-0}"; fi')
        self.stub("bin/konstapel", 'echo "$1-stdout"; echo "$1-stderr" >&2; if [[ $1 == acceptance ]]; then exit "${RUNNER_EXIT:-0}"; fi')
        self.stub("bin/chainsaw", "echo chainsaw")
        self.stub("scripts/targeting-live.sh", 'echo "targeting-${4:-all}"; echo "require-userns=${KONSTAPEL_LIVE_REQUIRE_USERNS:-false}"')
        self.stub("scripts/exception-admission-live.sh", "echo exceptions")
        self.stub("scripts/fetch-chart.sh", 'echo "chart-$1"')
        self.stub("bin/helm", 'echo "helm $*"')
        (self.repo / "scripts/image").mkdir()
        self.stub("scripts/image/build.sh", "echo image-build")
        # crictl reports kind's import alias; ctr names the image by digest.
        self.stub("bin/docker", 'if [[ $* == *crictl* ]]; then echo \'{"status":{"repoDigests":["docker.io/library/import@sha256:abc"]}}\'; '
                  'elif [[ $* == *" ctr "* ]]; then echo "tagged ${*: -1}"; else echo "prepared-userns $2"; fi')

    def test_acceptance_streams_stages_and_keeps_logs(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker, filename in (("build", "build.log"), ("environment-create", "environment.log"),
                                 ("acceptance-stdout", "runner.log"), ("acceptance-stderr", "runner.log"),
                                 ("validate-stdout", "validate.log"), ("chainsaw", "chainsaw.log"),
                                 ("convert-stdout", "reconvert.log"), ("diagnostics", "kind-export.log"),
                                 ("environment-delete", "teardown.log"), ("Acceptance passed", "result.txt")):
            self.assertIn(marker, result.stdout)
            self.assertIn(marker, (self.out / filename).read_text())
        self.assertIn("Running live targeting", (self.out / "progress.log").read_text())
        self.assertTrue(json.loads((self.out / "acceptance-result.json").read_text())["passed"])

    def test_runner_failure_survives_tee_and_teardown(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out, RUNNER_EXIT="23", DELETE_EXIT="9")
        self.assertEqual(result.returncode, 23)
        self.assertIn("environment-delete", result.stdout)
        self.assertIn("acceptance-stderr", (self.out / "runner.log").read_text())
        self.assertNotIn("Acceptance passed", result.stdout)
        self.assertEqual(json.loads((self.out / "acceptance-result.json").read_text()),
                         {"group": "all", "passed": False, "exitCode": 23})

    def test_groups_run_only_their_assigned_stages(self):
        self.setup_acceptance()
        groups = json.loads((ROOT / "scripts/acceptance-groups.json").read_text())
        for group, config in groups.items():
            with self.subTest(group=group):
                out = self.repo / group
                result = self.run_script("acceptance.sh", out, group)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"targeting-{group}", result.stdout)
                self.assertEqual("acceptance-stdout" in result.stdout, config["core"])
                self.assertEqual("chainsaw" in result.stdout, config["core"])
                self.assertEqual("exceptions" in result.stdout, config["exceptionAdmission"])
                self.assertEqual("prepared-userns konstapel-assessment-log-test-control-plane" in result.stdout, config["core"])
                self.assertEqual("require-userns=true" in result.stdout, config["core"])
                self.assertEqual("helm upgrade --install cert-manager chart-cert-manager" in result.stdout, config.get("certManager", False))
                image = config.get("image", False)
                self.assertEqual("image-build" in result.stdout, image)
                self.assertEqual("tagged ghcr.io/backend-bunny/konstapel@sha256:abc" in result.stdout, image)
                self.assertEqual(json.loads((out / "acceptance-result.json").read_text()),
                                 {"group": group, "passed": True, "exitCode": 0})
                self.assertIn("environment-delete", result.stdout)

    def test_userns_preparation_failure_fails_and_cleans_up(self):
        self.setup_acceptance()
        self.stub("bin/docker", "echo mount-failed >&2; exit 24")
        result = self.run_script("acceptance.sh", self.out, "admission")
        self.assertEqual(result.returncode, 24)
        self.assertIn("environment-delete", result.stdout)
        self.assertIn("mount-failed", (self.out / "userns-setup.log").read_text())
        self.assertNotIn("Acceptance passed", result.stdout)

    def test_unknown_group_stops_before_creating_output_or_cluster(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out, "typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.out.exists())
        self.assertNotIn("environment-create", result.stdout)

    def test_group_selectors_partition_the_full_run(self):
        self.stub("bin/go", 'while [[ $# -gt 0 ]]; do if [[ $1 == -run ]]; then printf "%s" "$2" > selected-tests; fi; shift; done')
        groups = json.loads((ROOT / "scripts/acceptance-groups.json").read_text())
        for group, config in groups.items():
            result = self.run_script("targeting-live.sh", "kubeconfig", "context", self.out, group)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.repo / "selected-tests").read_text(),
                             "^(" + "|".join(config["goTests"]) + ")$")
        result = self.run_script("targeting-live.sh", "kubeconfig", "context", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / "selected-tests").read_text(),
                         "^(" + "|".join(test for group in groups.values() for test in group["goTests"]) + ")$")
        self.assertNotEqual(self.run_script("targeting-live.sh", "kubeconfig", "context", self.out, "typo").returncode, 0)

    def test_teardown_failure_prevents_success(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out, DELETE_EXIT="9")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Acceptance passed", result.stdout)
        self.assertFalse(json.loads((self.out / "acceptance-result.json").read_text())["passed"])

    def test_targeting_output_arrives_before_go_finishes(self):
        self.stub("bin/go", 'echo live-output; echo live-stderr >&2; while [[ ! -e release ]]; do sleep 0.05; done; exit 17')
        shutil.copy(ROOT / "scripts/targeting-live.sh", self.repo / "scripts/targeting-live.sh")
        process = subprocess.Popen(["bash", "scripts/targeting-live.sh", "kubeconfig", "context", str(self.out)],
                                   cwd=self.repo, env=self.env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        first = b""
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5), "No output while test still running")
                first = os.read(process.stdout.fileno(), 4096)
            self.assertIn(b"live-output\n", first)
            self.assertIsNone(process.poll())
        finally:
            (self.repo / "release").touch()
            rest, _ = process.communicate(timeout=10)
        self.assertIn(b"live-stderr", first + rest)
        self.assertEqual(process.returncode, 17)
        self.assertEqual((self.out / "targeting-live.log").read_text(), "live-output\nlive-stderr\n")

    def test_exception_failure_keeps_logs_and_removes_temporary_inputs(self):
        self.stub("bin/go", 'echo compile-output; while [[ $# -gt 0 ]]; do if [[ $1 == -o ]]; then touch "$2"; fi; shift; done')
        self.stub("bin/docker", 'echo "$*" >> docker-calls; if [[ $1 == run ]]; then echo exception-stdout; echo exception-stderr >&2; exit 19; fi')
        result = self.run_script("exception-admission-live.sh", "konstapel-assessment-log-test", self.out)
        self.assertEqual(result.returncode, 19)
        self.assertIn("compile-output", result.stdout)
        self.assertIn("exception-stdout", result.stdout)
        self.assertIn("exception-stderr", (self.out / "exception-admission-live.log").read_text())
        self.assertFalse((self.out / "controller.test").exists())
        self.assertFalse((self.out / "kubeconfig-internal").exists())
        self.assertIn("rm --force konstapel-exception-", (self.repo / "docker-calls").read_text())

    def test_exception_compile_failure_stops_before_container_start(self):
        self.stub("bin/go", "echo compile-failed >&2; exit 18")
        self.stub("bin/docker", 'echo "$*" >> docker-calls')
        result = self.run_script("exception-admission-live.sh", "konstapel-assessment-log-test", self.out)
        self.assertEqual(result.returncode, 18)
        self.assertIn("compile-failed", result.stdout)
        self.assertIn("compile-failed", (self.out / "compile.log").read_text())
        self.assertNotIn("run --", (self.repo / "docker-calls").read_text())
        self.assertFalse((self.out / "kubeconfig-internal").exists())

    def test_helm_failure_reaches_stdout_and_file(self):
        self.stub("scripts/fetch-chart.sh", "echo fixture-chart")
        self.stub("bin/kubectl", "echo fixture-uid")
        self.stub("bin/helm", "echo helm-failed >&2; exit 21")
        result = self.run_script("environment.sh", "create", self.repo / "kubeconfig", self.out)
        self.assertEqual(result.returncode, 21)
        self.assertIn("helm-failed", result.stdout)
        self.assertIn("helm-failed", (self.out / "helm-install.log").read_text())


if __name__ == "__main__":
    unittest.main()
