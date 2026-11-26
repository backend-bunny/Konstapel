"""Run the real shell wrappers with fake tools; no Docker or cluster required."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
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
        self.stub("scripts/environment.sh", 'echo "environment-$1"; echo "environment-$1" >> "$PWD/calls.log"; if [[ $1 == delete ]]; then exit "${DELETE_EXIT:-0}"; fi')
        self.stub("scripts/acceptance-evidence.sh", 'echo "evidence-$1"; echo "evidence-$1" >> "$PWD/calls.log"')
        self.stub("bin/konstapel", 'echo "$1-stdout"; echo "$1-stderr" >&2; if [[ $1 == acceptance ]]; then exit "${RUNNER_EXIT:-0}"; fi')
        self.stub("bin/chainsaw", "echo chainsaw")
        self.stub("scripts/targeting-live.sh", 'echo "targeting-${4:-all}"; echo "require-userns=${KONSTAPEL_LIVE_REQUIRE_USERNS:-false}"')
        self.stub("scripts/exception-admission-live.sh", "echo exceptions")
        self.stub("scripts/fetch-chart.sh", 'echo "chart-$1"')
        self.stub("bin/helm", 'echo "helm $*"')
        self.stub("scripts/fetch-operator-crds.sh", 'echo "operator-bundle-$1"')
        self.stub("bin/kubectl", 'echo "kubectl $*"')
        (self.repo / "scripts/image").mkdir()
        self.stub("scripts/image/build.sh", "echo image-build")
        (self.repo / "scripts/examples").mkdir()
        self.stub("scripts/examples/reference-provider-image.sh", 'echo "reference-provider-image $1"')
        # crictl reports kind's import alias; ctr names the image by digest.
        self.stub("bin/docker", 'if [[ $* == *crictl* ]]; then echo \'{"status":{"repoDigests":["docker.io/library/import@sha256:abc"]}}\'; '
                  'elif [[ $* == *" ctr "* ]]; then echo "tagged ${*: -1}"; '
                  # Teardown verification lists containers labelled for the cluster.
                  'elif [[ $1 == ps ]]; then echo "$*" >> "$PWD/docker-ps.log"; [[ -z ${LEFTOVER:-} ]] || echo "$LEFTOVER"; '
                  'elif [[ $1 == rm ]]; then echo "removed ${*: -1}" >> "$PWD/docker-rm.log"; else echo "prepared-userns $2"; fi')

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
        # The version matrix comes first; diagnostics are collected before teardown, on success too.
        self.assertIn("evidence-versions", (self.out / "versions.log").read_text())
        self.assertIn("evidence-diagnostics", (self.out / "diagnostics.log").read_text())
        self.assertEqual(self.calls(), ["evidence-versions", "environment-create", "evidence-diagnostics", "environment-delete"])

    def calls(self):
        return (self.repo / "calls.log").read_text().split()

    def test_teardown_verification_fails_on_leftovers(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("label=konstapel.acceptance=konstapel-assessment-log-test", (self.repo / "docker-ps.log").read_text())
        self.assertIn("teardown verified", (self.out / "teardown.log").read_text())

        out = self.repo / "output-leftover"
        result = self.run_script("acceptance.sh", out, LEFTOVER="abc123")
        self.assertEqual(result.returncode, 1)
        self.assertIn("leftover test-owned containers: abc123", (out / "teardown.log").read_text())
        self.assertIn("removed abc123", (self.repo / "docker-rm.log").read_text())
        self.assertFalse(json.loads((out / "acceptance-result.json").read_text())["passed"])

        # A cluster that is still listed after the delete step fails the run.
        out = self.repo / "output-cluster"
        self.stub("scripts/environment.sh", 'echo "environment-$1"; if [[ $1 == delete ]]; then touch "$PWD/deleted"; fi')
        self.stub("bin/kind", 'if [[ $1 == get && $2 == clusters && -e $PWD/deleted ]]; then echo konstapel-assessment-log-test; fi; '
                  'if [[ $1 == get && $2 == nodes ]]; then echo stub-control-plane; fi')
        result = self.run_script("acceptance.sh", out)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("environment-delete", result.stdout)
        self.assertIn("leftover kind cluster: konstapel-assessment-log-test", (out / "teardown.log").read_text())
        self.assertNotIn("teardown verified", (out / "teardown.log").read_text())

    def test_runner_failure_survives_tee_and_teardown(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out, RUNNER_EXIT="23", DELETE_EXIT="9")
        self.assertEqual(result.returncode, 23)
        self.assertIn("environment-delete", result.stdout)
        self.assertIn("acceptance-stderr", (self.out / "runner.log").read_text())
        self.assertNotIn("Acceptance passed", result.stdout)
        self.assertEqual(json.loads((self.out / "acceptance-result.json").read_text()),
                         {"group": "all", "passed": False, "exitCode": 23, "outcome": "failed"})
        self.assertEqual(self.calls(), ["evidence-versions", "environment-create", "evidence-diagnostics", "environment-delete"])

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
                self.assertEqual("kubectl --kubeconfig" in result.stdout and "apply --server-side" in result.stdout, config.get("prometheusOperator", False))
                image = config.get("image", False)
                self.assertEqual("image-build" in result.stdout, image)
                self.assertEqual("tagged ghcr.io/backend-bunny/konstapel@sha256:abc" in result.stdout, image)
                reference = config.get("referenceProviderImage", False)
                self.assertEqual("reference-provider-image " + str(out / "reference-provider-image") in result.stdout, reference)
                self.assertEqual("tagged localhost/konstapel-example-reporting@sha256:abc" in result.stdout, reference)
                self.assertEqual(json.loads((out / "acceptance-result.json").read_text()),
                                 {"group": group, "passed": True, "exitCode": 0, "outcome": "passed"})
                self.assertIn("environment-delete", result.stdout)

    def test_deadline_stops_the_run_then_collects_and_tears_down(self):
        self.setup_acceptance()
        # A hung stage: the deadline must stop it and its children.
        self.stub("scripts/targeting-live.sh", 'echo targeting-started; sleep 300 & echo $! > "$PWD/hung.pid"; wait')
        result = self.run_script("acceptance.sh", self.out, "capabilities", KONSTAPEL_ACCEPTANCE_TIMEOUT="2s")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("targeting-started", result.stdout)
        self.assertIn("exceeded KONSTAPEL_ACCEPTANCE_TIMEOUT=2s", (self.out / "progress.log").read_text())
        self.assertTrue((self.out / "deadline-exceeded.txt").exists())
        self.assertEqual(self.calls(), ["evidence-versions", "environment-create", "evidence-diagnostics", "environment-delete"])
        self.assertIn("teardown verified", (self.out / "teardown.log").read_text())
        self.assertEqual(json.loads((self.out / "acceptance-result.json").read_text()),
                         {"group": "capabilities", "passed": False, "exitCode": 124, "outcome": "timed-out"})
        hung = int((self.repo / "hung.pid").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(hung, 0)

    def test_release_acceptance_bounds_each_group_and_stops_at_a_timeout(self):
        # The real release loop with stubbed group runs: each group gets its
        # own budget from evidence.py, a timed-out group fails the run, later
        # groups do not run, and no record can be written.
        (self.repo / "scripts/charts").mkdir()
        shutil.copy(ROOT / "scripts/charts/acceptance.sh", self.repo / "scripts/charts/acceptance.sh")
        (self.repo / "scripts/charts/manifest.py").write_text("")
        (self.repo / "scripts/charts/evidence.py").write_text(
            "import sys\n"
            "if sys.argv[1] == 'groups':\n    print('charts 50\\nmonitoring 55\\navailability 45')\n"
            "else:\n    open('calls.log', 'a').write('record\\n'); sys.exit(1)\n")
        # Reading stdin proves a group run cannot consume the remaining budgets.
        self.stub("scripts/acceptance.sh", 'cat >/dev/null; echo "$2 $KONSTAPEL_ACCEPTANCE_TIMEOUT" >> "$PWD/calls.log"; '
                  'if [[ $2 == "${TIMEOUT_GROUP:-}" ]]; then exit 124; fi')
        (self.repo / "archives").mkdir()
        (self.repo / ".gitignore").write_text("output/\ncalls.log\n")
        for args in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "x"]):
            subprocess.run(["git", *args], cwd=self.repo, check=True)
        image = "ghcr.io/backend-bunny/konstapel@sha256:" + "0" * 64
        result = subprocess.run(["bash", "scripts/charts/acceptance.sh", str(self.out), "archives", image], cwd=self.repo,
                                env=dict(self.env, TIMEOUT_GROUP="monitoring"), text=True, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.repo / "calls.log").read_text().splitlines(), ["charts 50m", "monitoring 55m", "record"])
        self.assertIn("Release acceptance group monitoring failed", result.stderr)
        self.assertIn("(budget 55m)", result.stdout)
        self.assertFalse((self.out / "chart-acceptance.json").exists())

    def test_deadline_is_validated(self):
        self.setup_acceptance()
        result = self.run_script("acceptance.sh", self.out, "capabilities", KONSTAPEL_ACCEPTANCE_TIMEOUT="soon")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.out.exists())

    def test_cancellation_collects_diagnostics_and_tears_down(self):
        self.setup_acceptance()
        self.stub("scripts/targeting-live.sh", 'echo targeting-started; touch "$PWD/started"; sleep 300')
        # A second cancellation signal during cleanup must not stop teardown.
        self.stub("scripts/acceptance-evidence.sh", 'echo "evidence-$1" >> "$PWD/calls.log"; '
                  'if [[ $1 == diagnostics ]]; then main=$(cat "$PWD/acceptance.pid"); kill -INT "$main"; kill -TERM "$main"; sleep 0.2; fi')
        shutil.copy(ROOT / "scripts/acceptance.sh", self.repo / "scripts/acceptance.sh")
        process = subprocess.Popen(["bash", "scripts/acceptance.sh", str(self.out), "capabilities"], cwd=self.repo, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        (self.repo / "acceptance.pid").write_text(str(process.pid))
        try:
            for _ in range(200):
                if (self.repo / "started").exists():
                    break
                time.sleep(0.05)
            self.assertTrue((self.repo / "started").exists())
            # CI cancellation reaches the whole process group.
            os.killpg(process.pid, signal.SIGINT)
            output, _ = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        self.assertEqual(process.returncode, 130, output)
        self.assertEqual(self.calls(), ["evidence-versions", "environment-create", "evidence-diagnostics", "environment-delete"])
        self.assertIn("teardown verified", (self.out / "teardown.log").read_text())
        self.assertEqual(json.loads((self.out / "acceptance-result.json").read_text()),
                         {"group": "capabilities", "passed": False, "exitCode": 130, "outcome": "interrupted"})

    def test_evidence_versions_record_pins_tools_and_charts(self):
        for tool, output in (("go", "go1.27.3"), ("kind", "kind v0.33.0 go1.26.10 linux/amd64"), ("helm", "v4.3.1"),
                             ("chainsaw", "Version: v0.2.15"), ("docker", "29.9.2")):
            self.stub("bin/" + tool, f'echo "{output}"')
        self.stub("bin/kubectl", 'echo \'{"clientVersion":{"gitVersion":"v1.37.2"}}\'')
        for chart in ("konstapel", "konstapel-crds"):
            (self.repo / "charts" / chart).mkdir(parents=True)
            (self.repo / "charts" / chart / "Chart.yaml").write_text(f"name: {chart}\nversion: 0.4.0 # x-release-please-version\n")
        (self.repo / "devbox.lock").write_text("{}")
        self.out.mkdir()
        result = self.run_script("acceptance-evidence.sh", "versions", self.out, "charts")
        self.assertEqual(result.returncode, 0, result.stderr)
        matrix = json.loads((self.out / "version-matrix.json").read_text())
        pins = dict(line.split("=", 1) for line in (ROOT / "scripts/runtime.env").read_text().splitlines()
                    if line.startswith("KONSTAPEL_"))
        self.assertEqual(matrix["pins"], pins)
        self.assertEqual(matrix["tools"]["kubectl"], "v1.37.2")
        self.assertEqual(matrix["tools"]["chainsaw"], "v0.2.15")
        self.assertEqual(matrix["tools"]["kind"], "kind v0.33.0 go1.26.10 linux/amd64")
        self.assertEqual([(c["name"], c["version"]) for c in matrix["charts"]["charts"]], [("konstapel-crds", "0.4.0"), ("konstapel", "0.4.0")])
        self.assertEqual(matrix["group"], "charts")

        # Release acceptance binds the frozen archives by checksum.
        archives = self.repo / "frozen"
        archives.mkdir()
        (archives / "konstapel-0.4.0.tgz").write_bytes(b"archive")
        out = self.repo / "release"
        out.mkdir()
        result = self.run_script("acceptance-evidence.sh", "versions", out, "charts", KONSTAPEL_LIVE_CHART_ARCHIVES=str(archives),
                                 KONSTAPEL_ACCEPTANCE_IMAGE="ghcr.io/backend-bunny/konstapel@sha256:" + "a" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        matrix = json.loads((out / "version-matrix.json").read_text())
        self.assertEqual(matrix["charts"]["archives"], [{"sha256": hashlib.sha256(b"archive").hexdigest(), "file": "konstapel-0.4.0.tgz"}])
        self.assertEqual(matrix["controllerImage"], "ghcr.io/backend-bunny/konstapel@sha256:" + "a" * 64)

    def test_evidence_diagnostics_project_status_and_never_fail(self):
        fixtures = self.repo / "fixtures"
        fixtures.mkdir()
        (fixtures / "events").write_text(json.dumps({"items": [{"metadata": {"namespace": "kyverno"}, "type": "Warning", "reason": "BackOff",
            "message": "restarting", "involvedObject": {"kind": "Pod", "name": "kyverno-a"}, "count": 3, "lastTimestamp": "2026-11-19T05:00:00Z"}]}))
        (fixtures / "pods").write_text(json.dumps({"items": [{"metadata": {"namespace": "konstapel-system", "name": "controller-a", "uid": "u"},
            "spec": {"nodeName": "n", "containers": [{"env": [{"name": "SECRET", "value": "spec-only-value"}]}]},
            "status": {"phase": "Running", "containerStatuses": [{"name": "c", "image": "img", "imageID": "img@sha256:1", "ready": True, "restartCount": 1}]}}]}))
        (fixtures / "binding").write_text(json.dumps({"items": [{"kind": "ComplianceBinding", "metadata": {"name": "b", "generation": 2},
            "spec": {"profile": "spec-only-value"}, "status": {"observedGeneration": 2, "conditions": [{"type": "Ready", "status": "False"}]}}]}))
        (fixtures / "deploy").write_text(json.dumps({"items": [{"kind": "Deployment", "metadata": {"namespace": "kyverno", "name": "k"},
            "spec": {"template": "spec-only-value"}, "status": {"conditions": [{"type": "Available", "status": "True"}], "replicas": 1}}]}))
        self.stub("bin/kubectl", 'f=$PWD/fixtures; case "$*" in '
                  '*"get events"*) cat "$f/events";; *"get pods"*) cat "$f/pods";; '
                  '*api-resources*) printf "deployments.apps\ncompliancebindings.compliance.erenius.io\nconfigmaps\nsecrets\n";; '
                  '*"get compliancebindings"*) cat "$f/binding";; *"get deployments.apps"*) cat "$f/deploy";; '
                  '*"logs"*) echo "log $*";; *"get leases"*) echo \'{"items":[]}\';; '
                  '*"version -o json"*) echo \'{"serverVersion":{"gitVersion":"v1.37.0","platform":"linux/amd64"}}\';; '
                  '*"get nodes"*) echo \'{"items":[{"metadata":{"name":"n"},"status":{"nodeInfo":{"kubeletVersion":"v1.37.0"}}}]}\';; '
                  '*) exit 7;; esac')
        self.stub("bin/helm", 'echo \'[{"name":"konstapel","namespace":"konstapel-system","chart":"konstapel-0.4.0","app_version":"0.4.0","revision":"1","status":"deployed"}]\'')
        self.stub("bin/docker", 'echo "$*" >> "$PWD/docker-calls"')
        self.out.mkdir()
        (self.out / "kubeconfig").write_text("fixture")
        (self.out / "version-matrix.json").write_text('{"group":"charts"}')
        (self.out / "image-ref.txt").write_text("ghcr.io/backend-bunny/konstapel@sha256:" + "b" * 64 + "\n")
        result = self.run_script("acceptance-evidence.sh", "diagnostics", self.out / "kubeconfig", "kind-x", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        d = self.out / "diagnostics"
        self.assertEqual(json.loads((d / "events.json").read_text())[0]["reason"], "BackOff")
        conditions = json.loads((d / "conditions.json").read_text())
        self.assertEqual({c["kind"] for c in conditions}, {"ComplianceBinding", "Deployment"})
        self.assertEqual(next(c for c in conditions if c["kind"] == "ComplianceBinding")["status"]["conditions"][0]["type"], "Ready")
        self.assertEqual(next(c for c in conditions if c["kind"] == "Deployment")["conditions"][0]["type"], "Available")
        self.assertTrue((d / "logs/konstapel-system.controller-a.log").exists())
        self.assertTrue((d / "logs/konstapel-system.controller-a.previous.log").exists())
        matrix = json.loads((self.out / "version-matrix.json").read_text())
        self.assertEqual(matrix["group"], "charts")
        self.assertEqual(matrix["cluster"]["kubernetes"]["gitVersion"], "v1.37.0")
        self.assertEqual(matrix["cluster"]["helmReleases"][0]["chart"], "konstapel-0.4.0")
        self.assertEqual(matrix["cluster"]["runningImages"], [{"image": "img", "imageID": "img@sha256:1"}])
        self.assertEqual(matrix["controllerImage"], "ghcr.io/backend-bunny/konstapel@sha256:" + "b" * 64)
        # Secrets, specs and container environments are never read.
        everything = "".join(p.read_text() for p in self.out.rglob("*") if p.is_file())
        self.assertNotIn("spec-only-value", everything)
        self.assertNotIn("get secrets", everything)
        self.assertNotIn("inspect", (self.repo / "docker-calls").read_text())
        self.assertIn("ok: events", (d / "collect.log").read_text())

        # An unreachable cluster leaves a report, not a failure.
        self.stub("bin/kubectl", "echo unreachable >&2; exit 1")
        out = self.repo / "unreachable"
        out.mkdir()
        (out / "kubeconfig").write_text("fixture")
        result = self.run_script("acceptance-evidence.sh", "diagnostics", out / "kubeconfig", "kind-x", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("failed: events", (out / "diagnostics/collect.log").read_text())

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
