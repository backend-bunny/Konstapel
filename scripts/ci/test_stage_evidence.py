"""Hand-break the evidence staging scan with credentials generated at test time.

No credential is committed: every positive fixture is assembled from random
bytes (and, where the tool is present, a real throwaway Cosign key pair) in a
temporary directory, then staged exactly as CI stages acceptance output.
"""

import base64
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import string
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stage_evidence", HERE / "stage-evidence.py")
stage_evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_evidence)

# Markers are split so this file never itself contains a key header.
BEGIN, END = "-----BEGIN ", "-----END "


def rand(n, alphabet=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def pem(kind):
    body = base64.encodebytes(secrets.token_bytes(120)).decode()
    return f"{BEGIN}{kind}PRIVATE KEY-----\n{body}{END}{kind}PRIVATE KEY-----\n"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt():
    header = b64url(json.dumps({"alg": "RS256", "kid": rand(8)}).encode())
    claims = b64url(json.dumps({"iss": "https://kubernetes.default.svc", "sub": "system:serviceaccount:t:" + rand(6)}).encode())
    return f"{header}.{claims}.{b64url(secrets.token_bytes(64))}"


def gz(data):
    return gzip.compress(data.encode() if isinstance(data, str) else data)


def tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def zipped(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def kubeconfig_with_key():
    key = base64.b64encode(pem("RSA ").encode()).decode()
    return (f"apiVersion: v1\nkind: Config\nusers:\n- name: kind-x\n  user:\n"
            f"    client-certificate-data: {base64.b64encode(secrets.token_bytes(48)).decode()}\n"
            f"    client-key-data: {key}\n")


# One planted credential per class, each mapped to the rule that must catch it.
def secret_cases():
    s3_access, s3_secret = rand(20, string.ascii_uppercase + string.digits), rand(40)
    return {
        "pem-rsa": ("keys/server.log", pem("RSA "), "pem-private-key"),
        "pem-ec": ("tls.txt", pem("EC "), "pem-private-key"),
        "pem-pkcs8": ("cert-manager.log", "issued\n" + pem(""), "pem-private-key"),
        "pem-openssh": ("ssh.txt", pem("OPENSSH "), "pem-private-key"),
        "pem-cosign": ("cosign.txt", pem("ENCRYPTED SIGSTORE "), "pem-private-key"),
        "pem-cosign-legacy": ("cosign-old.txt", pem("ENCRYPTED COSIGN "), "pem-private-key"),
        "pem-in-json": ("status.json", json.dumps({"key": pem("EC ")}), "pem-private-key"),
        "kubeconfig-client-key": ("copied-config.yaml", kubeconfig_with_key(), "kubeconfig-client-key"),
        "encoded-private-key": ("secret-data.txt", "tls.key=" + base64.b64encode(pem("EC ").encode()).decode(), "encoded-private-key"),
        "kubeconfig-token": ("token-config.yaml", f"users:\n- name: ci\n  user:\n    token: {rand(48)}\n", "kubeconfig-credential"),
        "bearer-token": ("runner.log", f"GET /apis 200\nAuthorization: Bearer {rand(64)}\n", "bearer-token"),
        "service-account-jwt": ("pod.log", f"loaded token {jwt()}\n", "jwt"),
        "basic-authorization": ("proxy.log", "Authorization: Basic " + base64.b64encode(f"reader:{rand(16)}".encode()).decode(), "basic-authorization"),
        "url-credentials": ("registry.log", f"pull https://reader-a:{rand(16)}@registry.test:5000/v2/\n", "url-credentials"),
        "aws-access-key-id": ("aws.log", "using AKIA" + rand(16, string.ascii_uppercase + string.digits), "cloud-access-key-id"),
        "s3-env-secret": ("docker.log", f"docker run -e RUSTFS_ACCESS_KEY=x -e RUSTFS_SECRET_KEY={s3_secret} rustfs\n", "credential-variable"),
        "s3-dev-env": ("s3/dev-env.txt", f"KONSTAPEL_S3_ACCESS_KEY={s3_access}\nKONSTAPEL_S3_SECRET_KEY={s3_secret}\n", "credential-variable"),
        "s3-json-secret": ("destination.json", json.dumps({"secretAccessKey": s3_secret}), "credential-field"),
        "s3-json-access": ("credentials.json", json.dumps({"accessKeyID": s3_access}), "credential-field"),
        "cosign-password": ("sign.log", f"COSIGN_PASSWORD={rand(24)}\n", "credential-variable"),
        "registry-password-flag": ("login.log", f"helm registry login registry.test --username reader --password {rand(20)}\n", "credential-flag"),
        "dockerconfigjson": ("auth.json", json.dumps({"auths": {"registry.test": {"auth": base64.b64encode(f"u:{rand(12)}".encode()).decode()}}}), "registry-auth"),
        "htpasswd-bcrypt": ("users.txt", "reader-a:$2y$04$" + rand(53, string.ascii_letters + string.digits + "./") + "\n", "htpasswd-entry"),
        "age-secret-key": ("age.txt", "AGE-SECRET-KEY-1" + rand(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"), "age-secret-key"),
        "github-token": ("gh.log", "token ghp_" + rand(36), "github-token"),
        "kubernetes-secret-json": ("objects.json", json.dumps({"items": [{"kind": "Secret", "data": {"secretAccessKey": base64.b64encode(s3_secret.encode()).decode()}}]}), "kubernetes-secret-data"),
        "kubernetes-secret-yaml": ("secret.yaml", f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s3\ndata:\n  accessKeyID: {base64.b64encode(s3_access.encode()).decode()}\n", "kubernetes-secret-data"),
        "key-filename": ("registry/server.key", "binary-ish key material", "sensitive-filename"),
        "htpasswd-filename": ("registry/htpasswd", "", "sensitive-filename"),
    }


class StageTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.source = self.tmp / "acceptance"
        self.dest = self.tmp / "upload"
        self.report = self.tmp / "report.txt"
        self.write("acceptance-result.json", json.dumps({"group": "charts", "passed": False, "exitCode": 1}))

    def write(self, name, content):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def stage(self):
        return stage_evidence.main([str(self.source), str(self.dest), "--report", str(self.report)])

    def assert_caught(self, rule, *secrets_values):
        self.assertEqual(self.stage(), 1)
        self.assertFalse(self.dest.exists(), "nothing may remain to upload")
        report = self.report.read_text()
        self.assertIn(rule, report)
        for value in secrets_values:
            self.assertNotIn(value, report, "the report must never repeat the credential")


class CatchesEachSecretClass(StageTest):
    def test_each_class_alone_fails_closed(self):
        for case, (name, content, rule) in secret_cases().items():
            with self.subTest(case=case):
                shutil.rmtree(self.source / "planted", ignore_errors=True)
                self.write("planted/" + name, content)
                self.assert_caught(rule, *[line for line in content.splitlines() if len(line) > 20])
                self.assertIn("planted/" + name, self.report.read_text())

    def test_archived_secrets_are_found_inside_members(self):
        key = pem("EC ")
        for name, data, member in (
                ("package.tar.gz", gz(tar({"content/a.json": "{}", "keys/k.txt": key})), "package.tar.gz!keys/k.txt"),
                ("logs.gz", gz("ok\n" + key), "logs.gz:2"),
                ("bundle.zip", zipped({"x/token.log": f"Authorization: Bearer {rand(40)}"}), "bundle.zip!x/token.log")):
            with self.subTest(archive=name):
                shutil.rmtree(self.source / "a", ignore_errors=True)
                self.write("a/" + name, data)
                self.assertEqual(self.stage(), 1)
                self.assertIn("a/" + member, self.report.read_text())

    def test_unreadable_archive_cannot_pass(self):
        self.write("broken.tar.gz", b"\x1f\x8b" + secrets.token_bytes(64))
        self.assert_caught("unscannable-archive")

    def test_real_cosign_key_pair(self):
        if not shutil.which("cosign"):
            self.skipTest("cosign is not on PATH (it is in the Devbox environment)")
        keys = self.source / "signing"
        keys.mkdir(parents=True)
        subprocess.run(["cosign", "generate-key-pair"], cwd=keys, check=True, capture_output=True, timeout=60,
                       env=dict(os.environ, COSIGN_PASSWORD=rand(16)))
        # Rename so only the content rule, not the file name, can catch it.
        (keys / "cosign.key").rename(keys / "generated.txt")
        self.assert_caught("signing/generated.txt:1: pem-private-key")

    def test_one_finding_among_clean_evidence_blocks_everything(self):
        self.write("targeting/targeting-live.log", "=== RUN TestLiveHelmInstall\n--- PASS\n")
        self.write("diagnostics/logs/konstapel-system.controller.log", f"level=info msg=started\nsecretAccessKey: {rand(40)}\n")
        self.assertEqual(self.stage(), 1)
        self.assertFalse(self.dest.exists())


class CleanEvidencePasses(StageTest):
    def test_clean_directory_is_staged_with_exclusions(self):
        self.write("targeting/targeting-live.log", "=== RUN TestLiveHelmBundles\n    bearer token authentication enabled\n--- PASS\n")
        self.write("targeting/TestLiveHelmDurableRecovery.json", json.dumps([{"privateKey": "deleted before handover"}, {"privateKey": "absent"}]))
        self.write("environment/kind-config.yaml", "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n")
        self.write("trusted-2026.pub", f"{BEGIN}PUBLIC KEY-----\n{base64.b64encode(secrets.token_bytes(64)).decode()}\n{END}PUBLIC KEY-----\n")
        self.write("ca.crt", f"{BEGIN}CERTIFICATE-----\n{base64.b64encode(secrets.token_bytes(64)).decode()}\n{END}CERTIFICATE-----\n")
        self.write("catalog.json", json.dumps({"prose": "Basic configuration settings for organizational systems"}))
        self.write("diagnostics/conditions.json", json.dumps([{"resource": "evidencedestinations.compliance.erenius.io", "status": {
            "conditions": [{"type": "Ready", "reason": "CredentialsMissing", "message": "Secret s3 has no key secretAccessKey"}]}}]))
        self.write("logs/controller.log", 'token: <redacted>\nAWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}\n"password": "REDACTED"\n')
        self.write("helm.yaml", "kind: Secret\nmetadata:\n  name: empty\ntype: Opaque\n")
        self.write("package.tar.gz", gz(tar({"content/component.json": "{}"})))
        # Left out, never uploaded: a live kubeconfig, test binaries, node logs, the Kyverno manifest.
        self.write("kubeconfig", kubeconfig_with_key())
        self.write("kubeconfig.lock", "")
        self.write("controller.test", b"\x7fELF" + pem("RSA ").encode())
        self.write("kind-logs/node/kubelet.log", f"Authorization: Bearer {rand(40)}")
        self.write("environment/helm-manifest.yaml", "kind: Secret\ndata:\n  tls.key: " + rand(40) + "\n")
        outside = self.tmp / "outside.txt"
        outside.write_text(pem("EC "))
        (self.source / "linked").symlink_to(outside)
        (self.source / "linked-dir").symlink_to(self.tmp)

        self.assertEqual(self.stage(), 0, self.report.read_text())
        self.assertEqual(self.report.read_text(), "")
        staged = sorted(p.relative_to(self.dest).as_posix() for p in self.dest.rglob("*") if p.is_file())
        for left_out in ("kubeconfig", "kubeconfig.lock", "controller.test", "kind-logs/node/kubelet.log",
                         "environment/helm-manifest.yaml", "linked", "linked-dir/outside.txt"):
            self.assertNotIn(left_out, staged)
        self.assertIn("targeting/targeting-live.log", staged)
        self.assertIn("package.tar.gz", staged)
        summary = json.loads((self.dest / "evidence-scan.json").read_text())
        self.assertEqual(summary["findings"], 0)
        self.assertIn("kubeconfig", summary["excluded"])
        self.assertIn("kind-logs/", summary["excluded"])
        self.assertIn("linked", summary["skipped"])
        self.assertIn("linked-dir/", summary["skipped"])

    def test_destination_must_be_fresh_and_separate(self):
        self.dest.mkdir()
        self.assertEqual(self.stage(), 1)
        self.assertEqual(stage_evidence.main([str(self.source), str(self.source / "upload")]), 1)
        self.assertEqual(stage_evidence.main([str(self.tmp / "missing"), str(self.tmp / "fresh")]), 1)


class UploadIsGated(unittest.TestCase):
    """Every workflow that uploads acceptance evidence uploads only the staged
    directory, and only after staging succeeded."""

    def test_acceptance_uploads_require_successful_staging(self):
        for workflow, source, staged, artifact in (
                ("test.yml", "$RUNNER_TEMP/acceptance", "acceptance-upload", "acceptance-evidence-"),
                ("charts.yml", "$RUNNER_TEMP/chart-acceptance", "chart-acceptance-upload", "chart-acceptance-evidence")):
            with self.subTest(workflow=workflow):
                text = (HERE.parents[1] / ".github/workflows" / workflow).read_text()
                stage_at = text.index("scripts/ci/stage-evidence.py \"" + source + "\"")
                upload_at = text.index("name: " + artifact)
                self.assertLess(stage_at, upload_at)
                upload = text[text.rindex("- uses: actions/upload-artifact", 0, upload_at):upload_at]
                self.assertIn("if: always() && steps.stage-evidence.outcome == 'success'", upload)
                paths = text[upload_at:text.index("retention-days", upload_at)]
                included = [line.strip() for line in paths.splitlines() if line.strip().startswith("${{ runner.temp }}")]
                self.assertEqual(included, ["${{ runner.temp }}/" + staged])


if __name__ == "__main__":
    unittest.main()
