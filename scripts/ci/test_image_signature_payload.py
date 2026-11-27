"""Tests for scripts/image/verify-signature-payload.sh, the controller image's
signature payload check, and for the places that must use or quote it: every
`cosign verify` of an image or chart in workflows and scripts. The
payloads have the shape `cosign verify` (pinned Cosign v3.1.3) prints; the
live behaviour is pinned by the signing fixture
(scripts/examples/reference-provider-signing.sh, acceptance group
`providers`). Needs jq; no network, registry or Cosign."""

import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/image/verify-signature-payload.sh"
REPO = "ghcr.io/backend-bunny/konstapel"
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
SIGN = "https://sigstore.dev/cosign/sign/v1"

spec = importlib.util.spec_from_file_location("image_summary", ROOT / "scripts/image/summary.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


notes = load("chart_release_notes", ROOT / "scripts/charts/release-notes.py")
attest = load("chart_attest", ROOT / "scripts/charts/attest.py")
# `cosign verify` itself, not verify-attestation or verify-blob.
VERIFY = re.compile(r"cosign verify(?![-\w])")
# ... run as a shell command (or quoted as one), not mentioned in prose.
VERIFY_COMMAND = re.compile(r"""(?:^|[;&|(]|\$\()\s*(?:devbox run -- )?['"]?cosign verify(?![-\w])""")


def unquote(line):
    """A command quoted in a shell array of documented lines, as written."""
    line = line.strip()
    if len(line) > 1 and line[0] == line[-1] and line[0] in "'\"":
        line = line[1:-1]
        if line and line[0] != "'":
            line = line.replace('\\"', '"').replace("\\$", "$")
    return line


def payload(kind, digest=DIGEST):
    return {"critical": {"identity": {"docker-reference": f"{REPO}@{digest}"},
                         "image": {"docker-manifest-digest": digest}, "type": kind},
            "optional": {}}


# What `cosign verify` printed for the published v0.3.0 image: the signature
# and every attestation, each as a verified payload.
PUBLISHED = [payload("https://github.com/backend-bunny/Konstapel/sources/v1"), payload("https://spdx.dev/Document"),
             payload("https://spdx.dev/Document"), payload(SIGN),
             payload("https://github.com/backend-bunny/Konstapel/notices/v1"), payload("https://slsa.dev/provenance/v1")]
ATTESTATIONS_ONLY = [p for p in PUBLISHED if p["critical"]["type"] != SIGN]


def script_filter():
    m = re.search(r"^filter='([^']*)'$", SCRIPT.read_text(), re.M)
    assert m, "verify-signature-payload.sh: filter not found"
    return m.group(1)


class PayloadCheckTests(unittest.TestCase):
    def run_check(self, content, image=f"{REPO}@{DIGEST}"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "signature.json"
            path.write_text(content if isinstance(content, str) else json.dumps(content))
            return subprocess.run([str(SCRIPT), str(path), image], capture_output=True, text=True)

    def assertAccepted(self, content, **kw):
        r = self.run_check(content, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)

    def assertRejected(self, content, **kw):
        r = self.run_check(content, **kw)
        self.assertNotEqual(r.returncode, 0, r.stdout)

    def test_signature_with_attestations_is_accepted(self):
        self.assertAccepted(PUBLISHED)

    def test_signature_alone_is_accepted(self):
        self.assertAccepted([payload(SIGN)])

    def test_attestations_only_is_rejected(self):
        r = self.run_check(ATTESTATIONS_ONLY)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no cosign image signature", r.stderr)

    def test_signature_for_another_digest_is_rejected(self):
        self.assertRejected([payload(SIGN, OTHER)] + ATTESTATIONS_ONLY)

    def test_type_and_digest_must_be_in_one_payload(self):
        # A signature for another digest and an attestation for this one.
        self.assertRejected([payload(SIGN, OTHER), payload("https://spdx.dev/Document")])

    def test_legacy_or_lookalike_types_are_rejected(self):
        for kind in ("cosign container image signature", SIGN + "/", "https://sigstore.dev/cosign/sign/v2", ""):
            with self.subTest(kind=kind):
                self.assertRejected([payload(kind)])

    def test_empty_or_malformed_output_is_rejected(self):
        for content in ("[]", "", "{}", "null", "not json", json.dumps(payload(SIGN)), '[{"critical":null}]'):
            with self.subTest(content=content):
                self.assertRejected(content)

    def test_image_must_be_a_digest_reference(self):
        for image in (f"{REPO}:0.3.0", REPO, DIGEST, f"{REPO}@sha256:abc", f"{REPO}@{DIGEST} x"):
            with self.subTest(image=image):
                self.assertRejected(PUBLISHED, image=image)

    def test_missing_file_is_rejected(self):
        r = subprocess.run([str(SCRIPT), "/nonexistent/signature.json", f"{REPO}@{DIGEST}"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


class UsageTests(unittest.TestCase):
    def test_docs_quote_the_filter_verbatim(self):
        line = f"jq -e --arg digest \"${{IMAGE#*@}}\" '{script_filter()}' signature.json"
        self.assertIn(line, (ROOT / "docs/images.md").read_text())

    def test_job_summary_uses_the_same_filter(self):
        self.assertEqual(summary.SIGNATURE_FILTER, script_filter())

    def test_chart_release_notes_use_the_same_filter(self):
        self.assertEqual(notes.SIGNATURE_FILTER, script_filter())

    def test_every_workflow_verify_is_followed_by_the_check(self):
        # Each `cosign verify` in a workflow (only the controller image's today;
        # the charts' run in scripts/charts/attest.py) is followed directly by
        # the payload check of the file it wrote, for the same reference.
        found = 0
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            lines = workflow.read_text().splitlines()
            for i, line in enumerate(lines):
                if not VERIFY.search(line):
                    continue
                found += 1
                m = re.search(r'cosign verify (?:--\S+ \S+ )*"(\$IMAGE@\$\w+)" > (\S+)$', line)
                self.assertTrue(m, f"{workflow.name}:{i + 1}: unrecognised cosign verify: {line.strip()}")
                ref, out = m.groups()
                self.assertEqual(lines[i + 1].strip(),
                                 f'devbox run -- bash scripts/image/verify-signature-payload.sh {out} "{ref}"',
                                 f"{workflow.name}:{i + 2}")
        self.assertEqual(found, 3)

    def test_every_shell_script_verify_is_followed_by_the_check(self):
        # In scripts, the next command after each `cosign verify` (step
        # markers aside) checks the payloads it wrote: by the script, or by
        # the same filter quoted verbatim (unescaped from a quoted string).
        found = 0
        for script in sorted((ROOT / "scripts").rglob("*.sh")):
            if script == SCRIPT:
                continue
            lines = script.read_text().splitlines()
            for i, line in enumerate(lines):
                if not VERIFY_COMMAND.search(line):
                    continue
                found += 1
                where = f"{script.relative_to(ROOT)}:{i + 1}"
                m = re.search(r"> (\S+?)['\"]?$", line)
                self.assertTrue(m, f"{where}: cosign verify output is not kept for the payload check")
                out = m.group(1)
                quoted = line.strip()[0] in "'\""
                rest = [unquote(l) if quoted else l.strip() for l in lines[i + 1:] if not l.strip().startswith(("step ", "#"))]
                self.assertTrue(rest, where)
                check = rest[0]
                self.assertTrue(
                    re.fullmatch(r'"\$root/scripts/image/verify-signature-payload\.sh" ' + re.escape(out) + r" .+", check)
                    or re.fullmatch(r'jq -e --arg digest "\$\{\w+#\*@\}" ' + re.escape(f"'{script_filter()}' {out}"), check),
                    f"{where}: not followed by the signature payload check: {check}")
        self.assertEqual(found, 5)

    def test_every_python_verify_uses_the_check(self):
        sites = {p.relative_to(ROOT).as_posix() for p in (ROOT / "scripts").rglob("*.py")
                 if p.parent.name != "ci" and re.search(r'cosign verify |"verify",? ', p.read_text())
                 and "cosign" in p.read_text()}
        self.assertEqual(sites, {"scripts/charts/attest.py", "scripts/charts/release-notes.py", "scripts/image/summary.py"})

    def test_chart_attest_runs_cosign_verify_only_with_the_check(self):
        self.assertEqual(attest.PAYLOAD_CHECK, SCRIPT)
        tree = ast.parse((ROOT / "scripts/charts/attest.py").read_text())
        funcs = {f.name: f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)}
        owners = []
        for name, f in funcs.items():
            for call in ast.walk(f):
                if (isinstance(call, ast.Call) and getattr(call.func, "id", None) == "cosign" and len(call.args) > 1
                        and isinstance(call.args[1], ast.Constant) and call.args[1].value == "verify"):
                    owners.append(name)
        self.assertEqual(owners, ["signature_failure"])
        self.assertIn("PAYLOAD_CHECK", ast.unparse(funcs["signature_failure"]))
        for caller in ("sign", "verify"):
            calls = [c.func.id for c in ast.walk(funcs[caller]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]
            self.assertIn("signature_failure", calls, caller)

    def test_chart_release_notes_check_each_verified_signature(self):
        charts = {n: {"version": "0.3.0", "reference": f"ghcr.io/backend-bunny/charts/{n}", "digest": d, "archiveSha256": "sha256:" + "c" * 64}
                  for n, d in (("konstapel-crds", DIGEST), ("konstapel", OTHER))}
        lines = notes.block({"source": {"commit": "d" * 40, "tag": "v0.3.0"}, "image": {"digest": DIGEST}, "charts": charts}).splitlines()
        found = 0
        for i, line in enumerate(lines):
            if not VERIFY.search(line):
                continue
            found += 1
            m = re.search(r" (\S+@(sha256:[0-9a-f]{64})) > (\S+)$", line)
            self.assertTrue(m, line)
            ref, digest, out = m.groups()
            self.assertEqual(lines[i + 1], f"jq -e --arg digest {digest} '{script_filter()}' {out} > /dev/null")
            self.assertEqual(subprocess.run(["jq", "-e", "--arg", "digest", digest, script_filter()], input=json.dumps(ATTESTATIONS_ONLY),
                                            capture_output=True, text=True).returncode, 1, "the notes' check accepts attestations only")
        self.assertEqual(found, 2)

    def test_job_summary_checks_its_verified_signature(self):
        text = (ROOT / "scripts/image/summary.py").read_text().splitlines()
        i = next(i for i, l in enumerate(text) if VERIFY.search(l))
        self.assertIn("> signature.json", text[i])
        rest = [l for l in text[i + 1:] if not l.strip().startswith('"#')]
        self.assertIn('"jq -e --arg digest \\"${IMAGE#*@}\\" " + shlex.quote(SIGNATURE_FILTER) + " signature.json"', rest[0])

if __name__ == "__main__":
    unittest.main()
