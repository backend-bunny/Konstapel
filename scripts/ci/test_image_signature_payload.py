"""Tests for scripts/image/verify-signature-payload.sh, the controller image's
signature payload check, and for the places that must use or quote it. The
payloads have the shape `cosign verify` (pinned Cosign v3.1.3) prints; the
live behaviour is pinned by the signing fixture
(scripts/examples/reference-provider-signing.sh, acceptance group
`providers`). Needs jq; no network, registry or Cosign."""

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

    def test_every_controller_image_verify_is_followed_by_the_check(self):
        # Each `cosign verify` of the controller image in the publication
        # workflows is followed directly by the payload check of the file it
        # wrote, for the same reference.
        found = 0
        for workflow in ("publish.yml", "charts.yml"):
            lines = (ROOT / ".github/workflows" / workflow).read_text().splitlines()
            for i, line in enumerate(lines):
                m = re.search(r'cosign verify (?:--\S+ \S+ )*"(\$IMAGE@\$\w+)" > (\S+)$', line)
                if not m:
                    continue
                found += 1
                ref, out = m.groups()
                self.assertEqual(lines[i + 1].strip(),
                                 f'devbox run -- bash scripts/image/verify-signature-payload.sh {out} "{ref}"',
                                 f"{workflow}:{i + 2}")
            self.assertNotRegex("\n".join(lines), r'cosign verify [^\n]*"\$IMAGE@[^\n]*> /dev/null',
                                f"{workflow} discards a controller image's verified payloads")
        self.assertEqual(found, 3)


if __name__ == "__main__":
    unittest.main()
