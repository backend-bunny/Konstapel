"""Write-once chart publication against a fake OCI registry
(add-helm-oci-distribution 5.2, 6.6): frozen inputs and a matching acceptance
record, with every release-required group and test of the frozen source
passed, are required before any write; existing versions are never
replaced; a retry after partial publication pushes only what is missing."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/charts"))
sys.path.insert(0, str(ROOT / "scripts/ci"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


manifest = load("manifest", ROOT / "scripts/charts/manifest.py")
evidence = load("evidence", ROOT / "scripts/charts/evidence.py")
attest = load("attest", ROOT / "scripts/charts/attest.py")
notes = load("release_notes", ROOT / "scripts/charts/release-notes.py")
publish = load("publish", ROOT / "scripts/charts/publish.py")
fixtures = load("test_chart_manifest", ROOT / "scripts/ci/test_chart_manifest.py")
from oci_fake import FakeRegistry  # noqa: E402

HEAD = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
DIGEST = fixtures.DIGEST


# The release-required groups and tests as committed at HEAD, the frozen
# source of these fixtures.
REQUIRED = evidence.frozen_groups(HEAD)
FILES = {f: "sha256:" + "12" * 32 for f in evidence.EVIDENCE_FILES}


def groups_for(required=None) -> dict:
    return {g: {"required": True, "passed": True, "exitCode": 0, "files": dict(FILES),
                "tests": [{"name": t, "result": "pass"} for t in tests]}
            for g, tests in (required or REQUIRED).items()}


def acceptance_for(m: dict, **override) -> dict:
    record = {
        "apiVersion": "konstapel.dev/chart-acceptance/v2",
        "passed": True,
        "source": dict(m["source"]),
        "image": "ghcr.io/backend-bunny/konstapel@" + m["image"]["digest"],
        "crdContent": m["crdContent"],
        "charts": {n: {"version": c["version"], "sha256": c["sha256"]} for n, c in m["charts"].items()},
        "groups": groups_for(),
        "runtime": {"kind": "v0.0.0"},
    }
    record.update(override)
    return record


def mutated(m: dict, change) -> dict:
    record = acceptance_for(m)
    change(record)
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
        record = acceptance_for(self.frozen)
        del record["passed"]
        self.write_acceptance(record)
        self.assertRefusedBeforeWrites("did not pass")

    def test_missing_or_partial_record_is_refused(self):
        # A cancelled or crashed acceptance leaves no record, or a cut one.
        self.acceptance.unlink()
        self.assertRefusedBeforeWrites("no chart acceptance record")
        self.acceptance.write_text(json.dumps(acceptance_for(self.frozen))[:200])
        self.assertRefusedBeforeWrites("unreadable chart acceptance record")
        for value in ([], "passed", None):
            with self.subTest(record=value):
                self.write_acceptance(value)
                self.assertRefusedBeforeWrites("not an object")

    def test_stale_record_version_is_refused(self):
        # A v1 record carried no per-group evidence: charts group only.
        v1 = acceptance_for(self.frozen, apiVersion="konstapel.dev/chart-acceptance/v1", tests=REQUIRED["charts"])
        del v1["groups"]
        for record in (v1, acceptance_for(self.frozen, apiVersion="konstapel.dev/chart-acceptance/v1"),
                       acceptance_for(self.frozen, apiVersion="konstapel.dev/chart-acceptance/v3")):
            with self.subTest(apiVersion=record["apiVersion"]):
                self.write_acceptance(record)
                self.assertRefusedBeforeWrites("stale or unknown")

    def test_release_groups_are_charts_and_availability_at_least(self):
        self.assertLessEqual({"charts", "availability"}, set(REQUIRED))

    def test_missing_failed_cancelled_or_skipped_group_evidence_is_refused(self):
        first = next(iter(REQUIRED))
        tests = REQUIRED[first]

        def set_group(**fields):
            return lambda r: r["groups"][first].update(fields)

        def set_test(index, **fields):
            return lambda r: r["groups"][first]["tests"][index].update(fields)

        def drop_test_key(r):
            del r["groups"][first]["tests"][0]["result"]

        def drop_file(r):
            del r["groups"][first]["files"][evidence.LOG]

        cases = {
            "no group results": (lambda r: r.pop("groups"), "no group results"),
            "groups not an object": (lambda r: r.update(groups=list(r["groups"])), "no group results"),
            "empty groups": (lambda r: r.update(groups={}), "is missing"),
            "group malformed": (lambda r: r["groups"].update({first: "passed"}), "malformed result"),
            "group failed": (set_group(passed=False), "did not pass"),
            "group passed absent": (lambda r: r["groups"][first].pop("passed"), "did not pass"),
            "group passed as string": (set_group(passed="true"), "did not pass"),
            "group exit nonzero": (set_group(exitCode=1), "exited 1"),
            "group cancelled": (set_group(exitCode=130), "exited 130"),
            "group exit as bool": (set_group(exitCode=False), "exited False"),
            "group exit as string": (set_group(exitCode="0"), "exited '0'"),
            "group exit absent": (lambda r: r["groups"][first].pop("exitCode"), "exited None"),
            "group not required": (set_group(required=False), "not recorded as required"),
            "test failed": (set_test(0, result="fail"), "result 'fail'"),
            "test skipped": (set_test(-1, result="skip"), "result 'skip'"),
            "test missing from log": (set_test(0, result="missing"), "result 'missing'"),
            "test ambiguous in log": (set_test(0, result="ambiguous"), "result 'ambiguous'"),
            "test result absent": (drop_test_key, "result None"),
            "test results malformed": (set_group(tests=["x"]), "malformed test results"),
            "no test results": (set_group(tests=[]), "frozen source requires"),
            "test dropped": (set_group(tests=[{"name": t, "result": "pass"} for t in tests[:-1]]), "frozen source requires"),
            "test added": (set_group(tests=[{"name": t, "result": "pass"} for t in tests + ["TestLiveOther"]]), "frozen source requires"),
            "test renamed": (set_test(0, name=tests[0] + "X"), "frozen source requires"),
            "test duplicated": (set_group(tests=[{"name": t, "result": "pass"} for t in tests + tests[:1]]), "frozen source requires"),
            "log digest missing": (drop_file, "evidence file digests incomplete"),
            "log digest malformed": (lambda r: r["groups"][first]["files"].update({evidence.LOG: "abc"}), "evidence file digests incomplete"),
            "files absent": (lambda r: r["groups"][first].pop("files"), "evidence file digests incomplete"),
        }
        for group in REQUIRED:
            cases[f"group {group} absent"] = ((lambda g: lambda r: r["groups"].pop(g))(group), f"required acceptance group {group} is missing")
        cases["unrequired group recorded"] = (lambda r: r["groups"].update(admission=r["groups"][first]), "not release-required")
        # The record cannot name its own requirements: only the frozen source does.
        cases["self-declared requirements"] = (
            lambda r: r.update(groups={first: r["groups"][first]}, requiredGroups=[first]), "is missing")
        for what, (change, text) in cases.items():
            with self.subTest(what):
                self.write_acceptance(mutated(self.frozen, change))
                self.assertRefusedBeforeWrites(text)

    def test_requirements_come_from_the_frozen_source_commit(self):
        calls = []
        real = evidence.frozen_groups

        def stricter(commit, *args):
            calls.append(commit)
            required = real(commit, *args)
            first = next(iter(required))
            required[first] = required[first] + ["TestLiveAddedAtFrozenSource"]
            return required

        with patch.object(publish.evidence, "frozen_groups", stricter):
            self.assertRefusedBeforeWrites("frozen source requires")
        self.assertEqual(calls, [self.frozen["source"]["commit"]])
        # An unreadable or malformed group file at the source fails closed.
        with patch.object(publish.evidence, "frozen_groups", side_effect=publish.evidence.Rejected("cannot read")):
            self.assertRefusedBeforeWrites("cannot read")

    def test_acceptance_of_other_inputs_is_refused(self):
        other = "sha256:" + "ee" * 32
        cases = {
            "image": acceptance_for(self.frozen, image="ghcr.io/backend-bunny/konstapel@" + other),
            "source commit": acceptance_for(self.frozen, source={"commit": "f" * 40, "tag": fixtures.TAG}),
            "CRD content": acceptance_for(self.frozen, crdContent=other),
            "tag": acceptance_for(self.frozen, source={"commit": HEAD, "tag": "v9.9.9"}),
            "konstapel-crds archive": mutated(self.frozen, lambda r: r["charts"]["konstapel-crds"].update(sha256=other)),
            "konstapel archive": mutated(self.frozen, lambda r: r["charts"]["konstapel"].update(sha256=other)),
            "konstapel version": mutated(self.frozen, lambda r: r["charts"]["konstapel"].update(version="9.9.9")),
            "konstapel-crds archive None": mutated(self.frozen, lambda r: r["charts"].pop("konstapel-crds")),
        }
        for what, record in cases.items():
            with self.subTest(what):
                self.write_acceptance(record)
                self.assertRefusedBeforeWrites(f"tested {what.removesuffix(' None')}")

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

    def test_documented_install_commands_pull_the_frozen_archives(self):
        self.assertEqual(self.publish()[0], 0)
        r = self.result()
        text = notes.update("Generated changelog.\n\nUser note.\n", r)
        commands = [l for l in text.splitlines() if l.startswith(("helm pull", "echo '", "helm install"))]
        work = self.dir / "install"
        work.mkdir()
        for cmd in commands:
            if cmd.startswith("helm pull"):
                cmd += " --plain-http"
            if cmd.startswith("helm install"):
                # Render instead of installing: the archive the command names
                # is the one pulled and checked above.
                cmd = cmd.replace("helm install", "helm template", 1)
            p = subprocess.run(cmd, shell=True, cwd=work, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, f"{cmd}: {p.stderr}")
        self.assertEqual(len(commands), 6)

    def test_release_notes_block_is_idempotent(self):
        self.assertEqual(self.publish()[0], 0)
        r = self.result()
        once = notes.update("## Changelog\n\n* feat: x\n\nOperator note.\n", r)
        twice = notes.update(once, r)
        self.assertEqual(once, twice)
        self.assertIn("Operator note.", twice)
        self.assertEqual(twice.count(notes.START), 1)
        for c in r["charts"].values():
            self.assertIn(f"{c['reference']}@{c['digest']}", twice)
        bad = json.loads(json.dumps(r))
        bad["charts"]["konstapel"]["digest"] = "latest"
        with self.assertRaises(ValueError):
            notes.update(once, bad)


class AttestTests(PublishTests):
    """Signing and verification of the published subjects, with a key pair
    standing in for the release's keyless identity (5.3)."""

    def setUp(self):
        super().setUp()
        self.keys = self.dir / "keys"
        self.keys.mkdir()
        for prefix in ("release", "other"):
            subprocess.run(["cosign", "generate-key-pair", "--output-key-prefix", str(self.keys / prefix)], check=True,
                           capture_output=True, env=dict(os.environ, COSIGN_PASSWORD=""))
        self.assertEqual(self.publish()[0], 0)

    def attest(self, command, key="release", release="result.json", acceptance=None):
        suffix = ".key" if command == "sign" else ".pub"
        args = [command, "--release", str(self.dir / release), "--archives", str(self.archives), "--key", str(self.keys / (key + suffix)), "--plain-http"]
        if command == "sign":
            args += ["--acceptance", str(acceptance or self.acceptance)]
        return self.quiet(attest.main, args)

    def test_signed_release_verifies_and_pulls_the_frozen_bytes(self):
        self.assertEqual(self.attest("sign")[0], 0)
        code, err = self.attest("verify")
        self.assertEqual(code, 0, err)

    def test_unsigned_or_foreign_signatures_do_not_verify(self):
        code, err = self.attest("verify")
        self.assertNotEqual(code, 0)
        self.assertEqual(self.attest("sign", key="other")[0], 0)
        code, err = self.attest("verify")
        self.assertNotEqual(code, 0, "a signature by another key verified")

    def forge(self, record):
        """Sign and attest with an acceptance record that sign itself would
        refuse, as a compromised or buggy signer could: verify must still
        reject it."""
        forged = self.dir / "forged-acceptance.json"
        forged.write_text(json.dumps(record))
        with patch.object(attest.evidence, "check"), patch.object(attest, "verified_attestation", return_value=False):
            self.assertEqual(self.attest("sign", acceptance=forged)[0], 0)

    def test_sign_refuses_acceptance_the_publisher_would_refuse(self):
        first = next(iter(REQUIRED))
        for what, record in {
            "skipped test": mutated(self.frozen, lambda r: r["groups"][first]["tests"][0].update(result="skip")),
            "missing group": mutated(self.frozen, lambda r: r["groups"].pop(first)),
            "stale record": acceptance_for(self.frozen, apiVersion="konstapel.dev/chart-acceptance/v1"),
        }.items():
            with self.subTest(what):
                forged = self.dir / "refused-acceptance.json"
                forged.write_text(json.dumps(record))
                writes = len(self.registry.manifest_writes())
                code, err = self.attest("sign", acceptance=forged)
                self.assertNotEqual(code, 0)
                self.assertIn("acceptance:", err)
                self.assertEqual(len(self.registry.manifest_writes()), writes, "a refused acceptance was signed or attested")

    def test_attestation_for_other_inputs_does_not_verify(self):
        self.forge(acceptance_for(self.frozen, source={"commit": "f" * 40, "tag": fixtures.TAG}))
        code, err = self.attest("verify")
        self.assertNotEqual(code, 0)
        self.assertIn("no chart-inputs attestation", err)

    def test_attestation_with_incomplete_group_evidence_does_not_verify(self):
        # Each forged predicate names the released inputs exactly; only the
        # group evidence is wrong.
        groups = list(REQUIRED)
        for what, record in {
            "skipped test": mutated(self.frozen, lambda r: r["groups"][groups[-1]]["tests"][-1].update(result="skip")),
            "missing group": mutated(self.frozen, lambda r: r["groups"].pop(groups[-1])),
        }.items():
            with self.subTest(what):
                self.forge(record)
                code, err = self.attest("verify")
                self.assertNotEqual(code, 0)
                self.assertIn("no chart-inputs attestation", err)
        # The genuine record still attests and verifies alongside the forgeries.
        self.assertEqual(self.attest("sign")[0], 0)
        code, err = self.attest("verify")
        self.assertEqual(code, 0, err)

    def test_predicate_check_uses_the_released_source_groups(self):
        statement = {"predicateType": attest.CHART_INPUTS, "subject": [{"digest": {"sha256": self.result()["charts"]["konstapel"]["digest"].removeprefix("sha256:")}}],
                     "predicate": {"publication": self.frozen, "acceptance": acceptance_for(self.frozen)}}
        attest.check_predicate(self.result(), "konstapel", statement)
        statement["predicate"]["acceptance"]["groups"][next(iter(REQUIRED))]["exitCode"] = 1
        with self.assertRaisesRegex(attest.Failed, "attested acceptance: .* exited 1"):
            attest.check_predicate(self.result(), "konstapel", statement)

    def test_release_record_naming_other_bytes_does_not_verify(self):
        self.assertEqual(self.attest("sign")[0], 0)
        r = self.result()
        r["charts"]["konstapel"]["digest"] = r["charts"]["konstapel-crds"]["digest"]
        r["charts"]["konstapel"]["reference"] = r["charts"]["konstapel-crds"]["reference"]
        (self.dir / "swapped.json").write_text(json.dumps(r))
        code, err = self.attest("verify", release="swapped.json")
        self.assertNotEqual(code, 0)

    def test_signing_resumes_without_duplicating(self):
        self.assertEqual(self.attest("sign")[0], 0)
        writes = len(self.registry.manifest_writes())
        code, err = self.attest("sign")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.registry.manifest_writes()), writes, "a verified subject was signed again")

    # The publication cases are inherited; skip re-running them here.
    test_publishes_both_subjects_with_the_frozen_layers = None
    test_republishing_is_a_no_op = None
    test_requires_passing_acceptance = None
    test_missing_or_partial_record_is_refused = None
    test_stale_record_version_is_refused = None
    test_release_groups_are_charts_and_availability_at_least = None
    test_missing_failed_cancelled_or_skipped_group_evidence_is_refused = None
    test_requirements_come_from_the_frozen_source_commit = None
    test_acceptance_of_other_inputs_is_refused = None
    test_changed_archive_is_refused = None
    test_partial_publication_resumes = None
    test_existing_version_with_other_content_is_never_replaced = None
    test_documented_install_commands_pull_the_frozen_archives = None
    test_release_notes_block_is_idempotent = None


if __name__ == "__main__":
    unittest.main()
