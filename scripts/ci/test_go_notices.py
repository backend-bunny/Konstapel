"""Unit tests for the Go license classification and the reviewed overrides in
scripts/image/go-notices.py. No network, Go toolchain or image build needed."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("go_notices", ROOT / "scripts/image/go-notices.py")
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)

APACHE_NOTICE = b"Copyright 2021 Example\n\nLicensed under the Apache License, Version 2.0 (the \"License\");\n"


def modules(*pairs, main=None):
    out = {path: {"Path": path, "Version": version} for path, version in pairs}
    if main:
        out[main] = {"Path": main, "Main": True}
    return out


class ClassifyTests(unittest.TestCase):
    def test_identified_modules_pass(self):
        mods = modules(("example.com/a", "v1.0.0"), ("example.com/b", "v2.0.0"), main="github.com/backend-bunny/Konstapel")
        report = ("example.com/a/pkg,https://x,MIT\n"
                  "example.com/b,https://x,Apache-2.0\n"
                  "github.com/backend-bunny/Konstapel/cmd,https://x,Apache-2.0\n")
        got = notices.classify(report, mods, {})
        self.assertEqual(got["example.com/a"], {"MIT"})

    def test_unknown_license_fails_for_any_other_module(self):
        mods = modules(("example.com/a", "v1.0.0"), ("example.com/fake-unknown", "v0.1.0"),
                       ("github.com/in-toto/attestation", "v1.2.0"))
        overrides = notices.applicable_overrides(mods)
        report = "example.com/a,https://x,MIT\nexample.com/fake-unknown/pkg,Unknown,Unknown\n"
        with self.assertRaises(SystemExit) as e:
            notices.classify(report, mods, overrides)
        self.assertIn("example.com/fake-unknown@v0.1.0", str(e.exception))
        self.assertNotIn("in-toto", str(e.exception))

    def test_module_missing_from_report_fails(self):
        mods = modules(("example.com/a", "v1.0.0"), ("example.com/silent", "v1.0.0"))
        with self.assertRaises(SystemExit) as e:
            notices.classify("example.com/a,https://x,MIT\n", mods, {})
        self.assertIn("example.com/silent", str(e.exception))

    def test_unknown_row_of_an_overridden_module_is_tolerated_only_for_it(self):
        mods = modules(("github.com/in-toto/in-toto-golang", "v0.11.0"))
        overrides = notices.applicable_overrides(mods)
        notices.classify("github.com/in-toto/in-toto-golang/in_toto,Unknown,Unknown\n", mods, overrides)
        with self.assertRaises(SystemExit):
            notices.classify("github.com/in-toto/in-toto-golang/in_toto,Unknown,Unknown\n", mods, {})


class OverrideTableTests(unittest.TestCase):
    def test_exact_versions_apply(self):
        mods = modules(*notices.LICENSE_OVERRIDES)
        got = notices.applicable_overrides(mods)
        self.assertEqual(sorted(got), sorted(path for path, _ in notices.LICENSE_OVERRIDES))
        for (path, _), o in notices.LICENSE_OVERRIDES.items():
            self.assertEqual(o["license"], "Apache-2.0")
            self.assertRegex(o["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(o["reason"])

    def test_version_bump_fails_until_reviewed(self):
        mods = modules(("github.com/in-toto/attestation", "v1.3.0"))
        with self.assertRaises(SystemExit) as e:
            notices.applicable_overrides(mods)
        self.assertIn("v1.3.0", str(e.exception))

    def test_module_sharing_an_override_prefix_fails(self):
        mods = modules(("github.com/in-toto/attestation-extra", "v1.0.0"))
        with self.assertRaises(SystemExit):
            notices.applicable_overrides(mods)

    def test_unlinked_override_is_ignored(self):
        self.assertEqual(notices.applicable_overrides(modules(("example.com/a", "v1.0.0"))), {})

    def test_full_text_is_the_reviewed_apache_license(self):
        path, digest = notices.LICENSE_TEXTS["Apache-2.0"]
        self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)

    def test_shipped_commands_follow_the_build_script(self):
        self.assertEqual(notices.shipped_commands(ROOT / "scripts/build.sh"), ["./cmd/konstapel", "./cmd/konstapel-provider"])


class WriteOverrideTests(unittest.TestCase):
    path, version = "example.com/notice-only", "v1.0.0"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.tmp = Path(self.dir.name)

    def archive(self, notice):
        z = self.tmp / "module.zip"
        with zipfile.ZipFile(z, "w") as w:
            w.writestr(f"{self.path}@{self.version}/LICENSE", notice)
            w.writestr(f"{self.path}@{self.version}/go.mod", f"module {self.path}\n")
        return z

    def override(self, notice=APACHE_NOTICE):
        return dict(license="Apache-2.0", file="LICENSE", sha256=hashlib.sha256(notice).hexdigest(), reason="notice only")

    def gosum(self, z):
        return f"{self.path} {self.version} {notices.zip_h1(z)}\n{self.path} {self.version}/go.mod h1:x=\n"

    def test_copies_verified_notice_and_full_text(self):
        z = self.archive(APACHE_NOTICE)
        out = self.tmp / "out"
        got = notices.write_override(out, self.path, self.version, self.override(), z, self.gosum(z), root=ROOT)
        dest = out / "licenses" / self.path
        self.assertEqual((dest / "LICENSE").read_bytes(), APACHE_NOTICE)
        self.assertEqual((dest / got["fullText"]).read_bytes(), (ROOT / "LICENSE").read_bytes())
        self.assertEqual(got["license"], "Apache-2.0")

    def test_changed_license_file_fails(self):
        z = self.archive(APACHE_NOTICE + b"changed\n")
        with self.assertRaises(SystemExit) as e:
            notices.write_override(self.tmp / "out", self.path, self.version, self.override(), z, self.gosum(z), root=ROOT)
        self.assertIn("changed", str(e.exception))

    def test_archive_not_matching_go_sum_fails(self):
        z = self.archive(APACHE_NOTICE)
        gosum = f"{self.path} {self.version} h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        with self.assertRaises(SystemExit) as e:
            notices.write_override(self.tmp / "out", self.path, self.version, self.override(), z, gosum, root=ROOT)
        self.assertIn("go.sum", str(e.exception))

    def test_module_missing_from_go_sum_fails(self):
        z = self.archive(APACHE_NOTICE)
        with self.assertRaises(SystemExit):
            notices.write_override(self.tmp / "out", self.path, self.version, self.override(), z, "", root=ROOT)


if __name__ == "__main__":
    unittest.main()
