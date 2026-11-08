#!/usr/bin/env python3
"""Release acceptance evidence for the frozen chart inputs.

  evidence.py groups --source SHA
      Print the release-required acceptance groups of the source commit's
      scripts/acceptance-groups.json, one per line.
  evidence.py record --archives DIR --groups-dir DIR --image IMAGE@DIGEST \
      --source SHA --runtime JSON --out CHART_ACCEPTANCE_JSON
      Derive each required group's result from its own files and write the
      chart-acceptance record only when every required group fully passed.

A group is release-required when acceptance-groups.json marks it
`"release": true`: it installs the frozen chart archives with the released
image, so it must run against those exact bytes before publication. Every
group states the marker explicitly; scripts/ci/test_acceptance.py keeps it
consistent with the tests that install charts.

The requirements always come from the frozen source commit (`git show
SHA:scripts/acceptance-groups.json`), never from the working tree or from the
record being checked. A test counts as passed only when its own top-level
`--- PASS:` line appears exactly once in the group's `go test -v` log, with
no FAIL or SKIP for it or its subtests; an exit status alone never passes a
test, and anything the parser cannot account for fails the group.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest as frozen  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
ACCEPTANCE = "konstapel.dev/chart-acceptance/v2"
GROUPS_FILE = "scripts/acceptance-groups.json"
IMAGE = re.compile(r"^ghcr\.io/backend-bunny/konstapel@sha256:[0-9a-f]{64}$")
TEST_NAME = re.compile(r"^TestLive\w+$")
# Files under each group's output directory whose digests the record carries.
LOG = "targeting/targeting-live.log"
RESULT = "acceptance-result.json"
IMAGE_REF = "image-ref.txt"
EVIDENCE_FILES = (LOG, RESULT, IMAGE_REF)

RESULT_LINE = re.compile(r"^(\s*)--- (PASS|FAIL|SKIP): (\S+) \(")


class Rejected(Exception):
    pass


def release_groups(groups: dict) -> dict:
    """{group: [tests]} for the release-required groups, in file order.

    Every group must classify itself with a boolean `release`; a required
    group needs the published image and at least one test."""
    if not isinstance(groups, dict) or not groups:
        raise Rejected("acceptance groups must be a non-empty object")
    required = {}
    for name, group in groups.items():
        if not isinstance(group, dict) or not isinstance(group.get("release"), bool):
            raise Rejected(f"acceptance group {name!r} must set \"release\" to true or false")
        if not group["release"]:
            continue
        tests = group.get("goTests")
        if not isinstance(tests, list) or not tests or not all(isinstance(t, str) and TEST_NAME.match(t) for t in tests):
            raise Rejected(f"release acceptance group {name!r} needs a non-empty list of TestLive tests")
        if len(set(tests)) != len(tests):
            raise Rejected(f"release acceptance group {name!r} lists a test twice")
        if group.get("image") is not True:
            raise Rejected(f"release acceptance group {name!r} must install the published image (\"image\": true)")
        required[name] = list(tests)
    if not required:
        raise Rejected("no acceptance group is marked release-required")
    return required


def frozen_groups(commit: str, root: Path = ROOT) -> dict:
    """The release-required groups as committed at the frozen source commit."""
    if not isinstance(commit, str) or not frozen.SHA.match(commit):
        raise Rejected(f"source commit {commit!r} is not a full SHA")
    p = subprocess.run(["git", "show", f"{commit}:{GROUPS_FILE}"], cwd=root, capture_output=True, text=True)
    if p.returncode != 0:
        raise Rejected(f"cannot read {GROUPS_FILE} at {commit}: {p.stderr.strip()}")
    try:
        groups = json.loads(p.stdout)
    except json.JSONDecodeError as e:
        raise Rejected(f"{GROUPS_FILE} at {commit}: {e}")
    return release_groups(groups)


def parse_log(text: str, tests: list) -> tuple:
    """({test: result}, problems) from a `go test -v` log.

    result is pass, fail, skip, missing or ambiguous. problems lists anything
    that makes the whole log untrustworthy (failed package, panic, a test
    that should not have run, no package result)."""
    outcomes = {t: [] for t in tests}
    sub = {t: set() for t in tests}
    problems = []
    for line in text.splitlines():
        m = RESULT_LINE.match(line)
        if m:
            indent, verdict, name = m.groups()
            top = name.split("/", 1)[0]
            if top not in outcomes:
                problems.append(f"unexpected test result: {line.strip()}")
            elif indent == "" and "/" not in name:
                outcomes[top].append(verdict)
            elif verdict != "PASS":
                sub[top].add(verdict)
            continue
        if line.startswith("FAIL") or line.startswith("panic:") or line.startswith("--- "):
            problems.append(f"unexpected log line: {line.strip()[:200]}")
    if not re.search(r"(?m)^ok\s+\S+", text):
        problems.append("no package reported ok")
    results = {}
    for t in tests:
        seen = outcomes[t]
        if not seen:
            results[t] = "missing"
        elif len(seen) > 1:
            results[t] = "ambiguous"
        elif seen[0] == "FAIL" or "FAIL" in sub[t]:
            results[t] = "fail"
        elif seen[0] == "SKIP" or "SKIP" in sub[t]:
            results[t] = "skip"
        else:
            results[t] = "pass"
    return results, problems


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def group_evidence(directory: Path, group: str, tests: list, image: str) -> tuple:
    """(evidence, problems) for one group's acceptance output directory."""
    problems = []
    evidence = {"required": True, "passed": False, "exitCode": None,
                "tests": [{"name": t, "result": "missing"} for t in tests], "files": {}}
    if not directory.is_dir():
        return evidence, [f"{group}: no output directory (group did not run)"]
    for rel in EVIDENCE_FILES:
        path = directory / rel
        if path.is_file():
            evidence["files"][rel] = sha256_file(path)
        else:
            problems.append(f"{group}: {rel} missing")
    try:
        result = json.loads((directory / RESULT).read_text())
        if result.get("group") != group:
            problems.append(f"{group}: result names group {result.get('group')!r}")
        code = result.get("exitCode")
        evidence["exitCode"] = code if type(code) is int else None
        if type(code) is not int or code != 0 or result.get("passed") is not True:
            problems.append(f"{group}: acceptance exited {code!r}")
    except (OSError, ValueError, AttributeError) as e:
        problems.append(f"{group}: unreadable {RESULT}: {e}")
    try:
        ref = (directory / IMAGE_REF).read_text().strip()
        if ref != image:
            problems.append(f"{group}: cluster ran {ref!r}, not {image}")
    except OSError:
        pass
    try:
        results, log_problems = parse_log((directory / LOG).read_text(errors="replace"), tests)
        problems += [f"{group}: {p}" for p in log_problems]
        evidence["tests"] = [{"name": t, "result": results[t]} for t in tests]
        problems += [f"{group}: {t} {r}" for t, r in results.items() if r != "pass"]
    except OSError:
        pass
    evidence["passed"] = not problems
    return evidence, problems


def build(archives: Path, groups_dir: Path, image: str, source: str, runtime: dict, root: Path = ROOT) -> tuple:
    """(record, problems); the record is valid only when problems is empty."""
    if not IMAGE.match(image):
        raise Rejected(f"image {image!r} is not ghcr.io/backend-bunny/konstapel@sha256:<digest>")
    manifest = json.loads((archives / "publication.json").read_text())
    required = frozen_groups(source, root)
    problems = []
    if manifest["source"]["commit"] != source:
        problems.append(f"frozen manifest source {manifest['source']['commit']} is not {source}")
    groups = {}
    for group, tests in required.items():
        groups[group], found = group_evidence(groups_dir / group, group, tests, image)
        problems += found
    record = {
        "apiVersion": ACCEPTANCE,
        "passed": not problems,
        "source": {"commit": source, "tag": manifest["source"]["tag"]},
        "image": image,
        "crdContent": manifest["crdContent"],
        "charts": {n: {"version": c["version"], "sha256": c["sha256"]} for n, c in manifest["charts"].items()},
        "groups": groups,
        "runtime": runtime,
    }
    return record, problems


def check(manifest: dict, record, required: dict) -> None:
    """The record must be a full pass of the required groups for exactly the
    frozen inputs. `required` comes from frozen_groups(source commit)."""
    if not isinstance(record, dict):
        raise Rejected("chart acceptance record is not an object")
    if record.get("apiVersion") != ACCEPTANCE:
        raise Rejected(f"chart acceptance record {record.get('apiVersion')!r} is stale or unknown; want {ACCEPTANCE}")
    if record.get("passed") is not True:
        raise Rejected("chart acceptance did not pass")
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    charts = record.get("charts") if isinstance(record.get("charts"), dict) else {}
    want_image = "ghcr.io/backend-bunny/konstapel@" + manifest["image"]["digest"]
    checks = [
        ("source commit", source.get("commit"), manifest["source"]["commit"]),
        ("tag", source.get("tag"), manifest["source"]["tag"]),
        ("image", record.get("image"), want_image),
        ("CRD content", record.get("crdContent"), manifest["crdContent"]),
    ]
    for name in frozen.CHARTS:
        got = charts.get(name) if isinstance(charts.get(name), dict) else {}
        checks.append((f"{name} archive", got.get("sha256"), manifest["charts"][name]["sha256"]))
        checks.append((f"{name} version", got.get("version"), manifest["charts"][name]["version"]))
    for what, got, want in checks:
        if got != want:
            raise Rejected(f"chart acceptance tested {what} {got!r}, frozen {want!r}")
    groups = record.get("groups")
    if not isinstance(groups, dict):
        raise Rejected("chart acceptance record has no group results")
    for group in required:
        if group not in groups:
            raise Rejected(f"required acceptance group {group} is missing")
    for group in groups:
        if group not in required:
            raise Rejected(f"acceptance group {group} is not release-required at the frozen source")
    for group, tests in required.items():
        g = groups[group]
        if not isinstance(g, dict):
            raise Rejected(f"acceptance group {group}: malformed result")
        if g.get("required") is not True:
            raise Rejected(f"acceptance group {group}: not recorded as required")
        if g.get("passed") is not True:
            raise Rejected(f"acceptance group {group} did not pass")
        if type(g.get("exitCode")) is not int or g["exitCode"] != 0:
            raise Rejected(f"acceptance group {group} exited {g.get('exitCode')!r}")
        recorded = g.get("tests")
        if not isinstance(recorded, list) or not all(isinstance(t, dict) for t in recorded):
            raise Rejected(f"acceptance group {group}: malformed test results")
        names = [t.get("name") for t in recorded]
        if names != tests:
            raise Rejected(f"acceptance group {group} tested {names}, frozen source requires {tests}")
        for t in recorded:
            if t.get("result") != "pass":
                raise Rejected(f"acceptance group {group}: {t['name']} result {t.get('result')!r}")
        files = g.get("files")
        if not isinstance(files, dict) or set(files) != set(EVIDENCE_FILES) or not all(
                isinstance(v, str) and frozen.DIGEST.match(v) for v in files.values()):
            raise Rejected(f"acceptance group {group}: evidence file digests incomplete")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("groups")
    g.add_argument("--source", required=True)
    r = sub.add_parser("record")
    for flag in ("--archives", "--groups-dir", "--image", "--source", "--runtime", "--out"):
        r.add_argument(flag, required=True)
    args = p.parse_args(argv)
    try:
        if args.command == "groups":
            print("\n".join(frozen_groups(args.source)))
            return 0
        out = Path(args.out)
        if out.exists():
            raise Rejected(f"{out} exists; acceptance records are never replaced")
        record, problems = build(Path(args.archives), Path(args.groups_dir), args.image, args.source, json.loads(args.runtime))
        summary = json.dumps({g: {"passed": e["passed"], "exitCode": e["exitCode"],
                                  "tests": {t["name"]: t["result"] for t in e["tests"]}} for g, e in record["groups"].items()}, indent=2)
        if problems:
            print("release acceptance did not pass; no chart-acceptance record written:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            print(summary, file=sys.stderr)
            return 1
        out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(summary)
        return 0
    except (Rejected, frozen.Mismatch, OSError, ValueError, KeyError) as e:
        print(f"release acceptance evidence: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
