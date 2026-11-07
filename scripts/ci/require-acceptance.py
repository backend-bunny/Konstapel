#!/usr/bin/env python3
"""Require full, successful main-branch acceptance for an exact source commit.

Automatic publishing supplies the completed test run ID. Release/manual callers
wait for the main-branch test run instead of starting another disposable cluster.
GitHub API errors, skipped jobs, and missing evidence never authorize publishing.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


WORKFLOW = ".github/workflows/test.yml"
GROUPS = json.loads((Path(__file__).resolve().parents[1] / "acceptance-groups.json").read_text())
REQUIRED_JOBS = ("checks", "acceptance", *(f"acceptance-live ({group})" for group in GROUPS))


class AcceptanceError(Exception):
    pass


def api(endpoint, paginate=False):
    command = ["gh", "api"]
    if paginate:
        command += ["--paginate", "--slurp"]
    result = subprocess.run(
        command + [endpoint], text=True, capture_output=True, timeout=60, check=False
    )
    if result.returncode:
        raise AcceptanceError(f"GitHub API request failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def matches_source(run, repository, commit):
    return (
        run.get("path") == WORKFLOW
        and run.get("head_sha") == commit
        and run.get("head_branch") == "main"
        and run.get("event") in ("push", "workflow_dispatch")
        and (run.get("head_repository") or {}).get("full_name") == repository
    )


def select_run(runs, repository, commit):
    candidates = [run for run in runs if matches_source(run, repository, commit)]
    # Do not silently use an older success after a newer run failed.
    return max(candidates, key=lambda run: run["id"], default=None)


def verify_jobs(jobs):
    for name in REQUIRED_JOBS:
        matching = [job for job in jobs if job.get("name") == name]
        if len(matching) != 1 or matching[0].get("conclusion") != "success":
            raise AcceptanceError(f"Required job {name!r} did not complete successfully")


def wait_for_acceptance(repository, commit, run_id, timeout, interval):
    deadline = time.monotonic() + timeout
    while True:
        if run_id:
            run = api(f"repos/{repository}/actions/runs/{run_id}")
            if not matches_source(run, repository, commit):
                raise AcceptanceError("Acceptance run does not match the trusted source commit")
        else:
            pages = api(
                f"repos/{repository}/actions/workflows/test.yml/runs"
                f"?head_sha={commit}&branch=main&per_page=100",
                paginate=True,
            )
            run = select_run(
                [run for page in pages for run in page["workflow_runs"]], repository, commit
            )

        if run and run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise AcceptanceError(
                    f"Acceptance run {run['id']} concluded {run.get('conclusion')}; "
                    "rerun the failed test workflow before retrying publication"
                )
            attempt = run["run_attempt"]
            pages = api(
                f"repos/{repository}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100",
                paginate=True,
            )
            verify_jobs([job for page in pages for job in page["jobs"]])
            current = api(f"repos/{repository}/actions/runs/{run['id']}")
            if (
                current.get("run_attempt") == attempt
                and current.get("status") == "completed"
                and current.get("conclusion") == "success"
                and matches_source(current, repository, commit)
            ):
                print(f"Full acceptance verified for {commit}: {run['html_url']}", flush=True)
                return
            # A rerun started while jobs were inspected. Check its current result.

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AcceptanceError(f"Timed out waiting for full main-branch acceptance of {commit}")
        state = run.get("status", "unknown") if run else "not yet started"
        print(f"Waiting for acceptance of {commit}: {state}", flush=True)
        time.sleep(min(interval, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--timeout", type=int, default=5400)
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        parser.error("GITHUB_REPOSITORY must identify the publishing repository")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("--commit must be a full Git commit SHA")
    if args.timeout < 0 or args.interval <= 0 or (args.run_id is not None and args.run_id <= 0):
        parser.error("invalid timeout, interval, or run ID")
    try:
        wait_for_acceptance(repository, args.commit, args.run_id, args.timeout, args.interval)
    except (AcceptanceError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"Publication blocked: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
