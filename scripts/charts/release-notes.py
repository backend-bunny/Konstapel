#!/usr/bin/env python3
"""Add or replace the Helm chart block in release notes, idempotently:
  CHARTS_RELEASE='<charts-release.json>' release-notes.py NOTES.md
Text outside the markers (generated changelog, user notes, the image block)
is preserved; rerunning replaces only the chart block. The commands verify
each OCI subject by digest and install the archive pulled by that same
digest, never an unchecked tag."""

import json
import os
from pathlib import Path
import re
import sys

START, END = "<!-- konstapel-charts:start -->", "<!-- konstapel-charts:end -->"
IDENTITY = r"^https://github.com/backend-bunny/Konstapel/\.github/workflows/(charts|release-please)\.yml@refs/heads/main$"
ISSUER = "https://token.actions.githubusercontent.com"
CHART_INPUTS = "https://github.com/backend-bunny/Konstapel/chart-inputs/v1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def pulled(name: str, c: dict) -> str:
    """The file `helm pull oci://REPO/CHART@DIGEST` writes."""
    return f"{name}@sha256-{c['digest'].removeprefix('sha256:')}.tgz"


def block(release: dict) -> str:
    src, image = release["source"], release["image"]["digest"]
    if not (DIGEST.match(image) and re.fullmatch(r"[0-9a-f]{40}", src["commit"])):
        raise ValueError("release record lacks a source commit or image digest")
    lines = [START, "## Helm charts", "",
             f"Built from `{src['commit']}`; the runtime chart defaults to `ghcr.io/backend-bunny/konstapel@{image}`.", "",
             "| Chart | Version | OCI subject | Archive SHA-256 |", "| --- | --- | --- | --- |"]
    for name in ("konstapel-crds", "konstapel"):
        c = release["charts"][name]
        if not DIGEST.match(c["digest"]) or not DIGEST.match(c["archiveSha256"]):
            raise ValueError(f"{name}: malformed digest")
        lines.append(f"| {name} | {c['version']} | `{c['reference']}@{c['digest']}` | `{c['archiveSha256']}` |")
    lines += ["", "Verify each chart, then install exactly the archive pulled by that digest:", "", "```sh"]
    for name in ("konstapel-crds", "konstapel"):
        c = release["charts"][name]
        ref = f"{c['reference']}@{c['digest']}"
        lines += [
            f"cosign verify --certificate-identity-regexp '{IDENTITY}' --certificate-oidc-issuer {ISSUER} {ref}",
            f"cosign verify-attestation --type {CHART_INPUTS} --certificate-identity-regexp '{IDENTITY}' --certificate-oidc-issuer {ISSUER} {ref} > /dev/null",
            f"gh attestation verify oci://{ref} --repo backend-bunny/Konstapel",
            f"helm pull oci://{ref}",
            f"echo '{c['archiveSha256'].removeprefix('sha256:')}  {pulled(name, c)}' | sha256sum --check",
        ]
    crds, runtime = release["charts"]["konstapel-crds"], release["charts"]["konstapel"]
    lines += [f"helm install konstapel-crds './{pulled('konstapel-crds', crds)}' --namespace konstapel-system --create-namespace",
              f"helm install konstapel './{pulled('konstapel', runtime)}' --namespace konstapel-system",
              "```", "",
              "[Chart documentation](https://github.com/backend-bunny/Konstapel/blob/main/docs/charts.md)", END]
    return "\n".join(lines)


def update(text: str, release: dict) -> str:
    body = re.sub(re.escape(START) + r".*?" + re.escape(END), "", text, flags=re.S).rstrip()
    return body + "\n\n" + block(release) + "\n"


def main() -> int:
    path = Path(sys.argv[1])
    path.write_text(update(path.read_text(), json.loads(os.environ["CHARTS_RELEASE"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
