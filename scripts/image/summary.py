#!/usr/bin/env python3
"""Render build evidence for the GitHub Actions job summary, including failures."""
import html
import json
import os
from pathlib import Path
import re
import shlex
import sys

IMAGE = "ghcr.io/backend-bunny/konstapel"
REPOSITORY = "https://github.com/backend-bunny/Konstapel"
IDENTITY = r"^https://github.com/backend-bunny/Konstapel/\.github/workflows/(publish|release-please)\.yml@refs/heads/main$"


def cell(value):
    return html.escape(str(value or "NOASSERTION")).replace("|", "\\|").replace("\n", " ")


def details(title, body):
    return f"<details><summary>{title}</summary>\n\n{body.rstrip()}\n\n</details>\n"


def render(out):
    sections = ["## Konstapel image\n"]
    if (out / "digest").exists():
        digest = (out / "digest").read_text().strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("Invalid published image digest")
        sections.append(f"Published image: `{IMAGE}@{digest}`\n")
        tag = os.environ.get("RELEASE_TAG", "")
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
            sections.append(f"Release tag: `{IMAGE}:{tag[1:]}`\n")
        verified = os.environ.get("PUBLISH_VERIFICATION") == "success"
        sections.append("Signature and all attestations verified successfully.\n" if verified
                        else "Signature and attestation verification did not complete successfully; inspect the verification step.\n")
        commands = [
            "### Verify this image\n",
            "```sh",
            f"IMAGE={IMAGE}@{digest}",
            f"IDENTITY={shlex.quote(IDENTITY)}",
            'cosign verify "$IMAGE" --certificate-identity-regexp "$IDENTITY" \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com',
        ]
        for label, predicate in (
            ("SPDX SBOMs", "spdxjson"),
            ("Pinned dependency sources", REPOSITORY + "/sources/v1"),
            ("License texts and notices", REPOSITORY + "/notices/v1"),
        ):
            commands.extend([
                f"\n# {label}",
                f'cosign verify-attestation "$IMAGE" --type {predicate} \\\n  --certificate-identity-regexp "$IDENTITY" \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com',
            ])
        commands.extend([
            "\n# GitHub build provenance",
            'gh attestation verify "oci://$IMAGE" --repo backend-bunny/Konstapel',
            "```\n",
        ])
        sections.append("\n".join(commands))
    else:
        sections.append("Build evidence only; this job has not published an image.\n")

    if (out / "sbom-complete.spdx.json").exists():
        sbom = json.loads((out / "sbom-complete.spdx.json").read_text())
        rows = sorted({
            (p["name"], p.get("versionInfo", ""), p.get("licenseDeclared", "NOASSERTION"),
             p.get("licenseConcluded", "NOASSERTION"))
            for p in sbom["packages"]
        })
        table = [
            "Runtime APKs and embedded Go dependencies from the complete image SBOM. "
            "Duplicate entries with the same version and license metadata appear once. "
            "`NOASSERTION` means the SBOM supplies no assertion for that field.\n",
            "| Dependency | Version | Declared license | Detected license |",
            "| --- | --- | --- | --- |",
        ]
        table.extend("| " + " | ".join(cell(v) for v in row) + " |" for row in rows)
        sections.append(details(f"Dependencies and licenses ({len(rows)} entries)", "\n".join(table)))
    else:
        sections.append("The complete image SBOM is unavailable; inspect the build step.\n")

    for title, filename in (("Dependency sources", "sources.md"), ("License texts and notices", "notices.md")):
        path = out / filename
        sections.append(details(title, path.read_text()) if path.exists()
                        else f"{title} are unavailable; inspect the build step.\n")
    sections.append("Generated evidence is retained in this run's artifact. "
                    f"See the [image guide]({REPOSITORY}/blob/main/docs/images.md) for the build and licensing details.\n")
    return "\n".join(sections)


if __name__ == "__main__":
    print(render(Path(sys.argv[1] if len(sys.argv) > 1 else "out/image")))
