#!/usr/bin/env python3
"""Markdown job summary for a chart release: summary.py charts-release.json VERIFY_OUTCOME"""
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
outcome = sys.argv[2] if len(sys.argv) > 2 else "unknown"
print("## Helm charts\n")
if not path or not path.exists():
    print("No chart release record: publication did not complete.")
    sys.exit(0)
r = json.loads(path.read_text())
print(f"Source `{r['source']['commit']}` ({r['source']['tag']}), image `ghcr.io/backend-bunny/konstapel@{r['image']['digest']}`\n")
print("| Chart | Version | OCI subject | Archive SHA-256 | State |")
print("| --- | --- | --- | --- | --- |")
for name, c in r["charts"].items():
    print(f"| {name} | {c['version']} | `{c['reference']}@{c['digest']}` | `{c['archiveSha256']}` | {c['state']} |")
print(f"\nRemote verification (signatures, chart-inputs attestations, provenance, pulled bytes): **{outcome}**")
