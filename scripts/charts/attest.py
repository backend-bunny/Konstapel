#!/usr/bin/env python3
"""Sign, attest and verify published chart subjects.

  attest.py sign   --release release.json --archives DIR --acceptance chart-acceptance.json TRUST
  attest.py verify --release release.json --archives DIR [--out DIR] TRUST

TRUST is either the release identity (keyless, Sigstore public instance):
  --identity-regexp REGEX --issuer https://token.actions.githubusercontent.com
or a key pair, for test registries only:
  --key PATH (private key for sign, public key for verify) --plain-http

sign is resumable: a subject whose signature, or whose chart-inputs
attestation, already verifies under TRUST is not signed again, so a retry
after a partial publication adds only what is missing. The attestation
predicate (type CHART_INPUTS) records the frozen publication manifest and
the passing acceptance record, so the OCI subject is bound to its source
commit, image digest and archive checksum.

verify checks, for both charts:
  - a signature on the OCI subject (repository@digest) under TRUST;
  - a chart-inputs attestation under TRUST whose in-toto subject is that
    digest and whose predicate names the release's source commit, tag,
    image digest and that chart's archive checksum, with acceptance passed;
  - pulling the subject by digest yields exactly the frozen archive bytes,
    so what is verified is what an operator installs.
Nothing is reported verified unless both charts pass.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

CHART_INPUTS = "https://github.com/backend-bunny/Konstapel/chart-inputs/v1"
CHARTS = ("konstapel-crds", "konstapel")


class Failed(Exception):
    pass


def cosign(args, *rest, check=True):
    cmd = ["cosign", *rest]
    if args.key:
        cmd.insert(2, "--allow-http-registry")
    p = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, COSIGN_PASSWORD=os.environ.get("COSIGN_PASSWORD", "")))
    if check and p.returncode != 0:
        raise Failed(f"cosign {rest[0]} {rest[-1]}: {(p.stderr or p.stdout).strip()[-400:]}")
    return p


def trust(args, signing=False):
    if args.key:
        if signing:
            return ["--key", args.key, "--use-signing-config=false", "--tlog-upload=false"]
        # sign checks existing signatures with the private key's public half.
        key = str(Path(args.key).with_suffix(".pub")) if args.key.endswith(".key") else args.key
        return ["--key", key, "--insecure-ignore-tlog=true"]
    if signing:
        return []
    if not (args.identity_regexp and args.issuer):
        raise Failed("verification needs --identity-regexp and --issuer (or --key for test registries)")
    return ["--certificate-identity-regexp", args.identity_regexp, "--certificate-oidc-issuer", args.issuer]


def subject(c):
    return f"{c['reference']}@{c['digest']}"


def statements(output: str):
    """In-toto statements from cosign verify-attestation output."""
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        envelope = json.loads(line)
        yield json.loads(base64.b64decode(envelope["payload"]))


def check_predicate(release: dict, name: str, statement: dict) -> None:
    c = release["charts"][name]
    if statement.get("predicateType") != CHART_INPUTS:
        raise Failed(f"{name}: attestation type {statement.get('predicateType')}")
    digests = [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]
    if c["digest"].removeprefix("sha256:") not in digests:
        raise Failed(f"{name}: attestation subject {digests} is not {c['digest']}")
    pred = statement.get("predicate", {})
    pub, acc = pred.get("publication", {}), pred.get("acceptance", {})
    wants = [
        ("source commit", pub.get("source", {}).get("commit"), release["source"]["commit"]),
        ("tag", pub.get("source", {}).get("tag"), release["source"]["tag"]),
        ("image digest", pub.get("image", {}).get("digest"), release["image"]["digest"]),
        ("archive", pub.get("charts", {}).get(name, {}).get("sha256"), c["archiveSha256"]),
        ("acceptance", acc.get("passed"), True),
        ("accepted source", acc.get("source", {}).get("commit"), release["source"]["commit"]),
        ("accepted archive", acc.get("charts", {}).get(name, {}).get("sha256"), c["archiveSha256"]),
        ("accepted image", acc.get("image"), "ghcr.io/backend-bunny/konstapel@" + release["image"]["digest"]),
    ]
    for what, got, want in wants:
        if got != want:
            raise Failed(f"{name}: attested {what} {got!r}, released {want!r}")


def verified_attestation(args, release, name) -> bool:
    p = cosign(args, "verify-attestation", "--type", CHART_INPUTS, *trust(args), subject(release["charts"][name]), check=False)
    if p.returncode != 0:
        return False
    for st in statements(p.stdout):
        try:
            check_predicate(release, name, st)
            return True
        except Failed:
            continue
    return False


def sign(args) -> None:
    release = json.loads(Path(args.release).read_text())
    publication = json.loads((Path(args.archives) / "publication.json").read_text())
    acceptance = json.loads(Path(args.acceptance).read_text())
    if publication["source"] != release["source"] or publication["image"] != release["image"]:
        raise Failed("release.json and publication.json disagree")
    predicate = Path(tempfile.mkdtemp()) / "chart-inputs.json"
    predicate.write_text(json.dumps({"publication": publication, "acceptance": acceptance}, sort_keys=True))
    for name in CHARTS:
        ref = subject(release["charts"][name])
        if cosign(args, "verify", *(trust(args) if args.key else trust_for_check(args)), ref, check=False).returncode == 0:
            print(f"signature present: {ref}")
        else:
            cosign(args, "sign", "--yes", *trust(args, signing=True), ref)
            print(f"signed: {ref}")
        if (args.key or args.identity_regexp) and verified_attestation(args, release, name):
            print(f"attestation present: {ref}")
        else:
            cosign(args, "attest", "--yes", "--type", CHART_INPUTS, "--predicate", str(predicate), *trust(args, signing=True), ref)
            print(f"attested: {ref}")


def trust_for_check(args):
    """Keyless signing can only skip existing signatures if told whom to trust."""
    if args.identity_regexp and args.issuer:
        return trust(args)
    return ["--certificate-identity-regexp", "^$", "--certificate-oidc-issuer", "none"]


def verify(args) -> dict:
    release = json.loads(Path(args.release).read_text())
    publication = json.loads((Path(args.archives) / "publication.json").read_text())
    result = {}
    for name in CHARTS:
        c = release["charts"][name]
        if c["archiveSha256"] != publication["charts"][name]["sha256"]:
            raise Failed(f"{name}: release archive {c['archiveSha256']} is not the frozen {publication['charts'][name]['sha256']}")
        ref = subject(c)
        cosign(args, "verify", *trust(args), ref)
        if not verified_attestation(args, release, name):
            raise Failed(f"{name}: no chart-inputs attestation under the trusted identity matches the release")
        pulled = Path(tempfile.mkdtemp())
        cmd = ["helm", "pull", f"oci://{ref}", "--destination", str(pulled)]
        if args.plain_http:
            cmd.append("--plain-http")
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise Failed(f"helm pull {ref}: {p.stderr.strip()}")
        archive = next(pulled.glob("*.tgz"))
        got = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
        if got != c["archiveSha256"]:
            raise Failed(f"{name}: pulled {got}, released {c['archiveSha256']}")
        result[name] = {"subject": ref, "archiveSha256": got, "signature": "verified", "chartInputs": "verified"}
        print(f"verified: {ref}")
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["sign", "verify"])
    p.add_argument("--release", required=True)
    p.add_argument("--archives", required=True)
    p.add_argument("--acceptance")
    p.add_argument("--out")
    p.add_argument("--key")
    p.add_argument("--identity-regexp")
    p.add_argument("--issuer")
    p.add_argument("--plain-http", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.command == "sign":
            if not args.acceptance:
                raise Failed("sign needs --acceptance")
            sign(args)
        else:
            result = verify(args)
            if args.out:
                Path(args.out).mkdir(parents=True, exist_ok=True)
                (Path(args.out) / "chart-verification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except Failed as e:
        print(f"chart {args.command}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
