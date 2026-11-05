#!/usr/bin/env python3
"""Render an image's source manifest from its apko SPDX SBOM.

For every APK in the image, apko's SBOM links the package to its upstream
source (GENERATED_FROM: VCS URL + commit, or a download URL + checksum, often
with an archived copy on tarballs.cgr.dev) and to its build recipe
(DESCRIBED_BY: repo@commit#path). This collects those links into one list per
image. publish.sh attests it on the index digest next to the SBOM.

Third-party code that a package bundles without its own APK (e.g. signal-cli's
Maven jars, crowdsec-web-ui's npm packages) is declared by the package in
/usr/share/doc/<pkg>/bundled-sources.json and listed separately.

Every source must be pinned (a commit, a checksum, a content-addressed
archive, or for Wolfi-internal packages with no upstream, the recipe commit);
render fails otherwise, so an unpinned checkout can't ship.

  sources.py render SBOM IMAGE_TAR OUT_JSON OUT_MD
      IMAGE_TAR is apko's image tarball, searched for bundled-sources.json
      files; pass - to skip.
"""

import fnmatch
import json
import re
import sys
import tarfile
from urllib.parse import unquote

SHA1 = re.compile(r"\b[0-9a-f]{40}\b")
BUNDLED_GLOB = "usr/share/doc/*/bundled-sources.json"


def purl_of(pkg):
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref["referenceLocator"]
    return ""


def qualifiers(purl):
    if "?" not in purl:
        return {}
    query = purl.split("?", 1)[1].split("#", 1)[0]
    return dict(unquote(q).split("=", 1) for q in query.split("&") if "=" in q)


def known(value):
    return value if value and value not in ("NOASSERTION", "NONE") else ""


def source_entry(src):
    """Upstream source of one GENERATED_FROM package: (url, ref, archive, pinned)."""
    purl = purl_of(src)
    quals = qualifiers(purl)
    archive = known(src.get("downloadLocation"))
    url, ref = "", src.get("versionInfo", "")

    if "vcs_url" in quals:
        vcs = quals["vcs_url"].removeprefix("git+")
        url, _, commit = vcs.rpartition("@")
        if not SHA1.fullmatch(commit):
            url, commit = vcs, ""
        ref = commit or ref
    elif purl.startswith("pkg:github/"):
        url = "https://github.com/" + purl.split("/", 1)[1].split("@", 1)[0]
    url = url or quals.get("download_url", "") or archive

    archive_sha = SHA1.search(archive)
    if archive_sha and not SHA1.fullmatch(ref):
        ref = archive_sha.group(0)
    pinned = bool(
        SHA1.fullmatch(ref)
        or "checksum" in quals
        or archive.startswith("https://tarballs.cgr.dev/")
    )
    return url, ref, archive, quals.get("checksum", ""), pinned


def recipe_entry(recipe):
    purl = purl_of(recipe)
    m = re.match(r"pkg:github/([^@]+)@([0-9a-f]{40})#(.+)$", purl)
    if not m:
        return "", ""
    return f"https://github.com/{m.group(1)}/blob/{m.group(2)}/{m.group(3)}", m.group(2)


def apks(sbom):
    """APK packages in the image: CONTAINS targets of the image or its layers."""
    by_id = {p["SPDXID"]: p for p in sbom["packages"]}
    roots = {
        p["SPDXID"]
        for p in sbom["packages"]
        if p["SPDXID"].startswith(("SPDXRef-Package-Image-", "SPDXRef-Package-ImageLayer-"))
    }
    seen = []
    for rel in sbom["relationships"]:
        target = rel["relatedSpdxElement"]
        if (
            rel["relationshipType"] == "CONTAINS"
            and rel["spdxElementId"] in roots
            and target.startswith("SPDXRef-Package-apk-")
            and target not in seen
        ):
            seen.append(target)
    return [by_id[i] for i in seen]


def packages(sbom):
    by_id = {p["SPDXID"]: p for p in sbom["packages"]}
    links = {}
    for rel in sbom["relationships"]:
        kind = rel["relationshipType"]
        if kind in ("GENERATED_FROM", "DESCRIBED_BY"):
            links.setdefault((rel["spdxElementId"], kind), []).append(
                by_id[rel["relatedSpdxElement"]]
            )

    out = []
    for apk in apks(sbom):
        recipe, recipe_commit = "", ""
        for r in links.get((apk["SPDXID"], "DESCRIBED_BY"), []):
            recipe, recipe_commit = recipe_entry(r)
        sources = []
        for src in links.get((apk["SPDXID"], "GENERATED_FROM"), []):
            url, ref, archive, checksum, pinned = source_entry(src)
            sources.append({"url": url, "ref": ref, "archive": archive,
                            "checksum": checksum, "pinned": pinned})
        if not sources:
            # Wolfi-internal packages (baselayout, config files) have no
            # upstream: the recipe at its commit is the source.
            sources.append({"url": recipe, "ref": recipe_commit, "archive": "",
                            "checksum": "", "pinned": bool(recipe_commit)})
        out.append({
            "package": apk["name"],
            "version": apk.get("versionInfo", ""),
            "license": known(apk.get("licenseDeclared")),
            "sources": sources,
            "recipe": recipe,
        })
    return out


def image_files(image_tar, wanted):
    """Yield (path, bytes) for the regular files in apko's image tarball whose
    path (relative, e.g. usr/lib/...) satisfies wanted(path)."""
    with tarfile.open(image_tar) as image:
        manifest = json.load(image.extractfile("manifest.json"))
        for layer_name in manifest[0]["Layers"]:
            with tarfile.open(fileobj=image.extractfile(layer_name), mode="r:*") as layer:
                for member in layer:
                    path = member.name.removeprefix("./").lstrip("/")
                    if member.isfile() and wanted(path):
                        yield path, layer.extractfile(member).read()


def bundled(image_tar):
    """Entries of every bundled-sources.json in the image's layers."""
    out = []
    if image_tar == "-":
        return out
    for path, data in image_files(image_tar, lambda p: fnmatch.fnmatch(p, BUNDLED_GLOB)):
        owner = path.split("/")[3]
        out.extend({"bundled_in": owner, **entry} for entry in json.loads(data))
    for entry in out:
        purl, ref = entry.get("purl", ""), entry.get("ref", "")
        # Maven Central releases, npm registry versions and Wolfi APK
        # versions are immutable, so a versioned purl pins them.
        entry["pinned"] = bool(
            SHA1.fullmatch(ref)
            or entry.get("checksum")
            or re.match(r"pkg:(maven|npm|apk)/[^@]+@.+", purl)
        )
    return out


def cell(value):
    return str(value).replace("|", "\\|") if value else ""


def markdown(pkgs, extra):
    lines = [
        "| Package | Version | License | Source | Ref | Archive |",
        "|---|---|---|---|---|---|",
    ]
    for p in pkgs:
        for s in p["sources"]:
            lines.append(
                f"| `{cell(p['package'])}` | {cell(p['version'])} | {cell(p['license'])} "
                f"| {cell(s['url'])} | {cell(s['ref'])} | {cell(s['archive'])} |"
            )
    if extra:
        lines += [
            "",
            "Bundled inside packages:",
            "",
            "| Component | Version | In | Source | Ref |",
            "|---|---|---|---|---|",
        ]
        for b in extra:
            lines.append(
                f"| `{cell(b.get('name'))}` | {cell(b.get('version'))} | `{cell(b['bundled_in'])}` "
                f"| {cell(b.get('source') or b.get('purl'))} | {cell(b.get('ref'))} |"
            )
    return "\n".join(lines) + "\n"


def render(sbom_path, image_tar, out_json, out_md):
    with open(sbom_path) as f:
        sbom = json.load(f)
    pkgs, extra = packages(sbom), bundled(image_tar)

    with open(out_json, "w") as f:
        json.dump({"packages": pkgs, "bundled": extra}, f, indent=2)
        f.write("\n")
    with open(out_md, "w") as f:
        f.write(markdown(pkgs, extra))

    unpinned = [
        f"{p['package']}: {s['url'] or 'no source'} @ {s['ref'] or '?'}"
        for p in pkgs for s in p["sources"] if not s["pinned"]
    ] + [
        f"{b.get('name')} (bundled in {b['bundled_in']}): {b.get('source') or b.get('purl') or 'no source'}"
        for b in extra if not b["pinned"]
    ]
    print(f"  {len(pkgs)} packages, {len(extra)} bundled components")
    if unpinned:
        for line in unpinned:
            print(f"  unpinned: {line}", file=sys.stderr)
        sys.exit("error: sources must be pinned to a commit, checksum or archive "
                 "(melange git-checkout: set expected-commit; bundled-sources.json: "
                 "a versioned maven/npm/apk purl, a commit ref or a checksum)")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "render" and len(args) == 4:
        render(*args)
    else:
        sys.exit(__doc__)
