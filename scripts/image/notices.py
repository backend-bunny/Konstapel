#!/usr/bin/env python3
"""Collect the license texts and notices that must accompany an image.

The SBOM names licenses by SPDX id only. Most licenses (GPL, LGPL, Apache,
BSD, MIT) also want their text, and BSD/MIT/Apache the upstream copyright
notice or NOTICE file, delivered with the binaries. Wolfi APKs ship none of
that, so this gathers it next to the image (publish attests it):

- APK packages: license files at the top of each package's pinned source
  archive (from sources.py's manifest; downloads are cached, keyed by URL),
  plus the canonical SPDX text of every license in its declared expression.
- Bundled Maven jars: META-INF license/notice files from the jar in the
  image, plus the canonical text of the POM's licenses (parent POMs
  included).
- Bundled npm packages: license files at the top of the package's registry
  tarball (verified against the lockfile's integrity), plus the canonical
  text of package.json's license.
- Other bundled parts: the jlink'd JDK's jre/legal/ files from the image.
  A bundled entry's own SPDX "license" field wins over the POM's, and one
  with a GitHub source + ref also gets the license files of that archive.

Texts are stored once, keyed by SHA256. render fails if something ends up
with no text at all. The one exception is a bundled entry with license
NOASSERTION (upstream declares none) and a "note": the component reviewed
it by name and version. Those and canonical-only packages are warnings.

  notices.py render SOURCES_JSON IMAGE_TAR CACHE_DIR OUT_JSON OUT_MD
"""

import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True  # importing sources.py must not leave __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sources import image_files  # noqa: E402

# spdx/license-list-data v3.29.0, pinned by commit.
SPDX_TEXT = "https://raw.githubusercontent.com/spdx/license-list-data/31ba1a50e5397e00a304dbadc76531740e89ee48/text/{}.txt"
MAVEN = "https://repo1.maven.org/maven2"
MAX_BYTES = 1 << 20  # the attestation predicate; see the build-pipeline wiki page

NOTICE_NAME = re.compile(r"(?i)^(licen[cs]e|copying|copyright|notice)[\w.-]*$")
JAR_NOTICE = re.compile(r"(?i)^(meta-inf/)?([^/]*/)?(licen[cs]e|copying|copyright|notice)([-._][^/]*)?$")

# POM <license><name> → SPDX id, first match wins. Names already in SPDX
# form pass through unchanged.
POM_LICENSES = [
    (r"apache.*2", "Apache-2.0"),
    (r"^mit-0$", "MIT-0"),
    (r"(^|\b)mit\b", "MIT"),
    (r"bouncy ?castle", "MIT"),
    (r"gpl2 w/ cpe|gpl.*2.*classpath", "GPL-2.0-only WITH Classpath-exception-2.0"),
    (r"^(epl|eclipse public license)[ -]*(v|version )?2", "EPL-2.0"),
    (r"^(epl|eclipse public license)[ -]*(v|version )?1", "EPL-1.0"),
    (r"lesser general public license.*2\.1|lgpl[ -]*(v|version )?2\.1", "LGPL-2.1-only"),
    (r"affero|agpl", "AGPL-3.0-only"),
    (r"^gplv3$|general public license.*3|^gpl[ -]*(v|version )?3", "GPL-3.0-only"),
    (r"bsd[ -]*3|new bsd|revised bsd", "BSD-3-Clause"),
    (r"bsd[ -]*2|simplified bsd", "BSD-2-Clause"),
]


def fetch(url, cache_dir):
    """Download url once; the cache key is the URL (all inputs are pinned)."""
    path = os.path.join(cache_dir, hashlib.sha256(url.encode()).hexdigest())
    if not os.path.exists(path):
        os.makedirs(cache_dir, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "container-dropshipping-notices"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=300) as resp, open(path + ".part", "wb") as f:
                    while chunk := resp.read(1 << 20):
                        f.write(chunk)
                break
            except OSError as e:
                if getattr(e, "code", None) == 404 or attempt == 2:
                    raise
                time.sleep(5 * (attempt + 1))
        os.replace(path + ".part", path)
    return path


def spdx_ids(expression):
    tokens = re.split(r"[\s()]+", expression or "")
    return [current_id(t) for t in tokens
            if t and t not in ("AND", "OR", "WITH", "NOASSERTION", "NONE")
            and not t.startswith("LicenseRef-")]


def current_id(spdx_id):
    """Deprecated GNU ids (LGPL-2.1, GPL-2.0+) have no text file of their own."""
    m = re.fullmatch(r"((?:A|L)?GPL-\d\.\d)(\+?)", spdx_id)
    if m:
        return m.group(1) + ("-or-later" if m.group(2) else "-only")
    return spdx_id


class Texts:
    """License texts stored once by SHA256."""

    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        self.texts = {}

    def add(self, data):
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        sha = hashlib.sha256(text.encode()).hexdigest()
        self.texts[sha] = text
        return sha

    def spdx(self, expression):
        """Canonical texts for every id in an SPDX expression; ids without one are returned."""
        files, missing = [], []
        for spdx_id in spdx_ids(expression):
            try:
                with open(fetch(SPDX_TEXT.format(spdx_id), os.path.join(self.cache_dir, "spdx")), "rb") as f:
                    files.append({"path": f"spdx:{spdx_id}", "sha256": self.add(f.read()), "origin": "spdx"})
            except OSError:
                missing.append(spdx_id)
        return files, missing


def archive_notices(path, checksum):
    """License files at the archive root, plus notices in vendored Go sources."""
    if checksum:
        algo, _, want = checksum.partition(":")
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
        if h.hexdigest() != want:
            sys.exit(f"error: {path}: {algo} mismatch (want {want})")

    def wanted(name):
        parts = name.strip("/").split("/")
        rest = parts[1:] if len(parts) > 1 else parts  # drop the archive's root dir
        return ((len(rest) == 1 and NOTICE_NAME.match(rest[0]))
                or (len(rest) == 2 and rest[0] == "LICENSES")
                or (len(rest) > 1 and rest[0] == "vendor" and NOTICE_NAME.match(rest[-1])))

    found = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith("/") and wanted(name):
                    found.append((name.split("/", 1)[-1], z.read(name)))
    else:
        with tarfile.open(path, mode="r:*") as t:
            for m in t:
                if m.isfile() and wanted(m.name):
                    found.append((m.name.strip("/").split("/", 1)[-1], t.extractfile(m).read()))
    return sorted(found)


def pom_licenses(group, artifact, version, cache_dir, depth=0):
    """SPDX ids (or raw names) of a POM's licenses, following <parent>."""
    url = f"{MAVEN}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
    try:
        root = ET.parse(fetch(url, os.path.join(cache_dir, "maven"))).getroot()
    except (OSError, ET.ParseError):
        return []
    for el in root.iter():  # drop the POM namespace
        el.tag = el.tag.rsplit("}", 1)[-1]
    names = [n.text.strip() for n in root.findall("./licenses/license/name") if n.text]
    if names:
        return [to_spdx(n) for n in names]
    parent = root.find("./parent")
    if parent is not None and depth < 3:
        g, a, v = (parent.findtext(k, "").strip() for k in ("groupId", "artifactId", "version"))
        if g and a and v:
            return pom_licenses(g, a, v, cache_dir, depth + 1)
    return []


def to_spdx(name):
    for pattern, spdx_id in POM_LICENSES:
        if re.search(pattern, name, re.IGNORECASE):
            return spdx_id
    return name.replace(" ", "-")


def jar_notices(jar_bytes):
    with zipfile.ZipFile(io.BytesIO(jar_bytes)) as z:
        return sorted((n, z.read(n)) for n in z.namelist() if JAR_NOTICE.match(n))


def harvest(url, checksum, texts, cache_dir, files, unavailable):
    """Add the license files of a source archive to files; a 404 goes to unavailable."""
    print(f"  {url}", file=sys.stderr)
    try:
        path = fetch(url, os.path.join(cache_dir, "sources"))
    except urllib.error.HTTPError as e:
        # A pinned archive that's gone (tarballs.cgr.dev lacks a few) leaves
        # the canonical texts; anything else is a real failure.
        if e.code != 404:
            raise
        unavailable.append(url)
        return
    for name, data in archive_notices(path, checksum):
        files.append({"path": name, "sha256": texts.add(data), "origin": url})


def collect(sources_json, image_tar, cache_dir):
    with open(sources_json) as f:
        manifest = json.load(f)
    texts = Texts(cache_dir)

    packages = []
    for p in manifest["packages"]:
        files, unavailable = [], []
        for s in p["sources"]:
            if s.get("archive"):
                harvest(s["archive"], s.get("checksum"), texts, cache_dir, files, unavailable)
        canonical, missing = texts.spdx(p["license"])
        packages.append({**{k: p[k] for k in ("package", "version", "license")},
                         "files": files + canonical, "missing": missing, "unavailable": unavailable})

    # Files the bundled parts need from the image: jars and jre/legal/.
    bundled = manifest.get("bundled", [])
    jars, legal, shipped_notices = {}, {}, {}
    notice_paths = {path for b in bundled for path in b.get("noticeFiles", [])}
    notice_paths.update(("usr/share/konstapel/NOTICE", "usr/share/doc/konstapel/GO-LICENSE"))
    if bundled and image_tar != "-":
        for path, data in image_files(image_tar, lambda p: p in notice_paths or p.endswith(".jar") or "/jre/legal/" in p):
            if path in notice_paths:
                shipped_notices[path] = data
            else:
                (legal if "/jre/legal/" in path else jars)[path] = data

    extra = []
    for b in bundled:
        # An SPDX "license" in bundled-sources.json wins over the POM's.
        files, unavailable, expression = [], [], b.get("license", "")
        for path in b.get("noticeFiles", []):
            if path not in shipped_notices:
                sys.exit(f"error: declared license file is missing from image: {path}")
            files.append({"path": path, "sha256": texts.add(shipped_notices[path]), "origin": "image"})
        if b.get("name") == "github.com/backend-bunny/Konstapel":
            for path in ("usr/share/konstapel/NOTICE", "usr/share/doc/konstapel/GO-LICENSE"):
                files.append({"path": path, "sha256": texts.add(shipped_notices[path]), "origin": "image"})
        purl, source, ref = b.get("purl", ""), b.get("source", ""), b.get("ref", "")
        m = re.match(r"pkg:maven/([^/]+)/([^@]+)@(.+)$", purl)
        if m:
            group, artifact, version = m.groups()
            for path, data in jars.items():
                if path.endswith(f"/{artifact}-{version}.jar"):
                    for name, text in jar_notices(data):
                        files.append({"path": f"{os.path.basename(path)}!/{name}",
                                      "sha256": texts.add(text), "origin": "jar"})
            expression = expression or " AND ".join(pom_licenses(group, artifact, version, cache_dir))
        if purl.startswith("pkg:npm/"):
            harvest(source, b.get("checksum", ""), texts, cache_dir, files, unavailable)
        if purl.startswith("pkg:apk/wolfi/openjdk"):
            for path, data in sorted(legal.items()):
                files.append({"path": path, "sha256": texts.add(data), "origin": "image"})
        if source.startswith("https://github.com/") and ref and not b.get("noticeFiles"):
            kind = "" if re.fullmatch(r"[0-9a-f]{40}", ref) else "refs/tags/"
            harvest(f"{source}/archive/{kind}{ref}.tar.gz", "", texts, cache_dir, files, unavailable)
        canonical, missing = texts.spdx(expression)
        extra.append({"name": b.get("name"), "version": b.get("version"), "bundled_in": b["bundled_in"],
                      "license": expression, "files": files + canonical, "missing": missing,
                      "unavailable": unavailable, **({"note": b["note"]} if b.get("note") else {})})
    return {"packages": packages, "bundled": extra, "texts": texts.texts}


def markdown(notices):
    lines = ["| Package | License | Upstream notices | Canonical texts |", "|---|---|---|---|"]
    rows = [(f"`{p['package']}`", p) for p in notices["packages"]]
    rows += [(f"`{b['name']}` (in `{b['bundled_in']}`)", b) for b in notices["bundled"]]
    for label, p in rows:
        upstream = ", ".join(f"`{f['path']}`" for f in p["files"] if f["origin"] != "spdx")
        canonical = ", ".join(f["path"].removeprefix("spdx:") for f in p["files"] if f["origin"] == "spdx")
        lines.append(f"| {label} | {p['license'] or '?'} | {upstream or '⚠ none'} | {canonical} |")
    return "\n".join(lines) + "\n"


def reviewed(item):
    """A bundled part with no license at all, accepted by its component."""
    return item["license"] == "NOASSERTION" and not item["files"] and bool(item.get("note"))


def render(sources_json, image_tar, cache_dir, out_json, out_md):
    notices = collect(sources_json, image_tar, cache_dir)
    with open(out_json, "w") as f:
        json.dump(notices, f, indent=1)
        f.write("\n")
    with open(out_md, "w") as f:
        f.write(markdown(notices))

    items = notices["packages"] + notices["bundled"]
    size = os.path.getsize(out_json)
    print(f"  {len(items)} items, {len(notices['texts'])} distinct texts, {size // 1024} KiB")
    for p in items:
        name = p.get("package") or p.get("name")
        for url in p["unavailable"]:
            print(f"  warning: {name}: source archive gone (404): {url}", file=sys.stderr)
        if p["missing"]:
            print(f"  warning: {name}: no SPDX text for {', '.join(p['missing'])}", file=sys.stderr)
        if reviewed(p):
            print(f"  warning: {name}: upstream declares no license ({p['note']})", file=sys.stderr)
        elif not any(f["origin"] != "spdx" for f in p["files"]):
            print(f"  warning: {name}: canonical text only, no upstream notice", file=sys.stderr)
    empty = [p.get("package") or p.get("name") for p in items
             if not p["files"] and not reviewed(p)]
    if empty:
        sys.exit(f"error: no license text at all for: {', '.join(empty)}")
    if size > MAX_BYTES:
        sys.exit(f"error: {out_json} is {size} bytes, over the {MAX_BYTES}-byte attestation budget")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "render" and len(args) == 5:
        render(*args)
    else:
        sys.exit(__doc__)
