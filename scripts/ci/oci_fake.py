"""A minimal in-process OCI distribution registry for chart publication
tests: blob uploads, manifests by tag or digest, and fault injection. It
speaks just enough of the distribution API for `helm push` and `helm pull`
(oras-go) over plain HTTP, with no Docker or network access."""

import hashlib
import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeRegistry:
    def __init__(self):
        self.blobs = {}  # digest -> bytes
        self.manifests = {}  # (repo, digest) -> (media type, bytes)
        self.tags = {}  # (repo, tag) -> digest
        self.uploads = {}
        self.writes = []  # (method, path) of every write
        self.fail_manifest_put = set()  # repos whose manifest PUTs fail until cleared
        self.lock = threading.Lock()
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, code, body=b"", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def route(self):
                path = self.path.split("?", 1)[0]
                query = dict(p.split("=", 1) for p in self.path.split("?", 1)[1].split("&")) if "?" in self.path else {}
                if path in ("/v2/", "/v2"):
                    return self.send(200, b"{}")
                m = re.match(r"^/v2/(.+)/(blobs|manifests)/(uploads/?([^/]*)|[^/]+)$", path)
                if not m:
                    return self.send(404)
                repo, kind, ref = m.group(1), m.group(2), m.group(3)
                with registry.lock:
                    if kind == "blobs" and ref.startswith("uploads"):
                        return self.upload(repo, m.group(4), query)
                    if kind == "blobs":
                        data = registry.blobs.get(ref)
                        if data is None:
                            return self.send(404)
                        return self.send(200, data, {"Docker-Content-Digest": ref, "Content-Type": "application/octet-stream"})
                    return self.manifest(repo, ref)

            def upload(self, repo, upload_id, query):
                registry.writes.append((self.command, self.path))
                if self.command == "POST":
                    uid = uuid.uuid4().hex
                    registry.uploads[uid] = b""
                    return self.send(202, b"", {"Location": f"/v2/{repo}/blobs/uploads/{uid}", "Docker-Upload-UUID": uid})
                if self.command == "PATCH":
                    registry.uploads[upload_id] = registry.uploads.get(upload_id, b"") + self.body()
                    return self.send(202, b"", {"Location": f"/v2/{repo}/blobs/uploads/{upload_id}", "Range": f"0-{len(registry.uploads[upload_id]) - 1}"})
                if self.command == "PUT":
                    data = registry.uploads.pop(upload_id, b"") + self.body()
                    digest = "sha256:" + hashlib.sha256(data).hexdigest()
                    if query.get("digest", "").replace("%3A", ":") != digest:
                        return self.send(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}')
                    registry.blobs[digest] = data
                    return self.send(201, b"", {"Location": f"/v2/{repo}/blobs/{digest}", "Docker-Content-Digest": digest})
                return self.send(405)

            def manifest(self, repo, ref):
                if self.command == "PUT":
                    registry.writes.append(("PUT", self.path))
                    if repo in registry.fail_manifest_put:
                        return self.send(500, b'{"errors":[{"code":"UNKNOWN","message":"injected failure"}]}')
                    data = self.body()
                    digest = "sha256:" + hashlib.sha256(data).hexdigest()
                    media = self.headers.get("Content-Type") or json.loads(data).get("mediaType", "")
                    registry.manifests[(repo, digest)] = (media, data)
                    if not ref.startswith("sha256:"):
                        registry.tags[(repo, ref)] = digest
                    return self.send(201, b"", {"Location": f"/v2/{repo}/manifests/{digest}", "Docker-Content-Digest": digest})
                digest = ref if ref.startswith("sha256:") else registry.tags.get((repo, ref))
                found = registry.manifests.get((repo, digest)) if digest else None
                if not found:
                    return self.send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
                media, data = found
                return self.send(200, data, {"Content-Type": media, "Docker-Content-Digest": digest})

            do_GET = do_HEAD = do_PUT = do_POST = do_PATCH = route

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()

    def manifest_writes(self):
        return [w for w in self.writes if "/manifests/" in w[1]]
