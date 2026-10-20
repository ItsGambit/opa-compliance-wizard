"""A local stand-in for GitHub's release API and release downloads, for the
update-check tests: serves what a test scripts, records every request.

    server.respond("/latest", status=200, body=..., headers={...})
    server.respond("/latest", mode="truncate")      # promises more bytes than it sends
    server.respond("/latest", mode="slow", delay=2) # answers after `delay` seconds
    server.requests  -> [{"path", "headers"}, ...]
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def release_json(version="5.47.0", prerelease=False, draft=False, assets="signed", published="2026-10-01T12:00:00Z"):
    names = {"signed": [f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig", "manifest.json"],
             "unsigned": [f"ocw-{version}.tar.gz"], "none": []}[assets]
    return json.dumps({"tag_name": f"v{version}", "draft": draft, "prerelease": prerelease, "published_at": published,
                       "html_url": f"https://github.com/example/example/releases/tag/v{version}",
                       "assets": [{"name": n} for n in names]}).encode()


class FakeReleaseServer:
    def __init__(self):
        self.script = {}
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
                spec = outer.script.get(self.path.split("?")[0])
                if spec is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if spec.get("mode") == "slow":
                    time.sleep(spec["delay"])
                body = spec.get("body", b"")
                status = spec.get("status", 200)
                if spec.get("etag") and self.headers.get("If-None-Match") == spec["etag"]:
                    status, body = 304, b""
                self.send_response(status)
                for k, v in (spec.get("headers") or {}).items():
                    self.send_header(k, v)
                if spec.get("etag") and status != 304:
                    self.send_header("ETag", spec["etag"])
                if spec.get("mode") == "truncate":
                    self.send_header("Content-Length", str(len(body) + 500))
                else:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if status != 304 and self.command != "HEAD":
                    self.wfile.write(body)
                    self.wfile.flush()
                if spec.get("mode") == "truncate":
                    self.close_connection = True

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def respond(self, path, **spec):
        self.script[path] = spec

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
