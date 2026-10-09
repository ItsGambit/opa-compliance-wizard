"""Runs the REAL nginx against server/nginx-opa-secrets-wizard.conf (GATE-06,
5.40.5) -- deploy.sh copies that file over the live site, so a template that
fails `nginx -t` fails a deploy, and a hardening directive that silently does
nothing (add_header inheritance, a prefix location) only shows up when nginx
actually serves a request.

Two layers:
- `nginx -t` on the template plus the second site server/nginx_second_site.py
  generates from it, both included in one http {} the way sites-enabled is.
- The same config served on ephemeral loopback ports in front of two stub
  upstreams (a fake gate and a fake backend), checking the security headers,
  the exact-match /healthz, the identity-header stripping there, and the
  callback rate limit.

Skipped when no nginx binary is available (OPA_TEST_NGINX, or `nginx` on
PATH / in /usr/sbin). CI installs nginx so these always run there.
"""
import datetime
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from server import nginx_second_site

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "server" / "nginx-opa-secrets-wizard.conf"


def _nginx_bin():
    for candidate in (os.environ.get("OPA_TEST_NGINX"), shutil.which("nginx"), "/usr/sbin/nginx"):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


NGINX = _nginx_bin()
if NGINX is None and os.environ.get("OPA_REQUIRE_NGINX_TESTS") == "1":  # set in CI: never skip silently there
    raise RuntimeError("OPA_REQUIRE_NGINX_TESTS=1 but no nginx binary was found")
pytestmark = pytest.mark.skipif(NGINX is None, reason="nginx binary not available")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _self_signed(tmp):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256()))
    crt, pem = tmp / "test.crt", tmp / "test.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return crt, pem


def _write_config(tmp, site_text, extra_sites=()):
    for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi", "logs"):
        (tmp / d).mkdir(exist_ok=True)
    (tmp / "main.conf").write_text(site_text)
    includes = [f"    include {tmp / 'main.conf'};"]
    for i, text in enumerate(extra_sites):
        (tmp / f"extra{i}.conf").write_text(text)
        includes.append(f"    include {tmp / f'extra{i}.conf'};")
    (tmp / "nginx.conf").write_text(f"""
pid {tmp / 'nginx.pid'};
error_log {tmp / 'logs' / 'error.log'} warn;
daemon off;
master_process off;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {tmp / 'client_body'};
    proxy_temp_path {tmp / 'proxy'};
    fastcgi_temp_path {tmp / 'fastcgi'};
    uwsgi_temp_path {tmp / 'uwsgi'};
    scgi_temp_path {tmp / 'scgi'};
{chr(10).join(includes)}
}}
""")
    return tmp / "nginx.conf"


def _template_with(tmp, crt, key, *, http_port=None, https_port=None, backend=8766, gate=8767):
    http_port = http_port or _free_port()
    https_port = https_port or _free_port()
    text = TEMPLATE.read_text()
    text = text.replace("/etc/nginx/ssl/opa-secrets-wizard.crt", str(crt))
    text = text.replace("/etc/nginx/ssl/opa-secrets-wizard.key", str(key))
    # `nginx -t` binds the listen sockets on Linux, so an unprivileged run
    # (CI) needs ports it may bind: always rewrite 80/443 to loopback ports.
    text = text.replace("listen 80;", f"listen 127.0.0.1:{http_port};", 1)
    text = text.replace("listen 443 ssl;", f"listen 127.0.0.1:{https_port} ssl;", 1)
    assert f"listen 127.0.0.1:{http_port};" in text and f"listen 127.0.0.1:{https_port} ssl;" in text
    text = text.replace("127.0.0.1:8766", f"127.0.0.1:{backend}")
    text = text.replace("127.0.0.1:8767", f"127.0.0.1:{gate}")
    return text


def _nginx_t(conf, prefix):
    return subprocess.run([NGINX, "-t", "-p", str(prefix), "-c", str(conf), "-e", str(prefix / "logs" / "t.log")],
                          capture_output=True, text=True, timeout=30)


def test_template_and_generated_second_site_pass_nginx_t(tmp_path):
    crt, key = _self_signed(tmp_path)
    main = _template_with(tmp_path, crt, key)
    # The generator needs the real `listen 443 ssl;` shape, so build the
    # second site from the unmodified template, then serve both on free ports.
    raw = TEMPLATE.read_text()
    second = nginx_second_site.build(raw, 8768, f"127.0.0.1:{_free_port()}", "opa.example.com", "second")
    conf = _write_config(tmp_path, main, [second])
    result = _nginx_t(conf, tmp_path)
    assert result.returncode == 0, result.stderr


def test_template_declares_the_hardening_once_at_server_level():
    """add_header / limit_req are inherited only by locations that define
    none of their own (nginx.org) -- a location adding one would silently
    drop every security header for that location."""
    text = TEMPLATE.read_text()
    https = [b for b in nginx_second_site.server_blocks(text) if "listen 443" in b][0]
    for _path, block in nginx_second_site._location_blocks(https):
        structure = nginx_second_site._structure(block)
        assert "add_header" not in structure, _path
    for header in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"):
        assert f'add_header {header} ' in https


# ---------------------------------------------------------------------------
# Served for real, against stub upstreams.
# ---------------------------------------------------------------------------
class _Recorder:
    def __init__(self):
        self.backend_requests = []
        self.callback_hits = 0


def _start(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def served(tmp_path):
    rec = _Recorder()

    class Gate(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/verify":
                if "opa_wizard_session=good" in (self.headers.get("Cookie") or ""):
                    self.send_response(200)
                    self.send_header("X-Auth-Sub", "00uREALUSER")
                    self.send_header("X-Auth-User", "user@example.com")
                    self.send_header("X-Auth-Is-Admin", "false")
                else:
                    self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/authorization-code/callback":
                rec.callback_hits += 1
            self.send_response(302)
            self.send_header("Location", "https://idp.example.com/authorize")
            self.send_header("Content-Length", "0")
            self.end_headers()

    class Backend(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            rec.backend_requests.append((self.path, dict(self.headers)))
            body = json.dumps({"path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    gate, backend = _start(Gate), _start(Backend)
    crt, key = _self_signed(tmp_path)
    http_port, https_port = _free_port(), _free_port()
    site = _template_with(tmp_path, crt, key, http_port=http_port, https_port=https_port,
                          backend=backend.server_address[1], gate=gate.server_address[1])
    conf = _write_config(tmp_path, site)
    assert _nginx_t(conf, tmp_path).returncode == 0
    proc = subprocess.Popen([NGINX, "-p", str(tmp_path), "-c", str(conf), "-e", str(tmp_path / "logs" / "e.log")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", https_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def request(path, headers=None, port=https_port, tls=True):
        conn = (http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10) if tls
                else http.client.HTTPConnection("127.0.0.1", port, timeout=10))
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    try:
        yield request, rec, http_port
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        gate.shutdown()
        backend.shutdown()


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "same-origin",
}


@pytest.mark.parametrize("path,cookie", [
    ("/", "opa_wizard_session=good"),      # proxied app response (200)
    ("/", None),                           # 401 -> /login redirect
    ("/login", None),                      # gate route
    ("/healthz", None),                    # public health check
])
def test_security_headers_on_every_kind_of_response(served, path, cookie):
    request, _rec, _ = served
    resp = request(path, {"Cookie": cookie} if cookie else {})
    for name, value in SECURITY_HEADERS.items():
        assert resp.getheader(name) == value, (path, name, resp.status)
    assert "nginx/" not in (resp.getheader("Server") or "")  # server_tokens off


def test_healthz_is_an_exact_match_and_drops_client_identity_headers(served):
    request, rec, _ = served
    resp = request("/healthz", {"X-Auth-Sub": "00uVICTIM", "X-Auth-Is-Admin": "true",
                                "X-Nginx-Proxy-Secret": "guess", "X-Auth-User": "x", "X-Auth-Action-Id": "y"})
    assert resp.status == 200
    _path, headers = rec.backend_requests[-1]
    lowered = {k.lower() for k in headers}
    for name in ("x-auth-sub", "x-auth-is-admin", "x-nginx-proxy-secret", "x-auth-user", "x-auth-action-id"):
        assert name not in lowered
    # /healthzanything no longer skips the login: it goes through auth_request.
    before = len(rec.backend_requests)
    resp = request("/healthzanything")
    assert resp.status == 302 and resp.getheader("Location") == "https://idp.example.com/authorize"
    assert len(rec.backend_requests) == before


def test_callback_is_rate_limited_with_429(served):
    request, rec, _ = served
    responses = [request("/authorization-code/callback?code=x&state=y") for _ in range(80)]
    statuses = [r.status for r in responses]
    assert statuses[0] == 302
    assert 429 in statuses
    # 429 is not in add_header's default status list -- only `always` puts
    # the security headers on it.
    limited = responses[statuses.index(429)]
    for name, value in SECURITY_HEADERS.items():
        assert limited.getheader(name) == value, name
    assert statuses[:60] == [302] * 60  # burst: a busy NAT or test run is not cut off early
    assert rec.callback_hits < 80  # the limited ones never reached the gate


def test_login_is_not_rate_limited(served):
    """/login is the error_page target for every 401 -- limiting it would turn
    session-expiry responses into 429s."""
    request, _rec, _ = served
    assert all(request("/login").status == 302 for _ in range(90))


def test_port_80_redirect_ignores_the_client_host_header(served):
    request, _rec, http_port = served
    resp = request("/x?y=1", {"Host": "evil.example.com"}, port=http_port, tls=False)
    import re

    server_name = re.search(r"server_name\s+([^;\s]+);", TEMPLATE.read_text()).group(1)
    assert resp.status == 301
    assert resp.getheader("Location") == f"https://{server_name}/x?y=1"
