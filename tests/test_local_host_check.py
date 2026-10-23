"""5.53.0 local-mode Host check: a request whose Host is not this server's own
loopback name and port is answered 421 before any handler runs (DNS rebinding
defence). Hosted mode is unchanged."""
import socket
import threading
import time

import pytest
import requests


@pytest.fixture
def host_server(fake_keyring, tmp_audit_log):
    import server.serve as serve

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            requests.get(f"http://127.0.0.1:{port}/api/version", timeout=0.5)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    yield port, serve
    instance.shutdown()
    instance.server_close()


def _raw(port, method, host, path="/api/version", body=b"", extra=""):
    """Sends the exact Host given (None = no Host header); returns (status, body)."""
    head = f"{method} {path} HTTP/1.1\r\n"
    if host is not None:
        head += f"Host: {host}\r\n"
    head += f"{extra}Connection: close\r\n"
    if body:
        head += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.settimeout(5)
        conn.sendall(head.encode() + b"\r\n" + body)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    status = int(data.split(b" ", 2)[1])
    return status, data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""


def test_rebinding_host_is_refused_for_get_and_post(host_server):
    port, _serve = host_server
    status, body = _raw(port, "GET", f"attacker.example.com:{port}")
    assert status == 421 and body.startswith(b"Misdirected request")
    status, _ = _raw(port, "POST", f"attacker.example.com:{port}", "/api/banner", b'{"enabled": false}')
    assert status == 421


def test_refused_before_any_handler_runs_for_every_method(host_server):
    port, _serve = host_server
    for method in ("GET", "HEAD", "POST", "DELETE", "PUT", "OPTIONS"):
        status, _ = _raw(port, method, f"attacker.example.com:{port}", "/api/environments")
        assert status == 421, method


def test_three_loopback_forms_are_accepted(host_server):
    port, _serve = host_server
    for host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}", f"LocalHost:{port}"):
        status, _ = _raw(port, "GET", host)
        assert status == 200, host


def test_wrong_port_missing_and_duplicate_host_are_refused(host_server):
    port, _serve = host_server
    other = port + 1 if port < 65535 else port - 1
    assert _raw(port, "GET", f"127.0.0.1:{other}")[0] == 421
    assert _raw(port, "GET", "127.0.0.1")[0] == 421  # no port
    assert _raw(port, "GET", None)[0] == 421
    assert _raw(port, "GET", f"127.0.0.1:{port}", extra="Host: attacker.example.com\r\n")[0] == 421


def test_extra_origins_override_is_honoured(host_server, monkeypatch):
    port, serve = host_server
    assert _raw(port, "GET", "dashboard.example.com")[0] == 421
    monkeypatch.setattr(serve, "EXTRA_ALLOWED_ORIGINS", {"https://dashboard.example.com", "http://192.0.2.10:9000"})
    assert _raw(port, "GET", "dashboard.example.com")[0] == 200
    assert _raw(port, "GET", "192.0.2.10:9000")[0] == 200
    assert _raw(port, "GET", "other.example.com")[0] == 421


def test_hosted_mode_is_unaffected(host_server, monkeypatch):
    port, serve = host_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "test-proxy-secret")
    status, _ = _raw(port, "GET", "anything.example.com",
                     extra="X-Nginx-Proxy-Secret: test-proxy-secret\r\nX-Auth-Sub: 00uUSER\r\n")
    assert status == 200
