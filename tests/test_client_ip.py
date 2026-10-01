"""Covers Handler._request_client_ip -- audit logging must capture the
REAL originating client IP, not nginx's own loopback peer address, when
reverse-proxied. The real client IP in that mode only exists in the
X-Real-IP header nginx sets from $remote_addr; this must only be trusted
when _request_is_from_nginx confirms the request actually transited
nginx (same trust boundary that already gates X-Auth-Is-Admin/X-Auth-Sub
-- X-Real-IP is exactly as spoofable by a direct loopback request)."""
import server.serve as serve


class _FakeHandler:
    """Minimal stand-in for Handler -- avoids spinning up a real
    http.server.BaseHTTPRequestHandler just to test one method, which
    expects a live socket/rfile/wfile in its __init__."""

    def __init__(self, headers, client_address):
        self.headers = headers
        self.client_address = client_address

    _request_client_ip = serve.Handler._request_client_ip


def test_trusts_x_real_ip_when_request_is_from_nginx(monkeypatch):
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler(
        headers={"X-Real-IP": "203.0.113.42", "X-Nginx-Proxy-Secret": "real-secret"},
        client_address=("127.0.0.1", 54321),
    )
    assert handler._request_client_ip() == "203.0.113.42"


def test_falls_back_to_socket_peer_when_not_from_nginx(monkeypatch):
    """A request straight to the loopback port (bypassing nginx) must
    never have its claimed X-Real-IP trusted -- same exploit shape as
    X-Auth-Is-Admin spoofing."""
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler(
        headers={"X-Real-IP": "203.0.113.42"},  # no matching proxy secret
        client_address=("127.0.0.1", 54321),
    )
    assert handler._request_client_ip() == "127.0.0.1"


def test_falls_back_to_socket_peer_in_standalone_mode(monkeypatch):
    """NGINX_PROXY_SECRET unset entirely (standalone/local-only mode, no
    nginx in front at all) -- the socket peer IS the real client here."""
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", None)
    handler = _FakeHandler(
        headers={},
        client_address=("127.0.0.1", 54321),
    )
    assert handler._request_client_ip() == "127.0.0.1"


def test_falls_back_to_socket_peer_when_x_real_ip_missing_despite_nginx(monkeypatch):
    """Defensive: nginx always sets X-Real-IP per the repo's own template,
    but a request confirmed-from-nginx with no such header shouldn't
    crash or return None when a real client_address exists."""
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler(
        headers={"X-Nginx-Proxy-Secret": "real-secret"},
        client_address=("127.0.0.1", 54321),
    )
    assert handler._request_client_ip() == "127.0.0.1"
