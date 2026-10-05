"""Covers ENG1-02 (external review, 2026-10-05): base_domain/okta_url had
no validation at all before this fix, and the module's HTTP client
followed any redirect -- including cross-host and https->http -- while
carrying forward the Authorization/SSWS header, delivering this
project's real OPA key_secret/Okta API token to whatever host a
malicious or compromised value's server redirected to.

Two independent layers, each tested here:
1. validate_base_domain/validate_okta_url reject anything that isn't a
   bare hostname / bare https origin.
2. _SAFE_OPENER (installed in http_json_request) refuses a redirect that
   changes host/port/scheme, as a defense-in-depth backstop even if a
   bad value somehow reached the HTTP layer anyway."""
import http.server
import threading

import pytest

import create_secret_folders as engine


# ---------------------------------------------------------------------------
# validate_base_domain
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("good", [
    "your-org.okta.com",
    "mxmco-3.pam.oktapreview.com",
    "a.b.c.d.example.com",
])
def test_validate_base_domain_accepts_real_hostname_shapes(good):
    assert engine.validate_base_domain(good) == good


@pytest.mark.parametrize("bad", [
    "",
    "your-org.okta.com/evil",
    "your-org.okta.com@attacker.example.com",
    "http://your-org.okta.com",
    "https://your-org.okta.com",
    "your-org.okta.com:8080",
    "your-org.okta.com?x=1",
    "..",
    "no-dots-at-all",
])
def test_validate_base_domain_rejects_anything_not_a_bare_hostname(bad):
    with pytest.raises(ValueError):
        engine.validate_base_domain(bad)


# ---------------------------------------------------------------------------
# validate_okta_url
# ---------------------------------------------------------------------------
def test_validate_okta_url_is_optional():
    assert engine.validate_okta_url(None) is None
    assert engine.validate_okta_url("") == ""


@pytest.mark.parametrize("good", ["https://your-org.okta.com", "https://your-org.okta.com/"])
def test_validate_okta_url_accepts_a_bare_https_origin(good):
    assert engine.validate_okta_url(good) == good


@pytest.mark.parametrize("bad", [
    "https://your-org.okta.com/path",
    "https://your-org.okta.com?x=1",
    "https://your-org.okta.com#frag",
    "https://user@attacker.example.com",
    "https://user:pass@attacker.example.com",
    "http://your-org.okta.com",
    "ftp://your-org.okta.com",
])
def test_validate_okta_url_rejects_anything_beyond_a_bare_https_origin(bad):
    with pytest.raises(ValueError):
        engine.validate_okta_url(bad)


# ---------------------------------------------------------------------------
# upsert_environment wires both validators in -- a bad value is rejected
# at save time, not just by the standalone validator functions.
# ---------------------------------------------------------------------------
def test_upsert_environment_rejects_a_malicious_base_domain(tmp_audit_store, fake_keyring):
    import audit_store
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        engine.upsert_environment(
            "dev",
            {
                "base_domain": "real-tenant.okta.com@attacker.example.com",
                "team_name": "team", "key_id": "key", "key_secret": "secret",
            },
        )


def test_upsert_environment_rejects_a_malicious_okta_url(tmp_audit_store, fake_keyring):
    import audit_store
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        engine.upsert_environment(
            "dev",
            {
                "base_domain": "real-tenant.okta.com", "team_name": "team", "key_id": "key",
                "key_secret": "secret", "okta_url": "https://user@attacker.example.com",
            },
        )


def test_upsert_environment_accepts_well_formed_values(tmp_audit_store, fake_keyring):
    import audit_store
    audit_store.run_migrations()
    name, env_id = engine.upsert_environment(
        "dev",
        {
            "base_domain": "real-tenant.okta.com", "team_name": "team", "key_id": "key",
            "key_secret": "secret", "okta_url": "https://real-tenant.okta.com",
        },
    )
    assert name == "dev"
    assert env_id


# ---------------------------------------------------------------------------
# _SAFE_OPENER: defense-in-depth backstop at the HTTP layer itself.
# ---------------------------------------------------------------------------
class _RedirectingHandler(http.server.BaseHTTPRequestHandler):
    """Serves /same-host-redirect (same host, must succeed, auth header
    preserved) and /cross-host-redirect (a different host:port, must be
    refused before the second server ever sees the request)."""
    cross_host_target = None  # set by the fixture to the second server's URL

    def do_GET(self):
        if self.path == "/same-host-redirect":
            self.send_response(302)
            self.send_header("Location", "/same-host-target")
            self.end_headers()
        elif self.path == "/same-host-target":
            self._respond_json(200, {"ok": True, "auth": self.headers.get("Authorization")})
        elif self.path == "/cross-host-redirect":
            self.send_response(302)
            self.send_header("Location", self.cross_host_target)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def _respond_json(self, status, body_dict):
        import json
        body = json.dumps(body_dict).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    """The attacker-controlled second host a cross-host redirect would
    point at -- records whether it ever received the Authorization
    header, which it must NOT if the guard works."""
    captured_auth_header = [None]  # class-level, shared mutable slot

    def do_GET(self):
        _CaptureHandler.captured_auth_header[0] = self.headers.get("Authorization")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


@pytest.fixture
def two_servers():
    srv1 = http.server.HTTPServer(("127.0.0.1", 0), _RedirectingHandler)
    srv2 = http.server.HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port1, port2 = srv1.server_address[1], srv2.server_address[1]
    _RedirectingHandler.cross_host_target = f"http://127.0.0.1:{port2}/capture"
    _CaptureHandler.captured_auth_header[0] = None
    t1 = threading.Thread(target=srv1.serve_forever, daemon=True)
    t2 = threading.Thread(target=srv2.serve_forever, daemon=True)
    t1.start()
    t2.start()
    yield port1, port2
    srv1.shutdown()
    srv2.shutdown()


def test_same_host_redirect_still_works_and_keeps_the_auth_header(two_servers):
    port1, _ = two_servers
    result = engine.http_json_request(
        "GET", f"http://127.0.0.1:{port1}/same-host-redirect", headers={"Authorization": "real-secret-token"}
    )
    assert result == {"ok": True, "auth": "real-secret-token"}


def test_cross_host_redirect_is_refused_and_the_token_never_reaches_the_second_host(two_servers):
    port1, _ = two_servers
    with pytest.raises(engine.OpaApiError):
        engine.http_json_request(
            "GET", f"http://127.0.0.1:{port1}/cross-host-redirect", headers={"Authorization": "real-secret-token"}
        )
    assert _CaptureHandler.captured_auth_header[0] is None
