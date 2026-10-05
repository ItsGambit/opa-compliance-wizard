"""Regression test for the P0 header-spoofing fix (external review,
2026-09-30): server/serve.py must NEVER trust X-Auth-Is-Admin / X-Auth-Sub
unless the request actually transited nginx's auth_request flow (proven
by a matching X-Nginx-Proxy-Secret header). This test exists specifically
so a future revert of that fix fails loudly here instead of silently
reopening the admin-impersonation hole.

NGINX_PROXY_SECRET is read into a module-level global at IMPORT time
(server/serve.py), so tests must monkeypatch the module attribute
directly -- monkeypatch.setenv after import has no effect."""
import server.serve as serve


def test_admin_header_rejected_without_matching_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    # No X-Nginx-Proxy-Secret at all -- before the fix, this alone would
    # have been treated as a genuine admin request.
    assert serve._is_admin_from_headers({"X-Auth-Is-Admin": "true"}) is False
    # Wrong secret is just as untrusted as no secret.
    assert serve._is_admin_from_headers(
        {"X-Auth-Is-Admin": "true", "X-Nginx-Proxy-Secret": "wrong"}
    ) is False


def test_admin_header_trusted_with_matching_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    assert serve._is_admin_from_headers(
        {"X-Auth-Is-Admin": "true", "X-Nginx-Proxy-Secret": "real-secret"}
    ) is True


def test_admin_header_trusted_unconditionally_when_proxy_secret_unset(monkeypatch):
    """Standalone/local-only mode, by design -- unchanged behavior."""
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", None)
    assert serve._is_admin_from_headers({"X-Auth-Is-Admin": "true"}) is True


def test_owner_key_impersonation_rejected_without_matching_proxy_secret(monkeypatch):
    """Sibling exploit shape to the admin check above -- impersonating a
    specific user's owner_key (X-Auth-Sub) instead of granting admin."""
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    owner_key = serve._owner_key_from_headers({"X-Auth-Sub": "00uVICTIM"})
    assert owner_key == serve.LOCAL_OWNER_KEY_HEADER  # falls back, never impersonates


def test_owner_key_trusted_with_matching_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    owner_key = serve._owner_key_from_headers(
        {"X-Auth-Sub": "00uREALUSER", "X-Nginx-Proxy-Secret": "real-secret"}
    )
    assert owner_key == "00uREALUSER"


# ---------------------------------------------------------------------------
# SRV-01 (external review, 2026-10-05): CONFIRMED EXPLOITABLE IN PRODUCTION.
# In hosted mode, a request that fails the nginx proxy-secret check used to
# be silently DOWNGRADED to the privileged `__local__` owner instead of
# being rejected -- and every admin-only route's guard
# (`owner_key != LOCAL_OWNER_KEY_HEADER and not is_admin`) treats
# `__local__` as exempt. Combined with GATE-01 (any gate-signed cookie
# verifying as a session cookie), this let an unauthenticated caller with
# no Okta account read/write admin-only routes over the network. The fix:
# _reject_if_hosted_without_nginx must return True (401) for exactly this
# shape of request, and False for every case that must stay working.
# ---------------------------------------------------------------------------
class _FakeHandler:
    """Minimal stand-in for Handler -- _reject_if_hosted_without_nginx only
    needs .headers and ._send_json; using the real HTTP handler class here
    would require a live socket for no benefit."""

    def __init__(self, headers):
        self.headers = headers
        self.sent = None

    def _send_json(self, status, payload):
        self.sent = (status, payload)


def test_hosted_mode_rejects_request_with_no_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler({})
    assert serve._reject_if_hosted_without_nginx(handler, "/api/audit_log") is True
    assert handler.sent[0] == 401


def test_hosted_mode_rejects_request_with_wrong_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler({"X-Nginx-Proxy-Secret": "wrong"})
    assert serve._reject_if_hosted_without_nginx(handler, "/api/access_control") is True
    assert handler.sent[0] == 401


def test_hosted_mode_allows_request_with_matching_proxy_secret(monkeypatch):
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler({"X-Nginx-Proxy-Secret": "real-secret"})
    assert serve._reject_if_hosted_without_nginx(handler, "/api/audit_log") is False
    assert handler.sent is None


def test_hosted_mode_still_allows_healthz_with_no_proxy_secret(monkeypatch):
    """/healthz's nginx location has auth_request off and never sets
    X-Nginx-Proxy-Secret either (see nginx-opa-secrets-wizard.conf) -- an
    external uptime monitor has no Okta session and this route holds no
    tenant data, so it must stay reachable even in hosted mode."""
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "real-secret")
    handler = _FakeHandler({})
    assert serve._reject_if_hosted_without_nginx(handler, "/healthz") is False
    assert handler.sent is None


def test_local_mode_never_rejects_regardless_of_proxy_secret_header(monkeypatch):
    """local mode (the default, no nginx at all) must be byte-for-byte
    unaffected -- this guard only ever fires in hosted mode."""
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "local")
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", None)
    handler = _FakeHandler({})
    assert serve._reject_if_hosted_without_nginx(handler, "/api/audit_log") is False
    assert handler.sent is None
