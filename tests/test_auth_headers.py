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
