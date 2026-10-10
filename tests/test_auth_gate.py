"""Covers server/auth_gate.py (TEST-04, external review, 2026-10-05): this
module had ZERO tests and 0% coverage before this file -- it is the entire
hosted-mode security boundary (OIDC/JWT verification, cookie signing,
fail-closed group-membership checks, access-control fallback behaviour).

auth_gate.py does real work at IMPORT time (reads required env vars,
resolves secrets from the OS keyring, creates/loads a session-signing key
file on disk), so importing it for a test needs that environment staged
first -- same approach the external review's own proof-of-concept used: a
fake `keyring` module in sys.modules, required env vars set, and a
temp-file session key path, all in place BEFORE the first import. Every
test in this file goes through the `gate` fixture below rather than
importing server.auth_gate directly.

Covers, at minimum (per the review's TEST-04 remediation):
- _verify_signed_payload: good MAC, tampered MAC, expired, and -- the
  actual GATE-01 bypass -- a token minted for one cookie "typ" must NOT
  verify as a different one (flow-as-session, session-as-stepup).
- _resolve_membership: fails closed when group_ids is None (a broken/
  expired admin-check token or transient Okta API error must never
  silently grant admin or login rights).
- _read_access_control_config: missing file -> bootstrap default;
  malformed file with a prior good read -> last-good; malformed file with
  NO prior good read -> bootstrap default (the 2026-09-30 fix this
  function's own docstring describes).
- The GATE-03 action_id pattern a real id must match.
"""
import base64
import hashlib
import hmac
import json
import sys
import time
import types

import pytest


class _FakeKeyring(types.ModuleType):
    def __init__(self):
        super().__init__("keyring")
        self._store = {
            ("opa-compliance-wizard:default", "okta_client_secret"): "test-client-secret",
            ("opa-compliance-wizard:default", "okta_admin_check_token"): "test-admin-check-token",
        }

    def get_password(self, service, field):
        return self._store.get((service, field))


def _stage_gate_env(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", _FakeKeyring())
    monkeypatch.setenv("OKTA_ORG_URL", "https://example.oktapreview.com")
    monkeypatch.setenv("OKTA_OIDC_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("OKTA_ADMIN_GROUP_ID", "00gBOOTSTRAPADMIN")
    monkeypatch.setenv("DASHBOARD_ORIGIN", "https://dashboard.example.com")
    monkeypatch.setenv("OPA_SESSION_KEY_PATH", str(tmp_path / "session.key"))
    monkeypatch.setenv(
        "OPA_ACCESS_CONTROL_PATH", str(tmp_path / "access_control.json")
    )
    monkeypatch.delenv("OKTA_ENV_NAME", raising=False)
    monkeypatch.delenv("OKTA_AUTH_SERVER", raising=False)
    monkeypatch.delenv("INTERNAL_API_SHARED_SECRET", raising=False)


def _import_gate():
    sys.modules.pop("server.auth_gate", None)
    sys.modules.pop("auth_gate", None)
    import server.auth_gate as auth_gate

    return auth_gate


@pytest.fixture
def gate(tmp_path, monkeypatch):
    """Imports server.auth_gate with a stubbed keyring, required env vars,
    and a disposable session-key file -- fresh every test via a forced
    reimport, so no test can see another test's SESSION_KEY or
    _LAST_GOOD_ACCESS_CONTROL_CONFIG state."""
    _stage_gate_env(tmp_path, monkeypatch)
    auth_gate = _import_gate()

    yield auth_gate

    sys.modules.pop("server.auth_gate", None)
    sys.modules.pop("auth_gate", None)


# ---------------------------------------------------------------------------
# GATE-01: cookie-type confusion. Before the fix, _verify_signed_payload had
# no notion of which cookie a token was minted for, so a flow token (minted
# pre-authentication by GET /login for ANY unauthenticated visitor) verified
# equally well as a session cookie or a step-up cookie -- a confirmed,
# live, pre-auth authentication bypass.
# ---------------------------------------------------------------------------
def test_flow_token_does_not_verify_as_a_session_token(gate):
    flow_token = gate._sign_payload({"typ": "flow", "state": "s", "verifier": "v"}, 600)
    assert gate._verify_signed_payload(flow_token, "session") is None
    # Without an expected type, the old (vulnerable) behaviour returns the
    # payload -- callers must always pass expected_typ for a cookie check.
    assert gate._verify_signed_payload(flow_token, "flow") is not None


def test_session_token_does_not_verify_as_a_stepup_token(gate):
    session_token = gate._sign_payload({"typ": "session", "sub": "00uVICTIM"}, 600)
    assert gate._verify_signed_payload(session_token, "stepup") is None
    assert gate._verify_signed_payload(session_token, "session") is not None


def test_verify_session_rejects_a_replayed_flow_cookie(gate, monkeypatch):
    """End-to-end shape of the live GATE-01 exploit: the flow cookie /login
    hands to an unauthenticated visitor, replayed as the session cookie,
    must now 401 instead of returning identity headers for __local__."""
    flow_token = gate._sign_payload(
        {"typ": "flow", "state": "s", "verifier": "v", "purpose": "login", "action_id": None}, 600
    )

    sent = {}

    class _FakeHandler(gate.Handler):
        def __init__(self):
            self.headers = {"Cookie": f"opa_wizard_session={flow_token}"}

        def send_response(self, status):
            sent["status"] = status

        def send_header(self, name, value):
            sent.setdefault("headers", {})[name] = value

        def end_headers(self):
            pass

    _FakeHandler()._verify_session()
    assert sent["status"] == 401
    assert "headers" not in sent  # no X-Auth-Sub ever gets a chance to be emitted


# ---------------------------------------------------------------------------
# _verify_signed_payload: baseline signature/expiry behaviour.
# ---------------------------------------------------------------------------
def test_tampered_payload_is_rejected(gate):
    token = gate._sign_payload({"typ": "session", "sub": "00uUSER"}, 600)
    body, mac = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(body.encode()))
    payload["sub"] = "00uATTACKER"
    tampered_body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    tampered_token = f"{tampered_body}.{mac}"
    assert gate._verify_signed_payload(tampered_token, "session") is None


def test_signed_with_a_different_key_is_rejected(gate):
    body = base64.urlsafe_b64encode(
        json.dumps({"typ": "session", "sub": "00uUSER", "exp": int(time.time()) + 600}, separators=(",", ":")).encode()
    ).decode()
    wrong_mac = hmac.new(b"not-the-real-key", body.encode(), hashlib.sha256).hexdigest()
    assert gate._verify_signed_payload(f"{body}.{wrong_mac}", "session") is None


def test_expired_payload_is_rejected(gate):
    token = gate._sign_payload({"typ": "session", "sub": "00uUSER"}, -1)
    assert gate._verify_signed_payload(token, "session") is None


def test_malformed_token_shapes_are_rejected(gate):
    assert gate._verify_signed_payload("not-a-token-at-all", "session") is None
    assert gate._verify_signed_payload("", "session") is None


# ---------------------------------------------------------------------------
# _resolve_membership: must fail closed, never open.
# ---------------------------------------------------------------------------
def test_resolve_membership_fails_closed_when_group_lookup_failed(gate):
    """group_ids is None means the Okta API call failed/the token is
    broken -- must never be treated as "in zero groups" (which would be a
    real, if empty, list)."""
    is_admin, is_allowed = gate._resolve_membership(None, "00gADMIN", "00gUSER")
    assert (is_admin, is_allowed) == (False, False)


def test_resolve_membership_grants_admin_for_a_real_admin_group_member(gate):
    is_admin, is_allowed = gate._resolve_membership(["00gADMIN", "00gOTHER"], "00gADMIN", "00gUSER")
    assert (is_admin, is_allowed) == (True, True)


def test_resolve_membership_grants_user_but_not_admin(gate):
    is_admin, is_allowed = gate._resolve_membership(["00gUSER"], "00gADMIN", "00gUSER")
    assert (is_admin, is_allowed) == (False, True)


def test_resolve_membership_denies_a_real_empty_group_list_when_groups_are_configured(gate):
    is_admin, is_allowed = gate._resolve_membership([], "00gADMIN", "00gUSER")
    assert (is_admin, is_allowed) == (False, False)


def test_resolve_membership_allows_everyone_when_nothing_is_configured(gate):
    """Neither admin_group_id nor user_group_id set -- nothing to restrict
    against yet (a fresh install), matching the bootstrap default."""
    is_admin, is_allowed = gate._resolve_membership([], None, None)
    assert (is_admin, is_allowed) == (False, True)


# ---------------------------------------------------------------------------
# _read_access_control_config: missing vs malformed, and the
# malformed-with-no-prior-good-read edge case (2026-09-30 fix).
# ---------------------------------------------------------------------------
def test_missing_access_control_file_returns_bootstrap_default(gate, monkeypatch):
    # Only when OPA_ACCESS_CONTROL_PATH is NOT set (the main gate) -- GATE-14
    # below covers the explicitly configured case, which fails closed.
    monkeypatch.setattr(gate, "ACCESS_CONTROL_PATH_EXPLICIT", False)
    config = gate._read_access_control_config()
    assert config == {"admin_group_id": "00gBOOTSTRAPADMIN", "user_group_id": None, "restrict_login": False}


def test_malformed_file_with_no_prior_good_read_falls_back_to_bootstrap_default(gate, monkeypatch):
    monkeypatch.setattr(gate, "ACCESS_CONTROL_PATH_EXPLICIT", False)
    gate.ACCESS_CONTROL_FILE_PATH.write_text("{not valid json", encoding="utf-8")
    config = gate._read_access_control_config()
    assert config == {"admin_group_id": "00gBOOTSTRAPADMIN", "user_group_id": None, "restrict_login": False}


def test_malformed_file_after_a_prior_good_read_falls_back_to_last_good(gate):
    good = {"admin_group_id": "00gREAL", "user_group_id": "00gUSERS", "restrict_login": True}
    gate.ACCESS_CONTROL_FILE_PATH.write_text(json.dumps(good), encoding="utf-8")
    first = gate._read_access_control_config()
    assert first == good

    gate.ACCESS_CONTROL_FILE_PATH.write_text("{not valid json", encoding="utf-8")
    second = gate._read_access_control_config()
    # Restrictive settings stay enforced even though the file is now
    # unreadable -- NOT silently reset to the permissive bootstrap default.
    assert second == good


def test_well_formed_file_is_read_through(gate):
    config = {"admin_group_id": "00gREAL", "user_group_id": None, "restrict_login": False}
    gate.ACCESS_CONTROL_FILE_PATH.write_text(json.dumps(config), encoding="utf-8")
    assert gate._read_access_control_config() == config


# ---------------------------------------------------------------------------
# GATE-03: the action_id shape every real id (secrets.token_urlsafe(32))
# already matches, and what must be rejected.
# ---------------------------------------------------------------------------
def test_action_id_pattern_accepts_a_real_token_urlsafe_id(gate):
    import secrets

    real_id = secrets.token_urlsafe(32)
    assert gate._ACTION_ID_PATTERN.fullmatch(real_id)


@pytest.mark.parametrize(
    "bad",
    [
        "x\r\nX-Auth-Is-Admin: true",
        "has a space",
        "semi;colon",
        "short",
        "x" * 200,
        "",
    ],
)
def test_action_id_pattern_rejects_injection_and_malformed_shapes(gate, bad):
    assert not gate._ACTION_ID_PATTERN.fullmatch(bad)


# ===========================================================================
# Review batch 3 (v5.40.5): GATE-07..GATE-14 and the mfa_log_lookup 5xx.
# Handler tests run the real Handler on a loopback ThreadingHTTPServer, so
# send_header's own encoding rules and the real status line are exercised.
# ===========================================================================
import http.client  # noqa: E402
import os  # noqa: E402
import stat  # noqa: E402
import threading  # noqa: E402
import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

ORIGIN = "https://dashboard.example.com"


@pytest.fixture
def gate_server(gate):
    server = ThreadingHTTPServer(("127.0.0.1", 0), gate.Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield gate, server.server_address[1]
    server.shutdown()
    server.server_close()


def _call(port, path, headers=None, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, resp.getheaders(), body


def _cookies_set(headers):
    return [v for k, v in headers if k.lower() == "set-cookie"]


def _header(headers, name):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def _session(gate, sub="00uUSER1", email="user@example.com", is_admin=False, id_token="idtok"):
    return gate._sign_payload({"typ": "session", "sub": sub, "email": email, "id_token": id_token,
                               "is_admin": is_admin}, 600)


def _flow(gate, state="STATE1", nonce="NONCE1", purpose="login"):
    return gate._sign_payload({"typ": "flow", "state": state, "nonce": nonce, "verifier": "v",
                               "purpose": purpose, "action_id": None}, 600)


# --------------------------------------------------------------------- GATE-07
def test_empty_session_key_file_refuses_to_start(tmp_path, monkeypatch):
    _stage_gate_env(tmp_path, monkeypatch)
    (tmp_path / "session.key").write_bytes(b"")
    with pytest.raises(RuntimeError, match="0 bytes"):
        _import_gate()


def test_short_session_key_file_refuses_to_start(tmp_path, monkeypatch):
    _stage_gate_env(tmp_path, monkeypatch)
    (tmp_path / "session.key").write_bytes(b"x" * 31)
    with pytest.raises(RuntimeError, match="31 bytes"):
        _import_gate()


def test_new_session_key_is_32_random_bytes_owner_only_and_leaves_no_temp_file(gate, tmp_path):
    key_path = tmp_path / "session.key"
    assert key_path.read_bytes() == gate.SESSION_KEY
    assert len(gate.SESSION_KEY) == 32
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_existing_session_key_is_used_unchanged(tmp_path, monkeypatch):
    _stage_gate_env(tmp_path, monkeypatch)
    (tmp_path / "session.key").write_bytes(b"k" * 48)
    gate = _import_gate()
    assert gate.SESSION_KEY == b"k" * 48


def test_session_key_creation_race_uses_the_winners_key(tmp_path, monkeypatch):
    """Another process creates the key between our exists() check and our
    link(): os.link raises FileExistsError, and we must use ITS key."""
    _stage_gate_env(tmp_path, monkeypatch)
    real_link = os.link

    def racing_link(src, dst):
        Path(dst).write_bytes(b"w" * 32)
        return real_link(src, dst)

    from pathlib import Path

    monkeypatch.setattr(os, "link", racing_link)
    gate = _import_gate()
    assert gate.SESSION_KEY == b"w" * 32
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


# --------------------------------------------------------------------- GATE-09
class _FakeResponse:
    """urlopen's response shape. `link` may be a list: Okta sends rel="self"
    and rel="next" as separate Link header lines, which only an
    email.message.Message (what urllib really returns) can represent."""

    def __init__(self, body, link=None):
        import email.message

        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = email.message.Message()
        for value in ([link] if isinstance(link, str) else (link or [])):
            self.headers["Link"] = value

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.parametrize("exc", [TimeoutError("read timed out"), http.client.IncompleteRead(b"x"),
                                 urllib.error.URLError("down"), ConnectionResetError()])
def test_group_lookup_fails_closed_on_any_transport_error(gate, monkeypatch, exc):
    def boom(req, timeout=None):
        raise exc

    monkeypatch.setattr(gate.urllib.request, "urlopen", boom)
    assert gate._fetch_user_group_ids("00uUSER1") is None


def test_callback_hides_the_exception_text_and_logs_it(gate_server, monkeypatch, capsys):
    gate, port = gate_server

    def stall(code, verifier):
        raise TimeoutError("internal-detail-xyz")

    monkeypatch.setattr(gate, "_exchange_code_for_tokens", stall)
    status, headers, body = _call(port, "/authorization-code/callback?code=c&state=STATE1",
                                  {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    assert status == 401
    assert b"internal-detail-xyz" not in body and b"Reference:" in body
    assert not _cookies_set(headers)
    assert "internal-detail-xyz" in capsys.readouterr().err


def test_unexpected_exception_is_a_500_with_a_reference_not_a_dropped_connection(gate_server, monkeypatch, capsys):
    gate, port = gate_server

    def explode(self, require_stepup=False):
        raise RuntimeError("kaboom-detail")

    monkeypatch.setattr(gate.Handler, "_verify_session", explode)
    status, _headers, body = _call(port, "/verify")
    assert status == 500
    assert b"kaboom-detail" not in body and b"Reference:" in body
    assert "kaboom-detail" in capsys.readouterr().err


@pytest.mark.parametrize("email", ["用户@example.com", "a@b.com\r\nX-Auth-Is-Admin: true", "", None])
def test_verify_falls_back_to_sub_for_an_unsendable_email(gate_server, email):
    gate, port = gate_server
    status, headers, _ = _call(port, "/verify", {"Cookie": f"opa_wizard_session={_session(gate, email=email)}"})
    assert status == 200
    assert _header(headers, "X-Auth-User") == "00uUSER1"
    assert _header(headers, "X-Auth-Is-Admin") == "false"


def test_verify_names_the_gates_issuer_for_the_backend(gate_server):
    """5.43.0: a sub is only unique within one Okta org; serve.py keys
    per-user permission exceptions on (issuer, sub), so /verify says which
    org's gate vouched for the session -- and the issuer matches the shape
    serve.py accepts."""
    import create_secret_folders as engine

    gate, port = gate_server
    status, headers, _ = _call(port, "/verify", {"Cookie": f"opa_wizard_session={_session(gate)}"})
    assert status == 200
    assert _header(headers, "X-Auth-Issuer") == gate.OKTA_ISSUER == "https://example.oktapreview.com/oauth2/default"
    assert engine.SHARED_GRANT_ISSUER_PATTERN.fullmatch(gate.OKTA_ISSUER)
    status, headers, _ = _call(port, "/verify")
    assert status == 401 and _header(headers, "X-Auth-Issuer") is None


@pytest.mark.parametrize("auth_server,issuer", [
    ("default", "https://login.example.com/oauth2/default"), ("org", "https://login.example.com"),
    ("aus1a2b3c4D5e6F7g8", "https://login.example.com/oauth2/aus1a2b3c4D5e6F7g8"),
])
def test_every_gate_issuer_shape_is_accepted_by_the_backend(auth_server, issuer):
    import create_secret_folders as engine
    from server.gate_config import okta_endpoints

    assert okta_endpoints("https://login.example.com", auth_server)["issuer"] == issuer
    assert engine.SHARED_GRANT_ISSUER_PATTERN.fullmatch(issuer)


def test_verify_refuses_a_session_whose_sub_is_not_header_safe(gate_server):
    gate, port = gate_server
    status, headers, _ = _call(port, "/verify", {"Cookie": f"opa_wizard_session={_session(gate, sub='00u X')}"})
    assert status == 401 and _header(headers, "X-Auth-Sub") is None


def test_malformed_cookie_header_is_a_plain_401(gate_server):
    _gate, port = gate_server
    status, _h, _b = _call(port, "/verify", {"Cookie": 'opa_wizard_session="unterminated; ,;=='})
    assert status == 401


# --------------------------------------------------------------------- GATE-10
def test_group_lookup_follows_link_next_and_finds_admin_on_page_two(gate, monkeypatch):
    org = gate.OKTA_ORG_URL
    pages = {
        f"{org}/api/v1/users/00uUSER1/groups": _FakeResponse(
            [{"id": "00gOTHER"}], link=[f'<{org}/api/v1/users/00uUSER1/groups>; rel="self"',
                                        f'<{org}/api/v1/users/00uUSER1/groups?after=1>; rel="next"']),
        f"{org}/api/v1/users/00uUSER1/groups?after=1": _FakeResponse([{"id": "00gADMIN"}]),
    }
    seen = []

    def fake(req, timeout=None):
        seen.append((req.full_url, req.get_header("Authorization")))
        return pages[req.full_url]

    monkeypatch.setattr(gate.urllib.request, "urlopen", fake)
    ids = gate._fetch_user_group_ids("00uUSER1")
    assert ids == ["00gOTHER", "00gADMIN"]
    assert gate._resolve_membership(ids, "00gADMIN", None) == (True, True)
    assert len(seen) == 2 and all(auth.startswith("SSWS ") for _u, auth in seen)


def test_group_lookup_never_follows_a_link_to_another_host(gate, monkeypatch):
    calls = []

    def fake(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResponse([{"id": "00gOTHER"}], link='<https://evil.example.com/api/v1/x>; rel="next"')

    monkeypatch.setattr(gate.urllib.request, "urlopen", fake)
    # Fails closed: the unfetched page might have held the admin group.
    assert gate._fetch_user_group_ids("00uUSER1") is None
    assert calls == [f"{gate.OKTA_ORG_URL}/api/v1/users/00uUSER1/groups"]


def test_group_lookup_fails_closed_when_a_later_page_fails(gate, monkeypatch):
    org = gate.OKTA_ORG_URL

    def fake(req, timeout=None):
        if "after=" in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 500, "x", {}, None)
        return _FakeResponse([{"id": "00gADMIN"}], link=f'<{org}/api/v1/users/00uUSER1/groups?after=1>; rel="next"')

    monkeypatch.setattr(gate.urllib.request, "urlopen", fake)
    assert gate._fetch_user_group_ids("00uUSER1") is None


@pytest.mark.parametrize("body,expected", [
    ({"errorCode": "E0000006"}, None),   # an object, not a list: fail closed
    ("not json", None),
    ([1, "x", None, {"id": 5}, {"id": "00gOK"}], ["00gOK"]),  # junk entries skipped
])
def test_group_lookup_handles_unexpected_bodies(gate, monkeypatch, body, expected):
    raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda req, timeout=None: _FakeResponse(raw))
    assert gate._fetch_user_group_ids("00uUSER1") == expected


def test_group_lookup_page_cap_fails_closed(gate, monkeypatch):
    org = gate.OKTA_ORG_URL
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda req, timeout=None: _FakeResponse(
        [{"id": "00gX"}], link=f'<{org}/api/v1/users/00uUSER1/groups?after=n>; rel="next"'))
    assert gate._fetch_user_group_ids("00uUSER1") is None


def test_group_lookup_follows_okta_style_separate_link_headers_over_real_http(gate, monkeypatch):
    """Okta answers with two Link header LINES (self, next); a real HTTP
    server + real urlopen proves the gate reads both."""
    from http.server import BaseHTTPRequestHandler

    class FakeOkta(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            page2 = "after" in self.path
            body = json.dumps([{"id": "00gADMIN" if page2 else "00gOTHER"}]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Link", f'<{base}{self.path}>; rel="self"')
            if not page2:
                self.send_header("Link", f'<{base}/api/v1/users/00uUSER1/groups?after=a,b>; rel="next"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    okta = ThreadingHTTPServer(("127.0.0.1", 0), FakeOkta)
    threading.Thread(target=okta.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        monkeypatch.setattr(gate, "OKTA_ORG_URL", f"http://127.0.0.1:{okta.server_address[1]}")
        ids = gate._fetch_user_group_ids("00uUSER1")
    finally:
        okta.shutdown()
        okta.server_close()
    assert ids == ["00gOTHER", "00gADMIN"]


def test_group_lookup_stays_inside_its_time_budget(gate, monkeypatch):
    org = gate.OKTA_ORG_URL
    clock = [1000.0]
    timeouts = []
    monkeypatch.setattr(gate.time, "monotonic", lambda: clock[0])

    def slow(req, timeout=None):
        timeouts.append(timeout)
        clock[0] += 9
        return _FakeResponse([{"id": "00gX"}], link=f'<{org}/api/v1/users/00uUSER1/groups?after=n>; rel="next"')

    monkeypatch.setattr(gate.urllib.request, "urlopen", slow)
    assert gate._fetch_user_group_ids("00uUSER1") is None
    # 25 s budget: two full 10 s calls (9 s each), then only the 7 s left, then out of time.
    assert timeouts == [10, 10, 7.0]


@pytest.mark.parametrize("header,expected", [
    ('<https://example.oktapreview.com/api/v1/a?after=2>; rel="next"', "https://example.oktapreview.com/api/v1/a?after=2"),
    ('<https://example.oktapreview.com/api/v1/a>; rel="self", <https://example.oktapreview.com/api/v1/a?after=3>; rel="next"',
     "https://example.oktapreview.com/api/v1/a?after=3"),
    ('<https://example.oktapreview.com/api/v1/a>; rel="self"', None),
    ("", None),
    ('<https://example.oktapreview.com/api/v1/a?after=x,y>; rel="next"', "https://example.oktapreview.com/api/v1/a?after=x,y"),
    ('<https://example.oktapreview.com/api/v1/a?after=4>; type="x"; rel=next', "https://example.oktapreview.com/api/v1/a?after=4"),
    ('<https://example.oktapreview.com/api/v1/a?after=5>; rel="prev next"', "https://example.oktapreview.com/api/v1/a?after=5"),
    ('<https://example.oktapreview.com/api/v1/a?after=6>; rel="nextpage"', None),
    ('<https://example.oktapreview.com/api/v1/a?after=7>; title="x,y"; rel="next"', "https://example.oktapreview.com/api/v1/a?after=7"),
    ('<https://example.oktapreview.com/api/v1/a?after=8>; REL="Next"', "https://example.oktapreview.com/api/v1/a?after=8"),
    ('<https://example.oktapreview.com/api/v1/a?after=9>; title="x;rel=next"', None),
])
def test_next_link_parsing(gate, header, expected):
    assert gate._next_link(header) == expected


@pytest.mark.parametrize("header", [
    '<https://example.oktapreview.com.evil.com/api/v1/a>; rel="next"',
    '<https://example.oktapreview.com@evil.com/api/v1/a>; rel="next"',
    '<https://example.oktapreview.com/oauth2/v1/a>; rel="next"',
    '<https://example.oktapreview.com/api/v1/a\\b>; rel="next"',
])
def test_next_link_outside_the_org_api_is_flagged_foreign(gate, header):
    assert gate._next_link(header) is gate._FOREIGN_LINK


# --------------------------------------------------------------------- GATE-12
def test_logout_clears_all_three_gate_cookies(gate_server):
    gate, port = gate_server
    status, headers, _ = _call(port, "/logout", {"Cookie": f"opa_wizard_session={_session(gate)}",
                                                  "Sec-Fetch-Site": "same-origin"})
    assert status == 302
    assert _header(headers, "Location").startswith(gate.OKTA_LOGOUT_URL + "?")
    cleared = {c.split("=", 1)[0] for c in _cookies_set(headers) if "Max-Age=0" in c}
    assert cleared == {"opa_wizard_session", "opa_wizard_stepup", "opa_wizard_flow"}


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_site_logout_asks_first_and_changes_nothing(gate_server, site):
    gate, port = gate_server
    status, headers, body = _call(port, "/logout", {"Cookie": f"opa_wizard_session={_session(gate)}",
                                                     "Sec-Fetch-Site": site})
    assert status == 200 and b'<form method=post action=/logout>' in body
    assert not _cookies_set(headers) and _header(headers, "Location") is None


@pytest.mark.parametrize("site", ["none", None])
def test_typed_or_legacy_logout_still_logs_out(gate_server, site):
    gate, port = gate_server
    hdrs = {"Cookie": f"opa_wizard_session={_session(gate)}"}
    if site:
        hdrs["Sec-Fetch-Site"] = site
    status, headers, _ = _call(port, "/logout", hdrs)
    assert status == 302 and len(_cookies_set(headers)) == 3


@pytest.mark.parametrize("origin", [None, "https://evil.example.com", "null"])
def test_logout_post_needs_the_dashboard_origin(gate_server, origin):
    gate, port = gate_server
    hdrs = {"Cookie": f"opa_wizard_session={_session(gate)}", "Content-Length": "0"}
    if origin:
        hdrs["Origin"] = origin
    status, headers, _ = _call(port, "/logout", hdrs, method="POST")
    assert status == 403 and not _cookies_set(headers)


def test_logout_post_from_the_dashboard_logs_out(gate_server):
    gate, port = gate_server
    status, headers, _ = _call(port, "/logout", {"Cookie": f"opa_wizard_session={_session(gate)}",
                                                  "Origin": ORIGIN, "Content-Length": "0"}, method="POST")
    assert status == 303 and len(_cookies_set(headers)) == 3
    assert _header(headers, "Location").startswith(gate.OKTA_LOGOUT_URL)


def test_post_to_any_other_path_is_404(gate_server):
    _gate, port = gate_server
    assert _call(port, "/verify", {"Content-Length": "0"}, method="POST")[0] == 404


# --------------------------------------------------------------------- GATE-13
def _rsa_and_stub_jwks(gate, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class _Key:
        def __init__(self, k):
            self.key = k

    class _Jwks:
        def get_signing_key_from_jwt(self, token):
            return _Key(key.public_key())

    monkeypatch.setattr(gate, "_JWKS_CLIENT", _Jwks())
    return key


def _id_token(gate, key, **overrides):
    import jwt as pyjwt

    now = int(time.time())
    claims = {"iss": gate.OKTA_ISSUER, "aud": gate.OKTA_CLIENT_ID, "sub": "00uUSER1", "iat": now,
              "exp": now + 300, "nonce": "NONCE1", "auth_time": now, "email": "user@example.com"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return pyjwt.encode(claims, key, algorithm="RS256")


def test_login_sends_a_nonce_and_binds_it_into_the_flow_cookie(gate_server):
    gate, port = gate_server
    status, headers, _ = _call(port, "/login")
    assert status == 302
    params = urllib.parse.parse_qs(urllib.parse.urlparse(_header(headers, "Location")).query)
    import http.cookies

    jar = http.cookies.SimpleCookie()
    jar.load(_cookies_set(headers)[0])
    flow = gate._verify_signed_payload(jar["opa_wizard_flow"].value, "flow")
    assert params["nonce"] == [flow["nonce"]] and len(flow["nonce"]) >= 20


def test_id_token_with_matching_nonce_verifies(gate, monkeypatch):
    key = _rsa_and_stub_jwks(gate, monkeypatch)
    assert gate._verify_id_token(_id_token(gate, key), "NONCE1")["sub"] == "00uUSER1"


@pytest.mark.parametrize("overrides,expected_nonce", [
    ({"nonce": "OTHER"}, "NONCE1"),
    ({"nonce": None}, "NONCE1"),
    ({}, None),                   # a flow cookie without a nonce never verifies
    ({"iat": None}, "NONCE1"),
    ({"exp": None}, "NONCE1"),
    ({"sub": None}, "NONCE1"),
    ({"sub": "00u\r\nX"}, "NONCE1"),
    ({"aud": "someone-else"}, "NONCE1"),
])
def test_id_token_rejections(gate, monkeypatch, overrides, expected_nonce):
    import jwt as pyjwt

    key = _rsa_and_stub_jwks(gate, monkeypatch)
    with pytest.raises(pyjwt.PyJWTError):
        gate._verify_id_token(_id_token(gate, key, **overrides), expected_nonce)


def test_callback_with_a_wrong_nonce_issues_no_session(gate_server, monkeypatch):
    gate, port = gate_server
    key = _rsa_and_stub_jwks(gate, monkeypatch)
    monkeypatch.setattr(gate, "_exchange_code_for_tokens",
                        lambda code, verifier: {"id_token": _id_token(gate, key, nonce="REPLAYED")})
    status, headers, _ = _call(port, "/authorization-code/callback?code=c&state=STATE1",
                               {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    assert status == 401 and not _cookies_set(headers)


def test_callback_success_issues_a_session(gate_server, monkeypatch, capsys):
    gate, port = gate_server
    key = _rsa_and_stub_jwks(gate, monkeypatch)
    gate.ACCESS_CONTROL_FILE_PATH.write_text(json.dumps(
        {"admin_group_id": "00gADMIN", "user_group_id": None, "restrict_login": True}))
    monkeypatch.setattr(gate, "_exchange_code_for_tokens", lambda c, v: {"id_token": _id_token(gate, key)})
    monkeypatch.setattr(gate, "_fetch_user_group_ids", lambda sub: ["00gADMIN"])
    status, headers, _ = _call(port, "/authorization-code/callback?code=c&state=STATE1",
                               {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    assert status == 302
    import http.cookies

    jar = http.cookies.SimpleCookie()
    for c in _cookies_set(headers):
        jar.load(c)
    session = gate._verify_signed_payload(jar["opa_wizard_session"].value, "session")
    assert session["sub"] == "00uUSER1" and session["is_admin"] is True
    assert '"login for 00uUSER1 (admin=True)"' in capsys.readouterr().out


def test_callback_state_mismatch_is_400(gate_server):
    gate, port = gate_server
    status, headers, _ = _call(port, "/authorization-code/callback?code=c&state=WRONG",
                               {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    assert status == 400 and not _cookies_set(headers)


# --------------------------------------------------------------------- GATE-14
def test_explicit_access_control_path_missing_fails_closed(gate):
    assert gate.ACCESS_CONTROL_PATH_EXPLICIT is True  # the fixture sets OPA_ACCESS_CONTROL_PATH
    with pytest.raises(gate.AccessControlUnavailable):
        gate._read_access_control_config()


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '"restrict_login"'])
def test_explicit_access_control_path_never_parsed_fails_closed(gate, content):
    gate.ACCESS_CONTROL_FILE_PATH.write_text(content)
    with pytest.raises(gate.AccessControlUnavailable):
        gate._read_access_control_config()


def test_explicit_path_keeps_last_good_after_a_later_corruption(gate):
    good = {"admin_group_id": "00gA", "user_group_id": "00gU", "restrict_login": True}
    gate.ACCESS_CONTROL_FILE_PATH.write_text(json.dumps(good))
    assert gate._read_access_control_config() == good
    gate.ACCESS_CONTROL_FILE_PATH.write_text("[]")
    assert gate._read_access_control_config() == good


def test_callback_refuses_login_when_explicit_access_control_is_missing(gate_server, monkeypatch, capsys):
    gate, port = gate_server
    key = _rsa_and_stub_jwks(gate, monkeypatch)
    monkeypatch.setattr(gate, "_exchange_code_for_tokens", lambda c, v: {"id_token": _id_token(gate, key)})
    monkeypatch.setattr(gate, "_fetch_user_group_ids", lambda sub: ["00gANY"])
    status, headers, body = _call(port, "/authorization-code/callback?code=c&state=STATE1",
                                  {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    assert status == 503 and not _cookies_set(headers)
    assert b"Reference:" in body
    assert "access control unavailable" in capsys.readouterr().err


def test_main_gate_without_an_access_control_file_still_signs_in(tmp_path, monkeypatch):
    """The main gate (OPA_ACCESS_CONTROL_PATH unset, file missing): first-boot
    bootstrap default, login succeeds -- the 503 is only for an explicitly
    configured path."""
    _stage_gate_env(tmp_path, monkeypatch)
    monkeypatch.delenv("OPA_ACCESS_CONTROL_PATH")
    gate = _import_gate()
    monkeypatch.setattr(gate, "ACCESS_CONTROL_FILE_PATH", tmp_path / "absent.json")
    key = _rsa_and_stub_jwks(gate, monkeypatch)
    monkeypatch.setattr(gate, "_exchange_code_for_tokens", lambda c, v: {"id_token": _id_token(gate, key)})
    monkeypatch.setattr(gate, "_fetch_user_group_ids", lambda sub: ["00gBOOTSTRAPADMIN"])
    server = ThreadingHTTPServer(("127.0.0.1", 0), gate.Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        status, headers, _ = _call(server.server_address[1], "/authorization-code/callback?code=c&state=STATE1",
                                   {"Cookie": f"opa_wizard_flow={_flow(gate)}"})
    finally:
        server.shutdown()
        server.server_close()
    assert status == 302 and any(c.startswith("opa_wizard_session=") for c in _cookies_set(headers))


def test_unset_access_control_path_is_not_explicit(tmp_path, monkeypatch):
    _stage_gate_env(tmp_path, monkeypatch)
    monkeypatch.delenv("OPA_ACCESS_CONTROL_PATH")
    assert _import_gate().ACCESS_CONTROL_PATH_EXPLICIT is False


# -------------------------------------------- mfa_log_lookup (batch 3 carry-over)
@pytest.fixture
def mfa_gate(tmp_path, monkeypatch):
    _stage_gate_env(tmp_path, monkeypatch)
    monkeypatch.setenv("INTERNAL_API_SHARED_SECRET", "internal-secret")
    gate = _import_gate()
    server = ThreadingHTTPServer(("127.0.0.1", 0), gate.Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield gate, server.server_address[1]
    server.shutdown()
    server.server_close()


NEAR = "2026-10-08T11:00:00+00:00"


def _lookup(port, sub="00uADMIN1", secret="internal-secret"):
    q = urllib.parse.urlencode({"sub": sub, "near": NEAR})
    return _call(port, f"/internal/mfa_log_lookup?{q}", {"X-Internal-Secret": secret} if secret else {})


def test_mfa_lookup_is_404_when_not_configured(gate_server):
    _gate, port = gate_server
    assert _lookup(port)[0] == 404


@pytest.mark.parametrize("secret", [None, "wrong", "internal-secre", "internal-secret-x"])
def test_mfa_lookup_wrong_secret_is_403(mfa_gate, secret):
    _gate, port = mfa_gate
    assert _lookup(port, secret=secret)[0] == 403


@pytest.mark.parametrize("sub", ['00u" or actor.id pr "', "00u X", "", "x" * 65])
def test_mfa_lookup_rejects_a_sub_that_is_not_an_okta_id(mfa_gate, monkeypatch, sub):
    gate, port = mfa_gate
    monkeypatch.setattr(gate, "_query_mfa_log_event", lambda *a: pytest.fail("must not query Okta"))
    assert _lookup(port, sub=sub)[0] == 400


@pytest.mark.parametrize("failure", [urllib.error.URLError("down"), TimeoutError(), ValueError("bad json")])
def test_query_mfa_log_event_raises_when_okta_cannot_answer(gate, monkeypatch, failure):
    def boom(req, timeout=None):
        raise failure

    monkeypatch.setattr(gate.urllib.request, "urlopen", boom)
    with pytest.raises(gate.MfaLookupFailed):
        gate._query_mfa_log_event("00uADMIN1", datetime(2026, 10, 8, tzinfo=timezone.utc))


@pytest.mark.parametrize("body", [{"errorCode": "E0000011"}, ["not-an-object"]])
def test_query_mfa_log_event_raises_on_an_unusable_answer(gate, monkeypatch, body):
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda req, timeout=None: _FakeResponse(body))
    with pytest.raises(gate.MfaLookupFailed):
        gate._query_mfa_log_event("00uADMIN1", datetime(2026, 10, 8, tzinfo=timezone.utc))


def test_query_mfa_log_event_none_only_for_a_real_miss(gate, monkeypatch):
    seen = []

    def fake(req, timeout=None):
        seen.append(req.full_url)
        return _FakeResponse([])

    monkeypatch.setattr(gate.urllib.request, "urlopen", fake)
    since = datetime(2026, 10, 8, 4, 0, tzinfo=timezone(timedelta(hours=-7)))
    assert gate._query_mfa_log_event("00uADMIN1", since.astimezone(timezone.utc)) is None
    assert "since=2026-10-08T11%3A00%3A00.000Z" in seen[0]


def test_mfa_lookup_returns_502_when_okta_fails(mfa_gate, monkeypatch):
    gate, port = mfa_gate

    def fail(sub, since):
        raise gate.MfaLookupFailed("URLError")

    monkeypatch.setattr(gate, "_query_mfa_log_event", fail)
    assert _lookup(port)[0] == 502


def test_mfa_lookup_offset_near_is_converted_to_utc(mfa_gate, monkeypatch):
    gate, port = mfa_gate
    got = []
    monkeypatch.setattr(gate, "_query_mfa_log_event", lambda sub, since: got.append(since) or None)
    q = urllib.parse.urlencode({"sub": "00uADMIN1", "near": "2026-10-08T04:00:00-07:00"})
    status, _h, body = _call(port, f"/internal/mfa_log_lookup?{q}", {"X-Internal-Secret": "internal-secret"})
    assert status == 200 and body == b"null"
    assert got[0] == datetime(2026, 10, 8, 10, 58, tzinfo=timezone.utc)
    # UTC fields, since _query_mfa_log_event formats them with a literal "Z".
    assert got[0].utcoffset() == timedelta(0) and got[0].hour == 10


# End to end through serve.py's client and the engine's backfill: a failed
# Okta call must stop the run WITHOUT charging the entry an attempt, while a
# real miss is charged (it is older than the grace period).
@pytest.fixture
def serve_against_gate(mfa_gate, monkeypatch):
    import server.serve as serve

    gate, port = mfa_gate
    monkeypatch.setattr(serve, "AUTH_GATE_INTERNAL_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setattr(serve, "INTERNAL_API_SHARED_SECRET", "internal-secret")
    return gate, serve


def _seed_entry(path):
    entry = {"timestamp": NEAR, "actor_email": "a@example.com", "actor_sub": "00uADMIN1",
             "action": "access_control.update", "details": {"okta_mfa_log_event": None},
             "client_ip": None, "user_agent": None}
    path.write_text(json.dumps(entry) + "\n")


def _attempts(path):
    return json.loads(path.read_text().splitlines()[0])["details"].get("okta_mfa_log_lookup_attempts")


def test_e2e_okta_failure_is_unavailable_and_charges_no_attempt(serve_against_gate, monkeypatch, tmp_audit_log):
    import create_secret_folders as engine

    gate, serve = serve_against_gate

    def fail(sub, since):
        raise gate.MfaLookupFailed("URLError")

    monkeypatch.setattr(gate, "_query_mfa_log_event", fail)
    with pytest.raises(engine.MfaLookupUnavailable):
        serve._lookup_mfa_log_event("00uADMIN1", NEAR)
    _seed_entry(tmp_audit_log)
    now = datetime(2026, 10, 8, 14, 0, tzinfo=timezone.utc)
    assert engine.backfill_mfa_log_events(serve._lookup_mfa_log_event, now=now) == 0
    assert _attempts(tmp_audit_log) is None


def test_e2e_real_miss_is_none_and_is_charged(serve_against_gate, monkeypatch, tmp_audit_log):
    import create_secret_folders as engine

    gate, serve = serve_against_gate
    monkeypatch.setattr(gate, "_query_mfa_log_event", lambda sub, since: None)
    assert serve._lookup_mfa_log_event("00uADMIN1", NEAR) is None
    _seed_entry(tmp_audit_log)
    now = datetime(2026, 10, 8, 14, 0, tzinfo=timezone.utc)
    assert engine.backfill_mfa_log_events(serve._lookup_mfa_log_event, now=now) == 0
    assert _attempts(tmp_audit_log) == 1


def test_e2e_hit_fills_in_the_event(serve_against_gate, monkeypatch, tmp_audit_log):
    import create_secret_folders as engine

    gate, serve = serve_against_gate
    event = {"published": NEAR, "eventType": "user.authentication.auth_via_mfa", "outcome_result": "SUCCESS",
             "display_message": "Authentication of user via MFA"}
    monkeypatch.setattr(gate, "_query_mfa_log_event", lambda sub, since: event)
    _seed_entry(tmp_audit_log)
    now = datetime(2026, 10, 8, 14, 0, tzinfo=timezone.utc)
    assert engine.backfill_mfa_log_events(serve._lookup_mfa_log_event, now=now) == 1
    assert json.loads(tmp_audit_log.read_text().splitlines()[0])["details"]["okta_mfa_log_event"] == event


def test_e2e_bad_sub_is_rejected_for_that_entry_only(serve_against_gate):
    import create_secret_folders as engine

    _gate, serve = serve_against_gate
    with pytest.raises(engine.MfaLookupEntryRejected):
        serve._lookup_mfa_log_event('00u"bad', NEAR)


def test_internal_secret_is_compared_in_constant_time(mfa_gate, monkeypatch):
    gate, port = mfa_gate
    calls = []
    real = gate.hmac.compare_digest
    monkeypatch.setattr(gate.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    monkeypatch.setattr(gate, "_query_mfa_log_event", lambda sub, since: None)
    assert _lookup(port)[0] == 200
    assert (b"internal-secret", b"internal-secret") in calls


def test_gate_handler_has_a_socket_timeout(gate):
    assert gate.Handler.timeout == 30


def test_verify_stepup_refuses_a_malformed_action_id_in_a_valid_cookie(gate_server):
    """Belt and braces for GATE-03: even a correctly signed step-up cookie
    never puts a non-id-shaped action_id into a response header."""
    gate, port = gate_server
    stepup = gate._sign_payload({"typ": "stepup", "sub": "00uUSER1", "action_id": "x\r\nX-Evil: 1"}, 60)
    cookie = f"opa_wizard_session={_session(gate)}; opa_wizard_stepup={stepup}"
    status, headers, _ = _call(port, "/verify?require_stepup=1", {"Cookie": cookie})
    assert status == 401 and _header(headers, "X-Auth-Action-Id") is None
    import secrets

    good = secrets.token_urlsafe(32)
    stepup = gate._sign_payload({"typ": "stepup", "sub": "00uUSER1", "action_id": good}, 60)
    status, headers, _ = _call(port, "/verify?require_stepup=1",
                               {"Cookie": f"opa_wizard_session={_session(gate)}; opa_wizard_stepup={stepup}"})
    assert status == 200 and _header(headers, "X-Auth-Action-Id") == good


def test_refused_next_link_logs_only_the_host(gate, capsys):
    assert gate._next_link('<https://other.okta.example/api/v1/a?after=SECRETCURSOR>; rel="next"') is gate._FOREIGN_LINK
    err = capsys.readouterr().err
    assert "other.okta.example" in err and "SECRETCURSOR" not in err


def test_jwks_client_timeout_fits_inside_nginx_proxy_timeout(gate):
    assert gate._JWKS_CLIENT.timeout <= 10
    assert 10 + gate._JWKS_CLIENT.timeout + gate.GROUP_LOOKUP_BUDGET_SECONDS < 60
