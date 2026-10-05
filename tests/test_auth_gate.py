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


@pytest.fixture
def gate(tmp_path, monkeypatch):
    """Imports server.auth_gate with a stubbed keyring, required env vars,
    and a disposable session-key file -- fresh every test via a forced
    reimport, so no test can see another test's SESSION_KEY or
    _LAST_GOOD_ACCESS_CONTROL_CONFIG state."""
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

    sys.modules.pop("server.auth_gate", None)
    sys.modules.pop("auth_gate", None)
    import server.auth_gate as auth_gate

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
def test_missing_access_control_file_returns_bootstrap_default(gate):
    config = gate._read_access_control_config()
    assert config == {"admin_group_id": "00gBOOTSTRAPADMIN", "user_group_id": None, "restrict_login": False}


def test_malformed_file_with_no_prior_good_read_falls_back_to_bootstrap_default(gate):
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
