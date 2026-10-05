"""
Okta OIDC login gate in front of the OPA Compliance Wizard.

Why this exists: the app itself has no auth of its own (deliberately -- see
serve.py's own docstring, it's meant to be a local-only tool), and the
original plan to gate network access with plain HTTP Basic Auth
(nginx auth_basic) hit a real wall -- a managed Edge/Chromium policy on the
accessing machine restricts AuthSchemes to ntlm/negotiate, so Basic Auth
challenges are silently swallowed (server sends a correct 401 +
WWW-Authenticate: Basic, browser never shows the login popup). Okta OIDC
sidesteps that entirely (it's a normal browser redirect + form on Okta's own
hosted page, not an HTTP-auth challenge), and fits this project's existing
identity story -- it already manages real Okta credentials and pulls Okta
System Log data elsewhere (see create_secret_folders.py's OktaClient).

Runs standalone on 127.0.0.1:8767, fronted by nginx's auth_request module
(see server/nginx-opa-secrets-wizard.conf):
  - GET  /login                          -> starts Authorization Code + PKCE,
                                             redirects to Okta's hosted login
  - GET  /step-up                        -> same as /login, but adds
                                             max_age=0 + acr_values (Identity
                                             Engine step-up params -- see
                                             _start_step_up) to force a fresh
                                             MFA challenge regardless of the
                                             existing Okta session. Used
                                             before saving changes to the
                                             Access Control group IDs (see
                                             "Admin access" in the main
                                             README) -- NOT for ordinary login.
  - GET  /authorization-code/callback    -> Okta redirects back here with
                                             ?code=...&state=...; exchanges
                                             the code for tokens, verifies the
                                             ID token, then either completes
                                             an ordinary login (sets the
                                             session cookie) or, if this was
                                             a /step-up flow, sets a
                                             short-lived step-up cookie
                                             instead (see _handle_callback's
                                             purpose branch)
  - GET  /verify                         -> nginx auth_request target; 200 if
                                             the session cookie is valid, 401
                                             otherwise. With
                                             ?require_stepup=1, ALSO requires
                                             a valid, unexpired step-up
                                             cookie matching the session's
                                             sub -- used to gate the one
                                             endpoint that saves Access
                                             Control changes.
  - GET  /logout                         -> clears the local session cookie
                                             AND redirects through Okta's own
                                             logout endpoint (otherwise the
                                             gate forgets you but Okta's own
                                             SSO session silently logs you
                                             back in on the next /login)
  - GET  /internal/mfa_log_lookup        -> LOOPBACK-ONLY (not proxied by
                                             nginx at all), gated by
                                             INTERNAL_API_SHARED_SECRET (see
                                             that constant). Lets serve.py
                                             backfill Okta MFA log
                                             corroboration for an existing
                                             audit_log.jsonl entry when an
                                             admin clicks Refresh on the
                                             Audit Log page -- see
                                             _mfa_log_lookup.

Session cookie is a signed ("<expiry>.<hmac>") token, same scheme as this
project's other short-lived signed tokens conceptually -- HMAC-SHA256 over a
server-only secret in /etc/opa-secrets-wizard-session.key (root:rparikh,
0640, generated once on first run). The PKCE code_verifier + OAuth `state`
for an in-flight login are held in a short-lived signed cookie too (nothing
server-side to garbage-collect), since this gate is a single Python process
and doesn't need a shared session store. The step-up cookie (opa_wizard_
stepup, STEPUP_TTL_SECONDS) uses the exact same signing scheme.

Required environment variables (set via the systemd unit's EnvironmentFile,
/etc/opa-compliance-wizard.env -- same file that already holds
KEYRING_UNLOCK_PASSWORD; this process exits immediately at import time if
any are missing, rather than silently pointing at a wrong/no org):
  OKTA_ORG_URL       e.g. https://your-org.oktapreview.com
  OKTA_OIDC_CLIENT_ID  the OIDC web app's client_id (not secret, but still
                       deployment-specific -- see "Register an OIDC
                       application" in docs/hosting.md)
  DASHBOARD_ORIGIN   the public origin this dashboard is reachable at,
                     e.g. https://192.168.1.10 or https://opa.example.com
  OKTA_ADMIN_GROUP_ID  bootstrap-only default for the admin group ID --
                       used verbatim (with no user group, restrict_login
                       off) until an admin saves real settings via the
                       dashboard's Access Control panel (POST
                       /api/access_control/save, server/serve.py), at which
                       point access_control.json (see
                       create_secret_folders.py's get/set_access_control_
                       config) becomes the sole source of truth and this
                       env var is no longer consulted. Exists so a fresh
                       deployment always has a working admin group from
                       first boot, without requiring the dashboard to be
                       used once (chicken-and-egg) before anyone can get
                       admin rights to configure it via the UI. See "Admin
                       access" in docs/hosting.md for how to create an
                       Okta group and find its ID -- a group ID (not name)
                       is required so membership checks are one direct API
                       call, never a name-to-id lookup.
  OKTA_ENV_NAME      (optional, defaults to "default") -- keyring service
                     suffix; client_secret AND the admin-group-check API
                     token (see below) are both resolved via the OS
                     keyring at startup using this project's existing
                     per-environment secret-storage convention (see
                     create_secret_folders.py -- service name
                     f"opa-compliance-wizard:{OKTA_ENV_NAME}"), not a
                     separate mechanism. An install that predates the
                     5.20.0 rename still resolves via a read-only
                     fallback to the old "opa-secrets-wizard:{...}"
                     service name -- see _load_keyring_secret below.

Also requires an Okta API token stored in the keyring under
f"opa-compliance-wizard:{OKTA_ENV_NAME}" / "okta_admin_check_token" -- a
read-only, org-wide token (Users + Groups read scope is enough) used
solely to check "/api/v1/users/{sub}/groups" at login time. This is
deliberately separate from any per-environment `okta_api_token` this
project's other credentials use (create_secret_folders.py) -- this check
must work for every logged-in user regardless of which environment(s)
they've configured, so it can't depend on any one environment's own
token existing at all.

Login gate (restrict_login in access_control.json, off by default): once an
admin sets a User Group ID and/or Admin Group ID and turns this on, anyone
in NEITHER group is denied at the callback step (403, no session issued) --
before that, any successfully-authenticated Okta user gets a session
(non-admin unless in the admin group), same as always. Off by default so a
fresh install, or one where nobody has configured a user group yet, never
locks out real users the moment this ships. A group membership change
(admin OR user group, and turning restrict_login on/off) takes effect on
next login/session refresh, not instantly -- same accepted tradeoff as the
existing admin-group check always had.

Step-up MFA note (Okta IDENTITY ENGINE, not Classic -- the two engines use
different /authorize parameters): _start_step_up sends max_age=0 (Classic
uses 1) + acr_values=urn:okta:loa:2fa:any. This still depends on the OIDC
app's own Authentication Policy (Identity Engine's App Sign-On Policy model)
actually permitting/requiring a second factor for this app -- if it doesn't,
Okta may silently satisfy the step-up from the existing session without ever
prompting for MFA. Verify this in the Okta admin console; it cannot be set
from this repo. See developer.okta.com/docs/guides/step-up-authentication.

Okta System Log corroboration for step-up (Phase 4, 2026-10-01): since
pending_admin_actions (see serve.py's /api/access_control/prepare and
/save) is now the authoritative, SQL-provable record of exactly which
admin approved exactly which payload via a validated step-up
transaction, Okta's own System Log event is only ever OPTIONAL
corroborating evidence for the audit trail, never something that gates
authorization. There is no synchronous lookup in the step-up callback
itself anymore (that used to add up to ~6s of redirect latency for
evidence that was never load-bearing). An admin can still fill in
Okta's own corroboration asynchronously via the Audit Log page's
Refresh button (POST /api/audit_log/backfill_mfa ->
engine.backfill_mfa_log_events -> this process's /internal/mfa_log_lookup
-> _query_mfa_log_event below) -- a miss there (Okta indexing lag,
transient API error) is NOT an error; see _mfa_log_lookup's docstring.
"""

import argparse
import base64
import contextvars
import hashlib
import hmac
import http.cookies
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from jwt import PyJWKClient

try:  # run as a script (systemd: python server/auth_gate.py)
    from gate_config import okta_endpoints, session_key_path
except ImportError:  # imported as server.auth_gate
    from server.gate_config import okta_endpoints, session_key_path

# Phase 8 of docs/fast-follow-redesign.md: same JSON-line structured-
# logging shape as create_secret_folders.py's own log()/CORRELATION_ID
# (see that module's docstring for the full ThreadingHTTPServer/
# background-thread reasoning), deliberately NOT imported from there --
# this is a wholly separate process with no existing import relationship
# to the engine module, and introducing one just for logging would be a
# bigger structural change than this phase needs.
CORRELATION_ID = contextvars.ContextVar("correlation_id", default=None)


def log(level, message):
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "level": level,
        "msg": message,
    }
    correlation_id = CORRELATION_ID.get()
    if correlation_id:
        record["correlation_id"] = correlation_id
    stream = sys.stderr if level in ("WARN", "ERROR") else sys.stdout
    print(json.dumps(record), file=stream)


# Every value below is deployment-specific -- which Okta org, which OIDC
# app, which public origin this dashboard is reachable at -- so none of it
# is hardcoded here; it's a real requirement, not a secret, and belongs in
# each deployment's own config (this project's systemd unit sets it via
# EnvironmentFile=/etc/opa-compliance-wizard.env, same file that already
# holds KEYRING_UNLOCK_PASSWORD). No default is provided for any of these three --
# an operator MUST choose a real org/client/origin before this can run;
# guessing a value here would silently point at nothing (or worse, a wrong
# real org) rather than failing loudly and obviously at startup.
def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required (see server/auth_gate.py's docstring).")
    return value


OKTA_ORG_URL = _require_env("OKTA_ORG_URL")  # e.g. https://your-org.oktapreview.com
# "default" (unset) = {org}/oauth2/default as always; "org" = the org authorization server (issuer = the org
# URL, e.g. a custom domain). See server/gate_config.py.
OKTA_AUTH_SERVER = os.environ.get("OKTA_AUTH_SERVER", "default")
_ENDPOINTS = okta_endpoints(OKTA_ORG_URL, OKTA_AUTH_SERVER)
OKTA_ISSUER = _ENDPOINTS["issuer"]
OKTA_AUTHORIZE_URL = _ENDPOINTS["authorize"]
OKTA_TOKEN_URL = _ENDPOINTS["token"]
OKTA_JWKS_URL = _ENDPOINTS["jwks"]
OKTA_LOGOUT_URL = _ENDPOINTS["logout"]
OKTA_CLIENT_ID = _require_env("OKTA_OIDC_CLIENT_ID")  # not secret, but still deployment-specific
OKTA_ADMIN_GROUP_ID = _require_env("OKTA_ADMIN_GROUP_ID")  # Okta group ID -- members get admin rights
OKTA_ENV_NAME = os.environ.get("OKTA_ENV_NAME", "default")  # keyring service suffix -- see create_secret_folders.py convention
# Optional -- gates /internal/mfa_log_lookup (see _mfa_log_lookup), the
# loopback-only endpoint serve.py calls to backfill Okta MFA corroboration
# on Audit Log refresh. Both processes read the SAME EnvironmentFile
# (/etc/opa-compliance-wizard.env), so this is a genuinely shared secret,
# not something serve.py has to be separately told. Left unset by default
# -- the endpoint responds 404 (not 401/403, so its very existence isn't
# revealed) until an operator opts in, since this is a real Okta System
# Log query surface and shouldn't be reachable by anything on this
# machine without an explicit, deliberate setup step.
INTERNAL_API_SHARED_SECRET = os.environ.get("INTERNAL_API_SHARED_SECRET")

DASHBOARD_ORIGIN = _require_env("DASHBOARD_ORIGIN")  # e.g. https://192.168.1.10 or https://opa-wizard.example.com
REDIRECT_URI = f"{DASHBOARD_ORIGIN}/authorization-code/callback"
POST_LOGOUT_REDIRECT_URI = f"{DASHBOARD_ORIGIN}/login"

# One key per gate instance (OPA_SESSION_KEY_PATH): a second gate for another Okta org must not accept this
# gate's session cookies. Unset = the long-standing path.
SESSION_KEY_PATH = session_key_path(os.environ)
SESSION_COOKIE = "opa_wizard_session"
FLOW_COOKIE = "opa_wizard_flow"
STEPUP_COOKIE = "opa_wizard_stepup"
SESSION_TTL_SECONDS = 12 * 60 * 60  # 12h -- re-login once a workday
FLOW_TTL_SECONDS = 10 * 60  # 10 min is generous for "redirect to Okta and log in"
STEPUP_TTL_SECONDS = 120  # short-lived on purpose -- proof of a JUST-completed MFA challenge, not a second session
# Generous window for _query_mfa_log_event's actor+timing correlation,
# used by the async Audit-Log-page backfill path (_mfa_log_lookup) --
# covers real-world System Log ingest lag plus clock skew between this
# process and Okta, not just the OIDC round trip itself, which is
# normally only a few seconds.
#
# Phase 4 (2026-10-01): the SYNCHRONOUS version of this lookup that used
# to run inside the step-up callback itself (_find_stepup_mfa_log_event,
# with its own retry loop -- up to 4 attempts x 2s = ~6s of added
# redirect latency) is removed -- pending_admin_actions is now the
# authoritative record of a step-up approval, so blocking the redirect
# on Okta's own System Log catching up bought nothing but optional
# corroborating evidence. STEPUP_LOG_RETRY_ATTEMPTS/
# STEPUP_LOG_RETRY_DELAY_SECONDS (that retry loop's own constants) were
# removed along with it -- the async backfill path below has no retry
# loop of its own (by the time an admin clicks Refresh, the triggering
# event is already seconds-to-minutes old, so a single query is enough).
STEPUP_LOG_LOOKBACK_SECONDS = 120

# access_control.json lives at the repo root, same place as
# environments.json/banner_config.json -- read directly here (own plain
# open+json.load, no import of create_secret_folders, see module docstring)
# rather than via the dashboard app, since this is a separate process with
# its own minimal dependency footprint. This file is the sole writer, via
# POST /api/access_control/save (server/serve.py) calling
# create_secret_folders.set_access_control_config -- auth_gate.py never
# writes it, avoiding any dual-writer race between the two processes.
ACCESS_CONTROL_FILE_PATH = Path(__file__).resolve().parent.parent / "access_control.json"


_LAST_GOOD_ACCESS_CONTROL_CONFIG = None  # see _read_access_control_config


def _read_access_control_config() -> dict:
    """Read fresh on every callback -- a login is already a network round
    trip to Okta, so one extra stat+read is negligible, and this avoids any
    cache-staleness bug (a saved change takes effect on the very next login,
    with zero restart of this process required).

    SECURITY FIX (external review, 2026-09-30): this used to catch
    `ValueError` (json.JSONDecodeError's base class) from a MALFORMED file
    the exact same way as a genuinely MISSING one -- falling back to the
    unrestricted bootstrap default (OKTA_ADMIN_GROUP_ID, no user group,
    restrict_login OFF) either way. That's correct for "no file yet"
    (nobody has configured this feature at all), but confirmed exploitable
    for "file exists but is malformed" -- e.g. this process's own atomic-
    write guarantee (see create_secret_folders._atomic_write_json) means a
    normal save can never leave a truncated file on disk anymore, but a
    disk-full mid-write, a manual edit gone wrong, or any other corruption
    still shouldn't silently disable a real admin's login restriction.
    Now: file-not-found still means "not configured yet" (safe bootstrap
    default, unchanged). A file that EXISTS but fails to parse instead
    falls back to the last config that DID parse successfully in this
    process's lifetime -- restrictive settings stay enforced even if the
    file becomes unreadable later. Only if this process has NEVER seen a
    valid file at all (freshly started, and the on-disk file is already
    corrupt) does a parse failure fall back to the bootstrap default --
    there's no better answer available at that point, and failing every
    login outright would be worse than a temporary bootstrap-default
    window that a restart or a fixed file resolves."""
    global _LAST_GOOD_ACCESS_CONTROL_CONFIG
    try:
        with open(ACCESS_CONTROL_FILE_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"admin_group_id": OKTA_ADMIN_GROUP_ID, "user_group_id": None, "restrict_login": False}
    except ValueError:
        if _LAST_GOOD_ACCESS_CONTROL_CONFIG is not None:
            return dict(_LAST_GOOD_ACCESS_CONTROL_CONFIG)
        return {"admin_group_id": OKTA_ADMIN_GROUP_ID, "user_group_id": None, "restrict_login": False}
    config = {
        "admin_group_id": data.get("admin_group_id") or None,
        "user_group_id": data.get("user_group_id") or None,
        "restrict_login": bool(data.get("restrict_login", False)),
    }
    _LAST_GOOD_ACCESS_CONTROL_CONFIG = config
    return config


def _load_or_create_session_key() -> bytes:
    if SESSION_KEY_PATH.exists():
        return SESSION_KEY_PATH.read_bytes()
    key = os.urandom(32)
    SESSION_KEY_PATH.write_bytes(key)
    SESSION_KEY_PATH.chmod(0o640)
    return key


SESSION_KEY = _load_or_create_session_key()


# Renamed at 5.20.0 from "opa-secrets-wizard" -- kept as a read-only
# fallback below so an existing install's already-stored client secret/
# admin-check token keep resolving with zero changes required on upgrade.
# Never written to; a value naturally migrates to the new prefix the next
# time it's re-stored via `keyring.set_password(...)`.
_KEYRING_PREFIX = "opa-compliance-wizard"
_LEGACY_KEYRING_PREFIX = "opa-secrets-wizard"


def _load_keyring_secret(field: str, setup_hint: str) -> str:
    import keyring

    value = keyring.get_password(f"{_KEYRING_PREFIX}:{OKTA_ENV_NAME}", field)
    if not value:
        value = keyring.get_password(f"{_LEGACY_KEYRING_PREFIX}:{OKTA_ENV_NAME}", field)
    if not value:
        raise RuntimeError(
            f"No {field} in keyring for {_KEYRING_PREFIX}:{OKTA_ENV_NAME} -- {setup_hint}"
        )
    return value


def _load_client_secret() -> str:
    return _load_keyring_secret(
        "okta_client_secret",
        "was it stored via `keyring.set_password(...)` after creating the Okta app?",
    )


def _load_admin_check_token() -> str:
    return _load_keyring_secret(
        "okta_admin_check_token",
        "store a read-only, org-wide Okta API token (Users + Groups read scope) via "
        "`keyring.set_password('opa-compliance-wizard:{OKTA_ENV_NAME}', 'okta_admin_check_token', "
        "'<token>')`. See \"Admin access\" in docs/hosting.md.",
    )


OKTA_CLIENT_SECRET = _load_client_secret()
OKTA_ADMIN_CHECK_TOKEN = _load_admin_check_token()
_JWKS_CLIENT = PyJWKClient(OKTA_JWKS_URL)


def _fetch_user_group_ids(user_sub: str) -> list[str] | None:
    """GET /api/v1/users/{id}/groups, checked once at login (see the module
    docstring for why this is a direct API call rather than a groups claim
    on the ID token) -- SSWS token auth, same scheme as
    create_secret_folders.py's OktaClient, but this file deliberately
    doesn't import that module (this is a standalone auth-gate process with
    its own minimal dependency footprint, not part of the dashboard app).
    Returns None on any failure (fails closed -- see _resolve_membership),
    never an empty list to mean "unknown"; a real "in zero groups" user
    still gets a real (empty) list back from Okta."""
    url = f"{OKTA_ORG_URL}/api/v1/users/{urllib.parse.quote(user_sub, safe='')}/groups"
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {OKTA_ADMIN_CHECK_TOKEN}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            groups = json.loads(r.read())
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None
    return [g.get("id") for g in groups if g.get("id")]


def _resolve_membership(group_ids: list[str] | None, admin_group_id: str | None, user_group_id: str | None) -> tuple[bool, bool]:
    """Pure -- returns (is_admin, is_allowed). Fails closed on group_ids is
    None (a broken/expired admin-check token or a transient Okta API error
    must never silently grant admin OR login rights -- worst case, a real
    user's login gets denied/downgraded until this is fixed, the safe
    direction for this failure to fall in). is_allowed is True whenever
    EITHER group matches, or whenever neither group ID is configured at all
    (nothing to restrict against yet) -- the actual login-time enforcement
    of is_allowed is gated separately by restrict_login, see
    _handle_callback."""
    if group_ids is None:
        return False, False
    is_admin = bool(admin_group_id) and admin_group_id in group_ids
    is_user = bool(user_group_id) and user_group_id in group_ids
    is_allowed = is_admin or is_user or (not admin_group_id and not user_group_id)
    return is_admin, is_allowed


def _query_mfa_log_event(user_sub: str, since_dt) -> dict | None:
    """One-shot System Log query, no retry -- called only by
    _mfa_log_lookup's on-demand backfill path now (Phase 4 removed the
    synchronous step-up-callback caller that used to retry this; an
    already-past event has had plenty of time to index, so there's no
    retry benefit here). Returns a small dict (published/eventType/
    outcome/displayMessage), or None on any miss/error."""
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filter_expr = f'actor.id eq "{user_sub}" and eventType eq "user.authentication.auth_via_mfa"'
    params = {"filter": filter_expr, "since": since, "sortOrder": "DESCENDING", "limit": "5"}
    url = f"{OKTA_ORG_URL}/api/v1/logs?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {OKTA_ADMIN_CHECK_TOKEN}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            events = json.loads(r.read())
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None
    if not events:
        return None
    event = events[0]
    outcome = event.get("outcome") or {}
    return {
        "published": event.get("published"),
        "eventType": event.get("eventType"),
        "outcome_result": outcome.get("result"),
        "display_message": event.get("displayMessage"),
    }


def _sign_payload(payload: dict, ttl_seconds: int) -> str:
    payload = dict(payload, exp=int(time.time()) + ttl_seconds)
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    mac = hmac.new(SESSION_KEY, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _verify_signed_payload(token: str) -> dict | None:
    try:
        body, mac = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(SESSION_KEY, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body.encode()))
    except (ValueError, json.JSONDecodeError):
        return None
    if time.time() > payload.get("exp", 0):
        return None
    return payload


def _pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _get_cookie(headers, name):
    raw = headers.get("Cookie", "")
    cookie = http.cookies.SimpleCookie()
    cookie.load(raw)
    morsel = cookie.get(name)
    return morsel.value if morsel else None


def _cookie_header(name, value, max_age=None):
    cookie = http.cookies.SimpleCookie()
    cookie[name] = value
    cookie[name]["path"] = "/"
    cookie[name]["httponly"] = True
    cookie[name]["samesite"] = "Lax"
    cookie[name]["secure"] = True
    if max_age is not None:
        cookie[name]["max-age"] = max_age
    return cookie[name].OutputString()


def _exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier,
        }
    ).encode()
    basic = base64.b64encode(f"{OKTA_CLIENT_ID}:{OKTA_CLIENT_SECRET}".encode()).decode()
    req = urllib.request.Request(
        OKTA_TOKEN_URL,
        data=body,
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _verify_id_token(id_token: str) -> dict:
    signing_key = _JWKS_CLIENT.get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=OKTA_CLIENT_ID,
        issuer=OKTA_ISSUER,
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        CORRELATION_ID.set(uuid.uuid4().hex[:12])
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/login":
            self._start_login()
        elif path == "/step-up":
            # Phase 3: action_id (minted by serve.py's
            # POST /api/access_control/prepare) identifies the SPECIFIC
            # pending change this step-up is approving -- threaded
            # through the signed flow cookie below so the callback can
            # carry it into the step-up cookie itself, closing the gap
            # where a step-up proof could be replayed for any payload,
            # not just the one reviewed. Absent entirely for any FUTURE
            # purpose="step_up" caller that predates this field (handled
            # as None end-to-end, never a hard requirement at this
            # layer -- the actual enforcement that a save needs a valid,
            # unconsumed action_id lives in serve.py/audit_store.py).
            self._start_login(purpose="step_up", action_id=query.get("action_id", [None])[0])
        elif path == "/authorization-code/callback":
            self._handle_callback(query)
        elif path == "/verify":
            self._verify_session(require_stepup=query.get("require_stepup", ["0"])[0] == "1")
        elif path == "/logout":
            self._logout()
        elif path == "/internal/mfa_log_lookup":
            self._mfa_log_lookup(query)
        else:
            self.send_response(404)
            self.end_headers()

    def _start_login(self, purpose="login", action_id=None):
        """Shared by /login and /step-up -- purpose is carried in the signed
        flow cookie so _handle_callback knows, once Okta redirects back,
        whether to issue an ordinary session or a short-lived step-up proof
        (see _handle_callback). /step-up additionally sends max_age=0 +
        acr_values to force a fresh MFA challenge regardless of the
        existing Okta session -- Identity Engine parameters, NOT Classic
        (Classic's equivalent max_age value is 1, not 0) -- see the module
        docstring's step-up note for the Authentication Policy prerequisite
        this depends on.

        `action_id` (Phase 3, step-up only) rides through this SAME
        already-signed, already-HMAC'd flow cookie alongside
        state/verifier/purpose -- no new cookie/signing infrastructure,
        directly mirroring the standard OAuth state-binding pattern of
        storing pending context server-side keyed by the opaque value
        the IdP round-trips, rather than trusting anything client-held."""
        verifier, challenge = _pkce_pair()
        state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
        flow_token = _sign_payload(
            {"state": state, "verifier": verifier, "purpose": purpose, "action_id": action_id}, FLOW_TTL_SECONDS
        )

        params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if purpose == "step_up":
            params["max_age"] = "0"
            params["acr_values"] = "urn:okta:loa:2fa:any"
        authorize_url = f"{OKTA_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        self.send_response(302)
        self.send_header("Set-Cookie", _cookie_header(FLOW_COOKIE, flow_token))
        self.send_header("Location", authorize_url)
        self.end_headers()

    def _handle_callback(self, query):
        error = query.get("error", [None])[0]
        if error:
            self._respond_text(400, f"Okta returned an error: {error} - {query.get('error_description', [''])[0]}")
            return

        code = query.get("code", [None])[0]
        returned_state = query.get("state", [None])[0]
        flow_token = _get_cookie(self.headers, FLOW_COOKIE)
        flow = _verify_signed_payload(flow_token) if flow_token else None

        if not code or not returned_state or not flow or flow.get("state") != returned_state:
            self._respond_text(400, "Invalid or expired login attempt -- please try logging in again.")
            return

        try:
            tokens = _exchange_code_for_tokens(code, flow["verifier"])
            claims = _verify_id_token(tokens["id_token"])
        except (urllib.error.HTTPError, urllib.error.URLError, KeyError, jwt.PyJWTError) as exc:
            self._respond_text(401, f"Login failed during token verification: {exc}")
            return

        if flow.get("purpose") == "step_up":
            # No group/admin check here at all -- a step-up flow only proves
            # a FRESH MFA challenge was just completed by whoever is already
            # logged in; it's a re-authentication proof, not a login. Who's
            # allowed to use that proof (e.g. only an admin) is enforced by
            # serve.py's own admin check on the endpoint that actually
            # consumes it (POST /api/access_control/save), same
            # defense-in-depth double-check this project already does
            # elsewhere for admin actions.
            #
            # Phase 3: action_id (the specific pending change this step-up
            # is approving, see /step-up above) carried straight through
            # from the flow cookie into the step-up cookie -- this is what
            # lets serve.py retrieve the EXACT payload that was reviewed
            # (audit_store.consume_pending_admin_action), rather than
            # trusting whatever the live request body says.
            #
            # Phase 4: the synchronous Okta System Log corroboration
            # lookup that used to happen HERE (_find_stepup_mfa_log_event,
            # up to 4 retries / ~6s added latency) is removed -- now that
            # pending_admin_actions is the authoritative, SQL-provable
            # record of this exact approval, Okta's own log event is
            # optional corroborating evidence only, not something that
            # needs to block this redirect. See the Audit Log page's
            # Refresh button (backfill_mfa_log_events) for how that
            # corroboration can still be filled in later, asynchronously.
            stepup_token = _sign_payload(
                {"sub": claims["sub"], "action_id": flow.get("action_id")}, STEPUP_TTL_SECONDS
            )
            self.send_response(302)
            self.send_header("Set-Cookie", _cookie_header(STEPUP_COOKIE, stepup_token, max_age=STEPUP_TTL_SECONDS))
            self.send_header("Set-Cookie", _cookie_header(FLOW_COOKIE, "", max_age=0))
            self.send_header("Location", "/?stepup_complete=1")
            self.end_headers()
            return

        # Checked once here, not on every request -- consistent with how
        # email/sub already work for the life of a session. A group
        # membership change (admin OR user group, and restrict_login itself)
        # takes effect on next login/session refresh (SESSION_TTL_SECONDS),
        # not instantly -- an accepted tradeoff of this session model, not
        # an oversight.
        access_control = _read_access_control_config()
        group_ids = _fetch_user_group_ids(claims["sub"])
        is_admin, is_allowed = _resolve_membership(
            group_ids, access_control["admin_group_id"], access_control["user_group_id"]
        )

        if access_control["restrict_login"] and not is_allowed:
            self._respond_text(
                403,
                "You don't have access to this dashboard. Contact an administrator to be "
                "added to the required Okta group.",
            )
            return

        session_token = _sign_payload(
            {"sub": claims["sub"], "email": claims.get("email"), "id_token": tokens["id_token"], "is_admin": is_admin},
            SESSION_TTL_SECONDS,
        )

        self.send_response(302)
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE, session_token, max_age=SESSION_TTL_SECONDS))
        self.send_header("Set-Cookie", _cookie_header(FLOW_COOKIE, "", max_age=0))
        self.send_header("Location", "/")
        self.end_headers()

    def _verify_session(self, require_stepup=False):
        token = _get_cookie(self.headers, SESSION_COOKIE)
        session = _verify_signed_payload(token) if token else None
        if not session:
            self.send_response(401)
            self.end_headers()
            return

        action_id = None
        if require_stepup:
            stepup_token = _get_cookie(self.headers, STEPUP_COOKIE)
            stepup = _verify_signed_payload(stepup_token) if stepup_token else None
            # sub must match the CURRENT session's sub -- otherwise a
            # step-up cookie left over from a previous user on a shared
            # machine/browser profile could authorize a save on behalf of
            # whoever is logged in now. A mismatch or missing/expired
            # step-up cookie is treated identically to no step-up at all.
            if not stepup or stepup.get("sub") != session.get("sub"):
                self.send_response(401)
                self.end_headers()
                return
            action_id = stepup.get("action_id")

        self.send_response(200)
        # Two distinct headers, deliberately: `sub` is Okta's stable,
        # never-reused identity id -- the correct key for scoping
        # storage (see create_secret_folders.py's per-owner
        # environments). `email` can change (a user's email is updated,
        # or reused across a re-provisioned account) and exists here
        # purely for human-readable display/audit-log purposes -- never
        # used as a storage/permission key downstream.
        self.send_header("X-Auth-Sub", session.get("sub", ""))
        self.send_header("X-Auth-User", session.get("email") or session.get("sub", ""))
        self.send_header("X-Auth-Is-Admin", "true" if session.get("is_admin") else "false")
        if action_id is not None:
            # Phase 3: carries the pending-action id this step-up is
            # approving through to serve.py's save route, which consumes
            # it (audit_store.consume_pending_admin_action) to retrieve
            # the EXACT payload that was reviewed -- never trusting the
            # live request body for the settings themselves. Plain value,
            # not base64-wrapped like the old X-Auth-Mfa-Log-Event -- an
            # action_id is already a safe opaque token (secrets.token_urlsafe),
            # with no structured JSON to encode.
            self.send_header("X-Auth-Action-Id", action_id)
        self.end_headers()

    def _mfa_log_lookup(self, query):
        """Loopback-only endpoint (see INTERNAL_API_SHARED_SECRET) letting
        serve.py backfill Okta MFA corroboration for an audit_log.jsonl
        entry that's missing it (System Log indexing lag confirmed live,
        2026-09-30: a real tenant can take real time to index a fresh
        auth_via_mfa event). Triggered by an admin clicking Refresh on the Audit Log
        page, NOT run automatically/periodically -- an explicit user action
        each time, same as this project's existing Sync/Refresh buttons
        elsewhere never auto-run on a timer either.

        No retry here (unlike the step-up flow) -- by the time an admin
        clicks Refresh, the triggering event is at least seconds old, often
        much older, so if Okta's indexing was ever going to catch up, it
        already has; a single query is enough, and a genuine miss (event
        expired past retention, or truly never indexed) shouldn't cost
        every future refresh a multi-second retry loop for nothing.

        Disabled entirely (404, not 401/403) unless
        INTERNAL_API_SHARED_SECRET is configured -- see that constant."""
        if not INTERNAL_API_SHARED_SECRET:
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("X-Internal-Secret") != INTERNAL_API_SHARED_SECRET:
            self.send_response(403)
            self.end_headers()
            return

        user_sub = query.get("sub", [None])[0]
        near_iso = query.get("near", [None])[0]
        if not user_sub or not near_iso:
            self.send_response(400)
            self.end_headers()
            return
        try:
            near_dt = datetime.fromisoformat(near_iso.replace("Z", "+00:00"))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        # Narrow-window-around-the-moment correlation -- `near` is the
        # audit entry's own timestamp, so querying from just before it
        # (clock-skew slop) covers the real event with a single shot, no
        # retry loop needed (see _query_mfa_log_event's docstring).
        since_dt = near_dt - timedelta(seconds=STEPUP_LOG_LOOKBACK_SECONDS)
        result = _query_mfa_log_event(user_sub, since_dt)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = json.dumps(result).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _logout(self):
        token = _get_cookie(self.headers, SESSION_COOKIE)
        session = _verify_signed_payload(token) if token else None
        id_token = session.get("id_token") if session else None

        clear_header = _cookie_header(SESSION_COOKIE, "", max_age=0)
        if id_token:
            params = {"id_token_hint": id_token, "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI}
            location = f"{OKTA_LOGOUT_URL}?{urllib.parse.urlencode(params)}"
        else:
            location = "/login"

        self.send_response(302)
        self.send_header("Set-Cookie", clear_header)
        self.send_header("Location", location)
        self.end_headers()

    def _respond_text(self, status, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    log("SUCCESS", f"Okta auth gate listening on 127.0.0.1:{args.port}, issuer={OKTA_ISSUER}")
    server.serve_forever()


if __name__ == "__main__":
    main()
