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
  - GET  /logout                         -> clears the gate's cookies
                                             AND redirects through Okta's own
                                             logout endpoint (otherwise the
                                             gate forgets you but Okta's own
                                             SSO session silently logs you
                                             back in on the next /login).
                                             A cross-site GET gets a "Log
                                             out?" page instead (GATE-12).
  - POST /logout                         -> that page's form; same-origin
                                             (Origin == DASHBOARD_ORIGIN) only
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
server-only secret in /etc/opa-secrets-wizard-session.key (root:<app-user>,
0640 if pre-created; 0600 if this process creates it; at least 32 bytes or
the gate refuses to start -- see _load_or_create_session_key and "Session-
signing key" in docs/hosting.md). The PKCE code_verifier + OAuth `state`
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

# OPS-07: keeps the PEP 604 annotations (`list[str] | None`) from being
# evaluated at import time, so the gate imports on Python 3.9 -- the
# minimum the README and launch.py document. CI runs the suite on 3.9.
from __future__ import annotations

import argparse
import base64
import contextvars
import hashlib
import hmac
import http.client
import http.cookies
import json
import os
import re
import sys
import threading
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
    from gate_config import access_control_path, okta_endpoints, session_key_path
except ImportError:  # imported as server.auth_gate
    from server.gate_config import access_control_path, okta_endpoints, session_key_path

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
# GATE-03: real action_ids are minted server-side by audit_store's
# create_pending_admin_action via secrets.token_urlsafe(32), which only
# ever produces URL-safe base64 characters (43 chars for 32 random
# bytes, no padding). Anything outside this shape -- CRLF, non-ASCII, a
# client trying to smuggle an arbitrary value through -- is rejected
# before it enters a signed cookie or a response header.
_ACTION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}")
SESSION_COOKIE = "opa_wizard_session"
FLOW_COOKIE = "opa_wizard_flow"
STEPUP_COOKIE = "opa_wizard_stepup"
SESSION_TTL_SECONDS = 12 * 60 * 60  # 12h -- re-login once a workday
FLOW_TTL_SECONDS = 10 * 60  # 10 min is generous for "redirect to Okta and log in"
STEPUP_TTL_SECONDS = 120  # short-lived on purpose -- proof of a JUST-completed MFA challenge, not a second session
# GATE-02: how stale the ID token's auth_time may be and still count as
# "just completed a fresh challenge". Generous enough to cover the full
# step-up redirect round trip (Okta login page + MFA prompt + redirect
# back) plus clock skew between this process and Okta, not an attempt to
# pin the exact round-trip latency.
STEPUP_MAX_AUTH_AGE_SECONDS = 300
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
# Per gate instance (OPA_ACCESS_CONTROL_PATH, 5.38.3): an additional gate for another Okta org must not check
# the main org's group IDs. Unset = access_control.json next to the app, as always.
ACCESS_CONTROL_FILE_PATH = access_control_path(os.environ, Path(__file__).resolve().parent.parent / "access_control.json")
# GATE-14 (external review, 2026-10-05): an operator who points a gate at its own access-control file (every
# additional gate does -- setup-second-gate.sh writes it with restrict_login on) has said "this gate's rules live
# HERE". A missing or never-parseable file then means "config lost", not "not configured yet", so the callback
# refuses logins (AccessControlUnavailable) instead of silently opening them to every user assigned to the Okta
# app. Unset (the main gate) keeps the documented first-boot bootstrap default below.
ACCESS_CONTROL_PATH_EXPLICIT = bool(os.environ.get("OPA_ACCESS_CONTROL_PATH"))


class AccessControlUnavailable(Exception):
    """The explicitly configured access-control file is missing or has never parsed (GATE-14)."""


_LAST_GOOD_ACCESS_CONTROL_CONFIG = None  # see _read_access_control_config
_ACCESS_CONTROL_LOCK = threading.Lock()


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
    bootstrap = {"admin_group_id": OKTA_ADMIN_GROUP_ID, "user_group_id": None, "restrict_login": False}
    with _ACCESS_CONTROL_LOCK:
        try:
            with open(ACCESS_CONTROL_FILE_PATH, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("access-control file is not a JSON object")
        except FileNotFoundError:
            if ACCESS_CONTROL_PATH_EXPLICIT:
                raise AccessControlUnavailable(f"{ACCESS_CONTROL_FILE_PATH} is missing") from None
            return bootstrap
        except ValueError:
            if _LAST_GOOD_ACCESS_CONTROL_CONFIG is not None:
                return dict(_LAST_GOOD_ACCESS_CONTROL_CONFIG)
            if ACCESS_CONTROL_PATH_EXPLICIT:
                raise AccessControlUnavailable(f"{ACCESS_CONTROL_FILE_PATH} does not parse") from None
            return bootstrap
        config = {
            "admin_group_id": data.get("admin_group_id") or None,
            "user_group_id": data.get("user_group_id") or None,
            "restrict_login": bool(data.get("restrict_login", False)),
        }
        _LAST_GOOD_ACCESS_CONTROL_CONFIG = config
        return dict(config)


SESSION_KEY_MIN_BYTES = 32


def _load_or_create_session_key() -> bytes:
    """GATE-07 (external review, 2026-10-05): an empty or short key file
    (`touch` + `chown` is the obvious way to pre-create it under /etc, and
    a crash mid-write used to leave one too) was used as-is, so every
    cookie was signed with an empty HMAC key and anyone could forge one.
    Now: a key shorter than SESSION_KEY_MIN_BYTES refuses to start, and a
    new key is written to a private temp file in the same directory and
    then hard-linked into place -- os.link fails if the name already
    exists, so the key appears complete or not at all, and two processes
    starting at once both end up with whichever key won."""
    if not SESSION_KEY_PATH.exists():
        key = os.urandom(SESSION_KEY_MIN_BYTES)
        tmp = SESSION_KEY_PATH.with_name(f".{SESSION_KEY_PATH.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, SESSION_KEY_PATH)
            except FileExistsError:
                pass  # another process won the race -- use its key, read below
        finally:
            tmp.unlink(missing_ok=True)
    key = SESSION_KEY_PATH.read_bytes()
    if len(key) < SESSION_KEY_MIN_BYTES:
        raise RuntimeError(
            f"Session key {SESSION_KEY_PATH} is {len(key)} bytes; at least {SESSION_KEY_MIN_BYTES} random bytes "
            "are required. Remove it so the gate creates one, or write one with e.g. "
            f"`head -c {SESSION_KEY_MIN_BYTES} /dev/urandom > <path>` (see docs/hosting.md)."
        )
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
# timeout=10 (PyJWT's default is 30): with the 10 s token exchange and the
# 25 s group-lookup budget, a callback against a slow Okta still answers
# inside nginx's default 60 s proxy_read_timeout.
_JWKS_CLIENT = PyJWKClient(OKTA_JWKS_URL, timeout=10)

# GATE-09 (external review, 2026-10-05): what an outbound urllib call can
# raise besides the HTTPError/URLError the helpers used to catch -- a read
# timeout after the headers arrived (TimeoutError, an OSError, not wrapped
# in URLError), a truncated body (http.client.HTTPException), or a
# non-JSON body (ValueError). URLError and HTTPError are OSError
# subclasses, so OSError covers them too.
OUTBOUND_ERRORS = (OSError, ValueError, http.client.HTTPException)
GROUP_LOOKUP_MAX_PAGES = 20
GROUP_LOOKUP_BUDGET_SECONDS = 25
# Okta user ids (the `sub` of every ID token this gate accepts, and what
# /internal/mfa_log_lookup interpolates into a System Log filter) are
# short alphanumeric ids. Checked before a sub becomes a response header
# or a filter-expression string literal.
_OKTA_SUB_PATTERN = re.compile(r"[A-Za-z0-9]{1,64}")
# Header values nginx forwards to serve.py: printable ASCII only (no
# CR/LF, no characters BaseHTTPRequestHandler.send_header can't encode).
_HEADER_SAFE = re.compile(r"[\x21-\x7e]{1,320}")


class MfaLookupFailed(Exception):
    """The System Log query could not be made or its answer was unusable."""


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
    ids = []
    # GATE-10 (external review, 2026-10-05): only the first page used to be
    # read. Okta's spec documents no paging parameters for this endpoint,
    # but its general convention is a `Link: <...>; rel="next"` header, so
    # follow one if present -- bounded, and only to this org's own
    # /api/v1/ (the SSWS token must never be sent anywhere else). Any page
    # failing fails the whole lookup closed (None).
    # The whole lookup stays inside GROUP_LOOKUP_BUDGET_SECONDS so the
    # callback (10 s token exchange + 10 s JWKS fetch + this) answers within
    # nginx's default 60 s proxy_read_timeout. urlopen's timeout is per
    # socket operation, so a response trickling in byte by byte could still
    # overrun a single call; only Okta is on the other end.
    deadline = time.monotonic() + GROUP_LOOKUP_BUDGET_SECONDS
    for _page in range(GROUP_LOOKUP_MAX_PAGES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            log("WARN", f"group lookup for {user_sub} ran out of time")
            return None
        req = urllib.request.Request(url, headers={"Authorization": f"SSWS {OKTA_ADMIN_CHECK_TOKEN}", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=min(10, remaining)) as r:
                groups = json.loads(r.read())
                # Okta sends rel="self" and rel="next" as SEPARATE Link
                # header lines; .get() would return only the first.
                get_all = getattr(r.headers, "get_all", None)
                links = get_all("Link") if get_all else [r.headers.get("Link")]
                link_header = ", ".join(v for v in (links or []) if v)
        except OUTBOUND_ERRORS as exc:
            log("WARN", f"group lookup for {user_sub} failed: {type(exc).__name__}")
            return None
        if not isinstance(groups, list):
            log("WARN", f"group lookup for {user_sub} returned a {type(groups).__name__}, not a list")
            return None
        ids.extend(g["id"] for g in groups if isinstance(g, dict) and isinstance(g.get("id"), str) and g.get("id"))
        url = _next_link(link_header)
        if url is _FOREIGN_LINK:
            return None  # fail closed: a page we won't fetch might hold the admin group
        if url is None:
            return ids
    log("WARN", f"group lookup for {user_sub} exceeded {GROUP_LOOKUP_MAX_PAGES} pages")
    return None


_FOREIGN_LINK = object()  # _next_link: a rel="next" we refuse to follow


def _next_link(link_header: str):
    """The rel="next" URL from RFC 8288 Link header value(s), None when
    there is no next page, or _FOREIGN_LINK when the next page is outside
    this org's /api/v1/ (never followed with the SSWS token; the caller
    fails closed). The URL sits between <...>, so a comma inside it does
    not split the entry."""
    for m in re.finditer(r'<([^>]*)>((?:\s*;\s*(?:"[^"]*"|[^;,<"])*)*)', link_header or ""):
        # Parameters one by one, so a quoted value (title="a;rel=next") is
        # consumed whole and never read as a rel. Relation types compare
        # case-insensitively (RFC 8288 2.1.1).
        rels = []
        for param in re.finditer(r';\s*([A-Za-z*-]+)\s*=\s*("([^"]*)"|[^;,\s"]*)', m.group(2)):
            if param.group(1).lower() == "rel":
                value = param.group(3) if param.group(3) is not None else param.group(2)
                rels.extend(value.lower().split())
        if "next" not in rels:
            continue
        target = m.group(1)
        if target.startswith(f"{OKTA_ORG_URL}/api/v1/") and not any(c in target for c in "\r\n\\"):
            return target
        host = urllib.parse.urlsplit(target).hostname if target.isprintable() else "?"
        log("WARN", f"refused a Link rel=next to host {host!r}, outside {OKTA_ORG_URL}/api/v1/")
        return _FOREIGN_LINK
    return None


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
    outcome/displayMessage), or None when Okta answered and there is no
    matching event. Raises MfaLookupFailed when Okta could not be asked
    or gave an unusable answer -- that used to be None as well, which
    serve.py's backfill counted as a definite miss and so used up an
    entry's lookup attempts during an Okta or token outage."""
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filter_expr = f'actor.id eq "{user_sub}" and eventType eq "user.authentication.auth_via_mfa"'
    params = {"filter": filter_expr, "since": since, "sortOrder": "DESCENDING", "limit": "5"}
    url = f"{OKTA_ORG_URL}/api/v1/logs?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {OKTA_ADMIN_CHECK_TOKEN}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            events = json.loads(r.read())
    except OUTBOUND_ERRORS as exc:
        raise MfaLookupFailed(type(exc).__name__) from exc
    if not isinstance(events, list):
        raise MfaLookupFailed(f"System Log returned a {type(events).__name__}, not a list")
    if not events:
        return None
    event = events[0]
    if not isinstance(event, dict):
        raise MfaLookupFailed("System Log event is not an object")
    outcome = event.get("outcome") if isinstance(event.get("outcome"), dict) else {}
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


def _verify_signed_payload(token: str, expected_typ: str | None = None) -> dict | None:
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
    # SECURITY FIX (external review, 2026-10-05, GATE-01): all three
    # cookie kinds (flow/session/step-up) used to share one generic
    # sign/verify pair with no "what kind of token is this" marker, so
    # the flow cookie /login hands to ANY unauthenticated visitor verified
    # equally well as a session cookie or a step-up cookie -- a pre-auth
    # bypass confirmed exploitable end-to-end in production (replayed as
    # opa_wizard_session, it reached serve.py's admin-exempt `__local__`
    # owner; replayed as both session AND step-up, it also passed
    # require_stepup with an attacker-chosen action_id). Every payload
    # minted below now carries a "typ" claim, and a caller that knows
    # which cookie slot it's checking must say which `typ` it expects.
    if expected_typ is not None and payload.get("typ") != expected_typ:
        return None
    return payload


def _pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _get_cookie(headers, name):
    raw = headers.get("Cookie", "")
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(raw)
    except http.cookies.CookieError:
        return None
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


def _verify_id_token(id_token: str, expected_nonce: str | None) -> dict:
    """GATE-13 (external review, 2026-10-05): exp/iat/sub/aud/iss are now
    REQUIRED (PyJWT otherwise validates exp/aud/iss only when present), and
    the ID token's `nonce` must equal the one this gate put in the signed
    flow cookie and the /authorize request -- Okta returns it in the ID
    token (oauth spec, `nonce`: "A value that's returned in the ID
    token"), binding the token to this browser's login attempt."""
    signing_key = _JWKS_CLIENT.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=OKTA_CLIENT_ID,
        issuer=OKTA_ISSUER,
        options={"require": ["exp", "iat", "sub", "aud", "iss"]},
    )
    nonce = claims.get("nonce")
    if not expected_nonce or not isinstance(nonce, str) or not hmac.compare_digest(
        nonce.encode(), expected_nonce.encode()
    ):
        raise jwt.InvalidTokenError("ID token nonce does not match this login attempt")
    if not isinstance(claims.get("sub"), str) or not _OKTA_SUB_PATTERN.fullmatch(claims["sub"]):
        raise jwt.InvalidTokenError("ID token sub is not an Okta user id")
    return claims


def _header_safe(value):
    """value if it can go into a response header unchanged, else None."""
    return value if isinstance(value, str) and _HEADER_SAFE.fullmatch(value) else None


# GATE-12: shown instead of logging out when a GET /logout came from another
# site (Sec-Fetch-Site: cross-site/same-site). Static -- nothing from the
# request is echoed into it. The form posts back to /logout, same origin.
_LOGOUT_CONFIRM_PAGE = (
    "<!doctype html><html lang=en><head><meta charset=utf-8>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
    "<title>Log out?</title></head><body style=\"font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;"
    "padding:0 1rem\"><h1 style=\"font-size:1.25rem\">Log out of the OPA Compliance Wizard?</h1>"
    "<p>Another site sent you to the log-out page. Log out only if you meant to.</p>"
    "<form method=post action=/logout><button type=submit>Log out</button> <a href=\"/\">Stay signed in</a>"
    "</form></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    # GATE-15: an idle or slow connection no longer holds a thread forever.
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self._dispatch(self._route_get)

    def do_POST(self):
        self._dispatch(self._route_post)

    def _dispatch(self, route):
        """GATE-09: an unexpected exception used to drop the connection
        (nginx: bare 502) with only a traceback on stderr. Now it is logged
        with the correlation id and answered with a generic 500 that
        quotes the id, never the exception text."""
        correlation_id = uuid.uuid4().hex[:12]
        CORRELATION_ID.set(correlation_id)
        try:
            route()
        except Exception as exc:  # noqa: BLE001 -- last-resort handler
            log("ERROR", f"{self.command} {urllib.parse.urlparse(self.path).path} failed: {type(exc).__name__}: {exc}")
            try:
                self._respond_text(500, f"Something went wrong signing you in. Reference: {correlation_id}")
            except OSError:
                pass

    def _route_post(self):
        if urllib.parse.urlparse(self.path).path == "/logout":
            self._logout_post()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _route_get(self):
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
            action_id = query.get("action_id", [None])[0]
            # GATE-03 (external review, 2026-10-05): action_id used to be
            # written straight into a response header further down the
            # chain (/verify's X-Auth-Action-Id) with no validation at
            # all -- a %0d%0a-containing value could inject an arbitrary
            # extra header (e.g. a second X-Auth-Is-Admin: true) into the
            # auth_request response nginx reads. serve.py's own
            # create_pending_admin_action always mints a real id via
            # secrets.token_urlsafe(32), so this regex is simply what a
            # genuine id already looks like -- anything else is rejected
            # before it can ride through the signed flow/step-up cookies
            # at all.
            if action_id is not None and not _ACTION_ID_PATTERN.fullmatch(action_id):
                self._respond_text(400, "Invalid action_id.")
                return
            self._start_login(purpose="step_up", action_id=action_id)
        elif path == "/authorization-code/callback":
            self._handle_callback(query)
        elif path == "/verify":
            self._verify_session(require_stepup=query.get("require_stepup", ["0"])[0] == "1")
        elif path == "/logout":
            self._logout_get()
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
        nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()  # GATE-13
        flow_token = _sign_payload(
            {"typ": "flow", "state": state, "nonce": nonce, "verifier": verifier, "purpose": purpose,
             "action_id": action_id},
            FLOW_TTL_SECONDS,
        )

        params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "nonce": nonce,
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
            # Okta's own error code/description (e.g. access_denied when the
            # user isn't assigned to the app) -- useful to the user, and
            # sent as text/plain, so nothing in it is interpreted.
            log("WARN", f"login callback: Okta returned error={error!r}")
            self._respond_text(400, f"Okta returned an error: {error} - {query.get('error_description', [''])[0]}")
            return

        code = query.get("code", [None])[0]
        returned_state = query.get("state", [None])[0]
        flow_token = _get_cookie(self.headers, FLOW_COOKIE)
        flow = _verify_signed_payload(flow_token, "flow") if flow_token else None

        if (not code or not returned_state or not flow or not isinstance(flow.get("state"), str)
                or not hmac.compare_digest(flow["state"].encode(), returned_state.encode())):
            self._respond_text(400, "Invalid or expired login attempt -- please try logging in again.")
            return

        try:
            tokens = _exchange_code_for_tokens(code, flow["verifier"])
            if not isinstance(tokens, dict) or not isinstance(tokens.get("id_token"), str):
                raise ValueError("token response has no id_token")
            claims = _verify_id_token(tokens["id_token"], flow.get("nonce"))
        except (*OUTBOUND_ERRORS, KeyError, TypeError, jwt.PyJWTError) as exc:
            # GATE-09: the detail goes to the gate's log, not the browser.
            log("WARN", f"login callback: token exchange/verification failed: {type(exc).__name__}: {exc}")
            self._respond_text(
                401,
                "Login failed while verifying your sign-in with Okta -- please try logging in again. "
                f"Reference: {CORRELATION_ID.get()}",
            )
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
            # GATE-02 (external review, 2026-10-05): a session cookie
            # used to be accepted anywhere a step-up cookie was expected
            # (same root cause as GATE-01 -- no "typ" marker), and even on
            # a REAL step-up callback this code never checked whether
            # Okta actually prompted for a fresh MFA challenge before
            # returning: max_age=0 + acr_values are a REQUEST, not a
            # guarantee, and the OIDC spec requires the client to verify
            # auth_time when it sent max_age. A stale auth_time (an
            # existing Okta SSO session silently satisfying this without
            # any prompt) now refuses the step-up cookie outright --
            # small clock-skew allowance, not a hard "must be instant"
            # check, since the Okta round trip itself takes a few seconds.
            auth_time = claims.get("auth_time")
            if not isinstance(auth_time, (int, float)) or time.time() - auth_time > STEPUP_MAX_AUTH_AGE_SECONDS:
                log("WARN", f"step-up refused for {claims['sub']}: auth_time not fresh")
                self._respond_text(
                    401,
                    "Step-up verification failed: Okta did not report a fresh authentication. "
                    "Please try again.",
                )
                return
            stepup_token = _sign_payload(
                {"typ": "stepup", "sub": claims["sub"], "action_id": flow.get("action_id")}, STEPUP_TTL_SECONDS
            )
            log("INFO", f"step-up completed for {claims['sub']}")
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
        try:
            access_control = _read_access_control_config()
        except AccessControlUnavailable as exc:
            log("ERROR", f"login refused for {claims['sub']}: access control unavailable ({exc})")
            self._respond_text(
                503,
                "Sign-in is temporarily unavailable: this dashboard's access settings could not be read. "
                f"Contact an administrator. Reference: {CORRELATION_ID.get()}",
            )
            return
        group_ids = _fetch_user_group_ids(claims["sub"])
        is_admin, is_allowed = _resolve_membership(
            group_ids, access_control["admin_group_id"], access_control["user_group_id"]
        )

        if access_control["restrict_login"] and not is_allowed:
            log("INFO", f"login denied for {claims['sub']}: not in the user or admin group"
                        + (" (group lookup failed)" if group_ids is None else ""))
            self._respond_text(
                403,
                "You don't have access to this dashboard. Contact an administrator to be "
                "added to the required Okta group.",
            )
            return

        session_token = _sign_payload(
            {"typ": "session", "sub": claims["sub"], "email": claims.get("email"),
             "id_token": tokens["id_token"], "is_admin": is_admin},
            SESSION_TTL_SECONDS,
        )

        log("INFO", f"login for {claims['sub']} (admin={is_admin})")
        self.send_response(302)
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE, session_token, max_age=SESSION_TTL_SECONDS))
        self.send_header("Set-Cookie", _cookie_header(FLOW_COOKIE, "", max_age=0))
        self.send_header("Location", "/")
        self.end_headers()

    def _verify_session(self, require_stepup=False):
        token = _get_cookie(self.headers, SESSION_COOKIE)
        session = _verify_signed_payload(token, "session") if token else None
        # GATE-01: require a non-empty `sub` as well as a valid
        # signature/type. An empty/missing sub is exactly what the
        # pre-auth bypass produced (the gate would otherwise emit
        # X-Auth-Sub: "", which serve.py's `headers.get("X-Auth-Sub") or
        # LOCAL_OWNER_KEY_HEADER` maps straight to the privileged
        # `__local__` owner) -- belt-and-suspenders with the SRV-01 fix
        # on the serve.py side.
        sub = _header_safe(session.get("sub")) if session else None
        if not sub:
            self.send_response(401)
            self.end_headers()
            return

        action_id = None
        if require_stepup:
            stepup_token = _get_cookie(self.headers, STEPUP_COOKIE)
            stepup = _verify_signed_payload(stepup_token, "stepup") if stepup_token else None
            # sub must match the CURRENT session's sub -- otherwise a
            # step-up cookie left over from a previous user on a shared
            # machine/browser profile could authorize a save on behalf of
            # whoever is logged in now. A mismatch or missing/expired
            # step-up cookie is treated identically to no step-up at all.
            if not stepup or not stepup.get("sub") or stepup.get("sub") != sub:
                self.send_response(401)
                self.end_headers()
                return
            action_id = stepup.get("action_id")
            if action_id is not None and not (isinstance(action_id, str) and _ACTION_ID_PATTERN.fullmatch(action_id)):
                self.send_response(401)
                self.end_headers()
                return

        self.send_response(200)
        # Two distinct headers, deliberately: `sub` is Okta's stable,
        # never-reused identity id -- the correct key for scoping
        # storage (see create_secret_folders.py's per-owner
        # environments). `email` can change (a user's email is updated,
        # or reused across a re-provisioned account) and exists here
        # purely for human-readable display/audit-log purposes -- never
        # used as a storage/permission key downstream.
        self.send_header("X-Auth-Sub", sub)
        # GATE-09: an e-mail send_header can't encode (non-latin-1) used to
        # raise on every request, locking that user out; anything that isn't
        # printable ASCII now falls back to the sub, as a missing e-mail does.
        self.send_header("X-Auth-User", _header_safe(session.get("email")) or sub)
        self.send_header("X-Auth-Is-Admin", "true" if session.get("is_admin") else "false")
        # 5.43.0: which Okta org vouched for this `sub`. A sub is only unique
        # within one org (OIDC Core 5.7: iss + sub together identify a
        # user), and an additional gate (setup-second-gate.sh) fronts another
        # org on the same backend; serve.py keys per-user permission
        # exceptions on the pair. This gate's own configured issuer -- every
        # session it signs came from a token validated against it.
        self.send_header("X-Auth-Issuer", OKTA_ISSUER)
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
        # GATE-08: constant-time compare.
        if not hmac.compare_digest(
            (self.headers.get("X-Internal-Secret") or "").encode(), INTERNAL_API_SHARED_SECRET.encode()
        ):
            self.send_response(403)
            self.end_headers()
            return

        user_sub = query.get("sub", [None])[0]
        near_iso = query.get("near", [None])[0]
        # The sub is interpolated into a System Log filter string literal --
        # only an Okta user id shape gets that far (400 = "this entry's
        # parameters are bad", which serve.py counts against that entry only).
        if not user_sub or not near_iso or not _OKTA_SUB_PATTERN.fullmatch(user_sub):
            self.send_response(400)
            self.end_headers()
            return
        try:
            near_dt = datetime.fromisoformat(near_iso.replace("Z", "+00:00"))
            if near_dt.tzinfo is None:
                near_dt = near_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        # Narrow-window-around-the-moment correlation -- `near` is the
        # audit entry's own timestamp, so querying from just before it
        # (clock-skew slop) covers the real event with a single shot, no
        # retry loop needed (see _query_mfa_log_event's docstring).
        since_dt = (near_dt - timedelta(seconds=STEPUP_LOG_LOOKBACK_SECONDS)).astimezone(timezone.utc)
        try:
            result = _query_mfa_log_event(user_sub, since_dt)
        except MfaLookupFailed as exc:
            # Batch 3 carry-over: "couldn't ask Okta" is a 502, not `200 null`
            # (which serve.py reads as a definite "no such event" and counts
            # as a used-up attempt). serve.py maps any 5xx to
            # MfaLookupUnavailable: the backfill stops and charges nobody.
            log("WARN", f"mfa_log_lookup: System Log query failed: {exc}")
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = json.dumps(result).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _logout_get(self):
        """GATE-12 (external review, 2026-10-05): GET /logout is a
        state-changing GET, so any other site could log a user out of the
        dashboard and of Okta with a plain link. Browsers that send Fetch
        Metadata say where a navigation came from: `same-origin` (the app's
        own Log out link) and `none` (typed, bookmarked) log out as before;
        anything else (`cross-site`, `same-site`) gets a static "Log out?"
        page whose button POSTs back here. A browser that sends no
        Sec-Fetch-Site at all keeps the old behaviour."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            body = _LOGOUT_CONFIRM_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._do_logout()

    def _logout_post(self):
        """The confirm page's form. Only a same-origin POST logs out (Origin
        must be DASHBOARD_ORIGIN -- nginx's site sets Referrer-Policy:
        same-origin, under which a same-origin form POST still sends its
        real Origin)."""
        if self.headers.get("Origin") != DASHBOARD_ORIGIN:
            self._respond_text(403, "Log out must be confirmed from this dashboard.")
            return
        self._do_logout()

    def _do_logout(self):
        token = _get_cookie(self.headers, SESSION_COOKIE)
        session = _verify_signed_payload(token, "session") if token else None
        id_token = session.get("id_token") if session else None

        if id_token:
            params = {"id_token_hint": id_token, "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI}
            location = f"{OKTA_LOGOUT_URL}?{urllib.parse.urlencode(params)}"
        else:
            location = "/login"

        if session:
            log("INFO", f"logout for {session.get('sub')}")
        self.send_response(303 if self.command == "POST" else 302)
        # GATE-12: clear every gate cookie, not only the session -- a
        # step-up proof or half-finished login must not outlive the logout.
        for name in (SESSION_COOKIE, STEPUP_COOKIE, FLOW_COOKIE):
            self.send_header("Set-Cookie", _cookie_header(name, "", max_age=0))
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond_text(self, status, text):
        body = text.encode("utf-8", "replace")
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
