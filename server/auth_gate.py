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
  - GET  /authorization-code/callback    -> Okta redirects back here with
                                             ?code=...&state=...; exchanges
                                             the code for tokens, verifies the
                                             ID token, sets the session cookie
  - GET  /verify                         -> nginx auth_request target; 200 if
                                             the session cookie is valid, 401
                                             otherwise
  - GET  /logout                         -> clears the local session cookie
                                             AND redirects through Okta's own
                                             logout endpoint (otherwise the
                                             gate forgets you but Okta's own
                                             SSO session silently logs you
                                             back in on the next /login)

Session cookie is a signed ("<expiry>.<hmac>") token, same scheme as this
project's other short-lived signed tokens conceptually -- HMAC-SHA256 over a
server-only secret in /etc/opa-secrets-wizard-session.key (root:rparikh,
0640, generated once on first run). The PKCE code_verifier + OAuth `state`
for an in-flight login are held in a short-lived signed cookie too (nothing
server-side to garbage-collect), since this gate is a single Python process
and doesn't need a shared session store.

Required environment variables (set via the systemd unit's EnvironmentFile,
e.g. /etc/opa-secrets-wizard.env -- same file that already holds
KEYRING_UNLOCK_PASSWORD; this process exits immediately at import time if
any are missing, rather than silently pointing at a wrong/no org):
  OKTA_ORG_URL       e.g. https://your-org.oktapreview.com
  OKTA_OIDC_CLIENT_ID  the OIDC web app's client_id (not secret, but still
                       deployment-specific -- see "Register an OIDC
                       application" in the main README)
  DASHBOARD_ORIGIN   the public origin this dashboard is reachable at,
                     e.g. https://192.168.1.10 or https://opa.example.com
  OKTA_ADMIN_GROUP_ID  the Okta GROUP ID (not name) whose members get
                       admin/"see + manage every environment" rights in
                       the dashboard -- see "Admin access" in the main
                       README for how to create this group and find its
                       ID. A group ID (not name) is required specifically
                       so this check is one direct API call, not a
                       name-to-id lookup on every single login.
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
"""

import argparse
import base64
import hashlib
import hmac
import http.cookies
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from jwt import PyJWKClient

# Every value below is deployment-specific -- which Okta org, which OIDC
# app, which public origin this dashboard is reachable at -- so none of it
# is hardcoded here; it's a real requirement, not a secret, and belongs in
# each deployment's own config (this project's systemd unit sets it via
# EnvironmentFile=/etc/opa-secrets-wizard.env, same file that already holds
# KEYRING_UNLOCK_PASSWORD). No default is provided for any of these three --
# an operator MUST choose a real org/client/origin before this can run;
# guessing a value here would silently point at nothing (or worse, a wrong
# real org) rather than failing loudly and obviously at startup.
def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required (see server/auth_gate.py's docstring).")
    return value


OKTA_ORG_URL = _require_env("OKTA_ORG_URL")  # e.g. https://your-org.oktapreview.com
OKTA_ISSUER = f"{OKTA_ORG_URL}/oauth2/default"
OKTA_AUTHORIZE_URL = f"{OKTA_ISSUER}/v1/authorize"
OKTA_TOKEN_URL = f"{OKTA_ISSUER}/v1/token"
OKTA_JWKS_URL = f"{OKTA_ISSUER}/v1/keys"
OKTA_LOGOUT_URL = f"{OKTA_ISSUER}/v1/logout"
OKTA_CLIENT_ID = _require_env("OKTA_OIDC_CLIENT_ID")  # not secret, but still deployment-specific
OKTA_ADMIN_GROUP_ID = _require_env("OKTA_ADMIN_GROUP_ID")  # Okta group ID -- members get admin rights
OKTA_ENV_NAME = os.environ.get("OKTA_ENV_NAME", "default")  # keyring service suffix -- see create_secret_folders.py convention

DASHBOARD_ORIGIN = _require_env("DASHBOARD_ORIGIN")  # e.g. https://192.168.1.10 or https://opa-wizard.example.com
REDIRECT_URI = f"{DASHBOARD_ORIGIN}/authorization-code/callback"
POST_LOGOUT_REDIRECT_URI = f"{DASHBOARD_ORIGIN}/login"

SESSION_KEY_PATH = Path("/etc/opa-secrets-wizard-session.key")
SESSION_COOKIE = "opa_wizard_session"
FLOW_COOKIE = "opa_wizard_flow"
SESSION_TTL_SECONDS = 12 * 60 * 60  # 12h -- re-login once a workday
FLOW_TTL_SECONDS = 10 * 60  # 10 min is generous for "redirect to Okta and log in"


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
        "'<token>')`. See \"Admin access\" in the main README.",
    )


OKTA_CLIENT_SECRET = _load_client_secret()
OKTA_ADMIN_CHECK_TOKEN = _load_admin_check_token()
_JWKS_CLIENT = PyJWKClient(OKTA_JWKS_URL)


def _is_member_of_admin_group(user_sub: str) -> bool:
    """GET /api/v1/users/{id}/groups, checked once at login (see the module
    docstring for why this is a direct API call rather than a groups claim
    on the ID token) -- SSWS token auth, same scheme as
    create_secret_folders.py's OktaClient, but this file deliberately
    doesn't import that module (this is a standalone auth-gate process with
    its own minimal dependency footprint, not part of the dashboard app)."""
    url = f"{OKTA_ORG_URL}/api/v1/users/{urllib.parse.quote(user_sub, safe='')}/groups"
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {OKTA_ADMIN_CHECK_TOKEN}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            groups = json.loads(r.read())
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        # Fails closed -- a broken/expired admin-check token or a transient
        # Okta API error must never silently grant admin rights. Worst case,
        # a real admin's login gets treated as non-admin until this is
        # fixed, which is the safe direction for this failure to fall in.
        return False
    return any(g.get("id") == OKTA_ADMIN_GROUP_ID for g in groups)


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
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/login":
            self._start_login()
        elif path == "/authorization-code/callback":
            self._handle_callback(query)
        elif path == "/verify":
            self._verify_session()
        elif path == "/logout":
            self._logout()
        else:
            self.send_response(404)
            self.end_headers()

    def _start_login(self):
        verifier, challenge = _pkce_pair()
        state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
        flow_token = _sign_payload({"state": state, "verifier": verifier}, FLOW_TTL_SECONDS)

        params = {
            "client_id": OKTA_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
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

        # Checked once here, not on every request -- consistent with how
        # email/sub already work for the life of a session. A group
        # membership change takes effect on next login/session refresh
        # (SESSION_TTL_SECONDS), not instantly -- an accepted tradeoff of
        # this session model, not an oversight.
        is_admin = _is_member_of_admin_group(claims["sub"])

        session_token = _sign_payload(
            {"sub": claims["sub"], "email": claims.get("email"), "id_token": tokens["id_token"], "is_admin": is_admin},
            SESSION_TTL_SECONDS,
        )

        self.send_response(302)
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE, session_token, max_age=SESSION_TTL_SECONDS))
        self.send_header("Set-Cookie", _cookie_header(FLOW_COOKIE, "", max_age=0))
        self.send_header("Location", "/")
        self.end_headers()

    def _verify_session(self):
        token = _get_cookie(self.headers, SESSION_COOKIE)
        session = _verify_signed_payload(token) if token else None
        if session:
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
            self.end_headers()
        else:
            self.send_response(401)
            self.end_headers()

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
    print(f"Okta auth gate listening on 127.0.0.1:{args.port}, issuer={OKTA_ISSUER}")
    server.serve_forever()


if __name__ == "__main__":
    main()
