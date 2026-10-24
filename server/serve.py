"""
Local-only server for the OPA Compliance Wizard dashboard.

Serves frontend/dist/ as static files and exposes a small JSON API the React
app uses to: manage named environments (dev/uat/prod, metadata in SQLite via
audit_store.py and secrets in the OS keyring -- see create_secret_folders.py's
upsert_environment/keyring helpers, all imported as `engine` so nothing is
duplicated), list/create
resource groups, projects, and groups (the group-creation path goes through
Okta's core API + Group Push, never OPA's own local-group endpoint, by
design), load/save the folder-tree CSV, and run preview (dry-run) / execute
against the real OPA Secrets API.

Usage:
    python serve.py [--port 8766] [--no-browser]

Binds to 127.0.0.1 only - never reachable from other machines on the network.
No credentials are required to START this server -- if no environment is
configured yet (first boot), the dashboard UI itself prompts for one and
saves it via POST /api/environments.
"""

import argparse
import contextlib
import errno
import csv as _csv
import hashlib
import hmac
import io
import json
import re
import os
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, urlencode

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import create_secret_folders as engine  # noqa: E402
from server import refresh_jobs as rj  # noqa: E402
from server import evidence_jobs  # noqa: E402
from server.updater import service as update_service  # noqa: E402
from server.updater import upgrade as upgrade_service  # noqa: E402
from server.gate_config import SESSION_COOKIE  # noqa: E402

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
# 5.47.0: user-saved folder templates and execution records live with the data
# files when OPA_DATA_DIR is set (the /var/lib layout; the code directory is
# read-only to this process there). Unset = the project directory, as always.
EXPORT_MIN_FREE_BYTES = 256 * 1024 * 1024  # a report export is refused (507) below this much free space


def _free_bytes(path):
    import shutil
    return shutil.disk_usage(path).free


def _csv_dir():
    return Path(os.environ["OPA_DATA_DIR"]) if os.environ.get("OPA_DATA_DIR") else PROJECT_ROOT

# Real-world Group Push/SCIM propagation can take well over the old 7.5s
# window (5 x 1.5s) under load -- 20 x 1.5s = 30s gives real syncs more
# room before the UI falls back to the "still propagating, refresh" message.
GROUP_PUSH_PROPAGATION_RETRIES = 20
GROUP_PUSH_PROPAGATION_DELAY_SECS = 1.5

# Generous cap for this API's JSON bodies (the largest realistic payload is
# a CSV-derived folder tree with a few thousand rows) -- rejecting anything
# claiming to be bigger BEFORE reading it into memory is what actually
# matters here; see _read_json_body.
MAX_REQUEST_BODY_BYTES = 5 * 1024 * 1024

# This dashboard's own frontend origins: the Vite dev server (proxies /api
# to this server -- see frontend/vite.config.ts) and, in production, this
# same server's own origin once it starts serving frontend/dist directly.
# Requests with no Origin header at all (curl, scripts, same-process
# tooling) are allowed through, same as CORS itself only ever constraining
# browsers, never other HTTP clients.
DEV_FRONTEND_ORIGIN = "http://localhost:5173"

# When this app is reverse-proxied behind nginx on a real hostname/IP (see
# server/nginx-opa-secrets-wizard.conf), the browser's Origin header is that
# public origin (e.g. "https://192.168.1.10"), not 127.0.0.1/localhost --
# neither of which this app can know in advance, since it's set by whoever
# deploys it. EXTRA_ALLOWED_ORIGINS (comma-separated, e.g. in the systemd
# unit's EnvironmentFile) adds those without hardcoding a specific
# IP/hostname into source or touching local/direct-run behavior at all: if
# this is empty (the default, e.g. any local Windows/Mac/Linux run), the
# allowed-origins set is exactly what it always was.
EXTRA_ALLOWED_ORIGINS = {o.strip() for o in os.environ.get("EXTRA_ALLOWED_ORIGINS", "").split(",") if o.strip()}

# Shared with server/auth_gate.py via the SAME EnvironmentFile
# (/etc/opa-compliance-wizard.env) -- gates POST /api/audit_log/backfill_mfa
# (see that route below), which calls auth_gate.py's loopback-only
# GET /internal/mfa_log_lookup to backfill Okta MFA System Log
# corroboration for older access_control.update entries. Both sides no-op
# safely if this is unset: auth_gate.py's endpoint 404s, and this route
# below reports zero backfilled rather than erroring, so a hosted-only
# deployment that never configures this just sees "no new corroboration
# found" instead of a failure.
INTERNAL_API_SHARED_SECRET = os.environ.get("INTERNAL_API_SHARED_SECRET")
AUTH_GATE_INTERNAL_URL = "http://127.0.0.1:8767"

# SECURITY FIX (external review, 2026-09-30, flagged independently by
# multiple reviewers as the single most severe finding): this process
# binds 127.0.0.1:8766 and, before this fix, trusted X-Auth-Is-Admin/
# X-Auth-Sub UNCONDITIONALLY -- nothing verified a request actually
# transited nginx's auth_request flow (see nginx-opa-secrets-wizard.conf)
# rather than coming from any other local process on the same machine
# (or a hypothetical SSRF from some other local service) that simply set
# those headers directly. Confirmed exploitable: `curl
# http://127.0.0.1:8766/api/access_control/save -H "X-Auth-Is-Admin:
# true"` would have been treated identically to a real nginx-forwarded
# admin request, bypassing login, group checks, AND step-up MFA entirely.
#
# NGINX_PROXY_SECRET closes this: nginx is configured to set
# X-Nginx-Proxy-Secret on every request it proxies to this port (see the
# two `location` blocks in nginx-opa-secrets-wizard.conf that proxy to
# 8766 -- confirmed exactly two: `location /` and
# `location /api/access_control/save`), and _request_is_from_nginx below
# requires a match before ANY X-Auth-* header is trusted.
#
# Deliberately a SEPARATE secret from INTERNAL_API_SHARED_SECRET above --
# that one authenticates serve.py AS A CLIENT calling INTO auth_gate.py
# (a different direction, a different trust relationship); reusing the
# same value across two distinct authentication purposes is the kind of
# thing that turns "rotate one secret" into "rotate everything," and a
# leak of one no longer implies the other is compromised too.
#
# Optional (unset by default) so a fresh standalone/local-only run (no
# nginx in front at all -- this app's other explicit supported mode, see
# this file's own module docstring) is never blocked: with it unset,
# _request_is_from_nginx always returns True (nothing to check against),
# identical to today's behavior. This is REQUIRED, not optional, for any
# real hosted multi-user deployment -- see docs/hosting.md's "Hosting on
# a server" section.
NGINX_PROXY_SECRET = os.environ.get("NGINX_PROXY_SECRET")

# Fast-follow-redesign Phase 9: closes the "which trust model am I in"
# ambiguity above. NGINX_PROXY_SECRET being optional is the right call for
# not breaking standalone usage, but it means the SAME binary, with ONE
# missing environment variable, silently runs in a dramatically weaker
# trust mode with no error, no startup warning, nothing -- an easy
# misconfiguration to make exactly once, on exactly the deploy that
# matters, and never notice. DEPLOYMENT_MODE makes the intended trust
# model explicit instead of inferring it from whether NGINX_PROXY_SECRET
# happens to be set: in "hosted" mode, this process refuses to start at
# all without NGINX_PROXY_SECRET -- fails loudly at boot, not silently at
# the first spoofed request. "local" (the default) is byte-for-byte
# today's behavior; every existing standalone/CLI run is unaffected.
#
# An unrecognized value fails fast too, deliberately -- not a silent
# fallback to "local". A typo'd DEPLOYMENT_MODE=Hosted landing in the weak
# trust mode unnoticed would just be this exact failure mode moved up one
# level, which defeats the point of adding this check at all.
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "local")
if DEPLOYMENT_MODE not in ("local", "hosted"):
    raise RuntimeError(
        f"DEPLOYMENT_MODE must be 'local' or 'hosted', got {DEPLOYMENT_MODE!r} (see docs/hosting.md)."
    )
if DEPLOYMENT_MODE == "hosted" and not NGINX_PROXY_SECRET:
    raise RuntimeError(
        "DEPLOYMENT_MODE=hosted requires NGINX_PROXY_SECRET to be set -- refusing to start in a "
        "weakened trust mode. See docs/hosting.md."
    )

# Phase 3: how long a prepared access_control.json change (see
# /api/access_control/prepare) stays claimable before expiring unused.
# Must comfortably outlive the full round trip it has to survive: Okta's
# own flow cookie (auth_gate.py's FLOW_TTL_SECONDS, 10 min -- "redirect
# to Okta and log in") PLUS the step-up cookie's own window after return
# (STEPUP_TTL_SECONDS, 120s) -- 15 min gives real margin over both
# without leaving an abandoned pending action claimable indefinitely.
STEPUP_PREPARE_TTL_SECONDS = 15 * 60

# 5.42.0: every change made from the Environments area needs a fresh MFA
# challenge, by the SAME mechanism as the Access Control save above (no
# second step-up system).
# In hosted mode each of these routes checks the request, stores it as a
# pending action (audit_store.create_pending_admin_action, these types)
# and answers 202 {"step_up_required": true, "action_id": ...}; the browser
# goes through the gate's /step-up and comes back to
# POST /api/environment_changes/save -- its own nginx location with
# auth_request /verify_stepup, like /api/access_control/save -- which
# consumes the action (bound to the caller's sub, single use, expiring)
# and runs the stored request. Local mode has no Okta identity and no
# gate, so there the routes act at once, as before. Activating an
# environment, "Sync now" and read-only views are not configuration
# changes and are not gated.
ENV_CHANGE_ACTION_TYPES = (
    "environment.upsert", "environment.share", "environment.delete",
    "sync_schedule.update", "sync.reset_watermark", "sync.import_csv",
    "archive.purge", "shared_permissions.update", "upgrade.settings", "upgrade.request",
    # 5.53.0: the announcement banner is an org-wide message, so saving it needs a fresh MFA like the rest.
    "banner.update",
    # 5.53.0: opening Settings and Updates needs a fresh MFA; the approval only ever creates the unlock (see
    # SETTINGS_RENEWING_ACTION_TYPES for what may extend it).
    "settings.unlock",
    # 5.53.0: the evidence package build. Its approval starts one build and never touches the Settings unlock (it is not in
    # SETTINGS_RENEWING_ACTION_TYPES).
    "evidence_package.build",
)

# 5.53.0: how long a Settings/Updates unlock lasts after the MFA that opened it. An application constant that matches the
# identity provider's own 10-minute re-authentication policy by decision; it is not read from the provider (the step-up
# always forces a fresh sign-in, so the provider asks regardless).
SETTINGS_UNLOCK_TTL_SECONDS = 10 * 60

# 5.53.0: the action types whose completed approval renews the caller's Settings unlock, because they just passed a fresh
# MFA for the same user in the same session. An explicit tuple on purpose: a new action type never renews anything until it
# is added HERE deliberately. `settings.unlock` is not in it (it only creates the window) and neither is
# `evidence_package.build` (a build approval must never open or extend Settings). The first ten are the
# ENV_CHANGE_ACTION_TYPES of 5.52.0.
SETTINGS_RENEWING_ACTION_TYPES = (
    "environment.upsert", "environment.share", "environment.delete",
    "sync_schedule.update", "sync.reset_watermark", "sync.import_csv",
    "archive.purge", "shared_permissions.update", "upgrade.settings", "upgrade.request",
    "access_control.update", "banner.update",
)

# The environment form's two secrets never go into pending_admin_actions
# (credentials are never written to disk -- they live only in the OS
# keychain): they wait here, in this process's memory, for the same TTL,
# keyed by the action they belong to. A restart during the MFA round trip
# loses them, and the save then asks for them again instead of saving
# without them. Bounded so an authenticated caller can't grow it without
# limit by preparing and abandoning saves.
MAX_PENDING_ENV_SECRETS = 1024
# Open (unconsumed, unexpired) Environments approvals one user may have at
# once -- any authenticated user can prepare one, so this bounds what an
# abandoned-save loop can add to pending_admin_actions and to the secrets
# held above.
MAX_OPEN_ENV_CHANGES_PER_USER = 20
# The environment form's fields are the only ones stored for a save, each
# capped (a secret this long is not a real API key or token).
# 5.53.0: "evidence_builders" is the form's "Who can build evidence packages" choice: "owner" or "shared" (stored as the
# environment's build_evidence_package permission override).
ENV_FORM_FIELDS = ("id", "name", "base_domain", "team_name", "key_id", "okta_url", "key_secret", "okta_api_token", "evidence_builders")
MAX_ENV_FIELD_CHARS = 4096
_pending_env_secrets_lock = threading.Lock()
_pending_env_secrets = {}  # action_id -> (expires_monotonic, {field: value})
# Makes the per-user count and the insert of a new pending change one step.
_pending_env_changes_lock = threading.Lock()


def _remember_pending_secrets(action_id, secrets_by_field):
    now = time.monotonic()
    with _pending_env_secrets_lock:
        for key in [k for k, (expires, _v) in _pending_env_secrets.items() if expires < now]:
            _pending_env_secrets.pop(key, None)
        if len(_pending_env_secrets) >= MAX_PENDING_ENV_SECRETS:
            # Drop the oldest-expiring entry; its save will ask for the
            # secrets again rather than fail silently.
            oldest = min(_pending_env_secrets, key=lambda k: _pending_env_secrets[k][0])
            _pending_env_secrets.pop(oldest, None)
        _pending_env_secrets[action_id] = (now + STEPUP_PREPARE_TTL_SECONDS, dict(secrets_by_field))


def _take_pending_secrets(action_id):
    """The secrets stored for this action (removed), or None if they are
    gone (expired, or the process restarted)."""
    with _pending_env_secrets_lock:
        entry = _pending_env_secrets.pop(action_id, None)
    if entry is None or entry[0] < time.monotonic():
        return None
    return entry[1]


def _step_up_required_for_changes():
    """True when Environments changes need a step-up approval: behind the
    hosted login gate. Local mode has no identity provider to step up with."""
    return DEPLOYMENT_MODE == "hosted"


def _request_passed_stepup_location(headers):
    """The Environments save must have come through nginx's step-up
    location, not through `location /`. Only that location sets
    X-Nginx-Stepup-Location (to the proxy secret, which a browser never
    knows). Needed because an nginx site generated before 5.42.0 -- e.g. an
    additional gate's site, which deploy.sh does not regenerate -- has no
    such location: the request would fall through to `location /`, which
    passes a client-sent X-Auth-Action-Id straight to this process. With
    this check that site fails closed (the save is refused) instead."""
    if not NGINX_PROXY_SECRET:
        return False
    presented = headers.get("X-Nginx-Stepup-Location")
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented.encode("utf-8"), NGINX_PROXY_SECRET.encode("utf-8"))


NOTICE_RUN_FIELDS = ("correlation_id", "action", "version_from", "version_to", "step", "result", "reason_code", "failed_step",
                     "started_at", "updated_at", "seconds", "rolled_back_to", "step_started_at")
NOTICE_REVOCATION_FIELDS = ("serial", "issued_at", "applied_at", "reason", "advisory_url", "revoked", "added", "signed_by", "source")


def _notice_run(run):
    """The upgrade run as the notice shows it to administrators: progress only. The backup's file name, the steps' details and
    the failure text stay on the Updates page (behind the unlock)."""
    if not isinstance(run, dict):
        return None
    out = {k: run.get(k) for k in NOTICE_RUN_FIELDS}
    backup = run.get("backup")
    if isinstance(backup, dict):
        out["backup"] = {"size": backup.get("size"), "integrity": backup.get("integrity")}
    # 5.53.0: the step list and the health checks as progress only (names, times, pass or fail), so the Updates page can keep
    # showing the steps while its own status is locked or the server restarts. No step details, no check text.
    steps = run.get("steps_done")
    out["steps_done"] = [{"step": str(s.get("step"))[:40], "at": s.get("at"), "seconds": s.get("seconds")}
                         for s in steps[:20] if isinstance(s, dict)] if isinstance(steps, list) else None
    health = run.get("health")
    out["health"] = [{"id": str(h.get("id"))[:40], "ok": bool(h.get("ok"))}
                     for h in health[:20] if isinstance(h, dict)] if isinstance(health, list) else None
    return out


def _notice_revocation(rev):
    """The recent key revocation as the banner needs it, nothing else of the history entry."""
    if not isinstance(rev, dict):
        return None
    return {k: rev.get(k) for k in NOTICE_REVOCATION_FIELDS}


def _session_fingerprint(headers):
    """5.53.0: tells one login session from another for the Settings unlock. sha256 of the gate's opaque session cookie value
    (first 32 hex characters); this process never parses or trusts the cookie's content, it only hashes the string the gate
    minted. The session token is minted once per sign-in and not rotated, so the value is stable across the MFA round trip and
    changes at every sign-out and sign-in. Local mode has no gate and no cookie: "local". None in hosted mode when the cookie
    is absent or unreadable, which makes every unlock check fail closed."""
    if not _step_up_required_for_changes():
        return "local"
    raw = headers.get("Cookie")
    if not isinstance(raw, str) or not raw:
        return None
    import http.cookies
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(raw)
    except http.cookies.CookieError:
        return None
    morsel = jar.get(SESSION_COOKIE)
    if morsel is None or not morsel.value:
        return None
    return hashlib.sha256(morsel.value.encode("utf-8", "replace")).hexdigest()[:32]


LOCAL_MODE_NOTICE = (
    "No MFA in local mode. This computer runs the wizard without a login gate or identity provider, so Settings and "
    "Updates open without a second factor. Anyone who can use this computer as you can change these settings. Each "
    "opening is recorded in the Audit Log."
)
SETTINGS_AREAS = ("settings", "updates")
LOCAL_ACCESS_AUDIT_INTERVAL_SECONDS = 10 * 60
_local_access_logged = {}  # area -> time.monotonic() of the last audit entry in this process
_local_access_lock = threading.Lock()


def _local_access_due(area):
    """True at most once per area per 10 minutes per process (the first opening, then one line per window)."""
    now = time.monotonic()
    with _local_access_lock:
        last = _local_access_logged.get(area)
        if last is not None and now - last < LOCAL_ACCESS_AUDIT_INTERVAL_SECONDS:
            return False
        _local_access_logged[area] = now
        return True


def _shared_permission_message(capability):
    label = next((c["label"] for c in engine.SHARED_CAPABILITIES if c["key"] == capability), capability)
    return (f"Not allowed on this shared environment: {label}. Only its owner can do this unless an admin "
            "allows it for shared users (Shared permissions).")


def _request_is_from_nginx(headers):
    """True if NGINX_PROXY_SECRET is unset (nothing to check -- standalone/
    local-only mode, unchanged behavior) OR the request's
    X-Nginx-Proxy-Secret header matches it exactly. False otherwise --
    callers must then treat the request as unauthenticated/local
    (_owner_key_from_headers already maps a missing X-Auth-Sub to
    LOCAL_OWNER_KEY_HEADER; the real enforcement is in
    _is_admin_from_headers below, which now calls this first)."""
    if not NGINX_PROXY_SECRET:
        return True
    # GATE-08 (external review, 2026-10-05): constant-time compare -- this
    # secret is the whole trust boundary for every X-Auth-* header.
    presented = headers.get("X-Nginx-Proxy-Secret")
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented.encode("utf-8"), NGINX_PROXY_SECRET.encode("utf-8"))

# Per-owner session state, replacing what used to be three bare globals
# (client/okta_client/active_env_name) shared by every request regardless
# of who was asking. `owner_key` is the verified Okta `sub` from the
# X-Auth-Sub header nginx forwards once behind the auth gate (see
# server/nginx-opa-secrets-wizard.conf + server/auth_gate.py), or the
# literal string "__local__" when that header is absent -- i.e. a direct
# local run with no login gate in front of it at all. "__local__" is the
# ONE owner this dashboard has ever had before this change, so a request
# with no identity behaves byte-for-byte like it always did: one shared
# session, matching engine.LOCAL_OWNER_KEY's storage-layer meaning exactly.
LOCAL_OWNER_KEY_HEADER = "__local__"
_sessions_lock = threading.Lock()
_sessions = {}  # owner_key -> {"client": OpaClient, "okta_client": OktaClient|None, "env_name": str}
_seen_owners = set()  # tracks who's already had a lazy auto-activate attempt this process
_recorded_identities = set()  # 5.43.0: (issuer, sub, email) already written to known_identities today
_recorded_identities_day = [None]  # the UTC date _recorded_identities is for (cleared when it changes)


def _owner_key_from_headers(headers):
    # SECURITY: only trust X-Auth-Sub when it actually came via nginx (see
    # NGINX_PROXY_SECRET/_request_is_from_nginx above) -- otherwise a
    # request straight to this process's loopback port could impersonate
    # ANY specific user's owner_key (not just admin -- see
    # _is_admin_from_headers below for the sibling check), gaining access
    # to that user's own/shared environments. Falling back to
    # LOCAL_OWNER_KEY_HEADER here is safe: it's the same identity a
    # genuine no-headers-at-all local/CLI request already gets.
    if not _request_is_from_nginx(headers):
        return LOCAL_OWNER_KEY_HEADER
    return headers.get("X-Auth-Sub") or LOCAL_OWNER_KEY_HEADER


def _engine_owner(owner_key):
    """Maps an HTTP-layer owner_key back to what the engine's storage layer
    expects: LOCAL_OWNER_KEY (None) for the local sentinel, the real Okta
    sub otherwise."""
    return engine.LOCAL_OWNER_KEY if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key


def _issuer_from_headers(headers):
    """5.43.0: the Okta issuer of the login gate that authenticated this
    request (auth_gate.py's X-Auth-Issuer on /verify, forwarded by nginx) --
    trusted only when the request came through nginx, like X-Auth-Sub, AND
    carries X-Nginx-Issuer-Forwarded = the proxy secret, which only a
    5.43.0+ nginx site sets, in exactly the locations that also overwrite
    X-Auth-Issuer with the gate's value. An older site (an additional gate's
    site not yet regenerated, or the main site during a deploy) passes a
    client-sent X-Auth-Issuer through untouched, and would otherwise let any
    user claim another org. Only a gate-built shape is accepted. None
    otherwise (local mode has no proxy secret, so always None): then no
    per-user exception can match this caller, since a `sub` alone is only
    unique within one Okta org."""
    if not NGINX_PROXY_SECRET or not _request_is_from_nginx(headers):
        return None
    marker = headers.get("X-Nginx-Issuer-Forwarded")
    if not isinstance(marker, str) or not hmac.compare_digest(marker.encode("utf-8"), NGINX_PROXY_SECRET.encode("utf-8")):
        return None
    issuer = headers.get("X-Auth-Issuer")
    return issuer if isinstance(issuer, str) and engine.SHARED_GRANT_ISSUER_PATTERN.fullmatch(issuer) else None


def _reject_ambiguous_api_path(handler, path):
    """5.43.0 (SP-5 review): refuses an /api/ path with a "." or ".."
    segment (also percent-encoded). nginx resolves those before matching
    its locations and checks, while this server routes on the raw path, so
    the two would disagree about which route a request is -- e.g. an
    additional gate's site refusing DELETE /api/environments/<name>?purge...
    sees /api/environments/..?id=... as /api/. No route of this app has
    such a segment."""
    if not path.startswith("/api/"):
        return False
    if any(unquote(segment) in (".", "..") for segment in path.split("/")):
        handler._send_json(400, {"error": "Invalid path."})
        return True
    return False


# The two routes reachable without the nginx proxy secret in hosted mode
# (see _reject_if_hosted_without_nginx's docstring for why each is safe).
UNAUTHENTICATED_PATHS = frozenset({"/healthz", "/api/version"})


def _reject_if_hosted_without_nginx(handler, path):
    """SECURITY FIX (external review, 2026-10-05, SRV-01): in hosted mode, a
    request that fails the nginx proxy-secret check used to be silently
    DOWNGRADED to the privileged `__local__` owner (see
    _owner_key_from_headers above) instead of being rejected outright --
    and every admin-only route's guard is `owner_key != LOCAL_OWNER_KEY_HEADER
    and not is_admin`, so `__local__` sails straight through as the exempt
    local operator. Combined with GATE-01 (auth_gate.py accepting any
    gate-signed cookie as a session), this was reachable from the network
    with no Okta account at all -- confirmed live in production: a replayed
    flow cookie against `GET /api/audit_log` returned 200.

    DEPLOYMENT_MODE == "hosted" means this process REQUIRES a real nginx +
    Okta gate in front of it (enforced at startup -- see the
    NGINX_PROXY_SECRET check above); a request that didn't actually transit
    that flow is UNAUTHENTICATED, not local, and must be rejected before any
    routing happens -- never silently treated as the local super-owner.
    `local` mode (the default, no nginx at all) is completely unaffected:
    _request_is_from_nginx always returns True when NGINX_PROXY_SECRET is
    unset, so this never fires there.

    `/healthz` and `/api/version` are the two deliberate exceptions.
    `/healthz`'s nginx location has `auth_request off` and -- unlike every
    other location -- never sets X-Nginx-Proxy-Secret either (see
    nginx-opa-secrets-wizard.conf), since it exists for an external uptime
    monitor/load balancer with no Okta session to present. `/api/version`
    is `deploy.sh`'s own restart-confirmation check (see that script's
    `_live_version` curl): it deliberately calls `http://127.0.0.1:8766`
    directly, bypassing nginx entirely, specifically to prove serve.py
    itself came back up after a restart -- requiring the proxy secret
    there would make every deploy fail this exact guard. Both routes
    return only a version string / non-tenant health summary, no admin
    check, no owner-scoped data -- staying reachable here costs nothing."""
    if _hosted_request_unauthenticated(handler.headers, path):
        handler._send_json(401, {"error": "Authentication required."})
        return True
    return False


def _hosted_request_unauthenticated(headers, path):
    """The hosted-mode authentication test shared by every method handler
    (GET/POST/DELETE, and HEAD, which answers without a body).

    Defense in depth (5.40.3): a request that DID transit nginx but carries
    no verified identity (X-Auth-Sub empty -- e.g. a gate bug returning 2xx
    without the header) would otherwise also map to the exempt `__local__`
    owner. In hosted mode no real request is identity-less, so both shapes
    are rejected the same way."""
    if DEPLOYMENT_MODE != "hosted" or path in UNAUTHENTICATED_PATHS:
        return False
    return not _request_is_from_nginx(headers) or not headers.get("X-Auth-Sub")


def _can_admin(owner_key, headers):
    """The ONE admin predicate every admin-only route uses (it was copied
    into ten routes as `owner_key != LOCAL_OWNER_KEY_HEADER and not
    _is_admin_from_headers(...)`). True for a verified admin (auth_gate.py's
    X-Auth-Is-Admin via nginx), or for the local operator of a local-mode
    run (no login gate exists there; that operator already sees every
    environment it owns -- see the /api/audit_log route). The local
    exemption never applies in hosted mode, whatever owner_key a request
    resolves to. Also exposed to the frontend as /api/whoami's
    `can_admin` (UI-06), so the UI shows exactly what the server allows."""
    if _is_admin_from_headers(headers):
        return True
    return DEPLOYMENT_MODE == "local" and owner_key == LOCAL_OWNER_KEY_HEADER


def _is_admin_from_headers(headers):
    """True only when auth_gate.py's verified /verify subrequest set
    X-Auth-Is-Admin: true (see nginx-opa-secrets-wizard.conf) -- a direct/
    local run (no login gate in front at all) has no such header and is
    never treated as admin, since local mode already sees/manages every
    environment unscoped anyway (see list_environments_for's LOCAL_OWNER_KEY
    handling); there's nothing further an admin flag would unlock there.

    SECURITY FIX (external review, 2026-09-30): previously trusted
    X-Auth-Is-Admin UNCONDITIONALLY -- confirmed exploitable, see
    NGINX_PROXY_SECRET's module-level comment above for the full
    exploit shape. Now requires _request_is_from_nginx(headers) first --
    a request that skipped nginx (or nginx itself hasn't been configured
    with the matching secret yet) can never be treated as admin,
    regardless of what X-Auth-Is-Admin claims."""
    if not _request_is_from_nginx(headers):
        return False
    return headers.get("X-Auth-Is-Admin") == "true"


def _lookup_mfa_log_event(actor_sub, near_iso_timestamp):
    """The `lookup_fn` engine.backfill_mfa_log_events expects (see that
    function's docstring for why the actual Okta call is injected rather
    than made by create_secret_folders.py directly) -- calls
    auth_gate.py's loopback-only GET /internal/mfa_log_lookup.

    Returns the event dict, or None when the gate answered "no matching
    event". Raises engine.MfaLookupUnavailable when it could not ask at all
    (secret not configured, gate unreachable, timeout, non-200, bad body)
    -- ENG1-05 follow-up: those used to look identical to "not found", so a
    gate outage or a few quick Refresh clicks would use up an entry's
    lookup attempts for good. The backfill still never errors out over it:
    it stops and keeps what it already found."""
    if not INTERNAL_API_SHARED_SECRET:
        raise engine.MfaLookupUnavailable("INTERNAL_API_SHARED_SECRET is not configured")
    params = urlencode({"sub": actor_sub, "near": near_iso_timestamp})
    url = f"{AUTH_GATE_INTERNAL_URL}/internal/mfa_log_lookup?{params}"
    req = urllib.request.Request(url, headers={"X-Internal-Secret": INTERNAL_API_SHARED_SECRET})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            result = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (401, 403, 404):
            # The gate refused THIS entry's parameters -- skip it (counted),
            # don't stop the run for every other entry.
            raise engine.MfaLookupEntryRejected(f"HTTP {exc.code}") from exc
        raise engine.MfaLookupUnavailable(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise engine.MfaLookupUnavailable(f"{type(exc).__name__}: {exc}") from exc
    return result if isinstance(result, dict) else None


def _drop_sessions_for_environment(environment_id, except_owner=None, reactivate=False):
    """ENG1-06 (external review, 2026-10-05): "unshare", admin edit and
    delete used to leave every OTHER owner's already-activated session on
    that environment alive -- its cached OpaClient (key id/secret and a
    bearer token in memory, able to re-mint on 401) kept working until the
    process restarted, so withdrawing access took effect only at the next
    deploy. Drops every session whose env_id matches; those owners get the
    ordinary "No active environment" 409 on their next call and must
    activate something they are still allowed to see.

    reactivate=True (an EDIT, not a withdrawal -- 5.40.3) also forgets that
    those owners were seen this process, so their next request re-runs
    _try_activate_saved_environment: exactly what a restart would do. It
    re-resolves visibility and credentials from storage, so they reconnect
    with the new credentials (or get the 409 if no longer allowed)."""
    with _sessions_lock:
        for key in [k for k, s in _sessions.items() if s.get("env_id") == environment_id and k != except_owner]:
            _sessions.pop(key, None)
            if reactivate:
                _seen_owners.discard(key)


def _ingest_running(environment_id):
    """True while a sync OR a CSV import holds this environment's ingest
    slot (DATA-11: the two must never interleave writes, and a purge must
    not race either)."""
    with _sync_jobs_lock:
        if _sync_jobs.get(environment_id, {}).get("status") == "running":
            return True
    return _refresh_running(environment_id)  # 5.51.0: a refresh job in flight owns the archive too


def _session_snapshot(owner_key):
    """Returns (client, okta_client, env_name, env_id) for this owner, all
    None if they have no active session yet. Snapshotting a dict lookup
    under the lock, same spirit as the pre-existing single-global snapshot
    pattern: a concurrent switch/delete for the SAME owner must not affect
    a request already in flight for that owner.

    `env_id` (added for Phase 1's UUID migration) is this owner's active
    environment's real, stable `environment_id`, resolved ONCE at
    activation time (see activate_environment) rather than recomputed per
    route -- every route below that needs to key _access_jobs/_sync_jobs
    by something unambiguous reads this directly instead of calling
    engine.environment_storage_name (removed; see
    docs/fast-follow-redesign.md's Phase 1)."""
    with _sessions_lock:
        session = _sessions.get(owner_key)
    if session is None:
        return None, None, None, None
    return session["client"], session["okta_client"], session["env_name"], session["env_id"]

# Access Explorer bootstrap job -- build_access_model takes real time
# (~30s+ on a tenant with data), so it runs in a background thread and the
# frontend polls _access_jobs' status instead of holding one HTTP request
# open the whole time.
#
# SECURITY FIX (external review, 2026-09-30): this used to be a single
# GLOBAL job/result with no owner or environment key at all -- confirmed
# exploitable: User A starts a bootstrap against Tenant A, User B (with
# Tenant B active, or even no environment configured) polls
# /api/access/bootstrap/result and gets User A's tenant's access model
# verbatim. Now keyed by the requester's own ACTIVE environment's real,
# stable `environment_id` (resolved once at activation time -- see
# activate_environment/_session_snapshot) -- a second start while THAT
# SAME owner+environment's job is already running is still a no-op
# (unchanged behavior for the one case that matters), but a different
# owner, or the same owner on a different environment, always gets their
# own separate job/result, never someone else's.
_access_jobs_lock = threading.Lock()
_access_jobs = {}  # environment_id -> {"status": ..., "steps": [...], "error": str|None, "result": ...}


def _access_job_progress(storage_name):
    def _progress(key, status, detail=None):
        with _access_jobs_lock:
            _access_jobs.setdefault(storage_name, {"status": "running", "steps": [], "error": None, "result": None})
            _access_jobs[storage_name]["steps"].append({"key": key, "status": status, "detail": detail})
    return _progress


def _failure_summary(exc):
    """What an audit entry says about a failed background call: the error class and, for an OPA or Okta call, its HTTP status or
    kind. Never the message, which carries the request URL (the OPA team name, the Okta org host) and part of the response body."""
    status = getattr(exc, "status", None)
    return f"{type(exc).__name__}: {status}" if status is not None else type(exc).__name__


def _job_error_message(exc):
    """SRV-03 for background jobs (their error is returned by the status
    routes): an upstream OPA/Okta error or a deliberate ValueError (e.g. the
    DATA-03 "unusable watermark" message) is the user's own, actionable
    information and is kept; anything else is replaced by a generic message
    with the job's correlation id, and the detail is logged."""
    if isinstance(exc, (engine.OpaApiError, engine.OktaApiError, ValueError, engine.CredentialStoreUnavailable)) and not isinstance(
        exc, (UnicodeError, json.JSONDecodeError)  # these quote fragments of the input they choked on
    ):
        return str(exc)
    correlation_id = engine.CORRELATION_ID.get()
    engine.log("ERROR", f"Background job failed with {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
    return f"Internal error (reference {correlation_id}). The details are in the server log."


def _failed_step(steps):
    """The step that was started and never finished (the one a failed scan stopped in), or None."""
    current = None
    for step in steps or []:
        if step.get("status") == "start":
            current = step.get("key")
        elif step.get("status") == "done" and step.get("key") == current:
            current = None
    return current


def _utc_now_ms_iso():
    import audit_store
    return audit_store._iso_ms(datetime.now(timezone.utc))


def _audit_for(audit_ctx, action, details):
    """One counts-only audit entry for a background job; a no-op without context (a test calling the job body directly)."""
    if not audit_ctx:
        return
    engine.log_audit_event(audit_ctx.get("actor_email"), audit_ctx.get("actor_sub"), action,
                           {"name": audit_ctx.get("name"), "trigger": audit_ctx.get("trigger"), **details},
                           client_ip=audit_ctx.get("client_ip"), user_agent=audit_ctx.get("user_agent"))


def _seal_access_state(environment_id, model, built_at, audit_ctx):
    """The daily sealed OPA access state (phase B), taken from the scan just read: no extra OPA or Okta call. One a day (20 hours apart);
    a failure here never fails the scan, it is reported and audited. Returns {"state": "sealed"|"not_due"|"error", ...}."""
    import opa_access_state
    try:
        snap = opa_access_state.capture_if_due(environment_id, model, built_at=built_at)
    except Exception as exc:
        engine.log("WARN", f"Today's OPA access state could not be sealed ({type(exc).__name__}); the scan itself is kept.")
        _audit_for(audit_ctx, "okta_snapshot.failed", {"kind": opa_access_state.KIND, "error": _failure_summary(exc)})
        return {"state": "error", "error": _failure_summary(exc)}
    if snap is None:
        return {"state": "not_due"}
    _audit_for(audit_ctx, "okta_snapshot.captured", {"kind": opa_access_state.KIND, "snapshot_id": snap["snapshot_id"], "status": snap["status"],
                                                      "item_count": snap["item_count"], "trigger": (audit_ctx or {}).get("snapshot_trigger") or (audit_ctx or {}).get("trigger")})
    return {"state": "sealed", "snapshot_id": snap["snapshot_id"], "items": snap["item_count"]}


def _run_access_job(storage_name, job_client, job_okta_client, correlation_id=None, audit_ctx=None):
    """The OPA scan: build the model, strip it for storage (a credential-shaped value fails the scan and nothing is
    stored), replace the stored scan, and publish the result to _access_jobs. The previous result stays readable
    (`previous`) while this one runs and after it fails. Runs in the caller's thread, which may carry a cancel flag."""
    # A new thread does NOT inherit the parent thread's contextvars, so
    # the triggering request's own id (if any) has to be set again here
    # explicitly -- same reasoning as _run_sync_job below.
    engine.CORRELATION_ID.set(correlation_id)
    import audit_store
    started = time.monotonic()
    try:
        result = engine.build_access_model(
            job_client, okta_client=job_okta_client, on_progress=_access_job_progress(storage_name)
        )
        built_at = _utc_now_ms_iso()
        duration = round(time.monotonic() - started, 1)
        engine.checkpoint()  # a stop (or a deadline) that arrived while the last call ran: nothing is stored
        redacted, redacted_paths = engine.redact_model_for_storage_report(result)
        if redacted_paths:  # values under name fields that looked like credentials were replaced: say where (key paths only), never what
            _audit_for(audit_ctx, "access_scan.redacted", {"count": len(redacted_paths), "key_paths": redacted_paths[:20]})
        del result
        stored, store_problem = "memory_only", None
        try:
            put = audit_store.store_opa_model_cache(
                storage_name, redacted, built_at=built_at, duration_seconds=duration, already_redacted=True)
            if put["stored"]:
                stored = "cache"
            else:
                store_problem = put["reason"]
        except Exception as store_exc:  # the scan is still good in memory: say so rather than fail it
            store_problem = type(store_exc).__name__
            engine.log("WARN", f"The OPA scan could not be stored ({store_problem}); it stays in memory until the next scan.")
        counts = audit_store.opa_model_counts(redacted)
        warnings = _unreadable_sections(redacted)  # sections the key cannot read; values hidden under name fields are counted apart (hidden)
        hidden = len(redacted_paths)
        snapshot = _seal_access_state(storage_name, redacted, built_at, audit_ctx)
        with _access_jobs_lock:
            job = _access_jobs.setdefault(storage_name, {"status": "running", "steps": [], "error": None, "result": None})
            job.update(status="done", result=redacted, result_at=built_at, error=None, error_kind=None, source="scan",
                       stored=stored, store_problem=store_problem, duration_seconds=duration, warnings=warnings,
                       counts=counts, previous=None, snapshot=snapshot, hidden=hidden)
        _audit_for(audit_ctx, "access_scan.completed", {"seconds": duration, **counts, "warnings": warnings, "stored": stored,
                                                        **({"snapshot_id": snapshot["snapshot_id"]} if snapshot.get("snapshot_id") else {})})
    except engine.JobCancelled:
        _record_access_failure(storage_name, "The scan was stopped before it finished.", "cancelled", None, audit_ctx, None)
        _audit_for(audit_ctx, "access_scan.failed", {"reason": "cancelled"})
    except engine.ModelRedactionError as exc:
        _record_access_failure(storage_name, str(exc), "redaction", None, audit_ctx, exc)
        _audit_for(audit_ctx, "access_scan.failed", {"error": _failure_summary(exc), "reason": "redaction", "key_path": exc.key_path})
    except Exception as exc:
        status = getattr(exc, "status", None)
        kind = "refused" if isinstance(exc, engine.OpaApiError) and status in (401, 403) else "error"
        _record_access_failure(storage_name, _job_error_message(exc), kind, status, audit_ctx, exc)
        _audit_for(audit_ctx, "access_scan.failed", {"error": _failure_summary(exc)})


def _record_access_failure(storage_name, message, kind, status, audit_ctx, exc):
    with _access_jobs_lock:
        job = _access_jobs.setdefault(storage_name, {"status": "running", "steps": [], "error": None, "result": None})
        job.update(status="error", error=message, error_kind=kind, error_status=status, failed_step=_failed_step(job.get("steps")),
                   error_class=_failure_summary(exc) if exc is not None else None,
                   key_path=getattr(exc, "key_path", None))


def _scan_slot_previous(job):
    """What to keep readable while a new scan replaces `job` (an _access_jobs entry, or None)."""
    if not job:
        return None
    if job.get("status") == "done" and isinstance(job.get("result"), dict):
        return {"result": job["result"], "result_at": job.get("result_at"), "source": job.get("source") or "memory",
                "modified_at": job.get("modified_at"), "stored": job.get("stored")}
    return job.get("previous")


def _access_model_view(environment_id, hydrate=True):
    """The OPA model to show for this environment, from memory (the last finished scan, or the one kept while a new scan runs
    or after one failed), else the stored scan. {"model", "built_at", "source": "memory"|"cache", "modified_at"} or None."""
    import audit_store
    with _access_jobs_lock:
        job = _access_jobs.get(environment_id)
        if job:
            held = _scan_slot_previous(job)
            if held and isinstance(held.get("result"), dict):
                return {"model": held["result"], "built_at": held.get("result_at"),
                        "source": "cache" if held.get("source") == "cache" else "memory", "modified_at": held.get("modified_at")}
    if not hydrate:
        return None
    try:
        cached = audit_store.load_opa_model_cache(environment_id)
    except Exception as exc:
        engine.log("WARN", f"The stored OPA scan could not be read ({type(exc).__name__}).")
        cached = None
    if cached is None:
        return None
    held = {"result": cached["model"], "result_at": cached["built_at"], "source": "cache", "modified_at": cached.get("modified_at"), "stored": "cache"}
    with _access_jobs_lock:
        job = _access_jobs.get(environment_id)
        if job is None:
            _access_jobs[environment_id] = {"status": "done", "steps": [], "error": None, **held, "previous": None}
        elif _scan_slot_previous(job) is None:
            job["previous"] = held
    return {"model": cached["model"], "built_at": cached["built_at"], "source": "cache", "modified_at": cached.get("modified_at")}


def _patch_scan_member_removed(environment_id, group_id, user_name):
    """After a user is removed from a group in OPA, applies the same change to the scan the Access Explorer shows (memory) and
    to the stored scan, and records when it was edited ("edited since the scan"). Best effort: the removal itself already
    happened in OPA, so a failure here is logged and the next scan corrects it. Returns True when a scan was patched."""
    import audit_store
    patched = False
    stamp = _utc_now_iso()
    with _access_jobs_lock:
        job = _access_jobs.get(environment_id)
        held = _scan_slot_previous(job) if job else None
        model = job.get("result") if job and isinstance(job.get("result"), dict) else (held or {}).get("result")
        if isinstance(model, dict):
            for user in model.get("users") or []:
                if isinstance(user, dict) and user.get("name") == user_name and isinstance(user.get("groups"), list):
                    user["groups"] = [g for g in user["groups"] if not (isinstance(g, dict) and g.get("id") == group_id)]
                    patched = True
            if patched:
                for slot in (job, job.get("previous") if job else None):
                    if isinstance(slot, dict):
                        slot["modified_at"] = stamp
    try:
        if patched:
            audit_store.update_opa_model_cache(environment_id, model, modified_at=stamp)
        else:
            cached = audit_store.load_opa_model_cache(environment_id)
            if cached is not None:
                for user in cached["model"].get("users") or []:
                    if isinstance(user, dict) and user.get("name") == user_name and isinstance(user.get("groups"), list):
                        user["groups"] = [g for g in user["groups"] if not (isinstance(g, dict) and g.get("id") == group_id)]
                        patched = True
                if patched:
                    audit_store.update_opa_model_cache(environment_id, cached["model"], modified_at=stamp)
    except Exception as exc:
        engine.log("WARN", f"The stored OPA scan could not be updated after a group change ({type(exc).__name__}); the next scan corrects it.")
    return patched


# ENG2-05: wizard writes to one security policy are serialised (see the
# policy route). Keyed by (environment_id, policy_id); the dict only ever
# holds one small lock per policy the wizard has written to.
POLICY_WRITE_ATTEMPTS = 3  # a 429 on the policy PUT: wait, re-read, re-compare, retry
_policy_write_locks_guard = threading.Lock()
_policy_write_locks = {}


def _policy_write_lock(environment_id, policy_id):
    with _policy_write_locks_guard:
        return _policy_write_locks.setdefault((environment_id, policy_id), threading.Lock())


# Deep evidence-chain verification (5.40.6). A deep check re-reads and
# re-hashes every sealed curated event, and curated rows are never pruned,
# so its cost grows with the archive for ever (~8-20 s per million sealed
# rows measured for 5.40.4). Run inside one request it would eventually
# outlive nginx's 60 s proxy_read_timeout -- a 504 for the caller while the
# thread keeps working, and every retry stacking another CPU-bound pass.
# So: one verify per environment at a time, in a background thread. A
# request waits up to DEEP_VERIFY_WAIT_SECS for it; a check that finishes in
# time is answered exactly as before (200 + the verifier's result). A
# longer one answers 202 {"status": "running"}, and the caller polls the
# same URL; a finished result stays available to polls for
# DEEP_VERIFY_RESULT_TTL_SECS (with checked_at), after which the next
# request starts a fresh check. A FAILED check is handed to the next
# request once (within DEEP_VERIFY_ERROR_TTL_SECS) as a 500 -- so a poller
# always learns about it and stops -- and the request after that retries.
# The verifier itself is unchanged.
DEEP_VERIFY_WAIT_SECS = 20
DEEP_VERIFY_RESULT_TTL_SECS = 120
DEEP_VERIFY_ERROR_TTL_SECS = 30
# ---------------------------------------------------------------------------
# 5.53.0: evidence package builds. State and folder clean-up are in server/evidence_jobs.py, the zip is built by
# evidence_package.py; this is the glue: who may build (checked again when the job starts, on every status read and on
# every download), the worker thread, and the build log (audit log + journal).
# ---------------------------------------------------------------------------
_evidence = evidence_jobs.Registry(lambda: os.path.join(engine._data_dir(), "packages"))
EVIDENCE_CAPABILITIES = ("view_archive", "build_evidence_package")
EVIDENCE_STREAM_CHUNK = 1024 * 1024
# The coverage check reads the archive (one count per event type, one pass over the period's days): at most this many at once
# on the whole server, so a person with the permission cannot keep the archive busy by pressing the button; the rest are told to retry.
EVIDENCE_CHECKS_AT_ONCE = 2
_evidence_checks = threading.BoundedSemaphore(EVIDENCE_CHECKS_AT_ONCE)


# A full disk, an exhausted quota or a file over the filesystem's limit all end a build the same way (EDQUOT is absent on Windows).
_DISK_FULL_ERRNOS = tuple(getattr(errno, n) for n in ("ENOSPC", "EDQUOT", "EFBIG") if hasattr(errno, n))


def _evidence_caller_refusal(environment_id, engine_owner, issuer):
    """None when this caller may still build and read packages of the environment, else (status, body): 404 when the
    environment is gone, 403 for a withdrawn permission (shared-environment capabilities, owner always passes)."""
    exists, _owner = engine.environment_owner(environment_id)
    # Visibility first (a private environment of someone else, or one unshared since, is "gone" for this caller), then the capabilities.
    if not exists or not any(m.get("environment_id") == environment_id for m in engine.list_environments_for(engine_owner).values()):
        return 404, {"error": "The environment this package was built from no longer exists or is no longer shared with you."}
    for capability in EVIDENCE_CAPABILITIES:
        if not engine.shared_capability_allowed(environment_id, engine_owner, capability, caller_issuer=issuer):
            return 403, {"error": _shared_permission_message(capability), "reason": "shared_permission_denied", "capability": capability}
    return None


def _evidence_log(ctx, action, details, level="INFO"):
    """The build log: one audit-log entry and one journal line. Never row content."""
    entry = dict(details)
    entry.setdefault("job_id", ctx.get("job_id"))
    if ctx.get("issuer"):
        entry["actor_issuer"] = ctx["issuer"]
    engine.log_audit_event(ctx.get("actor_email"), ctx.get("actor_sub"), action, entry,
                           client_ip=ctx.get("client_ip"), user_agent=ctx.get("user_agent"))
    journal = {k: entry.get(k) for k in ("job_id", "environment_id", "period", "gaps_acknowledged", "outcome", "reason", "mode", "events",
                                         "report_rows", "bytes", "sha256", "chain_head", "seconds")}
    journal["actor_sub"] = ctx.get("actor_sub")
    journal["client_ip"] = ctx.get("client_ip")
    engine.log(level, action + " " + json.dumps({k: v for k, v in journal.items() if v is not None}, separators=(",", ":")))


def _run_evidence_build(job_id, ctx):
    """The worker thread of one build. Re-checks the caller's permission first, builds, and records the outcome."""
    engine.CORRELATION_ID.set(ctx.get("correlation_id"))
    import evidence_core
    import evidence_package
    started = time.monotonic()
    base = {"environment": ctx["environment_name"], "environment_id": ctx["environment_id"], "period": ctx["period"],
            "gaps_acknowledged": ctx["gaps_acknowledged"], "mode": ctx["mode"]}
    try:
        refusal = _evidence_caller_refusal(ctx["environment_id"], ctx["engine_owner"], ctx.get("issuer"))
        if refusal:
            _evidence.fail(job_id, "permission_withdrawn", refusal[1]["error"])
            _evidence_log(ctx, "evidence_package.build_failed", {**base, "outcome": "refused", "reason": "permission_withdrawn"}, "WARN")
            return
        period = evidence_core.parse_period(ctx["period"]["start"], ctx["period"]["end"])
        result = evidence_package.build_package(
            _evidence.package_path(job_id), ctx["environment_id"], ctx["environment_name"], period,
            builder=ctx.get("builder") or "unknown", app_version=engine.SCRIPT_VERSION, gaps_acknowledged=ctx["gaps_acknowledged"],
            progress=lambda stage, fraction: _evidence.progress(job_id, stage, fraction),
            prune_records=evidence_core.prune_records_from_audit_log(ctx["environment_name"]))
        filename = evidence_package.download_filename(ctx["environment_name"], period, result["built_at"])
        _evidence.finish(job_id, result, filename)
        _evidence_log(ctx, "evidence_package.build_finished", {
            **base, "outcome": "finished", "events": result["events"], "report_rows": result["report_rows"], "bytes": result["bytes"],
            "sha256": result["sha256"], "chain_head": result["chain_head"], "seconds": round(time.monotonic() - started, 1),
            "gap_days": result["gap_days"], "zero_days": result["zero_days"], "pruned_days": result["pruned_days"],
            "coverage_pct": result["coverage_pct"], "files": result["files"]})
    except evidence_package.PackageError as exc:
        _evidence.fail(job_id, exc.reason, str(exc))
        _evidence_log(ctx, "evidence_package.build_failed", {**base, "outcome": "refused" if exc.reason in (
            "no_coverage", "gaps_unacknowledged") else "failed", "reason": exc.reason, "seconds": round(time.monotonic() - started, 1)}, "WARN")
    except OSError as exc:
        if exc.errno not in _DISK_FULL_ERRNOS:
            engine.log("ERROR", f"Evidence package build {job_id[:6]} failed with {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            _evidence.fail(job_id, "internal", "The package could not be built because of an internal error. The details are in the server log.")
            _evidence_log(ctx, "evidence_package.build_failed", {**base, "outcome": "failed", "reason": "internal",
                                                                  "seconds": round(time.monotonic() - started, 1)}, "ERROR")
            return
        # the disk, the quota or the file size limit was hit while writing (a sync running at the same time can use the space the check saw): the partial file is removed
        _evidence.fail(job_id, "disk_space", "The disk ran out of space (or a quota was reached) while the package was being written. Free some space (or choose a shorter period) and try again.")
        _evidence_log(ctx, "evidence_package.build_failed", {**base, "outcome": "failed", "reason": "disk_space",
                                                              "seconds": round(time.monotonic() - started, 1)}, "WARN")
    except Exception as exc:  # the person sees a generic sentence; the detail stays in the server log
        engine.log("ERROR", f"Evidence package build {job_id[:6]} failed with {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        _evidence.fail(job_id, "internal", "The package could not be built because of an internal error. The details are in the server log.")
        _evidence_log(ctx, "evidence_package.build_failed", {**base, "outcome": "failed", "reason": "internal",
                                                              "seconds": round(time.monotonic() - started, 1)}, "ERROR")


_deep_verify_lock = threading.Lock()
_deep_verify_jobs = {}  # environment_id -> {"status", "started_at", "checked_at", "finished_mono", "result", "error", "event"}


def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _run_deep_verify(environment_id, job, correlation_id):
    engine.CORRELATION_ID.set(correlation_id)
    import audit_store
    try:
        with _sync_jobs_lock:
            syncing = (_sync_jobs.get(environment_id) or {}).get("status") == "running"
        # a sync running right now has events it has not sealed yet (it seals once, at its end): pending, not a break
        result, error = audit_store.verify_ingestion_chain(environment_id, deep=True, **({"sync_in_progress": True} if syncing else {})), None
    except Exception as exc:
        result, error = None, _job_error_message(exc)
    with _deep_verify_lock:
        job.update({
            "status": "error" if error else "done", "result": result, "error": error,
            "checked_at": _utc_now_iso(), "finished_mono": time.monotonic(),
        })
    job["event"].set()


def _deep_verify(environment_id, wait_secs=None):
    """Returns (http_status, body) for GET .../integrity?deep=1 -- see the
    comment above DEEP_VERIFY_WAIT_SECS."""
    wait_secs = DEEP_VERIFY_WAIT_SECS if wait_secs is None else wait_secs
    with _deep_verify_lock:
        job = _deep_verify_jobs.get(environment_id)
        age = None if job is None or job["finished_mono"] is None else time.monotonic() - job["finished_mono"]
        fresh = job is not None and (
            (job["status"] == "done" and age < DEEP_VERIFY_RESULT_TTL_SECS)
            # A failure not yet seen by anyone (it finished after the
            # request that started it stopped waiting) is reported once.
            or (job["status"] == "error" and not job.get("error_delivered") and age < DEEP_VERIFY_ERROR_TTL_SECS)
        )
        if job is None or (job["status"] != "running" and not fresh):
            job = {
                "status": "running", "started_at": _utc_now_iso(), "checked_at": None, "finished_mono": None,
                "result": None, "error": None, "event": threading.Event(),
            }
            _deep_verify_jobs[environment_id] = job
            try:
                threading.Thread(
                    target=_run_deep_verify, args=(environment_id, job, engine.CORRELATION_ID.get()),
                    daemon=True, name=f"deep-verify-{environment_id[:8]}",
                ).start()
            except BaseException:
                # Never leave a "running" job no thread will ever finish.
                _deep_verify_jobs.pop(environment_id, None)
                raise
    job["event"].wait(wait_secs)
    with _deep_verify_lock:
        if job["status"] == "running":
            return 202, {"status": "running", "started_at": job["started_at"],
                         "poll_after_seconds": 10, "deep": True}
        if job["status"] == "error":
            job["error_delivered"] = True
            return 500, {"error": job["error"], "checked_at": job["checked_at"]}
        return 200, {**job["result"], "checked_at": job["checked_at"]}


# Compliance-reporting daily sync job -- one job per environment (not a
# single global job like _access_jobs above already is, since multiple
# environments can each have their own schedule running independently).
# Same lock+dict+thread shape.
#
# SECURITY FIX (external review, 2026-09-30): this was keyed by bare
# display name (env_name) -- confirmed exploitable, identical bug shape
# to _access_jobs above: two different owners with a same-named
# environment shared one job entry, so one user's sync status/progress/
# result was visible to, and could be silently overwritten by, another
# user's unrelated sync. Now keyed by the real, stable `environment_id`,
# unambiguous across owners.
_sync_jobs_lock = threading.Lock()
_sync_jobs = {}  # environment_id -> {"status": "idle"|"running"|"done"|"error", "steps": [...], "error": str|None}

# Background scheduler thread state -- started once at server boot (see
# main()), NOT per-request. Every iteration re-reads sync_schedule +
# sync_state from disk rather than trusting any in-memory countdown, so a
# systemd restart (confirmed in this project: happens on every crash AND
# every `deploy.sh` run) never causes a missed or duplicate daily run --
# "was today's run already done" is answered from persisted state, not
# from an object that stopped existing when the process died.
# DATA-05 (external review, 2026-10-05): last_sync_completed_at is now
# written only by a SUCCESSFUL sync, so a failing environment is no longer
# mistaken for "already ran today" -- but without this back-off the loop
# would retry it on every poll (every 5 minutes, all day) against Okta's
# rate limits. A failed or still-"running" (e.g. process died mid-sync)
# attempt is retried once this much time has passed since it started.
SCHEDULER_RETRY_BACKOFF_SECS = 60 * 60
SCHEDULER_POLL_INTERVAL_SECS = 300  # 5 min -- frequent enough that "run at HH:MM" feels accurate,
                                     # cheap enough to not matter running forever in the background
# A catch-up run within one poll interval of its scheduled time is normal
# jitter, not worth flagging -- only tag minutes_late on the audit entry
# once a run is late by more than this (e.g. the server was down, or a
# poll got skipped) so the common on-time case doesn't get a "late" label
# for a few minutes of ordinary poll-cycle slack.
SCHEDULER_LATE_THRESHOLD_MINUTES = SCHEDULER_POLL_INTERVAL_SECS // 60
_scheduler_stop_event = threading.Event()


def _sync_job_progress(storage_name):
    def _progress(key, status, detail=None):
        with _sync_jobs_lock:
            _sync_jobs.setdefault(storage_name, {"status": "running", "steps": [], "error": None})
            _sync_jobs[storage_name]["steps"].append({"key": key, "status": status, "detail": detail})
    return _progress


def _run_sync_job(env_id, env_name, okta_client, ingestion_scope, owner, trigger="manual", actor_email=None, actor_sub=None, client_ip=None, user_agent=None, correlation_id=None):
    """Previously, a sync's actual outcome (success -- how many events,
    how long it took -- or failure -- what broke) lived ONLY in the
    ephemeral in-memory _sync_jobs dict, visible only while polling
    /sync/status from an open browser tab. Nothing was ever written to
    audit_log.jsonl either way -- confirmed live 2026-09-30 alongside the
    scheduled-sync-never-fired gap this same session found. Now logs
    sync.scheduled_completed/sync.manual_completed (or
    _failed) so the outcome survives past this process's own memory and
    shows up in the Audit Log page like every other write action.
    client_ip/user_agent are naturally None for a scheduler trigger (no
    request exists), threaded through from the ORIGINAL request for a
    manual trigger (this function runs in its own background thread, so
    it can't read self.client_address/self.headers itself).
    correlation_id is likewise threaded through explicitly (a new
    thread does NOT inherit its parent's contextvars) -- the triggering
    do_POST's own id for a manual trigger, or _scheduler_loop's own
    per-tick id for a scheduled one; set here, at the very top of this
    thread's own body, so every log line this sync produces (including
    everything audit_store.sync_okta_events itself logs) carries it."""
    import audit_store
    engine.CORRELATION_ID.set(correlation_id)
    # env_id (the real, stable environment_id -- Phase 1 UUID migration;
    # the caller already has it, either from the session via
    # _session_snapshot or from _scheduler_loop's own iteration, so it's
    # passed in rather than recomputed) is used both as the in-memory
    # _sync_jobs dict key (see that dict's module-level comment for the
    # cross-owner collision this fixes) AND, as of Phase 2's SQLite
    # migration, as the real archive key every audit_store call below
    # takes -- the archive is now partitioned by environment_id, not
    # display name.
    storage_name = env_id
    action_prefix = "sync.scheduled" if trigger == "scheduled" else "sync.manual"
    with _sync_jobs_lock:
        _sync_jobs[storage_name] = {"status": "running", "steps": [], "error": None}
    try:
        result = audit_store.sync_okta_events(
            okta_client, env_id, ingestion_scope, on_progress=_sync_job_progress(storage_name)
        )
        # FIX (external review, 2026-09-30, "1.5" follow-through): a hit
        # max_pages cap makes sync_okta_events return NORMALLY (no
        # exception) with complete=False and its own last_sync_status
        # already set to "error" in the DB -- without this check, this
        # function's try/except treats that as indistinguishable from a
        # real success, marking the in-memory job "done" (not "error")
        # and logging sync.*_completed (not _failed), even though the
        # DB-persisted sync_state and this response disagree with that.
        if not result.get("complete", True):
            with _sync_jobs_lock:
                _sync_jobs[storage_name]["status"] = "error"
                _sync_jobs[storage_name]["error"] = result.get("error") or "Sync stopped early: see sync_state for details."
                _sync_jobs[storage_name]["partial"] = True  # progress is saved; the next run continues (5.51.0: the refresh reports it as such)
                if result.get("cancelled"):
                    _sync_jobs[storage_name]["cancelled"] = True
            engine.log_audit_event(
                # a Stop is audited as cancelled, not as a failure (the saved position carries on)
                actor_email, actor_sub, f"{action_prefix}_{'cancelled' if result.get('cancelled') else 'failed'}", {"name": env_name, **result},
                client_ip=client_ip, user_agent=user_agent,
            )
            return
        # By id (5.42.0): the environment this sync ran for, never whatever
        # its display name resolves to for `owner`.
        schedule = engine.get_sync_schedule_by_id(env_id)
        prune_result = audit_store.prune_events(
            env_id,
            retention_days=schedule.get("retention_days"),
            max_size_mb=schedule.get("retention_max_size_mb"),
        )
        with _sync_jobs_lock:
            _sync_jobs[storage_name]["status"] = "done"
            _sync_jobs[storage_name]["result"] = {**result, **prune_result}
        engine.log_audit_event(
            actor_email, actor_sub, f"{action_prefix}_completed", {"name": env_name, **result, **prune_result},
            client_ip=client_ip, user_agent=user_agent,
        )
        # 5.51.0: the Okta admin snapshot, the inventory counts, the Okta status of OPA principals and the sign-in / MFA
        # figures no longer run inside this thread, unseen: they are the refresh job's `okta` part (_refresh_part_okta), which
        # reports each of them. A sync started on its own (the footer's Sync now, the legacy route) is the log part only.
    except Exception as exc:
        with _sync_jobs_lock:
            _sync_jobs[storage_name]["status"] = "error"
            _sync_jobs[storage_name]["error"] = _job_error_message(exc)
            # 5.51.0: what the refresh job needs to word the outcome without the exception (and without its URL)
            _sync_jobs[storage_name]["error_status"] = getattr(exc, "status", None)
            _sync_jobs[storage_name]["error_class"] = _failure_summary(exc)
            _sync_jobs[storage_name]["error_deliberate"] = isinstance(exc, ValueError) and not isinstance(exc, (UnicodeError, json.JSONDecodeError))
        with _sync_jobs_lock:
            deliberate = _sync_jobs[storage_name].get("error_deliberate")
        engine.log_audit_event(
            # 5.51.0: an upstream error's text carries the request URL (the Okta host); the audit line gets the class and status
            actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, "error": str(exc) if deliberate else _failure_summary(exc)},
            client_ip=client_ip, user_agent=user_agent,
        )


def _start_sync_job(env_id, env_name, ingestion_scope, owner=engine.LOCAL_OWNER_KEY, trigger="manual", actor_email=None, actor_sub=None, client_ip=None, user_agent=None, minutes_late=None, correlation_id=None, inline=False):
    """Starts (or no-ops if already running) a background sync for one
    environment. Returns True if actually started. Builds a fresh
    OktaClient directly from stored credentials -- deliberately NOT
    reusing any per-request session client, since a request-triggered
    sync and a scheduler-triggered sync both need their own client
    rather than sharing one that could be reassigned/closed mid-sync.

    `owner` MUST be the real owner that environment is actually stored
    under (the requesting session's identity for a manual "Sync now",
    or whatever the scheduler loop found it under) -- this environment
    can be a per-user, non-shared copy (e.g. a logged-in Okta identity's
    own `prod`, distinct from a shared `__local__::prod`), and its
    Okta API token lives in the OS keychain under that exact owner's
    storage key. Silently defaulting to LOCAL_OWNER_KEY here previously
    caused a real bug: an admin's token, saved onto their own per-user
    environment copy, was invisible to sync because credential lookup
    always checked the LOCAL_OWNER_KEY-owned copy instead.

    `env_id` (Phase 1 UUID migration) is the real, stable environment_id
    the caller already has (session's env_id for a manual trigger,
    _scheduler_loop's own iteration key for a scheduled one) -- used ONLY
    as the in-memory _sync_jobs dict key, same reasoning as _run_sync_job.

    `trigger` is "manual" (a logged action, e.g. from serve.py's own
    /sync/start route caller) or "scheduled" (from _scheduler_loop, no
    HTTP request/actor at all). Logging lives HERE, not at each call
    site, so every path that can fail to even START a sync -- bad/missing
    credentials, already running -- is captured too, not just a
    successful kickoff. Previously, a scheduled sync had ZERO audit trail
    at all (confirmed live 2026-09-30: a configured daily sync silently
    never fired because the server was down at its scheduled time, and
    there was no log entry anywhere -- success, failure, OR miss -- to
    show that). client_ip/user_agent are naturally None for a scheduled
    trigger, same as any other CLI/background-triggered audit entry in
    this project's existing convention."""
    storage_name = env_id
    if upgrade_service.quiesced():
        # 5.48.0: an upgrade was just handed to the updater; no new sync starts while it runs (a running one finishes first).
        if trigger == "scheduled":
            engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped", {"name": env_name, "reason": "an upgrade is starting"}, client_ip=client_ip, user_agent=user_agent)
        return False
    with _sync_jobs_lock:
        if _sync_jobs.get(storage_name, {}).get("status") == "running":
            if trigger == "scheduled":
                engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped", {"name": env_name, "reason": "already running"}, client_ip=client_ip, user_agent=user_agent)
            return False
        # FE-04 (external review, 2026-10-05): claim the slot HERE, under the
        # same lock as the check. It used to be set only inside the worker
        # thread, so two starts in that window could both pass the check
        # (two syncs writing one archive), and the UI's first status poll
        # could still read the PREVIOUS run's "done" and report completion
        # before this run began. _refuse below and the worker overwrite it.
        _sync_jobs[storage_name] = {"status": "running", "steps": [], "error": None}
    action_prefix = "sync.scheduled" if trigger == "scheduled" else "sync.manual"
    def _refuse(error_msg):
        # DATA-05: a credential failure is an attempt too -- recorded in
        # sync_state so the scheduler backs off instead of retrying every
        # poll all day (it used to leave sync_state untouched).
        with _sync_jobs_lock:
            _sync_jobs[storage_name] = {"status": "error", "steps": [], "error": error_msg}
        try:
            import audit_store
            audit_store._upsert_sync_state(
                audit_store._get_connection(), env_id,
                last_sync_attempt_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                last_sync_status="error", last_sync_error=error_msg,
            )
        except Exception as exc:
            engine.log("WARN", f"could not record the failed sync attempt for '{env_name}': {exc}")
        engine.log_audit_event(actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, "error": error_msg}, client_ip=client_ip, user_agent=user_agent)
        return False

    try:
        return _launch_claimed_sync(
            env_id, env_name, ingestion_scope, owner, trigger, actor_email, actor_sub, client_ip, user_agent,
            minutes_late, correlation_id, action_prefix, _refuse, inline=inline,
        )
    except BaseException as exc:
        # The slot was claimed above: never leave it "running" with no
        # worker behind it (every later start would be refused as busy).
        with _sync_jobs_lock:
            if _sync_jobs.get(storage_name, {}).get("status") == "running" and not _sync_jobs[storage_name]["steps"]:
                _sync_jobs[storage_name] = {"status": "error", "steps": [], "error": f"Could not start the sync: {exc}"}
        raise


def _launch_claimed_sync(env_id, env_name, ingestion_scope, owner, trigger, actor_email, actor_sub, client_ip,
                         user_agent, minutes_late, correlation_id, action_prefix, _refuse, inline=False):
    """Second half of _start_sync_job, run once the slot is claimed:
    resolve credentials (refusing cleanly) and start the worker thread. `inline` (5.51.0, the refresh job's log part) runs
    the sync in the calling thread instead, so the part's cancel flag and deadline govern it."""
    try:
        # By id, under the environment's real owner (5.42.0): a shared
        # user's "Sync now" runs with the owner's stored token, and display
        # names are not unique across owners (nor among owner-less rows) --
        # resolving by name picked another environment's credentials.
        creds = engine.get_environment_credentials_by_id(env_id, owner=owner)
    except (KeyError, engine.CredentialStoreUnavailable) as exc:
        # ENG1-10: a locked keychain is a refused attempt like any other
        # (recorded, so the scheduler backs off) -- never an exception that
        # escapes the scheduler tick and skips every other environment.
        return _refuse(str(exc))
    if not creds.get("okta_url") or not creds.get("okta_api_token"):
        return _refuse("No Okta URL/API token configured for this environment.")
    okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"])
    start_details = {"name": env_name, "ingestion_scope": ingestion_scope}
    if minutes_late is not None:
        # Only ever set for trigger="scheduled" (see _scheduler_loop) --
        # a real, human-readable signal that this run was a catch-up, not
        # an on-time fire, distinguishing "the scheduler is broken" from
        # "the scheduler correctly caught up after the server was down."
        start_details["minutes_late"] = minutes_late
    engine.log_audit_event(actor_email, actor_sub, f"{action_prefix}_start", start_details, client_ip=client_ip, user_agent=user_agent)
    sync_kwargs = {"trigger": trigger, "actor_email": actor_email, "actor_sub": actor_sub, "client_ip": client_ip, "user_agent": user_agent, "correlation_id": correlation_id}
    if inline:
        with _flag_registered("sync", env_id):
            _run_sync_job(env_id, env_name, okta_client, ingestion_scope, owner, **sync_kwargs)
        return True
    threading.Thread(
        target=_run_sync_job, args=(env_id, env_name, okta_client, ingestion_scope, owner),
        kwargs=sync_kwargs, daemon=True,
    ).start()
    return True


# Okta snapshot captures (5.50.0): the admin list and the Okta status of every OPA principal are read
# from Okta in a background thread (a few dozen to a few hundred calls), stored as a chained snapshot, and
# the report routes poll `capture` below. One capture per environment at a time; nothing is retried.
_capture_jobs_lock = threading.Lock()
_capture_jobs = {}  # environment_id -> {"status": idle|running|done|error, "kind", "error", "finished_at"}
CAPTURE_KINDS = ("okta_admins", "opa_principal_status", "inventory_counts", "mfa_aggregates")


def _capture_state(environment_id):
    with _capture_jobs_lock:
        job = dict(_capture_jobs.get(environment_id) or {"status": "idle"})
    out = {k: job[k] for k in ("kind", "error", "finished_at", "started_at") if job.get(k) is not None}
    out["status"] = job["status"]
    return out


def _okta_host(environment_id, meta):
    """The host of the environment's Okta org (for the Overview's wording), never a credential."""
    from urllib.parse import urlparse as _up
    url = (meta or {}).get("okta_url") or ""
    host = _up(url).hostname if url else None
    return host


OPA_SCAN_STALE_HOURS = 24      # an amber "Stale" badge from here (shared with the Overview)
OPA_SCAN_VERY_STALE_DAYS = 7   # a red "Very stale" badge from here


def _scan_age_seconds(built_at, now=None):
    try:
        built = datetime.fromisoformat(str(built_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int(((now or datetime.now(timezone.utc)) - built).total_seconds()))


def _scan_staleness(age_seconds):
    """(stale, very_stale) for a scan of this age; both False when the age is unknown."""
    if age_seconds is None:
        return False, False
    return age_seconds >= OPA_SCAN_STALE_HOURS * 3600, age_seconds >= OPA_SCAN_VERY_STALE_DAYS * 86400


def _access_model_payload(view):
    """GET /api/access/model: the model with when it was read. The browser derives the label from built_at; age_seconds and
    the stale flags are the server's reading at this moment (the thresholds are the same constants the Overview uses)."""
    import audit_store
    model = view["model"]
    age = _scan_age_seconds(view["built_at"])
    stale, very_stale = _scan_staleness(age)
    return {"model": model, "built_at": view["built_at"], "age_seconds": age, "source": view["source"], "stale": stale,
            "very_stale": very_stale, "counts": audit_store.opa_model_counts(model), "warnings": _unreadable_sections(model),
            "modified_at": view.get("modified_at")}


def _unreadable_sections(model):
    """How many sections the service key could not read (the model's warnings, without the one that says values were hidden)."""
    return len([w for w in (model.get("warnings") or []) if not (isinstance(w, dict) and w.get("status") == "redacted")])


def _hidden_values(model):
    """How many values under name fields looked like credentials and were removed before the scan was stored."""
    return sum(1 for w in (model.get("warnings") or []) if isinstance(w, dict) and w.get("status") == "redacted")


def _scan_overview_block(environment_id):
    """What the Overview's sources strip says about the stored OPA scan: when, from where, how old, how big. None without a scan."""
    import audit_store
    view = _access_model_view(environment_id)
    if not view:
        return None
    age = _scan_age_seconds(view["built_at"])
    stale, very_stale = _scan_staleness(age)
    model = view["model"]
    return {"built_at": view["built_at"], "age_seconds": age, "source": view["source"], "stale": stale, "very_stale": very_stale,
            "counts": audit_store.opa_model_counts(model), "warnings_count": _unreadable_sections(model), "hidden_values": _hidden_values(model), "modified_at": view.get("modified_at")}


def _sync_schedule_or_none(environment_id):
    try:
        return engine.get_sync_schedule_by_id(environment_id)
    except KeyError:
        return None


def _access_model_time(environment_id):
    view = _access_model_view(environment_id)
    return view["built_at"] if view else None


def _access_model_for(environment_id):
    """The Access Explorer model for this environment (the OPA roster: users, groups with roles, Okta-UD accounts): the last
    finished scan in this process, the one kept while a new scan runs, else the stored scan (so a restart no longer loses
    it). None only when no scan has ever been stored."""
    view = _access_model_view(environment_id)
    return view["model"] if view else None


def _run_capture_job(env_id, env_name, owner, kind, model, correlation_id, actor_email, actor_sub, client_ip, user_agent):
    import audit_store
    import okta_admins
    engine.CORRELATION_ID.set(correlation_id)
    try:
        creds = engine.get_environment_credentials_by_id(env_id, owner=owner)
        if kind != "mfa_aggregates" and (not creds.get("okta_url") or not creds.get("okta_api_token")):
            raise ValueError("No Okta URL/API token configured for this environment.")
        okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"]) if creds.get("okta_api_token") else None
        if kind == "mfa_aggregates":
            import signin_mfa
            result = signin_mfa.refresh(env_id)
            with _capture_jobs_lock:
                _capture_jobs[env_id] = {"status": "done", "kind": kind, "error": None, "finished_at": _utc_now_iso()}
            engine.log_audit_event(actor_email, actor_sub, "okta_snapshot.captured", {
                "name": env_name, "kind": kind, "events_scanned": result["events_scanned"], "trigger": "manual"},
                client_ip=client_ip, user_agent=user_agent)
            return
        if kind == okta_admins.KIND_ADMINS:
            snap = okta_admins.capture_and_store(env_id, okta_client)
        elif kind == "inventory_counts":
            import inventory_counts
            opa_client = engine.OpaClient(creds["base_domain"], creds["team_name"], creds["key_id"], creds["key_secret"])
            snap = inventory_counts.capture_inventory(env_id, okta_client=okta_client, opa_client=opa_client, model=model)
        else:
            cap = okta_admins.capture_principal_status(okta_client, model)
            snap = audit_store.record_config_snapshot(
                env_id, okta_admins.KIND_PRINCIPAL_STATUS, cap["items"], status=cap["status"],
                source_endpoint=cap["source_endpoint"], meta=cap["meta"])
        with _capture_jobs_lock:
            _capture_jobs[env_id] = {"status": "done", "kind": kind, "error": None, "finished_at": _utc_now_iso()}
        engine.log_audit_event(actor_email, actor_sub, "okta_snapshot.captured", {
            "name": env_name, "kind": kind, "snapshot_id": snap["snapshot_id"], "status": snap["status"],
            "item_count": snap["item_count"], "error_code": (snap.get("meta") or {}).get("error_code"), "trigger": "manual",
        }, client_ip=client_ip, user_agent=user_agent)
    except Exception as exc:
        message = _job_error_message(exc)
        with _capture_jobs_lock:
            _capture_jobs[env_id] = {"status": "error", "kind": kind, "error": message, "finished_at": _utc_now_iso()}
        engine.log_audit_event(actor_email, actor_sub, "okta_snapshot.failed", {"name": env_name, "kind": kind, "error": _failure_summary(exc)},
                               client_ip=client_ip, user_agent=user_agent)


def _start_capture_job(env_id, env_name, owner, kind, model, actor_email, actor_sub, client_ip, user_agent):
    """True if a capture was started, False if one is already running."""
    with _capture_jobs_lock:
        if (_capture_jobs.get(env_id) or {}).get("status") == "running":
            return False
        _capture_jobs[env_id] = {"status": "running", "kind": kind, "error": None, "finished_at": None, "started_at": _utc_now_iso()}
    try:
        threading.Thread(
            target=_run_capture_job,
            args=(env_id, env_name, owner, kind, model, engine.CORRELATION_ID.get(), actor_email, actor_sub, client_ip, user_agent),
            daemon=True,
        ).start()
    except BaseException:
        with _capture_jobs_lock:
            _capture_jobs.pop(env_id, None)
        raise
    return True


# ---------------------------------------------------------------------------
# The combined Refresh (5.51.0): one job per environment, three parts, two lanes
# ---------------------------------------------------------------------------
# POST /api/environments/<name>/refresh starts ONE job that conducts the existing background jobs: the OPA scan
# (_access_jobs / _run_access_job), the System Log sync (_sync_jobs / _start_sync_job) and the Okta captures
# (_capture_jobs). Those dicts, their routes and their tests keep working: the refresh job is a conductor, not a rewrite.
#
#   OPA lane   the `opa` part
#   Okta lane  the `log` part, then the `okta` part (admins, sign-in figures, then principal status and inventory once the
#              OPA lane has the model ready)
#
# The two lanes have separate rate budgets and the OPA scan is the slow part, so they run side by side. One refresh per
# environment at a time (a second request attaches to the running one). Every part has its own deadline and cancel flag; a
# part that fails, is refused, times out or is stopped never hides the others. The daily scheduled run is this same job.
_refresh_jobs_lock = threading.Lock()
_refresh_jobs = {}  # environment_id -> refresh_jobs.RefreshJob (the running one, or the last finished one)
REFRESH_ADOPT_POLL_SECS = 2.0
REFRESH_SUPERVISE_POLL_SECS = 1.0
REFRESH_CANCEL_WAIT_SECS = 30.0
OKTA_SUB_KINDS = {"admins": "okta_admins", "principal_status": "opa_principal_status", "inventory": "inventory_counts",
                  "mfa_aggregates": "mfa_aggregates"}


def _refresh_running(environment_id):
    with _refresh_jobs_lock:
        job = _refresh_jobs.get(environment_id)
    return job is not None and job.status == "running"


def _refresh_current(job):
    """False once this job was removed or replaced (a deleted environment, a test's reset): its threads then stop at once."""
    with _refresh_jobs_lock:
        return _refresh_jobs.get(job.environment_id) is job


def _refresh_audit(job, ctx):
    return {"name": ctx["env_name"], "trigger": job.trigger, "snapshot_trigger": _snapshot_trigger(job), "actor_email": ctx.get("actor_email"),
            "actor_sub": ctx.get("actor_sub"), "client_ip": ctx.get("client_ip"), "user_agent": ctx.get("user_agent")}


def _snapshot_trigger(job):
    if job.trigger == "scheduled":
        return "scheduled"
    return "refresh" if len(job.parts) > 1 else "manual"


def _scan_time(environment_id):
    """When the scan now on offer for this environment was read: memory first, else the stored scan's recorded time."""
    import audit_store
    view = _access_model_view(environment_id, hydrate=False)
    if view:
        return view["built_at"]
    try:
        info = audit_store.opa_model_cache_info(environment_id)
    except Exception:
        info = None
    return info["built_at"] if info else None


def _refresh_status(environment_id, caller_sub=None):
    """The JSON for GET .../refresh/status: the job's record with the live step lists of the parts that are running."""
    with _refresh_jobs_lock:
        job = _refresh_jobs.get(environment_id)
    if job is None:
        return rj.idle_view()
    steps = {}
    running = job.running_parts()
    if "opa" in running:
        with _access_jobs_lock:
            steps["opa"] = list((_access_jobs.get(environment_id) or {}).get("steps") or [])
    if "log" in running:
        with _sync_jobs_lock:
            steps["log"] = list((_sync_jobs.get(environment_id) or {}).get("steps") or [])
    view = job.status_view(steps)
    view["started_by"] = "the schedule" if job.trigger == "scheduled" else ("you" if job.started_by_sub == caller_sub else "another user")
    if "opa" in job.parts:
        view["parts"]["opa"]["step_defs"] = engine.ACCESS_MODEL_STEPS  # the ordered [key, label] list the step display needs
    return view


def _start_refresh_job(env_id, env_name, parts=None, trigger="manual", owner=engine.LOCAL_OWNER_KEY, ingestion_scope=None,
                       options=None, actor_email=None, actor_sub=None, client_ip=None, user_agent=None, minutes_late=None,
                       correlation_id=None):
    """Starts the refresh for one environment, or attaches to the one running. Returns
    {"started", "already_running", "upgrade_starting", "job_id"}. `parts` is validated by the caller (rj.normalize_parts)."""
    parts = rj.normalize_parts(parts)
    audit = {"name": env_name, "trigger": trigger, "actor_email": actor_email, "actor_sub": actor_sub, "client_ip": client_ip, "user_agent": user_agent}
    if upgrade_service.quiesced():
        # An upgrade was just handed to the updater: no new refresh starts while it runs (a running one finishes first).
        if trigger == "scheduled":
            engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped", {"name": env_name, "reason": "an upgrade is starting"},
                                   client_ip=client_ip, user_agent=user_agent)
        return {"started": False, "already_running": False, "upgrade_starting": True, "job_id": None}
    with _refresh_jobs_lock:
        current = _refresh_jobs.get(env_id)
        if current is not None and current.status == "running":
            missing = [p for p in parts if p not in current.parts]
            still_running = current.running_parts() + [p for p in current.parts if current.part_state(p) == rj.PENDING]
            # Attaching is honest only when the running job will do (some of) what was asked: every part the job is still working on,
            # or the whole refresh. A request for a part the job does not include, or only for parts that already ended, would be
            # reported as "already running" while nothing runs for it.
            busy = bool(missing) or not (set(parts) & set(still_running) or parts == list(rj.PARTS))
            if busy:
                running_labels = ", ".join(rj.PART_LABELS[p] for p in rj.PARTS if p in still_running)
                asked = [p for p in parts if p in missing] or parts
                if trigger == "scheduled":
                    engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped",
                                           {"name": env_name, "reason": f"a refresh of {running_labels} is running"}, client_ip=client_ip, user_agent=user_agent)
                return {"started": False, "already_running": True, "upgrade_starting": False, "job_id": current.job_id, "busy_other_parts": True,
                        "missing": asked, "running": [p for p in rj.PARTS if p in still_running],
                        "message": f"A refresh of {running_labels} is running. The {' and '.join(rj.PART_LABELS[p] for p in asked)} can start when it finishes."}
            if trigger == "scheduled":
                engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped", {"name": env_name, "reason": "already running"},
                                       client_ip=client_ip, user_agent=user_agent)
            return {"started": False, "already_running": True, "upgrade_starting": False, "job_id": current.job_id}
        # Claimed under the lock that checked it (FE-04): two requests in the same tick can never both start a job.
        job = rj.RefreshJob(env_id, parts, trigger, options=options, started_by_sub=actor_sub)
        _refresh_jobs[env_id] = job
    ctx = {"env_name": env_name, "owner": owner, "ingestion_scope": ingestion_scope or "curated", "actor_email": actor_email,
           "actor_sub": actor_sub, "client_ip": client_ip, "user_agent": user_agent, "minutes_late": minutes_late,
           "correlation_id": correlation_id}
    try:
        engine.log_audit_event(actor_email, actor_sub, "refresh.started", {"name": env_name, "parts": parts, "trigger": trigger},
                               client_ip=client_ip, user_agent=user_agent)
        threading.Thread(target=_run_refresh_job, args=(job, ctx), daemon=True, name=f"refresh-{env_id[:8]}").start()
    except BaseException:
        # The slot was claimed above: never leave it "running" with no thread behind it.
        with _refresh_jobs_lock:
            if _refresh_jobs.get(env_id) is job:
                _refresh_jobs.pop(env_id, None)
        raise
    return {"started": True, "already_running": False, "upgrade_starting": False, "job_id": job.job_id}


def _cancel_refresh(environment_id, by=None, audit_ctx=None):
    """Asks the running refresh to stop. Returns {"cancelling": bool, "job_id"}; nothing running -> cancelling False."""
    with _refresh_jobs_lock:
        job = _refresh_jobs.get(environment_id)
    if job is None or job.status != "running":
        return {"cancelling": False, "job_id": job.job_id if job else None}
    running = job.running_parts()
    if job.request_cancel(by=by) and audit_ctx:
        _audit_for(audit_ctx, "refresh.cancelled", {"by": by, "parts_running": running})
    return {"cancelling": True, "job_id": job.job_id}


def _cancel_refresh_and_wait(environment_id, timeout=None):
    """For an environment delete: stop its refresh and wait (bounded) until its parts have stopped. True when nothing is running."""
    timeout = REFRESH_CANCEL_WAIT_SECS if timeout is None else timeout
    _cancel_refresh(environment_id, by=None)
    end = time.monotonic() + timeout
    while _refresh_running(environment_id) and time.monotonic() < end:
        time.sleep(0.05)
    return not _refresh_running(environment_id)


def _forget_environment_jobs(environment_id):
    """Drops every in-memory job record of an environment (it was deleted)."""
    with _refresh_jobs_lock:
        _refresh_jobs.pop(environment_id, None)
    with _access_jobs_lock:
        _access_jobs.pop(environment_id, None)
    with _sync_jobs_lock:
        _sync_jobs.pop(environment_id, None)
    with _capture_jobs_lock:
        _capture_jobs.pop(environment_id, None)


# -- the supervisor ----------------------------------------------------------------------------------------------------
def _run_refresh_job(job, ctx):
    engine.CORRELATION_ID.set(ctx.get("correlation_id"))
    lanes = []  # [(thread, [parts])]
    try:
        if "opa" in job.parts:
            lanes.append((threading.Thread(target=_run_lane, args=(job, ctx, ["opa"]), daemon=True, name="refresh-opa"), ["opa"]))
        okta_lane = [p for p in ("log", "okta") if p in job.parts]
        if okta_lane:
            lanes.append((threading.Thread(target=_run_lane, args=(job, ctx, okta_lane), daemon=True, name="refresh-okta"), okta_lane))
        for thread, _parts in lanes:
            thread.start()
        _supervise(job, lanes)
    except BaseException as exc:  # a failure of the conductor itself must still end every part and the job
        engine.log("ERROR", f"Refresh supervisor failed with {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        for part in job.parts:
            job.finish(part, "error", f"Internal error (reference {engine.CORRELATION_ID.get()}). The details are in the server log.")
    finally:
        _conclude_refresh(job, ctx)


def _supervise(job, lanes):
    grace_until = {}
    cancel_seen_at = None
    while _refresh_current(job):
        for part in job.overdue():
            if job.is_cancelled():
                # A Stop that landed before the deadline is a Stop: the part ends at its checkpoint as "cancelled", not "timed_out".
                # Only for the kill grace, so a part stuck inside one call that never returns still ends the job (as timed_out).
                cancel_seen_at = cancel_seen_at or time.monotonic()
                if time.monotonic() - cancel_seen_at < rj.KILL_GRACE_SECS:
                    break
            minutes = rj.PART_DEADLINES_SECS[part] // 60
            if job.finish(part, "timed_out", rj.timed_out_message(part, minutes)):
                job.cancel_events[part].reason = "timed_out"  # so the sync can record a deadline, not a Stop
                job.cancel_events[part].set()
                grace_until[part] = time.monotonic() + rj.KILL_GRACE_SECS
        alive = [thread for thread, _p in lanes if thread.is_alive()]
        if not alive:
            break
        if job.all_terminal() and all(time.monotonic() >= grace_until.get(p, 0) for p in job.parts if p in grace_until):
            break  # every part has an outcome and any part we timed out has had its grace
        time.sleep(REFRESH_SUPERVISE_POLL_SECS)
    for part in job.parts:  # anything that never got to run (a lane that stopped, a part behind a timed-out one)
        if job.part_state(part) in rj.ACTIVE_STATES:
            job.finish(part, "cancelled" if job.is_cancelled() else "skipped",
                       rj.cancelled_message() if job.is_cancelled() else "Did not run: an earlier part of this refresh did not finish.")


def _run_lane(job, ctx, parts):
    engine.CORRELATION_ID.set(ctx.get("correlation_id"))
    runners = {"opa": _refresh_part_opa, "log": _refresh_part_log, "okta": _refresh_part_okta}
    for part in parts:
        if not _refresh_current(job):
            return
        try:
            runners[part](job, ctx)
        except engine.JobCancelled:
            _finish_cancelled(job, part)
        except BaseException as exc:
            engine.log("ERROR", f"Refresh part '{part}' failed with {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            job.finish(part, "error", f"Internal error (reference {engine.CORRELATION_ID.get()}). The details are in the server log.")


def _finish_cancelled(job, part):
    """A part that stopped at a checkpoint: a deadline already recorded timed_out (then this is a no-op); a Stop is cancelled."""
    job.finish(part, "cancelled", rj.cancelled_message() if job.is_cancelled() else "Stopped.")


def _conclude_refresh(job, ctx):
    # The finish record is stored BEFORE the job reads as done: an environment delete waits for "done", so it also waits for this write,
    # and the write is skipped for a job that is no longer current or whose environment is gone (it would re-create a row for it).
    finished_at = rj.utc_now_iso()
    try:
        if _refresh_current(job) and engine.environment_owner(job.environment_id)[0]:
            _persist_last_refresh(job, finished_at)
    except Exception as exc:
        engine.log("WARN", f"The refresh outcome could not be recorded ({type(exc).__name__}).")
    job.conclude()
    outcome = job.outcome()
    seconds = round(time.monotonic() - job.started_mono, 1)
    try:
        engine.log_audit_event(ctx.get("actor_email"), ctx.get("actor_sub"), "refresh.completed",
                               {"name": ctx["env_name"], "trigger": job.trigger, "seconds": seconds, "outcome": outcome},
                               client_ip=ctx.get("client_ip"), user_agent=ctx.get("user_agent"))
    except Exception as exc:
        engine.log("WARN", f"The refresh outcome could not be written to the audit log ({type(exc).__name__}).")


def _persist_last_refresh(job, finished_at=None):
    """Remember what the last scheduled and the last other refresh did, per part (state and a short message, no names), so the
    Overview can still say a scheduled run did not read OPA after a restart."""
    import audit_store
    view = job.status_view()
    record = {"job_id": job.job_id, "trigger": job.trigger, "finished_at": finished_at or view["finished_at"],
              "parts": {p: {"state": view["parts"][p]["state"], "message": (view["parts"][p].get("message") or "")[:300]} for p in job.parts}}
    state = audit_store.get_sync_state(job.environment_id) or {}
    stored = state.get("last_refresh") if isinstance(state.get("last_refresh"), dict) else {}
    stored["scheduled" if job.trigger == "scheduled" else "manual"] = record
    log_state = view["parts"].get("log", {}).get("state") if "log" in job.parts else None
    if log_state == "timed_out":  # consecutive runs whose log part hit its deadline (the Overview names a pattern, not one slow run)
        stored["log_timeouts"] = int(stored.get("log_timeouts") or 0) + 1
    elif log_state:  # any other outcome of the log part (ok, error, cancelled, skipped) ends the streak: it counts runs IN A ROW
        stored["log_timeouts"] = 0
    audit_store._upsert_sync_state(audit_store._get_connection(), job.environment_id, last_refresh_json=json.dumps(stored, sort_keys=True))


# -- a scan or sync that was told to stop is not adopted (5.52.0) -----------------------------------------------------------
# A part that runs a scan or a sync in its own thread registers that thread's cancel flag while it runs. A later refresh that finds the
# slot still "running" looks the flag up: when it is already set (a Stop, or the part's deadline passed) the work is on its way out and its
# result will be a stop, so the later refresh waits for it to exit and then runs a fresh one instead of adopting it.
_running_flags_lock = threading.Lock()
_running_flags = {}  # ("access" | "sync", environment_id) -> the cancel Event of the thread running it


@contextlib.contextmanager
def _flag_registered(kind, environment_id):
    flag = engine.CANCEL_FLAG.get()
    if flag is None:
        yield
        return
    key = (kind, environment_id)
    with _running_flags_lock:
        _running_flags[key] = flag
    try:
        yield
    finally:
        with _running_flags_lock:
            if _running_flags.get(key) is flag:
                _running_flags.pop(key, None)


def _scan_is_stopping(kind, environment_id):
    with _running_flags_lock:
        flag = _running_flags.get((kind, environment_id))
    return flag is not None and flag.is_set()


def _wait_out_a_stopping_run(job, part, kind, environment_id, still_running):
    """True when the caller may go on (nothing is stopping, or it has exited); False when this part itself was stopped or ran out of time
    while waiting (the part is finished as cancelled; a deadline is the supervisor's to record)."""
    if not _scan_is_stopping(kind, environment_id):
        return True
    reason = _wait_until(job, part, lambda: not still_running(), time.monotonic() + rj.PART_DEADLINES_SECS[part])
    if reason == "done":
        return True
    if reason == "cancelled":
        job.finish(part, "cancelled", rj.cancelled_message())
    return False


# -- waiting for something another thread is doing ------------------------------------------------------------------------
def _wait_until(job, part, condition, deadline_mono=None):
    """Polls `condition()` until true. Returns "done", "cancelled" (this part's cancel flag), "abandoned" (the job record was
    removed) or "deadline"."""
    flag = job.cancel_events[part]
    while True:
        if condition():
            return "done"
        if not _refresh_current(job):
            return "abandoned"
        if flag.is_set():
            return "cancelled"
        if deadline_mono is not None and time.monotonic() >= deadline_mono:
            return "deadline"
        time.sleep(REFRESH_ADOPT_POLL_SECS)


def _store_clients(job, ctx, need_opa=True):
    """(OpaClient|None, OktaClient|None) built from the environment's stored credentials, by id, under its real owner: a refresh
    never shares a client with a request, and a session switch cannot affect it. The OPA client exchanges the service key when it is
    built, so only the OPA part builds it (need_opa): the Okta part must not depend on OPA accepting the key."""
    creds = engine.get_environment_credentials_by_id(job.environment_id, owner=ctx["owner"])
    opa_client = engine.OpaClient(creds["base_domain"], creds["team_name"], creds["key_id"], creds["key_secret"]) if need_opa else None
    okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"]) if creds.get("okta_url") and creds.get("okta_api_token") else None
    return opa_client, okta_client


# -- the opa part ------------------------------------------------------------------------------------------------------
def _refresh_part_opa(job, ctx):
    part, env_id = "opa", job.environment_id
    if not job.begin(part):
        return
    flag = job.cancel_events[part]
    engine.CANCEL_FLAG.set(flag)
    previous_at = _scan_time(env_id)
    if flag.is_set():
        job.finish(part, "cancelled", rj.cancelled_message())
        return
    try:
        opa_client, okta_client = _store_clients(job, ctx)
    except (KeyError, engine.CredentialStoreUnavailable) as exc:
        job.finish(part, "error", f"The saved credentials could not be read: {exc} Nothing was changed.")
        return
    except engine.JobCancelled:
        job.finish(part, "cancelled", rj.cancelled_message())
        return
    except Exception as exc:  # the key exchange happens in the client's constructor: a refusal or an outage is a result, not an internal error
        refused = isinstance(exc, engine.OpaApiError) and exc.status in (401, 403)
        state, message = rj.opa_failure("refused" if refused else "error", getattr(exc, "status", None), "key_exchange", previous_at,
                                        type(exc).__name__)
        engine.log("WARN", f"OPA key exchange for '{ctx['env_name']}' failed: {type(exc).__name__}")
        _audit_for(_refresh_audit(job, ctx), "access_scan.failed", {"error": _failure_summary(exc)})
        job.finish(part, state, message, previous_built_at=previous_at, audit_line=rj.audit_line("refused" if refused else "error", type(exc).__name__))
        return
    if not _wait_out_a_stopping_run(job, part, "access", env_id, lambda: (_access_jobs.get(env_id) or {}).get("status") == "running"):
        return
    adopted = False
    with _access_jobs_lock:
        current = _access_jobs.get(env_id)
        if current is not None and current.get("status") == "running":
            adopted = True  # a scan another caller started (an older tab) is already running: use its result
        else:
            _access_jobs[env_id] = {"status": "running", "steps": [], "error": None, "result": None, "previous": _scan_slot_previous(current)}
    if adopted:
        reason = _wait_until(job, part, lambda: (_access_jobs.get(env_id) or {}).get("status") != "running",
                             time.monotonic() + rj.PART_DEADLINES_SECS[part])
        if reason != "done":
            if reason == "cancelled":
                job.finish(part, "cancelled", "Stopped waiting for the scan that was already running; it continues.")
            return
    else:
        with _flag_registered("access", env_id):
            _run_access_job(env_id, opa_client, okta_client, correlation_id=ctx.get("correlation_id"), audit_ctx=_refresh_audit(job, ctx))
    with _access_jobs_lock:
        entry = dict(_access_jobs.get(env_id) or {})
    steps = list(entry.get("steps") or [])
    status = entry.get("status")
    if status == "done" and isinstance(entry.get("result"), dict):
        job.fresh_model = entry["result"]
        job.finish(part, "ok", rj.opa_success_message(entry.get("counts") or {}, entry.get("warnings") or 0, entry.get("stored"), entry.get("snapshot"), entry.get("hidden") or 0),
                   built_at=entry.get("result_at"), counts=entry.get("counts") or {}, warnings=entry.get("warnings") or 0,
                   stored=entry.get("stored"), steps=steps, snapshot=entry.get("snapshot"))
    elif status == "running":
        return  # still going (the job record was dropped under it, or a stubbed body returned): the supervisor decides
    else:
        state, message = rj.opa_failure(entry.get("error_kind") or "error", entry.get("error_status"), entry.get("failed_step"),
                                        previous_at, entry.get("error_class") or "an error", entry.get("key_path"))
        job.finish(part, state, message, steps=steps, previous_built_at=previous_at,
                   audit_line=rj.audit_line(entry.get("error_kind") or "error", entry.get("error_class")))


# -- the log part ------------------------------------------------------------------------------------------------------
def _refresh_part_log(job, ctx):
    part, env_id = "log", job.environment_id
    if not job.begin(part):
        return
    flag = job.cancel_events[part]
    engine.CANCEL_FLAG.set(flag)
    if flag.is_set():
        job.finish(part, "cancelled", rj.cancelled_message())
        return
    if not _wait_out_a_stopping_run(job, part, "sync", env_id, lambda: (_sync_jobs.get(env_id) or {}).get("status") == "running"):
        return
    trigger = "scheduled" if job.trigger == "scheduled" else "manual"
    # The sync's own start/skip/refusal logic (slot claim under the lock, upgrade quiesce, a refused credential recorded as an
    # attempt) is reused whole; it runs here, in the lane's thread, so this part's cancel flag and deadline govern it.
    started = _start_sync_job(
        env_id, ctx["env_name"], ctx["ingestion_scope"], owner=ctx["owner"], trigger=trigger, actor_email=ctx.get("actor_email"),
        actor_sub=ctx.get("actor_sub"), client_ip=ctx.get("client_ip"), user_agent=ctx.get("user_agent"),
        minutes_late=ctx.get("minutes_late"), correlation_id=ctx.get("correlation_id"), inline=True)
    adopted = False
    with _sync_jobs_lock:
        entry = dict(_sync_jobs.get(env_id) or {})
    if not started and entry.get("status") == "running":
        adopted = True
        job.annotate(part, adopted=True, note="A sync was already running; this refresh used its result.")
    elif not started and upgrade_service.quiesced():
        job.finish(part, "skipped", "An upgrade is starting; refreshes are paused until it finishes (a few minutes).")
        return
    if entry.get("status") == "running":  # an adopted sync, or a body that has not finished
        reason = _wait_until(job, part, lambda: (_sync_jobs.get(env_id) or {}).get("status") != "running",
                             time.monotonic() + rj.PART_DEADLINES_SECS[part])
        if reason != "done":
            if reason == "cancelled":
                job.finish(part, "cancelled", "Stopped waiting for the sync that was already running; it continues." if adopted
                           else rj.cancelled_message())
            return
        with _sync_jobs_lock:
            entry = dict(_sync_jobs.get(env_id) or {})
    steps = list(entry.get("steps") or [])
    status = entry.get("status")
    if status == "done":
        result = entry.get("result") or {}
        inserted = int(result.get("inserted") or 0)
        job.finish(part, "ok", f"{inserted} new event{'s' if inserted != 1 else ''} stored.", events_new=inserted,
                   mode=result.get("mode"), steps=steps)
        return
    if status == "error":
        error_status = entry.get("error_status")
        if entry.get("cancelled"):
            state, message = rj.log_failure("cancelled", None)
        elif entry.get("partial"):
            state, message = rj.log_failure("partial", None, entry.get("error"))
        elif error_status in (401, 403):
            state, message = rj.log_failure("refused", error_status)
        else:
            safe = entry.get("error") if (entry.get("error_deliberate") or "error_class" not in entry) else rj.plain_error(entry.get("error_class"))
            state, message = rj.log_failure("error", error_status, safe)
        job.finish(part, state, message, steps=steps)


# -- the okta part -----------------------------------------------------------------------------------------------------
def _claim_capture(job, kind, deadline_mono):
    """Takes the environment's capture slot for one capture; waits (bounded) while a manual 'Capture now' holds it."""
    env_id = job.environment_id
    while True:
        with _capture_jobs_lock:
            if (_capture_jobs.get(env_id) or {}).get("status") != "running":
                _capture_jobs[env_id] = {"status": "running", "kind": kind, "error": None, "finished_at": None, "started_at": _utc_now_iso()}
                return True
        if _wait_until(job, "okta", lambda: (_capture_jobs.get(env_id) or {}).get("status") != "running", deadline_mono) != "done":
            return False


def _release_capture(env_id, kind, error=None):
    with _capture_jobs_lock:
        _capture_jobs[env_id] = {"status": "error" if error else "done", "kind": kind, "error": error, "finished_at": _utc_now_iso()}


def _refresh_part_okta(job, ctx):
    import audit_store
    import inventory_counts
    import okta_admins
    part, env_id = "okta", job.environment_id
    if not job.begin(part):
        return
    flag = job.cancel_events[part]
    engine.CANCEL_FLAG.set(flag)
    wanted = [s for s in rj.OKTA_SUBS if s in (job.options.get("okta_subs") or rj.OKTA_SUBS)]
    for sub in rj.OKTA_SUBS:
        job.set_sub(sub, "pending" if sub in wanted else "not_requested")
    if flag.is_set():
        job.finish(part, "cancelled", rj.cancelled_message())
        return
    try:
        _opa_client, okta_client = _store_clients(job, ctx, need_opa=False)
    except (KeyError, engine.CredentialStoreUnavailable) as exc:
        job.finish(part, "error", f"The saved credentials could not be read: {exc} Nothing was changed.")
        return
    if okta_client is None:
        job.finish(part, "skipped", "No Okta URL or API token is configured for this environment, so the Okta scan did not run.")
        for sub in wanted:
            job.set_sub(sub, "skipped")
        return
    forced = job.trigger != "scheduled"  # a person pressing Refresh is never held back by a cadence gate
    trigger = _snapshot_trigger(job)
    audit = _refresh_audit(job, ctx)
    deadline = job.part_data[part]["_started_mono"] + rj.PART_DEADLINES_SECS[part]

    def model_for_counts():
        """The model the principal-status and inventory captures read: this refresh's fresh scan, or - when the OPA part was not
        part of this refresh - the stored scan. None when the OPA part ran and did not finish: nothing stale is passed off as today's."""
        if "opa" in job.parts:
            return getattr(job, "fresh_model", None) if job.part_state("opa") == "ok" else None
        return _access_model_for(env_id)

    def sub_runner(sub, fn):
        kind = OKTA_SUB_KINDS[sub]
        job.set_sub(sub, "running")
        if not _claim_capture(job, kind, deadline):
            job.set_sub(sub, "cancelled")
            raise engine.JobCancelled("cancelled")
        try:
            state, message, extra = fn()
            _release_capture(env_id, kind)
        except engine.JobCancelled:
            _release_capture(env_id, kind, "Stopped.")
            job.set_sub(sub, "cancelled", rj.cancelled_message())
            raise
        except Exception as exc:
            message_out = _job_error_message(exc) if isinstance(exc, ValueError) else f"{rj.OKTA_SUB_LABELS[sub]} failed ({rj.plain_error(_failure_summary(exc))}). Nothing was changed."
            _release_capture(env_id, kind, message_out)
            engine.log("WARN", f"Okta {sub} capture for '{ctx['env_name']}' failed: {type(exc).__name__}")
            _audit_for(audit, "okta_snapshot.failed", {"kind": kind, "error": _failure_summary(exc)})
            if okta_admins.is_refused(exc):
                job.set_sub(sub, "refused", message_out)
            else:
                job.set_sub(sub, "error", message_out)
            return
        job.set_sub(sub, state, message, **extra)

    def snapshot_audit(snap, kind, **more):
        _audit_for(audit, "okta_snapshot.captured", {
            "kind": kind, "snapshot_id": snap["snapshot_id"], "status": snap["status"], "item_count": snap["item_count"],
            "error_code": (snap.get("meta") or {}).get("error_code"), "trigger": trigger, **more})

    def snapshot_result(snap, ok_message):
        if snap["status"] == "ok":
            return "ok", ok_message, {"snapshot_id": snap["snapshot_id"], "items": snap["item_count"]}
        if snap["status"] == "refused":
            return "refused", okta_admins.MISSING_ROLES_MESSAGE if snap["kind"] == okta_admins.KIND_ADMINS else \
                "Okta refused the read (the token cannot read users). The refusal was recorded.", {"snapshot_id": snap["snapshot_id"]}
        return "error", "Okta did not answer; the failure was recorded.", {"snapshot_id": snap["snapshot_id"]}

    def do_admins():
        snap = okta_admins.capture_and_store(env_id, okta_client) if forced else okta_admins.capture_if_due(env_id, okta_client)
        if snap is None:
            return "skipped", "Admin roles were recorded recently; they are read again after the next interval.", {}
        snapshot_audit(snap, snap["kind"])
        return snapshot_result(snap, f"{snap['item_count']} item(s) recorded.")

    def do_mfa():
        import signin_mfa
        result = signin_mfa.refresh(env_id)
        _audit_for(audit, "okta_snapshot.captured", {"kind": "mfa_aggregates", "events_scanned": result["events_scanned"], "trigger": trigger})
        return "ok", f"{result['events_scanned']} archived event(s) folded in.", {"events_scanned": result["events_scanned"]}

    def do_principals():
        model = model_for_counts()
        if model is None:
            if "opa" in job.parts:
                return "skipped", "Not run: the OPA scan did not finish. It runs with the next refresh.", {}
            return "skipped", "Not run: no OPA scan is stored yet. Select Refresh to scan OPA first.", {}
        cap = okta_admins.capture_principal_status(okta_client, model)
        snap = audit_store.record_config_snapshot(env_id, okta_admins.KIND_PRINCIPAL_STATUS, cap["items"], status=cap["status"],
                                                  source_endpoint=cap["source_endpoint"], meta=cap["meta"])
        snapshot_audit(snap, okta_admins.KIND_PRINCIPAL_STATUS)
        return snapshot_result(snap, f"{snap['item_count']} OPA user(s) looked up in Okta.")

    def do_inventory():
        model = model_for_counts()
        started = time.monotonic()
        if forced:
            snap = inventory_counts.capture_inventory(env_id, okta_client=okta_client, opa_client=None, model=model)
        else:
            snap = inventory_counts.capture_if_due(env_id, okta_client=okta_client, opa_client=None, model=model)
        if snap is None:
            return "skipped", "An inventory point was recorded in the last 20 hours; the next one is taken after that.", {}
        snapshot_audit(snap, snap["kind"], inventory_seconds=round(time.monotonic() - started, 1))
        text = f"{snap['item_count']} series recorded."
        if model is None:
            text = "Okta counts recorded. OPA counts are missing from today's snapshot because the OPA scan did not finish." if "opa" in job.parts \
                else "Okta counts recorded. OPA counts are missing from this snapshot because no OPA scan is stored yet."
        return "ok", text, {"snapshot_id": snap["snapshot_id"], "items": snap["item_count"], "okta_only": model is None}

    def await_model():
        if "opa" in job.parts and not job.model_ready.is_set():
            reason = _wait_until(job, part, job.model_ready.is_set, deadline)
            if reason == "cancelled":
                raise engine.JobCancelled("cancelled")
            if reason != "done":
                raise engine.JobCancelled("cancelled")

    try:
        if "admins" in wanted:
            sub_runner("admins", do_admins)
        if "mfa_aggregates" in wanted:
            sub_runner("mfa_aggregates", do_mfa)
        if "principal_status" in wanted or "inventory" in wanted:
            for sub in ("principal_status", "inventory"):
                if sub in wanted:
                    job.set_sub(sub, "waiting" if "opa" in job.parts and not job.model_ready.is_set() else "pending")
            await_model()
            if "principal_status" in wanted:
                sub_runner("principal_status", do_principals)
            if "inventory" in wanted:
                sub_runner("inventory", do_inventory)
    except engine.JobCancelled:
        _finish_cancelled(job, part)
        return
    subs = {s: job.sub_data[s] for s in wanted}
    refused = [s for s in wanted if subs[s]["state"] == "refused"]
    failed = [s for s in wanted if subs[s]["state"] == "error"]
    if refused:
        job.finish(part, "refused", subs[refused[0]].get("message"))
    elif failed:
        job.finish(part, "error", subs[failed[0]].get("message"))
    else:
        recorded = [rj.OKTA_SUB_LABELS[s] for s in wanted if subs[s]["state"] == "ok"]
        job.finish(part, "ok", ("Recorded: " + ", ".join(recorded) + ".") if recorded else "Nothing was due; the Okta scan has no new data to record yet.")


def _upgrade_context():
    """What the upgrade preflight and the schedule tick need to know about this process."""
    import audit_store
    with _sync_jobs_lock:
        running = any(j.get("status") == "running" for j in _sync_jobs.values())
    with _refresh_jobs_lock:
        running = running or any(j.status == "running" for j in _refresh_jobs.values())  # 5.51.0: the OPA scan is included
    try:
        db_bytes = os.path.getsize(audit_store._audit_db_path())
    except OSError:
        db_bytes = 0
    try:
        log_bytes = os.path.getsize(engine._audit_log_path())
    except OSError:
        log_bytes = 0
    backups = upgrade_service.backups_view() or {}
    return {"sync_running": running, "evidence_build_running": _evidence.running(),
            "evidence_package_waiting_until": _evidence.waiting_until(), "db_bytes": db_bytes, "audit_log_bytes": log_bytes, "backups_total": backups.get("total_bytes") or 0,
            "sync_hint": Handler._upgrade_sync_hint(), "run": update_service.upgrade_run()}


def _scheduler_loop():
    """Runs forever in a daemon thread, started once at server boot.
    Every SCHEDULER_POLL_INTERVAL_SECS, checks every saved environment's
    sync_schedule -- if enabled and today's run hasn't completed yet
    (per audit_store.get_sync_state, on disk, not in-memory), starts one.

    Both `run_time` and "today" are interpreted in UTC, not local time --
    a REAL bug caught live during this feature's own testing: comparing
    last_sync_completed_at (always stored in UTC, via
    datetime.now(timezone.utc) in audit_store.py) against a NAIVE
    datetime.now() (local time) meant "already ran today" could never
    match whenever UTC's calendar date had already rolled over past
    local midnight but local time hadn't -- e.g. 5:04pm PDT is already
    12:04am the next UTC day, so a sync that just completed got its
    completion date stamped as "tomorrow" from local time's perspective,
    and the scheduler immediately re-triggered a duplicate run on its
    very next poll. Keeping everything in one timezone end-to-end (UTC)
    is what actually fixes this, not a smarter date-math routine --
    admins configuring run_time should be told it's UTC in the UI.

    Self-heals from a server that was simply down at the scheduled time
    (confirmed live 2026-09-30: a real deployment restart meant the
    process, and therefore this loop, didn't exist yet at the configured
    run time) -- there's no separate "did today's run happen on time"
    check; the very next poll after the process comes back up sees
    "today hasn't completed yet" and starts one immediately, however late.
    Previously this had NO audit trail at all either way -- confirmed live
    the same day: no log entry showed the run ever kicking off (on time or
    late), failing, or being skipped, which is exactly what made a missed
    run indistinguishable from a silently-broken scheduler. Every outcome
    below is now logged via _start_sync_job/_run_sync_job (start/skip/
    fail there) or directly here (a catch-up run gets an explicit
    `minutes_late` in its start event; an unexpected exception in this
    loop itself, previously only a print() that's easy to miss in
    systemd's journal, now also gets a real audit_log.jsonl entry)."""
    while not _scheduler_stop_event.is_set():
        # No HTTP request exists to correlate this tick with (see
        # engine.CORRELATION_ID's own docstring) -- a "sched-" prefixed
        # id, regenerated every poll, still ties together every sync
        # this one tick starts and everything _run_sync_job itself logs
        # for them, without implying a request that was never made.
        engine.CORRELATION_ID.set(f"sched-{uuid.uuid4().hex[:8]}")
        try:
            _scheduler_tick(datetime.now(timezone.utc))
        except Exception as exc:
            engine.log("ERROR", f"[scheduler] Unexpected error in scheduler loop: {exc}")
            engine.log_audit_event(None, None, "sync.scheduler_error", {"error": str(exc)})
        # 5.46.0: the opt-in update check (own thread; a failure here never
        # affects syncs, and update_service.maybe_start never raises).
        update_service.maybe_start(engine.SCRIPT_VERSION)
        # 5.48.0: a scheduled upgrade that has come due is handed to the updater here (or marked missed).
        upgrade_service.tick(engine.SCRIPT_VERSION, _upgrade_context)
        _scheduler_stop_event.wait(SCHEDULER_POLL_INTERVAL_SECS)


def _scheduler_tick(now_utc):
    """One poll of _scheduler_loop: starts every environment's due sync.
    Split out (TEST-10) so the date math, catch-up and back-off rules are
    tested with an injected clock."""
    import audit_store
    # list_all_environments(), NOT list_environments_for(LOCAL_OWNER_KEY):
    # a per-user, non-shared environment (e.g. a logged-in Okta
    # identity's own private copy of "prod") owns its own
    # sync_schedule and Okta token just like a shared one does, and
    # the scheduler must still find and run it -- list_environments_for
    # deliberately hides another owner's non-shared environments from
    # a single requesting identity, which is correct for a live HTTP
    # request but was silently starving this background loop of any
    # environment that wasn't LOCAL_OWNER_KEY's own or shared=True.
    environments = engine.list_all_environments()
    for environment_id, meta in environments.items():
        env_name = meta.get("name")
        owner = meta.get("owner")
        try:
            schedule = engine.get_sync_schedule_by_id(environment_id)
        except KeyError:
            continue
        if not schedule.get("enabled"):
            continue

        run_time_str = schedule.get("run_time") or "02:00"
        try:
            run_hour, run_minute = (int(x) for x in run_time_str.split(":"))
        except (ValueError, AttributeError):
            run_hour, run_minute = 2, 0
        if (now_utc.hour, now_utc.minute) < (run_hour, run_minute):
            continue  # not time yet today (UTC)

        # audit_store's archive is keyed by environment_id (Phase 2
        # SQLite migration) -- each environment_id has its own
        # distinct sync_state row even when two different owners'
        # environments share a display name.
        state = audit_store.get_sync_state(environment_id)
        last_completed = state.get("last_sync_completed_at") if state else None
        if last_completed:
            last_completed_date = last_completed[:10]  # "YYYY-MM-DD" prefix of the ISO (UTC) timestamp
            if last_completed_date == now_utc.strftime("%Y-%m-%d"):
                continue  # already ran today (UTC)
        # DATA-05: back off after a failed/unfinished attempt instead of
        # retrying on every poll (see SCHEDULER_RETRY_BACKOFF_SECS).
        last_attempt = state.get("last_sync_attempt_at") if state else None
        if last_attempt and (state.get("last_sync_status") in ("error", "running", "cancelled", "timed_out")):
            try:
                attempt_dt = datetime.fromisoformat(last_attempt.replace("Z", "+00:00"))
                if now_utc - attempt_dt < timedelta(seconds=SCHEDULER_RETRY_BACKOFF_SECS):
                    continue
            except ValueError:
                pass  # unparseable attempt timestamp -- don't let it block the retry

        minutes_late = (now_utc.hour * 60 + now_utc.minute) - (run_hour * 60 + run_minute)
        # 5.51.0: the daily run is the same job as the Overview's Refresh (OPA scan, Okta scan, System Log), on a timer. The
        # back-off above is keyed off the log part's sync_state; a failed OPA part alone never delays tomorrow's run.
        _start_refresh_job(
            environment_id, env_name, parts=list(rj.PARTS), trigger="scheduled", owner=owner,
            ingestion_scope=schedule.get("ingestion_scope", "curated"),
            minutes_late=minutes_late if minutes_late > SCHEDULER_LATE_THRESHOLD_MINUTES else None,
            correlation_id=engine.CORRELATION_ID.get(),
        )


class StrictBindHTTPServer(ThreadingHTTPServer):
    # http.server.HTTPServer sets allow_reuse_address=True, which on Windows
    # (unlike POSIX) lets a second process silently bind to a port that
    # another process is already actively listening on, instead of raising
    # "address already in use". Disabling it makes the OSError-on-bind check
    # in main() actually fire consistently on Windows, Mac, and Linux.
    #
    # 5.39.1: except on POSIX, where SO_REUSEADDR does NOT allow binding over
    # an active listener (a second instance still fails with "address already
    # in use") -- it only lets a restart bind while the old process's closed
    # connections sit in TIME_WAIT (up to 60 s). Without it, every
    # `systemctl restart` under traffic crash-looped until those expired and
    # deploy.sh's 5-second version check failed the deploy (seen live, 5.39.0).
    allow_reuse_address = os.name != "nt"


# 5.53.0: the entry fields only the Settings unlock may read (see GET /api/settings/environments).
ENV_CONFIG_FIELDS = ("base_domain", "team_name", "key_id", "okta_url", "has_okta_token", "sync_schedule")
# A random per-process key: the `scope` token below is only ever compared with an earlier copy of itself.
_SCOPE_TOKEN_KEY = os.urandom(32)


def _connection_scope(meta):
    """An opaque token that changes when the settings deciding WHICH tenant an environment reaches (OPA domain, team, Okta URL)
    change, so the browser can drop cached tenant data after such an edit without being told the settings themselves
    (5.53.0). A keyed hash with a per-process key: it reveals nothing about the values and changes at a restart."""
    text = "\n".join(str(meta.get(field, "")) for field in ("base_domain", "team_name", "okta_url"))
    return hmac.new(_SCOPE_TOKEN_KEY, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _public_entry(environment_id, name, meta, requesting_owner, full=True):
    """Non-secret fields only -- key_secret/okta_api_token never leave the
    keychain, let alone reach the browser. `requesting_owner` is the
    engine-layer owner (see _engine_owner) of whoever is asking, used only
    to compute `is_own` -- lets the frontend show "yours" vs. "shared with
    you" without exposing anyone else's real owner id.

    FIX (Phase 1 UUID migration): this used to MANUFACTURE the id itself
    via engine.environment_storage_name(meta.get("owner"), name) rather
    than reading one that's actually stored -- every caller already has
    the real environment_id in hand (either as the dict key from
    engine.list_all_environments()/list_environments_for(), or inside
    meta["environment_id"] since list_environments_for now includes it),
    so this just takes it as an explicit parameter instead."""
    entry = {
        "id": environment_id,
        "name": name,
        "shared": bool(meta.get("shared", False)),
        "is_own": meta.get("owner") == requesting_owner,
        "scope": _connection_scope(meta),
    }
    if full:  # 5.53.0: the configuration fields are for the Settings unlock only (ENV_CONFIG_FIELDS)
        entry.update({
            "base_domain": meta.get("base_domain", ""),
            "team_name": meta.get("team_name", ""),
            "key_id": meta.get("key_id", ""),
            "okta_url": meta.get("okta_url", ""),
            "has_okta_token": bool(engine.keyring_get(environment_id, "okta_api_token")),
            "sync_schedule": meta.get("sync_schedule", dict(engine.SYNC_SCHEDULE_DEFAULTS)),
        })
    return entry


def activate_environment(owner_key, name, environment_id=None):
    """Loads `name` (visible to this owner) from the encrypted store,
    authenticates to OPA, and (if Okta credentials are present) to Okta
    too. On success stores the new client/okta_client/env_name/env_id in
    this owner's session slot. Raises KeyError (unknown/not visible to
    this owner) or engine.OpaApiError (OPA auth failed).

    `env_id` (Phase 1's UUID migration) is resolved HERE, once, from
    `creds["environment_id"]` (get_environment_credentials already
    returns it, since it reads straight from the stored record) -- every
    downstream route reads it back out of the session via
    _session_snapshot instead of recomputing it per-request.

    environment_id (5.40.3): restore exactly that environment (own or
    shared, re-checked here) rather than whatever `name` resolves to now --
    used when re-activating a saved session, where the pointer IS an id."""
    engine_owner = _engine_owner(owner_key)
    if environment_id is not None:
        creds = engine.get_environment_credentials_by_id(environment_id, owner=engine_owner)
        name = creds["name"]
    else:
        creds = engine.get_environment_credentials(name, owner=engine_owner)  # raises KeyError if unknown/not visible

    new_client = engine.OpaClient(creds["base_domain"], creds["team_name"], creds["key_id"], creds["key_secret"])
    new_okta_client = None
    if creds.get("okta_url") and creds.get("okta_api_token"):
        new_okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"])

    with _sessions_lock:
        _sessions[owner_key] = {
            "client": new_client, "okta_client": new_okta_client,
            "env_name": name, "env_id": creds["environment_id"],
        }

    if environment_id is None:
        # (by id, the pointer already names exactly this environment)
        engine.set_active_environment(engine_owner, name)
    engine.log("INFO", f"Activated environment '{name}' ({creds['base_domain']}) for owner '{owner_key}'.")


# ---------------------------------------------------------------------------
# Folder-tree helpers
# ---------------------------------------------------------------------------
def _row_dict(path, folder_id, status, error_message):
    return {"path": "/".join(path), "folder_id": folder_id, "status": status, "error_message": error_message}


def _plan_dict(ordered_paths, existing, collisions, name_in_use=None, case_variants=None):
    name_in_use = name_in_use or {}
    return {
        "tree": [
            {"path": "/".join(p), "depth": len(p) - 1, "exists": p in existing, "folder_id": existing.get(p, ""),
             # ENG2-02: a same-named folder elsewhere in the project (never
             # adopted; OPA decides on the create) -- None when there is none.
             "name_in_use_at": name_in_use.get(p)}
            for p in ordered_paths
        ],
        "collisions": {name: ["/".join(p) for p in paths] for name, paths in collisions.items()},
        "case_variants": [["/".join(p) for p in paths] for paths in (case_variants or {}).values()],
    }


def _safe_csv_path(filename):
    """Only allow a bare filename ending in .csv, resolved inside PROJECT_ROOT
    (no path traversal via '..' or absolute paths). A name containing a path
    separator is refused outright (5.40.3) rather than silently reduced to
    its basename -- "../x.csv" used to quietly mean "x.csv"."""
    raw = (filename or "").strip() if isinstance(filename, str) else ""
    name = os.path.basename(raw)
    if not name or name != raw or "\\" in raw or not name.lower().endswith(".csv"):
        raise ValueError("filename must be a bare name ending in .csv")
    return _csv_dir() / name


# SRV-06 (external review, 2026-10-05): POST /api/csv could create or
# overwrite ANY bare *.csv in the project root -- including an Okta System
# Log export waiting to be imported via /sync/import_csv, or a
# folders_result_*.csv execution record. Writes are now limited to
# folder-template files: a conservative name, never a result file, and an
# existing file is only overwritten if it already is a folder template
# (header path,description). New files are capped in number so an
# authenticated caller can't fill the disk one 5 MB body at a time.
# ASCII-only and case-sensitive on purpose: re.IGNORECASE would also accept
# Unicode look-alikes (U+017F matches "s"), slipping past the result-file
# prefix check, and a ".CSV" name would escape the case-sensitive
# "*.csv" listing (and the file cap) on Linux.
_CSV_WRITE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._() -]{0,120}\.csv$", re.ASCII)
_CSV_RESULT_PREFIX = "folders_result_"
FOLDER_TEMPLATE_FIELDS = ["path", "description"]
MAX_PROJECT_CSV_FILES = 500


def _writable_template_csv_path(filename):
    """Resolves a POST /api/csv target, raising ValueError (-> 400) for a
    bad name and _CsvWriteRefused (-> 409) for a file that must not be
    overwritten."""
    csv_path = _safe_csv_path(filename)
    name = csv_path.name
    if not _CSV_WRITE_NAME_RE.match(name):
        raise ValueError("filename may only use ASCII letters, digits, spaces and . _ ( ) - and must end in lower-case .csv")
    if name.casefold().startswith(_CSV_RESULT_PREFIX):
        raise _CsvWriteRefused(f"{name} is an execution result record and can't be overwritten -- save under another name.")
    if csv_path.exists() and csv_path.stat().st_size > 0:
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                header = next(_csv.reader(f), None)
        except (OSError, UnicodeDecodeError, _csv.Error):
            header = None
        if [h.strip().lower() for h in (header or [])] != FOLDER_TEMPLATE_FIELDS:
            raise _CsvWriteRefused(f"{name} exists and is not a folder-template CSV (path,description) -- "
                                   "save under another name.")
    elif _count_template_csv_files() >= MAX_PROJECT_CSV_FILES:
        raise _CsvWriteRefused(f"Too many CSV files in the project folder (limit {MAX_PROJECT_CSV_FILES}) -- "
                               "remove some or overwrite an existing template.")
    return csv_path


def _count_template_csv_files():
    """CSV files in the project root that count toward the cap: any case of
    the .csv extension, excluding /api/execute's own folders_result_* records
    (which must never block saving a template)."""
    try:
        names = os.listdir(_csv_dir())
    except OSError:
        return 0
    return sum(1 for n in names if n.casefold().endswith(".csv") and not n.casefold().startswith(_CSV_RESULT_PREFIX))


class _CsvWriteRefused(Exception):
    """POST /api/csv target exists but must not be overwritten (409)."""


def _run_pipeline(active_client, rows, resource_group_id, project_id):
    """Shared by /api/preview and /api/execute: parse -> validate -> collision
    check -> existing-folder lookup. Returns (ordered_paths, descriptions,
    existing, collisions, invalid_names). Takes the client explicitly
    (a snapshot the caller took at the start of its request) rather than
    reading the module-level `client` global itself -- see the note on
    request-scoped client snapshots above do_GET."""
    if not isinstance(rows, list):
        raise ValueError("rows must be a list")
    ordered_paths, descriptions = engine.parse_rows(rows, warn=False)
    invalid_names = [
        {"path": "/".join(p), "name": p[-1]}
        for p in ordered_paths
        if not engine.is_valid_folder_name(p[-1])
    ]
    collisions = engine.detect_name_collisions(ordered_paths)
    case_variants = engine.detect_case_variant_names(ordered_paths)
    existing, name_in_use = engine.resolve_existing_folders(active_client, resource_group_id, project_id, ordered_paths)
    return ordered_paths, descriptions, existing, collisions, invalid_names, name_in_use, case_variants


def _validate_ids(**ids):
    """ENG2-16: every id that ends up inside an OPA URL path or an Okta
    filter is checked once at the route layer (ValueError -> 400). The
    client also percent-quotes ids (engine._path_id) as a second layer."""
    for label, value in ids.items():
        engine.validate_resource_id(value, label)


def _require_client(send_json, active_client):
    if active_client is None:
        send_json(409, {"error": "No active environment configured. Use the gear menu to set one up."})
        return False
    return True


def _require_okta_client(send_json, active_okta_client):
    if active_okta_client is None:
        send_json(
            409,
            {"error": "This environment has no Okta URL/API token configured. Add them via the gear menu to create groups."},
        )
        return False
    return True


class _RequestAborted(Exception):
    """Internal control-flow signal: a response (e.g. 413/403) was already
    sent for this request, so the caller should stop processing without
    sending anything else."""


# Action type -> the Handler method that runs it (see _environment_change).
_ENV_CHANGE_EXECUTORS = {
    "environment.upsert": "_exec_environment_upsert",
    "environment.share": "_exec_environment_share",
    "environment.delete": "_exec_environment_delete",
    "sync_schedule.update": "_exec_sync_schedule_update",
    "sync.reset_watermark": "_exec_sync_reset_watermark",
    "sync.import_csv": "_exec_sync_import_csv",
    "archive.purge": "_exec_archive_purge",
    "shared_permissions.update": "_exec_shared_permissions_update",
    "upgrade.settings": "_exec_upgrade_settings_update",
    "upgrade.request": "_exec_upgrade_request",
    "banner.update": "_exec_banner_update",
    "settings.unlock": "_exec_settings_unlock",
    "evidence_package.build": "_exec_evidence_package_build",
}
assert set(_ENV_CHANGE_EXECUTORS) == set(ENV_CHANGE_ACTION_TYPES)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIST), **kwargs)

    def log_message(self, fmt, *args):
        pass  # keep console output to our own explicit prints

    def _request_client_ip(self):
        """The real originating client IP, not this socket's own TCP peer.

        FIX (confirmed real, 2026-10-01): every caller of this used to read
        self.client_address[0] directly -- when reverse-proxied behind
        nginx (this app's hosted-deployment mode), that is ALWAYS nginx's
        own loopback address (127.0.0.1), never the actual browser/user --
        nginx terminates the real TCP connection and opens a brand-new one
        to this process. nginx already sets X-Real-IP from $remote_addr on
        every proxied request (see nginx-opa-secrets-wizard.conf) -- it was
        just never read. Only trust that header when _request_is_from_nginx
        confirms the request actually transited nginx's proxy (same trust
        boundary that already gates X-Auth-Is-Admin/X-Auth-Sub -- X-Real-IP
        is exactly as spoofable by a direct loopback request as those are);
        otherwise (standalone/local-only mode, no nginx in front at all)
        fall back to the raw socket peer, which IS the real client in that
        mode."""
        if _request_is_from_nginx(self.headers):
            real_ip = self.headers.get("X-Real-IP")
            if real_ip:
                return real_ip
        return self.client_address[0] if self.client_address else None

    def _log_audit_event(self, actor_email, actor_sub, action, details=None):
        """Thin wrapper around engine.log_audit_event that fills in
        client_ip/user_agent from THIS request automatically -- added
        2026-09-30 so every one of this class's ~17 existing call sites
        gets real client IP + user agent captured (Okta's own System Log
        always includes both; this audit log never did) without having to
        thread self.client_address/self.headers through each one by
        hand."""
        # 5.43.0: a sub is only unique within one Okta org; record which
        # org's gate vouched for the actor, when nginx says so.
        issuer = _issuer_from_headers(self.headers)
        if issuer:
            details = {**(details or {}), "actor_issuer": issuer}
        pending = getattr(self, "_settings_unlock_renewal", None)
        if pending is not None:
            # 5.53.0: the first audit entry of an approved change is written only once the change was applied, so that is when
            # its MFA restarts the Settings unlock (a refused re-check logs nothing and renews nothing).
            self._settings_unlock_renewal = None
            if self._renew_settings_unlock_after_mfa(*pending):
                details = {**(details or {}), "settings_unlock_renewed": True}
        return engine.log_audit_event(
            actor_email, actor_sub, action, details,
            client_ip=self._request_client_ip(),
            user_agent=self.headers.get("User-Agent"),
        )

    def end_headers(self):
        origin = self.headers.get("Origin")
        # Echo back the real request Origin if it's one this app actually
        # allows (see _allowed_origins) -- hardcoding the dev server's
        # origin here meant every response claimed to be for
        # http://localhost:5173 regardless of who was really asking, which
        # is simply wrong once this app is reverse-proxied behind a real
        # hostname/IP. Falls back to DEV_FRONTEND_ORIGIN when there's no
        # Origin header at all (non-browser callers -- this header is
        # meaningless to them anyway) to preserve the exact prior default.
        self.send_header(
            "Access-Control-Allow-Origin",
            origin if origin and origin in self._allowed_origins() else DEV_FRONTEND_ORIGIN,
        )
        super().end_headers()

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_internal_error(self, exc):
        """SRV-03 (external review, 2026-10-05): an unexpected exception used
        to be returned verbatim (`str(exc)` -- filesystem paths, SQLite
        errors, KeyError internals) to any authenticated caller. The detail
        (with traceback) now goes to the server log only; the response
        carries a generic message plus the request's correlation id, which
        is on every log line for this request, so an operator can find it."""
        correlation_id = engine.CORRELATION_ID.get()
        engine.log("ERROR", f"Unhandled {type(exc).__name__} in {self.command} {urlparse(self.path).path}: "
                            f"{exc}\n{traceback.format_exc()}")
        return self._send_json(500, {
            "error": f"Internal server error (reference {correlation_id}). The details are in the server log.",
            "correlation_id": correlation_id,
        })

    def _allowed_hosts(self):
        """5.53.0: the Host header values a local-mode request may carry: the
        three loopback forms on the bound port, plus the host part of each
        EXTRA_ALLOWED_ORIGINS entry (the existing operator override)."""
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        for origin in EXTRA_ALLOWED_ORIGINS:
            netloc = urlparse(origin).netloc.lower()
            if netloc:
                allowed.add(netloc)
        return allowed

    def parse_request(self):
        """Local mode only: refuse any request whose Host is not this
        server's own loopback name and port (DNS rebinding defence: a web
        page on another name that resolves to 127.0.0.1 carries its own name
        in Host). Runs after the request line and headers are parsed and
        before any do_* handler, so it covers every method. Hosted mode is
        unchanged (nginx sets Host)."""
        if not super().parse_request():
            return False
        if DEPLOYMENT_MODE == "hosted":
            return True
        hosts = self.headers.get_all("Host") or []
        if len(hosts) == 1 and hosts[0].strip().lower() in self._allowed_hosts():
            return True
        body = b"Misdirected request: this host name is not served here.\n"
        self.send_response(421)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True
        return False

    def _allowed_origins(self):
        port = self.server.server_address[1]
        return {DEV_FRONTEND_ORIGIN, f"http://127.0.0.1:{port}", f"http://localhost:{port}"} | EXTRA_ALLOWED_ORIGINS

    def _check_origin(self):
        """Rejects mutating requests whose Origin doesn't match this
        dashboard's own frontend. Browsers always attach an Origin header
        to cross-origin (and most same-origin) fetch/XHR requests, so an
        Origin that isn't one of this app's own is either a non-browser
        caller impersonating one, another local process, or a malicious
        page/DNS-rebinding attempt probing this credential-handling local
        server. A request with NO Origin header at all (curl, scripts) is
        let through -- Origin/CORS checks only ever constrain browsers to
        begin with, so there's nothing to enforce against a client that
        was never going to send it."""
        origin = self.headers.get("Origin")
        if origin is None or origin in self._allowed_origins():
            return True
        self._send_json(403, {"error": f"Origin '{origin}' is not allowed to call this API."})
        return False

    def _read_json_body(self):
        # FIX (external review, 2026-09-30, "2.3"): a malformed
        # Content-Length (non-numeric, or missing entirely in a way that
        # produces something int() rejects) previously raised an
        # unhandled ValueError straight out of this method -- a crafted
        # or malformed request could crash the request handler instead of
        # getting a clean 400. A NEGATIVE value also previously passed
        # straight through the `> MAX_REQUEST_BODY_BYTES` check below
        # (any negative number is less than that) and into
        # self.rfile.read(length) with a negative argument -- CPython's
        # socket file objects treat a negative read size as "read until
        # EOF", which would hang this request (and this threaded server's
        # one thread handling it) waiting for a close that normal HTTP
        # keep-alive traffic never sends.
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_json(400, {"error": "Malformed Content-Length header."})
            raise _RequestAborted()
        if length < 0:
            self._send_json(400, {"error": "Content-Length cannot be negative."})
            raise _RequestAborted()
        if length > MAX_REQUEST_BODY_BYTES:
            self._send_json(413, {
                "error": f"Request body too large (max {MAX_REQUEST_BODY_BYTES // (1024 * 1024)} MB)."
            })
            # Don't attempt to read/drain a body that claims to be this
            # large -- close the connection instead of risking the next
            # request on it being misread as leftover body bytes.
            self.close_connection = True
            raise _RequestAborted()
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(body, dict):
            # A JSON array/string/number body used to surface as a 500
            # ("'list' object has no attribute 'get'") -- TEST-08's probe.
            raise ValueError("Request body must be a JSON object.")
        return body

    # -----------------------------------------------------------------
    # Shared-environment permissions (5.42.0)
    # -----------------------------------------------------------------
    def _capability_refused(self, engine_owner, environment_id, capabilities, part=None):
        """THE route-side shared-environment check: every route that reads
        or acts on an environment (by name, or through the caller's active
        session) calls this with its fixed capability tuple, AFTER its own
        visibility/session checks (so it is never an existence oracle).
        Sends the one 403 shape and returns True when any capability is not
        allowed; owners always pass (engine.shared_capability_allowed).
        environment_id None (no active environment) refuses nothing: the
        route's own "no active environment" answer applies. An id with no
        environment row behind it is refused (fail closed)."""
        if environment_id is None:
            return False
        if not engine.environment_owner(environment_id)[0]:
            # The session's environment was deleted under it: that is "no
            # active environment", not a permission refusal.
            self._send_json(409, {"error": "No active environment configured. Use the gear menu to set one up."})
            return True
        for capability in capabilities:
            if not engine.shared_capability_allowed(environment_id, engine_owner, capability,
                                                    caller_issuer=_issuer_from_headers(self.headers)):
                self._send_json(403, {
                    "error": _shared_permission_message(capability),
                    "reason": "shared_permission_denied", "capability": capability,
                    **({"part": part} if part else {}),  # 5.51.0: the refresh part the caller may not run
                })
                return True
        return False

    def _report_csv_target(self, path, engine_owner):
        """(environment name, report key, meta) for /api/environments/<name>/reports/<report_key>/export.csv, or None after
        sending the 404. Visibility only; the route checks view_archive itself afterwards (never an existence oracle)."""
        middle = path[len("/api/environments/"):-len("/export.csv")]
        env_part, sep, report_key = middle.rpartition("/reports/")
        if not (sep and env_part and report_key):
            self._send_json(404, {"error": "Not found."})
            return None
        name = unquote(env_part)
        meta = engine.list_environments_for(engine_owner).get(name)
        if meta is None:
            self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
            return None
        return name, unquote(report_key), meta

    def _serve_report_csv(self, name, report_key, meta, qs):
        """5.53.0: GET /api/environments/<name>/reports/<report_key>/export.csv?since=YYYY-MM-DD&until=YYYY-MM-DD.

        Same visibility and permission as viewing the report (view_archive; not behind the Settings unlock). Every
        event of the report in the UTC period, none dropped: the rows come from ONE evidence_core snapshot and go
        through the same writer the evidence package uses. The file is built into a temporary file first and sent
        with a Content-Length, so a failure while building answers with an error instead of a download that ends
        early, and a transfer that is cut short is visible to the browser. Nothing is cached. The audit entry names
        who, which environment and report, the range and the row count; never any event content."""
        import audit_store
        import evidence_core
        import tempfile
        if report_key not in audit_store.COMPLIANCE_REPORTS:
            return self._send_json(404, {"error": "Unknown report."})
        since = (qs.get("since") or [""])[0]
        until = (qs.get("until") or [""])[0]
        try:
            period = evidence_core.parse_period(since, until)
        except evidence_core.PeriodError as exc:
            return self._send_json(400, {"error": str(exc)})
        # The file is built on disk in a `tmp` folder of the data directory (the archive's folder; the service's own /tmp
        # may be memory), anonymous and removed on close. Refuse early if the disk is nearly full.
        tmp_dir = os.path.join(os.path.dirname(audit_store._audit_db_path()), "tmp")
        try:
            os.makedirs(tmp_dir, mode=0o700, exist_ok=True)
            free = _free_bytes(tmp_dir)
        except OSError as exc:
            engine.log("WARN", f"report csv export: temporary folder unusable: {exc}")
            return self._send_json(507, {"error": "The server has no usable temporary space for this export."})
        if free < EXPORT_MIN_FREE_BYTES:
            return self._send_json(507, {"error": (
                f"The server has only {free // (1024 * 1024)} MB of free disk space; an export needs at least "
                f"{EXPORT_MIN_FREE_BYTES // (1024 * 1024)} MB. Free some space and try again.")})
        try:
            with tempfile.TemporaryFile(dir=tmp_dir) as out:
                with evidence_core.open_snapshot(meta["environment_id"], period) as snap:
                    rows = evidence_core.write_report_csv(out, snap.report_rows(report_key))
                size = out.tell()
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "report.csv_exported", {
                    "name": name, "report": report_key, "since": period.start.isoformat(),
                    "until": period.end.isoformat(), "rows": rows})
                filename = f"opa-report-{report_key}-{period.start.isoformat()}-to-{period.end.isoformat()}.csv"
                out.seek(0)
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Report-Rows", str(rows))
                self.end_headers()
                while True:
                    chunk = out.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except evidence_core.EvidenceError as exc:
            engine.log("WARN", f"report csv export: {exc}")
            return self._send_json(409, {"error": "The archive could not be read for this export."})

    def _environment_from_tail(self, path, tail, engine_owner):
        """(name, meta) for /api/environments/<name><tail>, or None after sending
        the 404. Visibility only: each route then checks its own capabilities
        with self._capability_refused (visibility first, so a refusal is never
        an existence oracle)."""
        name = unquote(path[len("/api/environments/"):-len(tail)])
        meta = engine.list_environments_for(engine_owner).get(name)
        if meta is None:
            self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
            return None
        return name, meta

    def _serve_overview(self, path, qs, owner_key, engine_owner, local_env_name):
        """GET /api/overview and GET /api/overview/privileged (see the routes in do_GET)."""
        # 5.50.0: counts only (/api/overview), or the audited list of the privileged people behind the
        # sign-in / MFA figures (/api/overview/privileged). Admin-only and not available through an
        # additional login gate (nginx answers 403 there for the whole /api/overview prefix). Each
        # Okta-derived block carries its own state, so a refused read says "refused", never zero.
        privileged = path.endswith("/privileged")
        people_route = path.endswith("/people")
        # 5.51.0: the counts (/api/overview) are also served to a caller who holds view_archive and live_read on the named environment
        # (an archive viewer): the same counts, never a name. The lists of people and the ?id= addressing stay administrators-only.
        is_admin = _can_admin(owner_key, self.headers)
        admin_id = (qs.get("id") or [None])[0]
        if not is_admin and (privileged or people_route or admin_id):
            return self._send_json(403, {"error": "Admin access required for the overview."})
        import audit_store
        import okta_admins
        name = (qs.get("environment") or qs.get("env") or [local_env_name])[0]
        if admin_id:
            meta = engine.list_all_environments().get(admin_id)
            name = (meta or {}).get("name")
            if meta is not None:
                meta = {**meta, "environment_id": admin_id}
        elif not name:
            return self._send_json(400, {"error": "No active environment and none specified via ?environment="})
        else:
            meta = engine.list_environments_for(engine_owner).get(name)
        if meta is None:
            return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
        if not is_admin:
            # Visibility first (the 404 above), then what an archive viewer needs: read the archive and live data of this environment.
            if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive", "live_read")):
                return
        as_of = (qs.get("as_of") or [None])[0] or None
        try:
            weeks = int((qs.get("weeks") or [26])[0])
        except ValueError:
            return self._send_json(400, {"error": "weeks must be an integer"})
        if not 1 <= weeks <= 156:
            return self._send_json(400, {"error": "weeks must be between 1 and 156"})
        env_id = meta["environment_id"]
        _o, _e, actor_email, actor_sub = self._caller()
        try:
            audit_store.normalize_window(None, as_of)
            model = _access_model_for(env_id)
            if people_route:
                which = (qs.get("list") or [""])[0]
                named = okta_admins.people_list(env_id, which, access_model=model, as_of=as_of)
                self._log_audit_event(actor_email, actor_sub, "overview.people_read", {"name": name, "list": which, "as_of": as_of, "people": len(named["people"])})
                return self._send_json(200, named)
            if privileged:
                people = okta_admins.privileged_people_report(env_id, access_model=model, as_of=as_of, weeks=weeks)
                self._log_audit_event(actor_email, actor_sub, "overview.privileged_read", {"name": name, "as_of": as_of, "people": len(people["people"]), "weeks": weeks})
                return self._send_json(200, people)
            accounts = (len(model.get("saas_accounts") or []) + len(model.get("okta_accounts") or [])) if model else None
            chain = audit_store.verify_ingestion_chain(env_id)
            overview = okta_admins.build_overview(
                env_id, as_of=as_of, access_model=model, service_accounts_total=accounts, weeks=weeks,
                model_time=_access_model_time(env_id), okta_host=_okta_host(env_id, meta),
                scan=_scan_overview_block(env_id), schedule=_sync_schedule_or_none(env_id),
                integrity={k: chain.get(k) for k in ("valid", "manifest_count", "reason", "head_hash")})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        overview["capture"] = _capture_state(env_id)
        self._log_audit_event(actor_email, actor_sub, "overview.read", {"name": name, "as_of": as_of, "viewer": "admin" if is_admin else "archive_viewer"})
        return self._send_json(200, overview)

    def _caller(self):
        """(owner_key, engine_owner, actor_email, actor_sub) for this request."""
        owner_key = _owner_key_from_headers(self.headers)
        actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key
        return owner_key, _engine_owner(owner_key), self.headers.get("X-Auth-User"), actor_sub

    # -----------------------------------------------------------------
    # Environments changes: act now (local mode) or after step-up MFA
    # -----------------------------------------------------------------
    def _environment_change(self, action, params):
        """Runs one Environments change. Every executor below takes
        (params, dry_run, via_step_up) and returns (status, body); with
        dry_run it makes every check it can without changing anything and
        returns (None, None) when the change may go ahead. Local mode: run
        it. Hosted mode: check it, store it as a pending action and answer
        202 so the browser can get the step-up approval; the stored request
        is run by POST /api/environment_changes/save afterwards, with every
        check made again."""
        executor = getattr(self, _ENV_CHANGE_EXECUTORS[action])
        if action == "environment.upsert":
            # Only the form's own fields, each capped -- the same values a
            # direct save would use (upsert_environment ignores the rest).
            body_in = params.get("body") or {}
            for field in ENV_FORM_FIELDS:
                value = body_in.get(field)
                if value is not None and not isinstance(value, str):
                    return self._send_json(400, {"error": f"{field} must be a string"})
                if isinstance(value, str) and len(value) > MAX_ENV_FIELD_CHARS:
                    return self._send_json(400, {"error": f"{field} is too long"})
            params = {**params, "body": {k: body_in[k] for k in ENV_FORM_FIELDS if k in body_in}}
        if not _step_up_required_for_changes():
            status, body = executor(params, dry_run=False, via_step_up=False)
            return self._send_json(status, body)
        # The dry run makes every check it can and returns what the change
        # was checked against ("bound": e.g. the environment id a name
        # resolved to). That is stored with the change, and the save refuses
        # (409 target_changed) if it no longer holds -- the approval covers
        # the environment that was checked, not whatever the name means later.
        status, body = executor(params, dry_run=True, via_step_up=False)
        if status is not None:
            return self._send_json(status, body)
        import audit_store
        _owner_key, _engine_owner_, _email, actor_sub = self._caller()
        stored = json.loads(json.dumps(params))
        if body:
            stored["bound"] = body
        secrets_by_field = {}
        if action == "environment.upsert":
            body_in = stored.get("body") or {}
            for field in engine.ENVIRONMENT_SECRET_FIELDS:
                value = body_in.pop(field, None)
                if isinstance(value, str) and value.strip():
                    secrets_by_field[field] = value
        payload = {"action": action, "params": stored, "secret_fields": sorted(secrets_by_field)}
        action_id = None
        with _pending_env_changes_lock:  # decide under the lock, answer after it (never a socket write inside)
            if audit_store.count_open_pending_admin_actions(actor_sub, ENV_CHANGE_ACTION_TYPES) < MAX_OPEN_ENV_CHANGES_PER_USER:
                action_id = audit_store.create_pending_admin_action(
                    actor_sub, action, payload, ttl_seconds=STEPUP_PREPARE_TTL_SECONDS
                )
        if action_id is None:
            return self._send_json(429, {"error": "Too many changes are waiting for MFA approval; finish or abandon "
                                                  "them (they expire after 15 minutes) and try again.",
                                         "reason": "too_many_pending"})
        if secrets_by_field:
            _remember_pending_secrets(action_id, secrets_by_field)
        return self._send_json(202, {"step_up_required": True, "action_id": action_id, "action": action})

    @staticmethod
    def _target_changed():
        return 409, {"error": "The environment this change was approved for has changed (renamed, shared, unshared "
                              "or deleted) since. Nothing was applied -- reload and try again.",
                     "reason": "target_changed"}

    def _exec_environment_upsert(self, params, dry_run, via_step_up):
        payload = params.get("body") or {}
        owner_key, engine_owner, actor_email, actor_sub = self._caller()
        is_admin = _is_admin_from_headers(self.headers)
        name = payload.get("name")
        if not isinstance(name, str) or not name.strip():
            return 400, {"error": "Environment name is required (e.g. dev, uat, prod)."}
        environment_id = payload.get("id")
        if environment_id is not None and not isinstance(environment_id, str):
            return 400, {"error": "id must be a string"}
        evidence_builders = payload.get("evidence_builders")
        if evidence_builders is not None and evidence_builders not in ("owner", "shared"):
            return 400, {"error": "evidence_builders must be 'owner' or 'shared'"}
        if dry_run:
            try:
                _n, checked_id = engine.upsert_environment(
                    name, payload, owner=engine_owner, is_admin=is_admin, environment_id=environment_id, dry_run=True,
                )
            except PermissionError as exc:
                return 403, {"error": str(exc)}
            return None, {"environment_id": checked_id}
        bound = params.get("bound")
        # The approved target is checked inside the save's own transaction.
        expected = {"expected_target_id": bound.get("environment_id")} if bound is not None else {}
        _c, _o, local_env_name, _i = _session_snapshot(owner_key)
        ids_before = set(engine.list_all_environments())
        try:
            name, upserted_id = engine.upsert_environment(
                name, payload, owner=engine_owner, is_admin=is_admin, environment_id=environment_id, **expected,
            )
        except PermissionError as exc:
            return 403, {"error": str(exc)}
        except engine.EnvironmentTargetChanged:
            return self._target_changed()
        target_meta = engine.list_all_environments().get(upserted_id) or {}
        caller_owns_target = target_meta.get("owner") == engine_owner
        details = {
            "name": name, "admin_override": is_admin,
            # Whose environment was written -- an admin editing
            # someone else's credentials is now explicit in the log.
            "environment_id": upserted_id, "edited_other_owner": not caller_owns_target,
        }
        if evidence_builders is not None:
            # 5.53.0: who may build evidence packages from this environment's archive; owners always can.
            changed = engine.set_shared_permissions(
                {"build_evidence_package": "allow" if evidence_builders == "shared" else "deny"},
                environment_id=upserted_id, updated_by=actor_email or actor_sub)
            details["evidence_builders"] = evidence_builders
            if changed:
                details["evidence_builders_changed"] = True
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "environment.upsert", details)
        # ENG1-06 (external review, 2026-10-05): every OTHER owner's
        # live session on this environment still holds a client built
        # from the OLD credentials (able to re-mint tokens on 401).
        # Drop them and let each owner's next request re-run the
        # normal saved-environment auto-activation, which re-checks
        # visibility and builds a client from what is stored now.
        if upserted_id in ids_before:
            # The caller's own session is kept only when it is about to
            # be rebuilt below (they own the target); an admin editing
            # someone else's environment loses a stale session on it
            # like everyone else and re-activates with the new values.
            _drop_sessions_for_environment(
                upserted_id, except_owner=owner_key if caller_owns_target else None, reactivate=True,
            )
        if not caller_owns_target:
            # An admin edited ANOTHER owner's environment by id. It
            # was saved; it is not the admin's to activate (by name
            # it would resolve to the admin's own same-named
            # environment, or not at all -- this used to 500 with a
            # KeyError after a successful save).
            return 200, {"saved": True, "activated": False, "active": local_env_name}
        # The caller's own environment: (re)activate it, so their own
        # session also picks up the new credentials.
        try:
            activate_environment(owner_key, name)
        except engine.OpaApiError as exc:
            return 502, {"error": f"Saved, but could not connect: {exc}", "saved": True}
        return 200, {"activated": True, "active": name}

    def _exec_environment_share(self, params, dry_run, via_step_up):
        owner_key, engine_owner, actor_email, actor_sub = self._caller()
        name = params.get("name") or ""
        payload = params.get("body") or {}
        shared = bool(payload.get("shared", False))
        is_admin = _is_admin_from_headers(self.headers)
        try:
            checked = engine.set_environment_shared(
                name, engine_owner, shared, is_admin=is_admin, environment_id=payload.get("id"), dry_run=True,
            )
            if dry_run:
                return None, {"environment_id": checked}
            bound = params.get("bound")
            if bound is not None and bound.get("environment_id") != checked:
                return self._target_changed()
            target_id = engine.set_environment_shared(
                name, engine_owner, shared, is_admin=is_admin, environment_id=payload.get("id"),
            )
        except KeyError as exc:
            return 404, {"error": str(exc)}
        except PermissionError as exc:
            return 403, {"error": str(exc)}
        if not shared:
            # ENG1-06: an unshare withdraws access NOW, not at the
            # next restart -- every other owner's live session on it
            # is dropped (the owner's own stays).
            _drop_sessions_for_environment(target_id, except_owner=owner_key)
        details = {"name": name, "shared": shared, "admin_override": is_admin}
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "environment.share", details)
        return 200, {"name": name, "shared": shared}

    def _exec_environment_delete(self, params, dry_run, via_step_up):
        owner_key, engine_owner, actor_email, actor_sub = self._caller()
        name = params.get("name") or ""
        is_admin = _is_admin_from_headers(self.headers)
        environment_id = params.get("id")
        # DATA-12: deleting the archive too is an explicit choice
        # (`?purge_archive=1`); the default keeps it as an orphan an
        # admin can review/purge later via /api/archives. Destroying
        # evidence is admin-only (local mode exempt), same rule as
        # /api/archives -- an environment's owner can delete the
        # environment, but not the compliance history other users
        # may report from (a shared environment's archive is
        # everyone's evidence).
        purge_archive = bool(params.get("purge_archive"))
        if purge_archive and not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to delete an environment's compliance archive; delete without purge_archive to keep it."}
        try:
            checked = engine.delete_environment(
                name, owner=engine_owner, is_admin=is_admin, environment_id=environment_id, dry_run=True,
            )["environment_id"]
        except PermissionError as exc:
            return 403, {"error": str(exc)}
        except KeyError as exc:
            return 404, {"error": str(exc)}
        if dry_run:
            return None, {"environment_id": checked}
        bound = params.get("bound")
        if bound is not None and bound.get("environment_id") != checked:
            return self._target_changed()
        # 5.51.0: a refresh in flight owns this environment's archive and stored scan: stop it and wait (bounded) first.
        if not _cancel_refresh_and_wait(checked):
            return 409, {"error": "A refresh of this environment is still stopping. Try again in a minute.", "reason": "refresh_stopping"}
        try:
            result = engine.delete_environment(
                name, owner=engine_owner, is_admin=is_admin, environment_id=environment_id,
                purge_archive=purge_archive,
            )
        except PermissionError as exc:
            return 403, {"error": str(exc)}
        except KeyError as exc:
            return 404, {"error": str(exc)}
        except Exception as exc:
            # The environment is gone even if the archive purge failed
            # (see delete_environment) -- log the delete before
            # surfacing the error, never lose the audit entry.
            self._log_audit_event(actor_email, actor_sub, "environment.delete",
                                  {"name": name, "admin_override": is_admin, "purge_archive": purge_archive,
                                   "archive_purge_error": str(exc)})
            raise
        # ENG1-06: every owner's live session on this environment is
        # now stale (its cached client still holds the old credentials
        # in memory) -- drop them all, not just the caller's.
        _drop_sessions_for_environment(result["environment_id"])
        _forget_environment_jobs(result["environment_id"])
        if result.get("opa_scan_removed"):
            self._log_audit_event(actor_email, actor_sub, "access_scan.cache_purged",
                                  {"environment_id": result["environment_id"], "reason": "archive_purged" if purge_archive else "environment_deleted"})
        details = {"name": name, "admin_override": is_admin, "purge_archive": purge_archive}
        if result["archive"]:
            details["archive_purged"] = result["archive"]
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "environment.delete", details)
        return 200, {"deleted": name, "archive_purged": purge_archive}

    def _visible_environment(self, name, params=None):
        """(meta, None) for the environment `name` resolves to for this
        caller, or (None, (status, body)): 404 when it resolves to nothing,
        409 target_changed when an approved change was checked against a
        different environment than the name resolves to now."""
        _owner_key, engine_owner, _email, _sub = self._caller()
        meta = engine.list_environments_for(engine_owner).get(name)
        if meta is None:
            return None, (404, {"error": f"No environment named '{name}' visible to this user."})
        bound = (params or {}).get("bound")
        if bound is not None and bound.get("environment_id") != meta["environment_id"]:
            return None, self._target_changed()
        return meta, None

    def _shared_refusal(self, meta, capability):
        """(403, body) when this caller may not use `capability` on `meta`'s
        environment, else None -- the executors' form of
        _capability_refused (same check, returned instead of sent)."""
        _owner_key, engine_owner, _email, _sub = self._caller()
        if engine.shared_capability_allowed(meta["environment_id"], engine_owner, capability,
                                            caller_issuer=_issuer_from_headers(self.headers)):
            return None
        return 403, {"error": _shared_permission_message(capability), "reason": "shared_permission_denied",
                     "capability": capability}

    def _exec_sync_reset_watermark(self, params, dry_run, via_step_up):
        # DATA-03 remedy: the only supported way out of an unusable
        # watermark. Same visibility rule as /sync/start; the next
        # sync backfills the full 90-day window (dedup makes that
        # free of duplicates).
        import audit_store
        _owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        name = params.get("name") or ""
        meta, refusal = self._visible_environment(name, params)
        if refusal:
            return refusal
        refusal = self._shared_refusal(meta, "reset_watermark")
        if refusal:
            return refusal
        if _ingest_running(meta["environment_id"]):
            return 409, {"error": "A sync or import is running for this environment; reset the watermark after it finishes."}
        if dry_run:
            return None, {"environment_id": meta["environment_id"]}
        previous = audit_store.reset_sync_watermark(meta["environment_id"])
        details = {"name": name, "previous_watermark": previous}
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "sync.reset_watermark", details)
        return 200, {"name": name, "previous_watermark": previous}

    def _exec_sync_schedule_update(self, params, dry_run, via_step_up):
        _owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        name = params.get("name") or ""
        config = params.get("body")
        meta, refusal = self._visible_environment(name, params)
        if refusal:
            return refusal
        refusal = self._shared_refusal(meta, "sync_settings")
        if refusal:
            return refusal
        try:
            clean = engine.validate_sync_schedule_config(config)
        except ValueError as exc:
            return 400, {"error": str(exc)}
        if meta.get("owner") != self._caller()[1]:
            # Retention prunes archived evidence at the next sync, and
            # destroying evidence is never a shared user's call: a shared
            # user allowed to change sync settings can't change retention.
            current = engine.get_sync_schedule_by_id(meta["environment_id"])
            if any(f in clean and clean[f] != current.get(f) for f in ("retention_days", "retention_max_size_mb")):
                return 403, {"error": "Only the environment's owner can change its retention (it deletes archived events).",
                             "reason": "owner_only"}
        if dry_run:
            return None, {"environment_id": meta["environment_id"]}
        try:
            # By id (5.42.0): exactly the environment just checked.
            saved = engine.set_sync_schedule_by_id(meta["environment_id"], config)
        except KeyError as exc:
            return 404, {"error": str(exc)}
        details = {"name": name, **saved}
        if meta.get("owner") != self._caller()[1]:
            details["shared_user"] = True
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "sync_schedule.update", details)
        return 200, {"name": name, "sync_schedule": saved}

    def _exec_sync_import_csv(self, params, dry_run, via_step_up):
        import audit_store
        _owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        name = params.get("name") or ""
        payload = params.get("body") or {}
        # SECURITY FIX (external review, 2026-09-30), two bugs fixed
        # together since both gate the same route:
        # (1) csv_path previously came straight from the request
        # body with only an os.path.isfile() check -- no
        # confinement at all, so any authenticated user could point
        # this at an arbitrary server-readable file (e.g.
        # /etc/passwd) and have its contents parsed as CSV and
        # ingested into the compliance archive. Reuses
        # _safe_csv_path's exact existing pattern (basename-only,
        # .csv suffix, confined to PROJECT_ROOT) -- same tradeoff
        # already accepted for /api/csv: the admin drops the Okta
        # System Log export into the project root first, then
        # picks it by bare filename, same as CsvFileBar.tsx's
        # existing file-picker workflow for the folder-template CSV.
        # (2) this route had NO ownership check at all, unlike its
        # sibling /sync/status -- any authenticated user who knew
        # (or guessed, e.g. "dev"/"prod") another owner's
        # environment display name could inject rows directly into
        # that owner's audit archive. Same cross-tenant class as
        # the report-read leaks fixed above, just on the write side.
        meta, refusal = self._visible_environment(name, params)
        if refusal:
            return refusal
        refusal = self._shared_refusal(meta, "import_csv")
        if refusal:
            return refusal
        try:
            csv_path = _safe_csv_path(payload.get("csv_path"))
        except ValueError as exc:
            return 400, {"error": str(exc)}
        ingestion_scope = payload.get("ingestion_scope", "curated")
        if ingestion_scope not in ("curated", "all"):
            return 400, {"error": 'ingestion_scope must be "curated" or "all"'}
        if not csv_path.is_file():
            return 400, {"error": f"{csv_path.name} not found on server filesystem"}
        env_id = meta["environment_id"]
        if dry_run:
            if _ingest_running(env_id):
                return 409, {"error": "A sync is running for this environment; import the CSV after it finishes."}
            return None, {"environment_id": env_id}
        # DATA-11 (external review, 2026-10-05): an import racing a
        # live sync for the same environment writes the same tables
        # from two threads; refuse rather than interleave. The
        # import takes the SAME ingest slot a sync does (atomically,
        # under the lock), so _start_sync_job's own "already running"
        # check refuses a sync for the duration of the import too.
        with _sync_jobs_lock:
            if _sync_jobs.get(env_id, {}).get("status") == "running":
                return 409, {"error": "A sync is running for this environment; import the CSV after it finishes."}
            previous_job = _sync_jobs.get(env_id)
            _sync_jobs[env_id] = {"status": "running", "steps": [], "error": None, "kind": "csv_import"}
        try:
            try:
                result = audit_store.import_from_csv(str(csv_path), env_id, ingestion_scope)
            except ValueError as exc:
                return 400, {"error": str(exc)}
        finally:
            with _sync_jobs_lock:
                if previous_job is None:
                    _sync_jobs.pop(env_id, None)
                else:
                    _sync_jobs[env_id] = previous_job
        details = {"name": name, "csv_path": csv_path.name, **result}
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "sync.import_csv", details)
        return 200, result

    def _exec_archive_purge(self, params, dry_run, via_step_up):
        # DATA-12 (external review, 2026-10-05): purge the archive a
        # deleted environment left behind. Admin-only (local mode
        # exempt, same rule as /api/audit_log) -- this destroys
        # evidence, so it is never a per-owner action, and it is
        # audit-logged with the per-table counts.
        import audit_store
        owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        if not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to purge an orphaned archive."}
        archive_id = params.get("archive_id") or ""
        if not archive_id:
            return 400, {"error": "missing environment_id"}
        if _ingest_running(archive_id):
            return 409, {"error": "A sync or import is still running for that environment; purge it after it finishes."}
        if dry_run:
            if archive_id in engine.list_all_environments():
                return 409, {"error": "That environment still exists; only an orphaned archive can be purged."}
            if not audit_store.archive_has_rows(archive_id):
                return 404, {"error": "No archive rows exist for that environment_id."}
            return None, None
        try:
            counts = audit_store.purge_environment_archive(archive_id)
        except ValueError as exc:
            return 409, {"error": str(exc)}
        if not any(counts.values()):
            return 404, {"error": "No archive rows exist for that environment_id."}
        details = {"environment_id": archive_id, **counts}
        if via_step_up:
            details["step_up_verified"] = True
        self._log_audit_event(actor_email, actor_sub, "archive.purge", details)
        return 200, {"purged": archive_id, **counts}

    def _environments_response(self, owner_key, engine_owner, local_env_name, local_env_id, full):
        """The environment list. full=False (GET /api/environments, every signed-in user): names, ids, permissions. full=True
        (GET /api/settings/environments, behind the Settings unlock): the configuration fields as well."""
        is_admin = _is_admin_from_headers(self.headers)
        if is_admin:
            # Admins see EVERY stored environment, not just their
            # own/shared ones -- list_all_environments() (added for
            # the scheduler, see its own docstring) returns
            # {environment_id: meta} across every owner.
            #
            # SECURITY FIX (external review, 2026-09-30): this used
            # to unpack storage_key into a bare display name and
            # collapse into visible[disp_name] = meta -- if two
            # different owners each had an environment named "dev",
            # the second one silently overwrote the first in this
            # dict, so an admin never even SAW both, let alone
            # could act on the right one. Now keeps every entry by
            # its real id (unambiguous), and passes each one's TRUE
            # display name (meta["name"], not a shared dict key)
            # into _public_entry -- two same-named environments
            # from different owners both survive to the response,
            # each with its own unique `id` (see _public_entry).
            envs = [
                _public_entry(environment_id, meta.get("name"), meta, engine_owner, full=full)
                for environment_id, meta in engine.list_all_environments().items()
            ]
        else:
            envs = [_public_entry(m["environment_id"], n, m, engine_owner, full=full) for n, m in engine.list_environments_for(engine_owner).items()]
        # UI-07 (external review, 2026-10-05), additive: every
        # name-keyed route (activate, sync, reports) acts on whatever
        # the NAME resolves to for this caller -- `addressable` says
        # whether that is this very row, and `active_id` lets the UI
        # mark the active row by id. Admins see other owners' rows
        # (and shared rows their own same-named environment hides);
        # those are not addressable by name.
        resolves_to = {n: m["environment_id"] for n, m in engine.list_environments_for(engine_owner).items()}
        # 5.42.0: what THIS caller may do with each row (the same
        # resolution the routes enforce) -- the UI only mirrors it.
        # An owner's own rows are always "allow" (source "owner").
        # Admins also get each row's stored overrides, for the
        # per-environment editor.
        defaults = engine.get_shared_permission_defaults()
        can_admin = _can_admin(owner_key, self.headers)
        for entry in envs:
            entry["addressable"] = resolves_to.get(entry["name"]) == entry["id"]
            if not entry["addressable"]:
                # Not what this caller's by-name routes reach (another
                # owner's private row, or one hidden by the caller's
                # own same-named environment): nothing to say.
                pass
            elif entry["is_own"]:
                entry["permissions"] = {k: {"value": "allow", "source": "owner"} for k in engine.SHARED_CAPABILITY_KEYS}
            else:
                entry["permissions"] = engine.effective_shared_permissions(
                    entry["id"], defaults=defaults,
                    caller_issuer=_issuer_from_headers(self.headers), caller_subject=engine_owner)
            if can_admin and full:
                entry["permission_overrides"] = engine.get_shared_permission_overrides(entry["id"])
            if full and (entry["is_own"] or can_admin):
                # 5.53.0: the environment form's "Who can build evidence packages" choice as stored (override, else the default).
                entry["evidence_builders"] = "shared" if engine.effective_shared_permissions(
                    entry["id"], defaults=defaults)["build_evidence_package"]["value"] == "allow" else "owner"
        return {"environments": envs, "active": local_env_name, "active_id": local_env_id}

    def _exec_banner_update(self, params, dry_run, via_step_up):
        """5.53.0: the org-wide announcement banner. Admin-only; in hosted mode it needs a fresh MFA approval like every other
        configuration change (a stolen admin session could otherwise post a message to every user)."""
        owner_key, _e, actor_email, actor_sub = self._caller()
        if not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to change the announcement banner."}
        payload = params.get("body") or {}
        message = payload.get("message", "")
        if not isinstance(message, str):
            return 400, {"error": "message must be a string"}
        if payload.get("variant", "warning") not in engine.BANNER_VARIANTS:
            return 400, {"error": f"variant must be one of {', '.join(engine.BANNER_VARIANTS)}"}
        if payload.get("enabled", False) and not message.strip():
            return 400, {"error": "message is required when the banner is enabled"}
        if dry_run:
            return None, None
        config = engine.set_banner_config(
            payload.get("enabled", False), message, payload.get("variant", "warning"), payload.get("dismissible", True),
        )
        self._log_audit_event(actor_email, actor_sub, "banner.update", {**config, **({"step_up_verified": True} if via_step_up else {})})
        return 200, config

    def _exec_evidence_package_build(self, params, dry_run, via_step_up):
        """5.53.0: builds an evidence package of one environment's archive for a period. Needs View archived reports AND
        Build evidence packages on the environment (owners always pass). Hosted mode: POST /api/evidence_packages/prepare
        checks everything (dry run), stores the request pinned to the environment id, period and gap acknowledgement, and the
        MFA step-up returns to /api/environment_changes/save, which runs this again with every check repeated and starts the
        job. Local mode starts it at once. `check_only` answers the coverage summary and starts nothing. This approval is not a
        Settings unlock and never opens or extends one."""
        import evidence_core
        import evidence_package
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            return 400, {"error": "environment is required"}
        body = params.get("body") or {}
        meta, refusal = self._visible_environment(name, params)
        if refusal:
            return refusal
        refusal = self._shared_refusal(meta, "view_archive")
        if refusal:
            return refusal
        refusal = self._shared_refusal(meta, "build_evidence_package")
        if refusal:
            return refusal
        expected_id = body.get("environment_id")
        if expected_id is not None and (not isinstance(expected_id, str) or expected_id != meta["environment_id"]):
            return self._target_changed()
        try:
            period = evidence_core.parse_period(body.get("start"), body.get("end"))
        except evidence_core.PeriodError as exc:
            return 400, {"error": str(exc), "reason": "bad_period"}
        gaps_ack = body.get("gaps_acknowledged") is True
        if not _evidence_checks.acquire(blocking=False):
            return 429, {"error": "The archive is busy with other coverage checks. Try again in a moment.", "reason": "busy"}
        try:
            summary = evidence_package.preview(meta["environment_id"], period,
                                               prune_records=evidence_core.prune_records_from_audit_log(meta.get("name") or name))
        except evidence_core.EvidenceError:
            return 409, {"error": "This environment has no archive yet, so there is nothing to put in a package.", "reason": "no_coverage"}
        finally:
            _evidence_checks.release()
        if params.get("check_only"):
            return 200, summary
        if not summary["has_coverage"]:
            return 409, {"error": "The archive has no coverage at all for this period, so there is nothing to put in a package.",
                         "reason": "no_coverage", "coverage": summary}
        if summary["needs_acknowledgement"] and not gaps_ack:
            return 409, {"error": "This period has days the archive did not cover. Confirm the gaps to build the package with them.",
                         "reason": "gaps_unacknowledged", "coverage": summary}
        actor_sub, issuer, fingerprint = self._unlock_identity()
        if _step_up_required_for_changes() and (not actor_sub or not fingerprint):
            return 403, {"error": "Could not tell which sign-in session this is. Sign in again.", "reason": "no_session"}
        if dry_run:
            return None, {"environment_id": meta["environment_id"], "start": period.start.isoformat(), "end": period.end.isoformat(),
                          "gaps_acknowledged": gaps_ack}
        _owner_key, engine_owner, actor_email, actor_sub = self._caller()
        local = not _step_up_required_for_changes()
        ctx = {
            "environment_id": meta["environment_id"], "environment_name": meta.get("name") or name, "period": period.as_dict(),
            "gaps_acknowledged": gaps_ack, "mode": "local mode, no MFA" if local else "hosted, MFA step-up",
            "engine_owner": engine_owner, "actor_email": actor_email, "actor_sub": actor_sub,
            "issuer": _issuer_from_headers(self.headers), "client_ip": self._request_client_ip(),
            "user_agent": self.headers.get("User-Agent"), "correlation_id": engine.CORRELATION_ID.get(),
            "builder": actor_email or actor_sub or "local operator",
        }
        try:
            job_id = _evidence.start({
                "environment_id": ctx["environment_id"], "environment_name": ctx["environment_name"], "period": ctx["period"],
                "gaps_acknowledged": gaps_ack, "owner": actor_sub or "", "issuer": issuer, "fingerprint": fingerprint,
                "mode": "local" if local else "hosted"})
        except evidence_jobs.Busy as exc:
            return 409, {"error": str(exc), "reason": exc.reason}
        except OSError as exc:
            engine.log("WARN", f"Evidence package not started: the packages folder cannot be used ({exc.strerror or type(exc).__name__}).")
            return 500, {"error": "The packages folder could not be created. Check the data folder's permissions and free space.", "reason": "packages_dir"}
        ctx["job_id"] = job_id
        details = {"environment": ctx["environment_name"], "environment_id": ctx["environment_id"], "period": ctx["period"],
                   "gaps_acknowledged": gaps_ack, "mode": ctx["mode"], "outcome": "started", "job_id": job_id}
        if via_step_up:
            details["step_up_verified"] = True
        else:
            details["mfa"] = "local mode, no MFA" if local else "none"
        self._log_audit_event(actor_email, actor_sub, "evidence_package.build", details)
        engine.log("INFO", "evidence_package.build " + json.dumps({"job_id": job_id, "environment_id": ctx["environment_id"], "period": ctx["period"],
                                                                    "gaps_acknowledged": gaps_ack, "mode": ctx["mode"], "outcome": "started",
                                                                    "actor_sub": actor_sub, "client_ip": ctx["client_ip"]}, separators=(",", ":")))
        try:
            threading.Thread(target=_run_evidence_build, args=(job_id, ctx), daemon=True, name=f"evidence-{job_id[:6]}").start()
        except BaseException:
            _evidence.fail(job_id, "internal", "The build could not be started.")
            raise
        return 202, {"job_id": job_id, "status": "running", "environment": ctx["environment_name"], "period": ctx["period"]}

    def _evidence_package_request(self, job_id, download):
        """GET /api/evidence_packages/<job_id> and .../download. The job must be this caller's own (sub, gate issuer, login
        session, job id) or it is a 404, whatever else is true; the caller's permission on the environment is checked again
        on every call. A download is repeatable until the window ends and every fetch is logged."""
        if not evidence_jobs.JOB_ID_RE.match(job_id or ""):
            return self._send_json(404, {"error": "No such package."})
        owner_key, engine_owner, actor_email, actor_sub = self._caller()
        sub, issuer, fingerprint = self._unlock_identity()
        status, job, path = _evidence.open_for_download(job_id, sub, issuer, fingerprint)
        if status == "notfound":
            return self._send_json(404, {"error": "No such package."})
        refusal = _evidence_caller_refusal(job["environment_id"], engine_owner, _issuer_from_headers(self.headers))
        if refusal:
            return self._send_json(*refusal)
        if not download:
            return self._send_json(200, _evidence.public(job))
        if status == "expired":
            return self._send_json(410, {"error": "The download window for this package has ended. The package was deleted from the server; build it again.",
                                         "reason": "expired"})
        if status == "notready":
            return self._send_json(409, {"error": "This package is not finished yet.", "reason": "not_ready", "status": job["status"]})
        result = job["result"]
        details = {"environment": job["environment_name"], "environment_id": job["environment_id"], "period": job["period"],
                   "sha256": result["sha256"], "bytes": result["bytes"], "chain_head": result["chain_head"], "job_id": job_id}
        try:
            fh = open(path, "rb")
        except OSError:
            return self._send_json(410, {"error": "The download window for this package has ended. Build it again.", "reason": "expired"})
        with fh:
            size = os.fstat(fh.fileno()).st_size
            self._log_audit_event(actor_email, actor_sub, "evidence_package.downloaded", {**details, "outcome": "started"})
            engine.log("INFO", "evidence_package.downloaded " + json.dumps({"job_id": job_id, "bytes": size, "sha256": result["sha256"],
                                                                            "actor_sub": actor_sub, "client_ip": self._request_client_ip()}, separators=(",", ":")))
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{job["filename"]}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            sent = 0
            try:
                while True:
                    block = fh.read(EVIDENCE_STREAM_CHUNK)
                    if not block:
                        break
                    self.wfile.write(block)
                    sent += len(block)
            except OSError:
                self.close_connection = True
                self._log_audit_event(actor_email, actor_sub, "evidence_package.downloaded", {**details, "outcome": "aborted", "bytes_sent": sent})
        return None

    def _unlock_identity(self):
        """(actor_sub, issuer, session fingerprint) of this request for the Settings unlock; sub or fingerprint may be None."""
        _owner_key, _e, _em, actor_sub = self._caller()
        return actor_sub, _issuer_from_headers(self.headers) or "", _session_fingerprint(self.headers)

    def _exec_settings_unlock(self, params, dry_run, via_step_up):
        """5.53.0: opens Settings and Updates for this user, this gate and this login session for SETTINGS_UNLOCK_TTL_SECONDS.
        Per user, never a privilege (it checks no admin right: every protected route keeps its own). It changes no setting.
        Local mode has no MFA: it answers at once and records nothing."""
        if not _step_up_required_for_changes():
            return 200, {"mode": "local", "mfa": False}
        import audit_store
        actor_sub, issuer, fingerprint = self._unlock_identity()
        if not actor_sub or not fingerprint:
            return 403, {"error": "Could not tell which sign-in session this is. Sign in again.", "reason": "no_session"}
        if dry_run:
            return None, None
        if params.get("session") != fingerprint:
            return 409, {"error": "You signed in again while approving. Nothing was unlocked; start again.",
                         "reason": "session_changed"}
        action_id = self.headers.get("X-Auth-Action-Id") or ""
        unlocked_at, expires_at = audit_store.upsert_settings_unlock(
            actor_sub, issuer, fingerprint, action_id, SETTINGS_UNLOCK_TTL_SECONDS)
        _o, _e, actor_email, _s = self._caller()
        self._log_audit_event(actor_email, actor_sub, "settings.unlocked", {
            "scope": "settings", "unlocked_until": expires_at, "ttl_seconds": SETTINGS_UNLOCK_TTL_SECONDS,
            "step_up_verified": True, "action_id": action_id})
        return 200, {"unlocked_until": expires_at, "seconds_left": SETTINGS_UNLOCK_TTL_SECONDS}

    def _require_settings_unlock(self):
        """5.53.0: True when this request may read Settings or Updates; otherwise answers 403 settings_locked and returns
        False. Call it AFTER the route's own admin or owner check (a non-admin keeps the admin message) and BEFORE reading any
        data. Local mode has no MFA and always passes. Branches on the process-level mode only, never on a header."""
        if not _step_up_required_for_changes():
            return True
        import audit_store
        actor_sub, issuer, fingerprint = self._unlock_identity()
        if actor_sub and fingerprint:
            expired = audit_store.take_expired_settings_unlock(actor_sub, issuer, fingerprint)
            if expired:  # the first refused request after expiry records it, once (the row is deleted atomically)
                _o, _e, actor_email, _s = self._caller()
                self._log_audit_event(actor_email, actor_sub, "settings.locked", {
                    "reason": "expired", "unlocked_at": expired["unlocked_at"], "expired_at": expired["expires_at"]})
            if audit_store.settings_unlock_active(actor_sub, issuer, fingerprint):
                return True
        self._send_json(403, {"error": "Unlock Settings with MFA to view this.", "step_up_required": True,
                              "scope": "settings", "reason": "settings_locked"})
        return False

    def _renew_settings_unlock_after_mfa(self, actor_sub, action_type, action_id):
        """5.53.0: called right after a pending approval was consumed. Only the action types in
        SETTINGS_RENEWING_ACTION_TYPES restart the caller's unlock (an upsert, so a save after expiry opens it again); any
        other type, `settings.unlock` and `evidence_package.build` included, never creates or extends it. Returns whether it
        renewed. Hosted mode only; fails closed without a subject or a session fingerprint."""
        if action_type not in SETTINGS_RENEWING_ACTION_TYPES or not _step_up_required_for_changes():
            return False
        import audit_store
        _sub, issuer, fingerprint = self._unlock_identity()
        if not actor_sub or not fingerprint:
            return False
        audit_store.renew_settings_unlock(actor_sub, issuer, fingerprint, action_id or "", SETTINGS_UNLOCK_TTL_SECONDS)
        return True

    def _settings_status(self, qs):
        """GET /api/settings/status: the countdown and mode for the UI. Writes nothing in hosted mode."""
        area = (qs.get("area") or [""])[0]
        if not _step_up_required_for_changes():
            if area in SETTINGS_AREAS and _local_access_due(area):
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "settings.access_without_mfa_local",
                                      {"area": area, "mode": "local", "mfa": False})
            return {"mode": "local", "mfa": False, "unlocked": True, "unlocked_until": None, "seconds_left": 0,
                    "local_notice": LOCAL_MODE_NOTICE}
        import audit_store
        actor_sub, issuer, fingerprint = self._unlock_identity()
        # (a read that leaves an expired row alone: the first refused request records the expiry, see _require_settings_unlock)
        row = audit_store.settings_unlock_active(actor_sub, issuer, fingerprint, delete_expired=False) if actor_sub and fingerprint else None
        left = 0
        if row:
            try:
                expires = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                left = max(0, int((expires - datetime.now(timezone.utc)).total_seconds()))
            except ValueError:
                row = None
        return {"mode": "hosted", "mfa": True, "unlocked": bool(row), "unlocked_until": row["expires_at"] if row else None,
                "seconds_left": left if row else 0, "local_notice": None}

    def _exec_upgrade_settings_update(self, params, dry_run, via_step_up):
        """5.46.0: the update check's frequency (daily / manual / off) and the share-version
        switch. Admin-only; in hosted mode it needs a fresh MFA approval like every other
        configuration change (the Updates screen says so). Audit-logged."""
        owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        if not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to change update settings."}
        payload = params.get("body") or {}
        problem = update_service.validate_settings_payload(payload)
        if problem:
            return 400, {"error": problem}
        switch, _bad = update_service.env_switch()
        wants_on = payload.get("frequency", "on" if payload.get("enabled") else "off") != "off" and ("frequency" in payload or "enabled" in payload)
        if wants_on and switch == "off":
            return 409, {"error": "The update check is switched off by OPA_UPDATE_CHECK=off in this server's environment, "
                                  "which always wins. Remove that setting (and restart) to allow it.", "reason": "env_locked"}
        if dry_run:
            return None, None

        def audit(action, details):
            extra = {"step_up_verified": True} if via_step_up else {}
            self._log_audit_event(actor_email, actor_sub, action, {**details, **extra})

        return update_service.apply_settings_request(payload, engine.SCRIPT_VERSION, audit)

    # -----------------------------------------------------------------
    # In-app upgrade (5.48.0)
    # -----------------------------------------------------------------
    def _upgrade_view(self, qs):
        now = datetime.now(timezone.utc)
        data = update_service.load()
        latest = data["state"].get("latest_version")
        run = upgrade_service.run_view()
        sched = upgrade_service.load_schedule()
        pa = upgrade_service.pending_approval(now)
        owner_key, _e, _em, actor_sub = self._caller()
        preview = upgrade_service.current_preview(latest) if latest and update_service.newer(latest, engine.SCRIPT_VERSION) else None
        rej = None
        for cid in (qs.get("correlation_id") or [])[:1]:
            rej = upgrade_service.rejection(cid)
        hist = upgrade_service.history_view()
        return {
            "run": run,
            "updater": upgrade_service.updater_state(),
            "preview": preview,
            "schedule": sched["schedule"],
            "last": sched["last"],
            "pending_approval": ({k: pa.get(k) for k in ("kind", "version", "sha256", "when_utc", "entered", "first_email", "created_at",
                                                         "expires_at", "correlation_id")}
                                 | {"mine": bool(actor_sub) and pa.get("first_sub") == actor_sub}) if pa else None,
            "settings": {"second_approval": data["settings"].get("second_approval") is True},
            "rejection": rej,
            "rollback": upgrade_service.rollback_view(run, now),
            "failures": upgrade_service.failures_view(),
            "history": hist,
            "backups": upgrade_service.backups_view(),
            "zone": {"iana": upgrade_service.server_zone()},
            "sync_hint": self._upgrade_sync_hint(),
            "step_up_required": _step_up_required_for_changes(),
            "now": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    @staticmethod
    def _upgrade_sync_hint():
        """For the schedule dialog's maintenance-window hint: when the last sync finished and when the daily syncs run (UTC)."""
        import audit_store
        last, times = None, set()
        try:
            for environment_id in engine.list_all_environments():
                try:
                    schedule = engine.get_sync_schedule_by_id(environment_id)
                except KeyError:
                    continue
                if schedule.get("enabled"):
                    times.add(str(schedule.get("run_time") or "02:00")[:5])
                state = audit_store.get_sync_state(environment_id) or {}
                done = state.get("last_sync_completed_at")
                if isinstance(done, str) and (last is None or done > last):
                    last = done
        except Exception:  # noqa: BLE001 - a hint must never break the status
            pass
        return {"last_sync_completed_at": last, "daily_run_times_utc": sorted(times)}

    def _upgrade_preview(self, actor_email, actor_sub):
        data = update_service.load()
        st = data["state"]
        if not update_service.is_enabled(data)[0]:
            return 409, {"error": "The update check is off; turn it on and use Check now first.", "reason": "check_off"}
        try:
            preview = upgrade_service.build_preview(engine.SCRIPT_VERSION, st.get("size"), _upgrade_context())
        except upgrade_service.PreviewError as exc:
            self._log_audit_event(actor_email, actor_sub, "upgrade.preview", {"result": "failed", "reason_code": exc.code, "detail": str(exc)[:300]})
            return (502 if exc.code == "fetch_failed" else 409), {"error": str(exc), "reason": exc.code}
        self._log_audit_event(actor_email, actor_sub, "upgrade.preview", {
            "result": "ok" if preview["preflight_ok"] else "preflight_failed", "version": preview["version"], "sha256": preview["sha256"],
            "signed_by": preview["key_id"], "preflight": {i["id"]: i["ok"] for i in preview["preflight"]}})
        return 200, {"preview": preview}

    UPGRADE_BODY_FIELDS = {"kind": 16, "version": 20, "sha256": 64, "when_utc": 24, "entered_tz": 64, "entered_local": 20, "target": 16,
                           "confirm": 16, "for_correlation_id": 16, "backup": 100}
    UPGRADE_KINDS = ("apply", "schedule", "reschedule", "cancel", "approve_second",
                     "rollback", "restore", "clear_failure", "bundle", "prune_backups")

    def _exec_upgrade_operation(self, kind, body, dry_run, via_step_up):
        """5.48.0: rollback / restore / clear a failure / rebuild the support bundle / delete old backups. Each is typed where it
        loses or deletes something, needs a fresh MFA approval, and is handed to the root-owned updater, which re-validates it."""
        owner_key, _e, actor_email, actor_sub = self._caller()
        now = datetime.now(timezone.utc)
        if kind == "prune_backups":
            # Deleting the root-held pre-upgrade copies is not something this application can ask the updater for: a request
            # from a compromised web process would look the same. The page shows the command instead.
            return 409, {"error": "Old pre-upgrade backups are deleted on the server, not from this page. Run "
                                  "`sudo ocw-updater prune-backups --keep N --confirm PRUNE` there.", "reason": "cli_only"}
        allowed = {"rollback": {"kind", "confirm"}, "restore": {"kind", "confirm", "backup"}, "clear_failure": {"kind"},
                   "bundle": {"kind", "include_hosts", "for_correlation_id"}}[kind]
        if set(body) - allowed:
            return 400, {"error": "Unexpected field for this request."}
        typed = {"rollback": "ROLLBACK", "restore": "RESTORE"}.get(kind)
        if typed and body.get("confirm") != typed:
            return 400, {"error": f"Type {typed} to confirm.", "reason": "confirm_required"}
        state = upgrade_service.updater_state()
        if not state["ready"]:
            return 409, {"error": state["message"], "reason": state["reason"]}
        if upgrade_service.activator_too_old(state.get("activator")):
            return 409, {"error": f"The installed updater (version {state.get('activator')}) does not take this request yet. It is replaced "
                                  "by the next upgrade, or run `sudo ocw-updater` on the server.", "reason": "activator_too_old",
                         "activator": state.get("activator")}
        run = upgrade_service.run_view()
        if run and run.get("result") is None and run.get("step"):
            return 409, {"error": "An upgrade is in progress.", "reason": "in_flight"}
        backups_status = upgrade_service.backups_view()  # None = the updater has not published the list yet (unknown, not "none")
        backups = (backups_status or {}).get("backups", [])
        if kind == "rollback":
            rb = upgrade_service.rollback_view(run, now)
            if not rb or not rb["available"]:
                return 409, {"error": "Rolling back is only offered for 24 hours after an upgrade completes.", "reason": "rollback_unavailable"}
        elif kind == "restore":
            shown = (run or {}).get("backup")
            if (backups_status is not None and not backups) or not (isinstance(shown, dict) and shown.get("name")):
                return 409, {"error": "There is no pre-upgrade copy of the archive to restore.", "reason": "no_backup"}
            name = body.get("backup")
            if not isinstance(name, str) or not upgrade_service.BACKUP_NAME_RE.match(name):
                return 400, {"error": "Name the backup copy to restore (backup).", "reason": "backup_required"}
            if name != shown["name"]:  # the copy named in the approved request is the one the updater would restore, or nothing happens
                return 409, {"error": "The pre-upgrade copy changed since this page was loaded. Nothing was restored; reload the page.",
                             "reason": "target_changed"}
        elif kind == "clear_failure":
            if run and run.get("result") == "failed_needs_operator":
                return 409, {"error": "The last upgrade could not be rolled back automatically. An operator must run "
                                      "`sudo ocw-updater clear-failure` on the server.", "reason": "needs_operator"}
            if not upgrade_service.failures_view() and not (run and run.get("result") == "failed_needs_operator"):
                return 409, {"error": "There is no recorded failure to clear.", "reason": "nothing_to_clear"}
        elif kind == "bundle":
            if not run or not run.get("correlation_id"):
                return 409, {"error": "There is no upgrade run to build a support bundle for.", "reason": "no_run"}
            fc = body.get("for_correlation_id")
            if fc is not None and (not upgrade_service.CID_RE.match(fc) or fc != run.get("correlation_id")):
                return 409, {"error": "A bundle can only be built for the last upgrade run.", "reason": "target_changed"}
        if dry_run:
            return None, ({"kind": kind, "backup": body["backup"]} if kind == "restore" else {"kind": kind})
        cid = upgrade_service.new_correlation_id()
        action_id = self.headers.get("X-Auth-Action-Id") if via_step_up else None
        fields = {k: v for k, v in body.items() if k != "kind"}
        try:
            upgrade_service.write_action(kind, correlation_id=cid, action_id=action_id, actor=actor_email or actor_sub, now=now, **fields)
        except OSError as exc:
            return 409, {"error": f"The upgrade inbox could not be written ({exc.strerror}). Nothing was started.", "reason": "inbox_not_writable"}
        details = {"correlation_id": cid, "kind": kind}
        if via_step_up:
            details.update(step_up_verified=True, action_id=action_id)
        if kind == "bundle":
            details["include_hosts"] = bool(body.get("include_hosts"))
        if kind == "restore":
            details["backup"] = body.get("backup")
        self._log_audit_event(actor_email, actor_sub, "upgrade.requested", details)
        return 200, {"kind": kind, "correlation_id": cid}

    def _exec_upgrade_request(self, params, dry_run, via_step_up):
        """5.48.0: upgrade now (apply) / schedule / reschedule / cancel / the second administrator's approval. Every check
        runs again when the approved request is applied; the approval covers this exact version, hash and time."""
        owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        if not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to upgrade."}
        body = params.get("body") or {}
        if not isinstance(body, dict):
            return 400, {"error": "Send a JSON object."}
        for key, value in body.items():
            if key in ("acknowledged", "include_hosts"):
                if not isinstance(value, bool):
                    return 400, {"error": f"{key} must be true or false."}
            elif key == "keep_last":
                if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 50:
                    return 400, {"error": "keep_last must be a whole number from 1 to 50."}
            elif key == "names":
                if not isinstance(value, list) or not 1 <= len(value) <= 50 \
                        or not all(isinstance(n, str) and upgrade_service.BACKUP_NAME_RE.match(n) for n in value):
                    return 400, {"error": "names must be 1 to 50 backup file names."}
            elif key not in self.UPGRADE_BODY_FIELDS or not isinstance(value, str) or len(value) > self.UPGRADE_BODY_FIELDS[key]:
                return 400, {"error": f"Unexpected or oversized field '{key}'."}
        kind = body.get("kind")
        if kind not in self.UPGRADE_KINDS:
            return 400, {"error": "kind must be one of: " + ", ".join(self.UPGRADE_KINDS) + "."}
        if kind in ("rollback", "restore", "clear_failure", "bundle", "prune_backups"):
            return self._exec_upgrade_operation(kind, body, dry_run, via_step_up)
        now = datetime.now(timezone.utc)
        stamp = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        sched_data = upgrade_service.load_schedule()
        sched = sched_data["schedule"] if (sched_data["schedule"] or {}).get("status") == "scheduled" else None
        pa = upgrade_service.pending_approval(now)
        two = update_service.load()["settings"].get("second_approval") is True and _step_up_required_for_changes()
        actor = (actor_email, actor_sub)
        if kind == "cancel":
            if not sched and not pa:
                return 409, {"error": "Nothing is scheduled or waiting for approval.", "reason": "not_scheduled"}
            if dry_run:
                return None, {"cancel": (sched or pa).get("correlation_id")}
            bound = (params.get("bound") or {}).get("cancel")
            with upgrade_service._lock:
                data = upgrade_service.load_schedule()
                target = data["schedule"] if (data["schedule"] or {}).get("status") == "scheduled" else None
                held = data["pending_approval"]
                cid = (target or held or {}).get("correlation_id")
                if cid is None or (bound is not None and bound != cid):
                    return self._target_changed()
                if target:
                    target["status"] = "cancelled"
                data["pending_approval"] = None
                data["last"] = {"kind": "cancelled", "version": (target or held).get("version"), "at": stamp(now), "correlation_id": cid}
                upgrade_service.save_schedule(data)
            details = {"correlation_id": cid, "version": (target or held).get("version"), "what": "schedule" if target else "approval request"}
            if held and not target and held.get("first_sub") != actor_sub:
                details["declined_by_second_admin"] = True
            if via_step_up:
                details["step_up_verified"] = True
            self._log_audit_event(actor_email, actor_sub, "upgrade.cancelled", details)
            return 200, {"kind": "cancel", "correlation_id": cid}

        # --- the kinds that start or schedule an install -------------------------------------------------------------
        if kind == "approve_second":
            if not pa:
                return 409, {"error": "No request is waiting for a second approval (it may have expired).", "reason": "no_pending"}
            if actor_sub and pa.get("first_sub") == actor_sub:
                return 403, {"error": "A different administrator must give the second approval.", "reason": "same_admin"}
            version, sha256, eff_kind = pa["version"], pa["sha256"], pa["kind"]
            when_utc, entered_tz, entered_local = pa.get("when_utc"), None, None
            ack = True
        else:
            version, sha256, eff_kind = body.get("version"), body.get("sha256"), kind
            when_utc, entered_tz, entered_local = body.get("when_utc"), body.get("entered_tz"), body.get("entered_local")
            ack = body.get("acknowledged") is True
            if not isinstance(version, str) or not upgrade_service.VERSION_RE.match(version) or not isinstance(sha256, str) \
                    or not upgrade_service.SHA_RE.match(sha256):
                return 400, {"error": "version (X.Y.Z) and sha256 (64 hex digits) are required."}
            if not ack:
                return 400, {"error": "Tick the acknowledgement: you must confirm the code-only rollback and the downtime.", "reason": "not_acknowledged"}
            if kind == "apply" and when_utc:
                return 400, {"error": "'apply' runs now; use 'schedule' for a time."}
            if pa:
                return 409, {"error": "An upgrade request is already waiting for a second administrator's approval; cancel it first.",
                             "reason": "already_pending"}
        if eff_kind in ("schedule", "reschedule"):
            when = update_service._parse_iso(when_utc) if isinstance(when_utc, str) else None
            if when is None:
                return 400, {"error": "when_utc must be a UTC time like 2026-10-21T02:30:00Z."}
            if (entered_tz or entered_local) and not (entered_tz and entered_local):
                return 400, {"error": "Send entered_tz and entered_local together."}
            if entered_tz:
                try:
                    consistent = upgrade_service.convert_local(entered_local, entered_tz) == when_utc
                except Exception:  # noqa: BLE001 - unknown zone / malformed time
                    return 400, {"error": "entered_tz / entered_local are not a valid zone and time."}
                if not consistent:
                    return 400, {"error": "entered_local in entered_tz is not the same moment as when_utc."}
            if when < now + upgrade_service.MIN_LEAD:
                return 409, {"error": "That time is in the past or less than two minutes away. Pick a later time.", "reason": "time_passed"}
            if when > now + upgrade_service.MAX_AHEAD:
                return 400, {"error": "An upgrade can be scheduled at most 31 days ahead."}
            if eff_kind == "schedule" and sched:
                return 409, {"error": "An upgrade is already scheduled; reschedule or cancel it.", "reason": "already_scheduled"}
            if eff_kind == "reschedule" and not sched:
                return 409, {"error": "Nothing is scheduled to reschedule.", "reason": "not_scheduled"}
        state = upgrade_service.updater_state()
        if not state["ready"]:
            return 409, {"error": state["message"], "reason": state["reason"]}
        data = update_service.load()
        latest = data["state"].get("latest_version")
        if latest != version or not update_service.newer(version, engine.SCRIPT_VERSION):
            return 409, {"error": f"{version} is not the latest known release for this installation. Use Check now.", "reason": "target_changed"}
        preview = upgrade_service.current_preview(version)
        if not preview or preview.get("sha256") != sha256:
            return 409, {"error": "The signed release information must be reviewed first (or it changed). Reload the Updates page.",
                         "reason": "preview_missing" if not preview else "target_changed"}
        fails = upgrade_service.failures_view()
        if fails.get(version, {}).get("count", 0) >= 1:
            return 409, {"error": f"{version} failed here before. An operator must run `ocw-updater clear-failure` on the server first.",
                         "reason": "version_failed_before"}
        if sum(v.get("count", 0) for v in fails.values()) >= 2:
            return 409, {"error": "Two upgrades have failed. Contact the maintainers with the support bundle; an operator must run "
                                  "`ocw-updater clear-failure` first.", "reason": "too_many_failures"}
        run = update_service.upgrade_run() or {}
        if run.get("result") == "failed_needs_operator":
            return 409, {"error": "The last upgrade could not be rolled back automatically. An operator must act on the server "
                                  "(`ocw-updater status`).", "reason": "needs_operator"}
        if run.get("result") is None and run.get("step"):
            return 409, {"error": "Another upgrade is in progress.", "reason": "in_flight"}
        fresh = upgrade_service.refresh_preflight(_upgrade_context(), now) or preview
        if not fresh.get("preflight_ok"):
            bad = next((i for i in fresh["preflight"] if not i["ok"]), {"text": "a preflight check failed"})
            return 409, {"error": "Preflight failed: " + bad["text"], "reason": "preflight_failed"}
        if dry_run:
            return None, {"version": version, "sha256": sha256, "when_utc": when_utc if eff_kind in ("schedule", "reschedule") else None}
        bound = params.get("bound") or {}
        if bound.get("version") != version or bound.get("sha256") != sha256 or (
                eff_kind in ("schedule", "reschedule") and bound.get("when_utc") != when_utc):
            return self._target_changed()
        if eff_kind in ("schedule", "reschedule"):
            if update_service._parse_iso(when_utc) < now + timedelta(seconds=60):
                return 409, {"error": "The scheduled time passed while waiting for the MFA approval. Pick a new time.", "reason": "time_passed"}
        cid = upgrade_service.new_correlation_id()
        action_id = self.headers.get("X-Auth-Action-Id") if via_step_up else None
        entered = f"{entered_tz} {entered_local[11:16]}" if entered_tz and entered_local else None
        details = {"correlation_id": cid, "version": version, "sha256": sha256, "signed_by": preview.get("key_id"),
                   "acknowledged": ["rollback is code-only", "downtime about a minute"]}
        if via_step_up:
            details.update(step_up_verified=True, action_id=action_id)
        if kind != "approve_second" and two:
            with upgrade_service._lock:
                d = upgrade_service.load_schedule()
                d["pending_approval"] = {"kind": eff_kind, "version": version, "sha256": sha256, "when_utc": when_utc if eff_kind != "apply" else None,
                                         "entered": entered, "first_sub": actor_sub, "first_email": actor_email, "correlation_id": cid,
                                         "action_id": action_id, "created_at": stamp(now),
                                         "expires_at": stamp(now + upgrade_service.APPROVAL_TTL)}
                upgrade_service.save_schedule(d)
            self._log_audit_event(actor_email, actor_sub, "upgrade.requested", {**details, "awaiting_second_approval": True,
                                                                               "when_utc": when_utc, "expires_at": stamp(now + upgrade_service.APPROVAL_TTL)})
            return 200, {"kind": kind, "awaiting_second_approval": True, "correlation_id": cid}
        if kind == "approve_second":
            cid = pa["correlation_id"]
            details.update(correlation_id=cid, second_approval=True, first_approved_by=pa.get("first_email") or "an administrator")
            entered = pa.get("entered")
        with upgrade_service._lock:
            d = upgrade_service.load_schedule()
            d["pending_approval"] = None
            if eff_kind == "apply":
                if sched:
                    if d["schedule"]:
                        d["schedule"]["status"] = "replaced"
                    self._log_audit_event(actor_email, actor_sub, "upgrade.cancelled", {
                        "correlation_id": sched.get("correlation_id"), "version": sched.get("version"), "what": "schedule",
                        "reason": "the administrator chose to upgrade now instead"})
                try:
                    upgrade_service.write_request(correlation_id=cid, version=version, sha256=sha256, action_id=action_id,
                                                  actor=actor_email or actor_sub, trigger_kind="app", now=now)
                except OSError as exc:
                    return 409, {"error": f"The upgrade inbox could not be written ({exc.strerror}). Nothing was started; re-run "
                                          "server/install.sh or check the permissions of the upgrade directory.", "reason": "inbox_not_writable"}
                upgrade_service.save_schedule(d)
                self._log_audit_event(actor_email, actor_sub, "upgrade.requested", {**details, "when": "now"})
                return 200, {"kind": "apply", "correlation_id": cid, "version": version}
            d["schedule"] = {"correlation_id": cid, "version": version, "sha256": sha256, "when_utc": when_utc, "entered": entered,
                             "entered_tz": entered_tz, "status": "scheduled", "actor_email": actor_email, "actor_sub": actor_sub,
                             "action_id": action_id, "approved_at": stamp(now), "key_id": preview.get("key_id"),
                             "replaces": sched.get("correlation_id") if sched else None}
            d["last"] = None
            upgrade_service.save_schedule(d)
        self._log_audit_event(actor_email, actor_sub, "upgrade.rescheduled" if eff_kind == "reschedule" else "upgrade.scheduled",
                              {**details, "when_utc": when_utc, "entered_tz": entered_tz, "entered_zone_time": entered})
        return 200, {"kind": eff_kind, "correlation_id": cid, "version": version, "when_utc": when_utc}

    def _exec_shared_permissions_update(self, params, dry_run, via_step_up):
        """Admin-only: the global defaults (no environment_id), one
        environment's overrides, or (5.43.0, `user` = {"issuer", "subject"})
        one user's exceptions on one environment. Audit-logged with every
        changed capability's stored value before and after."""
        owner_key, _engine_owner_, actor_email, actor_sub = self._caller()
        if not _can_admin(owner_key, self.headers):
            return 403, {"error": "Admin access required to change shared-environment permissions."}
        payload = params.get("body") or {}
        environment_id = payload.get("environment_id")
        if environment_id is not None and (not isinstance(environment_id, str) or not environment_id):
            return 400, {"error": "environment_id must be a non-empty string, or omitted for the global defaults"}
        try:
            changes = engine.validate_shared_permission_changes(payload.get("changes"))
        except ValueError as exc:
            return 400, {"error": str(exc)}
        grantee = payload.get("user")
        if grantee is not None:
            if environment_id is None:
                return 400, {"error": "A per-user exception needs an environment_id."}
            if not isinstance(grantee, dict) or not engine.valid_grant_identity(grantee.get("issuer"), grantee.get("subject")):
                return 400, {"error": "user must be {issuer: the Okta issuer URL, subject: the user's Okta id (sub)}"}
            grantee = {"issuer": grantee["issuer"], "subject": grantee["subject"]}
        meta = None
        if environment_id is not None:
            meta = engine.list_all_environments().get(environment_id)
            if meta is None:
                return 404, {"error": f"No saved environment with id '{environment_id}'"}
        if dry_run:
            return None, None
        try:
            diff = engine.set_shared_permissions(changes, environment_id=environment_id,
                                                 updated_by=actor_email or actor_sub, grantee=grantee)
        except KeyError as exc:
            return 404, {"error": str(exc)}
        details = {"scope": "user" if grantee else "environment" if environment_id else "default", "changes": diff}
        if environment_id:
            details.update({"environment_id": environment_id, "name": meta.get("name")})
        if grantee:
            known = {(i["issuer"], i["subject"]): i.get("email") for i in engine.list_known_identities()}
            details["user"] = {**grantee, "email": known.get((grantee["issuer"], grantee["subject"]))}
        if via_step_up:
            details["step_up_verified"] = True
        if diff:
            self._log_audit_event(actor_email, actor_sub, "shared_permissions.update", details)
        return 200, {
            "changed": diff,
            "defaults": engine.get_shared_permission_defaults(),
            **({"environment_id": environment_id,
                "overrides": engine.get_shared_permission_overrides(environment_id),
                "grants": engine.get_shared_permission_grants(environment_id),
                "effective": engine.effective_shared_permissions(environment_id)} if environment_id else {}),
        }

    # -----------------------------------------------------------------
    def do_HEAD(self):
        """Inherited from SimpleHTTPRequestHandler it served static-file
        metadata with no hosted-mode check at all (5.40.3 review). Same
        guard as every other method; a refusal has no body (HEAD)."""
        if _hosted_request_unauthenticated(self.headers, urlparse(self.path).path):
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_HEAD()

    # -----------------------------------------------------------------
    def do_GET(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if _reject_if_hosted_without_nginx(self, path) or _reject_ambiguous_api_path(self, path):
            return
        # Snapshot this owner's active client(s) ONCE at the start of this
        # request. Sessions are per-owner now (see _sessions above), but the
        # same reasoning still applies: a concurrent request for the SAME
        # owner (switching or deleting their active environment) can
        # reassign their session slot at any time -- reading it repeatedly
        # through a single request risks finishing against a different (or
        # no) client than the one the request started with.
        owner_key = _owner_key_from_headers(self.headers)
        engine_owner = _engine_owner(owner_key)
        _ensure_session_initialized(owner_key, self.headers)
        local_client, local_okta_client, local_env_name, local_env_id = _session_snapshot(owner_key)

        try:
            if path == "/api/version":
                # Lets the frontend show which version is actually running
                # without duplicating the number anywhere in frontend
                # source -- engine.SCRIPT_VERSION is this project's one
                # place version is bumped (see the "bump both together"
                # convention in the engine's header comment).
                return self._send_json(200, {"version": engine.SCRIPT_VERSION})

            if path == "/healthz":
                # Phase 8 of docs/fast-follow-redesign.md: cheap, no-auth
                # (see nginx-opa-secrets-wizard.conf's matching
                # `auth_request off`) target for an external uptime
                # monitor/load balancer -- gives it something real to
                # poll instead of inferring health from whether `/` 200s
                # (which it always will, even with zero environments
                # configured or a broken archive). Deliberately avoids
                # any live Okta API call (would make this endpoint slow
                # and rate-limit-consuming on every poll) -- both checks
                # below are local-only.
                checks = {}
                try:
                    if local_env_name:
                        engine.get_environment_credentials(local_env_name, owner=engine_owner)
                    checks["active_environment_credentials"] = "ok"
                except Exception as exc:
                    # SRV-03: /healthz is unauthenticated -- the detail goes
                    # to the log, never into the response.
                    engine.log("WARN", f"healthz: active environment credentials check failed: {exc}")
                    checks["active_environment_credentials"] = "error"
                try:
                    import audit_store
                    audit_store._get_connection().execute("SELECT 1")
                    checks["archive_writable"] = "ok"
                except Exception as exc:
                    engine.log("WARN", f"healthz: archive check failed: {exc}")
                    checks["archive_writable"] = "error"
                status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
                if DEPLOYMENT_MODE == "hosted" and not _request_is_from_nginx(self.headers):
                    # GATE-06 (external review, 2026-10-05): in hosted mode this
                    # is reachable by anyone who can reach the HTTPS port (nginx
                    # never attaches the proxy secret to it), so it answers only
                    # what a monitor needs. The exact version and which check
                    # failed stay off the network: /api/version on loopback and
                    # the WARN lines above in the journal have them.
                    return self._send_json(200, {"status": status})
                return self._send_json(200, {"status": status, "version": engine.SCRIPT_VERSION, "checks": checks})

            if path == "/api/whoami":
                # Lets the frontend show who's logged in without decoding
                # anything itself -- just echoes the identity nginx already
                # verified and forwarded (see nginx-opa-secrets-wizard.conf's
                # auth_request_set/proxy_set_header bridge). is_local=True
                # (no X-Auth-User header at all) means this is a direct/local
                # run with no login gate in front of it -- there's no "log
                # out" of that, so the frontend can hide the control instead
                # of showing one that does nothing.
                email = self.headers.get("X-Auth-User")
                # can_admin (UI-06, external review 2026-10-05): what the
                # admin-only routes will actually allow THIS caller -- a
                # local-mode operator is exempt server-side (see _can_admin)
                # but is_admin is False there, so the UI used to hide the
                # Audit Log and banner settings the server would serve.
                import audit_store
                return self._send_json(200, {
                    "email": email, "is_local": email is None,
                    "is_admin": _is_admin_from_headers(self.headers),
                    "can_admin": _can_admin(owner_key, self.headers),
                    # 5.51.0: on Windows, a data folder other users of the computer may read (None everywhere else); shown in About
                    "data_location_notice": audit_store.shared_location_notice(),
                })

            if path == "/api/environments":
                # 5.53.0: the list every screen uses to switch environments carries names, ids and permissions only. The
                # OPA domain, team, key id, Okta URL, token flag and sync schedule are read from /api/settings/environments
                # after the MFA unlock.
                return self._send_json(200, self._environments_response(owner_key, engine_owner, local_env_name, local_env_id, full=False))

            if path == "/api/settings/status":
                return self._send_json(200, self._settings_status(qs))

            if path == "/api/settings/environments":
                # 5.53.0: today's full environment entries (no secrets), same owner/admin scoping, behind the unlock.
                if not self._require_settings_unlock():
                    return
                return self._send_json(200, self._environments_response(owner_key, engine_owner, local_env_name, local_env_id, full=True))

            if path == "/api/banner":
                # No client/auth requirement -- this has to render even
                # before an environment is configured (same reasoning as
                # /api/whoami and /api/version above), and it holds no
                # tenant data of its own.
                return self._send_json(200, engine.get_banner_config())

            if path.startswith("/api/environments/") and path.endswith("/refresh/status"):
                # 5.51.0: the combined Refresh job's progress and per-part outcomes (never a name or a URL).
                found = self._environment_from_tail(path, "/refresh/status", engine_owner)
                if found is None:
                    return
                _name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("live_read",)):
                    return
                _o, _e, _email, caller_sub = self._caller()
                return self._send_json(200, _refresh_status(meta["environment_id"], caller_sub=caller_sub))

            if path.startswith("/api/environments/") and path.endswith("/sync/status"):
                name = unquote(path[len("/api/environments/"):-len("/sync/status")])
                import audit_store
                visible = engine.list_environments_for(engine_owner)
                meta = visible.get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
                environment_id = meta["environment_id"]
                if self._capability_refused(engine_owner, environment_id, ("view_archive",)):
                    return
                with _sync_jobs_lock:
                    job = dict(_sync_jobs.get(environment_id, {"status": "idle", "steps": [], "error": None}))
                job["sync_state"] = audit_store.get_sync_state(environment_id)
                if job["sync_state"] and not engine.shared_capability_allowed(environment_id, engine_owner, "live_read",
                                                                              caller_issuer=_issuer_from_headers(self.headers)):
                    job["sync_state"]["last_refresh"] = None  # the per-part outcomes need what /refresh/status needs (live_read)
                job["is_first_sync"] = audit_store.is_first_sync(environment_id)
                return self._send_json(200, job)

            if path.startswith("/api/environments/") and path.endswith("/integrity"):
                # Phase 6 / DATA-04: walks the hash-chained
                # ingestion_manifests table and checks its end against the
                # recorded head; the admin-only ?deep=1 also re-reads every
                # sealed curated event from `events` (see
                # audit_store.verify_ingestion_chain's docstring for what
                # this does and does not detect).
                name = unquote(path[len("/api/environments/"):-len("/integrity")])
                deep = (qs.get("deep") or ["0"])[0] in ("1", "true")  # DATA-04: also re-hash sealed curated events
                if deep and not _can_admin(owner_key, self.headers):
                    # Deep mode re-reads every sealed event (one streamed
                    # query per manifest) -- an admin-only cost.
                    return self._send_json(403, {"error": "Admin access required for a deep integrity check."})
                # Visibility is resolved here, before any job (or a cached
                # result) is touched, then the shared-environment check.
                meta = engine.list_environments_for(engine_owner).get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No saved environment named '{name}'"})
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                if deep:
                    # Bounded per request, single-flight per environment --
                    # see DEEP_VERIFY_WAIT_SECS.
                    status, body = _deep_verify(meta["environment_id"])
                    return self._send_json(status, body)
                import audit_store
                return self._send_json(200, audit_store.verify_ingestion_chain(meta["environment_id"], deep=False))

            if path.startswith("/api/environments/") and path.endswith("/export.csv"):
                # 5.53.0: one report's events for a period as a complete CSV (no row cap):
                # GET /api/environments/<name>/reports/<key>/export.csv?since=&until=
                found = self._report_csv_target(path, engine_owner)
                if found is None:
                    return
                name, report_key, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                return self._serve_report_csv(name, report_key, meta, qs)

            if path.startswith("/api/environments/") and path.endswith("/okta_admins"):
                # 5.50.0: the Okta Admins report, computed from the stored snapshot (never a live Okta call).
                # view_archive (the snapshot is archive evidence) + live_read (the separation-of-duties column
                # joins the OPA roster that live_read exposes).
                found = self._environment_from_tail(path, "/okta_admins", engine_owner)
                if found is None:
                    return
                name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive", "live_read")):
                    return
                import audit_store
                import okta_admins
                as_of = (qs.get("as_of") or [None])[0] or None
                try:
                    audit_store.normalize_window(None, as_of)
                    report = okta_admins.build_okta_admins_report(
                        meta["environment_id"], as_of=as_of, access_model=_access_model_for(meta["environment_id"]))
                except ValueError as exc:
                    return self._send_json(400, {"error": str(exc)})
                report["capture"] = _capture_state(meta["environment_id"])
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "okta_admins.report_read", {
                    "name": name, "as_of": as_of, "state": report["state"], "admins": report["summary"].get("admins"),
                    "snapshot_id": (report.get("as_of_snapshot") or {}).get("snapshot_id")})
                return self._send_json(200, report)

            if path.startswith("/api/environments/") and path.endswith("/cross_checks"):
                # 5.50.0: lifecycle cross-check C1 (the Okta status of every OPA principal) and the per-user flags
                # for the Access Explorer Users view. Stored snapshot + the cached OPA roster; no live call.
                found = self._environment_from_tail(path, "/cross_checks", engine_owner)
                if found is None:
                    return
                name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive", "live_read")):
                    return
                import okta_admins
                env_id = meta["environment_id"]
                model = _access_model_for(env_id)
                cards = [okta_admins.build_cross_checks(env_id, access_model=model)]
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "cross_checks.read", {
                    "name": name, "states": {c["id"]: c["state"] for c in cards}})
                return self._send_json(200, {"cards": cards, "user_flags": okta_admins.user_flags(env_id),
                                             "capture": _capture_state(env_id)})

            if path.startswith("/api/environments/") and path.endswith("/config_snapshots/diff"):
                found = self._environment_from_tail(path, "/config_snapshots/diff", engine_owner)
                if found is None:
                    return
                name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                import audit_store
                try:
                    older, newer = int((qs.get("older") or [""])[0]), int((qs.get("newer") or [""])[0])
                except ValueError:
                    return self._send_json(400, {"error": "older and newer must be snapshot ids"})
                # Only the inventory counts are free of names and e-mails; every other snapshot kind carries the OPA roster or the
                # Okta admins, which live_read guards everywhere else.
                kinds = {(audit_store.get_config_snapshot(meta["environment_id"], i, with_items=False) or {}).get("kind") for i in (older, newer)}
                if kinds - {"inventory_counts"} - {None} and self._capability_refused(engine_owner, meta["environment_id"], ("live_read",)):
                    return
                try:
                    return self._send_json(200, audit_store.diff_config_snapshots(meta["environment_id"], older, newer))
                except ValueError as exc:
                    return self._send_json(404 if "not found" in str(exc) else 400, {"error": str(exc)})

            if path.startswith("/api/environments/") and path.endswith("/config_snapshots/export"):
                found = self._environment_from_tail(path, "/config_snapshots/export", engine_owner)
                if found is None:
                    return
                name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                import audit_store
                try:
                    snapshot_id = int((qs.get("snapshot_id") or [""])[0])
                except ValueError:
                    return self._send_json(400, {"error": "snapshot_id must be a snapshot id"})
                exported = audit_store.export_config_snapshot(meta["environment_id"], snapshot_id)
                if exported is None:
                    return self._send_json(404, {"error": "No such snapshot in this environment."})
                if exported["kind"] != "inventory_counts" and self._capability_refused(engine_owner, meta["environment_id"], ("live_read",)):
                    return
                exported["verification"] = audit_store.verify_config_snapshot(meta["environment_id"], snapshot_id)
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "config_snapshot.exported", {
                    "name": name, "snapshot_id": snapshot_id, "kind": exported["kind"], "sha256": exported["sha256"]})
                return self._send_json(200, exported)

            if path.startswith("/api/environments/") and path.endswith("/config_snapshots"):
                found = self._environment_from_tail(path, "/config_snapshots", engine_owner)
                if found is None:
                    return
                _name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                import audit_store
                kind = (qs.get("kind") or [None])[0] or None
                if kind is not None and not re.match(r"^[a-z][a-z0-9_]{1,63}$", kind):
                    return self._send_json(400, {"error": "kind is not a snapshot kind"})
                return self._send_json(200, {"snapshots": audit_store.list_config_snapshots(meta["environment_id"], kind=kind, limit=200)})

            if path == "/api/overview":
                # 5.50.0: counts only, for the executive dashboard. Admin-only; not available through an additional
                # login gate (nginx answers 403 there). See _serve_overview.
                return self._serve_overview(path, qs, owner_key, engine_owner, local_env_name)

            if path == "/api/overview/people":
                # The named list behind one Overview count (C1 or C5). Admin-only; every read is audited.
                return self._serve_overview(path, qs, owner_key, engine_owner, local_env_name)

            if path == "/api/overview/privileged":
                # The audited list of the privileged people behind the Overview's sign-in / MFA figures. Admin-only.
                return self._serve_overview(path, qs, owner_key, engine_owner, local_env_name)

            if path == "/api/archives/orphaned":
                # DATA-12: archives whose environment no longer exists.
                # Admin-only read (local mode exempt), same rule as
                # /api/audit_log -- these rows belong to no owner any more.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to list orphaned archives."})
                if not self._require_settings_unlock():
                    return
                import audit_store
                return self._send_json(200, {"archives": audit_store.list_orphaned_archives()})

            if path == "/api/reports":
                import audit_store
                environment = (qs.get("environment") or [local_env_name])[0]
                environment_id = None
                if environment:
                    meta = engine.list_environments_for(engine_owner).get(environment)
                    if meta is None:
                        return self._send_json(404, {"error": f"No environment named '{environment}' visible to this user."})
                    environment_id = meta["environment_id"]
                    if self._capability_refused(engine_owner, environment_id, ("view_archive",)):
                        return
                reports = audit_store.list_reports()
                if environment_id:
                    since = (qs.get("from") or [None])[0]
                    until = (qs.get("to") or [None])[0]
                    for r in reports:
                        r["count"] = audit_store.count_events(environment_id, event_types=r["event_types"], since=since, until=until)
                return self._send_json(200, {"reports": reports})

            if path.startswith("/api/reports/"):
                import audit_store
                report_key = path[len("/api/reports/"):]
                environment = (qs.get("environment") or [local_env_name])[0]
                if not environment:
                    return self._send_json(400, {"error": "No active environment and none specified via ?environment="})
                meta = engine.list_environments_for(engine_owner).get(environment)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{environment}' visible to this user."})
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                since = (qs.get("from") or [None])[0]
                until = (qs.get("to") or [None])[0]
                try:
                    limit = min(int((qs.get("limit") or [1000])[0]), 5000)
                except ValueError:
                    return self._send_json(400, {"error": "limit must be an integer"})
                # DATA-06 (external review, 2026-10-05): SQLite's LIMIT
                # with a negative value means "no limit at all," not an
                # error -- so `?limit=-1` used to silently remove the
                # 5000-row cap this min() exists to enforce. Reject it
                # the same way a non-integer limit already is.
                if limit < 1:
                    return self._send_json(400, {"error": "limit must be a positive integer"})
                try:
                    result = audit_store.run_report(report_key, meta["environment_id"], since=since, until=until, limit=limit)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                # UI-03/DATA-07: total/truncated let the frontend show
                # "Showing newest N of M" instead of presenting a capped
                # result as the complete evidence window.
                return self._send_json(200, {
                    "report": report_key, "environment": environment,
                    "rows": result["rows"], "total": result["total"], "truncated": result["truncated"],
                })

            if path.startswith("/api/resources/") and path.endswith("/history"):
                import audit_store
                resource_id = unquote(path[len("/api/resources/"):-len("/history")])
                environment = (qs.get("environment") or [local_env_name])[0]
                if not environment:
                    return self._send_json(400, {"error": "No active environment and none specified via ?environment="})
                meta = engine.list_environments_for(engine_owner).get(environment)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{environment}' visible to this user."})
                if self._capability_refused(engine_owner, meta["environment_id"], ("view_archive",)):
                    return
                # resource_name: fallback exact-displayName match for
                # resource kinds with no discoverable log-side id at all
                # (database accounts, individual AD accounts -- see
                # audit_store.resource_history's docstring). resource_id
                # alone is kept working for every kind that DOES have one.
                resource_name = (qs.get("resource_name") or [None])[0]
                if not resource_id and not resource_name:
                    return self._send_json(400, {"error": "missing resource_id or resource_name"})
                since = (qs.get("from") or [None])[0]
                until = (qs.get("to") or [None])[0]
                try:
                    limit = min(int((qs.get("limit") or [1000])[0]), 5000)
                except ValueError:
                    return self._send_json(400, {"error": "limit must be an integer"})
                if limit < 1:  # DATA-06, same reasoning as /api/reports/{key} above
                    return self._send_json(400, {"error": "limit must be a positive integer"})
                result = audit_store.resource_history(
                    meta["environment_id"], resource_id=resource_id, resource_name=resource_name,
                    since=since, until=until, limit=limit,
                )
                return self._send_json(200, {
                    "resource_id": resource_id, "environment": environment,
                    "rows": result["rows"], "total": result["total"], "truncated": result["truncated"],
                })

            if path.startswith("/api/active_directory_connections/") and path.endswith("/discovery_config"):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                connection_id = unquote(
                    path[len("/api/active_directory_connections/"):-len("/discovery_config")]
                )
                if not connection_id:
                    return self._send_json(400, {"error": "missing connection_id"})
                engine.validate_resource_id(connection_id, "connection_id")
                return self._send_json(200, engine.get_ad_connection_discovery_config(local_client, connection_id))

            if path == "/api/resource_groups":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                return self._send_json(200, {"resource_groups": local_client.list_resource_groups()})

            if path.startswith("/api/resource_groups/") and path.endswith("/projects"):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                engine.validate_resource_id(rg_id, "resource_group_id")
                return self._send_json(200, {"projects": local_client.list_projects(rg_id)})

            if path == "/api/groups":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"groups": local_client.list_groups(contains=contains)})

            if (path.startswith("/api/resource_groups/") and path.endswith("/folders")
                    and "/projects/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                inner = path[len("/api/resource_groups/"):-len("/folders")]
                rg_id, _, proj_id = inner.partition("/projects/")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "missing resource_group_id or project_id"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id)
                # The plain folders list is top-level only (see engine docstring
                # fact #2) -- walk the full tree via fetch_all_folders() and
                # rebuild each folder's "Root/Child/.../Leaf" path from its
                # parent chain, same convention the CSV `path` column already
                # uses. treeFromRows() on the frontend needs no changes for
                # this -- it already parses slash-delimited paths.
                folders = engine.fetch_all_folders(local_client, rg_id, proj_id)
                by_id = {f["id"]: f for f in folders if f.get("id")}

                rows = [
                    {"path": engine.full_path(f, by_id), "description": f.get("description", ""), "folder_id": f.get("id")}
                    for f in folders
                ]
                return self._send_json(200, {"rows": rows})

            if (path.startswith("/api/resource_groups/") and path.endswith("/secrets_access_report")
                    and "/projects/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read", "view_archive")):
                    return
                inner = path[len("/api/resource_groups/"):-len("/secrets_access_report")]
                rg_id, _, proj_id = inner.partition("/projects/")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "missing resource_group_id or project_id"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id)
                # Phase 5 of the compliance-reporting-dashboard plan: once an
                # environment has a real compliance-sync archive (audit_store.py),
                # this report is sourced from THAT instead of a bounded live
                # Okta call -- strictly more complete (whole history ever
                # ingested, no 90-day/reveal_limit cap), confirmed to produce
                # identical bucketing output on real data before this switch.
                # This path needs no Okta client at all (unlike the fallback
                # below), so an environment with compliance sync set up but
                # no live Okta token configured still works. Environments
                # that have never run a compliance sync keep the exact
                # original live-query behavior (and its Okta-client
                # requirement) -- zero regression for anyone not using the
                # new feature yet.
                import audit_store
                # environment_has_archive, not is_first_sync (5.40.2): a
                # sync_state row now exists from the moment a sync STARTS
                # (DATA-05), so "a row exists" would switch this report to an
                # empty archive after a first sync that failed at once.
                if local_env_id and audit_store.environment_has_archive(local_env_id):
                    report = engine.build_project_secrets_report_from_archive(
                        local_client, local_env_id, rg_id, proj_id
                    )
                    return self._send_json(200, report)

                if not _require_okta_client(self._send_json, local_okta_client):
                    return
                report = engine.build_secrets_access_report(
                    local_client, local_okta_client, rg_id, proj_id,
                )
                return self._send_json(200, report)

            if path == "/api/service_accounts_report":
                # The SaaS / Okta service-account counterpart of the
                # secrets_access_report route above (same auth posture:
                # inside the nginx/owner-session gate, scoped to THIS
                # owner's active environment and client, not admin-only).
                # Tenant-wide rather than per-project -- see
                # engine.walk_service_account_rosters for why a project
                # scope could never report a deleted account honestly.
                # Archive-only by design: unlike the Secrets report there
                # is no live System Log fallback for an environment that
                # has never synced -- the archive is this tool's system of
                # record and the roster/event volumes here (AD rotations
                # alone were 83k rows on a real tenant) don't fit a
                # bounded live query anyway; the 409 tells the user what
                # to do instead of silently returning a thinner report.
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read", "view_archive")):
                    return
                if not local_env_id:
                    return self._send_json(409, {"error": "No active environment configured. Use the gear menu to set one up."})
                import audit_store
                # "Has an archive" means a COMPLETED live sync or a CSV
                # import, not just "a sync_state row exists" (which
                # is_first_sync checks): a first sync that is still running
                # or errored before its first day-chunk landed has nothing
                # honest to report from yet (DATA-03/DATA-05).
                if not audit_store.environment_has_archive(local_env_id):
                    return self._send_json(409, {
                        "error": "This environment has not completed a compliance sync yet. Run Sync now (footer) first -- the Service Accounts report is sourced from the compliance archive.",
                        "reason": "not_synced",
                    })
                try:
                    rotation_limit = int((qs.get("rotation_limit") or [engine.SERVICE_ACCOUNT_ROTATION_LIMIT_DEFAULT])[0])
                except ValueError:
                    return self._send_json(400, {"error": "rotation_limit must be an integer"})
                # An out-of-range rotation_limit raises ValueError inside
                # the builder -> 400 via the shared handler below. A
                # corrupt stored raw_json row would ALSO surface as a
                # ValueError (json.JSONDecodeError subclasses it) and be
                # mislabelled a client error by that shared handler, so
                # it is caught first and reported as what it is.
                try:
                    report = engine.build_service_accounts_report_from_archive(
                        local_client, local_env_id, rotation_limit=rotation_limit
                    )
                except json.JSONDecodeError as exc:
                    engine.log("ERROR", f"service_accounts_report: corrupt raw_json row in the archive: {exc}")
                    return self._send_json(500, {"error": "A stored event in the compliance archive could not be parsed."})
                summary = report["summary"]
                engine.log("INFO", (
                    f"service_accounts_report: {summary['total']} account(s) "
                    f"({summary['saas']} saas, {summary['okta']} okta; "
                    f"{summary['active']} active, {summary['deleted']} deleted, {summary['unknown']} unknown) "
                    f"across {report['walked']['projects']} project(s); excluded {report['excluded']}; "
                    f"warnings {report['warnings']}; truncated={report['truncated']}"
                ))
                return self._send_json(200, report)

            if path.startswith("/api/resource_groups/") and path.endswith("/security_policies"):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/security_policies")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                engine.validate_resource_id(rg_id, "resource_group_id")
                policies = [
                    engine.summarize_security_policy(p)
                    for p in local_client.list_security_policies()
                    if (p.get("resource_group") or {}).get("id") == rg_id
                ]
                return self._send_json(200, {"policies": policies})

            if path == "/api/workload_roles":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"workload_roles": local_client.list_workload_roles(contains=contains)})

            if path == "/api/service_account":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                current_user = local_client.get_current_user()
                # `list_user_groups` already returns each group's real `id`
                # (not just name) -- exposing that set directly is all the
                # frontend needs to answer "is the service account already
                # a member of group X" for any group ID it already has from
                # /api/groups, with zero per-group round trips.
                group_ids = [g["id"] for g in local_client.list_user_groups(current_user["name"]) if g.get("id")]
                return self._send_json(200, {
                    "id": current_user.get("id"),
                    "name": current_user.get("name"),
                    "group_ids": group_ids,
                })

            if path == "/api/access/model":
                # 5.51.0: the stored OPA scan (memory, else the local archive) with when it was read, so the Access Explorer
                # opens at once after a restart. 404 no_scan only when no scan has ever been stored for this environment.
                if not local_env_id:
                    return self._send_json(409, {"error": "No active environment."})
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                view = _access_model_view(local_env_id)
                if view is None:
                    return self._send_json(404, {"error": "No stored OPA scan for this environment yet.", "reason": "no_scan"})
                return self._send_json(200, _access_model_payload(view))

            if path == "/api/access/bootstrap/status":
                if not local_env_id:
                    return self._send_json(200, {"status": "idle", "steps": [], "error": None})
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                # Snapshot (shallow-copy the steps list) WHILE holding the
                # lock, then serialize/send OUTSIDE it -- holding a lock
                # through json.dumps + a socket write (self.wfile.write can
                # block on a slow/stalled client) needlessly blocks the
                # background job's progress-appending thread the whole
                # time. Copying `steps` also means a background append
                # racing this read can never be observed mid-mutation.
                with _access_jobs_lock:
                    job = _access_jobs.get(local_env_id, {"status": "idle", "steps": [], "error": None})
                    status_payload = {"status": job["status"], "steps": list(job["steps"]), "error": job["error"]}
                return self._send_json(200, status_payload)

            if path == "/api/access/bootstrap/result":
                if not local_env_id:
                    return self._send_json(409, {"error": "No active environment."})
                if self._capability_refused(engine_owner, local_env_id, ("live_read",)):
                    return
                with _access_jobs_lock:
                    job = _access_jobs.get(local_env_id)
                    if job is None or job["status"] != "done" or job.get("result") is None:
                        return self._send_json(409, {"error": "Job is not done yet."})
                    return self._send_json(200, job["result"])

            if path == "/api/csv_files":
                files = sorted(p.name for p in _csv_dir().glob("*.csv"))
                return self._send_json(200, {"files": files})

            if path == "/api/csv":
                filename = (qs.get("file") or [""])[0]
                csv_path = _safe_csv_path(filename)
                if not csv_path.is_file():
                    return self._send_json(404, {"error": f"{filename} not found"})
                with open(csv_path, newline="", encoding="utf-8-sig") as f:
                    rows = list(_csv.DictReader(f))
                return self._send_json(200, {"rows": rows})

            if path == "/api/upgrade/status":
                # 5.46.0: read-only update-check status (notify-only). Admin
                # only, like the audit log: what a server runs and whether it
                # is out of date is for the people who operate it.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to view update status."})
                if not self._require_settings_unlock():
                    return
                body = update_service.status(update_service.load(), engine.SCRIPT_VERSION)
                body["upgrade_run"] = update_service.upgrade_run()  # 5.47.0: the root-owned updater's current/last run
                body["upgrade"] = self._upgrade_view(qs)  # 5.48.0: everything the in-app flow shows
                return self._send_json(200, body)

            if path == "/api/upgrade/notice":
                # 5.48.0: the one-line banner (any signed-in user): an upgrade is scheduled / running / failed; only admins
                # are told that one is merely available.
                is_admin_caller = _can_admin(owner_key, self.headers)
                notice_body = upgrade_service.notice(engine.SCRIPT_VERSION, is_admin_caller)
                if is_admin_caller:
                    # 5.53.0: what the badge, the revocation banner and the progress card need while Updates is locked.
                    # Never settings, keys or backups; those stay behind the unlock.
                    st = update_service.status(update_service.load(), engine.SCRIPT_VERSION)
                    notice_body = {**notice_body,
                                   "update_available": (st["latest"] or {}).get("version") if st["check"]["enabled"] and st["update_available"] else None,
                                   "revocation": _notice_revocation(st["revocation"]), "run": _notice_run(upgrade_service.run_view())}
                return self._send_json(200, notice_body)

            if path.startswith("/api/evidence_packages/") and path.endswith("/download"):
                # 5.53.0: the finished package, repeatable for 15 minutes; bound to the person who built it (else 404).
                return self._evidence_package_request(path[len("/api/evidence_packages/"):-len("/download")], True)

            if path.startswith("/api/evidence_packages/"):
                # 5.53.0: a build's status and, when finished, its sha256 and chain head (for the server-side build log).
                return self._evidence_package_request(path[len("/api/evidence_packages/"):], False)

            if path == "/api/upgrade/bundle":
                # 5.47.0: download a redacted support bundle the updater built after a failed upgrade (the failed
                # upgrade's Audit Log entry names it). Admin-only and read-only; the bundle is created by root, holds no
                # secrets, tenant data or personal data (see docs and ocw_bundle.py), and is never uploaded anywhere.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to download a support bundle."})
                if not self._require_settings_unlock():
                    return
                name = (qs.get("name") or [""])[0]
                code, data = update_service.read_bundle(name)
                if code != 200:
                    return self._send_json(code, {"error": data})
                _o, _e, actor_email, actor_sub = self._caller()
                self._log_audit_event(actor_email, actor_sub, "upgrade.bundle_downloaded",
                                      {"bundle": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                self.send_response(200)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
                return

            if path == "/api/audit_log":
                # Admin-only -- this is every user's activity across every
                # environment, for compliance visibility, not a per-user
                # operational log. A direct/local run (owner_key ==
                # LOCAL_OWNER_KEY_HEADER, i.e. no login gate in front at
                # all) is exempt -- local mode already sees/manages every
                # environment unscoped anyway (same reasoning as the
                # /api/environments admin branch above), so it gets the
                # same access here rather than being permanently locked
                # out of its own audit log.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to view the audit log."})
                try:
                    limit = min(int((qs.get("limit") or [200])[0]), 1000)
                    offset = max(int((qs.get("offset") or [0])[0]), 0)
                except ValueError:
                    return self._send_json(400, {"error": "limit/offset must be integers"})
                return self._send_json(200, {"entries": engine.read_audit_log(limit=limit, offset=offset)})

            if path == "/api/shared_permissions":
                # 5.42.0: the capability catalogue, the global defaults and
                # every environment's overrides. Admin-only (local-mode
                # operator exempt), same rule as /api/access_control.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to view shared-environment permissions."})
                if not self._require_settings_unlock():
                    return
                defaults = engine.get_shared_permission_defaults()
                return self._send_json(200, {
                    "capabilities": [dict(c) for c in engine.SHARED_CAPABILITIES],
                    "defaults": defaults,
                    "environments": {
                        env_id: {"name": meta.get("name"), "shared": bool(meta.get("shared")),
                                 "overrides": engine.get_shared_permission_overrides(env_id),
                                 "grants": engine.get_shared_permission_grants(env_id),
                                 "effective": engine.effective_shared_permissions(env_id, defaults=defaults)}
                        for env_id, meta in engine.list_all_environments().items()
                    },
                    # 5.43.0: who a per-user exception can name -- every user
                    # a login gate has vouched for, with the e-mail last seen.
                    "identities": engine.list_known_identities(),
                })

            if path == "/api/access_control":
                # Admin-only read, same shape as /api/audit_log just above
                # (including the local-mode exemption) -- these are the
                # Okta group IDs that gate login/admin rights for EVERY
                # user, not a per-owner setting, so a non-admin has no
                # legitimate reason to see (let alone change) them.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to view access control settings."})
                if not self._require_settings_unlock():
                    return
                return self._send_json(200, engine.get_access_control_config())
        except engine.CredentialStoreUnavailable as exc:
            return self._send_json(503, {"error": str(exc)})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_internal_error(exc)

        super().do_GET()

    # -----------------------------------------------------------------
    def do_POST(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        path = urlparse(self.path).path
        if _reject_if_hosted_without_nginx(self, path) or _reject_ambiguous_api_path(self, path):
            return
        if not self._check_origin():
            return
        owner_key = _owner_key_from_headers(self.headers)
        engine_owner = _engine_owner(owner_key)
        actor_email = self.headers.get("X-Auth-User")
        actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key
        _ensure_session_initialized(owner_key, self.headers)
        # Snapshot ONCE at request start -- see the identical note in
        # do_GET. This matters even more here: /api/preview and
        # /api/execute can run for a while, and without this snapshot a
        # concurrent environment switch/delete could make an in-flight
        # execute silently continue against a different (or no) tenant
        # partway through.
        local_client, local_okta_client, _local_env_name, _local_env_id = _session_snapshot(owner_key)
        try:
            payload = self._read_json_body()

            if path == "/api/banner":
                # SECURITY FIX (external review, 2026-09-30): this had NO admin check at all. 5.53.0: the save is also an
                # org-wide message to every user, so in hosted mode it needs a fresh MFA approval (banner.update).
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to change the announcement banner."})
                return self._environment_change("banner.update", {"body": payload})

            if path == "/api/evidence_packages/prepare":
                # 5.53.0: check an environment and a UTC period, then build (local mode: at once; hosted: after the MFA
                # step-up, through /api/environment_changes/save). `check_only` answers the coverage summary and starts
                # nothing. The environment is named in the query (?environment=) or the body.
                env_names = parse_qs(urlparse(self.path).query).get("environment")
                evidence_params = {"name": env_names[0] if env_names else payload.get("environment"),
                                   "body": {k: payload.get(k) for k in ("start", "end", "gaps_acknowledged", "environment_id")}}
                if payload.get("check_only") is True:
                    status, body = self._exec_evidence_package_build({**evidence_params, "check_only": True}, dry_run=True, via_step_up=False)
                    return self._send_json(status, body)
                return self._environment_change("evidence_package.build", evidence_params)

            if path == "/api/settings/unlock":
                # 5.53.0: asks for the MFA that opens Settings and Updates (202 in hosted mode; local mode answers at once).
                return self._environment_change("settings.unlock", {"scope": "settings", "session": _session_fingerprint(self.headers)})

            if path == "/api/settings/lock":
                # 5.53.0: ends the caller's own window now. Changes nothing else.
                if _step_up_required_for_changes():
                    import audit_store
                    actor_sub_, issuer_, fingerprint_ = self._unlock_identity()
                    gone = audit_store.delete_settings_unlock(actor_sub_, issuer_, fingerprint_) if actor_sub_ and fingerprint_ else None
                    if gone:
                        self._log_audit_event(actor_email, actor_sub, "settings.locked", {
                            "reason": "manual", "unlocked_at": gone["unlocked_at"], "expired_at": gone["expires_at"]})
                return self._send_json(200, {"locked": True})

            if path == "/api/upgrade/settings":
                # 5.46.0: switch the update check on/off and choose whether it
                # shares the installed version. Admin-only and audited; not
                # step-up protected (it changes no tenant or access
                # configuration; it only decides whether this server may ask
                # GitHub for the latest release number).
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to change update settings."})
                return self._environment_change("upgrade.settings", {"body": payload})

            if path == "/api/upgrade/preview":
                # 5.48.0: read the release's signature file and manifest (a few KB), verify the signature's trusted comment
                # against the pinned keys and run the preflight. No install, no step-up: it is a read.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to review an update."})
                if not self._require_settings_unlock():
                    return
                status, body = self._upgrade_preview(actor_email, actor_sub)
                return self._send_json(status, body)

            if path == "/api/upgrade/request":
                # 5.48.0: upgrade now / schedule / reschedule / cancel / second approval. Admin-only; in hosted mode every one
                # is stored as a pending action bound to the exact version, hash and time and needs a fresh MFA approval.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to upgrade."})
                return self._environment_change("upgrade.request", {"body": payload})

            if path == "/api/upgrade/check":
                # 5.46.0: the Updates screen's "Check now" -- one request to the release server (never
                # installs anything), admin-only, at most once a minute, recorded in the audit log.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to check for updates."})
                if not self._require_settings_unlock():
                    return
                status, body = update_service.check_now(engine.SCRIPT_VERSION, actor_email, actor_sub)
                return self._send_json(status, body)

            if path == "/api/access_control/prepare":
                # Phase 3: validates the PROPOSED config and stores it
                # server-side (audit_store.pending_admin_actions), keyed
                # by an opaque action_id the browser carries through the
                # Okta step-up redirect in place of the actual settings
                # (see AccessControlDialog.tsx's handleSaveClick and
                # auth_gate.py's /step-up). Same admin gate as /save
                # below -- preparing a change an admin isn't allowed to
                # make at all shouldn't even reach the point of minting a
                # pending action for it.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to change access control settings."})
                import audit_store
                config = engine.validate_access_control_config(
                    payload.get("admin_group_id"),
                    payload.get("user_group_id"),
                    payload.get("restrict_login", False),
                )
                action_id = audit_store.create_pending_admin_action(
                    actor_sub, "access_control.update", config, ttl_seconds=STEPUP_PREPARE_TTL_SECONDS
                )
                return self._send_json(200, {"action_id": action_id})

            if path == "/api/access_control/save":
                # Admin check here too, in addition to nginx's own
                # auth_request /verify_stepup gate on this exact path (see
                # nginx-opa-secrets-wizard.conf) -- same defense-in-depth
                # double-check this project already does for every other
                # admin action (e.g. environment.upsert's is_admin check
                # just below still runs even though /api/environments has
                # no nginx-level admin gate of its own). A direct/local run
                # (no login gate in front at all) is exempt, same as
                # /api/audit_log and GET /api/access_control above.
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to change access control settings."})
                # Phase 3 FIX (real gap, confirmed via code review before
                # this change): previously trusted the LIVE request body
                # for admin_group_id/user_group_id/restrict_login -- the
                # step-up cookie only proved "fresh MFA happened for this
                # sub within the last 120s," never that it was approving
                # THIS specific payload. A step-up cookie, once issued,
                # could be replayed with ANY settings submitted within its
                # TTL. Now the request body is never trusted for the
                # settings themselves -- the ONE payload that was actually
                # prepared and reviewed is retrieved via the action_id
                # bound into the step-up cookie itself (threaded through
                # auth_gate.py's FLOW_COOKIE -> STEPUP_COOKIE, surfaced
                # here as X-Auth-Action-Id by nginx's auth_request_set,
                # same mechanism as X-Auth-Mfa-Log-Event).
                import audit_store
                action_id = self.headers.get("X-Auth-Action-Id")
                if not action_id:
                    return self._send_json(409, {"error": "No pending action -- start the save flow again.", "reason": "not_found"})
                try:
                    # action_types (5.42.0): an Environments approval can't be
                    # spent here -- it is left for its own save route.
                    config = audit_store.consume_pending_admin_action(
                        action_id, actor_sub, action_types=("access_control.update",)
                    )
                except audit_store.PendingActionError as exc:
                    status = 409 if exc.reason in ("already_consumed", "expired") else 403
                    return self._send_json(status, {"error": f"Could not apply this change ({exc.reason}) -- please try again.", "reason": exc.reason})
                config = engine.set_access_control_config(
                    config["admin_group_id"], config["user_group_id"], config["restrict_login"]
                )
                # only now, with the write done, does this approval's MFA restart the Settings unlock
                renewed = self._renew_settings_unlock_after_mfa(actor_sub, "access_control.update", action_id)
                # step_up_verified is now derived from having successfully
                # consumed a real pending action bound to this exact
                # step-up transaction -- not hardcoded-true-by-construction
                # as before (nginx's auth_request gate still independently
                # enforces that step-up happened at all; this marker
                # additionally confirms THIS payload is the one reviewed).
                #
                # okta_mfa_log_event starts None here (Phase 4): the
                # synchronous Okta System Log lookup that used to populate
                # X-Auth-Mfa-Log-Event at step-up time is removed --
                # pending_admin_actions is now the authoritative record,
                # so that lookup's ~6s of added redirect latency bought
                # nothing but optional corroborating evidence. The Audit
                # Log page's Refresh button (backfill_mfa_log_events) still
                # fills this field in asynchronously after the fact.
                details = {**config, "step_up_verified": True, "okta_mfa_log_event": None}
                if renewed:
                    details["settings_unlock_renewed"] = True
                audit_entry = self._log_audit_event(actor_email, actor_sub, "access_control.update", details)
                # Phase 10: step_up_verified/saved_at are returned to the
                # CALLER too, not just logged -- previously these only
                # ever landed in the audit entry, so the admin who just
                # relied on Phase 3's new transaction-binding guarantee
                # had no way to see it confirmed; AccessControlDialog/
                # App.tsx now show it directly instead of a generic
                # "saved" toast. okta_mfa_log_event is deliberately NOT
                # included here -- it's always None at save time now
                # (Phase 4 removed the synchronous lookup), so returning
                # a field that's always null would be misleading; the
                # audit entry remains the right place for whenever
                # backfill_mfa_log_events fills it in later. saved_at
                # reuses the audit entry's OWN timestamp rather than
                # computing a second, separately-timed one.
                return self._send_json(200, {**config, "step_up_verified": True, "saved_at": audit_entry["timestamp"]})

            if path == "/api/environment_changes/save":
                # 5.42.0: applies one Environments change after its step-up
                # MFA -- the same flow as /api/access_control/save above.
                # nginx sends this path through auth_request /verify_stepup
                # (a fresh step-up cookie for THIS session's sub), which
                # forwards the action id bound into that cookie; the request
                # body is never read. The stored request is then run with
                # every check made again (_environment_change's executors).
                if not _step_up_required_for_changes():
                    return self._send_json(404, {"error": "Step-up saves are only used behind the hosted login gate; "
                                                          "in local mode changes apply directly."})
                if not _request_passed_stepup_location(self.headers):
                    return self._send_json(403, {
                        "error": "This change needs a fresh MFA approval, and this site's nginx configuration does "
                                 "not have the step-up location for it. An operator must regenerate the site.",
                        "reason": "step_up_unavailable",
                    })
                import audit_store
                action_id = self.headers.get("X-Auth-Action-Id")
                if not action_id:
                    return self._send_json(409, {"error": "No pending action -- start the save flow again.", "reason": "not_found"})
                try:
                    stored, row_type = audit_store.consume_pending_admin_action(
                        action_id, actor_sub, action_types=ENV_CHANGE_ACTION_TYPES, return_action_type=True,
                    )
                except audit_store.PendingActionError as exc:
                    status = 409 if exc.reason in ("already_consumed", "expired") else 403
                    return self._send_json(status, {"error": f"Could not apply this change ({exc.reason}) -- please try again.", "reason": exc.reason})
                action = stored.get("action")
                if action != row_type or action not in _ENV_CHANGE_EXECUTORS:
                    return self._send_json(403, {"error": "Could not apply this change (action_type_mismatch) -- please try again.",
                                                 "reason": "action_type_mismatch"})
                params = stored.get("params") or {}
                if stored.get("secret_fields"):
                    held = _take_pending_secrets(action_id)
                    if held is None or set(held) != set(stored["secret_fields"]):
                        return self._send_json(409, {
                            "error": "The server restarted or the approval took too long, so the secrets you typed "
                                     "are gone (they are never stored on disk). Enter them again and save.",
                            "reason": "secrets_expired", "action": action,
                        })
                    params = {**params, "body": {**(params.get("body") or {}), **held}}
                # renewed when the change's own audit entry is written (see _log_audit_event), or below if it wrote none
                self._settings_unlock_renewal = (actor_sub, action, action_id)
                try:
                    status, body = getattr(self, _ENV_CHANGE_EXECUTORS[action])(params, dry_run=False, via_step_up=True)
                    if 200 <= status < 300 and self._settings_unlock_renewal is not None:
                        self._renew_settings_unlock_after_mfa(*self._settings_unlock_renewal)
                finally:
                    self._settings_unlock_renewal = None
                body = {**(body or {}), "action": action}
                if 200 <= status < 300:
                    body["step_up_verified"] = True
                return self._send_json(status, body)

            if path == "/api/shared_permissions":
                # 5.42.0, admin-only (local-mode operator exempt): the global
                # defaults ({"changes": {...}}) or one environment's overrides
                # ({"environment_id": ..., "changes": {...}}); each change is
                # allow / deny / inherit. Step-up MFA in hosted mode.
                return self._environment_change("shared_permissions.update", {"body": payload})

            if path == "/api/audit_log/backfill_mfa":
                # Same admin gate as GET /api/audit_log -- this both READS
                # and rewrites audit_log.jsonl, so it deserves at least the
                # same protection as viewing it. Triggered by an admin
                # clicking Refresh on the Audit Log page (see
                # engine.backfill_mfa_log_events's docstring for why this
                # exists: Okta System Log indexing lag can mean an
                # access_control.update entry's corroboration was still
                # missing at save time, even though the real event existed
                # in Okta moments later).
                if not _can_admin(owner_key, self.headers):
                    return self._send_json(403, {"error": "Admin access required to refresh MFA log corroboration."})
                try:
                    updated_count = engine.backfill_mfa_log_events(_lookup_mfa_log_event)
                except engine.MfaBackfillBusy as exc:
                    return self._send_json(409, {"error": str(exc), "reason": "busy"})
                return self._send_json(200, {"updated_count": updated_count})

            if path == "/api/environments":
                # Create or edit (5.42.0: step-up MFA in hosted mode -- see
                # _environment_change). The executor holds the route's logic.
                return self._environment_change("environment.upsert", {"body": payload})

            if path.startswith("/api/environments/") and path.endswith("/activate"):
                name = unquote(path[len("/api/environments/"):-len("/activate")])
                expected_id = payload.get("id")
                if expected_id is not None:
                    # UI-07: the UI sends the id of the row that was clicked.
                    # Activation is by name; refuse rather than activate a
                    # different environment the name resolves to now (a
                    # rename, a new same-named environment of the caller's
                    # own, or an unshare since the list was loaded).
                    if not isinstance(expected_id, str):
                        return self._send_json(400, {"error": "id must be a string"})
                    meta = engine.list_environments_for(engine_owner).get(name)
                    if meta is None:
                        return self._send_json(404, {"error": f"No saved environment named '{name}' visible to this user."})
                    if meta["environment_id"] != expected_id:
                        return self._send_json(409, {"error": f"'{name}' now refers to a different environment for you; reload the list and try again."})
                try:
                    if expected_id is not None:
                        # Activate exactly the checked id (visibility
                        # re-checked by id), and store the pointer as that
                        # id -- resolving the name a second time could land
                        # elsewhere after a rename/share in between. If the
                        # pointer write is refused (unshared in that gap),
                        # the caller's previous session is put back.
                        with _sessions_lock:
                            previous_session = _sessions.get(owner_key)
                        activate_environment(owner_key, None, environment_id=expected_id)
                        try:
                            engine.set_active_environment_id(engine_owner, expected_id)
                        except KeyError:
                            with _sessions_lock:
                                if previous_session is None:
                                    _sessions.pop(owner_key, None)
                                else:
                                    _sessions[owner_key] = previous_session
                            raise
                    else:
                        activate_environment(owner_key, name)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": str(exc)})
                details = {"name": name}
                if expected_id is not None:
                    details["environment_id"] = expected_id
                self._log_audit_event(actor_email, actor_sub, "environment.activate", details)
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/share"):
                name = unquote(path[len("/api/environments/"):-len("/share")])
                return self._environment_change("environment.share", {"name": name, "body": payload})

            if path.startswith("/api/environments/") and path.endswith("/sync/reset_watermark"):
                name = unquote(path[len("/api/environments/"):-len("/sync/reset_watermark")])
                return self._environment_change("sync.reset_watermark", {"name": name})

            if path.startswith("/api/environments/") and path.endswith("/sync_schedule"):
                name = unquote(path[len("/api/environments/"):-len("/sync_schedule")])
                return self._environment_change("sync_schedule.update", {"name": name, "body": payload})

            if path.startswith("/api/environments/") and path.endswith("/refresh/cancel"):
                found = self._environment_from_tail(path, "/refresh/cancel", engine_owner)
                if found is None:
                    return
                name, meta = found
                with _refresh_jobs_lock:
                    running_job = _refresh_jobs.get(meta["environment_id"])
                running_parts = list(running_job.parts) if running_job is not None and running_job.status == "running" else list(rj.PARTS)
                # Stopping needs what starting the running parts needed (every part's when nothing is running).
                if "opa" in running_parts and self._capability_refused(engine_owner, meta["environment_id"], ("live_read",), part="opa"):
                    return
                if "log" in running_parts and self._capability_refused(engine_owner, meta["environment_id"], ("sync_now",), part="log"):
                    return
                if "okta" in running_parts and self._capability_refused(engine_owner, meta["environment_id"], ("live_read", "sync_now"), part="okta"):
                    return
                return self._send_json(200, _cancel_refresh(meta["environment_id"], by=actor_sub, audit_ctx={
                    "name": name, "trigger": None, "actor_email": actor_email, "actor_sub": actor_sub,
                    "client_ip": self._request_client_ip(), "user_agent": self.headers.get("User-Agent")}))

            if path.startswith("/api/environments/") and path.endswith("/refresh"):
                # 5.51.0: one Refresh for the OPA scan, the Okta scan and the System Log sync (see _start_refresh_job). Each
                # part needs what its single-purpose button needs; a request naming a part the caller may not run is refused whole.
                found = self._environment_from_tail(path, "/refresh", engine_owner)
                if found is None:
                    return
                name, meta = found
                try:
                    parts = rj.normalize_parts(payload.get("parts"))
                except ValueError as exc:
                    return self._send_json(400, {"error": str(exc)})
                if "opa" in parts and self._capability_refused(engine_owner, meta["environment_id"], ("live_read",), part="opa"):
                    return
                if "log" in parts and self._capability_refused(engine_owner, meta["environment_id"], ("sync_now",), part="log"):
                    return
                if "okta" in parts and self._capability_refused(engine_owner, meta["environment_id"], ("live_read", "sync_now"), part="okta"):
                    return
                options = {}
                subs = payload.get("okta_subs")
                if subs is not None:
                    if not isinstance(subs, list) or not subs or not all(isinstance(x, str) and x in rj.OKTA_SUBS for x in subs):
                        return self._send_json(400, {"error": f"okta_subs must be a non-empty list drawn from {list(rj.OKTA_SUBS)}"})
                    options["okta_subs"] = [x for x in rj.OKTA_SUBS if x in subs]
                trigger = "explorer" if payload.get("trigger") == "explorer" else "manual"  # the Access Explorer says so; "OPA scan only" on the Overview is manual
                # The owner's saved sync settings (by id), as Sync now uses them: a shared user never chooses the scope.
                schedule = engine.get_sync_schedule_by_id(meta["environment_id"])
                outcome = _start_refresh_job(
                    meta["environment_id"], name, parts=parts, trigger=trigger, owner=meta.get("owner"),
                    ingestion_scope=schedule.get("ingestion_scope", "curated"), options=options,
                    actor_email=actor_email, actor_sub=actor_sub, client_ip=self._request_client_ip(),
                    user_agent=self.headers.get("User-Agent"), correlation_id=engine.CORRELATION_ID.get())
                if outcome["upgrade_starting"]:
                    return self._send_json(409, {"error": "An upgrade is starting; refreshes are paused until it finishes (a few minutes).",
                                                 "reason": "upgrade_starting", **outcome})
                if outcome.get("busy_other_parts"):
                    return self._send_json(409, {"error": outcome["message"], "reason": "busy_other_parts", **{k: v for k, v in outcome.items() if k != "message"}})
                return self._send_json(200, outcome)

            if path.startswith("/api/environments/") and path.endswith("/sync/start"):
                name = unquote(path[len("/api/environments/"):-len("/sync/start")])
                meta = engine.list_environments_for(engine_owner).get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
                if self._capability_refused(engine_owner, meta["environment_id"], ("sync_now",)):
                    return
                # 5.42.0: a shared user allowed to run "Sync now" runs the
                # OWNER's sync: the owner's saved schedule (by id), the
                # owner's stored Okta token (by id, see _launch_claimed_sync)
                # and the owner recorded as the environment's owner. Only the
                # owner may choose a different ingestion scope for a run.
                schedule = engine.get_sync_schedule_by_id(meta["environment_id"])
                saved_scope = schedule.get("ingestion_scope", "curated")
                requested_scope = payload.get("ingestion_scope")
                if requested_scope and requested_scope != saved_scope and meta.get("owner") != engine_owner:
                    return self._send_json(403, {
                        "error": "Only the environment's owner can choose the ingestion scope; Sync now uses the owner's saved setting.",
                        "reason": "owner_only",
                    })
                ingestion_scope = requested_scope or saved_scope
                # Logging (start, and later completion/failure) now happens
                # INSIDE _start_sync_job/_run_sync_job themselves -- see
                # those functions' docstrings -- so it's captured
                # uniformly for both this manual trigger and the
                # scheduler's own trigger, including every way a sync can
                # fail to even start (bad credentials, already running),
                # which previously had no audit trail at all.
                #
                # BUG FIX (found during Phase 2's SQLite migration review,
                # pre-existing since Phase 1/v5.28.0): this call was missing
                # its required env_id positional argument entirely -- `name`
                # was silently landing in _start_sync_job's env_id parameter
                # and `ingestion_scope` in its env_name parameter, shifting
                # every argument by one. Caught by inspection, not a test
                # failure (there's no automated coverage of this specific
                # HTTP route today) -- now passes meta["environment_id"]
                # explicitly, matching _start_sync_job's real signature.
                started = _start_sync_job(
                    meta["environment_id"], name, ingestion_scope, owner=meta.get("owner"), trigger="manual",
                    actor_email=actor_email, actor_sub=actor_sub,
                    client_ip=self._request_client_ip(),
                    user_agent=self.headers.get("User-Agent"),
                    correlation_id=engine.CORRELATION_ID.get(),
                )
                return self._send_json(200, {"started": started, "already_running": not started and not upgrade_service.quiesced(),
                                             "upgrade_starting": not started and upgrade_service.quiesced()})

            if path.startswith("/api/environments/") and path.endswith("/sync/import_csv"):
                name = unquote(path[len("/api/environments/"):-len("/sync/import_csv")])
                return self._environment_change("sync.import_csv", {"name": name, "body": payload})

            if path.startswith("/api/environments/") and path.endswith("/okta_snapshots/capture"):
                # 5.50.0: read Okta now (background) and store a chained snapshot: the Okta admin list, or the Okta
                # status of every OPA principal. Uses the owner's stored Okta token, so a shared user needs both
                # live_read and sync_now (the same permission "Sync now" needs).
                found = self._environment_from_tail(path, "/okta_snapshots/capture", engine_owner)
                if found is None:
                    return
                name, meta = found
                if self._capability_refused(engine_owner, meta["environment_id"], ("live_read", "sync_now")):
                    return
                kind = payload.get("kind")
                if kind not in CAPTURE_KINDS:
                    return self._send_json(400, {"error": f"kind must be one of {list(CAPTURE_KINDS)}"})
                model = None
                if kind == "inventory_counts":
                    model = _access_model_for(meta["environment_id"])  # reused when loaded, built fresh otherwise
                if kind == "opa_principal_status":
                    model = _access_model_for(meta["environment_id"])
                    if model is None:
                        return self._send_json(409, {"error": 'No OPA scan stored yet. Select "Refresh" on the Overview first.',
                                                     "reason": "no_scan"})
                started = _start_capture_job(
                    meta["environment_id"], name, meta.get("owner"), kind, model, actor_email, actor_sub,
                    self._request_client_ip(), self.headers.get("User-Agent"))
                running_since = None if started else _capture_state(meta["environment_id"]).get("started_at")
                return self._send_json(200, {"started": started, "already_running": not started, **({"started_at": running_since} if running_since else {})})

            if path.startswith("/api/environments/") and path.endswith("/okta_admins/export_log"):
                # The CSV / Markdown export itself is built in the browser; this records that one was taken.
                found = self._environment_from_tail(path, "/okta_admins/export_log", engine_owner)
                if found is None:
                    return
                name, _meta = found
                if self._capability_refused(engine_owner, _meta["environment_id"], ("view_archive", "live_read")):
                    return
                fmt = payload.get("format")
                as_of = payload.get("as_of")
                if fmt not in ("csv", "md") or (as_of is not None and not isinstance(as_of, str)):
                    return self._send_json(400, {"error": "format must be csv or md"})
                if as_of is not None and len(as_of) > 40:  # reaches the audit log: bounded like its other fields
                    return self._send_json(400, {"error": "as_of is too long"})
                self._log_audit_event(actor_email, actor_sub, "okta_admins.report_exported", {"name": name, "format": fmt, "as_of": as_of})
                return self._send_json(200, {"logged": True})

            if path == "/api/access/bootstrap/start":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("live_read",)):
                    return
                # 5.51.0: older tabs still start the scan here; it is the refresh job's `opa` part, so the stored scan, the
                # coalescing and the deadline are the same for every way of starting one.
                with _access_jobs_lock:
                    if _access_jobs.get(_local_env_id, {}).get("status") == "running":
                        # UI-10: the step list too, so a page that attaches to
                        # a job already running can still show its progress.
                        return self._send_json(200, {"started": False, "already_running": True, "steps": engine.ACCESS_MODEL_STEPS})
                local_meta = engine.list_all_environments().get(_local_env_id) or {}
                outcome = _start_refresh_job(
                    _local_env_id, _local_env_name, parts=["opa"], trigger="explorer", owner=local_meta.get("owner"),
                    actor_email=actor_email, actor_sub=actor_sub, client_ip=self._request_client_ip(),
                    user_agent=self.headers.get("User-Agent"), correlation_id=engine.CORRELATION_ID.get())
                if outcome["upgrade_starting"]:
                    return self._send_json(409, {"error": "An upgrade is starting; refreshes are paused until it finishes (a few minutes).",
                                                 "reason": "upgrade_starting"})
                if outcome.get("busy_other_parts"):
                    return self._send_json(409, {"error": outcome["message"], "reason": "busy_other_parts", "missing": outcome["missing"], "running": outcome["running"]})
                return self._send_json(200, {"started": outcome["started"], "already_running": outcome["already_running"],
                                             "job_id": outcome["job_id"], "steps": engine.ACCESS_MODEL_STEPS})

            if path == "/api/resource_groups":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                name = (payload.get("name") or "").strip()
                if not name:
                    return self._send_json(400, {"error": "name is required"})
                group_ids = payload.get("group_ids") or []
                if not group_ids:
                    return self._send_json(
                        400, {"error": "At least one group is required to create a resource group in OPA."}
                    )
                created = local_client.create_resource_group(
                    name, payload.get("description", ""), delegated_resource_admin_group_ids=group_ids
                )
                self._log_audit_event(actor_email, actor_sub, "resource_group.create", {
                    "env_name": _local_env_name, "name": name, "resource_group_id": created.get("id"),
                })
                return self._send_json(201, {"resource_group": created})

            if path.startswith("/api/resource_groups/") and path.endswith("/projects"):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                name = (payload.get("name") or "").strip()
                if not rg_id or not name:
                    return self._send_json(400, {"error": "resource_group_id (in URL) and name are required"})
                engine.validate_resource_id(rg_id, "resource_group_id")
                created = local_client.create_project(rg_id, name)
                self._log_audit_event(actor_email, actor_sub, "project.create", {
                    "env_name": _local_env_name, "resource_group_id": rg_id, "name": name, "project_id": created.get("id"),
                })
                return self._send_json(201, {"project": created})

            if (path.startswith("/api/resource_groups/") and path.endswith("/policy")
                    and "/projects/" in path and "/folders/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                inner = path[len("/api/resource_groups/"):-len("/policy")]
                rg_id, _, rest = inner.partition("/projects/")
                proj_id, _, folder_part = rest.partition("/folders/")
                folder_id = folder_part.rstrip("/")
                if not rg_id or not proj_id or not folder_id:
                    return self._send_json(400, {"error": "missing resource_group_id, project_id, or folder_id"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id, folder_id=folder_id)

                mode = payload.get("mode")
                if mode not in ("new", "existing"):
                    return self._send_json(400, {"error": "mode must be 'new' or 'existing'"})
                # ENG2-05: every browser-supplied part is checked before any
                # OPA call -- privileges must be real booleans ("false" used
                # to grant), refs need ids, mfa has exactly its two fields.
                privileges = engine.validate_secret_privilege_flags(payload.get("privileges"))
                mfa = engine.validate_mfa_condition(payload.get("mfa"))
                group_refs = engine.validate_principal_refs(payload.get("group_refs"), "group_refs")
                workload_role_refs = engine.validate_principal_refs(payload.get("workload_role_refs"), "workload_role_refs")
                rule_name = payload.get("rule_name")
                if rule_name is not None and not isinstance(rule_name, str):
                    return self._send_json(400, {"error": "rule_name must be a string"})
                policy_id = payload.get("policy_id")
                if mode == "existing":
                    if not policy_id:
                        return self._send_json(400, {"error": "policy_id is required to attach to an existing policy"})
                    engine.validate_resource_id(policy_id, "policy_id")
                # The folder must really be in this project, and its name
                # (written into the rule's selector) comes from OPA, not from
                # the request.
                try:
                    folder = local_client.get_folder(rg_id, proj_id, folder_id)
                except engine.OpaApiError as exc:
                    if exc.status in (400, 404):
                        return self._send_json(400, {"error": "That folder was not found in this project."})
                    raise
                folder_name = (folder or {}).get("name") if isinstance(folder, dict) else None
                if not isinstance(folder_name, str) or not folder_name:
                    return self._send_json(502, {"error": "OPA returned the folder without a name; try again."})
                rule_name = (rule_name or "").strip() or f"{folder_name}-access"

                if mode == "new":
                    name = (payload.get("name") or "").strip()
                    if not name:
                        return self._send_json(400, {"error": "name is required to create a new policy"})
                    policy_body = {
                        "name": name,
                        "description": payload.get("description", ""),
                        "active": True,
                        "type": "default",
                        "resource_group": {"id": rg_id},
                        "principals": engine.merge_principals(None, group_refs, workload_role_refs),
                        "rules": [],
                    }
                    engine.upsert_folder_rule_in_policy(policy_body, folder_id, folder_name, rule_name, privileges, mfa=mfa)
                    created = local_client.create_security_policy(policy_body)
                    self._log_audit_event(actor_email, actor_sub, "policy.create", {
                        "env_name": _local_env_name, "resource_group_id": rg_id, "folder_id": folder_id,
                        "policy_name": name, "policy_id": created.get("id"),
                    })
                    return self._send_json(201, {"policy": engine.summarize_security_policy(created)})

                # ENG2-05 (external review, 2026-10-05): PUT replaces the whole
                # policy and OPA offers no ETag/If-Match for it (checked
                # against the OPA OpenAPI spec), so this was an unconditional
                # read-modify-write: a change made in the OPA console (a group
                # REMOVED from principals) or by another wizard request
                # between the GET and the PUT was silently undone. Now wizard
                # writes to one policy are serialised, and the policy is
                # re-read right before the PUT -- if it changed, nothing is
                # written and the admin is asked to reload (409). That narrows
                # the window to one round trip; it cannot close it.
                with _policy_write_lock(_local_env_id, policy_id):
                    current = local_client.get_security_policy(policy_id)
                    if not isinstance(current, dict):
                        return self._send_json(502, {"error": "OPA returned an unreadable policy; try again."})
                    if (current.get("resource_group") or {}).get("id") != rg_id:
                        return self._send_json(400, {"error": "That policy does not belong to this resource group."})
                    before = engine.policy_fingerprint(current)
                    working = json.loads(json.dumps(current))
                    working["principals"] = engine.merge_principals(working.get("principals"), group_refs, workload_role_refs)
                    # UI-01: a rule whose selector already names more than
                    # just this one folder can't be safely replaced from
                    # this single-folder form -- refuse rather than
                    # silently dropping the other folders' access.
                    try:
                        engine.upsert_folder_rule_in_policy(working, folder_id, folder_name, rule_name, privileges, mfa=mfa)
                    except engine.MultiTargetRuleError as exc:
                        return self._send_json(409, {"error": str(exc)})
                    # The re-read and the PUT go out back to back: any
                    # rate-limit wait happens BEFORE the re-read, and the
                    # PUT itself never waits (a 429 on it re-waits and
                    # re-reads here, a few times at most). Otherwise a
                    # minute-long wait between the compare and the write
                    # would reopen the window this check exists to close.
                    for attempt in range(POLICY_WRITE_ATTEMPTS):
                        local_client.wait_for_rate_limit()
                        latest = local_client.get_security_policy(policy_id)
                        if engine.policy_fingerprint(latest) != before:
                            return self._send_json(409, {
                                "error": "This policy was changed in OPA while your change was being prepared. "
                                         "Nothing was saved -- reload the policy and try again.",
                            })
                        try:
                            local_client.update_security_policy(policy_id, working, rate_limit_wait=False)
                            break
                        except engine.OpaApiError as exc:
                            if exc.status != 429 or attempt == POLICY_WRITE_ATTEMPTS - 1:
                                raise
                    updated = local_client.get_security_policy(policy_id)
                self._log_audit_event(actor_email, actor_sub, "policy.update", {
                    "env_name": _local_env_name, "resource_group_id": rg_id, "folder_id": folder_id,
                    "policy_id": policy_id,
                })
                return self._send_json(200, {"policy": engine.summarize_security_policy(updated)})

            if path == "/api/groups":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                if not _require_okta_client(self._send_json, local_okta_client):
                    return
                name = (payload.get("name") or "").strip()
                if not name:
                    return self._send_json(400, {"error": "name is required"})

                app = local_okta_client.find_privileged_access_app()
                okta_group = local_okta_client.create_group(name, payload.get("description", ""))
                local_okta_client.create_group_push_mapping(app["id"], okta_group["id"], name)

                opa_group = None
                for _attempt in range(GROUP_PUSH_PROPAGATION_RETRIES):
                    matches = local_client.list_groups(contains=name)
                    opa_group = next((g for g in matches if g.get("name") == name), None)
                    if opa_group:
                        break
                    time.sleep(GROUP_PUSH_PROPAGATION_DELAY_SECS)

                if not opa_group:
                    self._log_audit_event(actor_email, actor_sub, "group.create", {
                        "env_name": _local_env_name, "name": name, "visible_in_opa": False,
                    })
                    return self._send_json(202, {
                        "created_in_okta": True,
                        "pushed": True,
                        "visible_in_opa": False,
                        "message": f"Group '{name}' was created in Okta and pushed, but hasn't appeared in "
                                   "OPA yet. Try refreshing the group list in a few seconds.",
                    })

                # Every group this dashboard creates is meant to be usable
                # by the dashboard itself (as a resource-group's
                # delegated_resource_admin_groups, or a policy principal)
                # without an extra manual step -- add the service account
                # running this dashboard to it now. Non-blocking: the group
                # was still created successfully either way, so a failure
                # here (e.g. this service account lacks the pam_admin role
                # this write requires) is surfaced as a warning, not an
                # error, and never undoes the group creation itself.
                service_account_added = False
                service_account_warning = None
                try:
                    me = local_client.get_current_user()
                    local_client.add_user_to_group(name, me["name"])
                    service_account_added = True
                except engine.OpaApiError as exc:
                    service_account_warning = (
                        f"Group created, but couldn't automatically add the service account to it: {exc}"
                    )

                self._log_audit_event(actor_email, actor_sub, "group.create", {
                    "env_name": _local_env_name, "name": name, "visible_in_opa": True,
                    "group_id": (opa_group or {}).get("id"),
                })
                return self._send_json(201, {
                    "created_in_okta": True,
                    "pushed": True,
                    "visible_in_opa": True,
                    "group": opa_group,
                    "service_account_added": service_account_added,
                    "service_account_warning": service_account_warning,
                })

            if path == "/api/service_account/groups":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                group_id = payload.get("group_id")
                if not group_id:
                    return self._send_json(400, {"error": "group_id is required"})
                group = next((g for g in local_client.list_groups() if g.get("id") == group_id), None)
                if not group:
                    return self._send_json(404, {"error": f"Unknown group id '{group_id}'"})
                me = local_client.get_current_user()
                local_client.add_user_to_group(group["name"], me["name"])
                self._log_audit_event(actor_email, actor_sub, "service_account.join_group", {
                    "env_name": _local_env_name, "group_id": group_id,
                })
                return self._send_json(200, {"added": True, "group_id": group_id})

            if path == "/api/csv":
                try:
                    csv_path = _writable_template_csv_path(payload.get("file"))
                except _CsvWriteRefused as exc:
                    return self._send_json(409, {"error": str(exc)})
                rows = payload.get("rows") or []
                if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                    return self._send_json(400, {"error": "rows must be a list of objects"})
                buf = io.StringIO()
                writer = _csv.DictWriter(buf, fieldnames=FOLDER_TEMPLATE_FIELDS)
                writer.writeheader()
                for row in rows:
                    writer.writerow({"path": row.get("path", ""), "description": row.get("description", "")})
                # Atomic (temp file + os.replace): a crash mid-save can't
                # leave a truncated template behind.
                try:
                    mode = csv_path.stat().st_mode & 0o777  # keep an existing template's permissions
                except OSError:
                    mode = 0o600
                engine._atomic_write_text(str(csv_path), buf.getvalue(), mode=mode)
                engine.log("INFO", f"Saved {len(rows)} row(s) to {csv_path.name}")
                self._log_audit_event(actor_email, actor_sub, "csv.save", {
                    "file": csv_path.name, "row_count": len(rows),
                })
                return self._send_json(200, {"saved": True, "file": csv_path.name, "row_count": len(rows)})

            if path == "/api/preview":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("live_read",)):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id)
                ordered_paths, _descriptions, existing, collisions, invalid_names, name_in_use, case_variants = _run_pipeline(
                    local_client, payload.get("rows") or [], rg_id, proj_id
                )
                result = _plan_dict(ordered_paths, existing, collisions, name_in_use, case_variants)
                result["invalid_names"] = invalid_names
                return self._send_json(200, result)

            if path == "/api/execute":
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id)
                ordered_paths, descriptions, existing, collisions, invalid_names, _name_in_use, _case = _run_pipeline(
                    local_client, payload.get("rows") or [], rg_id, proj_id
                )
                if invalid_names:
                    return self._send_json(
                        400, {"error": "Invalid folder name(s); fix and retry.", "invalid_names": invalid_names}
                    )
                results = engine.execute_plan(local_client, rg_id, proj_id, ordered_paths, descriptions, existing)
                output_path = _csv_dir() / f"folders_result_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
                # ENG2-06: folders now exist -- a failure to write the results
                # file must not also lose the audit entry and the response.
                try:
                    engine.write_results_csv(output_path, results)
                    output_file = output_path.name
                    engine.log("INFO", f"Execute complete: results written to {output_file}")
                except OSError as exc:
                    output_file = None
                    engine.log("ERROR", f"Execute complete, but the results file could not be written "
                                        f"({type(exc).__name__}: {exc.strerror or exc}).")
                self._log_audit_event(actor_email, actor_sub, "folders.execute", {
                    "env_name": _local_env_name, "resource_group_id": rg_id, "project_id": proj_id,
                    "output_file": output_file, "folder_count": len(results),
                    "created": sum(1 for r in results if r[2] == "created"),
                    "errors": sum(1 for r in results if r[2] == "error"),
                })
                return self._send_json(200, {
                    "results": [_row_dict(*r) for r in results],
                    "collisions": {name: ["/".join(p) for p in paths] for name, paths in collisions.items()},
                    "output_file": output_file,
                })

            if path.startswith("/api/access/users/") and path.endswith("/resource_access"):
                if not _require_okta_client(self._send_json, local_okta_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("live_read",)):
                    return
                user_id = path[len("/api/access/users/"):-len("/resource_access")]
                if not user_id:
                    return self._send_json(400, {"error": "missing user_id"})
                # 5.45.0: every id and kind is validated (ValueError -> 400).
                resources = engine.validate_access_requests(payload.get("resources") or [])
                if not resources:
                    return self._send_json(200, {"results": {}})
                with _access_jobs_lock:
                    job = _access_jobs.get(_local_env_id)
                if job is None or job.get("result") is None:
                    return self._send_json(409, {"error": "Access model not loaded yet -- run the Access Explorer bootstrap first."})
                opa_user = next((u for u in job["result"]["users"] if u.get("id") == user_id), None)
                if not opa_user:
                    return self._send_json(404, {"error": f"Unknown user id '{user_id}'"})
                # System Log's actor.id is the Okta identity id, not this PAM
                # user's own (OPA-internal) id -- see resolve_okta_actor_id.
                actor_id = engine.resolve_okta_actor_id(local_okta_client, (opa_user.get("details") or {}).get("email"))
                # 5.45.0: the answer is archive-first (the app's synced System
                # Log, this environment only) topped up from the live log.
                # Reading the archive needs the same `view_archive` permission
                # as the reports; without it the lookup is live-only (what it
                # was before) and says so. Live access still needs `live_read`
                # (checked above), so nobody sees more than they could.
                use_archive = bool(_local_env_id) and engine.shared_capability_allowed(
                    _local_env_id, engine_owner, "view_archive", caller_issuer=_issuer_from_headers(self.headers))
                evidence = engine.find_access_evidence(
                    local_okta_client, actor_id, resources, environment_id=_local_env_id, use_archive=use_archive)
                return self._send_json(200, evidence)

            return self._send_json(404, {"error": "not found"})
        except _RequestAborted:
            return
        except engine.CredentialStoreUnavailable as exc:
            return self._send_json(503, {"error": str(exc)})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_internal_error(exc)

    # -----------------------------------------------------------------
    def do_DELETE(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if _reject_if_hosted_without_nginx(self, path) or _reject_ambiguous_api_path(self, path):
            return
        if not self._check_origin():
            return
        owner_key = _owner_key_from_headers(self.headers)
        engine_owner = _engine_owner(owner_key)
        actor_email = self.headers.get("X-Auth-User")
        actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key
        _ensure_session_initialized(owner_key, self.headers)
        # Snapshot for the folder-delete branch below -- see the identical
        # note in do_GET/do_POST. The environment-delete branch legitimately
        # clears this owner's session slot itself (that's the whole point
        # of that branch).
        local_client, _local_okta_client, local_env_name, _local_env_id = _session_snapshot(owner_key)
        try:
            if path.startswith("/api/archives/"):
                archive_id = unquote(path[len("/api/archives/"):]).rstrip("/")
                return self._environment_change("archive.purge", {"archive_id": archive_id})

            if path.startswith("/api/environments/"):
                name = unquote(path[len("/api/environments/"):])
                return self._environment_change("environment.delete", {
                    "name": name, "id": (qs.get("id") or [None])[0],
                    "purge_archive": (qs.get("purge_archive") or ["0"])[0] in ("1", "true"),
                })

            if (path.startswith("/api/resource_groups/") and "/projects/" in path
                    and "/folders/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                inner = path[len("/api/resource_groups/"):]
                rg_id, _, rest = inner.partition("/projects/")
                proj_id, _, folder_id = rest.partition("/folders/")
                folder_id = folder_id.rstrip("/")
                if not rg_id or not proj_id or not folder_id:
                    return self._send_json(400, {"error": "missing resource_group_id, project_id, or folder_id"})
                _validate_ids(resource_group_id=rg_id, project_id=proj_id, folder_id=folder_id)
                # The raw API gives no cascade guarantee for a non-empty
                # folder (see engine delete_folder docstring), so this
                # dashboard refuses to delete one rather than risk
                # orphaning or mass-deleting its contents.
                items = local_client.list_folder_items(rg_id, proj_id, folder_id)
                if items:
                    return self._send_json(409, {
                        "error": f"Folder is not empty ({len(items)} item(s) inside) -- "
                                 "remove or move its contents first, then delete it."
                    })
                local_client.delete_folder(rg_id, proj_id, folder_id)
                self._log_audit_event(actor_email, actor_sub, "folder.delete", {
                    "env_name": local_env_name, "resource_group_id": rg_id, "project_id": proj_id,
                    "folder_id": folder_id,
                })
                return self._send_json(200, {"deleted": folder_id})

            if path.startswith("/api/groups/") and "/members/" in path:
                if not _require_client(self._send_json, local_client):
                    return
                if self._capability_refused(engine_owner, _local_env_id, ("tenant_write",)):
                    return
                inner = path[len("/api/groups/"):]
                group_id, _, user_name = inner.partition("/members/")
                user_name = unquote(user_name.rstrip("/"))
                if not group_id or not user_name:
                    return self._send_json(400, {"error": "missing group_id or user_name"})
                group = next((g for g in local_client.list_groups() if g.get("id") == group_id), None)
                if not group:
                    return self._send_json(404, {"error": f"Unknown group id '{group_id}'"})
                local_client.remove_user_from_group(group["name"], user_name)
                _patch_scan_member_removed(_local_env_id, group_id, user_name)
                self._log_audit_event(actor_email, actor_sub, "group.remove_member", {
                    "env_name": local_env_name, "group_id": group_id, "user_name": user_name,
                })
                return self._send_json(200, {"removed": True, "group_id": group_id, "user_name": user_name})

            return self._send_json(404, {"error": "not found"})
        except engine.CredentialStoreUnavailable as exc:
            return self._send_json(503, {"error": str(exc)})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        # (no blanket KeyError -> 404 here any more: the routes catch the
        # engine's deliberate not-found KeyErrors themselves; an internal
        # KeyError is a 500 like any other bug -- SRV-03.)
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_internal_error(exc)


def _try_activate_saved_environment(owner_key):
    """If this owner has a persisted active environment (from a previous
    run/request) and no live session yet this process, try to reconnect
    automatically. Failure here is NOT fatal -- the request/boot continues,
    and the dashboard UI will show the setup screen since this owner's
    session stays empty. Called both at process boot (for
    LOCAL_OWNER_KEY_HEADER, matching this dashboard's original one-shared-
    environment boot behavior exactly) and lazily, the first time any given
    logged-in owner is ever seen by a request in this process."""
    engine_owner = _engine_owner(owner_key)
    # By id (5.40.3): the pointer stores an environment_id; turning it back
    # into a display name and resolving that could pick a different
    # same-named environment (after a rename, or one the owner owns
    # shadowing one shared with them). Visibility is re-checked by id.
    # The shared rule (engine.restorable_active_environment_credentials)
    # also refuses an id whose name now resolves to a different environment
    # for this owner -- the UI and every name-keyed route would otherwise
    # point at a different tenant than the session client.
    try:
        creds = engine.restorable_active_environment_credentials(engine_owner)
        if creds is None:
            return
        activate_environment(owner_key, None, environment_id=creds["environment_id"])
    except engine.CredentialStoreUnavailable as exc:
        # ENG1-10: a locked keychain is temporary -- let this owner's next
        # request try again instead of staying un-activated until restart.
        with _sessions_lock:
            _seen_owners.discard(owner_key)
        engine.log("WARN", f"Could not auto-activate the saved environment for owner '{owner_key}': {exc}")
    except Exception as exc:
        engine.log("WARN", f"Could not auto-activate the saved environment for owner '{owner_key}': {exc}")


def _remember_identity(owner_key, headers):
    """5.43.0: records the gate-verified (issuer, sub, e-mail) of a hosted
    request in known_identities, once per UTC day per triple and process (so
    last_seen_at keeps moving for active users and the 400-day prune never
    drops one, however long the process runs), so an admin can pick this
    user for a per-user exception by e-mail. Never fails the request."""
    issuer = _issuer_from_headers(headers)
    if issuer is None or owner_key == LOCAL_OWNER_KEY_HEADER:
        return
    email = headers.get("X-Auth-User")
    if email == owner_key:  # the gate sends the sub when the user has no usable e-mail
        email = None
    key = (issuer, owner_key, email)
    today = datetime.now(timezone.utc).date()
    with _sessions_lock:
        if _recorded_identities_day[0] != today:
            _recorded_identities.clear()
            _recorded_identities_day[0] = today
        if key in _recorded_identities:
            return
        _recorded_identities.add(key)
    try:
        engine.record_known_identity(*key)
    except Exception as exc:
        with _sessions_lock:
            _recorded_identities.discard(key)
        engine.log("WARN", f"Could not record the identity of owner '{owner_key}': {type(exc).__name__}")


def _ensure_session_initialized(owner_key, headers=None):
    """Lazily runs _try_activate_saved_environment for an owner the first
    time any request from them arrives in this process -- avoids requiring
    every logged-in user to explicitly re-activate an environment they'd
    already set active in a previous session/process. With `headers`, also
    remembers the caller's identity (_remember_identity)."""
    if headers is not None:
        _remember_identity(owner_key, headers)
    with _sessions_lock:
        already_seen = owner_key in _sessions or owner_key in _seen_owners
        _seen_owners.add(owner_key)
    if not already_seen:
        _try_activate_saved_environment(owner_key)


def _sweep_orphaned_scans():
    """5.51.0: removes any stored OPA scan whose environment is gone (an older release's delete, a restored backup), audited."""
    import audit_store
    try:
        for environment_id in audit_store.sweep_orphaned_opa_model_caches():
            engine.log_audit_event(None, None, "access_scan.cache_purged", {"environment_id": environment_id, "reason": "orphan"})
    except Exception as exc:
        engine.log("WARN", f"The stored-scan clean-up at start-up failed ({type(exc).__name__}); it is tried again at the next start.")


def main():
    parser = argparse.ArgumentParser(description="Local server for the OPA Compliance Wizard dashboard.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    # BUG FIX (found live deploying Phase 2's SQLite migration to the
    # Ubuntu server, 2026-10-01): init_db() must run BEFORE anything
    # touches app_environments/active_environments -- those tables don't
    # exist until migration 1 creates them. This order was backwards
    # (activate-then-init_db), which only "worked" by accident on a
    # machine where init_db() had already been run manually in an earlier
    # Python process; a real fresh process start (every systemd restart)
    # crash-looped with "no such table: active_environments."
    import audit_store
    audit_store.init_db()
    _sweep_orphaned_scans()
    audit_store._warn_if_shared_location()

    _seen_owners.add(LOCAL_OWNER_KEY_HEADER)
    _try_activate_saved_environment(LOCAL_OWNER_KEY_HEADER)

    # 5.53.0: evidence packages never outlive the process that built them (their download window is 15 minutes).
    try:
        removed = _evidence.cleanup_startup()
        if _evidence.startup_skipped:
            engine.log("WARN", f"Evidence packages folder not cleaned: {_evidence.startup_skipped}.")
        if removed:
            engine.log("INFO", f"Deleted {removed} evidence package folder(s) left from an earlier run.")
    except OSError as exc:
        engine.log("WARN", f"Could not clean the evidence packages folder: {exc}")

    threading.Thread(target=_scheduler_loop, daemon=True).start()

    if not FRONTEND_DIST.exists():
        engine.log("WARN", f"{FRONTEND_DIST} does not exist yet -- run 'npm run build' in frontend/ first.")

    # FIX (confirmed live, 2026-10-01): on the hosted Linux server, a
    # `systemctl restart` can start this new process before the OS has
    # actually released the OLD process's socket on this exact port --
    # systemd considers the unit "stopped" as soon as the old process
    # exits, with no guarantee the kernel's TCP teardown (TIME_WAIT, etc.)
    # has finished by the time the new ExecStart runs. StrictBindHTTPServer
    # deliberately keeps allow_reuse_address=False (see its own comment --
    # this is what makes a GENUINE double-bind mistake fail loudly instead
    # of silently succeeding on Windows), so this transient race surfaced
    # as a real bind failure, not a silent success -- confirmed live via
    # repeated clean (no manual interference) systemctl restarts: it
    # failed outright 2-3 times in a row before eventually succeeding,
    # relying entirely on systemd's RestartSec=3 to paper over it with a
    # visible crash-loop in `systemctl status` each time. A short in-process
    # retry here resolves the exact same transient condition directly,
    # without the restart-counter noise, while still failing with the
    # SAME clear error message below if the port is genuinely never
    # released (e.g. an actual second instance left running).
    max_bind_attempts = 5
    bind_retry_delay_secs = 1
    server = None
    last_exc = None
    for attempt in range(1, max_bind_attempts + 1):
        try:
            server = StrictBindHTTPServer(("127.0.0.1", args.port), Handler)
            break
        except OSError as exc:
            last_exc = exc
            if attempt < max_bind_attempts:
                time.sleep(bind_retry_delay_secs)
    if server is None:
        engine.log("ERROR", f"Could not bind 127.0.0.1:{args.port} ({last_exc}) after {max_bind_attempts} attempts. "
                             "Likely an existing server is already running on this port -- stop it (Ctrl+C in its "
                             "window, or close it) and try again, or run with --port <other_port>.")
        sys.exit(1)

    url = f"http://127.0.0.1:{args.port}/"
    engine.log("SUCCESS", f"Serving OPA Compliance Wizard at {url}")
    if LOCAL_OWNER_KEY_HEADER not in _sessions:
        engine.log("INFO", "No environment configured yet -- the dashboard will prompt you to set one up.")
    engine.log("INFO", "Press Ctrl+C to stop.")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        engine.log("INFO", "Stopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
