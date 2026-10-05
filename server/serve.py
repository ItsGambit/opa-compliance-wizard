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
import csv as _csv
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, urlencode

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import create_secret_folders as engine  # noqa: E402

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"

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
# public origin (e.g. "https://192.168.15.139"), not 127.0.0.1/localhost --
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
    return headers.get("X-Nginx-Proxy-Secret") == NGINX_PROXY_SECRET

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
    if DEPLOYMENT_MODE == "hosted" and path not in ("/healthz", "/api/version") and not _request_is_from_nginx(handler.headers):
        handler._send_json(401, {"error": "Authentication required."})
        return True
    return False


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
    auth_gate.py's loopback-only GET /internal/mfa_log_lookup. Returns
    None on ANY failure (secret not configured, auth_gate.py unreachable,
    bad response) -- same fail-open reasoning as everywhere else this
    corroboration is best-effort, never something a backfill attempt
    should error out over."""
    if not INTERNAL_API_SHARED_SECRET:
        return None
    params = urlencode({"sub": actor_sub, "near": near_iso_timestamp})
    url = f"{AUTH_GATE_INTERNAL_URL}/internal/mfa_log_lookup?{params}"
    req = urllib.request.Request(url, headers={"X-Internal-Secret": INTERNAL_API_SHARED_SECRET})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None


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


def _run_access_job(storage_name, job_client, job_okta_client, correlation_id=None):
    # A new thread does NOT inherit the parent thread's contextvars, so
    # the triggering request's own id (if any) has to be set again here
    # explicitly -- same reasoning as _run_sync_job below.
    engine.CORRELATION_ID.set(correlation_id)
    try:
        result = engine.build_access_model(
            job_client, okta_client=job_okta_client, on_progress=_access_job_progress(storage_name)
        )
        with _access_jobs_lock:
            _access_jobs[storage_name]["status"] = "done"
            _access_jobs[storage_name]["result"] = result
    except Exception as exc:
        with _access_jobs_lock:
            _access_jobs[storage_name]["status"] = "error"
            _access_jobs[storage_name]["error"] = str(exc)


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
            engine.log_audit_event(
                actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, **result},
                client_ip=client_ip, user_agent=user_agent,
            )
            return
        schedule = engine.get_sync_schedule(env_name, owner=owner)
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
    except Exception as exc:
        with _sync_jobs_lock:
            _sync_jobs[storage_name]["status"] = "error"
            _sync_jobs[storage_name]["error"] = str(exc)
        engine.log_audit_event(
            actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, "error": str(exc)},
            client_ip=client_ip, user_agent=user_agent,
        )


def _start_sync_job(env_id, env_name, ingestion_scope, owner=engine.LOCAL_OWNER_KEY, trigger="manual", actor_email=None, actor_sub=None, client_ip=None, user_agent=None, minutes_late=None, correlation_id=None):
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
    own `patlabs`, distinct from a shared `__local__::patlabs`), and its
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
    with _sync_jobs_lock:
        if _sync_jobs.get(storage_name, {}).get("status") == "running":
            if trigger == "scheduled":
                engine.log_audit_event(actor_email, actor_sub, "sync.scheduled_skipped", {"name": env_name, "reason": "already running"}, client_ip=client_ip, user_agent=user_agent)
            return False
    action_prefix = "sync.scheduled" if trigger == "scheduled" else "sync.manual"
    try:
        creds = engine.get_environment_credentials(env_name, owner=owner)
    except KeyError as exc:
        with _sync_jobs_lock:
            _sync_jobs[storage_name] = {"status": "error", "steps": [], "error": str(exc)}
        engine.log_audit_event(actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, "error": str(exc)}, client_ip=client_ip, user_agent=user_agent)
        return False
    if not creds.get("okta_url") or not creds.get("okta_api_token"):
        error_msg = "No Okta URL/API token configured for this environment."
        with _sync_jobs_lock:
            _sync_jobs[storage_name] = {"status": "error", "steps": [], "error": error_msg}
        engine.log_audit_event(actor_email, actor_sub, f"{action_prefix}_failed", {"name": env_name, "error": error_msg}, client_ip=client_ip, user_agent=user_agent)
        return False
    okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"])
    start_details = {"name": env_name, "ingestion_scope": ingestion_scope}
    if minutes_late is not None:
        # Only ever set for trigger="scheduled" (see _scheduler_loop) --
        # a real, human-readable signal that this run was a catch-up, not
        # an on-time fire, distinguishing "the scheduler is broken" from
        # "the scheduler correctly caught up after the server was down."
        start_details["minutes_late"] = minutes_late
    engine.log_audit_event(actor_email, actor_sub, f"{action_prefix}_start", start_details, client_ip=client_ip, user_agent=user_agent)
    threading.Thread(
        target=_run_sync_job, args=(env_id, env_name, okta_client, ingestion_scope, owner),
        kwargs={"trigger": trigger, "actor_email": actor_email, "actor_sub": actor_sub, "client_ip": client_ip, "user_agent": user_agent, "correlation_id": correlation_id},
        daemon=True,
    ).start()
    return True


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
    import audit_store
    while not _scheduler_stop_event.is_set():
        # No HTTP request exists to correlate this tick with (see
        # engine.CORRELATION_ID's own docstring) -- a "sched-" prefixed
        # id, regenerated every poll, still ties together every sync
        # this one tick starts and everything _run_sync_job itself logs
        # for them, without implying a request that was never made.
        engine.CORRELATION_ID.set(f"sched-{uuid.uuid4().hex[:8]}")
        try:
            now_utc = datetime.now(timezone.utc)
            # list_all_environments(), NOT list_environments_for(LOCAL_OWNER_KEY):
            # a per-user, non-shared environment (e.g. a logged-in Okta
            # identity's own private copy of "patlabs") owns its own
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
                    schedule = engine.get_sync_schedule(env_name, owner=owner)
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

                minutes_late = (now_utc.hour * 60 + now_utc.minute) - (run_hour * 60 + run_minute)
                _start_sync_job(
                    environment_id, env_name, schedule.get("ingestion_scope", "curated"), owner=owner, trigger="scheduled",
                    minutes_late=minutes_late if minutes_late > SCHEDULER_LATE_THRESHOLD_MINUTES else None,
                    correlation_id=engine.CORRELATION_ID.get(),
                )
        except Exception as exc:
            engine.log("ERROR", f"[scheduler] Unexpected error in scheduler loop: {exc}")
            engine.log_audit_event(None, None, "sync.scheduler_error", {"error": str(exc)})
        _scheduler_stop_event.wait(SCHEDULER_POLL_INTERVAL_SECS)


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


def _public_entry(environment_id, name, meta, requesting_owner):
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
    return {
        "id": environment_id,
        "name": name,
        "base_domain": meta.get("base_domain", ""),
        "team_name": meta.get("team_name", ""),
        "key_id": meta.get("key_id", ""),
        "okta_url": meta.get("okta_url", ""),
        "has_okta_token": bool(engine.keyring_get(environment_id, "okta_api_token")),
        "shared": bool(meta.get("shared", False)),
        "is_own": meta.get("owner") == requesting_owner,
        "sync_schedule": meta.get("sync_schedule", dict(engine.SYNC_SCHEDULE_DEFAULTS)),
    }


def activate_environment(owner_key, name):
    """Loads `name` (visible to this owner) from the encrypted store,
    authenticates to OPA, and (if Okta credentials are present) to Okta
    too. On success stores the new client/okta_client/env_name/env_id in
    this owner's session slot. Raises KeyError (unknown/not visible to
    this owner) or engine.OpaApiError (OPA auth failed).

    `env_id` (Phase 1's UUID migration) is resolved HERE, once, from
    `creds["environment_id"]` (get_environment_credentials already
    returns it, since it reads straight from the stored record) -- every
    downstream route reads it back out of the session via
    _session_snapshot instead of recomputing it per-request."""
    engine_owner = _engine_owner(owner_key)
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

    engine.set_active_environment(engine_owner, name)
    engine.log("INFO", f"Activated environment '{name}' ({creds['base_domain']}) for owner '{owner_key}'.")


# ---------------------------------------------------------------------------
# Folder-tree helpers
# ---------------------------------------------------------------------------
def _row_dict(path, folder_id, status, error_message):
    return {"path": "/".join(path), "folder_id": folder_id, "status": status, "error_message": error_message}


def _plan_dict(ordered_paths, existing, collisions):
    return {
        "tree": [
            {"path": "/".join(p), "depth": len(p) - 1, "exists": p in existing, "folder_id": existing.get(p, "")}
            for p in ordered_paths
        ],
        "collisions": {name: ["/".join(p) for p in paths] for name, paths in collisions.items()},
    }


def _safe_csv_path(filename):
    """Only allow a bare filename ending in .csv, resolved inside PROJECT_ROOT
    (no path traversal via '..' or absolute paths)."""
    name = os.path.basename((filename or "").strip())
    if not name or not name.lower().endswith(".csv"):
        raise ValueError("filename must be a bare name ending in .csv")
    return PROJECT_ROOT / name


def _run_pipeline(active_client, rows, resource_group_id, project_id):
    """Shared by /api/preview and /api/execute: parse -> validate -> collision
    check -> existing-folder lookup. Returns (ordered_paths, descriptions,
    existing, collisions, invalid_names). Takes the client explicitly
    (a snapshot the caller took at the start of its request) rather than
    reading the module-level `client` global itself -- see the note on
    request-scoped client snapshots above do_GET."""
    ordered_paths, descriptions = engine.parse_rows(rows, warn=False)
    invalid_names = [
        {"path": "/".join(p), "name": p[-1]}
        for p in ordered_paths
        if not engine.NAME_PATTERN.match(p[-1])
    ]
    collisions = engine.detect_name_collisions(ordered_paths)
    existing = engine.resolve_existing_folders(active_client, resource_group_id, project_id, ordered_paths)
    return ordered_paths, descriptions, existing, collisions, invalid_names


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
        return json.loads(raw.decode("utf-8")) if raw else {}

    # -----------------------------------------------------------------
    def do_GET(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if _reject_if_hosted_without_nginx(self, path):
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
        _ensure_session_initialized(owner_key)
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
                    checks["active_environment_credentials"] = f"error: {exc}"
                try:
                    import audit_store
                    audit_store._get_connection().execute("SELECT 1")
                    checks["archive_writable"] = "ok"
                except Exception as exc:
                    checks["archive_writable"] = f"error: {exc}"
                status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
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
                return self._send_json(200, {"email": email, "is_local": email is None, "is_admin": _is_admin_from_headers(self.headers)})

            if path == "/api/environments":
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
                        _public_entry(environment_id, meta.get("name"), meta, engine_owner)
                        for environment_id, meta in engine.list_all_environments().items()
                    ]
                else:
                    visible = engine.list_environments_for(engine_owner)
                    envs = [_public_entry(m["environment_id"], n, m, engine_owner) for n, m in visible.items()]
                return self._send_json(200, {"environments": envs, "active": local_env_name})

            if path == "/api/banner":
                # No client/auth requirement -- this has to render even
                # before an environment is configured (same reasoning as
                # /api/whoami and /api/version above), and it holds no
                # tenant data of its own.
                return self._send_json(200, engine.get_banner_config())

            if path.startswith("/api/environments/") and path.endswith("/sync/status"):
                name = unquote(path[len("/api/environments/"):-len("/sync/status")])
                import audit_store
                visible = engine.list_environments_for(engine_owner)
                meta = visible.get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
                environment_id = meta["environment_id"]
                with _sync_jobs_lock:
                    job = dict(_sync_jobs.get(environment_id, {"status": "idle", "steps": [], "error": None}))
                job["sync_state"] = audit_store.get_sync_state(environment_id)
                job["is_first_sync"] = audit_store.is_first_sync(environment_id)
                return self._send_json(200, job)

            if path.startswith("/api/environments/") and path.endswith("/integrity"):
                # Phase 6: cheap, mechanical "has this environment's
                # ingestion history been tampered with" check -- walks
                # the hash-chained ingestion_manifests table, never
                # touches `events` itself (see
                # audit_store.verify_ingestion_chain's docstring).
                name = unquote(path[len("/api/environments/"):-len("/integrity")])
                try:
                    result = engine.verify_environment_evidence_chain(name, owner=engine_owner)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                return self._send_json(200, result)

            if path == "/api/reports":
                import audit_store
                environment = (qs.get("environment") or [local_env_name])[0]
                environment_id = None
                if environment:
                    meta = engine.list_environments_for(engine_owner).get(environment)
                    if meta is None:
                        return self._send_json(404, {"error": f"No environment named '{environment}' visible to this user."})
                    environment_id = meta["environment_id"]
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
                connection_id = unquote(
                    path[len("/api/active_directory_connections/"):-len("/discovery_config")]
                )
                if not connection_id:
                    return self._send_json(400, {"error": "missing connection_id"})
                return self._send_json(200, engine.get_ad_connection_discovery_config(local_client, connection_id))

            if path == "/api/resource_groups":
                if not _require_client(self._send_json, local_client):
                    return
                return self._send_json(200, {"resource_groups": local_client.list_resource_groups()})

            if path.startswith("/api/resource_groups/") and path.endswith("/projects"):
                if not _require_client(self._send_json, local_client):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                return self._send_json(200, {"projects": local_client.list_projects(rg_id)})

            if path == "/api/groups":
                if not _require_client(self._send_json, local_client):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"groups": local_client.list_groups(contains=contains)})

            if (path.startswith("/api/resource_groups/") and path.endswith("/folders")
                    and "/projects/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                inner = path[len("/api/resource_groups/"):-len("/folders")]
                rg_id, _, proj_id = inner.partition("/projects/")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "missing resource_group_id or project_id"})
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
                inner = path[len("/api/resource_groups/"):-len("/secrets_access_report")]
                rg_id, _, proj_id = inner.partition("/projects/")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "missing resource_group_id or project_id"})
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
                if local_env_id and not audit_store.is_first_sync(local_env_id):
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

            if path.startswith("/api/resource_groups/") and path.endswith("/security_policies"):
                if not _require_client(self._send_json, local_client):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/security_policies")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                policies = [
                    engine.summarize_security_policy(p)
                    for p in local_client.list_security_policies()
                    if (p.get("resource_group") or {}).get("id") == rg_id
                ]
                return self._send_json(200, {"policies": policies})

            if path == "/api/workload_roles":
                if not _require_client(self._send_json, local_client):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"workload_roles": local_client.list_workload_roles(contains=contains)})

            if path == "/api/service_account":
                if not _require_client(self._send_json, local_client):
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

            if path == "/api/access/bootstrap/status":
                if not local_env_id:
                    return self._send_json(200, {"status": "idle", "steps": [], "error": None})
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
                with _access_jobs_lock:
                    job = _access_jobs.get(local_env_id)
                    if job is None or job["status"] != "done" or job.get("result") is None:
                        return self._send_json(409, {"error": "Job is not done yet."})
                    return self._send_json(200, job["result"])

            if path == "/api/csv_files":
                files = sorted(p.name for p in PROJECT_ROOT.glob("*.csv"))
                return self._send_json(200, {"files": files})

            if path == "/api/csv":
                filename = (qs.get("file") or [""])[0]
                csv_path = _safe_csv_path(filename)
                if not csv_path.is_file():
                    return self._send_json(404, {"error": f"{filename} not found"})
                with open(csv_path, newline="", encoding="utf-8-sig") as f:
                    rows = list(_csv.DictReader(f))
                return self._send_json(200, {"rows": rows})

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
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
                    return self._send_json(403, {"error": "Admin access required to view the audit log."})
                try:
                    limit = min(int((qs.get("limit") or [200])[0]), 1000)
                    offset = max(int((qs.get("offset") or [0])[0]), 0)
                except ValueError:
                    return self._send_json(400, {"error": "limit/offset must be integers"})
                return self._send_json(200, {"entries": engine.read_audit_log(limit=limit, offset=offset)})

            if path == "/api/access_control":
                # Admin-only read, same shape as /api/audit_log just above
                # (including the local-mode exemption) -- these are the
                # Okta group IDs that gate login/admin rights for EVERY
                # user, not a per-owner setting, so a non-admin has no
                # legitimate reason to see (let alone change) them.
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
                    return self._send_json(403, {"error": "Admin access required to view access control settings."})
                return self._send_json(200, engine.get_access_control_config())
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})

        super().do_GET()

    # -----------------------------------------------------------------
    def do_POST(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        path = urlparse(self.path).path
        if _reject_if_hosted_without_nginx(self, path):
            return
        if not self._check_origin():
            return
        owner_key = _owner_key_from_headers(self.headers)
        engine_owner = _engine_owner(owner_key)
        actor_email = self.headers.get("X-Auth-User")
        actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key
        _ensure_session_initialized(owner_key)
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
                # SECURITY FIX (external review, 2026-09-30): this had NO
                # admin check at all -- confirmed exploitable: any
                # authenticated user could publish/modify/disable the
                # org-wide announcement banner. Same check every other
                # admin-only write in this file already uses.
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
                    return self._send_json(403, {"error": "Admin access required to change the announcement banner."})
                config = engine.set_banner_config(
                    payload.get("enabled", False),
                    payload.get("message", ""),
                    payload.get("variant", "warning"),
                    payload.get("dismissible", True),
                )
                self._log_audit_event(actor_email, actor_sub, "banner.update", config)
                return self._send_json(200, config)

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
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
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
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
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
                    config = audit_store.consume_pending_admin_action(action_id, actor_sub)
                except audit_store.PendingActionError as exc:
                    status = 409 if exc.reason in ("already_consumed", "expired") else 403
                    return self._send_json(status, {"error": f"Could not apply this change ({exc.reason}) -- please try again.", "reason": exc.reason})
                config = engine.set_access_control_config(
                    config["admin_group_id"], config["user_group_id"], config["restrict_login"]
                )
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
                if owner_key != LOCAL_OWNER_KEY_HEADER and not _is_admin_from_headers(self.headers):
                    return self._send_json(403, {"error": "Admin access required to refresh MFA log corroboration."})
                updated_count = engine.backfill_mfa_log_events(_lookup_mfa_log_event)
                return self._send_json(200, {"updated_count": updated_count})

            if path == "/api/environments":
                is_admin = _is_admin_from_headers(self.headers)
                try:
                    name, _upserted_id = engine.upsert_environment(
                        payload.get("name"), payload, owner=engine_owner, is_admin=is_admin,
                        environment_id=payload.get("id"),
                    )
                except PermissionError as exc:
                    return self._send_json(403, {"error": str(exc)})
                self._log_audit_event(actor_email, actor_sub, "environment.upsert", {"name": name, "admin_override": is_admin})
                try:
                    activate_environment(owner_key, name)
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": f"Saved, but could not connect: {exc}", "saved": True})
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/activate"):
                name = unquote(path[len("/api/environments/"):-len("/activate")])
                try:
                    activate_environment(owner_key, name)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": str(exc)})
                self._log_audit_event(actor_email, actor_sub, "environment.activate", {"name": name})
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/share"):
                name = unquote(path[len("/api/environments/"):-len("/share")])
                shared = bool(payload.get("shared", False))
                is_admin = _is_admin_from_headers(self.headers)
                try:
                    engine.set_environment_shared(
                        name, engine_owner, shared, is_admin=is_admin,
                        environment_id=payload.get("id"),
                    )
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except PermissionError as exc:
                    return self._send_json(403, {"error": str(exc)})
                self._log_audit_event(actor_email, actor_sub, "environment.share", {"name": name, "shared": shared, "admin_override": is_admin})
                return self._send_json(200, {"name": name, "shared": shared})

            if path.startswith("/api/environments/") and path.endswith("/sync_schedule"):
                name = unquote(path[len("/api/environments/"):-len("/sync_schedule")])
                try:
                    saved = engine.set_sync_schedule(name, payload, owner=engine_owner)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except ValueError as exc:
                    return self._send_json(400, {"error": str(exc)})
                self._log_audit_event(actor_email, actor_sub, "sync_schedule.update", {"name": name, **saved})
                return self._send_json(200, {"name": name, "sync_schedule": saved})

            if path.startswith("/api/environments/") and path.endswith("/sync/start"):
                name = unquote(path[len("/api/environments/"):-len("/sync/start")])
                try:
                    schedule = engine.get_sync_schedule(name, owner=engine_owner)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                meta = engine.list_environments_for(engine_owner).get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
                ingestion_scope = payload.get("ingestion_scope") or schedule.get("ingestion_scope", "curated")
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
                    meta["environment_id"], name, ingestion_scope, owner=engine_owner, trigger="manual",
                    actor_email=actor_email, actor_sub=actor_sub,
                    client_ip=self._request_client_ip(),
                    user_agent=self.headers.get("User-Agent"),
                    correlation_id=engine.CORRELATION_ID.get(),
                )
                return self._send_json(200, {"started": started, "already_running": not started})

            if path.startswith("/api/environments/") and path.endswith("/sync/import_csv"):
                name = unquote(path[len("/api/environments/"):-len("/sync/import_csv")])
                import audit_store
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
                meta = engine.list_environments_for(engine_owner).get(name)
                if meta is None:
                    return self._send_json(404, {"error": f"No environment named '{name}' visible to this user."})
                try:
                    csv_path = _safe_csv_path(payload.get("csv_path"))
                except ValueError as exc:
                    return self._send_json(400, {"error": str(exc)})
                ingestion_scope = payload.get("ingestion_scope", "curated")
                if not csv_path.is_file():
                    return self._send_json(400, {"error": f"{csv_path.name} not found on server filesystem"})
                try:
                    result = audit_store.import_from_csv(str(csv_path), meta["environment_id"], ingestion_scope)
                except ValueError as exc:
                    return self._send_json(400, {"error": str(exc)})
                self._log_audit_event(actor_email, actor_sub, "sync.import_csv", {"name": name, "csv_path": csv_path.name, **result})
                return self._send_json(200, result)

            if path == "/api/access/bootstrap/start":
                if not _require_client(self._send_json, local_client):
                    return
                with _access_jobs_lock:
                    if _access_jobs.get(_local_env_id, {}).get("status") == "running":
                        return self._send_json(200, {"started": False, "already_running": True})
                    _access_jobs[_local_env_id] = {"status": "running", "steps": [], "error": None, "result": None}
                threading.Thread(
                    target=_run_access_job, args=(_local_env_id, local_client, local_okta_client),
                    kwargs={"correlation_id": engine.CORRELATION_ID.get()}, daemon=True
                ).start()
                return self._send_json(200, {"started": True, "steps": engine.ACCESS_MODEL_STEPS})

            if path == "/api/resource_groups":
                if not _require_client(self._send_json, local_client):
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
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                name = (payload.get("name") or "").strip()
                if not rg_id or not name:
                    return self._send_json(400, {"error": "resource_group_id (in URL) and name are required"})
                created = local_client.create_project(rg_id, name)
                self._log_audit_event(actor_email, actor_sub, "project.create", {
                    "env_name": _local_env_name, "resource_group_id": rg_id, "name": name, "project_id": created.get("id"),
                })
                return self._send_json(201, {"project": created})

            if (path.startswith("/api/resource_groups/") and path.endswith("/policy")
                    and "/projects/" in path and "/folders/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                inner = path[len("/api/resource_groups/"):-len("/policy")]
                rg_id, _, rest = inner.partition("/projects/")
                proj_id, _, folder_part = rest.partition("/folders/")
                folder_id = folder_part.rstrip("/")
                if not rg_id or not proj_id or not folder_id:
                    return self._send_json(400, {"error": "missing resource_group_id, project_id, or folder_id"})

                mode = payload.get("mode")
                folder_name = payload.get("folder_name", "")
                rule_name = payload.get("rule_name") or f"{folder_name}-access"
                privileges = payload.get("privileges") or {}
                mfa = payload.get("mfa")
                group_refs = payload.get("group_refs") or []
                workload_role_refs = payload.get("workload_role_refs") or []

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

                if mode == "existing":
                    policy_id = payload.get("policy_id")
                    if not policy_id:
                        return self._send_json(400, {"error": "policy_id is required to attach to an existing policy"})
                    current = local_client.get_security_policy(policy_id)
                    current["principals"] = engine.merge_principals(current.get("principals"), group_refs, workload_role_refs)
                    engine.upsert_folder_rule_in_policy(current, folder_id, folder_name, rule_name, privileges, mfa=mfa)
                    local_client.update_security_policy(policy_id, current)
                    updated = local_client.get_security_policy(policy_id)
                    self._log_audit_event(actor_email, actor_sub, "policy.update", {
                        "env_name": _local_env_name, "resource_group_id": rg_id, "folder_id": folder_id,
                        "policy_id": policy_id,
                    })
                    return self._send_json(200, {"policy": engine.summarize_security_policy(updated)})

                return self._send_json(400, {"error": "mode must be 'new' or 'existing'"})

            if path == "/api/groups":
                if not _require_client(self._send_json, local_client):
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
                csv_path = _safe_csv_path(payload.get("file"))
                rows = payload.get("rows") or []
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = _csv.DictWriter(f, fieldnames=["path", "description"])
                    writer.writeheader()
                    for row in rows:
                        writer.writerow({"path": row.get("path", ""), "description": row.get("description", "")})
                engine.log("INFO", f"Saved {len(rows)} row(s) to {csv_path.name}")
                self._log_audit_event(actor_email, actor_sub, "csv.save", {
                    "file": csv_path.name, "row_count": len(rows),
                })
                return self._send_json(200, {"saved": True, "file": csv_path.name, "row_count": len(rows)})

            if path == "/api/preview":
                if not _require_client(self._send_json, local_client):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                ordered_paths, _descriptions, existing, collisions, invalid_names = _run_pipeline(
                    local_client, payload.get("rows") or [], rg_id, proj_id
                )
                result = _plan_dict(ordered_paths, existing, collisions)
                result["invalid_names"] = invalid_names
                return self._send_json(200, result)

            if path == "/api/execute":
                if not _require_client(self._send_json, local_client):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                ordered_paths, descriptions, existing, collisions, invalid_names = _run_pipeline(
                    local_client, payload.get("rows") or [], rg_id, proj_id
                )
                if invalid_names:
                    return self._send_json(
                        400, {"error": "Invalid folder name(s); fix and retry.", "invalid_names": invalid_names}
                    )
                results = engine.execute_plan(local_client, rg_id, proj_id, ordered_paths, descriptions, existing)
                output_path = PROJECT_ROOT / f"folders_result_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
                engine.write_results_csv(output_path, results)
                engine.log("INFO", f"Execute complete: results written to {output_path.name}")
                self._log_audit_event(actor_email, actor_sub, "folders.execute", {
                    "env_name": _local_env_name, "resource_group_id": rg_id, "project_id": proj_id,
                    "output_file": output_path.name, "folder_count": len(results),
                })
                return self._send_json(200, {
                    "results": [_row_dict(*r) for r in results],
                    "collisions": {name: ["/".join(p) for p in paths] for name, paths in collisions.items()},
                    "output_file": output_path.name,
                })

            if path.startswith("/api/access/users/") and path.endswith("/resource_access"):
                if not _require_okta_client(self._send_json, local_okta_client):
                    return
                user_id = path[len("/api/access/users/"):-len("/resource_access")]
                if not user_id:
                    return self._send_json(400, {"error": "missing user_id"})
                resources = payload.get("resources") or []
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
                results = engine.find_last_access_for_user(local_okta_client, actor_id, resources)
                return self._send_json(200, {"results": results})

            return self._send_json(404, {"error": "not found"})
        except _RequestAborted:
            return
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})

    # -----------------------------------------------------------------
    def do_DELETE(self):
        correlation_id = uuid.uuid4().hex[:12]
        engine.CORRELATION_ID.set(correlation_id)
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if _reject_if_hosted_without_nginx(self, path):
            return
        if not self._check_origin():
            return
        owner_key = _owner_key_from_headers(self.headers)
        engine_owner = _engine_owner(owner_key)
        actor_email = self.headers.get("X-Auth-User")
        actor_sub = None if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key
        _ensure_session_initialized(owner_key)
        # Snapshot for the folder-delete branch below -- see the identical
        # note in do_GET/do_POST. The environment-delete branch legitimately
        # clears this owner's session slot itself (that's the whole point
        # of that branch).
        local_client, _local_okta_client, local_env_name, _local_env_id = _session_snapshot(owner_key)
        try:
            if path.startswith("/api/environments/"):
                name = unquote(path[len("/api/environments/"):])
                is_admin = _is_admin_from_headers(self.headers)
                environment_id = (qs.get("id") or [None])[0]
                try:
                    was_active = engine.delete_environment(
                        name, owner=engine_owner, is_admin=is_admin, environment_id=environment_id,
                    )
                except PermissionError as exc:
                    return self._send_json(403, {"error": str(exc)})
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                if was_active:
                    with _sessions_lock:
                        _sessions.pop(owner_key, None)
                self._log_audit_event(actor_email, actor_sub, "environment.delete", {"name": name, "admin_override": is_admin})
                return self._send_json(200, {"deleted": name})

            if (path.startswith("/api/resource_groups/") and "/projects/" in path
                    and "/folders/" in path):
                if not _require_client(self._send_json, local_client):
                    return
                inner = path[len("/api/resource_groups/"):]
                rg_id, _, rest = inner.partition("/projects/")
                proj_id, _, folder_id = rest.partition("/folders/")
                folder_id = folder_id.rstrip("/")
                if not rg_id or not proj_id or not folder_id:
                    return self._send_json(400, {"error": "missing resource_group_id, project_id, or folder_id"})
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
                inner = path[len("/api/groups/"):]
                group_id, _, user_name = inner.partition("/members/")
                user_name = unquote(user_name.rstrip("/"))
                if not group_id or not user_name:
                    return self._send_json(400, {"error": "missing group_id or user_name"})
                group = next((g for g in local_client.list_groups() if g.get("id") == group_id), None)
                if not group:
                    return self._send_json(404, {"error": f"Unknown group id '{group_id}'"})
                local_client.remove_user_from_group(group["name"], user_name)
                self._log_audit_event(actor_email, actor_sub, "group.remove_member", {
                    "env_name": local_env_name, "group_id": group_id, "user_name": user_name,
                })
                return self._send_json(200, {"removed": True, "group_id": group_id, "user_name": user_name})

            return self._send_json(404, {"error": "not found"})
        except KeyError as exc:
            return self._send_json(404, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})


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
    name = engine.get_active_environment_name(engine_owner)
    if not name:
        return
    try:
        activate_environment(owner_key, name)
    except Exception as exc:
        engine.log("WARN", f"Could not auto-activate saved environment '{name}' for owner '{owner_key}': {exc}")


def _ensure_session_initialized(owner_key):
    """Lazily runs _try_activate_saved_environment for an owner the first
    time any request from them arrives in this process -- avoids requiring
    every logged-in user to explicitly re-activate an environment they'd
    already set active in a previous session/process."""
    with _sessions_lock:
        already_seen = owner_key in _sessions or owner_key in _seen_owners
        _seen_owners.add(owner_key)
    if not already_seen:
        _try_activate_saved_environment(owner_key)


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

    _seen_owners.add(LOCAL_OWNER_KEY_HEADER)
    _try_activate_saved_environment(LOCAL_OWNER_KEY_HEADER)

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
