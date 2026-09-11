"""
Local-only server for the OPA Secrets Wizard dashboard.

Serves frontend/dist/ as static files and exposes a small JSON API the React
app uses to: manage named environments (dev/uat/prod, credentials stored
encrypted -- see create_secret_folders.py's environments.json + keyring
helpers, all imported as `engine` so nothing is duplicated), list/create
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
import webbrowser
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

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
    return headers.get("X-Auth-Sub") or LOCAL_OWNER_KEY_HEADER


def _engine_owner(owner_key):
    """Maps an HTTP-layer owner_key back to what the engine's storage layer
    expects: LOCAL_OWNER_KEY (None) for the local sentinel, the real Okta
    sub otherwise."""
    return engine.LOCAL_OWNER_KEY if owner_key == LOCAL_OWNER_KEY_HEADER else owner_key


def _session_snapshot(owner_key):
    """Returns (client, okta_client, env_name) for this owner, all None if
    they have no active session yet. Snapshotting a dict lookup under the
    lock, same spirit as the pre-existing single-global snapshot pattern:
    a concurrent switch/delete for the SAME owner must not affect a request
    already in flight for that owner."""
    with _sessions_lock:
        session = _sessions.get(owner_key)
    if session is None:
        return None, None, None
    return session["client"], session["okta_client"], session["env_name"]

# Access Explorer bootstrap job -- build_access_model takes real time
# (~30s+ on a tenant with data), so it runs in a background thread and the
# frontend polls _access_job's status instead of holding one HTTP request
# open the whole time. Single global job: a second start while one is
# already running is a no-op (see /api/access/bootstrap/start), so there's
# never more than one in flight.
_access_job_lock = threading.Lock()
_access_job = {"status": "idle", "steps": [], "error": None}
_access_job_result = None  # kept out of _access_job so status polls stay small


def _access_job_progress(key, status, detail=None):
    with _access_job_lock:
        _access_job["steps"].append({"key": key, "status": status, "detail": detail})


def _run_access_job(job_client):
    global _access_job, _access_job_result
    try:
        result = engine.build_access_model(job_client, on_progress=_access_job_progress)
        with _access_job_lock:
            _access_job["status"] = "done"
            _access_job_result = result
    except Exception as exc:
        with _access_job_lock:
            _access_job["status"] = "error"
            _access_job["error"] = str(exc)


class StrictBindHTTPServer(ThreadingHTTPServer):
    # http.server.HTTPServer sets allow_reuse_address=True, which on Windows
    # (unlike POSIX) lets a second process silently bind to a port that
    # another process is already actively listening on, instead of raising
    # "address already in use". Disabling it makes the OSError-on-bind check
    # in main() actually fire consistently on Windows, Mac, and Linux.
    allow_reuse_address = False


def _public_entry(name, meta, requesting_owner):
    """Non-secret fields only -- key_secret/okta_api_token never leave the
    keychain, let alone reach the browser. `requesting_owner` is the
    engine-layer owner (see _engine_owner) of whoever is asking, used only
    to compute `is_own` -- lets the frontend show "yours" vs. "shared with
    you" without exposing anyone else's real owner id."""
    storage_name = engine.environment_storage_name(meta.get("owner"), name)
    return {
        "name": name,
        "base_domain": meta.get("base_domain", ""),
        "team_name": meta.get("team_name", ""),
        "key_id": meta.get("key_id", ""),
        "okta_url": meta.get("okta_url", ""),
        "has_okta_token": bool(engine.keyring_get(storage_name, "okta_api_token")),
        "preserve_logs_locally": bool(meta.get("preserve_logs_locally", False)),
        "shared": bool(meta.get("shared", False)),
        "is_own": meta.get("owner") == requesting_owner,
    }


def activate_environment(owner_key, name):
    """Loads `name` (visible to this owner) from the encrypted store,
    authenticates to OPA, and (if Okta credentials are present) to Okta
    too. On success stores the new client/okta_client/env_name in this
    owner's session slot. Raises KeyError (unknown/not visible to this
    owner) or engine.OpaApiError (OPA auth failed)."""
    engine_owner = _engine_owner(owner_key)
    creds = engine.get_environment_credentials(name, owner=engine_owner)  # raises KeyError if unknown/not visible

    new_client = engine.OpaClient(creds["base_domain"], creds["team_name"], creds["key_id"], creds["key_secret"])
    new_okta_client = None
    if creds.get("okta_url") and creds.get("okta_api_token"):
        new_okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"])

    with _sessions_lock:
        _sessions[owner_key] = {"client": new_client, "okta_client": new_okta_client, "env_name": name}

    engine.set_active_environment(engine_owner, name)
    print(f"Activated environment '{name}' ({creds['base_domain']}) for owner '{owner_key}'.")


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
        length = int(self.headers.get("Content-Length", 0))
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
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
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
        local_client, local_okta_client, local_env_name = _session_snapshot(owner_key)

        try:
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
                return self._send_json(200, {"email": email, "is_local": email is None})

            if path == "/api/environments":
                visible = engine.list_environments_for(engine_owner)
                envs = [_public_entry(n, m, engine_owner) for n, m in visible.items()]
                return self._send_json(200, {"environments": envs, "active": local_env_name})

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
                if not _require_okta_client(self._send_json, local_okta_client):
                    return
                inner = path[len("/api/resource_groups/"):-len("/secrets_access_report")]
                rg_id, _, proj_id = inner.partition("/projects/")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "missing resource_group_id or project_id"})
                preserve_locally = False
                if local_env_name:
                    try:
                        env_meta = engine.get_environment_credentials(local_env_name, owner=engine_owner)
                        preserve_locally = bool(env_meta.get("preserve_logs_locally", False))
                    except KeyError:
                        pass
                report = engine.build_secrets_access_report(
                    local_client, local_okta_client, rg_id, proj_id,
                    preserve_locally=preserve_locally, env_name=local_env_name,
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
                with _access_job_lock:
                    return self._send_json(200, {
                        "status": _access_job["status"],
                        "steps": _access_job["steps"],
                        "error": _access_job["error"],
                    })

            if path == "/api/access/bootstrap/result":
                with _access_job_lock:
                    if _access_job["status"] != "done" or _access_job_result is None:
                        return self._send_json(409, {"error": "Job is not done yet."})
                    return self._send_json(200, _access_job_result)

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
                try:
                    limit = min(int((qs.get("limit") or [200])[0]), 1000)
                    offset = max(int((qs.get("offset") or [0])[0]), 0)
                except ValueError:
                    return self._send_json(400, {"error": "limit/offset must be integers"})
                return self._send_json(200, {"entries": engine.read_audit_log(limit=limit, offset=offset)})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})

        super().do_GET()

    # -----------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
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
        local_client, local_okta_client, _local_env_name = _session_snapshot(owner_key)
        try:
            payload = self._read_json_body()

            if path == "/api/environments":
                name = engine.upsert_environment(payload.get("name"), payload, owner=engine_owner)
                engine.log_audit_event(actor_email, actor_sub, "environment.upsert", {"name": name})
                try:
                    activate_environment(owner_key, name)
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": f"Saved, but could not connect: {exc}", "saved": True})
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/activate"):
                name = path[len("/api/environments/"):-len("/activate")]
                try:
                    activate_environment(owner_key, name)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": str(exc)})
                engine.log_audit_event(actor_email, actor_sub, "environment.activate", {"name": name})
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/share"):
                name = path[len("/api/environments/"):-len("/share")]
                shared = bool(payload.get("shared", False))
                try:
                    engine.set_environment_shared(name, engine_owner, shared)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except PermissionError as exc:
                    return self._send_json(403, {"error": str(exc)})
                engine.log_audit_event(actor_email, actor_sub, "environment.share", {"name": name, "shared": shared})
                return self._send_json(200, {"name": name, "shared": shared})

            if path.startswith("/api/environments/") and path.endswith("/preserve_logs_locally"):
                name = path[len("/api/environments/"):-len("/preserve_logs_locally")]
                enabled = bool(payload.get("enabled", False))
                try:
                    engine.set_preserve_logs_locally(name, enabled, owner=engine_owner)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                return self._send_json(200, {"name": name, "preserve_logs_locally": enabled})

            if path == "/api/access/bootstrap/start":
                if not _require_client(self._send_json, local_client):
                    return
                global _access_job
                with _access_job_lock:
                    if _access_job["status"] == "running":
                        return self._send_json(200, {"started": False, "already_running": True})
                    _access_job = {"status": "running", "steps": [], "error": None}
                threading.Thread(target=_run_access_job, args=(local_client,), daemon=True).start()
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
                engine.log_audit_event(actor_email, actor_sub, "resource_group.create", {
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
                engine.log_audit_event(actor_email, actor_sub, "project.create", {
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
                    engine.log_audit_event(actor_email, actor_sub, "policy.create", {
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
                    engine.log_audit_event(actor_email, actor_sub, "policy.update", {
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
                    engine.log_audit_event(actor_email, actor_sub, "group.create", {
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

                engine.log_audit_event(actor_email, actor_sub, "group.create", {
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
                engine.log_audit_event(actor_email, actor_sub, "service_account.join_group", {
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
                print(f"Saved {len(rows)} row(s) to {csv_path.name}")
                engine.log_audit_event(actor_email, actor_sub, "csv.save", {
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
                print(f"Execute complete: results written to {output_path.name}")
                engine.log_audit_event(actor_email, actor_sub, "folders.execute", {
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
                if _access_job_result is None:
                    return self._send_json(409, {"error": "Access model not loaded yet -- run the Access Explorer bootstrap first."})
                opa_user = next((u for u in _access_job_result["users"] if u.get("id") == user_id), None)
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
        path = urlparse(self.path).path
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
        local_client, _local_okta_client, local_env_name = _session_snapshot(owner_key)
        try:
            if path.startswith("/api/environments/"):
                name = path[len("/api/environments/"):]
                try:
                    was_active = engine.delete_environment(name, owner=engine_owner)
                except PermissionError as exc:
                    return self._send_json(403, {"error": str(exc)})
                if was_active:
                    with _sessions_lock:
                        _sessions.pop(owner_key, None)
                engine.log_audit_event(actor_email, actor_sub, "environment.delete", {"name": name})
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
                engine.log_audit_event(actor_email, actor_sub, "folder.delete", {
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
                engine.log_audit_event(actor_email, actor_sub, "group.remove_member", {
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
        print(f"Could not auto-activate saved environment '{name}' for owner '{owner_key}': {exc}")


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
    parser = argparse.ArgumentParser(description="Local server for the OPA Secrets Wizard dashboard.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    _seen_owners.add(LOCAL_OWNER_KEY_HEADER)
    _try_activate_saved_environment(LOCAL_OWNER_KEY_HEADER)

    if not FRONTEND_DIST.exists():
        print(f"Warning: {FRONTEND_DIST} does not exist yet -- run 'npm run build' in frontend/ first.")

    try:
        server = StrictBindHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"Could not bind 127.0.0.1:{args.port} ({exc}).")
        print("Likely an existing server is already running on this port -- stop it (Ctrl+C in its")
        print(f"window, or close it) and try again, or run with --port <other_port>.")
        sys.exit(1)

    url = f"http://127.0.0.1:{args.port}/"
    print(f"Serving OPA Secrets Wizard at {url}")
    if LOCAL_OWNER_KEY_HEADER not in _sessions:
        print("No environment configured yet -- the dashboard will prompt you to set one up.")
    print("Press Ctrl+C to stop.")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
