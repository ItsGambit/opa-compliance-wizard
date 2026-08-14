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
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
import create_secret_folders as engine  # noqa: E402

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"

GROUP_PUSH_PROPAGATION_RETRIES = 5
GROUP_PUSH_PROPAGATION_DELAY_SECS = 1.5

client = None  # OpaClient, set once an environment is successfully activated
okta_client = None  # OktaClient, set only if the active environment has okta_url + okta_api_token
active_env_name = None

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


def _public_entry(name, meta):
    """Non-secret fields only -- key_secret/okta_api_token never leave the
    keychain, let alone reach the browser."""
    return {
        "name": name,
        "base_domain": meta.get("base_domain", ""),
        "team_name": meta.get("team_name", ""),
        "key_id": meta.get("key_id", ""),
        "okta_url": meta.get("okta_url", ""),
        "has_okta_token": bool(engine.keyring_get(name, "okta_api_token")),
    }


def activate_environment(name):
    """Loads `name` from the encrypted store, authenticates to OPA, and (if
    Okta credentials are present) to Okta too. On success sets the
    module-level client/okta_client/active_env_name. Raises KeyError
    (unknown name) or engine.OpaApiError (OPA auth failed)."""
    global client, okta_client, active_env_name

    creds = engine.get_environment_credentials(name)  # raises KeyError if unknown
    new_client = engine.OpaClient(creds["base_domain"], creds["team_name"], creds["key_id"], creds["key_secret"])

    new_okta_client = None
    if creds.get("okta_url") and creds.get("okta_api_token"):
        new_okta_client = engine.OktaClient(creds["okta_url"], creds["okta_api_token"])

    client = new_client
    okta_client = new_okta_client
    active_env_name = name

    data = engine.load_environments()
    data["active"] = name
    engine.save_environments(data)
    print(f"Activated environment '{name}' ({creds['base_domain']}).")


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


def _run_pipeline(rows, resource_group_id, project_id):
    """Shared by /api/preview and /api/execute: parse -> validate -> collision
    check -> existing-folder lookup. Returns (ordered_paths, descriptions,
    existing, collisions, invalid_names)."""
    ordered_paths, descriptions = engine.parse_rows(rows, warn=False)
    invalid_names = [
        {"path": "/".join(p), "name": p[-1]}
        for p in ordered_paths
        if not engine.NAME_PATTERN.match(p[-1])
    ]
    collisions = engine.detect_name_collisions(ordered_paths)
    existing = engine.resolve_existing_folders(client, resource_group_id, project_id, ordered_paths)
    return ordered_paths, descriptions, existing, collisions, invalid_names


def _require_client(send_json):
    if client is None:
        send_json(409, {"error": "No active environment configured. Use the gear menu to set one up."})
        return False
    return True


def _require_okta_client(send_json):
    if okta_client is None:
        send_json(
            409,
            {"error": "This environment has no Okta URL/API token configured. Add them via the gear menu to create groups."},
        )
        return False
    return True


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIST), **kwargs)

    def log_message(self, fmt, *args):
        pass  # keep console output to our own explicit prints

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "http://localhost:5173")
        super().end_headers()

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    # -----------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        try:
            if path == "/api/environments":
                data = engine.load_environments()
                envs = [_public_entry(n, e) for n, e in data["environments"].items()]
                return self._send_json(200, {"environments": envs, "active": data.get("active")})

            if path == "/api/resource_groups":
                if not _require_client(self._send_json):
                    return
                return self._send_json(200, {"resource_groups": client.list_resource_groups()})

            if path.startswith("/api/resource_groups/") and path.endswith("/projects"):
                if not _require_client(self._send_json):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                return self._send_json(200, {"projects": client.list_projects(rg_id)})

            if path == "/api/groups":
                if not _require_client(self._send_json):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"groups": client.list_groups(contains=contains)})

            if (path.startswith("/api/resource_groups/") and path.endswith("/folders")
                    and "/projects/" in path):
                if not _require_client(self._send_json):
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
                folders = engine.fetch_all_folders(client, rg_id, proj_id)
                by_id = {f["id"]: f for f in folders if f.get("id")}

                def _full_path(folder):
                    names = []
                    current = folder
                    while current is not None:
                        names.append(current["name"])
                        parent_id = current.get("parent_id")
                        current = by_id.get(parent_id) if parent_id else None
                    return "/".join(reversed(names))

                rows = [
                    {"path": _full_path(f), "description": f.get("description", ""), "folder_id": f.get("id")}
                    for f in folders
                ]
                return self._send_json(200, {"rows": rows})

            if path.startswith("/api/resource_groups/") and path.endswith("/security_policies"):
                if not _require_client(self._send_json):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/security_policies")]
                if not rg_id:
                    return self._send_json(400, {"error": "missing resource_group_id"})
                policies = [
                    engine.summarize_security_policy(p)
                    for p in client.list_security_policies()
                    if (p.get("resource_group") or {}).get("id") == rg_id
                ]
                return self._send_json(200, {"policies": policies})

            if path == "/api/workload_roles":
                if not _require_client(self._send_json):
                    return
                contains = (qs.get("contains") or [None])[0]
                return self._send_json(200, {"workload_roles": client.list_workload_roles(contains=contains)})

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
        try:
            payload = self._read_json_body()

            if path == "/api/environments":
                name = engine.upsert_environment(payload.get("name"), payload)
                try:
                    activate_environment(name)
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": f"Saved, but could not connect: {exc}", "saved": True})
                return self._send_json(200, {"activated": True, "active": name})

            if path.startswith("/api/environments/") and path.endswith("/activate"):
                name = path[len("/api/environments/"):-len("/activate")]
                try:
                    activate_environment(name)
                except KeyError as exc:
                    return self._send_json(404, {"error": str(exc)})
                except engine.OpaApiError as exc:
                    return self._send_json(502, {"error": str(exc)})
                return self._send_json(200, {"activated": True, "active": name})

            if path == "/api/access/bootstrap/start":
                if not _require_client(self._send_json):
                    return
                global _access_job
                with _access_job_lock:
                    if _access_job["status"] == "running":
                        return self._send_json(200, {"started": False, "already_running": True})
                    _access_job = {"status": "running", "steps": [], "error": None}
                threading.Thread(target=_run_access_job, args=(client,), daemon=True).start()
                return self._send_json(200, {"started": True, "steps": engine.ACCESS_MODEL_STEPS})

            if path == "/api/resource_groups":
                if not _require_client(self._send_json):
                    return
                name = (payload.get("name") or "").strip()
                if not name:
                    return self._send_json(400, {"error": "name is required"})
                group_ids = payload.get("group_ids") or []
                if not group_ids:
                    return self._send_json(
                        400, {"error": "At least one group is required to create a resource group in OPA."}
                    )
                created = client.create_resource_group(
                    name, payload.get("description", ""), delegated_resource_admin_group_ids=group_ids
                )
                return self._send_json(201, {"resource_group": created})

            if path.startswith("/api/resource_groups/") and path.endswith("/projects"):
                if not _require_client(self._send_json):
                    return
                rg_id = path[len("/api/resource_groups/"):-len("/projects")]
                name = (payload.get("name") or "").strip()
                if not rg_id or not name:
                    return self._send_json(400, {"error": "resource_group_id (in URL) and name are required"})
                created = client.create_project(rg_id, name)
                return self._send_json(201, {"project": created})

            if (path.startswith("/api/resource_groups/") and path.endswith("/policy")
                    and "/projects/" in path and "/folders/" in path):
                if not _require_client(self._send_json):
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
                    created = client.create_security_policy(policy_body)
                    return self._send_json(201, {"policy": engine.summarize_security_policy(created)})

                if mode == "existing":
                    policy_id = payload.get("policy_id")
                    if not policy_id:
                        return self._send_json(400, {"error": "policy_id is required to attach to an existing policy"})
                    current = client.get_security_policy(policy_id)
                    current["principals"] = engine.merge_principals(current.get("principals"), group_refs, workload_role_refs)
                    engine.upsert_folder_rule_in_policy(current, folder_id, folder_name, rule_name, privileges, mfa=mfa)
                    client.update_security_policy(policy_id, current)
                    updated = client.get_security_policy(policy_id)
                    return self._send_json(200, {"policy": engine.summarize_security_policy(updated)})

                return self._send_json(400, {"error": "mode must be 'new' or 'existing'"})

            if path == "/api/groups":
                if not _require_client(self._send_json):
                    return
                if not _require_okta_client(self._send_json):
                    return
                name = (payload.get("name") or "").strip()
                if not name:
                    return self._send_json(400, {"error": "name is required"})

                app = okta_client.find_privileged_access_app()
                okta_group = okta_client.create_group(name, payload.get("description", ""))
                okta_client.create_group_push_mapping(app["id"], okta_group["id"], name)

                opa_group = None
                for _attempt in range(GROUP_PUSH_PROPAGATION_RETRIES):
                    matches = client.list_groups(contains=name)
                    opa_group = next((g for g in matches if g.get("name") == name), None)
                    if opa_group:
                        break
                    time.sleep(GROUP_PUSH_PROPAGATION_DELAY_SECS)

                if not opa_group:
                    return self._send_json(202, {
                        "created_in_okta": True,
                        "pushed": True,
                        "visible_in_opa": False,
                        "message": f"Group '{name}' was created in Okta and pushed, but hasn't appeared in "
                                   "OPA yet. Try refreshing the group list in a few seconds.",
                    })
                return self._send_json(201, {"created_in_okta": True, "pushed": True, "visible_in_opa": True, "group": opa_group})

            if path == "/api/csv":
                csv_path = _safe_csv_path(payload.get("file"))
                rows = payload.get("rows") or []
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = _csv.DictWriter(f, fieldnames=["path", "description"])
                    writer.writeheader()
                    for row in rows:
                        writer.writerow({"path": row.get("path", ""), "description": row.get("description", "")})
                print(f"Saved {len(rows)} row(s) to {csv_path.name}")
                return self._send_json(200, {"saved": True, "file": csv_path.name, "row_count": len(rows)})

            if path == "/api/preview":
                if not _require_client(self._send_json):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                ordered_paths, _descriptions, existing, collisions, invalid_names = _run_pipeline(
                    payload.get("rows") or [], rg_id, proj_id
                )
                result = _plan_dict(ordered_paths, existing, collisions)
                result["invalid_names"] = invalid_names
                return self._send_json(200, result)

            if path == "/api/execute":
                if not _require_client(self._send_json):
                    return
                rg_id = payload.get("resource_group_id")
                proj_id = payload.get("project_id")
                if not rg_id or not proj_id:
                    return self._send_json(400, {"error": "resource_group_id and project_id are required"})
                ordered_paths, descriptions, existing, collisions, invalid_names = _run_pipeline(
                    payload.get("rows") or [], rg_id, proj_id
                )
                if invalid_names:
                    return self._send_json(
                        400, {"error": "Invalid folder name(s); fix and retry.", "invalid_names": invalid_names}
                    )
                results = engine.execute_plan(client, rg_id, proj_id, ordered_paths, descriptions, existing)
                output_path = PROJECT_ROOT / f"folders_result_{engine.datetime.now(engine.timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
                engine.write_results_csv(output_path, results)
                print(f"Execute complete: results written to {output_path.name}")
                return self._send_json(200, {
                    "results": [_row_dict(*r) for r in results],
                    "collisions": {name: ["/".join(p) for p in paths] for name, paths in collisions.items()},
                    "output_file": output_path.name,
                })

            return self._send_json(404, {"error": "not found"})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})

    # -----------------------------------------------------------------
    def do_DELETE(self):
        global client, okta_client, active_env_name
        path = urlparse(self.path).path
        try:
            if path.startswith("/api/environments/"):
                name = path[len("/api/environments/"):]
                was_active = engine.delete_environment(name)
                if was_active:
                    client = None
                    okta_client = None
                    active_env_name = None
                return self._send_json(200, {"deleted": name})

            if (path.startswith("/api/resource_groups/") and "/projects/" in path
                    and "/folders/" in path):
                if not _require_client(self._send_json):
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
                items = client.list_folder_items(rg_id, proj_id, folder_id)
                if items:
                    return self._send_json(409, {
                        "error": f"Folder is not empty ({len(items)} item(s) inside) -- "
                                 "remove or move its contents first, then delete it."
                    })
                client.delete_folder(rg_id, proj_id, folder_id)
                return self._send_json(200, {"deleted": folder_id})

            return self._send_json(404, {"error": "not found"})
        except KeyError as exc:
            return self._send_json(404, {"error": str(exc)})
        except (engine.OpaApiError, engine.OktaApiError) as exc:
            return self._send_json(502, {"error": str(exc)})
        except Exception as exc:
            return self._send_json(500, {"error": str(exc)})


def _try_activate_saved_environment():
    """On startup, if the encrypted store already has an active environment
    (e.g. from a previous run), try to reconnect automatically. Failure here
    is NOT fatal -- the server still starts, and the dashboard UI will show
    the setup screen since `client` stays None."""
    data = engine.load_environments()
    name = data.get("active")
    if not name or name not in data.get("environments", {}):
        return
    try:
        activate_environment(name)
    except Exception as exc:
        print(f"Could not auto-activate saved environment '{name}': {exc}")
        print("The dashboard will start anyway -- fix or re-select an environment from the gear menu.")


def main():
    parser = argparse.ArgumentParser(description="Local server for the OPA Secrets Wizard dashboard.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    _try_activate_saved_environment()

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
    if client is None:
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
