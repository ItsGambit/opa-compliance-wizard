"""HTTP authorization matrix for every route in server/serve.py (TEST-01,
TEST-03 and the route half of TEST-08, external review 2026-10-05).

The review mutation-tested the suite: deleting any admin check in serve.py
(M06-M11), hardcoding is_admin=True into the delete/share routes
(M22/M23), or showing every owner's environments to a non-admin (M24)
all left it green. This file drives every route through a real HTTP
server as each kind of caller:

- hosted mode with no proxy secret, or with the secret but no verified
  identity -> 401 on every route except the two documented public ones;
- a non-admin vs an admin on every admin-only route -> 403 vs through;
- the local-mode operator (`__local__`) on every admin-only route ->
  through (UI-06 relies on this), and the same predicate surfaced as
  /api/whoami's can_admin;
- owner B vs owner A on every route keyed by an environment name -> B
  never reaches A's private environment;
- owner B (no session) vs owner A (live session) on every route that
  acts through the caller's active session -> B never uses A's client.

The route list is NOT hand-copied: ROUTES below must equal the set of
route conditions parsed out of serve.py's do_GET/do_POST/do_DELETE with
`ast`, and every sample path must reach exactly its own route under
serve.py's first-match order. A new route without a matrix entry, or a
changed route condition, fails test_matrix_covers_every_route.
"""
import ast
import datetime
import json
import socket
import threading
import time
from collections import namedtuple
from pathlib import Path

import pytest
import requests

import audit_store
import create_secret_folders as engine

SERVE_PY = Path(__file__).resolve().parent.parent / "server" / "serve.py"
SECRET = "test-proxy-secret"
OWNER_A = "00uOWNERA"
OWNER_B = "00uOWNERB"
ADMIN = "00uADMIN"
RG = "aaaaaaaa-0000-4000-8000-000000000001"
PROJ = "aaaaaaaa-0000-4000-8000-000000000002"
FOLDER = "aaaaaaaa-0000-4000-8000-000000000003"
OPA_USER = "aaaaaaaa-0000-4000-8000-000000000004"
ORPHAN = "aaaaaaaa-0000-4000-8000-0000000000ff"

# kind:
#   public   reachable without the proxy secret even in hosted mode
#   open     any authenticated caller; nothing owner-scoped
#   admin    admin-only (local-mode operator exempt)
#   env      keyed by an environment display name; visibility-scoped
#   session  acts through the caller's own active session client
# a_status: what owner A (env/session kinds) or an admin (admin kind) gets.
# caps (5.42.0): the shared-environment capabilities the route checks
#   (create_secret_folders.SHARED_CAPABILITIES). REQUIRED for every env and
#   session route -- None (not declared) fails test_every_environment_route_
#   declares_its_capability; () only for the owner/admin-only routes listed
#   in NO_CAPABILITY_ROUTES. Pinned to the code by an AST check and driven
#   behaviourally for a shared non-owner.
# stepup (5.42.0): the pending-action type of an Environments change that
#   needs step-up MFA in hosted mode; must match the route's
#   _environment_change(...) call exactly (and every such call needs one).
Route = namedtuple("Route", "method sample kind body a_status caps stepup", defaults=(None, None))

ROUTES = {
    ("GET", "path == '/api/version'"): Route("GET", "/api/version", "public", None, 200),
    ("GET", "path == '/healthz'"): Route("GET", "/healthz", "public", None, 200),
    ("GET", "path == '/api/whoami'"): Route("GET", "/api/whoami", "open", None, 200),
    ("GET", "path == '/api/environments'"): Route("GET", "/api/environments", "open", None, 200),
    ("GET", "path == '/api/banner'"): Route("GET", "/api/banner", "open", None, 200),
    ("GET", "path.startswith('/api/environments/') and path.endswith('/sync/status')"):
        Route("GET", "/api/environments/dev/sync/status", "env", None, 200, caps=('view_archive',)),
    ("GET", "path.startswith('/api/environments/') and path.endswith('/integrity')"):
        Route("GET", "/api/environments/dev/integrity", "env", None, 200, caps=('view_archive',)),
    ("GET", "path == '/api/archives/orphaned'"): Route("GET", "/api/archives/orphaned", "admin", None, 200),
    ("GET", "path == '/api/reports'"): Route("GET", "/api/reports?environment=dev", "env", None, 200, caps=('view_archive',)),
    ("GET", "path.startswith('/api/reports/')"):
        Route("GET", "/api/reports/session_activity?environment=dev", "env", None, 200, caps=('view_archive',)),
    ("GET", "path.startswith('/api/resources/') and path.endswith('/history')"):
        Route("GET", f"/api/resources/{FOLDER}/history?environment=dev", "env", None, 200, caps=('view_archive',)),
    ("GET", "path.startswith('/api/active_directory_connections/') and path.endswith('/discovery_config')"):
        Route("GET", f"/api/active_directory_connections/{RG}/discovery_config", "session", None, 502, caps=('live_read',)),
    ("GET", "path == '/api/resource_groups'"): Route("GET", "/api/resource_groups", "session", None, 502, caps=('live_read',)),
    ("GET", "path.startswith('/api/resource_groups/') and path.endswith('/projects')"):
        Route("GET", f"/api/resource_groups/{RG}/projects", "session", None, 502, caps=('live_read',)),
    ("GET", "path == '/api/groups'"): Route("GET", "/api/groups", "session", None, 502, caps=('live_read',)),
    ("GET", "path.startswith('/api/resource_groups/') and path.endswith('/folders') and ('/projects/' in path)"):
        Route("GET", f"/api/resource_groups/{RG}/projects/{PROJ}/folders", "session", None, 502, caps=('live_read',)),
    ("GET", "path.startswith('/api/resource_groups/') and path.endswith('/secrets_access_report') and ('/projects/' in path)"):
        Route("GET", f"/api/resource_groups/{RG}/projects/{PROJ}/secrets_access_report", "session", None, 502, caps=('live_read', 'view_archive')),
    # A has a session but no completed sync -> the route's own not_synced 409.
    ("GET", "path == '/api/service_accounts_report'"): Route("GET", "/api/service_accounts_report", "session", None, 409, caps=('live_read', 'view_archive')),
    ("GET", "path.startswith('/api/resource_groups/') and path.endswith('/security_policies')"):
        Route("GET", f"/api/resource_groups/{RG}/security_policies", "session", None, 502, caps=('live_read',)),
    ("GET", "path == '/api/workload_roles'"): Route("GET", "/api/workload_roles", "session", None, 502, caps=('live_read',)),
    ("GET", "path == '/api/service_account'"): Route("GET", "/api/service_account", "session", None, 502, caps=('live_read',)),
    ("GET", "path == '/api/access/bootstrap/status'"): Route("GET", "/api/access/bootstrap/status", "session", None, 200, caps=('live_read',)),
    ("GET", "path == '/api/access/bootstrap/result'"): Route("GET", "/api/access/bootstrap/result", "session", None, 200, caps=('live_read',)),
    ("GET", "path == '/api/csv_files'"): Route("GET", "/api/csv_files", "open", None, 200),
    ("GET", "path == '/api/csv'"): Route("GET", "/api/csv?file=folders_template.csv", "open", None, 200),
    ("GET", "path == '/api/audit_log'"): Route("GET", "/api/audit_log", "admin", None, 200),
    ("GET", "path == '/api/access_control'"): Route("GET", "/api/access_control", "admin", None, 200),
    ("GET", "path == '/api/shared_permissions'"): Route("GET", "/api/shared_permissions", "admin", None, 200),
    ("POST", "path == '/api/banner'"):
        Route("POST", "/api/banner", "admin", {"enabled": True, "message": "Maintenance tonight", "variant": "info"}, 200),
    ("POST", "path == '/api/access_control/prepare'"):
        Route("POST", "/api/access_control/prepare", "admin",
              {"admin_group_id": "00gADMINS", "user_group_id": "00gUSERS", "restrict_login": False}, 200),
    # Past the admin gate an admin with no step-up action id gets the route's own 409.
    ("POST", "path == '/api/access_control/save'"): Route("POST", "/api/access_control/save", "admin", {}, 409),
    ("POST", "path == '/api/audit_log/backfill_mfa'"): Route("POST", "/api/audit_log/backfill_mfa", "admin", {}, 200),
    # Only used in hosted mode (behind nginx's step-up location); local mode answers 404.
    ("POST", "path == '/api/environment_changes/save'"): Route("POST", "/api/environment_changes/save", "open", {}, 404),
    ("POST", "path == '/api/shared_permissions'"):
        Route("POST", "/api/shared_permissions", "admin", {"changes": {"sync_now": "allow"}}, 200,
              stepup="shared_permissions.update"),
    ("POST", "path == '/api/environments'"):
        Route("POST", "/api/environments", "open",
              {"name": "mine", "base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, 200, stepup='environment.upsert'),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/activate')"):
        Route("POST", "/api/environments/dev/activate", "env", {}, 200, caps=()),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/share')"):
        Route("POST", "/api/environments/dev/share", "env", {"shared": False}, 200, caps=(), stepup='environment.share'),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/sync/reset_watermark')"):
        Route("POST", "/api/environments/dev/sync/reset_watermark", "env", {}, 200, caps=('reset_watermark',), stepup='sync.reset_watermark'),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/sync_schedule')"):
        Route("POST", "/api/environments/dev/sync_schedule", "env", {"enabled": False}, 200, caps=('sync_settings',), stepup='sync_schedule.update'),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/sync/start')"):
        Route("POST", "/api/environments/dev/sync/start", "env", {}, 200, caps=('sync_now',)),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/sync/import_csv')"):
        Route("POST", "/api/environments/dev/sync/import_csv", "env", {"csv_path": "syslog_export.csv"}, 200, caps=('import_csv',), stepup='sync.import_csv'),
    ("POST", "path == '/api/access/bootstrap/start'"): Route("POST", "/api/access/bootstrap/start", "session", {}, 200, caps=('live_read',)),
    ("POST", "path == '/api/resource_groups'"):
        Route("POST", "/api/resource_groups", "session", {"name": "rg", "group_ids": ["g1"]}, 502, caps=('tenant_write',)),
    ("POST", "path.startswith('/api/resource_groups/') and path.endswith('/projects')"):
        Route("POST", f"/api/resource_groups/{RG}/projects", "session", {"name": "p"}, 502, caps=('tenant_write',)),
    ("POST", "path.startswith('/api/resource_groups/') and path.endswith('/policy') and ('/projects/' in path) and ('/folders/' in path)"):
        Route("POST", f"/api/resource_groups/{RG}/projects/{PROJ}/folders/{FOLDER}/policy", "session",
              {"mode": "existing", "policy_id": FOLDER}, 502, caps=('tenant_write',)),
    ("POST", "path == '/api/groups'"): Route("POST", "/api/groups", "session", {"name": "g"}, 502, caps=('tenant_write',)),
    ("POST", "path == '/api/service_account/groups'"):
        Route("POST", "/api/service_account/groups", "session", {"group_id": "g1"}, 502, caps=('tenant_write',)),
    ("POST", "path == '/api/csv'"):
        Route("POST", "/api/csv", "open", {"file": "folders_template.csv", "rows": [{"path": "A", "description": ""}]}, 200),
    ("POST", "path == '/api/preview'"):
        Route("POST", "/api/preview", "session", {"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A"}]}, 502, caps=('live_read',)),
    ("POST", "path == '/api/execute'"):
        Route("POST", "/api/execute", "session", {"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A"}]}, 502, caps=('tenant_write',)),
    ("POST", "path.startswith('/api/access/users/') and path.endswith('/resource_access')"):
        Route("POST", f"/api/access/users/{OPA_USER}/resource_access", "session",
              {"resources": [{"resource_kind": "secret", "resource_id": FOLDER}]}, 502, caps=('live_read',)),
    # Past the admin gate: no archive rows for that id -> the route's own 404.
    ("DELETE", "path.startswith('/api/archives/')"): Route("DELETE", f"/api/archives/{ORPHAN}", "admin", None, 404, stepup='archive.purge'),
    ("DELETE", "path.startswith('/api/environments/')"): Route("DELETE", "/api/environments/dev", "env", None, 200, caps=(), stepup='environment.delete'),
    ("DELETE", "path.startswith('/api/resource_groups/') and '/projects/' in path and ('/folders/' in path)"):
        Route("DELETE", f"/api/resource_groups/{RG}/projects/{PROJ}/folders/{FOLDER}", "session", None, 502, caps=('tenant_write',)),
    ("DELETE", "path.startswith('/api/groups/') and '/members/' in path"):
        Route("DELETE", "/api/groups/g1/members/someone", "session", None, 502, caps=('tenant_write',)),
}

# Admin-only variants of non-admin routes (same route, an admin-only flag).
ADMIN_VARIANTS = [
    ("GET", "/api/environments/dev/integrity?deep=1", None, 200),
    ("DELETE", "/api/environments/dev?purge_archive=1", None, 200),
]


def _route_conditions():
    """[(method, condition_source, condition_ast)] in serve.py's own order,
    for every top-level route `if` inside do_GET/do_POST/do_DELETE's try."""
    tree = ast.parse(SERVE_PY.read_text(encoding="utf-8"))
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Handler")
    # A new HTTP method handler (do_PUT, do_PATCH, ...) would carry routes
    # this scan doesn't read -- it must be added here deliberately.
    methods = {n.name for n in handler.body if isinstance(n, ast.FunctionDef) and n.name.startswith("do_")}
    assert methods == {"do_GET", "do_POST", "do_DELETE", "do_HEAD"}, methods
    # Routes may only live in the three dispatchers: no route-shaped
    # condition in any other Handler method (a helper that dispatches would
    # escape the matrix) -- do_HEAD included.
    for fn in handler.body:
        if isinstance(fn, ast.FunctionDef) and fn.name not in ("do_GET", "do_POST", "do_DELETE"):
            stray = [ast.unparse(n.test) for n in ast.walk(fn) if isinstance(n, ast.If) and _mentions_route(n.test)]
            assert not stray, f"route-shaped condition outside the dispatchers in {fn.name}: {stray}"
    found = []
    for fn in handler.body:
        if not (isinstance(fn, ast.FunctionDef) and fn.name in ("do_GET", "do_POST", "do_DELETE")):
            continue
        method = fn.name[3:]
        top_level = []
        for node in fn.body:
            if isinstance(node, ast.Try):
                for stmt in node.body:
                    if isinstance(stmt, ast.If) and _mentions_route(stmt.test):
                        top_level.append(stmt)
        # Every route-shaped condition anywhere in the method must be a
        # top-level one -- a route hidden inside another branch (or before
        # the try) would otherwise escape the matrix.
        everywhere = [n for n in ast.walk(fn) if isinstance(n, ast.If) and _mentions_route(n.test)]
        assert {id(n) for n in everywhere} == {id(n) for n in top_level}, f"{fn.name} has a nested route condition"
        found.extend((method, ast.unparse(s.test), s.test) for s in top_level)
    return found


def _mentions_route(test):
    """Any condition comparing against a "/..." literal is route-shaped,
    whatever it compares (`path`, `parsed.path`, another name)."""
    literals = [n.value for n in ast.walk(test) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return any(v.startswith("/") for v in literals)


def test_matrix_covers_every_route():
    discovered = [(m, src) for m, src, _ in _route_conditions()]
    assert len(discovered) == len(set(discovered)), "duplicate route condition in serve.py"
    assert set(discovered) == set(ROUTES), (
        "serve.py routes and this matrix disagree -- add an entry for every new route.\n"
        f"missing from matrix: {sorted(set(discovered) - set(ROUTES))}\n"
        f"stale in matrix: {sorted(set(ROUTES) - set(discovered))}"
    )


def test_every_sample_path_reaches_its_own_route():
    """First-match evaluation of serve.py's real conditions: each sample
    must land on exactly the route it is listed under (otherwise the matrix
    would be testing some other route's guard)."""
    conditions = _route_conditions()
    for key, route in ROUTES.items():
        path = route.sample.split("?", 1)[0]
        hit = next(
            (m, src) for m, src, test in conditions
            if m == route.method and eval(compile(ast.Expression(test), "<route>", "eval"), {"path": path})
        )
        assert hit == key, f"{route.sample} reaches {hit}, not {key}"
    for method, sample, _body, _status in ADMIN_VARIANTS:
        assert any(r.method == method and r.sample.split("?")[0] == sample.split("?")[0] for r in ROUTES.values())


# ---------------------------------------------------------------------------
# Live server
# ---------------------------------------------------------------------------
class _UpstreamProbe:
    """Stands in for OpaClient/OktaClient. Constructing one never touches
    the network; calling anything on it raises the upstream error type, so
    a 502 proves the request got past every guard and reached the session's
    OWN client. Okta's get_system_log returns an empty, complete page so a
    sync thread (if one ever ran) finishes harmlessly."""

    def __init__(self, *args, **kwargs):
        self.args = args

    def get_system_log(self, *args, **kwargs):
        return [], True

    def __getattr__(self, name):
        def _call(*args, **kwargs):
            raise engine.OpaApiError(599, f"probe://{name}", "upstream reached")
        return _call


@pytest.fixture
def matrix_server(tmp_audit_store, tmp_environments_file, fake_keyring, tmp_audit_log, tmp_path, monkeypatch):
    import server.serve as serve

    audit_store.run_migrations()
    access_control_path = tmp_path / "access_control.json"
    monkeypatch.setattr(engine, "_access_control_file_path", lambda: str(access_control_path))
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "folders_template.csv").write_text("path,description\nA,\n", encoding="utf-8")
    (project_root / "syslog_export.csv").write_text("event_type,timestamp\n", encoding="utf-8")
    monkeypatch.setattr(serve, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", SECRET)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "local")
    monkeypatch.setattr(serve, "INTERNAL_API_SHARED_SECRET", None)
    monkeypatch.setattr(engine, "OpaClient", _UpstreamProbe)
    monkeypatch.setattr(engine, "OktaClient", _UpstreamProbe)
    # Background job bodies never run here (a thread outliving the test
    # could otherwise write to whatever database the restored path points
    # at); the routes' own start/guard logic still runs in full.
    started = []
    REAL_JOB_BODIES.update(sync=serve._run_sync_job, access=serve._run_access_job)
    monkeypatch.setattr(serve, "_run_sync_job", lambda *a, **k: started.append(("sync", a)))
    monkeypatch.setattr(serve, "_run_access_job", lambda *a, **k: started.append(("access", a)))
    with serve._sessions_lock:
        serve._seen_owners.clear()
        serve._recorded_identities.clear()  # 5.43.0: each test starts with a fresh DB

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server_instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    threading.Thread(target=server_instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(base_url + "/api/version", timeout=0.5)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    yield base_url, serve
    server_instance.shutdown()
    server_instance.server_close()
    with serve._sessions_lock:
        serve._seen_owners.clear()
        serve._recorded_identities.clear()  # 5.43.0: each test starts with a fresh DB


REAL_JOB_BODIES = {}  # the unpatched job functions, for tests that run one synchronously


def _who(sub, admin=False):
    return {"X-Nginx-Proxy-Secret": SECRET, "X-Auth-Sub": sub, "X-Auth-Is-Admin": "true" if admin else "false"}


def _call(base_url, method, sample, body=None, headers=None):
    kwargs = {"headers": headers or {}, "timeout": 10}
    if method == "POST":
        kwargs["json"] = body if body is not None else {}
    return requests.request(method, base_url + sample, **kwargs)


def _seed_owner_a_with_session(serve):
    """Owner A: a private "dev" environment plus a live session on it
    (with an access-model job result, so the session routes that read it
    get past their own 'not loaded yet' 409)."""
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
                "okta_url": "https://a.example.com", "okta_api_token": "tok"}, owner=OWNER_A,
    )
    with serve._sessions_lock:
        serve._sessions[OWNER_A] = {"client": _UpstreamProbe(), "okta_client": _UpstreamProbe(),
                                    "env_name": "dev", "env_id": env_id}
        serve._seen_owners.update({OWNER_A, OWNER_B, ADMIN})
    with serve._access_jobs_lock:
        serve._access_jobs[env_id] = {
            "status": "done", "steps": [{"key": "a-only", "status": "done", "detail": None}], "error": None,
            "result": {"users": [{"id": OPA_USER, "details": {"email": "a@example.com"}}], "owner": "A"},
        }
    return env_id


# ---------------------------------------------------------------------------
# Unauthenticated / identity-less in hosted mode
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("headers", [
    {},                                                    # straight to the loopback port
    {"X-Nginx-Proxy-Secret": "wrong", "X-Auth-Sub": ADMIN, "X-Auth-Is-Admin": "true"},  # spoofed identity
    {"X-Nginx-Proxy-Secret": SECRET},                      # transited nginx, no identity
], ids=["no-secret", "wrong-secret", "no-identity"])
def test_hosted_mode_refuses_every_non_public_route_without_a_verified_identity(matrix_server, monkeypatch, headers):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    for route in ROUTES.values():
        resp = _call(base_url, route.method, route.sample, route.body, headers)
        if route.kind == "public":
            assert resp.status_code == 200, route.sample
        else:
            assert resp.status_code == 401, (route.method, route.sample, resp.status_code)
    # The static frontend is behind the same guard, for GET and HEAD alike.
    assert requests.get(base_url + "/index.html", headers=headers, timeout=10).status_code == 401
    head = requests.head(base_url + "/index.html", headers=headers, timeout=10)
    assert head.status_code == 401 and head.content == b""
    assert requests.head(base_url + "/healthz", headers=headers, timeout=10).status_code != 401


# ---------------------------------------------------------------------------
# Admin-only routes
# ---------------------------------------------------------------------------
ADMIN_ROUTES = [r for r in ROUTES.values() if r.kind == "admin"]


@pytest.mark.parametrize("hosted", [False, True], ids=["local-mode", "hosted-mode"])
@pytest.mark.parametrize("route", ADMIN_ROUTES, ids=[f"{r.method} {r.sample}" for r in ADMIN_ROUTES])
def test_admin_routes_refuse_non_admins_and_admit_admins(matrix_server, monkeypatch, route, hosted):
    base_url, serve = matrix_server
    if hosted:
        monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    refused = _call(base_url, route.method, route.sample, route.body, _who(OWNER_B))
    assert refused.status_code == 403, refused.text
    allowed = _call(base_url, route.method, route.sample, route.body, _who(ADMIN, admin=True))
    if hosted and route.stepup:
        # 5.42.0: past the admin check, a hosted admin is sent to step-up MFA.
        # A request the route itself refuses (this sample's archive id has no
        # rows -> 404) is refused before any MFA, exactly as in local mode.
        if route.a_status >= 400:
            assert allowed.status_code == route.a_status, allowed.text
        else:
            assert allowed.status_code == 202 and allowed.json()["step_up_required"] is True, allowed.text
        return
    assert allowed.status_code == route.a_status, allowed.text


@pytest.mark.parametrize("route", ADMIN_ROUTES, ids=[f"{r.method} {r.sample}" for r in ADMIN_ROUTES])
def test_admin_routes_admit_the_local_mode_operator(matrix_server, route):
    """No identity headers at all in local mode = the local operator (no
    login gate exists). The server exempts it; UI-06 makes the UI agree."""
    base_url, _serve = matrix_server
    resp = _call(base_url, route.method, route.sample, route.body, {})
    assert resp.status_code == route.a_status, resp.text


@pytest.mark.parametrize("method, sample, body, status", ADMIN_VARIANTS)
def test_admin_only_flags_on_owner_routes(matrix_server, method, sample, body, status):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    # The owner themself is refused the admin-only flag...
    assert _call(base_url, method, sample, body, _who(OWNER_A)).status_code == 403
    # ...an admin acting on that environment (by id) is not.
    admin_sample = sample + (f"&id={env_id}" if method == "DELETE" else "")
    if method == "GET":
        engine.set_environment_shared("dev", OWNER_A, True)  # an admin reads by name, so make it visible
    assert _call(base_url, method, admin_sample, body, _who(ADMIN, admin=True)).status_code == status


def test_whoami_can_admin_matches_the_server_side_predicate(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    local = requests.get(base_url + "/api/whoami", timeout=10).json()
    assert local["is_local"] is True and local["is_admin"] is False and local["can_admin"] is True
    user = requests.get(base_url + "/api/whoami", headers=_who(OWNER_B), timeout=10).json()
    assert user["can_admin"] is False
    admin = requests.get(base_url + "/api/whoami", headers=_who(ADMIN, admin=True), timeout=10).json()
    assert admin["is_admin"] is True and admin["can_admin"] is True


# ---------------------------------------------------------------------------
# Environment-name routes: owner B never reaches owner A's private env
# ---------------------------------------------------------------------------
ENV_ROUTES = [r for r in ROUTES.values() if r.kind == "env"]


@pytest.mark.parametrize("route", ENV_ROUTES, ids=[f"{r.method} {r.sample}" for r in ENV_ROUTES])
def test_env_routes_are_scoped_to_what_the_caller_can_see(matrix_server, route):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    # B (non-admin, no "dev" of their own) -- with A's real id in the
    # payload/query too, which only an admin override may use (M22/M23).
    body = dict(route.body or {}, id=env_id) if route.sample.endswith("/share") else route.body
    sample = route.sample + (f"?id={env_id}" if route.method == "DELETE" else "")
    other = _call(base_url, route.method, sample, body, _who(OWNER_B))
    assert other.status_code == 404, (route.sample, other.status_code, other.text)
    assert env_id in engine.list_all_environments()
    assert engine.list_all_environments()[env_id]["shared"] is False
    # A, the owner, is served.
    own = _call(base_url, route.method, route.sample, route.body, _who(OWNER_A))
    assert own.status_code == route.a_status, (route.sample, own.status_code, own.text)


def test_environment_list_shows_a_non_admin_only_own_and_shared(matrix_server):
    base_url, serve = matrix_server
    engine.upsert_environment("a-private", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k",
                                            "key_secret": "s"}, owner=OWNER_A)
    engine.upsert_environment("a-shared", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k",
                                           "key_secret": "s"}, owner=OWNER_A)
    engine.set_environment_shared("a-shared", OWNER_A, True)
    engine.upsert_environment("b-own", {"base_domain": "b.example.com", "team_name": "t", "key_id": "k",
                                        "key_secret": "s"}, owner=OWNER_B)
    names = lambda resp: sorted(e["name"] for e in resp.json()["environments"])  # noqa: E731
    as_b = requests.get(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10)
    assert names(as_b) == ["a-shared", "b-own"]
    as_admin = requests.get(base_url + "/api/environments", headers=_who(ADMIN, admin=True), timeout=10)
    assert names(as_admin) == ["a-private", "a-shared", "b-own"]


def test_non_admin_save_with_another_owners_id_never_edits_it(matrix_server):
    """The admin-edit path (TEST-03 M18 at the HTTP layer): a non-admin
    passing someone else's environment_id creates/edits their OWN row."""
    base_url, serve = matrix_server
    _, env_id = engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k",
                                                  "key_secret": "s"}, owner=OWNER_A)
    resp = requests.post(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10, json={
        "id": env_id, "name": "dev", "base_domain": "evil.example.com", "team_name": "t", "key_id": "k2", "key_secret": "s2",
    })
    assert resp.status_code == 200
    assert engine.list_all_environments()[env_id]["base_domain"] == "a.example.com"
    assert fake_secret(env_id) == "s"


def fake_secret(env_id):
    return engine.keyring_get(env_id, "key_secret")


# ---------------------------------------------------------------------------
# Session routes: owner B never uses owner A's live client
# ---------------------------------------------------------------------------
SESSION_ROUTES = [r for r in ROUTES.values() if r.kind == "session"]


@pytest.mark.parametrize("route", SESSION_ROUTES, ids=[f"{r.method} {r.sample}" for r in SESSION_ROUTES])
def test_session_routes_only_ever_use_the_callers_own_session(matrix_server, route):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    other = _call(base_url, route.method, route.sample, route.body, _who(OWNER_B))
    if route.sample == "/api/access/bootstrap/status":
        assert other.status_code == 200 and other.json() == {"status": "idle", "steps": [], "error": None}
    else:
        assert other.status_code == 409, (route.sample, other.status_code, other.text)
        assert "upstream reached" not in other.text and "a-only" not in other.text
    own = _call(base_url, route.method, route.sample, route.body, _who(OWNER_A))
    assert own.status_code == route.a_status, (route.sample, own.status_code, own.text)
    if route.a_status == 502:
        assert "upstream reached" in own.text  # it really was A's session client


def test_open_routes_serve_any_authenticated_caller(matrix_server):
    base_url, _serve = matrix_server
    for route in ROUTES.values():
        if route.kind == "open":
            resp = _call(base_url, route.method, route.sample, route.body, _who(OWNER_B))
            assert resp.status_code == route.a_status, (route.sample, resp.status_code, resp.text)


# ---------------------------------------------------------------------------
# ENG1-06: an edit drops other owners' stale sessions; admin edit of
# someone else's environment no longer 500s or activates it for the admin
# ---------------------------------------------------------------------------
def test_admin_edit_of_another_owners_environment_saves_without_activating(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    stale = object()
    engine.set_active_environment(OWNER_B, "dev")  # B activated A's shared "dev"
    with serve._sessions_lock:
        serve._sessions[OWNER_B] = {"client": stale, "okta_client": None, "env_name": "dev", "env_id": env_id}
        # The admin had it active too: their own client is just as stale.
        serve._sessions[ADMIN] = {"client": stale, "okta_client": None, "env_name": "dev", "env_id": env_id}
    resp = requests.post(base_url + "/api/environments", headers=_who(ADMIN, admin=True), timeout=10, json={
        "id": env_id, "name": "dev", "base_domain": "fixed.example.com", "team_name": "t", "key_id": "k", "key_secret": "",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["activated"] is False and resp.json()["saved"] is True
    meta = engine.list_all_environments()[env_id]
    assert meta["owner"] == OWNER_A and meta["base_domain"] == "fixed.example.com"
    with serve._sessions_lock:
        assert ADMIN not in serve._sessions                 # stale admin session dropped, never re-activated by name
        assert OWNER_B not in serve._sessions              # B's stale client is gone...
        assert OWNER_B not in serve._seen_owners           # ...and B re-activates on the next request
        assert OWNER_A not in serve._sessions
    # B's next request reconnects with the NEW stored credentials.
    requests.get(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10)
    with serve._sessions_lock:
        session_b = serve._sessions.get(OWNER_B)
    assert session_b is not None and session_b["client"] is not stale and session_b["env_id"] == env_id
    assert session_b["client"].args[0] == "fixed.example.com"
    entry = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()][-1]
    assert entry["action"] == "environment.upsert"
    assert entry["details"]["edited_other_owner"] is True and entry["details"]["environment_id"] == env_id


def test_owner_edit_of_a_shared_environment_drops_sharers_stale_sessions(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    with serve._sessions_lock:
        serve._sessions[OWNER_B] = {"client": object(), "okta_client": None, "env_name": "dev", "env_id": env_id}
    resp = requests.post(base_url + "/api/environments", headers=_who(OWNER_A), timeout=10, json={
        "name": "dev", "base_domain": "rotated.example.com", "team_name": "t", "key_id": "k", "key_secret": "new",
    })
    assert resp.status_code == 200 and resp.json()["activated"] is True
    with serve._sessions_lock:
        assert OWNER_B not in serve._sessions
        assert serve._sessions[OWNER_A]["client"].args[0] == "rotated.example.com"


def test_creating_an_environment_leaves_other_sessions_alone(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    resp = requests.post(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10, json={
        "name": "dev", "base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
    })
    assert resp.status_code == 200
    with serve._sessions_lock:
        assert serve._sessions[OWNER_A]["env_id"] == env_id


# ---------------------------------------------------------------------------
# TEST-08: Origin, body limits, body shape, CSV confinement
# ---------------------------------------------------------------------------
def _raw_post(base_url, path, headers, body=b""):
    """Sends exactly the bytes/headers given (requests would fix up a bad
    Content-Length itself)."""
    host, port = base_url.replace("http://", "").split(":")
    with socket.create_connection((host, int(port)), timeout=10) as conn:
        conn.settimeout(3)  # a handler stuck reading the body never answers -> socket.timeout fails the test
        head = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        conn.sendall(head.encode() + b"\r\n" + body)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return int(data.split(b" ", 2)[1])


def test_disallowed_origin_is_refused_on_every_mutating_route(matrix_server):
    base_url, _serve = matrix_server
    evil = {**_who(ADMIN, admin=True), "Origin": "https://evil.example.com"}
    for route in ROUTES.values():
        if route.method in ("POST", "DELETE"):
            resp = _call(base_url, route.method, route.sample, route.body, evil)
            assert resp.status_code == 403 and "Origin" in resp.json()["error"], route.sample
    # This app's own origins are accepted.
    port = base_url.rsplit(":", 1)[1]
    ok = {**_who(ADMIN, admin=True), "Origin": f"http://127.0.0.1:{port}"}
    assert _call(base_url, "POST", "/api/banner", {"enabled": False}, ok).status_code == 200


# "-1" is the case that matters: BufferedReader.read(-1) means "read until
# EOF", which hangs the handler thread on a keep-alive connection (any value
# below -1 raises ValueError on its own and would mask a removed check).
@pytest.mark.parametrize("content_length, expected", [("-1", 400), ("-5", 400), ("abc", 400), (str(6 * 1024 * 1024), 413)])
def test_malformed_or_oversize_content_length_is_refused(matrix_server, content_length, expected):
    base_url, _serve = matrix_server
    headers = {**_who(ADMIN, admin=True), "Content-Type": "application/json", "Content-Length": content_length}
    assert _raw_post(base_url, "/api/banner", headers) == expected


@pytest.mark.parametrize("raw", [b"[1, 2]", b'"text"', b"{not json"])
def test_a_non_object_or_invalid_json_body_is_a_400(matrix_server, raw):
    base_url, _serve = matrix_server
    headers = {**_who(ADMIN, admin=True), "Content-Type": "application/json", "Content-Length": str(len(raw))}
    assert _raw_post(base_url, "/api/banner", headers, raw) == 400


@pytest.mark.parametrize("name", ["../x.csv", "../../etc/passwd", "/etc/hosts.csv", "sub/dir.csv", "..\\x.csv", "notcsv.txt", ""])
def test_csv_read_and_import_refuse_anything_but_a_bare_csv_name(matrix_server, name):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    resp = requests.get(base_url + "/api/csv", params={"file": name}, headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 400, resp.text
    resp = requests.post(base_url + "/api/environments/dev/sync/import_csv", headers=_who(OWNER_A), timeout=10,
                         json={"csv_path": name})
    assert resp.status_code == 400, resp.text


def test_csv_save_refuses_to_clobber_exports_and_result_files(matrix_server):
    """SRV-06: any authenticated user could create or overwrite any bare
    *.csv in the project root -- an Okta System Log export waiting to be
    imported, or a folders_result_* execution record."""
    base_url, serve = matrix_server
    root = serve.PROJECT_ROOT
    (root / "folders_result_20260101_000000.csv").write_text("path,folder_id,status,error_message\n", encoding="utf-8")
    rows = [{"path": "A/B", "description": "d"}]
    for name, status in [
        ("syslog_export.csv", 409),                      # not a folder template
        ("folders_result_20260101_000000.csv", 409),     # an execution record
        ("FOLDERS_RESULT_new.csv", 409),
        ("../escape.csv", 400),
        ("bad;name.csv", 400),
        (".hidden.csv", 400),
        ("new template (1).csv", 200),
        ("folders_template.csv", 200),                   # an existing template may be overwritten
    ]:
        resp = requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10, json={"file": name, "rows": rows})
        assert resp.status_code == status, (name, resp.status_code, resp.text)
    assert (root / "syslog_export.csv").read_text(encoding="utf-8") == "event_type,timestamp\n"
    assert (root / "new template (1).csv").read_text(encoding="utf-8").splitlines() == ["path,description", "A/B,d"]
    assert not (root.parent / "escape.csv").exists()
    resp = requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10, json={"file": "x.csv", "rows": "nope"})
    assert resp.status_code == 400


def test_csv_save_caps_the_number_of_new_files(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "MAX_PROJECT_CSV_FILES", 2)  # two fixture files already exist
    resp = requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10, json={"file": "third.csv", "rows": []})
    assert resp.status_code == 409
    # Overwriting an existing template is still allowed at the cap.
    resp = requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10, json={"file": "folders_template.csv", "rows": []})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# ENG2-16: ids interpolated into OPA URLs / Okta filters
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("sample", [
    "/api/resource_groups/..%2F..%2Fusers/projects",
    "/api/resource_groups/a%3Fall%3Dtrue/projects",
    f"/api/resource_groups/{RG}/projects/x%22%20or%20%22/folders",
    f"/api/resource_groups/{RG}/security_policies?x=1".replace(RG, "rg.with.dots"),
    "/api/active_directory_connections/a%2Fb/discovery_config",
])
def test_ids_that_could_reshape_an_upstream_url_are_a_400(matrix_server, sample):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    resp = requests.get(base_url + sample, headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 400, (sample, resp.status_code, resp.text)
    assert "upstream reached" not in resp.text


def test_post_and_delete_ids_are_validated_too(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    bad = "x/../y"
    cases = [
        ("POST", "/api/preview", {"resource_group_id": bad, "project_id": PROJ, "rows": []}),
        ("POST", "/api/execute", {"resource_group_id": RG, "project_id": bad, "rows": []}),
        ("POST", f"/api/resource_groups/{RG}/projects/{PROJ}/folders/{FOLDER}/policy", {"mode": "existing", "policy_id": bad}),
        ("DELETE", f"/api/resource_groups/{RG}/projects/{PROJ}/folders/a%3Fb", None),
    ]
    for method, sample, body in cases:
        resp = _call(base_url, method, sample, body, _who(OWNER_A))
        assert resp.status_code == 400, (sample, resp.status_code, resp.text)


def test_opa_client_quotes_ids_into_a_single_path_segment(monkeypatch):
    seen = []

    class _Client(engine.OpaClient):
        def __init__(self):
            self.team_name = "team"
            self.base_url = "https://opa.example.com"

        def request(self, method, path, **kwargs):
            seen.append(path)
            return {}

        def _list(self, path):
            seen.append(path)
            return []

    client = _Client()
    client.list_projects("../users?x=1")
    client.get_security_policy("a/b")
    client.get_assignment("c#d")
    assert seen == [
        "/v1/teams/team/resource_groups/..%2Fusers%3Fx%3D1/projects",
        "/v1/teams/team/security_policy/a%2Fb",
        "/v1/teams/team/assignments/c%23d",
    ]


def test_okta_filter_builders_refuse_ids_that_would_break_out_of_the_string():
    with pytest.raises(ValueError):
        engine.find_last_access_for_user(None, 'x" or "1" eq "1', [{"resource_kind": "secret", "resource_id": "s"}])


# ---------------------------------------------------------------------------
# SRV-03: no internal exception text in responses
# ---------------------------------------------------------------------------
def test_unhandled_exceptions_return_a_generic_message_with_a_reference(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    secret_detail = "/srv/private/path/audit_store.db: database disk image is malformed"

    def boom(*args, **kwargs):
        raise RuntimeError(secret_detail)

    logged = []
    real_log = engine.log
    monkeypatch.setattr(engine, "log", lambda level, msg: (logged.append((level, msg)), real_log(level, msg)))
    monkeypatch.setattr(engine, "get_banner_config", boom)
    monkeypatch.setattr(engine, "set_banner_config", boom)
    monkeypatch.setattr(engine, "delete_environment", boom)
    for method, sample, body in [("GET", "/api/banner", None), ("POST", "/api/banner", {"enabled": False}),
                                 ("DELETE", "/api/environments/dev", None)]:
        resp = _call(base_url, method, sample, body, _who(ADMIN, admin=True))
        assert resp.status_code == 500
        payload = resp.json()
        assert secret_detail not in resp.text
        assert payload["correlation_id"] and payload["correlation_id"] in payload["error"]
        assert any(level == "ERROR" and secret_detail in msg for level, msg in logged)


def test_healthz_never_echoes_exception_text(matrix_server, monkeypatch):
    base_url, serve = matrix_server

    def broken_connection():
        raise RuntimeError("/srv/private/path: unable to open database file")

    with serve._sessions_lock:
        serve._seen_owners.add(serve.LOCAL_OWNER_KEY_HEADER)  # no lazy auto-activate against the broken DB
    monkeypatch.setattr(audit_store, "_get_connection", broken_connection)
    resp = requests.get(base_url + "/healthz", timeout=10)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded" and body["checks"]["archive_writable"] == "error"
    assert "/srv/private" not in resp.text


def test_reactivation_after_an_edit_restores_the_same_environment_by_id(matrix_server):
    """After an admin renames A's shared "dev" (which B had active) the
    restore reconnects B to that same environment id under its new name.
    (When the new name is shadowed by one of B's own, the restore is refused
    instead -- test_a_shadowed_saved_environment_is_not_restored.)"""
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    # B owns a "staging"; the rename below targets a name nothing of B's shadows.
    _, b_prod = engine.upsert_environment("staging", {"base_domain": "b.example.com", "team_name": "t", "key_id": "k",
                                                      "key_secret": "s"}, owner=OWNER_B)
    engine.set_active_environment(OWNER_B, "dev")
    with serve._sessions_lock:
        serve._sessions[OWNER_B] = {"client": object(), "okta_client": None, "env_name": "dev", "env_id": env_id}
    resp = requests.post(base_url + "/api/environments", headers=_who(ADMIN, admin=True), timeout=10, json={
        "id": env_id, "name": "prod", "base_domain": "a2.example.com", "team_name": "t", "key_id": "k", "key_secret": "",
    })
    assert resp.status_code == 200, resp.text
    requests.get(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10)
    with serve._sessions_lock:
        session_b = serve._sessions.get(OWNER_B)
    assert session_b is not None and session_b["env_id"] == env_id and session_b["env_id"] != b_prod
    assert engine.get_active_environment_id(OWNER_B) == env_id


def test_reactivation_never_restores_an_environment_no_longer_visible(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_active_environment(OWNER_B, "dev")
    engine.set_environment_shared("dev", OWNER_A, False)
    with serve._sessions_lock:
        serve._seen_owners.discard(OWNER_B)
    resp = requests.get(base_url + "/api/resource_groups", headers=_who(OWNER_B), timeout=10)
    assert resp.status_code == 409
    with serve._sessions_lock:
        assert OWNER_B not in serve._sessions
    assert env_id in engine.list_all_environments()


def test_csv_save_names_are_ascii_lowercase_csv_and_result_files_never_count(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    for name in ("UPPER.CSV", "mixed.Csv", "folders_re\u017fult_a.csv", "Pr\u00fcfung.csv"):
        resp = requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10, json={"file": name, "rows": []})
        assert resp.status_code == 400, (name, resp.status_code)
    root = serve.PROJECT_ROOT
    for i in range(3):
        (root / f"folders_result_2026010{i}_000000.csv").write_text("path,folder_id,status,error_message\n", encoding="utf-8")
    (root / "Export.CSV").write_text("path,description\n", encoding="utf-8")
    monkeypatch.setattr(serve, "MAX_PROJECT_CSV_FILES", 4)  # 2 fixtures + Export.CSV = 3; result files don't count
    assert requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10,
                         json={"file": "fourth.csv", "rows": []}).status_code == 200
    assert requests.post(base_url + "/api/csv", headers=_who(OWNER_B), timeout=10,
                         json={"file": "fifth.csv", "rows": []}).status_code == 409


def test_background_job_errors_do_not_echo_internal_exception_text(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)

    def boom(*args, **kwargs):
        raise RuntimeError("/srv/private/path: secret internals")

    monkeypatch.setattr(engine, "build_access_model", boom)
    run_access_job = REAL_JOB_BODIES["access"]
    with serve._access_jobs_lock:
        serve._access_jobs[env_id] = {"status": "running", "steps": [], "error": None, "result": None}
    run_access_job(env_id, None, None, correlation_id="cid123")
    status = requests.get(base_url + "/api/access/bootstrap/status", headers=_who(OWNER_A), timeout=10).json()
    assert status["status"] == "error"
    assert "/srv/private" not in status["error"] and "cid123" in status["error"]
    # An upstream error is the user's own, actionable information and is kept.
    monkeypatch.setattr(engine, "build_access_model",
                        lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(403, "probe://x", "missing role")))
    run_access_job(env_id, None, None, correlation_id="cid456")
    with serve._access_jobs_lock:
        assert "missing role" in serve._access_jobs[env_id]["error"]


def test_an_internal_keyerror_is_a_500_not_a_404(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)

    class _Client(_UpstreamProbe):
        def list_groups(self, *a, **k):
            return [{"id": "g1"}]  # no "name" -> KeyError inside the route

    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = _Client()
    resp = requests.delete(base_url + "/api/groups/g1/members/someone", headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 500 and "'name'" not in resp.text


def test_a_shadowed_saved_environment_is_not_restored(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_active_environment(OWNER_B, "dev")
    engine.upsert_environment("prod", {"base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"},
                              owner=OWNER_B)
    with serve._sessions_lock:
        serve._sessions[OWNER_B] = {"client": object(), "okta_client": None, "env_name": "dev", "env_id": env_id}
    requests.post(base_url + "/api/environments", headers=_who(ADMIN, admin=True), timeout=10, json={
        "id": env_id, "name": "prod", "base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "",
    })
    assert requests.get(base_url + "/api/resource_groups", headers=_who(OWNER_B), timeout=10).status_code == 409
    with serve._sessions_lock:
        assert OWNER_B not in serve._sessions


def test_concurrent_mfa_refresh_is_a_409_busy(matrix_server, monkeypatch):
    base_url, _serve = matrix_server

    def busy(*a, **k):
        raise engine.MfaBackfillBusy("An MFA log refresh is already running.")

    monkeypatch.setattr(engine, "backfill_mfa_log_events", busy)
    resp = requests.post(base_url + "/api/audit_log/backfill_mfa", headers=_who(ADMIN, admin=True), timeout=10, json={})
    assert resp.status_code == 409 and resp.json()["reason"] == "busy"


def test_job_errors_drop_decode_errors_that_quote_input(matrix_server):
    _base_url, serve = matrix_server
    try:
        b"\xff secret-fragment".decode("utf-8")
    except UnicodeDecodeError as exc:
        assert serve._job_error_message(exc).startswith("Internal error (reference ")
    try:
        json.loads('{"k": ')
    except json.JSONDecodeError as exc:
        assert serve._job_error_message(exc).startswith("Internal error (reference ")
    assert serve._job_error_message(ValueError("watermark is in the future")) == "watermark is in the future"


# ---------------------------------------------------------------------------
# GATE-06 / GATE-08 (review batch 3, v5.40.5)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("headers", [{}, {"X-Nginx-Proxy-Secret": "wrong"}, {"X-Auth-Sub": ADMIN}])
def test_hosted_anonymous_healthz_answers_status_only(matrix_server, monkeypatch, headers):
    """nginx serves /healthz without auth and without the proxy secret, so in
    hosted mode anyone who can reach the HTTPS port gets this answer: no
    version, no per-check detail."""
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    resp = requests.get(base_url + "/healthz", headers=headers, timeout=10)
    assert resp.status_code == 200
    assert set(resp.json()) == {"status"} and resp.json()["status"] in ("ok", "degraded")
    assert engine.SCRIPT_VERSION not in resp.text


def test_hosted_healthz_with_the_proxy_secret_keeps_the_detail(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    resp = requests.get(base_url + "/healthz", headers={"X-Nginx-Proxy-Secret": SECRET, "X-Auth-Sub": ADMIN},
                        timeout=10)
    assert resp.status_code == 200 and set(resp.json()) == {"status", "version", "checks"}


def test_local_healthz_keeps_the_detail(matrix_server):
    base_url, _serve = matrix_server
    assert set(requests.get(base_url + "/healthz", timeout=10).json()) == {"status", "version", "checks"}


@pytest.mark.parametrize("presented,expected", [
    (SECRET, True), (SECRET + "x", False), (SECRET[:-1], False), ("", False), (None, False),
    ("é" + SECRET, False),
])
def test_proxy_secret_compare(matrix_server, monkeypatch, presented, expected):
    _base_url, serve = matrix_server
    headers = {} if presented is None else {"X-Nginx-Proxy-Secret": presented}
    assert serve._request_is_from_nginx(headers) is expected


def test_proxy_secret_compare_is_constant_time(monkeypatch):
    """GATE-08: the comparison goes through hmac.compare_digest."""
    import hmac as _hmac

    import server.serve as serve

    calls = []
    real = _hmac.compare_digest
    monkeypatch.setattr(serve.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "abc")
    assert serve._request_is_from_nginx({"X-Nginx-Proxy-Secret": "abc"}) is True
    assert calls == [(b"abc", b"abc")]


# ---------------------------------------------------------------------------
# 5.42.0: shared-environment permissions, pinned per route
# ---------------------------------------------------------------------------
# Environment routes that take no shared-environment capability on purpose:
# activating is what sharing grants; share/unshare and delete are the
# owner's (or an admin's) own actions, never a shared user's.
NO_CAPABILITY_ROUTES = {
    ("POST", "path.startswith('/api/environments/') and path.endswith('/activate')"),
    ("POST", "path.startswith('/api/environments/') and path.endswith('/share')"),
    ("DELETE", "path.startswith('/api/environments/')"),
}


def _handler_methods():
    tree = ast.parse(SERVE_PY.read_text(encoding="utf-8"))
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Handler")
    return {fn.name: fn for fn in handler.body if isinstance(fn, ast.FunctionDef)}


def _route_if_nodes():
    """{(method, condition source): the route's `if` node}."""
    out = {}
    for name, fn in _handler_methods().items():
        if name not in ("do_GET", "do_POST", "do_DELETE"):
            continue
        for node in fn.body:
            if isinstance(node, ast.Try):
                for stmt in node.body:
                    if isinstance(stmt, ast.If) and _mentions_route(stmt.test):
                        out[(name[3:], ast.unparse(stmt.test))] = stmt
    return out


def _self_calls(node, method):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == method and isinstance(n.func.value, ast.Name) and n.func.value.id == "self"]


def _checked_capabilities(if_node):
    """(capabilities the route checks, the step-up action type it uses or
    None). Direct checks are self._capability_refused(owner, env, (caps,));
    a route handing over to self._environment_change("type", ...) is
    checked through that action's executor (self._shared_refusal(meta, cap))."""
    import server.serve as serve

    caps = set()
    for call in _self_calls(if_node, "_capability_refused"):
        tup = call.args[2]
        assert isinstance(tup, ast.Tuple), ast.unparse(call)
        caps.update(elt.value for elt in tup.elts)
    stepups = [call.args[0].value for call in _self_calls(if_node, "_environment_change")]
    assert len(stepups) <= 1
    stepup = stepups[0] if stepups else None
    if stepup:
        executor = _handler_methods()[serve._ENV_CHANGE_EXECUTORS[stepup]]
        for call in _self_calls(executor, "_shared_refusal"):
            caps.add(call.args[1].value)
    return caps, stepup


def test_every_environment_route_declares_its_capability():
    """A new env/session route without a declared capability fails here;
    so does a declared capability the code doesn't check (or the reverse),
    and a step-up type that doesn't match the code."""
    nodes = _route_if_nodes()
    known = set(engine.SHARED_CAPABILITY_KEYS)
    for key, route in ROUTES.items():
        caps, stepup = _checked_capabilities(nodes[key])
        assert stepup == route.stepup, (key, stepup, route.stepup)
        assert caps <= known, (key, caps)
        if route.kind in ("env", "session"):
            assert route.caps is not None, f"{key}: declare caps= for this environment route"
            if key not in NO_CAPABILITY_ROUTES:
                assert route.caps, f"{key}: an environment route must check at least one capability"
            assert caps == set(route.caps), (key, caps, route.caps)
        else:
            assert not caps, (key, caps)


def test_every_environment_change_type_has_a_route_and_an_executor():
    import server.serve as serve

    used = {r.stepup for r in ROUTES.values() if r.stepup}
    assert used == set(serve.ENV_CHANGE_ACTION_TYPES) == set(serve._ENV_CHANGE_EXECUTORS)


def _share_a_dev_with_b_session(serve):
    """A's "dev", shared, with B holding a live session on it (B has no
    "dev" of their own, so the name resolves to A's)."""
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    for who in (OWNER_B, ADMIN):
        with serve._sessions_lock:
            serve._sessions[who] = {"client": _UpstreamProbe(), "okta_client": _UpstreamProbe(),
                                    "env_name": "dev", "env_id": env_id}
    return env_id


CAP_ROUTES = [r for r in ROUTES.values() if r.caps]

# What a shared non-owner gets with nothing configured, pinned here rather
# than read from the engine (so a changed built-in default fails this
# matrix too). 5.43.0 (SP-1, SP-2): tenant writes and CSV import are denied.
BUILT_IN = {"view_archive": "allow", "live_read": "allow", "tenant_write": "deny", "import_csv": "deny",
            "reset_watermark": "allow", "sync_now": "deny", "sync_settings": "deny"}


def test_matrix_built_ins_match_the_engine():
    assert {c["key"]: c["builtin"] for c in engine.SHARED_CAPABILITIES} == BUILT_IN


def test_tenant_write_and_csv_import_routes_are_denied_to_shared_users_by_default():
    """SP-1/SP-2: every route that writes to the owner's tenant or imports a
    CSV checks a capability that is denied out of the box (the behavioural
    403 per route is driven in test_shared_capabilities_default_global_and_override)."""
    denied = [r for r in CAP_ROUTES if {"tenant_write", "import_csv"} & set(r.caps)]
    tenant_routes = [r for r in denied if "tenant_write" in r.caps]
    assert len(tenant_routes) == SERVE_PY.read_text(encoding="utf-8").count('("tenant_write",)') == 8
    assert [r.sample for r in denied if "import_csv" in r.caps] == ["/api/environments/dev/sync/import_csv"]
    assert all(any(BUILT_IN[c] == "deny" for c in r.caps) for r in denied)


def _expected_when_allowed(route):
    # B reaches exactly what A reaches (B's session client is an upstream probe too).
    return route.a_status


@pytest.mark.parametrize("route", CAP_ROUTES, ids=[f"{r.method} {r.sample}" for r in CAP_ROUTES])
def test_shared_capabilities_default_global_and_override(matrix_server, route):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    builtin = BUILT_IN

    def as_(who, admin=False):
        return _call(base_url, route.method, route.sample, route.body, _who(who, admin=admin))

    def assert_denied(resp):
        assert resp.status_code == 403, (route.sample, resp.status_code, resp.text)
        assert resp.json()["reason"] == "shared_permission_denied" and resp.json()["capability"] in route.caps
        assert "upstream reached" not in resp.text and "a-only" not in resp.text

    def reset():
        with serve._sync_jobs_lock:
            serve._sync_jobs.clear()

    # 1. Built-in defaults (5.43.0: tenant writes and CSV import denied ->
    #    403 shared_permission_denied; the owner still reaches the route).
    resp = as_(OWNER_B)
    if all(builtin[c] == "allow" for c in route.caps):
        assert resp.status_code == _expected_when_allowed(route), (route.sample, resp.status_code, resp.text)
    else:
        assert_denied(resp)
    reset()
    # 2. Global default deny for every capability the route checks.
    engine.set_shared_permissions({c: "deny" for c in route.caps})
    assert_denied(as_(OWNER_B))
    assert_denied(as_(ADMIN, admin=True))           # an admin using someone else's shared env is not exempt
    assert as_(OWNER_A).status_code == route.a_status  # the owner never is limited
    reset()
    # 3. A per-environment allow overrides the global deny.
    engine.set_shared_permissions({c: "allow" for c in route.caps}, environment_id=env_id)
    assert as_(OWNER_B).status_code == _expected_when_allowed(route)
    reset()
    # 4. Global allow, per-environment deny -> denied.
    engine.set_shared_permissions({c: "allow" for c in route.caps})
    engine.set_shared_permissions({c: "deny" for c in route.caps}, environment_id=env_id)
    assert_denied(as_(OWNER_B))
    reset()
    # 5. Inherit again -> the global allow applies.
    engine.set_shared_permissions({c: "inherit" for c in route.caps}, environment_id=env_id)
    assert as_(OWNER_B).status_code == _expected_when_allowed(route)


def test_capability_check_never_reveals_a_private_environment(matrix_server):
    """The capability check runs after visibility: a private environment is
    still a 404, never a 403 that would confirm it exists."""
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)  # A's "dev" stays private
    engine.set_shared_permissions({k: "deny" for k in engine.SHARED_CAPABILITY_KEYS})
    for route in ROUTES.values():
        if route.kind == "env" and route.caps:
            assert _call(base_url, route.method, route.sample, route.body, _who(OWNER_B)).status_code == 404


def test_shared_sync_now_runs_the_owners_sync_with_the_owners_schedule(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_sync_schedule("dev", {"ingestion_scope": "all"}, owner=OWNER_A)
    # Another owner's same-named, owner-less environment must not be picked up.
    engine.upsert_environment("dev", {"base_domain": "x.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
                                      "okta_url": "https://x.example.com", "okta_api_token": "other"})
    calls = []
    monkeypatch.setattr(serve, "_start_sync_job", lambda *a, **k: calls.append((a, k)) or True)
    url = base_url + "/api/environments/dev/sync/start"
    assert requests.post(url, json={}, headers=_who(OWNER_B), timeout=10).status_code == 403  # built-in: deny
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id)
    resp = requests.post(url, json={}, headers=_who(OWNER_B), timeout=10)
    assert resp.status_code == 200, resp.text
    (args, kwargs), = calls
    assert args[0] == env_id and args[2] == "all" and kwargs["owner"] == OWNER_A
    # Only the owner may pick another ingestion scope for a run.
    resp = requests.post(url, json={"ingestion_scope": "curated"}, headers=_who(OWNER_B), timeout=10)
    assert resp.status_code == 403 and resp.json()["reason"] == "owner_only"
    assert requests.post(url, json={"ingestion_scope": "all"}, headers=_who(OWNER_B), timeout=10).status_code == 200
    assert requests.post(url, json={"ingestion_scope": "curated"}, headers=_who(OWNER_A), timeout=10).status_code == 200


def test_shared_sync_worker_uses_the_owners_credentials_by_id(matrix_server, monkeypatch):
    """_launch_claimed_sync resolves the token by id under the real owner --
    a same-named environment elsewhere can't hand it someone else's token."""
    _base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.upsert_environment("dev", {"base_domain": "x.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
                                      "okta_url": "https://x.example.com", "okta_api_token": "other"}, owner=OWNER_B)
    built = []
    monkeypatch.setattr(engine, "OktaClient", lambda url, token: built.append((url, token)) or _UpstreamProbe())
    assert serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A, trigger="manual") is True
    assert built == [("https://a.example.com", "tok")]


def test_environment_list_reports_effective_permissions(matrix_server):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"tenant_write": "deny"})
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id)
    row = next(e for e in requests.get(base_url + "/api/environments", headers=_who(OWNER_B), timeout=10).json()["environments"])
    assert row["permissions"]["tenant_write"] == {"value": "deny", "source": "default"}
    assert row["permissions"]["sync_now"] == {"value": "allow", "source": "override"}
    assert row["permissions"]["live_read"] == {"value": "allow", "source": "built_in"}
    assert "permission_overrides" not in row  # admins only
    own = requests.get(base_url + "/api/environments", headers=_who(OWNER_A), timeout=10).json()["environments"][0]
    assert all(v == {"value": "allow", "source": "owner"} for v in own["permissions"].values())
    admin_row = next(e for e in requests.get(base_url + "/api/environments", headers=_who(ADMIN, admin=True),
                                             timeout=10).json()["environments"] if e["id"] == env_id)
    assert admin_row["permission_overrides"] == {"sync_now": "allow"}


def test_shared_permission_settings_are_admin_only_and_audited(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    url = base_url + "/api/shared_permissions"
    assert requests.get(url, headers=_who(OWNER_A), timeout=10).status_code == 403  # owners don't decide this
    assert requests.post(url, json={"changes": {"sync_now": "allow"}}, headers=_who(OWNER_A), timeout=10).status_code == 403
    assert requests.post(url, json={"changes": {"bogus": "allow"}}, headers=_who(ADMIN, admin=True), timeout=10).status_code == 400
    assert requests.post(url, json={"changes": {"sync_now": "maybe"}}, headers=_who(ADMIN, admin=True), timeout=10).status_code == 400
    assert requests.post(url, json={"environment_id": "nope", "changes": {"sync_now": "allow"}},
                         headers=_who(ADMIN, admin=True), timeout=10).status_code == 404
    resp = requests.post(url, json={"changes": {"tenant_write": "deny"}}, headers=_who(ADMIN, admin=True), timeout=10)
    assert resp.status_code == 200 and resp.json()["defaults"]["tenant_write"]["source"] == "default"
    resp = requests.post(url, json={"environment_id": env_id, "changes": {"tenant_write": "allow", "sync_now": "deny"}},
                         headers=_who(ADMIN, admin=True), timeout=10)
    assert resp.status_code == 200 and resp.json()["overrides"] == {"tenant_write": "allow", "sync_now": "deny"}
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    updates = [e for e in entries if e["action"] == "shared_permissions.update"]
    assert updates[0]["details"] == {"scope": "default", "changes": [
        {"capability": "tenant_write", "before": "inherit", "after": "deny"}]}
    assert updates[1]["details"]["scope"] == "environment" and updates[1]["details"]["environment_id"] == env_id
    assert updates[1]["details"]["name"] == "dev"
    assert sorted(updates[1]["details"]["changes"], key=lambda c: c["capability"]) == [
        {"capability": "sync_now", "before": "inherit", "after": "deny"},
        {"capability": "tenant_write", "before": "inherit", "after": "allow"}]
    # A no-op change is not logged.
    requests.post(url, json={"changes": {"tenant_write": "deny"}}, headers=_who(ADMIN, admin=True), timeout=10)
    assert len([e for e in (json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip())
                if e["action"] == "shared_permissions.update"]) == 2
    body = requests.get(url, headers=_who(ADMIN, admin=True), timeout=10).json()
    assert [c["key"] for c in body["capabilities"]] == list(engine.SHARED_CAPABILITY_KEYS)
    assert body["environments"][env_id]["overrides"] == {"tenant_write": "allow", "sync_now": "deny"}
    # The local-mode operator is the admin there.
    assert requests.get(url, timeout=10).status_code == 200


# --- per-user exceptions (5.43.0) ----------------------------------------------
PERSONAL_ISS = "https://login.example.org"      # e.g. an additional gate's org
WORK_ISS = "https://work.example.com/oauth2/default"
OWNER_C = "00uOWNERC"


def _as_user(sub, issuer, email=None, admin=False):
    # What a 5.43.0 nginx site sends: the gate's issuer plus the marker
    # proving the site overwrote it (an older site passes client copies on).
    headers = {**_who(sub, admin=admin), "X-Auth-Issuer": issuer, "X-Nginx-Issuer-Forwarded": SECRET}
    if email:
        headers["X-Auth-User"] = email
    return headers


def test_a_granted_user_can_sync_now_and_other_shared_users_cannot(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    calls = []
    monkeypatch.setattr(serve, "_start_sync_job", lambda *a, **k: calls.append((a, k)) or True)
    url = base_url + "/api/environments/dev/sync/start"
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id,
                                  grantee={"issuer": PERSONAL_ISS, "subject": OWNER_B})
    resp = requests.post(url, json={}, headers=_as_user(OWNER_B, PERSONAL_ISS), timeout=10)
    assert resp.status_code == 200, resp.text
    assert calls[-1][1]["owner"] == OWNER_A  # still the owner's sync
    # Everyone else stays on the setting: another shared user, the same sub
    # vouched for by another org, the same sub with no verified issuer.
    for headers in (_as_user(OWNER_C, PERSONAL_ISS), _as_user(OWNER_B, WORK_ISS), _who(OWNER_B),
                    _as_user(OWNER_B, PERSONAL_ISS + "/oauth2/x"), _as_user(ADMIN, PERSONAL_ISS, admin=True)):
        resp = requests.post(url, json={}, headers=headers, timeout=10)
        assert resp.status_code == 403 and resp.json()["capability"] == "sync_now", (headers, resp.text)
    assert len(calls) == 1
    # The issuer is only believed from nginx (the proxy secret), like X-Auth-Sub.
    marked = {"X-Auth-Sub": OWNER_B, "X-Auth-Issuer": PERSONAL_ISS, "X-Nginx-Proxy-Secret": SECRET,
              "X-Nginx-Issuer-Forwarded": SECRET}
    assert serve._issuer_from_headers(marked) == PERSONAL_ISS
    assert serve._issuer_from_headers({**marked, "X-Nginx-Proxy-Secret": "wrong"}) is None
    assert serve._issuer_from_headers({**marked, "X-Auth-Issuer": "https://x.example/evil"}) is None
    # Through a site older than 5.43.0 (no marker; a client-sent issuer passes
    # through it) or with a guessed marker, the issuer is not believed.
    assert serve._issuer_from_headers({**marked, "X-Nginx-Issuer-Forwarded": "guess"}) is None
    unmarked = {k: v for k, v in marked.items() if k != "X-Nginx-Issuer-Forwarded"}
    assert serve._issuer_from_headers(unmarked) is None
    resp = requests.post(url, json={}, headers=unmarked, timeout=10)
    assert resp.status_code == 403 and resp.json()["capability"] == "sync_now"
    # Local mode (no proxy secret at all) never has an issuer.
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "")
    assert serve._issuer_from_headers({**marked, "X-Nginx-Issuer-Forwarded": ""}) is None


def test_a_user_deny_beats_the_environment_allow_over_http(matrix_server):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"live_read": "deny"}, environment_id=env_id,
                                  grantee={"issuer": PERSONAL_ISS, "subject": OWNER_B})
    resp = requests.post(base_url + "/api/preview", json={"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A"}]},
                         headers=_as_user(OWNER_B, PERSONAL_ISS), timeout=10)
    assert resp.status_code == 403 and resp.json()["capability"] == "live_read"
    assert requests.post(base_url + "/api/preview", json={"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A"}]},
                         headers=_as_user(OWNER_B, WORK_ISS), timeout=10).status_code != 403


def test_environment_list_shows_the_callers_own_exception(matrix_server):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id,
                                  grantee={"issuer": PERSONAL_ISS, "subject": OWNER_B})
    rows = requests.get(base_url + "/api/environments", headers=_as_user(OWNER_B, PERSONAL_ISS), timeout=10).json()
    assert rows["environments"][0]["permissions"]["sync_now"] == {"value": "allow", "source": "user"}
    assert "permission_grants" not in rows["environments"][0]
    rows = requests.get(base_url + "/api/environments", headers=_as_user(OWNER_B, WORK_ISS), timeout=10).json()
    assert rows["environments"][0]["permissions"]["sync_now"] == {"value": "deny", "source": "built_in"}
    admin_row = next(e for e in requests.get(base_url + "/api/environments", headers=_who(ADMIN, admin=True),
                                             timeout=10).json()["environments"] if e["id"] == env_id)
    # Grants (other users' e-mails) are not in the list: it is reachable from
    # an additional gate's site, /api/shared_permissions is not (SP-5).
    assert "permission_grants" not in admin_row and "permission_overrides" in admin_row


def test_identities_are_recorded_for_the_picker_and_grants_are_audited(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    requests.get(base_url + "/api/environments", headers=_as_user(OWNER_B, PERSONAL_ISS, "me@example.org"), timeout=10)
    requests.get(base_url + "/api/environments", headers=_who(OWNER_C), timeout=10)  # no issuer: not recorded
    url = base_url + "/api/shared_permissions"
    body = requests.get(url, headers=_who(ADMIN, admin=True), timeout=10).json()
    assert [(i["issuer"], i["subject"], i["email"]) for i in body["identities"]] == [
        (PERSONAL_ISS, OWNER_B, "me@example.org")]
    user = {"issuer": PERSONAL_ISS, "subject": OWNER_B}
    # Admin-only, validated, needs an environment.
    assert requests.post(url, json={"environment_id": env_id, "user": user, "changes": {"sync_now": "allow"}},
                         headers=_who(OWNER_A), timeout=10).status_code == 403
    for bad in ({"environment_id": env_id, "user": {"issuer": PERSONAL_ISS, "subject": "a-b"}},
                {"environment_id": env_id, "user": {"subject": OWNER_B}},
                {"environment_id": env_id, "user": "00uOWNERB"},
                {"user": user}):
        resp = requests.post(url, json={**bad, "changes": {"sync_now": "allow"}}, headers=_who(ADMIN, admin=True), timeout=10)
        assert resp.status_code == 400, (bad, resp.text)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_grants").fetchone()[0] == 0
    resp = requests.post(url, json={"environment_id": env_id, "user": user, "changes": {"sync_now": "allow"}},
                         headers=_who(ADMIN, admin=True), timeout=10)
    assert resp.status_code == 200, resp.text
    assert resp.json()["grants"] == [{**user, "email": "me@example.org", "capability": "sync_now", "value": "allow"}]
    assert resp.json()["overrides"] == {}
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    update, = [e for e in entries if e["action"] == "shared_permissions.update"]
    assert update["details"] == {"scope": "user", "environment_id": env_id, "name": "dev",
                                 "user": {**user, "email": "me@example.org"},
                                 "changes": [{"capability": "sync_now", "before": "inherit", "after": "allow"}]}
    assert requests.get(url, headers=_who(ADMIN, admin=True), timeout=10).json()["environments"][env_id]["grants"] == \
        resp.json()["grants"]
    # The actor's own org is recorded when nginx vouches for it.
    requests.post(url, json={"environment_id": env_id, "user": user, "changes": {"sync_now": "deny"}},
                  headers=_as_user(ADMIN, WORK_ISS, admin=True), timeout=10)
    last = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()][-1]
    assert last["action"] == "shared_permissions.update" and last["details"]["actor_issuer"] == WORK_ISS


def test_identities_are_refreshed_daily_not_on_every_request(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    calls = []
    real = engine.record_known_identity
    monkeypatch.setattr(engine, "record_known_identity", lambda *a: calls.append(a) or real(*a))
    headers = _as_user(OWNER_B, PERSONAL_ISS, "me@example.org")
    for _ in range(3):
        requests.get(base_url + "/api/environments", headers=headers, timeout=10)
    assert len(calls) == 1
    serve._recorded_identities_day[0] = datetime.date(2000, 1, 1)  # the next day
    requests.get(base_url + "/api/environments", headers=headers, timeout=10)
    assert len(calls) == 2


def test_a_grant_reaches_the_step_up_executors_too(matrix_server):
    """The Environments-change executors check through _shared_refusal --
    with the caller's issuer, like every other route."""
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    url = base_url + "/api/environments/dev/sync/import_csv"
    body = {"csv_path": "syslog_export.csv"}
    engine.set_shared_permissions({"import_csv": "allow"}, environment_id=env_id,
                                  grantee={"issuer": PERSONAL_ISS, "subject": OWNER_B})
    assert requests.post(url, json=body, headers=_as_user(OWNER_B, WORK_ISS), timeout=10).status_code == 403
    assert requests.post(url, json=body, headers=_as_user(OWNER_B, PERSONAL_ISS), timeout=10).status_code == 200


def test_paths_with_dot_segments_are_refused(matrix_server):
    """nginx resolves . / .. before its own checks while serve.py routes on
    the raw path -- an admin delete resolves by ?id= whatever the name, so
    /api/environments/..?id=<id>&purge_archive=1 could slip past the
    additional gate's purge block. No route has such a segment."""
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    import http.client
    from urllib.parse import urlparse as _urlparse

    host = _urlparse(base_url)

    def raw(method, target):  # sent exactly as written (requests would resolve the dots first)
        conn = http.client.HTTPConnection(host.hostname, host.port, timeout=10)
        conn.request(method, target, headers=_who(ADMIN, admin=True))
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    for path in ("/api/environments/..", "/api/environments/%2e%2e", "/api/environments/%2E", "/api/./environments",
                 "/api/environments/dev/../x"):
        assert raw("DELETE", f"{path}?id={env_id}&purge_archive=1") == 400, path
        assert raw("GET", path) == 400, path
    assert env_id in engine.list_all_environments()
    assert requests.get(base_url + "/api/environments", headers=_who(OWNER_A), timeout=10).status_code == 200


def test_a_grant_change_is_bound_to_its_mfa_approval(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    user = {"issuer": PERSONAL_ISS, "subject": OWNER_B}
    aid = _prepare(base_url, "POST", "/api/shared_permissions",
                   {"environment_id": env_id, "user": user, "changes": {"sync_now": "allow"}}, ADMIN, admin=True)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_grants").fetchone()[0] == 0
    # The save's own body can't redirect the approval to another user or capability.
    resp = requests.post(base_url + "/api/environment_changes/save",
                         json={"environment_id": env_id, "user": {"issuer": PERSONAL_ISS, "subject": OWNER_C},
                               "changes": {"tenant_write": "allow"}},
                         headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": aid,
                                  "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert resp.status_code == 200, resp.text
    assert engine.get_shared_permission_grants(env_id) == [{**user, "email": None, "capability": "sync_now", "value": "allow"}]
    assert _stepup(base_url, ADMIN, aid, admin=True).status_code != 200  # single use
    # Another admin can't spend this admin's approval.
    aid = _prepare(base_url, "POST", "/api/shared_permissions",
                   {"environment_id": env_id, "user": user, "changes": {"sync_now": "inherit"}}, ADMIN, admin=True)
    assert _stepup(base_url, "00uOTHERADMIN", aid, admin=True).status_code != 200
    assert len(engine.get_shared_permission_grants(env_id)) == 1


def test_overrides_go_with_their_environment(matrix_server):
    _base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id)
    engine.delete_environment("dev", owner=OWNER_A)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_overrides").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# 5.42.0: step-up MFA for every Environments change (hosted mode)
# ---------------------------------------------------------------------------
STEPUP_ROUTES = [r for r in ROUTES.values() if r.stepup]


def _stepup(base_url, who, action_id, admin=False, location=True):
    headers = {**_who(who, admin=admin), "X-Auth-Action-Id": action_id}
    if location:
        headers["X-Nginx-Stepup-Location"] = SECRET
    return requests.post(base_url + "/api/environment_changes/save", json={}, headers=headers, timeout=10)


def _stepup_case(serve, route):
    """(caller, admin flag, sample, body) that the route accepts for owner A's
    shared "dev" -- and a state probe to prove nothing happened before the
    approval."""
    env_id = _share_a_dev_with_b_session(serve)
    who, admin, sample, body = OWNER_A, False, route.sample, route.body
    if route.stepup == "archive.purge":
        conn = audit_store._get_connection()
        conn.execute("INSERT INTO sync_state (environment_id, total_events_ingested) VALUES (?, 0)", (ORPHAN,))
        conn.commit()
        who, admin = ADMIN, True
    elif route.stepup == "shared_permissions.update":
        who, admin = ADMIN, True
    elif route.stepup == "environment.share":
        body = {"shared": False}
    return env_id, who, admin, sample, body


def _state():
    conn = audit_store._get_connection()
    return (sorted((m["name"], m["shared"], m["base_domain"]) for m in engine.list_all_environments().values()),
            conn.execute("SELECT COUNT(*) FROM shared_permission_defaults").fetchone()[0],
            [tuple(r) for r in conn.execute("SELECT * FROM sync_schedules")],
            conn.execute("SELECT COUNT(*) FROM sync_state").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])


@pytest.mark.parametrize("route", STEPUP_ROUTES, ids=[f"{r.method} {r.sample}" for r in STEPUP_ROUTES])
def test_every_environment_change_needs_a_step_up_bound_to_it(matrix_server, monkeypatch, tmp_audit_log, route):
    base_url, serve = matrix_server
    env_id, who, admin, sample, body = _stepup_case(serve, route)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    before = _state()
    resp = _call(base_url, route.method, sample, body, _who(who, admin=admin))
    assert resp.status_code == 202, resp.text
    prepared = resp.json()
    assert prepared["step_up_required"] is True and prepared["action"] == route.stepup
    assert _state() == before                      # nothing happened yet
    action_id = prepared["action_id"]
    # Not through nginx's step-up location -> refused, and the action stays claimable.
    refused = _stepup(base_url, who, action_id, admin=admin, location=False)
    assert refused.status_code == 403 and refused.json()["reason"] == "step_up_unavailable"
    # Another user's approval can't spend it.
    other = _stepup(base_url, OWNER_B, action_id)
    assert other.status_code == 403 and other.json()["reason"] == "actor_mismatch"
    # No action id at all.
    none = requests.post(base_url + "/api/environment_changes/save", json={},
                         headers={**_who(who, admin=admin), "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert none.status_code == 409 and none.json()["reason"] == "not_found"
    assert _state() == before
    # The approved request runs, whatever this request's own body says.
    done = requests.post(base_url + "/api/environment_changes/save",
                         json={"shared": True, "name": "evil", "changes": {"live_read": "deny"}},
                         headers={**_who(who, admin=admin), "X-Auth-Action-Id": action_id,
                                  "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert 200 <= done.status_code < 300, done.text
    assert done.json()["step_up_verified"] is True and done.json()["action"] == route.stepup
    entry = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()][-1]
    assert entry["action"] == route.stepup
    assert entry["details"]["step_up_verified"] is True
    # Single use: a replay of the same approval is refused.
    replay = _stepup(base_url, who, action_id, admin=admin)
    assert replay.status_code == 409 and replay.json()["reason"] == "already_consumed"


def test_a_step_up_approval_expires(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    action_id = requests.post(base_url + "/api/environments/dev/share", json={"shared": False},
                              headers=_who(OWNER_A), timeout=10).json()["action_id"]
    conn = audit_store._get_connection()
    conn.execute("UPDATE pending_admin_actions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE action_id = ?", (action_id,))
    conn.commit()
    resp = _stepup(base_url, OWNER_A, action_id)
    assert resp.status_code == 409 and resp.json()["reason"] == "expired"
    assert next(iter(engine.list_all_environments().values()))["shared"] is True


def test_one_approval_cannot_be_used_for_another_kind_of_change(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    # An Access Control approval is never an Environments approval...
    ac_id = audit_store.create_pending_admin_action(ADMIN, "access_control.update",
                                                    {"admin_group_id": "g", "user_group_id": None, "restrict_login": False}, 60)
    resp = _stepup(base_url, ADMIN, ac_id, admin=True)
    assert resp.status_code == 403 and resp.json()["reason"] == "action_type_mismatch"
    # ...and an Environments approval can't be spent on (or burned by) the Access Control save.
    env_action = requests.post(base_url + "/api/environments/dev/share", json={"shared": False},
                               headers=_who(OWNER_A), timeout=10).json()["action_id"]
    resp = requests.post(base_url + "/api/access_control/save", json={},
                         headers={**_who(OWNER_A, admin=True), "X-Auth-Action-Id": env_action}, timeout=10)
    assert resp.status_code == 403 and resp.json()["reason"] == "action_type_mismatch"
    assert _stepup(base_url, OWNER_A, env_action).status_code == 200  # still claimable by its own route
    # The Access Control approval is also still claimable by its own route.
    resp = requests.post(base_url + "/api/access_control/save", json={},
                         headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": ac_id}, timeout=10)
    assert resp.status_code == 200, resp.text


def test_two_approvals_each_apply_only_their_own_payload(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    url = base_url + "/api/environments/dev/sync_schedule"
    first = requests.post(url, json={"run_time": "03:00"}, headers=_who(OWNER_A), timeout=10).json()["action_id"]
    second = requests.post(url, json={"run_time": "04:00"}, headers=_who(OWNER_A), timeout=10).json()["action_id"]
    assert _stepup(base_url, OWNER_A, second).status_code == 200
    assert engine.get_sync_schedule_by_id(env_id)["run_time"] == "04:00"
    assert _stepup(base_url, OWNER_A, first).status_code == 200
    assert engine.get_sync_schedule_by_id(env_id)["run_time"] == "03:00"


def test_environment_secrets_never_reach_the_pending_actions_table(matrix_server, monkeypatch, fake_keyring):
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    body = {"name": "new", "base_domain": "n.example.com", "team_name": "t", "key_id": "k",
            "key_secret": "TOP-SECRET-KEY", "okta_url": "https://n.example.com", "okta_api_token": "TOP-SECRET-TOKEN"}
    action_id = requests.post(base_url + "/api/environments", json=body, headers=_who(OWNER_A), timeout=10).json()["action_id"]
    raw = audit_store._get_connection().execute("SELECT payload_json FROM pending_admin_actions").fetchall()
    assert raw and all("TOP-SECRET" not in r[0] for r in raw)
    resp = _stepup(base_url, OWNER_A, action_id)
    assert resp.status_code == 200, resp.text
    env_id = next(i for i, m in engine.list_all_environments().items() if m["name"] == "new")
    assert fake_keyring[(env_id, "key_secret")] == "TOP-SECRET-KEY"
    assert fake_keyring[(env_id, "okta_api_token")] == "TOP-SECRET-TOKEN"
    # A restart during the round trip loses the secrets: the save asks again, nothing is saved.
    action_id = requests.post(base_url + "/api/environments", json={**body, "name": "newer"},
                              headers=_who(OWNER_A), timeout=10).json()["action_id"]
    with serve._pending_env_secrets_lock:
        serve._pending_env_secrets.clear()
    resp = _stepup(base_url, OWNER_A, action_id)
    assert resp.status_code == 409 and resp.json()["reason"] == "secrets_expired"
    assert "newer" not in {m["name"] for m in engine.list_all_environments().values()}


def test_a_refused_change_is_refused_before_any_mfa(matrix_server, monkeypatch):
    """The checks run before the step-up too: a change the caller may not
    make never sends them through MFA for nothing."""
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    assert requests.post(base_url + "/api/environments/dev/share", json={"shared": False},
                         headers=_who(OWNER_B), timeout=10).status_code == 404   # not B's
    assert requests.post(base_url + "/api/environments/dev/sync_schedule", json={"enabled": True},
                         headers=_who(OWNER_B), timeout=10).status_code == 403   # sync_settings: built-in deny
    assert requests.post(base_url + "/api/environments/dev/sync_schedule", json={"run_time": "25:00"},
                         headers=_who(OWNER_A), timeout=10).status_code == 400
    assert requests.delete(base_url + "/api/environments/dev?purge_archive=1", headers=_who(OWNER_A),
                           timeout=10).status_code == 403
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM pending_admin_actions").fetchone()[0] == 0


def test_the_approved_change_is_checked_again_when_it_runs(matrix_server, monkeypatch):
    """Rights withdrawn between the approval request and the save win."""
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    engine.set_shared_permissions({"sync_settings": "allow"}, environment_id=env_id)
    action_id = requests.post(base_url + "/api/environments/dev/sync_schedule", json={"enabled": True},
                              headers=_who(OWNER_B), timeout=10).json()["action_id"]
    engine.set_shared_permissions({"sync_settings": "deny"}, environment_id=env_id)
    resp = _stepup(base_url, OWNER_B, action_id)
    assert resp.status_code == 403 and resp.json()["reason"] == "shared_permission_denied"
    assert engine.get_sync_schedule_by_id(env_id)["enabled"] is False


def test_activate_and_sync_now_need_no_step_up(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    assert requests.post(base_url + "/api/environments/dev/activate", json={}, headers=_who(OWNER_B),
                         timeout=10).status_code == 200
    assert requests.post(base_url + "/api/environments/dev/sync/start", json={}, headers=_who(OWNER_A),
                         timeout=10).status_code == 200


def test_local_mode_applies_environment_changes_directly(matrix_server):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    resp = requests.post(base_url + "/api/environments/dev/share", json={"shared": False}, headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 200 and resp.json() == {"name": "dev", "shared": False}
    assert requests.post(base_url + "/api/environment_changes/save", json={}, timeout=10).status_code == 404


# --- review round 1 (5.42.0) ---------------------------------------------------
def test_the_saves_own_body_never_changes_what_is_applied(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    action_id = requests.post(base_url + "/api/environments/dev/share", json={"shared": False},
                              headers=_who(OWNER_A), timeout=10).json()["action_id"]
    resp = requests.post(base_url + "/api/environment_changes/save", json={"shared": True, "id": env_id},
                         headers={**_who(OWNER_A), "X-Auth-Action-Id": action_id, "X-Nginx-Stepup-Location": SECRET},
                         timeout=10)
    assert resp.status_code == 200
    assert engine.list_all_environments()[env_id]["shared"] is False
    action_id = requests.post(base_url + "/api/shared_permissions", json={"changes": {"sync_now": "allow"}},
                              headers=_who(ADMIN, admin=True), timeout=10).json()["action_id"]
    resp = requests.post(base_url + "/api/environment_changes/save", json={"changes": {"live_read": "deny"}},
                         headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": action_id,
                                  "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert resp.status_code == 200
    defaults = engine.get_shared_permission_defaults()
    assert defaults["sync_now"]["value"] == "allow" and defaults["live_read"]["source"] == "built_in"


def _prepare(base_url, method, path, body, who, admin=False):
    resp = _call(base_url, method, path, body, _who(who, admin=admin))
    assert resp.status_code == 202, resp.text
    return resp.json()["action_id"]


@pytest.mark.parametrize("case", [
    "reset_watermark_revoked", "import_csv_revoked", "purge_admin_demoted", "permissions_admin_demoted",
    "delete_purge_admin_demoted", "unshared_during_mfa", "name_now_means_another_environment",
])
def test_every_check_runs_again_when_the_approved_change_is_applied(matrix_server, monkeypatch, case):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    conn = audit_store._get_connection()
    if case == "reset_watermark_revoked":
        aid = _prepare(base_url, "POST", "/api/environments/dev/sync/reset_watermark", {}, OWNER_B)
        engine.set_shared_permissions({"reset_watermark": "deny"}, environment_id=env_id)
        expected, who, admin = (403, "shared_permission_denied"), OWNER_B, False
    elif case == "import_csv_revoked":
        engine.set_shared_permissions({"import_csv": "allow"})  # built-in is deny (5.43.0)
        aid = _prepare(base_url, "POST", "/api/environments/dev/sync/import_csv", {"csv_path": "syslog_export.csv"}, OWNER_B)
        engine.set_shared_permissions({"import_csv": "deny"})
        expected, who, admin = (403, "shared_permission_denied"), OWNER_B, False
    elif case == "purge_admin_demoted":
        conn.execute("INSERT INTO sync_state (environment_id, total_events_ingested) VALUES (?, 0)", (ORPHAN,))
        conn.commit()
        aid = _prepare(base_url, "DELETE", f"/api/archives/{ORPHAN}", None, ADMIN, admin=True)
        expected, who, admin = (403, None), ADMIN, False
    elif case == "permissions_admin_demoted":
        aid = _prepare(base_url, "POST", "/api/shared_permissions", {"changes": {"sync_now": "allow"}}, ADMIN, admin=True)
        expected, who, admin = (403, None), ADMIN, False
    elif case == "delete_purge_admin_demoted":
        aid = _prepare(base_url, "DELETE", "/api/environments/dev?purge_archive=1", None, OWNER_A, admin=True)
        expected, who, admin = (403, None), OWNER_A, False
    elif case == "unshared_during_mfa":
        aid = _prepare(base_url, "POST", "/api/environments/dev/sync/reset_watermark", {}, OWNER_B)
        engine.set_environment_shared("dev", OWNER_A, False)
        expected, who, admin = (404, None), OWNER_B, False
    else:
        # B's "dev" resolves to A's when prepared; then a newer shared "dev"
        # (C's) takes the name -- the approval must not move to C's archive.
        aid = _prepare(base_url, "POST", "/api/environments/dev/sync/reset_watermark", {}, OWNER_B)
        engine.upsert_environment("dev", {"base_domain": "c.example.com", "team_name": "t", "key_id": "k",
                                          "key_secret": "s"}, owner="00uOWNERC")
        conn.execute("UPDATE app_environments SET created_at = '2999-01-01T00:00:00.000Z' WHERE owner_id = '00uOWNERC'")
        conn.commit()
        engine.set_environment_shared("dev", "00uOWNERC", True)
        expected, who, admin = (409, "target_changed"), OWNER_B, False
    resp = _stepup(base_url, who, aid, admin=admin)
    assert resp.status_code == expected[0], resp.text
    if expected[1]:
        assert resp.json()["reason"] == expected[1]
    assert env_id in engine.list_all_environments()
    assert engine.get_shared_permission_defaults()["sync_now"]["source"] == "built_in"


def test_held_secrets_expire_with_the_approval(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    aid = _prepare(base_url, "POST", "/api/environments", {"name": "new", "base_domain": "n.example.com",
                                                           "team_name": "t", "key_id": "k", "key_secret": "S"}, OWNER_A)
    with serve._pending_env_secrets_lock:
        expires, held = serve._pending_env_secrets[aid]
        serve._pending_env_secrets[aid] = (0.0, held)
    resp = _stepup(base_url, OWNER_A, aid)
    assert resp.status_code == 409 and resp.json()["reason"] == "secrets_expired"


def test_a_denied_shared_user_gets_403_whatever_the_body(matrix_server):
    """The permission check comes before the request's own validation."""
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"import_csv": "deny", "reset_watermark": "deny"})
    for path, body in [("/api/environments/dev/sync_schedule", {"run_time": "99:99"}),
                       ("/api/environments/dev/sync/import_csv", {"csv_path": "../etc/passwd"}),
                       ("/api/environments/dev/sync/reset_watermark", {})]:
        resp = requests.post(base_url + path, json=body, headers=_who(OWNER_B), timeout=10)
        assert resp.status_code == 403 and resp.json()["reason"] == "shared_permission_denied", (path, resp.text)


def test_sync_worker_credentials_follow_the_id_not_a_same_named_environment(matrix_server, monkeypatch):
    _base_url, serve = matrix_server
    ids = []
    for domain, token in (("first.example.com", "tok-1"), ("second.example.com", "tok-2")):
        _, env_id = engine.upsert_environment("dev", {"base_domain": domain, "team_name": "t", "key_id": "k",
                                                      "key_secret": "s", "okta_url": f"https://{domain}",
                                                      "okta_api_token": token}, owner=OWNER_A)
        ids.append(env_id)
        conn = audit_store._get_connection()  # rename it so the second "dev" can be created
        conn.execute("UPDATE app_environments SET display_name = 'tmp-' || environment_id WHERE environment_id = ?", (env_id,))
        conn.commit()
    conn = audit_store._get_connection()
    conn.execute("UPDATE app_environments SET display_name = 'dev', owner_id = NULL")  # two owner-less "dev" rows
    conn.execute("UPDATE app_environments SET created_at = '2000-01-01T00:00:00.000Z' WHERE environment_id = ?", (ids[0],))
    conn.commit()
    built = []
    monkeypatch.setattr(engine, "OktaClient", lambda url, token: built.append(token) or _UpstreamProbe())
    assert serve._start_sync_job(ids[0], "dev", "curated", owner=None, trigger="manual") is True
    assert built == ["tok-1"]


def test_one_user_cannot_pile_up_pending_changes(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    monkeypatch.setattr(serve, "MAX_OPEN_ENV_CHANGES_PER_USER", 3)
    for _ in range(3):
        _prepare(base_url, "POST", "/api/environments/dev/share", {"shared": False}, OWNER_A)
    resp = requests.post(base_url + "/api/environments/dev/share", json={"shared": False}, headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 429 and resp.json()["reason"] == "too_many_pending"
    # Someone else is not affected.
    assert _call(base_url, "POST", "/api/environments/dev/sync/reset_watermark", {}, _who(OWNER_B)).status_code == 202


def test_only_the_upsert_form_fields_are_stored_and_they_are_capped(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    body = {"name": "x", "base_domain": "x.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
            "junk": "y" * 10000}
    _prepare(base_url, "POST", "/api/environments", body, OWNER_A)
    raw = audit_store._get_connection().execute("SELECT payload_json FROM pending_admin_actions").fetchone()[0]
    assert "junk" not in raw
    resp = requests.post(base_url + "/api/environments", json={**body, "team_name": "t" * 5000},
                         headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 400
    # Invalid input is refused before the MFA round trip, as in local mode.
    resp = requests.post(base_url + "/api/environments", json={**body, "base_domain": "evil.example.com/path"},
                         headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 400


def test_a_shared_user_with_sync_settings_cannot_change_retention(matrix_server):
    base_url, serve = matrix_server
    env_id = _share_a_dev_with_b_session(serve)
    engine.set_shared_permissions({"sync_settings": "allow"}, environment_id=env_id)
    url = base_url + "/api/environments/dev/sync_schedule"
    resp = requests.post(url, json={"retention_days": 1}, headers=_who(OWNER_B), timeout=10)
    assert resp.status_code == 403 and resp.json()["reason"] == "owner_only"
    assert requests.post(url, json={"run_time": "04:00", "retention_days": None}, headers=_who(OWNER_B),
                         timeout=10).status_code == 200
    assert requests.post(url, json={"retention_days": 30}, headers=_who(OWNER_A), timeout=10).status_code == 200


def test_a_session_on_a_deleted_environment_is_no_active_environment(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["env_id"] = "gone"
    resp = requests.get(base_url + "/api/resource_groups", headers=_who(OWNER_A), timeout=10)
    assert resp.status_code == 409 and "No active environment" in resp.json()["error"]


def test_permissions_are_listed_only_for_rows_the_caller_can_address(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)  # A's private "dev"
    rows = requests.get(base_url + "/api/environments", headers=_who(ADMIN, admin=True), timeout=10).json()["environments"]
    assert rows and all("permissions" not in r for r in rows if not r["addressable"])


@pytest.mark.parametrize("method, path, body", [
    ("POST", "/api/environments/dev/share", {"shared": True}),
    ("DELETE", "/api/environments/dev", None),
    ("POST", "/api/environments", {"name": "dev", "base_domain": "a.example.com", "team_name": "t", "key_id": "k2"}),
])
def test_owner_changes_stay_bound_to_the_environment_that_was_checked(matrix_server, monkeypatch, method, path, body):
    """The approval names the environment the change was checked against: if
    the owner's "dev" is a different environment by the time it is applied,
    nothing happens."""
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    aid = _prepare(base_url, method, path, body, OWNER_A)
    conn = audit_store._get_connection()
    conn.execute("UPDATE app_environments SET display_name = 'old-dev' WHERE environment_id = ?", (env_id,))
    conn.commit()
    _, new_id = engine.upsert_environment("dev", {"base_domain": "n.example.com", "team_name": "t", "key_id": "k",
                                                  "key_secret": "s"}, owner=OWNER_A)
    resp = _stepup(base_url, OWNER_A, aid)
    assert resp.status_code == 409 and resp.json()["reason"] == "target_changed", resp.text
    envs = engine.list_all_environments()
    assert envs[new_id]["shared"] is False and envs[new_id]["key_id"] == "k" and env_id in envs


def test_a_stored_action_must_match_its_rows_type(matrix_server, monkeypatch):
    """Defence in depth: the save runs only the action its pending row was
    created for, even if a stored payload named another one."""
    base_url, serve = matrix_server
    _share_a_dev_with_b_session(serve)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    aid = audit_store.create_pending_admin_action(
        OWNER_A, "environment.share",
        {"action": "archive.purge", "params": {"archive_id": ORPHAN}, "secret_fields": []}, 60)
    resp = _stepup(base_url, OWNER_A, aid)
    assert resp.status_code == 403 and resp.json()["reason"] == "action_type_mismatch"
