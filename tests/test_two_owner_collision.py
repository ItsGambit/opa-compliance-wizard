"""The two-owner collision integration test named by
docs/fast-follow-redesign.md's Phase 7 as the single test that would have
caught the original F1/F2/F3 cross-tenant bugs (external review,
2026-09-30) automatically instead of needing a human review to surface
them.

Scenario: two different owners each have an environment named "dev".
Written against the STABLE PUBLIC CONTRACT (_resolve_admin_target called
WITH an explicit environment_id, _environment_visible_to, and the HTTP
routes' `id` round-trip) rather than any particular storage shape.

Real ids are read back from upsert_environment's own return value (it
returns (name, environment_id)) rather than precomputed via the retired
environment_storage_name -- Phase 1's UUID migration means there's no
longer a deterministic function of (owner, name) that produces the real
id ahead of time; the system has to be asked.

Phase 2 (SQLite migration, 2026-10-01) retired environments.json and
load_environments()/save_environments() entirely -- this file now reads
state back via list_all_environments() ({environment_id: meta}) instead
of load_environments()'s old data["environments"] dict, and every test
uses tmp_audit_store (not just tmp_environments_file) since
app_environments/active_environments now live in audit_store.db. Each
test calls audit_store.run_migrations() directly (NOT init_db(), which
would also call migrate_legacy_environments_json() against this
process's real environments.json -- never wanted in a test)."""
import socket
import threading
import time

import pytest
import requests

import create_secret_folders as engine

OWNER_A = engine.LOCAL_OWNER_KEY  # None -- "__local__"
OWNER_B = "00uOWNERB"


@pytest.fixture
def tmp_schema(tmp_audit_store):
    import audit_store
    audit_store.run_migrations()
    return tmp_audit_store


def _seed_two_owner_dev_environments(tmp_schema, tmp_environments_file, fake_keyring):
    """Builds two "dev" environments, one per owner, directly through the
    real public API (upsert_environment) rather than hand-constructing
    any particular storage shape -- this IS part of the stable contract
    this test is meant to survive a future storage-format migration
    against. Returns (id_a, id_b, all_envs) -- the real ids come straight
    from upsert_environment's own return value; all_envs is
    list_all_environments()'s {environment_id: meta} dict."""
    _, id_a = engine.upsert_environment(
        "dev",
        {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    _, id_b = engine.upsert_environment(
        "dev",
        {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )
    all_envs = engine.list_all_environments()
    return id_a, id_b, all_envs


# ---------------------------------------------------------------------------
# 1. Admin edit/delete/share must disambiguate by environment_id, never by
#    bare name.
# ---------------------------------------------------------------------------
def test_admin_resolves_correct_owner_by_environment_id(tmp_schema, tmp_environments_file, fake_keyring):
    id_a, id_b, _ = _seed_two_owner_dev_environments(tmp_schema, tmp_environments_file, fake_keyring)

    found_id, meta = engine._resolve_admin_target(id_b)
    assert found_id == id_b
    assert meta["base_domain"] == "b.example.com"

    found_id, meta = engine._resolve_admin_target(id_a)
    assert found_id == id_a
    assert meta["base_domain"] == "a.example.com"


def test_admin_set_environment_shared_targets_only_the_specified_owner(tmp_schema, tmp_environments_file, fake_keyring):
    id_a, id_b, _ = _seed_two_owner_dev_environments(tmp_schema, tmp_environments_file, fake_keyring)

    engine.set_environment_shared("dev", owner=OWNER_A, shared=True, is_admin=True, environment_id=id_b)

    all_envs = engine.list_all_environments()
    assert all_envs[id_b]["shared"] is True
    # Owner A's own "dev" must be completely untouched by an admin action
    # explicitly targeting owner B's environment_id.
    assert all_envs[id_a].get("shared") in (False, None)


def test_admin_delete_environment_removes_only_the_targeted_owner(tmp_schema, tmp_environments_file, fake_keyring):
    id_a, id_b, _ = _seed_two_owner_dev_environments(tmp_schema, tmp_environments_file, fake_keyring)

    engine.delete_environment("dev", owner=OWNER_A, is_admin=True, environment_id=id_b)

    all_envs = engine.list_all_environments()
    assert id_b not in all_envs
    assert id_a in all_envs  # owner A's "dev" survives


# ---------------------------------------------------------------------------
# 1b. ENG1-01 (external review, 2026-10-05): an admin "create" (no
#     environment_id -- a create never has one) must create the ADMIN's
#     own environment, never silently adopt/overwrite another owner's
#     same-named one. This is the confirmed-exploitable credential-capture
#     path: before the fix, upsert_environment(is_admin=True, no id) fell
#     back to a by-name scan across every owner, so an admin's real
#     privileged secrets landed in a non-admin's existing "prod"/"dev" row.
# ---------------------------------------------------------------------------
ADMIN = "00uADMIN"


def test_admin_create_with_colliding_name_never_touches_other_owners_environment(
    tmp_schema, tmp_environments_file, fake_keyring
):
    # Owner B already has a "prod" with their own (unprivileged) secrets.
    engine.upsert_environment(
        "prod",
        {"base_domain": "victim.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )

    # Admin "creates" an environment also named "prod" with no id -- the
    # exact shape of a real "add environment" form submission.
    name, admin_env_id = engine.upsert_environment(
        "prod",
        {"base_domain": "admin.example.com", "team_name": "team-admin", "key_id": "key-admin",
         "key_secret": "ADMIN-PRIVILEGED-SECRET"},
        owner=ADMIN,
        is_admin=True,
    )

    all_envs = engine.list_all_environments()
    # Owner B's row is untouched: still their own domain/secret, still a
    # SEPARATE environment_id from whatever the admin's create produced.
    victim_meta = next(m for m in all_envs.values() if m["owner"] == OWNER_B and m["name"] == "prod")
    assert victim_meta["base_domain"] == "victim.example.com"
    assert engine.keyring_get(victim_meta["environment_id"], "key_secret") == "secret-b"

    # The admin's own create landed under the admin's OWN owner, as a
    # genuinely separate row -- never adopting owner B's existing one.
    assert admin_env_id != victim_meta["environment_id"]
    admin_meta = all_envs[admin_env_id]
    assert admin_meta["owner"] == ADMIN
    assert admin_meta["base_domain"] == "admin.example.com"
    assert engine.keyring_get(admin_env_id, "key_secret") == "ADMIN-PRIVILEGED-SECRET"


# ---------------------------------------------------------------------------
# 2. Non-admin visibility must not leak.
# ---------------------------------------------------------------------------
def test_private_environment_not_visible_to_other_owner(tmp_schema, tmp_environments_file, fake_keyring):
    engine.upsert_environment(
        "dev",
        {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )
    # Owner B's "dev" defaults to shared=False (upsert_environment's
    # meta.setdefault("shared", False)) -- owner A, who has no "dev" of
    # their own, must never see it.
    visible_to_a = engine.list_environments_for(OWNER_A)
    assert "dev" not in visible_to_a


def test_shared_environment_is_visible_but_private_one_is_not(tmp_schema, tmp_environments_file, fake_keyring):
    engine.upsert_environment(
        "dev",
        {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )
    engine.set_environment_shared("dev", owner=OWNER_B, shared=True)
    visible_to_a = engine.list_environments_for(OWNER_A)
    assert "dev" in visible_to_a
    assert visible_to_a["dev"]["base_domain"] == "b.example.com"


# ---------------------------------------------------------------------------
# 3. Access Explorer / sync job isolation (keyed by the real environment_id,
#    never a bare display name).
# ---------------------------------------------------------------------------
def test_access_and_sync_jobs_keyed_by_full_environment_id_not_bare_name():
    import uuid

    import server.serve as serve

    id_a = str(uuid.uuid4())
    id_b = str(uuid.uuid4())

    with serve._access_jobs_lock:
        serve._access_jobs[id_a] = {"status": "done", "steps": [], "error": None, "result": "A's model"}

    with serve._access_jobs_lock:
        job_for_a = serve._access_jobs.get(id_a)
        job_for_b = serve._access_jobs.get(id_b)

    assert job_for_a is not None and job_for_a["result"] == "A's model"
    assert job_for_b is None  # B's job entry must not exist/leak A's result


# ---------------------------------------------------------------------------
# 3b. TEST-02 (external review, 2026-10-05): the test above is
#     tautological -- it populates serve._access_jobs itself and asserts
#     on a plain dict's own behavior, never calling the real
#     /api/access/bootstrap/result route or _run_access_job. It passes
#     whether or not the ROUTE itself is actually keyed correctly.
#     Mutation M25 (rewriting the route to
#     `next(iter(_access_jobs.values()), None)` -- the real,
#     confirmed-exploitable cross-tenant leak this project's own history
#     names, see serve.py:276-287's comment) SURVIVED against the test
#     above. This test drives the SAME scenario through the real HTTP
#     route with two owners each having their own active session, so a
#     revert back to that global-lookup shape fails HERE.
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server_with_sessions(tmp_schema, tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
    """Same as live_server (section 4 below) but also lets the test seed
    _sessions directly -- activate_environment itself requires a live
    OPA/Okta connection (OpaClient.__init__ fetches a real bearer token),
    which is out of scope for an owner-isolation test; _sessions'
    structure is this project's own stable internal contract for "which
    env_id is this owner's active one," not an implementation detail this
    test invents."""
    import server.serve as serve

    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "test-proxy-secret")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server_instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    for _ in range(50):
        try:
            requests.get(base_url + "/api/environments", timeout=0.5,
                         headers={"X-Nginx-Proxy-Secret": "test-proxy-secret"})
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)

    yield base_url, serve
    server_instance.shutdown()
    server_instance.server_close()


def _user_headers(sub):
    return {"X-Nginx-Proxy-Secret": "test-proxy-secret", "X-Auth-Sub": sub, "X-Auth-Is-Admin": "false"}


def test_bootstrap_result_route_never_leaks_another_owners_tenant_model(live_server_with_sessions):
    base_url, serve = live_server_with_sessions
    id_a, id_b = "env-id-owner-a", "env-id-owner-b"

    with serve._sessions_lock:
        serve._sessions["00uOWNERA"] = {"client": None, "okta_client": None, "env_name": "dev", "env_id": id_a}
        serve._sessions["00uOWNERB"] = {"client": None, "okta_client": None, "env_name": "dev", "env_id": id_b}
    with serve._access_jobs_lock:
        serve._access_jobs[id_a] = {"status": "done", "steps": [], "error": None, "result": {"tenant": "A's model"}}
        # B's own job is deliberately NOT "done" yet -- confirms the route
        # doesn't just return *some* done job, it returns B's own.

    # Owner B polls the real route. The confirmed-exploitable regression
    # this guards against: a global/unscoped lookup would return A's
    # result here (the only "done" job in the dict).
    resp = requests.get(f"{base_url}/api/access/bootstrap/result", headers=_user_headers("00uOWNERB"), timeout=5)
    assert resp.status_code == 409  # B's own job isn't done -- never A's result
    assert resp.json()["error"] == "Job is not done yet."

    # Owner A polls the same route and gets their OWN result.
    resp = requests.get(f"{base_url}/api/access/bootstrap/result", headers=_user_headers("00uOWNERA"), timeout=5)
    assert resp.status_code == 200
    assert resp.json() == {"tenant": "A's model"}


def test_bootstrap_status_route_never_leaks_another_owners_steps(live_server_with_sessions):
    base_url, serve = live_server_with_sessions
    id_a, id_b = "env-id-owner-a", "env-id-owner-b"

    with serve._sessions_lock:
        serve._sessions["00uOWNERA"] = {"client": None, "okta_client": None, "env_name": "dev", "env_id": id_a}
        serve._sessions["00uOWNERB"] = {"client": None, "okta_client": None, "env_name": "dev", "env_id": id_b}
    with serve._access_jobs_lock:
        serve._access_jobs[id_a] = {"status": "running", "steps": [{"key": "fetch_a", "status": "progress"}], "error": None, "result": None}

    resp = requests.get(f"{base_url}/api/access/bootstrap/status", headers=_user_headers("00uOWNERB"), timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "idle"  # B has no job of their own -- never A's "running"
    assert body["steps"] == []


# ---------------------------------------------------------------------------
# 4. The admin HTTP routes' `id` round-trip actually disambiguates
#    end-to-end, through real HTTP requests against a live server
#    instance -- bypasses nginx entirely (fine for a backend test; the
#    nginx trust boundary itself is covered by test_auth_headers.py).
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server(tmp_schema, tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
    import server.serve as serve

    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "test-proxy-secret")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server_instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    for _ in range(50):
        try:
            requests.get(base_url + "/api/environments", timeout=0.5,
                         headers={"X-Nginx-Proxy-Secret": "test-proxy-secret"})
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)

    yield base_url
    server_instance.shutdown()
    server_instance.server_close()


def _admin_headers():
    return {
        "X-Nginx-Proxy-Secret": "test-proxy-secret",
        "X-Auth-Is-Admin": "true",
        "X-Auth-Sub": "00uADMIN",
    }


def test_http_delete_with_environment_id_deletes_only_that_owners_dev(live_server, tmp_schema, tmp_environments_file, fake_keyring):
    _, id_a = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    _, id_b = engine.upsert_environment(
        "dev", {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )

    resp = requests.delete(
        f"{live_server}/api/environments/dev",
        params={"id": id_b},
        headers=_admin_headers(),
        timeout=5,
    )
    assert resp.status_code == 200, resp.text

    all_envs = engine.list_all_environments()
    assert id_b not in all_envs
    assert id_a in all_envs


def test_http_share_with_environment_id_shares_only_that_owners_dev(live_server, tmp_schema, tmp_environments_file, fake_keyring):
    _, id_a = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    _, id_b = engine.upsert_environment(
        "dev", {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )

    resp = requests.post(
        f"{live_server}/api/environments/dev/share",
        json={"shared": True, "id": id_b},
        headers=_admin_headers(),
        timeout=5,
    )
    assert resp.status_code == 200, resp.text

    all_envs = engine.list_all_environments()
    assert all_envs[id_b]["shared"] is True
    assert all_envs[id_a].get("shared") in (False, None)
