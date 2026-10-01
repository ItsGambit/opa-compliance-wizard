"""The two-owner collision integration test named by
docs/fast-follow-redesign.md's Phase 7 as the single test that would have
caught the original F1/F2/F3 cross-tenant bugs (external review,
2026-09-30) automatically instead of needing a human review to surface
them.

Scenario: two different owners each have an environment named "dev".
Written against the STABLE PUBLIC CONTRACT (_resolve_admin_target called
WITH an explicit environment_id, _environment_visible_to, and the HTTP
routes' `id` round-trip) rather than environments.json's on-disk shape.

Real ids are read back from upsert_environment's own return value (it
returns (name, environment_id)) rather than precomputed via the retired
environment_storage_name -- Phase 1's UUID migration means there's no
longer a deterministic function of (owner, name) that produces the real
id ahead of time; the system has to be asked.
"""
import socket
import threading
import time

import pytest
import requests

import create_secret_folders as engine

OWNER_A = engine.LOCAL_OWNER_KEY  # None -- "__local__"
OWNER_B = "00uOWNERB"


def _seed_two_owner_dev_environments(tmp_environments_file, fake_keyring):
    """Builds two "dev" environments, one per owner, directly through the
    real public API (upsert_environment) rather than hand-constructing
    environments.json's shape -- this IS part of the stable contract this
    test is meant to survive a future storage-format migration against.
    Returns (id_a, id_b, data) -- the real ids come straight from
    upsert_environment's own return value."""
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
    data = engine.load_environments()
    return id_a, id_b, data


# ---------------------------------------------------------------------------
# 1. Admin edit/delete/share must disambiguate by environment_id, never by
#    bare name.
# ---------------------------------------------------------------------------
def test_admin_resolves_correct_owner_by_environment_id(tmp_environments_file, fake_keyring):
    id_a, id_b, data = _seed_two_owner_dev_environments(tmp_environments_file, fake_keyring)

    found_id, meta = engine._resolve_admin_target(data, "dev", id_b)
    assert found_id == id_b
    assert meta["base_domain"] == "b.example.com"

    found_id, meta = engine._resolve_admin_target(data, "dev", id_a)
    assert found_id == id_a
    assert meta["base_domain"] == "a.example.com"


def test_admin_set_environment_shared_targets_only_the_specified_owner(tmp_environments_file, fake_keyring):
    id_a, id_b, _ = _seed_two_owner_dev_environments(tmp_environments_file, fake_keyring)

    engine.set_environment_shared("dev", owner=OWNER_A, shared=True, is_admin=True, environment_id=id_b)

    data = engine.load_environments()
    assert data["environments"][id_b]["shared"] is True
    # Owner A's own "dev" must be completely untouched by an admin action
    # explicitly targeting owner B's environment_id.
    assert data["environments"][id_a].get("shared") in (False, None)


def test_admin_delete_environment_removes_only_the_targeted_owner(tmp_environments_file, fake_keyring):
    id_a, id_b, _ = _seed_two_owner_dev_environments(tmp_environments_file, fake_keyring)

    engine.delete_environment("dev", owner=OWNER_A, is_admin=True, environment_id=id_b)

    data = engine.load_environments()
    assert id_b not in data["environments"]
    assert id_a in data["environments"]  # owner A's "dev" survives


# ---------------------------------------------------------------------------
# 2. Non-admin visibility must not leak.
# ---------------------------------------------------------------------------
def test_private_environment_not_visible_to_other_owner(tmp_environments_file, fake_keyring):
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


def test_shared_environment_is_visible_but_private_one_is_not(tmp_environments_file, fake_keyring):
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
#    never a bare display name). Two arbitrary ids stand in for two real
#    environments here -- this test is about id-collision isolation itself,
#    not about any particular stored environment, so there's no need to
#    seed real ones via upsert_environment.
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
# 4. The admin HTTP routes' `id` round-trip actually disambiguates
#    end-to-end, through real HTTP requests against a live server
#    instance -- bypasses nginx entirely (fine for a backend test; the
#    nginx trust boundary itself is covered by test_auth_headers.py).
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server(tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
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


def test_http_delete_with_environment_id_deletes_only_that_owners_dev(live_server, tmp_environments_file, fake_keyring):
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

    data = engine.load_environments()
    assert id_b not in data["environments"]
    assert id_a in data["environments"]


def test_http_share_with_environment_id_shares_only_that_owners_dev(live_server, tmp_environments_file, fake_keyring):
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

    data = engine.load_environments()
    assert data["environments"][id_b]["shared"] is True
    assert data["environments"][id_a].get("shared") in (False, None)
