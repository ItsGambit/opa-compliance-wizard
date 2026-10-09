"""Server-side pieces of review batch 5 (frontend), 2026-10-05 review.

- UI-07: GET /api/environments reports `active_id` and, per row,
  `addressable` (the row's NAME resolves to that row for the caller), and
  POST .../activate refuses (409) when the id the UI clicked is no longer
  what the name resolves to.
- UI-10: POST /api/access/bootstrap/start returns the step list with
  already_running too.
- FE-04: _start_sync_job claims the job slot under the lock before the
  worker starts (no double start, no stale "done" for the first poll), and
  never leaves the slot "running" if starting fails.
"""
import pytest

import create_secret_folders as engine
from tests.test_http_authz_matrix import (  # noqa: F401  (fixture re-export)
    ADMIN, OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server,
)

CREDS = {"base_domain": "x.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}


def _envs(base_url, sub, admin=False):
    resp = _call(base_url, "GET", "/api/environments", headers=_who(sub, admin))
    assert resp.status_code == 200
    return resp.json()


def test_environment_list_reports_active_id_and_addressable_rows(matrix_server):
    base_url, serve = matrix_server
    a_env = _seed_owner_a_with_session(serve)                     # A's private "dev" + live session
    _, b_dev = engine.upsert_environment("dev", dict(CREDS), owner=OWNER_B)
    _, admin_dev = engine.upsert_environment("dev", dict(CREDS), owner=ADMIN)

    body = _envs(base_url, OWNER_A)
    assert body["active"] == "dev" and body["active_id"] == a_env
    assert [(e["id"], e["addressable"]) for e in body["environments"]] == [(a_env, True)]

    admin_view = {e["id"]: e for e in _envs(base_url, ADMIN, admin=True)["environments"]}
    assert set(admin_view) == {a_env, b_dev, admin_dev}
    assert admin_view[admin_dev]["addressable"] is True        # the admin's own "dev"
    assert admin_view[a_env]["addressable"] is False           # another owner's private "dev"
    assert admin_view[b_dev]["addressable"] is False
    assert _envs(base_url, ADMIN, admin=True)["active_id"] is None


def test_shared_row_shadowed_by_own_same_name_is_not_addressable(matrix_server):
    base_url, serve = matrix_server
    _, shared_id = engine.upsert_environment("team", dict(CREDS), owner=OWNER_B)
    engine.set_environment_shared("team", OWNER_B, True)
    body = {e["id"]: e for e in _envs(base_url, OWNER_A)["environments"]}
    assert body[shared_id]["addressable"] is True
    _, own_id = engine.upsert_environment("team", dict(CREDS), owner=ADMIN)
    admin_view = {e["id"]: e for e in _envs(base_url, ADMIN, admin=True)["environments"]}
    assert admin_view[own_id]["addressable"] is True
    assert admin_view[shared_id]["addressable"] is False       # hidden behind the admin's own "team"


def test_activate_refuses_when_the_name_now_resolves_elsewhere(matrix_server):
    base_url, serve = matrix_server
    _, shared_id = engine.upsert_environment("team", dict(CREDS), owner=OWNER_B)
    engine.set_environment_shared("team", OWNER_B, True)
    _, own_id = engine.upsert_environment("team", dict(CREDS), owner=OWNER_A)
    # The UI still shows B's shared row (stale list) -- by name it is A's own now.
    resp = _call(base_url, "POST", "/api/environments/team/activate", {"id": shared_id}, headers=_who(OWNER_A))
    assert resp.status_code == 409
    with serve._sessions_lock:
        assert OWNER_A not in serve._sessions                  # nothing was activated
    resp = _call(base_url, "POST", "/api/environments/team/activate", {"id": own_id}, headers=_who(OWNER_A))
    assert resp.status_code == 200
    with serve._sessions_lock:
        assert serve._sessions[OWNER_A]["env_id"] == own_id
    assert engine.get_active_environment_id(OWNER_A) == own_id     # pointer stored as that id


def test_activate_id_must_be_a_string_and_visible(matrix_server):
    base_url, serve = matrix_server
    engine.upsert_environment("dev", dict(CREDS), owner=OWNER_A)
    assert _call(base_url, "POST", "/api/environments/dev/activate", {"id": 5}, headers=_who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", "/api/environments/nope/activate", {"id": "x"}, headers=_who(OWNER_A)).status_code == 404
    # No id: the old by-name behaviour is unchanged.
    assert _call(base_url, "POST", "/api/environments/dev/activate", {}, headers=_who(OWNER_A)).status_code == 200


def test_bootstrap_already_running_still_returns_the_steps(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    with serve._access_jobs_lock:
        serve._access_jobs[env_id] = {"status": "running", "steps": [], "error": None, "result": None}
    body = _call(base_url, "POST", "/api/access/bootstrap/start", {}, headers=_who(OWNER_A)).json()
    assert body["already_running"] is True and body["started"] is False
    assert body["steps"] == [list(s) for s in engine.ACCESS_MODEL_STEPS]


def test_sync_start_claims_the_slot_before_the_worker_runs(matrix_server):
    _base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    with serve._sync_jobs_lock:
        serve._sync_jobs[env_id] = {"status": "done", "steps": [{"key": "old"}], "error": None, "result": {"inserted": 9}}
    # The worker body is stubbed by the fixture (it never sets "running"),
    # so whatever status is there now was set by _start_sync_job itself.
    assert serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A) is True
    with serve._sync_jobs_lock:
        job = dict(serve._sync_jobs[env_id])
    assert job["status"] == "running" and job["steps"] == []    # never the previous run's "done"
    assert serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A) is False


def test_sync_start_failure_never_leaves_the_slot_running(matrix_server, monkeypatch):
    _base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)

    def boom(*a, **k):
        raise RuntimeError("client construction failed")
    monkeypatch.setattr(engine, "OktaClient", boom)
    with pytest.raises(RuntimeError):
        serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A)
    with serve._sync_jobs_lock:
        assert serve._sync_jobs[env_id]["status"] == "error"
    # The slot is free again: a later start is not refused as "already running".
    monkeypatch.setattr(engine, "OktaClient", lambda *a, **k: object())
    assert serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A) is True


def test_activate_by_id_uses_exactly_that_id(matrix_server, monkeypatch):
    """Review round 1, finding 10: after the check, the route activates the
    checked id itself -- it never resolves the name a second time."""
    base_url, serve = matrix_server
    _, own_id = engine.upsert_environment("dev", dict(CREDS), owner=OWNER_A)
    calls = []
    real = serve.activate_environment
    monkeypatch.setattr(serve, "activate_environment", lambda owner, name, environment_id=None: (calls.append((name, environment_id)), real(owner, name, environment_id=environment_id))[1])
    assert _call(base_url, "POST", "/api/environments/dev/activate", {"id": own_id}, headers=_who(OWNER_A)).status_code == 200
    assert calls == [(None, own_id)]


def test_set_active_environment_id_requires_visibility(matrix_server):
    _base_url, _serve = matrix_server
    _, b_private = engine.upsert_environment("secret", dict(CREDS), owner=OWNER_B)
    with pytest.raises(KeyError):
        engine.set_active_environment_id(OWNER_A, b_private)
    engine.set_environment_shared("secret", OWNER_B, True)
    engine.set_active_environment_id(OWNER_A, b_private)
    assert engine.get_active_environment_id(OWNER_A) == b_private


def test_activate_by_id_restores_the_previous_session_if_the_pointer_write_is_refused(matrix_server, monkeypatch):
    """Review round 2: unshared between the check and the pointer write ->
    404, and the caller's session is what it was before."""
    base_url, serve = matrix_server
    a_env = _seed_owner_a_with_session(serve)                      # A is on "dev"
    _, shared_id = engine.upsert_environment("team", dict(CREDS), owner=OWNER_B)
    engine.set_environment_shared("team", OWNER_B, True)

    def refuse(owner, environment_id):
        raise KeyError("unshared meanwhile")
    monkeypatch.setattr(engine, "set_active_environment_id", refuse)
    resp = _call(base_url, "POST", "/api/environments/team/activate", {"id": shared_id}, headers=_who(OWNER_A))
    assert resp.status_code == 404
    with serve._sessions_lock:
        assert serve._sessions[OWNER_A]["env_id"] == a_env
