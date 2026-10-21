"""5.50.0 HTTP behaviour of the Okta Admins report, cross-checks, snapshot and overview routes
(the authorization matrix covers who may reach them; this covers what they answer and audit)."""
import json
import time

import pytest
import requests

import audit_store
import create_secret_folders as engine
import okta_admins as oa
from test_http_authz_matrix import (ADMIN, OWNER_A, OWNER_B, REAL_JOB_BODIES, _call, _seed_owner_a_with_session, _who, matrix_server)  # noqa: F401,E402
from test_okta_admins_5500 import FakeOkta, REFUSED, StatusOkta, _err, _model  # noqa: E402


def _audit_actions(path):
    return [json.loads(line)["action"] for line in open(path, encoding="utf-8") if line.strip()]


def _wait_capture(serve, env_id):
    for _ in range(100):
        with serve._capture_jobs_lock:
            if (serve._capture_jobs.get(env_id) or {}).get("status") != "running":
                return serve._capture_jobs.get(env_id)
        time.sleep(0.05)
    raise AssertionError("capture did not finish")


def _put_model(serve, env_id, model):
    with serve._access_jobs_lock:
        serve._access_jobs[env_id] = {"status": "done", "steps": [], "error": None, "result": model}


def test_report_never_captured_then_after_a_capture(matrix_server, monkeypatch, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_capture_job", REAL_JOB_BODIES["capture"])
    monkeypatch.setattr(engine, "OktaClient", lambda url, tok: FakeOkta())
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A))
    assert r.status_code == 200 and r.json()["state"] == "never_captured" and r.json()["capture"]["status"] == "idle"
    started = _call(base_url, "POST", "/api/environments/dev/okta_snapshots/capture", {"kind": "okta_admins"}, _who(OWNER_A))
    assert started.json() == {"started": True, "already_running": False}
    assert _wait_capture(serve, env_id)["status"] == "done"
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A)).json()
    assert r["state"] == "ok" and r["summary"]["admins"] == 2 and r["capture"]["status"] == "done"
    actions = _audit_actions(tmp_audit_log)
    assert "okta_snapshot.captured" in actions and actions.count("okta_admins.report_read") == 2


def test_a_refused_token_gives_the_honest_message_over_http(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_capture_job", REAL_JOB_BODIES["capture"])
    monkeypatch.setattr(engine, "OktaClient", lambda url, tok: FakeOkta(fail={"assignees": REFUSED}))
    _call(base_url, "POST", "/api/environments/dev/okta_snapshots/capture", {"kind": "okta_admins"}, _who(OWNER_A))
    _wait_capture(serve, env_id)
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A)).json()
    assert r["state"] == "refused" and r["message"] == oa.MISSING_ROLES_MESSAGE and r["rows"] == []
    o = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(ADMIN, admin=True))
    # the admin does not own "dev" and it is private -> invisible by name; read it by id as the admin override
    assert o.status_code == 404
    o = _call(base_url, "GET", f"/api/overview?id={env_id}", headers=_who(ADMIN, admin=True)).json()
    assert o["okta_admins"]["state"] == "refused" and o["okta_admins"]["count"] is None


def test_capture_validation_and_missing_credentials(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_capture_job", REAL_JOB_BODIES["capture"])
    url = "/api/environments/dev/okta_snapshots/capture"
    assert _call(base_url, "POST", url, {"kind": "nope"}, _who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", url, {}, _who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", url, {"kind": ["okta_admins"]}, _who(OWNER_A)).status_code == 400
    with serve._access_jobs_lock:
        serve._access_jobs.pop(env_id)
    r = _call(base_url, "POST", url, {"kind": "opa_principal_status"}, _who(OWNER_A))
    assert r.status_code == 409 and r.json()["reason"] == "roster_not_loaded"
    engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
                                      "okta_url": "", "okta_api_token": ""}, owner=OWNER_A, environment_id=env_id)
    _call(base_url, "POST", url, {"kind": "okta_admins"}, _who(OWNER_A))
    job = _wait_capture(serve, env_id)
    assert job["status"] == "error" and "No Okta URL/API token" in job["error"]


def test_a_second_capture_while_one_runs_is_refused_not_queued(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    with serve._capture_jobs_lock:
        serve._capture_jobs[env_id] = {"status": "running", "kind": "okta_admins", "error": None, "finished_at": None}
    r = _call(base_url, "POST", "/api/environments/dev/okta_snapshots/capture", {"kind": "okta_admins"}, _who(OWNER_A))
    assert r.json() == {"started": False, "already_running": True}


def test_cross_check_flow_and_user_flags(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_capture_job", REAL_JOB_BODIES["capture"])
    monkeypatch.setattr(engine, "OktaClient", lambda url, tok: StatusOkta({"alex@example.com": "DEPROVISIONED", "sam@example.com": "ACTIVE", "00uSVC": "ACTIVE"}))
    _put_model(serve, env_id, _model())
    r = _call(base_url, "GET", "/api/environments/dev/cross_checks", headers=_who(OWNER_A)).json()
    assert r["cards"][0]["state"] == "never_run" and r["user_flags"]["users"] == {}
    _call(base_url, "POST", "/api/environments/dev/okta_snapshots/capture", {"kind": "opa_principal_status"}, _who(OWNER_A))
    _wait_capture(serve, env_id)
    r = _call(base_url, "GET", "/api/environments/dev/cross_checks", headers=_who(OWNER_A)).json()
    card = r["cards"][0]
    assert card["id"] == "C1" and card["counts"]["inactive_in_okta"] == 1 and card["rows"][0]["name"] == "alex@example.com"
    assert r["user_flags"]["users"]["ou1"]["flag"] == "inactive" and r["user_flags"]["users"]["ou2"]["flag"] is None


def test_report_uses_the_cached_opa_roster_for_separation_of_duties(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    oa.capture_and_store(env_id, FakeOkta())
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A)).json()
    assert r["separation_of_duties"]["overlaps"] == []  # the seeded roster has no admin roles
    with serve._access_jobs_lock:
        serve._access_jobs.pop(env_id)
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A)).json()
    assert r["separation_of_duties"]["state"] == "not_loaded"
    _put_model(serve, env_id, _model())
    r = _call(base_url, "GET", "/api/environments/dev/okta_admins", headers=_who(OWNER_A)).json()
    assert len(r["separation_of_duties"]["overlaps"]) == 1


def test_as_of_and_hostile_query_values(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    oa.capture_and_store(env_id, FakeOkta(), captured_at="2026-10-05T00:00:00.000Z")
    get = lambda q: _call(base_url, "GET", "/api/environments/dev/okta_admins" + q, headers=_who(OWNER_A))  # noqa: E731
    assert get("?as_of=2026-10-06").json()["state"] == "ok"
    assert get("?as_of=2026-10-04").json()["state"] == "no_snapshot_for_date"
    for bad in ("?as_of=garbage", "?as_of=2026-13-45", "?as_of=" + "9" * 5000):
        assert get(bad).status_code == 400


def test_snapshot_list_diff_and_export(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    a = oa.capture_and_store(env_id, FakeOkta(), captured_at="2026-10-01T00:00:00.000Z")
    b = oa.capture_and_store(env_id, FakeOkta(users=["00u1"]), captured_at="2026-10-02T00:00:00.000Z")
    base = "/api/environments/dev/config_snapshots"
    listed = _call(base_url, "GET", base, headers=_who(OWNER_A)).json()["snapshots"]
    assert [s["snapshot_id"] for s in listed] == [b["snapshot_id"], a["snapshot_id"]]
    assert _call(base_url, "GET", base + "?kind=nope%20bad", headers=_who(OWNER_A)).status_code == 400
    d = _call(base_url, "GET", f"{base}/diff?older={a['snapshot_id']}&newer={b['snapshot_id']}", headers=_who(OWNER_A)).json()
    assert [x["key"] for x in d["removed"]] == ["user:00u2"] and d["added"] == []
    assert _call(base_url, "GET", f"{base}/diff?older=x&newer=1", headers=_who(OWNER_A)).status_code == 400
    assert _call(base_url, "GET", f"{base}/diff?older=999&newer=998", headers=_who(OWNER_A)).status_code == 404
    e = _call(base_url, "GET", f"{base}/export?snapshot_id={a['snapshot_id']}", headers=_who(OWNER_A)).json()
    assert e["verification"]["valid"] and e["sha256"] == a["sha256"] and "credentials" not in json.dumps(e)
    assert _call(base_url, "GET", f"{base}/export?snapshot_id=999", headers=_who(OWNER_A)).status_code == 404
    assert "config_snapshot.exported" in _audit_actions(tmp_audit_log)


def test_a_snapshot_of_another_environment_is_never_served(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _, other_id = engine.upsert_environment("mine", {"base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=OWNER_A)
    foreign = audit_store.record_config_snapshot(other_id, "okta_admins", [("user:x", {"id": "x"})])
    own = oa.capture_and_store(env_id, FakeOkta())
    base = "/api/environments/dev/config_snapshots"
    assert _call(base_url, "GET", f"{base}/export?snapshot_id={foreign['snapshot_id']}", headers=_who(OWNER_A)).status_code == 404
    assert _call(base_url, "GET", f"{base}/diff?older={own['snapshot_id']}&newer={foreign['snapshot_id']}", headers=_who(OWNER_A)).status_code == 404


def test_export_log_validation_and_audit(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    url = "/api/environments/dev/okta_admins/export_log"
    assert _call(base_url, "POST", url, {"format": "pdf"}, _who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", url, {"format": "md", "as_of": 5}, _who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", url, {"format": "md", "as_of": "2026-10-01"}, _who(OWNER_A)).json() == {"logged": True}
    entry = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()][-1]
    assert entry["action"] == "okta_admins.report_exported" and entry["details"]["format"] == "md"


def test_overview_is_admin_only_counts_only_and_audited(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    _put_model(serve, env_id, _model())
    oa.capture_and_store(env_id, FakeOkta())
    assert _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(OWNER_A)).status_code == 403  # the owner is not an admin
    r = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(ADMIN, admin=True))
    assert r.status_code == 200
    o = r.json()
    assert o["okta_admins"]["count"] == 2 and o["sod_overlaps"]["count"] == 1 and o["opa_privileged_users"]["count"] == 1
    assert o["opa_service_accounts"]["count"] == 1 and o["archive"]["chain"]["valid"] is True
    assert "alex@example.com" not in r.text  # counts only
    assert _call(base_url, "GET", "/api/overview?env=dev", headers=_who(ADMIN, admin=True)).status_code == 200  # alias
    assert _call(base_url, "GET", "/api/overview?environment=dev&as_of=garbage", headers=_who(ADMIN, admin=True)).status_code == 400
    assert _call(base_url, "GET", "/api/overview?environment=nope", headers=_who(ADMIN, admin=True)).status_code == 404
    assert _call(base_url, "GET", "/api/overview?id=00000000-0000-0000-0000-000000000000", headers=_who(ADMIN, admin=True)).status_code == 404
    assert "overview.read" in _audit_actions(tmp_audit_log)


def test_overview_explicit_id_is_still_admin_only(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    assert _call(base_url, "GET", f"/api/overview?id={env_id}", headers=_who(OWNER_B)).status_code == 403
    assert _call(base_url, "GET", f"/api/overview?id={env_id}", headers=_who(OWNER_A)).status_code == 403


def test_sync_job_takes_a_snapshot_after_the_sync_and_never_fails_because_of_it(tmp_audit_store, tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
    import server.serve as serve
    audit_store.run_migrations()
    _, env = engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"})

    class Sync(FakeOkta):
        def get_system_log(self, **k):
            return [], True

        def get_system_log_page(self, path):
            return [], None
    serve._run_sync_job(env, "dev", Sync(), "all", engine.LOCAL_OWNER_KEY)
    assert serve._sync_jobs[env]["status"] == "done"
    assert audit_store.list_config_snapshots(env, kind="okta_admins")[0]["status"] == "ok"
    # a second sync inside the minimum interval does not hit Okta's role endpoints again
    fake = Sync()
    serve._run_sync_job(env, "dev", fake, "all", engine.LOCAL_OWNER_KEY)
    assert not [c for c in fake.calls if c[0] == "assignees"] and len(audit_store.list_config_snapshots(env, kind="okta_admins")) == 1
    # and a snapshot that blows up leaves the sync "done"
    monkeypatch.setattr(oa, "capture_if_due", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    serve._run_sync_job(env, "dev", Sync(), "all", engine.LOCAL_OWNER_KEY)
    assert serve._sync_jobs[env]["status"] == "done"
