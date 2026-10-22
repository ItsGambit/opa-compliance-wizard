"""5.51.0 (work package A2): the combined Refresh. One job per environment, three independently reported parts (OPA scan,
Okta scan, System Log sync) in two lanes. Covers coalescing, adopting a sync that already runs, cancel checkpoints, part
deadlines, partial failure, the cadence gates, purge on delete, restart behaviour, privacy of the audit entries, and the
route-level permission rules. Every identity here is a placeholder; nothing touches a network."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine
import okta_admins as oa
import server.refresh_jobs as rj
from test_http_authz_matrix import (ADMIN, OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server)  # noqa: F401,E402
from test_okta_admins_5500 import FakeOkta, REFUSED, _err, _model  # noqa: E402

FIXTURE_NAME = "Alexandra Example"
FIXTURE_EMAIL = "alexandra@example.com"
FIXTURE_TEAM = "fixture-team-name"


def _ts(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(uuid, minutes_ago):
    return {"uuid": uuid, "eventType": "user.session.start", "published": _ts(minutes_ago), "actor": {"id": "00u1"},
            "outcome": {"result": "SUCCESS"}, "target": []}


class SyncOkta(FakeOkta):
    """Okta stand-in: an empty, complete System Log; countable objects; user lookups through FakeOkta."""

    def get_system_log(self, **k):
        return [], True

    def get_system_log_page(self, path):
        return [], None

    def count_okta_objects(self, kind, policy_type=None, max_items=50000):
        return 5, False


def _default_builder(client, okta_client=None, on_progress=None):
    for key in ("resource_groups", "projects", "users", "policies"):
        on_progress(key, "start", None)
        on_progress(key, "done", "1 read")
    model = _model()
    model["users"][0]["name"] = FIXTURE_NAME
    model["users"][0]["details"]["email"] = FIXTURE_EMAIL
    model.update(projects=[], policies=[], servers=[], devices=[], warnings=[], inventory_totals={"secret_folders": 1, "secrets": 2})
    return model


class _NoNetwork:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        def call(*a, **k):
            raise engine.OpaApiError(599, name, "no network in tests")
        return call


class Rig:
    def __init__(self, serve, env_id, monkeypatch):
        self.serve, self.env, self.monkeypatch = serve, env_id, monkeypatch
        self.okta = SyncOkta()
        self.builder = _default_builder
        monkeypatch.setattr(engine, "OpaClient", _NoNetwork)
        monkeypatch.setattr(engine, "OktaClient", lambda *a, **k: self.okta)
        monkeypatch.setattr(engine, "build_access_model", lambda *a, **k: self.builder(*a, **k))
        monkeypatch.setattr(serve, "REFRESH_ADOPT_POLL_SECS", 0.05)
        monkeypatch.setattr(serve, "REFRESH_SUPERVISE_POLL_SECS", 0.05)

    def start(self, parts=None, trigger="manual", env=None, name="dev", **kw):
        return self.serve._start_refresh_job(env or self.env, name, parts=parts, trigger=trigger, **kw)

    def job(self, env=None):
        return self.serve._refresh_jobs[env or self.env]

    def wait(self, env=None, timeout=30):
        job = self.job(env)
        end = time.monotonic() + timeout
        while job.status == "running" and time.monotonic() < end:
            time.sleep(0.02)
        assert job.status == "done", job.status_view()
        return job

    def run(self, parts=None, trigger="manual", **kw):
        out = self.start(parts, trigger, **kw)
        assert out["started"], out
        return self.wait()

    def audit(self, tmp_audit_log):
        return [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]


@pytest.fixture
def rig(tmp_audit_store, tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
    import server.serve as serve
    audit_store.run_migrations()
    _, env = engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": FIXTURE_TEAM, "key_id": "k", "key_secret": "s",
                                               "okta_url": "https://example.okta.com", "okta_api_token": "t"})
    r = Rig(serve, env, monkeypatch)
    yield r
    for job in list(serve._refresh_jobs.values()):
        job.request_cancel()
    end = time.monotonic() + 10
    while any(j.status == "running" for j in serve._refresh_jobs.values()) and time.monotonic() < end:
        time.sleep(0.05)
    for d, lock in ((serve._refresh_jobs, serve._refresh_jobs_lock), (serve._access_jobs, serve._access_jobs_lock),
                    (serve._sync_jobs, serve._sync_jobs_lock), (serve._capture_jobs, serve._capture_jobs_lock)):
        with lock:
            d.clear()


def _blocking_builder(release, started=None, checkpoints=True):
    """A scan that waits until `release` is set (checking for a stop, as the real walkers do), then returns a model."""
    def build(client, okta_client=None, on_progress=None):
        on_progress("projects", "start", None)
        if started is not None:
            started.set()
        while not release.is_set():
            if checkpoints:
                engine.checkpoint()
            time.sleep(0.01)
        return _default_builder(client, okta_client, on_progress)
    return build


# -- the happy path ----------------------------------------------------------------------------------------------------
def test_a_full_refresh_runs_three_parts_stores_the_scan_and_reports_each(rig, tmp_audit_log):
    job = rig.run()
    view = job.status_view()
    assert {p: view["parts"][p]["state"] for p in rj.PARTS} == {"opa": "ok", "okta": "ok", "log": "ok"}
    assert view["summary"] == "3 of 3 parts completed."
    assert audit_store.opa_model_cache_info(rig.env)["built_at"]
    assert {k: v["state"] for k, v in view["parts"]["okta"]["sub"].items()} == {
        "admins": "ok", "principal_status": "ok", "inventory": "ok", "mfa_aggregates": "ok"}
    assert audit_store.list_config_snapshots(rig.env, kind="opa_principal_status")  # principal status is part of every refresh
    actions = [r["action"] for r in rig.audit(tmp_audit_log)]
    assert "refresh.started" in actions and "refresh.completed" in actions and "access_scan.completed" in actions


def test_the_audit_entries_of_a_refresh_carry_no_names_emails_hosts_or_urls(rig, tmp_audit_log):
    rig.run()
    raw = open(tmp_audit_log, encoding="utf-8").read()
    for needle in (FIXTURE_NAME, FIXTURE_EMAIL, FIXTURE_TEAM, "example.okta.com", "a.example.com", "http://", "https://"):
        assert needle not in raw, needle
    # and a failing refresh does not leak them either
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(503, f"https://{FIXTURE_TEAM}.example.com/v1/x", f"body {FIXTURE_EMAIL}"))
    rig.run(["opa"])
    raw = open(tmp_audit_log, encoding="utf-8").read()
    for needle in (FIXTURE_NAME, FIXTURE_EMAIL, FIXTURE_TEAM, "https://"):
        assert needle not in raw, needle


# -- concurrency -------------------------------------------------------------------------------------------------------
def test_two_requests_in_the_same_tick_make_one_job_and_the_second_attaches(rig):
    release, started = threading.Event(), threading.Event()
    rig.builder = _blocking_builder(release, started)
    results = []
    barrier = threading.Barrier(2)

    def go():
        barrier.wait()
        results.append(rig.start(["opa"]))
    threads = [threading.Thread(target=go) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(r["started"] for r in results) == [False, True]
    assert len({r["job_id"] for r in results}) == 1
    attached = next(r for r in results if not r["started"])
    assert attached["already_running"] is True
    release.set()
    rig.wait()


def test_different_environments_run_independently_and_same_named_environments_never_share_a_job(rig):
    release, started = threading.Event(), threading.Event()
    rig.builder = _blocking_builder(release, started)
    _, other = engine.upsert_environment("dev", {"base_domain": "b.example.com", "team_name": "t2", "key_id": "k", "key_secret": "s",
                                                 "okta_url": "https://other.example.okta.com", "okta_api_token": "t"}, owner="00uOTHEROWNER")
    assert other != rig.env
    a = rig.start(["opa"])
    b = rig.start(["opa"], env=other)
    assert a["started"] and b["started"] and a["job_id"] != b["job_id"]
    release.set()
    rig.wait()
    rig.wait(env=other)


def test_a_refresh_with_the_log_part_adopts_a_sync_that_already_runs_and_reports_its_outcome(rig):
    serve = rig.serve
    with serve._sync_jobs_lock:
        serve._sync_jobs[rig.env] = {"status": "running", "steps": [], "error": None}
    out = rig.start(["log"])
    assert out["started"]
    time.sleep(0.4)
    assert rig.job().part_state("log") == "running"  # waiting for the other run, not racing it
    with serve._sync_jobs_lock:
        serve._sync_jobs[rig.env] = {"status": "done", "steps": [], "error": None, "result": {"inserted": 7, "mode": "polling"}}
    job = rig.wait()
    data = job.status_view()["parts"]["log"]
    assert data["state"] == "ok" and data["events_new"] == 7 and data.get("adopted") is True


def test_a_scheduled_tick_during_a_refresh_is_skipped_and_audited(rig, tmp_audit_log):
    release, started = threading.Event(), threading.Event()
    rig.builder = _blocking_builder(release, started)
    assert rig.start(["opa"])["started"]
    again = rig.start(parts=list(rj.PARTS), trigger="scheduled")
    assert again["started"] is False and again["already_running"] is True
    release.set()
    rig.wait()
    skipped = [r for r in rig.audit(tmp_audit_log) if r["action"] == "sync.scheduled_skipped"]
    assert skipped and skipped[0]["details"]["reason"] == "a refresh of OPA scan is running"  # the schedule tries again at its next poll


def test_the_log_part_records_the_day_as_done_once(rig):
    rig.run(["log"], trigger="scheduled")
    state = audit_store.get_sync_state(rig.env)
    assert state["last_sync_completed_at"] and state["last_sync_status"] == "success"
    first = state["last_sync_completed_at"]
    assert first[:10] == datetime.now(timezone.utc).strftime("%Y-%m-%d")


def test_a_bootstrap_started_from_an_older_tab_during_a_refresh_attaches(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    job = rj.RefreshJob(env_id, ["opa"], "manual")
    with serve._refresh_jobs_lock:
        serve._refresh_jobs[env_id] = job  # a refresh in flight
    with serve._access_jobs_lock:
        serve._access_jobs[env_id]["status"] = "running"
    resp = _call(base_url, "POST", "/api/access/bootstrap/start", {}, _who(OWNER_A))
    assert resp.status_code == 200 and resp.json()["already_running"] is True and resp.json()["steps"]
    with serve._access_jobs_lock:
        serve._access_jobs[env_id]["status"] = "done"
    resp = _call(base_url, "POST", "/api/access/bootstrap/start", {}, _who(OWNER_A))
    assert resp.status_code == 200 and resp.json()["already_running"] is True and resp.json()["started"] is False  # the job record says running
    with serve._refresh_jobs_lock:
        serve._refresh_jobs.pop(env_id, None)


def test_an_upgrade_starting_refuses_a_new_refresh_with_a_message(rig, monkeypatch):
    monkeypatch.setattr(rig.serve.upgrade_service, "quiesced", lambda: True)
    out = rig.start()
    assert out["started"] is False and out["upgrade_starting"] is True
    assert rig.env not in rig.serve._refresh_jobs


# -- cancel and deadlines ----------------------------------------------------------------------------------------------
def test_a_stop_ends_the_scan_at_the_next_checkpoint_and_leaves_the_previous_scan_untouched(rig):
    rig.run(["opa"])
    before = audit_store.opa_model_cache_info(rig.env)
    indexed = []

    def build(client, okta_client=None, on_progress=None):
        for i in range(50):
            engine.checkpoint()  # between projects
            indexed.append(i)
            if i == 2:
                rig.job().request_cancel()
            time.sleep(0.005)
        return _default_builder(client, okta_client, on_progress)
    rig.builder = build
    job = rig.run(["opa"])
    assert job.part_state("opa") == "cancelled" and len(indexed) < 10
    after = audit_store.opa_model_cache_info(rig.env)
    assert after["built_at"] == before["built_at"]  # the stored scan is still the earlier one
    assert "still shown and stored" in job.status_view()["parts"]["opa"]["message"]


def test_a_stop_during_the_log_part_leaves_the_cursor_saved_and_the_run_partial(rig, tmp_audit_log, monkeypatch):
    conn = audit_store._get_connection()
    cursor = "/api/v1/logs?after=c1&limit=1000&sortOrder=ASCENDING&since=x"
    audit_store._upsert_sync_state(conn, rig.env, last_synced_at=_ts(30), last_sync_completed_at=_ts(30), last_sync_status="success",
                                   ingestion_scope="all", poll_cursor=cursor)

    class Pages(SyncOkta):
        def get_system_log_page(self, path):
            rig.job().request_cancel()  # the stop arrives while the first page is being read
            return [_event("p1", 5)], "/api/v1/logs?after=c2&limit=1000&sortOrder=ASCENDING&since=x"
    rig.okta = Pages()
    job = rig.run(["log"])
    data = job.status_view()["parts"]["log"]
    assert data["state"] == "cancelled" and "the next run continues from there" in data["message"]
    # F1: a user's Stop is not a failure: audited as cancelled, status not "error" (so no back-off, no banner)
    state = audit_store.get_sync_state(rig.env)
    assert state["last_sync_status"] == "cancelled" and state["last_sync_error"] is None
    actions = [r["action"] for r in rig.audit(tmp_audit_log)]
    assert "sync.manual_cancelled" in actions and "sync.manual_failed" not in actions
    started = []
    monkeypatch.setattr(rig.serve, "_start_refresh_job", lambda *a, **k: started.append(a))
    audit_store._upsert_sync_state(audit_store._get_connection(), rig.env, last_sync_completed_at=_ts(25 * 60))  # yesterday: a run is due
    monkeypatch.setattr(engine, "get_sync_schedule_by_id", lambda env_id: {"enabled": True, "run_time": "00:00"})
    rig.serve._scheduler_tick(datetime.now(timezone.utc))
    assert len(started) == 1  # a stop does not arm the scheduler's retry back-off
    banner = oa.build_overview(rig.env)["attention"]
    assert not [a for a in banner if a["kind"] == "sync" and "failed" in a["text"]]
    stored = audit_store._get_connection().execute("SELECT poll_cursor FROM sync_state WHERE environment_id = ?", (rig.env,)).fetchone()[0]
    assert "after=c2" in stored  # progress saved
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM events WHERE environment_id = ?", (rig.env,)).fetchone()[0] == 1


def test_a_part_over_its_deadline_is_timed_out_the_job_completes_and_the_previous_scan_stays(rig, monkeypatch):
    rig.run(["opa"])
    before = audit_store.opa_model_cache_info(rig.env)["built_at"]
    monkeypatch.setitem(rj.PART_DEADLINES_SECS, "opa", 0.3)
    monkeypatch.setattr(rj, "KILL_GRACE_SECS", 0.2)
    release = threading.Event()
    rig.builder = _blocking_builder(release)  # never finishes by itself, but stops at its checkpoint
    job = rig.run(["opa"])
    data = job.status_view()["parts"]["opa"]
    assert data["state"] == "timed_out" and "previous data is kept" in data["message"]
    release.set()
    time.sleep(0.3)
    assert audit_store.opa_model_cache_info(rig.env)["built_at"] == before


def test_deleting_the_environment_cancels_the_refresh_and_waits_for_the_parts_to_stop(rig):
    release, started = threading.Event(), threading.Event()
    rig.builder = _blocking_builder(release, started)
    assert rig.start()["started"]
    assert started.wait(10)
    assert rig.serve._refresh_running(rig.env)
    assert rig.serve._cancel_refresh_and_wait(rig.env, timeout=15) is True
    assert not rig.serve._refresh_running(rig.env)
    assert audit_store.opa_model_cache_info(rig.env) is None  # nothing was stored by the stopped scan
    rig.serve._forget_environment_jobs(rig.env)
    assert rig.env not in rig.serve._refresh_jobs and rig.env not in rig.serve._access_jobs


def test_a_restart_loses_the_job_records_but_the_stored_scan_serves_the_explorer_and_the_overview(rig):
    serve = rig.serve
    rig.run(["opa"])
    for d, lock in ((serve._refresh_jobs, serve._refresh_jobs_lock), (serve._access_jobs, serve._access_jobs_lock)):
        with lock:
            d.clear()  # a new process: nothing in memory
    view = serve._access_model_view(rig.env)
    assert view["source"] == "cache" and view["model"]["users"]
    payload = serve._access_model_payload(view)
    assert payload["source"] == "cache" and "model_zlib" not in json.dumps(payload) and payload["counts"]["users"] == 3


# -- partial failure ---------------------------------------------------------------------------------------------------
def test_opa_refused_while_okta_and_log_succeed_keeps_the_others_and_says_why(rig):
    rig.run(["opa"])
    before = audit_store.opa_model_cache_info(rig.env)["built_at"]
    rig.builder = lambda client, okta_client=None, on_progress=None: (
        on_progress("projects", "start", None), (_ for _ in ()).throw(engine.OpaApiError(403, "https://x.example.com/p", "denied")))[1]
    job = rig.run()
    view = job.status_view()
    assert view["parts"]["opa"]["state"] == "refused"
    assert "HTTP 403" in view["parts"]["opa"]["message"] and "listing projects" in view["parts"]["opa"]["message"]
    assert "Nothing was changed: the scan from" in view["parts"]["opa"]["message"] and "To fix:" in view["parts"]["opa"]["message"] and "https://" not in view["parts"]["opa"]["message"]
    assert view["parts"]["log"]["state"] == "ok" and view["parts"]["okta"]["state"] == "ok"
    sub = view["parts"]["okta"]["sub"]
    assert sub["principal_status"]["state"] == "skipped" and "OPA scan did not finish" in sub["principal_status"]["message"]
    assert sub["principal_status"]["message"].endswith("It runs with the next refresh.")
    assert "OPA counts are missing" in sub["inventory"]["message"]
    items = {i["key"] for i in audit_store.get_config_snapshot(
        rig.env, audit_store.list_config_snapshots(rig.env, kind="inventory_counts")[0]["snapshot_id"])["items"]}
    assert "okta.users" in items and not any(k.startswith("opa.") for k in items)  # Okta side only, never a zero
    assert audit_store.opa_model_cache_info(rig.env)["built_at"] == before
    assert view["summary"] == "2 of 3 parts completed; OPA scan refused."


def test_okta_admin_roles_refused_seals_one_refused_snapshot_and_the_other_subparts_finish(rig):
    rig.okta = type("Refusing", (SyncOkta,), {})(fail={"assignees": REFUSED})
    job = rig.run(["okta"])
    view = job.status_view()
    assert view["parts"]["okta"]["state"] == "refused" and view["parts"]["okta"]["message"] == oa.MISSING_ROLES_MESSAGE
    sub = view["parts"]["okta"]["sub"]
    assert sub["admins"]["state"] == "refused" and sub["inventory"]["state"] == "ok" and sub["mfa_aggregates"]["state"] == "ok"
    snaps = audit_store.list_config_snapshots(rig.env, kind="okta_admins")
    assert len(snaps) == 1 and snaps[0]["status"] == "refused"


def test_a_system_log_refusal_is_reported_and_the_archive_and_other_parts_are_unaffected(rig):
    class Refused(SyncOkta):
        def get_system_log(self, **k):
            raise _err(403, "E0000006", "no")
    rig.okta = Refused()
    job = rig.run()
    view = job.status_view()
    assert view["parts"]["log"]["state"] == "refused" and "HTTP 403" in view["parts"]["log"]["message"]
    assert "https://" not in view["parts"]["log"]["message"]
    assert view["parts"]["opa"]["state"] == "ok" and view["parts"]["okta"]["state"] == "ok"
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM events WHERE environment_id = ?", (rig.env,)).fetchone()[0] == 0


def test_optional_section_warnings_leave_the_scan_ok_with_a_count_and_absent_counts_stay_absent(rig):
    def build(client, okta_client=None, on_progress=None):
        model = _default_builder(client, okta_client, on_progress)
        model["warnings"] = [{"section": "gateways", "status": 404, "message": "gateways could not be read"},
                             {"section": "database accounts", "status": 403, "message": "database accounts could not be read"}]
        return model
    rig.builder = build
    job = rig.run(["opa"])
    data = job.status_view()["parts"]["opa"]
    assert data["state"] == "ok" and data["warnings"] == 2 and "2 sections the key cannot read" in data["message"]
    assert audit_store.opa_model_cache_info(rig.env)["warnings_count"] == 2


def test_a_credential_shaped_value_fails_the_scan_nothing_is_stored_and_the_audit_names_only_the_key_path(rig, tmp_audit_log):
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"

    def build(client, okta_client=None, on_progress=None):
        model = _default_builder(client, okta_client, on_progress)
        model["users"][0]["details"]["note"] = secret
        return model
    rig.builder = build
    job = rig.run(["opa"])
    data = job.status_view()["parts"]["opa"]
    assert data["state"] == "error" and "credential" in data["message"] and secret not in data["message"]
    assert audit_store.opa_model_cache_info(rig.env) is None
    raw = open(tmp_audit_log, encoding="utf-8").read()
    failed = [json.loads(line) for line in raw.splitlines() if '"access_scan.failed"' in line]
    assert failed and failed[0]["details"]["reason"] == "redaction" and "users" in failed[0]["details"]["key_path"]
    assert secret not in raw


# -- cadence gates, back-off, who may run what -------------------------------------------------------------------------
def test_a_manual_refresh_forces_the_admin_capture_after_a_recent_refusal_and_a_scheduled_one_waits(rig):
    refused = type("Refusing", (SyncOkta,), {})(fail={"assignees": REFUSED})
    oa.capture_and_store(rig.env, refused)  # a refusal just now
    rig.okta = SyncOkta()
    scheduled = rig.run(["okta"], trigger="scheduled")
    assert scheduled.status_view()["parts"]["okta"]["sub"]["admins"]["state"] == "skipped"  # the 24 h back-off holds
    manual = rig.run(["okta"], trigger="manual")
    assert manual.status_view()["parts"]["okta"]["sub"]["admins"]["state"] == "ok"  # a person is never held back
    assert [s["status"] for s in audit_store.list_config_snapshots(rig.env, kind="okta_admins")][0] == "ok"


def test_a_failed_opa_part_alone_does_not_start_the_sync_back_off(rig):
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(503, "u", "x"))
    rig.run(list(rj.PARTS), trigger="scheduled")
    state = audit_store.get_sync_state(rig.env)
    assert state["last_sync_status"] == "success" and state["last_sync_completed_at"]  # the log part's own result governs the schedule


def test_the_scheduler_does_not_retry_a_failed_log_part_inside_the_back_off(rig, monkeypatch):
    class Failing(SyncOkta):
        def get_system_log(self, **k):
            raise engine.OktaApiError(500, "u", "x")
    rig.okta = Failing()
    rig.run(["log"], trigger="scheduled")
    state = audit_store.get_sync_state(rig.env)
    assert state["last_sync_status"] == "error"
    started = []
    monkeypatch.setattr(rig.serve, "_start_refresh_job", lambda *a, **k: started.append(a))
    audit_store._upsert_sync_state(audit_store._get_connection(), rig.env, last_sync_completed_at=_ts(25 * 60))  # yesterday: a run is due
    monkeypatch.setattr(engine, "get_sync_schedule_by_id", lambda env_id: {"enabled": True, "run_time": "00:00"})
    rig.serve._scheduler_tick(datetime.now(timezone.utc))
    assert started == []  # the last attempt is under SCHEDULER_RETRY_BACKOFF_SECS old
    later = datetime.now(timezone.utc) + timedelta(seconds=rig.serve.SCHEDULER_RETRY_BACKOFF_SECS + 60)
    rig.serve._scheduler_tick(later)
    assert len(started) == 1 and started[0][0] == rig.env


def test_a_429_with_retry_after_during_the_scan_is_waited_out_and_the_scan_completes_without_duplicate_calls(rig, monkeypatch):
    from test_review_batch4_engine import _FakeHTTPError, _Resp, _ScriptedOpener, _headers
    url = "https://rate.example.com/v1/list"
    opener = _ScriptedOpener([_FakeHTTPError(url, 429, _headers(Retry_After="2")), _Resp(b'{"list": [1]}')])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    waits = []
    monkeypatch.setattr(engine, "_cancellable_sleep", waits.append)

    def build(client, okta_client=None, on_progress=None):
        on_progress("projects", "start", None)
        assert engine.http_json_request("GET", url) == {"list": [1]}
        return _default_builder(client, okta_client, on_progress)
    rig.builder = build
    job = rig.run(["opa"])
    assert job.part_state("opa") == "ok"
    assert sum(waits) >= 2 and opener.calls == ["GET", "GET"]  # one wait of at least Retry-After, the call repeated exactly once


def test_refresh_permissions_follow_the_parts_over_http(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_refresh_job", lambda job, ctx: time.sleep(0.2))
    url = "/api/environments/dev/refresh"

    def forget():
        end = time.monotonic() + 5
        while serve._refresh_running(env_id) and time.monotonic() < end:
            time.sleep(0.05)
        with serve._refresh_jobs_lock:
            serve._refresh_jobs.pop(env_id, None)
    # a bad body is a 400, not a started job
    assert _call(base_url, "POST", url, {"parts": ["nope"]}, _who(OWNER_A)).status_code == 400
    assert _call(base_url, "POST", url, {"parts": []}, _who(OWNER_A)).status_code == 400
    # the owner may run everything; a second request attaches to the running job
    out = _call(base_url, "POST", url, {"parts": ["opa"]}, _who(OWNER_A))
    assert out.status_code == 200 and out.json()["started"] is True
    again = _call(base_url, "POST", url, {"parts": ["opa"]}, _who(OWNER_A))
    assert again.json()["already_running"] is True and again.json()["job_id"] == out.json()["job_id"]
    status = _call(base_url, "GET", url + "/status", headers=_who(OWNER_A))
    assert status.status_code == 200 and status.json()["job_id"] == out.json()["job_id"]
    forget()
    # a user the environment is not shared with gets nothing
    assert _call(base_url, "POST", url, {"parts": ["opa"]}, _who(OWNER_B)).status_code in (403, 404)
    # shared: live_read only. opa is allowed; naming a part the caller may not run refuses the whole request, naming the part
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_shared_permissions({"live_read": "allow", "sync_now": "deny"}, environment_id=env_id)
    assert _call(base_url, "POST", url, {"parts": ["opa"]}, _who(OWNER_B)).status_code == 200
    forget()
    refused = _call(base_url, "POST", url, {"parts": ["opa", "log"]}, _who(OWNER_B))
    assert refused.status_code == 403 and refused.json()["part"] == "log" and refused.json()["capability"] == "sync_now"
    assert _call(base_url, "POST", url, {}, _who(OWNER_B)).status_code == 403  # the default (all parts) includes log
    assert _call(base_url, "POST", url, {"parts": ["okta"]}, _who(OWNER_B)).status_code == 403
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=env_id)
    assert _call(base_url, "POST", url, {"parts": ["opa", "log"]}, _who(OWNER_B)).status_code == 200
    forget()
    # stopping needs what the running parts needed
    engine.set_shared_permissions({"sync_now": "deny"}, environment_id=env_id)
    assert _call(base_url, "POST", url + "/cancel", {}, _who(OWNER_B)).status_code in (200, 403)
    forget()


# -- schema ------------------------------------------------------------------------------------------------------------
def test_migration_11_adds_last_refresh_json_to_sync_state_and_a_stored_record_round_trips(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    columns = {r[1] for r in conn.execute("PRAGMA table_info(sync_state)")}
    assert "last_refresh_json" in columns
    audit_store._upsert_sync_state(conn, "e1", last_refresh_json=json.dumps({"scheduled": {"parts": {"opa": {"state": "ok"}}}}))
    state = audit_store.get_sync_state("e1")
    assert state["last_refresh"]["scheduled"]["parts"]["opa"]["state"] == "ok"


def test_a_finished_refresh_records_what_each_part_did_without_names(rig):
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(503, f"https://{FIXTURE_TEAM}.example.com", FIXTURE_EMAIL))
    rig.run(list(rj.PARTS), trigger="scheduled")
    record = audit_store.get_sync_state(rig.env)["last_refresh"]["scheduled"]
    assert record["parts"]["opa"]["state"] == "error" and record["parts"]["log"]["state"] == "ok"
    blob = json.dumps(record)
    assert FIXTURE_TEAM not in blob and FIXTURE_EMAIL not in blob and "https://" not in blob


# -- the explorer's local correction ------------------------------------------------------------------------------------
def test_removing_a_user_from_a_group_patches_the_stored_scan_and_marks_it_edited(rig):
    serve = rig.serve
    rig.run(["opa"])
    assert serve._patch_scan_member_removed(rig.env, "g-admins", FIXTURE_NAME) is True
    cached = audit_store.load_opa_model_cache(rig.env)
    user = next(u for u in cached["model"]["users"] if u["name"] == FIXTURE_NAME)
    assert user["groups"] == [] and cached["modified_at"]
    assert serve._access_model_view(rig.env)["modified_at"]
    # after a restart the stored scan still carries the correction
    with serve._access_jobs_lock:
        serve._access_jobs.clear()
    view = serve._access_model_view(rig.env)
    assert next(u for u in view["model"]["users"] if u["name"] == FIXTURE_NAME)["groups"] == []
    assert serve._patch_scan_member_removed(rig.env, "g-nope", "nobody") is False


# -- vocabulary --------------------------------------------------------------------------------------------------------
def test_normalize_parts_keeps_display_order_and_rejects_the_unknown():
    assert rj.normalize_parts(None) == ["opa", "okta", "log"]
    assert rj.normalize_parts(["log", "opa", "opa"]) == ["opa", "log"]
    for bad in ([], "opa", ["nope"], [1], ["opa"] * 5, {"opa": 1}):
        with pytest.raises(ValueError):
            rj.normalize_parts(bad)


def test_the_summary_line_counts_outcomes():
    parts = {"opa": {"state": "ok"}, "okta": {"state": "refused"}, "log": {"state": "timed_out"}}
    assert rj.summary_line(parts) == "1 of 3 parts completed; Okta scan refused, System Log timed out."
    assert rj.summary_line({"opa": {"state": "ok"}}) == "OPA scan completed."


# -- the words ---------------------------------------------------------------------------------------------------------
def test_no_refresh_message_uses_alarm_words_or_carries_a_url_or_a_name():
    import re
    samples = [
        rj.opa_success_message({"users": 3, "groups": 2}, 2, "memory_only"),
        *(rj.opa_failure(k, 403, "projects", "2026-10-21T02:20:00.000Z", "OpaApiError: 503", "users[0].note")[1] for k in ("refused", "redaction", "cancelled", "error")),
        rj.opa_failure("error", None, None, None, "OpaApiError: 503")[1],
        *(rj.log_failure(k, 403, "Read 2000 System Log pages in one run; the cursor is saved, so the next sync continues from where this one stopped.")[1] for k in ("refused", "cancelled", "partial", "error")),
        rj.timed_out_message("opa", 45), rj.cancelled_message(), rj.cancelled_message(False),
    ]
    for text in samples:
        assert not re.search(r"tamper|attack|malicious|security", text, re.I), text
        assert "http://" not in text and "https://" not in text and "@" not in text, text
        assert text.rstrip().endswith((".", ")")), text  # a sentence, not a fragment
    assert any("the scan from 21 Oct 2026, 02:20 UTC is still shown and stored" in t for t in samples)  # the time carries its zone, once
    assert any("no scan is stored yet" in t for t in samples)
    assert not any("archive is unchanged" in t.lower() for t in samples)  # events stored before a refusal or a stop are kept, so "unchanged" would be untrue


# -- deleting an environment that is being refreshed ---------------------------------------------------------------------
def test_deleting_an_environment_during_a_refresh_stops_it_first_and_leaves_no_job_or_stored_scan(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    audit_store.store_opa_model_cache(env_id, {"users": [], "groups": [], "policies": [], "warnings": []}, built_at="2026-10-21T02:20:00.000Z", duration_seconds=1.0)
    assert audit_store.opa_model_cache_info(env_id)
    job = rj.RefreshJob(env_id, ["opa"], "manual")
    job.begin("opa")
    with serve._refresh_jobs_lock:
        serve._refresh_jobs[env_id] = job
    stopped = threading.Event()

    def worker():  # a part that notices the stop at its next checkpoint, as the real walkers do
        job.cancel_events["opa"].wait(20)
        job.finish("opa", "cancelled", rj.cancelled_message())
        job.conclude()
        stopped.set()
    threading.Thread(target=worker, daemon=True).start()
    resp = _call(base_url, "DELETE", f"/api/environments/dev?id={env_id}", headers=_who(OWNER_A))
    assert resp.status_code == 200, resp.text
    assert stopped.is_set() and job.part_state("opa") == "cancelled"
    assert env_id not in serve._refresh_jobs and audit_store.opa_model_cache_info(env_id) is None


def test_a_refresh_that_will_not_stop_blocks_the_delete_with_a_message_instead_of_purging_under_it(matrix_server, monkeypatch):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "REFRESH_CANCEL_WAIT_SECS", 0.3)
    job = rj.RefreshJob(env_id, ["opa"], "manual")
    job.begin("opa")
    with serve._refresh_jobs_lock:
        serve._refresh_jobs[env_id] = job  # never stops
    resp = _call(base_url, "DELETE", f"/api/environments/dev?id={env_id}", headers=_who(OWNER_A))
    assert resp.status_code == 409 and resp.json()["reason"] == "refresh_stopping" and "Try again" in resp.json()["error"]
    assert env_id in engine.list_all_environments()
    job.finish("opa", "cancelled", "x")
    job.conclude()


def test_a_redact_and_continue_hit_is_audited_by_key_path_only_and_the_scan_is_stored(rig, tmp_audit_log):  # noqa: F811
    secret = "opk_" + "Zq8vK2mXp9LrT4wYb7NcD1fH"

    def build(client, okta_client=None, on_progress=None):
        model = _default_builder(client, okta_client, on_progress)
        model["servers"] = [{"id": "s1", "hostname": secret}]
        return model
    rig.builder = build
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert data["state"] == "ok" and data["warnings"] == 1
    assert audit_store.opa_model_cache_info(rig.env)
    assert secret not in json.dumps(audit_store.load_opa_model_cache(rig.env)["model"])
    rows = rig.audit(tmp_audit_log)
    redacted = [r for r in rows if r["action"] == "access_scan.redacted"]
    assert redacted and redacted[0]["details"]["key_paths"] == ["servers[0].hostname"] and redacted[0]["details"]["count"] == 1
    assert secret not in open(tmp_audit_log, encoding="utf-8").read()


def test_a_scan_with_hyphenated_names_stores_and_seals(rig):  # noqa: F811
    def build(client, okta_client=None, on_progress=None):
        model = _default_builder(client, okta_client, on_progress)
        model["servers"] = [{"id": "s1", "hostname": "sk-prod-db-01"}]
        model["policies"] = [{"id": "p1", "name": "Prod-DB-Admins-ReadOnly-Policy-2026-Q4-Rev3", "active": True, "rules": []}]
        return model
    rig.builder = build
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert data["state"] == "ok" and data["warnings"] == 0
    names = [p["name"] for p in audit_store.load_opa_model_cache(rig.env)["model"]["policies"]]
    assert names == ["Prod-DB-Admins-ReadOnly-Policy-2026-Q4-Rev3"]


# -- review M1: coalescing knows which parts the running job covers ------------------------------------------------------------
def _running_job(serve, env_id, parts, states):
    job = rj.RefreshJob(env_id, parts, "manual")
    for part, state in states.items():
        if state == "running":
            job.begin(part)
        elif state != "pending":
            job.begin(part)
            job.finish(part, state, "x")
    with serve._refresh_jobs_lock:
        serve._refresh_jobs[env_id] = job
    return job


def test_a_request_for_parts_the_running_job_does_not_include_is_busy_not_attached(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _running_job(serve, env_id, ["log"], {"log": "running"})
    r = _call(base_url, "POST", "/api/environments/dev/refresh", {"parts": ["opa"]}, _who(OWNER_A))
    assert r.status_code == 409 and r.json()["reason"] == "busy_other_parts"
    assert r.json()["missing"] == ["opa"] and r.json()["running"] == ["log"]
    assert r.json()["error"] == "A refresh of System Log is running. The OPA scan can start when it finishes."
    assert serve._refresh_jobs[env_id].parts == ["log"]  # no second job, nothing queued


def test_a_retry_of_a_part_that_already_ended_while_another_lane_runs_is_busy(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _running_job(serve, env_id, ["opa", "okta", "log"], {"opa": "error", "log": "running", "okta": "pending"})
    r = _call(base_url, "POST", "/api/environments/dev/refresh", {"parts": ["opa"]}, _who(OWNER_A))
    assert r.status_code == 409 and r.json()["reason"] == "busy_other_parts" and r.json()["running"] == ["okta", "log"]
    assert "The OPA scan can start when it finishes" in r.json()["error"]


def test_all_parts_while_a_full_refresh_runs_still_attaches_even_if_some_part_ended(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    job = _running_job(serve, env_id, ["opa", "okta", "log"], {"opa": "ok", "log": "running", "okta": "pending"})
    r = _call(base_url, "POST", "/api/environments/dev/refresh", {}, _who(OWNER_A))
    assert r.status_code == 200 and r.json() == {"started": False, "already_running": True, "upgrade_starting": False, "job_id": job.job_id}
    covered = _call(base_url, "POST", "/api/environments/dev/refresh", {"parts": ["log"]}, _who(OWNER_A))
    assert covered.status_code == 200 and covered.json()["already_running"] is True  # a part the job is still running attaches


def test_the_legacy_bootstrap_start_is_busy_too_and_the_scheduler_logs_why(matrix_server, tmp_audit_log):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    with serve._access_jobs_lock:
        serve._access_jobs[env_id]["status"] = "done"
    _running_job(serve, env_id, ["log"], {"log": "running"})
    r = _call(base_url, "POST", "/api/access/bootstrap/start", {}, _who(OWNER_A))
    assert r.status_code == 409 and r.json()["reason"] == "busy_other_parts"
    out = serve._start_refresh_job(env_id, "dev", parts=list(rj.PARTS), trigger="scheduled")
    assert out["busy_other_parts"] is True and out["already_running"] is True
    rows = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    skipped = [x for x in rows if x["action"] == "sync.scheduled_skipped"]
    assert skipped and skipped[-1]["details"]["reason"] == "a refresh of System Log is running"


def test_the_trigger_is_what_the_caller_says_not_a_guess_from_the_parts(matrix_server, monkeypatch, tmp_audit_log):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    monkeypatch.setattr(serve, "_run_refresh_job", lambda job, ctx: None)
    triggers = []
    for body in ({"parts": ["opa"]}, {"parts": ["opa"], "trigger": "explorer"}, {"parts": ["opa"], "trigger": "scheduled"}):
        with serve._refresh_jobs_lock:
            serve._refresh_jobs.pop(env_id, None)
        assert _call(base_url, "POST", "/api/environments/dev/refresh", body, _who(OWNER_A)).status_code == 200
        triggers.append(serve._refresh_jobs[env_id].trigger)
    assert triggers == ["manual", "explorer", "manual"]  # only the two the UI uses are accepted


# -- review M2: the finish record is written before the job reads as done, and never for a deleted environment -------------------------
def test_the_real_supervisor_leaves_no_sync_state_row_behind_when_the_environment_is_deleted_mid_refresh(matrix_server, monkeypatch):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)

    def part(job, ctx):  # a part that notices the stop at its next checkpoint, then takes a moment to wind down
        job.begin("opa")
        job.cancel_events["opa"].wait(20)
        time.sleep(0.2)
        job.finish("opa", "cancelled", rj.cancelled_message())
    monkeypatch.setattr(serve, "_refresh_part_opa", part)
    monkeypatch.setattr(serve, "REFRESH_SUPERVISE_POLL_SECS", 0.02)
    out = serve._start_refresh_job(env_id, "dev", parts=["opa"], trigger="manual", owner=OWNER_A)
    assert out["started"]
    time.sleep(0.2)
    resp = _call(base_url, "DELETE", f"/api/environments/dev?id={env_id}&purge_archive=1", headers=_who(ADMIN, admin=True))
    assert resp.status_code == 200, resp.text
    time.sleep(0.6)  # anything the supervisor still wanted to write would be written by now
    assert audit_store.get_sync_state(env_id) is None
    assert env_id not in serve._refresh_jobs
    assert [a for a in audit_store.list_orphaned_archives() if a.get("environment_id") == env_id] == []


def test_a_finished_job_has_its_record_stored_before_it_reads_as_done(rig):  # noqa: F811
    seen = []
    real = rig.serve._persist_last_refresh
    rig.monkeypatch.setattr(rig.serve, "_persist_last_refresh", lambda job, *a, **k: (seen.append(job.status), real(job, *a, **k))[1])
    rig.run(["log"])
    assert seen == ["running"]  # persisted while the job still read as running: a delete waiting for "done" waits for the write
    assert audit_store.get_sync_state(rig.env)["last_refresh"]["manual"]["finished_at"]


# -- review L2: the per-part outcomes are read with the same permission on both routes ------------------------------------------------
def test_the_sync_status_route_shows_the_refresh_outcomes_only_to_callers_who_may_read_the_refresh_status(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    audit_store._upsert_sync_state(audit_store._get_connection(), env_id, last_refresh_json=json.dumps({"scheduled": {
        "finished_at": "2026-10-21T02:20:00.000Z", "parts": {"opa": {"state": "refused", "message": "OPA refused the service key for projects (HTTP 403)."}}}}))
    engine.set_shared_permissions({"view_archive": "allow", "live_read": "deny"}, environment_id=env_id)
    get = lambda who: _call(base_url, "GET", "/api/environments/dev/sync/status", headers=who)  # noqa: E731
    r = get(_who(OWNER_B))
    assert r.status_code == 200 and r.json()["sync_state"]["last_refresh"] is None and "refused the service key" not in r.text
    assert _call(base_url, "GET", "/api/environments/dev/refresh/status", headers=_who(OWNER_B)).status_code == 403
    engine.set_shared_permissions({"live_read": "allow"}, environment_id=env_id)
    assert get(_who(OWNER_B)).json()["sync_state"]["last_refresh"]["scheduled"]["parts"]["opa"]["state"] == "refused"
    assert _call(base_url, "GET", "/api/environments/dev/refresh/status", headers=_who(OWNER_B)).status_code == 200


# -- UI fidelity round: what the screens need from the status ----------------------------------------------------------------------
def test_the_status_says_who_started_it_without_naming_anyone_and_a_refused_scan_carries_its_audit_line(matrix_server, monkeypatch):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_shared_permissions({"live_read": "allow", "sync_now": "allow"}, environment_id=env_id)
    monkeypatch.setattr(serve, "_run_refresh_job", lambda job, ctx: time.sleep(0.3))
    assert _call(base_url, "POST", "/api/environments/dev/refresh", {"parts": ["log"]}, _who(OWNER_A)).status_code == 200
    mine = _call(base_url, "GET", "/api/environments/dev/refresh/status", headers=_who(OWNER_A)).json()
    other = _call(base_url, "GET", "/api/environments/dev/refresh/status", headers=_who(OWNER_B)).json()
    assert mine["started_by"] == "you" and other["started_by"] == "another user" and OWNER_A not in json.dumps(other)
    time.sleep(0.5)
    with serve._refresh_jobs_lock:
        serve._refresh_jobs.pop(env_id, None)
    job = rj.RefreshJob(env_id, ["opa"], "scheduled")
    with serve._refresh_jobs_lock:
        serve._refresh_jobs[env_id] = job
    assert _call(base_url, "GET", "/api/environments/dev/refresh/status", headers=_who(OWNER_A)).json()["started_by"] == "the schedule"


def test_a_refused_scan_message_leads_with_what_happened_then_nothing_changed_then_to_fix(rig):  # noqa: F811
    rig.builder = lambda client, okta_client=None, on_progress=None: (
        on_progress("users", "start", None), (_ for _ in ()).throw(engine.OpaApiError(403, "https://x.example.com/u", "denied")))[1]
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert data["state"] == "refused" and data["audit_line"] == "access_scan.failed (HTTP 403)"
    assert data["message"].startswith("OPA refused the service key when listing users (HTTP 403). Nothing was changed: no scan is stored yet")
    assert "To fix: open Environments and check the service key" in data["message"] and data["message"].endswith("Then retry.")



# -- F2: no exception class names in what a person reads -------------------------------------------------------------------------------
def test_an_opa_5xx_says_http_500_not_a_class_name(rig):  # noqa: F811
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(500, "https://x.example.com/p", "boom"))
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert data["state"] == "error" and data["message"].startswith("OPA did not answer as expected (HTTP 500).")
    assert data["audit_line"] == "access_scan.failed (HTTP 500)"
    assert "OpaApiError" not in json.dumps(data)


def test_a_network_failure_and_an_unexpected_error_are_described_in_words(rig):  # noqa: F811
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(engine.API_STATUS_NETWORK, "u", "x"))
    assert "(a network error)" in rig.run(["opa"]).status_view()["parts"]["opa"]["message"]
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(KeyError("odd"))
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert "KeyError" not in json.dumps(data) and "an unexpected error" in data["message"] or data["message"].startswith("Internal error")


def test_no_part_or_sub_message_of_a_failed_refresh_names_an_exception_class(rig):  # noqa: F811
    import re
    class Boom(SyncOkta):
        def get_system_log(self, **k):
            raise engine.OktaApiError(500, "https://example.okta.com/x", "boom")

        def count_okta_objects(self, *a, **k):
            raise RuntimeError("counting broke")
    rig.okta = Boom()
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(502, "u", "x"))
    view = rig.run().status_view()
    texts = [view["parts"][p].get("message", "") for p in rj.PARTS] + [v.get("message", "") for v in view["parts"]["okta"]["sub"].values()] + [view["parts"]["opa"].get("audit_line", "")]
    assert not [t for t in texts if re.search(r"\b[A-Za-z]+(Error|Exception)\b", t)], texts
