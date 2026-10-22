"""5.52.0: a Stop that lands just before a deadline is a Stop (H4), and the log-timeout streak resets on any other outcome (H5).
Every identity here is a placeholder; nothing touches a network."""

import audit_store
import server.refresh_jobs as rj
from test_refresh_job_5510 import rig  # noqa: F401  (fixture)


class _StopLandsAtTheDeadline(rj.RefreshJob):
    """overdue() reports the part as over its deadline and, in the same instant, the person's Stop arrives."""

    def overdue(self, deadlines=None):
        late = super().overdue({p: -1 for p in rj.PARTS})
        self.request_cancel(by="owner")
        return late


def test_a_stop_landing_just_before_the_deadline_is_cancelled_not_timed_out(rig):  # noqa: F811
    job = _StopLandsAtTheDeadline(rig.env, ["log"], "manual")
    assert job.begin("log")
    rig.serve._refresh_jobs[rig.env] = job
    rig.serve._supervise(job, [])
    job.conclude()
    assert job.part_state("log") == "cancelled"


def test_a_part_over_its_deadline_without_a_stop_is_still_timed_out(rig):  # noqa: F811
    class _Late(rj.RefreshJob):
        def overdue(self, deadlines=None):
            return super().overdue({p: -1 for p in rj.PARTS})
    job = _Late(rig.env, ["log"], "manual")
    assert job.begin("log")
    rig.serve._refresh_jobs[rig.env] = job
    rig.serve._supervise(job, [])
    job.conclude()
    assert job.part_state("log") == "timed_out"


class _FakeJob:
    def __init__(self, env, log_state, trigger="manual"):
        self.environment_id, self.trigger, self.job_id, self.parts = env, trigger, "j1", ["log"]
        self._state = log_state

    def status_view(self):
        return {"finished_at": "2026-10-21T00:00:00.000Z", "parts": {"log": {"state": self._state, "message": ""}}}


def _streak(rig, states):  # noqa: F811
    out = []
    for state in states:
        rig.serve._persist_last_refresh(_FakeJob(rig.env, state))
        out.append(int((audit_store.get_sync_state(rig.env) or {}).get("last_refresh", {}).get("log_timeouts") or 0))
    return out


def test_the_log_timeout_streak_resets_on_any_outcome_other_than_timed_out(rig):  # noqa: F811
    assert _streak(rig, ["timed_out", "error", "timed_out"]) == [1, 0, 1]


def test_the_log_timeout_streak_counts_consecutive_timeouts_and_cancelled_resets_it(rig):  # noqa: F811
    assert _streak(rig, ["timed_out", "timed_out", "cancelled", "timed_out", "ok"]) == [1, 2, 0, 1, 0]


# -- F1: a refresh never adopts a scan or sync that was already told to stop ----------------------------------------------------------
import threading  # noqa: E402
import time  # noqa: E402

import create_secret_folders as engine  # noqa: E402
from test_refresh_job_5510 import SyncOkta, _blocking_builder, _event, _ts  # noqa: E402


def _wait_job(rig, timeout=15):  # noqa: F811
    job = rig.job()
    end = time.monotonic() + timeout
    while job.status == "running" and time.monotonic() < end:
        time.sleep(0.02)
    assert job.status == "done"
    return job


def test_a_refresh_does_not_adopt_an_opa_scan_that_was_told_to_stop_it_waits_and_runs_a_fresh_one(rig, monkeypatch):  # noqa: F811
    monkeypatch.setitem(rj.PART_DEADLINES_SECS, "opa", 0.2)
    monkeypatch.setattr(rj, "KILL_GRACE_SECS", 0.1)
    release, started = threading.Event(), threading.Event()
    calls = []
    stuck = _blocking_builder(release, started, checkpoints=False)  # ignores the stop until released, like a long unbroken call

    def builder(*a, **k):
        calls.append(1)
        return stuck(*a, **k)
    rig.builder = builder
    assert rig.start(["opa"])["started"]
    assert started.wait(10)
    first = _wait_job(rig)  # the deadline passes; the job ends while the scan's thread is still inside the walk
    assert first.part_state("opa") == "timed_out"
    assert rig.serve._access_jobs[rig.env]["status"] == "running"
    monkeypatch.setitem(rj.PART_DEADLINES_SECS, "opa", 30)
    threading.Timer(0.5, release.set).start()
    assert rig.start(["opa"])["started"]
    second = _wait_job(rig)
    assert second.part_state("opa") == "ok", second.status_view()["parts"]["opa"]
    assert len(calls) == 2  # a fresh scan ran; the stopping one was not adopted
    assert audit_store.opa_model_cache_info(rig.env)["built_at"]


class _StuckThenFastPages(SyncOkta):
    """The first System Log page waits (ignoring any stop) until released; every later page is empty and final."""

    def __init__(self, release, started):
        self.release, self.started, self.first = release, started, True

    def get_system_log_page(self, path):
        if self.first:
            self.first = False
            self.started.set()
            self.release.wait(15)
            return [_event("s1", 5)], "/api/v1/logs?after=c2&limit=1000&sortOrder=ASCENDING&since=x"
        return [], None


def test_a_refresh_does_not_adopt_a_system_log_sync_that_was_told_to_stop_it_waits_and_runs_a_fresh_one(rig, monkeypatch):  # noqa: F811
    audit_store._upsert_sync_state(audit_store._get_connection(), rig.env, last_synced_at=_ts(30), last_sync_completed_at=_ts(25 * 60),
                                   last_sync_status="success", ingestion_scope="all",
                                   poll_cursor="/api/v1/logs?after=c1&limit=1000&sortOrder=ASCENDING&since=x")
    monkeypatch.setitem(rj.PART_DEADLINES_SECS, "log", 0.2)
    monkeypatch.setattr(rj, "KILL_GRACE_SECS", 0.1)
    release, started = threading.Event(), threading.Event()
    rig.okta = _StuckThenFastPages(release, started)
    assert rig.start(["log"])["started"]
    assert started.wait(10)
    first = _wait_job(rig)
    assert first.part_state("log") == "timed_out"
    assert rig.serve._sync_jobs[rig.env]["status"] == "running"
    monkeypatch.setitem(rj.PART_DEADLINES_SECS, "log", 30)
    threading.Timer(0.5, release.set).start()
    assert rig.start(["log"])["started"]
    second = _wait_job(rig)
    view = second.status_view()["parts"]["log"]
    assert view["state"] == "ok" and not view.get("adopted"), view


def test_a_scan_started_elsewhere_without_a_stop_is_still_adopted(rig):  # noqa: F811
    release, started = threading.Event(), threading.Event()
    calls = []
    inner = _blocking_builder(release, started)

    def builder(*a, **k):
        calls.append(1)
        return inner(*a, **k)
    rig.builder = builder
    assert rig.start(["opa"])["started"]
    assert started.wait(10)
    # the same slot, as a second refresh job would find it (the first job's lane keeps running)
    assert rig.serve._access_jobs[rig.env]["status"] == "running" and not rig.serve._scan_is_stopping("access", rig.env)
    release.set()
    _wait_job(rig)
    assert len(calls) == 1
