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
