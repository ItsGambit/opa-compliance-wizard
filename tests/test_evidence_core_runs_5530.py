"""Recorded runs and prunes (migration 013) and the coverage that rests on them. Synthetic data only."""
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import evidence_core as core
from test_evidence_core_5530 import (  # noqa: F401  (store is a fixture)
    ENV, ROOT, FakeOkta, build_prunable_archive, day_start, evt, ingest, iso, rel_day, rel_period, set_state, stamp, store,
)


def rows_of(table, **where):
    conn = audit_store._get_connection()
    clause = " AND ".join(f"{k} = ?" for k in where) or "1"
    return [dict(r) for r in conn.execute(f"SELECT * FROM {table} WHERE {clause} ORDER BY id", tuple(where.values()))]


def add_run(kind, outcome, since, until, started=None):
    now = datetime.now(timezone.utc)
    conn = audit_store._get_connection()
    conn.execute(
        "INSERT INTO sync_runs (environment_id, kind, started_at, finished_at, outcome, window_since, window_until) VALUES (?,?,?,?,?,?,?)",
        (ENV, kind, started or iso(now), iso(now) if outcome else None, outcome, since, until))
    conn.commit()


def test_migration_013_is_declared_additive_and_rollback_safe(store):
    declared = json.load(open(os.path.join(ROOT, "server", "schema_migrations.json")))["migrations"]["13"]
    assert declared["rollback_safe"] is True and declared["since"] == "5.53.0"
    assert 13 in audit_store.MIGRATIONS
    conn = audit_store._get_connection()
    cols = lambda t: [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
    assert cols("prune_history") == ["id", "environment_id", "pruned_at", "cutoff", "rows_pruned", "scope"]
    assert cols("sync_runs") == ["id", "environment_id", "kind", "started_at", "finished_at", "outcome", "window_since", "window_until", "rows"]
    idx = {r[1] for r in conn.execute("SELECT * FROM sqlite_master WHERE type = 'index'")}
    assert {"idx_sync_runs_env_started", "idx_prune_history_env_pruned"} <= idx
    audit_store.run_migrations()  # idempotent


def test_purging_an_environments_archive_removes_its_run_and_prune_rows(store):
    assert "sync_runs" in audit_store.ARCHIVE_TABLES and "prune_history" in audit_store.ARCHIVE_TABLES


def test_a_successful_sync_records_a_run_with_its_window(store):
    since = stamp(120)
    result = audit_store.sync_okta_events(FakeOkta([evt("r-1", stamp(100)), evt("r-2", stamp(99), "app.misc.synthetic")]), ENV, "all", since=since)
    run = rows_of("sync_runs", environment_id=ENV)
    assert len(run) == 1 and run[0]["kind"] == "sync" and run[0]["outcome"] == "ok"
    assert run[0]["window_since"] == result["since"] == since and run[0]["window_until"] > run[0]["window_since"]
    assert run[0]["rows"] == 2 and run[0]["started_at"] <= run[0]["finished_at"]


class FailingOkta(FakeOkta):
    def get_system_log(self, since, until, limit, sort_order, max_pages):
        raise RuntimeError("synthetic outage")


def test_a_failed_sync_records_failed_and_never_counts_as_coverage(store):
    now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError):
        audit_store.sync_okta_events(FailingOkta([]), ENV, "all", since=iso(day_start(10)))
    run = rows_of("sync_runs")[0]
    assert run["outcome"] == "failed" and run["finished_at"]
    add_run("sync", None, iso(day_start(10)), iso(now))             # an unfinished run (a killed process) either
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    ingest([], since=iso(day_start(10)), until=iso(now - timedelta(minutes=5)))   # the failed run's manifest still names a window
    with core.open_snapshot(ENV, rel_period(8, 1)) as snap:
        cov = snap.coverage()
    assert cov["recorded_from"] is None
    assert {d["basis"] for d in cov["days"]} == {"inferred"}


def test_a_cancelled_sync_is_recorded_stopped(store, monkeypatch):
    import create_secret_folders as engine
    monkeypatch.setattr(engine, "cancel_requested", lambda: True)
    audit_store.sync_okta_events(FakeOkta([evt("c-1", stamp(100))]), ENV, "all", since=stamp(120))
    assert [r["outcome"] for r in rows_of("sync_runs")] == ["stopped"]


def test_a_csv_import_records_the_date_range_of_its_rows(store, tmp_path):
    path = tmp_path / "export.csv"
    path.write_text("uuid,event_type,timestamp,actor.id,actor.display_name,actor.alternate_id,outcome.result\n"
                    "i-1,user.session.start,2026-02-03T10:00:00.000Z,u1,A,a@example.com,SUCCESS\n"
                    "i-2,user.session.start,2026-02-09T11:30:00.500Z,u1,A,a@example.com,SUCCESS\n", encoding="utf-8")
    audit_store.import_from_csv(str(path), ENV, "all")
    run = rows_of("sync_runs")[0]
    assert (run["kind"], run["outcome"], run["rows"]) == ("import", "ok", 2)
    assert run["window_since"] == "2026-02-03T10:00:00.000Z" and run["window_until"] == "2026-02-09T11:30:00.501Z"


def test_prune_writes_a_row_only_when_it_deletes(store):
    build_prunable_archive()
    assert audit_store.prune_events(ENV, retention_days=100)["pruned"] == 0
    assert rows_of("prune_history") == []
    result = audit_store.prune_events(ENV, retention_days=20)
    rows = rows_of("prune_history", environment_id=ENV)
    assert len(rows) == 1 and rows[0]["rows_pruned"] == result["pruned"] == 2 and rows[0]["cutoff"] == result["cutoff"]
    assert rows[0]["scope"] == "retention" and rows[0]["pruned_at"]


def test_a_size_prune_is_recorded_with_its_own_scope(store):
    now = datetime.now(timezone.utc)
    ingest([evt(f"sz-{i}", rel_day(30 - i), "app.misc.synthetic") for i in range(5)], since=iso(day_start(40)), until=iso(now))
    result = audit_store.prune_events(ENV, max_size_mb=0.0005)
    rows = rows_of("prune_history")
    assert result["pruned"] > 0 and len(rows) == 1 and rows[0]["scope"] == "size" and rows[0]["rows_pruned"] == result["pruned"]


def test_recorded_and_inferred_days_are_reported_per_day(store):
    now = datetime.now(timezone.utc)
    ingest([evt("m-1", rel_day(20))], since=iso(day_start(25)), until=iso(day_start(12)))   # before records: a manifest window
    add_run("sync", "ok", iso(day_start(10)), iso(day_start(6)))
    add_run("sync", "failed", iso(day_start(6)), iso(day_start(1)))                       # never counts
    add_run("import", "ok", iso(day_start(4)), iso(day_start(3)))                         # counts for its range only
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    with core.open_snapshot(ENV, rel_period(26, 2)) as snap:
        cov = snap.coverage()
    st = {d["date"]: d for d in cov["days"]}
    day = lambda n: day_start(n).date().isoformat()
    assert st[day(26)]["state"] == core.DAY_BEFORE_ARCHIVE
    assert st[day(20)]["state"] == core.DAY_COVERED_EVENTS and st[day(20)]["basis"] == "inferred"
    assert st[day(11)]["state"] == core.DAY_NOT_COVERED and st[day(11)]["basis"] == "inferred"
    assert st[day(8)]["state"] == core.DAY_COVERED_ZERO and st[day(8)]["basis"] == "recorded"
    assert st[day(5)]["state"] == core.DAY_NOT_COVERED and st[day(5)]["basis"] == "recorded"      # only a failed run claimed it
    assert st[day(4)]["state"] == core.DAY_COVERED_ZERO and st[day(4)]["basis"] == "recorded"     # the import's range
    assert st[day(2)]["state"] == core.DAY_NOT_COVERED
    assert cov["recorded_from"] == day(10)
    assert cov["basis_counts"] == {"recorded": 9, "inferred": 16}
    text = " ".join(cov["limits"])
    assert "recorded sync and import runs" in text and "manifest windows (inferred)" in text


def test_events_without_a_recorded_window_are_not_covered_on_the_recorded_basis(store):
    now = datetime.now(timezone.utc)
    add_run("sync", "ok", iso(day_start(6)), iso(day_start(4)))
    ingest([evt("x-1", rel_day(2))], source="sync_recovery")
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    with core.open_snapshot(ENV, rel_period(6, 1)) as snap:
        cov = snap.coverage()
    row = [d for d in cov["days"] if d["date"] == day_start(2).date().isoformat()][0]
    assert row["state"] == core.DAY_NOT_COVERED and row["events"] == 1


def test_a_sync_resumed_from_its_cursor_chains_to_the_previous_ok_run(store):
    now = datetime.now(timezone.utc)
    add_run("sync", "ok", iso(day_start(8)), iso(day_start(5)))
    add_run("sync", "ok", None, iso(day_start(2)))          # resumed from its saved cursor: starts where the last ok run ended
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    with core.open_snapshot(ENV, rel_period(8, 3)) as snap:
        cov = snap.coverage()
    assert cov["counts"][core.DAY_NOT_COVERED] == 0 and cov["recorded_from"] == day_start(8).date().isoformat()


def test_recorded_prune_run_makes_the_pruned_days_recorded(store):
    build_prunable_archive()
    audit_store.prune_events(ENV, retention_days=20)
    with core.open_snapshot(ENV, rel_period(45, 1)) as snap:
        cov = snap.coverage()
    pruned = [d for d in cov["days"] if d["state"] == core.DAY_PRUNED]
    assert pruned and {d["prune_basis"] for d in pruned} == {"recorded"} and cov["pruned_basis"] == "recorded"
    assert "recorded prune run" in " ".join(cov["limits"])
