"""5.50.0 follow-ups from the VM test: events an interrupted sync stored but never sealed (F1), the reported `since` with a cursor (F2),
the bounded walk's gradual recovery and retry cap (F4), and the polling page size that must not be saved (F5)."""
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

import audit_store
import create_secret_folders as engine

ENV = "12121212-1212-1212-1212-121212121212"


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _ts(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(uuid, minutes_ago):
    return {"uuid": uuid, "eventType": "user.session.start", "published": _ts(minutes_ago), "actor": {"id": "00u1"}, "outcome": {"result": "SUCCESS"}, "target": []}


def _next(token, limit=1000):
    return f"/api/v1/logs?after={token}&limit={limit}&sortOrder=ASCENDING&since=x"


class Pages:
    def __init__(self, script):
        self.script, self.paths = dict(script), []

    def get_system_log(self, **k):
        return [], True

    def get_system_log_page(self, path):
        self.paths.append(path)
        item = self.script.get(path)
        if isinstance(item, BaseException):
            raise item
        return item if item is not None else ([], path)


def _seed(cursor="c1"):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at=_ts(30), last_sync_completed_at=_ts(30), last_sync_status="success",
                                   ingestion_scope="all", poll_cursor=_next(cursor))


# --- F1 ----------------------------------------------------------------------------------------------------------
def test_a_killed_sync_leaves_events_that_verify_reports_and_the_next_sync_seals(db):
    _seed("c1")
    killed = Pages({_next("c1"): ([_event(f"k{i}", 20 - i) for i in range(5)], _next("c2")), _next("c2"): KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):  # not an Exception: skips the failure sealing, as a kill does
        audit_store.sync_okta_events(killed, ENV, "all")
    conn = audit_store._get_connection()
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5 and conn.execute("SELECT COUNT(*) FROM manifest_entries").fetchone()[0] == 0
    v = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert v["valid"] is False and v["unsealed_events"] == 5 and "5 events are stored but not sealed" in v["reason"]
    # the next sync seals them first, in a recovery manifest that says what it is, then continues from the saved cursor
    resumed = Pages({_next("c2"): ([_event("n1", 2)], _next("c3"))})
    result = audit_store.sync_okta_events(resumed, ENV, "all")
    assert result["recovered_events"] == 5 and result["inserted"] == 1 and resumed.paths[0] == _next("c2")
    rec = conn.execute("SELECT source, since, until, row_count FROM ingestion_manifests WHERE source = 'sync_recovery'").fetchone()
    assert rec["row_count"] == 5 and rec["since"] and rec["until"] >= rec["since"]
    v = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert v["valid"] is True and v["unsealed_events"] == 0 and v["verified_rows"] == 6  # every curated row is now accounted for
    again = audit_store.sync_okta_events(Pages({}), ENV, "all")
    assert again["recovered_events"] == 0
    assert conn.execute("SELECT COUNT(*) FROM ingestion_manifests WHERE source = 'sync_recovery'").fetchone()[0] == 1


def test_a_sync_running_right_now_is_pending_not_a_break(db):
    _seed()
    with pytest.raises(KeyboardInterrupt):
        audit_store.sync_okta_events(Pages({_next("c1"): ([_event("p1", 5)], _next("c2")), _next("c2"): KeyboardInterrupt()}), ENV, "all")
    pending = audit_store.verify_ingestion_chain(ENV, deep=True, sync_in_progress=True)
    assert pending["valid"] is True and pending["unsealed_pending"] is True and pending["unsealed_events"] == 1


def test_a_chain_of_nothing_with_no_events_and_a_healthy_archive_stay_valid(db):
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True
    audit_store.sync_okta_events(Pages({}), ENV, "all", since=_ts(60))
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["unsealed_events"] == 0


def test_a_legacy_archive_does_not_report_its_unsealed_history(db):
    """Rows written under the pre-5.40.4 chain were never content-sealed; they are not 'an interrupted sync'."""
    conn = audit_store._get_connection()
    audit_store._insert_rows(conn, ENV, [audit_store._normalize_live_event(_event(f"old{i}", 500 - i)) for i in range(3)], "all")
    conn.execute("INSERT INTO ingestion_manifests (environment_id, source, since, until, row_count, batch_hash, prev_manifest_hash, created_at) "
                 "VALUES (?, 'sync', NULL, NULL, 3, 'h', NULL, '2026-01-01T00:00:00.000Z')", (ENV,))
    conn.execute("INSERT INTO chain_heads (environment_id, manifest_id, head_hash, updated_at) VALUES (?, 1, 'h', 'x')", (ENV,))
    conn.commit()
    v = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert v["valid"] is True and v["unsealed_events"] == 0 and v["legacy_manifests"] == 1
    assert audit_store.seal_unsealed_events(ENV)["sealed"] == 0  # nothing to adopt: the recovery never claims legacy history
    audit_store.sync_okta_events(Pages({}), ENV, "all", since=_ts(10))  # a normal sealed run afterwards
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True


def test_a_failed_recovery_does_not_block_the_sync(db, monkeypatch):
    _seed()
    monkeypatch.setattr(audit_store, "seal_unsealed_events", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk")))
    result = audit_store.sync_okta_events(Pages({}), ENV, "all")
    assert result["complete"] is True and result["recovered_events"] is None


# --- F2 ----------------------------------------------------------------------------------------------------------
def test_with_a_cursor_the_result_reports_the_cursor_not_a_clamped_since(db):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at="2025-01-01T00:00:00.000Z", last_sync_completed_at=_ts(30), last_sync_status="success",
                                   ingestion_scope="all", poll_cursor=_next("c1"))
    pages = Pages({})
    result = audit_store.sync_okta_events(pages, ENV, "all")
    assert pages.paths[0] == _next("c1")  # the run continued from the cursor
    assert result["since"] is None and result["since_clamped"] is False and result["from_cursor"] is True
    # no cursor and the same stale watermark: it really did start from the clamped date
    conn.execute("UPDATE sync_state SET poll_cursor = NULL")
    conn.commit()
    result = audit_store.sync_okta_events(Pages({}), ENV, "all")
    assert result["since_clamped"] is True and result["since"] and result["from_cursor"] is False


# --- F4 ----------------------------------------------------------------------------------------------------------
class Windowed:
    """Times out any window longer than `limit_minutes`; records every window it was asked for."""
    def __init__(self, limit_minutes):
        self.limit, self.windows = limit_minutes, []

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        a, b = datetime.fromisoformat(since.replace("Z", "+00:00")), datetime.fromisoformat(until.replace("Z", "+00:00"))
        minutes = round((b - a).total_seconds() / 60)
        self.windows.append(minutes)
        if minutes > self.limit:
            raise engine.OktaApiError(500, "u", '{"errorCode":"E0000009"}')
        return [], True

    def get_system_log_page(self, path):
        return [], None


def test_the_bounded_walk_recovers_gradually_and_never_returns_to_a_size_that_failed(db):
    client = Windowed(150)
    result = audit_store.sync_okta_events(client, ENV, "all", since=_ts(60 * 24 * 40))
    failed = [w for w in client.windows if w > 150]
    assert result["complete"] is True and len(failed) == len(set(failed))  # no window size that timed out is asked for again
    assert len(failed) < audit_store.MAX_TIMEOUTS_PER_RUN
    ok = [w for w in client.windows if w <= 150]
    assert all(b <= a * 1.5 + 1 for a, b in zip(ok, ok[1:]) if b > a)  # grows by at most x1.5 after a success, not x2
    assert max(ok[len(ok) // 2:]) <= 150  # settled below the failing size


def test_the_bounded_walk_stops_as_partial_after_too_many_timeouts_instead_of_grinding(db, monkeypatch):
    monkeypatch.setattr(audit_store, "MAX_TIMEOUTS_PER_RUN", 2)
    client = Windowed(0)  # everything times out
    result = audit_store.sync_okta_events(client, ENV, "all", since=_ts(60 * 24 * 40))
    assert result["complete"] is False and result["error"].startswith("partial: Okta timed out 3 times")
    assert len(client.windows) == 3 and audit_store.get_sync_state(ENV)["last_sync_status"] == "error"
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True  # the partial run is sealed too


def test_a_healthy_bounded_walk_is_unaffected(db):
    client = Windowed(10 ** 9)
    result = audit_store.sync_okta_events(client, ENV, "all", since=_ts(60 * 24 * 3))
    assert result["complete"] is True and result["chunks"] >= 3


# --- F5 ----------------------------------------------------------------------------------------------------------
class Echo:
    """Okta-like polling: a page longer than 100 times out; `next` echoes the request's limit."""
    def __init__(self, pages):
        self.paths, self.pages = [], pages

    def get_system_log(self, **k):
        return [], True

    def get_system_log_page(self, path):
        self.paths.append(path)
        q = parse_qs(urlsplit(path).query)
        if int(q["limit"][0]) > 100:
            raise engine.OktaApiError(500, "u", '{"errorCode":"E0000009"}')
        n = int(q["after"][0])
        events = self.pages.get(n, [])
        return events, (f"/api/v1/logs?after={n + 1}&limit={q['limit'][0]}&sortOrder=ASCENDING&since=x" if events else path)


def test_a_page_size_shrunk_by_a_timeout_is_not_saved_in_the_cursor(db):
    _seed()
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, poll_cursor=_next("0"))
    client = Echo({0: [_event("e0", 10)], 1: [_event("e1", 9)]})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["inserted"] == 2 and result["complete"] is True
    assert [int(parse_qs(urlsplit(p).query)["limit"][0]) for p in client.paths][:3] == [1000, 250, 62]  # shrank to get through
    saved = audit_store._read_poll_cursor(conn, ENV)
    assert parse_qs(urlsplit(saved).query)["limit"] == ["1000"]  # the normal size is what the next run starts with
    assert parse_qs(urlsplit(saved).query)["after"] == ["2"] and urlsplit(saved).path == "/api/v1/logs"
    again = Echo({})
    audit_store.sync_okta_events(again, ENV, "all")
    assert parse_qs(urlsplit(again.paths[0]).query)["limit"] == ["1000"]  # the first request of the next healthy run is at the normal size
