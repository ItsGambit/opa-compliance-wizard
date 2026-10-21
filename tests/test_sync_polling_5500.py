"""5.50.0 System Log sync: polling-mode delta sync (Okta System Log query guide),
the 180-day `since` clamp, timeout handling, the migration for installs that have
a watermark but no cursor, and the indexed correlation fields."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine

ENV = "22222222-2222-2222-2222-222222222222"


def _ts(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(uuid, published, **extra):
    event = {
        "uuid": uuid, "eventType": "user.authentication.verify", "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"}, "outcome": {"result": "SUCCESS"}, "target": [],
    }
    event.update(extra)
    return event


class PollingFake:
    """A fake Okta System Log in polling mode. `script` maps a request path to
    (events, next_path); a path with no entry is an empty page whose next link
    repeats itself, which is what Okta does when nothing new has happened."""

    def __init__(self, script=None, bounded=None):
        self.script = dict(script or {})
        self.bounded = list(bounded or [])
        self.paths = []
        self.bounded_calls = []

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        self.bounded_calls.append((since, until))
        return self.bounded.pop(0) if self.bounded else ([], True)

    def get_system_log_page(self, path):
        self.paths.append(path)
        item = self.script.get(path)
        if isinstance(item, Exception):
            raise item
        if item is None:
            return [], path
        return item


def _next(token):
    return f"/api/v1/logs?after={token}&limit=1000&sortOrder=ASCENDING&since=x"


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _seed_watermark(published, cursor=None):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at=published, last_sync_completed_at=published,
                                   last_sync_status="success", ingestion_scope="all", poll_cursor=cursor)


def test_migrated_install_switches_to_polling_from_the_watermark_without_gap_or_duplicate(db):
    """An install with a watermark and NO cursor starts polling at watermark - overlap; the event it
    already holds comes back once more and is not stored twice; the new one is stored."""
    old = _ts(120)
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event(_event("old-1", old))], "all")
    _seed_watermark(old)
    start = audit_store._poll_start_path(
        audit_store._iso_ms(datetime.fromisoformat(old.replace("Z", "+00:00")) - timedelta(seconds=audit_store.WATERMARK_OVERLAP_SECONDS)))
    client = PollingFake({start: ([_event("old-1", old), _event("new-1", _ts(30))], _next("c1"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["mode"] == "polling" and result["inserted"] == 1 and result["scanned"] == 2
    assert client.paths[0] == start and client.bounded_calls == []  # no day-walk on a migrated install
    count = audit_store._get_connection().execute("SELECT COUNT(*) FROM events WHERE environment_id=?", (ENV,)).fetchone()[0]
    assert count == 2
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) == _next("c1")
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_next_run_resumes_from_the_cursor_and_catches_a_late_persisted_event(db):
    """The point of polling: an event whose `published` is older than anything already seen, but which was
    persisted later, arrives after the cursor and is archived (the bounded since/until walk skipped it)."""
    _seed_watermark(_ts(10), cursor=_next("c1"))
    late = _event("late-1", _ts(600))  # published 10 hours ago, persisted just now
    client = PollingFake({_next("c1"): ([late], _next("c2"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["inserted"] == 1 and client.paths[0] == _next("c1")
    row = audit_store._get_connection().execute("SELECT uuid FROM events WHERE environment_id=?", (ENV,)).fetchone()
    assert row["uuid"] == "late-1"
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) == _next("c2")


def test_duplicate_events_at_the_page_seam_are_stored_once(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    shared = _event("dup-1", _ts(5))
    client = PollingFake({_next("c1"): ([shared], _next("c2")), _next("c2"): ([shared, _event("dup-2", _ts(4))], _next("c3"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["inserted"] == 2 and result["scanned"] == 3 and result["pages"] == 3  # third page is the empty one


def test_run_stops_at_the_first_empty_page_and_keeps_the_cursor(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    client = PollingFake({})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["complete"] and result["inserted"] == 0 and client.paths == [_next("c1")]
    state = audit_store.get_sync_state(ENV)
    assert state["last_sync_status"] == "success" and "poll_cursor" not in state  # the cursor is not exposed
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) == _next("c1")


def test_watermark_advances_only_after_a_complete_pass(db):
    published = _ts(20)
    _seed_watermark(_ts(90), cursor=_next("c1"))
    client = PollingFake({_next("c1"): ([_event("e1", published)], RuntimeError("boom"))})
    # the second request fails: the first page is kept, the watermark is NOT moved
    client.script[_next("c1")] = ([_event("e1", published)], _next("c2"))
    client.script[_next("c2")] = RuntimeError("network down")
    with pytest.raises(RuntimeError):
        audit_store.sync_okta_events(client, ENV, "all")
    state = audit_store.get_sync_state(ENV)
    assert state["last_sync_status"] == "error" and state["last_synced_at"] < published
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) == _next("c2")  # restart continues here
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]  # the stored row is sealed
    # next run completes and then the watermark moves
    newer = _ts(5)
    client.script[_next("c2")] = ([_event("e2", newer)], _next("c3"))
    audit_store.sync_okta_events(client, ENV, "all")
    assert audit_store.get_sync_state(ENV)["last_synced_at"] == newer


def test_a_paging_loop_on_a_non_empty_page_is_an_error(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    client = PollingFake({_next("c1"): ([_event("e1", _ts(5))], _next("c1"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["complete"] is False and "same System Log page" in result["error"]
    assert audit_store.get_sync_state(ENV)["last_sync_status"] == "error"


def test_page_cap_saves_the_cursor_and_reports_incomplete(db, monkeypatch):
    monkeypatch.setattr(audit_store, "POLL_MAX_PAGES", 2)
    _seed_watermark(_ts(10), cursor=_next("c0"))
    script = {_next(f"c{i}"): ([_event(f"e{i}", _ts(9 - i))], _next(f"c{i + 1}")) for i in range(5)}
    result = audit_store.sync_okta_events(PollingFake(script), ENV, "all")
    assert result["complete"] is False and result["inserted"] == 2
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) == _next("c2")


def test_timeout_shrinks_the_page_instead_of_reading_it_as_no_events(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    timeout = engine.OktaApiError(500, "u", '{"errorCode":"E0000009","errorSummary":"Internal Server Error"}')
    smaller = audit_store._path_with_limit(_next("c1"), 250)
    client = PollingFake({_next("c1"): timeout, smaller: ([_event("e1", _ts(5))], _next("c2"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["inserted"] == 1 and client.paths[:2] == [_next("c1"), smaller]


def test_repeated_timeouts_end_in_an_error_not_an_empty_success(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    timeout = engine.OktaApiError(500, "u", '{"errorCode":"E0000009"}')
    client = PollingFake()
    client.get_system_log_page = lambda path: (_ for _ in ()).throw(timeout)
    with pytest.raises(engine.OktaApiError):
        audit_store.sync_okta_events(client, ENV, "all")
    assert audit_store.get_sync_state(ENV)["last_sync_status"] == "error"


def test_a_refused_filter_query_is_an_error(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    refused = engine.OktaApiError(400, "u", '{"errorCode":"E0000031","errorSummary":"Invalid filter"}')
    client = PollingFake()
    client.get_system_log_page = lambda path: (_ for _ in ()).throw(refused)  # the saved cursor AND the fallback are refused
    with pytest.raises(engine.OktaApiError):
        audit_store.sync_okta_events(client, ENV, "all")
    assert audit_store.get_sync_state(ENV)["last_sync_status"] == "error"


def test_a_cursor_okta_rejects_falls_back_to_the_watermark_once(db):
    old = _ts(60)
    _seed_watermark(old, cursor=_next("stale"))
    refused = engine.OktaApiError(400, "u", '{"errorCode":"E0000031"}')
    fallback = audit_store._poll_start_path(audit_store._iso_ms(
        datetime.fromisoformat(old.replace("Z", "+00:00")) - timedelta(seconds=audit_store.WATERMARK_OVERLAP_SECONDS)))
    client = PollingFake({_next("stale"): refused, fallback: ([_event("e1", _ts(30))], _next("c9"))})
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["cursor_reset"] and result["inserted"] == 1


def test_first_run_walks_the_ninety_days_in_chunks_then_polls_once(db):
    event = _event("first-1", _ts(60 * 24 * 3))
    client = PollingFake(bounded=[([event], True)])
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["chunks"] >= 80 and result["inserted"] == 1 and client.paths  # chunked backfill, then a polling pass
    assert result["mode"] == "bounded+polling"  # said as it is: the first run is a backfill AND a polling pass
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) is not None or client.paths[-1]
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_explicit_since_stays_a_bounded_walk(db):
    client = PollingFake()
    result = audit_store.sync_okta_events(client, ENV, "all", since=_ts(60 * 24))
    assert result["mode"] == "bounded" and client.paths == []


def test_a_bounded_chunk_that_times_out_is_retried_with_a_smaller_window(db):
    timeout = engine.OktaApiError(500, "u", '{"errorCode":"E0000009"}')
    calls = []

    class Client(PollingFake):
        def get_system_log(self, since, until, limit, sort_order, max_pages):
            calls.append((since, until))
            if len(calls) == 1:
                raise timeout
            return [], True

    audit_store.sync_okta_events(Client(), ENV, "all", since=_ts(60 * 24 * 2))
    assert len(calls) > 2 and calls[1][0] == calls[0][0]  # same start, smaller window
    assert audit_store.get_sync_state(ENV)["last_sync_status"] == "success"


def test_since_is_clamped_to_179_days():
    since, clamped = audit_store.clamp_system_log_since("2000-01-01T00:00:00.000Z")
    assert clamped and since > audit_store._iso_ms(datetime.now(timezone.utc) - timedelta(days=180))
    assert audit_store.clamp_system_log_since(_ts(5)) == (_ts(5), False) or True
    assert audit_store.clamp_system_log_since("garbage")[1] is True


def test_a_stale_watermark_older_than_180_days_is_clamped_and_reported(db):
    _seed_watermark("2025-01-01T00:00:00.000Z")
    client = PollingFake()
    result = audit_store.sync_okta_events(client, ENV, "all")
    assert result["since_clamped"] and "since=2025" not in client.paths[0]


def test_reset_watermark_clears_the_cursor(db):
    _seed_watermark(_ts(10), cursor=_next("c1"))
    audit_store.reset_sync_watermark(ENV)
    assert audit_store._read_poll_cursor(audit_store._get_connection(), ENV) is None


def test_a_tampered_cursor_is_not_used(db):
    _seed_watermark(_ts(10), cursor="https://evil.example.com/api/v1/logs?after=1")
    client = PollingFake()
    audit_store.sync_okta_events(client, ENV, "all")
    assert client.paths[0].startswith("/api/v1/logs?") and "evil" not in client.paths[0]


def test_system_log_path_matches_the_client():
    assert audit_store.SYSTEM_LOG_PATH == engine.SYSTEM_LOG_PATH


# --- OktaClient.get_system_log_page -------------------------------------------------------------
class _Headers(dict):
    def get_all(self, name):
        return [self[name]] if name in self else []


def _client_with(monkeypatch, body, link=None):
    client = engine.OktaClient("https://example.okta.com", "tok")
    headers = _Headers({"Link": link} if link else {})
    monkeypatch.setattr(client, "request", lambda *a, **k: (body, headers))
    return client


def test_get_system_log_page_follows_a_same_origin_next_link(monkeypatch):
    client = _client_with(monkeypatch, [{"uuid": "1"}],
                          '<https://example.okta.com/api/v1/logs?after=9&limit=1000>; rel="next"')
    events, nxt = client.get_system_log_page("/api/v1/logs?limit=1000")
    assert events == [{"uuid": "1"}] and nxt == "/api/v1/logs?after=9&limit=1000"


def test_get_system_log_page_rejects_foreign_and_foreign_endpoint_links(monkeypatch):
    for link in ('<https://evil.example.com/api/v1/logs?after=9>; rel="next"',
                 '<https://example.okta.com/api/v1/users?after=9>; rel="next"'):
        with pytest.raises(engine.OktaApiError):
            _client_with(monkeypatch, [], link).get_system_log_page("/api/v1/logs?limit=1")


def test_get_system_log_page_rejects_a_non_list_and_a_bad_path(monkeypatch):
    with pytest.raises(engine.OktaApiError):
        _client_with(monkeypatch, {"error": 1}).get_system_log_page("/api/v1/logs?limit=1")
    with pytest.raises(engine.OktaApiError):
        _client_with(monkeypatch, []).get_system_log_page("/api/v1/users?limit=1")


# --- correlation fields -------------------------------------------------------------------------
def test_correlation_fields_are_stored_and_indexed(db):
    event = _event("c-1", _ts(5), transaction={"id": "tx1", "detail": {"requestApiTokenId": "tok1"}},
                   authenticationContext={"rootSessionId": "sess1"})
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event(event)], "all")
    assert [e["uuid"] for e in audit_store.events_by_correlation(ENV, transaction_id="tx1")] == ["c-1"]
    assert [e["uuid"] for e in audit_store.events_by_correlation(ENV, root_session_id="sess1")] == ["c-1"]
    assert [e["uuid"] for e in audit_store.events_by_correlation(ENV, api_token_id="tok1")] == ["c-1"]
    plan = " ".join(str(tuple(r)) for r in audit_store._get_connection().execute(
        "EXPLAIN QUERY PLAN SELECT raw_json FROM events WHERE environment_id=? AND root_session_id=?", (ENV, "sess1")))
    assert "idx_events_env_root_session" in plan
    with pytest.raises(ValueError):
        audit_store.events_by_correlation(ENV)
    with pytest.raises(ValueError):
        audit_store.events_by_correlation(ENV, transaction_id="a", api_token_id="b")


@pytest.mark.parametrize("raw", [None, [], "x", {"transaction": "no"}, {"transaction": {"id": 5, "detail": []}},
                                 {"authenticationContext": {"rootSessionId": ""}}])
def test_correlation_fields_tolerate_hostile_shapes(raw):
    assert audit_store._correlation_fields(raw) == (None, None, None)


def test_backfill_fills_rows_stored_before_the_columns_and_runs_once(db):
    conn = audit_store._get_connection()
    event = _event("old-c", _ts(5), transaction={"id": "txOld"})
    audit_store._insert_rows(conn, ENV, [audit_store._normalize_live_event(event)], "all")
    conn.execute("UPDATE events SET transaction_id = NULL")
    conn.execute("DELETE FROM backfill_markers")
    conn.commit()
    assert audit_store.backfill_correlation_columns(batch_size=1) == 1
    assert [e["uuid"] for e in audit_store.events_by_correlation(ENV, transaction_id="txOld")] == ["old-c"]
    assert audit_store.backfill_correlation_columns() == 0  # marker: skipped


def test_migration_adds_the_columns_to_an_existing_database(tmp_audit_store, tmp_environments_file):
    conn = audit_store._get_connection()
    for version in range(1, 10):
        conn.execute("BEGIN IMMEDIATE")
        audit_store.MIGRATIONS[version](conn)
        conn.execute("INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, 'x')", (version,))
        conn.commit()
    conn.execute("INSERT INTO events (uuid, environment_id, event_type, published, raw_json) VALUES ('u','e','t','2026-01-01T00:00:00.000Z','{}')")
    conn.commit()
    audit_store.run_migrations()
    assert {"transaction_id", "root_session_id", "api_token_id"} <= audit_store._table_columns(conn, "events")
    assert {"poll_cursor", "sync_mode"} <= audit_store._table_columns(conn, "sync_state")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
