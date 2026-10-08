"""Batch 1 of the 2026-10-05 external review's remaining findings
(v5.40.2) -- the compliance archive's data-integrity fixes:

- DATA-03  CSV import never moves the live-sync watermark; timestamps are
           canonicalised; an unusable stored watermark is an explicit error.
- DATA-04  Evidence chain v2 (content-bearing, field-sealing links, deep
           verify) -- implemented, shipped dormant behind EVIDENCE_CHAIN_V2.
- DATA-05  Exception mid-sync records the manifest + error status; the
           scheduler's "ran today" is driven by completion, retries by attempt.
- DATA-08  SQLite floor, idempotent migration 4, transactional migrations.
- DATA-11  Rollback on write paths; single-statement sync_state upsert.
- DATA-12  Per-environment size cap; orphaned-archive listing and purge.
- DATA-13  Window validation; curated re-flagging at boot.
- DATA-14  0600 database files; OPA_AUDIT_DB_PATH override.
- ENG2-04  Sync-schedule validation.
Plus the serve.py wiring: import-while-syncing 409, orphan-archive admin
routes, delete ?purge_archive=1, /integrity?deep=1.
"""
import json
import os
import socket
import stat
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import audit_store
import create_secret_folders as engine

ENV = "11111111-1111-4111-8111-111111111111"
ENV_B = "22222222-2222-4222-8222-222222222222"
BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)


def _ts(hours_ago=0):
    return (BASE - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeOktaClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        self.calls.append((since, until))
        if self._responses:
            item = self._responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return [], True


def _event(uuid, published, event_type="user.session.start", target=None):
    return {
        "uuid": uuid, "eventType": event_type, "published": published,
        "actor": {"id": "00uEXAMPLE", "displayName": "Alex Example", "alternateId": "alex@example.com"},
        "outcome": {"result": "SUCCESS"}, "target": target or [],
    }


def _sync(env, events, since=None):
    since = since or min((e["published"] for e in events), default=_ts(24))
    return audit_store.sync_okta_events(FakeOktaClient([(events, True)]), env, "all", since=since)


@pytest.fixture
def schema(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    return tmp_audit_store


# ---------------------------------------------------------------------------
# DATA-03 / DATA-13: timestamps and the CSV import
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("2026-09-29T10:00:00.000Z", "2026-09-29T10:00:00.000Z"),
    ("2026-09-29T10:00:00Z", "2026-09-29T10:00:00.000Z"),
    ("2026-09-29 10:00:00", "2026-09-29T10:00:00.000Z"),          # Okta CSV shape: space, no zone -> UTC
    ("2026-09-29T12:00:00.5+02:00", "2026-09-29T10:00:00.500Z"),  # offset converted to UTC
    ("2026-09-29T10:00:00.123456789Z", "2026-09-29T10:00:00.123Z"),
    ("Oct 4, 2026 zzz", None),
    ("2026-13-01T00:00:00Z", None),
    ("2026-09-29T10:00:00+24:00", None),       # offset timezone() rejects
    ("0001-01-01T00:30:00+01:00", None),       # UTC conversion underflows
    ("9999-12-31T23:59:59-01:00", None),       # UTC conversion overflows
    ("２０２６-09-29T10:00:00Z", None),          # full-width digits are not digits here
    ("", None),
    (None, None),
])
def test_canonical_published(raw, expected):
    assert audit_store._canonical_published(raw) == expected


def test_canonicalize_stored_timestamps_rewrites_pre_5_40_2_csv_rows(schema):
    """Rows imported before 5.40.2 kept the file's own shape (a space, no
    milliseconds), which sorts before every canonical value -- and dedup
    by uuid means a later live fetch never corrects them. The boot
    backfill rewrites the column and the raw_json copy; a row that cannot
    be parsed is left alone and counted."""
    conn = audit_store._get_connection()
    for uuid, published in (("legacy-1", "2026-09-01 08:00:00"), ("legacy-2", "garbage"), ("fine", "2026-09-02T00:00:00.000Z")):
        raw = _event(uuid, published)
        conn.execute(
            """INSERT INTO events (uuid, environment_id, event_type, published, actor_id, actor_display_name,
               actor_alternate_id, outcome_result, is_curated, raw_json, resource_id, resource_alternate_id, resource_type_detail)
               VALUES (?, ?, ?, ?, 'a', 'A', 'a@example.com', 'SUCCESS', 1, ?, NULL, NULL, NULL)""",
            (uuid, ENV, raw["eventType"], published, json.dumps(raw)),
        )
    conn.commit()
    assert audit_store.canonicalize_stored_timestamps() == (1, 1)
    rows = {r["uuid"]: r for r in audit_store.query_events(ENV, limit=10)}
    assert rows["legacy-1"]["published"] == "2026-09-01T08:00:00.000Z"
    assert rows["legacy-1"]["raw"]["published"] == "2026-09-01T08:00:00.000Z"
    assert rows["fine"]["published"] == "2026-09-02T00:00:00.000Z"
    assert audit_store.canonicalize_stored_timestamps() == (0, 1)  # idempotent; the garbage row is still counted


def test_reset_sync_watermark_clears_only_the_watermark(schema):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at="2099-01-01T00:00:00.000Z", last_sync_completed_at=_ts(5),
                                   last_sync_status="error", last_sync_error="x", ingestion_scope="all")
    assert audit_store.reset_sync_watermark(ENV) == "2099-01-01T00:00:00.000Z"
    state = audit_store.get_sync_state(ENV)
    assert state["last_synced_at"] is None and state["last_sync_status"] is None and state["last_sync_error"] is None
    assert state["last_sync_completed_at"] == _ts(5) and state["ingestion_scope"] == "all"  # untouched
    client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(client, ENV, "all")  # backfills from scratch again
    assert client.calls[0][0] < _ts(24 * 80)


def test_unusable_watermark_still_records_the_attempt(schema):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at="2099-01-01T00:00:00.000Z")
    with pytest.raises(ValueError):
        audit_store.sync_okta_events(FakeOktaClient([]), ENV, "all")
    assert audit_store.get_sync_state(ENV)["last_sync_attempt_at"] is not None  # so the scheduler backs off


def _write_csv(tmp_path, rows):
    path = tmp_path / "export.csv"
    header = "uuid,event_type,timestamp,actor.id,actor.display_name,actor.alternate_id,outcome.result,target0.id,target0.type\n"
    path.write_text(header + "".join(rows), encoding="utf-8")
    return str(path)


def test_csv_import_never_touches_the_live_sync_watermark_and_skips_unparseable_rows(schema, tmp_path):
    _sync(ENV, [_event("live-1", _ts(5))])
    before = audit_store.get_sync_state(ENV)
    csv_path = _write_csv(tmp_path, [
        f"csv-1,user.session.start,2099-01-01T00:00:00.000Z,00uEXAMPLE,Alex Example,alex@example.com,SUCCESS,,\n",  # future
        f"csv-2,user.session.start,Oct 4 2026 zzz,00uEXAMPLE,Alex Example,alex@example.com,SUCCESS,,\n",            # garbage
        f"csv-3,user.session.start,2026-09-01 08:00:00,00uEXAMPLE,Alex Example,alex@example.com,SUCCESS,,\n",       # fine, no zone
    ])
    result = audit_store.import_from_csv(csv_path, ENV, "all")

    assert result["inserted"] == 2 and result["scanned"] == 3 and result["skipped_unparseable"] == 1
    assert result["chain_head"]
    after = audit_store.get_sync_state(ENV)
    assert after["last_synced_at"] == before["last_synced_at"]  # a 2099 row no longer poisons the watermark
    assert after["last_sync_completed_at"] == before["last_sync_completed_at"]
    assert after["last_import_at"] is not None
    stored = {r["uuid"]: r["published"] for r in audit_store.query_events(ENV)}
    assert stored["csv-3"] == "2026-09-01T08:00:00.000Z"  # canonicalised in the column...
    raw = next(r["raw"] for r in audit_store.query_events(ENV) if r["uuid"] == "csv-3")
    assert raw["published"] == "2026-09-01T08:00:00.000Z"  # ...and inside raw_json
    assert "csv-2" not in stored

    # The next live sync still behaves as a resume from the LIVE watermark, not the file's.
    client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(client, ENV, "all")
    assert client.calls[0][0] < before["last_synced_at"]  # overlap window before the live watermark


def test_csv_import_on_a_fresh_environment_does_not_skip_the_first_live_backfill(schema, tmp_path):
    csv_path = _write_csv(tmp_path, ["csv-1,user.session.start,2026-09-01 08:00:00,00uEXAMPLE,A,a@example.com,SUCCESS,,\n"])
    audit_store.import_from_csv(csv_path, ENV, "all")
    assert audit_store.is_first_sync(ENV) is False  # the row exists (reports can read the archive)...
    assert audit_store.environment_has_archive(ENV) is True
    client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(client, ENV, "all")
    ninety_days_ago = (datetime.now(timezone.utc) - timedelta(days=90, minutes=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert client.calls[0][0] >= ninety_days_ago  # ...but the first LIVE sync still backfills the full window
    assert client.calls[0][0] < _ts(24 * 80)


def test_unusable_stored_watermark_is_an_explicit_error_not_a_silent_noop(schema):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at="2099-01-01T00:00:00.000Z")
    with pytest.raises(ValueError, match="unusable"):
        audit_store.sync_okta_events(FakeOktaClient([]), ENV, "all")
    assert audit_store.get_sync_state(ENV)["last_sync_status"] == "error"
    audit_store._upsert_sync_state(conn, ENV, last_synced_at="not a date", last_sync_status=None)
    with pytest.raises(ValueError, match="unusable"):
        audit_store.sync_okta_events(FakeOktaClient([]), ENV, "all")


@pytest.mark.parametrize("since, until, expected", [
    ("2026-09-29", "2026-09-29", ("2026-09-29T00:00:00.000Z", "2026-09-29T23:59:59.999Z")),
    ("2026-09-29T10:00", None, None),  # no seconds -> rejected
    ("2026-09-29T12:00:00+02:00", None, ("2026-09-29T10:00:00.000Z", None)),
    (None, "2026-09-29T10:00:00Z", (None, "2026-09-29T10:00:00.000Z")),
    ("2026-02-30", None, None),
    ("garbage", None, None),
    ("2026-09-30", "2026-09-29", None),  # from after to
    (None, None, (None, None)),
])
def test_normalize_window(since, until, expected):
    if expected is None:
        with pytest.raises(ValueError):
            audit_store.normalize_window(since, until)
    else:
        assert audit_store.normalize_window(since, until) == expected


def test_query_and_count_reject_a_malformed_window(schema):
    _sync(ENV, [_event("e1", _ts(1))])
    with pytest.raises(ValueError):
        audit_store.query_events(ENV, since="2026-09-29T10:00")
    with pytest.raises(ValueError):
        audit_store.count_events(ENV, until="nope")
    # A bare `to` date still includes that whole day (the pre-existing _normalize_until rule).
    day = _ts(1)[:10]
    assert audit_store.count_events(ENV, since=day, until=day) == 1


def test_reflag_curated_rows_promotes_rows_whose_type_became_curated(schema):
    _sync(ENV, [_event("e1", _ts(1), event_type="example.future.event")])
    conn = audit_store._get_connection()
    assert conn.execute("SELECT is_curated FROM events WHERE uuid='e1'").fetchone()[0] == 0
    original = dict(audit_store.COMPLIANCE_EVENT_TYPES)
    try:
        audit_store.COMPLIANCE_EVENT_TYPES["example.future.event"] = "mfa_enforcement"
        assert audit_store.reflag_curated_rows() == 1
        assert conn.execute("SELECT is_curated FROM events WHERE uuid='e1'").fetchone()[0] == 1
        assert audit_store.reflag_curated_rows() == 0  # idempotent
    finally:
        audit_store.COMPLIANCE_EVENT_TYPES.clear()
        audit_store.COMPLIANCE_EVENT_TYPES.update(original)
    # Removing a type from the mapping never demotes rows that were curated when ingested.
    assert conn.execute("SELECT is_curated FROM events WHERE uuid='e1'").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# DATA-05: failure mid-sync
# ---------------------------------------------------------------------------
def test_exception_on_a_later_chunk_records_the_manifest_and_an_error_status(schema):
    start = BASE - timedelta(days=2)
    since = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = FakeOktaClient([
        ([_event("e1", since)], True),
        RuntimeError("network dropped"),
    ])
    with pytest.raises(RuntimeError, match="network dropped"):
        audit_store.sync_okta_events(client, ENV, "all", since=since)

    state = audit_store.get_sync_state(ENV)
    assert state["last_sync_status"] == "error"
    assert "RuntimeError: network dropped" in state["last_sync_error"]
    assert state["last_sync_completed_at"] is None  # never completed
    assert state["last_sync_attempt_at"] is not None
    assert state["total_events_ingested"] == 1
    conn = audit_store._get_connection()
    manifests = conn.execute("SELECT row_count FROM ingestion_manifests WHERE environment_id = ?", (ENV,)).fetchall()
    assert [m["row_count"] for m in manifests] == [1]  # the row that did land is in the chain


def test_successful_sync_sets_completion_and_clears_the_error(schema):
    with pytest.raises(RuntimeError):
        audit_store.sync_okta_events(FakeOktaClient([RuntimeError("boom")]), ENV, "all", since=_ts(5))
    result = _sync(ENV, [_event("e1", _ts(1))], since=_ts(5))
    state = audit_store.get_sync_state(ENV)
    assert state["last_sync_status"] == "success" and state["last_sync_error"] is None
    assert state["last_sync_completed_at"] is not None
    assert result["chain_head"] and result["incomplete_chunks"] == 0


# ---------------------------------------------------------------------------
# DATA-04: evidence chain v2 (dormant by default)
# ---------------------------------------------------------------------------
def test_chain_is_v1_by_default_and_verifies(schema):
    _sync(ENV, [_event("e1", _ts(2))])
    _sync(ENV, [_event("e2", _ts(1))])
    conn = audit_store._get_connection()
    rows = conn.execute("SELECT entry_hash, content_hash, entries_json FROM ingestion_manifests").fetchall()
    assert all(r["entry_hash"] is None and r["content_hash"] is None and r["entries_json"] is None for r in rows)
    result = audit_store.verify_ingestion_chain(ENV)
    assert result["valid"] is True and result["manifest_count"] == 2 and result["legacy_manifests"] == 2
    assert result["broken_at"] is None and result["reason"] is None


@pytest.fixture
def chain_v2(monkeypatch):
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", True)


def test_chain_v2_links_to_the_last_v1_row_and_deep_verifies(schema, chain_v2, monkeypatch):
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", False)
    _sync(ENV, [_event("v1-row", _ts(3))])  # a pre-upgrade manifest
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", True)
    _sync(ENV, [_event("e1", _ts(2), event_type="user.authentication.auth_via_mfa"),  # curated
                _event("e2", _ts(2), event_type="example.noise")])                   # not curated
    head = _sync(ENV, [])["chain_head"]  # an empty batch is still a sealed, distinct link

    conn = audit_store._get_connection()
    rows = conn.execute("SELECT * FROM ingestion_manifests WHERE environment_id = ? ORDER BY id", (ENV,)).fetchall()
    assert rows[0]["entry_hash"] is None
    assert rows[1]["prev_manifest_hash"] == rows[0]["batch_hash"]  # explicit v1 -> v2 boundary
    assert rows[2]["prev_manifest_hash"] == rows[1]["entry_hash"]
    assert rows[1]["entry_hash"] != rows[2]["entry_hash"]  # two different links even though row 3 is empty
    entries = json.loads(rows[1]["entries_json"])
    assert [u for u, _s in entries] == ["e1"]  # curated rows only are listed; row_count still counts both
    assert rows[1]["row_count"] == 2

    shallow = audit_store.verify_ingestion_chain(ENV)
    assert shallow["valid"] is True and shallow["head_hash"] == head and shallow["legacy_manifests"] == 1
    assert shallow["deep_applicable"] is True
    deep = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert deep["valid"] is True and deep["verified_rows"] == 1 and deep["unverifiable_rows"] == 1


def test_chain_v2_rejects_a_downgrade_to_legacy_rows(schema, chain_v2, monkeypatch):
    _sync(ENV, [_event("e1", _ts(2), event_type="user.authentication.auth_via_mfa")])
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", False)
    _sync(ENV, [])  # what nulling the v2 columns of the tail and relinking by batch_hash looks like
    result = audit_store.verify_ingestion_chain(ENV)
    assert result["valid"] is False and "downgraded" in result["reason"]


def test_v1_chain_reports_deep_not_applicable(schema):
    _sync(ENV, [_event("e1", _ts(2))])
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] is True and result["deep"] is True and result["deep_applicable"] is False
    assert result["verified_rows"] == 0


@pytest.mark.parametrize("tamper, reason_fragment", [
    ("UPDATE ingestion_manifests SET row_count = 999 WHERE id = (SELECT MIN(id) FROM ingestion_manifests)", "entry_hash"),
    ("UPDATE ingestion_manifests SET since = 'x' WHERE id = (SELECT MIN(id) FROM ingestion_manifests)", "entry_hash"),
    ("UPDATE ingestion_manifests SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = (SELECT MIN(id) FROM ingestion_manifests)", "entry_hash"),
    ("DELETE FROM ingestion_manifests WHERE id = (SELECT MIN(id) + 1 FROM ingestion_manifests)", "prev_manifest_hash"),
    ("UPDATE events SET raw_json = '{\"uuid\":\"e1\",\"eventType\":\"user.authentication.auth_via_mfa\",\"edited\":true}' WHERE uuid = 'e1'", "content does not match"),
    ("DELETE FROM event_targets WHERE uuid = 'e1'; DELETE FROM events WHERE uuid = 'e1'", "missing from the archive"),
])
def test_chain_v2_detects_every_tamper_the_review_reproduced_against_v1(schema, chain_v2, tamper, reason_fragment):
    """DATA-04 reproduced each of these against the v1 chain and got
    valid=True every time. Each must now break the chain, with a reason."""
    _sync(ENV, [_event("e1", _ts(3), event_type="user.authentication.auth_via_mfa")])
    _sync(ENV, [])
    _sync(ENV, [])
    conn = audit_store._get_connection()
    conn.executescript(tamper)
    conn.commit()
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] is False
    assert result["broken_at"] is not None
    assert reason_fragment in result["reason"]


def test_chain_v2_tolerates_a_pruned_non_curated_row(schema, chain_v2):
    _sync(ENV, [_event("noise", _ts(3), event_type="example.noise"),
                _event("kept", _ts(3), event_type="user.authentication.auth_via_mfa")])
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM events WHERE uuid = 'noise'")  # what retention pruning legitimately does
    conn.commit()
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] is True and result["verified_rows"] == 1 and result["unverifiable_rows"] == 1


# ---------------------------------------------------------------------------
# DATA-08: migrations
# ---------------------------------------------------------------------------
def test_migration_4_is_idempotent_when_the_column_is_already_gone(tmp_audit_store, tmp_environments_file):
    conn = audit_store._get_connection()
    # Apply 1..3, then drop the column by hand (what a crash between the DROP and the version INSERT left behind).
    for v in (1, 2, 3):
        audit_store.MIGRATIONS[v](conn)
        conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, 'x')", (v,))
    conn.execute("ALTER TABLE app_environments DROP COLUMN preserve_logs_locally")
    conn.commit()
    audit_store.run_migrations()  # must not raise "no such column"
    assert audit_store._schema_version(conn) == max(audit_store.MIGRATIONS)


def test_migration_6_is_idempotent_and_adds_the_columns(schema):
    conn = audit_store._get_connection()
    assert {"content_hash", "entry_hash", "entries_json"} <= audit_store._table_columns(conn, "ingestion_manifests")
    assert {"last_sync_attempt_at", "last_import_at"} <= audit_store._table_columns(conn, "sync_state")
    audit_store._migration_006_evidence_chain_v2_and_sync_attempts(conn)  # re-run: no "duplicate column"
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_events_env_type_published" in names


def test_run_migrations_refuses_an_old_sqlite(tmp_audit_store, tmp_environments_file, monkeypatch):
    monkeypatch.setattr(audit_store.sqlite3, "sqlite_version_info", (3, 34, 1))
    monkeypatch.setattr(audit_store.sqlite3, "sqlite_version", "3.34.1")
    with pytest.raises(RuntimeError, match="too old"):
        audit_store.run_migrations()


def test_a_failing_migration_is_rolled_back_atomically(tmp_audit_store, tmp_environments_file, monkeypatch):
    audit_store.run_migrations()
    conn = audit_store._get_connection()

    def bad_migration(c):
        c.execute("CREATE TABLE half_done (x INTEGER)")
        raise RuntimeError("midway")

    monkeypatch.setitem(audit_store.MIGRATIONS, 99, bad_migration)
    with pytest.raises(RuntimeError, match="midway"):
        audit_store.run_migrations()
    assert conn.in_transaction is False
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "half_done" not in names  # the DDL was undone with the failed version
    assert audit_store._schema_version(conn) == max(v for v in audit_store.MIGRATIONS if v != 99)


# ---------------------------------------------------------------------------
# DATA-11: write paths
# ---------------------------------------------------------------------------
def test_insert_rows_rolls_back_a_bad_batch_and_leaves_no_open_transaction(schema):
    conn = audit_store._get_connection()
    good = audit_store._normalize_live_event(_event("ok-1", _ts(1)))
    bad = list(good)
    bad[0], bad[-1] = "bad-1", ["not-a-dict-target"]  # targets fan-out does t.get(...) -> AttributeError
    with pytest.raises(AttributeError):
        audit_store._insert_rows(conn, ENV, [good, tuple(bad)], "all")
    assert conn.in_transaction is False
    assert audit_store.count_events(ENV) == 0  # the good row did not survive the failed batch


def test_upsert_sync_state_writes_only_the_supplied_fields(schema):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_synced_at=_ts(5), last_sync_status="success", ingestion_scope="all")
    audit_store._upsert_sync_state(conn, ENV, last_sync_error="x")  # a racing writer touching one field
    state = audit_store.get_sync_state(ENV)
    assert state["last_synced_at"] == _ts(5) and state["last_sync_status"] == "success" and state["ingestion_scope"] == "all"
    assert state["last_sync_error"] == "x"
    with pytest.raises(ValueError):
        audit_store._upsert_sync_state(conn, ENV, not_a_column=1)


# ---------------------------------------------------------------------------
# DATA-12: size cap and orphaned archives
# ---------------------------------------------------------------------------
def test_size_cap_counts_only_this_environments_payload(schema):
    big = {"padding": "x" * 20000}
    noise = "example.noise"  # NOT a curated type -- curated rows are never pruned by any cap
    _sync(ENV_B, [{**_event(f"b{i}", _ts(100 + i), event_type=noise), **big} for i in range(10)])  # ~200 KB belonging to ENV_B
    _sync(ENV, [{**_event("a-old", _ts(72 * 24), event_type=noise), **big}, {**_event("a-new", _ts(1), event_type=noise), **big}])
    # ENV holds ~40 KB; a 100 KB cap must NOT prune it even though the FILE holds ~240 KB.
    result = audit_store.prune_events(ENV, max_size_mb=0.1)
    assert result["pruned"] == 0
    assert audit_store.count_events(ENV) == 2
    # A cap below ENV's own payload prunes ENV's oldest non-curated rows only.
    result = audit_store.prune_events(ENV, max_size_mb=0.03)
    assert result["pruned"] == 1
    assert {r["uuid"] for r in audit_store.query_events(ENV)} == {"a-new"}
    assert audit_store.count_events(ENV_B) == 10  # the neighbour is untouched


def test_orphaned_archives_are_listed_and_purged_only_once_the_environment_is_gone(schema, fake_keyring):
    _sync(ENV, [_event("e1", _ts(1))])
    assert [a["environment_id"] for a in audit_store.list_orphaned_archives()] == [ENV]  # no app_environments row
    # Register a real environment, then confirm it is NOT an orphan and cannot be purged directly.
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "k", "key_secret": "s"}, owner=engine.LOCAL_OWNER_KEY,
    )
    _sync(env_id, [_event("e2", _ts(1))])
    assert env_id not in {a["environment_id"] for a in audit_store.list_orphaned_archives()}
    with pytest.raises(ValueError, match="still exists"):
        audit_store.purge_environment_archive(env_id)
    # Default delete keeps the archive as an orphan...
    engine.delete_environment("dev", owner=engine.LOCAL_OWNER_KEY)
    orphans = {a["environment_id"]: a for a in audit_store.list_orphaned_archives()}
    assert env_id in orphans and orphans[env_id]["event_count"] == 1 and orphans[env_id]["manifest_count"] == 1
    # ...which an admin can then purge, with per-table counts.
    counts = audit_store.purge_environment_archive(env_id)
    assert counts["events"] == 1 and counts["ingestion_manifests"] == 1 and counts["sync_state"] == 1
    assert env_id not in {a["environment_id"] for a in audit_store.list_orphaned_archives()}


def test_delete_environment_can_purge_its_archive_in_one_step(schema, fake_keyring):
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "k", "key_secret": "s"}, owner=engine.LOCAL_OWNER_KEY,
    )
    _sync(env_id, [_event("e1", _ts(1))])
    result = engine.delete_environment("dev", owner=engine.LOCAL_OWNER_KEY, purge_archive=True)
    assert result["environment_id"] == env_id and result["was_active"] is False
    assert result["archive"]["events"] == 1 and result["archive"]["sync_state"] == 1
    assert audit_store.count_events(env_id) == 0
    assert audit_store.get_sync_state(env_id) is None
    # Without purge the archive stays and the result says so.
    _, env_id2 = engine.upsert_environment(
        "dev2", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "k", "key_secret": "s"}, owner=engine.LOCAL_OWNER_KEY,
    )
    assert engine.delete_environment("dev2", owner=engine.LOCAL_OWNER_KEY)["archive"] is None


# ---------------------------------------------------------------------------
# DATA-14: file modes and path override
# ---------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_database_files_are_created_owner_only(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    mode = stat.S_IMODE(os.stat(str(tmp_audit_store)).st_mode)
    assert mode == 0o600
    for sidecar in ("-wal", "-shm"):
        path = str(tmp_audit_store) + sidecar
        if os.path.exists(path):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_audit_db_path_honours_the_environment_override(monkeypatch, tmp_path):
    monkeypatch.setenv("OPA_AUDIT_DB_PATH", str(tmp_path / "elsewhere.db"))
    assert audit_store._audit_db_path() == str(tmp_path / "elsewhere.db")
    monkeypatch.delenv("OPA_AUDIT_DB_PATH")
    assert audit_store._audit_db_path().endswith("audit_store.db")


# ---------------------------------------------------------------------------
# ENG2-04: schedule validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    {"run_time": "25:00"}, {"run_time": "2:75"}, {"run_time": "abc"}, {"run_time": ""}, {"run_time": 200},
    {"retention_days": 0}, {"retention_days": -1}, {"retention_days": "7"}, {"retention_days": True}, {"retention_days": 1.5},
    {"retention_max_size_mb": 0}, {"enabled": "false"}, {"enabled": 1}, {"ingestion_scope": "everything"},
    {"surprise": 1}, ["not", "a", "dict"],
])
def test_validate_sync_schedule_config_rejects(bad):
    with pytest.raises(ValueError):
        engine.validate_sync_schedule_config(bad)


def test_validate_sync_schedule_config_accepts_and_whitelists():
    ok = {"enabled": True, "run_time": "02:30", "ingestion_scope": "all", "retention_days": 30, "retention_max_size_mb": None}
    assert engine.validate_sync_schedule_config(ok) == ok
    assert engine.validate_sync_schedule_config({}) == {}


def test_get_sync_schedule_reads_a_stored_invalid_retention_as_no_limit(schema, fake_keyring):
    """An install that saved 0 before validation existed must stop losing
    every non-curated event on each sync -- the read side coerces, the
    write side rejects."""
    _, env_id = engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"})
    conn = audit_store._get_connection()
    conn.execute(
        "INSERT INTO sync_schedules (environment_id, enabled, run_time, ingestion_scope, retention_days, retention_max_size_mb) "
        "VALUES (?, 1, '02:00', 'all', 0, -5)", (env_id,),
    )
    conn.commit()
    schedule = engine.get_sync_schedule("dev")
    assert schedule["retention_days"] is None and schedule["retention_max_size_mb"] is None


def test_set_sync_schedule_rejects_zero_retention_and_never_stores_unknown_keys(schema, fake_keyring):
    engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"})
    with pytest.raises(ValueError):
        engine.set_sync_schedule("dev", {"retention_days": 0})
    with pytest.raises(ValueError):
        engine.set_sync_schedule("dev", {"enabled": True, "evil_key": "x"})
    saved = engine.set_sync_schedule("dev", {"enabled": True, "run_time": "03:15", "retention_days": 14})
    assert saved["run_time"] == "03:15" and saved["retention_days"] == 14 and "evil_key" not in saved


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server(schema, fake_keyring, tmp_audit_log, monkeypatch):
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
            requests.get(base_url + "/api/version", timeout=0.5)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    yield base_url, serve
    server_instance.shutdown()
    server_instance.server_close()


def _headers(sub="00uUSER", admin="false"):
    return {"X-Nginx-Proxy-Secret": "test-proxy-secret", "X-Auth-Sub": sub, "X-Auth-Is-Admin": admin}


def test_orphan_archive_routes_are_admin_only_and_audit_logged(live_server, tmp_audit_log):
    base_url, serve = live_server
    _sync(ENV, [_event("e1", _ts(1))])  # ENV has no app_environments row -> orphan

    assert requests.get(f"{base_url}/api/archives/orphaned", headers=_headers(), timeout=5).status_code == 403
    assert requests.delete(f"{base_url}/api/archives/{ENV}", headers=_headers(), timeout=5).status_code == 403

    listed = requests.get(f"{base_url}/api/archives/orphaned", headers=_headers(admin="true"), timeout=5)
    assert listed.status_code == 200
    assert [a["environment_id"] for a in listed.json()["archives"]] == [ENV]

    # Not while that environment's ingest slot is held.
    with serve._sync_jobs_lock:
        serve._sync_jobs[ENV] = {"status": "running", "steps": [], "error": None}
    assert requests.delete(f"{base_url}/api/archives/{ENV}", headers=_headers(admin="true"), timeout=5).status_code == 409
    with serve._sync_jobs_lock:
        serve._sync_jobs.pop(ENV, None)

    purged = requests.delete(f"{base_url}/api/archives/{ENV}", headers=_headers(admin="true"), timeout=5)
    assert purged.status_code == 200 and purged.json()["events"] == 1
    assert audit_store.count_events(ENV) == 0
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    assert any(e["action"] == "archive.purge" and e["details"]["environment_id"] == ENV for e in entries)
    # An id with no archive rows at all is a 404, and leaves no audit entry.
    assert requests.delete(f"{base_url}/api/archives/{ENV_B}", headers=_headers(admin="true"), timeout=5).status_code == 404
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    assert not any(e["action"] == "archive.purge" and e["details"]["environment_id"] == ENV_B for e in entries)
    # Purging an id that still has an environment is refused (409), never silently done.
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uADMIN",
    )
    assert requests.delete(f"{base_url}/api/archives/{env_id}", headers=_headers("00uADMIN", "true"), timeout=5).status_code == 409


def test_environment_delete_purges_only_when_asked_and_only_for_admins(live_server, tmp_audit_log):
    base_url, serve = live_server
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    _sync(env_id, [_event("e1", _ts(1))])
    # The owner may delete the environment but not its evidence.
    resp = requests.delete(f"{base_url}/api/environments/dev?purge_archive=1", headers=_headers(), timeout=5)
    assert resp.status_code == 403
    assert audit_store.count_events(env_id) == 1
    # An admin acting on it by id may purge, and the audit entry carries the counts.
    resp = requests.delete(f"{base_url}/api/environments/dev?purge_archive=1&id={env_id}", headers=_headers("00uADMIN", "true"), timeout=5)
    assert resp.status_code == 200 and resp.json() == {"deleted": "dev", "archive_purged": True}
    assert audit_store.count_events(env_id) == 0
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    delete_entry = next(e for e in entries if e["action"] == "environment.delete")
    assert delete_entry["details"]["archive_purged"]["events"] == 1


def test_delete_and_unshare_drop_other_owners_live_sessions(live_server):
    """ENG1-06: B activated A's shared environment; A's unshare (or a
    delete) must end B's live session now, not at the next restart."""
    base_url, serve = live_server
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uOWNERA",
    )
    engine.set_environment_shared("dev", "00uOWNERA", True)
    for sub in ("00uOWNERA", "00uOWNERB"):
        with serve._sessions_lock:
            serve._sessions[sub] = {"client": object(), "okta_client": None, "env_name": "dev", "env_id": env_id}
    resp = requests.post(f"{base_url}/api/environments/dev/share", headers=_headers("00uOWNERA"), json={"shared": False}, timeout=5)
    assert resp.status_code == 200
    with serve._sessions_lock:
        assert "00uOWNERB" not in serve._sessions and "00uOWNERA" in serve._sessions  # the owner keeps their own
    with serve._sessions_lock:
        serve._sessions["00uOWNERB"] = {"client": object(), "okta_client": None, "env_name": "dev", "env_id": env_id}
    resp = requests.delete(f"{base_url}/api/environments/dev", headers=_headers("00uOWNERA"), timeout=5)
    assert resp.status_code == 200
    with serve._sessions_lock:
        assert "00uOWNERB" not in serve._sessions and "00uOWNERA" not in serve._sessions


def test_reset_watermark_route(live_server, tmp_audit_log):
    base_url, serve = live_server
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    audit_store._upsert_sync_state(audit_store._get_connection(), env_id, last_synced_at="2099-01-01T00:00:00.000Z")
    assert requests.post(f"{base_url}/api/environments/nope/sync/reset_watermark", headers=_headers(), timeout=5).status_code == 404
    with serve._sync_jobs_lock:
        serve._sync_jobs[env_id] = {"status": "running", "steps": [], "error": None}
    assert requests.post(f"{base_url}/api/environments/dev/sync/reset_watermark", headers=_headers(), timeout=5).status_code == 409
    with serve._sync_jobs_lock:
        serve._sync_jobs.pop(env_id, None)
    resp = requests.post(f"{base_url}/api/environments/dev/sync/reset_watermark", headers=_headers(), timeout=5)
    assert resp.status_code == 200 and resp.json()["previous_watermark"] == "2099-01-01T00:00:00.000Z"
    assert audit_store.get_sync_state(env_id)["last_synced_at"] is None
    entries = [json.loads(line) for line in open(tmp_audit_log, encoding="utf-8") if line.strip()]
    assert any(e["action"] == "sync.reset_watermark" for e in entries)


def test_deep_integrity_is_admin_only(live_server):
    base_url, serve = live_server
    engine.upsert_environment("dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER")
    engine.set_environment_shared("dev", "00uUSER", True)  # visible to the admin identity too
    assert requests.get(f"{base_url}/api/environments/dev/integrity?deep=1", headers=_headers(), timeout=5).status_code == 403
    assert requests.get(f"{base_url}/api/environments/dev/integrity", headers=_headers(), timeout=5).status_code == 200
    assert requests.get(f"{base_url}/api/environments/dev/integrity?deep=1", headers=_headers("00uADMIN", "true"), timeout=5).status_code == 200


def test_csv_import_holds_the_ingest_slot_so_a_sync_cannot_start(live_server, tmp_path, monkeypatch):
    base_url, serve = live_server
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    monkeypatch.setattr(serve, "PROJECT_ROOT", tmp_path, raising=False)
    (tmp_path / "export.csv").write_text("uuid,event_type,timestamp\n", encoding="utf-8")
    seen = {}

    def slow_import(csv_path, environment_id, ingestion_scope, on_progress=None):
        with serve._sync_jobs_lock:
            seen["slot"] = serve._sync_jobs.get(environment_id, {}).get("status")
        seen["sync_started"] = serve._start_sync_job(environment_id, "dev", "all", owner="00uUSER")
        return {"inserted": 0, "scanned": 0, "skipped_unparseable": 0, "chain_head": "x"}

    monkeypatch.setattr(audit_store, "import_from_csv", slow_import)
    resp = requests.post(f"{base_url}/api/environments/dev/sync/import_csv", headers=_headers(),
                         json={"csv_path": "export.csv", "ingestion_scope": "all"}, timeout=5)
    assert resp.status_code == 200
    assert seen == {"slot": "running", "sync_started": False}  # the slot was held; the sync was refused
    with serve._sync_jobs_lock:
        assert env_id not in serve._sync_jobs  # and released afterwards


def test_credential_failure_records_a_sync_attempt(live_server):
    base_url, serve = live_server
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )  # no Okta URL/token
    assert serve._start_sync_job(env_id, "dev", "all", owner="00uUSER") is False
    state = audit_store.get_sync_state(env_id)
    assert state["last_sync_status"] == "error" and state["last_sync_attempt_at"] is not None
    assert "Okta URL/API token" in state["last_sync_error"]


def test_secrets_report_falls_back_to_live_until_an_archive_exists(live_server, monkeypatch):
    """A sync_state row now exists from the moment a sync STARTS; a first
    sync that failed at once must not switch the report to an empty
    archive."""
    base_url, serve = live_server
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    audit_store._upsert_sync_state(audit_store._get_connection(), env_id, last_sync_attempt_at=_ts(1), last_sync_status="error")
    with serve._sessions_lock:
        serve._sessions["00uUSER"] = {"client": object(), "okta_client": object(), "env_name": "dev", "env_id": env_id}
    calls = []
    monkeypatch.setattr(engine, "build_secrets_access_report", lambda *a, **k: calls.append("live") or {"live": True})
    monkeypatch.setattr(engine, "build_project_secrets_report_from_archive", lambda *a, **k: calls.append("archive") or {"archive": True})
    requests.get(f"{base_url}/api/resource_groups/rg/projects/p/secrets_access_report", headers=_headers(), timeout=5)
    assert calls == ["live"]
    _sync(env_id, [])  # a COMPLETED sync -> archive path from now on
    requests.get(f"{base_url}/api/resource_groups/rg/projects/p/secrets_access_report", headers=_headers(), timeout=5)
    assert calls == ["live", "archive"]


def test_csv_import_is_refused_while_a_sync_is_running(live_server, tmp_path, monkeypatch):
    base_url, serve = live_server
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    monkeypatch.setattr(serve, "PROJECT_ROOT", tmp_path, raising=False)
    (tmp_path / "export.csv").write_text("uuid,event_type,timestamp\n", encoding="utf-8")
    with serve._sync_jobs_lock:
        serve._sync_jobs[env_id] = {"status": "running", "steps": [], "error": None}
    resp = requests.post(f"{base_url}/api/environments/dev/sync/import_csv", headers=_headers(),
                         json={"csv_path": "export.csv", "ingestion_scope": "all"}, timeout=5)
    assert resp.status_code == 409
    assert "sync is running" in resp.json()["error"]


def test_integrity_route_supports_deep_verification(live_server):
    base_url, serve = live_server
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    _sync(env_id, [_event("e1", _ts(1))])
    engine.set_environment_shared("dev", "00uUSER", True)  # so the admin identity below can see it
    shallow = requests.get(f"{base_url}/api/environments/dev/integrity", headers=_headers(), timeout=5).json()
    deep = requests.get(f"{base_url}/api/environments/dev/integrity?deep=1", headers=_headers("00uADMIN", "true"), timeout=5).json()
    assert shallow["valid"] is True and shallow["deep"] is False
    assert deep["valid"] is True and deep["deep"] is True and deep["deep_applicable"] is False  # v1 rows: nothing sealed to re-read


def test_report_routes_return_400_for_a_malformed_window(live_server):
    base_url, serve = live_server
    name, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner="00uUSER",
    )
    resp = requests.get(f"{base_url}/api/reports/mfa_enforcement?environment=dev&from=2026-09-29T10:00", headers=_headers(), timeout=5)
    assert resp.status_code == 400
    resp = requests.get(f"{base_url}/api/reports?environment=dev&from=garbage", headers=_headers(), timeout=5)
    assert resp.status_code == 400


def test_curated_scope_resume_point_comes_from_every_fetched_row(schema):
    """DATA-09 in the DEFAULT scope: a capped chunk whose rows after the
    cursor are all non-curated must still advance the resume point (it
    is the newest row FETCHED, not the newest row stored)."""
    start = BASE - timedelta(days=2)
    since = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    noise_at = (start + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = FakeOktaClient([
        ([_event("n1", noise_at, event_type="example.noise")], False),  # capped, nothing curated
        ([], True),
    ])
    result = audit_store.sync_okta_events(client, ENV, "curated", since=since)
    assert result["complete"] is True and result["incomplete_chunks"] == 1
    assert client.calls[1][0] == noise_at
    assert audit_store.count_events(ENV) == 0  # the noise row was never stored (curated scope)
