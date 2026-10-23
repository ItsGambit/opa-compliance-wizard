"""Evidence package core (5.53.0, WP2): period, one-snapshot reader, server CSV writer, coverage, completeness.

Every archive here is built with the real ingestion code (sync_okta_events, _insert_rows, _write_manifest_row);
nothing is stubbed in audit_store. Synthetic data only."""
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import threading
import zipfile
from datetime import date, datetime, timedelta, timezone

import pytest

import audit_store
import evidence_core as core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(ROOT, "tools", "verify_evidence_package.py")
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "csv_formula_cases.json")
ENV = "11111111-1111-1111-1111-111111111111"
OTHER_ENV = "22222222-2222-2222-2222-222222222222"
FIXED_TODAY = date(2026, 10, 23)


# ---------------------------------------------------------------------------
# Archive builders (real ingestion code)
# ---------------------------------------------------------------------------
def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def evt(uuid, when, event_type="user.session.start", actor="Someone", targets=None, outcome="SUCCESS"):
    return {
        "uuid": uuid, "eventType": event_type, "published": when if isinstance(when, str) else iso(when),
        "displayMessage": "synthetic " + event_type,
        "actor": {"id": "00uActor", "displayName": actor, "alternateId": "user@example.com"},
        "outcome": {"result": outcome}, "client": {"ipAddress": "192.0.2.1"},
        "target": targets if targets is not None else [{"id": "00uT", "type": "User", "displayName": "Target"}],
    }


def ingest(events, since=None, until=None, scope="all", source="sync", environment_id=ENV):
    """Stores events and seals one manifest for them, exactly as an ingestion call does."""
    conn = audit_store._get_connection()
    rows = [audit_store._normalize_live_event(e) for e in events]
    _inserted, _mx, new_entries = audit_store._insert_rows(conn, environment_id, rows, scope)
    with audit_store._db_lock:
        conn.execute("BEGIN IMMEDIATE")
        audit_store._write_manifest_row(conn, environment_id, source, since, until, new_entries)
        conn.commit()


def set_state(**fields):
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, **fields)


def set_retention(days=None, size_mb=None):
    conn = audit_store._get_connection()
    now = iso(datetime.now(timezone.utc))
    conn.execute(
        "INSERT OR IGNORE INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name, key_id, created_at, updated_at) "
        "VALUES (?, 'owner', 'Synthetic', 'example.okta.com', 'team', 'key', ?, ?)", (ENV, now, now))
    conn.execute(
        "INSERT OR REPLACE INTO sync_schedules (environment_id, enabled, run_time, ingestion_scope, retention_days, retention_max_size_mb) "
        "VALUES (?, 1, '02:00', 'all', ?, ?)", (ENV, days, size_mb))
    conn.commit()


@pytest.fixture
def store(tmp_audit_store):
    audit_store.run_migrations()
    return tmp_audit_store


def period_of(start, end, today=FIXED_TODAY):
    return core.parse_period(start, end, today=today)


MARCH = period_of("2026-03-01", "2026-03-05")


def march(day, hh=10, mm=0, ss=0, ms=0):
    return datetime(2026, 3, day, hh, mm, ss, ms * 1000, tzinfo=timezone.utc)


def build_march_archive():
    """A small archive with curated and non-curated events inside and outside the period, in two syncs and one
    other environment."""
    first = [
        evt("a-01", march(1, 0, 0, 0)),                                # first instant of the period
        evt("a-02", march(2), "user.lifecycle.create"),
        evt("a-03", march(2), "user.lifecycle.deactivate"),
        evt("a-04", march(3), "app.misc.synthetic"),                   # not curated
        evt("a-05", datetime(2026, 2, 28, 23, 59, 59, 999000, tzinfo=timezone.utc)),  # just before
    ]
    second = [
        evt("b-01", march(5, 23, 59, 59, 999)),                        # last instant of the period
        evt("b-02", datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc)),  # just after
        evt("b-03", march(4), "group.user_membership.add"),
        evt("b-04", march(4), "pam.secret.reveal"),
    ]
    ingest(first, since="2026-02-25T00:00:00.000Z", until="2026-03-04T00:00:00.000Z")
    ingest(second, since="2026-03-03T23:00:00.000Z", until="2026-03-07T00:00:00.000Z")
    ingest([evt("z-01", march(2))], environment_id=OTHER_ENV)


def direct_report_count(report_key, period=MARCH, environment_id=ENV):
    types = audit_store._event_types_for_report(report_key)
    conn = audit_store._get_connection()
    marks = ",".join("?" for _ in types)
    return conn.execute(
        f"SELECT COUNT(*) FROM events WHERE environment_id = ? AND event_type IN ({marks}) "
        "AND substr(published, 1, 10) >= ? AND substr(published, 1, 10) <= ?",
        (environment_id, *types, period.start.isoformat(), period.end.isoformat())).fetchone()[0]


# ---------------------------------------------------------------------------
# 1. Period
# ---------------------------------------------------------------------------
def test_period_is_inclusive_and_half_open_on_published():
    p = period_of("2026-03-01", "2026-03-05")
    assert (p.start_ts, p.end_ts) == ("2026-03-01T00:00:00.000Z", "2026-03-06T00:00:00.000Z")
    assert p.day_count == 5 and p.days()[0] == date(2026, 3, 1) and p.days()[-1] == date(2026, 3, 5)
    assert p.as_dict() == {"start": "2026-03-01", "end": "2026-03-05"}


def test_period_one_day_and_today_are_allowed():
    assert period_of("2026-10-23", "2026-10-23").day_count == 1


@pytest.mark.parametrize("start,end,fragment", [
    ("2026-03-05", "2026-03-01", "after the end"),
    ("2026-10-22", "2026-10-24", "future"),
    ("2026-02-30", "2026-03-01", "real calendar date"),
    ("26-03-01", "2026-03-02", "YYYY-MM-DD"),
    ("2026-03-01T00:00:00Z", "2026-03-02", "YYYY-MM-DD"),
    ("٢٠٢٦-03-01", "2026-03-02", "YYYY-MM-DD"),   # Arabic-Indic digits are not dates
    ("", "2026-03-02", "YYYY-MM-DD"),
    (None, "2026-03-02", "YYYY-MM-DD"),
    (20260301, "2026-03-02", "YYYY-MM-DD"),
    ("2000-01-01", "2026-10-23", "longer than"),
])
def test_period_refuses_bad_input(start, end, fragment):
    with pytest.raises(core.PeriodError) as err:
        period_of(start, end)
    assert fragment in str(err.value)


def test_period_default_today_is_utc_today():
    today = datetime.now(timezone.utc).date()
    assert core.parse_period(today.isoformat(), today.isoformat()).end == today
    with pytest.raises(core.PeriodError):
        core.parse_period(today.isoformat(), (today + timedelta(days=1)).isoformat())


# ---------------------------------------------------------------------------
# 3. CSV writer
# ---------------------------------------------------------------------------
def _cases():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: json.dumps(c["input"]))
def test_shared_cases_neutralisation_and_quoting(case):
    assert core.neutralize_formula(case["input"]) == case["neutralised"]
    assert core.csv_field(case["input"]) == case["server_csv"]
    # the same text as the app's export, quoted when the app did not need to
    fe = case["frontend_csv"]
    assert case["server_csv"] == (fe if fe.startswith('"') else '"' + fe + '"')


def test_shared_cases_are_the_ones_the_frontend_test_reads():
    src = open(os.path.join(ROOT, "frontend", "src", "utils", "export.test.ts"), encoding="utf-8").read()
    assert "tests/fixtures/csv_formula_cases.json" in src


def test_csv_line_is_quoted_crlf_no_bom_and_round_trips():
    line = core.csv_line(["a", None, "x,y", 'q"q', "=1+1", 7])
    assert line == b'"a","","x,y","q""q","\'=1+1","7"\r\n'
    assert not line.startswith(b"\xef\xbb\xbf")
    row = next(csv.reader(io.StringIO(line.decode("utf-8"), newline="")))
    assert row == ["a", "", "x,y", 'q"q', "'=1+1", "7"]


def test_csv_embedded_newlines_stay_inside_quotes():
    buf = io.BytesIO()
    w = core.CsvWriter(buf, ["c"])
    w.write_row(["line1\nline2\r\nline3"])
    w.flush()
    rows = list(csv.reader(io.StringIO(buf.getvalue().decode("utf-8"), newline="")))
    assert rows == [["c"], ["line1\nline2\r\nline3"]]


def test_csv_lone_surrogate_does_not_fail_the_build():
    assert core.csv_line(["a\ud800b"]) == b'"a?b"\r\n'


def test_report_csv_header_has_event_uuid_and_the_apps_columns():
    assert core.REPORT_CSV_COLUMNS[-1] == "event_uuid"
    # complianceReportRow in frontend/src/utils/exportSections.ts, in order
    src = open(os.path.join(ROOT, "frontend", "src", "utils", "exportSections.ts"), encoding="utf-8").read()
    body = src[src.index("export function complianceReportRow"):src.index("export function complianceReportExportSections")]
    app_columns = re.findall(r"^\s+(?:'([^']+)'|(\w+)):", body, re.M)
    app_columns = [a or b for a, b in app_columns]
    assert list(core.REPORT_CSV_COLUMNS[:-1]) == app_columns


def test_resource_type_labels_equal_the_frontends():
    src = open(os.path.join(ROOT, "frontend", "src", "utils", "resourceTypeLabels.ts"), encoding="utf-8").read()
    body = src[src.index("RESOURCE_TYPE_DETAIL_LABEL"):src.index("/** The most specific label")]
    pairs = dict(re.findall(r"^\s+(\w+): '([^']+)',", body, re.M))
    assert pairs == core.RESOURCE_TYPE_DETAIL_LABEL


def test_report_csv_neutralises_every_cell_and_header(store):
    ingest([evt("h-1", march(2), actor="=cmd|' /C calc'!A0", targets=[{"id": "-1", "type": "User", "displayName": "@evil"}])],
           since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        buf = io.BytesIO()
        assert core.write_report_csv(buf, snap.report_rows("session_activity")) == 1
    text = buf.getvalue().decode("utf-8")
    assert text.endswith("\r\n") and "\n" not in text.replace("\r\n", "")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert rows[0] == list(core.REPORT_CSV_COLUMNS)
    data = dict(zip(rows[0], rows[1]))
    assert data["User"] == "'=cmd|' /C calc'!A0"
    assert data["Affected Resource"] == "'@evil"
    assert data["event_uuid"] == "h-1"
    assert data["Timestamp"] == "2026-03-02T10:00:00.000Z"
    for line in text.split("\r\n")[:-1]:
        assert line.startswith('"') and line.endswith('"')


def test_empty_report_is_a_header_only_file(store):
    with core.open_snapshot(ENV, MARCH) as snap:
        buf = io.BytesIO()
        assert core.write_report_csv(buf, snap.report_rows("pam_secrets")) == 0
    assert buf.getvalue().count(b"\r\n") == 1


def test_missing_resource_is_an_em_dash_like_the_app(store):
    ingest([evt("h-2", march(2), targets=[])], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        row = next(snap.report_rows("session_activity"))
    assert core.report_csv_cells(row)[7] == "—"


# ---------------------------------------------------------------------------
# 2. One-snapshot reader
# ---------------------------------------------------------------------------
def test_events_ndjson_is_byte_exact_ordered_and_inside_the_period(store):
    build_march_archive()
    with core.open_snapshot(ENV, MARCH) as snap:
        lines = list(snap.event_lines())
    conn = audit_store._get_connection()
    expect = [r["raw_json"].encode("utf-8") + b"\n" for r in conn.execute(
        "SELECT raw_json FROM events WHERE environment_id = ? AND substr(published, 1, 10) BETWEEN '2026-03-01' AND '2026-03-05' "
        "ORDER BY published, uuid", (ENV,))]
    assert lines == expect
    uuids = [json.loads(line)["uuid"] for line in lines]
    # both boundary instants are inside; the events just outside and the other environment's are not; equal times by uuid
    assert uuids == ["a-01", "a-02", "a-03", "a-04", "b-03", "b-04", "b-01"]


def test_ties_are_broken_by_uuid(store):
    ingest([evt(u, march(2)) for u in ("m-3", "m-1", "m-2", "m-10")], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        assert [json.loads(l)["uuid"] for l in snap.event_lines()] == ["m-1", "m-10", "m-2", "m-3"]
        assert [r["uuid"] for r in snap.report_rows("session_activity")] == ["m-1", "m-10", "m-2", "m-3"]


def test_event_lines_use_the_published_order_index(store):
    build_march_archive()
    conn = audit_store._get_connection()
    plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + core._EVENT_LINE_SQL, (ENV, MARCH.start_ts, MARCH.end_ts)))
    assert "idx_events_env_published" in plan
    assert "TEMP B-TREE FOR ORDER BY" not in plan.replace("RIGHT PART OF ORDER BY", "")  # only the tie-break part is sorted


def test_report_counts_equal_direct_sql_for_every_report(store):
    """Acceptance criterion 1."""
    types = sorted(audit_store.COMPLIANCE_EVENT_TYPES)
    events = []
    for i, t in enumerate(types * 3):
        events.append(evt(f"c-{i:03d}", march(1 + i % 5, i % 24, i % 60), t))
    events += [evt(f"o-{i}", march(1 + i % 5), "app.misc.synthetic") for i in range(7)]
    events += [evt("edge-before", datetime(2026, 2, 28, 23, 59, 59, 999000, tzinfo=timezone.utc)),
               evt("edge-after", datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc))]
    ingest(events, since="2026-02-20T00:00:00.000Z", until="2026-03-07T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        counts = snap.report_counts()
        assert set(counts) == set(audit_store.COMPLIANCE_REPORTS)
        for key in audit_store.COMPLIANCE_REPORTS:
            rows = list(snap.report_rows(key))
            assert counts[key] == direct_report_count(key) == len(rows), key
            assert [r["timestamp"] for r in rows] == sorted(r["timestamp"] for r in rows)
        assert sum(counts.values()) == snap.completeness_counts()["curated"]
        assert snap.events_in_period() == snap.completeness_counts()["events"] == len(list(snap.event_lines()))


def test_nothing_is_capped_at_a_thousand_rows(store):
    n = 1500
    ingest([evt(f"big-{i:05d}", march(2, 0, 0, 0) + timedelta(seconds=i)) for i in range(n)],
           since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        assert snap.report_counts()["session_activity"] == n
        assert len(list(snap.report_rows("session_activity"))) == n
        assert len(list(snap.event_lines())) == n
        assert snap.completeness()["reports"]["session_activity"]["truncated"] is False


def test_rows_are_streamed_not_listed(store):
    ingest([evt(f"s-{i}", march(2) + timedelta(seconds=i)) for i in range(10)], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        for it in (snap.report_rows("session_activity"), snap.event_lines(), snap.iter_manifests(), snap.iter_seal_chunks()):
            assert iter(it) is it and not isinstance(it, (list, tuple))


def test_a_sync_writing_during_an_open_snapshot_does_not_change_what_it_yields(store):
    ingest([evt(f"w-{i}", march(2) + timedelta(seconds=i)) for i in range(50)], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        first_half = []
        stream = snap.event_lines()
        for _ in range(10):
            first_half.append(next(stream))
        head_before = snap.chain_head["head_hash"]
        # a sync commits more events and a new manifest on the app's own connection, from another thread, mid-stream
        errors = []

        def writer():
            try:
                ingest([evt(f"late-{i}", march(2) + timedelta(seconds=100 + i)) for i in range(20)],
                       since="2026-03-02T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
        t = threading.Thread(target=writer)
        t.start()
        t.join(30)
        assert not errors
        conn = audit_store._get_connection()
        assert conn.execute("SELECT COUNT(*) FROM events WHERE environment_id = ?", (ENV,)).fetchone()[0] == 70  # the write is real
        rest = list(stream)
        assert len(first_half) + len(rest) == 50
        assert snap.events_in_period() == 50
        assert snap.report_counts()["session_activity"] == 50
        assert len(list(snap.report_rows("session_activity"))) == 50
        assert snap.chain_head["head_hash"] == head_before
        assert [m["manifest_id"] for m in snap.iter_manifests()] == [1]
        assert snap.period_manifest_ids() == [1]
        assert snap.completeness_counts()["events"] == 50
    with core.open_snapshot(ENV, MARCH) as fresh:   # a new snapshot does see it
        assert fresh.events_in_period() == 70
        assert [m["manifest_id"] for m in fresh.iter_manifests()] == [1, 2]


def test_snapshot_refuses_a_missing_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_store, "_audit_db_path", lambda: str(tmp_path / "nope.db"))
    with pytest.raises(core.EvidenceError):
        with core.open_snapshot(ENV, MARCH):
            pass
    assert not (tmp_path / "nope.db").exists()


def test_snapshot_connection_is_read_only(store):
    with core.open_snapshot(ENV, MARCH) as snap:
        with pytest.raises(Exception):
            snap._conn.execute("DELETE FROM events")


def test_event_line_with_a_line_break_fails_the_build(store):
    conn = audit_store._get_connection()
    conn.execute(
        "INSERT INTO events (uuid, environment_id, event_type, published, is_curated, raw_json) VALUES ('nl', ?, 'user.session.start', ?, 1, ?)",
        (ENV, "2026-03-02T10:00:00.000Z", '{"uuid":"nl",\n"x":1}'))
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        with pytest.raises(core.EvidenceError):
            list(snap.event_lines())


# -- manifests, head, seals ---------------------------------------------------
def test_manifests_first_to_head_with_the_documented_fields(store):
    build_march_archive()
    with core.open_snapshot(ENV, MARCH) as snap:
        manifests = list(snap.iter_manifests())
        assert [m["manifest_id"] for m in manifests] == [1, 2]
        assert set(manifests[0]) == {"manifest_id", "environment_id", "source", "since", "until", "row_count", "batch_hash",
                                     "prev_manifest_hash", "created_at", "content_hash", "entry_hash", "entries_json"}
        assert manifests[0]["prev_manifest_hash"] is None and manifests[1]["prev_manifest_hash"] == manifests[0]["entry_hash"]
        assert manifests[0]["entries_json"] is False and manifests[0]["row_count"] == 5
        assert snap.chain_head["head_hash"] == manifests[-1]["entry_hash"]
        assert snap.head_consistent() is True
        assert all(m["environment_id"] == ENV for m in manifests)


def test_chain_head_comes_from_the_chain_heads_row_and_rows_after_it_are_left_out(store):
    build_march_archive()
    conn = audit_store._get_connection()
    # what code older than 5.40.4 leaves behind: a manifest row appended without moving chain_heads
    last = conn.execute("SELECT entry_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id DESC LIMIT 1", (ENV,)).fetchone()[0]
    conn.execute(
        "INSERT INTO ingestion_manifests (environment_id, source, row_count, batch_hash, prev_manifest_hash, created_at) VALUES (?, 'sync', 0, ?, ?, ?)",
        (ENV, "0" * 64, last, "2026-03-09T00:00:00.000Z"))
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        ids = [m["manifest_id"] for m in snap.iter_manifests()]
        assert snap.chain_head["manifest_id"] == 2 and ids == [1, 2]
        assert snap.head_consistent() is True


def test_a_cut_tail_is_visible_as_an_inconsistent_head(store):
    build_march_archive()
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM ingestion_manifests WHERE id = 2")
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        assert snap.chain_head["manifest_id"] == 2          # the head still names the removed manifest
        assert snap.head_consistent() is False


def test_environment_without_an_archive_has_no_head_and_no_manifests(store):
    with core.open_snapshot(ENV, MARCH) as snap:
        assert snap.chain_head is None and list(snap.iter_manifests()) == [] and snap.head_consistent() is True
        assert list(snap.event_lines()) == [] and snap.period_manifest_ids() == []
        assert b"".join(snap.iter_seal_chunks()) == b""


def _content_hash(entries):
    return hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()


def test_seals_recompute_to_the_manifest_content_hash_and_carry_canonical_published(store):
    build_march_archive()
    with core.open_snapshot(ENV, MARCH) as snap:
        seals = list(snap.iter_seals())
        manifests = {m["manifest_id"]: m for m in snap.iter_manifests()}
        assert snap.period_manifest_ids() == [m["manifest_id"] for m in seals] == [1, 2]
        for seal in seals:
            assert _content_hash(seal["entries"]) == manifests[seal["manifest_id"]]["content_hash"]
            assert seal["entries"] == sorted(seal["entries"])
            assert len(seal["published"]) == len(seal["entries"])
            assert all(audit_store._canonical_published(p) == p for p in seal["published"])
        # the first manifest sealed the curated events of its batch, including the one outside the period
        uuids = {e.rsplit(":", 1)[0] for e in seals[0]["entries"]}
        assert uuids == {"a-01", "a-02", "a-03", "a-05"}                      # a-04 is not curated: counted, not sealed
        by_uuid = dict(zip([e.rsplit(":", 1)[0] for e in seals[0]["entries"]], seals[0]["published"]))
        assert by_uuid["a-05"] == "2026-02-28T23:59:59.999Z"
        assert snap.sealed_entries_without_event() == 0


def test_seal_chunks_form_valid_ndjson_lines(store):
    build_march_archive()
    with core.open_snapshot(ENV, MARCH) as snap:
        blob = b"".join(snap.iter_seal_chunks())
    assert blob.endswith(b"\n")
    for line in blob.split(b"\n")[:-1]:
        rec = json.loads(line)
        assert list(rec) == ["manifest_id", "entries", "published"]


def test_a_manifest_holding_no_period_event_has_no_seal(store):
    ingest([evt("old-1", march(1) - timedelta(days=30))], since="2026-01-20T00:00:00.000Z", until="2026-02-01T00:00:00.000Z")
    ingest([evt("in-1", march(2))], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        assert snap.period_manifest_ids() == [2]
        assert [s["manifest_id"] for s in snap.iter_seals()] == [2]
        assert [m["manifest_id"] for m in snap.iter_manifests()] == [1, 2]   # the chain is complete regardless


def test_a_sealed_entry_whose_event_is_gone_is_counted(store):
    build_march_archive()
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM event_targets WHERE uuid = 'a-05' AND environment_id = ?", (ENV,))
    conn.execute("DELETE FROM events WHERE uuid = 'a-05' AND environment_id = ?", (ENV,))
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        seal = next(snap.iter_seals())
        assert snap.sealed_entries_without_event() == 1
        assert len(seal["published"]) == len(seal["entries"])
        assert all(audit_store._canonical_published(p) == p for p in seal["published"])


def test_entries_json_manifests_are_sealed_too(store):
    build_march_archive()
    conn = audit_store._get_connection()
    pairs = [[r["uuid"], r["sha"]] for r in conn.execute("SELECT uuid, sha FROM manifest_entries WHERE manifest_id = 1")]
    conn.execute("UPDATE ingestion_manifests SET entries_json = ? WHERE id = 1", (json.dumps(pairs),))
    conn.execute("DELETE FROM manifest_entries WHERE manifest_id = 1")
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        assert next(iter(snap.iter_manifests()))["entries_json"] is True
        assert snap.period_manifest_ids() == [1, 2]
        seals = {s["manifest_id"]: s for s in snap.iter_seals()}
        assert {e.rsplit(":", 1)[0] for e in seals[1]["entries"]} == {"a-01", "a-02", "a-03", "a-05"}
        manifest = next(iter(snap.iter_manifests()))
        assert _content_hash(seals[1]["entries"]) == manifest["content_hash"]
        counts = snap.completeness_counts()
        assert counts["curated_sealed"] == counts["curated"] and counts["curated_unsealed"] == 0


def test_snapshot_manifests_are_not_sealed_as_event_manifests(store):
    build_march_archive()
    audit_store.record_config_snapshot(ENV, "users", [("k1", {"a": 1}), ("k2", {"b": 2})], captured_at="2026-03-03T12:00:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        manifests = list(snap.iter_manifests())
        assert any(m["source"].startswith("snapshot:") for m in manifests)
        assert [s["manifest_id"] for s in snap.iter_seals()] == [1, 2]
        counts = snap.completeness_counts()
        assert counts["snapshots"] == 1 and counts["snapshot_objects"] == 2


# -- legacy -------------------------------------------------------------------
def build_with_legacy_first():
    """The first batch is written by the pre-sealing (v1) chain: identifier-only."""
    old = audit_store.EVIDENCE_CHAIN_V2
    audit_store.EVIDENCE_CHAIN_V2 = False
    try:
        ingest([evt("l-1", march(1, 12)), evt("l-2", march(2, 12), "user.lifecycle.create"), evt("l-3", march(2, 13), "app.misc.synthetic")],
               since="2026-02-20T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    finally:
        audit_store.EVIDENCE_CHAIN_V2 = old
    ingest([evt("n-1", march(4)), evt("n-2", march(4), "app.misc.synthetic")], since="2026-03-03T00:00:00.000Z", until="2026-03-05T12:00:00.000Z")


def test_legacy_manifests_are_listed_only_when_unsealed_curated_events_need_them(store):
    build_with_legacy_first()
    with core.open_snapshot(ENV, MARCH) as snap:
        counts = snap.completeness_counts()
        assert counts["legacy_v1"] == 2 and counts["curated_sealed"] == 1 and counts["curated_unsealed"] == 0
        assert counts["non_curated_unsealed"] == 2
        assert snap.period_manifest_ids() == [1, 2]
        assert [s["manifest_id"] for s in snap.iter_seals()] == [2]       # a legacy manifest has no seal
        first = next(iter(snap.iter_manifests()))
        assert first["entry_hash"] is None and first["content_hash"] is None


def test_legacy_manifest_is_not_listed_when_the_period_needs_none(store):
    build_with_legacy_first()
    later = period_of("2026-03-04", "2026-03-05")
    with core.open_snapshot(ENV, later) as snap:
        assert snap.completeness_counts()["legacy_v1"] == 0
        assert snap.period_manifest_ids() == [2]


def test_curated_events_with_no_seal_and_no_legacy_manifest_are_a_break_not_legacy(store):
    ingest([evt("s-1", march(2))], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z")
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM manifest_entries")
    conn.commit()
    with core.open_snapshot(ENV, MARCH) as snap:
        counts = snap.completeness_counts()
        assert (counts["curated_sealed"], counts["legacy_v1"], counts["curated_unsealed"]) == (0, 0, 1)
        assert snap.period_manifest_ids() == []


# -- completeness ---------------------------------------------------------------
def test_completeness_reports_rows_scope_counts_and_zero_event_types(store):
    build_march_archive()
    set_state(ingestion_scope="all", last_sync_completed_at="2026-03-07T00:00:00.000Z", last_synced_at="2026-03-06T23:59:00.000Z")
    with core.open_snapshot(ENV, MARCH) as snap:
        c = snap.completeness()
    json.dumps(c)  # plain data
    assert c["scope"] == "everything"
    assert c["period"] == {"start": "2026-03-01", "end": "2026-03-05"}
    assert c["reports"]["session_activity"]["rows"] == 2          # a-01, b-01
    assert c["reports"]["provisioning"]["rows"] == 2
    assert c["reports"]["pam_secrets"]["rows"] == 1
    assert c["reports"]["pam_secrets"]["zero_event_types"] == sorted(
        t for t in audit_store._event_types_for_report("pam_secrets") if t != "pam.secret.reveal")
    assert c["reports"]["mfa_enforcement"]["rows"] == 0
    assert c["reports"]["mfa_enforcement"]["zero_event_types"] == sorted(audit_store._event_types_for_report("mfa_enforcement"))
    assert all(r["truncated"] is False for r in c["reports"].values())
    assert c["reports"]["session_activity"]["curated_sealed"] == 2
    assert c["counts"] == {"events": 7, "curated": 6, "curated_sealed": 6, "legacy_v1": 0, "curated_unsealed": 0,
                           "non_curated_unsealed": 1, "snapshots": 0, "snapshot_objects": 0}
    assert c["data_as_of"] == "2026-03-07T00:00:00.000Z" and c["chain_head"] and c["period_manifest_ids"] == [1, 2]
    assert c["curated_event_types"] == sorted(audit_store.COMPLIANCE_EVENT_TYPES)


def test_scope_is_curated_when_nothing_else_was_ever_stored(store):
    ingest([evt("c-1", march(2))], since="2026-03-01T00:00:00.000Z", until="2026-03-03T00:00:00.000Z", scope="curated")
    set_state(ingestion_scope="curated")
    with core.open_snapshot(ENV, MARCH) as snap:
        assert snap.scope() == "curated"


# ---------------------------------------------------------------------------
# 4. Coverage
# ---------------------------------------------------------------------------
def rel_day(n, hh=10):
    today = datetime.now(timezone.utc).date()
    d = today - timedelta(days=n)
    return datetime(d.year, d.month, d.day, hh, 0, 0, tzinfo=timezone.utc)


def day_start(n):
    return rel_day(n, 0)


def rel_period(first, last):
    """Days `first` .. `last` ago, inclusive (first >= last)."""
    return core.parse_period((day_start(first)).date().isoformat(), (day_start(last)).date().isoformat())


def states(snap, first=None, last=None):
    return {d["date"]: d["state"] for d in snap.coverage()["days"]}


def test_day_states_covered_zero_gap_before_archive_and_after_data_as_of(store):
    now = datetime.now(timezone.utc)
    ingest([evt("d-1", rel_day(25))], since=iso(day_start(30)), until=iso(day_start(19)))
    ingest([evt("d-2", rel_day(3))], since=iso(day_start(10)), until=iso(now - timedelta(minutes=5)))
    set_state(last_sync_completed_at=iso(now), last_synced_at=iso(now - timedelta(minutes=5)), last_sync_status="success")
    p = rel_period(35, 0)
    with core.open_snapshot(ENV, p) as snap:
        cov = snap.coverage()
        st = states(snap)
    day = lambda n: day_start(n).date().isoformat()
    assert all(st[day(n)] == core.DAY_BEFORE_ARCHIVE for n in range(35, 30, -1))
    assert st[day(30)] == core.DAY_COVERED_ZERO and st[day(25)] == core.DAY_COVERED_EVENTS and st[day(20)] == core.DAY_COVERED_ZERO
    assert all(st[day(n)] == core.DAY_NOT_COVERED for n in range(19, 10, -1))           # between the two windows
    assert st[day(10)] == core.DAY_COVERED_ZERO and st[day(3)] == core.DAY_COVERED_EVENTS and st[day(1)] == core.DAY_COVERED_ZERO
    assert st[day(0)] == core.DAY_AFTER_DATA_AS_OF                                       # today: not a gap
    assert cov["counts"] == {core.DAY_COVERED_EVENTS: 2, core.DAY_COVERED_ZERO: 10 + 9, core.DAY_NOT_COVERED: 9,
                             core.DAY_PRUNED: 0, core.DAY_BEFORE_ARCHIVE: 5, core.DAY_AFTER_DATA_AS_OF: 1}
    assert cov["gap_days"] == [day(n) for n in range(19, 10, -1)]
    assert cov["archive_start_date"] == day(30)
    assert cov["has_coverage"] and cov["covered_days"] == 2 + 19
    assert cov["coverage_pct"] == round(100.0 * 21 / 36, 1)
    assert sum(cov["counts"].values()) == p.day_count == len(cov["days"])
    assert [d["events"] for d in cov["days"] if d["date"] == day(25)] == [1]


def test_events_after_data_as_of_are_not_a_gap(store):
    now = datetime.now(timezone.utc)
    ingest([evt("e-1", rel_day(5))], since=iso(day_start(8)), until=iso(day_start(2)))
    set_state(last_sync_completed_at=iso(day_start(2) + timedelta(hours=1)), last_sync_status="success")
    with core.open_snapshot(ENV, rel_period(6, 0)) as snap:
        cov = snap.coverage()
    st = {d["date"]: d["state"] for d in cov["days"]}
    assert st[day_start(2).date().isoformat()] == core.DAY_AFTER_DATA_AS_OF
    assert st[day_start(1).date().isoformat()] == core.DAY_AFTER_DATA_AS_OF and st[day_start(0).date().isoformat()] == core.DAY_AFTER_DATA_AS_OF
    assert cov["counts"][core.DAY_NOT_COVERED] == 0
    assert cov["data_as_of"] == iso(day_start(2) + timedelta(hours=1)) and cov["data_as_of_source"] == "sync"
    assert now  # silence linters


def test_polling_run_without_since_continues_from_the_previous_window(store):
    now = datetime.now(timezone.utc)
    ingest([], since=iso(day_start(12)), until=iso(day_start(8)))
    ingest([evt("p-1", rel_day(6))], since=None, until=iso(day_start(4)))      # a run resumed from its saved cursor
    ingest([], since=None, until=iso(now - timedelta(minutes=5)))
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    with core.open_snapshot(ENV, rel_period(11, 1)) as snap:
        cov = snap.coverage()
    assert cov["counts"][core.DAY_NOT_COVERED] == 0 and cov["counts"][core.DAY_BEFORE_ARCHIVE] == 0
    assert cov["coverage_pct"] == 100.0


def test_a_failed_latest_attempt_does_not_claim_its_whole_window(store):
    now = datetime.now(timezone.utc)
    ingest([], since=iso(day_start(20)), until=iso(day_start(10)))
    attempt = iso(now - timedelta(seconds=30))
    ingest([], since=iso(day_start(10)), until=iso(now - timedelta(minutes=5)))   # the window it asked for
    set_state(last_sync_completed_at=iso(now - timedelta(days=1)), last_sync_attempt_at=attempt, last_sync_status="error",
              last_synced_at=iso(day_start(7) + timedelta(hours=12)))
    with core.open_snapshot(ENV, rel_period(12, 2)) as snap:
        st = states(snap)
    assert st[day_start(8).date().isoformat()] == core.DAY_COVERED_ZERO              # up to the watermark
    assert st[day_start(6).date().isoformat()] == core.DAY_NOT_COVERED               # past it: not claimed
    assert st[day_start(2).date().isoformat()] == core.DAY_NOT_COVERED


def test_import_only_environment(store):
    now = datetime.now(timezone.utc)
    ingest([evt("i-1", rel_day(3)), evt("i-2", rel_day(1))], source="csv_import")
    set_state(last_import_at=iso(now))
    with core.open_snapshot(ENV, rel_period(5, 1)) as snap:
        cov = snap.coverage()
    st = {d["date"]: d["state"] for d in cov["days"]}
    assert st[day_start(5).date().isoformat()] == core.DAY_BEFORE_ARCHIVE
    assert st[day_start(3).date().isoformat()] == core.DAY_COVERED_EVENTS
    assert st[day_start(2).date().isoformat()] == core.DAY_NOT_COVERED              # an import records no range: not claimed
    assert st[day_start(1).date().isoformat()] == core.DAY_COVERED_EVENTS
    assert cov["data_as_of_source"] == "import"


def test_no_archive_means_no_coverage(store):
    with core.open_snapshot(ENV, rel_period(3, 1)) as snap:
        cov = snap.coverage()
    assert cov["has_coverage"] is False and cov["coverage_pct"] == 0.0 and cov["archive_start_date"] is None
    assert cov["counts"][core.DAY_BEFORE_ARCHIVE] == 3


# -- pruned days (criterion 5) ---------------------------------------------------
def build_prunable_archive():
    """Scope 'all', 60 days of syncs. Non-curated events on days 40, 30 and 5 ago; curated events on days 35 and 3."""
    now = datetime.now(timezone.utc)
    events = [evt("nc-40", rel_day(40), "app.misc.synthetic"), evt("nc-30", rel_day(30), "app.misc.synthetic"),
              evt("nc-05", rel_day(5), "app.misc.synthetic"), evt("cu-35", rel_day(35)), evt("cu-03", rel_day(3)),
              evt("both-30", rel_day(30)), ]
    ingest(events, since=iso(day_start(60)), until=iso(now - timedelta(minutes=5)))
    set_state(last_sync_completed_at=iso(now), last_sync_status="success", ingestion_scope="all")
    return now


def test_pruned_days_are_reported_as_pruned_not_as_gaps(store):
    """Acceptance criterion 5."""
    build_prunable_archive()
    set_retention(days=20)
    p = rel_period(45, 1)
    day = lambda n: day_start(n).date().isoformat()
    with core.open_snapshot(ENV, p) as snap:
        before = states(snap)
    assert before[day(40)] == core.DAY_COVERED_EVENTS and before[day(38)] == core.DAY_COVERED_ZERO   # nothing pruned yet: no day is
    result = audit_store.prune_events(ENV, retention_days=20)
    assert result["pruned"] == 2
    with core.open_snapshot(ENV, p) as snap:
        cov = snap.coverage()
    st = {d["date"]: d["state"] for d in cov["days"]}
    assert st[day(40)] == core.DAY_PRUNED                      # its only event was non-curated and is gone
    assert st[day(38)] == core.DAY_PRUNED                      # empty and under the horizon: shown pruned (an inference)
    assert st[day(35)] == core.DAY_COVERED_EVENTS              # a curated event is never pruned
    assert st[day(30)] == core.DAY_COVERED_EVENTS and day(30) in cov["non_curated_pruned_days"]
    assert st[day(5)] == core.DAY_COVERED_EVENTS and day(5) not in cov["non_curated_pruned_days"]   # inside retention
    assert st[day(10)] == core.DAY_COVERED_ZERO                # inside retention, genuinely empty
    assert core.DAY_NOT_COVERED not in st.values() and cov["gap_days"] == []
    assert day(40) in cov["pruned_days"] and cov["counts"][core.DAY_PRUNED] == len(cov["pruned_days"])
    assert cov["prune_history_recorded"] is True and cov["pruned_basis"] == "recorded"   # prune_events wrote a prune_history row
    assert cov["retention"]["days"] == 20 and cov["limits"]
    # the same archive without the record (a prune from before 5.53.0): the days are the same, the basis is said to be inferred
    audit_store._get_connection().execute("DELETE FROM prune_history")
    audit_store._get_connection().commit()
    with core.open_snapshot(ENV, p) as snap:
        older = snap.coverage()
    assert older["pruned_days"] == cov["pruned_days"] and older["pruned_basis"] == "inferred" and older["prune_history_recorded"] is False


def test_pruned_state_with_recorded_prune_runs(store):
    build_prunable_archive()
    set_retention(days=None)                                        # the setting was removed since; the run is on record
    audit_store.prune_events(ENV, retention_days=20)
    audit_store._get_connection().execute("DELETE FROM prune_history")   # an older prune: only the audit log knows
    audit_store._get_connection().commit()
    now = datetime.now(timezone.utc)
    records = [{"at": iso(now), "cutoff": iso(now - timedelta(days=20)), "pruned": 2}]
    day = lambda n: day_start(n).date().isoformat()
    with core.open_snapshot(ENV, rel_period(45, 1), prune_records=records) as snap:
        cov = snap.coverage()
    st = {d["date"]: d["state"] for d in cov["days"]}
    assert st[day(40)] == core.DAY_PRUNED and st[day(35)] == core.DAY_COVERED_EVENTS
    assert cov["prune_history_recorded"] is True and cov["pruned_basis"] == "audit_log"
    with core.open_snapshot(ENV, rel_period(45, 1), prune_records=[]) as snap:     # the log shows no run
        none = snap.coverage()
    assert none["pruned_days"] == [] and none["prune_history_recorded"] is True
    assert core.DAY_NOT_COVERED not in {d["state"] for d in none["days"]}


def test_a_curated_only_archive_has_no_pruned_days(store):
    now = datetime.now(timezone.utc)
    ingest([evt("k-1", rel_day(30)), evt("k-2", rel_day(3))], since=iso(day_start(40)), until=iso(now - timedelta(minutes=5)), scope="curated")
    set_state(last_sync_completed_at=iso(now), last_sync_status="success", ingestion_scope="curated")
    set_retention(days=10)
    with core.open_snapshot(ENV, rel_period(35, 1)) as snap:
        cov = snap.coverage()
    assert cov["pruned_days"] == [] and cov["counts"][core.DAY_NOT_COVERED] == 0


def test_a_day_before_the_retention_horizon_outside_every_window_is_still_a_gap(store):
    now = datetime.now(timezone.utc)
    ingest([evt("g-1", rel_day(2), "app.misc.synthetic")], since=iso(day_start(10)), until=iso(now - timedelta(minutes=5)))
    set_state(last_sync_completed_at=iso(now), last_sync_status="success")
    set_retention(days=5)
    with core.open_snapshot(ENV, rel_period(14, 11)) as snap:
        assert set(states(snap).values()) <= {core.DAY_BEFORE_ARCHIVE, core.DAY_NOT_COVERED}


def test_prune_records_from_the_audit_log(tmp_path):
    log = tmp_path / "audit_log.jsonl"
    lines = [
        {"action": "sync.scheduled_completed", "timestamp": "2026-10-01T02:00:00+00:00", "details": {"name": "Env One", "pruned": 4, "cutoff": "2026-09-01T02:00:00.000Z"}},
        {"action": "sync.manual_completed", "timestamp": "2026-10-02T02:00:00+00:00", "details": {"name": "Env One", "pruned": 0, "cutoff": None}},
        {"action": "sync.scheduled_completed", "timestamp": "2026-10-02T02:00:00+00:00", "details": {"name": "Env Two", "pruned": 9, "cutoff": "2026-09-02T02:00:00.000Z"}},
        {"action": "sync.scheduled_failed", "timestamp": "2026-10-03T02:00:00+00:00", "details": {"name": "Env One", "pruned": 1}},
        {"action": "settings.unlocked", "details": {"name": "Env One", "pruned": 1}},
    ]
    log.write_text("\n".join(json.dumps(x) for x in lines) + "\nnot json _completed \"pruned\"\n", encoding="utf-8")
    recs = core.prune_records_from_audit_log("Env One", path=str(log))
    assert recs == [{"at": "2026-10-01T02:00:00+00:00", "cutoff": "2026-09-01T02:00:00.000Z", "pruned": 4},
                    {"at": "2026-10-02T02:00:00+00:00", "cutoff": None, "pruned": 0}]
    assert core.prune_records_from_audit_log("Env One", path=str(tmp_path / "missing.jsonl")) == []


# ---------------------------------------------------------------------------
# The verifier accepts what this core produces
# ---------------------------------------------------------------------------
class FakeOkta:
    def __init__(self, events):
        self.events = events

    def get_system_log_page(self, path):
        return [], None

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        return [e for e in self.events if since <= e["published"] < until], True


def stamp(minutes_ago):
    return iso(datetime.now(timezone.utc) - timedelta(minutes=minutes_ago))


def sync_events(events, legacy=False):
    old = audit_store.EVIDENCE_CHAIN_V2
    audit_store.EVIDENCE_CHAIN_V2 = not legacy
    try:
        audit_store.sync_okta_events(FakeOkta(events), ENV, "all", since=stamp(120))
    finally:
        audit_store.EVIDENCE_CHAIN_V2 = old


def build_recent_archive(legacy_first=False, snapshot=False, entries_json=False):
    batches = [
        [evt("evt-a1", stamp(100)), evt("evt-a2", stamp(99), "user.lifecycle.create"), evt("evt-a3", stamp(98), "app.misc.synthetic")],
        [evt("evt-b1", stamp(60)), evt("evt-b2", stamp(59), "app.misc.synthetic"), evt("evt-b3", stamp(58), "pam.secret.reveal")],
        [evt("evt-c1", stamp(20)), evt("evt-c2", stamp(19)), evt("evt-c3", stamp(18), "app.misc.synthetic")],
    ]
    for i, b in enumerate(batches):
        sync_events(b, legacy=legacy_first and i == 0)
    if snapshot:
        audit_store.record_config_snapshot(ENV, "users", [("k1", {"a": 1}), ("k2", {"b": 2})])
    if entries_json:
        conn = audit_store._get_connection()
        pairs = [[r["uuid"], r["sha"]] for r in conn.execute("SELECT uuid, sha FROM manifest_entries WHERE manifest_id = 2")]
        conn.execute("UPDATE ingestion_manifests SET entries_json = ? WHERE id = 2", (json.dumps(pairs),))
        conn.execute("DELETE FROM manifest_entries WHERE manifest_id = 2")
        conn.commit()


def pack_with_core(path, period):
    """A minimal packer that uses ONLY this module for the archive-derived parts (WP4 builds the rest)."""
    reports = ["session_activity", "provisioning", "pam_secrets"]
    with core.open_snapshot(ENV, period) as snap:
        events = b"".join(snap.event_lines())
        manifests = b"".join((json.dumps(m, sort_keys=True) + "\n").encode() for m in snap.iter_manifests())
        seals = b"".join(snap.iter_seal_chunks())
        csvs, matrix = {}, [b'"control_id","framework","mapping_status","reports","rows_in_period","status"\r\n']
        for i, key in enumerate(reports):
            buf = io.BytesIO()
            n = core.write_report_csv(buf, snap.report_rows(key))
            assert n == snap.report_counts()[key]
            csvs["controls/CC%d/%s.csv" % (i + 1, key)] = buf.getvalue()
            matrix.append(('"CC%d","SOC 2","proposed","%s","%d","ok"\r\n' % (i + 1, key, n)).encode())
        completeness = json.dumps(snap.completeness(), sort_keys=True).encode()
        cov = snap.coverage()
        pm_extra = {"chain_head": snap.chain_head["head_hash"] if snap.chain_head else None,
                    "curated_event_types": snap.curated_event_types, "period_manifest_ids": snap.period_manifest_ids(),
                    "data_as_of": cov["data_as_of"] or iso(datetime.now(timezone.utc))}
    files = [("README-FOR-AUDITORS.txt", b"synthetic\n"), ("cover-sheet.html", b"<html></html>\n"), ("control-matrix.csv", b"".join(matrix))]
    files += sorted(csvs.items())
    files += [("events.ndjson", events), ("chain/manifests.ndjson", manifests), ("chain/seals.ndjson", seals),
              ("completeness.json", completeness), ("what-this-tool-reads.txt", b"synthetic\n")]
    files += [("methodology/%s.txt" % k, b"synthetic\n") for k in reports]
    pm = {"format": 1, "files": [{"path": n, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for n, b in files],
          "built_at": iso(datetime.now(timezone.utc)), "app_version": "0.0.0-test", "environment_label_ascii": "Synthetic",
          "period": period.as_dict(), "catalogue_version": "test", **pm_extra}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for n, b in files:
            zf.writestr(n, b)
        zf.writestr("package-manifest.json", json.dumps(pm).encode())
    return pm


def run_verifier(path, cwd):
    proc = subprocess.run([sys.executable, "-I", VERIFIER, str(path)], capture_output=True, text=True, cwd=str(cwd))
    return proc.returncode, proc.stdout


@pytest.mark.parametrize("kwargs", [{}, {"legacy_first": True}, {"snapshot": True}, {"entries_json": True}],
                         ids=["plain", "legacy-first", "with-snapshot", "entries-json"])
def test_the_verifier_passes_a_package_built_from_this_core(store, tmp_path, kwargs):
    build_recent_archive(**kwargs)
    today = datetime.now(timezone.utc).date()
    period = core.parse_period((today - timedelta(days=1)).isoformat(), today.isoformat())
    out_dir = tmp_path / "empty"
    out_dir.mkdir()
    pack_with_core(tmp_path / "pkg.zip", period)
    code, out = run_verifier(tmp_path / "pkg.zip", out_dir)
    assert code == 0 and "RESULT: PASS" in out, out
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True


