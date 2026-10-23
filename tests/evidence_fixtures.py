"""Shared synthetic-archive helpers for the evidence package tests (5.53.0, WP4).

Archives are built with the real ingestion code (_insert_rows, _write_manifest_row, _upsert_sync_state). Dates are
relative to today (UTC) because the routes validate the period against the real clock. Synthetic data only."""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import audit_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(ROOT, "tools", "verify_evidence_package.py")


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def today_utc():
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def day(offset, hh=10, mm=0, ss=0):
    """A datetime `offset` days from today (negative = past) at hh:mm:ss UTC."""
    return today_utc() + timedelta(days=offset, hours=hh, minutes=mm, seconds=ss)


def evt(uuid, when, event_type="user.session.start", actor="Someone", outcome="SUCCESS", email="user@example.com"):
    return {
        "uuid": uuid, "eventType": event_type, "published": when if isinstance(when, str) else iso(when),
        "displayMessage": "synthetic " + event_type,
        "actor": {"id": "00uActor", "displayName": actor, "alternateId": email},
        "outcome": {"result": outcome}, "client": {"ipAddress": "192.0.2.1"},
        "target": [{"id": "00uT", "type": "User", "displayName": "Target"}],
    }


def ingest(environment_id, events, since=None, until=None, scope="all", source="sync"):
    conn = audit_store._get_connection()
    rows = [audit_store._normalize_live_event(e) for e in events]
    _inserted, _mx, new_entries = audit_store._insert_rows(conn, environment_id, rows, scope)
    with audit_store._db_lock:
        conn.execute("BEGIN IMMEDIATE")
        audit_store._write_manifest_row(conn, environment_id, source, since, until, new_entries)
        conn.commit()


def build_archive(environment_id, with_gap=False):
    """Events on days -10..-2 (a curated and a non-curated one most days, none on day -6), sealed in syncs whose windows
    cover days -12..-1; with_gap leaves days -8 and -7 out of every window. Returns the list of event uuids."""
    audit_store.run_migrations()
    uuids = []
    first, second = [], []
    for off in range(-10, -1):
        if off == -6 or (with_gap and off in (-8, -7)):
            continue
        for kind, etype in (("c", "user.session.start"), ("n", "app.misc.synthetic")):
            u = f"e{kind}{abs(off):02d}"
            uuids.append(u)
            (first if off < -6 else second).append(evt(u, day(off), etype))
    first.append(evt("ec-lifecycle", day(-9, 11), "user.lifecycle.create"))
    second.append(evt("ec-admin", day(-3, 12), "user.account.privilege.grant"))
    if with_gap:
        ingest(environment_id, first, since=iso(day(-12, 0)), until=iso(day(-8, 0)))
        ingest(environment_id, second, since=iso(day(-6, 0)), until=iso(day(0, 0)))
    else:
        ingest(environment_id, first, since=iso(day(-12, 0)), until=iso(day(-6, 0)))
        ingest(environment_id, second, since=iso(day(-6, 0)), until=iso(day(0, 0)))
    audit_store._upsert_sync_state(
        audit_store._get_connection(), environment_id, last_sync_completed_at=iso(datetime.now(timezone.utc)),
        last_sync_status="success", ingestion_scope="all", last_synced_at=iso(day(0, 0)))
    return uuids + ["ec-lifecycle", "ec-admin"]


def run_verifier(path, cwd):
    """The verifier as a subprocess under -I from `cwd`. Returns (exit code, stdout)."""
    proc = subprocess.run([sys.executable, "-I", VERIFIER, str(path)], capture_output=True, text=True, cwd=str(cwd))
    return proc.returncode, proc.stdout


def seed_fixed_archive(environment_id):
    """A small archive with fixed dates (2020-03-01 to 2020-03-05, one event on days 2 to 4), sealed in one sync whose window
    covers all five days, for tests whose period must not depend on the clock."""
    audit_store.run_migrations()
    events = [evt("fx-1", "2020-03-02T10:00:00.000Z"), evt("fx-2", "2020-03-03T10:00:00.000Z", "user.lifecycle.create"),
              evt("fx-3", "2020-03-04T10:00:00.000Z", "app.misc.synthetic")]
    ingest(environment_id, events, since="2020-03-01T00:00:00.000Z", until="2020-03-06T00:00:00.000Z")
    audit_store._upsert_sync_state(
        audit_store._get_connection(), environment_id, last_sync_completed_at="2020-03-06T00:00:00.000Z",
        last_sync_status="success", ingestion_scope="all", last_synced_at="2020-03-06T00:00:00.000Z")
