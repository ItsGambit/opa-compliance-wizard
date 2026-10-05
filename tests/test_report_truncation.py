"""Covers UI-03/DATA-06/DATA-07 (external review, 2026-10-05): report and
resource-history queries used to be silently capped at `limit` with
nothing in the response saying so, and a negative `limit` removed the cap
entirely (SQLite's `LIMIT -1` means "no limit," not an error). Fixes:
- audit_store._require_positive_limit rejects limit < 1 everywhere it's
  used (query_events, run_report, resource_history).
- run_report/resource_history now return {"rows", "total", "truncated"}
  instead of a bare list -- total is the real, uncapped count for the
  same filters, truncated is True whenever rows.length < total."""
from datetime import datetime, timedelta, timezone

import pytest

import audit_store

ENV = "11111111-1111-1111-1111-111111111111"


def _seed_events(conn, count, event_type="user.authentication.verify", with_target=False):
    import audit_store as a

    now = datetime.now(timezone.utc)
    for i in range(count):
        published = (now - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        uuid = f"evt-{i}"
        conn.execute(
            """INSERT INTO events
               (uuid, environment_id, event_type, published, actor_id, actor_display_name,
                actor_alternate_id, outcome_result, is_curated, raw_json, resource_id,
                resource_alternate_id, resource_type_detail)
               VALUES (?, ?, ?, ?, 'actor', 'Actor', 'actor@x.com', 'SUCCESS', 0, '{}', NULL, NULL, NULL)""",
            (uuid, ENV, event_type, published),
        )
        if with_target:
            conn.execute(
                """INSERT INTO event_targets (environment_id, uuid, target_id, target_alternate_id, target_display_name)
                   VALUES (?, ?, 'tgt-1', 'tgt-1', 'Target One')""",
                (ENV, uuid),
            )
    conn.commit()


# ---------------------------------------------------------------------------
# DATA-06: negative/zero limit must be rejected, not silently uncapped.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_limit", [-1, -1000, 0])
def test_query_events_rejects_non_positive_limit(tmp_audit_store, bad_limit):
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        audit_store.query_events(ENV, limit=bad_limit)


@pytest.mark.parametrize("bad_limit", [-1, 0])
def test_run_report_rejects_non_positive_limit(tmp_audit_store, bad_limit):
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        audit_store.run_report("mfa_enforcement", ENV, limit=bad_limit)


@pytest.mark.parametrize("bad_limit", [-1, 0])
def test_resource_history_rejects_non_positive_limit(tmp_audit_store, bad_limit):
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        audit_store.resource_history(ENV, resource_id="x", limit=bad_limit)


def test_negative_limit_would_have_removed_the_cap_in_sqlite_itself(tmp_audit_store):
    """Documents WHY the guard exists -- not a test of audit_store, a
    direct demonstration of the underlying SQLite behavior the review
    flagged, so a future reader doesn't have to take the claim on faith."""
    conn = audit_store._get_connection()
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(10)])
    assert conn.execute("SELECT COUNT(*) FROM (SELECT x FROM t LIMIT ?)", (-5,)).fetchone()[0] == 10
    assert conn.execute("SELECT COUNT(*) FROM (SELECT x FROM t LIMIT ?)", (3,)).fetchone()[0] == 3


# ---------------------------------------------------------------------------
# UI-03/DATA-07: total/truncated must reflect the REAL count, not just len(rows).
# ---------------------------------------------------------------------------
def test_run_report_reports_truncated_when_more_rows_exist_than_the_limit(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    _seed_events(conn, 10, event_type="user.authentication.auth_via_mfa")  # a real mfa_enforcement event type

    result = audit_store.run_report("mfa_enforcement", ENV, limit=3)

    assert len(result["rows"]) == 3
    assert result["total"] == 10
    assert result["truncated"] is True


def test_run_report_not_truncated_when_limit_covers_everything(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    _seed_events(conn, 3, event_type="user.authentication.auth_via_mfa")

    result = audit_store.run_report("mfa_enforcement", ENV, limit=1000)

    assert len(result["rows"]) == 3
    assert result["total"] == 3
    assert result["truncated"] is False


def test_resource_history_reports_truncated_when_more_rows_exist_than_the_limit(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    _seed_events(conn, 10, with_target=True)

    result = audit_store.resource_history(ENV, resource_id="tgt-1", limit=4)

    assert len(result["rows"]) == 4
    assert result["total"] == 10
    assert result["truncated"] is True


def test_resource_history_empty_lookup_returns_the_zero_shape(tmp_audit_store):
    """No resource_id AND no resource_name -- "nothing to look up"."""
    audit_store.run_migrations()
    result = audit_store.resource_history(ENV)
    assert result == {"rows": [], "total": 0, "truncated": False}
