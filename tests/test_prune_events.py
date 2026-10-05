"""Covers audit_store.prune_events (DATA-01, external review, 2026-10-05):
retention/size-based pruning used to raise sqlite3.IntegrityError on ANY
non-curated row that had a target -- event_targets has a FOREIGN KEY on
(environment_id, uuid) -> events, and nearly every real Okta event has at
least one target (_insert_rows fans every event's `target` array out into
one event_targets row each). The fix deletes the matching event_targets
rows FIRST, in the same transaction, before deleting their parent events."""
from datetime import datetime, timedelta, timezone

import audit_store

ENV = "11111111-1111-1111-1111-111111111111"


class FakeOktaClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _event_with_target(uuid, published, event_type="user.authentication.verify"):
    return {
        "uuid": uuid,
        "eventType": event_type,
        "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"},
        "outcome": {"result": "SUCCESS"},
        # A real target -- this is what makes _insert_rows write a row into
        # event_targets, which is the FOREIGN KEY DATA-01 is about.
        "target": [{"id": "00uTARGET", "displayName": "Target User"}],
    }


def _seed_old_noncurated_event_with_target(tmp_audit_store, tmp_environments_file, days_old=100):
    audit_store.run_migrations()
    published = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = FakeOktaClient([([_event_with_target("evt-old", published)], True)])
    audit_store.sync_okta_events(client, ENV, "all", since=published)
    return published


def test_retention_prune_does_not_raise_on_an_event_with_targets(tmp_audit_store, tmp_environments_file):
    """The exact reproduction from the review: one non-curated event with
    one target, pruned with a retention window that matches it. Before
    the fix this raised sqlite3.IntegrityError and pruned_total stayed 0
    forever on any real tenant (nearly every Okta event has a target)."""
    _seed_old_noncurated_event_with_target(tmp_audit_store, tmp_environments_file, days_old=100)

    conn = audit_store._get_connection()
    before_targets = conn.execute(
        "SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (ENV,)
    ).fetchone()[0]
    assert before_targets == 1  # sanity: the target row really exists before pruning

    result = audit_store.prune_events(ENV, retention_days=30)

    assert result["pruned"] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 0


def test_size_based_prune_does_not_raise_on_an_event_with_targets(tmp_audit_store, tmp_environments_file):
    """Same FOREIGN KEY hazard, the max_size_mb step-loop branch instead of
    the retention_days branch -- a separate code path with its own DELETE
    FROM events, so it needs its own repro."""
    _seed_old_noncurated_event_with_target(tmp_audit_store, tmp_environments_file, days_old=5)
    conn = audit_store._get_connection()

    result = audit_store.prune_events(ENV, max_size_mb=0)  # 0 MB -- always "over the cap"

    assert result["pruned"] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 0


def test_retention_prune_never_deletes_curated_rows_even_with_targets(tmp_audit_store, tmp_environments_file):
    """Curated rows are never auto-pruned regardless of age -- confirm
    that still holds now that the FOREIGN KEY-safe delete touches
    event_targets too (a curated row's target rows must survive right
    alongside it, not get swept up by the children-first delete)."""
    audit_store.run_migrations()
    old_published = (datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # user.session.start IS in COMPLIANCE_EVENT_TYPES -- a curated type.
    client = FakeOktaClient([([_event_with_target("evt-curated", old_published, "user.session.start")], True)])
    audit_store.sync_okta_events(client, ENV, "all", since=old_published)

    conn = audit_store._get_connection()
    is_curated = conn.execute(
        "SELECT is_curated FROM events WHERE environment_id = ? AND uuid = ?", (ENV, "evt-curated")
    ).fetchone()[0]
    assert is_curated == 1  # sanity: this event type really is curated

    result = audit_store.prune_events(ENV, retention_days=30)

    assert result["pruned"] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 1


def test_retention_prune_leaves_recent_events_with_targets_alone(tmp_audit_store, tmp_environments_file):
    """A non-curated event that's NOT past the retention window must
    survive, targets and all -- the fix's children-first delete must use
    the exact same WHERE clause as the parent delete, not a broader one."""
    audit_store.run_migrations()
    recent_published = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = FakeOktaClient([([_event_with_target("evt-recent", recent_published)], True)])
    audit_store.sync_okta_events(client, ENV, "all", since=recent_published)

    conn = audit_store._get_connection()
    result = audit_store.prune_events(ENV, retention_days=30)

    assert result["pruned"] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM event_targets WHERE environment_id = ?", (ENV,)
    ).fetchone()[0] == 1
