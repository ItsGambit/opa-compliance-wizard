"""Covers sync_okta_events' incomplete-chunk watermark behavior (external
review, 2026-09-30, "1.5"): if a day-chunk hits get_system_log's
max_pages cap, the sync must stop immediately, mark last_sync_status as
"error", and -- critically -- NOT advance the watermark past that
incomplete chunk, so the next sync run retries it rather than silently
skipping events that aged out of Okta's own 90-day retention.

Uses audit_store.run_migrations() (schema only), NOT init_db() -- init_db
also calls migrate_legacy_environments_json(), which reads AND DELETES
environments.json. A real incident during this file's own Phase 2 update
(2026-10-01): these tests called init_db() with only tmp_audit_store
applied (redirects the DB path) and no tmp_environments_file (redirects
the JSON path) -- the migration ran against this machine's REAL
environments.json and deleted it. Recovered from a pytest temp dir's
audit_store.db from that same run (migrate_legacy_environments_json
copies before deleting, so the data wasn't actually lost, just briefly
sitting in a temp file instead of the real one) and environments.json
was restored. Every test below now takes BOTH fixtures whenever it
triggers a schema-creating/migrating call, as a direct result."""
from datetime import datetime, timedelta, timezone

import audit_store


class FakeOktaClient:
    """Returns a scripted sequence of (events, complete) tuples, one per
    call to get_system_log -- lets a test control exactly which day-chunk
    comes back incomplete without a real Okta tenant. Any call beyond the
    scripted sequence returns (events=[], complete=True) -- the exact
    number of 1-day chunks between a watermark and "now" can vary by one
    depending on wall-clock timing between when a test computes `since`
    and when sync_okta_events itself calls datetime.now(), which isn't
    what these tests are trying to pin down; what matters is the content
    and ordering of the calls that ARE asserted on below."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        self.calls.append((since, until))
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _event(uuid, published):
    return {
        "uuid": uuid,
        "eventType": "user.session.start",
        "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"},
        "outcome": {"result": "SUCCESS"},
        "target": [],
    }


def test_incomplete_chunk_stops_sync_and_does_not_advance_watermark(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    environment = "11111111-1111-1111-1111-111111111111"

    since = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    okta_client = FakeOktaClient([
        ([_event("evt-1", since)], True),   # day 1: complete
        ([_event("evt-2", since)], False),  # day 2: INCOMPLETE -- hit max_pages
    ])

    result = audit_store.sync_okta_events(okta_client, environment, "all", since=since)

    assert result["complete"] is False
    assert "error" in result
    assert result["chunks"] == 2

    state = audit_store.get_sync_state(environment)
    assert state["last_sync_status"] == "error"
    assert state["last_sync_error"] is not None
    # Watermark must sit at day 1's completion, NOT be advanced into day 2
    # (the incomplete chunk) -- confirmed via the published timestamp of
    # the only event that was inserted during the completed day.
    assert state["last_synced_at"] is not None
    assert state["last_synced_at"] <= okta_client.calls[0][1]  # <= day 1's "until"

    # Both chunks' events were still inserted (the error path doesn't
    # discard already-fetched rows, only stops advancing the watermark).
    assert state["total_events_ingested"] == 2


def test_resuming_after_incomplete_chunk_retries_same_window(tmp_audit_store, tmp_environments_file):
    """The actual regression this fix prevents: a subsequent sync call
    with since=None must resume from the retained watermark and retry
    the SAME day-chunk that previously came back incomplete, not skip
    past it and not restart from scratch.

    Note on `since=None`'s fallback behavior (audit_store.py's own
    sync_okta_events): if NO prior watermark exists at all (a sync whose
    very first chunk fails immediately, so last_synced_at is still None),
    resuming defaults all the way back to 90 days ago, same as a true
    first-ever sync -- there's nothing earlier to resume FROM yet. To
    test the actual "retry the specific failed chunk, don't skip it"
    guarantee, this test needs a watermark to already exist: day 1
    succeeds, day 2 fails -- so the retained watermark is day 1's
    completion, and the resumed sync must start exactly there, not at
    day 2 (which would silently skip day 2's un-fetched events) and not
    at 90 days ago (which would silently re-scan day 1 for nothing)."""
    audit_store.run_migrations()
    environment = "11111111-1111-1111-1111-111111111111"
    day1_since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    first_client = FakeOktaClient([
        ([_event("evt-1", day1_since)], True),   # day 1: completes, watermark advances
        ([_event("evt-2", day1_since)], False),  # day 2: INCOMPLETE -- stops here
    ])
    first_result = audit_store.sync_okta_events(first_client, environment, "all", since=day1_since)
    assert first_result["complete"] is False
    assert first_result["chunks"] == 2

    state_after_failure = audit_store.get_sync_state(environment)
    assert state_after_failure["last_sync_status"] == "error"
    retained_watermark = state_after_failure["last_synced_at"]
    # The watermark advances to the max `published` timestamp actually
    # seen in a completed chunk (not the chunk's clock-time boundary) --
    # day 1's one event's published time, in this case.
    assert retained_watermark == day1_since

    # Resume with since=None -- must pick up exactly at the retained
    # watermark (day 1's completion), i.e. retry day 2's window, not skip
    # past it to day 3+ and not restart from 90 days ago. Only the FIRST
    # call's `since` matters for this assertion -- its `until` naturally
    # differs run-to-run (each call caps `until` at its OWN wall-clock
    # "now", and real time passes between the two sync_okta_events calls
    # in this test), which is expected, not a regression. FakeOktaClient
    # auto-completes any further trailing chunk needed to reach "now"
    # (see its docstring).
    second_client = FakeOktaClient([
        ([_event("evt-3", day1_since)], True),  # the retried (previously-failed) chunk
    ])
    second_result = audit_store.sync_okta_events(second_client, environment, "all", since=None)
    assert second_result["complete"] is True

    retried_since = second_client.calls[0][0]
    assert retried_since == retained_watermark  # resumes from day 1's end, not day 2's end or 90 days ago

    final_state = audit_store.get_sync_state(environment)
    assert final_state["last_sync_status"] == "success"


def test_full_success_marks_status_success_with_no_error(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    environment = "11111111-1111-1111-1111-111111111111"
    since = (datetime.now(timezone.utc) - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    okta_client = FakeOktaClient([
        ([_event("evt-1", since)], True),
    ])
    result = audit_store.sync_okta_events(okta_client, environment, "all", since=since)
    assert result["complete"] is True
    assert "error" not in result
    state = audit_store.get_sync_state(environment)
    assert state["last_sync_status"] == "success"
    assert state["last_sync_error"] is None
