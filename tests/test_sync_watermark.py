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


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_incomplete_chunk_resumes_from_its_newest_event_not_the_chunk_end(tmp_audit_store, tmp_environments_file):
    """DATA-09 (external review, 2026-10-05) + TEST-06. The fetch is
    ASCENDING, so when a day-chunk hits the page cap everything up to the
    newest `published` actually returned is complete. The sync must set
    the watermark to EXACTLY that instant and ask Okta for the same day
    again starting there -- not stop (the old behaviour, which could never
    get past a day busier than the cap), and not jump to the chunk's end
    (which would skip the un-fetched remainder of the day). TEST-06 named
    the gap in the old assertions: a watermark advanced to the newest
    event of the TRUNCATED page passed them; here that instant is the one
    required value, and the second call's `since` must equal it."""
    audit_store.run_migrations()
    environment = "11111111-1111-1111-1111-111111111111"
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=2)
    since = _iso(start)
    mid_day = _iso(start + timedelta(hours=6))   # newest event the capped first page returned
    later = _iso(start + timedelta(hours=18))    # still inside day 1, only reachable by resuming
    okta_client = FakeOktaClient([
        ([_event("evt-1", since), _event("evt-2", mid_day)], False),  # day 1, page cap hit at mid_day
        ([_event("evt-2", mid_day), _event("evt-3", later)], True),   # resumed from mid_day (inclusive -> evt-2 again, deduped)
    ])

    result = audit_store.sync_okta_events(okta_client, environment, "all", since=since)

    assert result["complete"] is True
    assert result["incomplete_chunks"] == 1
    assert result["scanned"] == 4  # the re-read instant counts as fetched (documented), inserted stays 3
    assert "error" not in result
    assert okta_client.calls[1][0] == mid_day  # resumed from exactly the newest fetched event
    assert okta_client.calls[1][1] >= okta_client.calls[0][1]  # the resumed window still covers the rest of day 1
    state = audit_store.get_sync_state(environment)
    assert state["last_sync_status"] == "success"
    assert state["last_sync_error"] is None
    assert state["total_events_ingested"] == 3  # evt-2 was re-read and deduplicated, not doubled
    assert state["last_synced_at"] >= later


def test_incomplete_chunk_with_no_progress_stops_with_an_error_instead_of_looping(tmp_audit_store, tmp_environments_file):
    """The one case resuming cannot help: every page of the capped fetch
    carried the same instant as the chunk start, so resuming from
    max_published would ask the identical question forever."""
    audit_store.run_migrations()
    environment = "11111111-1111-1111-1111-111111111111"
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=2)
    since = _iso(start)
    okta_client = FakeOktaClient([
        ([_event("evt-1", since)], False),  # cap hit, newest event == chunk start: no progress possible
    ])

    result = audit_store.sync_okta_events(okta_client, environment, "all", since=since)

    assert result["complete"] is False
    assert result["incomplete_chunks"] == 1
    assert "without making progress" in result["error"]
    assert len(okta_client.calls) == 1  # did not loop
    state = audit_store.get_sync_state(environment)
    assert state["last_sync_status"] == "error"
    assert state["last_sync_error"] is not None
    assert state["last_sync_completed_at"] is None  # DATA-05: completion is only ever a success
    assert state["last_sync_attempt_at"] is not None
    assert state["total_events_ingested"] == 1  # the fetched row is kept, not discarded


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

    day2_since = (
        datetime.fromisoformat(day1_since.replace("Z", "+00:00")) + timedelta(days=1)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    first_client = FakeOktaClient([
        ([_event("evt-1", day1_since)], True),   # day 1: completes, watermark advances to evt-1's instant
        # day 2: INCOMPLETE with no progress -- every event the capped page
        # returned carries the chunk's own first instant (a burst of events
        # sharing one millisecond), so resuming from it would re-ask the same
        # question; the one shape that still stops the run.
        ([_event("evt-2", day2_since)], False),
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

    # Resume with since=None -- must pick up AT OR BEFORE the retained
    # watermark (day 1's completion), i.e. retry day 2's window, not skip
    # past it to day 3+ and not restart from 90 days ago. DATA-02 (external
    # review, 2026-10-05): resuming from a stored watermark now starts
    # WATERMARK_OVERLAP_SECONDS before it, not exactly at it, so an event
    # indexed by Okta just after a prior sync already ran past its
    # `published` time still gets picked up on the next sync (INSERT OR
    # IGNORE's existing dedup-by-uuid makes the re-scanned overlap free of
    # duplicates). Only the FIRST call's `since` matters for this
    # assertion -- its `until` naturally differs run-to-run (each call
    # caps `until` at its OWN wall-clock "now" minus the safety lag, and
    # real time passes between the two sync_okta_events calls in this
    # test), which is expected, not a regression. FakeOktaClient
    # auto-completes any further trailing chunk needed to reach "now"
    # (see its docstring).
    second_client = FakeOktaClient([
        ([_event("evt-3", day1_since)], True),  # the retried (previously-failed) chunk
    ])
    second_result = audit_store.sync_okta_events(second_client, environment, "all", since=None)
    assert second_result["complete"] is True

    retried_since = second_client.calls[0][0]
    assert retried_since <= retained_watermark  # resumes at/before day 1's end, never after it
    expected_earliest = (
        datetime.fromisoformat(retained_watermark.replace("Z", "+00:00"))
        - timedelta(seconds=audit_store.WATERMARK_OVERLAP_SECONDS)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert retried_since == expected_earliest

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
