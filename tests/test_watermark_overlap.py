"""Covers audit_store.sync_okta_events' watermark overlap and safety-lag
guards (DATA-02, external review, 2026-10-05): the System Log is
eventually consistent, so an event with a `published` time just behind a
sync's watermark can become queryable moments AFTER that sync already ran
-- without a safety margin, the next sync's `since` starts right at (or
past) that event's timestamp and never fetches it, permanently, since
Okta's 90-day retention makes the gap unrecoverable later.

Uses the same FakeOktaClient/_event helpers as test_sync_watermark.py
(duplicated here rather than imported, matching that file's own
precedent of being self-contained)."""
from datetime import datetime, timedelta, timezone

import audit_store

ENV = "11111111-1111-1111-1111-111111111111"


class FakeOktaClient:
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
        "eventType": "user.authentication.verify",
        "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"},
        "outcome": {"result": "SUCCESS"},
        "target": [],
    }


def test_resume_rescans_an_overlap_window_before_the_stored_watermark(tmp_audit_store, tmp_environments_file):
    """The actual DATA-02 scenario: run 1 ingests an event and advances the
    watermark to its published time. Run 2 (resuming with since=None) must
    start BEFORE that watermark by WATERMARK_OVERLAP_SECONDS, not exactly
    at it -- the dedup-by-uuid on INSERT OR IGNORE makes re-scanning that
    window free of duplicates, and it's exactly the margin that would have
    caught an event Okta indexed moments late."""
    audit_store.run_migrations()
    first_published = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    first_client = FakeOktaClient([([_event("evt-1", first_published)], True)])
    audit_store.sync_okta_events(first_client, ENV, "all", since=first_published)

    state = audit_store.get_sync_state(ENV)
    assert state["last_synced_at"] == first_published

    second_client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(second_client, ENV, "all", since=None)

    first_call_since = second_client.calls[0][0]
    expected = (
        datetime.fromisoformat(first_published.replace("Z", "+00:00"))
        - timedelta(seconds=audit_store.WATERMARK_OVERLAP_SECONDS)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert first_call_since == expected


def test_a_late_indexed_event_below_the_watermark_is_not_permanently_lost(tmp_audit_store, tmp_environments_file):
    """End-to-end proof: a sync resuming from a stored watermark queries
    Okta starting BEFORE a late-indexed event's published time, not at or
    after it -- the actual guarantee that makes the event recoverable.
    (FakeOktaClient, like every test double in this suite, returns its
    scripted response regardless of the since/until it's called with --
    it can't simulate "Okta would have excluded this event from a window
    starting after its published time" -- so the real assertion has to be
    on the REQUESTED window, which is exactly what a real Okta API would
    use to decide what's in range.)"""
    audit_store.run_migrations()
    watermark_published = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    first_client = FakeOktaClient([([_event("evt-on-time", watermark_published)], True)])
    audit_store.sync_okta_events(first_client, ENV, "all", since=watermark_published)

    # This event's published time is a few minutes BEFORE the watermark
    # that run 1 just set -- exactly what "indexed late" looks like.
    late_published = (
        datetime.fromisoformat(watermark_published.replace("Z", "+00:00")) - timedelta(minutes=2)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    second_client = FakeOktaClient([([_event("evt-late", late_published)], True)])
    audit_store.sync_okta_events(second_client, ENV, "all", since=None)

    first_requested_since = second_client.calls[0][0]
    assert first_requested_since <= late_published  # the window covers the late event's own published time

    conn = audit_store._get_connection()
    row = conn.execute(
        "SELECT 1 FROM events WHERE environment_id = ? AND uuid = ?", (ENV, "evt-late")
    ).fetchone()
    assert row is not None  # and it really is ingested once the window covers it


def test_final_chunk_never_reaches_literal_now(tmp_audit_store, tmp_environments_file):
    """SAFETY_LAG_SECONDS: a sync's last chunk must stop short of the
    actual wall-clock moment it ran, so an event indexed in the few
    seconds right around "now" doesn't get skipped by a watermark that
    was set to a point in time Okta might still be catching up to."""
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    before_call = datetime.now(timezone.utc)

    client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(client, ENV, "all", since=since)

    last_until = datetime.fromisoformat(client.calls[-1][1].replace("Z", "+00:00"))
    assert last_until <= before_call - timedelta(seconds=audit_store.SAFETY_LAG_SECONDS - 1)


def test_explicit_since_is_not_shifted_by_the_overlap(tmp_audit_store, tmp_environments_file):
    """The overlap only applies to the automatic resume-from-watermark path
    (since=None). A caller that passes an explicit `since` (a manual
    backfill, a test, a deliberate re-sync from a specific point) asked
    for that exact start -- it must not be silently pulled earlier."""
    audit_store.run_migrations()
    explicit_since = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    client = FakeOktaClient([([], True)])
    audit_store.sync_okta_events(client, ENV, "all", since=explicit_since)

    assert client.calls[0][0] == explicit_since
