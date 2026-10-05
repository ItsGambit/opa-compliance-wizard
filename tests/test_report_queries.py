"""Covers TEST-05 (external review, 2026-10-05): audit_store's report/
query layer (query_events, count_events, run_report, resource_history)
and prune_events/_normalize_until had no tests at all before this file
(and tests/test_prune_events.py, tests/test_report_truncation.py, both
added in this same review pass) -- cross-tenant scoping, curated-row
retention, and date-window inclusiveness were all unverified. The
review's own mutation harness found four real survivors here:

- M44: events INSERT OR REPLACE instead of OR IGNORE -- would silently
  rewrite an immutable, already-stored event on a re-sync/re-import
  instead of a true no-op.
- M45: the curated-scope filter removed from _insert_rows -- an
  ingestion_scope="curated" sync would write everything, not just
  curated event types.
- M47: query_events missing its environment_id scoping -- a report for
  one environment would include every OTHER environment's rows too, a
  cross-tenant data leak through the report API.
- _normalize_until's day-inclusion fix (the whole reason that function
  exists) had no test asserting a bare "YYYY-MM-DD" `to:` date actually
  includes that day's events, not just up to its first second.

prune_events' own FOREIGN KEY bug (DATA-01) and run_report/
resource_history's truncation reporting (UI-03/DATA-06) are covered in
their own dedicated test files added in this same pass; this file is
the remaining report/query gap TEST-05 names."""
from datetime import datetime, timedelta, timezone

import audit_store

ENV_A = "11111111-1111-1111-1111-111111111111"
ENV_B = "22222222-2222-2222-2222-222222222222"


class FakeOktaClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _event(uuid, published, event_type="user.authentication.verify", target=None):
    return {
        "uuid": uuid,
        "eventType": event_type,
        "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"},
        "outcome": {"result": "SUCCESS"},
        "target": target or [],
    }


def _sync(env, events, scope="all"):
    client = FakeOktaClient([(events, True)])
    since = min((e["published"] for e in events), default=(datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    audit_store.sync_okta_events(client, env, scope, since=since)


# ---------------------------------------------------------------------------
# M47: query_events/count_events/resource_history must scope by
# environment_id -- a report for ENV_A must never include ENV_B's rows.
# ---------------------------------------------------------------------------
def test_query_events_is_scoped_to_the_requested_environment(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    now = datetime.now(timezone.utc)
    t = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    _sync(ENV_A, [_event("evt-a", t)])
    _sync(ENV_B, [_event("evt-b", t)])

    rows_a = audit_store.query_events(ENV_A)
    rows_b = audit_store.query_events(ENV_B)

    assert {r["uuid"] for r in rows_a} == {"evt-a"}
    assert {r["uuid"] for r in rows_b} == {"evt-b"}


def test_count_events_is_scoped_to_the_requested_environment(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    now = datetime.now(timezone.utc)
    t = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    _sync(ENV_A, [_event("evt-a1", t), _event("evt-a2", t)])
    _sync(ENV_B, [_event("evt-b1", t)])

    assert audit_store.count_events(ENV_A) == 2
    assert audit_store.count_events(ENV_B) == 1


def test_resource_history_is_scoped_to_the_requested_environment(tmp_audit_store, tmp_environments_file):
    """Both environments have an event whose target shares the SAME
    target_id -- a cross-tenant leak here would surface the OTHER
    environment's event for a lookup scoped to just one."""
    audit_store.run_migrations()
    now = datetime.now(timezone.utc)
    t = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    shared_target = [{"id": "tgt-shared", "displayName": "Shared Name"}]
    _sync(ENV_A, [_event("evt-a", t, target=shared_target)])
    _sync(ENV_B, [_event("evt-b", t, target=shared_target)])

    result_a = audit_store.resource_history(ENV_A, resource_id="tgt-shared")
    result_b = audit_store.resource_history(ENV_B, resource_id="tgt-shared")

    assert {r["uuid"] for r in result_a["rows"]} == {"evt-a"}
    assert {r["uuid"] for r in result_b["rows"]} == {"evt-b"}


def test_run_report_is_scoped_to_the_requested_environment(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    now = datetime.now(timezone.utc)
    t = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    _sync(ENV_A, [_event("evt-a", t, event_type="user.authentication.auth_via_mfa")])
    _sync(ENV_B, [_event("evt-b", t, event_type="user.authentication.auth_via_mfa")])

    result = audit_store.run_report("mfa_enforcement", ENV_A)
    assert {r["uuid"] for r in result["rows"]} == {"evt-a"}


# ---------------------------------------------------------------------------
# M44: re-ingesting an already-stored uuid must be a true no-op (OR
# IGNORE), never a silent rewrite (OR REPLACE) -- a raw Okta event is
# immutable once published.
# ---------------------------------------------------------------------------
def test_reingesting_the_same_uuid_does_not_rewrite_the_stored_row(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    t = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    original = _event("evt-1", t, event_type="user.authentication.verify")
    _sync(ENV_A, [original])

    # A second sync returns the SAME uuid but with different content (as
    # if something tried to "correct" an already-stored, published
    # event) -- the stored row must be unaffected.
    tampered = _event("evt-1", t, event_type="user.account.privilege.grant")
    client = FakeOktaClient([([tampered], True)])
    audit_store.sync_okta_events(client, ENV_A, "all", since=t)

    rows = audit_store.query_events(ENV_A)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "user.authentication.verify"  # original, not overwritten


# ---------------------------------------------------------------------------
# M45: ingestion_scope="curated" must only ever write curated event
# types -- never silently fall through to writing everything.
# ---------------------------------------------------------------------------
def test_curated_scope_sync_only_writes_curated_event_types(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    t = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    curated_event = _event("evt-curated", t, event_type="user.authentication.auth_via_mfa")  # IS curated
    noncurated_event = _event("evt-noncurated", t, event_type="user.authentication.verify")  # NOT curated

    client = FakeOktaClient([([curated_event, noncurated_event], True)])
    audit_store.sync_okta_events(client, ENV_A, "curated", since=t)

    rows = audit_store.query_events(ENV_A)
    assert {r["uuid"] for r in rows} == {"evt-curated"}


def test_all_scope_sync_writes_both_curated_and_noncurated(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    t = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    curated_event = _event("evt-curated", t, event_type="user.authentication.auth_via_mfa")
    noncurated_event = _event("evt-noncurated", t, event_type="user.authentication.verify")

    client = FakeOktaClient([([curated_event, noncurated_event], True)])
    audit_store.sync_okta_events(client, ENV_A, "all", since=t)

    rows = audit_store.query_events(ENV_A)
    assert {r["uuid"] for r in rows} == {"evt-curated", "evt-noncurated"}


# ---------------------------------------------------------------------------
# _normalize_until: a bare "YYYY-MM-DD" `to:` date must include that
# WHOLE day's events, not just up to its first second (the exact bug a
# naive string "<=" comparison produces -- "2026-09-29" sorts BEFORE
# "2026-09-29T10:00:00.000Z" lexicographically).
# ---------------------------------------------------------------------------
def test_bare_date_to_filter_includes_the_whole_day(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    morning = "2026-09-29T08:00:00.000Z"
    evening = "2026-09-29T22:00:00.000Z"
    next_day = "2026-09-30T01:00:00.000Z"
    client = FakeOktaClient([([_event("evt-morning", morning), _event("evt-evening", evening), _event("evt-next-day", next_day)], True)])
    audit_store.sync_okta_events(client, ENV_A, "all", since="2026-09-29T00:00:00.000Z")

    rows = audit_store.query_events(ENV_A, until="2026-09-29")  # bare date, no time component
    uuids = {r["uuid"] for r in rows}
    assert "evt-morning" in uuids
    assert "evt-evening" in uuids  # the whole day, not just its first second
    assert "evt-next-day" not in uuids  # the NEXT day must still be excluded
