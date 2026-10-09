"""Service Accounts report (v5.40.0): build_service_accounts_report_from_archive,
audit_store.count_events_by_resource, the serviceAccountType
resource_type_detail fallback, the shared create/delete rules the Secrets
builders now use too, migration 005's indexes, and the
/api/service_accounts_report route (auth gating, owner isolation, error
mapping).

Every event shape here mirrors what a read-only probe of a real archive
showed on 2026-10-07 (see SERVICE_ACCOUNT_REPORT_EVENT_TYPES' comment in
create_secret_folders.py): pam.service_account.* carries the account as a
"Service Account" target (uuid id == alternateId) followed by the Team,
with debugData.serviceAccountType naming the family; pam.resource.checkout
carries Team first, then the same "Service Account" target, with
debugData.resourceType instead. All ids/names below are synthetic.

Timestamps come from ONE frozen base time per process (BASE), so an
assertion never recomputes "now" after the code under test ran -- the
original version of this file called datetime.now() in both places and
could flake across a second boundary.
"""
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import audit_store
import create_secret_folders as engine

ENV = "11111111-1111-4111-8111-111111111111"
ENV_OTHER = "22222222-2222-4222-8222-222222222222"
TEAM_ID = "33333333-3333-4333-8333-333333333333"

SAAS_LIVE = "aaaaaaaa-0000-4000-8000-000000000001"
OKTA_LIVE = "aaaaaaaa-0000-4000-8000-000000000002"
SAAS_GONE = "aaaaaaaa-0000-4000-8000-000000000003"
OKTA_GONE = "aaaaaaaa-0000-4000-8000-000000000004"
DB_ACCT = "aaaaaaaa-0000-4000-8000-000000000005"
AD_ACCT = "aaaaaaaa-0000-4000-8000-000000000006"
MYSTERY = "aaaaaaaa-0000-4000-8000-000000000007"

BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
class FakeOktaClient:
    def __init__(self, events):
        self._responses = [(list(events), True)]

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _ts(hours_ago):
    return (BASE - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ingest(env, events):
    """Goes through the real ingest path (sync_okta_events -> _insert_rows)
    so resource_id/resource_type_detail land in the DB exactly as they
    would for a real sync -- also records a COMPLETED sync for the
    environment, which the route's not-synced guard keys off."""
    since = min((e["published"] for e in events), default=_ts(24))
    audit_store.sync_okta_events(FakeOktaClient(events), env, "all", since=since)


def _sa_event(uuid, event_type, account_id, published, *, sa_type="APP_ACCOUNT", outcome="SUCCESS",
              reason=None, actor="Alex Example", name="Example account", system_initiated=None,
              resource_type=None, checkout_expiry=None, actor_type="User"):
    debug = {"teamName": "example-team", "traceId": uuid[:8]}
    if sa_type is not None:
        debug["serviceAccountType"] = sa_type
    if resource_type is not None:
        debug["resourceType"] = resource_type
    if system_initiated is not None:
        debug["system Initiated"] = system_initiated
    if checkout_expiry is not None:
        debug["checkoutExpiry"] = checkout_expiry
    account_target = {"id": account_id, "type": "Service Account", "alternateId": account_id, "displayName": name}
    team_target = {"id": TEAM_ID, "type": "Team", "alternateId": TEAM_ID, "displayName": "example-team"}
    targets = [team_target, account_target] if event_type == "pam.resource.checkout" else [account_target, team_target]
    return {
        "uuid": uuid,
        "eventType": event_type,
        "published": published,
        "displayMessage": f"(PAM) {event_type}",
        "actor": {"id": "00uEXAMPLE", "type": actor_type, "alternateId": "alex@example.com", "displayName": actor},
        "outcome": {"result": outcome, "reason": reason},
        "target": targets,
        "debugContext": {"debugData": debug},
        "transaction": {"type": "WEB", "id": f"txn-{uuid}"},
    }


def _checkout(uuid, account_id, published, resource_type, **kw):
    return _sa_event(uuid, "pam.resource.checkout", account_id, published, sa_type=None,
                     resource_type=resource_type, **kw)


def _rotation(uuid, account_id, published, **kw):
    kw.setdefault("actor_type", "SystemPrincipal")
    kw.setdefault("actor", "Okta System")
    return _sa_event(uuid, "pam.service_account.password_rotation.end", account_id, published, **kw)


def _insert_legacy_row(env, raw, resource_type_detail=None):
    """A row as it would exist from BEFORE the serviceAccountType fallback
    shipped: resource_id set (so backfill_resource_columns never revisits
    it), resource_type_detail NULL unless given."""
    conn = audit_store._get_connection()
    sa = next(t for t in raw["target"] if t["type"] == "Service Account")
    conn.execute(
        """INSERT INTO events (uuid, environment_id, event_type, published, actor_id, actor_display_name,
           actor_alternate_id, outcome_result, is_curated, raw_json, resource_id, resource_alternate_id, resource_type_detail)
           VALUES (?, ?, ?, ?, 'a', 'A', 'a@example.com', ?, 1, ?, ?, ?, ?)""",
        (raw["uuid"], env, raw["eventType"], raw["published"], raw["outcome"]["result"], json.dumps(raw),
         sa["id"], sa["id"], resource_type_detail),
    )
    conn.commit()


class FakeOpaClient:
    """Just the four list calls walk_service_account_rosters makes."""

    def __init__(self, resource_groups=None, projects=None, saas=None, okta=None):
        self._rgs = resource_groups or []
        self._projects = projects or {}
        self._saas = saas or {}
        self._okta = okta or {}
        self.calls = []

    def list_resource_groups(self):
        self.calls.append("resource_groups")
        return self._rgs

    def list_projects(self, rg_id):
        self.calls.append(("projects", rg_id))
        return self._projects.get(rg_id, [])

    def list_project_saas_app_accounts(self, rg_id, project_id):
        self.calls.append(("saas", rg_id, project_id))
        return self._saas.get(project_id, [])

    def list_project_okta_ud_accounts(self, rg_id, project_id):
        self.calls.append(("okta", rg_id, project_id))
        return self._okta.get(project_id, [])


def _one_project_client(saas=(), okta=()):
    return FakeOpaClient(
        resource_groups=[{"id": "rg-1", "name": "Example RG"}],
        projects={"rg-1": [{"id": "proj-1", "name": "Example Project"}]},
        saas={"proj-1": list(saas)},
        okta={"proj-1": list(okta)},
    )


def _saas_acct(aid, name="Example SaaS account", **extra):
    return {"id": aid, "name": name, "username": "svc@example.com", "application_instance_id": "app-1",
            "application_instance_name": "Example App", "privileged_resource_id": "opr-example-1",
            "sync_status": "SYNCED", "last_password_change_system_timestamp": "2026-10-01T00:00:00.000Z", **extra}


def _okta_acct(aid, name="Example Okta account", **extra):
    return {"id": aid, "name": name, "username": "svc-okta@example.com", "okta_user_id": "00uEXAMPLESA",
            "sync_status": "SYNCED", **extra}


@pytest.fixture
def schema(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    return tmp_audit_store


def _by_id(report):
    return {r["id"]: r for r in report["accounts"]}


EMPTY_ROTATIONS = {"total": 0, "by_outcome": {}, "first_at": None, "last_at": None, "recent": []}


# ---------------------------------------------------------------------------
# Status honesty: active / deleted / unknown
# ---------------------------------------------------------------------------
def test_live_account_with_no_history_is_active_with_empty_history(schema):
    _ingest(ENV, [])
    client = _one_project_client(saas=[_saas_acct(SAAS_LIVE)], okta=[_okta_acct(OKTA_LIVE)])

    report = engine.build_service_accounts_report_from_archive(client, ENV)

    rows = _by_id(report)
    assert set(rows) == {SAAS_LIVE, OKTA_LIVE}
    saas, okta = rows[SAAS_LIVE], rows[OKTA_LIVE]
    assert saas["status"] == okta["status"] == "active"
    assert saas["kind"] == "saas" and okta["kind"] == "okta"
    assert saas["app_name"] == "Example App" and saas["okta_user_id"] is None
    assert okta["okta_user_id"] == "00uEXAMPLESA" and okta["app_name"] is None
    assert saas["project_name"] == "Example Project" and saas["resource_group_name"] == "Example RG"
    assert saas["sync_status"] == "SYNCED"  # informational, passed through untouched
    for row in (saas, okta):
        assert row["created"] is None and row["deleted"] is None
        assert row["updated"] == [] and row["assigned"] == [] and row["reveals"] == [] and row["checkouts"] == []
        assert row["rotations"] == EMPTY_ROTATIONS
    assert report["summary"] == {"total": 2, "saas": 1, "okta": 1, "active": 2, "deleted": 0, "unknown": 0}
    assert report["walked"] == {"resource_groups": 1, "projects": 1}
    assert report["excluded"] == {"other_account_types": 0, "unclassified": 0}
    assert report["warnings"] == {"conflicting_family_markers": 0}
    assert report["event_total"] == 0 and report["truncated"] is False
    assert report["local_retention_enabled"] is True and report["since_days"] is None
    assert report["oldest_captured_at"] is None


def test_event_only_account_is_deleted_only_with_a_successful_delete_event(schema):
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.create", SAAS_GONE, _ts(10), name="Gone SaaS"),
        _sa_event("e2", "pam.service_account.delete", SAAS_GONE, _ts(5), name="Gone SaaS", actor="Dana Example"),
        _sa_event("e3", "pam.service_account.create", OKTA_GONE, _ts(12), sa_type="OKTA_USER_ACCOUNT", name="Gone Okta"),
        # A FAILED delete is not evidence of deletion.
        _sa_event("e4", "pam.service_account.delete", OKTA_GONE, _ts(4), sa_type="OKTA_USER_ACCOUNT", outcome="FAILURE",
                  reason="example failure", name="Gone Okta"),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)

    rows = _by_id(report)
    assert rows[SAAS_GONE]["status"] == "deleted"
    assert rows[SAAS_GONE]["kind"] == "saas"
    assert rows[SAAS_GONE]["name"] == "Gone SaaS"
    assert rows[SAAS_GONE]["deleted"]["by"] == "Dana Example"
    assert rows[SAAS_GONE]["deleted"]["outcome"] == "SUCCESS"
    assert rows[SAAS_GONE]["deleted"]["request_id"] == "txn-e2"
    # Not attributable to a project once gone -- never guessed.
    assert rows[SAAS_GONE]["project_id"] is None and rows[SAAS_GONE]["resource_group_name"] is None
    assert rows[SAAS_GONE]["username"] is None

    assert rows[OKTA_GONE]["status"] == "unknown"
    assert rows[OKTA_GONE]["kind"] == "okta"
    assert rows[OKTA_GONE]["deleted"] is None
    assert report["summary"]["deleted"] == 1 and report["summary"]["unknown"] == 1
    assert report["oldest_captured_at"] == _ts(12)


def test_live_roster_wins_over_a_stale_delete_event(schema):
    """Present live => active, even if the archive holds a delete for the
    same id (the delete entry is still surfaced, status is not guessed)."""
    _ingest(ENV, [_sa_event("e1", "pam.service_account.delete", SAAS_LIVE, _ts(5))])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(saas=[_saas_acct(SAAS_LIVE)]), ENV)
    row = _by_id(report)[SAAS_LIVE]
    assert row["status"] == "active"
    assert row["deleted"]["at"] == _ts(5)


# ---------------------------------------------------------------------------
# Classification: SaaS vs Okta vs the families this report is NOT about
# ---------------------------------------------------------------------------
def test_database_and_ad_accounts_are_excluded_and_counted_not_silently_dropped(schema):
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.password.reveal", DB_ACCT, _ts(3), sa_type="DATABASE_ACCOUNT"),
        _rotation("e2", AD_ACCT, _ts(2), sa_type="PAM_AD_ACCOUNT", outcome="FAILURE", reason="example"),
        _sa_event("e3", "pam.service_account.password.reveal", SAAS_GONE, _ts(1)),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)

    assert set(_by_id(report)) == {SAAS_GONE}
    assert report["excluded"] == {"other_account_types": 2, "unclassified": 0}


def test_update_with_empty_marker_resolves_from_the_accounts_other_evidence(schema):
    """Seen live: an update event whose serviceAccountType is ''. For a
    roster account it attaches; for an id with no other evidence at all
    it is excluded as unclassified (counted), never guessed."""
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.update", OKTA_LIVE, _ts(2), sa_type=""),
        _sa_event("e2", "pam.service_account.update", MYSTERY, _ts(2), sa_type=""),
        # Older create for SAAS_GONE carries the marker; its newer update does not.
        _sa_event("e3", "pam.service_account.update", SAAS_GONE, _ts(1), sa_type=""),
        _sa_event("e4", "pam.service_account.create", SAAS_GONE, _ts(9)),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(okta=[_okta_acct(OKTA_LIVE)]), ENV)

    rows = _by_id(report)
    assert set(rows) == {OKTA_LIVE, SAAS_GONE}
    assert len(rows[OKTA_LIVE]["updated"]) == 1
    assert rows[SAAS_GONE]["kind"] == "saas" and len(rows[SAAS_GONE]["updated"]) == 1
    assert report["excluded"]["unclassified"] == 1


def test_checkout_attaches_to_known_accounts_but_only_creates_one_from_a_confirmed_type(schema):
    _ingest(ENV, [
        # Confirmed SaaS marker on an otherwise unknown id -> creates a SaaS row.
        _checkout("c1", SAAS_GONE, _ts(4), "MANAGED_SAAS_APP_SERVICE_ACCOUNT", checkout_expiry="2026-10-08T00:00:00.000Z"),
        # Unconfirmed marker on a LIVE Okta account -> attaches (the roster already knows the id).
        _checkout("c2", OKTA_LIVE, _ts(3), "SOME_FUTURE_OKTA_MARKER"),
        # Unconfirmed marker on an unknown id -> excluded as unclassified, never a new row.
        _checkout("c3", MYSTERY, _ts(2), "SOME_FUTURE_OKTA_MARKER"),
        # Database account checkout (shares the "Service Account" target type) -> excluded as other.
        _checkout("c4", DB_ACCT, _ts(1), "PAM_DATABASE_ACCOUNT"),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(okta=[_okta_acct(OKTA_LIVE)]), ENV)

    rows = _by_id(report)
    assert set(rows) == {SAAS_GONE, OKTA_LIVE}
    assert rows[SAAS_GONE]["kind"] == "saas" and rows[SAAS_GONE]["status"] == "unknown"
    assert rows[SAAS_GONE]["checkouts"][0]["expires_at"] == "2026-10-08T00:00:00.000Z"
    assert len(rows[OKTA_LIVE]["checkouts"]) == 1
    assert report["excluded"] == {"other_account_types": 1, "unclassified": 1}


def test_conflicting_family_markers_are_counted_and_the_roster_wins(schema):
    """A roster SaaS id whose events claim DATABASE_ACCOUNT, and an
    event-only id that votes both saas and okta -- real evidence
    disagreeing with itself is surfaced as a count, not resolved silently."""
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.password.reveal", SAAS_LIVE, _ts(3), sa_type="DATABASE_ACCOUNT"),
        _sa_event("e2", "pam.service_account.create", OKTA_GONE, _ts(2), sa_type="OKTA_USER_ACCOUNT"),
        _sa_event("e3", "pam.service_account.update", OKTA_GONE, _ts(1), sa_type="APP_ACCOUNT"),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(saas=[_saas_acct(SAAS_LIVE)]), ENV)
    rows = _by_id(report)
    assert rows[SAAS_LIVE]["kind"] == "saas" and len(rows[SAAS_LIVE]["reveals"]) == 1
    assert OKTA_GONE in rows  # still reported (saas wins the tie-break), but flagged
    assert report["warnings"] == {"conflicting_family_markers": 2}


# ---------------------------------------------------------------------------
# History entries
# ---------------------------------------------------------------------------
def test_created_prefers_a_successful_create_over_a_deferred_attempt(schema):
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.create", SAAS_LIVE, _ts(10), outcome="DEFERRED", actor="System"),
        _sa_event("e2", "pam.service_account.create", SAAS_LIVE, _ts(9), outcome="SUCCESS", actor="Alex Example"),
        _sa_event("e3", "pam.service_account.create", OKTA_LIVE, _ts(8), sa_type="OKTA_USER_ACCOUNT", outcome="FAILURE",
                  reason="example reason"),
        _sa_event("e4", "pam.service_account.assign", SAAS_LIVE, _ts(7), actor="Dana Example"),
        _sa_event("e5", "pam.service_account.password.reveal", SAAS_LIVE, _ts(6), actor="Dana Example"),
        _sa_event("e6", "pam.service_account.password.reveal", SAAS_LIVE, _ts(5), actor="Alex Example"),
        # A newer DEFERRED create must not displace the older SUCCESS one.
        _sa_event("e7", "pam.service_account.create", SAAS_LIVE, _ts(4), outcome="DEFERRED", actor="System"),
    ])
    client = _one_project_client(saas=[_saas_acct(SAAS_LIVE)], okta=[_okta_acct(OKTA_LIVE)])
    report = engine.build_service_accounts_report_from_archive(client, ENV)

    rows = _by_id(report)
    assert rows[SAAS_LIVE]["created"]["by"] == "Alex Example"
    assert rows[SAAS_LIVE]["created"]["outcome"] == "SUCCESS"
    # No successful create at all -> the attempt is shown, with its outcome, not hidden.
    assert rows[OKTA_LIVE]["created"]["outcome"] == "FAILURE"
    assert rows[OKTA_LIVE]["created"]["outcome_reason"] == "example reason"
    assert [a["by"] for a in rows[SAAS_LIVE]["assigned"]] == ["Dana Example"]
    # Most-recent-first.
    assert [r["by"] for r in rows[SAAS_LIVE]["reveals"]] == ["Alex Example", "Dana Example"]
    assert rows[SAAS_LIVE]["reveals"][0]["request_id"] == "txn-e6"


def test_rotation_summary_counts_every_outcome_and_caps_the_recent_list(schema):
    events = [
        _rotation(f"r{i}", SAAS_LIVE, _ts(10 - i),
                  outcome=("FAILURE" if i in (1, 3) else "SUCCESS"), reason=("example" if i in (1, 3) else None),
                  system_initiated=("No" if i == 4 else "Yes"))
        for i in range(5)
    ]
    # .start is in the generic card but deliberately NOT part of this report's rotation history.
    events.append(_sa_event("s1", "pam.service_account.password_rotation.start", SAAS_LIVE, _ts(3), actor_type="SystemPrincipal"))
    _ingest(ENV, events)

    report = engine.build_service_accounts_report_from_archive(
        _one_project_client(saas=[_saas_acct(SAAS_LIVE)]), ENV, rotation_limit=2
    )
    rot = _by_id(report)[SAAS_LIVE]["rotations"]
    assert rot["total"] == 5
    assert rot["by_outcome"] == {"SUCCESS": 3, "FAILURE": 2}
    assert rot["first_at"] == _ts(10) and rot["last_at"] == _ts(6)
    assert [r["at"] for r in rot["recent"]] == [_ts(6), _ts(7)]  # newest first, capped at 2
    assert rot["recent"][0]["system_initiated"] is False  # "No"
    assert rot["recent"][1]["system_initiated"] is True  # "Yes"
    assert rot["recent"][1]["outcome"] == "FAILURE" and rot["recent"][1]["outcome_reason"] == "example"
    assert report["oldest_captured_at"] == _ts(10)


def test_rotation_only_account_is_discovered_and_classified_from_stored_markers(schema):
    """An account whose lifecycle predates the archive still shows up:
    totals come from the GROUP BY and its family from the stored
    resource_type_detail values -- even when the NEWEST row carries an
    empty marker (seen live), the older rows that do carry one decide."""
    _ingest(ENV, [
        _rotation("r1", OKTA_GONE, _ts(3), sa_type="OKTA_USER_ACCOUNT", name="Rotation-only Okta"),
        _rotation("r2", OKTA_GONE, _ts(2), sa_type="", name=""),
    ])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)
    rows = _by_id(report)
    assert set(rows) == {OKTA_GONE}
    assert rows[OKTA_GONE]["kind"] == "okta" and rows[OKTA_GONE]["status"] == "unknown"
    assert rows[OKTA_GONE]["name"] == "Rotation-only Okta"  # newest NON-EMPTY name, not the newest row's ''
    assert rows[OKTA_GONE]["rotations"]["total"] == 2


def test_rotation_only_rows_ingested_before_the_fallback_are_classified_from_raw_json(schema):
    """Pre-5.40.0 rows have resource_type_detail NULL, so the GROUP BY
    carries no marker for them -- the builder reads a few raw rows for
    exactly those ids. A DB account found this way is still excluded;
    an id with no marker anywhere stays unclassified (counted)."""
    _ingest(ENV, [])
    _insert_legacy_row(ENV, _rotation("l1", SAAS_GONE, _ts(3), name="Legacy SaaS"))
    _insert_legacy_row(ENV, _rotation("l2", DB_ACCT, _ts(2), sa_type="DATABASE_ACCOUNT"))
    _insert_legacy_row(ENV, _rotation("l3", MYSTERY, _ts(1), sa_type=""))
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)
    rows = _by_id(report)
    assert set(rows) == {SAAS_GONE}
    assert rows[SAAS_GONE]["kind"] == "saas" and rows[SAAS_GONE]["name"] == "Legacy SaaS"
    assert report["excluded"] == {"other_account_types": 1, "unclassified": 1}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
def test_empty_roster_and_empty_archive_returns_the_zero_shape(schema):
    report = engine.build_service_accounts_report_from_archive(FakeOpaClient(), ENV)
    assert report["accounts"] == []
    assert report["summary"] == {"total": 0, "saas": 0, "okta": 0, "active": 0, "deleted": 0, "unknown": 0}
    assert report["walked"] == {"resource_groups": 0, "projects": 0}
    assert report["excluded"] == {"other_account_types": 0, "unclassified": 0}
    assert report["oldest_captured_at"] is None


def test_events_from_another_environment_are_never_included(schema):
    _ingest(ENV_OTHER, [_sa_event("x1", "pam.service_account.delete", SAAS_GONE, _ts(1))])
    _ingest(ENV, [])
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)
    assert report["accounts"] == []


def test_roster_rows_without_an_id_are_skipped_and_duplicates_collapse(schema):
    _ingest(ENV, [])
    client = FakeOpaClient(
        resource_groups=[{"id": "rg-1", "name": "RG"}, {"id": "rg-2", "name": "RG 2"}],
        projects={"rg-1": [{"id": "p1", "name": "P1"}], "rg-2": [{"id": "p2", "name": "P2"}]},
        saas={"p1": [{"name": "no id"}, _saas_acct(SAAS_LIVE)], "p2": [_saas_acct(SAAS_LIVE, name="dup")]},
    )
    report = engine.build_service_accounts_report_from_archive(client, ENV)
    assert [r["id"] for r in report["accounts"]] == [SAAS_LIVE]
    assert report["accounts"][0]["project_name"] == "P1"  # first sighting wins, walk order
    assert report["walked"] == {"resource_groups": 2, "projects": 2}


def test_live_rows_come_first_in_walk_order_then_event_only_rows_by_name(schema):
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.create", OKTA_GONE, _ts(2), sa_type="OKTA_USER_ACCOUNT", name="zeta"),
        _sa_event("e2", "pam.service_account.create", SAAS_GONE, _ts(2), name="Alpha"),
    ])
    client = _one_project_client(saas=[_saas_acct(SAAS_LIVE, name="zz live")], okta=[_okta_acct(OKTA_LIVE, name="aa live")])
    report = engine.build_service_accounts_report_from_archive(client, ENV)
    assert [r["id"] for r in report["accounts"]] == [SAAS_LIVE, OKTA_LIVE, SAAS_GONE, OKTA_GONE]


def test_truncated_is_reported_when_the_bulk_load_cap_is_hit(schema, monkeypatch):
    _ingest(ENV, [_sa_event(f"e{i}", "pam.service_account.password.reveal", SAAS_GONE, _ts(i + 1)) for i in range(4)])
    monkeypatch.setattr(engine, "SERVICE_ACCOUNT_EVENT_LOAD_LIMIT", 2)
    report = engine.build_service_accounts_report_from_archive(_one_project_client(), ENV)
    assert report["event_total"] == 4 and report["truncated"] is True
    assert len(_by_id(report)[SAAS_GONE]["reveals"]) == 2  # the newest two, never silently "complete"


@pytest.mark.parametrize("bad", [0, -1, 201, "5", None, 2.5])
def test_rotation_limit_is_validated(schema, bad):
    with pytest.raises(ValueError):
        engine.build_service_accounts_report_from_archive(FakeOpaClient(), ENV, rotation_limit=bad)


# ---------------------------------------------------------------------------
# The shared create/delete rules now apply to the Secrets builders too
# ---------------------------------------------------------------------------
def _secret_event(uuid, event_type, secret_id, published, outcome="SUCCESS"):
    return {
        "uuid": uuid, "eventType": event_type, "published": published,
        "actor": {"id": "00uEXAMPLE", "type": "User", "alternateId": "alex@example.com", "displayName": "Alex Example"},
        "outcome": {"result": outcome, "reason": None},
        "target": [
            {"id": secret_id, "type": "Secret", "alternateId": secret_id, "displayName": "example-secret"},
            {"id": "proj-1", "type": "Project", "alternateId": "proj-1", "displayName": "Example Project"},
        ],
        "debugContext": {"debugData": {"requestId": f"req-{uuid}"}},
    }


def test_secrets_archive_report_ignores_a_failed_delete_and_prefers_a_successful_create(schema, monkeypatch):
    secret_id = "bbbbbbbb-0000-4000-8000-000000000001"
    gone_id = "bbbbbbbb-0000-4000-8000-000000000002"
    _ingest(ENV, [
        _secret_event("s1", "pam.secret.create", secret_id, _ts(10), outcome="FAILURE"),
        _secret_event("s2", "pam.secret.create", secret_id, _ts(9)),
        _secret_event("s3", "pam.secret.delete", secret_id, _ts(2), outcome="FAILURE"),
        _secret_event("s4", "pam.secret.create", gone_id, _ts(8)),
        _secret_event("s5", "pam.secret.delete", gone_id, _ts(1)),
    ])
    # The live walk says neither secret exists any more.
    monkeypatch.setattr(engine, "fetch_all_folders_and_secrets", lambda client, rg, proj: ([], []))
    report = engine.build_project_secrets_report_from_archive(object(), ENV, "rg-1", "proj-1")
    rows = {r["id"]: r for r in report["secrets"]}
    assert rows[secret_id]["status"] == "unknown"  # a FAILED delete is not evidence of deletion
    assert rows[secret_id]["deleted"] is None
    assert rows[secret_id]["created"]["at"] == _ts(9) and rows[secret_id]["created"]["outcome"] == "SUCCESS"
    assert rows[gone_id]["status"] == "deleted"
    assert rows[gone_id]["deleted"]["request_id"] == "req-s5"


def test_entry_succeeded_treats_only_an_explicit_non_success_as_failure():
    assert engine._entry_succeeded({"outcome": "SUCCESS"}) is True
    assert engine._entry_succeeded({"outcome": None}) is True
    assert engine._entry_succeeded({}) is True
    assert engine._entry_succeeded({"outcome": "DEFERRED"}) is False
    assert engine._entry_succeeded({"outcome": "FAILURE"}) is False


# ---------------------------------------------------------------------------
# audit_store: migration 005, count_events_by_resource, the fallback
# ---------------------------------------------------------------------------
def test_migration_005_creates_the_report_indexes(schema):
    conn = audit_store._get_connection()
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events'")}
    assert {"idx_events_env_resource_type_published", "idx_events_env_type_resource_outcome"} <= names
    assert audit_store._schema_version(conn) >= 5


def test_query_events_can_match_resource_id_alone(schema):
    _ingest(ENV, [_rotation("r1", SAAS_LIVE, _ts(1))])
    both = audit_store.query_events(ENV, resource_id=SAAS_LIVE)
    only = audit_store.query_events(ENV, resource_id=SAAS_LIVE, match_alternate_id=False)
    assert [r["uuid"] for r in both] == [r["uuid"] for r in only] == ["r1"]
    assert audit_store.query_events(ENV, resource_id="nope", match_alternate_id=False) == []


def test_count_events_by_resource_groups_per_resource_outcome_and_stored_marker(schema):
    _ingest(ENV, [
        _rotation("r1", SAAS_LIVE, _ts(5), outcome="SUCCESS"),
        _rotation("r2", SAAS_LIVE, _ts(4), outcome="FAILURE", reason="x"),
        _rotation("r3", OKTA_LIVE, _ts(3), sa_type="OKTA_USER_ACCOUNT"),
        _rotation("r4", OKTA_LIVE, _ts(2), sa_type=""),  # empty marker -> not a type_details bucket
        _sa_event("r5", "pam.service_account.password_rotation.start", SAAS_LIVE, _ts(2)),  # wrong type, ignored
    ])
    _ingest(ENV_OTHER, [_rotation("r9", SAAS_LIVE, _ts(1))])
    types = ["pam.service_account.password_rotation.end"]

    out = audit_store.count_events_by_resource(ENV, types)
    assert out[SAAS_LIVE] == {"total": 2, "by_outcome": {"SUCCESS": 1, "FAILURE": 1}, "type_details": {"APP_ACCOUNT": 2},
                              "first_at": _ts(5), "last_at": _ts(4)}
    assert out[OKTA_LIVE]["total"] == 2
    assert out[OKTA_LIVE]["type_details"] == {"OKTA_USER_ACCOUNT": 1}
    assert audit_store.count_events_by_resource(ENV, []) == {}


def test_service_account_family_is_stored_as_resource_type_detail_at_ingest(schema):
    _ingest(ENV, [
        _sa_event("e1", "pam.service_account.password.reveal", SAAS_LIVE, _ts(2)),
        _sa_event("e2", "pam.service_account.update", OKTA_LIVE, _ts(1), sa_type=""),  # empty -> stays NULL
    ])
    rows = {r["uuid"]: r for r in audit_store.query_events(ENV)}
    assert rows["e1"]["resource_type_detail"] == "APP_ACCOUNT"
    assert rows["e2"]["resource_type_detail"] is None

    report = audit_store.run_report("pam_credential_reveals", ENV)
    assert report["rows"][0]["resource_type_detail"] == "APP_ACCOUNT"
    assert report["rows"][0]["resource_type"] == "Service Account"


def test_rows_ingested_before_the_fallback_existed_get_it_at_read_time(schema):
    """A pre-existing row has resource_id set and resource_type_detail
    NULL, so backfill_resource_columns never revisits it -- _four_field_row
    must apply the same fallback when reading."""
    _insert_legacy_row(ENV, _rotation("old1", OKTA_LIVE, _ts(3), sa_type="OKTA_USER_ACCOUNT"))
    report = audit_store.run_report("credential_rotation", ENV)
    assert report["rows"][0]["resource_type_detail"] == "OKTA_USER_ACCOUNT"
    # The MFA factor branch is shared by the same helper and must still work.
    assert audit_store._resource_type_detail_fallback("user.authentication.auth_via_mfa", {"factor": "OKTA_VERIFY_PUSH"}) == "OKTA_VERIFY_PUSH"
    assert audit_store._resource_type_detail_fallback("pam.secret.reveal", {"serviceAccountType": "APP_ACCOUNT"}) is None
    assert audit_store._resource_type_detail_fallback(None, {}) is None


# ---------------------------------------------------------------------------
# Route: GET /api/service_accounts_report
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server(schema, fake_keyring, tmp_audit_log, monkeypatch):
    """Same shape as tests/test_two_owner_collision.py's live server --
    a real StrictBindHTTPServer on a free loopback port, nginx proxy
    secret set so X-Auth-Sub/X-Auth-Is-Admin are honoured, sessions
    seeded directly (activate_environment needs a live OPA token)."""
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


def _register_environment_row(environment_id, owner):
    """5.42.0: session routes check the session's environment (shared-
    environment permissions), so a seeded session needs a real row."""
    import audit_store
    conn = audit_store._get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO app_environments
           (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url, shared, created_at, updated_at)
           VALUES (?, ?, ?, 'x.example.com', 't', 'k', '', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')""",
        (environment_id, owner, f"env-{environment_id[:8]}"),
    )
    conn.commit()


def _headers(sub="00uOWNERA", admin="false"):
    return {"X-Nginx-Proxy-Secret": "test-proxy-secret", "X-Auth-Sub": sub, "X-Auth-Is-Admin": admin}


def _seed_session(serve, sub, env_id, client=None):
    if env_id is not None:
        _register_environment_row(env_id, None if sub == serve.LOCAL_OWNER_KEY_HEADER else sub)
    with serve._sessions_lock:
        serve._sessions[sub] = {"client": client if client is not None else object(), "okta_client": None,
                                "env_name": "dev", "env_id": env_id}


def test_route_requires_an_active_environment(live_server):
    base_url, serve = live_server
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 409
    assert "No active environment" in resp.json()["error"]
    # A session with a client but no resolved environment id gets the same answer, not "not synced".
    _seed_session(serve, "00uOWNERA", None)
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 409
    assert "No active environment" in resp.json()["error"]


def test_route_refuses_an_environment_without_a_completed_sync(live_server):
    base_url, serve = live_server
    _seed_session(serve, "00uOWNERA", ENV)  # ENV has no sync_state row at all
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 409
    assert resp.json()["reason"] == "not_synced"
    # A sync that started but never completed a chunk is still "not synced".
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, last_sync_status="running")
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 409
    assert resp.json()["reason"] == "not_synced"


def test_route_serves_each_synced_owner_their_own_environment_through_the_real_builder(live_server):
    """Two owners, two synced environments, two different rosters -- the
    real builder runs for both and neither sees the other's accounts
    or archive rows (the session's own client and env_id are what scope
    the report)."""
    base_url, serve = live_server
    _ingest(ENV, [_sa_event("a1", "pam.service_account.create", SAAS_GONE, _ts(2), name="Owner A gone")])
    _ingest(ENV_OTHER, [])
    _seed_session(serve, "00uOWNERA", ENV, client=_one_project_client(saas=[_saas_acct(SAAS_LIVE, name="Owner A live")]))
    _seed_session(serve, "00uOWNERB", ENV_OTHER, client=_one_project_client(okta=[_okta_acct(OKTA_LIVE, name="Owner B live")]))

    a = requests.get(f"{base_url}/api/service_accounts_report?rotation_limit=7", headers=_headers("00uOWNERA"), timeout=5)
    b = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers("00uOWNERB"), timeout=5)
    assert a.status_code == 200 and b.status_code == 200
    assert sorted(r["name"] for r in a.json()["accounts"]) == ["Owner A gone", "Owner A live"]
    assert [r["name"] for r in b.json()["accounts"]] == ["Owner B live"]
    assert b.json()["summary"] == {"total": 1, "saas": 0, "okta": 1, "active": 1, "deleted": 0, "unknown": 0}


def test_route_passes_rotation_limit_through_and_defaults_it(live_server, monkeypatch):
    base_url, serve = live_server
    _ingest(ENV, [])
    _seed_session(serve, "00uOWNERA", ENV)
    seen = {}

    def fake_builder(client, environment_id, rotation_limit):
        seen["env"] = environment_id
        seen["rotation_limit"] = rotation_limit
        return {"accounts": [], "summary": {"total": 0, "saas": 0, "okta": 0, "active": 0, "deleted": 0, "unknown": 0},
                "walked": {"resource_groups": 0, "projects": 0}, "excluded": {"other_account_types": 0, "unclassified": 0},
                "warnings": {"conflicting_family_markers": 0}, "event_total": 0, "truncated": False,
                "since_days": None, "local_retention_enabled": True, "oldest_captured_at": None}

    monkeypatch.setattr(engine, "build_service_accounts_report_from_archive", fake_builder)
    resp = requests.get(f"{base_url}/api/service_accounts_report?rotation_limit=7", headers=_headers(), timeout=5)
    assert resp.status_code == 200 and seen == {"env": ENV, "rotation_limit": 7}
    requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert seen["rotation_limit"] == engine.SERVICE_ACCOUNT_ROTATION_LIMIT_DEFAULT


@pytest.mark.parametrize("bad", ["abc", "0", "999"])
def test_route_rejects_a_bad_rotation_limit_with_400(live_server, bad):
    base_url, serve = live_server
    _ingest(ENV, [])
    _seed_session(serve, "00uOWNERA", ENV)
    resp = requests.get(f"{base_url}/api/service_accounts_report?rotation_limit={bad}", headers=_headers(), timeout=5)
    assert resp.status_code == 400
    assert "rotation_limit" in resp.json()["error"]


def test_route_is_behind_the_hosted_mode_nginx_gate(live_server, monkeypatch):
    """SRV-01's guard applies here exactly as to every other data route:
    in hosted mode a request that didn't transit nginx is 401, never
    downgraded to the local owner."""
    base_url, serve = live_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    _ingest(ENV, [])
    _seed_session(serve, serve.LOCAL_OWNER_KEY_HEADER, ENV)
    resp = requests.get(f"{base_url}/api/service_accounts_report", timeout=5)  # no proxy secret at all
    assert resp.status_code == 401
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers={"X-Nginx-Proxy-Secret": "wrong"}, timeout=5)
    assert resp.status_code == 401


def test_route_maps_an_upstream_opa_failure_to_502(live_server, monkeypatch):
    base_url, serve = live_server
    _ingest(ENV, [])
    _seed_session(serve, "00uOWNERA", ENV)

    def failing_builder(client, environment_id, rotation_limit):
        raise engine.OpaApiError(503, "GET /example", "upstream unavailable")

    monkeypatch.setattr(engine, "build_service_accounts_report_from_archive", failing_builder)
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 502


def test_route_reports_a_corrupt_archive_row_as_500_not_400(live_server):
    """json.JSONDecodeError subclasses ValueError, which the shared handler
    maps to 400 -- a corrupt stored row is a server-side problem."""
    base_url, serve = live_server
    _ingest(ENV, [])
    conn = audit_store._get_connection()
    conn.execute(
        """INSERT INTO events (uuid, environment_id, event_type, published, actor_id, actor_display_name,
           actor_alternate_id, outcome_result, is_curated, raw_json, resource_id, resource_alternate_id, resource_type_detail)
           VALUES ('bad1', ?, 'pam.service_account.create', ?, 'a', 'A', 'a@example.com', 'SUCCESS', 1, '{not json', ?, ?, NULL)""",
        (ENV, _ts(1), SAAS_GONE, SAAS_GONE),
    )
    conn.commit()
    _seed_session(serve, "00uOWNERA", ENV, client=_one_project_client())
    resp = requests.get(f"{base_url}/api/service_accounts_report", headers=_headers(), timeout=5)
    assert resp.status_code == 500
    assert "could not be parsed" in resp.json()["error"]
