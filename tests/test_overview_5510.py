"""5.51.0 Overview additions: the stored-scan block of the sources strip, the schedule and last-refresh view, and the banner
sentences (a failing sync by how long ago the last success was, a scheduled refresh that did not read OPA)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import okta_admins as oa
from test_http_authz_matrix import ADMIN, OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server  # noqa: F401,E402
import create_secret_folders as engine
from test_okta_admins_5500 import FakeOkta, _model
from test_okta_routes_5500 import _audit_actions, _put_model

ENV = "99999999-9999-9999-9999-999999999999"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _sync_failed(days_ago, error="rate limited (HTTP 429)"):
    stamp = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, last_sync_completed_at=stamp, last_synced_at=stamp,
                                   last_sync_status="error", last_sync_error=error, ingestion_scope="all")


@pytest.mark.parametrize("days,needle,absent", [
    (3, "still inside Okta's 90-day window", "no longer available"),
    (79, "still inside Okta's 90-day window", "leave Okta's"),
    (82, "leave Okta's 90-day window in 8 days", "still inside"),
    (89, "leave Okta's 90-day window in 1 day.", "still inside"),
    (95, "are no longer available from Okta; the archive has a gap there", "still inside"),
])
def test_the_sync_banner_depends_on_how_long_ago_the_last_success_was(db, days, needle, absent):
    _sync_failed(days)
    text = next(a["text"] for a in oa.build_overview(ENV, now=NOW)["attention"] if a["kind"] == "sync")
    assert needle in text and absent not in text and "Refresh" in text


def test_the_gap_message_names_the_dates_and_the_one_pager_keeps_the_plain_sentence(db):
    _sync_failed(95)
    o = oa.build_overview(ENV, now=NOW)
    text = next(a["text"] for a in o["attention"] if a["kind"] == "sync")
    assert "Events from 18 Jul 2026 to 23 Jul 2026" in text
    assert "Select" not in o["paragraph"] and "has not succeeded for 95 day(s)" in o["paragraph"]  # no button names in a leadership PDF


def test_no_scan_stored_yet_is_a_plain_none_with_a_schedule(db):
    o = oa.build_overview(ENV, now=NOW, schedule={"enabled": True, "run_time": "03:30"})
    block = o["sources"]["opa_model"]
    assert block["source"] == "none" and block["built_at"] is None and block["stale"] is False and block["loaded"] is False
    assert o["sources"]["refresh"]["schedule"] == {"enabled": True, "run_time": "03:30"}


def test_the_stored_scan_block_carries_time_age_source_counts_and_outcome(db):
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, last_refresh_json=json.dumps({"scheduled": {
        "finished_at": "2026-10-21T02:20:00.000Z", "trigger": "scheduled", "parts": {"opa": {"state": "ok", "message": "x"}}}}))
    scan = {"built_at": "2026-10-20T02:20:00.000Z", "age_seconds": 100000, "source": "cache", "stale": True, "very_stale": False,
            "counts": {"users": 3}, "warnings_count": 2, "modified_at": None}
    block = oa.build_overview(ENV, now=NOW, scan=scan)["sources"]["opa_model"]
    assert block["source"] == "cache" and block["stale"] is True and block["counts"] == {"users": 3} and block["warnings_count"] == 2
    assert block["last_scan_outcome"] == "ok" and block["built_at"] == "2026-10-20T02:20:00.000Z"


def test_a_scheduled_refresh_that_did_not_read_opa_is_in_the_banner(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-21T02:14:00.000Z")
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, last_refresh_json=json.dumps({"scheduled": {
        "finished_at": "2026-10-21T02:20:00.000Z", "trigger": "scheduled",
        "parts": {"opa": {"state": "refused", "message": "OPA refused the service key for projects (HTTP 403)."}, "log": {"state": "ok"}}}}))
    kinds = {a["kind"]: a["text"] for a in oa.build_overview(ENV, now=NOW)["attention"]}
    assert "did not read OPA" in kinds["scheduled_opa"] and "HTTP 403" in kinds["scheduled_opa"]
    audit_store._upsert_sync_state(audit_store._get_connection(), ENV, last_refresh_json=json.dumps({"scheduled": {
        "finished_at": "2026-10-21T02:20:00.000Z", "parts": {"opa": {"state": "ok"}}}}))
    assert "scheduled_opa" not in {a["kind"] for a in oa.build_overview(ENV, now=NOW)["attention"]}


# -- Overview counts for archive viewers (never names) ------------------------------------------------------------------
def _viewer_rows(path):
    import json as _json
    return [_json.loads(line) for line in open(path, encoding="utf-8") if line.strip() and '"overview.read"' in line]


def test_an_archive_viewer_gets_the_counts_and_never_a_name_or_a_list(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    _put_model(serve, env_id, _model())
    oa.capture_and_store(env_id, FakeOkta())
    engine.set_shared_permissions({"view_archive": "allow", "live_read": "allow"}, environment_id=env_id)
    r = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(OWNER_B))
    assert r.status_code == 200 and "alex@example.com" not in r.text and "sam@example.com" not in r.text
    body = r.json()
    assert "people" not in body and "privileged" not in body and body["okta_admins"]["count"] == 2
    for lists in ("/api/overview/people?environment=dev&list=c1", "/api/overview/privileged?environment=dev"):
        assert _call(base_url, "GET", lists, headers=_who(OWNER_B)).status_code == 403
    assert _call(base_url, "GET", f"/api/overview?id={env_id}", headers=_who(OWNER_B)).status_code == 403  # ?id= addressing stays admin-only
    viewers = [row["details"]["viewer"] for row in _viewer_rows(tmp_audit_log)]
    assert viewers == ["archive_viewer"]
    assert _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(ADMIN, admin=True)).status_code == 200
    assert [row["details"]["viewer"] for row in _viewer_rows(tmp_audit_log)] == ["archive_viewer", "admin"]


@pytest.mark.parametrize("deny", ["view_archive", "live_read"])
def test_without_either_capability_the_counts_are_refused(matrix_server, deny):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_shared_permissions({"view_archive": "allow", "live_read": "allow", deny: "deny"}, environment_id=env_id)
    r = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(OWNER_B))
    assert r.status_code == 403 and r.json()["capability"] == deny


def test_an_environment_the_caller_cannot_see_is_not_found_not_forbidden(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)  # private to A
    assert _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(OWNER_B)).status_code == 404
