"""5.51.0 Overview additions: the stored-scan block of the sources strip, the schedule and last-refresh view, and the banner
sentences (a failing sync by how long ago the last success was, a scheduled refresh that did not read OPA)."""
import json
import time
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


SENTINELS = ["Zelda Sentinel", "zelda.sentinel@example.com", "Quentin Probe", "quentin.probe@example.com", "Ursula Actor", "ursula.actor@example.com",
             "Ivan Capture", "ivan.capture@example.com", "Mira Listed", "mira.listed@example.com", "svc-sentinel-account", "sentinel-host.example.com"]


def test_the_archive_viewer_body_holds_no_name_or_e_mail_from_any_source_the_overview_reads(matrix_server, tmp_audit_log):  # noqa: F811
    """Names and e-mails are seeded through every source the Overview reads, then the whole body (and the admin one, for contrast) is searched."""
    import server.refresh_jobs as rj
    import signin_mfa
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_shared_permissions({"view_archive": "allow", "live_read": "allow"}, environment_id=env_id)
    # 1. Okta admin-role holders (the snapshot items hold login, e-mail, first and last name)
    fake = FakeOkta(users=["00uS1"], roles={"00uS1": [{"id": "r1", "label": "Super administrator", "type": "SUPER_ADMIN", "status": "ACTIVE", "assignmentType": "USER"}]},
                    profiles={"00uS1": {"id": "00uS1", "status": "ACTIVE", "profile": {"login": SENTINELS[1], "email": SENTINELS[1], "firstName": "Zelda", "lastName": "Sentinel"}}})
    oa.capture_and_store(env_id, fake)
    # 2. grant / revoke event actors and targets, sign-in events (the weekly counts are derived from them)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    events = [{"uuid": f"ev{i}", "eventType": et, "published": now, "displayMessage": SENTINELS[2],
               "actor": {"id": "00uA", "alternateId": SENTINELS[3], "displayName": SENTINELS[2]}, "outcome": {"result": "SUCCESS"},
               "target": [{"id": "00uT", "alternateId": SENTINELS[5], "displayName": SENTINELS[4], "type": "User"}],
               "authenticationContext": {"credentialType": "OTP"}, "debugContext": {"debugData": {"factor": "SIGNED_NONCE"}}}
              for i, et in enumerate(("user.account.privilege.grant", "user.account.privilege.revoke", "user.session.start", "user.authentication.auth_via_mfa"))]
    conn = audit_store._get_connection()
    audit_store._insert_rows(conn, env_id, [audit_store._normalize_live_event(e) for e in events], "all")
    signin_mfa.refresh(env_id)
    # 3. the OPA scan: users (names, e-mails), service accounts, servers, the people lists' source
    model = _model()
    model["users"][0].update(name=SENTINELS[8], details={"email": SENTINELS[9]})
    model["okta_accounts"] = [{"id": "acct1", "okta_user_id": "00uSVC", "name": SENTINELS[10], "project_name": "P"}]
    model["servers"] = [{"id": "s1", "hostname": SENTINELS[11]}]
    _put_model(serve, env_id, model)
    # 4. the Okta status of principals (login, e-mail, name per row), the capture actor and the refresh's starting actor
    snap = audit_store.record_config_snapshot(env_id, "opa_principal_status", [("opa_user:1", {"name": SENTINELS[8], "email": SENTINELS[9], "okta_login": SENTINELS[7], "okta_state": "ACTIVE"})])
    assert snap["item_count"] == 1
    out = serve._start_refresh_job(env_id, "dev", parts=["log"], trigger="manual", owner=OWNER_A, actor_email=SENTINELS[5], actor_sub="00uACTOR",
                                   client_ip="203.0.113.9", user_agent="agent")
    assert out["started"]
    for _ in range(100):
        if not serve._refresh_running(env_id):
            break
        time.sleep(0.05)
    serve._audit_for({"name": "dev", "trigger": "manual", "actor_email": SENTINELS[7], "actor_sub": "00uCAPTURE"}, "okta_snapshot.captured", {"kind": "okta_admins"})
    audit_store._upsert_sync_state(conn, env_id, last_sync_error="rate limited (HTTP 429)", last_sync_status="error", last_sync_completed_at=now)
    # the archive viewer's body: counts and wording only
    viewer = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(OWNER_B))
    assert viewer.status_code == 200
    body = viewer.json()
    assert body["okta_admins"]["count"] == 1  # the seeded sources really fed the figures
    assert [s for s in SENTINELS if s in viewer.text] == []
    admin = _call(base_url, "GET", "/api/overview?environment=dev", headers=_who(ADMIN, admin=True))
    assert admin.status_code == 200 and [s for s in SENTINELS if s in admin.text] == []  # the counts body is the same for an administrator
    # the lists stay behind the admin check
    for lists in ("/api/overview/people?environment=dev&list=c5", "/api/overview/privileged?environment=dev"):
        r = _call(base_url, "GET", lists, headers=_who(OWNER_B))
        assert r.status_code == 403 and not any(s in r.text for s in SENTINELS)


def test_the_sources_name_the_okta_host_and_the_chain_check_time_is_the_overview_time(db):
    o = oa.build_overview(ENV, now=NOW, okta_host="example.okta.com")
    assert o["sources"]["okta_org"]["host"] == "example.okta.com" and o["generated_at"].startswith("2026-10-21T12:00")
