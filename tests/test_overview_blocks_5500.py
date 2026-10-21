"""5.50.0 Overview blocks: sources, tiles, the state paragraph, trends, evidence readiness, effective OPA access, people lists."""
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import inventory_counts as inv
import okta_admins as oa
import overview_extras as ox
import signin_mfa as sm
from test_okta_admins_5500 import FakeOkta, REFUSED, StatusOkta, _model
from test_okta_routes_5500 import _audit_actions, _put_model
from test_http_authz_matrix import ADMIN, OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server  # noqa: F401
import create_secret_folders as engine

ENV = "88888888-8888-8888-8888-888888888888"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _model_with_policy():
    m = _model()
    m["policies"] = [{"id": "p1", "name": "Servers", "active": True, "principals": {"user_groups": [{"id": "g-users"}], "workload_roles": []},
                      "rules": [{"resolutions": [{"kind": "resolved", "id": "s1"}, {"kind": "resolved", "id": "00uSVC"}]}]},
                     {"id": "p2", "name": "Off", "active": False, "principals": {"user_groups": [{"id": "g-admins"}]}, "rules": [{"resolutions": [{"kind": "resolved", "id": "s2"}]}]},
                     {"id": "p3", "name": "Empty", "active": True, "principals": {"user_groups": [{"id": "g-admins"}]}, "rules": [{"resolutions": [{"kind": "condition"}]}]}]
    return m


def test_effective_access_needs_an_active_policy_with_a_resolved_resource():
    users, ud = oa.effective_access(_model_with_policy())
    assert set(users) == {"ou2"} and users["ou2"] == {"groups": 1, "policies": 1, "resources": 2}  # ou1 only reaches an inactive / empty policy
    assert ud == {"00uSVC": {"policies": 1}}
    assert oa.effective_access(None) is None and oa.effective_access({"policies": "x"}) is None
    oa.effective_access({"policies": [None, {"active": True, "principals": "x", "rules": [None, {"resolutions": "x"}]}], "users": [None, {"id": "u"}], "okta_accounts": [None]})


def test_c1_counts_only_people_whose_access_still_resolves(db):
    cap = oa.capture_principal_status(StatusOkta({"alex@example.com": "DEPROVISIONED", "sam@example.com": "SUSPENDED", "00uSVC": "DEPROVISIONED"}), _model_with_policy())
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"], meta=cap["meta"])
    card = oa.build_cross_checks(ENV, access_model=_model_with_policy())
    assert card["counts"]["inactive_in_okta"] == 3 and card["counts"]["effective_people"] == 1 and card["counts"]["effective_accounts"] == 1
    named = oa.people_list(ENV, "c1", access_model=_model_with_policy())
    assert {p["name"] for p in named["people"]} == {"sam@example.com", "svc-okta"} and all(p["footprint"] for p in named["people"])
    with pytest.raises(ValueError):
        oa.people_list(ENV, "nope")


def test_tiles_and_paragraph_for_a_healthy_environment(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-21T01:00:00.000Z")
    cap = oa.capture_principal_status(StatusOkta({"alex@example.com": "ACTIVE", "sam@example.com": "ACTIVE", "00uSVC": "ACTIVE"}), _model_with_policy())
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"], captured_at="2026-10-21T01:05:00.000Z")
    o = oa.build_overview(ENV, access_model=_model_with_policy(), now=NOW, okta_host="example.okta.com", model_time="2026-10-21T01:10:00.000Z")
    t = o["tiles"]
    assert t["okta_people"] == 2 and t["okta_by_role"]["SUPER_ADMIN"] == 1 and t["opa_privileged"] == 1 and t["opa_by_role"] == {"pam_admin": 1}
    assert t["both"] == 1 and t["left_okta"]["people"] == 0 and t["service"] == {"saas": 0, "okta_ud": 1, "service_users": 1, "total": 1}
    p = o["paragraph"]
    assert "2 people hold an Okta admin role in example.okta.com (1 of them Super Administrator)" in p and "1 holds a privileged OPA role" in p
    assert "1 person holds both" in p and "Nobody who has left Okta" in p and "1 service accounts" in p
    assert o["sources"]["opa_model"]["refreshed_at"] == "2026-10-21T01:10:00.000Z" and o["sources"]["okta_snapshot"]["index"] == 1


def test_paragraph_says_when_sources_are_unavailable(db):
    oa.capture_and_store(ENV, FakeOkta(fail={"assignees": REFUSED}), captured_at="2026-10-21T01:00:00.000Z")
    o = oa.build_overview(ENV, now=NOW)
    p = o["paragraph"]
    assert "cannot read admin role assignments" in p and "No OPA scan is stored yet" in p and "has not been looked up" in p
    assert "Nobody holds both" not in p and o["tiles"]["opa_privileged"] is None and o["tiles"]["both"] is None
    assert oa.build_overview(ENV, now=NOW)["cross_checks"][1]["result"]["state"] == "refused"


def test_attention_names_a_failing_sync_and_a_stale_snapshot(db):
    conn = audit_store._get_connection()
    audit_store._upsert_sync_state(conn, ENV, last_sync_completed_at="2026-10-18T02:14:00.000Z", last_sync_status="error",
                                   last_sync_error="rate limited (HTTP 429)", ingestion_scope="all", last_synced_at="2026-10-18T02:14:00.000Z")
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-18T02:14:00.000Z")
    o = oa.build_overview(ENV, now=NOW)
    kinds = {a["kind"]: a["text"] for a in o["attention"]}
    assert "3 days" in kinds["sync"] and "rate limited" in kinds["sync"] and "still inside Okta's 90-day window" in kinds["sync"] and "3 days old" in kinds["snapshot"]
    assert "last synced 3 day(s) ago" in o["paragraph"] or "has not succeeded for 3 day(s)" in o["paragraph"]


def test_trends_admin_holders_privilege_events_and_requests(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-14T01:00:00.000Z")
    oa.capture_and_store(ENV, FakeOkta(users=["00u1"]), captured_at="2026-10-15T01:00:00.000Z")
    for i, (typ, day) in enumerate([("user.account.privilege.grant", "2026-10-13"), ("user.account.privilege.revoke", "2026-10-14"),
                                    ("access.request.create", "2026-10-15"), ("access.request.resolve", "2026-10-15"), ("access.request.expire", "2026-10-02")]):
        ev = {"uuid": f"t{i}", "eventType": typ, "published": day + "T10:00:00.000Z", "actor": {}, "outcome": {"result": "SUCCESS"}, "target": []}
        audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event(ev)], "all")
    t = oa.build_overview(ENV, access_model=_model(), now=NOW)["trends"]
    assert [p["count"] for p in t["admin_holders"]["okta"]] == [2, 1]
    week = next(w for w in t["privilege_events"] if w["week"] == "2026-10-12")
    assert week["granted"] == 1 and week["revoked"] == 1 and len(t["privilege_events"]) == 13
    assert next(w for w in t["access_requests"] if w["week"] == "2026-10-12")["created"] == 1


def test_evidence_readiness_groups_reports_by_control(db):
    rows = ox.evidence_readiness(NOW, {"newest": "2026-10-21T02:14:00.000Z"}, "2026-10-20T01:00:00.000Z")
    names = [r["group"] for r in rows]
    assert names[:3] == ["CC6 Access controls", "CC7 System operations", "CC8 Change management"] and "Okta Admins" in names
    assert rows[0]["current_through"] == "2026-10-21T02:14:00.000Z" and "MFA Enforcement" in rows[0]["reports"]


def test_inventory_includes_privileged_opa_users(db):
    assert inv.opa_counts(_model_with_policy())["opa.privileged_users"] == 1


def test_people_endpoint_is_admin_only_and_audited(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    _put_model(serve, env_id, _model_with_policy())
    oa.capture_and_store(env_id, FakeOkta())
    url = "/api/overview/people?environment=dev&list="
    assert _call(base_url, "GET", url + "c5", headers=_who(OWNER_A)).status_code == 403
    r = _call(base_url, "GET", url + "c5", headers=_who(ADMIN, admin=True))
    assert r.status_code == 200 and r.json()["people"][0]["login"] == "alex@example.com"
    assert _call(base_url, "GET", url + "bogus", headers=_who(ADMIN, admin=True)).status_code == 400
    assert _call(base_url, "GET", url + "c1", headers=_who(ADMIN, admin=True)).json()["state"] == "never_run"
    assert _audit_actions(tmp_audit_log).count("overview.people_read") == 2


def test_people_counts_and_lists_for_the_privileged_cohort(db):
    t = "2026-10-20T10:00:00.000Z"
    evs = [("a1", "00u1", "alex@example.com", "SIGNED_NONCE"), ("a2", "00u1", "alex@example.com", "OKTA_VERIFY_PUSH"), ("b1", "00u2", "sam@example.com", "SMS_FACTOR"),
           ("c1", "00uZ", "z@example.com", "SMS_FACTOR"), ("c2", "00uY", "y@example.com", "SIGNED_NONCE")]
    for i, (u, actor, alt, factor) in enumerate(evs):
        ev = {"uuid": u, "eventType": "user.authentication.auth_via_mfa", "published": t, "actor": {"id": actor, "alternateId": alt}, "outcome": {"result": "SUCCESS"},
              "debugContext": {"debugData": {"factor": factor}}, "target": []}
        audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event(ev)], "all")
    sm.refresh(ENV)
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-21T01:00:00.000Z")
    o = oa.build_overview(ENV, access_model=_model(), now=NOW)
    p = o["signins_mfa"]["people"]
    assert p["everyone_sms_voice_30d"] == 2 and p["privileged_sms_voice_30d"] == 1 and p["privileged_non_pr"] == 2
    assert p["privileged_by_class"]["fastpass"] == 1 and p["privileged_by_class"]["sms"] == 1 and p["privileged_total"] == 2
    nonpr = oa.people_list(ENV, "mfa_nonpr", access_model=_model())
    assert {x["login"] for x in nonpr["people"]} == {"alex@example.com", "sam@example.com"}
    sms = oa.people_list(ENV, "mfa_smsvoice", access_model=_model())
    assert [x["login"] for x in sms["people"]] == ["sam@example.com"]


def test_mfa_people_lists_honour_as_of(db):
    ev = {"uuid": "a1", "eventType": "user.authentication.auth_via_mfa", "published": "2026-09-01T10:00:00.000Z", "actor": {"id": "00u1", "alternateId": "alex@example.com"},
          "outcome": {"result": "SUCCESS"}, "debugContext": {"debugData": {"factor": "SMS_FACTOR"}}, "target": []}
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event(ev)], "all")
    sm.refresh(ENV)
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-09-02T00:00:00.000Z")
    # as of 5 Sep the SMS sign-in of 1 Sep is inside the last five weeks; read today it is long past
    then = oa.people_list(ENV, "mfa_smsvoice", access_model=_model(), as_of="2026-09-05")
    assert [p["login"] for p in then["people"]] == ["alex@example.com"]
    assert oa.people_list(ENV, "mfa_smsvoice", access_model=_model())["people"] == []
    assert [p["login"] for p in oa.people_list(ENV, "mfa_nonpr", access_model=_model(), as_of="2026-09-05")["people"]] == ["alex@example.com"]
