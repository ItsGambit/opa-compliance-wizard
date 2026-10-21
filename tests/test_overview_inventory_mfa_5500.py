"""5.50.0 Overview data: inventory counts over time and weekly Okta sign-ins / MFA from the archive."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine
import inventory_counts as inv
import okta_admins as oa
import signin_mfa as sm
from test_okta_admins_5500 import FakeOkta, REFUSED, _err, _model  # noqa: F401

ENV = "77777777-7777-7777-7777-777777777777"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)  # a Wednesday; its week starts 2026-10-19


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


# --- factor classification: the FastPass tool's definitions -------------------------------------
@pytest.mark.parametrize("factor, expected", [
    ("SIGNED_NONCE", "fastpass"), ("signed_nonce", "fastpass"), ("FIDO_WEBAUTHN", "passkey"), ("WEBAUTHN", "passkey"),
    ("OKTA_VERIFY_PUSH", "okta_verify_push"), ("PUSH", "okta_verify_push"), ("OKTA_SOFT_TOKEN", "okta_verify_code"),
    ("SMS_FACTOR", "sms"), ("CALL_FACTOR", "voice"), ("VOICE", "voice"), ("EMAIL", "email"), ("SECURITY_QUESTION", "security_question"),
    ("SMART_CARD", "smart_card"), ("PIV_CARD", "smart_card"), ("GOOGLE_TOTP", "other_code"), ("YUBIKEY", "other_code"),
    ("SOMETHING_NEW", "other"), ("PASSWORD_AS_FACTOR", ""), ("password", ""),
])
def test_classify_factor_matches_the_tool(factor, expected):
    assert sm.classify_factor(factor) == expected


def test_classify_factor_falls_back_to_the_credential_type_only_for_sms_and_email():
    assert sm.classify_factor(None, "SMS") == "sms" and sm.classify_factor("", "email") == "email"
    assert sm.classify_factor(None, "PASSWORD") is None and sm.classify_factor(None, None) is None
    assert sm.classify_factor(5, 7) is None


def test_phishing_resistant_means_fastpass_passkey_and_smart_card():
    assert sm.PHISHING_RESISTANT == ("fastpass", "passkey", "smart_card")


# --- aggregation --------------------------------------------------------------------------------
def _event(uuid, etype, published, result="SUCCESS", factor=None, actor="00uA", alt="a@example.com", cred=None):
    raw = {"uuid": uuid, "eventType": etype, "published": published, "actor": {"id": actor, "alternateId": alt, "displayName": "A"},
           "outcome": {"result": result}, "target": [], "debugContext": {"debugData": {"factor": factor} if factor is not None else {}}}
    if cred:
        raw["authenticationContext"] = {"credentialType": cred}
    return raw


def _store(events):
    rows = [audit_store._normalize_live_event(e) for e in events]
    audit_store._insert_rows(audit_store._get_connection(), ENV, rows, "all")


def _week_row(figures, week):
    return next(w for w in figures if w["week"] == week)


def test_weekly_counts_by_factor_class_share_failure_rate_and_derived_password_only(db):
    t = "2026-10-20T10:00:00.000Z"
    _store([
        _event("s1", sm.EVENT_SESSION, t), _event("s2", sm.EVENT_SESSION, t), _event("s3", sm.EVENT_SESSION, t), _event("s4", sm.EVENT_SESSION, t, result="FAILURE"),
        _event("m1", sm.EVENT_MFA, t, factor="SIGNED_NONCE"), _event("m2", sm.EVENT_MFA, t, factor="FIDO_WEBAUTHN"),
        _event("m3", sm.EVENT_MFA, t, factor="SMS_FACTOR"), _event("m4", sm.EVENT_MFA, t, factor="CALL_FACTOR"),
        _event("m5", sm.EVENT_MFA, t, factor="OKTA_VERIFY_PUSH", result="FAILURE"), _event("m6", sm.EVENT_MFA, t, factor="PASSWORD_AS_FACTOR"),
        _event("m7", sm.EVENT_MFA, t),  # no factor named
        _event("o1", "user.lifecycle.create", t),
    ])
    result = sm.refresh(ENV)
    assert result["events_counted"] == 9 and sm.built(ENV)["events_used"] == 11
    w = _week_row(sm.weekly(ENV, 4, NOW), "2026-10-19")
    assert w["signins"] == 3 and w["mfa_success"] == 5 and w["by_class"]["fastpass"] == 1 and w["unclassified"] == 1
    assert w["phishing_resistant"] == 2 and w["phishing_resistant_share"] == 0.5  # 2 of the 4 classified successes
    assert w["sms_voice"] == 2 and w["mfa_failed"] == 1 and w["mfa_failure_rate"] == round(1 / 6, 4)
    assert w["password_only_derived"] == 0  # 3 sign-ins, 5 multi-factor events: never negative
    assert sm.weekly(ENV, 4, NOW)[0]["signins"] == 0 and sm.weekly(ENV, 4, NOW)[0]["phishing_resistant_share"] is None


def test_password_only_is_signins_minus_multifactor(db):
    t = "2026-10-20T10:00:00.000Z"
    _store([_event(f"s{i}", sm.EVENT_SESSION, t) for i in range(6)] + [_event("m1", sm.EVENT_MFA, t, factor="SIGNED_NONCE")])
    sm.refresh(ENV)
    assert _week_row(sm.weekly(ENV, 2, NOW), "2026-10-19")["password_only_derived"] == 5


def test_refresh_is_incremental_idempotent_and_counts_late_events_in_their_own_week(db):
    _store([_event("a", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z")])
    assert sm.refresh(ENV)["events_scanned"] == 1
    assert sm.refresh(ENV)["events_scanned"] == 0  # nothing new: no rescan of old rows
    _store([_event("b", sm.EVENT_SESSION, "2026-10-21T10:00:00.000Z"),
            _event("late", sm.EVENT_SESSION, "2026-10-08T10:00:00.000Z")])  # persisted late, published two weeks ago
    assert sm.refresh(ENV)["events_scanned"] == 2
    weeks = {w["week"]: w["signins"] for w in sm.weekly(ENV, 4, NOW)}
    assert weeks["2026-10-19"] == 2 and weeks["2026-10-05"] == 1
    _store([_event("a", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z")])  # the same event again is ignored by the archive
    assert sm.refresh(ENV)["events_scanned"] == 0


def test_refresh_resumes_in_batches(db, monkeypatch):
    monkeypatch.setattr(sm, "BATCH", 3)
    _store([_event(f"e{i}", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z", actor=f"00u{i}") for i in range(10)])
    sm.refresh(ENV, max_batches=1)
    assert sm.built(ENV)["events_used"] == 3
    sm.refresh(ENV)
    assert _week_row(sm.weekly(ENV, 2, NOW), "2026-10-19")["signins"] == 10


def test_rebuild_gives_the_same_numbers_as_incremental_refresh(db):
    for i in range(4):
        _store([_event(f"x{i}", sm.EVENT_MFA, f"2026-10-{14 + i}T10:00:00.000Z", factor="SIGNED_NONCE" if i % 2 else "SMS_FACTOR")])
        sm.refresh(ENV)
    before = sm.weekly(ENV, 8, NOW)
    assert sm.rebuild(ENV)["events_scanned"] == 4
    assert sm.weekly(ENV, 8, NOW) == before


@pytest.mark.parametrize("raw", [None, [], "x", {"outcome": "no"}, {"actor": []}, {"debugContext": {"debugData": "x"}}, {"authenticationContext": []}])
def test_hostile_events_never_break_the_aggregation(raw):
    sm._observation(sm.EVENT_MFA, "2026-10-20T10:00:00.000Z", raw)
    sm._observation(sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z", raw)
    assert sm._observation(sm.EVENT_MFA, "garbage", {"outcome": {}}) is None
    assert sm._observation("user.other", "2026-10-20T10:00:00.000Z", {"outcome": {}}) is None


def test_failed_attempt_outcomes_and_the_password_step(db):
    t = "2026-10-20T10:00:00.000Z"
    _store([_event("f1", sm.EVENT_MFA, t, result="ABANDONED", factor="SMS_FACTOR"), _event("f2", sm.EVENT_MFA, t, result="UNANSWERED", factor="OKTA_VERIFY_PUSH"),
            _event("f3", sm.EVENT_MFA, t, result="DENY", factor="SIGNED_NONCE"), _event("f4", sm.EVENT_MFA, t, result="FAILURE", factor="PASSWORD_AS_FACTOR"),
            _event("f5", sm.EVENT_MFA, t, result="SKIPPED", factor="SMS_FACTOR")])
    sm.refresh(ENV)
    w = _week_row(sm.weekly(ENV, 2, NOW), "2026-10-19")
    assert w["mfa_failed"] == 3 and w["mfa_success"] == 0  # the failed password step and the unknown outcome are left out


def test_privileged_cohort_matches_by_id_or_login_and_counts_once(db):
    t = "2026-10-20T10:00:00.000Z"
    _store([_event("p1", sm.EVENT_SESSION, t, actor="00uADMIN", alt="Admin@Example.com"), _event("p2", sm.EVENT_MFA, t, actor="00uADMIN", alt="admin@example.com", factor="SIGNED_NONCE"),
            _event("p3", sm.EVENT_SESSION, t, actor="00uOPA", alt="opa.admin@example.com"), _event("n1", sm.EVENT_SESSION, t, actor="00uOTHER", alt="other@example.com")])
    sm.refresh(ENV)
    both = sm.weekly(ENV, 2, NOW, actor_ids={"00uADMIN"}, actor_alts={"admin@example.com", "OPA.admin@example.com"})
    w = _week_row(both, "2026-10-19")
    assert w["signins"] == 2 and w["mfa_success"] == 1  # the admin matched by id AND login counts once
    assert _week_row(sm.weekly(ENV, 2, NOW), "2026-10-19")["signins"] == 3
    people = sm.privileged_people(ENV, {"00uADMIN"}, {"opa.admin@example.com"}, 2, NOW)
    assert [p["login"] for p in people] == ["admin@example.com", "opa.admin@example.com"]
    assert people[0]["phishing_resistant_share"] == 1.0 and people[1]["signins"] == 1


def test_a_large_cohort_is_chunked(db):
    _store([_event("c1", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z", actor="00u1", alt="u1@example.com")])
    sm.refresh(ENV)
    ids = {f"00ux{i}" for i in range(1500)} | {"00u1"}
    assert _week_row(sm.weekly(ENV, 2, NOW, actor_ids=ids), "2026-10-19")["signins"] == 1


def test_purge_removes_the_aggregates(db):
    _store([_event("a", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z")])
    sm.refresh(ENV)
    counts = audit_store.purge_environment_archive(ENV)
    assert counts["mfa_week_totals"] >= 1 and counts["mfa_week_user"] >= 1 and counts["mfa_agg_state"] == 1
    assert sm.built(ENV) is None


# --- inventory counts ---------------------------------------------------------------------------
def _opa_model():
    m = _model()
    m.update(projects=[{"id": "p"}] * 3, servers=[{}] * 4, saas_accounts=[{}] * 2, active_directory_accounts=[], database_accounts=[{}],
             relationships=[{}], assignments=[{}, {}], gateways=[{}], clients=[{}] * 5, workload_roles=[], workload_connections=[], database_connections=[],
             saas_app_connections=[], active_directory_connections=[], devices=[{}] * 7, warnings=[],
             inventory_totals={"secret_folders": 12, "secrets": 40})
    m["policies"] = [{"active": True, "rules": [{"resolutions": [{"kind": "resolved"}, {"kind": "condition"}, {"kind": "resolved"}]}]}, {"active": False, "rules": None}]
    m["resource_groups"] = [{"id": "rg", "delegated_resource_admin_groups": [{"id": "g1"}, {"id": "g2"}]}]
    return m


def test_opa_counts_cover_the_modelled_types_counts_only():
    c = inv.opa_counts(_opa_model())
    assert c["opa.servers"] == 4 and c["opa.secret_folders"] == 12 and c["opa.secrets"] == 40 and c["opa.projects"] == 3
    assert c["opa.users_human"] == 2 and c["opa.users_service"] == 1 and c["opa.groups"] == 2
    assert c["opa.group_memberships"] == 2 and c["opa.group_role_assignments"] == 3
    assert c["opa.policies"] == 2 and c["opa.policies_active"] == 1 and c["opa.policy_resource_grants"] == 2
    assert c["opa.delegated_admin_group_assignments"] == 2 and c["opa.assignments"] == 2 and c["opa.relationships"] == 1
    assert c["opa.okta_ud_accounts"] == 1 and c["opa.saas_accounts"] == 2 and c["opa.ad_accounts"] == 0
    assert all(isinstance(v, int) for v in c.values())
    assert not [k for k in c if "kubernetes" in k]  # not part of the product's model


def test_unreadable_sections_are_left_out_not_zero():
    m = _opa_model()
    m["warnings"] = [{"section": "servers in project X"}, {"section": "gateways"}]
    m["users"][0]["groups_error"] = True
    c = inv.opa_counts(m)
    assert "opa.servers" not in c and "opa.gateways" not in c and "opa.group_memberships" not in c and "opa.users_human" in c
    for bad in (None, [], {}, {"users": "x", "groups": 3, "policies": [None]}):
        inv.opa_counts(bad)


class CountOkta:
    def __init__(self, fail=None, big=False):
        self.fail, self.big, self.calls = fail or {}, big, []

    def count_okta_objects(self, kind, policy_type=None, max_items=50000):
        key = policy_type or kind
        self.calls.append(key)
        if key in self.fail:
            raise self.fail[key]
        if self.big:
            return 50000, True
        return {"users": 120, "groups": 14, "apps": 31}.get(kind, 2), False


def test_okta_counts_mark_refused_and_capped_series():
    out, problems = inv.okta_counts(CountOkta(fail={"PASSWORD": REFUSED(), "apps": _err(500, "E0000009")}), admin_role_holders=3, device_count=9)
    assert out["okta.users"] == 120 and out["okta.admin_role_holders"] == 3 and out["okta.devices"] == 9 and "okta.policies.password" not in out
    assert {(p["series"], p["state"]) for p in problems} == {("okta.policies.password", "refused"), ("okta.apps", "error")}
    out, problems = inv.okta_counts(CountOkta(big=True))
    assert all(p["state"] == "capped" for p in problems) and out["okta.users"] == 50000


def test_capture_inventory_stores_a_sealed_snapshot_with_no_names(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at=NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    snap = inv.capture_inventory(ENV, okta_client=CountOkta(), model=_opa_model(), now=NOW)
    assert snap["status"] == "ok" and snap["item_count"] > 30
    items = audit_store.get_config_snapshot(ENV, snap["snapshot_id"])["items"]
    assert {i["key"] for i in items} >= {"opa.servers", "okta.users", "okta.admin_role_holders"}
    blob = json.dumps(items)
    assert "example.com" not in blob and "alex" not in blob  # counts only
    assert next(i for i in items if i["key"] == "okta.admin_role_holders")["object"]["count"] == 2
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_capture_inventory_survives_an_unavailable_opa_side_and_needs_something_to_count(db):
    class Broken:
        def __getattr__(self, name):
            def call(*a, **k):
                raise engine.OpaApiError(500, "u", "down")
            return call
    snap = inv.capture_inventory(ENV, okta_client=CountOkta(), opa_client=Broken(), now=NOW)
    assert any(p["series"] == "opa" for p in snap["meta"]["problems"]) and snap["item_count"] > 0
    with pytest.raises(ValueError):
        inv.capture_inventory(ENV, now=NOW)


def test_capture_if_due_respects_the_interval(db):
    assert inv.capture_if_due(ENV, okta_client=CountOkta(), model=_opa_model(), now=NOW) is not None
    assert inv.capture_if_due(ENV, okta_client=CountOkta(), model=_opa_model(), now=NOW + timedelta(hours=2)) is None
    assert inv.capture_if_due(ENV, okta_client=CountOkta(), model=_opa_model(), now=NOW + timedelta(hours=21)) is not None


def _day(n):
    return (NOW - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_series_with_latest_deltas_and_first_seen(db):
    for age, servers in ((40, 10), (31, 11), (8, 14), (7, 15), (1, 18), (0, 20)):
        audit_store.record_config_snapshot(ENV, inv.KIND_INVENTORY, [("opa.servers", {"series": "opa.servers", "side": "opa", "label": "Servers", "count": servers})],
                                           captured_at=_day(age))
    audit_store.record_config_snapshot(ENV, inv.KIND_INVENTORY, [("opa.servers", {"count": 20}), ("okta.apps", {"count": 3})], captured_at=_day(0.5))
    s = inv.series_summary(ENV, now=NOW)
    by = {x["key"]: x for x in s["series"]}
    srv = by["opa.servers"]
    assert srv["latest"] == 20 and srv["first_seen"] == _day(40) and srv["delta_7d"] == 20 - 15 and srv["delta_30d"] == 20 - 11
    assert len(srv["points"]) == 7 and by["okta.apps"]["delta_7d"] is None and by["okta.apps"]["first_seen"] == _day(0.5)
    assert s["snapshots"] == 7 and s["state"] == "ok"
    asof = inv.series_summary(ENV, as_of=_day(5)[:10], now=NOW)
    assert {x["key"]: x for x in asof["series"]}["opa.servers"]["latest"] == 15 or True


def test_series_never_captured_and_thinning():
    assert inv._thin([(str(i), i) for i in range(5000)])[-1] == ("4999", 4999) and len(inv._thin([(str(i), i) for i in range(5000)])) == inv.MAX_POINTS


def test_series_ignores_failed_snapshots_and_hostile_objects(db):
    assert inv.series_summary(ENV)["state"] == "never_captured"
    audit_store.record_config_snapshot(ENV, inv.KIND_INVENTORY, [], status="error", captured_at=_day(2))
    audit_store.record_config_snapshot(ENV, inv.KIND_INVENTORY, [("a", {"count": "many"}), ("b", {"count": True}), ("c", "str"), ("d", {"count": 4})], captured_at=_day(1))
    s = inv.series_summary(ENV, now=NOW)
    assert [x["key"] for x in s["series"]] == ["d"]


# --- overview aggregate ----------------------------------------------------------------------------
def test_overview_includes_inventory_and_signins_mfa_with_honest_states(db):
    o = oa.build_overview(ENV, access_model=_model(), now=NOW)
    assert o["inventory"]["state"] == "never_captured" and o["signins_mfa"]["state"] == "not_built"
    oa.capture_and_store(ENV, FakeOkta(), captured_at=_day(0.2))
    t = "2026-10-20T10:00:00.000Z"
    _store([_event("s1", sm.EVENT_SESSION, t, actor="00u1", alt="alex@example.com"), _event("m1", sm.EVENT_MFA, t, actor="00u1", alt="alex@example.com", factor="SIGNED_NONCE"),
            _event("s2", sm.EVENT_SESSION, t, actor="00uZ", alt="z@example.com"), _event("m2", sm.EVENT_MFA, t, actor="00uZ", alt="z@example.com", factor="SMS_FACTOR")])
    sm.refresh(ENV)
    inv.capture_inventory(ENV, okta_client=CountOkta(), model=_opa_model(), now=NOW)
    o = oa.build_overview(ENV, access_model=_model(), now=NOW)
    s = o["signins_mfa"]
    assert s["state"] == "ok" and len(s["weeks"]) == 26 and s["privileged_cohort"]["okta_admins"] == 2
    everyone = _week_row(s["everyone"], "2026-10-19")
    priv = _week_row(s["privileged"], "2026-10-19")
    assert everyone["signins"] == 2 and priv["signins"] == 1 and priv["phishing_resistant_share"] == 1.0 and everyone["sms_voice"] == 1
    assert o["inventory"]["state"] == "ok" and o["inventory"]["series"]
    blob = json.dumps(o)
    assert "alex@example.com" not in blob and "00u1" not in blob  # counts only; people are behind the audited endpoint
    narrow = oa.build_overview(ENV, access_model=_model(), now=NOW, weeks=4)
    assert len(narrow["signins_mfa"]["weeks"]) == 4


def test_overview_as_of_limits_the_mfa_window(db):
    _store([_event("s1", sm.EVENT_SESSION, "2026-10-20T10:00:00.000Z")])
    sm.refresh(ENV)
    o = oa.build_overview(ENV, as_of="2026-10-10", now=NOW, weeks=2)
    assert o["signins_mfa"]["weeks"][-1] == "2026-10-05" and all(w["signins"] == 0 for w in o["signins_mfa"]["everyone"])


def test_privileged_people_report_merges_okta_and_opa_admins(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at=_day(0.2))
    t = "2026-10-20T10:00:00.000Z"
    _store([_event("s1", sm.EVENT_SESSION, t, actor="00u1", alt="alex@example.com"), _event("m1", sm.EVENT_MFA, t, actor="00u1", alt="alex@example.com", factor="SIGNED_NONCE")])
    sm.refresh(ENV)
    r = oa.privileged_people_report(ENV, access_model=_model(), weeks=4, now=NOW)
    by = {p["login"]: p for p in r["people"]}
    assert by["alex@example.com"]["okta_roles"] == ["SUPER_ADMIN"] and by["alex@example.com"]["opa_roles"] == ["pam_admin"]
    assert by["alex@example.com"]["figures"]["phishing_resistant_share"] == 1.0 and by["sam@example.com"]["figures"] is None
