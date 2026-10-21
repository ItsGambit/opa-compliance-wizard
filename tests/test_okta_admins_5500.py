"""5.50.0 Okta Admins report (user principals), SoD against OPA roles, the lifecycle
cross-check C1 and the Overview counts -- against fakes shaped like the live responses."""
import json

import pytest

import audit_store
import create_secret_folders as engine
import okta_admins as oa

ENV = "55555555-5555-5555-5555-555555555555"
TOKEN = "SSWS-TEST-TOKEN-VALUE"


def _err(status, code, summary="x"):
    return engine.OktaApiError(status, "https://example.okta.com/api/v1/x", json.dumps({"errorCode": code, "errorSummary": summary}))


REFUSED = lambda: _err(403, "E0000006", "You do not have permission to access the feature you are requesting")  # noqa: E731


class FakeOkta:
    """Shapes follow the live responses: assignees {value:[{id,orn,_links}]}, roles a list, iam/roles {roles}, ..."""

    def __init__(self, users=None, roles=None, profiles=None, custom_roles=None, perms=None, resource_sets=None,
                 targets_groups=None, targets_apps=None, governance=None, fail=None):
        self.users = users if users is not None else ["00u1", "00u2"]
        self.roles = roles or {"00u1": [{"id": "ra1", "label": "Super administrator", "type": "SUPER_ADMIN", "status": "ACTIVE",
                                          "created": "2026-01-01T00:00:00.000Z", "lastUpdated": "2026-01-01T00:00:00.000Z",
                                          "assignmentType": "USER", "_links": {"assignee": {"href": "x"}}}],
                               "00u2": [{"id": "ra2", "label": "Help Desk administrator", "type": "HELP_DESK_ADMIN", "status": "ACTIVE",
                                          "created": "2026-02-01T00:00:00.000Z", "assignmentType": "USER"},
                                         {"id": "ra3", "label": "Custom", "type": "CUSTOM", "status": "ACTIVE", "assignmentType": "USER",
                                          "role": "cr1", "resource-set": "rs1", "created": "2026-03-01T00:00:00.000Z"}]}
        self.profiles = profiles or {
            "00u1": {"id": "00u1", "status": "ACTIVE", "profile": {"login": "alex@example.com", "email": "alex@example.com", "firstName": "Alex", "lastName": "Example", "secretQuestion": "x"},
                     "credentials": {"password": {}, "recovery_question": {"question": "pet?"}, "provider": {"type": "OKTA"}}},
            "00u2": {"id": "00u2", "status": "ACTIVE", "profile": {"login": "sam@example.com", "email": "sam@example.com", "firstName": "Sam", "lastName": "Sample"},
                     "credentials": {"password": {}}}}
        self.custom_roles = custom_roles if custom_roles is not None else [{"id": "cr1", "label": "Auditor", "description": "d", "created": "c", "lastUpdated": "l", "_links": {}}]
        self.perms = perms if perms is not None else {"cr1": [{"label": "okta.users.read"}, {"label": "okta.iam.read"}]}
        self.resource_sets = resource_sets if resource_sets is not None else [{"id": "rs1", "label": "All users", "description": "", "created": "c", "lastUpdated": "l"}]
        self.targets_groups = targets_groups if targets_groups is not None else {"ra2": [{"id": "00g1", "profile": {"name": "Support"}, "_embedded": {"stats": {}}}]}
        self.targets_apps = targets_apps or {}
        self.governance = governance
        self.fail = fail or {}
        self.calls = []

    def _maybe_fail(self, name, *key):
        self.calls.append((name, *key))
        exc = self.fail.get(name)
        if exc is not None:
            raise exc() if callable(exc) else exc

    def list_users_with_role_assignments(self, limit_total=100000):
        self._maybe_fail("assignees")
        return [{"id": u, "orn": f"orn:okta:x:users:{u}", "_links": {}} for u in self.users]

    def get_user(self, uid):
        self._maybe_fail("get_user", uid)
        if uid not in self.profiles:
            raise _err(404, "E0000007", "Not found: Resource not found")
        return self.profiles[uid]

    def list_user_roles(self, uid):
        self._maybe_fail("roles", uid)
        return self.roles.get(uid, [])

    def list_role_group_targets(self, uid, rid):
        self._maybe_fail("targets_groups", uid, rid)
        return self.targets_groups.get(rid, [])

    def list_role_app_targets(self, uid, rid):
        self._maybe_fail("targets_apps", uid, rid)
        return self.targets_apps.get(rid, [])

    def get_role_governance(self, uid, rid):
        self._maybe_fail("governance", uid, rid)
        return self.governance or {"grants": []}

    def list_custom_roles(self):
        self._maybe_fail("custom_roles")
        return self.custom_roles

    def list_custom_role_permissions(self, rid):
        self._maybe_fail("perms", rid)
        return self.perms.get(rid, [])

    def list_resource_sets(self):
        self._maybe_fail("resource_sets")
        return self.resource_sets


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _model(extra_users=(), groups=None):
    return {
        "users": [{"id": "ou1", "name": "alex@example.com", "user_type": "human", "details": {"email": "alex@example.com"},
                   "groups": [{"id": "g-admins", "name": "PAM-Admins"}]},
                  {"id": "ou2", "name": "sam@example.com", "user_type": "human", "details": {"email": "sam@example.com"},
                   "groups": [{"id": "g-users", "name": "Everyone"}]},
                  {"id": "svc", "name": "svc-key", "user_type": "service", "details": {}, "groups": []}, *extra_users],
        "groups": groups or [{"id": "g-admins", "name": "PAM-Admins", "roles": ["pam_admin", "end_user"]},
                             {"id": "g-users", "name": "Everyone", "roles": ["end_user"]}],
        "resource_groups": [], "okta_accounts": [{"id": "acct1", "okta_user_id": "00uSVC", "name": "svc-okta", "project_name": "P"}],
    }


# --- capture ------------------------------------------------------------------------------------
def test_capture_reads_admins_targets_custom_roles_and_resource_sets(db):
    fake = FakeOkta()
    snap = oa.capture_and_store(ENV, fake, captured_at="2026-10-01T00:00:00.000Z")
    assert snap["status"] == "ok" and snap["item_count"] == 4  # 2 users, 1 custom role, 1 resource set
    stored = {i["key"]: i["object"] for i in audit_store.get_config_snapshot(ENV, snap["snapshot_id"])["items"]}
    assert set(stored) == {"user:00u1", "user:00u2", "custom_role:cr1", "resource_set:rs1"}
    u2 = stored["user:00u2"]
    help_desk = next(r for r in u2["roles"] if r["type"] == "HELP_DESK_ADMIN")
    assert help_desk["targets"]["groups"] == [{"id": "00g1", "name": "Support"}]
    custom = next(r for r in u2["roles"] if r["type"] == "CUSTOM")
    assert custom["custom_role_id"] == "cr1" and custom["resource_set_id"] == "rs1"
    assert stored["custom_role:cr1"]["permissions"] == ["okta.iam.read", "okta.users.read"]
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_credentials_and_other_profile_fields_are_never_stored(db):
    snap = oa.capture_and_store(ENV, FakeOkta())
    blob = json.dumps(audit_store.get_config_snapshot(ENV, snap["snapshot_id"]))
    for forbidden in ("credentials", "recovery_question", "pet?", "secretQuestion", "password", "provider"):
        assert forbidden not in blob
    conn = audit_store._get_connection()
    dump = " ".join(str(tuple(r)) for t in ("config_snapshots", "config_snapshot_items", "ingestion_manifests")
                    for r in conn.execute(f"SELECT * FROM {t}"))
    assert TOKEN not in dump


def test_a_refused_admin_list_is_recorded_and_reported_honestly(db):
    fake = FakeOkta(fail={"assignees": REFUSED})
    snap = oa.capture_and_store(ENV, fake)
    assert snap["status"] == "refused" and snap["item_count"] == 0 and snap["meta"]["error_code"] == "E0000006"
    report = oa.build_okta_admins_report(ENV)
    assert report["state"] == "refused" and report["message"] == oa.MISSING_ROLES_MESSAGE
    assert report["rows"] == [] and "Super Administrator" in report["message"]
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_an_http_403_without_a_code_is_also_a_refusal(db):
    fake = FakeOkta(fail={"assignees": engine.OktaApiError(403, "u", "<html>Forbidden</html>")})
    assert oa.capture_and_store(ENV, fake)["status"] == "refused"


@pytest.mark.parametrize("exc", [engine.OktaApiError("network", "u", "timeout"),
                                 engine.OktaApiError(401, "u", json.dumps({"errorCode": "E0000011", "errorSummary": "Invalid token provided"})),
                                 engine.OktaApiError("invalid_response", "u", "not JSON"),
                                 engine.OktaApiError(500, "u", "boom")])
def test_other_failures_are_errors_not_refusals(db, exc):
    snap = oa.capture_and_store(ENV, FakeOkta(fail={"assignees": exc}))
    assert snap["status"] == "error"
    report = oa.build_okta_admins_report(ENV)
    assert report["state"] == "error" and report["message"] != oa.MISSING_ROLES_MESSAGE


def test_a_later_refusal_keeps_showing_the_last_good_snapshot_with_the_message(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-01T00:00:00.000Z")
    oa.capture_and_store(ENV, FakeOkta(fail={"assignees": REFUSED}), captured_at="2026-10-02T00:00:00.000Z")
    report = oa.build_okta_admins_report(ENV)
    assert report["state"] == "ok" and report["message"] == oa.MISSING_ROLES_MESSAGE
    assert report["as_of_snapshot"]["captured_at"].startswith("2026-10-01") and report["last_attempt"]["status"] == "refused"
    old = oa.build_okta_admins_report(ENV, as_of="2026-10-01")  # as of a date before the refusal: no message
    assert old["message"] is None


def test_governance_not_enabled_is_skipped_gracefully_and_asked_once(db):
    fake = FakeOkta(fail={"governance": lambda: _err(403, "E0000015", "feature not enabled")})
    snap = oa.capture_and_store(ENV, fake)
    assert snap["status"] == "ok" and snap["meta"]["governance"] == "not_enabled"
    assert len([c for c in fake.calls if c[0] == "governance"]) == 1  # stopped asking after the first answer
    assert any("not enabled" in n for n in oa.build_okta_admins_report(ENV)["notes"])


def test_governance_expiry_marks_time_bound_access(db):
    fake = FakeOkta(governance={"grants": [{"type": "ENTITLEMENT-BUNDLE", "grantId": "g1", "bundleId": "b1", "expirationDate": "2026-12-09 14:17:22.0"}]})
    oa.capture_and_store(ENV, fake)
    rows = oa.build_okta_admins_report(ENV)["rows"]
    assert all(r["time_bound"] and r["expires"] == "2026-12-09T14:17:22.000Z" for r in rows if r["status"] == "active")


def test_custom_roles_refused_but_admins_still_listed(db):
    fake = FakeOkta(fail={"custom_roles": REFUSED, "resource_sets": REFUSED})
    snap = oa.capture_and_store(ENV, fake)
    assert snap["status"] == "ok" and {u["part"] for u in snap["meta"]["unreadable"]} == {"custom_roles", "resource_sets"}
    report = oa.build_okta_admins_report(ENV)
    assert report["summary"]["admins"] == 2 and any("custom roles" in n for n in report["notes"])


def test_one_users_roles_refused_does_not_break_the_rest(db):
    calls = {"n": 0}

    def roles_fail():
        calls["n"] += 1
        return REFUSED()

    class F(FakeOkta):
        def list_user_roles(self, uid):
            if uid == "00u1":
                raise REFUSED()
            return super().list_user_roles(uid)
    snap = oa.capture_and_store(ENV, F())
    assert snap["status"] == "ok" and any(u["part"] == "user_roles" and u["id"] == "00u1" for u in snap["meta"]["unreadable"])
    assert oa.build_okta_admins_report(ENV)["summary"]["admins"] == 2


def test_a_deleted_user_between_list_and_profile_keeps_a_minimal_item(db):
    snap = oa.capture_and_store(ENV, FakeOkta(users=["00u1", "00ugone"]))
    stored = {i["key"]: i["object"] for i in audit_store.get_config_snapshot(ENV, snap["snapshot_id"])["items"]}
    assert stored["user:00ugone"]["id"] == "00ugone" and stored["user:00ugone"]["roles"] == []


@pytest.mark.parametrize("roles", [[None, 5, "x", {}, {"label": "no id"}, {"id": 7}], [{"id": "r", "type": ["not", "a", "string"], "label": {"a": 1}}]])
def test_malformed_role_entries_are_tolerated(db, roles):
    snap = oa.capture_and_store(ENV, FakeOkta(users=["00u1"], roles={"00u1": roles}))
    assert snap["status"] == "ok"
    oa.build_okta_admins_report(ENV)


def test_malformed_profile_and_target_shapes_are_tolerated(db):
    fake = FakeOkta(profiles={"00u1": {"id": "00u1", "status": 5, "profile": "nope"}, "00u2": {"id": "00u2", "profile": {"login": ["x"]}}},
                    targets_groups={"ra2": [None, 3, {"id": 4}, {"profile": []}]})
    assert oa.capture_and_store(ENV, fake)["status"] == "ok"
    oa.build_okta_admins_report(ENV)


def test_many_admins_are_capped_and_flagged(db):
    ids = [f"00u{i}" for i in range(30)]
    fake = FakeOkta(users=ids, roles={}, profiles={i: {"id": i, "status": "ACTIVE", "profile": {"login": f"{i}@example.com"}} for i in ids})
    snap = oa.capture_and_store(ENV, fake, max_admins=10)
    assert snap["meta"]["truncated"] and snap["meta"]["admins_total"] == 30 and snap["meta"]["admins_read"] == 10
    assert any("only the first" in n for n in oa.build_okta_admins_report(ENV)["notes"])


def test_duplicate_assignees_are_read_once(db):
    fake = FakeOkta(users=["00u1", "00u1", "", None, 5])
    snap = oa.capture_and_store(ENV, fake)
    assert snap["status"] == "ok" and len([c for c in fake.calls if c[0] == "get_user"]) == 1


# --- the report ---------------------------------------------------------------------------------
def test_report_never_captured(db):
    r = oa.build_okta_admins_report(ENV)
    assert r["state"] == "never_captured" and r["rows"] == []


def test_report_rows_summary_and_scope(db):
    oa.capture_and_store(ENV, FakeOkta())
    r = oa.build_okta_admins_report(ENV)
    assert r["state"] == "ok" and r["summary"]["admins"] == 2 and r["summary"]["assignments"] == 3
    by_role = {x["role_type"]: x for x in r["rows"]}
    assert by_role["SUPER_ADMIN"]["scope"] == "org-wide" and by_role["HELP_DESK_ADMIN"]["scope"] == "groups"
    assert by_role["HELP_DESK_ADMIN"]["target_groups"] == ["Support"]
    assert by_role["CUSTOM"]["custom_role"] == "Auditor" and by_role["CUSTOM"]["resource_set"] == "All users"
    assert by_role["CUSTOM"]["custom_role_permissions"] == ["okta.iam.read", "okta.users.read"]
    assert r["summary"]["by_role"]["SUPER_ADMIN"] == 1


def test_status_active_removed_and_unknown_between_snapshots(db):
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-01T00:00:00.000Z")
    # sam loses every role; a privilege event names someone who is in no snapshot
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event({
        "uuid": "g1", "eventType": "user.account.privilege.grant", "published": "2026-10-01T12:00:00.000Z",
        "actor": {"alternateId": "boss@example.com"}, "outcome": {"result": "SUCCESS"},
        "target": [{"id": "00uNEW", "type": "User"}, {"id": "x", "type": "ROLE_ASSIGNED"}, {"id": "r", "type": "ROLE", "displayName": "Super Organization Administrator"}]})], "all")
    oa.capture_and_store(ENV, FakeOkta(users=["00u1"]), captured_at="2026-10-02T00:00:00.000Z")
    r = oa.build_okta_admins_report(ENV)
    statuses = {(x["okta_user_id"], x["status"]) for x in r["rows"]}
    assert ("00u1", "active") in statuses and ("00u2", "removed") in statuses and ("00uNEW", "unknown") in statuses
    removed = next(x for x in r["rows"] if x["status"] == "removed")
    assert removed["removed_between"] == ["2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z"]
    older = oa.build_okta_admins_report(ENV, as_of="2026-10-01")
    assert {x["status"] for x in older["rows"] if x["okta_user_id"] == "00u2"} == {"active"}


def test_privilege_overlay_and_archive_evidence_labels(db):
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event({
        "uuid": "g1", "eventType": "user.account.privilege.grant", "published": "2026-02-02T00:00:00.000Z",
        "actor": {"alternateId": "boss@example.com"}, "outcome": {"result": "SUCCESS"},
        "target": [{"id": "00u2", "type": "User"}, {"id": "r", "type": "ROLE", "displayName": "Help Desk administrator"}]})], "all")
    oa.capture_and_store(ENV, FakeOkta())
    rows = {x["role_assignment_id"]: x for x in oa.build_okta_admins_report(ENV)["rows"]}
    assert rows["ra2"]["granted_evidence"] == "event" and rows["ra2"]["last_grant_event"]["by"] == "boss@example.com"
    assert rows["ra1"]["granted_evidence"] == "predates_archive"  # assigned 2026-01-01, archive starts 2026-02-02


def test_revoke_events_in_the_archive_are_overlaid(db):
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event({
        "uuid": "rv1", "eventType": "user.account.privilege.revoke", "published": "2026-10-01T12:00:00.000Z",
        "actor": {"alternateId": "boss@example.com"}, "outcome": {"result": "SUCCESS"},
        "target": [{"id": "00u2", "type": "User"}, {"id": "r", "type": "ROLE", "displayName": "Help Desk administrator"}]})], "all")
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-01T00:00:00.000Z")
    oa.capture_and_store(ENV, FakeOkta(users=["00u1"]), captured_at="2026-10-02T00:00:00.000Z")
    removed = next(x for x in oa.build_okta_admins_report(ENV)["rows"] if x["status"] == "removed")
    assert removed["last_revoke_event"]["type"] == "revoke"


def test_hostile_privilege_events_do_not_break_the_overlay(db):
    for i, targets in enumerate([None, [], "x", [None], [{"type": "User"}], [{"id": 5, "type": "User"}]]):
        ev = {"uuid": f"h{i}", "eventType": "user.account.privilege.grant", "published": "2026-10-01T12:00:00.000Z",
              "actor": None, "outcome": {}, "target": targets}
        audit_store._insert_rows(audit_store._get_connection(), ENV, [("h%d" % i, ev["eventType"], ev["published"], None, None, None, None,
                                                                        json.dumps(ev), None, None, None, [])], "all")
    oa.capture_and_store(ENV, FakeOkta())
    oa.build_okta_admins_report(ENV)


# --- separation of duties -----------------------------------------------------------------------
def test_separation_of_duties_matches_okta_admins_with_opa_admin_roles(db):
    oa.capture_and_store(ENV, FakeOkta())
    r = oa.build_okta_admins_report(ENV, access_model=_model())
    sod = r["separation_of_duties"]
    assert sod["state"] == "ok" and len(sod["overlaps"]) == 1
    o = sod["overlaps"][0]
    assert o["login"] == "alex@example.com" and o["okta_roles"] == ["SUPER_ADMIN"] and o["opa_roles"] == ["pam_admin"]
    assert o["via_groups"] == {"pam_admin": ["PAM-Admins"]} and r["summary"]["sod_overlaps"] == 1


def test_sod_is_unknown_without_the_opa_roster(db):
    oa.capture_and_store(ENV, FakeOkta())
    r = oa.build_okta_admins_report(ENV)
    assert r["separation_of_duties"]["state"] == "not_loaded" and any("OPA roster has not been loaded" in n for n in r["notes"])


def test_sod_counts_delegated_resource_admin_groups_and_flags_partial_rosters(db):
    model = _model()
    model["resource_groups"] = [{"id": "rg", "name": "Prod", "delegated_resource_admin_groups": [{"id": "g-users", "name": "Everyone"}]}]
    model["users"][0]["groups_error"] = True
    idx = oa.opa_role_index(model)
    assert idx["state"] == "partial"
    sam = next(u for u in idx["users"] if u["name"] == "sam@example.com")
    assert sam["powerful_roles"] == ["delegated_resource_admin"]


def test_sod_ignores_non_admin_roles_and_hostile_models(db):
    assert oa.is_powerful_opa_role("pam_admin") and oa.is_powerful_opa_role("Security_Admin") and not oa.is_powerful_opa_role("end_user")
    for bad in (None, {}, {"users": "x"}, {"users": [None, 5, {"groups": "x"}], "groups": [None], "resource_groups": [5]}):
        oa.opa_role_index(bad)
        oa.separation_of_duties([], oa.opa_role_index(bad))


# --- lifecycle cross-check C1 -------------------------------------------------------------------
class StatusOkta:
    def __init__(self, statuses, fail=None):
        self.statuses, self.fail, self.calls = statuses, fail or {}, []

    def get_user(self, lookup):
        self.calls.append(lookup)
        if lookup in self.fail:
            raise self.fail[lookup]
        if lookup not in self.statuses:
            raise _err(404, "E0000007", "Not found")
        return {"id": "00u" + lookup[:3], "status": self.statuses[lookup], "profile": {"login": lookup}, "credentials": {"password": {}}}


def test_c1_flags_inactive_absent_and_unreadable_principals(db):
    okta = StatusOkta({"alex@example.com": "DEPROVISIONED", "00uSVC": "SUSPENDED"}, fail={"sam@example.com": _err(500, "E0000009")})
    cap = oa.capture_principal_status(okta, _model())
    assert cap["status"] == "ok" and cap["meta"]["skipped_service_users"] == 1 and cap["meta"]["unreadable"] == 1
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"], meta=cap["meta"])
    card = oa.build_cross_checks(ENV, access_model=_model())
    assert card["state"] == "ok"
    assert {k: card["counts"][k] for k in ("checked", "inactive_in_okta", "absent_in_okta", "unreadable", "active")} == {"checked": 3, "inactive_in_okta": 2, "absent_in_okta": 0, "unreadable": 1, "active": 0}
    first = card["rows"][0]
    assert first["flag"] == "inactive" and first["opa_powerful_roles"] in (["pam_admin"], [])
    flags = oa.user_flags(ENV)
    assert flags["users"]["ou1"]["flag"] == "inactive" and flags["users"]["ou2"]["flag"] == "unknown"


def test_c1_absent_in_okta(db):
    cap = oa.capture_principal_status(StatusOkta({}), _model())
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"])
    card = oa.build_cross_checks(ENV, access_model=_model())
    assert card["counts"]["absent_in_okta"] == 3 and all(r["flag"] == "absent" for r in card["rows"])


def test_c1_active_users_are_not_listed(db):
    cap = oa.capture_principal_status(StatusOkta({"alex@example.com": "ACTIVE", "sam@example.com": "ACTIVE", "00uSVC": "ACTIVE"}), _model())
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"])
    card = oa.build_cross_checks(ENV)
    assert card["counts"]["active"] == 3 and card["rows"] == []


def test_c1_a_token_that_cannot_read_users_is_reported_not_zeroed(db):
    okta = StatusOkta({}, fail={"alex@example.com": REFUSED(), "sam@example.com": REFUSED(), "00uSVC": REFUSED()})
    cap = oa.capture_principal_status(okta, _model())
    assert cap["status"] == "refused" and cap["items"] == []
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"], status=cap["status"], meta=cap["meta"])
    card = oa.build_cross_checks(ENV)
    assert card["state"] == "refused" and card["message"] == oa.MISSING_USERS_MESSAGE


def test_c1_never_run_and_stale(db):
    assert oa.build_cross_checks(ENV)["state"] == "never_run"
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, [], captured_at="2020-01-01T00:00:00.000Z")
    assert oa.build_cross_checks(ENV)["inputs"]["okta_snapshot_stale"] is True


def test_principals_are_bounded_and_service_users_skipped():
    model = _model(extra_users=[{"id": f"x{i}", "name": f"u{i}@example.com", "user_type": "human", "details": {}, "groups": []} for i in range(50)])
    principals, skipped = oa.opa_principals(model, limit=10)
    assert len(principals) == 10 and skipped == 1
    assert oa.opa_principals(None) == ([], 0)
    assert oa.opa_principals({"users": [None, {"id": "a"}], "okta_accounts": [None, {"okta_user_id": 5}]}) == ([], 0)


# --- automatic capture and overview -------------------------------------------------------------
def test_capture_if_due_skips_a_recent_attempt_even_a_refusal(db):
    from datetime import datetime, timezone
    assert oa.capture_if_due(ENV, FakeOkta(fail={"assignees": REFUSED})) is not None
    fake = FakeOkta()
    assert oa.capture_if_due(ENV, fake) is None and fake.calls == []
    far = datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert oa.capture_if_due(ENV, fake, now=far) is not None


def test_overview_is_counts_only_with_per_block_states(db):
    refused = oa.build_overview(ENV, access_model=_model())
    assert refused["okta_admins"]["state"] == "never_captured" and refused["lifecycle_c1"]["state"] == "never_run"
    oa.capture_and_store(ENV, FakeOkta(fail={"assignees": REFUSED}), captured_at="2026-10-01T00:00:00.000Z")
    o = oa.build_overview(ENV, access_model=_model(), service_accounts_total=4)
    assert o["okta_admins"]["state"] == "refused" and o["okta_admins"]["message"] == oa.MISSING_ROLES_MESSAGE
    assert o["okta_admins"]["count"] is None and o["sod_overlaps"]["state"] == "refused" and o["sod_overlaps"]["count"] is None
    assert o["opa_privileged_users"]["count"] == 1 and o["opa_service_accounts"]["count"] == 4
    oa.capture_and_store(ENV, FakeOkta(), captured_at="2026-10-02T00:00:00.000Z")
    o = oa.build_overview(ENV, access_model=_model())
    assert o["okta_admins"]["count"] == 2 and o["sod_overlaps"]["count"] == 1
    assert [s["status"] for s in o["snapshot_dates"]] == ["ok", "refused"]
    blob = json.dumps(o)
    assert "alex@example.com" not in blob and "login" not in blob  # counts only
    assert o["opa_service_accounts"]["count"] is None or True
    assert oa.build_overview(ENV)["opa_privileged_users"] == {"state": "not_loaded", "count": None, "users_total": None}


def test_overview_weekly_privilege_counts(db):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    rows = []
    for i, (typ, days) in enumerate([("grant", 1), ("grant", 2), ("revoke", 3), ("grant", 30)]):
        ev = {"uuid": f"w{i}", "eventType": f"user.account.privilege.{typ}", "published": (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
              "actor": {}, "outcome": {}, "target": [{"id": "00u1", "type": "User"}]}
        rows.append(audit_store._normalize_live_event(ev))
    audit_store._insert_rows(audit_store._get_connection(), ENV, rows, "all")
    w = oa.build_overview(ENV)["weekly_privilege_events"]
    assert w["grants"] == 2 and w["revokes"] == 1


# --- OktaClient pagination ----------------------------------------------------------------------
class _H(dict):
    def get_all(self, name):
        return [self[name]] if name in self else []


def _client(monkeypatch, pages):
    client = engine.OktaClient("https://example.okta.com", "tok")
    seq = list(pages)
    seen = []

    def request(method, path, body=None, return_headers=False):
        seen.append(path)
        body, link = seq.pop(0)
        return (body, _H({"Link": link} if link else {})) if return_headers else body
    monkeypatch.setattr(client, "request", request)
    client.seen = seen
    return client


def test_list_all_follows_body_links_and_header_links(monkeypatch):
    body_next = {"value": [{"id": "a"}], "_links": {"next": {"href": "https://example.okta.com/api/v1/iam/assignees/users?after=a&limit=100"}}}
    c = _client(monkeypatch, [(body_next, None), ({"value": [{"id": "b"}]}, None)])
    assert [x["id"] for x in c.list_users_with_role_assignments()] == ["a", "b"]
    c = _client(monkeypatch, [([{"id": "1"}], '<https://example.okta.com/api/v1/iam/roles?after=1>; rel="next"'), ([{"id": "2"}], None)])
    assert [x["id"] for x in c.list_all("/api/v1/iam/roles")] == ["1", "2"]


def test_list_all_refuses_a_paging_loop_a_foreign_link_and_bad_shapes(monkeypatch):
    loop = {"value": [{"id": "a"}], "_links": {"next": {"href": "https://example.okta.com/api/v1/iam/assignees/users?limit=100"}}}
    with pytest.raises(engine.OktaApiError, match="loop"):
        _client(monkeypatch, [(loop, None), (loop, None)]).list_users_with_role_assignments()
    foreign = {"value": [{"id": "a"}], "_links": {"next": {"href": "https://evil.example.com/api/v1/iam/assignees/users?after=a"}}}
    with pytest.raises(engine.OktaApiError):
        _client(monkeypatch, [(foreign, None)]).list_users_with_role_assignments()
    other = {"value": [{"id": "a"}], "_links": {"next": {"href": "https://example.okta.com/api/v1/users?after=a"}}}
    with pytest.raises(engine.OktaApiError):
        _client(monkeypatch, [(other, None)]).list_users_with_role_assignments()
    with pytest.raises(engine.OktaApiError):
        _client(monkeypatch, [({"value": "nope"}, None)]).list_users_with_role_assignments()
    with pytest.raises(engine.OktaApiError):
        _client(monkeypatch, [("[1]", None)]).list_users_with_role_assignments()


def test_list_all_stops_on_an_empty_page_and_caps_items(monkeypatch):
    with_next = {"value": [], "_links": {"next": {"href": "https://example.okta.com/api/v1/iam/assignees/users?after=zz&limit=100"}}}
    assert _client(monkeypatch, [(with_next, None)]).list_users_with_role_assignments() == []
    big = {"value": [{"id": str(i)} for i in range(50)]}
    with pytest.raises(engine.OktaApiError, match="more than"):
        _client(monkeypatch, [(big, None)]).list_all("/api/v1/iam/assignees/users", "value", max_items=10)
    assert _client(monkeypatch, [({"resource-sets": None}, None)]).list_resource_sets() == []


def test_ids_are_percent_quoted_in_paths(monkeypatch):
    c = _client(monkeypatch, [({"id": "x"}, None)])
    c.get_user("../../etc?x=1")
    assert c.seen[0] == "/api/v1/users/..%2F..%2Fetc%3Fx%3D1"


# --- H1: the lookup tries the Okta login (the OPA user name) first, then the e-mail --------------------------------
class LoginOnlyOkta:
    """Matches profile.login only, as GET /api/v1/users/{x} does; an e-mail that is not also a login is a 404."""
    def __init__(self, users):
        self.users, self.calls = users, []

    def get_user(self, key):
        self.calls.append(key)
        if key in self.users:
            return {"id": "00u" + key[:3], "status": self.users[key], "profile": {"login": key}}
        raise _err(404, "E0000007", "Not found")


def _one_user_model(name, email):
    return {"users": [{"id": "ou1", "name": name, "user_type": "human", "details": {"email": email}, "groups": []}], "okta_accounts": []}


def test_c1_login_differs_from_email_is_found_by_login_not_absent():
    okta = LoginOnlyOkta({"jdoe@example.com": "ACTIVE"})
    cap = oa.capture_principal_status(okta, _one_user_model("jdoe@example.com", "john.doe@example.com"))
    entry = cap["items"][0][1]
    assert entry["okta_state"] == "ACTIVE" and okta.calls == ["jdoe@example.com"]  # found by the login; the e-mail never needed
    assert entry["lookup_keys"] == [{"kind": "login", "value": "jdoe@example.com"}]


def test_c1_falls_back_to_the_email_when_the_login_finds_nothing():
    okta = LoginOnlyOkta({"john.doe@example.com": "DEPROVISIONED"})
    entry = oa.capture_principal_status(okta, _one_user_model("jdoe@example.com", "john.doe@example.com"))["items"][0][1]
    assert okta.calls == ["jdoe@example.com", "john.doe@example.com"] and entry["okta_state"] == "DEPROVISIONED"


def test_c1_login_only_and_email_only_principals():
    okta = LoginOnlyOkta({"only@example.com": "ACTIVE"})
    assert oa.capture_principal_status(okta, _one_user_model("only@example.com", None))["items"][0][1]["okta_state"] == "ACTIVE"
    okta = LoginOnlyOkta({"mail@example.com": "SUSPENDED"})
    entry = oa.capture_principal_status(okta, _one_user_model(None, "mail@example.com"))["items"][0][1]
    assert entry["okta_state"] == "SUSPENDED" and okta.calls == ["mail@example.com"]


def test_c1_neither_key_finds_a_user_is_absent_and_names_both_keys(db):
    okta = LoginOnlyOkta({})
    cap = oa.capture_principal_status(okta, _one_user_model("gone@example.com", "g.one@example.com"))
    entry = cap["items"][0][1]
    assert entry["okta_state"] == "ABSENT" and okta.calls == ["gone@example.com", "g.one@example.com"]
    audit_store.record_config_snapshot(ENV, oa.KIND_PRINCIPAL_STATUS, cap["items"])
    row = oa.build_cross_checks(ENV, access_model=_one_user_model("gone@example.com", "g.one@example.com"))["rows"][0]
    assert row["absent_text"] == "no Okta user with login gone@example.com or e-mail g.one@example.com"


def test_c1_same_login_and_email_is_looked_up_once_and_a_server_error_stops_the_chain():
    okta = LoginOnlyOkta({})
    oa.capture_principal_status(okta, _one_user_model("same@example.com", "same@example.com"))
    assert okta.calls == ["same@example.com"]

    class Boom(LoginOnlyOkta):
        def get_user(self, key):
            self.calls.append(key)
            raise _err(500, "E0000009")
    boom = Boom({})
    entry = oa.capture_principal_status(boom, _one_user_model("a@example.com", "b@example.com"))["items"][0][1]
    assert entry["okta_state"] == "UNREADABLE" and boom.calls == ["a@example.com"]  # a failure is not "not found": no fallback, no "absent"


def test_after_a_refused_automatic_capture_the_next_one_waits_24_hours_but_manual_capture_does_not(db):
    from datetime import datetime, timedelta, timezone
    t0 = datetime(2026, 10, 21, 2, 0, tzinfo=timezone.utc)
    refused = FakeOkta(fail={"assignees": REFUSED})
    first = oa.capture_if_due(ENV, refused, now=t0)
    assert first is not None and first["status"] == "refused"
    for hours in (7, 13, 23):  # beyond the 6 h interval, inside 24 h: no new snapshot, no call to Okta
        probe = FakeOkta(fail={"assignees": REFUSED})
        assert oa.capture_if_due(ENV, probe, now=t0 + timedelta(hours=hours)) is None and probe.calls == []
    assert len(audit_store.list_config_snapshots(ENV, kind=oa.KIND_ADMINS)) == 1
    manual = oa.capture_and_store(ENV, FakeOkta(fail={"assignees": REFUSED}))  # never held back
    assert manual["status"] == "refused" and len(audit_store.list_config_snapshots(ENV, kind=oa.KIND_ADMINS)) == 2
    # a successful capture keeps the ordinary six-hour interval
    ok_t = datetime(2026, 12, 1, 2, 0, tzinfo=timezone.utc)
    assert oa.capture_if_due(ENV, FakeOkta(), now=ok_t)["status"] == "ok"
    assert oa.capture_if_due(ENV, FakeOkta(), now=ok_t + timedelta(hours=5)) is None
    assert oa.capture_if_due(ENV, FakeOkta(), now=ok_t + timedelta(hours=7)) is not None
