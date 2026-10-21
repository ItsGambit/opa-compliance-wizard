"""5.51.0 phase B: the daily sealed OPA access state. Items per user, group and policy (names and e-mails of people, ids only for
resources), one a day, sealed into the evidence chain from the scan the refresh just read; readable like the other snapshot kinds
(the list needs View archive; items, diff and export also need Live read)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine
import opa_access_state as oas
import server.refresh_jobs as rj
from test_refresh_job_5510 import FIXTURE_EMAIL, FIXTURE_NAME, Rig, _default_builder, rig  # noqa: F401
from test_http_authz_matrix import OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server  # noqa: F401
from test_okta_routes_5500 import _audit_actions
from test_okta_admins_5500 import _model

ENV = "77777777-7777-7777-7777-777777777777"
RESOURCE_NAME = "Payments Production Vault"  # a resource name: it must never reach the sealed items


def _scan():
    model = _model()
    model["users"][0].update(name=FIXTURE_NAME, status="ACTIVE", details={"email": FIXTURE_EMAIL})
    model["policies"] = [
        {"id": "p1", "name": "Servers", "active": True, "principals": {"user_groups": [{"id": "g-users", "name": "Everyone"}], "workload_roles": []},
         "relationship_ids": ["rel1"],
         "rules": [{"name": "r", "resource_type": "secret_based_resource", "privileges": [{"privilege_type": "secret", "flags": ["list", "secret_reveal"]}],
                    "conditions": [], "resolutions": [
                        {"kind": "resolved", "id": "s1", "name": RESOURCE_NAME, "resource_kind": "secret_folder", "project_id": "pr1", "project_name": RESOURCE_NAME},
                        {"kind": "condition", "description": RESOURCE_NAME}]}]},
        {"id": "p2", "name": "Off", "active": False, "principals": {"user_groups": [{"id": "g-admins"}]}, "rules": []},
    ]
    model["warnings"] = []
    return model


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _items(snap):
    return {i["key"]: i["object"] for i in audit_store.get_config_snapshot(ENV, snap["snapshot_id"])["items"]}


def test_items_are_per_user_group_and_policy_with_ids_only_for_resources(db):
    snap = oas.capture_if_due(ENV, _scan(), built_at="2026-10-21T02:20:00.000Z")
    items = _items(snap)
    assert snap["kind"] == "opa_access_state" and snap["status"] == "ok"
    assert {"user:ou1", "user:ou2", "group:g-admins", "group:g-users", "policy:p1", "policy:p2", "summary:counts"} <= set(items)
    u = items["user:ou1"]
    assert u["name"] == FIXTURE_NAME and u["email"] == FIXTURE_EMAIL and u["status"] == "ACTIVE" and u["group_ids"] == ["g-admins"]
    assert items["user:ou2"]["effective"] is True and items["user:ou1"]["effective"] is False  # only ou2's group reaches an active policy that resolves
    assert items["group:g-admins"] == {"id": "g-admins", "name": "PAM-Admins", "roles": ["end_user", "pam_admin"], "member_count": 1}
    p = items["policy:p1"]
    assert p["active"] is True and p["principal_group_ids"] == ["g-users"] and p["relationship_ids"] == ["rel1"]
    assert p["rules"] == [{"resource_type": "secret_based_resource", "resource_kinds": ["secret_folder"], "privilege_flags": ["list", "secret_reveal"],
                           "resolved_project_ids": ["pr1"], "resolved_resource_ids": ["s1"]}]
    blob = json.dumps(items)
    assert RESOURCE_NAME not in blob  # resource and project names stay in the stored scan and the exports
    for denied in engine.MODEL_REDACTED_KEYS - {"value"}:
        assert f'"{denied}"' not in blob.lower()
    assert items["summary:counts"]["counts"]["opa.policies"] == 2 and items["summary:counts"]["unreadable_sections"] == []


def test_a_group_whose_membership_could_not_be_read_has_no_member_count_never_zero(db):
    model = _scan()
    model["users"][0]["groups_error"] = True
    items = _items(oas.capture_if_due(ENV, model))
    assert items["group:g-admins"]["member_count"] is None and items["user:ou1"]["groups_error"] is True


def test_an_unreadable_section_is_named_in_the_summary_and_the_meta_and_its_count_is_absent(db):
    model = _scan()
    model["gateways"] = []
    model["warnings"] = [{"section": "gateways", "status": 403, "message": "gateways could not be read"}]
    snap = oas.capture_if_due(ENV, model)
    items = _items(snap)
    assert items["summary:counts"]["unreadable_sections"] == ["gateways"] and "opa.gateways" not in items["summary:counts"]["counts"]
    assert snap["meta"]["unreadable_sections"] == ["gateways"]


def test_one_a_day_with_a_20_hour_gate(db):
    first = oas.capture_if_due(ENV, _scan())
    assert first and oas.capture_if_due(ENV, _scan()) is None  # the cache updates every scan; the evidence point is once a day
    later = datetime.now(timezone.utc) + timedelta(hours=oas.GATE_HOURS + 1)
    assert oas.capture_if_due(ENV, _scan(), now=later)
    assert len(audit_store.list_config_snapshots(ENV, kind="opa_access_state")) == 2


def test_a_policy_item_over_the_size_cap_keeps_counts_and_says_it_was_truncated(db):
    model = _scan()
    big = [{"kind": "resolved", "id": f"{i:036d}", "resource_kind": "individual_server", "project_id": "pr1"} for i in range(9000)]
    model["policies"][0]["rules"][0]["resolutions"] = big
    snap = oas.capture_if_due(ENV, model)
    p = _items(snap)["policy:p1"]
    assert p["truncated"] is True and p["rules"][0]["resolved_resource_count"] == 9000 and p["rules"][0]["resolved_resource_ids"] == []
    assert snap["meta"]["truncated_policies"] == 1


def test_a_scan_with_nothing_in_it_writes_nothing(db):
    with pytest.raises(ValueError):
        oas.capture_if_due(ENV, {"users": [], "groups": [], "policies": []})
    with pytest.raises(ValueError):
        oas.capture_if_due(ENV, None)
    assert audit_store.list_config_snapshots(ENV, kind="opa_access_state") == []


def test_the_chain_verifies_with_the_new_kind_and_it_is_purged_with_the_archive(db):
    oas.capture_if_due(ENV, _scan())
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True
    assert audit_store.prune_events(ENV, retention_days=1, max_size_mb=None) is not None
    assert len(audit_store.list_config_snapshots(ENV, kind="opa_access_state")) == 1  # never pruned
    audit_store.purge_environment_archive(ENV)
    assert audit_store.list_config_snapshots(ENV, kind="opa_access_state") == []


# -- through the refresh job -----------------------------------------------------------------------------------------------
def test_a_refresh_seals_the_access_state_once_a_day_and_says_so(rig, tmp_audit_log):  # noqa: F811
    rig.builder = lambda client, okta_client=None, on_progress=None: (_default_builder(client, okta_client, on_progress))
    job = rig.run(["opa"])
    data = job.status_view()["parts"]["opa"]
    snaps = audit_store.list_config_snapshots(rig.env, kind="opa_access_state")
    assert len(snaps) == 1 and "sealed into the evidence chain" in data["message"] and data["snapshot"]["state"] == "sealed"
    rows = rig.audit(tmp_audit_log)
    captured = [r for r in rows if r["action"] == "okta_snapshot.captured" and r["details"]["kind"] == "opa_access_state"]
    assert captured and captured[0]["details"]["snapshot_id"] == snaps[0]["snapshot_id"] and captured[0]["details"]["trigger"] == "manual"
    completed = [r for r in rows if r["action"] == "access_scan.completed"][0]
    assert completed["details"]["snapshot_id"] == snaps[0]["snapshot_id"]
    # a second refresh inside 20 hours updates the stored scan but seals nothing more
    second = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert second["snapshot"]["state"] == "not_due" and "sealed" not in second["message"]
    assert len(audit_store.list_config_snapshots(rig.env, kind="opa_access_state")) == 1
    # the audit lines carry no name or e-mail
    raw = open(tmp_audit_log, encoding="utf-8").read()
    assert FIXTURE_NAME not in raw and FIXTURE_EMAIL not in raw


def test_a_failed_scan_seals_nothing(rig):  # noqa: F811
    rig.builder = lambda *a, **k: (_ for _ in ()).throw(engine.OpaApiError(503, "u", "x"))
    rig.run(["opa"])
    assert audit_store.list_config_snapshots(rig.env, kind="opa_access_state") == []


def test_a_snapshot_that_cannot_be_sealed_does_not_fail_the_scan(rig, monkeypatch):  # noqa: F811
    monkeypatch.setattr(oas, "capture_if_due", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    data = rig.run(["opa"]).status_view()["parts"]["opa"]
    assert data["state"] == "ok" and "could not be sealed" in data["message"] and data["snapshot"]["state"] == "error"
    assert audit_store.opa_model_cache_info(rig.env)  # the scan itself is stored


# -- who may read it -------------------------------------------------------------------------------------------------------
def test_the_list_needs_view_archive_but_items_diff_and_export_also_need_live_read(matrix_server):  # noqa: F811
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    engine.set_environment_shared("dev", OWNER_A, True)
    first = oas.capture_if_due(env_id, _scan())
    second = oas.capture_if_due(env_id, _scan(), now=datetime.now(timezone.utc) + timedelta(hours=21))
    engine.set_shared_permissions({"view_archive": "allow", "live_read": "deny"}, environment_id=env_id)
    base = "/api/environments/dev/config_snapshots"
    b = lambda path: _call(base_url, "GET", base + path, headers=_who(OWNER_B))  # noqa: E731
    listing = b("?kind=opa_access_state")
    assert listing.status_code == 200 and len(listing.json()["snapshots"]) == 2 and FIXTURE_EMAIL not in listing.text  # the list carries no objects
    for denied in (f"/export?snapshot_id={first['snapshot_id']}", f"/diff?older={first['snapshot_id']}&newer={second['snapshot_id']}"):
        r = b(denied)
        assert r.status_code == 403 and r.json()["capability"] == "live_read" and FIXTURE_EMAIL not in r.text, denied
    engine.set_shared_permissions({"live_read": "allow"}, environment_id=env_id)
    exported = b(f"/export?snapshot_id={first['snapshot_id']}")
    assert exported.status_code == 200 and exported.json()["kind"] == "opa_access_state" and FIXTURE_EMAIL in exported.text
    assert exported.json()["verification"]["valid"] is True
