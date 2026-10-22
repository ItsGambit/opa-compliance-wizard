"""5.51.0 (work package A1): the stored OPA scan. The redaction pass (a deny-list of keys and a canary on credential-shaped
values), the cache round trip, its size and shape limits, and its lifecycle (replace, delete with the environment,
purge parity, orphan sweep, retention). Every identity here is a placeholder."""
import copy
import json
import sqlite3
import zlib

import pytest

import audit_store
import create_secret_folders as engine

ENV = "55555555-5555-5555-5555-555555555555"
OTHER = "66666666-6666-6666-6666-666666666666"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
SSWS = "00" + "aB3_-" * 8  # 42 characters, starts with 00, like an Okta API token
LONG_SECRET = "Zq8vK2mXp9LrT4wYb7NcD1fHj6GsA3eUi5OoV0xRn2Qk8MtB"  # 50 characters, mixed case and digits


def _model(**extra):
    model = {
        "resource_groups": [{"id": "11111111-1111-1111-1111-111111111111", "name": "Platform"}],
        "projects": [{"id": "22222222-2222-2222-2222-222222222222", "name": "Core", "resource_group_id": "11111111-1111-1111-1111-111111111111"}],
        "groups": [{"id": "g1", "name": "Admins", "roles": ["resource_admin"]}],
        "users": [{"id": "u1", "name": "alex", "user_type": "human", "details": {"email": "alex@example.com"}, "groups": [{"id": "g1", "name": "Admins"}]}],
        "policies": [{"id": "p1", "name": "Policy One", "active": True, "rules": [{"name": "r", "conditions": [
            {"account_name_format": "STARTS_WITH", "value": "svc"}], "resolutions": [{"kind": "resolved", "sha": "a" * 64}]}]}],
        "servers": [], "devices": [], "warnings": [],
        "inventory_totals": {"secret_folders": 3, "secrets": 9},
    }
    model.update(extra)
    return model


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


# -- redaction -------------------------------------------------------------------------------------------------------
def test_denied_keys_are_dropped_at_every_depth():
    model = _model(users=[{"id": "u1", "name": "alex", "credentials": {"password": {"value": "x"}}, "details": {
        "api_token": "t", "nested": [{"Authorization": "Bearer x", "cookie": "c", "keep": "me"}]}}])
    out = engine.redact_model_for_storage(model)
    user = out["users"][0]
    assert "credentials" not in user and "api_token" not in user["details"]
    assert user["details"]["nested"] == [{"keep": "me"}]
    assert user["id"] == "u1" and user["name"] == "alex"


@pytest.mark.parametrize("key", sorted(engine.MODEL_REDACTED_KEYS - {"value"}))
def test_every_denied_key_is_dropped_whatever_its_case(key):
    out = engine.redact_model_for_storage(_model(extra_section=[{key.upper(): "anything", "id": "k"}]))
    assert out["extra_section"] == [{"id": "k"}]


def test_a_bare_value_key_is_dropped_but_a_name_condition_operand_is_kept():
    out = engine.redact_model_for_storage(_model(groups=[{"id": "g", "value": "should-go"}]))
    assert out["groups"] == [{"id": "g"}]
    kept = out["policies"][0]["rules"][0]["conditions"][0]
    assert kept == {"account_name_format": "STARTS_WITH", "value": "svc"}


def test_collection_names_that_contain_secret_are_not_confused_with_the_key():
    model = _model(secret_folders=[{"id": "f"}], secrets=[{"id": "s"}], privileges=[{"privilege_type": "secret"}])
    out = engine.redact_model_for_storage(model)
    assert out["secret_folders"] == [{"id": "f"}] and out["secrets"] == [{"id": "s"}]
    assert out["privileges"] == [{"privilege_type": "secret"}]


def test_the_input_is_not_modified():
    model = _model(users=[{"id": "u1", "password": "p"}])
    before = copy.deepcopy(model)
    engine.redact_model_for_storage(model)
    assert model == before


OPK_SECRET = "opk_" + "Zq8vK2mXp9LrT4wYb7NcD1fH"  # 24 high-entropy characters after the prefix
SK_SECRET = "sk-" + "Xt5Pq2Lm9Rv7Nc3Wb8Kd4Fh6"


@pytest.mark.parametrize("secret", [JWT, SSWS, LONG_SECRET, OPK_SECRET, SK_SECRET, "ghp_abcdefghijklmnop", "xoxb-1234567890abcdef"])
def test_a_credential_shaped_value_refuses_the_scan_and_names_the_path_not_the_value(secret):
    model = _model(users=[{"id": "u1", "name": "alex"}, {"id": "u2", "details": {"notes": [{"free_text": secret}]}}])
    with pytest.raises(engine.ModelRedactionError) as caught:
        engine.redact_model_for_storage(model)
    assert caught.value.key_path == "users[1].details.notes[0].free_text"
    assert secret not in str(caught.value) and caught.value.key_path in str(caught.value)
    assert isinstance(caught.value, ValueError)


@pytest.mark.parametrize("fine", [
    "11111111-1111-1111-1111-111111111111",  # an id
    "a" * 64,  # a hex digest
    "00uabcdefghijklmnopq",  # an Okta id
    "https://example.okta.com/api/v1/users/00uabcdefghijklmnopq?after=abc",
    "Production Linux servers owned by the platform team and reviewed every quarter",
    "alex@example.com",
])
def test_ordinary_values_pass_the_canary(fine):
    assert engine.redact_model_for_storage(_model(users=[{"id": "u1", "name": fine}]))["users"][0]["name"] == fine


def test_a_credential_under_a_denied_key_is_dropped_not_refused():
    # the key is removed before its value is read: nothing of it can reach the disk either way
    out = engine.redact_model_for_storage(_model(users=[{"id": "u1", "token": JWT}]))
    assert out["users"] == [{"id": "u1"}]


def test_devices_keep_only_what_the_resources_tab_shows():
    device = {"id": "d1", "status": "ACTIVE", "created": "2026-01-01T00:00:00.000Z", "lastUpdated": "2026-01-02T00:00:00.000Z",
              "profile": {"displayName": "Laptop", "platform": "MACOS", "osVersion": "15", "serialNumber": "SERIAL1", "registered": True,
                          "imei": "123456789012345", "udid": "UDID-1", "secureHardwarePresent": True, "diskEncryptionType": "ALL_INTERNAL_VOLUMES"},
              "authenticator_enrollments": [{"id": "e", "key": "okta_verify", "name": "Okta Verify", "status": "ACTIVE", "devicePushToken": "zzz"}],
              "users": ["alex@example.com"], "_links": {"self": {"href": "https://example.okta.com/api/v1/devices/d1"}}, "resourceId": "r"}
    out = engine.redact_model_for_storage(_model(devices=[device]))["devices"][0]
    assert set(out) == {"id", "status", "created", "lastUpdated", "profile", "authenticator_enrollments", "users"}
    assert "imei" not in out["profile"] and "udid" not in out["profile"] and out["profile"]["serialNumber"] == "SERIAL1"
    assert out["authenticator_enrollments"] == [{"id": "e", "key": "okta_verify", "name": "Okta Verify", "status": "ACTIVE"}]


@pytest.mark.parametrize("bad", [{"x": {1, 2}}, {"x": float("nan")}, {"x": object()}, {1: "numeric key"}])
def test_values_that_cannot_be_stored_are_refused(bad):
    with pytest.raises(engine.ModelRedactionError):
        engine.redact_model_for_storage(_model(extra=bad))


def test_absurd_nesting_is_refused_not_a_recursion_error():
    deep = current = {}
    for _ in range(100):
        current["n"] = {}
        current = current["n"]
    with pytest.raises(engine.ModelRedactionError):
        engine.redact_model_for_storage(_model(deep=deep))


def test_the_path_never_carries_an_unbounded_key():
    long_key = "k" * 500
    with pytest.raises(engine.ModelRedactionError) as caught:
        engine.redact_model_for_storage(_model(extra={long_key: JWT}))
    assert len(caught.value.key_path) < 100


# -- the cache -------------------------------------------------------------------------------------------------------
def test_a_clean_model_round_trips_byte_identical(db):
    model = _model()
    stored = audit_store.store_opa_model_cache(ENV, model, built_at="2026-10-21T02:20:00.000Z", duration_seconds=41.5)
    assert stored["stored"] and stored["built_at"] == "2026-10-21T02:20:00.000Z"
    loaded = audit_store.load_opa_model_cache(ENV)
    assert loaded["model"] == model
    assert engine.canonical_model_json(loaded["model"]) == engine.canonical_model_json(model)
    import hashlib
    assert loaded["sha256"] == stored["sha256"] == hashlib.sha256(engine.canonical_model_json(model).encode("utf-8")).hexdigest()
    assert loaded["counts"] == {"users": 1, "groups": 1, "policies": 1, "projects": 1, "servers": 0}
    assert loaded["duration_seconds"] == 41.5 and loaded["source_version"] == engine.SCRIPT_VERSION and loaded["warnings_count"] == 0


def test_the_stored_bytes_are_compressed_canonical_json(db):
    audit_store.store_opa_model_cache(ENV, _model())
    row = audit_store._get_connection().execute("SELECT model_zlib, raw_bytes FROM opa_model_cache").fetchone()
    raw = zlib.decompress(row["model_zlib"])
    assert len(raw) == row["raw_bytes"] and json.loads(raw)["users"][0]["name"] == "alex"


def test_a_credential_in_the_model_stores_nothing(db):
    with pytest.raises(engine.ModelRedactionError):
        audit_store.store_opa_model_cache(ENV, _model(users=[{"id": "u", "name": JWT}]))
    assert audit_store.load_opa_model_cache(ENV) is None
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM opa_model_cache").fetchone()[0] == 0


def test_denied_keys_never_reach_the_disk(db):
    audit_store.store_opa_model_cache(ENV, _model(users=[{"id": "u1", "name": "alex", "credentials": {"password": "hunter2-hunter2"}}]))
    row = audit_store._get_connection().execute("SELECT model_zlib FROM opa_model_cache").fetchone()
    assert b"hunter2" not in zlib.decompress(row["model_zlib"]) and b"credentials" not in zlib.decompress(row["model_zlib"])


def test_a_new_scan_replaces_the_old_one(db):
    audit_store.store_opa_model_cache(ENV, _model(), built_at="2026-10-20T02:00:00.000Z")
    audit_store.store_opa_model_cache(ENV, _model(groups=[]), built_at="2026-10-21T02:00:00.000Z")
    loaded = audit_store.load_opa_model_cache(ENV)
    assert loaded["built_at"] == "2026-10-21T02:00:00.000Z" and loaded["model"]["groups"] == []
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM opa_model_cache").fetchone()[0] == 1


def test_over_the_size_limit_nothing_is_stored_and_the_model_stays_usable(db, monkeypatch):
    monkeypatch.setattr(audit_store, "OPA_MODEL_CACHE_MAX_BYTES", 50)
    result = audit_store.store_opa_model_cache(ENV, _model())
    assert result["stored"] is False and result["reason"] == "too_large" and result["raw_bytes"] > 50
    assert result["model"]["users"][0]["name"] == "alex"
    assert audit_store.load_opa_model_cache(ENV) is None


def test_a_scan_over_the_limit_leaves_the_previous_row_alone(db, monkeypatch):
    audit_store.store_opa_model_cache(ENV, _model(), built_at="2026-10-20T02:00:00.000Z")
    monkeypatch.setattr(audit_store, "OPA_MODEL_CACHE_MAX_BYTES", 50)
    assert audit_store.store_opa_model_cache(ENV, _model(groups=[]))["stored"] is False
    assert audit_store.load_opa_model_cache(ENV)["built_at"] == "2026-10-20T02:00:00.000Z"


def test_environments_never_share_a_scan(db):
    audit_store.store_opa_model_cache(ENV, _model())
    audit_store.store_opa_model_cache(OTHER, _model(users=[]))
    assert audit_store.load_opa_model_cache(ENV)["model"]["users"] and audit_store.load_opa_model_cache(OTHER)["model"]["users"] == []


def test_a_scan_built_by_another_model_shape_is_treated_as_absent(db):
    audit_store.store_opa_model_cache(ENV, _model(), source_version="5.53.0")
    assert audit_store.load_opa_model_cache(ENV) is None and audit_store.opa_model_cache_info(ENV) is None
    audit_store.store_opa_model_cache(ENV, _model(), source_version="5.52.7")  # a patch release shares the shape
    assert audit_store.load_opa_model_cache(ENV) is not None


def test_a_damaged_row_is_ignored_not_served(db):
    audit_store.store_opa_model_cache(ENV, _model())
    conn = audit_store._get_connection()
    conn.execute("UPDATE opa_model_cache SET model_zlib = ?", (zlib.compress(b'{"users": []}'),))
    conn.commit()
    assert audit_store.load_opa_model_cache(ENV) is None  # hash mismatch
    conn.execute("UPDATE opa_model_cache SET model_zlib = ?", (b"not zlib",))
    conn.commit()
    assert audit_store.load_opa_model_cache(ENV) is None


def test_info_never_carries_the_model(db):
    audit_store.store_opa_model_cache(ENV, _model(warnings=[{"section": "gateways", "status": 403, "message": "m"}]))
    info = audit_store.opa_model_cache_info(ENV)
    assert "model" not in info and info["warnings_count"] == 1 and info["counts"]["users"] == 1


def test_a_local_correction_keeps_the_scan_time_and_records_the_edit(db):
    audit_store.store_opa_model_cache(ENV, _model(), built_at="2026-10-20T02:00:00.000Z")
    corrected = _model()
    corrected["users"][0]["groups"] = []
    assert audit_store.update_opa_model_cache(ENV, corrected, modified_at="2026-10-21T09:00:00.000Z")
    loaded = audit_store.load_opa_model_cache(ENV)
    assert loaded["built_at"] == "2026-10-20T02:00:00.000Z" and loaded["modified_at"] == "2026-10-21T09:00:00.000Z"
    assert loaded["model"]["users"][0]["groups"] == []
    assert audit_store.update_opa_model_cache(OTHER, corrected) is False


# -- lifecycle -------------------------------------------------------------------------------------------------------
def _register(name="dev"):
    return engine.upsert_environment(
        name, {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "k", "key_secret": "s"}, owner=engine.LOCAL_OWNER_KEY)[1]


def test_deleting_an_environment_removes_its_scan_and_keeps_the_sealed_evidence(db, fake_keyring):
    env_id = _register()
    audit_store.store_opa_model_cache(env_id, _model())
    audit_store.record_config_snapshot(env_id, "opa_access_state", [("k", {"a": 1})])
    result = engine.delete_environment("dev", owner=engine.LOCAL_OWNER_KEY)
    assert result["opa_scan_removed"] is True
    assert audit_store.load_opa_model_cache(env_id) is None
    assert len(audit_store.list_config_snapshots(env_id)) == 1  # evidence kept as an orphan archive


def test_deleting_with_the_archive_removes_both(db, fake_keyring):
    env_id = _register()
    audit_store.store_opa_model_cache(env_id, _model())
    audit_store.record_config_snapshot(env_id, "opa_access_state", [("k", {"a": 1})])
    engine.delete_environment("dev", owner=engine.LOCAL_OWNER_KEY, purge_archive=True)
    assert audit_store.load_opa_model_cache(env_id) is None and audit_store.list_config_snapshots(env_id) == []


def test_a_failure_removing_the_scan_does_not_undo_the_delete(db, fake_keyring, monkeypatch):
    env_id = _register()
    monkeypatch.setattr(audit_store, "delete_opa_model_cache", lambda _id: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    result = engine.delete_environment("dev", owner=engine.LOCAL_OWNER_KEY)
    assert result["environment_id"] == env_id and result["opa_scan_removed"] is False
    assert engine.list_all_environments().get(env_id) is None


def test_purging_an_orphan_archive_empties_the_scan_table_too(db):
    audit_store.store_opa_model_cache(ENV, _model())
    assert audit_store.archive_has_rows(ENV)
    assert [o["environment_id"] for o in audit_store.list_orphaned_archives()] == [ENV]
    assert audit_store.list_orphaned_archives()[0]["opa_scan_cached"] is True
    counts = audit_store.purge_environment_archive(ENV)
    assert counts["opa_model_cache"] == 1 and audit_store.load_opa_model_cache(ENV) is None
    assert not audit_store.archive_has_rows(ENV)


def test_purging_one_environment_leaves_another_scan(db):
    audit_store.store_opa_model_cache(ENV, _model())
    audit_store.store_opa_model_cache(OTHER, _model())
    audit_store.purge_environment_archive(ENV)
    assert audit_store.load_opa_model_cache(OTHER) is not None


def test_the_start_up_sweep_removes_only_scans_of_environments_that_are_gone(db, fake_keyring):
    live = _register()
    audit_store.store_opa_model_cache(live, _model())
    audit_store.store_opa_model_cache(ENV, _model())
    audit_store.store_opa_model_cache(OTHER, _model())
    assert sorted(audit_store.sweep_orphaned_opa_model_caches()) == sorted([ENV, OTHER])
    assert audit_store.load_opa_model_cache(live) is not None and audit_store.load_opa_model_cache(ENV) is None
    assert audit_store.sweep_orphaned_opa_model_caches() == []


def test_retention_never_touches_the_scan_or_the_daily_access_state(db):
    audit_store.store_opa_model_cache(ENV, _model())
    audit_store.record_config_snapshot(ENV, "opa_access_state", [("user:u1", {"id": "u1"})], captured_at="2020-01-01T00:00:00.000Z")
    audit_store.prune_events(ENV, retention_days=1, max_size_mb=0.001)
    assert audit_store.load_opa_model_cache(ENV) is not None
    assert len(audit_store.list_config_snapshots(ENV, kind="opa_access_state")) == 1


# -- the migration ---------------------------------------------------------------------------------------------------
def test_migration_eleven_upgrades_a_5_50_database_without_touching_its_data(tmp_audit_store, tmp_environments_file, monkeypatch):
    full = dict(audit_store.MIGRATIONS)
    monkeypatch.setattr(audit_store, "MIGRATIONS", {k: v for k, v in full.items() if k <= 10})
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 10
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'opa_model_cache'").fetchone() is None
    audit_store.record_config_snapshot(ENV, "okta_admins", [("u", {"a": 1})])
    monkeypatch.setattr(audit_store, "MIGRATIONS", full)
    audit_store.run_migrations()
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 11
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'opa_model_cache'").fetchone() is not None
    assert len(audit_store.list_config_snapshots(ENV)) == 1 and audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]
    audit_store.run_migrations()  # idempotent


def test_a_scan_row_does_not_disturb_deep_verification(db):
    audit_store.store_opa_model_cache(ENV, _model())
    audit_store.record_config_snapshot(ENV, "opa_access_state", [("user:u1", {"id": "u1"})])
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


# -- 5.51.0 review H1: ordinary names must store; the shapes of real credentials still refuse ----------------------------------
ORDINARY_NAMES = [
    "sk-prod-db-01", "sk-web-server-1", "opk_gateway_eu1", "Prod-DB-Admins-ReadOnly-Policy-2026-Q4-Rev3",
    "ProdDbAdminsReadOnlyPolicy2026Q4Rev3Backup01", "arn-aws-iam-123456789012-role-ProdAdminRole-Q4",
    "Marketing-Team-Shared-Database-Readers-Group-2026", "SN-4F9K2X7M1Q8W3Z5T6V0B", "Platform-Engineering-Break-Glass-Access-Production-2026",
]


@pytest.mark.parametrize("name", ORDINARY_NAMES)
def test_ordinary_names_are_stored_untouched_in_every_name_field(name):
    model = _model(servers=[{"id": "s1", "hostname": name, "display_name": name}], groups=[{"id": "g1", "name": name, "roles": []}],
                   users=[{"id": "u1", "name": name, "details": {"displayName": name}}],
                   policies=[{"id": "p1", "name": name, "active": True, "rules": [], "description": name}],
                   devices=[{"id": "d1", "profile": {"displayName": name, "serialNumber": name, "model": name, "manufacturer": name}}])
    out, hits = engine.redact_model_for_storage_report(model)
    assert hits == [] and out["servers"][0]["hostname"] == name and out["policies"][0]["name"] == name
    assert out["groups"][0]["name"] == name and out["devices"][0]["profile"]["serialNumber"] == name
    assert engine.redact_model_for_storage(model)["policies"][0]["name"] == name


@pytest.mark.parametrize("name", [n for n in ORDINARY_NAMES if not n.startswith("ProdDbAdmins")])  # an unseparated 44-character mixed-case name is only safe under a name field
def test_ordinary_names_under_other_keys_pass_too(name):
    assert engine.redact_model_for_storage(_model(users=[{"id": "u1", "details": {"notes": [{"free_text": name}]}}]))["users"][0]["details"]["notes"][0]["free_text"] == name


def test_a_prefix_shaped_value_under_a_name_field_is_replaced_and_the_scan_continues():
    model = _model(servers=[{"id": "s1", "hostname": OPK_SECRET}, {"id": "s2", "hostname": "web-01"}], groups=[{"id": "g1", "name": "ghp_abcdefghijklmnop"}])
    out, hits = engine.redact_model_for_storage_report(model)
    assert out["servers"][0]["hostname"] == "[redacted]" and out["servers"][1]["hostname"] == "web-01" and out["groups"][0]["name"] == "[redacted]"
    assert sorted(hits) == ["groups[0].name", "servers[0].hostname"]
    assert any(w.get("status") == "redacted" and "removed" in w["message"] for w in out["warnings"])
    assert OPK_SECRET not in json.dumps(out)


def test_an_exact_shape_still_refuses_under_a_name_field_and_a_heuristic_hit_elsewhere_still_refuses():
    for exact in (JWT, SSWS):
        with pytest.raises(engine.ModelRedactionError) as caught:
            engine.redact_model_for_storage(_model(servers=[{"id": "s1", "hostname": exact}]))
        assert caught.value.key_path == "servers[0].hostname"
    with pytest.raises(engine.ModelRedactionError):
        engine.redact_model_for_storage(_model(servers=[{"id": "s1", "details": {"owner_note": OPK_SECRET}}]))
    with pytest.raises(engine.ModelRedactionError):
        engine.redact_model_for_storage(_model(servers=[{"id": "s1", "details": {"owner_note": LONG_SECRET}}]))


@pytest.mark.parametrize("key", ["project_name", "resourceGroupName", "server_name", "owner_label", "canonical_name"])
def test_name_like_keys_are_recognised_by_suffix(key):
    out, hits = engine.redact_model_for_storage_report(_model(servers=[{"id": "s1", key: "ProdDbAdminsReadOnlyPolicy2026Q4Rev3Backup01"}]))
    assert hits == [] and out["servers"][0][key] == "ProdDbAdminsReadOnlyPolicy2026Q4Rev3Backup01"


# -- re-check N1 and N2 ------------------------------------------------------------------------------------------------------------------
LONG_NAME = "ProdDbAdminsReadOnlyPolicy2026Q4Rev3Backup01"


def test_label_values_alternative_names_and_rule_candidates_are_names_too():
    model = _model(servers=[{"id": "s1", "hostname": "web-01", "labels": {"env": LONG_NAME}, "alt_names": [LONG_NAME], "tags": [LONG_NAME], "aliases": [LONG_NAME]}],
                   policies=[{"id": "p1", "name": "p", "active": True, "rules": [{"name": "r", "conditions": [{"candidates": [LONG_NAME]}], "resolutions": []}]}])
    out, hits = engine.redact_model_for_storage_report(model)
    assert hits == []
    assert out["servers"][0]["labels"]["env"] == LONG_NAME and out["servers"][0]["alt_names"] == [LONG_NAME]
    assert out["policies"][0]["rules"][0]["conditions"][0]["candidates"] == [LONG_NAME]


def _random_alnum(n):
    import secrets
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789") for _ in range(n - 1)) + "7"


def _synthetic_keys():
    # generated on the fly: shaped like real provider keys, never a real key
    return {
        "sk-proj": "sk-proj-" + _random_alnum(40) + "_" + _random_alnum(30),
        "sk-ant": "sk-ant-api03-" + _random_alnum(48) + "-" + _random_alnum(40),
        "sk-plain": "sk-" + _random_alnum(40),
        "github_pat": "github_pat_" + _random_alnum(22) + "_" + _random_alnum(59),
    }


@pytest.mark.parametrize("kind", ["sk-proj", "sk-ant", "sk-plain", "github_pat"])
def test_hyphen_segmented_provider_keys_are_redacted_under_a_name_field_and_refused_elsewhere(kind):
    secret = _synthetic_keys()[kind]
    out, hits = engine.redact_model_for_storage_report(_model(servers=[{"id": "s1", "hostname": secret}]))
    assert out["servers"][0]["hostname"] == "[redacted]" and hits == ["servers[0].hostname"] and secret not in json.dumps(out)
    with pytest.raises(engine.ModelRedactionError) as caught:
        engine.redact_model_for_storage(_model(servers=[{"id": "s1", "details": {"owner_note": secret}}]))
    assert caught.value.key_path == "servers[0].details.owner_note" and secret not in str(caught.value)


@pytest.mark.parametrize("name", ["sk-prod-db-01", "sk-web-server-1", "sk-prod-eu-west-payments-db-01", "opk_gateway_eu1", "sk-proj-payments-team", "github-pat-rotation-runbook"])
def test_names_that_start_like_a_key_still_store(name):
    out, hits = engine.redact_model_for_storage_report(_model(servers=[{"id": "s1", "hostname": name, "details": {"owner_note": name}}]))
    assert hits == [] and out["servers"][0]["hostname"] == name and out["servers"][0]["details"]["owner_note"] == name


# -- exact shapes are found INSIDE strings too (a header, a sentence), refusing everywhere -------------------------------------------
@pytest.mark.parametrize("wrap", ["{t}", "SSWS {t}", "Authorization: SSWS {t}", "my token is {t} please keep it", "token={t};"])
@pytest.mark.parametrize("token", [SSWS, JWT])
@pytest.mark.parametrize("where", [("servers", "hostname"), ("servers", "details.owner_note")])
def test_an_exact_token_shape_inside_a_string_refuses_under_a_name_key_and_elsewhere(wrap, token, where):
    collection, key = where
    record = {"id": "s1"}
    if "." in key:
        record["details"] = {"owner_note": wrap.format(t=token)}
    else:
        record[key] = wrap.format(t=token)
    with pytest.raises(engine.ModelRedactionError) as caught:
        engine.redact_model_for_storage(_model(**{collection: [record]}))
    assert token not in str(caught.value)


@pytest.mark.parametrize("fine", [
    "00" + "a1b2c3d4" * 7 + "a1b2c3",  # a 64-hex digest that happens to start with 00
    "0f" * 20,  # a 40-hex sha1
    "sha1:" + "0f" * 20,
    "Production Linux servers owned by the platform team",
])
def test_digests_and_ordinary_text_store(fine):
    assert len(fine) != 42
    out = engine.redact_model_for_storage(_model(servers=[{"id": "s1", "hostname": "web-01", "details": {"owner_note": fine}}]))
    assert out["servers"][0]["details"]["owner_note"] == fine


# -- 5.52.0 hardening (H1-H3) -----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("key", ["api_key", "apikey", "secret_key", "access_key", "passwd", "API_KEY"])
def test_more_credential_keys_are_dropped_at_any_depth(key):
    model = _model(servers=[{"id": "s1", "hostname": "web-01", key: "x", "details": {"deep": {key: "x", "keep": "ok"}},
                             "labels": {"inner": {key: "x", "other": "fine"}}}])
    out = engine.redact_model_for_storage(model)
    server = out["servers"][0]
    assert key not in server and key not in server["details"]["deep"] and key not in server["labels"]["inner"]
    assert server["details"]["deep"]["keep"] == "ok" and server["labels"]["inner"]["other"] == "fine"


def test_a_name_like_key_still_covers_a_string_or_a_list_of_strings_directly_under_it():
    out, hits = engine.redact_model_for_storage_report(_model(servers=[{"id": "s1", "labels": {"env": LONG_NAME, "more": [LONG_NAME]}, "tags": [LONG_NAME]}]))
    assert hits == [] and out["servers"][0]["labels"]["env"] == LONG_NAME and out["servers"][0]["labels"]["more"] == [LONG_NAME]


def test_a_nested_object_under_a_name_like_key_does_not_inherit_name_status():
    with pytest.raises(engine.ModelRedactionError) as caught:
        engine.redact_model_for_storage(_model(servers=[{"id": "s1", "labels": {"inner": {"blob": LONG_SECRET}}}]))
    assert caught.value.key_path == "servers[0].labels.inner.blob" and LONG_SECRET not in str(caught.value)


def test_a_list_of_objects_under_a_name_like_key_does_not_inherit_name_status():
    with pytest.raises(engine.ModelRedactionError):
        engine.redact_model_for_storage(_model(servers=[{"id": "s1", "tags": [{"blob": LONG_SECRET}]}]))


def test_an_api_key_nested_under_a_name_like_key_is_dropped_not_refused():
    out = engine.redact_model_for_storage(_model(servers=[{"id": "s1", "labels": {"inner": {"api_key": LONG_SECRET}}}]))
    assert out["servers"][0]["labels"]["inner"] == {} and LONG_SECRET not in json.dumps(out)


@pytest.mark.parametrize("after_prefix,refused", [(40, True), (42, True), (44, True), (45, False)])
def test_an_okta_token_shape_is_40_to_44_characters_after_00(after_prefix, refused):
    token = "00" + ("aB3_-" * 10)[:after_prefix]
    record = {"id": "s1", "details": {"owner_note": f"token {token} end"}}
    if refused:
        with pytest.raises(engine.ModelRedactionError):
            engine.redact_model_for_storage(_model(servers=[record]))
    else:
        assert engine.redact_model_for_storage(_model(servers=[record]))["servers"][0]["details"]["owner_note"].find(token) > 0


@pytest.mark.parametrize("digest", ["00" + "a1b2c3d4" * 7 + "a1b2c3", "0f" * 20, "00" + "9f" * 19])
def test_a_sha1_and_a_64_hex_digest_still_store_with_the_wider_token_shape(digest):
    out = engine.redact_model_for_storage(_model(servers=[{"id": "s1", "details": {"owner_note": digest}}]))
    assert out["servers"][0]["details"]["owner_note"] == digest
