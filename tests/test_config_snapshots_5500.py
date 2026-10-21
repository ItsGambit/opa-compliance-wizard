"""5.50.0 chained configuration snapshots: storage, sealing into the evidence chain,
tamper detection (deep integrity), diff, as-of lookup, purge and export."""
import pytest

import audit_store

ENV = "33333333-3333-3333-3333-333333333333"
OTHER = "44444444-4444-4444-4444-444444444444"


@pytest.fixture
def db(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()


def _snap(items, env=ENV, kind="okta_admins", at="2026-10-01T00:00:00.000Z", **kw):
    return audit_store.record_config_snapshot(env, kind, list(items.items()), captured_at=at, **kw)


def test_a_snapshot_is_sealed_and_verifies_deeply(db):
    snap = _snap({"u1": {"role": "SUPER_ADMIN"}, "u2": {"role": "ORG_ADMIN"}})
    assert snap["item_count"] == 2 and snap["status"] == "ok" and snap["manifest_id"]
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] and result["verified_rows"] == 2 and result["manifest_count"] == 1
    assert audit_store.verify_config_snapshot(ENV, snap["snapshot_id"]) == {"valid": True, "reason": None}
    assert audit_store.verify_ingestion_chain(ENV)["head_hash"] == snap["chain_head"]


def test_a_snapshot_chains_to_the_event_chain(db):
    audit_store.sync_okta_events(type("C", (), {
        "get_system_log": lambda self, **k: ([], True), "get_system_log_page": lambda self, p: ([], None)})(), ENV, "all")
    first = audit_store.verify_ingestion_chain(ENV)["head_hash"]
    snap = _snap({"u1": {"a": 1}})
    row = audit_store._get_connection().execute(
        "SELECT prev_manifest_hash FROM ingestion_manifests WHERE id = ?", (snap["manifest_id"],)).fetchone()
    assert row["prev_manifest_hash"] == first
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_a_refused_attempt_is_sealed_with_no_items(db):
    snap = audit_store.record_config_snapshot(ENV, "okta_admins", [], status="refused", meta={"error_code": "E0000006"})
    assert snap["item_count"] == 0 and snap["meta"] == {"error_code": "E0000006"}
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]
    assert audit_store.latest_config_snapshot(ENV, "okta_admins") is None  # an attempt is not a state
    assert audit_store.latest_config_snapshot(ENV, "okta_admins", only_ok=False)["status"] == "refused"
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [("k", {})], status="refused")


def _tamper(sql, params=()):
    conn = audit_store._get_connection()
    conn.execute(sql, params)
    conn.commit()


def test_editing_an_object_is_detected(db):
    _snap({"u1": {"role": "READ_ONLY_ADMIN"}})
    _tamper("""UPDATE config_snapshot_items SET json = '{"role":"NONE"}'""")
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert not result["valid"] and "snapshot object u1" in result["reason"]
    assert audit_store.verify_ingestion_chain(ENV)["valid"]  # the shallow check cannot see content, as for events


def test_deleting_an_object_is_detected(db):
    snap = _snap({"u1": {"a": 1}, "u2": {"a": 2}})
    _tamper("DELETE FROM config_snapshot_items WHERE item_key = 'u2'")
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert not result["valid"] and "holds 1 objects but 2 were sealed" in result["reason"]
    assert not audit_store.verify_config_snapshot(ENV, snap["snapshot_id"])["valid"]


def test_adding_an_object_after_sealing_is_detected(db):
    snap = _snap({"u1": {"a": 1}})
    import json
    text = json.dumps({"a": 9})
    _tamper("INSERT INTO config_snapshot_items (snapshot_id, environment_id, item_key, sha, json) VALUES (?,?,?,?,?)",
            (snap["snapshot_id"], ENV, "intruder", audit_store._content_sha256(text), text))
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert not result["valid"] and "holds 2 objects but 1 were sealed" in result["reason"]


def test_removing_a_whole_snapshot_is_detected(db):
    snap = _snap({"u1": {"a": 1}})
    _tamper("DELETE FROM config_snapshot_items")
    _tamper("DELETE FROM config_snapshots")
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert not result["valid"] and "removed after it was sealed" in result["reason"]
    assert snap["snapshot_id"]


def test_removing_the_manifest_of_a_snapshot_is_detected(db):
    _snap({"u1": {"a": 1}}, at="2026-10-01T00:00:00.000Z")
    _snap({"u1": {"a": 2}}, at="2026-10-02T00:00:00.000Z")
    first = audit_store._get_connection().execute("SELECT MIN(id) FROM ingestion_manifests").fetchone()[0]
    _tamper("DELETE FROM manifest_entries WHERE manifest_id = ?", (first,))
    _tamper("DELETE FROM ingestion_manifests WHERE id = ?", (first,))
    assert not audit_store.verify_ingestion_chain(ENV)["valid"]


def test_a_snapshot_stored_with_the_wrong_manifest_is_detected(db):
    a = _snap({"u1": {"a": 1}}, at="2026-10-01T00:00:00.000Z")
    _snap({"u1": {"a": 2}}, at="2026-10-02T00:00:00.000Z")
    _tamper("UPDATE config_snapshots SET manifest_id = manifest_id + 1 WHERE snapshot_id = ?", (a["snapshot_id"],))
    assert not audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]


def test_a_failed_write_leaves_neither_snapshot_nor_seal(db, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk")
    monkeypatch.setattr(audit_store, "_write_manifest_row", boom)
    with pytest.raises(RuntimeError):
        _snap({"u1": {"a": 1}})
    conn = audit_store._get_connection()
    assert conn.execute("SELECT COUNT(*) FROM config_snapshots").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM config_snapshot_items").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM ingestion_manifests").fetchone()[0] == 0


def test_diff_added_removed_changed(db):
    a = _snap({"u1": {"role": "SUPER_ADMIN"}, "u2": {"role": "ORG_ADMIN"}, "u3": {"role": "X"}}, at="2026-10-01T00:00:00.000Z")
    b = _snap({"u1": {"role": "SUPER_ADMIN"}, "u2": {"role": "READ_ONLY_ADMIN"}, "u4": {"role": "Y"}}, at="2026-10-02T00:00:00.000Z")
    d = audit_store.diff_config_snapshots(ENV, a["snapshot_id"], b["snapshot_id"])
    assert [x["key"] for x in d["added"]] == ["u4"] and [x["key"] for x in d["removed"]] == ["u3"]
    assert d["changed"][0]["key"] == "u2" and d["changed"][0]["fields"] == ["role"] and d["unchanged"] == 1


def test_diff_refuses_other_kinds_unknown_ids_and_other_environments(db):
    a = _snap({"u1": {}}, kind="okta_admins")
    b = _snap({"u1": {}}, kind="opa_principal_status")
    c = _snap({"u1": {}}, env=OTHER)
    with pytest.raises(ValueError):
        audit_store.diff_config_snapshots(ENV, a["snapshot_id"], b["snapshot_id"])
    with pytest.raises(ValueError):
        audit_store.diff_config_snapshots(ENV, a["snapshot_id"], c["snapshot_id"])  # another environment's id is "not found"
    with pytest.raises(ValueError):
        audit_store.diff_config_snapshots(ENV, a["snapshot_id"], 9999)
    assert audit_store.get_config_snapshot(ENV, c["snapshot_id"]) is None
    assert audit_store.get_config_snapshot(ENV, "abc") is None


def test_as_of_picks_the_newest_snapshot_at_or_before_the_date(db):
    _snap({"u1": {"v": 1}}, at="2026-10-01T10:00:00.000Z")
    _snap({"u1": {"v": 2}}, at="2026-10-03T10:00:00.000Z")
    assert audit_store.latest_config_snapshot(ENV, "okta_admins", as_of="2026-10-02")["items"][0]["object"] == {"v": 1}
    assert audit_store.latest_config_snapshot(ENV, "okta_admins", as_of="2026-10-03")["items"][0]["object"] == {"v": 2}  # bare date = end of day
    assert audit_store.latest_config_snapshot(ENV, "okta_admins", as_of="2026-09-01") is None
    assert audit_store.latest_config_snapshot(ENV, "okta_admins")["captured_at"].startswith("2026-10-03")
    with pytest.raises(ValueError):
        audit_store.latest_config_snapshot(ENV, "okta_admins", as_of="not a date")


@pytest.mark.parametrize("kind", ["", "Okta Admins", "x", "a/b", None, "1abc", "a" * 70])
def test_hostile_kinds_are_refused(db, kind):
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, kind, [])


def test_hostile_items_are_refused(db):
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [("k", {}), ("k", {})])  # duplicate
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [("", {})])
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [("a\nb", {})])
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [("k", {"big": "x" * (300 * 1024)})])
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [], status="weird")
    with pytest.raises(ValueError):
        audit_store.record_config_snapshot(ENV, "okta_admins", [], captured_at="never")
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM ingestion_manifests").fetchone()[0] == 0


def test_keys_with_colons_and_unicode_round_trip_and_verify(db):
    _snap({"orn:okta:x:1": {"label": "Zoë ☃"}, "k:with:colons": {"a": [1, 2]}})
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"]
    items = {i["key"]: i["object"] for i in audit_store.latest_config_snapshot(ENV, "okta_admins")["items"]}
    assert items["orn:okta:x:1"]["label"] == "Zoë ☃"


def test_a_large_snapshot_seals_and_verifies(db):
    _snap({f"user{i:05d}": {"i": i} for i in range(3000)})
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] and result["verified_rows"] == 3000


def test_purge_removes_snapshots_and_orphans_list_them(db):
    _snap({"u1": {"a": 1}})
    orphans = audit_store.list_orphaned_archives()
    assert [o["environment_id"] for o in orphans] == [ENV] and orphans[0]["snapshot_count"] == 1
    assert audit_store.archive_has_rows(ENV)
    counts = audit_store.purge_environment_archive(ENV)
    assert counts["config_snapshots"] == 1 and counts["config_snapshot_items"] == 1 and counts["ingestion_manifests"] == 1
    assert not audit_store.archive_has_rows(ENV)
    assert audit_store.list_config_snapshots(ENV) == []


def test_purge_of_one_environment_keeps_the_other(db):
    _snap({"u1": {"a": 1}})
    keep = _snap({"u1": {"a": 1}}, env=OTHER)
    audit_store.purge_environment_archive(ENV)
    assert audit_store.get_config_snapshot(OTHER, keep["snapshot_id"]) is not None
    assert audit_store.verify_ingestion_chain(OTHER, deep=True)["valid"]


def test_export_carries_everything_needed_to_recheck_a_snapshot(db):
    snap = _snap({"u1": {"a": 1}})
    out = audit_store.export_config_snapshot(ENV, snap["snapshot_id"])
    assert out["format"].endswith("/1") and out["sha256"] == snap["sha256"]
    assert out["manifest"]["entry_hash"] == snap["chain_head"] and out["items"][0]["sha"]
    assert audit_store.export_config_snapshot(OTHER, snap["snapshot_id"]) is None


def test_listing_is_newest_first_and_bounded(db):
    for day in range(1, 4):
        _snap({"u1": {"d": day}}, at=f"2026-10-0{day}T00:00:00.000Z")
    listed = audit_store.list_config_snapshots(ENV)
    assert [s["captured_at"][:10] for s in listed] == ["2026-10-03", "2026-10-02", "2026-10-01"]
    assert len(audit_store.list_config_snapshots(ENV, limit=1)) == 1
    with pytest.raises(ValueError):
        audit_store.list_config_snapshots(ENV, limit=0)


def test_event_deep_verify_is_unaffected_by_snapshots(db):
    audit_store._insert_rows(audit_store._get_connection(), ENV, [audit_store._normalize_live_event({
        "uuid": "e1", "eventType": "user.account.privilege.grant", "published": "2026-10-01T00:00:00.000Z",
        "actor": {}, "outcome": {}, "target": []})], "all")
    new_entries = [("e1", 1, audit_store._content_sha256(
        audit_store._get_connection().execute("SELECT raw_json FROM events").fetchone()[0]))]
    audit_store._record_ingestion_manifest(audit_store._get_connection(), ENV, "sync", None, None, new_entries)
    _snap({"u1": {"a": 1}})
    result = audit_store.verify_ingestion_chain(ENV, deep=True)
    assert result["valid"] and result["verified_rows"] == 2
