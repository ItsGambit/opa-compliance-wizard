"""5.42.0: admin-configurable permissions for shared environments (storage,
resolution, migration 008) and the action-type filter on pending actions.
The per-route enforcement and the step-up flow are driven over HTTP in
tests/test_http_authz_matrix.py."""
import sqlite3

import pytest

import audit_store
import create_secret_folders as engine

OWNER = "00uOWNER"
OTHER = "00uOTHER"

# What a shared, non-owner user could do before 5.42.0 (from the route
# inventory in the release plan): everything an activated session allows,
# CSV import and watermark reset included; never the owner-only sync routes.
BEHAVIOUR_BEFORE_5_42 = {
    "view_archive": "allow", "live_read": "allow", "tenant_write": "allow",
    "import_csv": "allow", "reset_watermark": "allow",
    "sync_now": "deny", "sync_settings": "deny",
}


@pytest.fixture
def db(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=OWNER)
    engine.set_environment_shared("dev", OWNER, True)
    return env_id


def test_built_in_defaults_are_exactly_the_behaviour_before_the_feature():
    assert {c["key"]: c["builtin"] for c in engine.SHARED_CAPABILITIES} == BEHAVIOUR_BEFORE_5_42


def test_a_fresh_upgrade_resolves_every_capability_to_its_built_in_default(db):
    effective = engine.effective_shared_permissions(db)
    assert {k: v["value"] for k, v in effective.items()} == BEHAVIOUR_BEFORE_5_42
    assert {v["source"] for v in effective.values()} == {"built_in"}


def test_resolution_order_is_override_then_global_then_built_in(db):
    engine.set_shared_permissions({"live_read": "deny", "sync_now": "allow"})
    engine.set_shared_permissions({"live_read": "allow"}, environment_id=db)
    eff = engine.effective_shared_permissions(db)
    assert eff["live_read"] == {"value": "allow", "source": "override"}
    assert eff["sync_now"] == {"value": "allow", "source": "default"}
    assert eff["tenant_write"] == {"value": "allow", "source": "built_in"}
    assert engine.shared_capability_allowed(db, OTHER, "sync_now") is True
    engine.set_shared_permissions({"sync_now": "inherit"})
    assert engine.shared_capability_allowed(db, OTHER, "sync_now") is False


def test_owners_are_never_limited(db):
    engine.set_shared_permissions({k: "deny" for k in engine.SHARED_CAPABILITY_KEYS})
    engine.set_shared_permissions({k: "deny" for k in engine.SHARED_CAPABILITY_KEYS}, environment_id=db)
    assert all(engine.shared_capability_allowed(db, OWNER, k) for k in engine.SHARED_CAPABILITY_KEYS)
    assert not any(engine.shared_capability_allowed(db, OTHER, k) for k in engine.SHARED_CAPABILITY_KEYS)


def test_local_owner_is_an_owner_like_any_other(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"})
    engine.set_shared_permissions({"live_read": "deny"})
    assert engine.shared_capability_allowed(env_id, engine.LOCAL_OWNER_KEY, "live_read") is True
    engine.set_environment_shared("dev", engine.LOCAL_OWNER_KEY, True)
    assert engine.shared_capability_allowed(env_id, OTHER, "live_read") is False


def test_unknown_environment_or_capability(db):
    assert engine.shared_capability_allowed("no-such-id", OWNER, "live_read") is False
    with pytest.raises(ValueError):
        engine.shared_capability_allowed(db, OWNER, "everything")
    with pytest.raises(KeyError):
        engine.set_shared_permissions({"live_read": "deny"}, environment_id="no-such-id")


@pytest.mark.parametrize("changes", [{}, None, [], {"live_read": "maybe"}, {"bogus": "allow"}, {"live_read": True}])
def test_invalid_changes_are_refused_and_nothing_is_written(db, changes):
    with pytest.raises(ValueError):
        engine.set_shared_permissions(changes)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_defaults").fetchone()[0] == 0


def test_set_reports_stored_before_and_after_and_skips_no_ops(db):
    assert engine.set_shared_permissions({"live_read": "deny", "sync_now": "inherit"}) == [
        {"capability": "live_read", "before": "inherit", "after": "deny"}]
    assert engine.set_shared_permissions({"live_read": "allow"}) == [
        {"capability": "live_read", "before": "deny", "after": "allow"}]
    assert engine.set_shared_permissions({"live_read": "allow"}) == []
    assert engine.set_shared_permissions({"live_read": "inherit"}, environment_id=db) == []
    assert engine.set_shared_permissions({"live_read": "deny"}, environment_id=db) == [
        {"capability": "live_read", "before": "inherit", "after": "deny"}]
    assert engine.get_shared_permission_overrides(db) == {"live_read": "deny"}


def test_a_failed_change_writes_nothing(db, monkeypatch):
    """One transaction: a failure part-way leaves every value as it was."""
    engine.set_shared_permissions({"live_read": "deny"})
    real = audit_store._get_connection()

    class Flaky:
        def __init__(self, conn):
            self.conn, self.calls = conn, 0

        def execute(self, sql, *a):
            if sql.lstrip().startswith(("INSERT", "DELETE")):
                self.calls += 1
                if self.calls == 2:
                    raise sqlite3.OperationalError("disk I/O error")
            return self.conn.execute(sql, *a)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    flaky = Flaky(real)
    with monkeypatch.context() as patch:
        patch.setattr(audit_store, "_get_connection", lambda: flaky)
        with pytest.raises(sqlite3.OperationalError):
            engine.set_shared_permissions({"live_read": "allow", "tenant_write": "deny"})
    assert engine.get_shared_permission_defaults()["live_read"]["value"] == "deny"
    assert engine.get_shared_permission_defaults()["tenant_write"]["source"] == "built_in"


def test_stray_rows_are_ignored_on_read(db):
    """A capability a later version adds and an older one doesn't know (a
    rollback) is ignored, not an error."""
    conn = audit_store._get_connection()
    conn.execute("INSERT INTO shared_permission_defaults VALUES ('from_the_future', 'deny', 'x', NULL)")
    conn.execute("INSERT INTO shared_permission_overrides VALUES (?, 'from_the_future', 'allow', 'x', NULL)", (db,))
    conn.commit()
    assert "from_the_future" not in engine.get_shared_permission_defaults()
    assert engine.get_shared_permission_overrides(db) == {}


# --- migration 008 -------------------------------------------------------------
def _tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _schema_sql(conn, names):
    return {r[0]: r[1] for r in conn.execute("SELECT name, sql FROM sqlite_master WHERE name IN (%s)"
                                                 % ",".join("?" * len(names)), names)}


def test_migration_008_is_additive_and_leaves_the_evidence_chain_alone(tmp_audit_store):
    conn = audit_store._get_connection()
    conn.execute("BEGIN IMMEDIATE")
    for version in range(1, 8):
        audit_store.MIGRATIONS[version](conn)
        conn.execute("INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, 'x')", (version,))
    conn.commit()
    conn.execute("""INSERT INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name,
                    key_id, okta_url, shared, created_at, updated_at)
                    VALUES ('e1', 'o', 'dev', 'b', 't', 'k', '', 1, 'x', 'x')""")
    conn.execute("INSERT INTO ingestion_manifests (environment_id, source, since, until, row_count, created_at, "
                 "batch_hash, prev_manifest_hash) VALUES ('e1', 'live', 'a', 'b', 0, 'x', 'h', 'p')")
    conn.commit()
    chain = ["events", "event_targets", "sync_state", "ingestion_manifests", "manifest_entries", "chain_heads"]
    before_sql = _schema_sql(conn, chain)
    before_rows = conn.execute("SELECT * FROM ingestion_manifests").fetchall()
    before_tables = _tables(conn)

    audit_store.run_migrations()
    assert audit_store._schema_version(conn) == 8
    assert _tables(conn) - before_tables == {"shared_permission_defaults", "shared_permission_overrides"}
    assert _schema_sql(conn, chain) == before_sql
    assert [tuple(r) for r in conn.execute("SELECT * FROM ingestion_manifests")] == [tuple(r) for r in before_rows]
    # Both start empty: every capability is at its built-in default after an upgrade.
    assert conn.execute("SELECT COUNT(*) FROM shared_permission_defaults").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM shared_permission_overrides").fetchone()[0] == 0
    # Idempotent: a re-run (or the migration function itself again) is harmless.
    audit_store.run_migrations()
    audit_store.MIGRATIONS[8](conn)
    assert audit_store._schema_version(conn) == 8


def test_migration_008_constraints(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO shared_permission_defaults VALUES ('live_read', 'inherit', 'x', NULL)")
    conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):  # foreign key: no such environment
        conn.execute("INSERT INTO shared_permission_overrides VALUES ('nope', 'live_read', 'deny', 'x', NULL)")
    conn.rollback()


def test_overrides_are_removed_with_their_environment(db):
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db)
    engine.delete_environment("dev", owner=OWNER)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_overrides").fetchone()[0] == 0


# --- schedules by id ------------------------------------------------------------
def test_schedule_by_id_reads_and_writes_exactly_that_environment(tmp_audit_store, fake_keyring):
    """Two owner-less environments with the same display name (UNIQUE never
    matches NULL owners -- the class behind the 2026-10-09 502): by-name
    lookups pick one of them, by-id lookups the one asked for."""
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    for env_id in ("e1", "e2"):
        conn.execute("""INSERT INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name,
                        key_id, okta_url, shared, created_at, updated_at)
                        VALUES (?, NULL, 'dev', 'b', 't', 'k', '', 0, 'x', 'x')""", (env_id,))
    conn.commit()
    engine.set_sync_schedule_by_id("e2", {"run_time": "05:00", "ingestion_scope": "all"})
    assert engine.get_sync_schedule_by_id("e2")["run_time"] == "05:00"
    assert engine.get_sync_schedule_by_id("e1")["run_time"] == engine.SYNC_SCHEDULE_DEFAULTS["run_time"]
    with pytest.raises(KeyError):
        engine.get_sync_schedule_by_id("e3")
    with pytest.raises(ValueError):
        engine.set_sync_schedule_by_id("e1", {"run_time": "25:00"})


# --- pending actions: the action-type filter ------------------------------------
def test_consume_with_an_action_type_filter(tmp_audit_store):
    audit_store.run_migrations()
    env_action = audit_store.create_pending_admin_action(OWNER, "environment.share", {"x": 1}, ttl_seconds=60)
    with pytest.raises(audit_store.PendingActionError) as exc:
        audit_store.consume_pending_admin_action(env_action, OWNER, action_types=("access_control.update",))
    assert exc.value.reason == "action_type_mismatch"
    # ...left untouched, so its own route can still apply it once.
    assert audit_store.consume_pending_admin_action(env_action, OWNER, action_types=("environment.share",)) == {"x": 1}
    with pytest.raises(audit_store.PendingActionError) as exc:
        audit_store.consume_pending_admin_action(env_action, OWNER, action_types=("environment.share",))
    assert exc.value.reason == "already_consumed"
    # No filter: the old behaviour.
    other = audit_store.create_pending_admin_action(OWNER, "anything", {"y": 2}, ttl_seconds=60)
    assert audit_store.consume_pending_admin_action(other, OWNER) == {"y": 2}


# --- upsert dry run / expected target (5.42.0 step-up) -----------------------------
GOOD = {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}


def test_upsert_dry_run_writes_nothing_and_reports_the_target(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    assert engine.upsert_environment("dev", GOOD, owner=OWNER, dry_run=True) == ("dev", None)
    assert engine.list_all_environments() == {} and fake_keyring == {}
    _, env_id = engine.upsert_environment("dev", GOOD, owner=OWNER)
    assert engine.upsert_environment("dev", {**GOOD, "team_name": "t2"}, owner=OWNER, dry_run=True) == ("dev", env_id)
    assert engine.list_all_environments()[env_id]["team_name"] == "t"
    with pytest.raises(ValueError):
        engine.upsert_environment("dev", {**GOOD, "base_domain": "x.example.com/evil"}, owner=OWNER, dry_run=True)


def test_upsert_dry_run_inside_a_callers_transaction_keeps_that_transaction(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO banner_config (id, enabled, message) VALUES (1, 1, 'kept')")
    engine.upsert_environment("dev", GOOD, owner=OWNER, dry_run=True)
    assert conn.in_transaction
    conn.commit()
    assert conn.execute("SELECT message FROM banner_config").fetchone()[0] == "kept"
    assert engine.list_all_environments() == {}


def test_upsert_refuses_a_different_target_than_expected(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    with pytest.raises(engine.EnvironmentTargetChanged):
        engine.upsert_environment("dev", GOOD, owner=OWNER, expected_target_id="some-id")
    assert engine.list_all_environments() == {} and fake_keyring == {}
    _, env_id = engine.upsert_environment("dev", GOOD, owner=OWNER, expected_target_id=None)
    with pytest.raises(engine.EnvironmentTargetChanged):
        engine.upsert_environment("dev", {**GOOD, "team_name": "t2"}, owner=OWNER, expected_target_id=None)
    engine.upsert_environment("dev", {**GOOD, "team_name": "t2"}, owner=OWNER, expected_target_id=env_id)
    assert engine.list_all_environments()[env_id]["team_name"] == "t2"


def test_archive_has_rows_covers_every_table_the_purge_empties(tmp_audit_store):
    audit_store.run_migrations()
    assert audit_store.archive_has_rows("nope") is False
    conn = audit_store._get_connection()
    conn.execute("INSERT INTO chain_heads VALUES ('orph', 1, 'h', 'x')")
    conn.commit()
    assert audit_store.archive_has_rows("orph") is True
