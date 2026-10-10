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

# The built-in defaults, pinned. 5.42.0 shipped exactly what a shared,
# non-owner user could do before (everything but the owner-only sync
# routes); 5.43.0 (SP-1, SP-2) denies writing to the owner's OPA team / Okta
# org and importing a CSV into the owner's archive unless an admin allows it.
BUILT_IN_DEFAULTS = {
    "view_archive": "allow", "live_read": "allow", "tenant_write": "deny",
    "import_csv": "deny", "reset_watermark": "allow",
    "sync_now": "deny", "sync_settings": "deny",
}


@pytest.fixture
def db(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=OWNER)
    engine.set_environment_shared("dev", OWNER, True)
    return env_id


def test_built_in_defaults_are_pinned():
    assert {c["key"]: c["builtin"] for c in engine.SHARED_CAPABILITIES} == BUILT_IN_DEFAULTS


def test_a_fresh_upgrade_resolves_every_capability_to_its_built_in_default(db):
    effective = engine.effective_shared_permissions(db)
    assert {k: v["value"] for k, v in effective.items()} == BUILT_IN_DEFAULTS
    assert engine.shared_capability_allowed(db, OTHER, "tenant_write") is False
    assert engine.shared_capability_allowed(db, OTHER, "import_csv") is False
    assert engine.shared_capability_allowed(db, OWNER, "tenant_write") is True
    assert {v["source"] for v in effective.values()} == {"built_in"}


def test_resolution_order_is_override_then_global_then_built_in(db):
    engine.set_shared_permissions({"live_read": "deny", "sync_now": "allow"})
    engine.set_shared_permissions({"live_read": "allow"}, environment_id=db)
    eff = engine.effective_shared_permissions(db)
    assert eff["live_read"] == {"value": "allow", "source": "override"}
    assert eff["sync_now"] == {"value": "allow", "source": "default"}
    assert eff["tenant_write"] == {"value": "deny", "source": "built_in"}
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
    assert audit_store._schema_version(conn) == max(audit_store.MIGRATIONS)
    assert _tables(conn) - before_tables == {"shared_permission_defaults", "shared_permission_overrides",
                                             "shared_permission_grants", "known_identities"}
    assert _schema_sql(conn, chain) == before_sql
    assert [tuple(r) for r in conn.execute("SELECT * FROM ingestion_manifests")] == [tuple(r) for r in before_rows]
    # Both start empty: every capability is at its built-in default after an upgrade.
    assert conn.execute("SELECT COUNT(*) FROM shared_permission_defaults").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM shared_permission_overrides").fetchone()[0] == 0
    # Idempotent: a re-run (or the migration function itself again) is harmless.
    audit_store.run_migrations()
    audit_store.MIGRATIONS[8](conn)
    audit_store.MIGRATIONS[9](conn)
    assert audit_store._schema_version(conn) == max(audit_store.MIGRATIONS)


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


# --- per-user exceptions (5.43.0, migration 009) --------------------------------
MAIN_ISS = "https://main.example.com/oauth2/default"
SECOND_ISS = "https://login.example.org"
USER = {"issuer": SECOND_ISS, "subject": OTHER}


def test_precedence_is_user_then_override_then_global_then_built_in(db):
    def value(issuer=SECOND_ISS):
        return engine.effective_shared_permissions(db, caller_issuer=issuer, caller_subject=OTHER)["sync_now"]

    assert value() == {"value": "deny", "source": "built_in"}
    engine.set_shared_permissions({"sync_now": "allow"})
    assert value() == {"value": "allow", "source": "default"}
    engine.set_shared_permissions({"sync_now": "deny"}, environment_id=db)
    assert value() == {"value": "deny", "source": "override"}
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER)
    assert value() == {"value": "allow", "source": "user"}
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer=SECOND_ISS) is True
    # A user deny beats an environment allow too.
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db)
    engine.set_shared_permissions({"sync_now": "deny"}, environment_id=db, grantee=USER)
    assert value() == {"value": "deny", "source": "user"}
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer=SECOND_ISS) is False
    # Back to inherit: the environment's override applies again.
    engine.set_shared_permissions({"sync_now": "inherit"}, environment_id=db, grantee=USER)
    assert value() == {"value": "allow", "source": "override"}
    # Grants are per capability: the others still resolve as before.
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER)
    assert engine.effective_shared_permissions(db, caller_issuer=SECOND_ISS, caller_subject=OTHER)["tenant_write"] == {
        "value": "deny", "source": "built_in"}


def test_a_grant_never_matches_the_same_sub_from_another_org_or_without_an_issuer(db):
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER)
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer=SECOND_ISS) is True
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer=MAIN_ISS) is False
    assert engine.shared_capability_allowed(db, OTHER, "sync_now") is False           # no verified issuer
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer="") is False
    assert engine.shared_capability_allowed(db, OTHER, "sync_now", caller_issuer=SECOND_ISS + "/") is False
    assert engine.shared_capability_allowed(db, "00uSOMEONEELSE", "sync_now", caller_issuer=SECOND_ISS) is False
    assert engine.effective_shared_permissions(db)["sync_now"]["source"] == "built_in"  # what anyone else sees


def test_a_user_deny_never_limits_the_owner(db):
    engine.set_shared_permissions({"live_read": "deny"}, environment_id=db,
                                  grantee={"issuer": SECOND_ISS, "subject": OWNER})
    assert engine.shared_capability_allowed(db, OWNER, "live_read", caller_issuer=SECOND_ISS) is True


@pytest.mark.parametrize("grantee", [
    {"issuer": "http://login.example.org", "subject": OTHER},          # not https
    {"issuer": "https://login.example.org/x", "subject": OTHER},       # not a gate-built issuer
    {"issuer": SECOND_ISS, "subject": "00u-bad"},                      # not an Okta sub
    {"issuer": SECOND_ISS, "subject": ""}, {"issuer": SECOND_ISS}, "00uOTHER", None,
])
def test_invalid_grantees_are_refused_and_nothing_is_written(db, grantee):
    with pytest.raises(ValueError):
        engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=grantee or {})
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_grants").fetchone()[0] == 0


def test_a_grant_needs_an_existing_environment(db):
    with pytest.raises(ValueError):
        engine.set_shared_permissions({"sync_now": "allow"}, grantee=USER)
    with pytest.raises(KeyError):
        engine.set_shared_permissions({"sync_now": "allow"}, environment_id="no-such-id", grantee=USER)


def test_grant_changes_report_before_and_after_and_are_scoped_to_one_user(db):
    assert engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER) == [
        {"capability": "sync_now", "before": "inherit", "after": "allow"}]
    assert engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER) == []
    other_org = {"issuer": MAIN_ISS, "subject": OTHER}
    assert engine.set_shared_permissions({"sync_now": "deny"}, environment_id=db, grantee=other_org) == [
        {"capability": "sync_now", "before": "inherit", "after": "deny"}]
    assert engine.get_shared_permission_overrides(db) == {}  # grants are not overrides
    engine.record_known_identity(SECOND_ISS, OTHER, "me@example.org")
    assert engine.get_shared_permission_grants(db) == [  # ordered by issuer, subject, capability
        {"issuer": SECOND_ISS, "subject": OTHER, "email": "me@example.org", "capability": "sync_now", "value": "allow"},
        {"issuer": MAIN_ISS, "subject": OTHER, "email": None, "capability": "sync_now", "value": "deny"},
    ]


def test_inherit_removes_only_that_users_exception(db):
    other = {"issuer": MAIN_ISS, "subject": OTHER}
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER)
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=other)
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db)
    assert engine.set_shared_permissions({"sync_now": "inherit"}, environment_id=db, grantee=USER) == [
        {"capability": "sync_now", "before": "allow", "after": "inherit"}]
    assert [(g["issuer"], g["value"]) for g in engine.get_shared_permission_grants(db)] == [(MAIN_ISS, "allow")]
    assert engine.get_shared_permission_overrides(db) == {"sync_now": "allow"}


def test_known_identities_unseen_for_long_are_dropped_unless_an_exception_names_them(db):
    conn = audit_store._get_connection()
    for sub in ("00uOLD", "00uOLDGRANTED"):
        conn.execute("INSERT INTO known_identities VALUES (?, ?, 'x@example.org', '2020-01-01T00:00:00.000Z', "
                     "'2020-01-01T00:00:00.000Z')", (SECOND_ISS, sub))
    conn.commit()
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db,
                                  grantee={"issuer": SECOND_ISS, "subject": "00uOLDGRANTED"})
    engine.record_known_identity(SECOND_ISS, OTHER, "me@example.org")
    assert {r["subject"] for r in engine.list_known_identities()} == {OTHER, "00uOLDGRANTED"}


def test_grants_are_removed_with_their_environment(db):
    engine.set_shared_permissions({"sync_now": "allow"}, environment_id=db, grantee=USER)
    engine.delete_environment("dev", owner=OWNER)
    assert audit_store._get_connection().execute("SELECT COUNT(*) FROM shared_permission_grants").fetchone()[0] == 0


def test_known_identities_keep_the_last_email_and_ignore_non_gate_shapes(db):
    assert engine.record_known_identity(SECOND_ISS, OTHER, "old@example.org") is True
    assert engine.record_known_identity(SECOND_ISS, OTHER, None) is True          # keeps the e-mail it had
    assert engine.list_known_identities()[0]["email"] == "old@example.org"
    engine.record_known_identity(SECOND_ISS, OTHER, "new@example.org")
    engine.record_known_identity(MAIN_ISS, OTHER, "work@example.com")
    rows = {(r["issuer"], r["subject"]): r["email"] for r in engine.list_known_identities()}
    assert rows == {(SECOND_ISS, OTHER): "new@example.org", (MAIN_ISS, OTHER): "work@example.com"}
    assert engine.record_known_identity("", OTHER, "x@example.org") is False
    assert engine.record_known_identity(SECOND_ISS, None, "x@example.org") is False
    assert len(engine.list_known_identities()) == 2


def test_migration_009_constraints_and_stray_rows(db):
    conn = audit_store._get_connection()
    for row in [(db, "sync_now", "", OTHER, "allow"), (db, "sync_now", SECOND_ISS, "", "allow"),
                (db, "sync_now", SECOND_ISS, OTHER, "inherit"), ("nope", "sync_now", SECOND_ISS, OTHER, "allow")]:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO shared_permission_grants VALUES (?, ?, ?, ?, ?, 'x', NULL)", row)
        conn.rollback()
    conn.execute("INSERT INTO shared_permission_grants VALUES (?, 'from_the_future', ?, ?, 'allow', 'x', NULL)",
                 (db, SECOND_ISS, OTHER))
    conn.commit()
    assert engine.get_shared_permission_grants(db) == []
    assert "from_the_future" not in engine.effective_shared_permissions(db, caller_issuer=SECOND_ISS, caller_subject=OTHER)
