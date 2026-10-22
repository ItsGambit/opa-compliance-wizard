"""Migrations and code rollback (5.47.0).

* server/schema_migrations.json declares a rollback_safe flag for EVERY migration in audit_store.MIGRATIONS (the release
  tool refuses to build otherwise), and the manifest carries them.
* The previous release's audit_store.py (tests/fixtures/previous_release/, copied from the last released tag) opens a database
  migrated by THIS release's code, still passes its own run_migrations() and reads what the health checks read, for every
  migration the declaration calls rollback-safe. Update the fixture when a release ships: it is what an automatic code
  rollback runs after a failed upgrade.
"""

import importlib.util
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

import audit_store

REPO = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "previous_release" / "audit_store.py"
DECLARED = json.loads((REPO / "server" / "schema_migrations.json").read_text())["migrations"]


def test_every_migration_is_declared_with_a_rollback_flag():
    assert sorted(int(k) for k in DECLARED) == sorted(audit_store.MIGRATIONS)
    for k, v in DECLARED.items():
        assert isinstance(v["rollback_safe"], bool) and re.match(r"^\d+\.\d+\.\d+$", v["since"])


def test_release_tool_writes_the_declarations_into_the_manifest_and_refuses_an_undeclared_migration():
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location("release_tool", REPO / "tools" / "release.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    files = {"audit_store.py": (0o644, (REPO / "audit_store.py").read_bytes()),
             "server/schema_migrations.json": (0o644, (REPO / "server" / "schema_migrations.json").read_bytes()),
             "server/updater/root/ocw_activate.py": (0o644, (REPO / "server" / "updater" / "root" / "ocw_activate.py").read_bytes())}
    migrations, expected = tool._migrations_from(files)
    assert expected == max(audit_store.MIGRATIONS) and [m["version"] for m in migrations] == sorted(audit_store.MIGRATIONS)
    assert [m["rollback_safe"] for m in migrations if m["version"] == 4] == [False]
    assert tool._activator_version(files) == "5.52.0"
    bad = dict(files, **{"server/schema_migrations.json": (0o644, json.dumps({"migrations": {"1": {"since": "5.29.0", "rollback_safe": True}}}).encode())})
    with pytest.raises(tool.ReleaseError, match="does not declare"):
        tool._migrations_from(bad)
    assert tool._migrations_from({"CHANGELOG.md": (0o644, b"x")}) == ([], None)


def _load_previous(tmp_path):
    dest = tmp_path / "prev"
    dest.mkdir()
    shutil.copy(FIXTURE, dest / "audit_store.py")
    spec = importlib.util.spec_from_file_location("audit_store_previous", dest / "audit_store.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_previous_release_runs_on_a_database_migrated_by_this_release(tmp_path, monkeypatch, tmp_audit_store):
    prev = _load_previous(tmp_path)
    newer = [n for n in audit_store.MIGRATIONS if n not in prev.MIGRATIONS]
    unsafe = [n for n in newer if not DECLARED[str(n)]["rollback_safe"]]
    if unsafe:
        pytest.skip(f"migration(s) {unsafe} are declared NOT rollback-safe: restoring the archive copy is the way back")
    audit_store.run_migrations()  # this release migrates the database fully
    top = max(audit_store.MIGRATIONS)
    audit_store._get_connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # the previous release's code, in its own module state, on the same file
    monkeypatch.setenv("OPA_AUDIT_DB_PATH", str(tmp_audit_store))
    import threading
    monkeypatch.setattr(prev, "_thread_local", threading.local())
    prev.run_migrations()  # nothing left to do, nothing may fail
    conn = prev._get_connection()
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == top  # the schema stays
    conn.execute("SELECT 1")  # /healthz
    for table in ("sync_state", "chain_heads", "ingestion_manifests", "events", "app_environments", "banner_config", "shared_permission_grants", "known_identities"):
        conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    conn.close()


def test_5_50_code_on_a_5_51_database_keeps_working_and_the_next_start_sweeps_the_scan(tmp_path, monkeypatch, tmp_audit_store):
    """5.51.0: a rollback to 5.50.x finds the stored-scan table and the daily access-state snapshots it knows nothing
    about. It must start, verify the chain deeply (a snapshot of a new kind is sealed like any other), and an environment
    it deletes leaves a scan row that the next 5.51 start removes."""
    prev = _load_previous(tmp_path)
    audit_store.run_migrations()
    audit_store.record_config_snapshot("env-1", "opa_access_state", [("user:u1", {"id": "u1"}), ("summary:counts", {"users": 1})])
    audit_store.store_opa_model_cache("env-1", {"users": [], "groups": []})
    assert audit_store.verify_ingestion_chain("env-1", deep=True)["valid"]
    audit_store._get_connection().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    monkeypatch.setenv("OPA_AUDIT_DB_PATH", str(tmp_audit_store))
    import threading
    monkeypatch.setattr(prev, "_thread_local", threading.local())
    prev.run_migrations()
    verdict = prev.verify_ingestion_chain("env-1", deep=True)
    assert verdict["valid"], verdict
    prev_conn = prev._get_connection()
    prev_conn.execute("DELETE FROM app_environments WHERE environment_id = 'env-1'")  # what its delete leaves behind
    prev_conn.commit()
    prev_conn.close()
    assert audit_store.load_opa_model_cache("env-1") is not None  # the row survives the old release's delete
    assert audit_store.sweep_orphaned_opa_model_caches() == ["env-1"]
    assert audit_store.load_opa_model_cache("env-1") is None
