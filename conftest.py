"""Shared pytest fixtures for this repo's flat-script test suite.

No test anywhere in this suite may touch the REAL environments.json,
audit_store.db, or OS keychain -- those hold live credentials
(base_domain/team_name/key_id for a developer's own real environments)
and real tenant data. Every fixture below exists specifically to redirect this
project's module-level, hardcoded file paths and OS-keyring calls to
disposable per-test substitutes.
"""
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

# TEST-07 (external review, 2026-10-05): the suite must not depend on the
# developer's own environment. A repo-root .env (documented for CLI use via
# .env.example) used to be re-read by create_secret_folders._load_dotenv on
# import, so DEPLOYMENT_MODE=hosted there turned unrelated tests red (or
# aborted collection). Both the .env file and the ambient shell variables
# the server reads at import time are neutralised BEFORE the engine is
# imported; subprocess tests inherit the opt-out via os.environ.
os.environ["OPA_WIZARD_SKIP_DOTENV"] = "1"
for _ambient in ("DEPLOYMENT_MODE", "NGINX_PROXY_SECRET", "EXTRA_ALLOWED_ORIGINS",
                 "INTERNAL_API_SHARED_SECRET", "OPA_AUDIT_DB_PATH"):
    os.environ.pop(_ambient, None)

import create_secret_folders as engine  # noqa: E402


@pytest.fixture
def tmp_environments_file(tmp_path, monkeypatch):
    """Redirects environments.json to a disposable temp file so no test
    can ever read or write the real one (which holds live real
    environments' credentials metadata)."""
    path = tmp_path / "environments.json"
    monkeypatch.setattr(engine, "_environments_file_path", lambda: str(path))
    return path


@pytest.fixture
def fake_keyring(monkeypatch):
    """Replaces keyring_set/keyring_get/keyring_delete with an in-memory
    dict -- no test may write to the real OS keychain (Windows Credential
    Manager on this machine), which keyring_set would otherwise do for
    real on every upsert_environment call."""
    store = {}

    def _set(storage_name, field, value):
        store[(storage_name, field)] = value

    def _get(storage_name, field):
        return store.get((storage_name, field))

    def _delete(storage_name, field):
        store.pop((storage_name, field), None)

    monkeypatch.setattr(engine, "keyring_set", _set)
    monkeypatch.setattr(engine, "keyring_get", _get)
    monkeypatch.setattr(engine, "keyring_delete", _delete)
    return store


@pytest.fixture
def tmp_audit_log(tmp_path, monkeypatch):
    """Redirects audit_log.jsonl (create_secret_folders.log_audit_event's
    append-only file) to a disposable temp path -- never let a test
    append to the real one."""
    path = tmp_path / "audit_log.jsonl"
    monkeypatch.setattr(engine, "_audit_log_path", lambda: str(path))
    return path


@pytest.fixture
def tmp_audit_store(tmp_path, monkeypatch):
    """Redirects audit_store.db to a disposable temp file. audit_store's
    _get_connection() has no path-override parameter -- it always calls
    _audit_db_path() directly -- so the path FUNCTION itself must be
    monkeypatched, not a constant.

    Also redirects environments.json to a disposable temp file -- a REAL
    incident, 2026-10-01: a test called audit_store.init_db() (which also
    calls migrate_legacy_environments_json(), reading AND DELETING
    environments.json) with only this fixture applied, not
    tmp_environments_file -- the migration ran against this machine's
    REAL environments.json and deleted it (recovered; see
    tests/test_sync_watermark.py's docstring for the full account). Any
    test using tmp_audit_store now gets this redirect automatically too,
    so forgetting tmp_environments_file can no longer touch the real
    file -- redirecting unconditionally is harmless for tests that never
    call init_db() at all."""
    import audit_store

    path = tmp_path / "audit_store.db"
    monkeypatch.setattr(audit_store, "_audit_db_path", lambda: str(path))
    # Each test gets a fresh thread-local connection cache, since the real
    # one is keyed by threading.local() and would otherwise carry a stale
    # connection (to a PRIOR test's temp db) into this test if the same
    # worker thread ran both. LNCH-07: set through monkeypatch so the
    # original cache comes back at teardown, and this test's connection is
    # closed -- a later test that forgets the fixture then reaches the real
    # path function (and its own guard) instead of silently reusing this
    # test's temp database.
    local = threading.local()
    monkeypatch.setattr(audit_store, "_thread_local", local)

    env_path = tmp_path / "environments.json"
    monkeypatch.setattr(engine, "_environments_file_path", lambda: str(env_path))
    banner_path = tmp_path / "banner_config.json"
    monkeypatch.setattr(engine, "_banner_config_path", lambda: str(banner_path))

    yield path
    conn = getattr(local, "conn", None)
    if conn is not None:
        conn.close()
        local.conn = None


@pytest.fixture(autouse=True)
def never_open_the_real_audit_store(request, monkeypatch):
    """LNCH-07: a test that reaches audit_store without tmp_audit_store
    fails loudly instead of opening the developer's real audit_store.db (or
    a previous test's cached temp one). tmp_audit_store overrides this; a
    test of the path function itself opts out with
    @pytest.mark.real_audit_db_path (it never opens the database)."""
    import audit_store

    if request.node.get_closest_marker("real_audit_db_path"):
        return

    def _refuse():
        raise RuntimeError("this test opened audit_store.db without the tmp_audit_store fixture")

    monkeypatch.setattr(audit_store, "_audit_db_path", _refuse)
    monkeypatch.setattr(audit_store, "_thread_local", threading.local())


@pytest.fixture(autouse=True)
def never_write_the_real_audit_log(tmp_path, monkeypatch):
    """Every test writes audit_log.jsonl to its own temp dir unless it asks
    for tmp_audit_log (which points at the same place). Found by the 5.40.3
    review: tests that used tmp_audit_store without tmp_audit_log appended
    `evidence_chain.sealed` entries (and others) to the developer's REAL
    repo-root audit_log.jsonl on every run."""
    path = tmp_path / "audit_log.jsonl"
    monkeypatch.setattr(engine, "_audit_log_path", lambda: str(path))
    return path


@pytest.fixture(autouse=True)
def reset_serve_module_state(monkeypatch):
    """server/serve.py keeps several module-level mutable dicts
    (_sessions, _access_jobs, _sync_jobs) with zero built-in per-test
    isolation -- a test that imports server.serve and populates one of
    these would otherwise leak state into every later test in the same
    process. Only resets state IF server.serve has already been imported
    by an earlier fixture/test; importing it fresh here just to reset it
    would pull in its module-level env-var reads (NGINX_PROXY_SECRET,
    DEPLOYMENT_MODE, etc.) for tests that have nothing to do with it."""
    mod = sys.modules.get("server.serve")
    if mod is not None:
        with mod._sessions_lock:
            mod._sessions.clear()
        with mod._access_jobs_lock:
            mod._access_jobs.clear()
        with mod._sync_jobs_lock:
            mod._sync_jobs.clear()
    yield
    mod = sys.modules.get("server.serve")
    if mod is not None:
        with mod._sessions_lock:
            mod._sessions.clear()
        with mod._access_jobs_lock:
            mod._access_jobs.clear()
        with mod._sync_jobs_lock:
            mod._sync_jobs.clear()
