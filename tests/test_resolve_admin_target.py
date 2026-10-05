"""Covers _resolve_admin_target -- the CROSS-OWNER admin-override lookup,
which must disambiguate two different owners' same-named environments by
environment_id, never by a by-name scan. See docs/fast-follow-redesign.md's
Phase 7 for why this is one of the functions named as having the most
direct history of silent breakage (the original F1/F2/F3 cross-tenant
bugs, external review, 2026-09-30).

ENG1-01 (external review, 2026-10-05): the by-name fallback this file used
to test (`_resolve_admin_target(None, name=...)`) is REMOVED, not just
de-prioritized -- it was the root of a confirmed-exploitable credential
capture (an admin "creating" an environment with a name already used by
another owner silently adopted/overwrote that owner's row). `environment_id`
is now a required, non-optional argument; callers with no real cross-owner
id (set_environment_shared/delete_environment with is_admin but no id)
resolve through _find_own_environment_sql instead -- see
create_secret_folders.py's docstrings for both.

Phase 2 (SQLite migration, 2026-10-01) changed this function's signature
from `(data: dict, name, environment_id)` to `(environment_id)` -- it now
reads app_environments directly rather than scanning an in-memory
environments.json dict, since that dict no longer exists. These tests
insert rows straight into app_environments via raw SQL (the real
post-migration storage), not through environments.json."""
import pytest

import create_secret_folders as engine

ENV_ID_A = "11111111-1111-1111-1111-111111111111"
ENV_ID_B = "22222222-2222-2222-2222-222222222222"


def _insert_env(conn, environment_id, owner, name, base_domain="example.com"):
    import audit_store
    audit_store.run_migrations()  # creates app_environments etc. -- NOT migrate_legacy_environments_json(), so the real environments.json is never touched
    conn.execute(
        """INSERT INTO app_environments
           (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url,
            shared, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'team', 'key', '', 0, '2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z')""",
        (environment_id, owner, name, base_domain),
    )
    conn.commit()


def test_resolve_admin_target_prefers_explicit_environment_id(tmp_audit_store):
    import audit_store
    conn = audit_store._get_connection()
    _insert_env(conn, ENV_ID_A, None, "dev", "a.example.com")
    _insert_env(conn, ENV_ID_B, "00uOWNERB", "dev", "b.example.com")

    found_id, meta = engine._resolve_admin_target(ENV_ID_B)
    assert found_id == ENV_ID_B
    assert meta["base_domain"] == "b.example.com"

    found_id, meta = engine._resolve_admin_target(ENV_ID_A)
    assert found_id == ENV_ID_A
    assert meta["base_domain"] == "a.example.com"


def test_resolve_admin_target_raises_on_unknown_environment_id(tmp_audit_store):
    import audit_store
    conn = audit_store._get_connection()
    _insert_env(conn, ENV_ID_A, None, "dev")

    with pytest.raises(KeyError):
        engine._resolve_admin_target("nonexistent-id")


def test_resolve_admin_target_raises_without_an_environment_id(tmp_audit_store):
    """ENG1-01: there is no more by-name fallback at all -- a caller with
    no environment_id gets a clean KeyError, never an ambiguous scan
    across every owner's rows."""
    import audit_store
    conn = audit_store._get_connection()
    _insert_env(conn, ENV_ID_A, None, "dev")
    _insert_env(conn, ENV_ID_B, "00uOWNERB", "dev")

    with pytest.raises(KeyError):
        engine._resolve_admin_target(None)
    with pytest.raises(KeyError):
        engine._resolve_admin_target("")
