"""Covers _resolve_admin_target -- the admin-override lookup that must
disambiguate two different owners' same-named environments by
environment_id, not by a potentially-ambiguous by-name scan. See
docs/fast-follow-redesign.md's Phase 7 for why this is one of the
functions named as having the most direct history of silent breakage
(the original F1/F2/F3 cross-tenant bugs, external review, 2026-09-30).

Phase 2 (SQLite migration, 2026-10-01) changed this function's signature
from `(data: dict, name, environment_id)` to `(environment_id, name=None)`
-- it now reads app_environments directly rather than scanning an
in-memory environments.json dict, since that dict no longer exists.
These tests insert rows straight into app_environments via raw SQL
(the real post-migration storage), not through environments.json."""
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
            shared, preserve_logs_locally, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'team', 'key', '', 0, 0, '2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z')""",
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


def test_resolve_admin_target_falls_back_to_ambiguous_scan_without_id(tmp_audit_store):
    """Legacy by-name path only -- deliberately NOT asserting WHICH of the
    two same-named environments wins, since app_environments has no
    ordering guarantee across owners for the same display_name. New code
    should always pass environment_id; this test only proves the
    fallback resolves to SOME real entry rather than raising, matching
    backward-compat intent."""
    import audit_store
    conn = audit_store._get_connection()
    _insert_env(conn, ENV_ID_A, None, "dev")
    _insert_env(conn, ENV_ID_B, "00uOWNERB", "dev")

    found_id, meta = engine._resolve_admin_target(None, name="dev")
    assert found_id in (ENV_ID_A, ENV_ID_B)
    assert meta is not None


def test_resolve_admin_target_raises_when_name_not_found_at_all(tmp_audit_store):
    import audit_store
    audit_store.run_migrations()

    with pytest.raises(KeyError):
        engine._resolve_admin_target(None, name="dev")
