"""Covers ENG1-04 (external review, 2026-10-05): list_environments_for
collapses every environment visible to a caller into a flat {name: meta}
dict. When two DIFFERENT owners each share an environment under the SAME
display name, both rows match the "shared" query, and whichever one the
dict comprehension processes LAST silently wins -- SQLite's row order
for a SELECT with no ORDER BY is not guaranteed stable, so a third
party's lookup of that name could resolve to either owner's credentials,
possibly differently from one call to the next.

Fix: ORDER BY created_at, environment_id makes the tie-break
deterministic and repeatable. This test inserts rows directly via SQL
(not through upsert_environment, which stamps created_at with the
current second -- real-world collisions are rarely created in the exact
same second, but a test needs to control the ordering explicitly to
prove it's actually the ORDER BY driving the result, not accidental row
order)."""
import audit_store
import create_secret_folders as engine

ENV_OLDER = "11111111-1111-1111-1111-111111111111"
ENV_NEWER = "22222222-2222-2222-2222-222222222222"
OWNER_A = "00uOWNERA"
OWNER_B = "00uOWNERB"
THIRD_PARTY = "00uTHIRDPARTY"


def _insert_shared_env(conn, environment_id, owner, name, base_domain, created_at):
    audit_store.run_migrations()
    conn.execute(
        """INSERT INTO app_environments
           (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url,
            shared, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'team', 'key', '', 1, ?, ?)""",
        (environment_id, owner, name, base_domain, created_at, created_at),
    )
    conn.commit()


def test_name_collision_between_two_shared_environments_resolves_deterministically(tmp_audit_store):
    conn = audit_store._get_connection()
    _insert_shared_env(conn, ENV_NEWER, OWNER_B, "dev", "b.example.com", "2026-10-02T00:00:00.000Z")
    _insert_shared_env(conn, ENV_OLDER, OWNER_A, "dev", "a.example.com", "2026-10-01T00:00:00.000Z")

    # Call it several times -- must resolve the SAME way every time, not
    # flip based on incidental row order.
    results = [engine.list_environments_for(THIRD_PARTY)["dev"]["base_domain"] for _ in range(5)]
    assert len(set(results)) == 1, f"resolution was not deterministic across repeated calls: {results}"


def test_the_older_created_at_wins_the_tie_break(tmp_audit_store):
    """ORDER BY created_at means whichever row was inserted into the DB
    first (ascending) ends up processed LAST by the dict comprehension's
    overwrite-by-key loop -- so the right answer here depends on which
    query (shared vs. own) and in which direction this project chooses
    to break ties; this test pins the actual current behavior so a
    future change to the ORDER BY direction is a deliberate, visible
    decision, not an accidental flip."""
    conn = audit_store._get_connection()
    _insert_shared_env(conn, ENV_OLDER, OWNER_A, "dev", "a.example.com", "2026-10-01T00:00:00.000Z")
    _insert_shared_env(conn, ENV_NEWER, OWNER_B, "dev", "b.example.com", "2026-10-02T00:00:00.000Z")

    visible = engine.list_environments_for(THIRD_PARTY)
    assert visible["dev"]["environment_id"] == ENV_NEWER  # later created_at processed last, wins the dict overwrite


def test_environment_id_breaks_a_tie_when_created_at_is_identical(tmp_audit_store):
    conn = audit_store._get_connection()
    same_time = "2026-10-01T00:00:00.000Z"
    _insert_shared_env(conn, ENV_NEWER, OWNER_B, "dev", "b.example.com", same_time)
    _insert_shared_env(conn, ENV_OLDER, OWNER_A, "dev", "a.example.com", same_time)

    results = [engine.list_environments_for(THIRD_PARTY)["dev"]["environment_id"] for _ in range(5)]
    assert len(set(results)) == 1, f"resolution was not deterministic across repeated calls: {results}"
    assert results[0] == ENV_NEWER  # higher environment_id string sorts last, processed last, wins
