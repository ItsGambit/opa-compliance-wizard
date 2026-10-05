"""Covers ENG1-03 (external review, 2026-10-05): activating an
environment shared by someone else used to succeed at the Okta/OPA
authentication step (server/serve.py's activate_environment calls
get_environment_credentials, which resolves via list_environments_for --
own + shared=True) and populate the caller's session, but then raise
KeyError at set_active_environment, which resolved by a DIFFERENT,
narrower rule (_find_own_environment_sql -- the caller's OWN row only).
A request to activate a real, visible, shared environment therefore
failed outright even though the harder half of the work (a live OPA/Okta
auth round trip) had already succeeded.

Fix: set_active_environment now resolves through the SAME
list_environments_for visibility rule get_environment_credentials
already uses."""
import create_secret_folders as engine

OWNER_A = engine.LOCAL_OWNER_KEY  # None -- "__local__"
OWNER_B = "00uOWNERB"


def test_activating_a_shared_environment_as_a_non_owner_succeeds(tmp_audit_store, tmp_environments_file, fake_keyring):
    import audit_store
    audit_store.run_migrations()

    engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    engine.set_environment_shared("dev", OWNER_A, True)

    # Owner B is not the owner of "dev" -- it's only visible because it's
    # shared. This must not raise.
    engine.set_active_environment(OWNER_B, "dev")

    assert engine.get_active_environment_name(OWNER_B) == "dev"


def test_activating_a_private_environment_as_a_non_owner_still_fails(tmp_audit_store, tmp_environments_file, fake_keyring):
    """The fix must not become a bypass -- a non-shared environment
    belonging to someone else must stay invisible to set_active_environment,
    same as it already is to get_environment_credentials/list_environments_for."""
    import audit_store
    audit_store.run_migrations()

    engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    # Deliberately NOT shared.

    try:
        engine.set_active_environment(OWNER_B, "dev")
        assert False, "expected KeyError for a private environment"
    except KeyError:
        pass


def test_owners_own_copy_still_wins_over_a_same_named_shared_one(tmp_audit_store, tmp_environments_file, fake_keyring):
    """list_environments_for's own documented ordering (own applied AFTER
    shared, so it wins) must still hold through set_active_environment --
    activating "dev" as owner B, who has their OWN "dev" AND can also see
    owner A's shared "dev", must activate B's own copy, not A's."""
    import audit_store
    audit_store.run_migrations()

    engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=OWNER_A,
    )
    engine.set_environment_shared("dev", OWNER_A, True)
    _, id_b = engine.upsert_environment(
        "dev", {"base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b", "key_secret": "secret-b"},
        owner=OWNER_B,
    )

    engine.set_active_environment(OWNER_B, "dev")

    conn = audit_store._get_connection()
    row = conn.execute(
        "SELECT environment_id FROM active_environments WHERE owner_key = ?",
        (engine._owner_storage_key(OWNER_B),),
    ).fetchone()
    assert row["environment_id"] == id_b


def test_activating_an_unknown_environment_still_raises_keyerror(tmp_audit_store, tmp_environments_file, fake_keyring):
    import audit_store
    audit_store.run_migrations()
    try:
        engine.set_active_environment(OWNER_B, "does-not-exist")
        assert False, "expected KeyError"
    except KeyError:
        pass
