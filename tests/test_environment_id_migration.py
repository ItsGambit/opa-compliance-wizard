"""Covers load_environments()'s Phase 1 one-time migration: every legacy
environments.json shape (bare display-name key, or "{owner}::{name}"
storage_name key) gets rekeyed to a real environment_id (UUID4), with
`name` stored as an explicit field. Critically, this migration must be
IDEMPOTENT -- unlike the pre-existing legacy rekeying this builds on,
minting a random id must happen at most once per environment, ever, or
every boot would silently assign a brand-new (and therefore unresolvable)
id to the same real environment."""
import json

import create_secret_folders as engine


def _write_raw_environments_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def test_oldest_shape_bare_name_key_gets_migrated(tmp_environments_file):
    """Pre-multi-user shape: environments.json keyed by plain display
    name, no owner/shared/name fields at all."""
    _write_raw_environments_json(tmp_environments_file, {
        "active": "dev",
        "environments": {
            "dev": {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a"},
        },
    })
    data = engine.load_environments()
    assert len(data["environments"]) == 1
    environment_id, meta = next(iter(data["environments"].items()))
    assert "::" not in environment_id  # not a legacy-shaped key
    assert meta["name"] == "dev"
    assert meta["owner"] is None  # LOCAL_OWNER_KEY
    assert meta["shared"] is True  # pre-existing environments default to shared
    assert meta["base_domain"] == "a.example.com"


def test_multiuser_shape_owner_name_key_gets_migrated(tmp_environments_file):
    """Post-multi-user, pre-UUID shape: "{owner}::{name}" key, owner/shared
    already real fields, but no environment_id and `name` only implicit."""
    _write_raw_environments_json(tmp_environments_file, {
        "active": {},
        "environments": {
            "00uOWNERB::dev": {
                "owner": "00uOWNERB", "shared": False,
                "base_domain": "b.example.com", "team_name": "team-b", "key_id": "key-b",
            },
        },
    })
    data = engine.load_environments()
    assert len(data["environments"]) == 1
    environment_id, meta = next(iter(data["environments"].items()))
    assert environment_id != "00uOWNERB::dev"
    assert meta["name"] == "dev"
    assert meta["owner"] == "00uOWNERB"
    assert meta["shared"] is False  # pre-existing value preserved, not reset


def test_migration_persists_immediately_and_is_idempotent(tmp_environments_file):
    """The one deliberate deviation from the pre-existing lazy-rekey
    pattern: a second load_environments() call must NOT mint a new id --
    it must see the already-migrated record (environment_id already
    present, detected via "name" in meta) and leave it untouched."""
    _write_raw_environments_json(tmp_environments_file, {
        "active": "dev",
        "environments": {
            "dev": {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a"},
        },
    })
    first = engine.load_environments()
    first_id = next(iter(first["environments"].keys()))

    # Confirm the migration was actually WRITTEN to disk, not just held in
    # memory -- read the raw file directly.
    with open(tmp_environments_file, encoding="utf-8") as f:
        on_disk = json.load(f)
    assert first_id in on_disk["environments"]

    second = engine.load_environments()
    second_id = next(iter(second["environments"].keys()))
    assert second_id == first_id  # NOT a freshly-minted different UUID


def test_already_migrated_record_is_left_untouched(tmp_environments_file):
    """A record that already has a real environment_id key and a `name`
    field (the current, post-migration shape) must not be touched at all
    -- this is the common steady-state case on every normal boot."""
    real_id = "33333333-3333-3333-3333-333333333333"
    _write_raw_environments_json(tmp_environments_file, {
        "active": {},
        "environments": {
            real_id: {"owner": None, "name": "dev", "shared": True, "base_domain": "a.example.com"},
        },
    })
    data = engine.load_environments()
    assert list(data["environments"].keys()) == [real_id]
    assert data["environments"][real_id]["name"] == "dev"


def test_keyring_credentials_migrate_from_legacy_name_to_new_id(tmp_environments_file, fake_keyring):
    """Covers _migrate_environment_keyring_entries specifically: a real
    secret stored under the OLD (legacy) storage name must be readable
    under the NEW environment_id after migration, and gone from the old
    name."""
    legacy_storage_name = engine._legacy_environment_storage_name(engine.LOCAL_OWNER_KEY, "dev")
    engine.keyring_set(legacy_storage_name, "key_secret", "super-secret-value")

    _write_raw_environments_json(tmp_environments_file, {
        "active": "dev",
        "environments": {
            "dev": {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a"},
        },
    })
    data = engine.load_environments()
    new_id = next(iter(data["environments"].keys()))

    assert engine.keyring_get(new_id, "key_secret") == "super-secret-value"
    assert engine.keyring_get(legacy_storage_name, "key_secret") is None
