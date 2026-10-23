"""5.53.0: the Settings/Updates MFA unlock record (migration 012) and its store functions.

The HTTP behaviour (routes, renewal, local mode) is in tests/test_http_authz_matrix.py; this file covers the table and the
audit_store functions on their own, with synthetic subjects only."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import audit_store

SUB = "00uSUBJECT"
ISSUER = "https://login.example.com/oauth2/default"
FP = "f" * 32
NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)


def test_migration_012_creates_the_table_and_is_declared_rollback_safe(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(settings_unlocks)")}
    assert cols == {"actor_sub", "issuer", "session_fp", "action_id", "unlocked_at", "expires_at"}
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == max(audit_store.MIGRATIONS)
    declared = json.loads((Path(__file__).resolve().parent.parent / "server" / "schema_migrations.json").read_text())
    assert declared["migrations"]["12"]["rollback_safe"] is True
    assert declared["migrations"]["12"]["since"] == "5.53.0"
    audit_store.run_migrations()  # idempotent


def test_inactive_before_active_after_upsert_and_gone_after_expiry(tmp_audit_store):
    audit_store.run_migrations()
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW) is None
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    row = audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(seconds=599))
    assert row and row["action_id"] == "act-1"
    # The boundary is exclusive: at expires_at the window is closed.
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(seconds=600)) is None


def test_an_expired_row_is_deleted_when_read(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    conn = audit_store._get_connection()
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(hours=1)) is None
    assert conn.execute("SELECT COUNT(*) FROM settings_unlocks").fetchone()[0] == 0


def test_the_status_read_leaves_an_expired_row_for_the_first_refused_request(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    later = NOW + timedelta(hours=1)
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=later, delete_expired=False) is None
    assert len(audit_store.list_settings_unlocks()) == 1
    assert audit_store.take_expired_settings_unlock(SUB, ISSUER, FP, now=later) is not None


def test_a_clock_that_went_back_does_not_extend_the_window(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW - timedelta(minutes=5)) is None
    # Not deleted by that read: once the clock is right again the window is still there.
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(seconds=1)) is not None


def test_the_key_is_subject_issuer_and_session(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    later = NOW + timedelta(seconds=1)
    assert audit_store.settings_unlock_active("00uOTHER", ISSUER, FP, now=later) is None
    assert audit_store.settings_unlock_active(SUB, "https://other.example.com", FP, now=later) is None
    assert audit_store.settings_unlock_active(SUB, "", FP, now=later) is None
    assert audit_store.settings_unlock_active(SUB, ISSUER, "0" * 32, now=later) is None
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=later) is not None


def test_an_empty_subject_or_session_never_unlocks(tmp_audit_store):
    audit_store.run_migrations()
    for sub, fp in ((None, FP), ("", FP), (SUB, None), (SUB, "")):
        try:
            audit_store.upsert_settings_unlock(sub, ISSUER, fp, "act", 600, now=NOW)
        except ValueError:
            pass
        else:
            raise AssertionError("an unlock without a subject or session must be refused")
        assert audit_store.settings_unlock_active(sub, ISSUER, fp, now=NOW) is None
    assert audit_store.list_settings_unlocks() == []


def test_renew_moves_expiry_and_opens_a_lapsed_window_again(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    audit_store.renew_settings_unlock(SUB, ISSUER, FP, "act-2", 600, now=NOW + timedelta(minutes=8))
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(minutes=15))["action_id"] == "act-2"
    # After expiry a renewal is an upsert: one prompt, not two.
    audit_store.renew_settings_unlock(SUB, ISSUER, FP, "act-3", 600, now=NOW + timedelta(hours=2))
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(hours=2, seconds=1)) is not None
    assert len(audit_store.list_settings_unlocks()) == 1


def test_delete_ends_the_window_and_reports_what_it_ended(tmp_audit_store):
    audit_store.run_migrations()
    assert audit_store.delete_settings_unlock(SUB, ISSUER, FP) is None
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    gone = audit_store.delete_settings_unlock(SUB, ISSUER, FP)
    assert gone and gone["action_id"] == "act-1"
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW) is None


def test_take_expired_returns_the_row_once_and_leaves_a_live_one(tmp_audit_store):
    audit_store.run_migrations()
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600, now=NOW)
    assert audit_store.take_expired_settings_unlock(SUB, ISSUER, FP, now=NOW + timedelta(minutes=5)) is None
    assert audit_store.settings_unlock_active(SUB, ISSUER, FP, now=NOW + timedelta(minutes=5)) is not None
    first = audit_store.take_expired_settings_unlock(SUB, ISSUER, FP, now=NOW + timedelta(minutes=11))
    assert first and first["expires_at"] <= audit_store._unlock_iso(NOW + timedelta(minutes=11))
    assert audit_store.take_expired_settings_unlock(SUB, ISSUER, FP, now=NOW + timedelta(minutes=11)) is None


def test_the_start_up_sweep_and_the_operator_listing_and_clearing(tmp_audit_store):
    audit_store.run_migrations()
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    audit_store.upsert_settings_unlock("00uLIVE", ISSUER, FP, "act-live", 600)
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-old", 60, now=old)
    assert len(audit_store.list_settings_unlocks()) == 2
    audit_store._cleanup_expired_settings_unlocks()
    assert [r["actor_sub"] for r in audit_store.list_settings_unlocks()] == ["00uLIVE"]
    assert audit_store.clear_settings_unlocks() == 1
    assert audit_store.list_settings_unlocks() == []


# --- the operator's break-glass: `python -m server.updater settings-unlocks list | clear` (run as the application account) ----
def test_cli_lists_and_clears_the_windows_and_audits_the_clearing(tmp_audit_store, tmp_audit_log, monkeypatch, capsys):
    from server.updater import __main__ as cli

    audit_store.run_migrations()
    monkeypatch.setenv("SUDO_USER", "operator-example")
    assert cli.main(["settings-unlocks", "list"]) == 0
    assert "No Settings or Updates windows" in capsys.readouterr().out
    audit_store.upsert_settings_unlock(SUB, ISSUER, FP, "act-1", 600)
    audit_store.upsert_settings_unlock("00uOTHER", "", "e" * 32, "act-2", 600)
    assert cli.main(["settings-unlocks", "list"]) == 0
    out = capsys.readouterr().out
    assert SUB in out and "00uOTHER" in out and ("f" * 8) + "…" in out and FP not in out    # a session shows as a short prefix only
    # Refused without the typed word; nothing is touched.
    assert cli.main(["settings-unlocks", "clear"]) == 2 and cli.main(["settings-unlocks", "clear", "--confirm", "yes"]) == 2
    assert len(audit_store.list_settings_unlocks()) == 2
    assert cli.main(["settings-unlocks", "clear", "--confirm", "CLEAR"]) == 0
    assert "Ended 2" in capsys.readouterr().out and audit_store.list_settings_unlocks() == []
    entries = [json.loads(line) for line in tmp_audit_log.read_text().splitlines() if line.strip()]
    assert [(e["action"], e["actor_email"], e["details"]) for e in entries] == [
        ("settings.locked", "cli:operator-example", {"reason": "operator", "cleared": 2, "via": "cli"})]


def test_cli_on_an_archive_without_the_table_says_there_is_nothing(tmp_audit_store, tmp_audit_log, capsys):
    from server.updater import __main__ as cli

    audit_store.run_migrations()
    audit_store._get_connection().execute("DROP TABLE settings_unlocks")
    assert cli.main(["settings-unlocks", "list"]) == 0
    assert "No Settings or Updates windows" in capsys.readouterr().out
    assert cli.main(["settings-unlocks", "clear", "--confirm", "CLEAR"]) == 0
