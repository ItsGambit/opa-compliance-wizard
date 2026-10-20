"""`ocw-updater` (server/updater/root/ocw_cli.py): output, exit codes and audit events of every command, driven against
the fake machine. apply goes through the same request file and root path the in-app flow will use."""

import json
import os
import shutil
import sqlite3
from pathlib import Path

import pytest

import updater_fakes as uf
import ocw_cli
import ocw_trust
from updater_fakes import act


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def cli(m, *argv):
    return ocw_cli.main(list(argv), m.cfg(), m.host)


def prepare_release(m, version="5.47.0", **kw):
    m.build_release(version, **kw)
    m.host.schema_on_start[version] = 10
    return m.releases_dir / f"ocw-{version}.tar.gz"


def test_status_shows_the_picture_in_the_artboard_format(m, capsys):
    assert cli(m, "status") == 0
    out = capsys.readouterr().out
    assert out.startswith("installed      5.46.0   (releases/5.46.0")
    for label in ("updater        ", "keys           ", "backups        "):
        assert label in out
    assert cli(m, "status", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["installed"] == "5.46.0" and data["staged"] == [] and data["keys"]


def test_stage_from_a_file_then_apply_completes_with_the_artboard_steps(m, capsys):
    tar = prepare_release(m)
    assert cli(m, "stage", str(tar)) == 0
    out = capsys.readouterr().out
    assert "staged 5.47.0" in out and "next: ocw-updater apply 5.47.0" in out
    assert (m.opt / "staging" / "5.47.0" / ".staged").exists()
    assert cli(m, "status") == 0
    assert "staged         5.47.0   verified ok, venv built, sha256" in capsys.readouterr().out
    rc = cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0")
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "This upgrades 5.46.0 → 5.47.0" in out and "~45 s downtime" in out
    for token in ("✓ received   ✓ validated", "✓ staged (re-verified)", "✓ preflight", "✓ backup ", "(integrity ok)", "✓ switching", "✓ restarting (",
                  "✓ health 8/8", "✓ completed in "):
        assert token in out, token
    assert "audit: upgrade.started … upgrade.completed  correlation=upg-" in out
    actions = [e["action"] for e in m.audit_actions()]
    assert "upgrade.staged" in actions and "upgrade.requested" in actions and "upgrade.completed" in actions
    req = [e for e in m.audit_actions() if e["action"] == "upgrade.requested"][0]
    assert req["actor_email"].startswith("cli:") and req["details"]["via"] == "cli"


def test_apply_requires_the_typed_version(m, capsys, monkeypatch):
    prepare_release(m)
    cli(m, "stage", str(m.releases_dir / "ocw-5.47.0.tar.gz"))
    monkeypatch.setattr("builtins.input", lambda prompt="": "5.99.0")
    assert cli(m, "apply", "5.47.0") == 2
    assert "not confirmed" in capsys.readouterr().err
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    monkeypatch.setattr("builtins.input", lambda prompt="": "5.47.0")
    assert cli(m, "apply", "5.47.0") == 0


def test_stage_refuses_a_forged_release_with_exit_2_and_an_audit_event(m, capsys):
    tar = prepare_release(m, signer=uf.TestKey())
    assert cli(m, "stage", str(tar)) == 2
    assert "refused" in capsys.readouterr().err
    ev = [e for e in m.audit_actions() if e["action"] == "upgrade.verify_failed"][0]["details"]
    assert ev["reason_code"] == "key_unknown" and ev["via"] == "cli"


def test_apply_exit_codes_for_rollback_and_operator_needed(m, capsys):
    m.host.unhealthy_versions.add("5.47.0")
    tar = prepare_release(m)
    cli(m, "stage", str(tar))
    assert cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0") == 3
    out = capsys.readouterr().out
    assert "rolled back to 5.46.0" in out and "support bundle: ocw-support-5.46.0-to-5.47.0-" in out
    m2 = uf.Machine(m.root / "two")
    m2.host.unhealthy_versions.add("5.47.0")
    m2.env["OCW_UPDATER_FAULT"] = "rollback_fail"
    tar2 = prepare_release(m2)
    cli(m2, "stage", str(tar2))
    assert cli(m2, "apply", "5.47.0", "--confirm-text", "5.47.0") == 4
    assert "An operator must act" in capsys.readouterr().out


def test_a_second_apply_of_a_failed_version_is_refused_until_clear_failure(m, capsys):
    m.host.unhealthy_versions.add("5.47.0")
    tar = prepare_release(m)
    cli(m, "stage", str(tar))
    cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0")
    capsys.readouterr()
    m.host.unhealthy_versions.clear()
    assert cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0") == 2
    assert "failed before" in capsys.readouterr().err
    assert cli(m, "clear-failure") == 0
    assert any(e["action"] == "upgrade.clear_failure" for e in m.audit_actions())
    assert cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0") == 0


def test_rollback_is_code_only_typed_and_within_24_hours(m, capsys, monkeypatch):
    tar = prepare_release(m)
    cli(m, "stage", str(tar))
    cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0")
    capsys.readouterr()
    events_before = sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert cli(m, "rollback") == 2
    assert "Data is not touched" in capsys.readouterr().out
    assert os.readlink(m.opt / "current") == "releases/5.47.0"
    assert cli(m, "rollback", "--confirm-text", "ROLLBACK") == 0
    assert os.readlink(m.opt / "current") == "releases/5.46.0" and m.host.serving["opa-compliance-wizard"] == "5.46.0"
    assert sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == events_before
    assert sqlite3.connect(m.db).execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 10  # schema stays
    assert "upgrade.rolled_back" in [e["action"] for e in m.audit_actions()]
    # too old a window
    m.host.clock += 3 * 86400
    st = m.read_state()
    st.update(result="completed")
    (m.data / "upgrade" / "state.json").write_text(json.dumps(st))
    assert cli(m, "rollback", "--confirm-text", "ROLLBACK") == 2


def test_restore_replaces_the_archive_only_with_the_typed_word_and_keeps_the_old_one(m, capsys):
    tar = prepare_release(m)
    cli(m, "stage", str(tar))
    cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0")
    capsys.readouterr()
    conn = sqlite3.connect(m.db)
    conn.execute("INSERT INTO events (who, what) VALUES ('later@example.com', 'after the upgrade')")
    conn.commit()
    conn.close()
    assert cli(m, "restore") == 2
    assert cli(m, "restore", "--confirm", "restore") == 2
    assert "--confirm RESTORE" in capsys.readouterr().err
    assert sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 51
    assert cli(m, "restore", "--confirm", "RESTORE") == 0
    assert sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 50
    aside = list(m.data.glob("audit_store.db.pre-restore-*"))
    assert len(aside) == 1 and sqlite3.connect(str(aside[0])).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 51
    actions = [e["action"] for e in m.audit_actions()]
    assert "upgrade.restore_requested" in actions and "upgrade.restored" in actions


def test_restore_without_any_backup_is_refused(m, capsys):
    assert cli(m, "restore", "--confirm", "RESTORE") == 2
    assert "no pre-upgrade backup" in capsys.readouterr().err


def test_schedule_and_cancel(m, capsys):
    tar = prepare_release(m)
    cli(m, "stage", str(tar))
    rc = cli(m, "apply", "5.47.0", "--at", "2026-10-21 03:30", "--tz", "Europe/London", "--confirm-text", "5.47.0")
    out = capsys.readouterr().out
    assert rc == 0 and "scheduled for 2026-10-21T02:30:00Z (Europe/London 03:30)" in out
    files = list((m.data / "upgrade" / "schedule").glob("*.json"))
    assert len(files) == 1 and oct(files[0].stat().st_mode & 0o777) == "0o600"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    assert ("systemctl", "enable", "--now", "ocw-upgrade-due.timer") in m.host.calls
    st = cli(m, "status")
    assert "schedule       2026-10-21T02:30:00Z" in capsys.readouterr().out
    assert cli(m, "cancel") == 0 and not list((m.data / "upgrade" / "schedule").glob("*.json"))
    assert "upgrade.scheduled" in [e["action"] for e in m.audit_actions()] and "upgrade.cancelled" in [e["action"] for e in m.audit_actions()]


def test_bundle_command_writes_a_redacted_bundle(m, capsys):
    assert cli(m, "bundle", "--include-hosts") == 0
    out = capsys.readouterr().out
    assert "redaction:" in out and "wrote " in out and "Nothing is sent automatically" in out
    assert list((m.data / "upgrade" / "bundles").glob("ocw-support-*.tar.gz"))


def test_trust_commands(m, capsys, tmp_path):
    from release_helpers import make_revocation, revocation_payload
    assert cli(m, "trust", "list") == 0
    out = capsys.readouterr().out
    assert "primary  " in out and "standby" in out and "last revocation serial applied: 0" in out
    k2, sb2 = uf.TestKey(), uf.TestStandby()
    payload = revocation_payload(1, revoke=[{"key_id": m.primary.key_id, "last_good_version": "5.46.0"}, m.standby.key_id], add_keys=[k2, sb2])
    rev = make_revocation(tmp_path / "revocation.json", [m.standby], payload)
    assert cli(m, "trust", "apply", str(rev)) == 0
    out = capsys.readouterr().out
    assert "Revocation applied: serial 0 → 1" in out
    assert cli(m, "trust", "apply", str(rev)) == 0 and "Nothing to do" in capsys.readouterr().out
    trust = ocw_trust.load_trust(str(m.opt / "updater" / "trust.json"))
    assert trust["serial"] == 1 and {r["key_id"] for r in trust["revoked"]} == {m.primary.key_id, m.standby.key_id}
    assert "release_keys.revocation_applied" in [e["action"] for e in m.audit_actions()]
    # a release signed by the revoked primary after the revocation is now refused
    tar = prepare_release(m)
    assert cli(m, "stage", str(tar)) == 2
    # `trust add` takes only an active release key, with typed confirmation
    k3 = uf.TestKey()
    f = tmp_path / "k3.json"
    f.write_text(json.dumps(k3.entry()))
    assert cli(m, "trust", "add", str(f), "--confirm-text", "TRUST") == 0
    assert any(k["key_id"] == k3.key_id for k in ocw_trust.load_trust(str(m.opt / "updater" / "trust.json"))["keys"])
    sbf = tmp_path / "sb.json"
    sbf.write_text(json.dumps(uf.TestStandby().entry()))
    assert cli(m, "trust", "add", str(sbf), "--confirm-text", "TRUST") == 2


def test_trust_seed_uses_the_local_state_only_to_get_stricter(m, capsys, tmp_path):
    shipped = tmp_path / "release_keys.json"
    k2 = uf.TestKey()
    shipped.write_text(json.dumps(uf.key_list([m.primary, k2, m.standby])))
    local = tmp_path / "release_keys.local.json"
    local.write_text(json.dumps({"schema": 1, "serial": 3, "keys": [], "revoked": [
        {"key_id": m.primary.key_id, "revoked_at": "2026-02-01T00:00:00Z", "last_good_version": None}]}))
    trust_path = m.opt / "updater" / "trust.json"
    trust_path.unlink()
    assert cli(m, "trust", "seed", "--source", str(shipped), "--local-state", str(local)) == 0
    t = ocw_trust.load_trust(str(trust_path))
    assert [k["status"] for k in t["keys"] if k["key_id"] == m.primary.key_id] == ["revoked"] and t["serial"] == 3
    # keys that exist only in the application's state are not imported unless the operator says so
    local.write_text(json.dumps({"schema": 1, "serial": 1, "keys": [uf.TestKey().entry()], "revoked": []}))
    trust_path.unlink()
    assert cli(m, "trust", "seed", "--source", str(shipped), "--local-state", str(local)) == 2
    assert "not in the release's key list" in capsys.readouterr().err
    assert cli(m, "trust", "seed", "--source", str(shipped), "--local-state", str(local), "--import-local-keys") == 0
    assert len(ocw_trust.load_trust(str(trust_path))["keys"]) == 4
    assert cli(m, "trust", "seed", "--source", str(shipped)) == 2  # exists: needs --force


def test_nginx_sync_applies_the_current_releases_template(m, capsys):
    (m.opt / "releases" / "5.46.0" / "server").mkdir(parents=True, exist_ok=True)
    (m.opt / "releases" / "5.46.0" / "server" / "nginx-opa-secrets-wizard.conf").write_text(
        uf.SITE_NEW_TEMPLATE.format(name="REPLACE_WITH_SERVER_NAME", cert="REPLACE_WITH_CERT", key="REPLACE_WITH_KEY", secret="REPLACE_WITH_SECRET"))
    assert cli(m, "nginx-sync") == 0
    assert "maintenance/active.html" in m.site.read_text() and uf.PROXY_SECRET in m.site.read_text() and m.host.reloads == 1
    assert cli(m, "nginx-sync") == 0
    assert "already matches" in capsys.readouterr().out


def test_commands_that_change_things_refuse_non_root(m, capsys, monkeypatch):
    cfg = m.cfg()
    cfg.fast = False
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    for argv in (["apply", "5.47.0"], ["stage", "x"], ["rollback"], ["restore", "--confirm", "RESTORE"], ["bundle"], ["clear-failure"], ["cancel"],
                 ["trust", "seed"], ["nginx-sync"]):
        assert ocw_cli.main(argv, cfg, m.host) == 2, argv
        assert "must run as root" in capsys.readouterr().err


def test_every_command_accepts_json(m, capsys):
    tar = prepare_release(m)
    assert cli(m, "stage", str(tar), "--json") == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip().splitlines()[-1])["exit_code"] == 0 and "staged 5.47.0" in captured.err
    assert cli(m, "apply", "5.47.0", "--confirm-text", "5.47.0", "--json") == 0
    out = capsys.readouterr().out
    final = json.loads(out.strip().splitlines()[-1])
    assert final["command"] == "apply" and final["exit_code"] == 0 and final["state"]["result"] == "completed"
    assert cli(m, "bundle", "--json") == 0
    last = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert last["command"] == "bundle" and last["exit_code"] == 0
    assert cli(m, "clear-failure", "--json") == 0 and cli(m, "cancel", "--json") == 0


def test_app_side_audit_command_filters_by_correlation_and_count(capsys):
    """`ocw-updater audit --correlation ID --last N` (the application's own CLI, run as the application account)."""
    import create_secret_folders as engine
    from server.updater import __main__ as appcli
    for i in range(5):
        engine.log_audit_event(None, None, "upgrade.step", {"correlation_id": "upg-11111111", "n": i})
    engine.log_audit_event(None, None, "upgrade.step", {"correlation_id": "upg-22222222"})
    engine.log_audit_event(None, None, "environment.upsert", {"correlation_id": "upg-11111111"})  # not an upgrade event
    assert appcli.main(["audit", "--correlation", "upg-11111111", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 5
    assert appcli.main(["audit", "--correlation", "upg-11111111", "--last", "2", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["details"]["n"] for r in rows] == [4, 3]
    assert appcli.main(["apply", "5.48.0"]) == 2 and "sudo ocw-updater apply" in capsys.readouterr().err


def test_prune_backups_from_the_command_line_is_typed_and_keeps_the_newest(m, capsys):
    prepare_release(m)
    m.put_artifacts("5.47.0")
    assert cli(m, "apply", "5.47.0", "--yes", "--confirm-text", "5.47.0") == 0
    d = m.data / "upgrade" / "backups"
    old = d / "audit_store-pre-5.40.0-20250101T000000Z.db"
    old.write_bytes(b"x")
    os.utime(old, (1, 1))
    capsys.readouterr()
    assert cli(m, "prune-backups", "--keep", "1") == 2                                    # not typed
    assert cli(m, "prune-backups", "--keep", "1", "--name", "x.db", "--confirm", "PRUNE") == 2   # both
    assert cli(m, "prune-backups", "--confirm", "PRUNE") == 2                             # neither
    assert old.exists()
    assert cli(m, "prune-backups", "--keep", "1", "--confirm", "PRUNE") == 0
    assert not old.exists() and len(list(d.glob("*.db"))) == 1
    assert any(e["action"] == "upgrade.backups_pruned" for e in m.audit_actions())
    assert cli(m, "prune-backups", "--name", old.name, "--confirm", "PRUNE") == 2         # already gone
