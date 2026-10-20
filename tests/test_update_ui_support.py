"""What the 5.46.0 Updates screens need from the server: the Daily / Manual / Off choice, "Check now", the release
details (size, notes), the key table and a recent revocation in /api/upgrade/status, and the audit shapes."""

import json
from datetime import timedelta
from pathlib import Path

from fake_release_server import release_json
from server.updater import check, service
from server.updater import keys as keylib
from test_update_check import (ADMIN, NOW, OWNER_A, REAL, _call, _who, audit_rows, fake, matrix_server, mirror, pinned, run)  # noqa: F401


def test_manual_only_never_runs_by_itself_and_off_is_off(monkeypatch):
    monkeypatch.setattr(service, "kick", lambda v: None)
    assert service.status(service.load(), "5.46.0")["check"]["frequency"] is None          # never answered
    code, body = service.change_settings(None, None, "5.46.0", lambda a, d: None, frequency="manual")
    assert code == 200 and body["check"]["frequency"] == "manual" and body["check"]["enabled"] is True
    assert service.due(service.load(), NOW) is False                                       # the daily timer does not fire
    assert service.maybe_start("5.46.0", NOW) is False
    service.change_settings(None, None, "5.46.0", lambda a, d: None, frequency="daily")
    assert service.due(service.load(), NOW) is True
    code, body = service.change_settings(None, None, "5.46.0", lambda a, d: None, frequency="off")
    assert body["check"]["frequency"] == "off" and body["check"]["enabled"] is False
    assert service.validate_settings_payload({"frequency": "weekly"})
    assert service.validate_settings_payload({"frequency": "daily", "enabled": True})
    assert service.validate_settings_payload({"frequency": "manual", "share_version": True}) is None


def test_settings_audit_names_the_frequency(monkeypatch):
    monkeypatch.setattr(service, "kick", lambda v: None)
    events = []
    service.change_settings(None, True, "5.46.0", lambda a, d: events.append((a, d)), frequency="manual")
    assert events[0][1]["frequency"] == "manual" and events[0][1]["share_version"] is True


def test_check_now_rules_and_audit(mirror, monkeypatch):
    assert service.check_now("5.46.0", "admin@example.com", "00uA", now=NOW)[0] == 409       # off: nothing is sent
    assert mirror.requests == []
    service.set_settings(enabled=True, manual_only=True)                                       # Manual only still allows it
    service._last_manual["at"] = None
    mirror.respond("/latest", body=release_json("5.48.0", assets="signed"))
    code, body = service.check_now("5.46.0", "admin@example.com", "00uA", now=NOW)
    assert code == 200 and body["outcome"] == "update_available" and body["update_available"] is True
    assert body["last_check"]["by"] == "admin@example.com"
    row = audit_rows()[-1]
    assert row["actor_email"] == "admin@example.com" and row["details"]["trigger"] == "admin:admin@example.com"
    assert row["details"]["result"].startswith("newer release found: 5.48.0")
    assert service.check_now("5.46.0", "admin@example.com", "00uA", now=NOW + timedelta(seconds=10))[0] == 429   # once a minute
    assert service.check_now("5.46.0", "admin@example.com", "00uA", now=NOW + timedelta(seconds=61))[0] == 200
    monkeypatch.setenv("OPA_UPDATE_CHECK", "off")
    service._last_manual["at"] = None
    code, body = service.check_now("5.46.0", None, None, now=NOW + timedelta(hours=1))
    assert code == 409 and body["reason"] == "env_off"


def test_release_details_are_plain_bounded_text_and_stored(mirror):
    body = json.dumps({"tag_name": "v5.48.0", "name": "5.48.0 — Thing\x07", "body": "Para one.\r\n\r\n" + "word " * 400,
                       "published_at": "2026-10-01T12:00:00Z", "html_url": "https://example.com/releases/tag/v5.48.0",
                       "assets": [{"name": "ocw-5.48.0.tar.gz", "size": 15_500_000}, {"name": "ocw-5.48.0.tar.gz.minisig"},
                                  {"name": "manifest.json"}]}).encode()
    latest = check.parse_latest(body)
    assert latest.size == 15_500_000 and latest.notes_title == "5.48.0 — Thing" and "\x07" not in latest.notes_title
    assert latest.notes.startswith("Para one.") and len(latest.notes) <= 801 and latest.notes.endswith("…")
    odd = json.dumps({"tag_name": "v5.48.0", "assets": [{"name": "ocw-5.48.0.tar.gz", "size": "big"}]}).encode()
    assert check.parse_latest(odd).size is None
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=body)
    run()
    st = service.status(service.load(), "5.46.0")
    assert st["latest"]["size"] == 15_500_000 and st["latest"]["notes_title"].startswith("5.48.0") and st["check"]["url"].endswith("/latest")


def test_status_reports_keys_and_a_recent_revocation(pinned, mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.46.0"))
    mirror.respond("/rev/revocation.json", body=(REAL / "revocation.json").read_bytes())
    run()
    st = service.status(service.load(), "5.46.0")
    statuses = sorted((k["role"], k["status"]) for k in st["signing_keys"]["keys"])
    assert statuses == [("release", "active"), ("release", "revoked"), ("standby", "active"), ("standby", "revoked")]
    rev = st["revocation"]
    assert rev["serial"] == 1 and rev["source"] == "release_assets" and rev["advisory_url"].startswith("https://") and len(rev["revoked"]) == 2
    assert rev["applied_at"] and st["signing_keys"]["serial"] == 1
    state = json.loads(Path(keylib.local_path()).read_text())          # the red notice lasts 30 days
    state["history"][-1]["applied_at"] = "2020-01-01T00:00:00Z"
    Path(keylib.local_path()).write_text(json.dumps(state))
    assert service.status(service.load(), "5.46.0")["revocation"] is None


def test_an_older_state_file_without_history_still_loads():
    older = {"schema": 1, "serial": 2, "keys": [], "revoked": []}
    state = keylib.validate_state(older)
    assert state["history"] == [] and state["serial"] == 2
    noisy = {**older, "history": [{"serial": 2, "revoked": ["bad id", "A" * 16], "reason": "r" * 999}]}
    assert keylib.validate_state(noisy)["history"][0]["revoked"] == ["A" * 16]


def test_check_now_route_and_frequency_validation(matrix_server, monkeypatch):
    base_url, _serve = matrix_server
    monkeypatch.setattr(service, "kick", lambda v: None)
    admin = _who(ADMIN, admin=True)
    assert _call(base_url, "POST", "/api/upgrade/check", {}, _who(OWNER_A)).status_code == 403
    assert _call(base_url, "POST", "/api/upgrade/check", {}, admin).status_code == 409             # off: nothing sent
    for bad in ({"frequency": "weekly"}, {"frequency": "daily", "enabled": True}):
        assert _call(base_url, "POST", "/api/upgrade/settings", bad, admin).status_code == 400
    resp = _call(base_url, "POST", "/api/upgrade/settings", {"frequency": "manual"}, admin)
    assert resp.status_code == 200 and resp.json()["check"]["frequency"] == "manual"
    assert audit_rows()[-1]["details"]["frequency"] == "manual"
