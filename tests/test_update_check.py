"""The opt-in, notify-only update check (5.46.0): the network half against a
fake release server (every failure shape), the service that persists and
audits it, the admin routes and the command line.

Nothing here touches the real network or the developer's real state file
(conftest's isolate_update_check)."""

import json
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

import create_secret_folders as engine
from fake_release_server import FakeReleaseServer, release_json
from server.updater import __main__ as cli
from server.updater import check
from server.updater import keys as keylib
from server.updater import p256
from server.updater import service

REAL = Path(__file__).resolve().parent / "fixtures" / "minisign_real"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def fake():
    server = FakeReleaseServer()
    yield server
    server.close()


@pytest.fixture
def mirror(fake, monkeypatch):
    monkeypatch.setenv(service.API_URL_ENV, fake.base + "/latest")
    monkeypatch.setenv(service.REVOCATION_BASE_ENV, fake.base + "/rev/")
    return fake


def hosts(fake):
    return check.hosts_for(fake.base)


def audit_rows(prefix="upgrade."):
    return [e for e in reversed(engine.read_audit_log(limit=500)) if e["action"].startswith(prefix)]


# --- network half ------------------------------------------------------------------


def test_ok_response_is_parsed_and_sends_only_the_fixed_user_agent(fake):
    fake.respond("/latest", body=release_json("5.47.0"), etag='"abc"')
    got = check.fetch(fake.base + "/latest", hosts(fake))
    assert got.status == "ok" and got.etag == '"abc"'
    latest = check.parse_latest(got.body)
    assert (latest.version, latest.published_at, latest.signed_artifact) == ("5.47.0", "2026-10-01T12:00:00Z", True)
    headers = fake.requests[0]["headers"]
    assert headers["user-agent"] == "opa-compliance-wizard-update-check"  # no version unless opted in
    assert "authorization" not in headers and "cookie" not in headers and "if-none-match" not in headers
    check.fetch(fake.base + "/latest", hosts(fake), user_agent=check.USER_AGENT + "/5.46.0")
    assert fake.requests[1]["headers"]["user-agent"].endswith("/5.46.0")


def test_etag_gives_304(fake):
    fake.respond("/latest", body=release_json(), etag='"abc"')
    got = check.fetch(fake.base + "/latest", hosts(fake), etag='"abc"')
    assert got.status == "not_modified"
    assert fake.requests[0]["headers"]["if-none-match"] == '"abc"'


@pytest.mark.parametrize("status,headers,retry", [(403, {"Retry-After": "120"}, 120), (429, {"Retry-After": "30"}, 30),
                                                  (403, {}, None)])
def test_rate_limit_answers(fake, status, headers, retry):
    fake.respond("/latest", status=status, headers=headers, body=b"{}")
    got = check.fetch(fake.base + "/latest", hosts(fake))
    assert got.status == "rate_limited" and got.retry_after == retry


def test_404_500_and_unreachable(fake):
    assert check.fetch(fake.base + "/missing", hosts(fake)).status == "not_found"
    fake.respond("/latest", status=500, body=b"x")
    got = check.fetch(fake.base + "/latest", hosts(fake))
    assert (got.status, got.code) == ("error", "http_500")
    closed = FakeReleaseServer()
    base = closed.base
    closed.close()
    got = check.fetch(base + "/latest", check.hosts_for(base))
    assert (got.status, got.code) == ("error", "network") and "firewall" in got.detail


def test_timeout(fake):
    fake.respond("/latest", mode="slow", delay=2, body=release_json())
    got = check.fetch(fake.base + "/latest", hosts(fake), timeout=0.3)
    assert (got.status, got.code) == ("error", "timeout")


def test_truncated_and_oversized_bodies(fake):
    fake.respond("/latest", mode="truncate", body=release_json())
    assert check.fetch(fake.base + "/latest", hosts(fake)).code == "truncated"
    fake.respond("/big", body=b"x" * (check.MAX_RESPONSE_BYTES + 10))
    assert check.fetch(fake.base + "/big", hosts(fake)).code == "too_large"


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"tag_name": 5}', b'{"tag_name": "nightly"}',
                                  json.dumps({"tag_name": "v1.2"}).encode()])
def test_bad_bodies_are_rejected(body):
    with pytest.raises(ValueError):
        check.parse_latest(body)


def test_prerelease_and_draft_are_not_offered_and_unsigned_is_flagged():
    assert check.parse_latest(release_json(prerelease=True)) is None
    assert check.parse_latest(release_json(draft=True)) is None
    assert check.parse_latest(release_json(assets="unsigned")).signed_artifact is False
    assert check.parse_latest(release_json(assets="none")).signed_artifact is False
    hostile = json.dumps({"tag_name": "v9.9.9", "html_url": "javascript:alert(1)", "published_at": "soon", "assets": "x"}).encode()
    latest = check.parse_latest(hostile)
    assert latest.release_url is None and latest.published_at is None and latest.version == "9.9.9"


def test_redirects_only_to_allowed_hosts(fake):
    fake.respond("/hop", status=302, headers={"Location": "http://203.0.113.9:1/latest"}, body=b"")
    got = check.fetch(fake.base + "/hop", hosts(fake))
    assert (got.status, got.code) == ("error", "redirect_refused")
    fake.respond("/same", status=302, headers={"Location": fake.base + "/latest"}, body=b"")
    fake.respond("/latest", body=release_json())
    assert check.fetch(fake.base + "/same", hosts(fake)).status == "ok"
    # to a non-GitHub https host when no mirror is configured
    fake.respond("/away", status=302, headers={"Location": "https://example.org/latest"}, body=b"")
    assert check.fetch(fake.base + "/away", check.GITHUB_HOSTS | hosts(fake)).code == "redirect_refused"


def test_only_https_and_loopback_urls(fake):
    assert check.fetch("http://example.org/x", check.hosts_for("http://example.org/x")).code == "bad_url"
    assert check.fetch("file:///etc/passwd", check.GITHUB_HOSTS).code == "bad_url"
    assert check.fetch("https://evil.example/x", check.GITHUB_HOSTS).code == "bad_url"


# --- service: switches, state, audit -----------------------------------------------


def run(installed="5.46.0", now=NOW, **kw):
    return service.run_check(installed, now=now, **kw)


def test_default_is_off_and_nothing_is_sent(mirror, monkeypatch):
    data = service.load()
    assert service.is_enabled(data) == (False, "default_off")
    assert service.status(data, "5.46.0")["check"]["prompt_needed"] is True
    assert run() is None and mirror.requests == []
    assert service.due(data, NOW) is False
    assert service.maybe_start("5.46.0", NOW) is False


def test_env_switch_precedence(mirror, monkeypatch):
    service.set_settings(enabled=True)
    monkeypatch.setenv("OPA_UPDATE_CHECK", "off")
    assert service.is_enabled(service.load()) == (False, "env_off")
    assert run()["outcome"] == "blocked" and mirror.requests == []
    assert run(force=True)["reason"] == "env_off" and mirror.requests == []  # --force cannot override it
    monkeypatch.setenv("OPA_UPDATE_CHECK", "ON")
    service.set_settings(enabled=False)
    assert service.is_enabled(service.load()) == (True, "env_on")
    monkeypatch.setenv("OPA_UPDATE_CHECK", "maybe")  # unknown value: ignored, and reported
    st = service.status(service.load(), "5.46.0")
    assert st["check"]["env_invalid_value"] == "maybe" and st["check"]["enabled"] is False


def test_check_records_state_and_one_audit_row(mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.47.0"), etag='"e1"')
    mirror.respond("/rev/revocation.json", status=404)
    out = run()
    assert out["outcome"] == "update_available"
    st = service.status(service.load(), "5.46.0")
    assert st["update_available"] and st["latest"]["version"] == "5.47.0" and st["latest"]["signed_artifact"]
    assert st["last_check"]["status"] == "ok" and st["last_check"]["next_at"] == "2026-10-21T12:00:00Z"
    rows = audit_rows()
    assert [r["action"] for r in rows] == ["upgrade.check"] and rows[0]["details"]["outcome"] == "update_available"
    assert rows[0]["details"]["correlation_id"] and rows[0]["actor_email"] is None
    # nothing but the version metadata was stored
    stored = json.loads(Path(service.state_path()).read_text())
    assert set(stored) == {"settings", "state"} and "token" not in json.dumps(stored).lower()
    # a second check uses the ETag and (304) says up to date / still available
    out = run(now=NOW + timedelta(days=1))
    assert out["outcome"] == "update_available"
    assert mirror.requests[-2]["headers"].get("if-none-match") == '"e1"'


def test_up_to_date_and_no_release(mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.46.0"))
    assert run()["outcome"] == "up_to_date"
    mirror.respond("/latest", status=404)
    out = run(now=NOW + timedelta(days=1))
    assert out["outcome"] == "up_to_date" and service.load()["state"]["latest_version"] is None
    mirror.respond("/latest", body=release_json("5.47.0", prerelease=True))
    assert run(now=NOW + timedelta(days=2))["outcome"] == "up_to_date"  # a pre-release is never offered


def test_identical_repeated_failures_are_collapsed(mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", status=500, body=b"x")
    for hours in (0, 7, 14):
        run(now=NOW + timedelta(hours=hours))
    assert len(audit_rows()) == 1 and audit_rows()[0]["details"]["reason"] == "http_500"
    st = service.load()["state"]
    assert st["consecutive_failures"] == 3 and st["next_check_at"] == "2026-10-21T08:00:00Z"
    mirror.respond("/latest", status=503, body=b"x")  # a different failure is a new row
    run(now=NOW + timedelta(hours=21))
    assert [r["details"]["reason"] for r in audit_rows()] == ["http_500", "http_503"]
    mirror.respond("/latest", body=release_json("5.46.0"))  # recovery says how long it was down
    run(now=NOW + timedelta(hours=28))
    recovered = audit_rows()[-1]["details"]
    assert recovered["outcome"] == "up_to_date" and recovered["recovered_after_failures"] == 4
    assert recovered["failing_since"] == "2026-10-20T12:00:00Z"
    assert service.load()["state"]["consecutive_failures"] == 0


def test_rate_limit_backs_off(mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", status=429, headers={"Retry-After": "7200"}, body=b"{}")
    run()
    st = service.load()["state"]
    assert st["last_status"] == "rate_limited" and st["next_check_at"] == "2026-10-20T14:00:00Z"
    assert service.due(service.load(), NOW + timedelta(hours=1)) is False
    assert service.due(service.load(), NOW + timedelta(hours=3)) is True
    mirror.respond("/latest", status=403, headers={"Retry-After": "999999"}, body=b"{}")
    run(now=NOW + timedelta(hours=3))
    assert service.load()["state"]["next_check_at"] == "2026-10-21T15:00:00Z"  # capped at a day


def test_share_version_changes_only_the_user_agent(mirror):
    mirror.respond("/latest", body=release_json("5.46.0"))
    service.set_settings(enabled=True, share_version=True)
    run()
    assert mirror.requests[0]["headers"]["user-agent"] == "opa-compliance-wizard-update-check/5.46.0"


def test_damaged_state_file_means_off(tmp_path, mirror):
    Path(service.state_path()).write_text("{broken")
    assert service.is_enabled(service.load()) == (False, "default_off")
    Path(service.state_path()).write_text(json.dumps({"settings": {"enabled": "yes", "share_version": 1}, "state": []}))
    data = service.load()
    assert data["settings"] == {"enabled": None, "share_version": False, "manual_only": False, "channel": "stable"}


def test_settings_change_is_audited_locked_by_env_and_kicks(monkeypatch):
    kicked = []
    monkeypatch.setattr(service, "kick", lambda v: kicked.append(v))
    events = []
    code, body = service.change_settings(True, None, "5.46.0", lambda a, d: events.append((a, d)))
    assert code == 200 and body["changed"]["enabled"] == [None, True] and kicked == ["5.46.0"]
    assert events[0][0] == "upgrade.settings"
    code, body = service.change_settings(True, None, "5.46.0", lambda a, d: events.append((a, d)))
    assert body["changed"] == {} and len(events) == 1 and kicked == ["5.46.0"]  # no change, no row, no check
    monkeypatch.setenv("OPA_UPDATE_CHECK", "off")
    service.set_settings(enabled=False)
    code, body = service.change_settings(True, None, "5.46.0", lambda a, d: None)
    assert code == 409 and body["reason"] == "env_locked"
    assert service.change_settings(False, None, "5.46.0", lambda a, d: None)[0] == 200  # turning off is always allowed


def test_concurrent_checks_do_not_overlap(mirror):
    service.set_settings(enabled=True)
    mirror.respond("/latest", mode="slow", delay=0.6, body=release_json("5.46.0"))
    results = []
    t = threading.Thread(target=lambda: results.append(run()))
    t.start()
    import time
    time.sleep(0.2)
    assert run() is None  # a second one while the first runs
    t.join()
    assert results[0]["outcome"] == "up_to_date"


# --- revocation via the check ----------------------------------------------------


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    shipped = tmp_path / "release_keys.json"
    shutil.copy(REAL / "release_keys.json", shipped)
    monkeypatch.setattr(keylib, "SHIPPED_PATH", shipped)
    return shipped


def test_check_fetches_and_applies_a_published_revocation(mirror, pinned):
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.46.0"))
    mirror.respond("/rev/revocation.json", body=(REAL / "revocation.json").read_bytes(), etag='"r1"')
    run()
    assert keylib.effective_key_list()["serial"] == 1
    actions = [e["action"] for e in audit_rows("upgrade.key_")]
    assert actions == ["upgrade.key_revoked", "upgrade.key_added"] or sorted(actions) == ["upgrade.key_added", "upgrade.key_revoked"]
    run(now=NOW + timedelta(days=1))  # nothing new: no second entry
    assert len(audit_rows("upgrade.key_")) == 2


def test_a_forged_revocation_is_rejected_once_and_audited(mirror, pinned):
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.46.0"))
    envelope = json.loads((REAL / "revocation.json").read_text())
    payload = json.loads(p256.b64url_decode(envelope["payload"]))
    payload["revoke"] = []          # a forger drops the revocation but keeps the signature
    envelope["payload"] = p256.b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    mirror.respond("/rev/revocation.json", body=json.dumps(envelope).encode())
    run()
    run(now=NOW + timedelta(days=1))
    assert keylib.effective_key_list()["serial"] == 0
    rejected = audit_rows("upgrade.key_")
    assert len(rejected) == 1 and rejected[0]["action"] == "upgrade.key_revocation_rejected"
    assert rejected[0]["details"]["reason"] == "bad_signature" and rejected[0]["details"]["source"] == "release_assets"


def test_the_second_revocation_source_is_checked_too(mirror, pinned, monkeypatch):
    monkeypatch.setenv(service.REVOCATION_URL_ENV, mirror.base + "/static/revocation.json")
    service.set_settings(enabled=True)
    mirror.respond("/latest", body=release_json("5.46.0"))
    mirror.respond("/static/revocation.json", body=(REAL / "revocation.json").read_bytes())   # only the static URL has it
    run()
    assert keylib.effective_key_list()["serial"] == 1
    applied = [e for e in audit_rows("upgrade.key_") if e["action"] == "upgrade.key_revoked"]
    assert len(applied) == 1 and applied[0]["details"]["source"] == "static_url"
    assert {r["path"] for r in mirror.requests} >= {"/rev/revocation.json", "/static/revocation.json"}
    run(now=NOW + timedelta(days=1))   # both sources answer again: already applied, no new entry
    assert len(audit_rows("upgrade.key_")) == 2


# --- routes -----------------------------------------------------------------------

from test_http_authz_matrix import ADMIN, OWNER_A, _call, _who, matrix_server  # noqa: E402,F401


def test_status_route_is_admin_only_and_read_only(matrix_server):
    base_url, _serve = matrix_server
    assert _call(base_url, "GET", "/api/upgrade/status", headers=_who(OWNER_A)).status_code == 403
    body = _call(base_url, "GET", "/api/upgrade/status", headers=_who(ADMIN, admin=True)).json()
    assert body["installed_version"] == engine.SCRIPT_VERSION
    assert body["check"]["enabled"] is False and body["check"]["prompt_needed"] is True
    assert body["latest"] is None and body["update_available"] is False
    keys = body["signing_keys"]
    assert (keys["pinned"], keys["serial"], keys["error"]) == (True, 0, None)
    assert sorted((k["role"], k["status"]) for k in keys["keys"]) == [("release", "active"), ("standby", "active")]
    assert body["revocation"] is None and body["check"]["frequency"] is None and body["installed_at"]
    assert body["server"]["zone"] and set(body["latest"] or {}) == set()
    assert not Path(service.state_path()).exists()  # a read never writes


def test_settings_route(matrix_server, monkeypatch):
    base_url, _serve = matrix_server
    monkeypatch.setattr(service, "kick", lambda v: None)
    admin = _who(ADMIN, admin=True)
    assert _call(base_url, "POST", "/api/upgrade/settings", {"enabled": True}, _who(OWNER_A)).status_code == 403
    for bad in ({}, {"enabled": "yes"}, {"other": True}, {"enabled": None}):
        assert _call(base_url, "POST", "/api/upgrade/settings", bad, admin).status_code == 400
    resp = _call(base_url, "POST", "/api/upgrade/settings", {"enabled": True}, admin)
    assert resp.status_code == 200 and resp.json()["check"]["enabled"] is True
    row = audit_rows()[-1]
    assert row["action"] == "upgrade.settings" and row["details"]["changes"]["enabled"] == [None, True]
    assert row["actor_sub"] == ADMIN
    monkeypatch.setenv("OPA_UPDATE_CHECK", "off")
    service.set_settings(enabled=False)
    assert _call(base_url, "POST", "/api/upgrade/settings", {"enabled": True}, admin).status_code == 409


# --- command line -------------------------------------------------------------------


def test_cli_status_and_enable_disable(capsys, monkeypatch):
    monkeypatch.setattr(service, "kick", lambda v: None)
    assert cli.main(["status"]) == 0
    assert "OFF (never enabled" in capsys.readouterr().out
    assert cli.main(["enable-check"]) == 0 and "now ON" in capsys.readouterr().out
    row = audit_rows()[-1]
    assert row["action"] == "upgrade.settings" and row["actor_email"].startswith("cli:") and row["details"]["via"] == "cli"
    assert cli.main(["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["check"]["enabled"] is True
    assert cli.main(["disable-check"]) == 0
    monkeypatch.setenv("OPA_UPDATE_CHECK", "off")
    assert cli.main(["enable-check"]) == 3
    assert "OPA_UPDATE_CHECK=off" in capsys.readouterr().err


def test_cli_check_exit_codes(mirror, capsys):
    assert cli.main(["check"]) == 0 and "off" in capsys.readouterr().out and mirror.requests == []
    mirror.respond("/latest", body=release_json("5.99.0"))
    assert cli.main(["check", "--force"]) == 1  # a newer release exists
    out = capsys.readouterr().out
    assert "5.99.0" in out and "deploy.sh --release 5.99.0" in out
    assert audit_rows()[-1]["details"]["forced"] is True and audit_rows()[-1]["details"]["trigger"].startswith("cli:")
    mirror.respond("/latest", body=release_json(engine.SCRIPT_VERSION))
    assert cli.main(["check", "--force"]) == 0
    mirror.respond("/latest", status=500, body=b"x")
    assert cli.main(["check", "--force", "--json"]) == 3
    with pytest.raises(SystemExit) as info:
        cli.main(["bogus"])
    assert info.value.code == 2


def test_cli_audit_listing_and_keys(capsys, monkeypatch):
    monkeypatch.setattr(service, "kick", lambda v: None)
    cli.main(["enable-check"])
    capsys.readouterr()
    engine.log_audit_event("someone", None, "banner.update", {"x": 1})  # unrelated: not listed
    assert cli.main(["audit"]) == 0
    out = capsys.readouterr().out
    assert "upgrade.settings" in out and "banner.update" not in out
    assert cli.main(["audit", "--since", "2999-01-01", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["keys", "list"]) == 0
    out = capsys.readouterr().out
    assert "88DFB54FC6C0E819  release" in out and "76A2D96A6B0FAAAD  standby" in out
    # a malformed signature is refused plainly (exit 3) and audited
    bogus = Path(service.state_path()).parent / "ocw-1.0.0.tar.gz"
    bogus.write_bytes(b"x")
    (Path(str(bogus) + ".minisig")).write_text("x")
    assert cli.main(["verify", str(bogus), str(bogus) + ".minisig"]) == 3
    assert audit_rows()[-1]["action"] == "upgrade.verify_failed"
