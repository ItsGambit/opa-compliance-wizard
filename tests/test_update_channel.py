"""The release channel (5.49.0): stable (default) and prerelease. Nothing here touches the network."""

import json
from datetime import datetime, timezone

import pytest

from fake_release_server import FakeReleaseServer
from server.updater import __main__ as cli
from server.updater import check, service

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def rel(version, prerelease=False, draft=False, tag=None):
    names = [f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig", "manifest.json"]
    return {"tag_name": tag or f"v{version}", "draft": draft, "prerelease": prerelease, "published_at": "2026-10-01T12:00:00Z",
            "html_url": f"https://github.com/example/example/releases/tag/v{version}", "assets": [{"name": n} for n in names]}


def body(*releases):
    return json.dumps(list(releases)).encode()


@pytest.fixture
def fake():
    server = FakeReleaseServer()
    yield server
    server.close()


@pytest.fixture
def mirror(fake, monkeypatch):
    monkeypatch.setenv(service.API_URL_ENV, fake.base + "/repos/x/y/releases/latest")
    monkeypatch.setenv(service.REVOCATION_BASE_ENV, fake.base + "/rev/")
    service.set_settings(enabled=True)
    return fake


def test_the_list_parser_picks_the_newest_by_version_not_by_position():
    got = check.parse_latest_from_list(body(rel("5.49.0", True), rel("5.50.0", True), rel("5.48.0")))
    assert (got.version, got.prerelease) == ("5.50.0", True)
    got = check.parse_latest_from_list(body(rel("5.50.0", True), rel("5.51.0")))   # a newer stable beats an older prerelease
    assert (got.version, got.prerelease) == ("5.51.0", False)
    assert check.parse_latest_from_list(body(rel("5.10.0", True), rel("5.9.0", True))).version == "5.10.0"   # numeric, not text


def test_drafts_and_odd_tags_are_skipped_and_garbage_is_refused():
    got = check.parse_latest_from_list(body(rel("5.60.0", draft=True), rel("1", tag="nightly"), rel("5.49.0", True)))
    assert got.version == "5.49.0"
    assert check.parse_latest_from_list(body(rel("5.60.0", draft=True))) is None
    assert check.parse_latest_from_list(b"[]") is None
    for bad in (b"{}", b"not json", b"\xff"):
        with pytest.raises(ValueError):
            check.parse_latest_from_list(bad)


def test_the_stable_parser_still_ignores_prereleases():
    assert check.parse_latest(json.dumps(rel("5.49.0", True)).encode()) is None
    assert check.parse_latest(json.dumps(rel("5.49.0")).encode()).prerelease is False


def test_default_channel_is_stable_and_uses_latest(mirror):
    mirror.respond("/repos/x/y/releases/latest", body=json.dumps(rel("5.48.0")).encode())
    out = service.run_check("5.47.0", now=NOW)
    assert out["channel"] == "stable" and out["latest_version"] == "5.48.0"
    assert [r["path"].split("?")[0] for r in mirror.requests][:1] == ["/repos/x/y/releases/latest"]
    assert service.status(service.load(), "5.47.0")["check"]["channel"] == "stable"


def test_prerelease_channel_reads_the_list_and_still_flags_it(mirror):
    mirror.respond("/repos/x/y/releases", body=body(rel("5.49.0", True), rel("5.48.0")))
    service.set_settings(channel="prerelease")
    out = service.run_check("5.47.0", now=NOW)
    assert out["outcome"] == "update_available" and out["latest_version"] == "5.49.0" and out["channel"] == "prerelease"
    s = service.status(service.load(), "5.47.0")
    assert s["latest"]["prerelease"] is True and s["check"]["channel"] == "prerelease" and s["update_available"]
    assert mirror.requests[0]["path"] == "/repos/x/y/releases?per_page=10"
    assert mirror.requests[0]["headers"]["user-agent"] == "opa-compliance-wizard-update-check"   # no version unless opted in


def test_switching_channel_drops_what_was_learned_on_the_other_one(mirror):
    mirror.respond("/repos/x/y/releases/latest", body=json.dumps(rel("5.48.0")).encode(), etag='"s"')
    mirror.respond("/repos/x/y/releases", body=body(rel("5.49.0", True)), etag='"p"')
    service.run_check("5.47.0", now=NOW)
    assert service.load()["state"]["etag"] == '"s"'
    changes = service.set_settings(channel="prerelease")
    st = service.load()["state"]
    assert changes == {"channel": ["stable", "prerelease"]} and st["latest_version"] is None and st["etag"] is None
    service.run_check("5.47.0", now=NOW)
    assert "if-none-match" not in mirror.requests[-1]["headers"]   # the stable ETag was not replayed at the list URL
    assert service.load()["state"]["latest_version"] == "5.49.0"
    service.set_settings(channel="stable")
    assert service.set_settings(channel="stable") == {}


def test_a_mirror_without_a_list_url_fails_clearly(fake, monkeypatch):
    monkeypatch.setenv(service.API_URL_ENV, fake.base + "/custom-latest")
    monkeypatch.setenv(service.REVOCATION_BASE_ENV, fake.base + "/rev/")
    service.set_settings(enabled=True, channel="prerelease")
    out = service.run_check("5.47.0", now=NOW)
    assert out["outcome"] == "failed" and out["reason"] == "channel_unsupported"
    fake.respond("/lst", body=body(rel("5.49.0", True)))
    monkeypatch.setenv(service.LIST_URL_ENV, fake.base + "/lst")
    assert service.run_check("5.47.0", now=NOW)["latest_version"] == "5.49.0"


def test_env_fixes_the_channel_and_cannot_be_changed_from_the_ui(monkeypatch):
    monkeypatch.setenv("OPA_UPDATE_CHANNEL", "prerelease")
    assert service.effective_channel(service.load()) == ("prerelease", "env")
    code, body_ = service.change_settings(None, None, "5.47.0", lambda *a: None, channel="stable")
    assert code == 409 and body_["reason"] == "env_locked"
    assert service.change_settings(None, None, "5.47.0", lambda *a: None, channel="prerelease")[0] == 200
    monkeypatch.setenv("OPA_UPDATE_CHANNEL", "bogus")   # an invalid value is ignored, not trusted
    assert service.effective_channel(service.load())[1] == "setting"


def test_settings_api_validation_and_audit(monkeypatch):
    events = []
    monkeypatch.setattr(service, "kick", lambda v: None)
    code, out = service.apply_settings_request({"channel": "prerelease"}, "5.47.0", lambda a, d: events.append((a, d)))
    assert code == 200 and out["changed"] == {"channel": ["stable", "prerelease"]} and out["check"]["channel"] == "prerelease"
    assert events[0][0] == "upgrade.settings" and events[0][1]["channel"] == "prerelease"
    for bad in ({"channel": "nightly"}, {"channel": True}, {"channel": None}, {"channel": "stable", "extra": 1}):
        assert service.apply_settings_request(bad, "5.47.0", lambda a, d: None)[0] == 400
    assert service.load()["settings"]["channel"] == "prerelease"


def test_a_damaged_stored_channel_falls_back_to_stable():
    from pathlib import Path
    Path(service.state_path()).write_text(json.dumps({"settings": {"channel": "beta"}, "state": {}}))
    assert service.load()["settings"]["channel"] == "stable"


def test_cli_set_channel_and_share_version(capsys):
    assert cli.main(["set-channel", "prerelease"]) == 0
    assert "PRERELEASE" in capsys.readouterr().out and service.load()["settings"]["channel"] == "prerelease"
    assert cli.main(["status"]) == 0
    assert "Release channel   : prerelease" in capsys.readouterr().out
    assert cli.main(["share-version", "on"]) == 0 and service.load()["settings"]["share_version"] is True
    assert cli.main(["set-channel", "stable"]) == 0 and "never downgraded" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["set-channel", "nightly"])


def test_download_file_streams_and_enforces_limits(fake, tmp_path):
    hosts = check.hosts_for(fake.base)
    fake.respond("/f", body=b"x" * 1000)
    dest = tmp_path / "f.bin"
    assert check.download_file(fake.base + "/f", hosts, dest, 5000).status == "ok" and dest.read_bytes() == b"x" * 1000
    assert not (tmp_path / "f.bin.part").exists()
    big = tmp_path / "big.bin"
    got = check.download_file(fake.base + "/f", hosts, big, 10)
    assert (got.status, got.code) == ("error", "too_large") and not big.exists() and not (tmp_path / "big.bin.part").exists()
    fake.respond("/t", mode="truncate", body=b"abc")
    got = check.download_file(fake.base + "/t", hosts, tmp_path / "t.bin", 5000)
    assert got.code in ("truncated", "network") and not (tmp_path / "t.bin").exists()
    assert check.download_file(fake.base + "/missing", hosts, tmp_path / "m.bin", 5000).status == "not_found"
    assert check.download_file("http://example.com/x", hosts, tmp_path / "e.bin", 5000).code == "bad_url"
    assert check.download_file(fake.base + "/f", check.hosts_for("https://other.example.com"), tmp_path / "o.bin", 5000).code == "bad_url"
