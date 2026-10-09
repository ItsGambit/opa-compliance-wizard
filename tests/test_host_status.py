"""Covers server/host_status.py (5.39.0): the parsers, the overall state, the generated unit, and the
HTTP handler (only GET /__status answers; nothing secret-looking in the output)."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from server import host_status as hs

APT = """NOTE: This is only a simulation!
Inst libssl3t64 [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-3ubuntu1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Conf openssl (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])
"""


def test_apt_counts_pending_and_security():
    assert hs.parse_apt_simulation(APT) == (3, 2)
    assert hs.parse_apt_simulation("0 upgraded, 0 newly installed") == (0, 0)


def test_meminfo():
    m = hs.parse_meminfo("MemTotal:  4000000 kB\nMemFree: 100 kB\nMemAvailable: 1000000 kB\n")
    assert m == {"total_mb": 3906, "available_mb": 976, "used_pct": 75.0}
    assert hs.parse_meminfo("")["used_pct"] is None


def test_os_release_and_version():
    assert hs.parse_os_release('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n') == "Ubuntu 24.04.3 LTS"
    assert hs.parse_app_version('x = 1\nSCRIPT_VERSION = "5.39.0"\n') == "5.39.0"
    assert hs.parse_app_version("") == ""


def test_services_from_env_drops_anything_odd():
    assert hs.services_from_env("nginx opa-auth-gate-x cloudflared") == ["nginx", "opa-auth-gate-x", "cloudflared"]
    odd = hs.services_from_env("nginx; rm -rf / $(id) --now -x")
    assert odd == ["rm"]                                  # plain word: harmless, reported as "unknown"
    assert not any(n.startswith("-") for n in odd)        # nothing systemctl could read as an option
    assert hs.services_from_env(None) == []


def _status(**over):
    s = {"services": {"nginx": "active"}, "updates": {"security": 0, "reboot_required": False},
         "disk": {"used_pct": 40}, "memory": {"used_pct": 50}}
    s.update(over)
    return s


@pytest.mark.parametrize("over, state", [
    ({}, "ok"),
    ({"services": {"nginx": "active", "cloudflared": "failed"}}, "down"),
    ({"updates": {"security": 3, "reboot_required": False}}, "warn"),
    ({"updates": {"security": 0, "reboot_required": True}}, "warn"),
    ({"updates": {"security": None, "reboot_required": False}}, "ok"),
    ({"disk": {"used_pct": 95}}, "warn"),
    ({"memory": {"used_pct": 91}}, "warn"),
])
def test_overall_state(over, state):
    assert hs.overall_state(_status(**over)) == state


def test_unit_is_sandboxed_and_loopback_only():
    unit = hs.build_unit("/home/app/opa", "app", 8790, "nginx cloudflared")
    assert "User=app\n" in unit
    assert 'Environment=HOST_STATUS_SERVICES="nginx cloudflared"' in unit
    assert "ExecStart=/usr/bin/python3 /home/app/opa/server/host_status.py --port 8790" in unit
    for line in ("NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict", "ProtectHome=read-only"):
        assert line in unit


@pytest.mark.parametrize("args", [
    ("relative/dir", "app", 8790, "nginx"),
    ("/home/app/opa", "root", 8790, "nginx"),
    ("/home/app/opa", "app", 8766, "nginx"),
    ("/home/app/opa", "app", 8790, "nginx; reboot"),
    ("/home/app/opa", "app", 8790, ""),
    ("/home/app/opa\nExecStartPre=/bin/sh", "app", 8790, "nginx"),
])
def test_unit_rejects_bad_input(args):
    with pytest.raises(ValueError):
        hs.build_unit(*args)


@pytest.fixture()
def server(monkeypatch):
    monkeypatch.setattr(hs, "collect", lambda: {"state": "ok", "host": "vm"})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), hs.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_handler_serves_only_status(server):
    with urllib.request.urlopen(server + "/__status") as r:
        assert r.status == 200 and r.headers["Cache-Control"] == "no-store"
        assert json.load(r) == {"state": "ok", "host": "vm"}
    for path in ("/", "/__status/../etc/passwd", "/api/version"):
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(server + path)
        assert e.value.code == 404


def test_collect_runs_here_and_has_no_secret_fields(monkeypatch):
    monkeypatch.setenv("HOST_STATUS_SERVICES", "")
    monkeypatch.setattr(hs, "_updates", lambda: {"pending": 0, "security": 0, "reboot_required": False})
    s = hs.collect()
    assert s["state"] in ("ok", "warn", "down")
    assert set(s) == {"checked_at", "host", "os", "kernel", "uptime_seconds", "load", "cpus", "memory",
                      "disk", "services", "updates", "app_version", "state"}


# GATE-15 (5.40.5): a slow apt simulation no longer blocks concurrent callers.
def test_concurrent_callers_do_not_queue_behind_the_apt_refresh(monkeypatch):
    import time

    started, release = threading.Event(), threading.Event()

    def slow():
        started.set()
        release.wait(10)
        return {"pending": 1, "security": 0, "checked_at": "t"}

    monkeypatch.setattr(hs, "_run_apt_simulation", slow)
    monkeypatch.setattr(hs, "_updates_cache", {"at": 0.0, "value": {"pending": 9, "security": 9, "checked_at": "old"}})
    worker = threading.Thread(target=hs._updates)
    worker.start()
    assert started.wait(5)
    t0 = time.time()
    value = hs._updates()  # refresh in flight: answers at once with the previous result
    assert time.time() - t0 < 1 and value["pending"] == 9
    release.set()
    worker.join(5)
    assert hs._updates()["pending"] == 1


def test_first_ever_call_while_refreshing_returns_nulls(monkeypatch):
    monkeypatch.setattr(hs, "_updates_cache", {"at": 0.0, "value": None})
    assert hs._updates_lock.acquire(blocking=False)
    try:
        value = hs._updates()
    finally:
        hs._updates_lock.release()
    assert value["pending"] is None and value["security"] is None and "reboot_required" in value


def test_handler_has_a_socket_timeout():
    assert hs.Handler.timeout == 30
