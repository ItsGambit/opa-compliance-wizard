"""SystemHost (server/updater/root/ocw_host.py) against the shared command stubs in tests/deploy_sh_stubs.py (systemctl,
journalctl, nginx): the real command construction and output parsing, with nothing touching the machine."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import updater_fakes  # noqa: F401  (sys.path)
import ocw_host

STUBS = Path(__file__).resolve().parent / "deploy_sh_stubs.py"
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell wrappers")


@pytest.fixture
def host(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state = {"units": {
        "opa-compliance-wizard": {"MainPID": "10", "NRestarts": "0", "ActiveState": "active"},
        "opa-auth-gate": {"MainPID": "11", "ActiveState": "active", "ExecStart": "{ path=/x ; argv[]=/x/python server/auth_gate.py --port 8767 ; }"},
        "opa-auth-gate-second": {"MainPID": "12", "ActiveState": "active", "ExecStart": "{ argv[]=/x/python server/auth_gate.py --port 8790 ; }"},
        "opa-auth-gate-off": {"enabled": False},
    }, "journal": {"opa-compliance-wizard": [f"line {i}" for i in range(1, 11)]}, "nginx_t_results": [0, 1]}
    sp = tmp_path / "state.json"
    sp.write_text(json.dumps(state))
    for name in ("systemctl", "journalctl", "nginx"):
        w = bin_dir / name
        w.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{STUBS}" {name} "$@"\n')
        w.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DEPLOY_STUB_STATE", str(sp))
    h = ocw_host.SystemHost()
    h.state = lambda: json.loads(sp.read_text())
    return h


def test_unit_queries_parse_systemctl_output(host):
    assert host.unit_exists("opa-compliance-wizard") and not host.unit_exists("nope")
    assert host.unit_prop("opa-compliance-wizard", "MainPID") == "10"
    assert host.unit_prop("opa-compliance-wizard", "ActiveState") == "active"
    assert host.unit_enabled("opa-auth-gate") and not host.unit_enabled("opa-auth-gate-off")
    assert host.extra_gate_units() == ["opa-auth-gate-second"]  # enabled ones only
    assert host.gate_port("opa-auth-gate") == 8767 and host.gate_port("opa-auth-gate-second") == 8790


def test_restart_changes_the_pid_and_reports_failure(host):
    ok, _out = host.restart("opa-compliance-wizard")
    assert ok and host.unit_prop("opa-compliance-wizard", "MainPID") == "1010"
    ok, _out = host.restart("no-such-unit")
    assert not ok


def test_journal_returns_the_last_lines(host):
    out = host.journal("opa-compliance-wizard", lines=3)
    assert out.splitlines() == ["line 8", "line 9", "line 10"]


def test_nginx_test_and_a_missing_program(host):
    assert host.nginx_test()[0] == 0
    rc, out = host.nginx_test()
    assert rc != 0 and "emerg" in out
    assert host.run(["definitely-not-a-program"])[0] == 127


def test_atomic_symlink_switch(host, tmp_path):
    (tmp_path / "releases" / "a").mkdir(parents=True)
    (tmp_path / "releases" / "b").mkdir(parents=True)
    link = tmp_path / "current"
    host.switch_symlink(str(link), "releases/a")
    host.switch_symlink(str(link), "releases/b")
    assert os.readlink(link) == "releases/b" and not list(tmp_path.glob("current.tmp-*"))


def test_database_tool_runs_in_a_child_process_and_never_creates_a_database(host, tmp_path):
    import sqlite3
    db = tmp_path / "a.db"
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE schema_migrations (version INTEGER); INSERT INTO schema_migrations VALUES (9);"
                       "CREATE TABLE chain_heads (environment_id TEXT, manifest_id TEXT, head_hash TEXT);"
                       "INSERT INTO chain_heads VALUES ('e', 'm', 'h');")
    conn.commit()
    conn.close()
    snap = host.db_tool(["snapshot", str(db)])
    assert snap["ok"] and snap["schema_version"] == 9 and snap["chain_heads"] == {"e": "h"} and snap["quick_check"] == "ok"
    missing = host.db_tool(["snapshot", str(tmp_path / "none.db")])
    assert missing["ok"] and missing["exists"] is False and not (tmp_path / "none.db").exists()
    bk = host.db_tool(["backup", str(db), str(tmp_path / "b.db")])
    assert bk["ok"] and bk["integrity_check"] == "ok" and oct((tmp_path / "b.db").stat().st_mode & 0o777) == "0o600"
    assert host.db_tool(["bogus"])["ok"] is False
