"""5.53.0 (F1): a login gate that is installed but disabled and not running (a fresh install before the Okta setup) is neither
restarted nor health-checked by the root updater, so it cannot fail an upgrade or its rollback. Also the app's preflight item for a
server whose installed updater is older than 5.53.0, and the uninstall's removal of the staging account's cache (F2)."""

import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import updater_fakes as uf
from server.updater import upgrade
from test_install_fresh import world  # noqa: F401  (the fixture)
from test_updater_state_machine import run_apply

REPO = Path(__file__).resolve().parent.parent
GATE = "opa-auth-gate"


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def set_gate(m, enabled, active, extra=None):
    u = m.host.units[GATE]
    u["enabled"] = enabled
    u["ActiveState"] = "active" if active else "inactive"
    for name, spec in (extra or {}).items():
        m.host.units[name] = dict({"ActiveState": "active", "MainPID": "9", "NRestarts": "0", "port": 8790, "enabled": True}, **spec)


@pytest.mark.parametrize("enabled,active,listed", [(True, True, True), (True, False, True), (False, True, True), (False, False, False)])
def test_units_lists_the_main_gate_only_when_enabled_or_active(m, enabled, active, listed):
    set_gate(m, enabled, active)
    units = m.updater().units()
    assert (GATE in units) is listed and "opa-compliance-wizard" in units


def test_units_without_a_gate_unit_has_no_gate(m):
    del m.host.units[GATE]
    assert m.updater().units() == ["opa-compliance-wizard"]


def test_extra_gates_are_listed_only_when_enabled(m):
    set_gate(m, True, True, extra={"opa-auth-gate-a": {}, "opa-auth-gate-b": {"enabled": False, "ActiveState": "inactive"}})
    assert m.updater().units() == ["opa-compliance-wizard", GATE, "opa-auth-gate-a"]


def test_a_skipped_gate_is_logged_once_with_the_reason(m, capsys):
    set_gate(m, False, False)
    up = m.updater()
    up.units(), up.units(), up.units()
    out = capsys.readouterr().out
    assert out.count("installed but disabled and not running") == 1 and GATE in out


def test_upgrade_with_a_disabled_unconfigured_gate_completes_and_never_touches_it(m):
    set_gate(m, False, False)
    m.host.restart_fail_units.add(GATE)           # starting it would fail, as it does without OKTA_ORG_URL
    up, result = run_apply(m, cid="upg-aaaa0f01")
    assert result == "completed"
    assert not [c for c in m.host.calls if c[:1] == ("systemctl",) and GATE in c and c[1] in ("restart", "start")]
    assert m.host.units[GATE]["ActiveState"] == "inactive"


def test_rollback_with_a_disabled_unconfigured_gate_does_not_fail(m):
    set_gate(m, False, False)
    m.host.restart_fail_units.add(GATE)
    m.host.crash_versions.add("5.47.0")           # the new release crash-loops: the upgrade rolls back
    up, result = run_apply(m, cid="upg-aaaa0f02")
    assert result == "rolled_back" and m.read_state()["reason_code"] == "health_unit"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_an_enabled_gate_that_fails_to_restart_still_fails_the_upgrade(m):
    m.host.restart_fail_units.add(GATE)
    up, result = run_apply(m, cid="upg-aaaa0f03")
    assert result != "completed"


def test_the_activator_version_is_5_53_0():
    text = (REPO / "server" / "updater" / "root" / "ocw_activate.py").read_text()
    assert re.search(r'^ACTIVATOR_VERSION = "5\.53\.0"$', text, re.M)


# --- the app's preflight item ------------------------------------------------------------------------------------------------
def _preflight():
    return {i["id"]: i for i in upgrade.preflight({}, 1000, {}, datetime.now(timezone.utc))}


@pytest.fixture
def hazard(tmp_path, monkeypatch):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    (unit_dir / f"{GATE}.service").write_text("[Service]\n")
    monkeypatch.setenv("OCW_UNIT_DIR", str(unit_dir))
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.setattr(upgrade, "updater_activator_version", lambda: "5.52.0")
    state = {"is-enabled": False, "is-active": False}
    monkeypatch.setattr(upgrade, "_systemctl_ok", lambda *a: state[a[0]])
    return state, unit_dir


def test_preflight_refuses_an_unset_gate_with_an_old_activator_and_names_the_remedy(hazard):
    item = _preflight()["gate_not_set_up"]
    assert item["ok"] is False and "sudo bash get-ocw.sh --refresh-updater --version 5.53.0" in item["text"]
    assert "finish the gate setup" in item["text"]


@pytest.mark.parametrize("change", ["enabled", "active", "configured", "new_activator", "unknown_activator", "no_unit", "systemctl_unanswered"])
def test_preflight_has_no_gate_item_unless_the_hazard_is_certain(hazard, monkeypatch, change):
    state, unit_dir = hazard
    if change == "enabled":
        state["is-enabled"] = True
    elif change == "active":
        state["is-active"] = True
    elif change == "configured":
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
    elif change == "new_activator":
        monkeypatch.setattr(upgrade, "updater_activator_version", lambda: "5.53.0")
    elif change == "unknown_activator":
        monkeypatch.setattr(upgrade, "updater_activator_version", lambda: None)
    elif change == "no_unit":
        (unit_dir / f"{GATE}.service").unlink()
    elif change == "systemctl_unanswered":
        state["is-enabled"] = None
    assert "gate_not_set_up" not in _preflight()


# --- uninstall removes the staging account's cache (F2) -----------------------------------------------------------------------
pytestmark_install = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("bash"), reason="install.sh is a Linux server script")


def _make_cache(cache):
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "http").mkdir(exist_ok=True)
    (cache / "http" / "blob").write_text("pip cache")


@pytestmark_install
def test_uninstall_removes_the_updaters_cache_directory(world):  # noqa: F811
    cache = world.w / "var-cache" / "ocw-updater"
    assert world.fresh().returncode == 0
    _make_cache(cache)
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_UPDATER_CACHE_DIR": str(cache)})
    assert p.returncode == 0, p.stderr + p.stdout
    assert not cache.exists() and cache.parent.exists() and "pip cache" in p.stdout


@pytestmark_install
def test_uninstall_dry_run_lists_the_cache_and_keeps_it(world):  # noqa: F811
    cache = world.w / "var-cache" / "ocw-updater"
    assert world.fresh().returncode == 0
    _make_cache(cache)
    p = world.run("--uninstall", "--keep-data", "--dry-run", extra_env={"OCW_UPDATER_CACHE_DIR": str(cache)})
    assert p.returncode == 0 and str(cache) in p.stdout and cache.exists()


@pytestmark_install
def test_uninstall_leaves_a_cache_that_is_a_link_or_not_named_ocw_updater(world):  # noqa: F811
    real = world.w / "elsewhere"
    real.mkdir()
    (real / "keep").write_text("x")
    link = world.w / "var-cache" / "ocw-updater"
    link.parent.mkdir()
    link.symlink_to(real)
    other = world.w / "var-cache" / "other-name"
    other.mkdir()
    assert world.fresh().returncode == 0
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_UPDATER_CACHE_DIR": str(link)})
    assert p.returncode == 0, p.stderr + p.stdout
    assert (real / "keep").read_text() == "x" and link.is_symlink()
    assert world.fresh().returncode == 0
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_UPDATER_CACHE_DIR": str(other)})
    assert p.returncode == 0 and other.exists()
