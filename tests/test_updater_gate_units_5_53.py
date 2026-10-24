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
    monkeypatch.setattr(upgrade, "_unit_state", lambda verb, unit: state[verb])
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


def test_a_disabled_but_running_gate_that_dies_after_the_restart_fails_the_health_check_and_rolls_back(m):
    set_gate(m, False, True)                      # running, though not enabled
    orig = m.host._start_unit

    def start(unit):
        ok = orig(unit)
        if unit == GATE and uf._installed(m.opt_current()) == "5.47.0":      # the new release kills it
            m.host.units[GATE].update(ActiveState="inactive", NRestarts="1")
        return ok
    m.host._start_unit = start
    up, result = run_apply(m, cid="upg-aaaa0f04")
    assert result == "rolled_back" and m.read_state()["reason_code"] == "health_unit"
    assert GATE in up.units() and os.readlink(m.opt / "current") == "releases/5.46.0"


def test_the_skip_note_is_logged_again_for_each_new_run(m, capsys):
    set_gate(m, False, False)
    up = m.updater()
    up.units()
    up.begin_run()
    up.units()
    assert capsys.readouterr().out.count("installed but disabled and not running") == 2


# --- the activator version is read from the real layout -----------------------------------------------------------------------
def _lay_out(opt, version_line='ACTIVATOR_VERSION = "5.52.0"\n', with_launcher=True):
    lib = opt / "updater" / "lib" / "install-20260101"
    lib.mkdir(parents=True)
    (lib / "ocw_activate.py").write_text("# the activator\n" + version_line)
    (opt / "updater" / "current").symlink_to("lib/install-20260101")
    if with_launcher:
        (opt / "updater" / "ocw_activate.py").write_text("# the fixed launcher: follows the `current` link\n")


def test_the_version_is_read_through_the_current_link_behind_the_launcher(tmp_path, monkeypatch):
    opt = tmp_path / "opt"
    _lay_out(opt)
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    assert upgrade.updater_activator_version() == "5.52.0"


def test_the_version_of_a_layout_from_before_the_launcher_is_read_from_the_top_level_file(tmp_path, monkeypatch):
    opt = tmp_path / "opt"
    (opt / "updater").mkdir(parents=True)
    (opt / "updater" / "ocw_activate.py").write_text('ACTIVATOR_VERSION = "5.46.0"\n')
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    assert upgrade.updater_activator_version() == "5.46.0"


def test_the_preflight_refuses_on_a_real_on_disk_layout_without_patching_the_version(tmp_path, monkeypatch):
    opt = tmp_path / "opt"
    _lay_out(opt)
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    (unit_dir / f"{GATE}.service").write_text("[Service]\n")
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    monkeypatch.setenv("OCW_UNIT_DIR", str(unit_dir))
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.setattr(upgrade, "_unit_state", lambda verb, unit: False)
    items = _preflight()
    assert items["gate_not_set_up"]["ok"] is False


# --- systemctl answers: only the plain ones are certain -----------------------------------------------------------------------
class _R:
    def __init__(self, rc, out):
        self.returncode, self.stdout = rc, out.encode()


@pytest.mark.parametrize("verb,rc,out,want", [
    ("is-active", 0, "active\n", True), ("is-active", 3, "inactive\n", False), ("is-active", 3, "failed\n", False),
    ("is-active", 3, "activating\n", None), ("is-active", 1, "", None), ("is-active", 4, "", None), ("is-active", 1, "Failed to connect to bus\n", None),
    ("is-enabled", 1, "disabled\n", False), ("is-enabled", 0, "enabled\n", True), ("is-enabled", 0, "enabled-runtime\n", True),
    ("is-enabled", 0, "static\n", True), ("is-enabled", 0, "alias\n", True), ("is-enabled", 1, "", None),
    ("is-enabled", 1, "masked\n", None), ("is-enabled", 1, "Failed to connect to bus\n", None)])
def test_unit_state_reads_only_plain_answers(monkeypatch, verb, rc, out, want):
    monkeypatch.setattr(upgrade.subprocess, "run", lambda *a, **k: _R(rc, out))
    assert upgrade._unit_state(verb, GATE) is want


def test_unit_state_is_doubt_when_systemctl_is_missing_or_hangs(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("systemctl")
    monkeypatch.setattr(upgrade.subprocess, "run", boom)
    assert upgrade._unit_state("is-active", GATE) is None
    def hang(*a, **k):
        raise upgrade.subprocess.TimeoutExpired("systemctl", 5)
    monkeypatch.setattr(upgrade.subprocess, "run", hang)
    assert upgrade._unit_state("is-enabled", GATE) is None


def test_no_bus_does_not_refuse(hazard, monkeypatch):
    monkeypatch.undo()                              # the real _unit_state, with systemctl answering "no bus" for both
    monkeypatch.setenv("OCW_UNIT_DIR", str(hazard[1]))
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.setattr(upgrade, "updater_activator_version", lambda: "5.52.0")
    monkeypatch.setattr(upgrade.subprocess, "run", lambda *a, **k: _R(1, "Failed to connect to bus: No such file or directory\n"))
    assert "gate_not_set_up" not in _preflight()


# --- 5.53.0 requires the refresh (install_sh_min_version) -----------------------------------------------------------------------
def test_the_release_manifest_carries_install_sh_min_version_5_53_0():
    sys.path.insert(0, str(REPO / "tools"))
    import release as tool
    files = {"server/install.sh": (0, (REPO / "server" / "install.sh").read_bytes())}
    assert tool._install_sh_marker(files, "5.53.0") == "5.53.0"
    with pytest.raises(tool.ReleaseError):
        tool._install_sh_marker(files, "5.52.0")      # the marker may never be newer than the release


def test_a_5_52_0_style_updater_refuses_5_53_0_before_switching(m):
    from test_updater_hardening import _apply_5_47_0, _set_install_sh_version
    _set_install_sh_version(m, "5.52.0")
    assert _apply_5_47_0(m, {"install_sh_min_version": "5.53.0"}, "upg-aaaa0f05") == "failed"
    st = m.read_state()
    assert st["reason_code"] == "needs_install_sh" and "sudo server/install.sh --refresh-updater" in st["error"]
    assert "get-ocw.sh --refresh-updater --version" in st["error"]
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_after_the_refresh_record_of_5_53_0_the_upgrade_proceeds(m):
    from test_updater_hardening import _apply_5_47_0, _set_install_sh_version
    _set_install_sh_version(m, "5.53.0")             # what `install.sh --refresh-updater` records
    assert _apply_5_47_0(m, {"install_sh_min_version": "5.53.0"}, "upg-aaaa0f06") == "completed"
