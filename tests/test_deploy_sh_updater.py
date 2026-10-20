"""deploy.sh on an install that ran server/install.sh (5.47.0): a thin wrapper that stages the signed release and hands
over to the root-owned updater (`ocw-updater`), so the manual and the in-app path are the same code."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="deploy.sh runs on Linux servers")


@pytest.fixture
def layout(tmp_path):
    opt = tmp_path / "opt"
    (opt / "updater").mkdir(parents=True)
    (opt / "updater" / "ocw_activate.py").write_text("#!/usr/bin/env python3\n")
    (opt / "updater" / "ocw_activate.py").chmod(0o755)
    rel = opt / "releases" / "5.47.0" / "server"
    rel.mkdir(parents=True)
    shutil.copy(REPO / "server" / "deploy.sh", rel / "deploy.sh")
    log = tmp_path / "calls.log"
    fake = tmp_path / "ocw-updater"
    fake.write_text(f'#!/bin/bash\necho "$*" >> "{log}"\nexit "${{FAKE_RC:-0}}"\n')
    fake.chmod(0o755)
    sudo = tmp_path / "bin" / "sudo"
    sudo.parent.mkdir()
    sudo.write_text('#!/bin/bash\nexec "$@"\n')
    sudo.chmod(0o755)
    env = dict(os.environ, OCW_OPT_DIR=str(opt), OCW_UPDATER_BIN=str(fake), PATH=f"{sudo.parent}:{os.environ['PATH']}")
    for k in ("DEPLOY_SH_PHASE", "OPA_APP_DIR"):
        env.pop(k, None)

    def run(*args, rc=0):
        e = dict(env, FAKE_RC=str(rc))
        return subprocess.run(["bash", str(rel / "deploy.sh"), *args], capture_output=True, text=True, env=e, timeout=60)
    run.log = lambda: log.read_text().splitlines() if log.exists() else []
    run.tmp = tmp_path
    return run


def test_release_is_staged_then_applied_by_the_updater(layout):
    p = layout("--release", "5.48.0")
    assert p.returncode == 0, p.stderr
    assert layout.log() == ["stage 5.48.0", "apply 5.48.0"]


def test_release_from_a_directory_stages_the_file_and_applies_a_bundled_revocation_first(layout):
    d = layout.tmp / "dl"
    d.mkdir()
    (d / "ocw-5.48.0.tar.gz").write_bytes(b"x")
    (d / "ocw-5.48.0.tar.gz.minisig").write_text("x")
    assert layout("--release", "5.48.0", "--from-dir", str(d)).returncode == 0
    assert layout.log() == [f"stage {d}/ocw-5.48.0.tar.gz", "apply 5.48.0"]
    (d / "revocation.json").write_text("{}")
    layout.log()
    p = layout("--release", "5.48.0", "--from-dir", str(d))
    assert p.returncode == 0 and f"trust apply {d}/revocation.json" in layout.log()
    d2 = layout.tmp / "empty"
    d2.mkdir()
    p = layout("--release", "5.48.0", "--from-dir", str(d2))
    assert p.returncode == 1 and "must contain" in p.stderr


def test_a_refused_stage_stops_before_apply(layout):
    p = layout("--release", "5.48.0", rc=2)
    assert p.returncode == 2 and layout.log() == ["stage 5.48.0"]


def test_unsigned_ref_and_reinstall_are_refused_in_the_new_layout(layout):
    p = layout("--ref", "main")
    assert p.returncode == 2 and "UNSIGNED" in p.stderr and layout.log() == []
    p = layout("--release", "5.48.0", "--reinstall")
    assert p.returncode == 2 and "never installs the same version" in p.stderr
    p = layout()
    assert p.returncode == 2 and "usage" in p.stderr


def test_an_unmigrated_install_is_told_what_to_do(tmp_path):
    """Outside the upgrade layout the old logic runs, after a clear note (it fails fast here: not an installed copy)."""
    srv = tmp_path / "app" / "server"
    srv.mkdir(parents=True)
    shutil.copy(REPO / "server" / "deploy.sh", srv / "deploy.sh")
    env = {k: v for k, v in os.environ.items() if k not in ("DEPLOY_SH_PHASE", "OPA_APP_DIR")}
    p = subprocess.run(["bash", str(srv / "deploy.sh"), "--release", "5.48.0"], capture_output=True, text=True, env=env, timeout=60)
    assert "still uses the in-place layout" in p.stderr and "server/install.sh" in p.stderr
