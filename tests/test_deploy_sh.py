"""server/deploy.sh, run for real against a temp install with stubbed system
commands (tests/deploy_sh_stubs.py): git clones a local fixture copy of this
checkout, sudo/systemctl/nginx/npm/npx/curl answer from a state file.

Covers the review's OPS-02 (relocatable install dir, .deploy.conf), OPS-06
(--ref, npm --ignore-scripts), OPS-09 (secret-bearing files owner-only, live
site / leftover backup warnings), OPS-10 (exactly one terminal audit event per
run, with the stage), OPS-11 (preflight before anything changes, lock,
frontend swap, units must stay up, nginx rollback), the phase handoff from an
OLDER release's phase 1, and the systemd daemon-reload explanation.
"""

import fcntl
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
STUBS = Path(__file__).resolve().parent / "deploy_sh_stubs.py"
# server/deploy.sh as released in 5.40.7 (the last release before the 5.41.0
# rewrite), with its hardcoded install directory replaced by __APP_DIR__. A
# fixture rather than `git show`: CI checks out one commit, with no history.
OLD_DEPLOY_SH = (Path(__file__).resolve().parent / "fixtures" / "deploy_sh_5_40_7.sh.txt").read_text()
SECRET = "s3cr3t&with\\odd\\tchars"
SECRET_PLAIN = "0123456789abcdef0123456789abcdef"
SERVER_NAME = "opa.example.test"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="deploy.sh runs on Linux servers")


def _host_lacks(cmd_argv):
    try:
        return subprocess.run(cmd_argv, capture_output=True).returncode != 0
    except FileNotFoundError:
        return True


@pytest.fixture(scope="session")
def source_tree(tmp_path_factory):
    """The tracked files of this checkout, as they are in the working tree --
    so the deploy.sh under test is the one being changed."""
    root = tmp_path_factory.mktemp("src") / "tree"
    files = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=REPO,
                           capture_output=True, check=True).stdout
    for rel in files.decode().split("\0"):
        if not rel or not (REPO / rel).is_file():
            continue
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dest)
    return root


class Deploy:
    def __init__(self, tmp_path, source_tree):
        self.tmp = tmp_path
        self.remote = tmp_path / "remote"
        self.app = tmp_path / "srv" / "my install"  # a space and a non-default location (OPS-02)
        self.tmpdir = tmp_path / "t"
        self.bin = tmp_path / "bin"
        self.state_path = tmp_path / "state" / "state.json"
        self.nginx_live = tmp_path / "etc" / "sites-available" / "opa-secrets-wizard"
        shutil.copytree(source_tree, self.remote)
        shutil.copytree(source_tree, self.app)
        for d in (self.tmpdir, self.bin, self.state_path.parent, self.nginx_live.parent):
            d.mkdir(parents=True, exist_ok=True)
        venv_bin = self.app / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        self._wrapper(venv_bin / "python", f'exec "{sys.executable}" "$@"')
        self._stub(venv_bin / "pip", "pip")
        (self.app / "frontend" / "dist").mkdir(parents=True)
        (self.app / "frontend" / "dist" / "index.html").write_text("old build")
        for name in ("git", "sudo", "systemctl", "nginx", "npm", "npx", "curl", "sleep"):
            self._stub(self.bin / name, name)
        if shutil.which("flock") is None:
            self._stub(self.bin / "flock", "flock")
        if _host_lacks(["realpath", "-m", "--", "/nonexistent/x/.."]):
            self._stub(self.bin / "realpath", "realpath")
        self.version = self._script_version()
        self.state = {
            "units": {
                "opa-secrets-wizard": {"MainPID": "100", "ActiveState": "active",
                                       "ExecStart": "{ argv[]=/x/start-headless.sh }"},
                "opa-auth-gate": {"MainPID": "200", "ActiveState": "active",
                                  "ExecStart": "{ path=/x/python ; argv[]=/x/python server/auth_gate.py --port 8767 ; }"},
            },
            "backend_version": "0.0.1",
            "version_after_restart": self.version,
            "sudo_allow": self.full_grants(),
            "head_sha": "c" * 40,
        }

    def _wrapper(self, path, body):
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def _stub(self, path, name):
        self._wrapper(path, f'exec "{sys.executable}" "{STUBS}" {name} "$@"')

    def _script_version(self):
        for line in (self.remote / "create_secret_folders.py").read_text().splitlines():
            if line.startswith("SCRIPT_VERSION = "):
                return line.split('"')[1]
        raise AssertionError("no SCRIPT_VERSION")

    def full_grants(self, units=("opa-secrets-wizard", "opa-auth-gate"), nginx=True):
        grants = [f"systemctl restart {u}" for u in units]
        if nginx:
            repo_conf = self.app / "server" / "nginx-opa-secrets-wizard.conf"
            grants += [f"cp {repo_conf} {self.nginx_live}", f"cp {self.app / '.nginx-deploy-backup'} {self.nginx_live}",
                       "nginx -t", "systemctl reload nginx"]
        return grants

    def live_site(self, secret=SECRET, mode=0o640, extra=""):
        template = (self.remote / "server" / "nginx-opa-secrets-wizard.conf").read_text()
        text = (template.replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", secret)
                .replace("REPLACE_WITH_SERVER_NAME", SERVER_NAME) + extra)
        self.nginx_live.write_text(text)
        self.nginx_live.chmod(mode)
        return text

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "OPA_"))}
        env.update({
            "PATH": f"{self.bin}{os.pathsep}{env.get('PATH', '/usr/bin:/bin')}",
            "TMPDIR": str(self.tmpdir),
            "DEPLOY_STUB_STATE": str(self.state_path),
            "OPA_REPO_URL": f"file://{self.remote}",
            "OPA_NGINX_SITE": str(self.nginx_live),
            "OPA_WIZARD_SKIP_DOTENV": "1",
        })
        env.update({k: v for k, v in extra.items() if v is not None})
        for k, v in extra.items():
            if v is None:
                env.pop(k, None)
        return env

    def run(self, *args, script=None, env=None, timeout=180):
        self.state_path.write_text(json.dumps(self.state))
        calls = self.state_path.parent / "calls.jsonl"
        if calls.exists():
            calls.unlink()
        script = script or (self.app / "server" / "deploy.sh")
        proc = subprocess.run(["bash", str(script), *args], env=env or self.env(), capture_output=True,
                              text=True, timeout=timeout, cwd=str(self.tmp))
        self.state = json.loads(self.state_path.read_text())
        self.out = proc.stdout + proc.stderr
        return proc

    def calls(self, cmd=None):
        path = self.state_path.parent / "calls.jsonl"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        return [r["argv"] for r in rows if cmd is None or r["cmd"] == cmd]

    def events(self):
        path = self.app / "audit_log.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def deploy_events(self):
        return [(e["action"], e["details"]) for e in self.events() if e["action"].startswith("deploy.")]

    def assert_one_terminal(self, action, stage=None):
        evs = self.deploy_events()
        actions = [a for a, _ in evs]
        assert actions.count("deploy.started") == 1, (evs, self.out)
        terminal = [(a, d) for a, d in evs if a in ("deploy.completed", "deploy.failed")]
        assert len(terminal) == 1, (evs, self.out)
        assert terminal[0][0] == action, (evs, self.out)
        if stage is not None:
            assert terminal[0][1].get("stage") == stage, (evs, self.out)
        assert terminal[0][1]["commit"] == "c" * 40
        return terminal[0][1]

    def leftover_temp_dirs(self):
        return sorted(p.name for p in self.tmpdir.iterdir() if p.name.startswith("opa-deploy-"))


@pytest.fixture
def d(tmp_path, source_tree):
    return Deploy(tmp_path, source_tree)


# --- happy paths --------------------------------------------------------


def test_full_deploy_into_a_relocated_install(d):
    proc = d.run()
    assert proc.returncode == 0, d.out
    d.assert_one_terminal("deploy.completed")
    # phase 2 ran THIS install's pip, not a hardcoded path (OPS-02)
    assert d.state["pip_argv"] == ["install", "-q", "-r", str(d.app / "requirements.txt")]
    assert ["ci", "--ignore-scripts", "--silent"] in d.calls("npm")  # OPS-06
    assert ["vite", "build", "--outDir", "dist.new"] in d.calls("npx")
    assert (d.app / "frontend" / "dist" / "index.html").read_text() == "new build"
    assert not (d.app / "frontend" / "dist.new").exists()
    assert not (d.app / "frontend" / "dist.old").exists()
    assert d.state["restarted"] == ["opa-secrets-wizard", "opa-auth-gate"]
    assert d.leftover_temp_dirs() == []
    assert (d.app / ".deploy.lock").exists()
    assert "Deployed version " + d.version in d.out
    # nothing nginx-related without a live site
    assert d.state.get("nginx_reloads") is None


def test_local_state_survives_the_rsync(d):
    keep = {".deploy.conf": "OPA_BACKEND_PORT=8766\n", "my-folders.csv": "path\n", "audit_log.jsonl": "",
            ".env": "X=1\n", "access_control.json": "{}"}
    for name, body in keep.items():
        (d.app / name).write_text(body)
    (d.app / "stale-tracked-file.py").write_text("x")
    assert d.run().returncode == 0, d.out
    for name in keep:
        assert (d.app / name).exists(), name
    assert not (d.app / "stale-tracked-file.py").exists()


def test_frozen_copy_runs_without_an_exec_bit(d):
    """OPS-11: phases are started with `bash <file>`, so a noexec temp dir works."""
    (d.app / "server" / "deploy.sh").chmod(0o644)
    assert d.run().returncode == 0, d.out


def test_extra_gate_and_host_status_are_restarted_and_probed(d):
    d.state["units"]["opa-auth-gate-two"] = {"MainPID": "300", "ActiveState": "active",
                                             "ExecStart": "{ argv[]=/x/python server/auth_gate.py --port 8768 ; }"}
    d.state["units"]["opa-host-status"] = {"MainPID": "400", "ActiveState": "active"}
    d.state["sudo_allow"] = d.full_grants(units=("opa-secrets-wizard", "opa-auth-gate", "opa-auth-gate-two",
                                                 "opa-host-status"))
    assert d.run().returncode == 0, d.out
    assert d.state["restarted"] == ["opa-secrets-wizard", "opa-auth-gate", "opa-auth-gate-two", "opa-host-status"]
    probed = [a[-1] for a in d.calls("curl") if a[-1].endswith("/verify")]
    assert "http://127.0.0.1:8768/verify" in probed and "http://127.0.0.1:8767/verify" in probed


def test_disabled_extra_gate_is_skipped(d):
    d.state["units"]["opa-auth-gate-off"] = {"enabled": False}
    assert d.run().returncode == 0, d.out
    assert "opa-auth-gate-off" not in d.state["restarted"]


# --- settings (OPS-02 / OPS-06) -------------------------------------------


def test_deploy_conf_sets_the_repo_and_the_environment_wins(d, tmp_path):
    other = tmp_path / "fork"
    shutil.copytree(d.remote, other)
    (d.app / ".deploy.conf").write_text(f"# fork\nOPA_REPO_URL=\"file://{other}\"\n")
    assert d.run(env=d.env(OPA_REPO_URL=None)).returncode == 0, d.out
    assert d.state["clone_argv"][-2] == f"file://{other}"
    assert d.run().returncode == 0, d.out  # environment beats the file
    assert d.state["clone_argv"][-2] == f"file://{d.remote}"


def test_default_repo_is_upstream(d):
    proc = d.run(env=d.env(OPA_REPO_URL=None))
    assert proc.returncode != 0  # the stub refuses the network
    assert d.state["clone_argv"][-2] == "https://github.com/ItsGambit/opa-compliance-wizard.git"
    assert d.deploy_events() == []  # nothing started, nothing changed


@pytest.mark.parametrize("line", ["SOMETHING=1", "OPA_REPO_URL=ftp://x", "OPA_BACKEND_PORT=80a",
                                  "OPA_DEPLOY_REF=--upload-pack=x", "not a setting",
                                  "OPA_NGINX_SITE=relative/path", "OPA_DEPLOY_BACKUP_DIR=rel"])
def test_bad_settings_stop_before_anything_happens(d, line):
    (d.app / ".deploy.conf").write_text(line + "\n")
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    key = line.split("=", 1)[0]
    proc = d.run(env=d.env(**{key: None}) if key.startswith("OPA_") else None)  # the environment would win
    assert proc.returncode != 0
    assert "ERROR" in d.out
    assert d.calls("git") == []
    assert marker.exists()


def test_ref_branch_and_commit(d):
    assert d.run("--ref", "release-1").returncode == 0, d.out
    assert d.state["clone_argv"][:5] == ["clone", "--depth", "1", "--branch", "release-1"]
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert d.run(f"--ref={sha}").returncode == 0, d.out
    assert "--depth" not in d.state["clone_argv"]
    assert d.state["checked_out"] == sha


@pytest.mark.parametrize("args", [["--ref"], ["--bogus"], ["--ref", "a..b"]])
def test_bad_arguments(d, args):
    assert d.run(*args).returncode != 0
    assert d.calls("git") == []


def test_backup_dir_inside_the_install_is_refused(d):
    proc = d.run(env=d.env(OPA_DEPLOY_BACKUP_DIR=str(d.app / "backups")))
    assert proc.returncode == 1 and "outside" in d.out


# --- preflight / lock (OPS-11) ---------------------------------------------


def test_missing_sudo_grant_stops_before_the_rsync(d):
    d.live_site()
    d.state["sudo_allow"] = [g for g in d.full_grants() if ".nginx-deploy-backup" not in g]
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    proc = d.run()
    assert proc.returncode == 1
    assert ".nginx-deploy-backup" in d.out and "Nothing has been changed" in d.out
    assert marker.exists()  # no rsync --delete ran
    assert d.calls("git") == []
    assert d.deploy_events() == []
    assert d.leftover_temp_dirs() == []


def test_unlistable_sudo_only_warns(d):
    d.state["sudo_list_ok"] = False
    assert d.run().returncode == 0, d.out
    assert "were not pre-checked" in d.out


def test_unreadable_live_site_stops_before_the_rsync(d):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    d.live_site(mode=0o000)
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    proc = d.run()
    assert proc.returncode == 1 and "is not readable" in d.out
    assert marker.exists()


def test_a_second_deploy_waits_for_the_lock(d):
    lock = d.app / ".deploy.lock"
    with open(lock, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = d.run()
    assert proc.returncode == 1 and "another deploy.sh run" in d.out
    assert d.calls("git") == []


# --- phase handoff ------------------------------------------------------------


def _fake_old_phase1_handoff(d):
    """What an older release's phase 1 hands to `exec $APP_DIR/server/deploy.sh`:
    rsync already done, only the old variables set."""
    frozen = d.tmpdir / "opa-deploy-frozen.OLD12345"
    source = d.tmpdir / "opa-deploy-source.OLD12345"
    frozen.mkdir()
    source.mkdir()
    return d.env(DEPLOY_SH_PHASE="2", DEPLOY_SH_PHASE1_FROZEN_DIR=str(frozen),
                 DEPLOY_SH_PHASE1_TMP_DIR=str(source), DEPLOY_COMMIT="c" * 40, DEPLOY_VERSION=d.version)


def test_new_phase2_after_an_old_phase1(d):
    proc = d.run(env=_fake_old_phase1_handoff(d))
    assert proc.returncode == 0, d.out
    d.assert_one_terminal("deploy.completed")
    assert d.leftover_temp_dirs() == []
    assert any(a[:1] == ["-n"] and "-l" in a for a in d.calls("sudo"))  # preflight ran in phase 2


def test_new_phase2_after_an_old_phase1_takes_the_lock(d):
    with open(d.app / ".deploy.lock", "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = d.run(env=_fake_old_phase1_handoff(d))
    assert proc.returncode == 1 and "another deploy.sh run" in d.out
    assert d.calls("npm") == []


def test_new_phase2_after_an_old_phase1_still_refuses_a_missing_grant(d):
    d.state["sudo_allow"] = d.full_grants(units=("opa-secrets-wizard",), nginx=False)
    proc = d.run(env=_fake_old_phase1_handoff(d))
    assert proc.returncode == 1
    d.assert_one_terminal("deploy.failed", "preflight")
    assert d.calls("npm") == []


@pytest.mark.skipif(subprocess.run(["sh", "-c", "echo x | grep -P x"], capture_output=True).returncode != 0,
                    reason="the 5.40.7 deploy.sh needs GNU grep -P")
def test_end_to_end_upgrade_from_the_previous_release(d):
    """The first deploy of this release runs the PREVIOUS release's phases 0-1
    (installed copy, hardcoded install dir) and this release's phase 2."""
    old = OLD_DEPLOY_SH.replace('APP_DIR="__APP_DIR__"', f'APP_DIR="{d.app}"')
    old = old.replace('REPO_URL="https://github.com/ItsGambit/opa-compliance-wizard.git"',
                      f'REPO_URL="file://{d.remote}"')
    (d.app / "server" / "deploy.sh").write_text(old)
    proc = d.run()
    assert proc.returncode == 0, d.out
    d.assert_one_terminal("deploy.completed")
    assert d.leftover_temp_dirs() == []


def test_bad_phase_is_refused(d):
    assert d.run(env=d.env(DEPLOY_SH_PHASE="3")).returncode == 2


@pytest.mark.parametrize("var,value", [("DEPLOY_LOCK_HELD", "yes"), ("DEPLOY_STARTED_LOGGED", "0"),
                                       ("DEPLOY_PREFLIGHT_DONE", "true")])
def test_bad_handoff_flags_are_refused_in_phase2(d, var, value):
    env = _fake_old_phase1_handoff(d)
    env[var] = value
    assert d.run(env=env).returncode == 2
    assert d.calls("npm") == []


def test_phase0_ignores_handoff_variables_from_the_caller(d):
    proc = d.run(env=d.env(DEPLOY_APP_DIR="/nonexistent", DEPLOY_STARTED_LOGGED="1", DEPLOY_PREFLIGHT_DONE="1"))
    assert proc.returncode == 0, d.out
    d.assert_one_terminal("deploy.completed")


# --- failures: one terminal event with the stage (OPS-10) -----------------------


def test_pip_failure(d):
    d.state["pip_rc"] = 1
    assert d.run().returncode != 0
    d.assert_one_terminal("deploy.failed", "pip_install")
    assert d.state.get("restarted") is None
    assert d.leftover_temp_dirs() == []


def test_failed_build_keeps_the_old_ui(d):
    d.state["vite_rc"] = 2
    assert d.run().returncode != 0
    d.assert_one_terminal("deploy.failed", "frontend_build")
    assert (d.app / "frontend" / "dist" / "index.html").read_text() == "old build"
    assert d.state.get("restarted") is None


def test_backend_that_never_reports_the_new_version(d):
    d.state["version_after_restart"] = "0.0.1"
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "main_service_version_check_failed")


def test_backend_that_crash_loops(d):
    d.state["units"]["opa-secrets-wizard"]["nrestarts_after_restart"] = 1
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "main_service_version_check_failed")


def test_backend_whose_process_did_not_change_is_not_confirmed(d):
    """A same-version hotfix: /api/version already answers the new version
    string, so only a new MainPID proves the restart took effect."""
    d.state["backend_version"] = d.version
    d.state["units"]["opa-secrets-wizard"]["keep_pid"] = True
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "main_service_version_check_failed")


def test_gate_that_crashes_after_starting(d):
    d.state["units"]["opa-auth-gate"]["nrestarts_after_restart"] = 2
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "restart_gate")
    assert "crashed and was restarted" in d.out


def test_gate_that_answers_wrongly(d):
    d.state["verify_codes"] = {"8767": "502"}
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "restart_gate")
    assert "answered 502" in d.out


def test_extra_gate_failure(d):
    d.state["units"]["opa-auth-gate-two"] = {"MainPID": "300", "ExecStart": "--port 8768",
                                             "state_after_restart": "failed"}
    d.state["sudo_allow"] = d.full_grants(units=("opa-secrets-wizard", "opa-auth-gate", "opa-auth-gate-two"))
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "restart_extra_gate")


def test_host_status_failure(d):
    d.state["units"]["opa-host-status"] = {"MainPID": "400", "nrestarts_after_restart": 1}
    d.state["sudo_allow"] = d.full_grants(units=("opa-secrets-wizard", "opa-auth-gate", "opa-host-status"))
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "restart_host_status")


def test_denied_restart_fails_with_the_stage(d):
    d.state["sudo_list_ok"] = False  # skip the pre-check so the restart itself is denied
    d.state["sudo_allow"] = d.full_grants(units=("opa-secrets-wizard",))
    assert d.run().returncode != 0
    d.assert_one_terminal("deploy.failed", "restart_gate")


# --- nginx (OPS-09 / OPS-11) -------------------------------------------------------


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_nginx_drift_is_applied_with_the_live_secret_carried_forward(d):
    live_before = d.live_site(extra="# an old line\n")
    assert d.run().returncode == 0, d.out
    d.assert_one_terminal("deploy.completed")
    repo_conf = d.app / "server" / "nginx-opa-secrets-wizard.conf"
    assert f'set $nginx_proxy_secret "{SECRET}";' in repo_conf.read_text()
    assert _mode(repo_conf) == 0o600  # OPS-09: baked copy owner-only
    assert d.nginx_live.read_text() == repo_conf.read_text() != live_before
    assert _mode(d.nginx_live) == 0o640  # `cp` onto an existing file keeps its mode
    assert "every local account can read it" not in d.out
    assert d.state["nginx_reloads"] == 1
    assert not (d.app / ".nginx-deploy-backup").exists()
    assert not (d.app / "server" / "nginx-opa-secrets-wizard.conf.tmp").exists()


def test_no_drift_means_no_apply(d):
    d.live_site()
    assert d.run().returncode == 0, d.out
    assert d.state.get("nginx_reloads") is None
    assert not [a for a in d.calls("sudo") if a[:2] == ["-n", "cp"]]


def test_failed_validation_rolls_back_and_cleans_up(d):
    live_before = d.live_site(extra="# old\n")
    d.state["nginx_t_results"] = [1, 0]
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "nginx_validate_failed")
    assert d.nginx_live.read_text() == live_before
    assert not (d.app / ".nginx-deploy-backup").exists()


def test_failed_reload_rolls_back(d):
    live_before = d.live_site(extra="# old\n")
    d.state["nginx_reload_rc"] = 1
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "nginx_reload_failed")
    assert d.nginx_live.read_text() == live_before


def test_failed_rollback_keeps_an_owner_only_backup_and_blocks_the_next_deploy(d):
    live_before = d.live_site(extra="# old\n")
    d.state["nginx_t_results"] = [1]
    backup = d.app / ".nginx-deploy-backup"
    d.state["sudo_fail"] = [f"cp {backup} {d.nginx_live}"]
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "nginx_validate_rollback_failed")
    assert backup.read_text() == live_before
    assert _mode(backup) == 0o600
    assert "CRITICAL" in d.out
    # the next run must not overwrite the last good config
    d.state["sudo_fail"] = []
    (d.app / "audit_log.jsonl").unlink()
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    assert d.run().returncode == 1
    assert "rollback failed" in d.out
    assert d.deploy_events() == []  # refused in preflight: nothing started, nothing changed
    assert marker.exists()
    assert backup.read_text() == live_before
    # an older release's phase 1 (whose rsync deleted the backup) can't get
    # here; behind one, phase 2's preflight refuses before pip/build/restart
    assert d.run(env=_fake_old_phase1_handoff(d)).returncode == 1
    d.assert_one_terminal("deploy.failed", "preflight")
    assert backup.read_text() == live_before


def test_denied_apply_removes_its_backup(d):
    d.live_site(extra="# old\n")
    d.state["sudo_list_ok"] = False
    d.state["sudo_allow"] = [g for g in d.full_grants() if "nginx-opa-secrets-wizard.conf" not in g]
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "nginx_apply_denied")
    assert not (d.app / ".nginx-deploy-backup").exists()


def test_world_readable_live_site_and_leftover_backup_are_reported(d):
    d.live_site(mode=0o644)
    leftover = Path(str(d.nginx_live) + ".deploy-backup")
    leftover.write_text("old secret")
    assert d.run().returncode == 0, d.out
    assert "every local account can read it" in d.out
    assert f"sudo chmod 0640 {d.nginx_live}" in d.out
    assert f"sudo rm {leftover}" in d.out


def test_live_site_not_owned_by_root_is_reported(d):
    if os.geteuid() == 0:
        pytest.skip("files are root-owned when the suite runs as root")
    d.live_site(mode=0o640)
    assert d.run().returncode == 0, d.out
    assert "can be changed by an account other than root" in d.out


def test_server_names_are_carried_and_a_different_layout_is_never_applied(d):
    live_before = d.live_site(extra="# drift\n")
    assert d.run().returncode == 0, d.out
    assert d.nginx_live.read_text().count(f"server_name {SERVER_NAME};") == 2
    # a live site the template's values can't be mapped onto: refused, untouched
    # -- and refused BEFORE anything changes (no sync, no restart)
    odd = live_before.replace(f"    server_name {SERVER_NAME};\n", "", 1)
    d.nginx_live.write_text(odd)
    (d.app / "audit_log.jsonl").unlink()
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    d.state["restarted"] = []
    assert d.run().returncode == 1
    assert "`server_name` appears 1 time" in d.out
    assert d.deploy_events() == [] and marker.exists() and d.state["restarted"] == []
    assert d.nginx_live.read_text() == odd
    assert d.state["nginx_reloads"] == 1  # only the first run's
    # behind an older phase 1 (already synced), phase 2 refuses before pip/restart
    assert d.run(env=_fake_old_phase1_handoff(d)).returncode == 1
    d.assert_one_terminal("deploy.failed", "preflight")
    assert d.state["restarted"] == [] and d.calls("npm") == []


def test_a_live_site_still_on_the_placeholder_secret_is_not_overwritten(d):
    d.live_site(secret="REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", extra="# drift\n")
    assert d.run().returncode == 1
    assert d.deploy_events() == []  # refused before anything changed
    assert "no real NGINX_PROXY_SECRET" in d.out


def test_secret_with_awk_and_sed_special_characters_is_carried_faithfully(d):
    d.live_site(secret=SECRET_PLAIN + "&\\1", extra="# drift\n")
    assert d.run().returncode == 0, d.out
    assert f'"{SECRET_PLAIN}&\\1";' in d.nginx_live.read_text()


# --- systemd notes ------------------------------------------------------------------


def test_unit_file_writable_by_the_deploy_user_is_reported(d, tmp_path):
    unit = tmp_path / "opa-auth-gate.service"
    unit.write_text("[Service]\n")
    d.state["units"]["opa-auth-gate"]["FragmentPath"] = str(unit)
    assert d.run().returncode == 0, d.out
    assert f"{unit} (systemd unit opa-auth-gate) can be changed" in d.out


def test_manager_wide_daemon_reload_flag_is_explained_as_harmless(d):
    d.state["journald_need_reload"] = "yes"
    for u in d.state["units"].values():
        u["NeedDaemonReload"] = "yes"
    assert d.run().returncode == 0, d.out
    assert "pending daemon-reload for every unit" in d.out
    assert "use the OLD definition" not in d.out


def test_our_own_changed_unit_file_is_a_warning(d):
    d.state["units"]["opa-auth-gate"]["NeedDaemonReload"] = "yes"
    assert d.run().returncode == 0, d.out
    assert "opa-auth-gate changed on disk" in d.out and "use the OLD definition" in d.out


# --- opt-in archive backup ------------------------------------------------------------


def _make_db(path):
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (42)")
    con.commit()
    return con


def test_opt_in_backup_copies_the_archive_owner_only(d, tmp_path):
    con = _make_db(d.app / "audit_store.db")  # kept open: WAL not checkpointed
    (d.app / "audit_log.jsonl").write_text("")
    backups = tmp_path / "backups"
    backups.mkdir()
    try:
        assert d.run(env=d.env(OPA_DEPLOY_BACKUP_DIR=str(backups))).returncode == 0, d.out
    finally:
        con.close()
    copies = sorted(backups.glob(f"audit_store-pre-{d.version}-*.db"))
    assert len(copies) == 1
    assert _mode(copies[0]) & 0o077 == 0
    assert sqlite3.connect(copies[0]).execute("SELECT x FROM t").fetchone() == (42,)
    assert len(list(backups.glob("audit_log-pre-*.jsonl"))) == 1
    # taken before the backend restarted
    assert d.out.index("Backing up the archive") < d.out.index("Restarting opa-secrets-wizard")


def test_backup_follows_the_services_archive_path(d, tmp_path):
    elsewhere = tmp_path / "var-lib" / "archive.db"
    elsewhere.parent.mkdir()
    _make_db(elsewhere).close()
    envfile = tmp_path / "service.env"
    envfile.write_text(f'NGINX_PROXY_SECRET=x\nOPA_AUDIT_DB_PATH="{elsewhere}"\n')
    d.state["units"]["opa-secrets-wizard"]["EnvironmentFiles"] = f"{envfile} (ignore_errors=no)"
    backups = tmp_path / "backups"
    backups.mkdir()
    assert d.run(env=d.env(OPA_DEPLOY_BACKUP_DIR=str(backups))).returncode == 0, d.out
    copy = next(backups.glob("audit_store-pre-*.db"))
    assert sqlite3.connect(copy).execute("SELECT x FROM t").fetchone() == (42,)


def test_backup_to_a_missing_directory_stops_before_any_restart(d, tmp_path):
    _make_db(d.app / "audit_store.db").close()
    assert d.run(env=d.env(OPA_DEPLOY_BACKUP_DIR=str(tmp_path / "nope"))).returncode == 1
    d.assert_one_terminal("deploy.failed", "db_backup")
    assert d.state.get("restarted") is None


# --- review round 1 ----------------------------------------------------------------------


def test_a_grant_that_needs_a_password_is_reported_missing(d):
    d.live_site()
    rollback = f"cp {d.app / '.nginx-deploy-backup'} {d.nginx_live}"
    d.state["sudo_allow"] = [g for g in d.full_grants() if g != rollback]
    d.state["sudo_password_required"] = [rollback]  # e.g. via %sudo ALL=(ALL) ALL
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    assert d.run().returncode == 1
    assert "without a password" in d.out and ".nginx-deploy-backup" in d.out
    assert marker.exists()


def test_an_account_without_sudo_is_refused(d):
    d.state["sudo_not_allowed"] = True
    assert d.run().returncode == 1
    assert "may not run sudo at all" in d.out
    assert d.calls("git") == []


def test_a_unit_that_crashes_a_few_seconds_after_answering_is_caught(d):
    d.state["units"]["opa-auth-gate"]["crash_after_shows"] = 1  # answers once, then crash-loops
    assert d.run().returncode == 1
    d.assert_one_terminal("deploy.failed", "post_restart_check")
    assert "opa-auth-gate did not stay up" in d.out


def test_a_ref_older_than_this_release_is_refused_outside_its_hardcoded_path(d):
    old = OLD_DEPLOY_SH.replace('APP_DIR="__APP_DIR__"', 'APP_DIR="/srv/the-maintainers-path"')
    (d.remote / "server" / "deploy.sh").write_text(old)
    marker = d.app / "untracked-marker"
    marker.write_text("x")
    assert d.run("--ref", "old-release").returncode == 1
    assert "from before 5.41.0" in d.out
    assert marker.exists() and d.deploy_events() == []
    # where the old script's hardcoded path IS this install, it is allowed
    (d.remote / "server" / "deploy.sh").write_text(OLD_DEPLOY_SH.replace('APP_DIR="__APP_DIR__"', f'APP_DIR="{d.app}"'))
    d.run("--ref", "old-release")
    assert "older than 5.41.0" in d.out
    assert not marker.exists()  # it went ahead and synced


def test_unreadable_service_env_file_is_warned_about_in_the_backup(d, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    envfile = tmp_path / "service.env"
    envfile.write_text("OPA_AUDIT_DB_PATH=/elsewhere.db\n")
    envfile.chmod(0)
    d.state["units"]["opa-secrets-wizard"]["EnvironmentFiles"] = f"{envfile} (ignore_errors=no)"
    backups = tmp_path / "backups"
    backups.mkdir()
    assert d.run(env=d.env(OPA_DEPLOY_BACKUP_DIR=str(backups))).returncode == 0, d.out
    assert f"can't read {envfile}" in d.out


def test_sudo_that_prints_only_the_command_is_accepted_with_a_note(d):
    """sudo-rs (Ubuntu 25.10+) and sudo < 1.9.15 don't print the matching rule
    for `sudo -l -l <cmd>`: granted is all the pre-check can see (review r2)."""
    d.state["sudo_path_only_listing"] = True
    assert d.run().returncode == 0, d.out
    assert "can't show whether" in d.out
    d.state["sudo_allow"] = [g for g in d.full_grants() if "restart opa-auth-gate" not in g]
    assert d.run().returncode == 1
    assert "systemctl restart opa-auth-gate" in d.out


def test_this_release_carries_the_handoff_protocol_marker():
    text = (REPO / "server" / "deploy.sh").read_text()
    assert "\n# deploy.sh handoff protocol: 2\n" in text
    assert "# deploy.sh handoff protocol" not in OLD_DEPLOY_SH
