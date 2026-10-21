"""Hardening of the privileged updater against the less-trusted accounts that share its directories (the staging
account and the application account). Real temporary directory trees; ownership itself is asserted on a real host by
tests/integration/updater-vm.sh (these tests do not run as root)."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

import updater_fakes as uf
import ocw_cli
from updater_fakes import act

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def cli(m, *argv):
    return ocw_cli.main(list(argv), m.cfg(), m.host)


def staged(m, version="5.47.0", **kw):
    m.build_release(version, **kw)
    m.put_artifacts(version)
    m.host.schema_on_start[version] = 10
    assert m.host.run(["systemctl", "start", f"ocw-stage@{version}.service"])[0] == 0


# --- releases/ is root-only: the tree is moved there BEFORE it is owned and hashed -------------------------------


def test_the_staged_tree_is_moved_into_releases_before_it_is_owned_and_hashed(m):
    staged(m)
    assert (m.opt / "staging" / "5.47.0" / ".staged").exists() and not (m.opt / "releases" / "5.47.0").exists()
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000101")) == "completed"
    in_releases, still_in_staging = m.host.chown_seen
    assert in_releases and not still_in_staging
    assert not (m.opt / "staging" / "5.47.0").exists() and (m.opt / "releases" / "5.47.0" / ".staged").exists()


def test_a_staging_entry_swapped_for_a_link_is_never_followed(m, tmp_path):
    staged(m)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    os.chmod(victim, 0o777)
    os.rename(m.opt / "staging" / "5.47.0", tmp_path / "moved-away")
    os.symlink(victim, m.opt / "staging" / "5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000102")) == "failed"
    assert m.read_state()["reason_code"] == "not_staged"
    assert not os.path.lexists(m.opt / "releases" / "5.47.0")
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o777 and (victim / "keep.txt").read_text() == "keep"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_a_root_owned_leftover_of_an_earlier_attempt_is_replaced_not_trusted(m):
    staged(m)
    left = m.opt / "releases" / "5.47.0"
    (left / "server").mkdir(parents=True)
    (left / "server" / "planted.py").write_text("import os\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000103")) == "completed"
    assert not (m.opt / "releases" / "5.47.0" / "server" / "planted.py").exists()


def test_a_failure_after_the_move_leaves_nothing_the_staging_account_can_reuse(m):
    staged(m)
    (m.opt / "staging" / "5.47.0" / "requirements.lock").write_text("# evil\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000104")) == "failed"
    assert m.read_state()["reason_code"] == "tree_mismatch"
    assert not (m.opt / "staging" / "5.47.0").exists()  # moved: the account cannot touch it any more


def test_prune_removes_stale_staging_directories(m):
    (m.opt / "staging" / "5.40.0").mkdir()
    (m.opt / "staging" / "9.0.0").mkdir()
    m.updater().prune("5.47.0")
    assert not (m.opt / "staging" / "5.40.0").exists() and (m.opt / "staging" / "9.0.0").exists()


def test_status_lists_staged_releases_from_staging(m, capsys):
    staged(m)
    s = ocw_cli.collect_status(m.cfg())
    assert [r["version"] for r in s["staged"]] == ["5.47.0"]


def test_install_sh_makes_releases_root_owned_and_staging_account_owned(tmp_path):
    text = (REPO / "server" / "install.sh").read_text()
    assert 'mkd root:root 0755 "$OPT_DIR/releases"' in text
    assert 'mkd "$UPD_OWNER" 0755 "$OPT_DIR/staging"' in text
    assert 'mkd "$UPD_OWNER" 0755 "$OPT_DIR/releases"' not in text
    unit = (REPO / "server" / "ocw-stage@.service").read_text()
    assert "ReadWritePaths=__OPT_DIR__/staging" in unit and "ReadWritePaths=__OPT_DIR__/releases" not in unit
    assert "StateDirectoryMode=0750" in unit and "CacheDirectoryMode=0750" in unit


# --- an operator's file is handed over through a root-owned directory, never through the staging account's ----------


def test_stage_from_a_file_never_writes_chowns_or_chmods_inside_the_staging_accounts_directories(m, tmp_path, monkeypatch):
    victim = tmp_path / "victim.json"
    victim.write_text("precious")
    evil = tmp_path / "evil"
    evil.mkdir()
    os.symlink(victim, evil / "ocw-5.47.0.tar.gz")
    os.symlink(victim, evil / "ocw-5.47.0.tar.gz.minisig")
    art = m.data / "upgrade" / "artifacts"
    os.symlink(evil, art)
    tar = m.build_release("5.47.0")
    seen = {}

    def fake_stage():
        hand = m.opt / "handoff"
        seen["files"] = sorted(p.name for p in hand.iterdir())
        seen["modes"] = {p.name: stat.S_IMODE(p.stat().st_mode) for p in hand.iterdir()}
        return 0, ""
    m.stage_overrides["5.47.0"] = fake_stage
    touched = []
    real_chown, real_chmod = os.chown, os.chmod
    monkeypatch.setattr(os, "chown", lambda p, *a, **k: touched.append(str(p)) or real_chown(p, *a, **k))
    monkeypatch.setattr(os, "chmod", lambda p, *a, **k: touched.append(str(p)) or real_chmod(p, *a, **k))
    assert cli(m, "stage", str(tar)) == 0
    assert victim.read_text() == "precious"
    assert seen["files"] == ["ocw-5.47.0.tar.gz", "ocw-5.47.0.tar.gz.minisig"] and set(seen["modes"].values()) == {0o640}
    assert not [p for p in touched if str(art) in p or str(evil) in p]
    assert list((m.opt / "handoff").iterdir()) == []  # root cleans up after the stage step


def test_a_planted_file_in_the_handoff_directory_is_replaced_not_followed(m, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.symlink(victim, m.opt / "handoff" / "ocw-5.47.0.tar.gz")
    tar = m.build_release("5.47.0")
    import ocw_cli as c
    c._drop_in_handoff(m.cfg(), str(tar))
    assert victim.read_text() == "precious" and not os.path.islink(m.opt / "handoff" / "ocw-5.47.0.tar.gz")
    assert (m.opt / "handoff" / "ocw-5.47.0.tar.gz").read_bytes() == tar.read_bytes()


def test_the_stage_step_prefers_the_handoff_copy_over_a_stale_one_it_owns(tmp_path, monkeypatch):
    from server.updater import stage as stagemod
    opt = tmp_path / "opt"
    (opt / "handoff").mkdir(parents=True)
    art = tmp_path / "art"
    art.mkdir()
    for n in ("ocw-1.2.3.tar.gz", "ocw-1.2.3.tar.gz.minisig"):
        (art / n).write_text("stale")
        (opt / "handoff" / n).write_text("fresh")
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    assert stagemod._adopt_handoff(opt, art, "1.2.3") is True
    assert (art / "ocw-1.2.3.tar.gz").read_text() == "fresh"


def test_venv_paths_are_rewritten_for_the_final_location(tmp_path):
    from server.updater import stage as stagemod
    venv = tmp_path / "staging" / "1.2.3" / ".venv"
    (venv / "bin").mkdir(parents=True)
    old = str(tmp_path / "staging" / "1.2.3")
    (venv / "bin" / "gunicorn").write_text(f"#!{old}/.venv/bin/python\nimport sys\n")
    (venv / "bin" / "gunicorn").chmod(0o755)
    os.symlink("/usr/bin/python3", venv / "bin" / "python")
    stagemod._relocate_venv(venv, old, str(tmp_path / "releases" / "1.2.3"))
    assert (venv / "bin" / "gunicorn").read_text().startswith(f"#!{tmp_path}/releases/1.2.3/.venv/bin/python")
    assert os.access(venv / "bin" / "gunicorn", os.X_OK) and os.path.islink(venv / "bin" / "python")


# --- safe opens: links and pipes in directories another account owns ---------------------------------------------


def test_read_json_does_not_follow_links_or_block_on_pipes(tmp_path):
    real = tmp_path / "real.json"
    real.write_text('{"a": 1}')
    os.symlink(real, tmp_path / "link.json")
    os.mkfifo(tmp_path / "pipe.json")
    assert act.read_json(str(real)) == {"a": 1}
    assert act.read_json(str(tmp_path / "link.json"), "dflt") == "dflt"
    assert act.read_json(str(tmp_path / "pipe.json"), "dflt") == "dflt"
    assert act.read_json(str(tmp_path), "dflt") == "dflt"


# --- trust apply no longer copies into the application's directory -------------------------------------------------


def test_trust_apply_writes_nothing_through_a_link_planted_in_the_application_directory(m, tmp_path, capsys):
    from release_helpers import make_revocation, revocation_payload
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    revdir = m.data / "upgrade" / "revocations"
    revdir.mkdir(parents=True)
    os.symlink(victim, revdir / "1.json")
    k2, sb2 = uf.TestKey(), uf.TestStandby()
    payload = revocation_payload(1, revoke=[m.primary.key_id, m.standby.key_id], add_keys=[k2, sb2])
    rev = make_revocation(tmp_path / "revocation.json", [m.standby], payload)
    assert cli(m, "trust", "apply", str(rev)) == 0
    assert victim.read_text() == "precious"
    assert [p.name for p in revdir.iterdir()] == ["1.json"] and os.path.islink(revdir / "1.json")


# --- revocation: tool output, per-serial source ------------------------------------------------------------------


def _revoke_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("revoke_tool", REPO / "tools" / "revoke.py")
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(REPO / "tools"))
    spec.loader.exec_module(mod)
    return mod


def test_revoke_tool_pins_known_good_releases_by_digest_and_a_bare_revoke_is_allowed():
    from release_helpers import TestKey, TestStandby, key_list
    from server.updater import keys as keylib
    p, sb = TestKey(), TestStandby()
    eff = keylib.effective_from(keylib.validate_key_list(key_list([p, sb])))
    tool = _revoke_tool()
    assert tool.parse_revoke(p.key_id, eff) == p.key_id
    sha = "ab" * 32
    assert tool.parse_revoke(p.key_id, eff, [f"{p.key_id}:5.46.0:{sha}"]) == {"key_id": p.key_id, "known_good": {"5.46.0": sha}}
    for bad in (f"{p.key_id}:5.46.0:XYZ", f"{p.key_id}:nonsense:{sha}"):
        with pytest.raises(Exception):
            tool.parse_revoke(p.key_id, eff, [bad])


def test_a_per_serial_revocation_location_is_polled_next_to_the_fixed_one(monkeypatch):
    from server.updater import service
    monkeypatch.delenv("OPA_REVOCATION_URL", raising=False)
    monkeypatch.delenv("OPA_REVOCATION_URL_BASE", raising=False)
    names = dict(service.revocation_sources(2))
    assert names["release_assets_next"].endswith("/releases/download/revocation-3/revocation.json")
    assert names["release_assets"].endswith("/releases/download/revocation/revocation.json")
    assert "release_assets_next" not in dict(service.revocation_sources())


# --- nginx: skip when absent, and a failing `nginx -t` that fails on the restored site too is not the release's fault ---


def test_a_missing_nginx_site_skips_the_nginx_step_and_the_upgrade_completes(m):
    os.unlink(m.site)
    m.build_release("5.47.0", nginx_changed=True)
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000201")) == "completed"
    assert not m.site.exists() and m.host.reloads == 0
    assert any(e["details"].get("step") == "nginx_skipped" for e in m.audit_actions() if e["action"] == "upgrade.step")


def test_nginx_t_failing_on_the_restored_site_too_is_an_internal_error_and_blames_no_version(m):
    m.host.nginx_t_results = [1, 1]  # the new site fails, and so does the restored original: the test itself cannot run
    m.build_release("5.47.0", nginx_changed=True)
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000202")) == "rolled_back"
    assert m.read_state()["reason_code"] == "internal_error"
    assert not (act.read_json(m.cfg().failures_path, {}) or {}).get("versions")


def test_the_manifest_flag_is_a_real_comparison_with_the_previous_tag(tmp_path):
    tool = _release_tool()
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "server").mkdir()
    (repo / "server" / "nginx-opa-secrets-wizard.conf").write_text("a\n")
    run("add", "-A")
    run("commit", "-q", "-m", "one")
    run("tag", "v1.0.0")
    same = {"server/nginx-opa-secrets-wizard.conf": (0o644, b"a\n")}
    other = {"server/nginx-opa-secrets-wizard.conf": (0o644, b"b\n")}
    assert tool._nginx_template_changed(repo, same, "1.1.0") is False
    assert tool._nginx_template_changed(repo, other, "1.1.0") is True
    assert tool._nginx_template_changed(repo, other, "1.0.0") is True  # no earlier tag: nothing to compare with


def _release_tool():
    import importlib.util
    import sys
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location("release_tool", REPO / "tools" / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_root_unit_can_run_nginx_t(tmp_path):
    unit = (REPO / "server" / "ocw-upgrade.service").read_text()
    rw = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
    assert " /run" in rw and "/var/log/nginx" in rw
    caps = next(line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet="))
    assert "CAP_NET_BIND_SERVICE" in caps and "CAP_KILL" in caps
    assert "python3 -I -B " in unit


# --- chown_tree / check_tree on a real tree (no fakes) -------------------------------------------------------------


def _tree(tmp_path):
    root = tmp_path / "rel"
    (root / "server").mkdir(parents=True)
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / "server" / "a.py").write_text("x = 1\n")
    os.chmod(root, 0o777)
    os.chmod(root / "server", 0o1777)
    os.chmod(root / "server" / "a.py", 0o4775)
    return root


def test_chown_tree_locks_every_entry_and_never_touches_what_a_link_points_to(tmp_path):
    from ocw_host import SystemHost
    root = _tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    os.chmod(outside, 0o666)
    os.symlink(outside, root / "server" / "l")
    SystemHost().chown_tree(str(root), os.getuid(), os.getgid())
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o666           # the link target is untouched
    for base, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(base, n)
            if not os.path.islink(p):
                assert os.lstat(p).st_mode & 0o7022 == 0, p
    assert os.lstat(root).st_mode & 0o7022 == 0


def test_chown_tree_refuses_hard_links_and_special_files(tmp_path):
    from ocw_host import HostError, SystemHost
    root = _tree(tmp_path)
    os.link(root / "server" / "a.py", root / "server" / "b.py")
    with pytest.raises(HostError):
        SystemHost().chown_tree(str(root), os.getuid(), os.getgid())
    (tmp_path / "two").mkdir()
    root2 = _tree(tmp_path / "two")
    os.mkfifo(root2 / "server" / "pipe")
    with pytest.raises(HostError):
        SystemHost().chown_tree(str(root2), os.getuid(), os.getgid())


def test_chown_tree_does_not_follow_a_link_as_the_top(tmp_path):
    from ocw_host import SystemHost
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "top")
    with pytest.raises(OSError):
        SystemHost().chown_tree(str(tmp_path / "top"), os.getuid(), os.getgid())


def test_check_tree_walks_the_virtualenv_and_refuses_escaping_links_and_setuid_bits(m, tmp_path):
    staged(m)
    root = m.opt / "staging" / "5.47.0"
    up = m.updater()
    manifest = json.loads(__import__("tarfile").open(m.releases_dir / "ocw-5.47.0.tar.gz").extractfile("manifest.json").read())
    up.check_tree(str(root), manifest)
    os.symlink("/usr/bin/env", root / ".venv" / "bin" / "python3")                   # the base interpreter: allowed
    up.check_tree(str(root), manifest)
    os.symlink("/etc", root / ".venv" / "lib-evil")
    with pytest.raises(act.StepFailed) as e:
        up.check_tree(str(root), manifest)
    assert e.value.code == "tree_mismatch" and "leaves the release" in str(e.value)
    os.unlink(root / ".venv" / "lib-evil")
    os.symlink("/usr/bin/env", root / ".venv" / "bin" / "helper")                    # only bin/python* may leave
    with pytest.raises(act.StepFailed):
        up.check_tree(str(root), manifest)
    os.unlink(root / ".venv" / "bin" / "helper")
    os.chmod(root / "requirements.lock", 0o4644)
    with pytest.raises(act.StepFailed) as e:
        up.check_tree(str(root), manifest)
    assert "setuid" in str(e.value)


# --- a pipe or link in a directory root does not own must not block or redirect root --------------------------------


@pytest.fixture
def alarm():
    import signal

    def handler(*_a):
        raise AssertionError("blocked: the updater waited on a named pipe")
    old = signal.signal(signal.SIGALRM, handler)
    signal.alarm(10)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, old)


def test_a_pipe_among_the_revocation_files_does_not_block_the_updater(m, alarm):
    d = m.data / "upgrade" / "revocations"
    d.mkdir(parents=True)
    os.mkfifo(d / "9.json")
    os.symlink("/etc/hostname", d / "8.json")
    act.ingest_revocations(m.updater())  # returns instead of waiting for a writer


def test_a_pipe_as_the_audit_log_does_not_block_appends_or_reads(m, alarm):
    os.mkfifo(m.data / "audit_log.jsonl")
    act.audit_append(m.cfg(), "x.y", {"a": 1})
    assert act.audit_entries_for(m.cfg(), "upg-00000000") == []


def test_the_audit_lock_file_is_handed_to_the_application_account_when_root_creates_it(m, monkeypatch):
    chowned = []
    monkeypatch.setattr(act.os, "geteuid", lambda: 0)
    monkeypatch.setattr(act.os, "fchown", lambda fd, u, g: chowned.append((os.fstat(fd).st_ino, u, g)))
    act.audit_append(m.cfg(), "x.y", {}, ids=(4242, 4343))
    lock = os.stat(m.data / ".audit_log.jsonl.lock")
    log = os.stat(m.data / "audit_log.jsonl")
    assert (lock.st_ino, 4242, 4343) in chowned and (log.st_ino, 4242, 4343) in chowned


def test_a_planted_link_as_the_audit_lock_is_not_written_through(m, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    os.symlink(victim, m.data / ".audit_log.jsonl.lock")
    act.audit_append(m.cfg(), "x.y", {})
    assert victim.read_text() == "precious" and (m.data / "audit_log.jsonl").stat().st_size > 0


# --- the inbox is always drained ------------------------------------------------------------------------------------


def test_every_unprocessed_inbox_entry_is_moved_away(m):
    inbox = m.cfg().requests
    os.makedirs(inbox, exist_ok=True)
    Path(inbox, "x.txt").write_text("stray")
    os.mkdir(os.path.join(inbox, "adir"))
    Path(inbox, "adir", "inner").write_text("x")
    Path(inbox, "bad.json").write_text("{not json")
    os.mkfifo(os.path.join(inbox, "pipe.json"))
    act.run(m.cfg(), m.host)
    assert os.listdir(inbox) == []
    assert len(os.listdir(m.cfg().done)) == 4


def test_the_units_set_start_and_trigger_limits_on_purpose():
    assert "StartLimitIntervalSec=" in (REPO / "server" / "ocw-upgrade.service").read_text()
    assert "StartLimitBurst=" in (REPO / "server" / "ocw-upgrade.service").read_text()
    path = (REPO / "server" / "ocw-upgrade.path").read_text()
    assert "TriggerLimitIntervalSec=" in path and "TriggerLimitBurst=" in path


def test_no_new_upgrade_while_the_last_one_needs_an_operator_until_clear_failure(m, capsys):
    m.host.unhealthy_versions.add("5.47.0")
    m.env["OCW_UPDATER_FAULT"] = "rollback_fail"
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000301")) == "failed_needs_operator"
    m.env.pop("OCW_UPDATER_FAULT")
    m.host.unhealthy_versions.clear()
    m.build_release("5.48.0")
    m.put_artifacts("5.48.0")
    m.host.schema_on_start["5.48.0"] = 10
    assert m.updater().apply(m.request("5.48.0", correlation_id="upg-00000302")) == "rejected"
    rej = json.loads((m.data / "upgrade" / "rejections" / "upg-00000302.json").read_text())
    assert rej["code"] == "failed_before"
    assert cli(m, "clear-failure") == 0
    assert m.updater().apply(m.request("5.48.0", correlation_id="upg-00000303")) == "completed"


# --- environment overrides are not honoured by a root process without the marker ----------------------------------------


def _as_root(monkeypatch, marker=None):
    import types
    monkeypatch.setattr(act.os, "geteuid", lambda: 0)
    monkeypatch.setattr(act, "TEST_MARKER", str(marker) if marker else "/nonexistent/marker")
    if marker:
        real = os.lstat
        monkeypatch.setattr(act.os, "lstat", lambda p, *a, **k: types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
                            if str(p) == str(marker) else real(p, *a, **k))


def test_root_ignores_test_mode_and_path_overrides_without_the_marker(tmp_path, monkeypatch):
    for k, v in (("OCW_TEST_MODE", "1"), ("OCW_FAST", "1"), ("OCW_UPDATER_FAULT", "after_switch"), ("OCW_OPT_DIR", str(tmp_path / "opt")),
                 ("OCW_UPDATER_DIR", str(tmp_path / "evil")), ("OCW_ENV_FILE", str(tmp_path / "evil.env")),
                 ("OCW_ARTIFACTS_DIR", str(tmp_path / "art")), ("OCW_DATA_DIR", str(tmp_path / "data"))):
        monkeypatch.setenv(k, v)
    _as_root(monkeypatch)
    cfg = act.Cfg()
    assert cfg.faults == set() and cfg.fast is False
    assert cfg.opt == str(tmp_path / "opt") and cfg.data == str(tmp_path / "data")      # where the wrapper and the units put them
    assert cfg.updater_dir == str(tmp_path / "opt" / "updater")                          # derived, not taken from the environment
    assert cfg.env_file == "/etc/opa-compliance-wizard.env" and cfg.artifacts == "/var/lib/ocw-updater/artifacts"


def test_root_honours_them_only_with_a_root_owned_marker(tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    marker.write_text("")
    monkeypatch.setenv("OCW_TEST_MODE", "1")
    monkeypatch.setenv("OCW_UPDATER_FAULT", "after_switch")
    _as_root(monkeypatch, marker)
    assert act.Cfg().faults == {"after_switch"}
    _as_root(monkeypatch)             # marker missing
    assert act.Cfg().faults == set()
    monkeypatch.undo()
    monkeypatch.setattr(act.os, "geteuid", lambda: 0)
    monkeypatch.setattr(act, "TEST_MARKER", str(marker))       # a real file owned by this (non-root) user: refused
    monkeypatch.setenv("OCW_TEST_MODE", "1")
    monkeypatch.setenv("OCW_UPDATER_FAULT", "after_switch")
    assert act.Cfg().faults == set()


def test_the_wrapper_runs_the_root_updater_with_a_clean_environment():
    text = (REPO / "server" / "ocw-updater.sh").read_text()
    assert 'exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin' in text and '"$PY3" -I -B "$OPT/updater/ocw_activate.py" cli' in text


def test_apply_writes_its_request_through_no_link_and_with_a_random_temporary_name(m, tmp_path):
    import ocw_cli as c
    req = {"schema": 1, "x": 1}
    c._write_request(m.cfg(), "upg-0000aaaa", req)
    assert json.loads((m.cfg().requests and Path(m.cfg().requests) / "upg-0000aaaa.json").read_text()) == req
    assert not [p for p in Path(m.cfg().requests).iterdir() if p.name.endswith(".tmp")]
    # the inbox replaced by a link to another directory is refused
    inbox = m.data / "upgrade" / "inbox"
    other = tmp_path / "elsewhere"
    (other / "requests").mkdir(parents=True)
    os.rename(inbox, tmp_path / "moved")
    os.symlink(other, inbox)
    with pytest.raises(OSError):
        c._write_request(m.cfg(), "upg-0000bbbb", req)
    assert list((other / "requests").iterdir()) == []


def _set_install_sh_version(m, value):
    path = m.opt / "updater" / "config.json"
    cfg = json.loads(path.read_text())
    if value is None:
        cfg.pop("install_sh_version", None)
    else:
        cfg["install_sh_version"] = value
    path.write_text(json.dumps(cfg))


def _apply_5_47_0(m, over, cid):
    m.build_release("5.47.0", manifest_over=over)
    m.put_artifacts("5.47.0")
    return m.updater().apply(m.request("5.47.0", correlation_id=cid))


@pytest.mark.parametrize("recorded", [None, "5.46.0", "not-a-version"])
def test_a_release_whose_install_sh_minimum_is_newer_than_the_recorded_version_is_refused_with_the_command(m, recorded):
    _set_install_sh_version(m, recorded)
    assert _apply_5_47_0(m, {"install_sh_min_version": "5.47.0"}, "upg-00000401") == "failed"
    st = m.read_state()
    assert st["reason_code"] == "needs_install_sh"
    assert "sudo server/install.sh --refresh-updater" in st["error"] and "5.47.0" in st["error"]
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


@pytest.mark.parametrize("recorded", ["5.47.0", "5.48.0"])
def test_a_release_is_accepted_once_install_sh_has_recorded_a_version_that_is_new_enough(m, recorded):
    _set_install_sh_version(m, recorded)
    assert _apply_5_47_0(m, {"install_sh_min_version": "5.47.0", "requires_install_sh": False}, "upg-00000402") == "completed"


def test_the_old_boolean_alone_can_now_be_satisfied_and_a_manifest_without_either_is_not_gated(m):
    # a manifest from a release that only has the boolean: the release's own version is the minimum
    assert _apply_5_47_0(m, {"requires_install_sh": True}, "upg-00000403") == "failed"
    assert m.read_state()["reason_code"] == "needs_install_sh"


def test_the_boolean_alone_is_satisfied_by_a_recorded_version(m):
    _set_install_sh_version(m, "5.47.0")
    assert _apply_5_47_0(m, {"requires_install_sh": True}, "upg-00000404") == "completed"


def test_a_manifest_without_the_gating_fields_is_not_refused(m):
    _set_install_sh_version(m, None)
    assert _apply_5_47_0(m, {}, "upg-00000405") == "completed"


def test_requires_install_sh_is_a_real_comparison_with_the_previous_tag(tmp_path):
    tool = _release_tool()
    repo = tmp_path / "repo"
    (repo / "server").mkdir(parents=True)
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    for n in tool.INSTALL_SH_FILES:
        (repo / n).write_text("same\n")
    run("add", "-A")
    run("commit", "-q", "-m", "one")
    run("tag", "v1.0.0")
    same = {n: (0o644, b"same\n") for n in tool.INSTALL_SH_FILES}
    assert tool._requires_install_sh(repo, same, "1.1.0") is False
    changed = dict(same, **{"server/ocw-upgrade.service": (0o644, b"different\n")})
    assert tool._requires_install_sh(repo, changed, "1.1.0") is True


def _git_repo(tmp_path, tags):
    """A real git repo with one commit per entry of `tags` ({version: {file: text}}), each tagged vX."""
    tool = _release_tool()
    repo = tmp_path / "repo"
    (repo / "server").mkdir(parents=True)
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    state = {n: "base\n" for n in tool.INSTALL_SH_FILES}
    for version, changes in tags.items():
        state.update(changes)
        for n, text in state.items():
            (repo / n).write_text(text)
        run("add", "-A")
        run("commit", "-q", "--allow-empty", "-m", version)
        run("tag", f"v{version}")
    return tool, repo, state


def _files(state):
    return {n: (0o644, t.encode()) for n, t in state.items()}


def test_install_sh_min_version_walks_the_tags_back_to_the_newest_change(tmp_path):
    tool, repo, state = _git_repo(tmp_path, {
        "1.0.0": {},
        "1.1.0": {"server/ocw-updater.sh": "wrapper v2\n"},
        "1.2.0": {},
        "1.3.0": {"server/ocw-upgrade.service": "unit v2\n"},
        "1.4.0": {},
        "1.5.0": {},
    })
    # nothing changed in 1.6.0 against 1.5.0: the answer walks back through 1.5.0 and 1.4.0 to 1.3.0 (the unit)
    assert tool._install_sh_min_version(repo, _files(state), "1.6.0") == "1.3.0"
    # a change in this release is its own minimum
    changed = dict(state, **{"server/install.sh": "installer v2\n"})
    assert tool._install_sh_min_version(repo, _files(changed), "1.6.0") == "1.6.0"
    # a wrapper-only change: the minimum moves but the 5.47.0-compatible boolean (units only) stays false
    wrapper = dict(state, **{"server/ocw-updater.sh": "wrapper v3\n"})
    assert tool._install_sh_min_version(repo, _files(wrapper), "1.6.0") == "1.6.0"
    assert tool._requires_install_sh(repo, _files(wrapper), "1.6.0") is False
    # a unit change sets both
    unit = dict(state, **{"server/ocw-upgrade.path": "path v2\n"})
    assert tool._requires_install_sh(repo, _files(unit), "1.6.0") is True
    assert tool._install_sh_min_version(repo, _files(unit), "1.6.0") == "1.6.0"
    # in between releases: 1.2.0 inherits 1.1.0's wrapper change
    assert tool._install_sh_min_version(repo, _files(dict(state, **{"server/ocw-upgrade.service": "base\n"})), "1.2.0") == "1.1.0"


def test_install_sh_min_version_of_a_first_release_is_its_own_version(tmp_path):
    tool, repo, state = _git_repo(tmp_path, {"1.0.0": {}})
    assert tool._install_sh_min_version(repo, _files(state), "0.9.0") == "0.9.0"
    # the oldest tag counts as having introduced the files
    assert tool._install_sh_min_version(repo, _files(state), "1.0.1") == "1.0.0"


def _second_site(m, name, with_deny, header=True):
    from server.nginx_second_site import build
    text = build(uf.SITE_TEMPLATE.format(name="opa.example.com", cert="/c/full.pem", key="/c/key.pem", secret=uf.PROXY_SECRET),
                 8768, "127.0.0.1:8080", "opa2.example.com", name)
    if not with_deny:
        text = text.replace("    location /api/upgrade {\n        return 403;\n    }\n", "")
    if not header:
        text = "\n".join(l for l in text.splitlines() if not l.startswith("# OPA auth gate")) + "\n"
    path = m.root / "nginx-sites" / f"opa-{name}"
    path.write_text(text)
    return path


def test_preflight_warns_and_audits_when_a_second_gate_site_lacks_the_upgrade_deny_but_does_not_block(m):
    bare = _second_site(m, "bare", with_deny=False)
    _second_site(m, "good", with_deny=True)
    _second_site(m, "hand-made", with_deny=False, header=False)   # not generated by setup-second-gate.sh: ignored
    before = bare.read_text()
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000410")) == "completed"
    entries = [e for e in m.audit_actions() if e["action"] == "upgrade.step" and e["details"].get("step") == "second_gate_site_unprotected"]
    assert len(entries) == 1 and entries[0]["details"]["sites"] == ["opa-bare"]
    assert "--regenerate-second-sites" in entries[0]["details"]["detail"]
    assert bare.read_text() == before   # read-only


def test_preflight_is_silent_when_every_second_gate_site_denies_the_upgrade_routes(m):
    _second_site(m, "good", with_deny=True)
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000411")) == "completed"
    assert not [e for e in m.audit_actions() if e["details"].get("step") == "second_gate_site_unprotected"]
