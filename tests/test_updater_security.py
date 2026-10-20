"""Hostile inputs for the root-owned updater: links in directories the application account controls, swapped files, a
tampered staged tree, forged requests, faults that must not be honoured in production, a second concurrent run."""

import json
import os
import sqlite3
import threading

import pytest

import updater_fakes as uf
from updater_fakes import act


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def test_audit_append_never_follows_links_in_the_shared_data_directory(m, tmp_path):
    cfg = m.cfg()
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.symlink(victim, m.data / ".audit_log.jsonl.lock")  # the application account can plant these
    act.audit_append(cfg, "upgrade.step", {"x": 1})
    assert victim.read_text() == "precious"
    assert any(json.loads(line)["action"] == "upgrade.step" for line in (m.data / "audit_log.jsonl").read_text().splitlines())
    (m.data / "audit_log.jsonl").unlink()
    os.symlink(victim, m.data / "audit_log.jsonl")
    act.audit_append(cfg, "upgrade.step", {"x": 2})
    assert victim.read_text() == "precious"  # not written through the link


def test_safe_copy_refuses_link_sources_and_replaces_link_destinations(tmp_path):
    src = tmp_path / "src"
    src.write_text("data")
    victim = tmp_path / "victim"
    victim.write_text("precious")
    link = tmp_path / "dstlink"
    os.symlink(victim, link)
    act.safe_copy(str(src), str(link))
    assert victim.read_text() == "precious" and not os.path.islink(link) and link.read_text() == "data"
    os.symlink(victim, tmp_path / "srclink")
    with pytest.raises(OSError):
        act.safe_copy(str(tmp_path / "srclink"), str(tmp_path / "out"))


def test_a_backup_file_swapped_for_a_link_is_not_used(m, tmp_path):
    victim = tmp_path / "victim.db"
    sqlite3.connect(victim).execute("CREATE TABLE t (x)").connection.close()
    real = m.host.db_tool

    def evil(args):
        res = real(args)
        if args[0] == "backup":  # between the tool exiting and root reading, the application swaps the file for a link
            os.unlink(args[2])
            os.symlink(victim, args[2])
        return res
    m.host.db_tool = evil
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-aabb0001")) == "failed"
    assert m.read_state()["reason_code"] == "backup_failed" and os.readlink(m.opt / "current") == "releases/5.46.0"


def test_staged_tree_attacks_are_all_refused(m, tmp_path):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.run(["systemctl", "start", "ocw-stage@5.47.0.service"])
    root = m.opt / "releases" / "5.47.0"
    up = m.updater()
    manifest = json.loads(__import__("tarfile").open(m.releases_dir / "ocw-5.47.0.tar.gz").extractfile("manifest.json").read())
    up.check_tree(str(root), manifest)  # the honest tree passes
    # a symlink replacing a file
    target = root / "requirements.lock"
    target.unlink()
    os.symlink("/etc/hostname", target)
    with pytest.raises(act.StepFailed):
        up.check_tree(str(root), manifest)
    target.unlink()
    (root / "requirements.lock").write_bytes(b"# lock\n")
    # a hard link to a file outside the tree
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    os.link(outside, root / "server" / "hardlink.py")
    with pytest.raises(act.StepFailed):
        up.check_tree(str(root), manifest)
    os.unlink(root / "server" / "hardlink.py")
    # a missing file; a planted __pycache__ is deleted, not trusted
    (root / "server" / "__pycache__").mkdir()
    (root / "server" / "__pycache__" / "x.pyc").write_bytes(b"\0")
    up.check_tree(str(root), manifest)
    assert not (root / "server" / "__pycache__" / "x.pyc").exists()
    (root / "create_secret_folders.py").unlink()
    with pytest.raises(act.StepFailed):
        up.check_tree(str(root), manifest)


def test_the_artifact_is_verified_from_a_private_copy_so_a_late_swap_changes_nothing(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    art = m.data / "upgrade" / "artifacts" / "ocw-5.47.0.tar.gz"
    good = art.read_bytes()
    up = m.updater()
    real_snapshot = up.snapshot_artifact

    def snapshot_then_swap(artifact):
        copies = real_snapshot(artifact)
        art.write_bytes(b"swapped after root took its copy")  # the staging account tampers after the fact
        return copies
    up.snapshot_artifact = snapshot_then_swap
    m.host.schema_on_start["5.47.0"] = 10
    req = m.request("5.47.0", tar=m.releases_dir / "ocw-5.47.0.tar.gz", correlation_id="upg-aabb0002")
    assert up.apply(req) == "completed"  # root used its own root-only copy
    assert art.read_bytes() != good
    assert (m.data / "upgrade" / "verified" / "ocw-5.47.0.tar.gz").read_bytes() == good
    assert oct((m.data / "upgrade" / "verified").stat().st_mode & 0o777) == "0o700"


def test_faults_are_ignored_unless_test_mode_is_on(m):
    env = dict(m.env, OCW_UPDATER_FAULT="rollback_fail,health_fail,disk_full,kill_at:backup")
    env.pop("OCW_TEST_MODE")
    assert act.Cfg(env).faults == set()
    assert act.Cfg(dict(env, OCW_TEST_MODE="1")).faults == {"rollback_fail", "health_fail", "disk_full", "kill_at:backup"}


def test_second_concurrent_run_exits_quietly(m):
    cfg = m.cfg()
    fd = act.take_lock(cfg)
    try:
        assert fd is not None and act.take_lock(cfg) is None
        assert act.run(cfg, m.host) == 0  # someone else is working: do nothing
    finally:
        os.close(fd)


def test_a_request_for_a_staged_release_whose_tree_vanished_changes_nothing(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.run(["systemctl", "start", "ocw-stage@5.47.0.service"])
    import shutil
    shutil.rmtree(m.opt / "releases" / "5.47.0" / "server")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-aabb0003")) == "failed"
    assert m.read_state()["reason_code"] == "tree_mismatch" and os.readlink(m.opt / "current") == "releases/5.46.0"


def test_main_converts_a_simulated_kill_into_a_hard_exit(m, monkeypatch):
    for k, v in m.env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(act, "run", lambda cfg, host: (_ for _ in ()).throw(act.Killed("backup")))
    codes = []

    def fake_exit(code):
        codes.append(code)
        raise SystemExit(code)
    monkeypatch.setattr(act.os, "_exit", fake_exit)
    with pytest.raises(SystemExit):
        act.main(["run"])
    assert codes == [137]


def test_selftest_and_usage(capsys):
    assert act.main(["selftest"]) == 0 and "selftest ok" in capsys.readouterr().out
    assert act.main(["nonsense"]) == 2
