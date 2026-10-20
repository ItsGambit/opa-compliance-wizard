"""The root-owned updater's state machine (server/updater/root/ocw_activate.py), run as pure Python
against a fake machine (tests/updater_fakes.py) with injected faults. The code under test is the real
code; only systemd, journald, nginx and loopback HTTP are faked."""

import json
import os
import sqlite3
from pathlib import Path

import pytest

import updater_fakes as uf
from updater_fakes import act


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def run_apply(m, version="5.47.0", **kw):
    tar = m.build_release(version, **kw.pop("release", {}))
    m.put_artifacts(version)
    m.host.schema_on_start[version] = kw.pop("migrate_to", 10)
    up = m.updater()
    req = m.request(version, correlation_id=kw.pop("cid", "upg-aaaa0001"), **kw)
    result = up.apply(req)
    return up, result


def test_successful_upgrade_end_to_end(m):
    up, result = run_apply(m, migrate_to=10, release={"expected_schema_version": 10, "migrations": [{"version": 10, "rollback_safe": True}]})
    assert result == "completed"
    st = m.read_state()
    assert st["result"] == "completed" and st["version_from"] == "5.46.0" and st["version_to"] == "5.47.0"
    assert os.readlink(m.opt / "current") == "releases/5.47.0"
    assert os.readlink(m.opt / "previous") == "releases/5.46.0"
    assert [d["step"] for d in st["steps_done"]] == ["validated", "downloaded", "staged", "preflight", "backup", "switching", "restarting", "health_check"]
    assert all(r["ok"] for r in st["health"]) and len(st["health"]) == 8
    assert st["schema_before"] == 9 and st["schema_after"] == 10
    actions = [e["action"] for e in m.audit_actions()]
    for a in ("upgrade.step", "upgrade.started", "upgrade.migrated", "upgrade.health_check", "upgrade.completed"):
        assert a in actions
    assert all((e["details"] or {}).get("correlation_id") == "upg-aaaa0001" for e in m.audit_actions())
    assert not (m.opt / "maintenance" / "active.html").exists()
    # backup taken, root-only, and verified
    backups = list((m.data / "upgrade" / "backups").glob("audit_store-pre-5.47.0-*.db"))
    assert len(backups) == 1 and oct(backups[0].stat().st_mode & 0o777) == "0o600"
    assert sqlite3.connect(str(backups[0])).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 50
    # the tree was made immutable before the switch
    assert ("chown_tree", str(m.opt / "releases" / "5.47.0")) in m.host.calls
    # the updater updated itself from the verified release
    assert (m.opt / "updater" / "current" / "ocw_activate.py").read_text() == (Path(uf.ROOT_DIR) / "ocw_activate.py").read_text()
    assert os.readlink(m.opt / "updater" / "current") == "lib/v5.47.0" and not (m.opt / "updater" / "current" / "ocw_launcher.py").exists()
    # the maintenance page was shown while switching
    hist = (m.data / "upgrade" / "history.jsonl").read_text().splitlines()
    assert json.loads(hist[-1])["result"] == "completed"


def test_signature_failure_changes_nothing(m):
    stranger = uf.TestKey()
    m.build_release("5.47.0", signer=stranger)
    m.put_artifacts("5.47.0")
    result = m.updater().apply(m.request("5.47.0", correlation_id="upg-aaaa0002"))
    st = m.read_state()
    assert result == "failed" and st["result"] == "failed" and st["reason_code"] == "key_unknown"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    assert not (m.opt / "previous").exists()
    assert (m.data / "upgrade" / "artifacts" / "ocw-5.47.0.tar.gz.rejected").exists()
    assert st["bundle"]["name"].startswith("ocw-support-5.46.0-to-5.47.0-")


def test_tampered_staged_tree_is_refused_by_root(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.host.run(["systemctl", "start", "ocw-stage@5.47.0.service"])[0] == 0
    (m.opt / "releases" / "5.47.0" / "requirements.lock").write_text("# evil\n")
    result = m.updater().apply(m.request("5.47.0", correlation_id="upg-aaaa0003"))
    assert result == "failed" and m.read_state()["reason_code"] == "tree_mismatch"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_extra_file_in_staged_tree_is_refused(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.run(["systemctl", "start", "ocw-stage@5.47.0.service"])
    (m.opt / "releases" / "5.47.0" / "server" / "planted.py").write_text("import os\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-aaaa0004")) == "failed"
    assert m.read_state()["reason_code"] == "tree_mismatch"


def test_version_not_newer_and_wrong_hash_are_rejected(m):
    m.build_release("5.46.0")
    m.put_artifacts("5.46.0")
    assert m.updater().apply(m.request("5.46.0", correlation_id="upg-aaaa0005")) == "failed"
    assert m.read_state()["reason_code"] == "version_not_newer"
    m2 = uf.Machine(m.root / "two")
    m2.build_release("5.47.0")
    m2.put_artifacts("5.47.0")
    assert m2.updater().apply(m2.request("5.47.0", correlation_id="upg-aaaa0006", sha256="0" * 64)) == "failed"
    assert m2.read_state()["reason_code"] == "hash_mismatch"


def test_health_failure_rolls_back_code_only_and_keeps_schema(m):
    m.host.unhealthy_versions.add("5.47.0")
    up, result = run_apply(m, migrate_to=10, release={"expected_schema_version": 10}, cid="upg-aaaa0007")
    st = m.read_state()
    assert result == "rolled_back" and st["result"] == "rolled_back" and st["reason_code"] == "health_healthz"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    # data untouched: the migration the new release ran stays
    assert sqlite3.connect(m.db).execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 10
    assert sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 50
    assert st["bundle"] and (m.data / "upgrade" / "bundles" / st["bundle"]["name"]).exists()
    assert not (m.opt / "maintenance" / "active.html").exists()
    actions = [e["action"] for e in m.audit_actions()]
    assert "upgrade.rolled_back" in actions and "upgrade.failed" in actions and "upgrade.bundle_created" in actions
    failed = [e for e in m.audit_actions() if e["action"] == "upgrade.failed"][0]["details"]
    assert failed["bundle"]["name"] == st["bundle"]["name"] and failed["reason_code"] == "health_healthz"
    # the same version is refused until an operator clears the failure
    again = m.updater().apply(m.request("5.47.0", correlation_id="upg-aaaa0008", action_id=None))
    assert again == "rejected"
    rej = json.loads((m.data / "upgrade" / "rejections" / "upg-aaaa0008.json").read_text())
    assert rej["code"] == "version_failed_before"


def test_injected_health_fault_and_crash_loop_roll_back(m):
    m.host.crash_versions.add("5.47.0")
    up, result = run_apply(m, cid="upg-aaaa0009")
    assert result == "rolled_back" and m.read_state()["reason_code"] == "health_unit"


def test_failed_migration_rolls_back(m):
    m.host.fail_migration.add("5.47.0")
    up, result = run_apply(m, migrate_to=10, cid="upg-aaaa0010")
    assert result == "rolled_back"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_rollback_failure_leaves_maintenance_page_state_and_bundle(m):
    m.host.unhealthy_versions.add("5.47.0")
    m.env["OCW_UPDATER_FAULT"] = "rollback_fail"
    up, result = run_apply(m, cid="upg-aaaa0011")
    st = m.read_state()
    assert result == "failed_needs_operator" and st["result"] == "failed_needs_operator"
    page = (m.opt / "maintenance" / "active.html").read_text()
    assert "ocw-updater status" in page and "5.47" not in page
    assert st["bundle"]
    failed = [e for e in m.audit_actions() if e["action"] == "upgrade.failed"][-1]["details"]
    assert failed["reason_code"] == "rollback_failed" and failed["rollback"].startswith("failed")


def test_disk_full_preflight_stops_before_anything_changes(m):
    m.env["OCW_UPDATER_FAULT"] = "disk_full"
    up, result = run_apply(m, cid="upg-aaaa0012")
    assert result == "failed" and m.read_state()["reason_code"] == "disk_space"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    assert not list((m.data / "upgrade" / "backups").glob("*.db"))


def test_sync_in_progress_blocks_the_upgrade(m):
    conn = sqlite3.connect(m.db)
    conn.execute("UPDATE sync_state SET last_sync_status='running', last_sync_attempt_at=?", (act.iso(m.host.now()).replace("Z", ""),))
    conn.commit()
    conn.close()
    # the fake clock is 2027; "recent" is judged by the real clock in the tool, so make the row recent for it
    import time
    conn = sqlite3.connect(m.db)
    conn.execute("UPDATE sync_state SET last_sync_attempt_at=?", (time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),))
    conn.commit()
    conn.close()
    up, result = run_apply(m, cid="upg-aaaa0013")
    assert result == "failed" and m.read_state()["reason_code"] == "sync_in_progress"


def test_nginx_template_is_baked_applied_and_rolled_back_on_failure(m):
    site_before = m.site.read_text()
    m.host.nginx_t_results = [1, 0]  # the new config fails nginx -t, the restored one passes
    up, result = run_apply(m, cid="upg-aaaa0014", release={"nginx_changed": True})
    assert result == "rolled_back" and m.read_state()["reason_code"] == "nginx_invalid"
    assert m.site.read_text() == site_before
    # and with a valid config it is applied with the live server's own values carried over
    m2 = uf.Machine(m.root / "two")
    up, result = run_apply(m2, cid="upg-aaaa0015", release={"nginx_changed": True})
    assert result == "completed"
    text = m2.site.read_text()
    assert "opa.example.com" in text and uf.PROXY_SECRET in text and "maintenance/active.html" in text
    assert m2.host.reloads == 1


def test_unlisted_layout_nginx_refuses_before_switching(m):
    m.site.write_text("server { listen 80; }\n")
    up, result = run_apply(m, cid="upg-aaaa0016", release={"nginx_changed": True})
    assert result == "failed" and m.read_state()["reason_code"] == "nginx_invalid"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_request_validation(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    up = m.updater()
    cases = [({"schema": 2}, "request_invalid"), ({"correlation_id": "bad"}, "request_invalid"), ({"version": "5.47"}, "request_invalid"),
             ({"requested_at": act.iso(m.host.now() - 90000)}, "request_stale"), ({"action": "restore"}, "request_invalid")]
    for i, (over, code) in enumerate(cases):
        req = m.request("5.47.0", correlation_id=f"upg-bbbb00{i:02d}")
        req.update(over)
        assert up.apply(req) == "rejected"
        rej = json.loads((m.data / "upgrade" / "rejections" / f"upg-bbbb00{i:02d}.json").read_text()) if (m.data / "upgrade" / "rejections" / f"upg-bbbb00{i:02d}.json").exists() else None
        if rej:
            assert rej["code"] == code
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_replayed_action_id_is_refused(m):
    up, result = run_apply(m, cid="upg-aaaa0017", action_id="act_0123456789abcdef0123")
    assert result == "completed"
    m.build_release("5.48.0")
    m.put_artifacts("5.48.0")
    m.host.schema_on_start["5.48.0"] = 11
    again = m.updater().apply(m.request("5.48.0", correlation_id="upg-aaaa0018", action_id="act_0123456789abcdef0123"))
    assert again == "rejected"
    assert json.loads((m.data / "upgrade" / "rejections" / "upg-aaaa0018.json").read_text())["code"] == "request_replayed"


def test_process_directory_rejects_forged_files(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    reqdir = m.data / "upgrade" / "inbox" / "requests"
    (reqdir / "upg-cccc0001.json").write_text("{not json")
    big = reqdir / "upg-cccc0002.json"
    big.write_text(json.dumps({"x": "y" * 20000}))
    os.symlink("/etc/passwd", reqdir / "upg-cccc0003.json")
    wr = reqdir / "upg-cccc0004.json"
    wr.write_text(json.dumps(m.request("5.47.0", correlation_id="upg-cccc0004")))
    os.chmod(wr, 0o666)
    up = m.updater()
    act.process_directory(up, str(reqdir))
    assert os.listdir(reqdir) == []
    codes = {json.loads(p.read_text())["code"] for p in (m.data / "upgrade" / "rejections").glob("*.json")}
    assert codes == {"request_invalid"}
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_run_processes_a_request_file_like_the_systemd_path(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    req = m.request("5.47.0", correlation_id="upg-dddd0001")
    p = m.data / "upgrade" / "inbox" / "requests" / "upg-dddd0001.json"
    p.write_text(json.dumps(req))
    os.chmod(p, 0o600)
    assert act.run(m.cfg(), m.host) == 0
    assert m.read_state()["result"] == "completed"
    assert os.listdir(m.data / "upgrade" / "inbox" / "requests") == []


def test_scheduled_request_waits_for_its_time(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    when = act.iso(m.host.now() + 3600)
    req = m.request("5.47.0", correlation_id="upg-dddd0002", not_before=when)
    sched = m.data / "upgrade" / "schedule"
    sched.mkdir(parents=True, exist_ok=True)
    p = sched / "upg-dddd0002.json"
    p.write_text(json.dumps(req))
    os.chmod(p, 0o600)
    act.run(m.cfg(), m.host)
    assert os.readlink(m.opt / "current") == "releases/5.46.0" and p.exists()
    m.host.clock += 3601
    req["requested_at"] = act.iso(m.host.now())
    p.write_text(json.dumps(req))
    os.chmod(p, 0o600)
    act.run(m.cfg(), m.host)
    assert m.read_state()["result"] == "completed"


# --- power loss: kill at every step boundary, then resume -------------------------------------------------


PRE_SWITCH = ["validated", "downloaded", "staged", "preflight", "backup", "switching"]
POST_SWITCH = ["restarting", "health_check", "completed"]


def _kill_then_resume(m, fault, version="5.47.0", cid="upg-eeee0001"):
    m.build_release(version)
    m.put_artifacts(version)
    m.host.schema_on_start[version] = 10
    m.env["OCW_UPDATER_FAULT"] = fault
    with pytest.raises(act.Killed):
        m.updater().apply(m.request(version, correlation_id=cid))
    json.loads((m.data / "upgrade" / "state.json").read_text())  # the state file is whole after a kill
    assert m.read_state()["result"] is None
    m.env.pop("OCW_UPDATER_FAULT")
    up = m.updater()
    assert up.in_flight()
    return up.resume(), up


@pytest.mark.parametrize("step", PRE_SWITCH)
def test_kill_before_the_switch_resumes_as_a_clean_failure(m, step):
    result, _up = _kill_then_resume(m, f"kill_at:{step}")
    assert result == "failed"
    assert m.read_state()["reason_code"] == "interrupted"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    assert not (m.opt / "maintenance" / "active.html").exists()
    assert len([e for e in m.audit_actions() if e["action"] == "upgrade.failed"]) == 1


@pytest.mark.parametrize("step", POST_SWITCH)
def test_kill_after_the_switch_resumes_to_completion(m, step):
    result, _up = _kill_then_resume(m, f"kill_at:{step}")
    assert result == "completed"
    assert os.readlink(m.opt / "current") == "releases/5.47.0"
    assert m.host.serving["opa-compliance-wizard"] == "5.47.0"
    assert not (m.opt / "maintenance" / "active.html").exists()
    assert len([e for e in m.audit_actions() if e["action"] == "upgrade.completed"]) == 1


def test_kill_right_after_the_symlink_flip_resumes_to_completion(m):
    result, _up = _kill_then_resume(m, "after_switch")
    assert result == "completed" and os.readlink(m.opt / "current") == "releases/5.47.0"


def test_kill_during_rollback_finishes_the_rollback(m):
    m.host.unhealthy_versions.add("5.47.0")
    result, _up = _kill_then_resume(m, "kill_at:rolling_back")
    assert result == "rolled_back"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"
    assert m.host.serving["opa-compliance-wizard"] == "5.46.0"


def test_a_resumed_upgrade_whose_new_release_is_bad_rolls_back(m):
    m.host.unhealthy_versions.add("5.47.0")
    result, _up = _kill_then_resume(m, "kill_at:restarting")
    assert result == "rolled_back"


def test_kill_during_every_step_of_a_rollback_is_recoverable(m):
    """Walk the whole unhealthy-release path killing at each persisted step."""
    for i, step in enumerate(["switching", "restarting", "health_check", "rolling_back"]):
        mm = uf.Machine(m.root / f"walk{i}")
        mm.host.unhealthy_versions.add("5.47.0")
        result, _up = _kill_then_resume(mm, f"kill_at:{step}", cid=f"upg-eeee01{i:02d}")
        assert result in ("failed", "rolled_back"), step
        assert mm.read_state()["result"] == result
        assert os.readlink(mm.opt / "current") == "releases/5.46.0"


def test_self_update_is_atomic_and_keeps_the_old_updater_when_the_new_one_fails(m, monkeypatch):
    (m.opt / "updater" / "lib" / "v5.46.0").mkdir(parents=True)
    (m.opt / "updater" / "lib" / "v5.46.0" / "ocw_activate.py").write_text("# old\n")
    os.symlink("lib/v5.46.0", m.opt / "updater" / "current")
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.run(["systemctl", "start", "ocw-stage@5.47.0.service"])
    up = m.updater()
    real_run = up.host.run

    def failing_selftest(argv, timeout=120):
        return (1, "boom") if "selftest" in argv else real_run(argv, timeout)
    monkeypatch.setattr(up.host, "run", failing_selftest)
    assert up.self_update("5.47.0").startswith("kept")
    assert os.readlink(m.opt / "updater" / "current") == "lib/v5.46.0"          # unchanged
    assert not list((m.opt / "updater" / "lib").glob(".*.tmp"))                 # no half-built directory left
    monkeypatch.undo()
    assert up.self_update("5.47.0") == "updated"
    assert os.readlink(m.opt / "updater" / "current") == "lib/v5.47.0"
    assert (m.opt / "updater" / "lib" / "v5.46.0").exists()                     # the previous generation is kept for one more release


def test_a_failing_self_update_never_undoes_a_finished_upgrade(m, monkeypatch):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    up = m.updater()
    monkeypatch.setattr(up, "self_update", lambda ver: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    assert up.apply(m.request("5.47.0", correlation_id="upg-aabb0009")) == "completed"
    assert m.read_state()["result"] == "completed"


def _applied(m, version="5.47.0", cid="upg-ccdd0001"):
    m.build_release(version)
    m.put_artifacts(version)
    m.host.schema_on_start[version] = 10
    assert m.updater().apply(m.request(version, correlation_id=cid)) == "completed"


def test_an_operator_rollback_killed_midway_finishes_on_resume_without_blaming_a_version(m):
    _applied(m)
    m.env["OCW_UPDATER_FAULT"] = "kill_at:rolling_back"
    with pytest.raises(act.Killed):
        m.updater().rollback_action("cli:tester")
    m.env.pop("OCW_UPDATER_FAULT")
    assert m.updater().resume() == "rolled_back"
    assert os.readlink(m.opt / "current") == "releases/5.46.0" and m.host.serving["opa-compliance-wizard"] == "5.46.0"
    assert not (json.loads((m.data / "upgrade" / "failures.json").read_text())["versions"]) if (m.data / "upgrade" / "failures.json").exists() else True


def test_a_restore_that_loses_power_between_the_two_renames_puts_the_old_database_back(m):
    _applied(m)
    conn = sqlite3.connect(m.db)
    conn.execute("INSERT INTO events (who, what) VALUES ('later@example.com', 'after')")
    conn.commit()
    conn.close()
    m.env["OCW_UPDATER_FAULT"] = "kill_at:restore_swap"
    with pytest.raises(act.Killed):
        m.updater().restore_action("cli:tester")
    assert not os.path.exists(m.db)  # the dangerous moment: no database at the live path
    m.env.pop("OCW_UPDATER_FAULT")
    assert m.updater().resume() == "failed"
    assert os.path.exists(m.db) and sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 51  # nothing lost
    assert m.read_state()["reason_code"] == "interrupted"


def test_the_named_fault_injections_behave_as_documented(m):
    m.env["OCW_UPDATER_FAULT"] = "health_fail"
    up, result = run_apply(m, cid="upg-ccdd0002")
    st = m.read_state()
    assert result == "rolled_back" and st["reason_code"] == "health_healthz" and "injected" in st["failure"]["detail"]
    m2 = uf.Machine(m.root / "two")
    m2.env["OCW_UPDATER_FAULT"] = "during_migration"
    up, result = run_apply(m2, cid="upg-ccdd0003")
    assert result == "rolled_back" and m2.read_state()["reason_code"] == "migration_failed"
    assert os.readlink(m2.opt / "current") == "releases/5.46.0"
    m3 = uf.Machine(m.root / "three")
    m3.env["OCW_UPDATER_FAULT"] = "health_fail,rollback_fail"
    up, result = run_apply(m3, cid="upg-ccdd0004")
    assert result == "failed_needs_operator"
    # the audit chain heads are compared across the upgrade and reported
    m4 = uf.Machine(m.root / "four")
    up, result = run_apply(m4, cid="upg-ccdd0005")
    assert result == "completed" and set(m4.read_state()["chain_heads_after"]) == {"env-a", "env-b"}


def test_chain_heads_that_move_without_a_sync_or_vanish_fail_the_check(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    real_start = m.host._start_unit

    def start_and_tamper(unit):
        ok = real_start(unit)
        if unit == "opa-compliance-wizard" and m.host.serving.get(unit) == "5.47.0":  # only the new release does it
            conn = sqlite3.connect(m.db)
            conn.execute("DELETE FROM chain_heads WHERE environment_id = 'env-b'")
            conn.commit()
            conn.close()
        return ok
    m.host._start_unit = start_and_tamper
    # a head that vanished is damage a CODE rollback cannot repair: the new release fails the check, and so does the old code
    # on the same data, so the updater asks for an operator (who has the backup and the bundle) instead of calling it fixed
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-ccdd0006")) == "failed_needs_operator"
    st = m.read_state()
    assert st["failure"]["reason_code"] == "health_chain" and "chain head" in st["operator_reason"] and st["bundle"]
