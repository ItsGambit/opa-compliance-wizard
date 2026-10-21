"""5.48.0 review fixes on the root updater's request inbox: a request never replaces state it did not load, the rollback window
fails closed, restore is bound to the copy the administrator was shown, the leftovers of a request flood are bounded, replay
protection reads the newest ids, and the quiesce file covers a slow run."""
import json
import os
import time

import pytest

import updater_fakes  # noqa: F401  (puts the root modules on the path)
import ocw_cli
from updater_fakes import act
from server.updater import upgrade
from test_updater_app_requests import (  # noqa: F401  (m is the fixture)
    m, applied, inbox, send, process, rejection, raw_request, shown_backup, age_bundle, CID, AID)

STATE = lambda m: m.data / "upgrade" / "state.json"  # noqa: E731


def age_state(m, seconds):
    st = m.read_state()
    st["updated_at"] = act.iso(time.time() - seconds)
    STATE(m).write_text(json.dumps(st))
    return STATE(m).read_bytes()


# --- a request never replaces state it did not load; the rollback window fails closed ------------------------------------
def test_a_bundle_for_another_run_is_refused_and_state_json_is_untouched(m):
    applied(m)
    before = age_state(m, 3 * 86400)
    send(m, "bundle", for_correlation_id="upg-00000009")
    assert process(m) == ["rejected"] and rejection(m)["code"] == "request_invalid"
    assert STATE(m).read_bytes() == before
    send(m, "rollback", cid="upg-feed0002", aid="aid_0123456789abcdef0002", confirm="ROLLBACK")
    assert process(m) == ["rejected"] and rejection(m, "upg-feed0002")["code"] == "rollback_unavailable"
    assert os.readlink(m.opt / "current") == "releases/5.47.0"


def test_the_command_line_bundle_for_an_older_run_leaves_state_json_alone(m, capsys):
    applied(m)
    before = age_state(m, 3600)
    assert ocw_cli.main(["bundle", "--correlation", "upg-00000009"], m.cfg(), m.host) == 0
    assert STATE(m).read_bytes() == before
    assert list((m.data / "upgrade" / "bundles").glob("ocw-support-*.tar.gz"))


def test_a_bundle_for_the_last_run_does_not_move_the_rollback_window(m):
    applied(m)
    age_state(m, 20 * 3600)
    stamp = m.read_state()["updated_at"]
    send(m, "bundle")
    assert process(m) == ["bundle_created"]
    st = m.read_state()
    assert st["updated_at"] == stamp and st["bundle"]["name"] and st["result"] == "completed"


@pytest.mark.parametrize("state", [{"correlation_id": "upg-00000009", "bundle": {"name": "x"}}, {"result": "rolled_back", "action": "apply"},
                                   {"result": "completed", "action": "rollback", "updated_at": "now"}, {"result": "completed", "action": "apply"}])
def test_rollback_fails_closed_unless_the_state_is_a_completed_apply_in_the_window(m, state):
    applied(m)
    if state.get("updated_at") == "now":
        state["updated_at"] = act.iso(time.time())
    STATE(m).write_text(json.dumps(state))
    send(m, "rollback", confirm="ROLLBACK")
    assert process(m) == ["rejected"] and rejection(m)["code"] == "rollback_unavailable"
    assert os.readlink(m.opt / "current") == "releases/5.47.0"


# --- restore is bound to the copy shown ----------------------------------------------------------------------------------
def two_applies(m):
    applied(m, "5.47.0", "upg-ccdd0001")
    first = shown_backup(m)
    time.sleep(1.1)                                   # backup names carry a second-resolution stamp
    applied(m, "5.48.0", "upg-ccdd0002")
    return first, shown_backup(m)


def test_a_restore_naming_another_copy_than_the_one_it_would_restore_is_refused(m):
    first, second = two_applies(m)
    assert first != second
    send(m, "restore", confirm="RESTORE", backup=first)
    assert process(m) == ["rejected"] and rejection(m)["code"] == "target_changed"
    assert "upgrade.restore_requested" not in [e["action"] for e in m.audit_actions()]
    send(m, "restore", cid="upg-feed0002", aid="aid_0123456789abcdef0002", confirm="RESTORE", backup=second)
    assert process(m) == ["restored"]


def test_an_apply_queued_ahead_of_a_restore_changes_the_target_and_the_restore_is_refused(m):
    applied(m, "5.47.0", "upg-ccdd0001")
    shown = shown_backup(m)                            # what the page showed
    time.sleep(1.1)
    m.build_release("5.48.0")
    m.put_artifacts("5.48.0")
    m.host.schema_on_start["5.48.0"] = 10
    m.host.clock = time.time()
    req = m.request("5.48.0", correlation_id="upg-ccdd0002", requested_at=act.iso(time.time()), origin="app")
    d = inbox(m)
    d.mkdir(parents=True, exist_ok=True)
    (d / "upg-ccdd0002.json").write_text(json.dumps(req))
    os.chmod(d / "upg-ccdd0002.json", 0o600)
    os.utime(d / "upg-ccdd0002.json", (time.time() - 60, time.time() - 60))                 # the apply is older: it runs first
    send(m, "restore", confirm="RESTORE", backup=shown)
    assert process(m) == ["completed", "rejected"]
    assert rejection(m)["code"] == "target_changed"


def test_restore_is_refused_while_anything_is_in_flight(m):
    applied(m)
    name = shown_backup(m)
    st = m.read_state()
    st.update(result=None, step="restarting")
    STATE(m).write_text(json.dumps(st))
    send(m, "restore", confirm="RESTORE", backup=name)
    assert not any(e["action"] == "upgrade.restore_requested" for e in m.audit_actions())
    up = m.updater()
    m.host.clock = time.time()
    with pytest.raises(act.StepFailed) as exc:
        up.validate_request(act.read_request_file(m.cfg(), str(next(inbox(m).iterdir())), os.geteuid()), True)
    assert exc.value.code == "in_flight"
    with pytest.raises(act.StepFailed) as exc:
        up.restore_action("x", expect_backup=name)
    assert exc.value.code == "in_flight"


# --- the leftovers of a flood are bounded -------------------------------------------------------------------------------
def test_a_second_bundle_within_five_minutes_is_refused(m):
    applied(m)
    send(m, "bundle")
    assert process(m) == ["bundle_created"]
    send(m, "bundle", cid="upg-feed0002", aid="aid_0123456789abcdef0002")
    assert process(m) == ["rejected"] and rejection(m, "upg-feed0002")["code"] == "request_invalid"
    assert len(list((m.data / "upgrade" / "bundles").glob("ocw-support-*.tar.gz"))) <= 2


def test_a_run_keeps_the_newest_ten_bundles_and_a_bounded_number_of_handled_requests_and_rejections(m):
    applied(m)
    up_dir = m.data / "upgrade"
    (up_dir / "bundles").mkdir(exist_ok=True)
    (up_dir / "rejections").mkdir(exist_ok=True)
    (up_dir / "requests-done").mkdir(exist_ok=True)
    now = time.time()
    for i in range(25):
        p = up_dir / "bundles" / f"ocw-support-5.46.0-to-5.47.0-2026010{i % 9}T000000Z-{i:04x}.tar.gz"
        p.write_bytes(b"x")
        os.utime(p, (now - 1000 + i, now - 1000 + i))
    for i in range(300):
        for d, name in (("rejections", f"upg-{i:08x}.json"), ("requests-done", f"upg-{i:08x}.json.abc{i}")):
            p = up_dir / d / name
            p.write_text("{}")
            os.utime(p, (now - 5000 + i, now - 5000 + i))
    act.run(m.cfg(), m.host)
    left = sorted((up_dir / "bundles").glob("ocw-support-*.tar.gz"), key=lambda p: p.stat().st_mtime)
    assert len(left) <= act.BUNDLES_KEEP and left[-1].name.endswith("0018.tar.gz")        # the newest survived
    assert len(list((up_dir / "rejections").iterdir())) <= act.DONE_KEEP
    assert len(list((up_dir / "requests-done").iterdir())) <= act.DONE_KEEP
    assert (up_dir / "rejections" / "upg-0000012b.json").exists()                          # newest kept


def test_a_burst_of_bundle_requests_builds_one_and_leaves_the_directories_bounded(m):
    applied(m)
    d = inbox(m)
    d.mkdir(parents=True, exist_ok=True)
    for i in range(60):
        p = d / f"upg-bb{i:06x}.json"
        p.write_text(json.dumps(raw_request(m, action="bundle", correlation_id=f"upg-bb{i:06x}", action_id=f"aid_burst{i:016d}")))
        os.chmod(p, 0o600)
    res = process(m)
    assert res.count("bundle_created") == 1 and res.count("rejected") == 59
    assert list(d.iterdir()) == []
    assert len(list((m.data / "upgrade" / "bundles").glob("ocw-support-*.tar.gz"))) <= act.BUNDLES_KEEP


# --- clear_failure while the host needs an operator ----------------------------------------------------------------------
def test_root_refuses_clear_failure_from_the_inbox_while_the_run_needs_an_operator(m):
    applied(m)
    st = m.read_state()
    st["result"] = "failed_needs_operator"
    STATE(m).write_text(json.dumps(st))
    (m.data / "upgrade" / "failures.json").write_text(json.dumps({"versions": {"5.47.0": {"count": 1, "last_code": "x"}}}))
    send(m, "clear_failure")
    assert process(m) == ["rejected"] and rejection(m)["code"] == "needs_operator"
    assert json.loads((m.data / "upgrade" / "failures.json").read_text())["versions"]
    assert ocw_cli.main(["clear-failure"], m.cfg(), m.host) == 0                      # the command line still works
    assert m.read_state()["result"] == "failed"


# --- replay protection reads the newest ids ----------------------------------------------------------------------------
def test_an_approval_id_is_remembered_even_when_the_file_is_larger_than_the_read(m):
    up = m.updater()
    path = m.data / "upgrade" / "actions.jsonl"
    path.write_text("".join(f"aid_filler{i:016d}\n" for i in range(260000)))               # about 5.7 MB of old ids
    assert path.stat().st_size > act.ACTIONS_READ_BYTES
    up.remember_action_id("aid_fresh0123456789ab")
    assert up.action_id_used("aid_fresh0123456789ab")
    assert not up.action_id_used("aid_never0123456789ab")


def test_the_approval_ids_file_is_rotated_and_keeps_the_recent_ids(m):
    up = m.updater()
    path = m.data / "upgrade" / "actions.jsonl"
    old = int(m.host.now()) - 10 * 86400
    path.write_text("".join(f"aid_old{i:020d} {old}\n" for i in range(40000)))
    up.remember_action_id("aid_recent0123456789a")
    assert path.stat().st_size < act.ACTIONS_ROTATE_BYTES
    assert up.action_id_used("aid_recent0123456789a") and not up.action_id_used(f"aid_old{5:020d}")


def test_history_is_read_from_the_end(m):
    up = m.updater()
    path = m.data / "upgrade" / "history.jsonl"
    filler = json.dumps({"correlation_id": "upg-00000001", "action": "apply", "backup": "/x/old", "pad": "p" * 900}) + "\n"
    with open(path, "w") as fh:
        for _ in range(10000):
            fh.write(filler)
        fh.write(json.dumps({"correlation_id": "upg-00000002", "action": "apply", "backup": "/x/newest"}) + "\n")
    assert path.stat().st_size > 8 * 1024 * 1024
    assert up._history_lines()[-1]["backup"] == "/x/newest"


# --- the schedule directory takes installs only; the audit trail labels the application's claim -----------------------
def test_a_non_install_in_the_schedule_directory_is_refused(m):
    d = m.data / "upgrade" / "schedule"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{CID}.json"
    p.write_text(json.dumps(raw_request(m, action="clear_failure", not_before=act.iso(time.time() - 5))))
    os.chmod(p, 0o600)
    m.host.clock = time.time()
    assert act.process_directory(m.updater(), str(d), due_only=True) == []
    assert rejection(m)["code"] == "request_invalid" and list(d.iterdir()) == []


def test_the_requesters_name_is_labelled_as_the_applications_claim(m):
    applied(m)
    send(m, "rollback", confirm="ROLLBACK")
    assert process(m) == ["rolled_back"]
    row = [e for e in m.audit_actions() if e["details"].get("step") == "rollback_requested"][-1]
    assert row["actor_email"] == "admin@example.com" and "application's claim" in row["details"]["actor_is"]


# --- the quiesce file covers a slow run --------------------------------------------------------------------------------
def test_the_quiesce_file_is_refreshed_at_each_step_so_a_slow_restart_stays_covered(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    seen = {}
    real_run, real_get = m.host.run, m.host.http_get

    def slow_run(argv, timeout=120):
        if argv[0] == "systemctl" and "restart" in argv:
            m.host.clock += 700                      # a migration-heavy restart: longer than the ten minutes
        return real_run(argv, timeout)

    def watch(port, path, headers=None, timeout=3):
        q = m.data / "upgrade" / "quiesce.json"
        seen.setdefault("covered", []).append(q.exists() and act.parse_iso(json.loads(q.read_text())["until"]) > m.host.now())
        return real_get(port, path, headers, timeout)
    m.host.run, m.host.http_get = slow_run, watch
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-ccdd0001")) == "completed"
    assert seen["covered"] and all(seen["covered"][1:])                        # (the first call is the preflight baseline)
    assert not (m.data / "upgrade" / "quiesce.json").exists()


# --- the application side ----------------------------------------------------------------------------------------------------
def test_the_activator_version_check_refuses_only_a_known_old_one():
    assert upgrade.activator_too_old("5.47.0") and upgrade.activator_too_old("5.9.9")
    assert not upgrade.activator_too_old("5.48.0") and not upgrade.activator_too_old("5.48.1") and not upgrade.activator_too_old("6.0.0")
    assert not upgrade.activator_too_old(None) and not upgrade.activator_too_old("garbage")
