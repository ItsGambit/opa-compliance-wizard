"""5.48.0: the requests the web application may leave in the updater's inbox beyond "install now" -- rollback, restore, clear a
failure, rebuild the support bundle, delete old backups -- run by the real root state machine on the fake machine. Every kind the app
writes passes root's validator; malformed, oversized, unknown, replayed and unconfirmed ones are refused by both sides; hostile
inbox entries are drained."""
import json
import os
import sqlite3
import time

import pytest

import updater_fakes as uf
from updater_fakes import act
from server.updater import upgrade

CID = "upg-feed0001"
AID = "aid_0123456789abcdef0123"


@pytest.fixture
def m(tmp_path, monkeypatch):
    mm = uf.Machine(tmp_path)
    mm.host.clock = time.time()
    monkeypatch.setenv("OPA_UPGRADE_DIR", str(mm.data / "upgrade"))
    monkeypatch.setenv("OCW_OPT_DIR", str(mm.opt))
    return mm


def applied(m, version="5.47.0", cid="upg-ccdd0001"):
    m.build_release(version)
    m.put_artifacts(version)
    m.host.schema_on_start[version] = 10
    assert m.updater().apply(m.request(version, correlation_id=cid)) == "completed"


def shown_backup(m):
    """The copy name the page shows (state.json backup.name)."""
    return m.read_state()["backup"]["name"]


def inbox(m):
    return m.data / "upgrade" / "inbox" / "requests"


def send(m, action, cid=CID, aid=AID, **fields):
    """The application's writer -> the file in the inbox -> root's reader and validator."""
    path = upgrade.write_action(action, correlation_id=cid, action_id=aid, actor="admin@example.com", now=None, **fields)
    return path


def process(m):
    m.host.clock = time.time()
    return act.process_directory(m.updater(), str(inbox(m)))


def rejection(m, cid=CID):
    p = m.data / "upgrade" / "rejections" / f"{cid}.json"
    return json.loads(p.read_text()) if p.exists() else None


# --- each kind, accepted and carried out ----------------------------------------------------------------------------
def test_every_kind_the_app_writes_passes_roots_validator(m):
    applied(m)
    cases = [("rollback", {"confirm": "ROLLBACK"}), ("restore", {"confirm": "RESTORE", "backup": shown_backup(m)}), ("clear_failure", {}),
             ("bundle", {"include_hosts": True, "for_correlation_id": "upg-ccdd0001"})]
    up = m.updater()
    m.host.clock = time.time()
    for i, (kind, fields) in enumerate(cases):
        path = send(m, kind, cid=f"upg-feed01{i:02d}", aid=f"aid_0123456789abcdef01{i:02d}", **fields)
        req = act.read_request_file(m.cfg(), str(path), os.geteuid())
        up.validate_request(req, True)
        os.unlink(path)


def test_rollback_request_puts_the_previous_code_back_and_is_audited(m):
    applied(m)
    send(m, "rollback", confirm="ROLLBACK")
    assert process(m) == ["rolled_back"]
    assert os.readlink(m.opt / "current") == "releases/5.46.0" and m.host.serving["opa-compliance-wizard"] == "5.46.0"
    st = m.read_state()
    assert st["action"] == "rollback" and st["result"] == "rolled_back" and st["requested_by"] == "admin@example.com"
    assert not inbox(m).exists() or list(inbox(m).iterdir()) == []


def test_rollback_after_the_window_or_without_a_previous_release_is_refused(m):
    send(m, "rollback", confirm="ROLLBACK")
    assert process(m) == ["rejected"] and rejection(m)["code"] == "rollback_unavailable"        # nothing to go back to
    applied(m)
    st = m.read_state()
    st["updated_at"] = act.iso(time.time() - 25 * 3600)
    (m.data / "upgrade" / "state.json").write_text(json.dumps(st))
    send(m, "rollback", cid="upg-feed0002", aid="aid_0123456789abcdef0002", confirm="ROLLBACK")
    assert process(m) == ["rejected"] and rejection(m, "upg-feed0002")["code"] == "rollback_unavailable"
    assert os.readlink(m.opt / "current") == "releases/5.47.0"


def test_restore_request_puts_the_pre_upgrade_archive_back(m):
    applied(m)
    conn = sqlite3.connect(m.db)
    conn.execute("INSERT INTO events (who, what) VALUES ('later@example.com', 'after')")
    conn.commit()
    conn.close()
    send(m, "restore", confirm="RESTORE", backup=shown_backup(m))
    assert process(m) == ["restored"]
    assert sqlite3.connect(m.db).execute("SELECT COUNT(*) FROM events WHERE who = 'later@example.com'").fetchone()[0] == 0
    assert list(m.data.glob("audit_store.db.pre-restore-*"))                    # the replaced database is moved aside, never deleted
    assert "upgrade.restore_requested" in [e["action"] for e in m.audit_actions()]


def test_restore_without_a_backup_is_refused(m):
    send(m, "restore", confirm="RESTORE", backup="audit_store-pre-5.47.0-20260101T000000Z.db")
    assert process(m) == ["rejected"] and rejection(m)["code"] == "backup_failed"


def test_clear_failure_request_allows_the_version_again_and_is_audited(m):
    m.host.unhealthy_versions.add("5.47.0")
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-ccdd0009")) == "rolled_back"
    assert json.loads((m.data / "upgrade" / "failures.json").read_text())["versions"]
    send(m, "clear_failure")
    assert process(m) == ["failure_cleared"]
    assert json.loads((m.data / "upgrade" / "failures.json").read_text())["versions"] == {}
    row = [e for e in m.audit_actions() if e["action"] == "upgrade.clear_failure"][-1]
    assert row["details"]["cleared"] == ["5.47.0"] and row["details"]["via"] == "web application" and row["actor_email"] == "admin@example.com"


def age_bundle(m, seconds=3600):
    st = m.read_state()
    st["bundle"]["at"] = act.iso(time.time() - seconds)
    (m.data / "upgrade" / "state.json").write_text(json.dumps(st))


def test_bundle_request_rebuilds_with_hosts_only_when_asked(m):
    m.host.unhealthy_versions.add("5.47.0")
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.updater().apply(m.request("5.47.0", correlation_id="upg-ccdd0010"))
    first = m.read_state()["bundle"]
    assert first["include_hosts"] is False
    age_bundle(m)
    send(m, "bundle", include_hosts=True)
    assert process(m) == ["bundle_created"]
    second = m.read_state()["bundle"]
    assert second["include_hosts"] is True and second["name"] != first["name"]
    assert (m.data / "upgrade" / "bundles" / second["name"]).exists()
    age_bundle(m)
    send(m, "bundle", cid="upg-feed0003", aid="aid_0123456789abcdef0003")
    assert process(m) == ["bundle_created"] and m.read_state()["bundle"]["include_hosts"] is False


# --- backups: the published list and the typed delete ---------------------------------------------------------------
def three_backups(m):
    applied(m, "5.47.0", "upg-ccdd0001")
    d = m.data / "upgrade" / "backups"
    for i, stamp in enumerate(("20250101T000000Z", "20250601T000000Z")):
        f = d / f"audit_store-pre-5.4{i}.0-{stamp}.db"
        f.write_bytes(b"x" * (100 + i))
        os.utime(f, (time.time() - 86400 * (400 - 100 * i),) * 2)
    return sorted(p.name for p in d.glob("*.db"))


def test_the_backups_status_file_has_names_sizes_dates_and_integrity_but_no_paths(m):
    names = three_backups(m)
    m.updater().publish_backups()
    raw = (m.data / "upgrade" / "backups-status.json").read_text()
    data = json.loads(raw)
    assert [b["name"] for b in data["backups"]] == sorted(names, key=lambda n: [b["name"] for b in data["backups"]].index(n))
    assert str(m.data) not in raw and "/" not in "".join(b["name"] for b in data["backups"])
    real = [b for b in data["backups"] if "5.47.0" in b["name"]][0]
    assert real["integrity"] == "ok" and real["taken_before"] == "5.47.0" and real["size"] > 0
    assert oct((m.data / "upgrade" / "backups-status.json").stat().st_mode & 0o777) == "0o644"
    # the application reads it back without paths
    view = upgrade.backups_view()
    assert len(view["backups"]) == 3 and "path" not in json.dumps(view)


def test_prune_keeps_the_newest_and_the_last_upgrades_copy(m):
    names = three_backups(m)
    up = m.updater()
    up.st = {"correlation_id": None}
    req = {"confirm": "PRUNE", "keep_last": 1, "names": None}
    up.validate_prune(req)
    assert up.prune_backups(req, "cli:tester") == "backups_pruned"
    left = sorted(p.name for p in (m.data / "upgrade" / "backups").glob("*.db"))
    assert len(left) == 1 and "5.47.0" in left[0]                                  # the newest is the last upgrade's
    deleted = [e for e in m.audit_actions() if e["action"] == "upgrade.backups_pruned"][-1]["details"]
    assert set(deleted["deleted"]) == set(names) - set(left) and deleted["bytes_freed"] > 0
    assert len(json.loads((m.data / "upgrade" / "backups-status.json").read_text())["backups"]) == 1


def test_prune_by_name_refuses_the_protected_one_and_unknown_names(m):
    names = three_backups(m)
    protected = [n for n in names if "5.47.0" in n][0]
    up = m.updater()
    up.st = {"correlation_id": None}
    with pytest.raises(act.StepFailed) as exc:
        up.prune_backups({"confirm": "PRUNE", "names": [protected]}, "cli:tester")
    assert exc.value.code == "prune_refused"
    with pytest.raises(act.StepFailed):
        up.prune_backups({"confirm": "PRUNE", "names": ["audit_store-pre-9.9.9-20990101T000000Z.db"]}, "cli:tester")
    other = [n for n in names if n != protected][0]
    assert up.prune_backups({"confirm": "PRUNE", "names": [other]}, "cli:tester") == "backups_pruned"
    assert not (m.data / "upgrade" / "backups" / other).exists() and (m.data / "upgrade" / "backups" / protected).exists()


def test_deleting_backups_is_not_an_inbox_kind_root_refuses_it_and_the_writer_will_not_write_it(m):
    names = three_backups(m)
    with pytest.raises(ValueError):
        send(m, "prune_backups", confirm="PRUNE", keep_last=1)
    p = inbox(m) / f"{CID}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(raw_request(m, action="prune_backups", confirm="PRUNE", keep_last=1)))
    os.chmod(p, 0o600)
    assert process(m) == []
    assert rejection(m)["code"] == "request_invalid"
    assert sorted(x.name for x in (m.data / "upgrade" / "backups").glob("*.db")) == names      # nothing was deleted
    assert list(inbox(m).iterdir()) == []


# --- quiesce -------------------------------------------------------------------------------------------------------
def test_the_preflight_quiesces_new_syncs_until_the_end(m):
    seen = {}
    real = m.host.db_tool

    def watch(args):
        seen["file"] = seen.get("file") or (m.data / "upgrade" / "quiesce.json").exists()
        return real(args)
    m.host.db_tool = watch
    applied(m)
    assert seen["file"] is True or (m.data / "upgrade" / "quiesce.json").exists() is False
    assert not (m.data / "upgrade" / "quiesce.json").exists()                        # lifted when the upgrade finished
    m.updater().quiesce()
    q = json.loads((m.data / "upgrade" / "quiesce.json").read_text())
    assert act.parse_iso(q["until"]) > m.host.now()
    assert upgrade.quiesced()                                                         # the application honours it
    m.updater().unquiesce()
    assert not upgrade.quiesced()


# --- refusals: root and the app writer agree ------------------------------------------------------------------------
BAD = [
    ("rollback", {"confirm": "rollback"}), ("rollback", {}), ("restore", {"confirm": "ROLLBACK"}), ("restore", {"confirm": "RESTORE"}),
    ("restore", {"confirm": "RESTORE", "backup": "../../etc/passwd"}), ("prune_backups", {"confirm": "PRUNE", "keep_last": 2}),
    ("bundle", {"include_hosts": "yes"}), ("bundle", {"for_correlation_id": "../x"}),
    ("clear_failure", {"confirm": "x"}), ("clear_failure", {"names": []}),
]


@pytest.mark.parametrize("kind, fields", BAD)
def test_the_app_refuses_to_write_what_root_would_refuse(m, kind, fields):
    with pytest.raises(ValueError):
        send(m, kind, **fields)
    assert not inbox(m).exists() or list(inbox(m).iterdir()) == []


def raw_request(m, **over):
    req = {"schema": 1, "action": "clear_failure", "correlation_id": CID, "action_id": AID, "requested_at": act.iso(time.time()),
           "origin": "app", "actor": "a@example.com", "trigger_kind": "app"}
    req.update(over)
    return {k: v for k, v in req.items() if v is not ...}


@pytest.mark.parametrize("over, code", [
    ({"action": "format_disk"}, "request_invalid"), ({"extra": 1}, "request_invalid"), ({"action": "rollback"}, "confirm_required"),
    ({"action": "rollback", "confirm": "ROLLBACK", "version": "5.47.0"}, "request_invalid"), ({"actor": "x" * 500}, "request_invalid"),
    ({"actor": ["a"]}, "request_invalid"), ({"origin": "web"}, "request_invalid"), ({"correlation_id": "../../x"}, "request_invalid"),
    ({"action_id": "short"}, "request_invalid"), ({"requested_at": "yesterday"}, "request_stale"),
    ({"requested_at": act.iso(time.time() - 90000)}, "request_stale"), ({"schema": 2}, "request_invalid"),
    ({"action": "bundle", "include_hosts": 1}, "request_invalid"), ({"action": "prune_backups", "confirm": "PRUNE", "keep_last": 2}, "request_invalid"),
    ({"action": "restore", "confirm": "RESTORE", "names": []}, "request_invalid"), ({"action": "restore", "confirm": "RESTORE"}, "request_invalid"),
])
def test_root_refuses_malformed_requests_and_leaves_no_trace(m, over, code):
    up = m.updater()
    m.host.clock = time.time()
    with pytest.raises(act.StepFailed) as exc:
        up.validate_request(raw_request(m, **over), True)
    assert exc.value.code == code
    path = inbox(m) / f"{CID}.json"
    path.write_text(json.dumps(raw_request(m, **over)))
    os.chmod(path, 0o600)
    process(m)
    assert list(inbox(m).iterdir()) == [] and list((m.data / "upgrade" / "rejections").glob("*.json")) and not (m.data / "upgrade" / "failures.json").exists()


def test_a_replayed_approval_is_refused_whatever_the_kind(m):
    send(m, "clear_failure")
    assert process(m) == ["failure_cleared"]
    send(m, "clear_failure", cid="upg-feed0006")                         # same approval id
    assert process(m) == ["rejected"] and rejection(m, "upg-feed0006")["code"] == "request_replayed"
    applied(m)
    send(m, "rollback", cid="upg-feed0007", confirm="ROLLBACK")        # and across kinds
    assert process(m) == ["rejected"] and os.readlink(m.opt / "current") == "releases/5.47.0"


def test_an_inbox_apply_cannot_carry_a_start_time(m):
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    req = m.request("5.47.0", correlation_id=CID, not_before=act.iso(time.time() + 3600), requested_at=act.iso(time.time()), origin="app")
    p = inbox(m) / f"{CID}.json"
    p.write_text(json.dumps(req))
    os.chmod(p, 0o600)
    assert process(m) == []
    assert rejection(m)["code"] == "request_invalid" and os.readlink(m.opt / "current") == "releases/5.46.0"


def test_hostile_inbox_entries_are_all_drained(m):
    d = inbox(m)
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.json").write_text("[1, 2]")                       # valid JSON, wrong shape
    (d / "b.json").write_text("7")
    (d / "c.json").write_text("{not json")
    (d / "d.json").write_text(json.dumps({"x": "y" * 20000}))
    (d / "e.txt").write_text("stray")
    (d / "f.json").write_text(json.dumps(raw_request(m, action="bundle", include_hosts={"a": 1})))
    os.symlink("/etc/passwd", d / "g.json")
    os.mkdir(d / "h.json")
    os.mkfifo(d / "j.json")
    wide = d / "k.json"
    wide.write_text(json.dumps(raw_request(m)))
    os.chmod(wide, 0o666)
    for p in d.glob("*.json"):
        if not p.is_symlink() and p.is_file() and p.name != "k.json":
            os.chmod(p, 0o600)
    process(m)
    assert list(d.iterdir()) == []
    assert not (m.data / "upgrade" / "failures.json").exists() and os.readlink(m.opt / "current") == "releases/5.46.0"
