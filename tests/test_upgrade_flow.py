"""5.48.0: the in-app upgrade flow, application side (server/updater/upgrade.py and the /api/upgrade/request executor).

Driven against the fake release server (signature file + manifest.json served over loopback), a real HTTP server in
hosted mode with the step-up transaction, and the root updater's OWN request validator (tests/updater_fakes.py): a
request this application writes must pass what root checks, and what root rejects must never be written.
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import updater_fakes as uf
from fake_release_server import FakeReleaseServer
from release_helpers import TestKey, TestStandby, key_list, make_release_tar, sign_release
from test_http_authz_matrix import ADMIN, SECRET, _who, matrix_server  # noqa: F401  (the fixture)

import audit_store
import create_secret_folders as engine
from server.updater import keys as keylib
from server.updater import service
from server.updater import upgrade

TARGET = "5.99.0"
OTHER_ADMIN = "00uOTHERADMIN"
NOW = datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Armed:
    """A hosted-mode server with an update available: signed release served by the fake release server, preview taken."""

    def __init__(self, base_url, serve, machine, srv, key, tar, sha):
        self.base_url, self.serve, self.m, self.srv, self.key, self.tar, self.sha = base_url, serve, machine, srv, key, tar, sha

    def post(self, body, who=ADMIN, path="/api/upgrade/request"):
        return requests.post(self.base_url + path, json=body, headers=_who(who, admin=True), timeout=10)

    def request(self, body, who=ADMIN, status=200):
        """prepare -> 202, then the gate-approved save; returns the save response."""
        prep = self.post(body, who)
        assert prep.status_code == 202, prep.text
        done = requests.post(self.base_url + "/api/environment_changes/save", json={},
                             headers={**_who(who, admin=True), "X-Auth-Action-Id": prep.json()["action_id"],
                                      "X-Nginx-Stepup-Location": SECRET}, timeout=10)
        assert done.status_code == status, done.text
        return done

    def apply_body(self, **over):
        return {"kind": "apply", "version": TARGET, "sha256": self.sha, "acknowledged": True, **over}

    def schedule_body(self, hours=5, **over):
        when = iso(datetime.now(timezone.utc) + timedelta(hours=hours))
        return {"kind": "schedule", "version": TARGET, "sha256": self.sha, "acknowledged": True, "when_utc": when, **over}

    def requests_written(self):
        d = self.m.data / "upgrade" / "inbox" / "requests"
        return sorted(d.glob("*.json"))

    def audit(self):
        p = engine._audit_log_path()
        return [json.loads(line) for line in open(p, encoding="utf-8") if line.strip()]

    def status(self):
        return requests.get(self.base_url + "/api/upgrade/status", headers=_who(ADMIN, admin=True), timeout=10).json()


@pytest.fixture
def armed(matrix_server, monkeypatch, tmp_path):  # noqa: F811
    base_url, serve = matrix_server
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")
    machine = uf.Machine(tmp_path / "machine")
    monkeypatch.setenv("OPA_UPGRADE_DIR", str(machine.data / "upgrade"))
    monkeypatch.setenv("OCW_OPT_DIR", str(machine.opt))
    machine.host.clock = time.time()            # the fake machine runs on the real clock here
    key = machine.primary
    shipped = tmp_path / "release_keys.json"
    shipped.write_text(json.dumps(machine.key_list))
    monkeypatch.setattr(keylib, "SHIPPED_PATH", shipped)
    tar = machine.build_release(TARGET)
    sig = str(tar) + ".minisig"
    sha = __import__("hashlib").sha256(open(tar, "rb").read()).hexdigest()
    manifest = {"schema": 1, "version": TARGET, "min_upgrade_from": "5.41.0", "downtime_estimate_seconds": 45,
                "migrations": [{"version": 10, "since": TARGET, "rollback_safe": True},
                               {"version": 11, "since": TARGET, "rollback_safe": False}],
                "expected_schema_version": 11, "changelog_excerpt": f"{TARGET} — Test release\nA summary.",
                "nginx_template_changed": True, "activator_version": TARGET}
    srv = FakeReleaseServer()
    srv.respond(f"/v{TARGET}/ocw-{TARGET}.tar.gz.minisig", body=open(sig, "rb").read())
    srv.respond(f"/v{TARGET}/manifest.json", body=json.dumps(manifest).encode())
    monkeypatch.setenv("OPA_RELEASE_BASE_URL", srv.base)
    service.set_settings(enabled=True)
    data = service.load()
    data["state"].update(latest_version=TARGET, size=14_000_000)
    service.save(data)
    a = Armed(base_url, serve, machine, srv, key, tar, sha)
    a.sig_path, a.manifest, a.sig_bytes = sig, manifest, open(sig, "rb").read()
    yield a
    srv.close()


def take_preview(a, status=200):
    r = requests.post(a.base_url + "/api/upgrade/preview", json={}, headers=_who(ADMIN, admin=True), timeout=20)
    assert r.status_code == status, r.text
    return r.json()


# --- the preview ------------------------------------------------------------------------------------------------------
def test_preview_verifies_the_signed_comment_and_reports_the_preflight(armed):
    p = take_preview(armed)["preview"]
    assert p["version"] == TARGET and p["sha256"] == armed.sha and p["key_id"] == armed.key.key_id
    assert [m["rollback_safe"] for m in p["manifest"]["migrations"]] == [True, False]
    assert p["manifest"]["changelog_excerpt"].startswith(f"{TARGET} — Test release")
    ids = {i["id"]: i["ok"] for i in p["preflight"]}
    assert ids["python"] and ids["sqlite"] and ids["updater"] and "in_flight" not in ids     # only listed when it fails
    texts = {i["id"]: i["text"] for i in p["preflight"]}
    assert "No other upgrade in flight." in texts["updater"] and texts["python"].startswith("Python ") and "≥" in texts["python"]
    assert texts["disk_data"].startswith("Disk, data volume:") and "No sync running." in texts["sync"]
    st = armed.status()
    assert st["upgrade"]["preview"]["sha256"] == armed.sha
    assert [e["action"] for e in armed.audit() if e["action"] == "upgrade.preview"] == ["upgrade.preview"]


def test_preview_refuses_a_tampered_signature_file(armed):
    text = armed.sig_bytes.decode().replace(f"version={TARGET}", "version=5.99.1")
    armed.srv.respond(f"/v{TARGET}/ocw-{TARGET}.tar.gz.minisig", body=text.encode())
    body = take_preview(armed, 409)
    assert body["reason"] in ("bad_trusted_comment", "name_mismatch")
    assert service.load()["state"]["latest_version"] == TARGET and upgrade.load_preview() is None


def test_preview_refuses_unknown_key_missing_files_and_a_manifest_for_another_version(armed, monkeypatch):
    other = TestKey()
    tar = armed.tar
    sig = sign_release(tar, other, TARGET)
    armed.srv.respond(f"/v{TARGET}/ocw-{TARGET}.tar.gz.minisig", body=open(sig, "rb").read())
    assert take_preview(armed, 409)["reason"] == "unknown_key"
    armed.srv.respond(f"/v{TARGET}/ocw-{TARGET}.tar.gz.minisig", body=armed.sig_bytes)
    armed.srv.respond(f"/v{TARGET}/manifest.json", body=json.dumps({**armed.manifest, "version": "5.99.9"}).encode())
    assert take_preview(armed, 409)["reason"] == "bad_manifest"
    armed.srv.script.pop(f"/v{TARGET}/manifest.json")
    assert take_preview(armed, 502)["reason"] == "fetch_failed"
    armed.srv.respond(f"/v{TARGET}/manifest.json", body=b"x" * (upgrade.MAX_MANIFEST_BYTES + 10))
    assert take_preview(armed, 502)["reason"] == "fetch_failed"


def test_preview_refuses_when_the_installed_version_is_too_old(armed):
    armed.srv.respond(f"/v{TARGET}/manifest.json", body=json.dumps({**armed.manifest, "min_upgrade_from": "9.0.0"}).encode())
    assert take_preview(armed, 409)["reason"] == "too_old"


def test_preview_needs_a_known_newer_release_and_the_check_on(armed):
    data = service.load()
    data["state"]["latest_version"] = "5.0.0"
    service.save(data)
    assert take_preview(armed, 409)["reason"] == "no_update"
    service.set_settings(enabled=False)
    assert take_preview(armed, 409)["reason"] == "check_off"


# --- upgrade now ------------------------------------------------------------------------------------------------------
def test_upgrade_now_needs_the_review_the_acknowledgement_and_a_step_up(armed):
    r = armed.post(armed.apply_body())
    assert r.status_code == 409 and r.json()["reason"] == "preview_missing"
    take_preview(armed)
    assert armed.post(armed.apply_body(acknowledged=False)).status_code == 400
    assert armed.post({k: v for k, v in armed.apply_body().items() if k != "acknowledged"}).status_code == 400
    assert armed.requests_written() == []
    prep = armed.post(armed.apply_body())
    assert prep.status_code == 202 and prep.json()["action"] == "upgrade.request"
    assert armed.requests_written() == []              # nothing before the approval
    done = armed.request(armed.apply_body())
    assert done.json()["kind"] == "apply" and done.json()["step_up_verified"] is True
    files = armed.requests_written()
    assert len(files) == 1 and oct(os.stat(files[0]).st_mode & 0o777) == "0o600"
    req = json.loads(files[0].read_text())
    assert req["not_before"] is None and req["action"] == "apply" and req["version"] == TARGET and req["sha256"] == armed.sha
    ev = [e for e in armed.audit() if e["action"] == "upgrade.requested"]
    assert len(ev) == 1 and ev[0]["details"]["step_up_verified"] is True and ev[0]["details"]["correlation_id"] == req["correlation_id"]
    assert ev[0]["details"]["sha256"] == armed.sha and ev[0]["details"]["action_id"] == req["action_id"]


def test_the_request_the_app_writes_passes_the_root_validator_and_malformed_ones_fail_both(armed):
    take_preview(armed)
    armed.request(armed.apply_body())
    path = armed.requests_written()[0]
    armed.m.host.clock = time.time()      # the fake machine's clock is the real one for this test
    cfg = armed.m.cfg()
    req = uf.act.read_request_file(cfg, str(path), os.geteuid())
    up = armed.m.updater()
    up.validate_request(req, True)            # root accepts it (raises StepFailed otherwise)
    # the app refuses to write what root would reject ...
    for bad in ({"version": "5.99"}, {"sha256": "z" * 64}, {"correlation_id": "bad"}):
        kw = dict(correlation_id="upg-0123abcd", version=TARGET, sha256=armed.sha, action_id=None, actor="a@example.com",
                  trigger_kind="app")
        kw.update(bad)
        with pytest.raises(ValueError):
            upgrade.write_request(**kw)
    # ... and root rejects the same shapes if they arrive some other way
    for over in ({"version": "5.99"}, {"sha256": "z" * 64}, {"correlation_id": "bad"}, {"schema": 2}):
        with pytest.raises(uf.act.StepFailed):
            up.validate_request({**req, **over}, True)
    # an unusable action id is dropped, never forwarded
    p = upgrade.write_request(correlation_id="upg-0123abcd", version=TARGET, sha256=armed.sha, action_id="bad id!", actor="x", trigger_kind="app")
    assert json.loads(p.read_text())["action_id"] is None


def test_a_step_up_cannot_be_replayed_or_used_by_another_admin(armed):
    take_preview(armed)
    prep = armed.post(armed.apply_body()).json()
    hdr = {"X-Auth-Action-Id": prep["action_id"], "X-Nginx-Stepup-Location": SECRET}
    other = requests.post(armed.base_url + "/api/environment_changes/save", json={}, headers={**_who(OTHER_ADMIN, admin=True), **hdr}, timeout=10)
    assert other.status_code == 403 and armed.requests_written() == []
    ok = requests.post(armed.base_url + "/api/environment_changes/save", json={}, headers={**_who(ADMIN, admin=True), **hdr}, timeout=10)
    assert ok.status_code == 200
    again = requests.post(armed.base_url + "/api/environment_changes/save", json={}, headers={**_who(ADMIN, admin=True), **hdr}, timeout=10)
    assert again.status_code == 409 and again.json()["reason"] == "already_consumed"
    assert len(armed.requests_written()) == 1


def test_the_approval_is_bound_to_the_version_and_hash_it_showed(armed):
    take_preview(armed)
    prep = armed.post(armed.apply_body()).json()
    # the signed release information changes between the request and the approval
    p = upgrade.load_preview()
    p["sha256"] = "b" * 64
    upgrade.save_preview(p)
    r = requests.post(armed.base_url + "/api/environment_changes/save", json={"version": "6.0.0", "sha256": armed.sha},
                      headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": prep["action_id"], "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert r.status_code == 409 and r.json()["reason"] == "target_changed"
    assert armed.requests_written() == []
    # a wrong hash or another version is refused before any MFA
    take_preview(armed)
    assert armed.post(armed.apply_body(sha256="c" * 64)).status_code == 409
    assert armed.post(armed.apply_body(version="5.99.1")).status_code == 409
    assert armed.post(armed.apply_body(version="x.y")).status_code == 400


def test_a_failed_version_a_lockout_or_an_unready_updater_stops_it_before_mfa(armed, tmp_path):
    take_preview(armed)
    up_dir = armed.m.data / "upgrade"
    (up_dir / "failures.json").write_text(json.dumps({"versions": {TARGET: {"count": 1, "last_code": "health_version"}}}))
    r = armed.post(armed.apply_body())
    assert r.status_code == 409 and r.json()["reason"] == "version_failed_before"
    (up_dir / "failures.json").write_text(json.dumps({"versions": {"5.90.0": {"count": 1}, "5.91.0": {"count": 1}}}))
    assert armed.post(armed.apply_body()).json()["reason"] == "too_many_failures"
    (up_dir / "failures.json").unlink()
    (up_dir / "state.json").write_text(json.dumps({"correlation_id": "upg-1", "result": "failed_needs_operator", "step": "failed_needs_operator"}))
    assert armed.post(armed.apply_body()).json()["reason"] == "needs_operator"
    (up_dir / "state.json").write_text(json.dumps({"correlation_id": "upg-1", "result": None, "step": "switching"}))
    assert armed.post(armed.apply_body()).json()["reason"] == "in_flight"
    (up_dir / "state.json").unlink()
    os.chmod(up_dir / "inbox" / "requests", 0o500)
    try:
        if os.geteuid() != 0:
            assert armed.post(armed.apply_body()).json()["reason"] == "inbox_not_writable"
    finally:
        os.chmod(up_dir / "inbox" / "requests", 0o700)
    os.rmdir(up_dir / "inbox" / "requests")
    assert armed.post(armed.apply_body()).json()["reason"] == "updater_not_installed"


def test_hostile_bodies(armed):
    take_preview(armed)
    huge = "A" * 100_000
    for body in ({"kind": "format"}, {"kind": "apply", "version": TARGET, "sha256": armed.sha, "acknowledged": True, "evil": "x"},
                 {**armed.apply_body(), "version": huge}, {**armed.apply_body(), "acknowledged": "yes"}, {**armed.apply_body(), "sha256": 5},
                 {**armed.apply_body(), "when_utc": iso(NOW + timedelta(days=1))}, ["kind"], {"kind": None}):
        r = armed.post(body)
        assert r.status_code in (400, 413), (body if len(str(body)) < 200 else "big", r.status_code, r.text)
    assert armed.requests_written() == []


# --- scheduling -------------------------------------------------------------------------------------------------------
def test_schedule_reschedule_and_cancel(armed):
    take_preview(armed)
    t = (datetime.now(timezone.utc) + timedelta(hours=5)).replace(second=0, microsecond=0)
    done = armed.request(armed.schedule_body(when_utc=iso(t), entered_tz="UTC", entered_local=t.strftime("%Y-%m-%dT%H:%M")))
    assert done.json()["kind"] == "schedule" and armed.requests_written() == []   # nothing goes to the updater yet
    s = armed.status()["upgrade"]["schedule"]
    assert s["status"] == "scheduled" and s["version"] == TARGET and s["sha256"] == armed.sha
    assert armed.post(armed.schedule_body()).json()["reason"] == "already_scheduled"
    r = armed.request({**armed.schedule_body(hours=9), "kind": "reschedule"})
    assert r.json()["kind"] == "reschedule"
    assert armed.status()["upgrade"]["schedule"]["when_utc"] != s["when_utc"]
    armed.request({"kind": "cancel"})
    assert armed.status()["upgrade"]["schedule"]["status"] == "cancelled"
    assert armed.post({"kind": "cancel"}).json()["reason"] == "not_scheduled"
    names = [e["action"] for e in armed.audit() if e["action"].startswith("upgrade.") and e["action"] != "upgrade.preview"]
    assert names == ["upgrade.scheduled", "upgrade.rescheduled", "upgrade.cancelled"]
    resched = [e for e in armed.audit() if e["action"] == "upgrade.scheduled"][0]["details"]
    assert resched["step_up_verified"] is True and resched["entered_tz"] == "UTC" and resched["when_utc"]


def test_bad_times_are_refused(armed):
    take_preview(armed)
    for when, code in ((iso(NOW - timedelta(hours=1)), 409), (iso(NOW + timedelta(seconds=30)), 409),
                       (iso(NOW + timedelta(days=40)), 400), ("tomorrow", 400), ("2026-13-45T00:00:00Z", 400),
                       ("2026-10-21T02:30:00+01:00", 400)):
        r = armed.post(armed.schedule_body(when_utc=when))
        assert r.status_code == code, (when, r.status_code, r.text)
    # a zone/local pair that is not the same moment as when_utc, an unknown zone, a half pair
    ok_when = iso(NOW + timedelta(hours=5))
    for extra in ({"entered_tz": "UTC", "entered_local": "2030-01-01T00:00"}, {"entered_tz": "Nowhere/Land", "entered_local": "2030-01-01T00:00"},
                  {"entered_tz": "UTC"}, {"entered_tz": "../../etc", "entered_local": "2030-01-01T00:00"}):
        assert armed.post(armed.schedule_body(when_utc=ok_when, **extra)).status_code == 400, extra
    assert armed.post({**armed.apply_body(), "kind": "reschedule"}).status_code == 400   # no time
    assert armed.post({**armed.schedule_body(), "kind": "reschedule"}).json()["reason"] == "not_scheduled"


def test_a_time_that_passes_while_waiting_for_the_mfa_approval_is_refused(armed):
    take_preview(armed)
    near = iso(datetime.now(timezone.utc) + timedelta(minutes=3))
    prep = armed.post(armed.schedule_body(when_utc=near)).json()
    # the admin takes too long at the identity provider: the stored time is now less than a minute away
    soon = iso(datetime.now(timezone.utc) + timedelta(seconds=20))
    conn = audit_store._get_connection()
    row = conn.execute("SELECT payload_json FROM pending_admin_actions WHERE action_id = ?", (prep["action_id"],)).fetchone()
    payload = json.loads(row[0].replace(near, soon))
    conn.execute("UPDATE pending_admin_actions SET payload_json = ? WHERE action_id = ?", (json.dumps(payload), prep["action_id"]))
    conn.commit()
    r = requests.post(armed.base_url + "/api/environment_changes/save", json={},
                      headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": prep["action_id"], "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert r.status_code == 409 and r.json()["reason"] == "time_passed"
    assert upgrade.load_schedule()["schedule"] is None


def test_the_tick_hands_a_due_upgrade_to_the_updater_once(armed):
    take_preview(armed)
    armed.request(armed.schedule_body(hours=5))
    due = datetime.now(timezone.utc) + timedelta(hours=5, minutes=1)
    ctx = lambda: {"sync_running": False, "run": None}  # noqa: E731
    assert upgrade.tick("5.48.0", ctx, now=due - timedelta(hours=1)) is None and armed.requests_written() == []
    assert upgrade.tick("5.48.0", ctx, now=due) == "started"
    files = armed.requests_written()
    assert len(files) == 1
    req = json.loads(files[0].read_text())
    assert req["not_before"] is None and req["trigger_kind"].startswith("schedule ")
    armed.m.host.clock = time.time() + 5 * 3600
    armed.m.updater().validate_request(uf.act.read_request_file(armed.m.cfg(), str(files[0]), os.geteuid()), True)
    assert upgrade.tick("5.48.0", ctx, now=due + timedelta(seconds=30)) is None   # not twice
    assert len(armed.requests_written()) == 1
    assert upgrade.load_schedule()["schedule"]["status"] == "started"
    assert upgrade.quiesced(due + timedelta(minutes=1)) and not upgrade.quiesced(due + timedelta(minutes=30))


def test_a_time_the_app_missed_is_marked_missed_and_never_run_late(armed):
    take_preview(armed)
    armed.request(armed.schedule_body(hours=5))
    late = datetime.now(timezone.utc) + timedelta(hours=5, minutes=upgrade.MISSED_GRACE.seconds // 60 + 1)
    assert upgrade.tick("5.48.0", lambda: {"sync_running": False, "run": None}, now=late) == "missed"
    assert armed.requests_written() == []
    d = upgrade.load_schedule()
    assert d["schedule"]["status"] == "missed" and d["last"]["kind"] == "missed"
    assert any(e["action"] == "upgrade.missed" for e in armed.audit())
    assert armed.status()["upgrade"]["schedule"]["status"] == "missed"
    armed.request(armed.schedule_body(hours=2))      # a missed one does not block scheduling again
    assert armed.status()["upgrade"]["schedule"]["status"] == "scheduled"


def test_the_tick_waits_for_a_running_sync_then_stops_waiting(armed):
    take_preview(armed)
    armed.request(armed.schedule_body(hours=5))
    due = datetime.now(timezone.utc) + timedelta(hours=5, minutes=1)
    busy = lambda: {"sync_running": True, "run": None}  # noqa: E731
    assert upgrade.tick("5.48.0", busy, now=due) == "waiting_for_sync" and armed.requests_written() == []
    assert upgrade.tick("5.48.0", busy, now=due + upgrade.WAIT_FOR_SYNC) == "started"   # the updater waits for it as well


def test_the_tick_refuses_a_changed_release_or_a_busy_updater(armed):
    take_preview(armed)
    armed.request(armed.schedule_body(hours=5))
    due = datetime.now(timezone.utc) + timedelta(hours=5, minutes=1)
    p = upgrade.load_preview()
    p["sha256"] = "d" * 64
    upgrade.save_preview(p)
    assert upgrade.tick("5.48.0", lambda: {"sync_running": False, "run": None}, now=due) == "target_changed"
    assert armed.requests_written() == []
    assert any(e["action"] == "upgrade.failed" and e["details"]["reason_code"] == "target_changed" for e in armed.audit())


def test_a_quiesced_app_starts_no_new_sync(armed, monkeypatch):
    calls = []
    monkeypatch.setattr(armed.serve, "_launch_claimed_sync", lambda *a, **k: calls.append(a) or True)
    take_preview(armed)
    assert armed.serve._start_sync_job("env", "dev", "curated") is True and len(calls) == 1
    armed.serve._sync_jobs.clear()
    armed.request(armed.apply_body())
    assert armed.serve._start_sync_job("env2", "dev", "curated", trigger="scheduled") is False and len(calls) == 1


# --- the optional two-person rule -------------------------------------------------------------------------------------
def test_two_person_rule(armed):
    take_preview(armed)
    r = requests.post(armed.base_url + "/api/upgrade/settings", json={"second_approval": True}, headers=_who(ADMIN, admin=True), timeout=10)
    assert r.status_code == 202
    requests.post(armed.base_url + "/api/environment_changes/save", json={},
                  headers={**_who(ADMIN, admin=True), "X-Auth-Action-Id": r.json()["action_id"], "X-Nginx-Stepup-Location": SECRET}, timeout=10)
    assert armed.status()["check"]["second_approval"] is True
    first = armed.request(armed.apply_body())
    assert first.json()["awaiting_second_approval"] is True and armed.requests_written() == []
    pend = armed.status()["upgrade"]["pending_approval"]
    assert pend["version"] == TARGET and pend["mine"] is True
    assert armed.post(armed.apply_body()).json()["reason"] == "already_pending"
    # the same admin cannot be the second approver
    assert armed.post({"kind": "approve_second"}).json()["reason"] == "same_admin"
    assert armed.requests_written() == []
    second = armed.request({"kind": "approve_second"}, who=OTHER_ADMIN)
    assert second.json()["kind"] == "apply"
    req = json.loads(armed.requests_written()[0].read_text())
    assert req["correlation_id"] == first.json()["correlation_id"]
    ev = [e for e in armed.audit() if e["action"] == "upgrade.requested"]
    assert ev[0]["details"]["awaiting_second_approval"] is True
    assert ev[-1]["details"]["second_approval"] is True and ev[-1]["actor_sub"] == OTHER_ADMIN
    assert upgrade.load_schedule()["pending_approval"] is None


def test_the_held_approval_expires_and_can_be_declined(armed):
    take_preview(armed)
    service.set_settings(second_approval=True)
    armed.request(armed.schedule_body(hours=5))
    assert armed.status()["upgrade"]["schedule"] is None
    pa = upgrade.load_schedule()["pending_approval"]
    # a different admin declines it
    armed.request({"kind": "cancel"}, who=OTHER_ADMIN)
    assert upgrade.load_schedule()["pending_approval"] is None
    cancelled = [e for e in armed.audit() if e["action"] == "upgrade.cancelled"][-1]["details"]
    assert cancelled["declined_by_second_admin"] is True and cancelled["correlation_id"] == pa["correlation_id"]
    # an expired one is dropped and noted
    armed.request(armed.schedule_body(hours=5))
    d = upgrade.load_schedule()
    d["pending_approval"]["expires_at"] = iso(NOW - timedelta(hours=1))
    upgrade.save_schedule(d)
    assert upgrade.pending_approval() is None
    assert armed.post({"kind": "approve_second"}, who=OTHER_ADMIN).json()["reason"] == "no_pending"
    assert upgrade.load_schedule()["last"]["kind"] == "approval_expired"


# --- the banner and the status ------------------------------------------------------------------------------------------
def test_notice_for_users_and_admins(armed):
    user = lambda: requests.get(armed.base_url + "/api/upgrade/notice", headers=_who("00uUSER"), timeout=10).json()  # noqa: E731
    admin = lambda: requests.get(armed.base_url + "/api/upgrade/notice", headers=_who(ADMIN, admin=True), timeout=10).json()  # noqa: E731
    assert user()["kind"] == "none" and admin() == {"kind": "available", "version": TARGET}
    take_preview(armed)
    armed.request(armed.schedule_body(hours=5))
    assert user()["kind"] == "scheduled" and user()["version"] == TARGET and "sha256" not in user()
    up = armed.m.data / "upgrade"
    (up / "state.json").write_text(json.dumps({"result": None, "step": "switching", "version_to": TARGET, "started_at": "2026-01-01T00:00:00Z"}))
    assert user()["kind"] == "running"
    (up / "state.json").write_text(json.dumps({"result": "rolled_back", "version_to": TARGET, "rolled_back_to": "5.48.0",
                                               "updated_at": iso(datetime.now(timezone.utc))}))
    assert user()["kind"] == "failed" and user()["result"] == "rolled_back"
    assert requests.get(armed.base_url + "/api/upgrade/notice", timeout=10).status_code == 401


def test_status_carries_the_run_the_rollback_window_and_history(armed):
    up = armed.m.data / "upgrade"
    done = iso(datetime.now(timezone.utc) - timedelta(hours=2))
    (up / "state.json").write_text(json.dumps({
        "correlation_id": "upg-7f3a9c2e", "action": "apply", "version_from": "5.48.0", "version_to": TARGET, "result": "completed",
        "updated_at": done, "steps_done": [{"step": "validated", "at": done, "seconds": 0.4, "detail": {"secret": "x"}}],
        "health": [{"id": "version", "ok": True, "detail": "ok"}], "backup": {"name": "b.db", "size": 5, "integrity": "ok", "path": "/root/only/b.db"},
        "manifest": {"migrations": [], "files": {"a": "b"}}, "env_file": "/etc/secret"}))
    (up / "history.jsonl").write_text(json.dumps({"correlation_id": "upg-7f3a9c2e", "action": "apply", "version_from": "5.48.0",
                                                  "version_to": TARGET, "result": "completed", "backup": "/root/only/b.db"}) + "\n" + "not json\n")
    st = armed.status()
    run = st["upgrade_run"]
    assert run["correlation_id"] == "upg-7f3a9c2e"
    view = st["upgrade"]
    assert view["rollback"]["available"] is True and view["rollback"]["to"] == "5.48.0"
    assert view["history"][0]["backup"] == "b.db"                # a file name, never a path
    dumped = json.dumps(view)
    assert "/root/only" not in dumped and "env_file" not in dumped
    rows = requests.get(armed.base_url + "/api/upgrade/status?correlation_id=upg-7f3a9c2e", headers=_who(ADMIN, admin=True), timeout=10).json()
    assert rows["upgrade"]["rejection"] is None
    (up / "rejections").mkdir()
    (up / "rejections" / "upg-7f3a9c2e.json").write_text(json.dumps({"code": "version_failed_before", "message": "failed before", "at": done}))
    rows = requests.get(armed.base_url + "/api/upgrade/status?correlation_id=upg-7f3a9c2e", headers=_who(ADMIN, admin=True), timeout=10).json()
    assert rows["upgrade"]["rejection"]["code"] == "version_failed_before"
    # a hostile correlation id never reaches the filesystem
    rows = requests.get(armed.base_url + "/api/upgrade/status?correlation_id=../../etc/passwd", headers=_who(ADMIN, admin=True), timeout=10).json()
    assert rows["upgrade"]["rejection"] is None


def test_every_new_route_is_closed_to_non_admins_and_second_gate_sites(armed):
    nonadmin = _who("00uUSER")
    for method, path in (("POST", "/api/upgrade/request"), ("POST", "/api/upgrade/preview"), ("GET", "/api/upgrade/status")):
        r = requests.request(method, armed.base_url + path, json={"kind": "cancel"}, headers=nonadmin, timeout=10)
        assert r.status_code == 403, (path, r.status_code)
    from server import nginx_second_site
    assert "/api/upgrade" in nginx_second_site.SECOND_SITE_DENIED_PREFIXES   # a prefix: covers request, preview, notice, status
    # local mode: no updater layout -> a clear refusal, nothing written
    armed.serve.DEPLOYMENT_MODE = "local"
    r = requests.post(armed.base_url + "/api/upgrade/request", json=armed.apply_body(), timeout=10)
    assert r.status_code in (409,) and r.json()["reason"] in ("preview_missing", "updater_not_installed", "target_changed")


# --- end to end: the request the app writes, run by the real root state machine on the fake machine --------------------
def run_updater(a):
    a.m.put_artifacts(TARGET)
    a.m.host.clock = time.time()
    a.m.host.schema_on_start[TARGET] = 11
    uf.act.run(a.m.cfg(), a.m.host)


def test_end_to_end_success_shows_in_status_notice_and_history(armed):
    take_preview(armed)
    armed.request(armed.apply_body())
    run_updater(armed)
    assert armed.requests_written() == []                     # consumed by the updater
    st = armed.status()
    run = st["upgrade"]["run"]
    assert run["result"] == "completed" and run["version_to"] == TARGET and run["steps_done"]
    assert st["upgrade"]["history"][0]["result"] == "completed" and st["upgrade"]["history"][0]["version_to"] == TARGET
    assert st["upgrade"]["rollback"]["available"] is True and st["upgrade"]["rollback"]["to"] == "5.46.0"
    assert run["backup"]["name"] and "/" not in run["backup"]["name"]
    # the audit log holds the human's request and the updater's own rows, tied by one correlation id
    cid = json.loads(json.dumps(run))["correlation_id"]
    rows = [e["action"] for e in armed.audit() + armed.m.audit_actions() if e["details"].get("correlation_id") == cid]
    assert "upgrade.requested" in rows and "upgrade.started" in rows and "upgrade.completed" in rows


def test_end_to_end_a_failed_upgrade_is_rolled_back_and_offers_its_bundle(armed):
    take_preview(armed)
    armed.m.host.unhealthy_versions.add(TARGET)
    armed.request(armed.apply_body())
    run_updater(armed)
    st = armed.status()
    run = st["upgrade"]["run"]
    assert run["result"] == "rolled_back" and run["reason_code"] == "health_healthz" and run["rolled_back_to"] == "5.46.0"
    assert run["bundle"]["name"].startswith("ocw-support-") and st["upgrade"]["failures"][TARGET]["count"] == 1
    assert st["upgrade"]["rollback"] is None
    notice = requests.get(armed.base_url + "/api/upgrade/notice", headers=_who("00uUSER"), timeout=10).json()
    assert notice["kind"] == "failed" and notice["result"] == "rolled_back"
    # the same version is refused until an operator clears the failure, before any MFA
    r = armed.post(armed.apply_body())
    assert r.status_code == 409 and r.json()["reason"] == "version_failed_before"
    # the bundle downloads through the existing admin-only route, and the download is audited
    bundle = requests.get(armed.base_url + "/api/upgrade/bundle?name=" + run["bundle"]["name"], headers=_who(ADMIN, admin=True), timeout=10)
    assert bundle.status_code == 200 and bundle.headers["Content-Type"] == "application/gzip"
    assert any(e["action"] == "upgrade.bundle_downloaded" for e in armed.audit())
    assert requests.get(armed.base_url + "/api/upgrade/bundle?name=" + run["bundle"]["name"], headers=_who("00uUSER"), timeout=10).status_code == 403


def test_end_to_end_a_refusal_by_the_updater_is_visible_to_the_page(armed):
    take_preview(armed)
    armed.request(armed.apply_body())
    # the release disappears from the machine: the updater refuses the request and says why
    armed.m.host.clock = time.time()
    path = armed.requests_written()[0]
    cid = json.loads(path.read_text())["correlation_id"]
    uf.act.run(armed.m.cfg(), armed.m.host)       # no artifacts were put in place: staging fails
    r = requests.get(armed.base_url + "/api/upgrade/status?correlation_id=" + cid, headers=_who(ADMIN, admin=True), timeout=10).json()
    run = r["upgrade_run"]
    assert run["result"] == "failed" and run["correlation_id"] == cid and run["reason_code"]


def test_server_zone_and_local_time_conversion():
    assert upgrade.convert_local("2026-10-21T03:30", "Europe/London") == "2026-10-21T02:30:00Z"
    assert upgrade.convert_local("2026-10-20T22:30", "America/New_York") == "2026-10-21T02:30:00Z"
    assert upgrade.convert_local("2026-10-21T02:30", "UTC") == "2026-10-21T02:30:00Z"
    for bad in (("2026-10-21 02:30", "UTC"), ("2026-10-21T02:30", "No/Zone"), ("2026-10-21T02:30", "a b"), (None, "UTC")):
        with pytest.raises(Exception):
            upgrade.convert_local(*bad)
    assert upgrade.server_zone() is None or isinstance(upgrade.server_zone(), str)


# --- rollback, restore, clear failure, bundle and backups, from the page (through the real updater) -----------------------
def _applied(a):
    take_preview(a)
    a.request(a.apply_body())
    run_updater(a)
    assert a.status()["upgrade"]["run"]["result"] == "completed"


def _op(a, body, status=200, who=ADMIN):
    return a.request(body, who=who, status=status)


def test_rollback_from_the_page_is_typed_step_up_and_runs_in_the_updater(armed):
    _applied(armed)
    assert armed.post({"kind": "rollback"}).status_code == 400                                   # not typed
    assert armed.post({"kind": "rollback", "confirm": "rollback"}).json()["reason"] == "confirm_required"
    assert armed.post({"kind": "rollback", "confirm": "ROLLBACK", "version": "1.0.0"}).status_code == 400
    done = _op(armed, {"kind": "rollback", "confirm": "ROLLBACK"})
    assert done.json()["kind"] == "rollback" and done.json()["step_up_verified"] is True
    armed.m.host.clock = time.time()
    uf.act.run(armed.m.cfg(), armed.m.host)
    run = armed.status()["upgrade"]["run"]
    assert run["action"] == "rollback" and run["result"] == "rolled_back" and run["rolled_back_to"] == "5.46.0"
    ev = [e for e in armed.audit() if e["action"] == "upgrade.requested" and e["details"].get("kind") == "rollback"]
    assert len(ev) == 1 and ev[0]["details"]["step_up_verified"] is True
    # nothing left to roll back to / the window is over
    assert armed.post({"kind": "rollback", "confirm": "ROLLBACK"}).json()["reason"] == "rollback_unavailable"


def test_rollback_is_offered_only_inside_the_window(armed):
    _applied(armed)
    st = json.loads((armed.m.data / "upgrade" / "state.json").read_text())
    st["updated_at"] = iso(datetime.now(timezone.utc) - timedelta(hours=30))
    (armed.m.data / "upgrade" / "state.json").write_text(json.dumps(st))
    r = armed.post({"kind": "rollback", "confirm": "ROLLBACK"})
    assert r.status_code == 409 and r.json()["reason"] == "rollback_unavailable"
    assert armed.requests_written() == []


def test_restore_from_the_page(armed):
    _applied(armed)
    name = armed.status()["upgrade"]["run"]["backup"]["name"]
    assert armed.post({"kind": "restore", "confirm": "RESTORE ", "backup": name}).json()["reason"] == "confirm_required"
    assert armed.post({"kind": "restore", "confirm": "RESTORE"}).json()["reason"] == "backup_required"                # must name the copy
    assert armed.post({"kind": "restore", "confirm": "RESTORE", "backup": "audit_store-pre-9.9.9-1.db"}).json()["reason"] == "target_changed"
    _op(armed, {"kind": "restore", "confirm": "RESTORE", "backup": name})
    armed.m.host.clock = time.time()
    uf.act.run(armed.m.cfg(), armed.m.host)
    run = armed.status()["upgrade"]["run"]
    assert run["action"] == "restore" and run["result"] == "completed"
    assert any(e["action"] == "upgrade.restored" for e in armed.m.audit_actions())


def test_restore_without_a_backup_is_refused_before_mfa(armed):
    r = armed.post({"kind": "restore", "confirm": "RESTORE", "backup": "audit_store-pre-5.47.0-20260101T000000Z.db"})
    assert r.status_code == 409 and r.json()["reason"] in ("no_backup", "updater_not_installed")


def test_clear_failure_and_bundle_rebuild_from_the_page(armed):
    take_preview(armed)
    armed.m.host.unhealthy_versions.add(TARGET)
    armed.request(armed.apply_body())
    run_updater(armed)
    view = armed.status()["upgrade"]
    assert view["run"]["result"] == "rolled_back" and view["failures"][TARGET]["count"] == 1
    assert view["run"]["bundle"]["name"]
    first = view["run"]["bundle"]["name"]
    st = json.loads((armed.m.data / "upgrade" / "state.json").read_text())
    st["bundle"]["at"] = iso(datetime.now(timezone.utc) - timedelta(hours=1))         # (a repeat within five minutes is refused by the updater)
    (armed.m.data / "upgrade" / "state.json").write_text(json.dumps(st))
    _op(armed, {"kind": "bundle", "include_hosts": True})
    armed.m.host.clock = time.time()
    uf.act.run(armed.m.cfg(), armed.m.host)
    run = armed.status()["upgrade"]["run"]
    assert run["bundle"]["name"] != first
    assert armed.post({"kind": "bundle", "include_hosts": "yes"}).status_code == 400
    assert armed.post({"kind": "bundle", "for_correlation_id": "upg-0000dead"}).json()["reason"] == "target_changed"
    _op(armed, {"kind": "clear_failure"})
    uf.act.run(armed.m.cfg(), armed.m.host)
    assert armed.status()["upgrade"]["failures"] == {}
    assert armed.post({"kind": "clear_failure"}).json()["reason"] == "nothing_to_clear"


def test_backups_table_and_deleting_is_a_command_line_action(armed):
    _applied(armed)
    d = armed.m.data / "upgrade" / "backups"
    old = d / "audit_store-pre-5.40.0-20250101T000000Z.db"
    old.write_bytes(b"x" * 10)
    os.utime(old, (1, 1))
    armed.m.updater().publish_backups()
    rows = armed.status()["upgrade"]["backups"]["backups"]
    assert len(rows) == 2 and all("/" not in r["name"] for r in rows)
    for body in ({"kind": "prune_backups", "confirm": "PRUNE", "keep_last": 1}, {"kind": "prune_backups"},
                 {"kind": "prune_backups", "confirm": "PRUNE", "names": [old.name]}):
        r = armed.post(body)
        assert r.status_code == 409 and r.json()["reason"] == "cli_only" and "ocw-updater prune-backups" in r.json()["error"]
    assert armed.requests_written() == [] and old.exists()


def test_clear_failure_from_the_page_is_refused_while_the_run_needs_an_operator(armed):
    _applied(armed)
    st = json.loads((armed.m.data / "upgrade" / "state.json").read_text())
    st["result"] = "failed_needs_operator"
    (armed.m.data / "upgrade" / "state.json").write_text(json.dumps(st))
    r = armed.post({"kind": "clear_failure"})
    assert r.status_code == 409 and r.json()["reason"] == "needs_operator" and "clear-failure" in r.json()["error"]
    assert armed.requests_written() == []


def test_an_old_activator_gets_a_reason_instead_of_a_request_it_would_refuse(armed, monkeypatch):
    _applied(armed)
    monkeypatch.setattr(upgrade, "updater_activator_version", lambda: "5.47.0")
    for body in ({"kind": "rollback", "confirm": "ROLLBACK"}, {"kind": "clear_failure"}, {"kind": "bundle"}):
        r = armed.post(body)
        assert r.status_code == 409 and r.json()["reason"] == "activator_too_old" and r.json()["activator"] == "5.47.0"
    assert armed.requests_written() == []


def test_a_missing_backups_list_means_unknown_not_none_for_the_restore_pre_check(armed):
    _applied(armed)
    name = armed.status()["upgrade"]["run"]["backup"]["name"]
    f = armed.m.data / "upgrade" / "backups-status.json"
    if f.exists():
        f.unlink()
    r = armed.post({"kind": "restore", "confirm": "RESTORE", "backup": name})
    assert r.status_code == 202                        # accepted for the MFA approval: not refused as "no backup"


def test_operations_need_an_admin_and_the_updater(armed):
    for body in ({"kind": "rollback", "confirm": "ROLLBACK"}, {"kind": "clear_failure"}, {"kind": "restore", "confirm": "RESTORE", "backup": "audit_store-pre-5.47.0-20260101T000000Z.db"}):
        assert requests.post(armed.base_url + "/api/upgrade/request", json=body, headers=_who("00uUSER"), timeout=10).status_code == 403
    os.rmdir(armed.m.data / "upgrade" / "inbox" / "requests")
    assert armed.post({"kind": "clear_failure"}).json()["reason"] == "updater_not_installed"
