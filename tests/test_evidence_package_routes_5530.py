"""Evidence package routes and jobs (5.53.0, WP4): prepare, status, download, the permission, the step-up round trip,
one build at a time, the 15-minute window, clean-up, the build log. Real HTTP server, real worker thread, real builder and
the real verifier as a subprocess. Synthetic data only. The matrix entries are in test_http_authz_matrix.py."""
import hashlib
import json
import os
import socket
import threading
import time
import zipfile
from pathlib import Path

import pytest
import requests

import audit_store
import create_secret_folders as engine
from evidence_fixtures import build_archive, day, run_verifier, seed_fixed_archive

SECRET = "test-proxy-secret"
COOKIE = "opa_wizard_session"
OWNER_A = "00uOWNERA"
OWNER_B = "00uOWNERB"
ISSUER_1 = "https://one.example.okta.com"
ISSUER_2 = "https://two.example.okta.com"
PERIOD = {"start": "2020-03-01", "end": "2020-03-05"}


class _Probe:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        def call(*a, **k):
            raise engine.OpaApiError(599, f"probe://{name}", "upstream reached")
        return call


@pytest.fixture
def ev(tmp_audit_store, tmp_environments_file, fake_keyring, tmp_audit_log, tmp_path, monkeypatch):
    import server.serve as serve

    audit_store.run_migrations()
    monkeypatch.setattr(serve, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", SECRET)
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "local")
    monkeypatch.setattr(serve, "INTERNAL_API_SHARED_SECRET", None)
    monkeypatch.setattr(engine, "OpaClient", _Probe)
    monkeypatch.setattr(engine, "OktaClient", _Probe)
    monkeypatch.setattr(serve._evidence, "_dir_fn", lambda: str(tmp_path / "packages"))
    serve._evidence.reset()
    with serve._sessions_lock:
        serve._seen_owners.clear()
        serve._recorded_identities.clear()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server_instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    threading.Thread(target=server_instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(base + "/api/version", timeout=0.5)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s",
                "okta_url": "https://a.example.com", "okta_api_token": "tok"}, owner=OWNER_A)
    seed_fixed_archive(env_id)
    # "ldev" belongs to the local operator (no sign-in), "dev" to OWNER_A (hosted tests)
    _, local_id = engine.upsert_environment(
        "ldev", {"base_domain": "l.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=None)
    seed_fixed_archive(local_id)
    with serve._sessions_lock:
        serve._seen_owners.update({OWNER_A, OWNER_B})
    yield base, serve, env_id, tmp_path
    serve._evidence.reset()
    server_instance.shutdown()
    server_instance.server_close()
    with serve._sessions_lock:
        serve._seen_owners.clear()
        serve._recorded_identities.clear()


def who(sub, session=None, issuer=None, admin=False):
    h = {"X-Nginx-Proxy-Secret": SECRET, "X-Auth-Sub": sub, "X-Auth-Is-Admin": "true" if admin else "false",
         "X-Auth-User": f"{sub.lower()}@example.com", "Cookie": f"{COOKIE}={session or 'session-of-' + sub}"}
    if issuer:
        h["X-Auth-Issuer"] = issuer
        h["X-Nginx-Issuer-Forwarded"] = SECRET
    return h


def prepare(base, body=None, headers=None, env=None):
    env = env or ("dev" if headers else "ldev")      # a signed-in caller uses OWNER_A's "dev", the local operator its own "ldev"
    return requests.post(f"{base}/api/evidence_packages/prepare?environment={env}", json={**PERIOD, **(body or {})}, headers=headers or {}, timeout=15)


def save(base, action_id, headers):
    return requests.post(base + "/api/environment_changes/save", json={}, headers={**headers, "X-Auth-Action-Id": action_id, "X-Nginx-Stepup-Location": SECRET}, timeout=15)


def wait_done(base, job_id, headers=None, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        r = requests.get(f"{base}/api/evidence_packages/{job_id}", headers=headers or {}, timeout=10)
        assert r.status_code == 200, r.text
        if r.json()["status"] != "running":
            return r.json()
        time.sleep(0.05)
    raise AssertionError("the build did not finish")


def audit(path):
    p = Path(path)
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def hosted(serve, monkeypatch):
    monkeypatch.setattr(serve, "DEPLOYMENT_MODE", "hosted")


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------
def test_local_mode_builds_at_once_logs_it_and_the_package_passes_the_verifier(ev, tmp_audit_log, tmp_path):
    base, serve, env_id, root = ev
    resp = prepare(base)
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]
    status = wait_done(base, job_id)
    assert status["status"] == "done" and status["progress"] == 1.0 and status["seconds_left"] > 800
    result = status["result"]
    dl = requests.get(f"{base}/api/evidence_packages/{job_id}/download", timeout=15)
    assert dl.status_code == 200 and dl.headers["Content-Type"] == "application/zip"
    assert dl.headers["Cache-Control"] == "no-store" and int(dl.headers["Content-Length"]) == len(dl.content) == result["bytes"]
    assert hashlib.sha256(dl.content).hexdigest() == result["sha256"]
    disposition = dl.headers["Content-Disposition"]
    assert disposition.startswith('attachment; filename="evidence-package-ldev-2020-03-01-to-2020-03-05-') and disposition.endswith('.zip"')
    assert all(c.isalnum() or c in '._-"; =' for c in disposition)
    again = requests.get(f"{base}/api/evidence_packages/{job_id}/download", timeout=15)       # repeatable inside the window
    assert again.status_code == 200 and again.content == dl.content
    out = tmp_path / "out"
    out.mkdir()
    (out / "p.zip").write_bytes(dl.content)
    code, text = run_verifier(out / "p.zip", out)
    assert code == 0 and "RESULT: PASS" in text and result["sha256"] in text and result["chain_head"] in text
    with zipfile.ZipFile(out / "p.zip") as zf:
        assert zf.read("events.ndjson").count(b"\n") == result["events"] == 3
    # tamper one byte -> FAIL
    bad = bytearray(dl.content)
    with zipfile.ZipFile(out / "p.zip") as zf:
        info = zf.getinfo("events.ndjson")
        data = bytearray(zf.read("events.ndjson"))
    data[10] ^= 1
    with zipfile.ZipFile(out / "bad.zip", "w", zipfile.ZIP_DEFLATED) as zf, zipfile.ZipFile(out / "p.zip") as src:
        for i in src.infolist():
            zf.writestr(i.filename, bytes(data) if i.filename == "events.ndjson" else src.read(i.filename))
    code, text = run_verifier(out / "bad.zip", out)
    assert code == 1 and "RESULT: FAIL" in text
    del bad, info
    # the build log
    entries = audit(tmp_audit_log)
    started = next(e for e in entries if e["action"] == "evidence_package.build")
    assert started["details"]["mfa"] == "local mode, no MFA" and started["details"]["outcome"] == "started"
    assert started["details"]["period"] == PERIOD and started["details"]["gaps_acknowledged"] is False
    finished = next(e for e in entries if e["action"] == "evidence_package.build_finished")
    for key in ("sha256", "chain_head", "bytes", "events", "report_rows", "seconds", "environment", "period", "gaps_acknowledged", "outcome"):
        assert key in finished["details"], key
    assert finished["details"]["sha256"] == result["sha256"] and finished["details"]["outcome"] == "finished"
    assert len([e for e in entries if e["action"] == "evidence_package.downloaded"]) == 2        # every fetch is logged
    blob = json.dumps(entries)
    assert "fx-1" not in blob and "user@example.com" not in blob                                  # never row content


def test_hosted_without_step_up_is_202_and_starts_nothing_until_the_approved_save(ev, monkeypatch, tmp_audit_log):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    me = who(OWNER_A)
    resp = prepare(base, headers=me)
    assert resp.status_code == 202 and resp.json()["step_up_required"] is True and resp.json()["action"] == "evidence_package.build"
    assert not serve._evidence.running() and not (root / "packages").exists()
    assert not [e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build"]
    done = save(base, resp.json()["action_id"], me)
    assert done.status_code == 202 and done.json()["step_up_verified"] is True and done.json()["action"] == "evidence_package.build"
    job_id = done.json()["job_id"]
    status = wait_done(base, job_id, me)
    assert status["status"] == "done"
    started = next(e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build")
    assert started["details"]["step_up_verified"] is True and started["details"]["mode"] == "hosted, MFA step-up"
    assert "mfa" not in started["details"]
    replay = save(base, resp.json()["action_id"], me)
    assert replay.status_code == 409                                                               # single use


def test_a_build_approval_never_unlocks_settings_and_an_unlock_never_builds(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    me = who(OWNER_A)
    aid = prepare(base, headers=me).json()["action_id"]
    assert save(base, aid, me).status_code == 202
    assert audit_store.list_settings_unlocks() == []                                               # created nothing
    # with a window already open, the build approval leaves its expiry alone
    fingerprint = serve._session_fingerprint({"Cookie": f"{COOKIE}=session-of-{OWNER_A}"})
    audit_store.upsert_settings_unlock(OWNER_A, "", fingerprint, "x", 120)
    before = audit_store.list_settings_unlocks()
    serve._evidence.reset()
    aid = prepare(base, headers=me).json()["action_id"]
    assert save(base, aid, me).status_code == 202
    assert audit_store.list_settings_unlocks() == before
    # Settings unlock approval used at the build: refused, no job
    serve._evidence.reset()
    folders_before = set(os.listdir(root / "packages"))
    unlock = requests.post(base + "/api/settings/unlock", json={}, headers=me, timeout=10).json()["action_id"]
    forged = audit_store.create_pending_admin_action(
        OWNER_A, "settings.unlock", {"action": "evidence_package.build", "params": {"name": "dev", "body": PERIOD}}, 900)
    for aid in (unlock, forged):
        r = save(base, aid, me)
        assert r.status_code in (200, 403) and "job_id" not in r.json()
        assert not serve._evidence.running() and set(os.listdir(root / "packages")) == folders_before
    # a build is not behind the Settings unlock: with Settings locked, a build still starts
    audit_store.clear_settings_unlocks()
    aid = prepare(base, headers=me).json()["action_id"]
    assert save(base, aid, me).status_code == 202 and audit_store.list_settings_unlocks() == []


def test_check_only_returns_the_coverage_summary_and_starts_nothing(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    me = who(OWNER_A)
    r = requests.post(base + "/api/evidence_packages/prepare?environment=dev", json={**PERIOD, "check_only": True}, headers=me, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_coverage"] is True and body["days"] == 5 and body["needs_acknowledgement"] is False
    assert body["counts"]["covered_with_events"] == 3 and body["counts"]["covered_zero_events"] == 2
    assert [c["control_id"] for c in body["controls"]][:2] == ["CC6.1", "CC6.2"] and all(c["mapping_status"] == "proposed" for c in body["controls"])
    assert not serve._evidence.running() and audit_store.count_open_pending_admin_actions(OWNER_A, serve.ENV_CHANGE_ACTION_TYPES) == 0


def test_bad_period_and_unknown_environment(ev):
    base, serve, env_id, root = ev
    assert prepare(base, {"start": "2020-13-01"}).status_code == 400
    assert prepare(base, {"start": "2020-03-06", "end": "2020-03-05"}).status_code == 400
    assert prepare(base, {"end": "2999-01-01"}).status_code == 400
    assert prepare(base, env="nope").status_code == 404
    assert requests.post(base + "/api/evidence_packages/prepare", json=PERIOD, timeout=10).status_code == 400
    wrong = prepare(base, {"environment_id": "00000000-0000-4000-8000-000000000000"})
    assert wrong.status_code == 409 and wrong.json()["reason"] == "target_changed"


# ---------------------------------------------------------------------------
# Permission, binding, window
# ---------------------------------------------------------------------------
def share_dev(env_id, allow_build=False):
    engine.set_environment_shared("dev", OWNER_A, True)
    if allow_build:
        engine.set_shared_permissions({"build_evidence_package": "allow"}, environment_id=env_id)


def test_a_viewer_without_the_capability_is_refused_the_owner_and_an_allowed_viewer_are_not(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    share_dev(env_id)
    b = who(OWNER_B)
    refused = prepare(base, headers=b)
    assert refused.status_code == 403 and refused.json()["capability"] == "build_evidence_package"
    assert requests.post(base + "/api/evidence_packages/prepare?environment=dev", json={**PERIOD, "check_only": True}, headers=b, timeout=10).status_code == 403
    engine.set_shared_permissions({"build_evidence_package": "allow"}, environment_id=env_id)
    assert prepare(base, headers=b).status_code == 202
    engine.set_shared_permissions({"view_archive": "deny"}, environment_id=env_id)               # needs BOTH capabilities
    assert prepare(base, headers=b).status_code == 403
    assert prepare(base, headers=who(OWNER_A)).status_code == 202                                    # the owner always passes


def test_another_users_job_id_is_a_404_even_in_the_same_session_cookie_or_for_another_issuer(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    share_dev(env_id, allow_build=True)
    a = who(OWNER_B, issuer=ISSUER_1)
    aid = prepare(base, headers=a).json()["action_id"]
    job_id = save(base, aid, a).json()["job_id"]
    wait_done(base, job_id, a)
    assert requests.get(f"{base}/api/evidence_packages/{job_id}", headers=a, timeout=10).status_code == 200
    for headers in (
        who(OWNER_A),                                                         # the owner of the environment is not the builder
        who(OWNER_B, issuer=ISSUER_2),                                        # same sub, another login gate (second site)
        who(OWNER_B, session="another-login-session", issuer=ISSUER_1),       # same person, another sign-in
        who(OWNER_B),                                                         # same sub, no verified issuer
        {"X-Nginx-Proxy-Secret": SECRET, "X-Auth-Sub": OWNER_B, "X-Auth-Is-Admin": "false"},   # no session cookie at all
    ):
        for suffix in ("", "/download"):
            r = requests.get(f"{base}/api/evidence_packages/{job_id}{suffix}", headers=headers, timeout=10)
            assert r.status_code == 404 and "sha256" not in r.text, (suffix, r.status_code)
    assert requests.get(f"{base}/api/evidence_packages/{job_id}/download", headers=a, timeout=10).status_code == 200
    for bad in ("x", "../../etc/passwd", "a" * 100, "%2e%2e"):
        assert requests.get(f"{base}/api/evidence_packages/{bad}", headers=a, timeout=10).status_code in (400, 404)


def test_permission_is_checked_again_on_status_and_download(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    share_dev(env_id, allow_build=True)
    b = who(OWNER_B)
    job_id = save(base, prepare(base, headers=b).json()["action_id"], b).json()["job_id"]
    wait_done(base, job_id, b)
    engine.set_shared_permissions({"build_evidence_package": "deny"}, environment_id=env_id)
    for suffix in ("", "/download"):
        r = requests.get(f"{base}/api/evidence_packages/{job_id}{suffix}", headers=b, timeout=10)
        assert r.status_code == 403 and r.json()["reason"] == "shared_permission_denied"
    engine.set_shared_permissions({"build_evidence_package": "allow"}, environment_id=env_id)
    assert requests.get(f"{base}/api/evidence_packages/{job_id}/download", headers=b, timeout=10).status_code == 200
    engine.set_environment_shared("dev", OWNER_A, False)                                              # unshared: the environment is not theirs
    assert requests.get(f"{base}/api/evidence_packages/{job_id}", headers=b, timeout=10).status_code in (403, 404)


def test_the_worker_checks_the_permission_again_when_the_job_starts(ev, monkeypatch, tmp_audit_log):
    base, serve, env_id, root = ev
    share_dev(env_id)                                                                                  # B has no build capability
    ctx = {"environment_id": env_id, "environment_name": "dev", "period": PERIOD, "gaps_acknowledged": False, "mode": "hosted",
           "engine_owner": OWNER_B, "actor_email": "b@example.com", "actor_sub": OWNER_B, "issuer": None, "client_ip": "192.0.2.9",
           "user_agent": "t", "correlation_id": "c", "builder": "b"}
    job_id = serve._evidence.start({"environment_id": env_id, "environment_name": "dev", "period": PERIOD, "gaps_acknowledged": False,
                                    "owner": OWNER_B, "issuer": "", "fingerprint": "f"})
    ctx["job_id"] = job_id
    serve._run_evidence_build(job_id, ctx)
    job = serve._evidence.get(job_id, OWNER_B, "", "f")
    assert job["status"] == "error" and job["reason"] == "permission_withdrawn" and not (root / "packages" / job_id).exists()
    failed = [e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build_failed"][-1]
    assert failed["details"]["outcome"] == "refused" and failed["details"]["reason"] == "permission_withdrawn"


def test_an_expired_download_is_410_and_the_file_is_deleted(ev, monkeypatch):
    base, serve, env_id, root = ev
    monkeypatch.setattr(serve._evidence, "window_seconds", 1)
    job_id = prepare(base).json()["job_id"]
    status = wait_done(base, job_id)
    assert status["window_seconds"] == 1
    folder = root / "packages" / job_id
    assert folder.is_dir() and (folder / "evidence-package.zip").is_file()
    assert oct(folder.stat().st_mode & 0o777) == "0o700" and oct((folder / "evidence-package.zip").stat().st_mode & 0o777) == "0o600"
    assert requests.get(f"{base}/api/evidence_packages/{job_id}/download", timeout=10).status_code == 200
    time.sleep(1.4)
    gone = requests.get(f"{base}/api/evidence_packages/{job_id}/download", timeout=10)
    assert gone.status_code == 410 and gone.json()["reason"] == "expired"
    assert not folder.exists()
    assert requests.get(f"{base}/api/evidence_packages/{job_id}", timeout=10).json()["status"] == "expired"


def test_the_timer_deletes_a_package_when_its_window_ends_even_if_nobody_asks(ev, monkeypatch):
    base, serve, env_id, root = ev
    monkeypatch.setattr(serve._evidence, "window_seconds", 1)
    job_id = prepare(base).json()["job_id"]
    wait_done(base, job_id)
    folder = root / "packages" / job_id
    assert folder.exists()
    end = time.time() + 6
    while folder.exists() and time.time() < end:
        time.sleep(0.1)
    assert not folder.exists()


def test_start_up_removes_every_package_left_from_an_earlier_run(ev):
    base, serve, env_id, root = ev
    left = root / "packages" / "old-job"
    left.mkdir(parents=True)
    (left / "evidence-package.zip").write_bytes(b"x")
    (root / "packages" / "stray.zip").write_bytes(b"y")
    assert serve._evidence.cleanup_startup() == 2
    assert list((root / "packages").iterdir()) == []


# ---------------------------------------------------------------------------
# Refusals and limits
# ---------------------------------------------------------------------------
def test_unacknowledged_gaps_are_refused_acknowledged_ones_build(ev, tmp_audit_log):
    base, serve, env_id, root = ev
    _, other = engine.upsert_environment("gappy", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=None)
    build_archive(other, with_gap=True)
    period = {"start": day(-11, 0).date().isoformat(), "end": day(-1, 0).date().isoformat()}
    r = requests.post(base + "/api/evidence_packages/prepare?environment=gappy", json=period, timeout=15)
    assert r.status_code == 409 and r.json()["reason"] == "gaps_unacknowledged"
    cov = r.json()["coverage"]
    assert cov["gap_days_total"] == 2 and cov["gap_ranges"] == [[day(-8, 0).date().isoformat(), day(-7, 0).date().isoformat()]]
    assert not serve._evidence.running()
    ok = requests.post(base + "/api/evidence_packages/prepare?environment=gappy", json={**period, "gaps_acknowledged": True}, timeout=15)
    assert ok.status_code == 202
    status = wait_done(base, ok.json()["job_id"])
    assert status["status"] == "done" and status["gaps_acknowledged"] is True and status["result"]["gap_days"] == 2
    started = [e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build"][-1]
    assert started["details"]["gaps_acknowledged"] is True


def test_a_period_with_no_coverage_is_refused(ev):
    base, serve, env_id, root = ev
    r = prepare(base, {"start": "2019-01-01", "end": "2019-01-31"})
    assert r.status_code == 409 and r.json()["reason"] == "no_coverage"
    assert not serve._evidence.running()


def test_one_build_at_a_time_server_wide(ev, monkeypatch):
    base, serve, env_id, root = ev
    gate = threading.Event()
    real = serve._run_evidence_build

    def slow(job_id, ctx):
        gate.wait(10)
        real(job_id, ctx)
    monkeypatch.setattr(serve, "_run_evidence_build", slow)
    _, other = engine.upsert_environment("second", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=None)
    seed_fixed_archive(other)
    first = prepare(base)
    assert first.status_code == 202
    same = prepare(base)
    assert same.status_code == 409 and same.json()["reason"] == "build_running_environment"
    elsewhere = prepare(base, env="second")
    assert elsewhere.status_code == 409 and elsewhere.json()["reason"] == "build_running_server"
    running = requests.get(f"{base}/api/evidence_packages/{first.json()['job_id']}", timeout=10).json()
    assert running["status"] == "running" and running["seconds_left"] is None
    assert requests.get(f"{base}/api/evidence_packages/{first.json()['job_id']}/download", timeout=10).status_code == 409
    gate.set()
    assert wait_done(base, first.json()["job_id"])["status"] == "done"
    assert prepare(base, env="second").status_code == 202


def test_the_upgrade_preflight_refuses_while_a_build_runs(ev, monkeypatch):
    base, serve, env_id, root = ev
    from server.updater import upgrade as upgrade_service
    gate = threading.Event()
    real = serve._run_evidence_build
    monkeypatch.setattr(serve, "_run_evidence_build", lambda j, c: (gate.wait(10), real(j, c)))
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)

    def item():
        return next(i for i in upgrade_service.preflight({}, 1000, serve._upgrade_context(), now) if i["id"] == "evidence_build")
    assert item()["ok"] is True
    job_id = prepare(base).json()["job_id"]
    assert serve._upgrade_context()["evidence_build_running"] is True
    refused = item()
    assert refused["ok"] is False and "evidence package" in refused["text"]
    gate.set()
    wait_done(base, job_id)
    assert item()["ok"] is True


def test_a_failed_build_says_why_leaves_no_file_and_logs_the_failure(ev, monkeypatch, tmp_audit_log):
    base, serve, env_id, root = ev
    monkeypatch.setenv("OPA_EVIDENCE_MAX_BYTES", "2000")
    job_id = prepare(base).json()["job_id"]
    status = wait_done(base, job_id)
    assert status["status"] == "error" and status["reason"] == "size_limit" and "limit" in status["error"]
    assert not (root / "packages" / job_id).exists()
    failed = next(e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build_failed")
    assert failed["details"]["outcome"] == "failed" and failed["details"]["reason"] == "size_limit"
    assert requests.get(f"{base}/api/evidence_packages/{job_id}/download", timeout=10).status_code == 409


def test_an_unexpected_error_shows_no_detail(ev, monkeypatch):
    base, serve, env_id, root = ev
    import evidence_package

    def boom(*a, **k):
        raise RuntimeError("secret detail /var/lib/x")
    monkeypatch.setattr(evidence_package, "build_package", boom)
    status = wait_done(base, prepare(base).json()["job_id"])
    assert status["status"] == "error" and status["reason"] == "internal" and "secret detail" not in json.dumps(status)


def test_status_shows_no_owner_path_or_session(ev):
    base, serve, env_id, root = ev
    job_id = prepare(base).json()["job_id"]
    text = json.dumps(wait_done(base, job_id))
    for needle in (str(root), "fingerprint", "owner", "issuer", "evidence-package.zip"):
        assert needle not in text, needle


# ---------------------------------------------------------------------------
# Support bundle and the form
# ---------------------------------------------------------------------------
def test_the_support_bundle_builder_never_reads_the_packages_folder(ev):
    """The root-run bundle is built only from the texts it is handed (summary, journal lines, nginx test, the upgrade's own audit
    entries); it walks no data directory, so $DATA_DIR/packages cannot get in. This pins both facts."""
    import ast
    root = Path(__file__).resolve().parent.parent / "server" / "updater" / "root"
    bundle_src = (root / "ocw_bundle.py").read_text(encoding="utf-8")
    activate_tree = ast.parse((root / "ocw_activate.py").read_text(encoding="utf-8"))
    make_bundle = next(n for n in ast.walk(activate_tree) if isinstance(n, ast.FunctionDef) and n.name == "make_bundle")
    body = ast.get_source_segment((root / "ocw_activate.py").read_text(encoding="utf-8"), make_bundle)
    assert "packages" not in body and "os.walk" not in body and "listdir" not in body and "data_dir" not in body
    assert "packages" not in bundle_src and "os.walk" not in bundle_src and "listdir" not in bundle_src and "glob" not in bundle_src
    # behavioural: a bundle built while a packages folder exists holds only the files it was given
    import sys
    sys.path.insert(0, str(root))
    try:
        import ocw_bundle
        pk = Path(ev[3]) / "packages" / "job1"
        pk.mkdir(parents=True)
        (pk / "evidence-package.zip").write_bytes(b"PKZIP-synthetic")
        out = Path(ev[3]) / "bundles"
        out.mkdir()
        built = ocw_bundle.build(str(out), "ocw-support-test", {"k": "v"}, {"journal-app.txt": "line"}, [], ocw_bundle.Redactor())
        import tarfile
        with tarfile.open(built["path"]) as tf:
            names = tf.getnames()
        assert not any("package" in n for n in names) and b"PKZIP" not in b"".join(f.read_bytes() for f in out.iterdir())
    finally:
        sys.path.remove(str(root))


def test_the_environment_form_choice_is_stored_as_the_build_permission(ev):
    base, serve, env_id, root = ev
    form = {"id": env_id, "name": "dev", "base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": ""}
    h = who(OWNER_A)
    bad = requests.post(base + "/api/environments", json={**form, "evidence_builders": "everyone"}, headers=h, timeout=10)
    assert bad.status_code == 400
    ok = requests.post(base + "/api/environments", json={**form, "evidence_builders": "shared"}, headers=h, timeout=10)
    assert ok.status_code == 200, ok.text
    assert engine.get_shared_permission_overrides(env_id)["build_evidence_package"] == "allow"
    listed = requests.get(base + "/api/settings/environments", headers=h, timeout=10).json()["environments"]
    assert next(e for e in listed if e["id"] == env_id)["evidence_builders"] == "shared"
    requests.post(base + "/api/environments", json={**form, "evidence_builders": "owner"}, headers=h, timeout=10)
    assert engine.get_shared_permission_overrides(env_id)["build_evidence_package"] == "deny"
    listed = requests.get(base + "/api/settings/environments", headers=h, timeout=10).json()["environments"]
    assert next(e for e in listed if e["id"] == env_id)["evidence_builders"] == "owner"
    # a save without the field leaves the choice alone
    requests.post(base + "/api/environments", json=form, headers=h, timeout=10)
    assert engine.get_shared_permission_overrides(env_id)["build_evidence_package"] == "deny"
    audit_entry = [e for e in audit(os.environ.get("X") or engine._audit_log_path()) if e["action"] == "environment.upsert"]
    assert any(e["details"].get("evidence_builders") == "shared" for e in audit_entry)


def test_the_capability_is_in_the_catalogue_denied_by_default_and_says_it_holds_people_level_rows():
    cap = next(c for c in engine.SHARED_CAPABILITIES if c["key"] == "build_evidence_package")
    assert cap["builtin"] == "deny" and cap["label"] == "Build evidence packages"
    assert "people-level rows" in cap["description"] and "not encrypted" in cap["description"] and "not signed" in cap["description"]


def test_the_build_type_is_not_a_renewing_type_and_the_zip_never_stays_in_the_data_folder_after_a_failure(ev):
    base, serve, env_id, root = ev
    assert "evidence_package.build" in serve.ENV_CHANGE_ACTION_TYPES
    assert "evidence_package.build" not in serve.SETTINGS_RENEWING_ACTION_TYPES
    assert serve._ENV_CHANGE_EXECUTORS["evidence_package.build"] == "_exec_evidence_package_build"


def test_coverage_checks_are_limited_to_two_at_once(ev, monkeypatch):
    base, serve, env_id, root = ev
    import evidence_package
    gate = threading.Event()
    entered = threading.Semaphore(0)
    real = evidence_package.preview

    def slow(*a, **k):
        entered.release()
        gate.wait(10)
        return real(*a, **k)
    monkeypatch.setattr(evidence_package, "preview", slow)
    results = []

    def go():
        results.append(requests.post(base + "/api/evidence_packages/prepare?environment=ldev", json={**PERIOD, "check_only": True}, timeout=20).status_code)
    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)
    third = requests.post(base + "/api/evidence_packages/prepare?environment=ldev", json={**PERIOD, "check_only": True}, timeout=10)
    assert third.status_code == 429 and third.json()["reason"] == "busy"
    gate.set()
    for t in threads:
        t.join(15)
    assert results == [200, 200]
    assert requests.post(base + "/api/evidence_packages/prepare?environment=ldev", json={**PERIOD, "check_only": True}, timeout=10).status_code == 200


def test_every_check_runs_again_when_the_approved_build_is_started(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    share_dev(env_id, allow_build=True)
    b = who(OWNER_B)
    # 1. the permission is withdrawn during the MFA round trip
    aid = prepare(base, headers=b).json()["action_id"]
    engine.set_shared_permissions({"build_evidence_package": "deny"}, environment_id=env_id)
    refused = save(base, aid, b)
    assert refused.status_code == 403 and refused.json()["capability"] == "build_evidence_package"
    assert not serve._evidence.running()
    # 2. the name now means another environment (the target changed)
    engine.set_shared_permissions({"build_evidence_package": "allow"}, environment_id=env_id)
    aid = prepare(base, headers=b).json()["action_id"]
    engine.set_environment_shared("dev", OWNER_A, False)
    _, other = engine.upsert_environment("dev", {"base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}, owner=OWNER_B)
    seed_fixed_archive(other)
    changed = save(base, aid, b)
    assert changed.status_code == 409 and changed.json()["reason"] == "target_changed"
    assert not serve._evidence.running()


def test_the_approved_request_runs_whatever_the_save_request_says(ev, monkeypatch):
    base, serve, env_id, root = ev
    hosted(serve, monkeypatch)
    me = who(OWNER_A)
    aid = prepare(base, {"start": "2020-03-02", "end": "2020-03-03"}, headers=me).json()["action_id"]
    done = requests.post(base + "/api/environment_changes/save", json={"start": "2019-01-01", "end": "2020-12-31", "environment": "other"},
                         headers={**me, "X-Auth-Action-Id": aid, "X-Nginx-Stepup-Location": SECRET}, timeout=15)
    assert done.status_code == 202 and done.json()["period"] == {"start": "2020-03-02", "end": "2020-03-03"}


def test_a_full_disk_while_writing_is_a_plain_disk_space_failure(ev, monkeypatch, tmp_audit_log):
    import errno
    import evidence_package
    base, serve, env_id, root = ev

    def full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(evidence_package, "build_package", full)
    job_id = prepare(base).json()["job_id"]
    status = wait_done(base, job_id)
    assert status["status"] == "error" and status["reason"] == "disk_space" and "ran out of space" in status["error"]
    assert "No space left" not in json.dumps(status) and not (root / "packages" / job_id).exists()
    failed = next(e for e in audit(tmp_audit_log) if e["action"] == "evidence_package.build_failed")
    assert failed["details"]["reason"] == "disk_space"


def test_the_preflight_counts_a_finished_package_still_in_its_window_but_the_tick_does_not(ev, monkeypatch):
    base, serve, env_id, root = ev
    from datetime import datetime, timezone
    from server.updater import upgrade as upgrade_service
    now = datetime.now(timezone.utc)

    def items():
        return {i["id"]: i for i in upgrade_service.preflight({}, 1000, serve._upgrade_context(), now)}
    assert "evidence_package_waiting" not in items()
    job_id = prepare(base).json()["job_id"]
    wait_done(base, job_id)
    ctx = serve._upgrade_context()
    assert ctx["evidence_build_running"] is False and ctx["evidence_package_waiting_until"]
    waiting = items()["evidence_package_waiting"]
    until = ctx["evidence_package_waiting_until"][11:16]
    assert waiting["ok"] is False and f"a package is waiting to be downloaded (until {until} UTC)" in waiting["text"].replace("A package", "a package")
    assert items()["evidence_build"]["ok"] is True                 # nothing is being built; the tick only looks at that flag
    monkeypatch.setattr(serve._evidence, "_clock", lambda: time.monotonic() + 10_000)          # the window is over
    assert serve._evidence.waiting_until() is None and "evidence_package_waiting" not in items()


def test_start_up_cleanup_refuses_a_packages_folder_that_is_a_symlink(ev, tmp_path):
    base, serve, env_id, root = ev
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "keep.txt").write_text("not ours")
    (root / "packages").symlink_to(outside, target_is_directory=True)
    assert serve._evidence.cleanup_startup() == 0
    assert (outside / "keep.txt").exists() and "symbolic link" in serve._evidence.startup_skipped


def test_start_refuses_a_packages_folder_that_is_a_symlink_and_creates_nothing_through_it(ev, tmp_path):
    base, serve, env_id, root = ev
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (root / "packages").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        serve._evidence.start({"environment_id": env_id, "environment_name": "dev", "period": PERIOD, "gaps_acknowledged": False,
                               "owner": "", "issuer": "", "fingerprint": "local"})
    assert list(outside.iterdir()) == [] and serve._evidence.startup_skipped
    # and the route answers 500 packages_dir
    r = prepare(base)
    assert r.status_code == 500 and r.json()["reason"] == "packages_dir"


def test_fired_timers_do_not_pile_up(ev, monkeypatch):
    base, serve, env_id, root = ev
    monkeypatch.setattr(serve._evidence, "window_seconds", 0)
    for _ in range(3):
        wait_done(base, prepare(base).json()["job_id"])
    end = time.time() + 8
    while serve._evidence._timers and time.time() < end:
        time.sleep(0.1)
    assert len(serve._evidence._timers) == 0


@pytest.mark.parametrize("name", ["ENOSPC", "EDQUOT", "EFBIG"])
def test_a_full_disk_a_quota_or_a_file_size_limit_is_a_disk_space_failure(ev, monkeypatch, name):
    import errno
    import evidence_package
    base, serve, env_id, root = ev
    code = getattr(errno, name, None)
    if code is None:
        pytest.skip(name + " does not exist here")

    def boom(*a, **k):
        raise OSError(code, "x")
    monkeypatch.setattr(evidence_package, "build_package", boom)
    status = wait_done(base, prepare(base).json()["job_id"])
    assert status["reason"] == "disk_space"
