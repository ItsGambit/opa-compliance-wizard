"""Batch 4 of the 2026-10-05 external review (sync/report engine), v5.40.6.

One section per finding; each test names the defect it pins. The
evidence chain itself (hash formats, link rule, chain_heads, verifier
results) is deliberately untouched by this batch -- the tests here only
pin WHEN manifests are written and HOW a deep verify is delivered.
"""
import csv
import http.client
import io
import json
import os
import socket
import sys
import threading
import time
import urllib.error
from datetime import datetime, timedelta, timezone
from email.message import Message

import pytest

import audit_store
import create_secret_folders as engine

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_http_authz_matrix import (  # noqa: E402  (shared live-server fixture + helpers)
    ADMIN, FOLDER, OWNER_A, PROJ, RG, _call, _seed_owner_a_with_session, _who, matrix_server,  # noqa: F401
)

ENV = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def _fresh_audit_lock_memo(monkeypatch):
    """_audit_log_exclusive remembers an OS-lock failure for a minute;
    every test starts without that memory."""
    monkeypatch.setattr(engine, "_audit_os_lock_down_until", 0.0)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeOktaClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def get_system_log(self, since=None, until=None, limit=1000, sort_order="DESCENDING", max_pages=50, filter_expr=None):
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _event(uuid, published, event_type="user.session.start", targets=None):
    return {
        "uuid": uuid, "eventType": event_type, "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone", "alternateId": "someone@example.com"},
        "outcome": {"result": "SUCCESS"}, "target": targets or [],
    }


def _manifests(env=ENV):
    return audit_store._get_connection().execute(
        "SELECT * FROM ingestion_manifests WHERE environment_id = ? ORDER BY id", (env,)
    ).fetchall()


# ---------------------------------------------------------------------------
# (a) exactly one manifest per ingestion
# ---------------------------------------------------------------------------
def test_a_failure_after_the_success_manifest_never_seals_the_rows_twice(tmp_audit_store, monkeypatch):
    """5.40.4 follow-up: the final _upsert_sync_state failing after the
    success manifest committed used to fall into _fail, which wrote a
    second manifest for the same rows (row_count counted twice)."""
    audit_store.run_migrations()
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=2))
    real_upsert = audit_store._upsert_sync_state

    def flaky_upsert(conn, environment_id, **fields):
        if fields.get("last_sync_status") == "success":
            raise RuntimeError("disk full writing the final status")
        return real_upsert(conn, environment_id, **fields)

    monkeypatch.setattr(audit_store, "_upsert_sync_state", flaky_upsert)
    okta = FakeOktaClient([([_event("evt-1", since), _event("evt-2", since)], True)])
    with pytest.raises(RuntimeError):
        audit_store.sync_okta_events(okta, ENV, "all", since=since)

    rows = _manifests()
    assert len(rows) == 1
    assert rows[0]["row_count"] == 2
    state = audit_store.get_sync_state(ENV)
    assert state["last_sync_status"] == "error" and "disk full" in state["last_sync_error"]
    assert audit_store.verify_ingestion_chain(ENV, deep=True)["valid"] is True


def test_rows_are_still_sealed_when_the_error_status_write_fails_too(tmp_audit_store, monkeypatch):
    """_fail used to write the status first and seal second -- a failing
    status write left inserted rows covered by no manifest."""
    audit_store.run_migrations()
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=2))
    real_upsert = audit_store._upsert_sync_state

    def upsert(conn, environment_id, **fields):
        if fields.get("last_sync_status") == "error":
            raise RuntimeError("status write failed")
        return real_upsert(conn, environment_id, **fields)

    class BoomAfterFirstChunk(FakeOktaClient):
        calls = 0

        def get_system_log(self, **kwargs):
            BoomAfterFirstChunk.calls += 1
            if BoomAfterFirstChunk.calls == 1:
                return [_event("evt-1", since)], True
            raise RuntimeError("okta went away")

    monkeypatch.setattr(audit_store, "_upsert_sync_state", upsert)
    since = _iso(datetime.now(timezone.utc) - timedelta(days=2))
    with pytest.raises(RuntimeError, match="okta went away"):
        audit_store.sync_okta_events(BoomAfterFirstChunk([]), ENV, "all", since=since)
    rows = _manifests()
    assert len(rows) == 1 and rows[0]["row_count"] == 1


def test_a_seal_that_failed_is_retried_once_by_the_failure_path(tmp_audit_store, monkeypatch):
    """The 'already sealed' mark is set only after the manifest commits, so
    a seal that raised (rolled back) is still written by _fail."""
    audit_store.run_migrations()
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=2))
    real_record = audit_store._record_ingestion_manifest
    calls = {"n": 0}

    def record(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first seal failed")
        return real_record(*args, **kwargs)

    monkeypatch.setattr(audit_store, "_record_ingestion_manifest", record)
    with pytest.raises(RuntimeError, match="first seal failed"):
        audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), ENV, "all", since=since)
    rows = _manifests()
    assert len(rows) == 1 and rows[0]["row_count"] == 1


def test_a_normal_sync_still_writes_one_manifest(tmp_audit_store):
    audit_store.run_migrations()
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=2))
    result = audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), ENV, "all", since=since)
    assert result["complete"] is True
    assert len(_manifests()) == 1


# ---------------------------------------------------------------------------
# (b) deep verify: bounded per request, single-flight per environment
# ---------------------------------------------------------------------------
@pytest.fixture
def serve_module(tmp_audit_store):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
    from server import serve
    audit_store.run_migrations()
    with serve._deep_verify_lock:
        serve._deep_verify_jobs.clear()
    yield serve
    with serve._deep_verify_lock:
        serve._deep_verify_jobs.clear()


def test_a_quick_deep_verify_answers_like_before(serve_module):
    status, body = serve_module._deep_verify(ENV, wait_secs=5)
    assert status == 200
    assert body["valid"] is True and body["deep"] is True and body["checked_at"]


def test_a_slow_deep_verify_answers_202_and_the_same_url_collects_it(serve_module, monkeypatch):
    release = threading.Event()
    runs = []

    def slow_verify(environment_id, deep=False):
        runs.append(environment_id)
        release.wait(5)
        return {"valid": True, "deep": deep, "manifest_count": 0}

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", slow_verify)
    status, body = serve_module._deep_verify(ENV, wait_secs=0.05)
    assert status == 202 and body["status"] == "running"
    # A second request while it runs joins it -- no second CPU-bound pass.
    status, _ = serve_module._deep_verify(ENV, wait_secs=0.05)
    assert status == 202
    release.set()
    status, body = serve_module._deep_verify(ENV, wait_secs=5)
    assert status == 200 and body["valid"] is True
    assert runs == [ENV]
    # Within the TTL a poll gets the finished result, not a new run.
    status, _ = serve_module._deep_verify(ENV, wait_secs=1)
    assert status == 200 and runs == [ENV]


def test_a_finished_result_expires_and_the_next_request_checks_again(serve_module, monkeypatch):
    runs = []

    def verify(environment_id, deep=False):
        runs.append(environment_id)
        return {"valid": True, "deep": deep}

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", verify)
    assert serve_module._deep_verify(ENV, wait_secs=5)[0] == 200
    with serve_module._deep_verify_lock:
        serve_module._deep_verify_jobs[ENV]["finished_mono"] -= serve_module.DEEP_VERIFY_RESULT_TTL_SECS + 1
    assert serve_module._deep_verify(ENV, wait_secs=5)[0] == 200
    assert runs == [ENV, ENV]


def test_a_failing_deep_verify_is_a_generic_500_not_a_hang(serve_module, monkeypatch):
    def broken(environment_id, deep=False):
        raise RuntimeError("database disk image is malformed /secret/path")

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", broken)
    status, body = serve_module._deep_verify(ENV, wait_secs=5)
    assert status == 500
    assert "/secret/path" not in body["error"] and "Internal error" in body["error"]


def test_deep_verify_route_checks_visibility_before_touching_any_job(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    # Owner A's "dev" is private: another admin cannot even start a check on it.
    resp = _call(base_url, "GET", "/api/environments/dev/integrity?deep=1", headers=_who(ADMIN, admin=True))
    assert resp.status_code == 404
    with serve._deep_verify_lock:
        assert env_id not in serve._deep_verify_jobs
    # Owner A (as an admin) gets the verifier's answer, as before.
    resp = _call(base_url, "GET", "/api/environments/dev/integrity?deep=1", headers=_who(OWNER_A, admin=True))
    assert resp.status_code == 200 and resp.json()["valid"] is True and resp.json()["deep"] is True


# ---------------------------------------------------------------------------
# ENG2-02: existing folders are matched by full path, never by leaf name
# ---------------------------------------------------------------------------
class FolderClient:
    """Tree: Dev/DB. Records every create."""

    def __init__(self, tree=None):
        self.tree = tree if tree is not None else {"dev": ("Dev", None), "db": ("DB", "dev")}
        self.created = []

    def list_folders(self, rg, proj):
        return [{"id": fid, "name": name, "type": "folder"} for fid, (name, parent) in self.tree.items() if parent is None]

    def list_folder_items(self, rg, proj, folder_id):
        return [{"id": fid, "name": name, "type": "folder"} for fid, (name, parent) in self.tree.items() if parent == folder_id]

    def create_folder(self, rg, proj, name, description, parent_id=None):
        new_id = f"new-{len(self.created)}"
        self.created.append((name, parent_id))
        self.tree[new_id] = (name, parent_id)
        return {"id": new_id}


def test_a_same_named_folder_elsewhere_is_never_adopted_as_the_parent():
    client = FolderClient()
    ordered = [("Prod",), ("Prod", "DB"), ("Prod", "DB", "creds")]
    existing, name_in_use = engine.resolve_existing_folders(client, "rg", "proj", ordered)
    assert existing == {}
    assert name_in_use == {("Prod", "DB"): "Dev/DB"}
    results = engine.execute_plan(client, "rg", "proj", ordered, {}, existing)
    assert all(parent != "db" for _name, parent in client.created), "a create used Dev/DB as its parent"
    assert [r[2] for r in results] == ["created", "created", "created"]
    assert client.created[1] == ("DB", "new-0") and client.created[2] == ("creds", "new-1")


def test_an_exact_path_match_is_still_adopted_on_a_rerun():
    client = FolderClient()
    ordered = [("Dev",), ("Dev", "DB"), ("Dev", "DB", "creds")]
    existing, name_in_use = engine.resolve_existing_folders(client, "rg", "proj", ordered)
    assert existing == {("Dev",): "dev", ("Dev", "DB"): "db"}
    assert name_in_use == {}
    engine.execute_plan(client, "rg", "proj", ordered, {}, existing)
    assert client.created == [("creds", "db")]


def test_name_in_use_is_reported_case_insensitively():
    existing, name_in_use = engine.resolve_existing_folders(FolderClient(), "rg", "proj", [("db",)])
    assert existing == {} and name_in_use == {("db",): "Dev/DB"}


def test_preview_route_shows_name_in_use(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = FolderClient()
    resp = _call(base_url, "POST", "/api/preview",
                 {"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "Prod/DB"}, {"path": "prod"}]},
                 _who(OWNER_A))
    assert resp.status_code == 200, resp.text
    tree = {t["path"]: t for t in resp.json()["tree"]}
    assert tree["Prod/DB"]["exists"] is False and tree["Prod/DB"]["name_in_use_at"] == "Dev/DB"
    assert tree["Prod"]["name_in_use_at"] is None
    assert resp.json()["case_variants"] == [["Prod", "prod"]]


# ---------------------------------------------------------------------------
# ENG2-03 / ENG2-14: archive secrets report filtered in SQL, no cap; one
# bucketing implementation for both paths
# ---------------------------------------------------------------------------
PROJECT_X = "proj-x"
PROJECT_Y = "proj-y"


def _secret_event(uuid, published, event_type, secret_id, project_id, name="s1", outcome="SUCCESS"):
    event = _event(uuid, published, event_type, targets=[
        {"id": secret_id, "type": "Secret", "displayName": name},
        {"id": project_id, "type": "Project", "displayName": project_id},
        {"id": "/a/" + name, "type": "Secret Path", "displayName": "/a/" + name},
    ])
    event["outcome"] = {"result": outcome}
    return event


class ReportClient:
    def __init__(self, secrets=()):
        self.secrets = list(secrets)

    def list_folders(self, rg, proj):
        return [{"id": "fa", "name": "a", "type": "folder"}]

    def list_folder_items(self, rg, proj, folder_id):
        return [{"id": sid, "name": name, "type": "key_value_secret"} for sid, name in self.secrets]


def _ingest(events):
    conn = audit_store._get_connection()
    audit_store._insert_rows(conn, ENV, [audit_store._normalize_live_event(e) for e in events], "all")


def test_archive_report_keeps_an_old_create_however_many_other_projects_events_exist(tmp_audit_store, monkeypatch):
    audit_store.run_migrations()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [_secret_event("x-create", _iso(base), "pam.secret.create", "sec-x", PROJECT_X)]
    events += [_secret_event(f"y-{i}", _iso(base + timedelta(minutes=i + 1)), "pam.secret.reveal", "sec-y", PROJECT_Y)
               for i in range(50)]
    _ingest(events)
    # The old code capped the environment-wide query; any cap smaller than
    # the other project's volume dropped X's create. There is no cap now --
    # prove the query itself never sees project Y at all.
    seen = []
    real_iter = audit_store.iter_events_targeting

    def spy(environment_id, target_id, event_types):
        for row in real_iter(environment_id, target_id, event_types):
            seen.append(row["uuid"])
            yield row

    monkeypatch.setattr(audit_store, "iter_events_targeting", spy)
    report = engine.build_project_secrets_report_from_archive(ReportClient([("sec-x", "s1")]), ENV, "rg", PROJECT_X)
    assert seen == ["x-create"]
    row = next(r for r in report["secrets"] if r["id"] == "sec-x")
    assert row["created"] is not None and row["status"] == "active"
    assert report["oldest_captured_at"] == _iso(base)
    assert report["complete"] is True


def test_archive_report_ignores_an_event_naming_the_id_as_a_non_project_target(tmp_audit_store):
    """Same qualification rule as before: the id must appear as a Project."""
    audit_store.run_migrations()
    event = _event("odd", _iso(datetime(2026, 1, 2, tzinfo=timezone.utc)), "pam.secret.create", targets=[
        {"id": "sec-z", "type": "Secret", "displayName": "z"}, {"id": PROJECT_X, "type": "Folder", "displayName": "?"},
    ])
    _ingest([event])
    report = engine.build_project_secrets_report_from_archive(ReportClient(), ENV, "rg", PROJECT_X)
    assert report["secrets"] == []


def test_live_and_archive_reports_build_identical_rows_from_identical_events(tmp_audit_store):
    """Golden test for the shared bucketing (ENG2-14): the same events
    through both report paths give the same rows (reveal cap disabled)."""
    audit_store.run_migrations()
    base = datetime(2026, 2, 1, tzinfo=timezone.utc)
    events = [
        _secret_event("e1", _iso(base), "pam.secret.create", "sec-1", PROJECT_X, "one"),
        _secret_event("e2", _iso(base + timedelta(hours=1)), "pam.secret.update", "sec-1", PROJECT_X, "one"),
        _secret_event("e3", _iso(base + timedelta(hours=2)), "pam.secret.reveal", "sec-1", PROJECT_X, "one"),
        _secret_event("e4", _iso(base + timedelta(hours=3)), "pam.secret.create", "sec-gone", PROJECT_X, "gone"),
        _secret_event("e5", _iso(base + timedelta(hours=4)), "pam.secret.delete", "sec-gone", PROJECT_X, "gone"),
        _secret_event("e6", _iso(base + timedelta(hours=5)), "pam.secret.delete", "sec-1", PROJECT_X, "one", "FAILURE"),
        _secret_event("e7", _iso(base + timedelta(hours=6)), "pam.secret.create", "sec-unk", PROJECT_X, "unk"),
    ]
    _ingest(events)
    client = ReportClient([("sec-1", "one")])
    newest_first = sorted(events, key=lambda e: e["published"], reverse=True)
    live = engine.build_secrets_access_report(client, FakeOktaClient([(newest_first, True)]), "rg", PROJECT_X,
                                              reveal_limit=10**6)
    archive = engine.build_project_secrets_report_from_archive(client, ENV, "rg", PROJECT_X)
    assert live["secrets"] == archive["secrets"]
    assert live["folders"] == archive["folders"]
    statuses = {r["id"]: r["status"] for r in archive["secrets"]}
    assert statuses == {"sec-1": "active", "sec-gone": "deleted", "sec-unk": "unknown"}


def test_iter_events_targeting_uses_the_target_index(tmp_audit_store):
    audit_store.run_migrations()
    plan = audit_store._get_connection().execute(
        "EXPLAIN QUERY PLAN SELECT uuid FROM event_targets WHERE environment_id = ? AND target_id = ?", (ENV, PROJECT_X)
    ).fetchall()
    assert any("idx_event_targets_id" in str(tuple(r)) for r in plan)


# ---------------------------------------------------------------------------
# ENG2-09: live lookups say when they were cut short
# ---------------------------------------------------------------------------
def test_live_secrets_report_carries_the_complete_flag():
    report = engine.build_secrets_access_report(ReportClient(), FakeOktaClient([([], False)]), "rg", PROJECT_X)
    assert report["complete"] is False
    report = engine.build_secrets_access_report(ReportClient(), FakeOktaClient([([], True)]), "rg", PROJECT_X)
    assert report["complete"] is True


def test_last_access_lookup_carries_the_complete_flag():
    kind = next(iter(engine.RESOURCE_ACCESS_EVENT_TYPES))
    results = engine.find_last_access_for_user(
        FakeOktaClient([([], False)]), "00uUSER", [{"resource_kind": kind, "resource_id": "r1"}]
    )
    assert results["r1"]["complete"] is False


# ---------------------------------------------------------------------------
# ENG2-05: policy update -- lock, compare-before-PUT, server-side checks
# ---------------------------------------------------------------------------
class PolicyClient:
    def __init__(self, policy, folder_name="FolderName", changes_between_gets=False):
        self.policy = policy
        self.folder_name = folder_name
        self.changes_between_gets = changes_between_gets
        self.gets = 0
        self.puts = []

    def get_folder(self, rg, proj, folder_id):
        if folder_id != FOLDER:
            raise engine.OpaApiError(404, "get_folder", "not found")
        return {"id": FOLDER, "name": self.folder_name}

    def get_security_policy(self, policy_id):
        self.gets += 1
        policy = json.loads(json.dumps(self.policy))
        if self.changes_between_gets and self.gets >= 2:
            policy["principals"]["user_groups"] = []  # someone removed the group in the OPA console
        return policy

    def update_security_policy(self, policy_id, body, rate_limit_wait=True):
        self.put_waits = getattr(self, "put_waits", []) + [rate_limit_wait]
        self.puts.append(body)
        self.policy = body

    def wait_for_rate_limit(self):
        self.waits = getattr(self, "waits", 0) + 1
        return 0.0

    def create_security_policy(self, body):
        return {**body, "id": "new-policy"}


def _policy(rg=RG, extra_principal_key=False):
    principals = {"user_groups": [{"id": "g-keep", "name": "Keep"}], "workload_roles": []}
    if extra_principal_key:
        principals["future_kind"] = [{"id": "x"}]
    return {"id": "pol", "name": "P", "active": True, "type": "default", "resource_group": {"id": rg, "name": "RG"},
            "principals": principals, "rules": []}


def _assign(base_url, body):
    return _call(base_url, "POST", f"/api/resource_groups/{RG}/projects/{PROJ}/folders/{FOLDER}/policy", body,
                 _who(OWNER_A))


def _with_client(serve, client):
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = client


BASE_BODY = {"mode": "existing", "policy_id": "pol", "privileges": {"list": True}, "group_refs": [{"id": "g-new", "name": "New"}]}


def test_a_policy_changed_between_read_and_write_is_not_overwritten(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy(), changes_between_gets=True)
    _with_client(serve, client)
    resp = _assign(base_url, BASE_BODY)
    assert resp.status_code == 409 and "changed in OPA" in resp.json()["error"]
    assert client.puts == []


def test_a_normal_assignment_keeps_unknown_principal_keys_and_uses_opas_folder_name(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy(extra_principal_key=True), folder_name="RealName")
    _with_client(serve, client)
    resp = _assign(base_url, {**BASE_BODY, "folder_name": "SpoofedName"})
    assert resp.status_code == 200, resp.text
    put = client.puts[0]
    assert put["principals"]["future_kind"] == [{"id": "x"}]
    assert [g["id"] for g in put["principals"]["user_groups"]] == ["g-keep", "g-new"]
    selector = put["rules"][0]["resource_selector"]["selectors"][0]["selector"]["secret_folder"]
    assert selector == {"id": FOLDER, "name": "RealName"}
    assert put["rules"][0]["name"] == "RealName-access"


def test_a_policy_from_another_resource_group_is_refused(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy(rg="some-other-rg"))
    _with_client(serve, client)
    resp = _assign(base_url, BASE_BODY)
    assert resp.status_code == 400 and client.puts == []


@pytest.mark.parametrize("override", [
    {"privileges": {"secret_reveal": "false"}},          # a non-empty string used to GRANT
    {"privileges": ["list"]},
    {"group_refs": [{"name": "no id"}]},
    {"group_refs": "g1"},
    {"workload_role_refs": [{"id": "../x"}]},
    {"mfa": {"reauth_seconds": 30, "acr_values": "x", "extra": 1}},  # used to be a TypeError -> 500
    {"mfa": {"reauth_seconds": "30", "acr_values": "x"}},
    {"mfa": {"reauth_seconds": -1, "acr_values": "x"}},
    {"rule_name": 7},
    {"mode": "bogus"},
])
def test_malformed_assignment_input_is_a_400_before_any_write(matrix_server, override):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy())
    _with_client(serve, client)
    resp = _assign(base_url, {**BASE_BODY, **override})
    assert resp.status_code == 400, (override, resp.status_code, resp.text)
    assert client.puts == [] and client.gets == 0


def test_a_folder_not_in_the_project_is_refused(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy())
    client.get_folder = lambda rg, proj, fid: (_ for _ in ()).throw(engine.OpaApiError(404, "x", "nope"))
    _with_client(serve, client)
    resp = _assign(base_url, BASE_BODY)
    assert resp.status_code == 400 and client.puts == []


def test_wizard_writes_to_one_policy_are_serialised(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    inside = {"now": 0, "max": 0}
    guard = threading.Lock()

    class SlowClient(PolicyClient):
        def update_security_policy(self, policy_id, body, rate_limit_wait=True):
            with guard:
                inside["now"] += 1
                inside["max"] = max(inside["max"], inside["now"])
            time.sleep(0.2)
            with guard:
                inside["now"] -= 1
            super().update_security_policy(policy_id, body, rate_limit_wait)

    client = SlowClient(_policy())
    _with_client(serve, client)
    threads = [threading.Thread(target=_assign, args=(base_url, BASE_BODY)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert inside["max"] == 1
    assert len(client.puts) == 3


def test_policy_fingerprint_ignores_list_order_only():
    a = {"principals": {"user_groups": [{"id": "1"}, {"id": "2"}]}, "rules": [{"name": "r1"}, {"name": "r2"}]}
    b = {"principals": {"user_groups": [{"id": "2"}, {"id": "1"}]}, "rules": [{"name": "r2"}, {"name": "r1"}]}
    c = {"principals": {"user_groups": [{"id": "1"}]}, "rules": [{"name": "r2"}, {"name": "r1"}]}
    assert engine.policy_fingerprint(a) == engine.policy_fingerprint(b)
    assert engine.policy_fingerprint(a) != engine.policy_fingerprint(c)


def test_merge_principals_tolerates_entries_without_an_id():
    merged = engine.merge_principals({"user_groups": [{"name": "legacy, no id"}]}, [{"id": "g1"}], None)
    assert merged["user_groups"] == [{"name": "legacy, no id"}, {"id": "g1"}]
    assert merged["workload_roles"] == []


# ---------------------------------------------------------------------------
# ENG1-07: upsert_environment validates before storing anything
# ---------------------------------------------------------------------------
GOOD = {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": "OLD"}


def test_a_rejected_update_leaves_the_stored_secret_alone(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment("dev", GOOD)
    with pytest.raises(ValueError):
        engine.upsert_environment("dev", {**GOOD, "base_domain": "", "key_secret": "NEW"})
    assert fake_keyring[(env_id, "key_secret")] == "OLD"


def test_a_rejected_create_leaves_no_orphaned_secret(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    with pytest.raises(ValueError):
        engine.upsert_environment("dev", {"key_secret": "S", "okta_api_token": "T"})
    assert fake_keyring == {}
    with pytest.raises(ValueError):
        engine.upsert_environment("dev", {**GOOD, "base_domain": "evil.example.com@x"})
    assert fake_keyring == {}


def test_a_failing_row_write_puts_the_keychain_back(tmp_audit_store, fake_keyring, monkeypatch):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment("dev", GOOD)
    real_set = engine.keyring_set

    def failing_set(storage_name, field, value):
        if field == "okta_api_token":
            raise RuntimeError("keychain write failed")
        real_set(storage_name, field, value)

    monkeypatch.setattr(engine, "keyring_set", failing_set)
    with pytest.raises(RuntimeError):
        engine.upsert_environment("dev", {**GOOD, "key_secret": "NEW", "okta_api_token": "TOK", "team_name": "t2"})
    monkeypatch.setattr(engine, "keyring_set", real_set)
    assert fake_keyring[(env_id, "key_secret")] == "OLD"
    assert (env_id, "okta_api_token") not in fake_keyring
    assert engine.list_environments_for(None)["dev"]["team_name"] == "t"


def test_concurrent_local_creates_of_one_name_make_one_row(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    errors = []

    def create():
        try:
            engine.upsert_environment("dev", GOOD)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=create) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    count = audit_store._get_connection().execute(
        "SELECT COUNT(*) FROM app_environments WHERE owner_id IS NULL AND display_name = 'dev'"
    ).fetchone()[0]
    assert count == 1


def test_an_admin_rename_onto_an_existing_name_is_a_clean_error(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    engine.upsert_environment("prod", GOOD, owner="00uU")
    _, dev_id = engine.upsert_environment("dev", GOOD, owner="00uU")
    with pytest.raises(ValueError, match="already exists"):
        engine.upsert_environment("prod", {**GOOD, "key_secret": "NEW"}, owner="00uADMIN", is_admin=True,
                                  environment_id=dev_id)
    assert fake_keyring[(dev_id, "key_secret")] == "OLD"


# ---------------------------------------------------------------------------
# ENG1-08: rate-limit waits are bounded
# ---------------------------------------------------------------------------
def _headers(**values):
    msg = Message()
    for k, v in values.items():
        msg[k.replace("_", "-")] = v
    return msg


@pytest.mark.parametrize("value", ["-5", "nan", "inf", "1e9", "-inf", "garbage"])
def test_retry_after_is_clamped_and_never_negative_or_non_finite(value):
    wait = engine._retry_after_secs(_headers(Retry_After=value))
    assert 0 < wait <= engine.RATE_LIMIT_MAX_WAIT_SECS + engine.RATE_LIMIT_WAIT_BUFFER_SECS


def test_retry_after_http_date_is_honoured():
    date = "Thu, 01 Jan 2026 00:00:00 GMT"
    later = "Thu, 01 Jan 2026 00:00:30 GMT"
    wait = engine._retry_after_secs(_headers(Retry_After=later, Date=date))
    assert wait == pytest.approx(30 + engine.RATE_LIMIT_WAIT_BUFFER_SECS)


def test_a_far_future_reset_waits_at_most_the_cap(monkeypatch):
    slept = []
    monkeypatch.setattr(engine.time, "sleep", slept.append)
    url = "https://ratelimit.example.com/x"
    engine._record_rate_limit(url, _headers(x_ratelimit_remaining="0", x_ratelimit_reset=str(int(time.time()) + 10**8)))
    engine._wait_if_rate_limited(url)
    assert slept and slept[0] <= engine.RATE_LIMIT_MAX_WAIT_SECS + engine.RATE_LIMIT_WAIT_BUFFER_SECS
    with engine._rate_limit_lock:
        engine._rate_limit_state.pop("ratelimit.example.com", None)


class _FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, url, code, headers=None, body=b""):
        super().__init__(url, code, "x", headers or Message(), io.BytesIO(body))


class _ScriptedOpener:
    """Stands in for _SAFE_OPENER: each call pops the next action."""

    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append(req.get_method())
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action


class _Resp:
    def __init__(self, body=b"{}", headers=None):
        self._body = body
        self.headers = headers or Message()

    def read(self):
        if isinstance(self._body, BaseException):
            raise self._body
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(engine.time, "sleep", slept.append)
    return slept


def test_rate_limit_waits_stop_at_the_per_call_budget(monkeypatch, no_sleep):
    url = "https://budget.example.com/x"
    opener = _ScriptedOpener([_FakeHTTPError(url, 429, _headers(Retry_After="120")) for _ in range(20)])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("GET", url)
    assert exc_info.value.status == 429
    assert sum(no_sleep) <= engine.RATE_LIMIT_TOTAL_BUDGET_SECS


# ---------------------------------------------------------------------------
# ENG1-09: pagination and retry edge cases
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("base,link,expected", [
    ("https://your-org.okta.com", "https://your-org.okta.com/api/v1/logs?after=1", "/api/v1/logs?after=1"),
    ("https://Your-Org.Okta.com", "https://your-org.okta.com/api/v1/logs?after=1", "/api/v1/logs?after=1"),
    ("https://your-org.okta.com", "https://your-org.okta.com:443/api/v1/logs?after=1", "/api/v1/logs?after=1"),
    ("https://your-org.okta.com", "/api/v1/logs?after=1", "/api/v1/logs?after=1"),
    ("https://your-org.okta.com", "https://evil.example.com/api/v1/logs", None),
    ("https://your-org.okta.com", "http://your-org.okta.com/api/v1/logs", None),
    ("https://your-org.okta.com", "//evil.example.com/x", None),
    ("https://your-org.okta.com", "https://your-org.okta.com.evil.example.com/x", None),
    ("https://your-org.okta.com", "https://your-org.okta.com:8443/x", None),
])
def test_same_origin_path(base, link, expected):
    assert engine._same_origin_path(base, link) == expected


def _link(url):
    msg = Message()
    msg["Link"] = f'<{url}>; rel="next"'
    return msg


class _PagingOpa(engine.OpaClient):
    def __init__(self, pages):
        self.base_url = "https://opa.example.com"
        self.team_name = "t"
        self.bearer_token = "tok"
        self._token_lock = threading.Lock()
        self.pages = list(pages)
        self.requested = []

    def _raw_request(self, method, path, body=None, authed=True, return_headers=False, idempotent=None,
                     rate_limit_wait=True):
        self.requested.append(path)
        return self.pages.pop(0)


def test_opa_list_never_sends_the_token_to_another_host():
    """A Link naming another host is followed as a PATH on the configured
    origin (_raw_request always prefixes base_url) -- never as that URL."""
    client = _PagingOpa([({"list": [1]}, _link("https://evil.example.com/v1/teams/t/things?page=2")),
                         ({"list": [2]}, Message())])
    assert client._list("/v1/teams/t/things") == [1, 2]
    assert client.requested == ["/v1/teams/t/things", "/v1/teams/t/things?page=2"]
    assert all(not p.startswith("http") for p in client.requested)


def test_opa_list_stops_on_a_self_referencing_link():
    client = _PagingOpa([
        ({"list": [1]}, _link("https://opa.example.com/v1/teams/t/things?page=2")),
        ({"list": [2]}, _link("https://opa.example.com/v1/teams/t/things?page=2")),
    ])
    with pytest.raises(engine.OpaApiError, match="pagination loop"):
        client._list("/v1/teams/t/things")


def test_okta_pagination_works_with_a_mixed_case_org_url(monkeypatch):
    client = engine.OktaClient("https://Your-Org.okta.com", "tok")
    pages = [([{"uuid": "1"}], _link("https://your-org.okta.com/api/v1/logs?after=2")), ([{"uuid": "2"}], Message())]
    seen = []

    def request(method, path, body=None, return_headers=False):
        seen.append(path)
        return pages.pop(0)

    monkeypatch.setattr(client, "request", request)
    events, complete = client.get_system_log()
    assert [e["uuid"] for e in events] == ["1", "2"] and complete is True
    assert seen[1] == "/api/v1/logs?after=2"


def test_a_post_is_not_retried_on_a_502(monkeypatch, no_sleep):
    url = "https://okta.example.com/api/v1/groups"
    opener = _ScriptedOpener([_FakeHTTPError(url, 502), _Resp(b'{"id": "dup"}')])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OktaApiError) as exc_info:
        engine.http_json_request("POST", url, body={"x": 1}, error_cls=engine.OktaApiError)
    assert exc_info.value.status == 502 and opener.calls == ["POST"]


def test_a_get_is_still_retried_on_a_502(monkeypatch, no_sleep):
    url = "https://okta.example.com/api/v1/groups"
    opener = _ScriptedOpener([_FakeHTTPError(url, 502), _Resp(b'{"ok": true}')])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    assert engine.http_json_request("GET", url) == {"ok": True}


def test_a_post_is_retried_after_a_connect_phase_failure_only(monkeypatch, no_sleep):
    url = "https://okta.example.com/api/v1/groups"
    opener = _ScriptedOpener([urllib.error.URLError(ConnectionRefusedError()), _Resp(b'{"id": "g"}')])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    assert engine.http_json_request("POST", url, body={}) == {"id": "g"}
    opener = _ScriptedOpener([urllib.error.URLError(TimeoutError("timed out")), _Resp(b'{"id": "dup"}')])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("POST", url, body={})
    assert exc_info.value.status == engine.API_STATUS_NETWORK and opener.calls == ["POST"]


@pytest.mark.parametrize("failure", [TimeoutError("read timed out"), ConnectionResetError(), http.client.IncompleteRead(b"")])
def test_read_phase_failures_become_api_errors(monkeypatch, no_sleep, failure):
    url = "https://opa.example.com/x"
    opener = _ScriptedOpener([_Resp(failure)] * 4)
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("GET", url)
    assert exc_info.value.status == engine.API_STATUS_NETWORK
    assert len(opener.calls) == engine.MAX_RETRIES + 1


def test_a_non_json_200_is_an_api_error_not_a_400(monkeypatch, no_sleep):
    opener = _ScriptedOpener([_Resp(b"<html>proxy login</html>")])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("GET", "https://opa.example.com/x")
    assert exc_info.value.status == engine.API_STATUS_INVALID_RESPONSE
    assert not isinstance(exc_info.value, ValueError)


def test_network_errors_after_retries_become_api_errors(monkeypatch, no_sleep):
    opener = _ScriptedOpener([urllib.error.URLError(socket.gaierror("no such host"))] * 4)
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("GET", "https://opa.example.com/x")
    assert engine._is_network_error(exc_info.value)
    assert str(exc_info.value).startswith("Network error calling")


def test_missing_capability_401_does_not_refresh_the_token():
    class Client(_PagingOpa):
        fetched = 0

        def _fetch_token(self):
            Client.fetched += 1

        def _raw_request(self, *a, **k):
            raise engine.OpaApiError(401, "u", '{"error":"Missing capability: gateway.list"}')

    with pytest.raises(engine.OpaApiError):
        Client([]).request("GET", "/v1/teams/t/gateways")
    assert Client.fetched == 0


def test_an_expired_token_401_still_refreshes_once():
    class Client(_PagingOpa):
        fetched = 0
        attempts = 0

        def _fetch_token(self):
            Client.fetched += 1
            self.bearer_token = "fresh"

        def _raw_request(self, *a, **k):
            Client.attempts += 1
            if Client.attempts == 1:
                raise engine.OpaApiError(401, "u", '{"error":"token expired"}')
            return {"ok": True}

    assert Client([]).request("GET", "/v1/x") == {"ok": True}
    assert Client.fetched == 1


def test_unexpected_list_shape_is_logged_without_the_body(capsys):
    client = _PagingOpa([({"secret": "tenant-data-here"}, Message())])
    assert client._list("/v1/teams/t/x") == []
    captured = capsys.readouterr()
    assert "tenant-data-here" not in captured.out + captured.err


# ---------------------------------------------------------------------------
# ENG1-10: a keyring outage is not "no secret"
# ---------------------------------------------------------------------------
def test_a_backend_failure_raises_credential_store_unavailable(monkeypatch):
    class Locked:
        def get_password(self, service, field):
            raise RuntimeError("Keyring is locked")

    monkeypatch.setattr(engine, "keyring", Locked(), raising=False)
    monkeypatch.setattr(engine, "KEYRING_AVAILABLE", True)
    with pytest.raises(engine.CredentialStoreUnavailable) as exc_info:
        engine.keyring_get("some-env", "key_secret")
    assert "Keyring is locked" not in str(exc_info.value)


def test_a_missing_secret_is_still_none(monkeypatch):
    class Empty:
        def get_password(self, service, field):
            return None

    monkeypatch.setattr(engine, "keyring", Empty(), raising=False)
    monkeypatch.setattr(engine, "KEYRING_AVAILABLE", True)
    assert engine.keyring_get("some-env", "key_secret") is None


def test_routes_answer_503_when_the_credential_store_is_locked(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)

    def locked(storage_name, field):
        raise engine.CredentialStoreUnavailable("The OS credential store could not be read (KeyringLocked).")

    monkeypatch.setattr(engine, "keyring_get", locked)
    resp = _call(base_url, "GET", "/api/environments", headers=_who(OWNER_A))
    assert resp.status_code == 503 and "credential store" in resp.json()["error"]


# ---------------------------------------------------------------------------
# ENG1-11: app audit log
# ---------------------------------------------------------------------------
def test_audit_log_is_created_owner_only(tmp_audit_log):
    old = os.umask(0o022)
    try:
        engine.log_audit_event("u@example.com", "00uU", "x.test")
    finally:
        os.umask(old)
    assert (os.stat(tmp_audit_log).st_mode & 0o777) == 0o600


def test_an_append_failure_does_not_raise_after_the_action(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(engine, "_audit_log_path", lambda: str(tmp_path / "missing-dir" / "audit_log.jsonl"))
    entry = engine.log_audit_event("u@example.com", "00uU", "environment.delete", {"name": "dev"})
    assert entry["action"] == "environment.delete"
    err = capsys.readouterr().err
    assert "Audit log append FAILED" in err and "environment.delete" in err and "u@example.com" not in err


def test_read_audit_log_pages_from_the_end_with_the_old_semantics(tmp_audit_log):
    lines = []
    for i in range(300):
        lines.append(json.dumps({"action": f"a{i}", "timestamp": str(i)}))
        if i % 50 == 0:
            lines.extend(["", "not json", "[1, 2]"])
    tmp_audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    expected_all = [json.loads(l) for l in lines if l.startswith("{")][::-1]
    assert engine.read_audit_log(limit=200, offset=0) == expected_all[:200]
    assert engine.read_audit_log(limit=7, offset=290) == expected_all[290:297]
    assert engine.read_audit_log(limit=0) == []


def test_read_audit_log_handles_a_file_without_a_trailing_newline_and_tiny_blocks(tmp_audit_log, monkeypatch):
    tmp_audit_log.write_text('{"action":"first"}\n{"action":"second"}', encoding="utf-8")
    real = engine._audit_log_lines_newest_first
    monkeypatch.setattr(engine, "_audit_log_lines_newest_first", lambda p: real(p, block_size=3))
    assert [e["action"] for e in engine.read_audit_log()] == ["second", "first"]


def test_the_audit_log_lock_excludes_another_process(tmp_audit_log):
    """A child process holds the sidecar lock; our append must wait."""
    import subprocess
    lock_path = engine._audit_log_lock_path(str(tmp_audit_log))
    script = (
        "import fcntl, os, sys, time\n"
        f"fd = os.open({lock_path!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\n"
        "print('locked', flush=True)\n"
        "time.sleep(0.6)\n"
    )
    if sys.platform.startswith("win"):
        pytest.skip("POSIX flock child")
    child = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "locked"
    start = time.monotonic()
    engine.log_audit_event(None, None, "x.test")
    waited = time.monotonic() - start
    child.wait(5)
    assert waited >= 0.3, f"append did not wait for the other process's lock ({waited:.2f}s)"


# ---------------------------------------------------------------------------
# ENG1-12: .env parsing
# ---------------------------------------------------------------------------
def test_dotenv_utf8_bom_export_and_utf16(tmp_path):
    p = tmp_path / ".env"
    p.write_bytes("﻿OPA_TEAM_NAME=team\nexport OPA_KEY_ID = kid\n# c\nOPA_X=\"q\" # trailing\n".encode("utf-8"))
    assert dict(engine._parse_dotenv_text(engine._read_dotenv_text(str(p)))) == {
        "OPA_TEAM_NAME": "team", "OPA_KEY_ID": "kid", "OPA_X": "q",
    }
    p.write_bytes("OPA_TEAM_NAME=team16\r\n".encode("utf-16"))
    assert dict(engine._parse_dotenv_text(engine._read_dotenv_text(str(p)))) == {"OPA_TEAM_NAME": "team16"}


def test_an_undecodable_dotenv_is_skipped_not_a_crash(tmp_path, capsys):
    p = tmp_path / ".env"
    p.write_bytes(b"OPA_TEAM_NAME=\xff\xfe\xfa\x80bad")
    p.write_bytes(b"OPA_TEAM_NAME=\x80\x81bad")
    assert engine._read_dotenv_text(str(p)) == ""
    assert "ignoring" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# ENG2-06: a network failure mid-run keeps the record
# ---------------------------------------------------------------------------
def test_a_network_failure_mid_plan_returns_every_row(no_sleep):
    class Flaky(FolderClient):
        def create_folder(self, rg, proj, name, description, parent_id=None):
            if len(self.created) == 2:
                raise engine.OpaApiError(engine.API_STATUS_NETWORK, "u", "URLError: down")
            return super().create_folder(rg, proj, name, description, parent_id)

    client = Flaky(tree={})
    ordered = [("A",), ("B",), ("C",), ("D",), ("A", "x")]
    results = engine.execute_plan(client, "rg", "proj", ordered, {}, {})
    assert [r[2] for r in results] == ["created", "created", "error", "error", "error"]
    assert results[3][3] == engine.NOT_ATTEMPTED_AFTER_NETWORK_FAILURE
    assert len(client.created) == 2


def test_execute_route_still_audits_when_the_results_file_cannot_be_written(matrix_server, monkeypatch, tmp_audit_log):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = FolderClient(tree={})

    def unwritable(path, results):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(engine, "write_results_csv", unwritable)
    resp = _call(base_url, "POST", "/api/execute", {"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A"}]},
                 _who(OWNER_A))
    assert resp.status_code == 200 and resp.json()["output_file"] is None
    actions = [json.loads(l)["action"] for l in tmp_audit_log.read_text().splitlines()]
    assert "folders.execute" in actions


# ---------------------------------------------------------------------------
# ENG2-07 / ENG2-08 / ENG2-10 / ENG2-11: access model
# ---------------------------------------------------------------------------
class ModelClient:
    def __init__(self, deny=()):
        self.deny = set(deny)
        self.user_group_threads = set()

    def _maybe(self, name, value):
        if name in self.deny:
            raise engine.OpaApiError(403, name, "Missing capability")
        return value

    def list_resource_groups(self):
        return [{"id": "rg1", "name": "RG"}]

    def list_groups(self):
        return []

    def list_users(self):
        return [{"name": f"u{i}"} for i in range(6)]

    def list_workload_roles(self):
        return self._maybe("workload_roles", [])

    def list_workload_connections(self):
        return self._maybe("workload_connections", [])

    def list_gateways(self):
        return self._maybe("gateways", [])

    def list_database_connections(self):
        return self._maybe("database_connections", [])

    def list_saas_app_connections(self):
        return self._maybe("saas", [])

    def list_active_directory_connections(self):
        return self._maybe("ad", [])

    def list_assignments(self):
        return self._maybe("assignments", [{"id": "as1", "name": "A1"}, {"id": "as2", "name": "A2"}])

    def get_assignment(self, assignment_id):
        principal = {"as1": {"id": "g1", "name": "G1"}, "as2": {"id": "g2", "name": "G2"}}[assignment_id]
        secret = {"as1": "S1", "as2": "S2"}[assignment_id]
        return {
            "id": assignment_id, "name": assignment_id,
            "relationship_assignments": [{"relationship": {"id": "rel", "name": "R"}, "principal": principal}],
            "resource_assignments": {"secret_or_folder_assignments": [{"id": secret, "name": secret, "type": "secret"}]},
        }

    def list_relationships(self):
        return [{"id": "rel", "name": "R"}]

    def list_clients(self):
        return self._maybe("clients", [])

    def list_projects(self, rg):
        return [{"id": "p1", "name": "P1"}]

    def list_folders(self, rg, proj):
        return [{"id": "f1", "name": None, "type": "folder"}]  # ENG2-11: a folder with no name

    def list_folder_items(self, rg, proj, fid):
        return []

    def list_project_servers(self, rg, proj):
        return self._maybe("servers", [])

    def list_project_saas_app_accounts(self, rg, proj):
        return []

    def list_project_okta_ud_accounts(self, rg, proj):
        return []

    def list_project_active_directory_accounts(self, rg, proj):
        return []

    def list_project_database_accounts(self, rg, proj):
        return self._maybe("db_accounts", [])

    def list_user_groups(self, name):
        self.user_group_threads.add(threading.current_thread().name)
        time.sleep(0.02)
        return [{"id": f"g-{name}"}]

    def list_security_policies(self):
        return [
            {"id": "pol-null", "name": "N", "rules": None, "principals": None},
            {"id": "pol-rel", "name": "Rel", "relationships": [{"id": "rel"}],
             "rules": [{"name": "r", "privileges": None, "conditions": None, "resource_selector": None}]},
        ]


def test_one_forbidden_inventory_list_no_longer_sinks_the_model():
    model = engine.build_access_model(ModelClient(deny={"gateways", "db_accounts"}))
    assert model["gateways"] == [] and model["database_accounts"] == []
    sections = {w["section"] for w in model["warnings"]}
    assert "gateways" in sections and any(s.startswith("database accounts") for s in sections)


def test_a_forbidden_core_list_still_fails_the_model():
    class NoGroups(ModelClient):
        def list_resource_groups(self):
            raise engine.OpaApiError(403, "rg", "Missing capability")

    with pytest.raises(engine.OpaApiError):
        engine.build_access_model(NoGroups())


def test_user_groups_are_fetched_in_parallel_and_keep_user_order():
    client = ModelClient()
    model = engine.build_access_model(client)
    assert [u["name"] for u in model["users"]] == [f"u{i}" for i in range(6)]
    assert [u["groups"] for u in model["users"]] == [[{"id": f"g-u{i}"}] for i in range(6)]
    assert len(client.user_group_threads) > 1
    assert engine.USER_GROUP_WORKERS <= engine.RATE_LIMIT_MIN_REMAINING


def test_null_policy_fields_and_relationship_principals_are_handled():
    model = engine.build_access_model(ModelClient())
    by_id = {p["id"]: p for p in model["policies"]}
    assert by_id["pol-null"]["rules"] == [] and by_id["pol-null"]["principals"] == {}
    resolutions = by_id["pol-rel"]["rules"][0]["resolutions"]
    pairs = {(r["id"], r["principal_name"]) for r in resolutions}
    assert pairs == {("S1", "G1"), ("S2", "G2")}  # ENG2-10: each resource carries ITS assignment's principal


def test_summarize_and_full_path_tolerate_nulls():
    summary = engine.summarize_security_policy({"id": "p", "rules": [{"privileges": None, "conditions": None}], "principals": None})
    assert summary["rules"][0]["privileges"] == [] and summary["principals"] == {"user_groups": [], "workload_roles": []}
    assert engine.full_path({"name": None, "parent_id": "a"}, {"a": {"name": "A", "parent_id": None}}) == "A/?"
    loop = {"a": {"name": "A", "parent_id": "b"}, "b": {"name": "B", "parent_id": "a"}}
    assert engine.full_path(loop["a"], loop) in ("B/A", "A/B/A")


# ---------------------------------------------------------------------------
# ENG2-12: name validation and CSV parsing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,ok", [
    ("DB", True), ("a.b-c_d", True), (".", False), ("..", False), ("x" * 255, True), ("x" * 256, False),
    ("a b", False), ("", False), ("a\n", False), (None, False),
])
def test_is_valid_folder_name(name, ok):
    assert engine.is_valid_folder_name(name) is ok


@pytest.mark.parametrize("header", ["path,description", " Path ,Description", "PATH,description", "﻿path,description"])
def test_parse_csv_accepts_padded_or_capitalised_headers(tmp_path, header):
    p = tmp_path / "f.csv"
    p.write_text(f"{header}\nA/B,desc\n", encoding="utf-8")
    ordered, descriptions = engine.parse_csv(str(p))
    assert ordered == [("A",), ("A", "B")] and descriptions == {("A", "B"): "desc"}


def test_parse_csv_non_utf8_is_a_clean_exit(tmp_path):
    p = tmp_path / "f.csv"
    p.write_bytes("path\nCafé\n".encode("latin-1"))
    with pytest.raises(SystemExit):
        engine.parse_csv(str(p))


def test_case_variant_names_are_warned():
    variants = engine.detect_case_variant_names([("DB",), ("x",), ("x", "db")])
    assert variants == {"db": [("DB",), ("x", "db")]}
    assert engine.detect_case_variant_names([("DB",), ("x", "DB")]) == {}


@pytest.mark.parametrize("rows", [[{"path": 5}], [{"path": ["a"]}], ["A/B"], [{"path": "A", "description": 3}]])
def test_non_string_rows_are_a_400_not_a_500(matrix_server, rows):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = FolderClient(tree={})
    resp = _call(base_url, "POST", "/api/preview", {"resource_group_id": RG, "project_id": PROJ, "rows": rows}, _who(OWNER_A))
    assert resp.status_code == 400, resp.text


def test_dot_names_are_invalid_in_preview(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    with serve._sessions_lock:
        serve._sessions[OWNER_A]["client"] = FolderClient(tree={})
    resp = _call(base_url, "POST", "/api/preview", {"resource_group_id": RG, "project_id": PROJ, "rows": [{"path": "A/.."}]},
                 _who(OWNER_A))
    assert resp.status_code == 200
    assert resp.json()["invalid_names"] == [{"path": "A/..", "name": ".."}]


# ---------------------------------------------------------------------------
# ENG2-13: CLI credentials and output file
# ---------------------------------------------------------------------------
CLI_VARS = ("OPA_BASE_DOMAIN", "OPA_TEAM_NAME", "OPA_KEY_ID", "OPA_KEY_SECRET")


def test_cli_refuses_a_partial_environment_instead_of_mixing_sources(monkeypatch):
    for name in CLI_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPA_TEAM_NAME", "sandbox")
    monkeypatch.setattr(engine, "get_active_environment_credentials",
                        lambda: pytest.fail("must not fall back to the dashboard environment"))
    with pytest.raises(SystemExit):
        engine._resolve_cli_credentials()


def test_cli_uses_all_four_from_one_source(monkeypatch):
    for name in CLI_VARS:
        monkeypatch.delenv(name, raising=False)
    active = {"name": "prod", "base_domain": "b.example.com", "team_name": "t", "key_id": "k", "key_secret": "s"}
    monkeypatch.setattr(engine, "get_active_environment_credentials", lambda: active)
    assert engine._resolve_cli_credentials() == ("b.example.com", "t", "k", "s")
    for name, value in zip(CLI_VARS, ("e.example.com", "te", "ke", "se")):
        monkeypatch.setenv(name, value)
    assert engine._resolve_cli_credentials() == ("e.example.com", "te", "ke", "se")


def test_cli_does_not_overwrite_output_and_checks_it_before_creating(tmp_path, monkeypatch):
    csv_path = tmp_path / "in.csv"
    csv_path.write_text("path\nA\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    out.write_text("precious", encoding="utf-8")
    for name, value in zip(CLI_VARS, ("e.example.com", "te", "ke", "se")):
        monkeypatch.setenv(name, value)
    client = FolderClient(tree={})
    monkeypatch.setattr(engine, "OpaClient", lambda *a: client)
    monkeypatch.setattr(sys, "argv", ["x", "--csv", str(csv_path), "--resource-group-id", "rg", "--project-id", "p",
                                      "--execute", "--output", str(out)])
    with pytest.raises(SystemExit):
        engine.main()
    assert out.read_text(encoding="utf-8") == "precious" and client.created == []
    monkeypatch.setattr(sys, "argv", sys.argv + ["--force"])
    engine.main()
    assert client.created == [("A", None)]
    assert "created" in out.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ENG2-15: results CSV neutralises formula cells
# ---------------------------------------------------------------------------
def test_results_csv_neutralises_formula_leading_cells(tmp_path):
    out = tmp_path / "r.csv"
    engine.write_results_csv(str(out), [(("-A1",), "id", "created", ""), (("ok",), "=cmd", "error", "@x")])
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[1][0] == "'-A1" and rows[2][1] == "'=cmd" and rows[2][3] == "'@x" and rows[2][0] == "ok"


# ---------------------------------------------------------------------------
# Mutation-check follow-ups
# ---------------------------------------------------------------------------
def test_an_unusable_retry_after_falls_through_to_the_reset_header():
    date = "Thu, 01 Jan 2026 00:00:00 GMT"
    reset = str(int(datetime(2026, 1, 1, 0, 0, 40, tzinfo=timezone.utc).timestamp()))
    for bad in ("nan", "-5"):
        wait = engine._retry_after_secs(_headers(Retry_After=bad, Date=date, x_ratelimit_reset=reset))
        assert wait == pytest.approx(40 + engine.RATE_LIMIT_WAIT_BUFFER_SECS), bad


def test_the_environment_lookup_runs_inside_the_write_transaction(tmp_audit_store, fake_keyring, monkeypatch):
    """ENG1-07: the (owner, name) lookup must happen inside BEGIN IMMEDIATE,
    so another PROCESS can't insert the same name between lookup and
    insert (the in-process _db_lock alone can't stop that)."""
    audit_store.run_migrations()
    seen = []
    real_find = engine._find_own_environment_sql

    def spy(conn, owner, name):
        seen.append(conn.in_transaction)
        return real_find(conn, owner, name)

    monkeypatch.setattr(engine, "_find_own_environment_sql", spy)
    engine.upsert_environment("dev", GOOD)
    assert seen == [True]


# ---------------------------------------------------------------------------
# Opus review round 1 follow-ups
# ---------------------------------------------------------------------------
def test_policy_put_goes_out_without_rate_limit_waits_and_after_a_fresh_wait(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    client = PolicyClient(_policy())
    _with_client(serve, client)
    assert _assign(base_url, BASE_BODY).status_code == 200
    assert client.put_waits == [False] and client.waits == 1


def test_a_429_on_the_policy_put_re_waits_and_re_reads_before_retrying(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)

    class Limited(PolicyClient):
        def update_security_policy(self, policy_id, body, rate_limit_wait=True):
            if not getattr(self, "limited_once", False):
                self.limited_once = True
                raise engine.OpaApiError(429, "u", "slow down")
            super().update_security_policy(policy_id, body, rate_limit_wait)

    client = Limited(_policy())
    _with_client(serve, client)
    assert _assign(base_url, BASE_BODY).status_code == 200
    assert client.waits == 2 and client.gets == 4 and len(client.puts) == 1  # first read, 2 re-reads, final read


def test_http_json_request_without_rate_limit_wait_neither_waits_nor_retries(monkeypatch, no_sleep):
    url = "https://nowait.example.com/x"
    engine._record_rate_limit(url, _headers(x_ratelimit_remaining="0", x_ratelimit_reset=str(int(time.time()) + 60)))
    opener = _ScriptedOpener([_FakeHTTPError(url, 429, _headers(Retry_After="5")), _Resp(b"{}")])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError) as exc_info:
        engine.http_json_request("PUT", url, body={}, rate_limit_wait=False)
    assert exc_info.value.status == 429 and no_sleep == [] and opener.calls == ["PUT"]
    with engine._rate_limit_lock:
        engine._rate_limit_state.pop("nowait.example.com", None)


def test_keychain_is_never_touched_while_the_db_lock_is_held(tmp_audit_store, fake_keyring, monkeypatch):
    audit_store.run_migrations()
    held = []
    real_get, real_set = engine.keyring_get, engine.keyring_set
    monkeypatch.setattr(engine, "keyring_get", lambda *a: (held.append(audit_store._db_lock.locked()), real_get(*a))[1])
    monkeypatch.setattr(engine, "keyring_set", lambda *a: (held.append(audit_store._db_lock.locked()), real_set(*a))[1])
    engine.upsert_environment("dev", GOOD)
    engine.upsert_environment("dev", {**GOOD, "key_secret": "", "okta_api_token": "T"})
    assert held and not any(held)


def test_an_update_without_a_secret_keeps_the_stored_one(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment("dev", GOOD)
    engine.upsert_environment("dev", {**GOOD, "key_secret": "", "team_name": "t2"})
    assert fake_keyring[(env_id, "key_secret")] == "OLD"
    assert engine.list_environments_for(None)["dev"]["team_name"] == "t2"


def test_an_existing_duplicate_row_can_still_be_edited(tmp_audit_store, fake_keyring):
    """An install where the old race already made two local 'dev' rows must
    not be locked out of editing them by the new duplicate-name check."""
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment("dev", GOOD)
    conn = audit_store._get_connection()
    conn.execute(
        "INSERT INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name, key_id, okta_url,"
        " shared, created_at, updated_at) SELECT 'dup-id', owner_id, display_name, base_domain, team_name, key_id,"
        " okta_url, shared, created_at, updated_at FROM app_environments WHERE environment_id = ?", (env_id,))
    conn.commit()
    engine.upsert_environment("dev", {**GOOD, "team_name": "edited"})


def test_a_failed_create_keychain_write_removes_the_row(tmp_audit_store, fake_keyring, monkeypatch):
    audit_store.run_migrations()

    def failing(storage_name, field, value):
        raise RuntimeError("keychain write failed")

    monkeypatch.setattr(engine, "keyring_set", failing)
    with pytest.raises(RuntimeError):
        engine.upsert_environment("dev", GOOD)
    assert engine.list_environments_for(None) == {}


def test_sync_start_with_a_locked_keychain_is_a_recorded_refusal(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)

    def locked(*a, **k):
        raise engine.CredentialStoreUnavailable("The OS credential store could not be read (KeyringLocked).")

    monkeypatch.setattr(engine, "get_environment_credentials_by_id", locked)  # by id since 5.42.0
    assert serve._start_sync_job(env_id, "dev", "curated", owner=OWNER_A, trigger="scheduled") is False
    state = audit_store.get_sync_state(env_id)
    assert state["last_sync_status"] == "error" and state["last_sync_attempt_at"]


def test_a_locked_keychain_at_first_contact_is_retried_on_the_next_request(matrix_server, monkeypatch):
    base_url, serve = matrix_server

    def locked(*a, **k):
        raise engine.CredentialStoreUnavailable("locked")

    monkeypatch.setattr(engine, "restorable_active_environment_credentials", locked)
    with serve._sessions_lock:
        serve._seen_owners.discard("00uFRESH")
    serve._ensure_session_initialized("00uFRESH")
    with serve._sessions_lock:
        assert "00uFRESH" not in serve._seen_owners


def test_concurrent_401s_refresh_the_token_once():
    barrier = threading.Barrier(4)

    class Client(_PagingOpa):
        fetched = 0

        def _fetch_token(self):
            Client.fetched += 1
            time.sleep(0.05)
            self.bearer_token = "fresh"

        def _raw_request(self, *a, **k):
            if self.bearer_token == "tok":
                try:
                    barrier.wait(1)
                except threading.BrokenBarrierError:
                    pass
                raise engine.OpaApiError(401, "u", "expired")
            return {"ok": True}

    client = Client([])
    results = []
    threads = [threading.Thread(target=lambda: results.append(client.request("GET", "/x"))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [{"ok": True}] * 4 and Client.fetched == 1


def test_a_held_audit_lock_times_out_into_the_in_process_fallback(tmp_audit_log, monkeypatch, capsys):
    import subprocess
    if sys.platform.startswith("win"):
        pytest.skip("POSIX flock child")
    monkeypatch.setattr(engine, "AUDIT_LOG_LOCK_WAIT_SECS", 0.2)
    lock_path = engine._audit_log_lock_path(str(tmp_audit_log))
    script = (
        "import fcntl, os, time\n"
        f"fd = os.open({lock_path!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\n"
        "print('locked', flush=True)\n"
        "time.sleep(3)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        start = time.monotonic()
        engine.log_audit_event(None, None, "x.fallback")
        assert time.monotonic() - start < 2
    finally:
        child.kill()
        child.wait(5)
    assert "x.fallback" in tmp_audit_log.read_text()
    assert "cross-process lock unavailable" in capsys.readouterr().err


def test_an_older_world_readable_audit_log_is_narrowed(tmp_audit_log):
    tmp_audit_log.write_text("", encoding="utf-8")
    os.chmod(tmp_audit_log, 0o644)
    engine.log_audit_event(None, None, "x.test")
    assert (os.stat(tmp_audit_log).st_mode & 0o777) == 0o600


def test_null_sync_schedule_falls_back_to_defaults(tmp_audit_store, fake_keyring, monkeypatch):
    audit_store.run_migrations()
    engine.upsert_environment("dev", GOOD)
    real = engine.list_environments_for
    monkeypatch.setattr(engine, "list_environments_for",
                        lambda owner: {n: {**m, "sync_schedule": None} for n, m in real(owner).items()})
    assert engine.get_sync_schedule("dev")["run_time"] == engine.SYNC_SCHEDULE_DEFAULTS["run_time"]


def test_a_failed_deep_verify_is_not_reused(serve_module, monkeypatch):
    calls = []

    def flaky(environment_id, deep=False):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        return {"valid": True, "deep": deep}

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", flaky)
    assert serve_module._deep_verify(ENV, wait_secs=5)[0] == 500
    assert serve_module._deep_verify(ENV, wait_secs=5)[0] == 200


def test_a_thread_that_cannot_start_leaves_no_running_job(serve_module, monkeypatch):
    class NoThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(serve_module.threading, "Thread", NoThread)
    with pytest.raises(RuntimeError):
        serve_module._deep_verify(ENV, wait_secs=0.1)
    assert ENV not in serve_module._deep_verify_jobs


def test_deep_verify_route_answers_202_while_running(matrix_server, monkeypatch):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    release = threading.Event()

    def slow(environment_id, deep=False):
        release.wait(5)
        return {"valid": True, "deep": deep}

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", slow)
    monkeypatch.setattr(serve, "DEEP_VERIFY_WAIT_SECS", 0.05)
    with serve._deep_verify_lock:
        serve._deep_verify_jobs.clear()
    resp = _call(base_url, "GET", "/api/environments/dev/integrity?deep=1", headers=_who(OWNER_A, admin=True))
    assert resp.status_code == 202 and resp.json()["status"] == "running"
    release.set()
    monkeypatch.setattr(serve, "DEEP_VERIFY_WAIT_SECS", 5)
    resp = _call(base_url, "GET", "/api/environments/dev/integrity?deep=1", headers=_who(OWNER_A, admin=True))
    assert resp.status_code == 200 and resp.json()["valid"] is True
    with serve._deep_verify_lock:
        serve._deep_verify_jobs.clear()


# ---------------------------------------------------------------------------
# Opus review round 2 follow-ups
# ---------------------------------------------------------------------------
def test_a_deep_verify_failure_after_the_wait_is_reported_once_then_retried(serve_module, monkeypatch):
    release = threading.Event()
    runs = []

    def late_failure(environment_id, deep=False):
        runs.append(1)
        if len(runs) == 1:
            release.wait(5)
            raise RuntimeError("deterministic failure")
        return {"valid": True, "deep": deep}

    monkeypatch.setattr(audit_store, "verify_ingestion_chain", late_failure)
    assert serve_module._deep_verify(ENV, wait_secs=0.05)[0] == 202
    release.set()
    serve_module._deep_verify_jobs[ENV]["event"].wait(5)
    status, body = serve_module._deep_verify(ENV, wait_secs=0.05)
    assert status == 500 and runs == [1]           # the poller learns of the failure; no new pass
    assert serve_module._deep_verify(ENV, wait_secs=5)[0] == 200  # the next request retries
    assert len(runs) == 2


def test_a_bare_retry_after_429_is_waited_out_by_the_caller(monkeypatch, no_sleep):
    url = "https://bare429.example.com/v1/teams/t/security_policy/p"
    opener = _ScriptedOpener([_FakeHTTPError(url, 429, _headers(Retry_After="30"))])
    monkeypatch.setattr(engine, "_SAFE_OPENER", opener)
    with pytest.raises(engine.OpaApiError):
        engine.http_json_request("PUT", url, body={}, rate_limit_wait=False)
    assert no_sleep == []
    engine._wait_if_rate_limited(url)
    assert no_sleep and 29 <= no_sleep[0] <= 31 + engine.RATE_LIMIT_WAIT_BUFFER_SECS
    with engine._rate_limit_lock:
        engine._rate_limit_state.pop("bare429.example.com", None)


def test_the_backfill_rewrite_refuses_to_run_without_the_os_lock(tmp_audit_log, monkeypatch):
    monkeypatch.setattr(engine, "_lock_fd", lambda fd, wait: False)
    with pytest.raises(engine.MfaBackfillBusy):
        with engine._audit_log_exclusive(str(tmp_audit_log), require_os_lock=True):
            pytest.fail("must not get here")


def test_a_failed_os_lock_is_not_retried_for_a_while(tmp_audit_log, monkeypatch):
    attempts = []
    monkeypatch.setattr(engine, "_audit_os_lock_down_until", 0.0)
    monkeypatch.setattr(engine, "_lock_fd", lambda fd, wait: attempts.append(1) and False)
    for _ in range(3):
        engine.log_audit_event(None, None, "x.memo")
    assert len(attempts) == 1
    assert tmp_audit_log.read_text().count("x.memo") == 3


def test_a_cross_origin_link_to_another_collection_is_refused():
    client = _PagingOpa([({"list": [1]}, _link("https://other.example.com/v1/teams/t/secrets?page=2"))])
    with pytest.raises(engine.OpaApiError, match="different collection"):
        client._list("/v1/teams/t/things")


def test_the_cross_origin_warning_is_logged_once_per_walk(capsys):
    pages = [({"list": [i]}, _link(f"https://other.example.com/v1/teams/t/things?page={i + 1}")) for i in range(4)]
    client = _PagingOpa(pages + [({"list": [9]}, Message())])
    client._list("/v1/teams/t/things")
    out = capsys.readouterr()
    assert (out.out + out.err).count("names another origin") == 1


def test_the_row_undo_never_reverts_a_newer_write(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, env_id = engine.upsert_environment("dev", GOOD)
    conn = audit_store._get_connection()
    row = dict(conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (env_id,)).fetchone())
    ours = {col: row[col] for col in engine._ENVIRONMENT_ROW_COLUMNS}
    # Another write in the SAME second: updated_at unchanged, team_name changed.
    conn.execute("UPDATE app_environments SET team_name = 'newer' WHERE environment_id = ?", (env_id,))
    conn.commit()
    engine._undo_environment_row(conn, env_id, False, {**ours, "team_name": "older"}, ours)
    assert engine.list_environments_for(None)["dev"]["team_name"] == "newer"
    # Still ours -> undone.
    current = dict(conn.execute("SELECT * FROM app_environments WHERE environment_id = ?", (env_id,)).fetchone())
    engine._undo_environment_row(conn, env_id, False, {**ours, "team_name": "older"},
                                 {col: current[col] for col in engine._ENVIRONMENT_ROW_COLUMNS})
    assert engine.list_environments_for(None)["dev"]["team_name"] == "older"


def test_an_unusable_lock_file_is_reported_as_such_not_as_busy(tmp_audit_log, monkeypatch):
    real_open = os.open

    def deny(path, *a, **k):
        if str(path).endswith(".lock"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(engine.os, "open", deny)
    with pytest.raises(engine.MfaBackfillBusy, match="owner and permissions"):
        with engine._audit_log_exclusive(str(tmp_audit_log), require_os_lock=True):
            pass


def test_missing_metadata_is_reported_before_a_missing_secret(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    with pytest.raises(ValueError, match="base_domain"):
        engine.upsert_environment("dev", {})
