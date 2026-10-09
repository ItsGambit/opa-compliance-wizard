"""Engine-level tests for batch 2 of the 2026-10-05 external review (v5.40.3):
ENG1-05 (MFA backfill), SRV-05 (pending-action sweep) and TEST-03's
engine half (admin edit by id across same-named owners; own beats shared).
The HTTP half lives in test_http_authz_matrix.py."""
import json
import os
import threading
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def _entry(ts, action="access_control.update", sub="00uADMIN", **details):
    return {"timestamp": ts.isoformat(), "actor_email": "admin@example.com", "actor_sub": sub,
            "action": action, "details": {"okta_mfa_log_event": None, **details},
            "client_ip": None, "user_agent": None}


def _write_log(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write((item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))) + "\n")


def _read_log(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


# ---------------------------------------------------------------------------
# ENG1-05
# ---------------------------------------------------------------------------
def test_audited_writes_are_not_blocked_while_lookups_are_in_flight(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=1))])
    in_lookup, release = threading.Event(), threading.Event()

    def slow_lookup(sub, ts):
        in_lookup.set()
        release.wait(10)
        return {"uuid": "evt-1"}

    worker = threading.Thread(target=lambda: engine.backfill_mfa_log_events(slow_lookup, now=NOW))
    worker.start()
    assert in_lookup.wait(5)
    appended = threading.Thread(target=engine.log_audit_event, args=("u@example.com", "00uUSER", "environment.upsert"))
    appended.start()
    appended.join(2)
    try:
        assert not appended.is_alive(), "log_audit_event blocked behind the backfill's network lookup"
    finally:
        release.set()
        worker.join(5)
    entries = _read_log(tmp_audit_log)
    # The entry appended mid-lookup survived the rewrite, and the lookup result landed.
    assert [e["action"] for e in entries] == ["access_control.update", "environment.upsert"]
    assert entries[0]["details"]["okta_mfa_log_event"] == {"uuid": "evt-1"}


def test_a_failed_rewrite_leaves_the_original_log_intact(tmp_audit_log, monkeypatch):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=1))])
    before = open(tmp_audit_log, encoding="utf-8").read()

    def failing_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError):
        engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "evt"}, now=NOW)
    assert open(tmp_audit_log, encoding="utf-8").read() == before
    assert [p.name for p in tmp_audit_log.parent.iterdir() if p.name.startswith(".tmp-")] == []


def test_newest_entries_are_tried_first_so_old_unresolvable_ones_cannot_starve_them(tmp_audit_log):
    old = [_entry(NOW - timedelta(days=10, minutes=i)) for i in range(25)][::-1]
    newest = _entry(NOW - timedelta(minutes=5), sub="00uNEWEST")
    _write_log(tmp_audit_log, old + [newest])
    asked = []

    def lookup(sub, ts):
        asked.append(sub)
        return {"uuid": "evt-new"} if sub == "00uNEWEST" else None

    assert engine.backfill_mfa_log_events(lookup, max_lookups=20, now=NOW) == 1
    assert asked[0] == "00uNEWEST" and len(asked) == 20
    assert _read_log(tmp_audit_log)[-1]["details"]["okta_mfa_log_event"] == {"uuid": "evt-new"}


def test_failed_attempts_are_counted_and_capped(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=2))])
    calls = []
    for _ in range(engine.MFA_BACKFILL_MAX_ATTEMPTS + 2):
        engine.backfill_mfa_log_events(lambda sub, ts: calls.append(ts), now=NOW)
    assert len(calls) == engine.MFA_BACKFILL_MAX_ATTEMPTS
    assert _read_log(tmp_audit_log)[0]["details"]["okta_mfa_log_lookup_attempts"] == engine.MFA_BACKFILL_MAX_ATTEMPTS


def test_entries_older_than_okta_retention_are_not_looked_up(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(days=engine.MFA_BACKFILL_RETENTION_DAYS + 1))])
    calls = []
    assert engine.backfill_mfa_log_events(lambda sub, ts: calls.append(ts), now=NOW) == 0
    assert calls == []


def test_non_object_and_corrupt_lines_are_skipped_and_preserved(tmp_audit_log):
    _write_log(tmp_audit_log, ["123", "{not json", '"text"', _entry(NOW - timedelta(hours=1))])
    assert engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "e"}, now=NOW) == 1
    lines = [line.rstrip("\n") for line in open(tmp_audit_log, encoding="utf-8")]
    assert lines[:3] == ["123", "{not json", '"text"']
    entries = engine.read_audit_log()
    assert len(entries) == 1 and entries[0]["details"]["okta_mfa_log_event"] == {"uuid": "e"}


def test_nothing_to_do_never_rewrites_the_file(tmp_audit_log, monkeypatch):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=1), action="banner.update")])
    monkeypatch.setattr(engine, "_atomic_write_text", lambda *a, **k: pytest.fail("rewrote the log"))
    assert engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "e"}, now=NOW) == 0


def test_rewrite_keeps_the_logs_existing_permissions(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=1))])
    os.chmod(tmp_audit_log, 0o640)
    engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "e"}, now=NOW)
    assert oct(os.stat(tmp_audit_log).st_mode & 0o777) == oct(0o640)


# ---------------------------------------------------------------------------
# SRV-05
# ---------------------------------------------------------------------------
def test_creating_a_pending_action_sweeps_expired_abandoned_ones(tmp_audit_store):
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    expired = audit_store.create_pending_admin_action("00uA", "access_control.update", {"x": 1}, ttl_seconds=-7200)
    just_expired = audit_store.create_pending_admin_action("00uA", "access_control.update", {"x": 9}, ttl_seconds=-60)
    consumed = audit_store.create_pending_admin_action("00uA", "access_control.update", {"x": 2}, ttl_seconds=60)
    audit_store.consume_pending_admin_action(consumed, "00uA")
    conn.execute("UPDATE pending_admin_actions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE action_id = ?", (consumed,))
    conn.commit()
    live = audit_store.create_pending_admin_action("00uA", "access_control.update", {"x": 3}, ttl_seconds=60)
    remaining = {row["action_id"] for row in conn.execute("SELECT action_id FROM pending_admin_actions")}
    # The long-abandoned one is gone; a consumed one (an applied change) and
    # the new live one stay; one that expired moments ago stays for an hour
    # so its owner still gets the accurate "expired" rather than "not_found".
    assert remaining == {consumed, live, just_expired}
    assert expired not in remaining
    with pytest.raises(audit_store.PendingActionError) as err:
        audit_store.consume_pending_admin_action(just_expired, "00uA")
    assert err.value.reason == "expired"


# ---------------------------------------------------------------------------
# TEST-03 (engine half)
# ---------------------------------------------------------------------------
def _env(name, owner, domain, secret):
    return engine.upsert_environment(
        name, {"base_domain": domain, "team_name": "t", "key_id": "k", "key_secret": secret}, owner=owner,
    )


def test_admin_edit_by_id_targets_exactly_that_row_among_same_named_owners(tmp_audit_store, fake_keyring):
    """M18: an admin edit that ignored environment_id and fell back to a
    by-name scan would land on whichever same-named row came first."""
    audit_store.run_migrations()
    _, id_a = _env("dev", "00uOWNERA", "a.example.com", "secret-a")
    _, id_b = _env("dev", "00uOWNERB", "b.example.com", "secret-b")
    _, id_admin = _env("dev", "00uADMIN", "admin.example.com", "secret-admin")
    for target, other in ((id_b, id_a), (id_a, id_b)):
        name, edited = engine.upsert_environment(
            "dev", {"base_domain": f"fixed-{target[:4]}.example.com", "team_name": "t", "key_id": "k", "key_secret": ""},
            owner="00uADMIN", is_admin=True, environment_id=target,
        )
        envs = engine.list_all_environments()
        assert edited == target
        assert envs[target]["base_domain"] == f"fixed-{target[:4]}.example.com"
        assert envs[target]["owner"] in ("00uOWNERA", "00uOWNERB")  # ownership never moves to the admin
        assert envs[id_admin]["base_domain"] == "admin.example.com"
    assert engine.keyring_get(id_a, "key_secret") == "secret-a"  # a blank secret leaves it untouched
    assert engine.keyring_get(id_b, "key_secret") == "secret-b"


def test_own_environment_wins_over_a_same_named_shared_one(tmp_audit_store, fake_keyring):
    """M20: the two-query order in list_environments_for is what keeps a
    caller's own credentials from being shadowed by someone else's share."""
    audit_store.run_migrations()
    _env("prod", "00uOTHER", "other.example.com", "s1")
    engine.set_environment_shared("prod", "00uOTHER", True)
    _, own_id = _env("prod", "00uME", "mine.example.com", "s2")
    assert engine.list_environments_for("00uME")["prod"]["environment_id"] == own_id
    assert engine.get_environment_credentials("prod", owner="00uME")["base_domain"] == "mine.example.com"


def test_an_unavailable_lookup_costs_no_attempt_and_keeps_earlier_results(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=3), sub="00uOLD"), _entry(NOW - timedelta(hours=2), sub="00uNEW")])

    def lookup(sub, ts):
        if sub == "00uNEW":
            return {"uuid": "found-first"}
        raise engine.MfaLookupUnavailable("gate down")

    for _ in range(engine.MFA_BACKFILL_MAX_ATTEMPTS + 2):
        engine.backfill_mfa_log_events(lookup, now=NOW)
    old, new = _read_log(tmp_audit_log)
    assert new["details"]["okta_mfa_log_event"] == {"uuid": "found-first"}
    assert "okta_mfa_log_lookup_attempts" not in old["details"]  # an outage never uses up attempts
    # ...so once the gate is back, the entry is still looked up.
    assert engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "late"}, now=NOW) == 1


def test_a_transport_error_raised_by_the_lookup_is_treated_as_unavailable(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=2))])

    def lookup(sub, ts):
        raise TimeoutError("read timed out")

    assert engine.backfill_mfa_log_events(lookup, now=NOW) == 0
    assert "okta_mfa_log_lookup_attempts" not in _read_log(tmp_audit_log)[0]["details"]


def test_misses_during_okta_indexing_lag_are_not_counted(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(minutes=5))])
    for _ in range(engine.MFA_BACKFILL_MAX_ATTEMPTS + 3):
        engine.backfill_mfa_log_events(lambda sub, ts: None, now=NOW)
    assert "okta_mfa_log_lookup_attempts" not in _read_log(tmp_audit_log)[0]["details"]
    assert engine.backfill_mfa_log_events(lambda sub, ts: {"uuid": "indexed"}, now=NOW) == 1


def test_a_second_concurrent_backfill_returns_immediately(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=2))])
    in_lookup, release = threading.Event(), threading.Event()
    calls = []

    def slow(sub, ts):
        calls.append(sub)
        in_lookup.set()
        release.wait(10)
        return {"uuid": "e"}

    worker = threading.Thread(target=lambda: engine.backfill_mfa_log_events(slow, now=NOW))
    worker.start()
    assert in_lookup.wait(5)
    second = {}

    def race():
        try:
            second["result"] = engine.backfill_mfa_log_events(slow, now=NOW)
        except engine.MfaBackfillBusy:
            second["result"] = "busy"

    racer = threading.Thread(target=race)
    try:
        racer.start()
        racer.join(1)
        assert not racer.is_alive(), "a second Refresh waited for the first instead of returning"
        assert second["result"] == "busy"
    finally:
        release.set()
        worker.join(5)
    assert len(calls) == 1


def test_serve_lookup_reports_unavailable_rather_than_not_found(monkeypatch):
    import server.serve as serve

    monkeypatch.setattr(serve, "INTERNAL_API_SHARED_SECRET", None)
    with pytest.raises(engine.MfaLookupUnavailable):
        serve._lookup_mfa_log_event("00uA", NOW.isoformat())
    monkeypatch.setattr(serve, "INTERNAL_API_SHARED_SECRET", "x")
    monkeypatch.setattr(serve, "AUTH_GATE_INTERNAL_URL", "http://127.0.0.1:9")  # discard port: refused at once
    with pytest.raises(engine.MfaLookupUnavailable):
        serve._lookup_mfa_log_event("00uA", NOW.isoformat())


def test_every_opa_client_id_parameter_is_quoted_into_one_path_segment():
    """ENG2-16: drive EVERY OpaClient method that takes an id with a
    hostile value and check no request path gains a segment, a query or a
    fragment from it."""
    import inspect

    seen = []

    class _Client(engine.OpaClient):
        def __init__(self):
            self.team_name = "team"
            self.base_url = "https://opa.example.com"
            self._current_user = None

        def request(self, method, path, **kwargs):
            seen.append(path)
            return {}

        def _list(self, path):
            seen.append(path)
            return []

    id_params = {"resource_group_id", "project_id", "folder_id", "security_policy_id", "assignment_id", "ad_connection_id"}
    client = _Client()
    exercised = 0
    for name, fn in inspect.getmembers(engine.OpaClient, inspect.isfunction):
        params = list(inspect.signature(fn).parameters)[1:]
        if not id_params & set(params):
            continue
        args = ["../x?y#z" if p in id_params else "name" for p in params
                if inspect.signature(fn).parameters[p].default is inspect.Parameter.empty]
        seen.clear()
        getattr(client, name)(*args)
        exercised += 1
        assert seen, name
        for path in seen:
            assert "../" not in path and "?" not in path and "#" not in path, (name, path)
    assert exercised >= 15


def test_secrets_report_filter_refuses_a_hostile_project_id(monkeypatch):
    monkeypatch.setattr(engine, "fetch_all_folders_and_secrets", lambda *a, **k: ([], []))
    with pytest.raises(ValueError):
        engine.build_secrets_access_report(None, None, "rg", 'p" or eventType eq "x')


def test_an_entry_the_lookup_refuses_is_counted_and_skipped_not_a_run_stopper(tmp_audit_log):
    _write_log(tmp_audit_log, [_entry(NOW - timedelta(hours=3), sub="00uOLDER"), _entry(NOW - timedelta(minutes=5), sub="00uBAD")])

    def lookup(sub, ts):
        if sub == "00uBAD":
            raise engine.MfaLookupEntryRejected("HTTP 400")
        return {"uuid": "older-found"}

    assert engine.backfill_mfa_log_events(lookup, now=NOW) == 1  # the older entry behind it is still reached
    older, bad = _read_log(tmp_audit_log)
    assert older["details"]["okta_mfa_log_event"] == {"uuid": "older-found"}
    assert bad["details"]["okta_mfa_log_lookup_attempts"] == 1  # counted even inside the grace window


def test_restore_refuses_an_id_whose_name_is_now_shadowed(tmp_audit_store, fake_keyring):
    """Shared rule for the server restore and the CLI: A's shared "dev" (X)
    renamed to "prod" while B owns a "prod" -- restoring X by id would put
    B's session on A's tenant while every name-keyed route resolves B's own."""
    audit_store.run_migrations()
    _, x = _env("dev", "00uA", "a.example.com", "sa")
    engine.set_environment_shared("dev", "00uA", True)
    engine.set_active_environment("00uB", "dev")
    _env("prod", "00uB", "b.example.com", "sb")
    assert engine.restorable_active_environment_credentials("00uB")["environment_id"] == x
    engine.upsert_environment("prod", {"base_domain": "a.example.com", "team_name": "t", "key_id": "k", "key_secret": ""},
                              owner="00uADMIN", is_admin=True, environment_id=x)
    with pytest.raises(KeyError):
        engine.restorable_active_environment_credentials("00uB")
    assert engine.get_active_environment_credentials("00uB") is None  # the CLI path follows the same rule
    # No pointer at all is simply None.
    assert engine.restorable_active_environment_credentials("00uNOBODY") is None


def test_cli_restores_the_saved_environment_by_id(tmp_audit_store, fake_keyring):
    audit_store.run_migrations()
    _, own = _env("dev", engine.LOCAL_OWNER_KEY, "mine.example.com", "s")
    engine.set_active_environment(engine.LOCAL_OWNER_KEY, "dev")
    creds = engine.get_active_environment_credentials()
    assert creds["environment_id"] == own and creds["key_secret"] == "s" and creds["name"] == "dev"
