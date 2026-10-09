"""Review batch 6 (2026-10-05 review): TEST-10 (the scheduler's date math,
catch-up and back-off with an injected clock) and TEST-11 (table and seeded
property tests for the small parsers: dotenv values, the Link header, folder
names, the CSV row <-> tree round trip)."""

import random
from datetime import datetime, timedelta, timezone
from email.message import Message

import pytest

import create_secret_folders as engine

# --- TEST-10: _scheduler_tick ----------------------------------------------------


@pytest.fixture
def tick(monkeypatch):
    import audit_store
    import server.serve as serve

    envs, schedules, states, started = {}, {}, {}, []
    monkeypatch.setattr(engine, "list_all_environments", lambda: envs)

    def get_schedule(name, owner=None):
        if name not in schedules:
            raise KeyError(name)
        return schedules[name]

    monkeypatch.setattr(engine, "get_sync_schedule", get_schedule)
    monkeypatch.setattr(audit_store, "get_sync_state", lambda env_id: states.get(env_id))
    monkeypatch.setattr(serve, "_start_sync_job", lambda *a, **k: started.append((a, k)))

    def run(now):
        started.clear()
        serve._scheduler_tick(now)
        return [(a[0], k.get("minutes_late")) for a, k in started]

    def add(env_id, name, owner="__local__", **schedule):
        envs[env_id] = {"name": name, "owner": owner}
        schedules[name] = {"enabled": True, "run_time": "02:00", **schedule}
        return env_id

    return run, add, states, schedules


def _utc(h, m, day=9):
    return datetime(2026, 10, day, h, m, tzinfo=timezone.utc)


def test_not_before_the_run_time_then_once_that_day(tick):
    run, add, states, _ = tick
    add("e1", "prod", run_time="02:00")
    assert run(_utc(1, 59)) == []
    assert run(_utc(2, 0)) == [("e1", None)]
    states["e1"] = {"last_sync_completed_at": "2026-10-09T02:03:00+00:00", "last_sync_status": "success"}
    assert run(_utc(23, 59)) == []           # already ran today (UTC)
    assert run(_utc(2, 0, day=10)) == [("e1", None)]  # next UTC day


def test_catch_up_after_downtime_reports_how_late(tick, monkeypatch):
    import server.serve as serve

    run, add, states, _ = tick
    add("e1", "prod", run_time="02:00")
    states["e1"] = {"last_sync_completed_at": "2026-10-08T02:01:00+00:00", "last_sync_status": "success"}
    late = run(_utc(9, 30))
    assert late == [("e1", 7 * 60 + 30)]
    assert run(_utc(2, serve.SCHEDULER_LATE_THRESHOLD_MINUTES)) == [("e1", None)]  # within the poll slack


def test_a_completion_dated_in_utc_not_local_time(tick):
    """The original bug: a sync finishing at 5:04pm PDT is already the next
    UTC day; 'already ran today' compares UTC dates."""
    run, add, states, _ = tick
    add("e1", "prod", run_time="00:00")
    states["e1"] = {"last_sync_completed_at": "2026-10-10T00:04:00+00:00", "last_sync_status": "success"}
    assert run(_utc(0, 30, day=10)) == []


def test_back_off_after_a_failed_or_stuck_attempt(tick, monkeypatch):
    import server.serve as serve

    run, add, states, _ = tick
    add("e1", "prod")
    attempt = _utc(3, 0)
    for status in ("error", "running"):
        states["e1"] = {"last_sync_attempt_at": attempt.isoformat(), "last_sync_status": status}
        assert run(attempt + timedelta(seconds=serve.SCHEDULER_RETRY_BACKOFF_SECS - 60)) == []
        assert run(attempt + timedelta(seconds=serve.SCHEDULER_RETRY_BACKOFF_SECS)) != []
    states["e1"] = {"last_sync_attempt_at": "not a time", "last_sync_status": "error"}
    assert run(_utc(4, 0)) == [("e1", 120)]  # unparseable attempt never blocks the retry
    states["e1"] = {"last_sync_attempt_at": attempt.isoformat(), "last_sync_status": "success",
                    "last_sync_completed_at": "2026-10-08T02:00:00+00:00"}
    assert run(attempt + timedelta(minutes=1)) != []  # a success is not backed off


def test_disabled_missing_and_bad_schedules(tick):
    run, add, _, schedules = tick
    add("e1", "off", enabled=False)
    add("e2", "bad", run_time="nonsense")
    add("e3", "gone")
    del schedules["gone"]
    assert run(_utc(1, 0)) == []
    assert run(_utc(2, 0)) == [("e2", None)]  # a malformed run_time falls back to 02:00


def test_every_owner_and_every_environment_is_considered(tick):
    run, add, _, _ = tick
    add("e1", "prod", owner="00uA")
    add("e2", "prod2", owner="00uB", run_time="05:00")
    assert sorted(run(_utc(6, 0))) == [("e1", 240), ("e2", 60)]


def test_the_loop_survives_a_failing_tick(monkeypatch):
    import server.serve as serve

    calls, events = [], []

    def boom(now):
        calls.append(now)
        serve._scheduler_stop_event.set()
        raise RuntimeError("db locked")

    monkeypatch.setattr(serve, "_scheduler_tick", boom)
    monkeypatch.setattr(engine, "log_audit_event", lambda *a, **k: events.append(a[2]))
    serve._scheduler_stop_event.clear()
    try:
        serve._scheduler_loop()
    finally:
        serve._scheduler_stop_event.clear()
    assert len(calls) == 1 and events == ["sync.scheduler_error"]


# --- TEST-11: parsers -----------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("plain", "plain"),
    ("  padded  ", "padded"),
    ("my#secret", "my#secret"),                   # no space before '#': part of the value
    ("value # comment", "value"),
    ("value\t# comment", "value"),
    ("# only a comment", ""),
    ('"quoted # not a comment"', "quoted # not a comment"),
    ('"quoted" # trailing comment', "quoted"),
    ("'single'", "single"),
    ('"unterminated', '"unterminated'),           # passes through as is (pinned)
    ('""', ""),
    ("a=b=c", "a=b=c"),
])
def test_dotenv_values(raw, expected):
    assert engine._parse_dotenv_value(raw) == expected


def test_dotenv_never_truncates_a_secret_without_a_space_before_hash():
    rng = random.Random(20261009)
    alphabet = "abcXYZ0123456789#!$%^&*()-_=+[]{};:,.<>/?~"
    for _ in range(500):
        secret = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40))).lstrip("#")
        if not secret or secret[0] in "\"'":
            continue
        assert engine._parse_dotenv_value(secret) == secret
        assert engine._parse_dotenv_value(f'"{secret}"') == secret  # (no quote characters in the alphabet)


def _headers(*link_lines):
    msg = Message()
    for line in link_lines:
        msg["Link"] = line
    return msg


@pytest.mark.parametrize("lines,expected", [
    ([], None),
    (['<https://o.example/api/v1/logs?after=1>; rel="next"'], "https://o.example/api/v1/logs?after=1"),
    (['<https://o.example/a>; rel="self", <https://o.example/b>; rel="next"'], "https://o.example/b"),
    # Okta sends one Link header line per rel -- "next" often on the second line
    (['<https://o.example/a>; rel="self"', '<https://o.example/b>; rel="next"'], "https://o.example/b"),
    (['<https://o.example/a>; rel="self"'], None),
    (["garbage"], None),
])
def test_next_link(lines, expected):
    assert engine._parse_next_link(_headers(*lines)) == expected


def test_next_link_from_a_plain_mapping():
    assert engine._parse_next_link({"Link": '<https://o.example/b>; rel="next"'}) == "https://o.example/b"
    assert engine._parse_next_link({}) is None


@pytest.mark.parametrize("name,ok", [
    ("Prod", True), ("db-01", True), ("a_b.c", True), ("x" * engine.FOLDER_NAME_MAX_LEN, True),
    ("x" * (engine.FOLDER_NAME_MAX_LEN + 1), False), (".", False), ("..", False), ("", False),
    ("has space", False), ("slash/inside", False), ("ünïcode", False), ("tab\t", False),
])
def test_folder_names(name, ok):
    assert engine.is_valid_folder_name(name) is ok


def test_rows_round_trip_through_the_tree():
    """parse_rows -> rows_from_tree -> parse_rows is stable, every ancestor
    is present before its children, and explicit descriptions survive."""
    rng = random.Random(4242)
    names = ["A", "B", "c-1", "d.2", "e_3"]
    for _ in range(200):
        rows = []
        for _ in range(rng.randint(1, 8)):
            depth = rng.randint(1, 4)
            path = "/".join(rng.choice(names) for _ in range(depth))
            desc = rng.choice(["", "", "note", "two words"])
            rows.append({"path": f" {path} /", "description": desc})
        ordered, descs = engine.parse_rows(rows, warn=False)
        again, descs_again = engine.parse_rows(engine.rows_from_tree(ordered, descs), warn=False)
        assert again == ordered and descs_again == descs
        seen = set()
        for path in ordered:
            assert path[:-1] in seen or len(path) == 1
            seen.add(path)
        for row in rows:
            segs = tuple(s.strip() for s in row["path"].split("/") if s.strip())
            if row["description"]:
                assert segs in descs


@pytest.mark.parametrize("bad", [["not a dict"], [{"path": 5}], [{"path": "a", "description": 3}]])
def test_rows_with_the_wrong_shape_are_a_value_error(bad):
    with pytest.raises(ValueError):
        engine.parse_rows(bad, warn=False)


# --- LNCH-07 ---------------------------------------------------------------------------


def test_reaching_audit_store_without_the_fixture_fails_loudly():
    import audit_store

    with pytest.raises(RuntimeError, match="tmp_audit_store"):
        audit_store._get_connection()


def test_the_fixture_closes_its_connection_and_restores_the_cache(tmp_path):
    """Drives tmp_audit_store's generator by hand: after teardown the
    connection it opened is closed."""
    import audit_store
    import conftest

    mp = pytest.MonkeyPatch()
    try:
        gen = conftest.tmp_audit_store.__wrapped__(tmp_path, mp)
        next(gen)
        conn = audit_store._get_connection()
        conn.execute("SELECT 1")
        with pytest.raises(StopIteration):
            next(gen)
        with pytest.raises(Exception):
            conn.execute("SELECT 1")  # closed
    finally:
        mp.undo()
