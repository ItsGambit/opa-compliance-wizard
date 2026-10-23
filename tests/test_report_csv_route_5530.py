"""5.53.0 (WP6): GET /api/environments/<name>/reports/<key>/export.csv.

One report's events for a UTC period as a complete CSV: no row cap, the permission of viewing the report, the same
writer the evidence package uses, an audit entry that carries no event content. Synthetic data only."""
import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine
import evidence_core as core
from test_evidence_core_5530 import evt, ingest
from test_http_authz_matrix import OWNER_A, OWNER_B, _call, _seed_owner_a_with_session, _who, matrix_server  # noqa: F401,E402

URL = "/api/environments/dev/reports/session_activity/export.csv"
RANGE = "since=2026-03-01&until=2026-03-31"


def _when(i):
    return datetime(2026, 3, 1, tzinfo=timezone.utc) + timedelta(seconds=17 * i)


def _seed(env_id, count, actor="Someone"):
    ingest([evt(f"e-{i:05d}", _when(i), actor=actor) for i in range(count)],
           since="2026-03-01T00:00:00.000Z", until="2026-04-01T00:00:00.000Z", environment_id=env_id)


def _actions(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def _parse(body):
    return list(csv.reader(io.StringIO(body.decode("utf-8"), newline="")))


def test_streams_more_than_1000_rows_and_equals_the_shared_writer_byte_for_byte(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 1250)
    resp = _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A))
    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "text/csv; charset=utf-8"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Content-Disposition"] == 'attachment; filename="opa-report-session_activity-2026-03-01-to-2026-03-31.csv"'
    assert resp.headers["X-Report-Rows"] == "1250"
    assert int(resp.headers["Content-Length"]) == len(resp.content)
    records = _parse(resp.content)
    assert len(records) == 1 + 1250                       # header + every event, past the old 1,000-row cap
    assert records[0][-1] == core.EVENT_UUID_COLUMN
    # The same snapshot through the shared writer: identical bytes.
    out = io.BytesIO()
    with core.open_snapshot(env_id, core.parse_period("2026-03-01", "2026-03-31")) as snap:
        assert core.write_report_csv(out, snap.report_rows("session_activity")) == 1250
    assert resp.content == out.getvalue()


def test_audit_entry_names_actor_report_range_and_rows_but_no_content(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 3, actor="Distinctive Display Name")
    assert _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A)).status_code == 200
    entry = _actions(tmp_audit_log)[-1]
    assert entry["action"] == "report.csv_exported"
    assert entry["actor_sub"] == OWNER_A
    assert entry["details"] == {"name": "dev", "report": "session_activity", "since": "2026-03-01", "until": "2026-03-31", "rows": 3}
    assert "Distinctive Display Name" not in json.dumps(entry)


def test_a_failed_request_writes_no_audit_entry(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    assert _call(base_url, "GET", f"{URL}?since=2026-03-31&until=2026-03-01", headers=_who(OWNER_A)).status_code == 400
    assert not tmp_audit_log.exists() or not [a for a in _actions(tmp_audit_log) if a["action"] == "report.csv_exported"]


def test_a_viewer_without_view_archive_is_refused_and_one_with_it_is_served(matrix_server, tmp_audit_log):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 2)
    engine.set_environment_shared("dev", OWNER_A, True)
    engine.set_shared_permissions({"view_archive": "deny"})
    denied = _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_B))
    assert denied.status_code == 403 and denied.json()["capability"] == "view_archive"
    assert "text/csv" not in denied.headers["Content-Type"]
    assert not tmp_audit_log.exists() or not [a for a in _actions(tmp_audit_log) if a["action"] == "report.csv_exported"]
    engine.set_shared_permissions({"view_archive": "allow"}, environment_id=env_id)
    assert _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_B)).status_code == 200


def test_a_private_environment_is_a_404_not_a_403(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    engine.set_shared_permissions({"view_archive": "deny"})
    assert _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_B)).status_code == 404


def test_the_route_is_not_behind_the_settings_unlock(matrix_server):
    import inspect
    base_url, serve = matrix_server
    assert "_require_settings_unlock" not in inspect.getsource(serve.Handler._serve_report_csv)
    assert "_require_settings_unlock" not in inspect.getsource(serve.Handler._report_csv_target)
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 1)
    assert _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A)).status_code == 200


@pytest.mark.parametrize("query", [
    "", "since=2026-03-01", "until=2026-03-31", "since=2026-03-31&until=2026-03-01", "since=2026-13-01&until=2026-03-01",
    "since=nonsense&until=2026-03-01", "since=2026-03-01&until=2999-01-01", "since=1900-01-01&until=2026-03-01",
])
def test_a_bad_period_is_a_400_with_a_reason(matrix_server, query):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    resp = _call(base_url, "GET", f"{URL}?{query}", headers=_who(OWNER_A))
    assert resp.status_code == 400 and resp.json()["error"]


def test_unknown_report_is_a_404(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    for key in ("nope", "..", "a%2Fb"):
        assert _call(base_url, "GET", f"/api/environments/dev/reports/{key}/export.csv?{RANGE}", headers=_who(OWNER_A)).status_code in (400, 404)
    assert _call(base_url, "GET", f"/api/environments/dev/reports/nope/export.csv?{RANGE}", headers=_who(OWNER_A)).status_code == 404


def test_an_empty_period_is_a_valid_file_of_one_line(matrix_server):
    base_url, serve = matrix_server
    _seed_owner_a_with_session(serve)
    resp = _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A))
    assert resp.status_code == 200 and len(_parse(resp.content)) == 1 and resp.headers["X-Report-Rows"] == "0"


def test_only_the_period_and_the_environment_are_exported(matrix_server):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 5)
    ingest([evt("other-env", _when(1))], environment_id="22222222-2222-2222-2222-222222222222")
    ingest([evt("before", datetime(2026, 2, 28, 23, 59, tzinfo=timezone.utc)), evt("after", datetime(2026, 4, 1, 0, 0, tzinfo=timezone.utc))],
           environment_id=env_id)
    rows = _parse(_call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A)).content)
    assert [r[-1] for r in rows[1:]] == [f"e-{i:05d}" for i in range(5)]


@pytest.mark.parametrize("value,expected", [
    ("=1+1", "'=1+1"), ("+1", "'+1"), ("-1", "'-1"), ("@SUM(A1)", "'@SUM(A1)"), ("\tx", "'\tx"), ("plain", "plain"),
    ('say "hi", ok', 'say "hi", ok'),
])
def test_formula_like_cells_are_neutralised_and_every_field_is_quoted(matrix_server, value, expected):
    base_url, serve = matrix_server
    env_id = _seed_owner_a_with_session(serve)
    _seed(env_id, 1, actor=value)
    body = _call(base_url, "GET", f"{URL}?{RANGE}", headers=_who(OWNER_A)).content
    assert _parse(body)[1][0] == expected                 # the "User" column
    first_line = body.split(b"\r\n")[1].decode("utf-8")
    assert first_line.startswith('"') and first_line.endswith('"')   # quoted, CRLF line ends, no byte-order mark
    assert not body.startswith(b"\xef\xbb\xbf")
