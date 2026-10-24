"""The evidence package builder (5.53.0, WP4): packages made from a synthetic archive pass the offline verifier and
fail it when changed. The routes and the job are in test_evidence_package_routes_5530.py. Synthetic data only."""
import csv
import hashlib
import io
import json
import os
import zipfile

import pytest

import audit_store
import evidence_core as core
import evidence_package as ep
from evidence_fixtures import ROOT, build_archive, day, run_verifier, today_utc

ENV = "11111111-1111-1111-1111-111111111111"
SPEC_FILES = ["README-FOR-AUDITORS.txt", "cover-sheet.html", "control-matrix.csv", "events.ndjson", "chain/manifests.ndjson",
              "chain/seals.ndjson", "completeness.json", "what-this-tool-reads.txt", "tools/verify_evidence_package.py",
              "package-manifest.json"]


def period(a=-11, b=-1):
    return core.parse_period(day(a, 0).date().isoformat(), day(b, 0).date().isoformat())


@pytest.fixture
def store(tmp_audit_store):
    return tmp_audit_store


def build(tmp_path, per=None, gaps=False, name="pkg.zip", **kw):
    dest = tmp_path / name
    result = ep.build_package(str(dest), ENV, "Prod énvironment", per or period(), builder="the owner", app_version="5.53.0",
                              gaps_acknowledged=gaps, check_free_space=False, **kw)
    return dest, result


def read_zip(path):
    with zipfile.ZipFile(path) as zf:
        return {i.filename: zf.read(i.filename) for i in zf.infolist()}, [i.filename for i in zf.infolist()]


def test_package_passes_the_verifier_run_isolated_from_an_empty_directory(store, tmp_path):
    uuids = build_archive(ENV)
    dest, result = build(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out = run_verifier(dest, empty)
    assert code == 0 and out.rstrip().splitlines()[-1].startswith("RESULT: PASS"), out
    assert result["sha256"] in out and result["chain_head"] in out        # the verifier prints both for the build log
    assert result["events"] == len(uuids) and result["sha256"] == hashlib.sha256(dest.read_bytes()).hexdigest()


def test_entries_follow_the_format_in_order_and_the_manifest_is_last(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    files, order = read_zip(dest)
    assert order[:3] == ["README-FOR-AUDITORS.txt", "cover-sheet.html", "control-matrix.csv"]
    assert order[-1] == "package-manifest.json"
    for name in SPEC_FILES:
        assert name in files, name
    first_csv = min(i for i, n in enumerate(order) if n.startswith("controls/"))
    assert order.index("events.ndjson") > max(i for i, n in enumerate(order) if n.startswith("controls/")) > first_csv
    assert order.index("chain/manifests.ndjson") < order.index("chain/seals.ndjson") < order.index("completeness.json")
    for key in audit_store.COMPLIANCE_REPORTS:
        assert f"methodology/{key}.txt" in files
    assert all(n.isascii() and ".." not in n and not n.startswith("/") for n in order)
    manifest = json.loads(files["package-manifest.json"])
    listed = {f["path"]: f for f in manifest["files"]}
    assert set(listed) == set(order) - {"package-manifest.json"}
    for n, f in listed.items():
        assert f["sha256"] == hashlib.sha256(files[n]).hexdigest() and f["bytes"] == len(files[n])
    # the convenience copy is the shipped verifier, byte for byte
    with open(os.path.join(ROOT, "tools", "verify_evidence_package.py"), "rb") as fh:
        assert files["tools/verify_evidence_package.py"] == fh.read()


def test_manifest_carries_the_packer_requirements(store, tmp_path):
    build_archive(ENV)
    dest, result = build(tmp_path)
    files, _ = read_zip(dest)
    m = json.loads(files["package-manifest.json"])
    assert m["format"] == 1 and m["period"] == {"start": day(-11, 0).date().isoformat(), "end": day(-1, 0).date().isoformat()}
    assert m["curated_event_types"] == sorted(audit_store.COMPLIANCE_EVENT_TYPES)
    head = audit_store._get_connection().execute("SELECT head_hash, manifest_id FROM chain_heads WHERE environment_id = ?", (ENV,)).fetchone()
    assert m["chain_head"] == head["head_hash"] == result["chain_head"]
    rows = [json.loads(x) for x in files["chain/manifests.ndjson"].splitlines()]
    assert rows[-1]["manifest_id"] == head["manifest_id"] and rows[0]["prev_manifest_hash"] is None
    assert {"manifest_id", "environment_id", "source", "since", "until", "row_count", "created_at", "batch_hash", "content_hash",
            "entry_hash", "prev_manifest_hash", "entries_json"} <= set(rows[0])
    assert m["period_manifest_ids"] == [r["manifest_id"] for r in rows]
    assert m["environment_label_ascii"] == "Prod nvironment" or m["environment_label_ascii"].isascii()
    seals = [json.loads(x) for x in files["chain/seals.ndjson"].splitlines()]
    assert [s["manifest_id"] for s in seals] == m["period_manifest_ids"]


def test_events_are_byte_exact_in_published_order_with_ties_by_uuid(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    files, _ = read_zip(dest)
    lines = files["events.ndjson"].split(b"\n")
    assert lines[-1] == b""
    stored = [r[0] for r in audit_store._get_connection().execute(
        "SELECT raw_json FROM events WHERE environment_id = ? AND published >= ? AND published < ? ORDER BY published, uuid",
        (ENV, period().start_ts, period().end_ts))]
    assert [x.decode() for x in lines[:-1]] == stored


def test_control_rows_equal_a_direct_database_count(store, tmp_path):
    """Acceptance criterion 1."""
    build_archive(ENV)
    per = period()
    dest, _ = build(tmp_path, per)
    files, _ = read_zip(dest)
    conn = audit_store._get_connection()
    matrix = list(csv.DictReader(io.StringIO(files["control-matrix.csv"].decode())))
    assert matrix and all(r["framework"] == "soc2" and r["mapping_status"] == "proposed" for r in matrix)
    for row in matrix:
        total = 0
        for key in row["reports"].split(";"):
            types = audit_store._event_types_for_report(key)
            direct = conn.execute(
                f"SELECT COUNT(*) FROM events WHERE environment_id = ? AND event_type IN ({','.join('?' * len(types))}) "
                "AND substr(published,1,10) >= ? AND substr(published,1,10) <= ?",
                (ENV, *types, per.start.isoformat(), per.end.isoformat())).fetchone()[0]
            data = list(csv.reader(io.StringIO(files[f"controls/{row['control_id']}/{key}.csv"].decode())))
            assert len(data) - 1 == direct, (row["control_id"], key)
            total += direct
        assert int(row["rows_in_period"]) == total
    assert any(int(r["rows_in_period"]) > 0 for r in matrix) and any(int(r["rows_in_period"]) == 0 for r in matrix)
    done = json.loads(files["completeness.json"])["controls"]
    assert {c: v["rows"] for c, v in done.items()} == {r["control_id"]: int(r["rows_in_period"]) for r in matrix}
    assert all(v["truncated"] is False for v in done.values())


def test_completeness_states_coverage_scope_and_zero_event_types(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    c = json.loads(read_zip(dest)[0]["completeness.json"])
    assert c["scope"] == "everything" and c["gaps_acknowledged"] is False
    assert set(c["reports"]) == set(audit_store.COMPLIANCE_REPORTS) and all(r["truncated"] is False for r in c["reports"].values())
    assert c["coverage"]["counts"]["covered_zero_events"] == 3                    # days -11, -6 and -1
    assert c["archive_start_date"] == day(-12, 0).date().isoformat()
    assert c["data_as_of"] and c["pruned_days"] == []
    assert any(r["zero_event_types"] for r in c["reports"].values())


def test_cover_sheet_is_static_escaped_and_states_the_facts(store, tmp_path):
    build_archive(ENV)
    dest, result = ep.build_package(str(tmp_path / "x.zip"), ENV, '<script>alert(1)</script> "env"', period(), builder="<b>me</b>@@VERIFIER_SHA256@@",
                                    app_version="5.53.0", gaps_acknowledged=False, check_free_space=False), None
    files, _ = read_zip(tmp_path / "x.zip")
    html = files["cover-sheet.html"].decode()
    assert "<script" not in html.lower().replace("&lt;script", "") and "&lt;script&gt;" in html
    assert "http://" not in html and "https://" not in html and "src=" not in html and "<link" not in html.lower()
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "&lt;b&gt;me&lt;/b&gt;@@VERIFIER_SHA256@@" in html                      # a value that looks like a token stays text
    shipped = hashlib.sha256(open(os.path.join(ROOT, "tools", "verify_evidence_package.py"), "rb").read()).hexdigest()
    assert html.count(shipped) == 1
    for fact in (day(-11, 0).date().isoformat(), day(-1, 0).date().isoformat(), "proposed", "Archive starts", "Covered, zero events",
                 "Pruned by retention", "Gap days", "Coverage"):
        assert fact in html


def test_readme_covers_the_required_content_and_no_forbidden_claim(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    text = read_zip(dest)[0]["README-FOR-AUDITORS.txt"].decode()
    for needle in ("not affiliated with, endorsed by or supported by", "proposed", "Gap days", "Zero-event", "python3 -I", "RESULT: PASS",
                   "RESULT: FAIL", "apostrophe", "not signed", "unkeyed", "build log", "sha256", "Built at", "Built by", "Application version",
                   "Period (UTC dates)", "Environment label", "Never attach or paste the package"):
        assert needle in text, needle
    from test_claims_wording import FORBIDDEN
    assert not FORBIDDEN.search(text)
    assert "@@" not in text and text.isascii()


def test_no_forbidden_claim_anywhere_in_the_package(store, tmp_path):
    from test_claims_wording import FORBIDDEN
    build_archive(ENV)
    dest, _ = build(tmp_path)
    for name, data in read_zip(dest)[0].items():
        if name.endswith(".ndjson") or name.startswith("tools/"):
            continue
        assert not FORBIDDEN.search(data.decode("utf-8")), name
        assert b"@@" not in data, name


def test_tampering_one_byte_fails_the_verifier(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    files, order = read_zip(dest)
    for victim in ("events.ndjson", "package-manifest.json", next(n for n in order if n.startswith("controls/"))):
        bad = dict(files)
        data = bytearray(bad[victim])
        data[len(data) // 2] ^= 0x01
        bad[victim] = bytes(data)
        out = tmp_path / "bad.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for n in order:
                zf.writestr(n, bad[n])
        code, text = run_verifier(out, tmp_path)
        assert code == 1 and "RESULT: FAIL" in text, (victim, text)


def test_no_coverage_is_refused_and_leaves_no_file(store, tmp_path):
    audit_store.run_migrations()
    with pytest.raises(ep.PackageError) as exc:
        build(tmp_path)
    assert exc.value.reason == "no_coverage" and not (tmp_path / "pkg.zip").exists()


def test_unacknowledged_gaps_are_refused_acknowledged_gaps_are_written(store, tmp_path):
    build_archive(ENV, with_gap=True)
    with pytest.raises(ep.PackageError) as exc:
        build(tmp_path)
    assert exc.value.reason == "gaps_unacknowledged" and not (tmp_path / "pkg.zip").exists()
    dest, result = build(tmp_path, gaps=True)
    assert result["gap_days"] == 2
    files, _ = read_zip(dest)
    c = json.loads(files["completeness.json"])
    assert c["gaps_acknowledged"] is True and c["coverage"]["gap_days"] == [day(-8, 0).date().isoformat(), day(-7, 0).date().isoformat()]
    assert day(-8, 0).date().isoformat() in files["README-FOR-AUDITORS.txt"].decode()
    assert day(-8, 0).date().isoformat() in files["cover-sheet.html"].decode()
    code, out = run_verifier(dest, tmp_path)
    assert code == 0, out


def test_pruned_days_are_reported_as_pruned_not_as_gaps(store, tmp_path):
    """Acceptance criterion 5: the package's day states equal the coverage check's."""
    build_archive(ENV)
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM event_targets WHERE environment_id = ?", (ENV,))
    conn.execute("DELETE FROM events WHERE environment_id = ? AND is_curated = 0", (ENV,))
    conn.commit()
    per = period()
    records = [{"cutoff": day(-8, 0).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "pruned": 5, "at": "x"}]
    with core.open_snapshot(ENV, per, prune_records=records) as snap:
        expect = snap.coverage()
    dest, result = build(tmp_path, per, prune_records=records)
    c = json.loads(read_zip(dest)[0]["completeness.json"])["coverage"]
    assert c["counts"] == expect["counts"] and c["pruned_days"] == expect["pruned_days"] and c["gap_days"] == expect["gap_days"]
    assert c["counts"]["not_covered"] == 0 and result["gap_days"] == 0
    assert c["pruned_days"], "this archive should show pruned days"


def test_period_before_the_archive_and_after_data_as_of_are_stated(store, tmp_path):
    build_archive(ENV)
    per = period(-20, 0)                      # today is after the last successful sync's day-end
    dest, result = build(tmp_path, per)
    c = json.loads(read_zip(dest)[0]["completeness.json"])["coverage"]
    assert c["counts"]["before_archive"] >= 7 and c["counts"]["after_data_as_of"] == 1 and result["before_archive_days"] >= 7
    code, out = run_verifier(dest, tmp_path)
    assert code == 0, out


def test_size_limit_fails_clearly_and_removes_the_partial_file(store, tmp_path):
    build_archive(ENV)
    with pytest.raises(ep.PackageError) as exc:
        build(tmp_path, max_bytes=2000)
    assert exc.value.reason == "size_limit" and "limit" in str(exc.value) and not (tmp_path / "pkg.zip").exists()


def test_free_space_check_refuses_before_writing(store, tmp_path, monkeypatch):
    build_archive(ENV)
    import shutil
    monkeypatch.setattr(shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(100, 99, 1) if hasattr(shutil, "_ntuple_diskusage") else type("U", (), {"free": 1})())
    with pytest.raises(ep.PackageError) as exc:
        ep.build_package(str(tmp_path / "p.zip"), ENV, "dev", period(), builder="b", app_version="5.53.0", gaps_acknowledged=False)
    assert exc.value.reason == "disk_space" and not (tmp_path / "p.zip").exists()


def test_a_cut_chain_tail_refuses_instead_of_packaging_it(store, tmp_path):
    build_archive(ENV)
    conn = audit_store._get_connection()
    conn.execute("DELETE FROM ingestion_manifests WHERE id = (SELECT MAX(id) FROM ingestion_manifests WHERE environment_id = ?)", (ENV,))
    conn.commit()
    with pytest.raises(ep.PackageError) as exc:
        build(tmp_path)
    assert exc.value.reason == "chain_inconsistent"


def test_a_sync_committing_during_the_build_does_not_change_the_package(store, tmp_path, monkeypatch):
    """One snapshot for the whole build: a manifest and events committed after it opened are not in the package."""
    build_archive(ENV)
    from evidence_fixtures import evt, ingest
    original = core.Snapshot.event_lines
    fired = []

    def noisy(self):
        if not fired:
            fired.append(1)
            ingest(ENV, [evt("late-1", day(-4, 15))], since=None, until=None)
        return original(self)
    monkeypatch.setattr(core.Snapshot, "event_lines", noisy)
    dest, result = build(tmp_path)
    assert fired and b"late-1" not in read_zip(dest)[0]["events.ndjson"]
    code, out = run_verifier(dest, tmp_path)
    assert code == 0, out


def test_a_second_environment_never_leaks_into_the_package(store, tmp_path):
    from evidence_fixtures import evt, ingest
    build_archive(ENV)
    ingest("22222222-2222-2222-2222-222222222222", [evt("other-1", day(-4, 9))], since=None, until=None)
    dest, _ = build(tmp_path)
    blob = b"".join(d for n, d in read_zip(dest)[0].items() if n != "tools/verify_evidence_package.py")
    assert b"other-1" not in blob and b"22222222-2222" not in blob


def test_formula_cells_are_neutralised_and_the_event_is_still_exact(store, tmp_path):
    from evidence_fixtures import evt, ingest
    build_archive(ENV)
    ingest(ENV, [evt("f-1", day(-4, 16), actor="=HYPERLINK(\"x\")", email="@x@example.com")], since=None, until=None)
    dest, _ = build(tmp_path)
    files, _ = read_zip(dest)
    sessions = files["controls/CC7.2/session_activity.csv"].decode() if "controls/CC7.2/session_activity.csv" in files else None
    csv_blob = "".join(v.decode() for n, v in files.items() if n.startswith("controls/"))
    assert "'=HYPERLINK" in csv_blob and "\"=HYPERLINK" not in csv_blob and "'@x@example.com" in csv_blob
    assert b'"displayName":"=HYPERLINK' in files["events.ndjson"] or b"=HYPERLINK" in files["events.ndjson"]
    code, out = run_verifier(dest, tmp_path)
    assert code == 0, out
    del sessions


def test_file_name_is_sanitised():
    per = core.parse_period("2026-01-01", "2026-01-31")
    name = ep.download_filename('..\\"; rm -rf /\r\nX', per, "2026-02-01T10:11:12.000Z")
    assert name.isascii() and all(ch.isalnum() or ch in "._-" for ch in name) and name.endswith(".zip") and "/" not in name
    assert ep.ascii_label("Café ☃ prod") == "Cafe prod"


# ---------------------------------------------------------------------------
# Acceptance 2 (files), 6 (quoting), 9 (rollback)
# ---------------------------------------------------------------------------
def _rewrite(src, dst, drop=(), add=()):
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename not in drop:
                zout.writestr(info.filename, zin.read(info.filename))
        for name, data in add:
            zout.writestr(name, data)


def test_an_extra_or_a_missing_file_fails_the_verifier(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    for name, kwargs in (("extra", {"add": [("notes.txt", b"hello")]}), ("missing", {"drop": ["what-this-tool-reads.txt"]}),
                         ("missing-csv", {"drop": ["controls/CC7.2/session_activity.csv"]})):
        out = tmp_path / f"{name}.zip"
        _rewrite(dest, out, **kwargs)
        code, text = run_verifier(out, tmp_path)
        assert code == 1 and "RESULT: FAIL" in text, (name, text)


def test_every_report_field_is_quoted_with_crlf_line_ends(store, tmp_path):
    build_archive(ENV)
    dest, _ = build(tmp_path)
    files, order = read_zip(dest)
    csvs = [n for n in order if n.endswith(".csv")]
    assert len(csvs) > 20
    for n in csvs:
        data = files[n]
        assert not data.startswith(b"\xef\xbb\xbf") and data.endswith(b"\r\n")
        for line in data.split(b"\r\n")[:-1]:
            assert line.startswith(b'"') and line.endswith(b'"'), (n, line)
        header = next(csv.reader(io.StringIO(data.decode())))
        assert (header[-1] == "event_uuid") if n.startswith("controls/") else header[0] == "control_id"


def test_a_5_52_0_application_ignores_the_new_permission_row(store, tmp_path):
    """Acceptance 9, the unknown-capability half: the released 5.52.0 engine reads a database holding a build_evidence_package
    override row, ignores it and answers its own seven capabilities. (The migration half is test_migration_rollback_safety.py;
    this feature adds no migration.)"""
    import subprocess
    import sys
    try:
        engine_old = subprocess.run(["git", "show", "v5.52.0:create_secret_folders.py"], capture_output=True, cwd=ROOT, timeout=60)
        store_old = subprocess.run(["git", "show", "v5.52.0:audit_store.py"], capture_output=True, cwd=ROOT, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git is not available")
    if engine_old.returncode != 0 or store_old.returncode != 0:
        pytest.skip("the v5.52.0 tag is not available in this checkout")
    audit_store.run_migrations()
    env_id = ENV
    conn = audit_store._get_connection()
    now = "2026-01-01T00:00:00.000Z"
    conn.execute("INSERT OR IGNORE INTO app_environments (environment_id, owner_id, display_name, base_domain, team_name, key_id, created_at, updated_at) "
                 "VALUES (?, 'owner', 'Synthetic', 'example.okta.com', 'team', 'key', ?, ?)", (env_id, now, now))
    conn.execute("INSERT INTO shared_permission_overrides (environment_id, capability, value, updated_at, updated_by) VALUES (?, 'build_evidence_package', 'allow', ?, 'x')",
                 (env_id, now))
    conn.commit()
    old = tmp_path / "old"
    old.mkdir()
    (old / "create_secret_folders.py").write_bytes(engine_old.stdout)
    (old / "audit_store.py").write_bytes(store_old.stdout)
    script = ("import sys, json; sys.path.insert(0, %r); import create_secret_folders as e; "
              "print(json.dumps({'overrides': e.get_shared_permission_overrides(%r), 'effective': sorted(e.effective_shared_permissions(%r)), "
              "'keys': list(e.SHARED_CAPABILITY_KEYS)}))") % (str(old), env_id, env_id)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, cwd=str(old),
                          env={**os.environ, "OPA_AUDIT_DB_PATH": audit_store._audit_db_path(), "PYTHONPATH": str(old)}, timeout=120)
    assert proc.returncode == 0, proc.stderr[-1500:]
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    assert got["overrides"] == {} and "build_evidence_package" not in got["effective"] and len(got["keys"]) == 7


def test_free_space_rule_is_half_the_estimate_plus_the_margin_at_the_boundary(store, tmp_path, monkeypatch):
    import collections
    import shutil
    build_archive(ENV)
    with core.open_snapshot(ENV, period()) as snap:
        est = snap.estimate_event_bytes()
    need = int(est * ep.FREE_SPACE_FACTOR) + ep.FREE_SPACE_MARGIN
    assert ep.FREE_SPACE_FACTOR == 0.5 and ep.FREE_SPACE_MARGIN == 256 * 1024 * 1024 and need < est + ep.FREE_SPACE_MARGIN
    usage = collections.namedtuple("usage", "total used free")
    kw = dict(builder="b", app_version="5.53.0", gaps_acknowledged=False)
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(10 * need, 0, need - 1))
    with pytest.raises(ep.PackageError) as exc:
        ep.build_package(str(tmp_path / "a.zip"), ENV, "dev", period(), **kw)
    assert exc.value.reason == "disk_space" and not (tmp_path / "a.zip").exists()
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(10 * need, 0, need))
    ep.build_package(str(tmp_path / "b.zip"), ENV, "dev", period(), **kw)
    assert (tmp_path / "b.zip").exists()


def test_a_label_that_looks_like_the_matrix_token_cannot_duplicate_rows(store, tmp_path):
    build_archive(ENV)
    dest = tmp_path / "h.zip"
    ep.build_package(str(dest), ENV, "@@MATRIX_ROWS@@ @@MATRIX@@ <i>x</i>", period(), builder="@@MATRIX_ROWS@@", app_version="5.53.0",
                     gaps_acknowledged=False, check_free_space=False)
    html = read_zip(dest)[0]["cover-sheet.html"].decode()
    assert html.count("CC6.1</td>") == 1                   # one row per criterion, once
    assert "@@MATRIX_ROWS@@" in html and "&lt;i&gt;x&lt;/i&gt;" in html and "<i>x</i>" not in html
    code, out = run_verifier(dest, tmp_path)
    assert code == 0, out


@pytest.mark.parametrize("value", ["abc", "0", "-5", "1.5"])
def test_a_bad_max_bytes_setting_is_logged_once_and_ignored(monkeypatch, capsys, value):
    ep._max_bytes_warned.clear()
    monkeypatch.setenv("OPA_EVIDENCE_MAX_BYTES", value)
    assert ep.configured_max_bytes() == ep.DEFAULT_MAX_BYTES and ep.configured_max_bytes() == ep.DEFAULT_MAX_BYTES
    assert capsys.readouterr().err.count("OPA_EVIDENCE_MAX_BYTES") == 1
    monkeypatch.setenv("OPA_EVIDENCE_MAX_BYTES", "12345")
    assert ep.configured_max_bytes() == 12345
    monkeypatch.delenv("OPA_EVIDENCE_MAX_BYTES")
    assert ep.configured_max_bytes() == ep.DEFAULT_MAX_BYTES
