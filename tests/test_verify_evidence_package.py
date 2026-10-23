"""WP3 (5.53.0): the offline evidence package verifier (tools/verify_evidence_package.py).

- golden vectors for the three hash formulas of format v1, asserted against audit_store AND the verifier;
- a fixture builder: small synthetic archives made with audit_store's real ingestion code, written to a format v1 zip
  by a minimal test-only packer (the real packer is a later work package; do not import this one into the app);
- cross-checks: the verifier and audit_store.verify_ingestion_chain must agree on each archive;
- tamper cases on the zip itself, and a subprocess run under `python3 -I` from an empty directory.
All data is synthetic."""
import ast
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

import audit_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(ROOT, "tools", "verify_evidence_package.py")
ENV = "11111111-1111-1111-1111-111111111111"
FORBIDDEN = ("tamper-proof", "tamper-evident", "audit-ready", "certified", "compliant", "auditor-accepted")

_spec = importlib.util.spec_from_file_location("verify_evidence_package", VERIFIER)
vep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vep)


# ---------------------------------------------------------------------------
# Golden vectors (frozen: a change here is a format change)
# ---------------------------------------------------------------------------
RAW_1 = '{"uuid":"evt-1","eventType":"user.session.start","published":"2026-01-02T03:04:05.000Z"}'
RAW_2 = '{"uuid":"evt-2","eventType":"user.session.start","published":"2026-01-02T03:04:06.000Z","note":"café"}'
CONTENT_1 = "a37dfdb0ca8b86f92b3322a15a37d1c777dbd798d31e9701257cc95a0641d650"
CONTENT_2 = "cabc4b097a719c13fd5cf69695cc4fa5f198830dd6c7e8cf95205e5172352a8b"
MANIFEST_CONTENT = "89a18423836d2fb441ae349b0595e19653eccf647cff22640e8dc02a62a20364"
BATCH = "8d3f182a04c6d2bcb51a2e6f0201039af53aa777c6aa18236b3c6eae53083b44"
ENTRY_1 = "8a53dc4a39059e81e9d06559cc857a74a25a449ddd000084762147e606afb2d6"
ENTRY_2 = "f1b33e75efc68df57cd57fa928cd151ceb87d6f76b016bf64b73f87478040c98"
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_golden_event_content_hash():
    assert audit_store._content_sha256(RAW_1) == CONTENT_1
    assert audit_store._content_sha256(RAW_2) == CONTENT_2  # non-ASCII is hashed as UTF-8
    assert vep.content_hash_of_event(RAW_1.encode("utf-8")) == CONTENT_1
    assert vep.content_hash_of_event(RAW_2.encode("utf-8")) == CONTENT_2


def test_golden_manifest_content_hash():
    entries = [("evt-2", 1, CONTENT_2), ("evt-1", 1, CONTENT_1), ("evt-3", 0, "ignored-not-curated")]
    assert audit_store._manifest_content_hash(entries) == MANIFEST_CONTENT
    assert vep.manifest_content_hash(["evt-2:" + CONTENT_2, "evt-1:" + CONTENT_1]) == MANIFEST_CONTENT
    assert audit_store._manifest_content_hash([]) == EMPTY == vep.manifest_content_hash([])
    # the formula spelled out
    assert hashlib.sha256(("evt-1:%s\nevt-2:%s" % (CONTENT_1, CONTENT_2)).encode()).hexdigest() == MANIFEST_CONTENT


def test_golden_manifest_entry_hash():
    assert audit_store._sha256_of_lines(sorted(["evt-2", "evt-1", "evt-3"])) == BATCH
    args1 = (None, ENV, "sync", "2026-01-01T00:00:00.000Z", None, 3, "2026-01-02T03:05:00.000Z", BATCH, MANIFEST_CONTENT)
    assert audit_store._manifest_entry_hash(*args1) == ENTRY_1
    assert vep.manifest_entry_hash(*args1) == ENTRY_1
    args2 = (ENTRY_1, ENV, "csv_import", None, None, 0, "2026-01-03T00:00:00.000Z", EMPTY, EMPTY)
    assert audit_store._manifest_entry_hash(*args2) == ENTRY_2
    assert vep.manifest_entry_hash(*args2) == ENTRY_2
    # the formula spelled out: nine fields, newline-joined, empty string for a missing value
    joined = "\n".join(["", ENV, "sync", "2026-01-01T00:00:00.000Z", "", "3", "2026-01-02T03:05:00.000Z", BATCH, MANIFEST_CONTENT])
    assert hashlib.sha256(joined.encode()).hexdigest() == ENTRY_1


# ---------------------------------------------------------------------------
# Fixture builder: real ingestion code, test-only packer
# ---------------------------------------------------------------------------
class FakeOktaClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def get_system_log_page(self, path):
        return [], None

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        return self._responses.pop(0) if self._responses else ([], True)


def _stamp(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(uuid, published, event_type="user.session.start"):
    return {"uuid": uuid, "eventType": event_type, "published": published, "actor": {"id": "00uActor", "displayName": "Someone"},
            "outcome": {"result": "SUCCESS"}, "target": []}


def _sync(events):
    since = _stamp(120)
    audit_store.sync_okta_events(FakeOktaClient([(events, True)]), ENV, "all", since=since)


def build_archive(legacy_first=False, snapshot=False):
    """Three syncs: curated events plus one non-curated event per sync. Returns nothing; the store is the fixture."""
    audit_store.run_migrations()
    batches = [
        [_event("evt-a1", _stamp(100)), _event("evt-a2", _stamp(99)), _event("evt-a3", _stamp(98), "app.misc.synthetic")],
        [_event("evt-b1", _stamp(60)), _event("evt-b2", _stamp(59), "app.misc.synthetic"), _event("evt-b3", _stamp(58))],
        [_event("evt-c1", _stamp(20)), _event("evt-c2", _stamp(19)), _event("evt-c3", _stamp(18), "app.misc.synthetic")],
    ]
    for i, events in enumerate(batches):
        if legacy_first and i == 0:
            old = audit_store.EVIDENCE_CHAIN_V2
            audit_store.EVIDENCE_CHAIN_V2 = False
            try:
                _sync(events)
            finally:
                audit_store.EVIDENCE_CHAIN_V2 = old
        else:
            _sync(events)
    if snapshot:
        audit_store.record_config_snapshot(ENV, "users", [("k1", {"a": 1}), ("k2", {"b": 2})])


def _db():
    return audit_store._get_connection()


def pack(path, *, scope_curated_only=False):
    """Test-only packer: writes a format v1 zip from the archive in the current store. Mirrors docs/evidence-package-format.md."""
    conn = _db()
    ev_rows = conn.execute(
        "SELECT uuid, raw_json FROM events WHERE environment_id = ? ORDER BY published, uuid", (ENV,)
    ).fetchall()
    events_bytes = b"".join(r["raw_json"].encode("utf-8") + b"\n" for r in ev_rows)
    in_events = {r["uuid"] for r in ev_rows}
    manifests = conn.execute("SELECT * FROM ingestion_manifests WHERE environment_id = ? ORDER BY id", (ENV,)).fetchall()
    manifest_lines = []
    seal_lines = []
    period_ids = []
    published_of = {r["uuid"]: json.loads(r["raw_json"])["published"] for r in ev_rows}
    days = sorted(p[:10] for p in published_of.values()) or ["2026-01-01"]
    for m in manifests:
        manifest_lines.append(json.dumps({
            "manifest_id": m["id"], "environment_id": m["environment_id"], "source": m["source"], "since": m["since"],
            "until": m["until"], "row_count": m["row_count"], "batch_hash": m["batch_hash"],
            "prev_manifest_hash": m["prev_manifest_hash"], "created_at": m["created_at"], "content_hash": m["content_hash"],
            "entry_hash": m["entry_hash"], "entries_json": m["entries_json"] is not None,
        }, sort_keys=True))
        entries = [(r["uuid"], r["sha"]) for r in conn.execute(
            "SELECT uuid, sha FROM manifest_entries WHERE manifest_id = ?", (m["id"],))]
        if m["entries_json"] is not None:
            entries = [tuple(p) for p in json.loads(m["entries_json"])]
        ordinary = m["entry_hash"] and not m["source"].startswith("snapshot:") and m["entries_json"] is None
        if ordinary and any(u in in_events for u, _s in entries):
            period_ids.append(m["id"])
            ordered = sorted(entries, key=lambda e: "%s:%s" % e)
            seal_lines.append(json.dumps({
                "manifest_id": m["id"], "entries": ["%s:%s" % e for e in ordered],
                "published": [published_of.get(u) or conn.execute(
                    "SELECT published FROM events WHERE uuid = ?", (u,)).fetchone()[0] for u, _s in ordered]}))
        elif not m["entry_hash"] or (m["entries_json"] is not None and any(u in in_events for u, _s in entries)):
            period_ids.append(m["id"])  # may hold events of the period; its rows stay "not verified"
    head = conn.execute("SELECT head_hash FROM chain_heads WHERE environment_id = ?", (ENV,)).fetchone()
    buf = io.StringIO(newline="")
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(["event_uuid", "published", "event_type"])
    for r in ev_rows:
        raw = json.loads(r["raw_json"])
        w.writerow([r["uuid"], raw["published"], raw["eventType"]])
    report_csv = buf.getvalue().encode("utf-8")
    files = [
        ("README-FOR-AUDITORS.txt", b"synthetic readme\n"),
        ("cover-sheet.html", b"<html><body>synthetic</body></html>\n"),
        ("control-matrix.csv", b'"control_id","framework","mapping_status","reports","rows_in_period","status"\r\n'
                                b'"CC6.1","SOC 2","proposed","1","%d","ok"\r\n' % len(ev_rows)),
        ("controls/CC6.1/session_activity.csv", report_csv),
        ("events.ndjson", events_bytes),
        ("chain/manifests.ndjson", ("\n".join(manifest_lines) + ("\n" if manifest_lines else "")).encode()),
        ("chain/seals.ndjson", ("\n".join(seal_lines) + ("\n" if seal_lines else "")).encode()),
        ("completeness.json", json.dumps({"truncated": False, "pruned_days": []}).encode()),
        ("what-this-tool-reads.txt", b"synthetic statement\n"),
        ("methodology/session_activity.txt", b"synthetic methodology\n"),
    ]
    pm = {
        "format": 1,
        "files": [{"path": n, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for n, b in files],
        "built_at": "2026-01-05T00:00:00.000Z", "app_version": "0.0.0-test", "environment_label_ascii": "Synthetic environment",
        "period": {"start": days[0], "end": days[-1]}, "data_as_of": "2026-01-05T00:00:00.000Z",
        "chain_head": head["head_hash"] if head else None, "catalogue_version": "test",
        "curated_event_types": sorted(audit_store.COMPLIANCE_EVENT_TYPES), "period_manifest_ids": period_ids,
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for n, b in files:
            zf.writestr(n, b)
        zf.writestr("package-manifest.json", json.dumps(pm, indent=1).encode())
    return pm


def run_verifier(path, tmp_path=None):
    proc = subprocess.run([sys.executable, "-I", VERIFIER, str(path)], capture_output=True, text=True, cwd=str(tmp_path or os.path.dirname(str(path))))
    return proc.returncode, proc.stdout


def rewrite(src, dst, edit=None, drop=(), add=()):
    """Copy a zip, optionally editing {name: callable(bytes)->bytes}, dropping names, adding (name, bytes)."""
    edit = edit or {}
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            data = zin.read(info.filename)
            if info.filename in edit:
                data = edit[info.filename](data)
            zout.writestr(info.filename, data)
        for name, data in add:
            zout.writestr(zipfile.ZipInfo(name), data)


def _flip_first_byte_of(token):
    def edit(data):
        i = data.index(token)
        return data[:i] + bytes([data[i] ^ 0x01]) + data[i + 1:]
    return edit


@pytest.fixture
def archive(tmp_audit_store):
    build_archive()
    return tmp_audit_store


def _agree(tmp_path, expect_valid, name="pkg.zip"):
    """The verifier and verify_ingestion_chain(deep=True) must give the same answer. Returns (code, stdout, chain result)."""
    chain = audit_store.verify_ingestion_chain(ENV, deep=True)
    path = tmp_path / name
    pack(str(path))
    code, out = run_verifier(path, tmp_path)
    assert chain["valid"] is expect_valid, chain
    assert (code == 0) is expect_valid, out
    assert out.rstrip().splitlines()[-1].startswith("RESULT: PASS" if expect_valid else "RESULT: FAIL")
    return code, out, chain


# ---------------------------------------------------------------------------
# Cross-checks against verify_ingestion_chain
# ---------------------------------------------------------------------------
def test_intact_archive_passes_in_both(archive, tmp_path):
    code, out, chain = _agree(tmp_path, True)
    assert "RESULT: PASS" in out
    assert "6 match a sealed hash" in out  # six curated events across three syncs
    assert "3 have no seal" in out  # the three non-curated events are stated as not verified
    assert chain["unverifiable_rows"] == 3


def test_edited_event_fails_in_both(archive, tmp_path):
    conn = _db()
    conn.execute("UPDATE events SET raw_json = replace(raw_json, 'Someone', 'Somebody') WHERE uuid = 'evt-b1'")
    conn.commit()
    _code, out, _chain = _agree(tmp_path, False)
    assert "do not match their sealed hash" in out


def test_deleted_manifest_fails_in_both(archive, tmp_path):
    conn = _db()
    mid = conn.execute("SELECT id FROM ingestion_manifests ORDER BY id LIMIT 1 OFFSET 1").fetchone()["id"]
    conn.execute("DELETE FROM manifest_entries WHERE manifest_id = ?", (mid,))
    conn.execute("DELETE FROM ingestion_manifests WHERE id = ?", (mid,))
    conn.commit()
    _code, out, _chain = _agree(tmp_path, False)
    assert "chain broken" in out


def test_cut_tail_fails_in_both(archive, tmp_path):
    conn = _db()
    mid = conn.execute("SELECT MAX(id) AS m FROM ingestion_manifests").fetchone()["m"]
    conn.execute("DELETE FROM manifest_entries WHERE manifest_id = ?", (mid,))
    conn.execute("DELETE FROM ingestion_manifests WHERE id = ?", (mid,))
    conn.commit()
    _code, out, chain = _agree(tmp_path, False)
    assert "ends before the recorded head" in out
    assert "removed from the end" in chain["reason"]


def test_reordered_manifests_fail_in_both(archive, tmp_path):
    conn = _db()
    ids = [r["id"] for r in conn.execute("SELECT id FROM ingestion_manifests ORDER BY id")]
    a, b = ids[0], ids[1]
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("UPDATE ingestion_manifests SET id = -1 WHERE id = ?", (a,))
    conn.execute("UPDATE ingestion_manifests SET id = ? WHERE id = ?", (a, b))
    conn.execute("UPDATE ingestion_manifests SET id = ? WHERE id = -1", (b,))
    conn.commit()
    _code, out, _chain = _agree(tmp_path, False)
    assert "chain broken" in out


def test_downgrade_fails_in_both(archive, tmp_path, monkeypatch):
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", False)
    _sync([_event("evt-d1", _stamp(5))])
    _code, out, chain = _agree(tmp_path, False)
    assert "downgrade" in out
    assert "downgraded" in chain["reason"]


def test_partially_pruned_non_curated_rows_pass_in_both(archive, tmp_path):
    conn = _db()
    conn.execute("DELETE FROM event_targets WHERE environment_id = ?", (ENV,))
    conn.execute("DELETE FROM events WHERE uuid IN ('evt-a3', 'evt-b2')")  # retention removed two non-curated rows
    conn.commit()
    _code, out, chain = _agree(tmp_path, True)
    assert "6 match a sealed hash" in out
    assert "1 have no seal" in out  # only the surviving non-curated event
    assert "not content-sealed" in out
    assert chain["unverifiable_rows"] == 3  # the chain still counts the three rows retention may remove


def test_legacy_manifest_is_reported_not_verified(tmp_audit_store, tmp_path):
    build_archive(legacy_first=True)
    _code, out, chain = _agree(tmp_path, True)
    assert chain["legacy_manifests"] == 1
    assert "Legacy v1 manifests (identifier-only, no content seal): 1" in out
    assert "4 match a sealed hash" in out  # the legacy batch's two curated events have no content seal
    assert "5 have no seal" in out


def test_snapshot_manifest_is_reported_not_verified(tmp_audit_store, tmp_path):
    build_archive(snapshot=True)
    _code, out, _chain = _agree(tmp_path, True)
    assert "Snapshot manifests (chain link checked, objects not in this package): 1" in out


def test_entries_json_manifest_is_reported_not_verified(archive, tmp_path):
    conn = _db()
    mid = conn.execute("SELECT id FROM ingestion_manifests ORDER BY id LIMIT 1").fetchone()["id"]
    pairs = [[r["uuid"], r["sha"]] for r in conn.execute("SELECT uuid, sha FROM manifest_entries WHERE manifest_id = ?", (mid,))]
    conn.execute("UPDATE ingestion_manifests SET entries_json = ? WHERE id = ?", (json.dumps(pairs), mid))
    conn.execute("DELETE FROM manifest_entries WHERE manifest_id = ?", (mid,))
    conn.commit()
    _code, out, _chain = _agree(tmp_path, True)
    assert "entries_json manifests (older sealing format): 1" in out


# ---------------------------------------------------------------------------
# Tamper cases on the package itself
# ---------------------------------------------------------------------------
@pytest.fixture
def good_zip(archive, tmp_path):
    path = tmp_path / "good.zip"
    pack(str(path))
    code, out = run_verifier(path, tmp_path)
    assert code == 0, out
    return path


def _expect_fail(tmp_path, good_zip, fragment=None, **kw):
    bad = tmp_path / "bad.zip"
    rewrite(str(good_zip), str(bad), **kw)
    code, out = run_verifier(bad, tmp_path)
    assert code == 1, out
    last = out.rstrip().splitlines()[-1]
    assert last.startswith("RESULT: FAIL (")
    if fragment:
        assert fragment in last, last
    return out


def test_byte_changed_in_events_ndjson(good_zip, tmp_path):
    _expect_fail(tmp_path, good_zip, "events.ndjson", edit={"events.ndjson": _flip_first_byte_of(b"evt-a1")})


def test_byte_changed_in_a_csv(good_zip, tmp_path):
    _expect_fail(tmp_path, good_zip, "session_activity.csv", edit={"controls/CC6.1/session_activity.csv": _flip_first_byte_of(b"evt-b1")})


def test_byte_changed_in_package_manifest(good_zip, tmp_path):
    def flip_in_first_hash(data):
        i = data.index(b'"sha256": "') + len(b'"sha256": "')
        return data[:i] + (b"0" if data[i:i + 1] != b"0" else b"1") + data[i + 1:]
    _expect_fail(tmp_path, good_zip, "sha256", edit={"package-manifest.json": flip_in_first_hash})
    _expect_fail(tmp_path, good_zip, "package-manifest.json is unreadable", edit={"package-manifest.json": lambda d: d[:-20]})
    _expect_fail(tmp_path, good_zip, "size of", edit={"package-manifest.json": lambda d: d.replace(b'"bytes": ', b'"bytes": 1', 1)})


def test_package_manifest_hash_changed(good_zip, tmp_path):
    def edit(data):
        pm = json.loads(data)
        pm["files"][0]["sha256"] = "0" * 64
        return json.dumps(pm).encode()
    _expect_fail(tmp_path, good_zip, "README-FOR-AUDITORS.txt", edit={"package-manifest.json": edit})


def test_chain_head_changed_in_package_manifest(good_zip, tmp_path):
    def edit(data):
        pm = json.loads(data)
        pm["chain_head"] = "0" * 64
        return json.dumps(pm).encode()
    _expect_fail(tmp_path, good_zip, "chain", edit={"package-manifest.json": edit})


def test_resealed_edit_still_fails_on_the_archive_seals(good_zip, tmp_path):
    """Even when the package manifest is rewritten to match an edited event, the seals from the archive's chain disagree."""
    edited = {}

    def edit_events(data):
        edited["data"] = data.replace(b"Someone", b"Somebody", 1)
        return edited["data"]

    def edit_manifest(data):
        pm = json.loads(data)
        for item in pm["files"]:
            if item["path"] == "events.ndjson":
                item["sha256"] = hashlib.sha256(edited["data"]).hexdigest()
                item["bytes"] = len(edited["data"])
        return json.dumps(pm).encode()
    out = _expect_fail(tmp_path, good_zip, "sealed hash", edit={"events.ndjson": edit_events, "package-manifest.json": edit_manifest})
    assert "RESULT: FAIL" in out


def test_csv_row_naming_an_unknown_event(good_zip, tmp_path):
    def edit_csv(data):
        return data + b'"evt-not-there","2026-01-01T00:00:00.000Z","user.session.start"\r\n'

    def edit_manifest(data, name="controls/CC6.1/session_activity.csv"):
        return data
    with zipfile.ZipFile(good_zip) as zf:
        new_csv = edit_csv(zf.read("controls/CC6.1/session_activity.csv"))
        pm = json.loads(zf.read("package-manifest.json"))
    for item in pm["files"]:
        if item["path"] == "controls/CC6.1/session_activity.csv":
            item["sha256"] = hashlib.sha256(new_csv).hexdigest()
            item["bytes"] = len(new_csv)
    _expect_fail(tmp_path, good_zip, "not in events.ndjson",
                 edit={"controls/CC6.1/session_activity.csv": lambda d: new_csv, "package-manifest.json": lambda d: json.dumps(pm).encode()})


def test_extra_file(good_zip, tmp_path):
    _expect_fail(tmp_path, good_zip, "not listed", add=[("extra.txt", b"x")])


def test_missing_file(good_zip, tmp_path):
    _expect_fail(tmp_path, good_zip, "absent", drop=("what-this-tool-reads.txt",))


def test_missing_package_manifest(good_zip, tmp_path):
    _expect_fail(tmp_path, good_zip, "package-manifest.json is missing", drop=("package-manifest.json",))


@pytest.mark.parametrize("name", ["../evil", "/abs/path", "a\\b", "C:evil", "dir/../x", "x//y", "café.txt", "dir/"])
def test_unsafe_entry_names_are_refused(good_zip, tmp_path, name):
    out = _expect_fail(tmp_path, good_zip, "refused entry name", add=[(name, b"x")])
    assert not os.path.exists(os.path.join(str(tmp_path), "evil"))
    assert not os.path.exists(os.path.join(os.path.dirname(str(tmp_path)), "evil"))
    assert "RESULT: FAIL" in out


def test_symlink_entry_is_refused(good_zip, tmp_path):
    bad = tmp_path / "bad.zip"
    rewrite(str(good_zip), str(bad))
    with zipfile.ZipFile(bad, "a") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "events.ndjson")
    code, out = run_verifier(bad, tmp_path)
    assert code == 1 and "not a regular file" in out


def test_unusable_input_exits_2(tmp_path):
    not_zip = tmp_path / "x.zip"
    not_zip.write_bytes(b"this is not a zip")
    assert run_verifier(not_zip, tmp_path)[0] == 2
    assert run_verifier(tmp_path / "absent.zip", tmp_path)[0] == 2
    assert subprocess.run([sys.executable, "-I", VERIFIER], capture_output=True, cwd=str(tmp_path)).returncode == 2


def test_nothing_is_extracted(good_zip, tmp_path):
    before = sorted(os.listdir(tmp_path))
    run_verifier(good_zip, tmp_path)
    assert sorted(os.listdir(tmp_path)) == before


# ---------------------------------------------------------------------------
# Isolation and wording
# ---------------------------------------------------------------------------
def test_runs_isolated_from_an_empty_directory_and_imports_nothing_from_the_app(good_zip, tmp_path):
    work = tmp_path / "empty"
    work.mkdir()
    for decoy in ("audit_store.py", "create_secret_folders.py", "csv.py", "hashlib.py", "json.py", "zipfile.py"):
        (work / decoy).write_text("raise RuntimeError('decoy imported')\n")
    lone = tmp_path / "lone"
    lone.mkdir()
    script = lone / "verify_evidence_package.py"
    script.write_text(open(VERIFIER).read())
    for decoy in ("audit_store.py", "csv.py", "json.py"):
        (lone / decoy).write_text("raise RuntimeError('decoy imported')\n")
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(work)}
    proc = subprocess.run([sys.executable, "-I", "-X", "importtime", str(script), str(good_zip)], capture_output=True, text=True,
                          cwd=str(work), env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: PASS" in proc.stdout
    assert "decoy" not in proc.stdout + proc.stderr
    imported = set(re.findall(r"\| ([A-Za-z0-9_.]+)$", proc.stderr, re.M))
    assert "audit_store" not in imported and "create_secret_folders" not in imported
    assert sorted(os.listdir(work)) == sorted(
        ["audit_store.py", "create_secret_folders.py", "csv.py", "hashlib.py", "json.py", "zipfile.py"])  # nothing written
    assert not any(n.endswith(".pyc") for n in os.listdir(work))


def test_verifier_imports_only_the_standard_library():
    tree = ast.parse(open(VERIFIER).read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= {"csv", "hashlib", "io", "json", "os", "re", "stat", "sys", "zipfile"}


def test_report_wording_has_no_forbidden_claims_and_says_what_pass_does_not_prove(good_zip, tmp_path):
    _code, out = run_verifier(good_zip, tmp_path)
    low = out.lower()
    for word in FORBIDDEN + ("tamper",):
        assert word not in low
    assert "not signed" in low and "does not prove" in low and "build log" in low
    for path in (VERIFIER, os.path.join(ROOT, "docs", "evidence-package-format.md")):
        text = open(path).read().lower()
        for word in FORBIDDEN + ("tamper",):
            assert word not in text, (path, word)


def test_pass_report_names_not_verified_items(good_zip, tmp_path):
    _code, out = run_verifier(good_zip, tmp_path)
    for fragment in ("Not verified", "Legacy v1 manifests", "entries_json manifests", "Snapshot manifests",
                     "Exported events with no seal"):
        assert fragment in out


# ---------------------------------------------------------------------------
# Contract additions (curated_event_types, period_manifest_ids, ordering, matrix counts)
# ---------------------------------------------------------------------------
def _seal_lines(data):
    return [json.loads(x) for x in data.decode().splitlines()]


def _rewrite_with_manifest(good_zip, tmp_path, edits, pm_edit=None):
    """Edit named files and refresh the package manifest's hashes so only the contract check can object."""
    with zipfile.ZipFile(good_zip) as zf:
        pm = json.loads(zf.read("package-manifest.json"))
        files = {i["path"]: zf.read(i["path"]) for i in pm["files"]}
    for name, fn in edits.items():
        files[name] = fn(files[name])
    for item in pm["files"]:
        item["sha256"] = hashlib.sha256(files[item["path"]]).hexdigest()
        item["bytes"] = len(files[item["path"]])
    if pm_edit:
        pm_edit(pm)
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
        zout.writestr("package-manifest.json", json.dumps(pm).encode())
    code, out = run_verifier(bad, tmp_path)
    assert code == 1, out
    return out.rstrip().splitlines()[-1]


def test_stripped_seals_file_fails(good_zip, tmp_path):
    last = _rewrite_with_manifest(good_zip, tmp_path, {"chain/seals.ndjson": lambda d: b""})
    assert "no line in chain/seals.ndjson" in last


def test_one_seal_line_removed_fails(good_zip, tmp_path):
    last = _rewrite_with_manifest(good_zip, tmp_path, {"chain/seals.ndjson": lambda d: d.split(b"\n", 1)[1]})
    assert "no line in chain/seals.ndjson" in last


def test_curated_event_missing_from_events_fails(good_zip, tmp_path):
    def drop(data):
        return b"".join(x for x in data.splitlines(True) if b'"evt-b1"' not in x)
    last = _rewrite_with_manifest(good_zip, tmp_path, {"events.ndjson": drop})
    assert "missing from events.ndjson" in last


def test_events_out_of_order_fail(good_zip, tmp_path):
    def swap(data):
        lines = data.splitlines(True)
        lines[0], lines[1] = lines[1], lines[0]
        return b"".join(lines)
    last = _rewrite_with_manifest(good_zip, tmp_path, {"events.ndjson": swap})
    assert "not ordered" in last


def test_matrix_count_mismatch_fails(good_zip, tmp_path):
    last = _rewrite_with_manifest(good_zip, tmp_path, {"control-matrix.csv": lambda d: d.replace(b'"9"', b'"8"')})
    assert "control-matrix.csv says 8 rows" in last


def test_report_files_missing_from_matrix_fail(good_zip, tmp_path):
    last = _rewrite_with_manifest(good_zip, tmp_path, {"control-matrix.csv": lambda d: d.split(b"\r\n")[0] + b"\r\n"})
    assert "not in control-matrix.csv" in last


def test_curated_event_without_seal_fails_when_no_legacy_manifest_could_hold_it(good_zip, tmp_path):
    """The seal line is removed and its id is dropped from period_manifest_ids too: the curated events it covered now have no seal."""
    first_id = {}

    def drop_first(data):
        first_id["id"] = json.loads(data.split(b"\n", 1)[0])["manifest_id"]
        return data.split(b"\n", 1)[1]

    def drop_id(pm):
        pm["period_manifest_ids"].remove(first_id["id"])
    last = _rewrite_with_manifest(good_zip, tmp_path, {"chain/seals.ndjson": drop_first}, drop_id)
    assert "of a sealed type have no seal" in last


def test_package_manifest_must_carry_the_new_fields(good_zip, tmp_path):
    last = _rewrite_with_manifest(good_zip, tmp_path, {}, lambda pm: pm.pop("curated_event_types"))
    assert "lacks: curated_event_types" in last


def test_report_prints_the_chain_head_and_points_to_the_build_log(good_zip, tmp_path):
    _code, out = run_verifier(good_zip, tmp_path)
    with zipfile.ZipFile(good_zip) as zf:
        head = json.loads(zf.read("package-manifest.json"))["chain_head"]
    assert "Chain head: " + head in out
    assert "server-side build log" in out and "only independent record" in out
