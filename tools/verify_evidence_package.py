#!/usr/bin/env python3
"""Offline verifier for an OPA Compliance Wizard evidence package, format v1.

Usage:  python3 -I tools/verify_evidence_package.py <package.zip>

Standard library only. It does not import anything from the application, never
extracts a file, and never opens a path that is named inside the package: the
zip is read in memory, entry by entry. Exit status: 0 = PASS, 1 = FAIL,
2 = the input could not be used (missing, not a zip, unreadable).

What a PASS shows and does not show is printed with every report and written
out in docs/evidence-package-format.md, which also gives the three hash
formulas this file implements.
"""
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile

FORMAT = 1
SNAPSHOT_SOURCE_PREFIX = "snapshot:"
REQUIRED_FILES = (
    "README-FOR-AUDITORS.txt",
    "cover-sheet.html",
    "control-matrix.csv",
    "events.ndjson",
    "chain/manifests.ndjson",
    "chain/seals.ndjson",
    "completeness.json",
    "what-this-tool-reads.txt",
)
MANIFEST_NAME = "package-manifest.json"
MANIFEST_KEYS = ("files", "built_at", "app_version", "environment_label_ascii", "period", "data_as_of",
                 "chain_head", "catalogue_version")
MAX_ENTRIES = 100000
MAX_PACKAGE_MANIFEST_BYTES = 64 * 1024 * 1024
CHUNK = 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME_OK = re.compile(r"^[A-Za-z0-9._ -]+$")
EVENT_UUID_COLUMN = "event_uuid"

NOT_PROVED = (
    "A PASS means the files in this package are the files its manifest lists, the exported events match the hashes sealed in\n"
    "the archive's chain as it stood when the package was built, and that chain links from its first record to its recorded head.\n"
    "It does not prove who produced the events, that the archive was never altered by someone who could rewrite it, or that\n"
    "events.ndjson holds every event of the period. The hashes are unkeyed and the package is not signed. The operator's\n"
    "server-side build log is the independent record."
)


class Report:
    def __init__(self):
        self.lines = []
        self.failures = []

    def info(self, text):
        self.lines.append(text)

    def fail(self, text):
        self.failures.append(text)
        self.lines.append("  FAIL: " + text)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --- the three hash formulas of format v1 (docs/evidence-package-format.md) ---

def content_hash_of_event(raw_json_bytes):
    """Event content hash: sha256 of the raw_json bytes (UTF-8)."""
    return sha256_hex(raw_json_bytes)


def manifest_content_hash(entries):
    """sha256 of "\\n".join(sorted("uuid:content_hash")) over the curated rows of a manifest."""
    return sha256_hex("\n".join(sorted(entries)).encode("utf-8"))


def manifest_entry_hash(prev_hash, environment_id, source, since, until, row_count, created_at, batch_hash, content_hash):
    parts = [prev_hash or "", environment_id, source, since or "", until or "", str(row_count), created_at, batch_hash,
             content_hash]
    return sha256_hex("\n".join(parts).encode("utf-8"))


# --- reading the zip safely ---

def unsafe_name(name):
    """The reason an entry name is refused, or None. Names are only ever compared, never used as paths."""
    if not name:
        return "empty name"
    if not all(0x20 <= ord(c) <= 0x7e for c in name):
        return "name is not printable ASCII"
    if "\\" in name:
        return "name contains a backslash"
    if name.startswith("/"):
        return "absolute name"
    if ":" in name:
        return "name contains a colon (drive-qualified)"
    if name.endswith("/"):
        return "directory entry"
    for part in name.split("/"):
        if part in ("", ".", ".."):
            return "name contains an empty, '.' or '..' part"
        if not NAME_OK.match(part):
            return "name contains a character outside letters, digits, '.', '_', '-' and space"
    return None


def read_stream(zf, info, limit=None):
    """Yields chunks of one entry; stops with ValueError past `limit` bytes."""
    total = 0
    with zf.open(info, "r") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                return
            total += len(chunk)
            if limit is not None and total > limit:
                raise ValueError("entry is larger than expected")
            yield chunk


def read_bytes(zf, info, limit):
    return b"".join(read_stream(zf, info, limit))


def iter_lines(zf, info):
    """Lines of an entry as bytes, each with its trailing newline (the last may lack one)."""
    with zf.open(info, "r") as fh:
        for line in fh:
            yield line


def load_json_bytes(data):
    return json.loads(data.decode("utf-8"))


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


# --- verification steps ---

def check_names(zf, report):
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        report.fail("too many entries (%d)" % len(infos))
        return None
    seen = set()
    by_name = {}
    ok = True
    for info in infos:
        name = info.filename
        reason = unsafe_name(name)
        if reason:
            report.fail("refused entry name %r: %s" % (name if len(name) < 80 else name[:80] + "...", reason))
            ok = False
            continue
        low = name.lower()
        if low in seen:
            report.fail("duplicate entry name %r" % name)
            ok = False
            continue
        seen.add(low)
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            report.fail("entry %r is not a regular file" % name)
            ok = False
            continue
        if info.flag_bits & 0x1:
            report.fail("entry %r is encrypted" % name)
            ok = False
            continue
        by_name[name] = info
    return by_name if ok else None


def check_package_manifest(zf, by_name, report):
    """Returns the parsed package-manifest.json or None."""
    info = by_name.get(MANIFEST_NAME)
    if info is None:
        report.fail("package-manifest.json is missing")
        return None
    try:
        manifest = load_json_bytes(read_bytes(zf, info, MAX_PACKAGE_MANIFEST_BYTES))
    except (ValueError, UnicodeDecodeError, zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError):
        report.fail("package-manifest.json is unreadable")
        return None
    if not isinstance(manifest, dict):
        report.fail("package-manifest.json is not a JSON object")
        return None
    if manifest.get("format") != FORMAT or isinstance(manifest.get("format"), bool):
        report.fail("package format is %r; this verifier reads format %d" % (manifest.get("format"), FORMAT))
        return None
    missing = [k for k in MANIFEST_KEYS if k not in manifest]
    if missing:
        report.fail("package-manifest.json lacks: " + ", ".join(missing))
        return None
    period = manifest["period"]
    if not (isinstance(period, dict) and isinstance(period.get("start"), str) and isinstance(period.get("end"), str)):
        report.fail("package-manifest.json period is not {start, end}")
        return None
    files = manifest["files"]
    if not isinstance(files, list):
        report.fail("package-manifest.json files is not a list")
        return None
    return manifest


def check_file_list(zf, by_name, manifest, report):
    listed = {}
    for item in manifest["files"]:
        if not (isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str)
                and is_int(item.get("bytes")) and item["bytes"] >= 0):
            report.fail("package-manifest.json has a malformed file record")
            return False
        if item["path"] in listed:
            report.fail("package-manifest.json lists %r twice" % item["path"])
            return False
        if not HEX64.match(item["sha256"]):
            report.fail("package-manifest.json has a malformed sha256 for %r" % item["path"])
            return False
        listed[item["path"]] = item
    actual = set(by_name) - {MANIFEST_NAME}
    ok = True
    extra = sorted(actual - set(listed))
    missing = sorted(set(listed) - actual)
    if MANIFEST_NAME in listed:
        report.fail("package-manifest.json lists itself")
        ok = False
    for name in extra:
        report.fail("file not listed in the manifest: %s" % name)
        ok = False
    for name in missing:
        report.fail("file listed in the manifest but absent: %s" % name)
        ok = False
    for name in REQUIRED_FILES:
        if name not in actual:
            report.fail("required file absent: %s" % name)
            ok = False
    hashed = 0
    for name in sorted(actual & set(listed)):
        want = listed[name]
        info = by_name[name]
        if info.file_size != want["bytes"]:
            report.fail("size of %s differs from the manifest" % name)
            ok = False
            continue
        h = hashlib.sha256()
        n = 0
        try:
            for chunk in read_stream(zf, info, want["bytes"]):
                h.update(chunk)
                n += len(chunk)
        except (ValueError, zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError):
            report.fail("%s could not be read intact" % name)
            ok = False
            continue
        if n != want["bytes"]:
            report.fail("size of %s differs from the manifest" % name)
            ok = False
        elif h.hexdigest() != want["sha256"]:
            report.fail("sha256 of %s differs from the manifest" % name)
            ok = False
        else:
            hashed += 1
    report.info("  Files: %d listed, %d checked against their sha256 and byte count" % (len(listed), hashed))
    return ok


def load_manifest_rows(zf, by_name, report):
    """Reads chain/manifests.ndjson. Returns the list of rows or None."""
    rows = []
    try:
        for n, line in enumerate(iter_lines(zf, by_name["chain/manifests.ndjson"]), 1):
            if not line.endswith(b"\n"):
                report.fail("chain/manifests.ndjson line %d is not newline-terminated" % n)
                return None
            rows.append(load_json_bytes(line[:-1]))
    except (ValueError, UnicodeDecodeError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        report.fail("chain/manifests.ndjson is unreadable")
        return None
    return rows


def check_chain(rows, package_manifest, report):
    """Walks the manifest rows the way audit_store.verify_ingestion_chain does. Returns (by_id, stats) or (None, None)."""
    stats = {"total": len(rows), "sealed": 0, "legacy": 0, "entries_json": 0, "snapshot": 0}
    by_id = {}
    expected_prev = None
    seen_v2 = False
    env_id = None
    last_id = None
    for row in rows:
        if not isinstance(row, dict):
            report.fail("chain/manifests.ndjson holds a row that is not an object")
            return None, None
        mid = row.get("manifest_id")
        if not is_int(mid) or (last_id is not None and mid <= last_id):
            report.fail("manifest ids are missing, repeated or out of order (at %r)" % (mid,))
            return None, None
        last_id = mid
        str_fields = ("environment_id", "source", "created_at", "batch_hash")
        if not all(isinstance(row.get(k), str) for k in str_fields) or not is_int(row.get("row_count")) or row["row_count"] < 0:
            report.fail("manifest %s is malformed" % mid)
            return None, None
        for opt in ("since", "until", "prev_manifest_hash", "content_hash", "entry_hash"):
            if opt not in row or not (row[opt] is None or isinstance(row[opt], str)):
                report.fail("manifest %s is malformed (%s)" % (mid, opt))
                return None, None
        if env_id is None:
            env_id = row["environment_id"]
        elif row["environment_id"] != env_id:
            report.fail("manifest %s belongs to another environment" % mid)
            return None, None
        if row["prev_manifest_hash"] != expected_prev:
            report.fail("chain broken at manifest %s: its previous-link hash does not match the manifest before it" % mid)
            return None, None
        by_id[mid] = row
        if not row["entry_hash"]:
            if seen_v2:
                report.fail("chain broken at manifest %s: a manifest without v2 fields follows a sealed manifest (downgrade)" % mid)
                return None, None
            stats["legacy"] += 1
            expected_prev = row["batch_hash"]
            continue
        seen_v2 = True
        if not row["content_hash"]:
            report.fail("chain broken at manifest %s: sealed manifest without a content hash" % mid)
            return None, None
        recomputed = manifest_entry_hash(row["prev_manifest_hash"], row["environment_id"], row["source"], row["since"],
                                         row["until"], row["row_count"], row["created_at"], row["batch_hash"],
                                         row["content_hash"])
        if recomputed != row["entry_hash"]:
            report.fail("chain broken at manifest %s: entry hash does not match the manifest's fields" % mid)
            return None, None
        if row["source"].startswith(SNAPSHOT_SOURCE_PREFIX):
            stats["snapshot"] += 1
        elif row.get("entries_json") is True:
            stats["entries_json"] += 1
        else:
            stats["sealed"] += 1
        expected_prev = row["entry_hash"]
    head = package_manifest["chain_head"]
    if not (head is None or isinstance(head, str)):
        report.fail("chain_head in the package manifest is malformed")
        return None, None
    if head != expected_prev:
        if rows:
            report.fail("the chain ends before the recorded head: manifests were removed from the end, or the head differs")
        else:
            report.fail("the package records a chain head but holds no manifests")
        return None, None
    if not rows and head is None:
        report.info("  Chain: the package holds no manifests and records no head (an archive with nothing ingested)")
    else:
        report.info("  Chain: %d manifests link from the first record to the recorded head" % len(rows))
    return by_id, stats


def load_seals(zf, by_name, by_id, report):
    """Reads chain/seals.ndjson and recomputes each manifest's content hash.
    Returns (uuid_to_seals, info) or (None, None)."""
    uuid_seals = {}
    seen = set()
    checked = 0
    unsealed_rows = 0
    skipped = 0
    try:
        for n, line in enumerate(iter_lines(zf, by_name["chain/seals.ndjson"]), 1):
            if not line.endswith(b"\n"):
                report.fail("chain/seals.ndjson line %d is not newline-terminated" % n)
                return None, None
            rec = load_json_bytes(line[:-1])
            if not (isinstance(rec, dict) and is_int(rec.get("manifest_id")) and isinstance(rec.get("entries"), list)):
                report.fail("chain/seals.ndjson line %d is malformed" % n)
                return None, None
            mid = rec["manifest_id"]
            row = by_id.get(mid)
            if row is None:
                report.fail("a seal names manifest %s, which is not in the chain" % mid)
                return None, None
            if mid in seen:
                report.fail("manifest %s has two seal records" % mid)
                return None, None
            seen.add(mid)
            if (not row["entry_hash"] or row["source"].startswith(SNAPSHOT_SOURCE_PREFIX) or row.get("entries_json") is True):
                skipped += 1  # legacy, snapshot and entries_json manifests are reported as not verified
                continue
            pairs = []
            names = set()
            for item in rec["entries"]:
                if not isinstance(item, str) or ":" not in item:
                    report.fail("manifest %s has a malformed seal entry" % mid)
                    return None, None
                uuid, sha = item.rsplit(":", 1)
                if not uuid or not HEX64.match(sha) or uuid in names:
                    report.fail("manifest %s has a malformed or repeated seal entry" % mid)
                    return None, None
                names.add(uuid)
                pairs.append((uuid, sha))
            if len(pairs) > row["row_count"]:
                report.fail("manifest %s lists more sealed rows than its row_count" % mid)
                return None, None
            if manifest_content_hash([u + ":" + s for u, s in pairs]) != row["content_hash"]:
                report.fail("manifest %s: its sealed entries do not recompute to its content hash" % mid)
                return None, None
            for uuid, sha in pairs:
                uuid_seals.setdefault(uuid, []).append((mid, sha))
            unsealed_rows += row["row_count"] - len(pairs)
            checked += 1
    except (ValueError, UnicodeDecodeError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        report.fail("chain/seals.ndjson is unreadable")
        return None, None
    report.info("  Seals: content hash recomputed from the sealed entries for %d manifests" % checked)
    return uuid_seals, {"unsealed_rows": unsealed_rows, "skipped": skipped}


def check_events(zf, by_name, uuid_seals, report):
    """Hashes every line of events.ndjson against the seals. Returns (uuids set, counts) or (None, None)."""
    uuids = set()
    verified = 0
    unverified = 0
    bad = []
    try:
        for n, line in enumerate(iter_lines(zf, by_name["events.ndjson"]), 1):
            if not line.endswith(b"\n"):
                report.fail("events.ndjson line %d is not newline-terminated" % n)
                return None, None
            body = line[:-1]
            try:
                event = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                report.fail("events.ndjson line %d is not valid UTF-8 JSON" % n)
                return None, None
            uuid = event.get("uuid") if isinstance(event, dict) else None
            if not isinstance(uuid, str) or not uuid:
                report.fail("events.ndjson line %d has no event uuid" % n)
                return None, None
            if uuid in uuids:
                report.fail("events.ndjson holds event %s twice" % uuid)
                return None, None
            uuids.add(uuid)
            seals = uuid_seals.get(uuid)
            if not seals:
                unverified += 1
                continue
            digest = content_hash_of_event(body)
            if all(sha == digest for _mid, sha in seals):
                verified += 1
            else:
                bad.append(uuid)
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        report.fail("events.ndjson is unreadable")
        return None, None
    if bad:
        report.fail("%d event(s) do not match their sealed hash (first: %s)" % (len(bad), bad[0]))
    report.info("  Events: %d in events.ndjson; %d match a sealed hash; %d have no seal in this package (not verified)"
                % (len(uuids), verified, unverified))
    return uuids, {"verified": verified, "unverified": unverified, "bad": len(bad)}


def check_csvs(zf, by_name, uuids, report):
    names = sorted(n for n in by_name if n.endswith(".csv") and n.startswith("controls/"))
    csv.field_size_limit(64 * 1024 * 1024)
    rows_checked = 0
    rows_blank = 0
    missing = []
    for name in names:
        try:
            with zf.open(by_name[name], "r") as raw:
                text = io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
                reader = csv.reader(text)
                header = next(reader, None)
                if header is None or EVENT_UUID_COLUMN not in header:
                    report.fail("%s has no %s column" % (name, EVENT_UUID_COLUMN))
                    continue
                col = header.index(EVENT_UUID_COLUMN)
                for rec in reader:
                    if not rec:
                        continue
                    value = rec[col] if col < len(rec) else ""
                    if value == "":
                        rows_blank += 1
                        continue
                    if value in uuids or (value.startswith("'") and value[1:] in uuids):
                        rows_checked += 1
                    else:
                        missing.append((name, value))
        except (csv.Error, UnicodeDecodeError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
            report.fail("%s could not be read as CSV" % name)
    if missing:
        report.fail("%d CSV row(s) name an event that is not in events.ndjson (first: %s in %s)"
                    % (len(missing), missing[0][1], missing[0][0]))
    # control-matrix.csv must at least parse
    try:
        with zf.open(by_name["control-matrix.csv"], "r") as raw:
            for _ in csv.reader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")):
                pass
    except (csv.Error, UnicodeDecodeError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        report.fail("control-matrix.csv could not be read as CSV")
    report.info("  CSV files: %d report files; %d rows tie to an event in events.ndjson; %d rows carry no %s (not verified)"
                % (len(names), rows_checked, rows_blank, EVENT_UUID_COLUMN))
    return rows_blank


def read_completeness(zf, by_name, report):
    try:
        data = load_json_bytes(read_bytes(zf, by_name["completeness.json"], 256 * 1024 * 1024))
    except (ValueError, UnicodeDecodeError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        report.fail("completeness.json is unreadable")
        return None
    if not isinstance(data, dict):
        report.fail("completeness.json is not a JSON object")
        return None
    return data


def pruned_count(completeness):
    value = completeness.get("pruned_days")
    if is_int(value):
        return value
    if isinstance(value, list):
        return len(value)
    return None


def verify(path, out):
    report = Report()
    try:
        zf = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        out.write("Cannot use the input: %s\n" % (exc.__class__.__name__,))
        return 2
    with zf:
        report.info("OPA Compliance Wizard evidence package verifier (format v%d)" % FORMAT)
        report.info("Package: %s" % os.path.basename(path))
        by_name = check_names(zf, report)
        manifest = None
        if by_name is not None:
            manifest = check_package_manifest(zf, by_name, report)
        if manifest is not None:
            period = manifest["period"]
            report.info("Built %s by app version %s; environment label %s; period %s to %s (UTC, inclusive); data as of %s"
                        % (manifest["built_at"], manifest["app_version"], manifest["environment_label_ascii"],
                           period["start"], period["end"], manifest["data_as_of"]))
            report.info("Checks:")
            files_ok = check_file_list(zf, by_name, manifest, report)
            present = all(n in by_name for n in REQUIRED_FILES)
            if present:
                rows = load_manifest_rows(zf, by_name, report)
                by_id, stats = (None, None)
                if rows is not None:
                    by_id, stats = check_chain(rows, manifest, report)
                uuid_seals = seal_info = None
                if by_id is not None:
                    uuid_seals, seal_info = load_seals(zf, by_name, by_id, report)
                uuids = counts = None
                if uuid_seals is not None:
                    uuids, counts = check_events(zf, by_name, uuid_seals, report)
                blank = 0
                if uuids is not None:
                    blank = check_csvs(zf, by_name, uuids, report)
                completeness = read_completeness(zf, by_name, report)
                if stats is not None and seal_info is not None and counts is not None:
                    report.info("Not verified (stated, never counted as verified):")
                    report.info("  Legacy v1 manifests (identifier-only, no content seal): %d" % stats["legacy"])
                    report.info("  entries_json manifests (older sealing format): %d" % stats["entries_json"])
                    report.info("  Snapshot manifests (chain link checked, objects not in this package): %d" % stats["snapshot"])
                    report.info("  Rows counted by the sealed manifests that hold events of the period but not content-sealed "
                                "(not curated; retention may have removed them): %d" % seal_info["unsealed_rows"])
                    report.info("  Exported events with no seal in this package: %d" % counts["unverified"])
                    report.info("  CSV rows without an %s: %d" % (EVENT_UUID_COLUMN, blank))
                    if completeness is not None and pruned_count(completeness) is not None:
                        report.info("  Pruned days stated by the package builder: %d (a statement, not checked here)"
                                    % pruned_count(completeness))
                    if uuids and counts["verified"] == 0 and not report.failures:
                        report.info("  WARNING: none of the %d exported events could be matched to a seal." % len(uuids))
        report.lines.append("")
        report.lines.append(NOT_PROVED)
        report.lines.append("")
        if report.failures:
            shown = report.failures[:5]
            more = len(report.failures) - len(shown)
            reasons = "; ".join(shown) + ("; and %d more" % more if more else "")
            report.lines.append("RESULT: FAIL (%s)" % reasons)
            code = 1
        else:
            report.lines.append("RESULT: PASS")
            code = 0
    out.write("\n".join(report.lines) + "\n")
    return code


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write("usage: python3 -I verify_evidence_package.py <package.zip>\n")
        return 2
    path = argv[1]
    if not os.path.isfile(path):
        sys.stdout.write("Cannot use the input: not a file\n")
        return 2
    try:
        return verify(path, sys.stdout)
    except Exception as exc:  # never end without a RESULT line
        sys.stdout.write("RESULT: FAIL (the verifier could not finish: %s)\n" % exc.__class__.__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
