"""Streaming core of the evidence package (5.53.0, WP2).

Kept in its own module, not in audit_store.py: audit_store is already about
4,000 lines and everything here is read-only, so it sits on top of it
(importing its canonical-timestamp rule, its report definitions and its
seal helpers) without growing the module that owns the writes. The packer
(WP4) and the report CSV route (WP6) import from here; nothing in this
module opens an HTTP route, builds a zip or writes outside the file object
it is handed.

Pieces:

1. Period      parse_period(): two UTC dates, inclusive -> a half-open range on
               the canonical `published` text.
2. Snapshot    open_snapshot(): ONE read transaction on its own connection.
               Everything the package states about the archive (events, per
               report counts, manifests, the chain head, seals, coverage,
               completeness) is read inside it, so a sync that commits while
               a build runs cannot make the parts disagree. Rows are
               streamed with fetchmany; nothing is held as a full list and
               nothing is capped.
3. CSV         write_report_csv() / csv_line(): every field quoted, CRLF,
               no byte-order mark (the frontend export writes none), formula
               neutralisation identical to frontend/src/utils/export.ts.
4. Coverage    Snapshot.coverage(): a state per day of the period.
5. Completeness Snapshot.completeness(): per report row counts and seal
               status, scope, and the coverage statement.

Honesty limits are stated where they arise (see Snapshot.coverage()).
Nothing here writes to the archive.
"""
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

import audit_store

CSV_BATCH_LINES = 2000       # lines buffered before one write to the file object
FETCH_SIZE = 2000            # rows per fetchmany
MAX_PERIOD_DAYS = 3660       # ten years; a longer span is a typo or an abuse, and the per-day coverage list scales with it
EVENT_UUID_COLUMN = "event_uuid"

# Day states (Snapshot.coverage). `after_data_as_of` is not a gap: the build says the
# data ends at the last successful sync (spec section 4).
DAY_COVERED_EVENTS = "covered_with_events"
DAY_COVERED_ZERO = "covered_zero_events"
DAY_NOT_COVERED = "not_covered"
DAY_PRUNED = "pruned_by_retention"
DAY_BEFORE_ARCHIVE = "before_archive"
DAY_AFTER_DATA_AS_OF = "after_data_as_of"
DAY_STATES = (DAY_COVERED_EVENTS, DAY_COVERED_ZERO, DAY_NOT_COVERED, DAY_PRUNED, DAY_BEFORE_ARCHIVE, DAY_AFTER_DATA_AS_OF)
COVERED_STATES = (DAY_COVERED_EVENTS, DAY_COVERED_ZERO, DAY_PRUNED)


class EvidenceError(Exception):
    """The archive cannot be read as evidence (no archive file, an event line that would break the format)."""


class PeriodError(ValueError):
    """The period is not two UTC dates, start <= end, end not after today (UTC)."""


# ---------------------------------------------------------------------------
# 1. Period
# ---------------------------------------------------------------------------
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$", re.ASCII)


def _parse_date(label, value):
    if not isinstance(value, str) or not _DATE_RE.match(value):
        raise PeriodError(f"{label} must be a date written YYYY-MM-DD")
    try:
        return date(int(value[:4]), int(value[5:7]), int(value[8:10]))
    except ValueError:
        raise PeriodError(f"{label} is not a real calendar date") from None


class Period:
    """Two UTC calendar dates, inclusive. `start_ts`/`end_ts` are the half-open range
    [start 00:00:00.000Z, end+1 00:00:00.000Z) on the canonical `published` text."""

    def __init__(self, start, end):
        self.start = start
        self.end = end

    @property
    def start_ts(self):
        return self.start.strftime("%Y-%m-%dT00:00:00.000Z")

    @property
    def end_ts(self):
        return (self.end + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00.000Z")

    @property
    def day_count(self):
        return (self.end - self.start).days + 1

    def days(self):
        return [self.start + timedelta(days=i) for i in range(self.day_count)]

    def as_dict(self):
        """The shape package-manifest.json carries."""
        return {"start": self.start.isoformat(), "end": self.end.isoformat()}

    def __eq__(self, other):
        return isinstance(other, Period) and (self.start, self.end) == (other.start, other.end)

    def __hash__(self):
        return hash((self.start, self.end))

    def __repr__(self):
        return f"Period({self.start.isoformat()}..{self.end.isoformat()})"


def parse_period(start, end, today=None):
    """Validates a period (spec section 4) and returns a Period. `today` (a date) is for tests; the default is
    today in UTC. Raises PeriodError with a short reason that is safe to show to the person who asked."""
    s = _parse_date("The start date", start)
    e = _parse_date("The end date", end)
    if s > e:
        raise PeriodError("The start date is after the end date")
    today = today or datetime.now(timezone.utc).date()
    if e > today:
        raise PeriodError("The end date is in the future (dates are UTC)")
    if (e - s).days + 1 > MAX_PERIOD_DAYS:
        raise PeriodError(f"The period is longer than {MAX_PERIOD_DAYS} days")
    return Period(s, e)


# ---------------------------------------------------------------------------
# 3. CSV writer (spec section 6)
# ---------------------------------------------------------------------------
# Same rule, same test cases as frontend/src/utils/export.ts neutralizeFormula/csvEscape
# (tests/fixtures/csv_formula_cases.json is read by both test suites).
_FORMULA_START_RE = re.compile(r"^[=+\-@\t\r]")

REPORT_CSV_COLUMNS = (
    "User", "User Email/ID", "Client IP", "Client Location", "Action", "Timestamp", "Request ID",
    "Affected Resource", "Resource Email/ID", "Resource Type", "Outcome", "Outcome Reason", "Event Type",
    EVENT_UUID_COLUMN,
)

# Port of frontend/src/utils/resourceTypeLabels.ts (a test compares the two).
RESOURCE_TYPE_DETAIL_LABEL = {
    "PAM_DATABASE_ACCOUNT": "Database Account",
    "SERVER_ACCOUNT": "Server Account",
    "MANAGED_SAAS_APP_SERVICE_ACCOUNT": "SaaS Service Account",
    "APP_ACCOUNT": "SaaS Service Account",
    "OKTA_USER_ACCOUNT": "Okta Service Account",
    "DATABASE_ACCOUNT": "Database Account",
    "PAM_AD_ACCOUNT": "Active Directory Account",
    "SIGNED_NONCE": "Okta Verify (FastPass)",
    "signed_nonce": "Okta Verify (FastPass)",
    "OKTA_VERIFY_PUSH": "Okta Verify (Push)",
    "PASSWORD_AS_FACTOR": "Password",
}


def neutralize_formula(value):
    """A value starting with = + - @ tab or CR gets a leading apostrophe (spreadsheet formula injection)."""
    return "'" + value if _FORMULA_START_RE.match(value) else value


def csv_field(value):
    """One field, neutralised and always quoted. None is the empty string."""
    text = "" if value is None else value if isinstance(value, str) else str(value)
    return '"' + neutralize_formula(text).replace('"', '""') + '"'


def csv_line(cells):
    """One CSV record as bytes: every field quoted, CRLF line end, UTF-8 without a byte-order mark. A character that
    cannot be encoded (a lone surrogate from a JSON escape) becomes '?' rather than failing the build."""
    return (",".join(csv_field(c) for c in cells) + "\r\n").encode("utf-8", errors="replace")


class CsvWriter:
    """Streams records to a BINARY file object (an open file, a zip entry). Buffers CSV_BATCH_LINES lines per write."""

    def __init__(self, fp, columns):
        self._fp = fp
        self._buf = []
        self.rows = 0
        self._buf.append(csv_line(columns))

    def write_row(self, cells):
        self._buf.append(csv_line(cells))
        self.rows += 1
        if len(self._buf) >= CSV_BATCH_LINES:
            self.flush()

    def flush(self):
        if self._buf:
            self._fp.write(b"".join(self._buf))
            self._buf = []


def report_csv_cells(row):
    """The cells of one report row, in REPORT_CSV_COLUMNS order. `row` is a dict from Snapshot.report_rows()
    (or audit_store._four_field_row's output plus 'uuid'). Same columns as the report export in the app
    (complianceReportRow), plus event_uuid. The Timestamp is the archive's canonical UTC time (the app formats it in the
    reader's locale, which a file for auditors cannot depend on)."""
    detail = row.get("resource_type_detail") or ""
    resource_type = RESOURCE_TYPE_DETAIL_LABEL.get(detail, detail) if detail else (row.get("resource_type") or "")
    ids = [v for v in (row.get("resource_alternate_id"), row.get("resource_id")) if v and v != "unknown"]
    return [
        row.get("user") or "",
        row.get("actor_alternate_id") or "",
        row.get("client_ip") or "",
        row.get("client_geo") or "",
        row.get("action") or "",
        row.get("timestamp") or "",
        row.get("request_id") or "",
        row.get("resource") or "—",
        " / ".join(ids),
        resource_type,
        row.get("outcome") or "",
        row.get("outcome_reason") or "",
        row.get("event_type") or "",
        row.get("uuid") or "",
    ]


def write_report_csv(fp, rows):
    """Streams report rows (an iterable of dicts shaped by audit_store._four_field_row, e.g. Snapshot.report_rows())
    into `fp`. Returns the number of data rows written. The header is always written, so a report with no rows is a
    valid file of one line."""
    writer = CsvWriter(fp, REPORT_CSV_COLUMNS)
    for row in rows:
        writer.write_row(report_csv_cells(row))
    writer.flush()
    return writer.rows


def prune_records_from_audit_log(environment_name, path=None):
    """The retention runs the application logged for one environment: [{"at": iso, "cutoff": iso or None, "pruned": int}].
    Every sync ends with prune_events() and writes its result (`pruned`, `cutoff`) into the `sync.scheduled_completed` /
    `sync.manual_completed` entry of audit_log.jsonl, which carries the environment's display name (not its id). That
    file is outside the archive database and outside the snapshot, and can be rotated or absent: [] then means "no
    run recorded", which the coverage statement words as such. Streams the file; unparseable lines are skipped."""
    if path is None:
        import create_secret_folders
        path = create_secret_folders._audit_log_path()
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, "rb") as f:
        for raw in f:
            if b"_completed" not in raw or b'"pruned"' not in raw:
                continue
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            action = entry.get("action") if isinstance(entry, dict) else None
            details = entry.get("details") if isinstance(entry, dict) else None
            if not (isinstance(action, str) and action.startswith("sync.") and action.endswith("_completed") and isinstance(details, dict)):
                continue
            if details.get("name") != environment_name or not isinstance(details.get("pruned"), int):
                continue
            cutoff = details.get("cutoff")
            out.append({"at": entry.get("timestamp"), "cutoff": cutoff if isinstance(cutoff, str) else None, "pruned": details["pruned"]})
    return out


# ---------------------------------------------------------------------------
# 2. One-snapshot reader
# ---------------------------------------------------------------------------
_REPORT_ROW_SQL = (
    "SELECT uuid, event_type, published, actor_id, actor_display_name, actor_alternate_id, outcome_result, "
    "resource_id, resource_alternate_id, resource_type_detail, raw_json FROM events "
    "WHERE environment_id = ? AND event_type IN ({types}) AND published >= ? AND published < ? "
    "ORDER BY published, uuid"
)
# INDEXED BY: the (environment_id, published) index delivers rows already in published order, so SQLite only
# sorts the few rows that share a timestamp (by uuid) instead of the whole period with raw_json attached.
_EVENT_LINE_SQL = (
    "SELECT raw_json FROM events INDEXED BY idx_events_env_published "
    "WHERE environment_id = ? AND published >= ? AND published < ? ORDER BY published, uuid"
)

_MANIFEST_FIELDS = (
    "id AS manifest_id", "environment_id", "source", "since", "until", "row_count", "batch_hash",
    "prev_manifest_hash", "created_at", "content_hash", "entry_hash", "(entries_json IS NOT NULL) AS entries_json",
)


def _chunks(cursor, size=FETCH_SIZE):
    while True:
        rows = cursor.fetchmany(size)
        if not rows:
            return
        for row in rows:
            yield row


@contextmanager
def open_snapshot(environment_id, period, now=None, prune_records=None):
    """Opens ONE read transaction on a connection of its own and yields a Snapshot bound to it. The transaction is a
    deferred BEGIN made real by an immediate read; in WAL mode a sync (or anything else) may commit while it is
    open and the snapshot does not see it. The connection is closed on exit and every iterator taken from the
    snapshot must be used inside the `with`. A long snapshot holds back WAL checkpointing for its duration, which is
    the price of one consistent view.

    `prune_records`: what the caller knows of past retention runs, [{"cutoff": iso or None, "pruned": int}, ...]
    (see prune_records_from_audit_log). The archive database itself keeps no prune history; None means "not
    supplied" and the pruned days are then inferred from the current retention setting (see Snapshot.coverage)."""
    path = audit_store._audit_db_path()
    if path == ":memory:" or not os.path.exists(path):
        raise EvidenceError("the archive file does not exist")
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        snap = Snapshot(conn, environment_id, period, now=now, prune_records=prune_records)
        yield snap
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()


def _merge(intervals):
    merged = []
    for s, e in sorted(intervals):
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    return merged


class Snapshot:
    """Everything the package needs from the archive, read inside one transaction. Created by open_snapshot()."""

    def __init__(self, conn, environment_id, period, now=None, prune_records=None):
        self._conn = conn
        self._prune_records = prune_records
        self.environment_id = environment_id
        self.period = period
        self._now = now or datetime.now(timezone.utc)
        self._cache = {}
        # The first read is what pins the snapshot (a deferred BEGIN takes it at the first SELECT).
        head = conn.execute(
            "SELECT manifest_id, head_hash FROM chain_heads WHERE environment_id = ?", (environment_id,)
        ).fetchone()
        self.chain_head = {"manifest_id": head["manifest_id"], "head_hash": head["head_hash"]} if head else None
        self.curated_event_types = sorted(audit_store.COMPLIANCE_EVENT_TYPES)

    # -- helpers ----------------------------------------------------------
    def _range(self):
        return (self.period.start_ts, self.period.end_ts)

    def _cached(self, key, make):
        if key not in self._cache:
            self._cache[key] = make()
        return self._cache[key]

    # -- events -------------------------------------------------------------
    def report_event_types(self, report_key):
        if report_key not in audit_store.COMPLIANCE_REPORTS:
            raise KeyError(f"Unknown report: {report_key!r}")
        return audit_store._event_types_for_report(report_key)

    def report_rows(self, report_key):
        """Yields every event of one report in the period, oldest first (ties by uuid), as the dict
        audit_store._four_field_row produces (plus 'uuid'): never capped, never a full list."""
        types = self.report_event_types(report_key)
        if not types:
            return
        sql = _REPORT_ROW_SQL.format(types=",".join("?" for _ in types))
        cur = self._conn.execute(sql, (self.environment_id, *types, *self._range()))
        for r in _chunks(cur):
            d = dict(r)
            d["raw"] = json.loads(d.pop("raw_json"))
            yield audit_store._four_field_row(d)

    def event_lines(self):
        """Yields every stored event of the period, oldest first (ties by uuid), as bytes: the stored raw_json
        exactly, UTF-8, plus one b"\\n". These are the events.ndjson lines. A raw_json holding a line break would
        split a record, so it fails the build instead (json.dumps output never has one)."""
        cur = self._conn.execute(_EVENT_LINE_SQL, (self.environment_id, *self._range()))
        for r in _chunks(cur):
            line = r["raw_json"].encode("utf-8")
            if b"\n" in line or b"\r" in line:
                raise EvidenceError("a stored event holds a line break and cannot be written as one line")
            yield line + b"\n"

    def estimate_event_bytes(self, sample=500):
        """Rough size of events.ndjson for the period, in bytes: the period's event count times the average raw_json
        length of the newest `sample` events of the period (a bounded read through the published index). Used by the
        packer for its free-space check, never for a statement about the archive."""
        def make():
            n = self.events_in_period()
            if not n:
                return 0
            row = self._conn.execute(
                "SELECT AVG(l) FROM (SELECT LENGTH(raw_json) AS l FROM events INDEXED BY idx_events_env_published "
                "WHERE environment_id = ? AND published >= ? AND published < ? ORDER BY published DESC LIMIT ?)",
                (self.environment_id, *self._range(), sample)).fetchone()
            return int(n * ((row[0] or 0) + 1))
        return self._cached("estimate_event_bytes", make)

    # -- counts ---------------------------------------------------------------
    def event_type_counts(self):
        """{event_type: rows in the period} for every curated event type (zero included), from the covering index."""
        def make():
            out = {}
            for t in self.curated_event_types:
                out[t] = self._conn.execute(
                    "SELECT COUNT(*) FROM events WHERE environment_id = ? AND event_type = ? AND published >= ? AND published < ?",
                    (self.environment_id, t, *self._range()),
                ).fetchone()[0]
            return out
        return self._cached("type_counts", make)

    def report_counts(self):
        """{report_key: rows in the period} for every report, zero included. Equals the number of rows
        report_rows() yields (same snapshot, same predicate)."""
        counts = self.event_type_counts()
        return {key: sum(counts[t] for t in audit_store._event_types_for_report(key)) for key in audit_store.COMPLIANCE_REPORTS}

    def events_in_period(self):
        return self._cached("events_in_period", lambda: self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE environment_id = ? AND published >= ? AND published < ?",
            (self.environment_id, *self._range())).fetchone()[0])

    # -- chain ------------------------------------------------------------------
    def iter_manifests(self):
        """Yields every manifest row of the environment from the first to the head (the chain_heads row), in chain
        order, with exactly the fields chain/manifests.ndjson carries (docs/evidence-package-format.md).
        `entries_json` is a bool. Rows after the head (written by older code) are not included, so the last link
        equals the recorded head. Without a head row every manifest is included and chain_head is None."""
        sql = "SELECT " + ", ".join(_MANIFEST_FIELDS) + " FROM ingestion_manifests WHERE environment_id = ?"
        params = [self.environment_id]
        if self.chain_head:
            sql += " AND id <= ?"
            params.append(self.chain_head["manifest_id"])
        cur = self._conn.execute(sql + " ORDER BY id ASC", params)
        for r in _chunks(cur):
            d = dict(r)
            d["entries_json"] = bool(d["entries_json"])
            yield d

    def head_consistent(self):
        """True when the last manifest row up to the head links to the recorded head hash (or both are absent). A False
        here means the archive's own integrity check would fail; the packer should refuse rather than package it."""
        last = None
        for last in self.iter_manifests():
            pass
        if self.chain_head is None:
            return last is None
        if last is None:
            return False
        return (last["entry_hash"] or last["batch_hash"]) == self.chain_head["head_hash"]

    def _entries_json_pairs(self):
        """{manifest_id: [(uuid, sha), ...]} for older-format manifests (entries in one cell). Rare; held in memory."""
        out = {}
        for r in self._conn.execute(
            "SELECT id, entries_json FROM ingestion_manifests WHERE environment_id = ? AND entries_json IS NOT NULL",
            (self.environment_id,),
        ):
            try:
                out[r["id"]] = [(str(p[0]), str(p[1])) for p in json.loads(r["entries_json"])]
            except (ValueError, TypeError, IndexError):
                out[r["id"]] = []
        return out

    def _legacy_count(self):
        return self._cached("legacy_count", lambda: self._conn.execute(
            "SELECT COUNT(*) FROM ingestion_manifests WHERE environment_id = ? AND entry_hash IS NULL",
            (self.environment_id,)).fetchone()[0])

    def _boundary(self):
        return self._cached("boundary", lambda: audit_store._unsealed_boundary(self._conn, self.environment_id, self._legacy_count()))

    def _entries_json_uuids(self):
        return self._cached("ej_uuids", lambda: {u for pairs in self._entries_json_pairs().values() for u, _s in pairs})

    def _sealed_manifest_ids_with_period_events(self):
        """Ids of every sealed, non-snapshot manifest that holds a curated event of the period."""
        def make():
            ids = set()
            for r in self._conn.execute(
                """SELECT DISTINCT me.manifest_id AS mid
                   FROM events e
                   JOIN manifest_entries me ON me.environment_id = e.environment_id AND me.uuid = e.uuid
                   JOIN ingestion_manifests m ON m.id = me.manifest_id AND m.environment_id = e.environment_id
                   WHERE e.environment_id = ? AND e.is_curated = 1 AND e.published >= ? AND e.published < ?
                     AND m.source NOT LIKE 'snapshot:%'""",
                (self.environment_id, *self._range()),
            ):
                ids.add(r["mid"])
            for mid, pairs in self._entries_json_pairs().items():
                for u, _s in pairs:
                    hit = self._conn.execute(
                        "SELECT 1 FROM events WHERE environment_id = ? AND uuid = ? AND published >= ? AND published < ?",
                        (self.environment_id, u, *self._range()),
                    ).fetchone()
                    if hit:
                        ids.add(mid)
                        break
            return ids
        return self._cached("sealed_period_ids", make)

    def _legacy_candidate_ids(self):
        """Legacy (identifier-only) manifests that may hold events of the period. They record no uuids, so this is
        a plausibility rule, not knowledge: the manifest's own since/until window overlaps the period, or it has no
        window (a CSV import) and was written after the period began. Only used when the period holds curated events
        that no seal names (see period_manifest_ids)."""
        start, end = self._range()
        ids = []
        for r in self._conn.execute(
            "SELECT id, since, until, created_at FROM ingestion_manifests "
            "WHERE environment_id = ? AND entry_hash IS NULL AND source NOT LIKE 'snapshot:%' ORDER BY id",
            (self.environment_id,),
        ):
            if r["since"] and r["until"]:
                if r["since"] < end and r["until"] >= start:
                    ids.append(r["id"])
            elif (r["created_at"] or "") >= start:
                ids.append(r["id"])
        return ids

    def period_manifest_ids(self):
        """Ascending ids of every manifest that holds an event of the period. Sealed manifests (including older-format
        entries_json ones) are exact. Legacy manifests record no uuids: they are listed only when the period holds
        curated events no seal names and the archive has legacy manifests (the one case where the verifier must
        tolerate unsealed events), and then by the plausibility rule in _legacy_candidate_ids. Ids beyond the head
        are never listed (the packer ships the chain only up to the head)."""
        def make():
            ids = set(self._sealed_manifest_ids_with_period_events())
            if self.completeness_counts()["legacy_v1"]:
                ids.update(self._legacy_candidate_ids())
            if self.chain_head:
                ids = {i for i in ids if i <= self.chain_head["manifest_id"]}
            return sorted(ids)
        return self._cached("period_ids", make)

    def iter_seal_chunks(self):
        """Yields bytes: chain/seals.ndjson, one line per sealed non-snapshot manifest that holds an event of the
        period (older-format entries_json manifests included), ascending manifest_id:
        {"manifest_id": N, "entries": ["uuid:sha", ...], "published": [canonical time of each entry's event, ...]}.
        `entries` are ALL the manifest's curated rows, sorted by the full 'uuid:sha' string (the content-hash order);
        `published` is parallel. Streamed in pieces, so a manifest of a million entries is never a Python list.
        An entry whose event is no longer in the archive has no published time; the manifest's created_at stands in
        (an event cannot be older than the batch that sealed it is new) and is counted in
        sealed_entries_without_event() so the packer can refuse or warn."""
        ej = self._entries_json_pairs()
        ids = list(self._sealed_manifest_ids_with_period_events())
        if self.chain_head:
            ids = [i for i in ids if i <= self.chain_head["manifest_id"]]
        for mid in sorted(ids):
            created = self._conn.execute("SELECT created_at FROM ingestion_manifests WHERE id = ?", (mid,)).fetchone()["created_at"]
            fallback = audit_store._canonical_published(created) or created
            if mid in ej:
                rows = []
                for u, sha in ej[mid]:
                    e = self._conn.execute(
                        "SELECT published FROM events WHERE environment_id = ? AND uuid = ?", (self.environment_id, u)).fetchone()
                    rows.append((f"{u}:{sha}", e["published"] if e else fallback))
                rows.sort()
                yield (b'{"manifest_id":%d,"entries":' % mid) + json.dumps([r[0] for r in rows], separators=(",", ":")).encode("utf-8")
                yield b',"published":' + json.dumps([r[1] for r in rows], separators=(",", ":")).encode("utf-8") + b"}\n"
                continue
            yield b'{"manifest_id":%d,"entries":[' % mid
            cur = self._conn.execute(
                "SELECT me.uuid || ':' || me.sha AS line FROM manifest_entries me WHERE me.manifest_id = ? ORDER BY line", (mid,))
            first = True
            buf = []
            for r in _chunks(cur):
                buf.append(("" if first else ",") + json.dumps(r["line"]))
                first = False
                if len(buf) >= 1000:
                    yield "".join(buf).encode("utf-8")
                    buf = []
            if buf:
                yield "".join(buf).encode("utf-8")
            yield b'],"published":['
            cur = self._conn.execute(
                """SELECT COALESCE(e.published, ?) AS published
                   FROM manifest_entries me
                   LEFT JOIN events e ON e.environment_id = me.environment_id AND e.uuid = me.uuid
                   WHERE me.manifest_id = ? ORDER BY me.uuid || ':' || me.sha""", (fallback, mid))
            first = True
            buf = []
            for r in _chunks(cur):
                buf.append(("" if first else ",") + json.dumps(r["published"]))
                first = False
                if len(buf) >= 1000:
                    yield "".join(buf).encode("utf-8")
                    buf = []
            if buf:
                yield "".join(buf).encode("utf-8")
            yield b"]}\n"

    def iter_seals(self):
        """The seal records as dicts (convenience for tests and small archives; the packer should stream
        iter_seal_chunks())."""
        buf = b""
        for chunk in self.iter_seal_chunks():
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                yield json.loads(line)

    def sealed_entries_without_event(self):
        """Number of sealed entries (of the manifests in the seals file) whose event is gone from the archive. Not
        zero means the archive lost a sealed event (the integrity check says so too)."""
        ej = self._entries_json_pairs()
        total = 0
        for mid in self._sealed_manifest_ids_with_period_events():
            if mid in ej:
                total += sum(1 for u, _s in ej[mid] if self._conn.execute(
                    "SELECT 1 FROM events WHERE environment_id = ? AND uuid = ?", (self.environment_id, u)).fetchone() is None)
            else:
                total += self._conn.execute(
                    """SELECT COUNT(*) FROM manifest_entries me WHERE me.manifest_id = ? AND NOT EXISTS
                       (SELECT 1 FROM events e WHERE e.environment_id = me.environment_id AND e.uuid = me.uuid)""", (mid,)).fetchone()[0]
        return total

    # -- seal status counts (completeness) -----------------------------------------
    def _seal_counts_by_type(self):
        """{event_type: (curated rows in period, sealed, legacy_v1, curated_unsealed_other)} for curated events.
        An unsealed curated event is legacy_v1 when the archive has legacy manifests and it lies at or before the
        boundary (audit_store._unsealed_boundary; None = no event is sealed at all, so every one is legacy); with no
        legacy manifests none is."""
        def make():
            boundary = self._boundary()
            has_legacy = self._legacy_count() > 0
            ej = self._entries_json_uuids()
            sealed_expr = "EXISTS (SELECT 1 FROM manifest_entries m WHERE m.environment_id = e.environment_id AND m.uuid = e.uuid)"
            out = {}
            if ej:  # rare: some seals live in an older-format cell, so count row by row
                cur = self._conn.execute(
                    f"""SELECT e.event_type AS t, e.uuid AS u, e.rowid AS rid, {sealed_expr} AS sealed
                        FROM events e WHERE e.environment_id = ? AND e.is_curated = 1 AND e.published >= ? AND e.published < ?""",
                    (self.environment_id, *self._range()))
                for r in _chunks(cur):
                    n, sealed, legacy, other = out.get(r["t"], (0, 0, 0, 0))
                    if r["sealed"] or r["u"] in ej:
                        sealed += 1
                    elif has_legacy and (boundary is None or r["rid"] <= boundary):
                        legacy += 1
                    else:
                        other += 1
                    out[r["t"]] = (n + 1, sealed, legacy, other)
                return out
            for r in self._conn.execute(
                f"""SELECT e.event_type AS t, COUNT(*) AS n, SUM({sealed_expr}) AS sealed,
                           SUM(NOT {sealed_expr} AND ? AND (? IS NULL OR e.rowid <= ?)) AS legacy
                    FROM events e WHERE e.environment_id = ? AND e.is_curated = 1 AND e.published >= ? AND e.published < ?
                    GROUP BY e.event_type""",
                (1 if has_legacy else 0, boundary, boundary or 0, self.environment_id, *self._range()),
            ):
                n, sealed, legacy = r["n"], r["sealed"] or 0, r["legacy"] or 0
                out[r["t"]] = (n, sealed, legacy, n - sealed - legacy)
            return out
        return self._cached("seal_by_type", make)

    def completeness_counts(self):
        """Archive-wide counts for the period: events (all stored), curated_sealed, legacy_v1 (curated, no seal, in
        the legacy range), curated_unsealed (curated, no seal, NOT explained by a legacy manifest: the archive's
        integrity check reports these), non_curated_unsealed (events outside the curated set; never content-sealed),
        snapshot_objects (configuration snapshot objects captured in the period; not events)."""
        def make():
            by_type = self._seal_counts_by_type()
            curated = sum(v[0] for v in by_type.values())
            snaps = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(item_count), 0) FROM config_snapshots "
                "WHERE environment_id = ? AND captured_at >= ? AND captured_at < ?",
                (self.environment_id, *self._range())).fetchone()
            return {
                "events": self.events_in_period(),
                "curated": curated,
                "curated_sealed": sum(v[1] for v in by_type.values()),
                "legacy_v1": sum(v[2] for v in by_type.values()),
                "curated_unsealed": sum(v[3] for v in by_type.values()),
                "non_curated_unsealed": self.events_in_period() - curated,
                "snapshots": snaps[0],
                "snapshot_objects": snaps[1],
            }
        return self._cached("completeness_counts", make)

    # -- 4. coverage --------------------------------------------------------------------
    def coverage(self):
        """A state for each day of the period, and what the archive can and cannot say about it.

        Coverage windows come from the manifests. A sync manifest records the window it asked Okta for (`since`,
        `until`); a polling run that resumed from its saved cursor records no `since`, and then the window starts
        where the previous sync window ended. Day D (UTC) counts as covered when one merged window spans all of it,
        or when it holds stored events. Day states:

          covered_with_events   the day is covered and holds stored events
          covered_zero_events   the day is covered and holds none
          pruned_by_retention   the day is covered, holds no stored events, lies at or before the retention horizon,
                                and the archive demonstrably ingested non-curated events (see below)
          not_covered           a gap: after the archive began, before the data-as-of time, in no window
          before_archive        the day begins before the archive's first coverage (the first, partial day included)
          after_data_as_of      the day ends after the last successful sync; the events after it are not included
                                (not a gap)

        Honesty limits (also written into the result as `limits`):
        * The archive database records no prune history: prune_events() deletes rows and keeps no record in the
          database (the application writes the run's cutoff and count to its audit log). `pruned_by_retention` is
          therefore an INFERENCE about which days, made only when all hold: a horizon exists (from the supplied
          `prune_records`, basis "recorded", else from the current retention setting, basis "inferred"), the day
          ends at or before it, the day holds no stored events, and non-curated events are shown to have existed
          (stored now, a sealed manifest whose row_count exceeds its sealed entries, or a record that removed some).
          A genuinely empty old day in such an archive is also shown as pruned (in the inferred basis only when no
          non-curated event older than the horizon is still stored, which would show no run happened). Curated events are never pruned,
          so a day that still holds events keeps covered_with_events (its non-curated part may be gone: see
          `non_curated_pruned_days`).
        * The archive records no per-attempt outcome, only the latest (sync_state). A failed or stopped sync
          still writes a manifest naming the window it attempted, so an EARLIER failed run can make a day look
          covered that was not fully read. For the LATEST attempt, when it did not succeed, its window is cut at the
          watermark (last_synced_at).
        * A CSV import records no window. A day with stored events counts as covered even if only an import
          supplied them; an import that stopped part way through a day is not detected.
        """
        return self._cached("coverage", self._coverage)

    def _sync_windows(self, state):
        """Merged [start, end) windows as canonical timestamp strings, from the sync manifests."""
        intervals = []
        prev_end = None
        manifests = list(self._conn.execute(
            "SELECT id, source, since, until, created_at FROM ingestion_manifests WHERE environment_id = ? "
            "AND source = 'sync' ORDER BY id", (self.environment_id,)))
        failed_id = None
        if state and state.get("last_sync_status") not in (None, "success", "running") and state.get("last_sync_attempt_at"):
            attempt = (state["last_sync_attempt_at"] or "")[:19]
            for m in manifests:
                if (m["created_at"] or "")[:19] >= attempt:
                    failed_id = m["id"]
        watermark = audit_store._canonical_published(state.get("last_synced_at")) if state and state.get("last_synced_at") else None
        for m in manifests:
            start = audit_store._canonical_published(m["since"]) if m["since"] else prev_end
            end = audit_store._canonical_published(m["until"]) if m["until"] else None
            if start is None or end is None:
                continue
            if m["id"] == failed_id:
                if watermark is None:
                    continue
                end = min(end, watermark)
            if end <= start:
                continue
            intervals.append((start, end))
            prev_end = end if prev_end is None else max(prev_end, end)
        return _merge(intervals)

    def _recorded_windows(self):
        """Merged windows from the sync_runs table: only runs that finished ok count (a failed, stopped or unfinished run
        never does). A sync resumed from its cursor (no recorded since) starts where the previous ok sync ended; the
        first such run, with no ok predecessor on record, has no known start and is skipped. An import counts only for
        the date range of the rows it stored."""
        intervals = []
        prev_end = None
        for r in self._conn.execute(
                "SELECT kind, window_since, window_until FROM sync_runs WHERE environment_id = ? AND outcome = 'ok' ORDER BY id",
                (self.environment_id,)):
            end = audit_store._canonical_published(r["window_until"]) if r["window_until"] else None
            since = audit_store._canonical_published(r["window_since"]) if r["window_since"] else None
            start = since if (since or r["kind"] == "import") else prev_end
            if r["kind"] == "sync" and end:
                prev_end = end if prev_end is None else max(prev_end, end)
            if start and end and end > start:
                intervals.append((start, end))
        return _merge(intervals)

    def _recorded_prune_horizon(self):
        """Newest cutoff of a recorded prune that deleted rows, or None."""
        row = self._conn.execute("SELECT MAX(cutoff) FROM prune_history WHERE environment_id = ?", (self.environment_id,)).fetchone()
        return audit_store._canonical_published(row[0]) if row and row[0] else None

    def _retention_horizon(self):
        """(horizon canonical timestamp or None, retention_days, max_size_mb, basis): the time before which
        non-curated events are gone or subject to pruning. basis is "audit_log" when the caller supplied the prune
        records of past runs (the horizon is the newest cutoff a run recorded; a size-cap run with no cutoff uses the
        oldest non-curated event still stored), "inferred" when it comes from the current retention setting."""
        row = self._conn.execute(
            "SELECT retention_days, retention_max_size_mb FROM sync_schedules WHERE environment_id = ?", (self.environment_id,)).fetchone()
        days = row["retention_days"] if row else None
        size = row["retention_max_size_mb"] if row else None
        days = days if isinstance(days, int) and not isinstance(days, bool) and days > 0 else None
        size = size if isinstance(size, (int, float)) and not isinstance(size, bool) and size > 0 else None
        horizon = None
        size_pruned = bool(size)
        if self._prune_records is not None:
            basis = "audit_log"
            cutoffs = [audit_store._canonical_published(r.get("cutoff")) for r in self._prune_records if r.get("cutoff")]
            cutoffs = [c for c in cutoffs if c]
            horizon = max(cutoffs) if cutoffs else None
            size_pruned = any(not r.get("cutoff") and (r.get("pruned") or 0) > 0 for r in self._prune_records)
        else:
            basis = "inferred"
            if days:
                horizon = audit_store._iso_ms(self._now - timedelta(days=days))
                # A non-curated event older than the horizon is still stored, so a run at this horizon has not
                # happened (or retention was set after the event arrived): nothing may be called pruned.
                if self._conn.execute(
                        "SELECT 1 FROM events WHERE environment_id = ? AND is_curated = 0 AND published < ? LIMIT 1",
                        (self.environment_id, horizon)).fetchone():
                    horizon = None
        if size_pruned:
            oldest = self._conn.execute(
                "SELECT MIN(published) FROM events WHERE environment_id = ? AND is_curated = 0", (self.environment_id,)).fetchone()[0]
            if oldest and (horizon is None or oldest > horizon):
                horizon = oldest
        return horizon, days, size, basis

    def _ingested_non_curated(self):
        """True when the archive shows non-curated events were ingested at some point."""
        if self._conn.execute("SELECT 1 FROM events WHERE environment_id = ? AND is_curated = 0 LIMIT 1", (self.environment_id,)).fetchone():
            return True
        return self._conn.execute(
            """SELECT 1 FROM ingestion_manifests m
               WHERE m.environment_id = ? AND m.entry_hash IS NOT NULL AND m.entries_json IS NULL AND m.source NOT LIKE 'snapshot:%'
                 AND m.row_count > (SELECT COUNT(*) FROM manifest_entries me WHERE me.manifest_id = m.id) LIMIT 1""",
            (self.environment_id,)).fetchone() is not None

    def _coverage(self):
        env = self.environment_id
        state_row = self._conn.execute("SELECT * FROM sync_state WHERE environment_id = ?", (env,)).fetchone()
        state = dict(state_row) if state_row else {}
        windows = self._sync_windows(state)
        rec_windows = self._recorded_windows()
        recorded_from = rec_windows[0][0] if rec_windows else None   # days starting at or after this rest on records
        rec_prune = self._recorded_prune_horizon()
        per_day = {}
        for curated in (1, 0):
            for r in self._conn.execute(
                "SELECT substr(published, 1, 10) AS d, COUNT(*) AS n FROM events WHERE environment_id = ? AND is_curated = ? "
                "AND published >= ? AND published < ? GROUP BY d", (env, curated, *self._range())):
                cell = per_day.setdefault(r["d"], [0, 0])
                cell[0 if curated else 1] += r["n"]
        first_event = self._conn.execute("SELECT MIN(published) FROM events WHERE environment_id = ?", (env,)).fetchone()[0]
        # a day that holds stored events was read from the start of that day on as far as the archive can tell
        starts = [w[0] for w in windows] + [w[0] for w in rec_windows] + ([first_event[:10] + "T00:00:00.000Z"] if first_event else [])
        archive_start = min(starts) if starts else None
        as_of = state.get("last_sync_completed_at") or state.get("last_import_at")
        as_of_source = "sync" if state.get("last_sync_completed_at") else ("import" if state.get("last_import_at") else None)
        as_of_ts = audit_store._canonical_published(as_of) if as_of else None
        horizon, ret_days, ret_size, basis = self._retention_horizon()
        removed_evidence = self._prune_records is not None and any((r.get("pruned") or 0) > 0 for r in self._prune_records)
        prune_possible = horizon is not None and (removed_evidence or self._ingested_non_curated())

        days = []
        counts = {s: 0 for s in DAY_STATES}
        for d in self.period.days():
            ds = d.strftime("%Y-%m-%dT00:00:00.000Z")
            de = (d + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00.000Z")
            curated_n, non_curated_n = per_day.get(d.isoformat(), [0, 0])
            total = curated_n + non_curated_n
            use_records = recorded_from is not None and ds >= recorded_from
            day_windows = rec_windows if use_records else windows
            cov_basis = "recorded" if use_records else "inferred"
            prune_basis = None
            if non_curated_n == 0:
                if rec_prune is not None and de <= rec_prune:
                    prune_basis = "recorded"
                elif prune_possible and de <= horizon:
                    prune_basis = basis
            nc_pruned = prune_basis is not None
            if archive_start is None or ds < archive_start:
                state_name = DAY_BEFORE_ARCHIVE
            elif as_of_ts is not None and de > as_of_ts:
                state_name = DAY_AFTER_DATA_AS_OF
            elif not use_records and total > 0:
                state_name = DAY_COVERED_EVENTS
            elif not any(s <= ds and e >= de for s, e in day_windows):
                state_name = DAY_NOT_COVERED     # recorded basis: events alone do not make a day covered
            elif total > 0:
                state_name = DAY_COVERED_EVENTS
            else:
                state_name = DAY_PRUNED if nc_pruned else DAY_COVERED_ZERO
            counts[state_name] += 1
            days.append({"date": d.isoformat(), "state": state_name, "events": total, "basis": cov_basis,
                         "prune_basis": prune_basis if state_name in (DAY_PRUNED, DAY_COVERED_EVENTS) and nc_pruned else None,
                         "non_curated_pruned": bool(nc_pruned and total > 0 and state_name == DAY_COVERED_EVENTS)})
        covered = sum(counts[s] for s in COVERED_STATES)
        n = len(days)
        basis_counts = {"recorded": sum(1 for x in days if x["basis"] == "recorded"), "inferred": sum(1 for x in days if x["basis"] == "inferred")}
        used = sorted({x["prune_basis"] for x in days if x["prune_basis"]})
        pruned_basis = "+".join(used) if used else "none"
        limits = []
        if recorded_from:
            limits.append(
                "%d day(s) from %s onward rest on recorded sync and import runs: a failed, stopped or unfinished run never counts as "
                "coverage, and an import counts only for the date range of the rows it stored (a filtered export that omits some of its range is not detected)."
                % (basis_counts["recorded"], recorded_from[:10]))
            if basis_counts["inferred"]:
                limits.append(
                    "%d earlier day(s) rest on manifest windows (inferred): a manifest names the window a run asked for, and the archive "
                    "recorded no per-run outcome before then, so a failed or stopped sync can make such a day look covered; a day with stored "
                    "events counts as covered, since a CSV import then recorded no date range." % basis_counts["inferred"])
        else:
            limits.append(
                "All days rest on manifest windows (inferred): the archive recorded no sync or import runs yet. A failed or stopped sync can "
                "make a day look covered (only the latest attempt's outcome is kept, and its window is cut at the watermark), and a day "
                "with stored events counts as covered since a CSV import records no date range there.")
        if rec_prune is not None:
            limits.append("Days at or before %s with no stored events are shown pruned on the strength of a recorded prune run (the archive records "
                          "each run that deleted rows; which days held events is still inferred)." % rec_prune[:10])
        if basis in ("audit_log", "inferred"):
            limits.append(
                "Pruned days not covered by a recorded run (older prunes) use " + (
                    "the retention runs the caller supplied from the application's audit log (audit_log basis)." if basis == "audit_log" else
                    "the current retention setting (inferred; a run may never have happened)."))
        limits.append("sync_runs and prune_history are not trimmed; they stay small (one row per run).")
        return {
            "days": days,
            "counts": counts,
            "covered_days": covered,
            "coverage_pct": round(100.0 * covered / n, 1) if n else 0.0,
            "has_coverage": covered > 0,
            "gap_days": [x["date"] for x in days if x["state"] == DAY_NOT_COVERED],
            "pruned_days": [x["date"] for x in days if x["state"] == DAY_PRUNED],
            "non_curated_pruned_days": [x["date"] for x in days if x["non_curated_pruned"]],
            "archive_start_date": archive_start[:10] if archive_start else None,
            "data_as_of": as_of_ts,
            "data_as_of_source": as_of_source,
            "retention": {"days": ret_days, "max_size_mb": ret_size, "horizon": horizon},
            "prune_history_recorded": rec_prune is not None or self._prune_records is not None,
            "pruned_basis": pruned_basis,
            "recorded_from": recorded_from[:10] if recorded_from else None,
            "basis_counts": basis_counts,
            "limits": limits,
        }

    # -- 5. completeness ------------------------------------------------------------------
    def zero_event_types(self):
        """{report_key: [event types of that report with zero events in the period]} for every report that has any."""
        counts = self.event_type_counts()
        out = {}
        for key in audit_store.COMPLIANCE_REPORTS:
            zeros = sorted(t for t in audit_store._event_types_for_report(key) if counts[t] == 0)
            if zeros:
                out[key] = zeros
        return out

    def scope(self):
        """'everything' when the environment ingests all events, else 'curated'."""
        row = self._conn.execute("SELECT ingestion_scope FROM sync_state WHERE environment_id = ?", (self.environment_id,)).fetchone()
        stored = row["ingestion_scope"] if row else None
        if stored == "all" or self._conn.execute(
                "SELECT 1 FROM events WHERE environment_id = ? AND is_curated = 0 LIMIT 1", (self.environment_id,)).fetchone():
            return "everything"
        return "curated"

    def completeness(self):
        """The data for completeness.json outside its per-control part: per report rows (truncated is always False:
        this reader never truncates), seal status counts and zero-event types; the archive scope; counts for the
        whole period; the coverage statement. Plain dicts and lists, ready for json.dumps."""
        by_type = self._seal_counts_by_type()
        counts = self.event_type_counts()
        zero = self.zero_event_types()
        reports = {}
        for key in audit_store.COMPLIANCE_REPORTS:
            types = audit_store._event_types_for_report(key)
            vals = [by_type.get(t, (0, 0, 0, 0)) for t in types]
            reports[key] = {
                "rows": sum(counts[t] for t in types),
                "truncated": False,
                "curated_sealed": sum(v[1] for v in vals),
                "legacy_v1": sum(v[2] for v in vals),
                "curated_unsealed": sum(v[3] for v in vals),
                "zero_event_types": zero.get(key, []),
            }
        cov = self.coverage()
        return {
            "period": self.period.as_dict(),
            "scope": self.scope(),
            "reports": reports,
            "counts": self.completeness_counts(),
            "coverage": cov,
            "data_as_of": cov["data_as_of"],
            "archive_start_date": cov["archive_start_date"],
            "pruned_days": cov["pruned_days"],
            "curated_event_types": self.curated_event_types,
            "period_manifest_ids": self.period_manifest_ids(),
            "chain_head": self.chain_head["head_hash"] if self.chain_head else None,
        }
