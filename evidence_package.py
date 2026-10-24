"""The evidence package builder (5.53.0, WP4): one zip, format v1, from ONE archive snapshot.

docs/evidence-package-format.md is the contract and tools/verify_evidence_package.py is the check every package must
pass. This module only packs: every row, count, coverage statement, seal and manifest comes from evidence_core's
Snapshot (one read transaction, so the parts agree even when a sync commits during a build), and the CSV writer is
evidence_core's. Nothing here opens an HTTP route or knows about users, sessions or permissions; the job runner in
server/serve.py (via server/evidence_jobs.py) does that and calls build_package() on a worker thread.

Wording obeys the claims rules (spec section 7): the package is built from the archive on a date; the verifier detects
accidental or partial change and checks the exported events against the archive's chain as it stood at build time;
hashes are unkeyed and the package is not signed; control mappings are "proposed". The static texts are files in
server/evidence_templates/ (a test scans them for the forbidden claims).
"""
import hashlib
import html
import json
import os
import re
import shutil
import stat
import textwrap
import time
import unicodedata
import zipfile
from datetime import datetime, timezone

import audit_store
import evidence_core as core

ROOT = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(ROOT, "server", "evidence_templates")
VERIFIER_PATH = os.path.join(ROOT, "tools", "verify_evidence_package.py")
FORMAT = 1
ZIP_COMPRESSLEVEL = 4
WRITE_BLOCK = 1024 * 1024          # bytes gathered before one write into the zip entry
DEFAULT_MAX_BYTES = 2 * 1024 ** 3  # hard limit on the finished zip; OPA_EVIDENCE_MAX_BYTES overrides (tests, an operator)
# Free space needed before a build starts: half of the uncompressed estimate (JSON deflates much better, so this is
# conservative) plus a fixed margin so a build can never be what fills the disk.
FREE_SPACE_FACTOR = 0.5
FREE_SPACE_MARGIN = 256 * 1024 * 1024
MAX_RANGES_SHOWN = 40
_NAME_RE = re.compile(r"^[A-Za-z0-9._/-]{1,160}$", re.ASCII)
_CONTROL_ID_RE = re.compile(r"^[A-Za-z0-9.]{1,16}$", re.ASCII)
_REPORT_KEY_RE = re.compile(r"^[a-z0-9_]{1,64}$", re.ASCII)
_TOKEN_RE = re.compile(r"@@([A-Z0-9_]+)@@")


_max_bytes_warned = set()


def configured_max_bytes():
    """OPA_EVIDENCE_MAX_BYTES as a positive integer, else the default. A value that is not a positive integer is logged once and ignored."""
    raw = os.environ.get("OPA_EVIDENCE_MAX_BYTES")
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        value = int(raw)
        if value > 0:
            return value
    except ValueError:
        pass
    if raw not in _max_bytes_warned:
        _max_bytes_warned.add(raw)
        import create_secret_folders as engine
        engine.log("WARN", "OPA_EVIDENCE_MAX_BYTES is not a positive whole number; using the default of %d bytes." % DEFAULT_MAX_BYTES)
    return DEFAULT_MAX_BYTES


class PackageError(Exception):
    """A build that cannot go ahead or cannot finish. `reason` is a short stable code, str(exc) a plain sentence safe to
    show to the person who asked (never row content, never a path)."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def utc_stamp(dt=None):
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ascii_text(value, limit=120, default=""):
    """Printable ASCII only: accents folded, anything else dropped, whitespace collapsed. For text that goes into the
    README, the cover sheet and package-manifest.json from user-chosen names (environment label, builder)."""
    text = unicodedata.normalize("NFKD", str(value if value is not None else ""))
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^\x20-\x7e]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or default


def ascii_label(value):
    """environment_label_ascii: letters, digits, space, dot, underscore and hyphen only."""
    text = ascii_text(value, 80)
    return re.sub(r"[^A-Za-z0-9._ -]", "_", text) or "environment"


def download_filename(environment_name, period, built_at):
    """A sanitised file name for Content-Disposition: ASCII letters, digits, dot, underscore and hyphen only."""
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", ascii_label(environment_name)).strip("-.") or "environment"
    stamp = re.sub(r"[^0-9]", "", built_at)[:14]
    return f"evidence-package-{label[:40]}-{period.start.isoformat()}-to-{period.end.isoformat()}-{stamp}.zip"


def _ranges(dates):
    """[(start, end)] of consecutive ISO dates (a sorted list of 'YYYY-MM-DD')."""
    out = []
    for d in dates:
        if out and (datetime.strptime(d, "%Y-%m-%d") - datetime.strptime(out[-1][1], "%Y-%m-%d")).days == 1:
            out[-1][1] = d
        else:
            out.append([d, d])
    return [tuple(r) for r in out]


def _ranges_text(ranges, shown=MAX_RANGES_SHOWN):
    parts = [a if a == b else f"{a} to {b}" for a, b in ranges[:shown]]
    if len(ranges) > shown:
        parts.append(f"and {len(ranges) - shown} more ranges (the full list is in completeness.json)")
    return "; ".join(parts)


def verifier_bytes():
    try:
        with open(VERIFIER_PATH, "rb") as fh:
            return fh.read()
    except OSError:
        raise PackageError("verifier_missing", "The checking program (tools/verify_evidence_package.py) is missing from this installation, so no package can be built.") from None


def _template(name):
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _fill(template, values, escape=False, trusted=()):
    """One pass: every @@TOKEN@@ is replaced by its value, and a replaced value is never scanned again (a value that
    looks like a token stays text). `escape` HTML-escapes the values (the cover sheet)."""
    def sub(m):
        key = m.group(1)
        if key not in values:
            raise KeyError(key)
        text = str(values[key])
        return html.escape(text, quote=True) if escape and key not in trusted else text
    return _TOKEN_RE.sub(sub, template)


# ---------------------------------------------------------------------------
# The control matrix (from the catalogue and the snapshot's counts)
# ---------------------------------------------------------------------------
def _control_sort_key(cid):
    return [int(p) if p.isdigit() else p for p in re.findall(r"\d+|[A-Za-z]+", cid)]


def control_matrix(report_counts):
    """[{framework, control_id, mapping_status, reports: [keys], rows, status}] ordered by control id. `rows` is the number
    of data rows the control's report files hold: the sum of its reports' counts. A report that maps to two controls is
    in both, so a row can appear under two criteria."""
    controls = {}
    for key in audit_store.COMPLIANCE_REPORTS:
        if not _REPORT_KEY_RE.match(key):
            raise PackageError("internal", "A report key is not a fixed ASCII key.")
        for c in audit_store.report_controls(key):
            if not _CONTROL_ID_RE.match(c["id"]):
                raise PackageError("internal", "A control id is not a fixed ASCII id.")
            e = controls.setdefault((c["framework"], c["id"]), {"reports": [], "statuses": []})
            e["reports"].append(key)
            e["statuses"].append(c["status"])
    out = []
    for (framework, cid), e in sorted(controls.items(), key=lambda kv: (kv[0][0], _control_sort_key(kv[0][1]))):
        rows = sum(report_counts[k] for k in e["reports"])
        out.append({
            "framework": framework, "control_id": cid,
            "mapping_status": "auditor-reviewed" if set(e["statuses"]) == {"auditor-reviewed"} else "proposed",
            "reports": e["reports"], "rows": rows,
            "status": "events_present" if rows else "zero_events_in_period",
        })
    return out


# ---------------------------------------------------------------------------
# Coverage summary (the prepare step and the README/cover sheet)
# ---------------------------------------------------------------------------
def coverage_summary(snap, cap=MAX_RANGES_SHOWN):
    """What the person building a package must see first: the day states of the period as counts and date ranges, the
    gap acknowledgement rule, and the control matrix preview. Plain JSON-able dict. `cap` bounds how many date ranges
    of each kind are listed (the totals are always given); None lists all of them (the package's own text)."""
    cov = snap.coverage()
    days = cov["days"]
    by_state = {s: [d["date"] for d in days if d["state"] == s] for s in core.DAY_STATES}
    gap_ranges = _ranges(by_state[core.DAY_NOT_COVERED])
    zero_ranges = _ranges(by_state[core.DAY_COVERED_ZERO])
    pruned_ranges = _ranges(by_state[core.DAY_PRUNED])
    counts = snap.report_counts()
    return {
        "period": snap.period.as_dict(),
        "days": len(days),
        "has_coverage": bool(cov["has_coverage"]),
        "coverage_pct": cov["coverage_pct"],
        "covered_days": cov["covered_days"],
        "counts": cov["counts"],
        "gap_days_total": len(by_state[core.DAY_NOT_COVERED]),
        "gap_ranges": [list(r) for r in gap_ranges[:cap]],
        "gap_ranges_total": len(gap_ranges),
        "zero_days_total": len(by_state[core.DAY_COVERED_ZERO]),
        "zero_ranges": [list(r) for r in zero_ranges[:cap]],
        "zero_ranges_total": len(zero_ranges),
        "pruned_days_total": len(by_state[core.DAY_PRUNED]),
        "pruned_ranges": [list(r) for r in pruned_ranges[:cap]],
        "pruned_ranges_total": len(pruned_ranges),
        "before_archive_days": cov["counts"][core.DAY_BEFORE_ARCHIVE],
        "after_data_as_of_days": cov["counts"][core.DAY_AFTER_DATA_AS_OF],
        "needs_acknowledgement": bool(by_state[core.DAY_NOT_COVERED]),
        "archive_start_date": cov["archive_start_date"],
        "data_as_of": cov["data_as_of"],
        "pruned_basis": cov["pruned_basis"],
        "limits": cov["limits"],
        "events_in_period": snap.events_in_period(),
        "chain_head": snap.chain_head["head_hash"] if snap.chain_head else None,
        "controls": control_matrix(counts),
    }


def _wrap(text, indent=""):
    return textwrap.fill(text, width=78, initial_indent=indent, subsequent_indent=indent)


def _coverage_text(summary, gaps_acknowledged):
    c = summary["counts"]
    lines = [
        f"  Days in the period ........ {summary['days']}",
        f"  Coverage .................. {summary['coverage_pct']} percent of the days",
        f"  Covered, with events ...... {c[core.DAY_COVERED_EVENTS]}",
        f"  Covered, zero events ...... {c[core.DAY_COVERED_ZERO]}",
        f"  Pruned by retention ....... {c[core.DAY_PRUNED]}",
        f"  Gap days (not covered) .... {c[core.DAY_NOT_COVERED]}",
        f"  Before the archive began .. {c[core.DAY_BEFORE_ARCHIVE]}",
        f"  After the data-as-of time . {c[core.DAY_AFTER_DATA_AS_OF]}",
        "",
    ]
    if c[core.DAY_NOT_COVERED]:
        lines.append(_wrap("Gap days: the archive has no record that these days were read from the source system. "
                           "Events may have happened on them and be missing from this package."))
        lines.append(_wrap(_ranges_text([tuple(r) for r in summary["gap_ranges"]], MAX_RANGES_SHOWN), "  "))
        lines.append(_wrap("The person who built this package was shown these days and confirmed that the package should be built "
                           "with them." if gaps_acknowledged else "These days were not acknowledged."))
    else:
        lines.append("Gap days: none.")
    if c[core.DAY_COVERED_ZERO]:
        lines.append(_wrap("Zero-event days: the archive read these days and holds no event for them."))
        lines.append(_wrap(_ranges_text([tuple(r) for r in summary["zero_ranges"]]), "  "))
    if c[core.DAY_PRUNED]:
        lines.append(_wrap("Pruned days: the archive's retention setting removed events of these days (basis: "
                           f"{summary['pruned_basis']}). They are not gaps."))
        lines.append(_wrap(_ranges_text([tuple(r) for r in summary["pruned_ranges"]]), "  "))
    if c[core.DAY_BEFORE_ARCHIVE]:
        lines.append(_wrap("Days before the archive began are before this tool started archiving this environment."))
    for limit in summary["limits"]:
        lines.append(_wrap("Note: " + ascii_text(limit, 700)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The zip
# ---------------------------------------------------------------------------
class _Sink:
    """What a zip entry is written through: counts bytes, hashes them, batches small writes, enforces the size limit."""

    def __init__(self, writer, entry):
        self._w = writer
        self._entry = entry
        self._sha = hashlib.sha256()
        self.bytes = 0
        self._buf = []
        self._buf_len = 0

    def write(self, data):
        if not data:
            return 0
        self._buf.append(bytes(data))
        self._buf_len += len(data)
        if self._buf_len >= WRITE_BLOCK:
            self.flush()
        return len(data)

    def flush(self):
        if not self._buf:
            return
        block = b"".join(self._buf)
        self._buf = []
        self._buf_len = 0
        self._sha.update(block)
        self.bytes += len(block)
        self._entry.write(block)
        self._w.check_size()

    def result(self):
        self.flush()
        return self._sha.hexdigest(), self.bytes


class _ZipWriter:
    def __init__(self, path, max_bytes, built_at_dt):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        self._fp = os.fdopen(fd, "wb")
        self._zf = zipfile.ZipFile(self._fp, "w", zipfile.ZIP_DEFLATED, allowZip64=True, compresslevel=ZIP_COMPRESSLEVEL)
        self._max = max_bytes
        self._when = (built_at_dt.year, built_at_dt.month, built_at_dt.day, built_at_dt.hour, built_at_dt.minute, built_at_dt.second)
        self._names = set()
        self.files = []           # [{"path", "sha256", "bytes"}] in write order
        self._closed = False

    def check_size(self):
        if self._fp.tell() > self._max:
            raise PackageError("size_limit", "The package would be larger than the limit of %d MB. Choose a shorter period." % (self._max // (1024 * 1024)))

    def _info(self, name):
        if not _NAME_RE.match(name) or ".." in name.split("/") or name.startswith("/") or "//" in name:
            raise PackageError("internal", "A package file name is not a fixed ASCII name.")
        if name.lower() in self._names:
            raise PackageError("internal", "A package file name is repeated.")
        self._names.add(name.lower())
        info = zipfile.ZipInfo(name, date_time=self._when)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.create_system = 3
        return info

    def add_bytes(self, name, data):
        sink = self.open(name)
        with sink as s:
            s.write(data)
        return self.files[-1]

    def open(self, name):
        return _Entry(self, name)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._zf.close()
        finally:
            self._fp.flush()
            try:
                os.fsync(self._fp.fileno())
            except OSError:
                pass
            self._fp.close()

    def abort(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._zf.close()
        except Exception:
            pass
        try:
            self._fp.close()
        except Exception:
            pass


class _Entry:
    def __init__(self, writer, name):
        self._w = writer
        self._name = name
        self._info = writer._info(name)

    def __enter__(self):
        self._entry = self._w._zf.open(self._info, "w", force_zip64=True)
        self._sink = _Sink(self._w, self._entry)
        return self._sink

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            try:
                self._entry.close()
            except Exception:
                pass
            return False
        sha, size = self._sink.result()
        self._entry.close()
        self._w.check_size()
        self._w.files.append({"path": self._name, "sha256": sha, "bytes": size})
        return False


def _methodology_text(report_key, entry):
    controls = ", ".join(f"{c['framework'].upper()} {c['id']} ({c['status']})" for c in entry["controls"])
    limits = "\n".join(f"  - {x}" for x in entry["known_limits"])
    label = audit_store.COMPLIANCE_REPORTS[report_key]["label"]
    types = ", ".join(audit_store._event_types_for_report(report_key))
    return (
        f"{label} ({report_key})\n\n"
        f"Proposed mapping: {controls}\n"
        "A proposed mapping is a suggestion made by the project that wrote the tool. It has not been reviewed by an auditor.\n\n"
        f"How this is calculated\n{entry['methodology']}\n\n"
        f"Event types used by this report\n  {types}\n\n"
        f"Known limits\n{limits}\n\n"
        "About the files\n"
        "  - events.ndjson is the authoritative copy of every event of the period, exactly as the archive stores it.\n"
        "  - The report files under controls/ show a fixed set of columns taken from those events, one row per event, "
        "oldest first, with the event_uuid that names the event in events.ndjson.\n"
        "  - A cell that begins with an apostrophe had a value beginning with =, +, - or @ (or a tab or carriage return); the "
        "apostrophe is added on purpose so that a spreadsheet program cannot run the value as a formula. The value in "
        "events.ndjson has no apostrophe.\n"
    )


def _csv_bytes(header, rows):
    return b"".join(core.csv_line(r) for r in [header] + rows)


def build_package(dest_path, environment_id, environment_name, period, *, builder, app_version, gaps_acknowledged,
                  max_bytes=None, progress=None, now=None, prune_records=None, check_free_space=True):
    """Writes the package to `dest_path` (created owner-only, must not exist) and returns a result dict:
    {sha256, bytes, chain_head, events, report_rows, controls, files, coverage_pct, gap_days, ...}. Raises PackageError
    on a refusal (no coverage, unacknowledged gaps, an archive whose own chain check fails, no space, size limit) and
    leaves no partial file behind. `progress(stage, fraction)` is called as the build moves along."""
    started = time.monotonic()
    now = now or datetime.now(timezone.utc)
    built_at = utc_stamp(now)
    max_bytes = max_bytes or configured_max_bytes()
    say = progress or (lambda stage, fraction: None)
    verifier = verifier_bytes()
    verifier_sha = hashlib.sha256(verifier).hexdigest()
    catalogue = audit_store.load_control_catalogue()
    writer = None
    try:
        with core.open_snapshot(environment_id, period, now=now, prune_records=prune_records) as snap:
            say("Checking coverage", 0.02)
            if not snap.head_consistent():
                raise PackageError("chain_inconsistent", "The archive's own chain check does not hold (its last record does not match the recorded head). "
                                   "Run the integrity check on the environment and resolve it before building a package.")
            summary = coverage_summary(snap, cap=None)
            if not summary["has_coverage"]:
                raise PackageError("no_coverage", "The archive has no coverage at all for this period, so there is nothing to put in a package.")
            if summary["needs_acknowledgement"] and not gaps_acknowledged:
                raise PackageError("gaps_unacknowledged", "This period has days the archive did not cover. Confirm the gaps to build the package with them.")
            if check_free_space:
                est = snap.estimate_event_bytes()
                need = int(est * FREE_SPACE_FACTOR) + FREE_SPACE_MARGIN
                free = shutil.disk_usage(os.path.dirname(os.path.abspath(dest_path))).free
                if free < need:
                    raise PackageError("disk_space", "There is not enough free disk space to build this package (about %d MB needed, %d MB free). "
                                       "Free some space or choose a shorter period." % (need // (1024 * 1024), free // (1024 * 1024)))
            report_counts = snap.report_counts()
            controls = summary["controls"]
            data_as_of = summary["data_as_of"]
            tokens = {
                "ENVIRONMENT": ascii_text(environment_name, 120, "environment"),
                "PERIOD_START": period.start.isoformat(), "PERIOD_END": period.end.isoformat(),
                "BUILT_AT": built_at, "BUILDER": ascii_text(builder, 120, "unknown"),
                "APP_VERSION": ascii_text(app_version, 40, "unknown"), "CATALOGUE_VERSION": ascii_text(catalogue.get("version"), 40, "unknown"),
                "DATA_AS_OF": data_as_of or "no successful sync recorded", "ARCHIVE_START": summary["archive_start_date"] or "unknown",
                "EVENT_COUNT": summary["events_in_period"], "CHAIN_HEAD": summary["chain_head"] or "none",
                "COVERAGE_TEXT": _coverage_text(summary, gaps_acknowledged),
            }
            c = summary["counts"]
            gap_text = ("Gap days (not covered): " + _ranges_text([tuple(r) for r in summary["gap_ranges"]]) + ". Events may have happened on them and be missing. "
                        + ("The builder confirmed the package should be built with them." if gaps_acknowledged else "")) if c[core.DAY_NOT_COVERED] else "No gap days."
            matrix_rows = "\n".join(
                "<tr><td>%s %s</td><td>%s</td><td class=\"num\">%d</td><td>%s</td></tr>" % (
                    html.escape(m["framework"].upper()), html.escape(m["control_id"]), html.escape(", ".join(m["reports"])),
                    m["rows"], html.escape(m["mapping_status"]))
                for m in controls)
            cover = _fill(_template("cover-sheet.html"), {
                **tokens, "DAYS_TOTAL": summary["days"], "COVERAGE_PCT": summary["coverage_pct"],
                "DAYS_WITH_EVENTS": c[core.DAY_COVERED_EVENTS], "DAYS_ZERO": c[core.DAY_COVERED_ZERO], "DAYS_PRUNED": c[core.DAY_PRUNED],
                "DAYS_GAP": c[core.DAY_NOT_COVERED], "DAYS_BEFORE": c[core.DAY_BEFORE_ARCHIVE], "DAYS_AFTER": c[core.DAY_AFTER_DATA_AS_OF],
                "GAP_TEXT": gap_text, "MATRIX_ROWS": matrix_rows, "VERIFIER_SHA256": verifier_sha,
            }, escape=True, trusted=("MATRIX_ROWS",))
            readme = _fill(_template("README-FOR-AUDITORS.txt"), tokens)
            reads = _template("what-this-tool-reads.txt")

            writer = _ZipWriter(dest_path, max_bytes, now)
            writer.add_bytes("README-FOR-AUDITORS.txt", readme.encode("utf-8"))
            writer.add_bytes("cover-sheet.html", cover.encode("utf-8"))
            matrix_header = ["control_id", "framework", "mapping_status", "reports", "rows_in_period", "status"]
            writer.add_bytes("control-matrix.csv", _csv_bytes(matrix_header, [
                [m["control_id"], m["framework"], m["mapping_status"], ";".join(m["reports"]), m["rows"], m["status"]] for m in controls]))

            # controls/<control_id>/<report_key>.csv
            written = {}
            total_pairs = sum(len(m["reports"]) for m in controls) or 1
            done_pairs = 0
            for m in controls:
                for key in m["reports"]:
                    say("Writing report files", 0.05 + 0.45 * done_pairs / total_pairs)
                    with writer.open(f"controls/{m['control_id']}/{key}.csv") as sink:
                        n = core.write_report_csv(sink, snap.report_rows(key))
                    if n != report_counts[key]:
                        raise PackageError("internal_mismatch", "A report file's row count differs from the snapshot's count; the package was not completed.")
                    written[(m["control_id"], key)] = n
                    done_pairs += 1
            for m in controls:
                if sum(written[(m["control_id"], k)] for k in m["reports"]) != m["rows"]:
                    raise PackageError("internal_mismatch", "The control matrix row count differs from the report files; the package was not completed.")

            say("Writing events", 0.55)
            n_events = 0
            with writer.open("events.ndjson") as sink:
                for line in snap.event_lines():
                    sink.write(line)
                    n_events += 1
            if n_events != summary["events_in_period"]:
                raise PackageError("internal_mismatch", "The events written differ from the snapshot's count; the package was not completed.")

            say("Writing the chain", 0.85)
            n_manifests = 0
            with writer.open("chain/manifests.ndjson") as sink:
                for row in snap.iter_manifests():
                    sink.write((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                    n_manifests += 1
            with writer.open("chain/seals.ndjson") as sink:
                for chunk in snap.iter_seal_chunks():
                    sink.write(chunk)

            say("Writing the completeness statement", 0.92)
            completeness = snap.completeness()
            completeness["gaps_acknowledged"] = bool(gaps_acknowledged)
            completeness["sealed_entries_without_event"] = snap.sealed_entries_without_event()
            completeness["controls"] = {
                m["control_id"]: {"framework": m["framework"], "mapping_status": m["mapping_status"], "reports": m["reports"],
                                  "rows": m["rows"], "truncated": False}
                for m in controls}
            completeness["built_at"] = built_at
            writer.add_bytes("completeness.json", json.dumps(completeness, sort_keys=True, indent=1).encode("utf-8"))
            writer.add_bytes("what-this-tool-reads.txt", reads.encode("utf-8"))
            for key in audit_store.COMPLIANCE_REPORTS:
                writer.add_bytes(f"methodology/{key}.txt", _methodology_text(key, audit_store.report_catalogue_entry(key)).encode("utf-8"))
            writer.add_bytes("tools/verify_evidence_package.py", verifier)

            say("Finishing", 0.97)
            manifest = {
                "format": FORMAT,
                "files": list(writer.files),
                "built_at": built_at,
                "app_version": ascii_text(app_version, 40, "unknown"),
                "environment_label_ascii": ascii_label(environment_name),
                "period": period.as_dict(),
                "data_as_of": data_as_of,
                "chain_head": summary["chain_head"],
                "catalogue_version": ascii_text(catalogue.get("version"), 40, "unknown"),
                "curated_event_types": list(snap.curated_event_types),
                "period_manifest_ids": snap.period_manifest_ids(),
            }
            writer.add_bytes("package-manifest.json", json.dumps(manifest, indent=1).encode("utf-8"))
            result = {
                "chain_head": summary["chain_head"], "events": n_events, "report_rows": sum(written.values()),
                "controls": {m["control_id"]: m["rows"] for m in controls}, "files": len(writer.files),
                "manifests": n_manifests, "coverage_pct": summary["coverage_pct"], "gap_days": summary["gap_days_total"],
                "zero_days": summary["zero_days_total"], "pruned_days": summary["pruned_days_total"],
                "before_archive_days": summary["before_archive_days"], "data_as_of": data_as_of,
                "archive_start_date": summary["archive_start_date"], "verifier_sha256": verifier_sha,
            }
        writer.close()
        writer = None
        sha = hashlib.sha256()
        size = 0
        with open(dest_path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                sha.update(block)
                size += len(block)
        result.update({"sha256": sha.hexdigest(), "bytes": size, "built_at": built_at,
                       "seconds": round(time.monotonic() - started, 1)})
        say("Done", 1.0)
        return result
    except BaseException:
        if writer is not None:
            writer.abort()
        try:
            os.remove(dest_path)
        except OSError:
            pass
        raise


def preview(environment_id, period, prune_records=None, now=None):
    """The prepare step's read: coverage summary and control matrix preview, from a short snapshot."""
    with core.open_snapshot(environment_id, period, now=now, prune_records=prune_records) as snap:
        out = coverage_summary(snap)
        out["estimated_event_bytes"] = snap.estimate_event_bytes()
        return out
