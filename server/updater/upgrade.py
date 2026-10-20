"""The in-app upgrade flow, application side (5.48.0).

What the web application does -- and, deliberately, all it does -- to upgrade the
installation:

  * PREVIEW: fetch the release's `.minisig` and `manifest.json` (a few KB, never
    the archive), check the signature file's trusted comment against the pinned
    signing keys, and compute the preflight (disk, Python, SQLite, sync, updater).
    The sha256 the administrator approves is the one in that signed comment.
  * REQUEST: write ONE advisory request file into the updater's inbox
    (upgrade/inbox/requests/<correlation id>.json, the interface the root-owned
    updater defines). The updater re-verifies everything (signature, hash,
    version, replay, size) and does the install; this process never touches code.
  * SCHEDULE: keep a scheduled upgrade in its own small file and write the same
    request when the time comes (the scheduler tick). If the application is not
    running within MISSED_GRACE of that time the upgrade is marked MISSED and is
    never run late.
  * TWO-PERSON RULE (optional, off by default): the first administrator's
    approval is held for 24 hours until a DIFFERENT administrator approves it.

The approval of a human is the step-up MFA transaction in serve.py; this module
holds no identity logic. Nothing here is trusted by the updater beyond "install
this genuine newer release, now".
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import check
from . import keys as keylib
from . import minisign
from . import service

SCHEDULE_FILE_ENV = "OPA_UPGRADE_SCHEDULE_PATH"
PREVIEW_FILE_ENV = "OPA_UPGRADE_PREVIEW_PATH"
RELEASE_BASE_ENV = "OPA_RELEASE_BASE_URL"
OPT_DIR_ENV = "OCW_OPT_DIR"
MISSED_GRACE = timedelta(minutes=15)
MIN_LEAD = timedelta(minutes=2)
MAX_AHEAD = timedelta(days=31)
APPROVAL_TTL = timedelta(hours=24)
ROLLBACK_WINDOW = timedelta(hours=24)
QUIESCE = timedelta(minutes=10)
WAIT_FOR_SYNC = timedelta(minutes=10)
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIG_BYTES = 16 * 1024

CID_RE = re.compile(r"^upg-[0-9a-f]{8}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ACTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
ZONE_RE = re.compile(r"^[A-Za-z0-9_+\-/]{1,64}$")

_lock = threading.RLock()
_quiesce_until = [None]
_PY_MIN = (3, 9)
_SQLITE_MIN = (3, 35, 0)


def _engine():
    return keylib._engine()


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text):
    return service._parse_iso(text)


# --- paths -----------------------------------------------------------------------------------------------------------
def data_dir():
    return Path(os.environ.get("OPA_DATA_DIR") or keylib.REPO_ROOT)


def schedule_path():
    return Path(os.environ.get(SCHEDULE_FILE_ENV) or data_dir() / "upgrade_schedule.json")


def preview_path():
    return Path(os.environ.get(PREVIEW_FILE_ENV) or data_dir() / "upgrade_preview.json")


def inbox_dir():
    return service.upgrade_dir() / "inbox" / "requests"


def opt_dir():
    env = os.environ.get(OPT_DIR_ENV)
    if env:
        return Path(env)
    real = Path(keylib.REPO_ROOT).resolve()
    return real.parent.parent if real.parent.name == "releases" else None


def updater_activator_version():
    """The installed activator's version, read from its file (root-owned, world-readable), or None."""
    opt = opt_dir()
    if not opt:
        return None
    try:
        text = (opt / "updater" / "ocw_activate.py").read_text(encoding="utf-8", errors="replace")[:200000]
    except OSError:
        return None
    m = re.search(r'^ACTIVATOR_VERSION = "([^"]+)"', text, re.M)
    return m.group(1) if m else None


def updater_state():
    """{'ready': bool, 'reason': None | code, 'message': text, 'activator': version | None}."""
    inbox = inbox_dir()
    activator = updater_activator_version()
    if not inbox.is_dir():
        return {"ready": False, "reason": "updater_not_installed", "activator": activator,
                "message": "This server does not use the privileged updater (no upgrade inbox). Run server/install.sh once, "
                           "or upgrade with deploy.sh --release from a shell (README, \"Upgrading\")."}
    if not os.access(inbox, os.W_OK):
        return {"ready": False, "reason": "inbox_not_writable", "activator": activator,
                "message": "The upgrade inbox exists but this application cannot write to it. Re-run server/install.sh."}
    return {"ready": True, "reason": None, "activator": activator, "message": ""}


# --- server zone -----------------------------------------------------------------------------------------------------
def server_zone():
    """The server's IANA zone name (what the schedule dialog shows next to the browser's), best effort."""
    try:
        from zoneinfo import ZoneInfo
    except ImportError:  # pragma: no cover
        return None
    tz = os.environ.get("TZ")
    if tz and ZONE_RE.match(tz.lstrip(":")):
        try:
            ZoneInfo(tz.lstrip(":"))
            return tz.lstrip(":")
        except Exception:  # noqa: BLE001
            pass
    try:
        target = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            name = target.split("zoneinfo/", 1)[1]
            if ZONE_RE.match(name):
                return name
    except OSError:
        pass
    try:
        name = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if ZONE_RE.match(name):
            return name
    except OSError:
        pass
    return "UTC" if (datetime.now().astimezone().utcoffset() or timedelta(0)) == timedelta(0) else None


def convert_local(entered_local, zone):
    """UTC ISO string of a wall-clock 'YYYY-MM-DDTHH:MM' in IANA zone `zone` (or 'UTC'), else ValueError."""
    if not isinstance(entered_local, str) or not isinstance(zone, str) or not ZONE_RE.match(zone):
        raise ValueError("bad time zone or time")
    naive = datetime.strptime(entered_local, "%Y-%m-%dT%H:%M")
    if zone.upper() == "UTC":
        return _iso(naive.replace(tzinfo=timezone.utc))
    from zoneinfo import ZoneInfo
    return _iso(naive.replace(tzinfo=ZoneInfo(zone)))


# --- the schedule / pending approval file -------------------------------------------------------------------------------
def _empty():
    return {"schedule": None, "pending_approval": None, "last": None}


def load_schedule():
    try:
        with open(schedule_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            out = _empty()
            for k in out:
                if isinstance(data.get(k), dict):
                    out[k] = data[k]
            return out
    except (OSError, ValueError):
        pass
    return _empty()


def save_schedule(data):
    _engine()._atomic_write_json(str(schedule_path()), data)


def pending_approval(now=None):
    """The held first approval, or None (an expired one is dropped and noted)."""
    with _lock:
        data = load_schedule()
        pa = data["pending_approval"]
        if not pa:
            return None
        exp = _parse(pa.get("expires_at"))
        if exp is not None and (now or datetime.now(timezone.utc)) > exp:
            data["pending_approval"] = None
            data["last"] = {"kind": "approval_expired", "version": pa.get("version"), "at": _iso(now or datetime.now(timezone.utc)),
                            "correlation_id": pa.get("correlation_id")}
            save_schedule(data)
            _audit("upgrade.cancelled", {"correlation_id": pa.get("correlation_id"), "version": pa.get("version"),
                                         "reason": "the second approval was not given within 24 hours (expired)"})
            return None
        return pa


def _audit(action, details, actor=None):
    eng = _engine()
    details = dict(details)
    details.setdefault("correlation_id", eng.CORRELATION_ID.get())
    eng.log("INFO", f"{action}: {details}")
    eng.log_audit_event(actor[0] if actor else None, actor[1] if actor else None, action, details)


# --- preview ------------------------------------------------------------------------------------------------------------
def load_preview():
    try:
        with open(preview_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save_preview(data):
    _engine()._atomic_write_json(str(preview_path()), data)


def release_base():
    base = (os.environ.get(RELEASE_BASE_ENV) or check.DEFAULT_RELEASE_DOWNLOAD_BASE).rstrip("/")
    hosts = check.hosts_for(base) if os.environ.get(RELEASE_BASE_ENV) else check.GITHUB_HOSTS
    return base, hosts


class PreviewError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _verify_trusted_comment(sig, version):
    """Check the signature file's trusted comment is signed by a pinned, currently acceptable release key. (The archive
    itself is not here to hash; the updater checks the archive against this same sha256 before installing.)"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        fields = minisign.parse_trusted_comment(sig.trusted_comment, optional=("timestamp",))
        keylib.parse_version(fields["version"])
        eff = keylib.effective_key_list()
        pub = keylib.pick_signer(eff, sig.key_id, "release", fields.get("timestamp"), fields["version"])
    except (minisign.SignatureError, keylib.KeyListError) as exc:
        raise PreviewError(getattr(exc, "code", "signature_invalid"), str(exc))
    if not hasattr(pub, "raw") or pub.key_id != sig.key_id:
        raise PreviewError("unknown_alg", "the signing key uses an algorithm this version cannot check")
    try:
        Ed25519PublicKey.from_public_bytes(pub.raw).verify(sig.global_sig, sig.sig + sig.trusted_comment.encode("utf-8"))
    except InvalidSignature:
        raise PreviewError("bad_trusted_comment", "the signature file's trusted comment was altered")
    if fields["version"] != version or fields["file"] != f"ocw-{version}.tar.gz" or not SHA_RE.match(fields["sha256"]):
        raise PreviewError("name_mismatch", "the signature file is not for this release")
    entry = next((k for k in eff["keys"] if k["key_id"] == sig.key_id), {})
    return fields, entry


def _cap_text(value, limit):
    return check._plain(value, limit)


def _manifest_view(raw, version):
    try:
        m = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise PreviewError("bad_manifest", "manifest.json is not valid JSON")
    if not isinstance(m, dict) or m.get("schema") != 1 or m.get("version") != version:
        raise PreviewError("bad_manifest", "manifest.json is not for this release")
    migrations = []
    for item in (m.get("migrations") or [])[:200]:
        if isinstance(item, dict) and isinstance(item.get("version"), int) and not isinstance(item["version"], bool):
            migrations.append({"version": item["version"], "since": _cap_text(item.get("since"), 20),
                               "rollback_safe": item.get("rollback_safe") is True,
                               "summary": _cap_text(item.get("summary"), 200)})
    num = lambda v: v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10 ** 6 else None  # noqa: E731
    excerpt = _cap_text(m.get("changelog_excerpt"), 2000)
    return {"min_upgrade_from": _cap_text(m.get("min_upgrade_from"), 20), "downtime_estimate_seconds": num(m.get("downtime_estimate_seconds")),
            "migrations": migrations, "expected_schema_version": num(m.get("expected_schema_version")),
            "changelog_excerpt": excerpt, "nginx_template_changed": m.get("nginx_template_changed") is True,
            "activator_version": _cap_text(m.get("activator_version"), 20), "built_at": _cap_text(m.get("built_at"), 30),
            "min_python": _cap_text(m.get("min_python"), 12), "min_sqlite": _cap_text(m.get("min_sqlite"), 12)}


def _vtuple(text, default):
    try:
        return tuple(int(p) for p in str(text).split("."))
    except ValueError:
        return default


def preflight(manifest, size, ctx, now):
    """[{id, ok, text}]: what the Updates page shows as 'Preflight'. `ctx`: sync_running (bool), db_bytes (int), run (state.json
    fields or None)."""
    items = []
    opt = opt_dir() or Path(keylib.REPO_ROOT)
    data = data_dir()
    need_opt = 3 * (size or 20 * 2**20) + 100 * 2**20
    need_data = 3 * (ctx.get("db_bytes") or 0) + 100 * 2**20
    for ident, label, path, need in (("disk_opt", "Disk, code volume", opt, need_opt), ("disk_data", "Disk, data volume", data, need_data)):
        try:
            free = shutil.disk_usage(str(path)).free
            items.append({"id": ident, "ok": free >= need, "text": f"{label}: {free / 2**30:.1f} GB free; {need / 2**30:.1f} GB needed."})
        except OSError:
            items.append({"id": ident, "ok": False, "text": f"{label}: could not read free space."})
    want_py = _vtuple((manifest or {}).get("min_python"), _PY_MIN)
    have_py = sys.version_info[:3]
    items.append({"id": "python", "ok": have_py >= want_py,
                  "text": f"Python {'.'.join(map(str, have_py))} (needs {'.'.join(map(str, want_py))} or newer)."})
    want_sql = _vtuple((manifest or {}).get("min_sqlite"), _SQLITE_MIN)
    have_sql = tuple(int(p) for p in sqlite3.sqlite_version.split("."))
    items.append({"id": "sqlite", "ok": have_sql >= want_sql,
                  "text": f"SQLite {sqlite3.sqlite_version} (needs {'.'.join(map(str, want_sql))} or newer)."})
    items.append({"id": "sync", "ok": not ctx.get("sync_running"),
                  "text": "No sync is running." if not ctx.get("sync_running")
                  else "A sync is running: the upgrade waits up to 10 minutes for it to finish, then refuses to start."})
    run = ctx.get("run") or {}
    busy = bool(run) and run.get("result") is None and bool(run.get("step"))
    items.append({"id": "in_flight", "ok": not busy, "text": "No other upgrade is in flight." if not busy else "Another upgrade is in progress."})
    st = updater_state()
    items.append({"id": "updater", "ok": st["ready"],
                  "text": (f"Updater present{' (activator ' + st['activator'] + ')' if st['activator'] else ''}." if st["ready"] else st["message"])})
    return items


def build_preview(installed_version, size, ctx, now=None):
    """Fetch and verify the latest release's signature file and manifest, compute the preflight, store and return the
    preview. Raises PreviewError (stable code, plain message)."""
    now = now or datetime.now(timezone.utc)
    st = service.load()["state"]
    latest = st.get("latest_version")
    if not latest or not service.newer(latest, installed_version):
        raise PreviewError("no_update", "No newer release is known: use Check now first.")
    base, hosts = release_base()
    texts = {}
    for name, cap in ((f"ocw-{latest}.tar.gz.minisig", MAX_SIG_BYTES), ("manifest.json", MAX_MANIFEST_BYTES)):
        got = check.fetch(f"{base}/v{latest}/{name}", hosts, None, check.USER_AGENT, max_bytes=cap, accept="application/octet-stream")
        if got.status != "ok":
            raise PreviewError("fetch_failed", f"Could not read {name} from the release server ({got.detail or got.code}).")
        texts[name] = got.body
    try:
        sig = minisign.parse_signature(texts[f"ocw-{latest}.tar.gz.minisig"].decode("utf-8"))
    except (minisign.SignatureError, UnicodeDecodeError) as exc:
        raise PreviewError("signature_invalid", f"The signature file is malformed: {exc}")
    fields, key_entry = _verify_trusted_comment(sig, latest)
    manifest = _manifest_view(texts["manifest.json"], latest)
    if manifest["min_upgrade_from"]:
        try:
            if keylib.parse_version(installed_version) < keylib.parse_version(manifest["min_upgrade_from"]):
                raise PreviewError("too_old", f"This release can only be installed over {manifest['min_upgrade_from']} or newer "
                                              f"(installed: {installed_version}). Upgrade to that first.")
        except keylib.KeyListError:
            pass
    preview = {"schema": 1, "version": latest, "installed_version": installed_version, "sha256": fields["sha256"],
               "file": fields["file"], "size": size, "key_id": sig.key_id, "key_status": key_entry.get("status"),
               "key_since": key_entry.get("since"), "key_role": key_entry.get("role"), "signed_at": fields.get("timestamp"),
               "manifest": manifest, "manifest_source": "the release's manifest.json asset (not itself signed; the updater re-verifies the "
                                                        "signed copy inside the archive before installing)",
               "checked_at": _iso(now),
               "preflight": preflight(manifest, size, ctx, now)}
    preview["preflight_ok"] = all(i["ok"] for i in preview["preflight"])
    save_preview(preview)
    return preview


def refresh_preflight(ctx, now=None):
    now = now or datetime.now(timezone.utc)
    p = load_preview()
    if not p:
        return None
    p["preflight"] = preflight(p.get("manifest"), p.get("size"), ctx, now)
    p["preflight_ok"] = all(i["ok"] for i in p["preflight"])
    p["checked_at"] = _iso(now)
    save_preview(p)
    return p


def current_preview(latest_version):
    p = load_preview()
    return p if p and p.get("version") == latest_version else None


# --- request file -------------------------------------------------------------------------------------------------------
def new_correlation_id():
    return "upg-" + uuid.uuid4().hex[:8]


def write_request(*, correlation_id, version, sha256, action_id, actor, trigger_kind, entered=None, now=None):
    """Write the advisory request into the updater's inbox (atomic: written beside it, then renamed in). NEVER carries a
    `not_before`: the updater treats the inbox as 'now', scheduling is this module's job. Returns the path."""
    now = now or datetime.now(timezone.utc)
    if not CID_RE.match(correlation_id) or not VERSION_RE.match(version) or not SHA_RE.match(sha256):
        raise ValueError("invalid request fields")
    if action_id is not None and not ACTION_ID_RE.match(str(action_id)):
        action_id = None
    req = {"schema": 1, "action": "apply", "correlation_id": correlation_id, "version": version, "sha256": sha256,
           "action_id": action_id, "requested_at": _iso(now), "not_before": None, "origin": "app",
           "actor": (actor or "")[:120] or None, "trigger_kind": trigger_kind}
    if entered:
        req["entered"] = str(entered)[:80]
    inbox = inbox_dir()
    stage = inbox.parent / f".{correlation_id}.tmp"
    fd = os.open(str(stage), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(req, fh)
        fh.flush()
        os.fsync(fh.fileno())
    final = inbox / f"{correlation_id}.json"
    os.replace(str(stage), str(final))
    with _lock:
        _quiesce_until[0] = now + QUIESCE
    return final


def quiesced(now=None):
    until = _quiesce_until[0]
    return bool(until and (now or datetime.now(timezone.utc)) < until)


def rejection(correlation_id):
    """The updater's refusal of this request (root writes upgrade/rejections/<id>.json), or None."""
    if not isinstance(correlation_id, str) or not CID_RE.match(correlation_id):
        return None
    try:
        with open(service.upgrade_dir() / "rejections" / f"{correlation_id}.json", encoding="utf-8") as fh:
            r = json.load(fh)
    except (OSError, ValueError):
        return None
    return {"correlation_id": correlation_id, "code": str(r.get("code"))[:40], "message": str(r.get("message"))[:300], "at": r.get("at")} \
        if isinstance(r, dict) else None


# --- schedule tick -----------------------------------------------------------------------------------------------------
def tick(installed_version, ctx_fn, now=None):
    """Called from the scheduler loop each poll. Starts a due scheduled upgrade by writing its request; a time the application
    missed (not running within MISSED_GRACE) becomes 'missed' and is never run late. Never raises."""
    now = now or datetime.now(timezone.utc)
    try:
        with _lock:
            data = load_schedule()
            entry = data["schedule"]
            pending_approval(now)  # expire a stale held approval
            if not entry or entry.get("status") != "scheduled":
                return None
            when = _parse(entry.get("when_utc"))
            if when is None:
                data["schedule"]["status"] = "missed"
                save_schedule(data)
                return "invalid"
            if now < when:
                return None
            if now - when > MISSED_GRACE:
                entry["status"] = "missed"
                entry["noticed_at"] = _iso(now)
                data["last"] = {"kind": "missed", "version": entry.get("version"), "at": _iso(now), "correlation_id": entry.get("correlation_id")}
                save_schedule(data)
                _audit("upgrade.missed", {"correlation_id": entry.get("correlation_id"), "version": entry.get("version"),
                                          "when_utc": entry.get("when_utc"), "reason_code": "app_not_running",
                                          "detail": "the application was not running at the scheduled time; the upgrade was not run late"})
                return "missed"
            ctx = ctx_fn()
            if ctx.get("sync_running") and now - when < WAIT_FOR_SYNC:
                return "waiting_for_sync"      # the updater would wait too; a running sync is allowed to finish first
            state = updater_state()
            run = ctx.get("run") or {}
            if not state["ready"] or (run.get("result") is None and run.get("step")):
                entry["status"] = "missed"
                data["last"] = {"kind": "failed_to_start", "version": entry.get("version"), "at": _iso(now),
                                "correlation_id": entry.get("correlation_id"),
                                "message": state["message"] or "another upgrade was in progress"}
                save_schedule(data)
                _audit("upgrade.failed", {"correlation_id": entry.get("correlation_id"), "version_to": entry.get("version"),
                                          "step": "scheduled start", "reason_code": state["reason"] or "in_flight",
                                          "detail": data["last"]["message"]})
                return "not_started"
            preview = current_preview(entry.get("version"))
            if not preview or preview.get("sha256") != entry.get("sha256"):
                entry["status"] = "missed"
                data["last"] = {"kind": "failed_to_start", "version": entry.get("version"), "at": _iso(now),
                                "correlation_id": entry.get("correlation_id"), "message": "the release changed since it was approved"}
                save_schedule(data)
                _audit("upgrade.failed", {"correlation_id": entry.get("correlation_id"), "version_to": entry.get("version"),
                                          "step": "scheduled start", "reason_code": "target_changed",
                                          "detail": "the signed release information changed since the approval; nothing was installed"})
                return "target_changed"
            write_request(correlation_id=entry["correlation_id"], version=entry["version"], sha256=entry["sha256"],
                          action_id=entry.get("action_id"), actor=entry.get("actor_email") or entry.get("actor_sub"),
                          trigger_kind=f"schedule {entry['when_utc']}", entered=entry.get("entered"), now=now)
            entry["status"] = "started"
            entry["started_at"] = _iso(now)
            save_schedule(data)
            _audit("upgrade.started_by_schedule", {"correlation_id": entry["correlation_id"], "version": entry["version"],
                                                    "sha256": entry["sha256"], "when_utc": entry["when_utc"]})
            return "started"
    except Exception as exc:  # noqa: BLE001 - a schedule problem must never take the scheduler loop down
        try:
            _engine().log("ERROR", f"upgrade schedule tick failed: {type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            pass
        return None


# --- what the Updates page reads -----------------------------------------------------------------------------------------
RUN_EXTRA = ("steps_done", "health", "rollback_health", "rolled_back_to", "rollback_seconds", "failure", "signed_by", "sha256",
             "requested_by", "schema_before", "schema_after", "backup", "manifest", "downtime_estimate_seconds", "step_started_at")


def _read_state():
    try:
        with open(service.upgrade_dir() / "state.json", encoding="utf-8") as fh:
            st = json.load(fh)
        return st if isinstance(st, dict) else None
    except (OSError, ValueError):
        return None


def run_view():
    st = _read_state()
    if st is None:
        return None
    out = {k: st.get(k) for k in service._RUN_FIELDS}
    for k in RUN_EXTRA:
        v = st.get(k)
        if k == "backup" and isinstance(v, dict):
            v = {kk: v.get(kk) for kk in ("name", "size", "integrity")}
        if k == "manifest" and isinstance(v, dict):
            v = {kk: v.get(kk) for kk in ("migrations", "expected_schema_version")}
        if k == "steps_done" and isinstance(v, list):
            v = [{"step": s.get("step"), "at": s.get("at"), "seconds": s.get("seconds")} for s in v if isinstance(s, dict)][:20]
        if k in ("health", "rollback_health") and isinstance(v, list):
            v = [{"id": h.get("id"), "ok": h.get("ok"), "detail": str(h.get("detail"))[:200]} for h in v if isinstance(h, dict)][:20]
        if k == "failure" and isinstance(v, dict):
            v = {kk: (str(v.get(kk))[:300] if v.get(kk) is not None else None) for kk in ("step", "reason_code", "detail", "at")}
        out[k] = v
    return out


def history_view(limit=10):
    out = []
    try:
        with open(service.upgrade_dir() / "history.jsonl", encoding="utf-8") as fh:
            lines = fh.readlines()[-200:]
    except OSError:
        return out
    for line in lines:
        try:
            h = json.loads(line)
        except ValueError:
            continue
        if isinstance(h, dict) and h.get("action") in ("apply", "rollback", "restore"):
            b = h.get("backup")
            out.append({"correlation_id": h.get("correlation_id"), "action": h.get("action"), "version_from": h.get("version_from"),
                        "version_to": h.get("version_to"), "result": h.get("result"), "reason_code": h.get("reason_code"),
                        "started_at": h.get("started_at"), "updated_at": h.get("updated_at"), "seconds": h.get("seconds"),
                        "backup": os.path.basename(b) if isinstance(b, str) else None, "bundle": h.get("bundle")})
    return out[-limit:][::-1]


def failures_view():
    try:
        with open(service.upgrade_dir() / "failures.json", encoding="utf-8") as fh:
            f = json.load(fh)
        v = f.get("versions") if isinstance(f, dict) else None
        return {k: {"count": int(x.get("count", 0)), "last_code": x.get("last_code")} for k, x in (v or {}).items()
                if isinstance(x, dict)} if isinstance(v, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def rollback_view(run, now=None):
    """Is the 24-hour 'roll back' available, and to what? (Advice for the page; the CLI enforces it.)"""
    now = now or datetime.now(timezone.utc)
    if not run or run.get("result") != "completed" or run.get("action") != "apply":
        return None
    done = _parse(run.get("updated_at"))
    if done is None:
        return None
    until = done + ROLLBACK_WINDOW
    return {"available": now < until, "until": _iso(until), "to": run.get("version_from")}


def notice(installed_version, is_admin, now=None):
    """The one-line banner every signed-in user may see: kind none | available (admins) | scheduled | running | failed."""
    now = now or datetime.now(timezone.utc)
    run = _read_state() or {}
    if run.get("result") is None and run.get("step"):
        return {"kind": "running", "version": run.get("version_to"), "started_at": run.get("started_at")}
    if run.get("result") in ("rolled_back", "failed", "failed_needs_operator"):
        done = _parse(run.get("updated_at"))
        if done and now - done < timedelta(hours=48):
            return {"kind": "failed", "result": run.get("result"), "version": run.get("version_to"), "rolled_back_to": run.get("rolled_back_to"),
                    "at": run.get("updated_at")}
    entry = load_schedule()["schedule"]
    if entry and entry.get("status") == "scheduled":
        return {"kind": "scheduled", "version": entry.get("version"), "when_utc": entry.get("when_utc"),
                "downtime_estimate_seconds": (current_preview(entry.get("version")) or {}).get("manifest", {}).get("downtime_estimate_seconds")}
    if is_admin:
        data = service.load()
        enabled, _src = service.is_enabled(data)
        latest = data["state"].get("latest_version")
        if enabled and latest and service.newer(latest, installed_version):
            return {"kind": "available", "version": latest}
    return {"kind": "none"}
