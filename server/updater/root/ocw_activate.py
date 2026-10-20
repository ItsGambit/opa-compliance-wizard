#!/usr/bin/env python3
"""The root-owned updater: activate a staged, signed release; roll back; restore.

THIS FILE RUNS AS ROOT. It is installed by server/install.sh into
/opt/opa-compliance-wizard/updater/ (root:root, not writable by anyone else)
together with ocw_crypto.py, ocw_trust.py, ocw_host.py, ocw_bundle.py,
ocw_cli.py and nginx_bake.py, and it imports ONLY those and the Python
standard library. Root never executes anything from a release tree, the
application's virtualenv or the data directory.

What it trusts: its own trust list (updater/trust.json, root-owned); the
signed release file and its manifest (re-verified here, because the account
that staged them is not trusted); its own config (updater/config.json); and
the operator running the CLI as root. What it does NOT trust: the request
file (advisory: strictly validated, replay-protected, never obeyed beyond
"install this genuine newer release"), the data directory, the release tree
until every file in it matches the signed manifest.

The upgrade is a state machine whose position is written to
upgrade/state.json (atomic replace + fsync) BEFORE each step starts, so a
crash, kill or power loss at any point resumes correctly (`resume`).

    received/validated -> downloaded -> staged -> preflight -> backup ->
    switching -> restarting -> health_check -> completed
                                  \\-> rolling_back -> rolled_back | failed_needs_operator

A failure before `switching` changes nothing but the state file. A failure
at or after it does ONE automatic code-only rollback (symlink back, restart,
health checks); the database is never touched by it. Restoring the pre-upgrade
copy of the archive is a separate, typed operator action (`restore`).

The service is never left down silently: while switching, nginx serves the
maintenance page; on a rollback that also fails, the page changes to say an
operator is needed, a CRIT line goes to the journal, the audit log gets
`upgrade.failed`, the state file says `failed_needs_operator`, and a
redacted support bundle is written.

Fault injection for tests (honoured only when OCW_TEST_MODE=1 is ALSO set):
OCW_UPDATER_FAULT=after_unpack|during_migration|after_switch|health_fail|
rollback_fail|disk_full|kill_at:<step>, comma separated.
"""

import calendar
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if __name__ == "__main__":  # ocw_cli imports this module by name: it must be this very module, not a second copy
    sys.modules.setdefault("ocw_activate", sys.modules["__main__"])

import ocw_bundle  # noqa: E402
import ocw_host  # noqa: E402
import ocw_trust  # noqa: E402

ACTIVATOR_VERSION = "5.47.0"
STEP_ORDER = ["validated", "downloaded", "staged", "preflight", "backup", "switching", "restarting", "health_check", "completed"]
STEP_LABEL = {"validated": "Received and validated", "downloaded": "Downloaded", "staged": "Verified and staged",
              "preflight": "Preflight", "backup": "Backup", "switching": "Switching", "restarting": "Restarting",
              "health_check": "Health checks", "completed": "Completed"}
HEALTH_CHECKS = ["unit_active", "version", "healthz", "gate_401", "quick_check", "schema_version", "chain_heads", "smoke_read"]
REASONS = {"request_invalid", "request_replayed", "request_stale", "signature_invalid", "key_unknown", "version_not_newer",
           "hash_mismatch", "name_mismatch", "version_mismatch", "too_old", "disk_space", "sync_in_progress", "pip_failed",
           "stage_failed", "not_staged", "tree_mismatch", "backup_failed", "migration_failed", "nginx_invalid", "restart_failed",
           "health_unit", "health_version", "health_healthz", "health_gate", "health_quick_check", "health_schema",
           "health_chain", "health_smoke", "rollback_failed", "interrupted", "failed_before", "too_many_failures",
           "version_failed_before", "in_flight", "bad_release", "bad_artifact", "revoked_key", "retired_key", "wrong_role",
           "no_key_pinned", "keys_changed", "unknown_alg", "no_trust", "bad_trust", "internal_error"}
HEALTH_REASON = {"unit_active": "health_unit", "version": "health_version", "healthz": "health_healthz", "gate_401": "health_gate",
                 "quick_check": "health_quick_check", "schema_version": "health_schema", "chain_heads": "health_chain",
                 "smoke_read": "health_smoke"}
REQUEST_MAX_AGE = 24 * 3600
REQUEST_MAX_BYTES = 8192
_CID = re.compile(r"^(upg|sched)-[0-9a-f]{8}$")
_VER = re.compile(r"^\d+\.\d+\.\d+$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ACTION_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class Killed(BaseException):
    """A simulated kill (fault injection): not catchable by `except Exception`."""


class StepFailed(Exception):
    def __init__(self, code, message, step=None, detail=None):
        super().__init__(message)
        self.code, self.step, self.detail = code, step, detail or {}


# --- configuration ---------------------------------------------------------------------


class Cfg:
    def __init__(self, environ=None):
        env = environ if environ is not None else os.environ
        self.opt = env.get("OCW_OPT_DIR", "/opt/opa-compliance-wizard")
        self.data = env.get("OCW_DATA_DIR", "/var/lib/opa-compliance-wizard")
        self.updater_dir = env.get("OCW_UPDATER_DIR", os.path.join(self.opt, "updater"))
        self.env_file = env.get("OCW_ENV_FILE", "/etc/opa-compliance-wizard.env")
        c = {}
        try:
            with open(os.path.join(self.updater_dir, "config.json"), encoding="utf-8") as fh:
                c = json.load(fh)
        except (OSError, ValueError):
            pass
        self.app_user = c.get("app_user", "")
        self.app_group = c.get("app_group", "")
        self.stage_user = c.get("stage_user", "ocw-updater")
        self.backend_service = c.get("backend_service", "opa-compliance-wizard")
        self.gate_service = c.get("gate_service", "opa-auth-gate")
        self.nginx_site = c.get("nginx_site", "/etc/nginx/sites-available/opa-secrets-wizard")
        self.backend_port = int(c.get("backend_port", 8766))
        self.faults = set()
        if env.get("OCW_TEST_MODE") == "1":
            self.faults = {f for f in env.get("OCW_UPDATER_FAULT", "").split(",") if f}
        self.fast = env.get("OCW_TEST_MODE") == "1" and env.get("OCW_FAST") == "1"
        self.releases = os.path.join(self.opt, "releases")  # root-owned: only root renames or removes entries here
        self.handoff = os.path.join(self.opt, "handoff")  # root:<staging group> 0750: where an operator's file is handed to staging
        self.staging = os.path.join(self.opt, "staging")  # owned by the staging account: <staging>/<version> until root takes it
        self.current = os.path.join(self.opt, "current")
        self.previous = os.path.join(self.opt, "previous")
        self.maintenance_dir = os.path.join(self.opt, "maintenance")
        self.maintenance_page = os.path.join(self.maintenance_dir, "active.html")
        self.upgrade = os.path.join(self.data, "upgrade")
        self.requests = os.path.join(self.upgrade, "inbox", "requests")
        self.artifacts = env.get("OCW_ARTIFACTS_DIR", "/var/lib/ocw-updater/artifacts")
        self.verified = os.path.join(self.upgrade, "verified")
        self.state_path = os.path.join(self.upgrade, "state.json")
        self.history_path = os.path.join(self.upgrade, "history.jsonl")
        self.failures_path = os.path.join(self.upgrade, "failures.json")
        self.bundles = os.path.join(self.upgrade, "bundles")
        self.backups = os.path.join(self.upgrade, "backups")
        self.schedule = os.path.join(self.upgrade, "schedule")
        self.rejections = os.path.join(self.upgrade, "rejections")
        self.work = os.path.join(self.upgrade, "work")
        self.done = os.path.join(self.upgrade, "requests-done")
        self.lock_path = os.path.join(self.upgrade, "lock")
        self.trust_path = os.path.join(self.updater_dir, "trust.json")
        self.audit_log = os.path.join(self.data, "audit_log.jsonl")

    def env_values(self):
        out = {}
        try:
            with open(self.env_file, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                        v = v[1:-1]
                    out[k] = v
        except OSError:
            pass
        return out

    def db_path(self):
        return self.env_values().get("OPA_AUDIT_DB_PATH") or os.path.join(self.data, "audit_store.db")

    def ids(self):
        import grp
        import pwd
        try:
            uid = pwd.getpwnam(self.app_user).pw_uid
            gid = grp.getgrnam(self.app_group or self.app_user).gr_gid
        except (KeyError, TypeError):
            return None, None
        return uid, gid


# --- small helpers ------------------------------------------------------------------------

_cid = [None]


def log(level, msg, **fields):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), "level": level, "msg": msg}
    if _cid[0]:
        rec["correlation_id"] = _cid[0]
    rec.update(fields)
    print(json.dumps(rec, default=str), file=sys.stderr if level in ("WARN", "ERROR", "CRIT") else sys.stdout, flush=True)


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_iso(text):
    try:
        return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return None


def safe_copy(src, dst, mode=0o600, uid=None, gid=None):
    """Copy a file into a fresh file: the source is opened without following links and must be a plain file; the
    destination is removed if present and created exclusively (never written through a link). Used wherever root copies
    to or from a directory the application account can write."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    sfd = os.open(src, os.O_RDONLY | nofollow)
    with os.fdopen(sfd, "rb") as fin:
        if not stat.S_ISREG(os.fstat(fin.fileno()).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", src)
        try:
            os.unlink(dst)
        except FileNotFoundError:
            pass
        dfd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, mode)
        with os.fdopen(dfd, "wb") as fout:
            if uid is not None and os.geteuid() == 0:
                os.fchown(fout.fileno(), uid, gid)
            shutil.copyfileobj(fin, fout, 1 << 20)
            fout.flush()
            os.fsync(fout.fileno())


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json_atomic(path, obj, mode=0o644):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    fsync_dir(directory)


def open_regular(path, write=False):
    """Open a file in a directory root does not own: never follow a link, never block on a pipe, and only a plain file
    is accepted (checked on the open descriptor). `write` opens for append (no create)."""
    flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags | ((os.O_WRONLY | os.O_APPEND) if write else os.O_RDONLY))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_regular(path, max_bytes=16 * 1024 * 1024):
    """The bytes of a plain file (at most max_bytes), opened safely; OSError if it is a link, pipe or directory."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as fh:
        return fh.read(max_bytes)


def read_json(path, default=None):
    try:
        return json.loads(read_regular(path).decode("utf-8"))
    except (OSError, ValueError):
        return default


def dir_size(path):
    total = 0
    for base, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(base, f)).st_size
            except OSError:
                pass
    return total


def installed_version(cfg):
    """SCRIPT_VERSION of the tree `current` points at, read as text (never executed)."""
    try:
        with open(os.path.join(cfg.current, "create_secret_folders.py"), encoding="utf-8") as fh:
            m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', fh.read(), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def link_version(link):
    try:
        target = os.readlink(link)
    except OSError:
        return None
    name = os.path.basename(target.rstrip("/"))
    return name if _VER.match(name) else None


# --- audit log (same file and line format the application writes) ------------------------------


def audit_append(cfg, action, details, actor_email=None, ids=(None, None)):
    """Append one entry to audit_log.jsonl in the application's own line format. The data directory is shared with the
    (less trusted) application account, so nothing here follows a link or changes the owner of a file it did not just create."""
    entry = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00", time.gmtime()), "actor_email": actor_email,
             "actor_sub": None, "action": action, "details": details, "client_ip": None, "user_agent": None}
    data = (json.dumps(entry, separators=(",", ":"), default=str) + "\n").encode("utf-8")
    path = cfg.audit_log
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    lock_fd = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            lock_fd = os.open(os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".lock"),
                              os.O_RDWR | os.O_CREAT | nofollow, 0o600)
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        break
                    time.sleep(0.05)
        except OSError:
            lock_fd = None
        try:  # created by us: hand it to the application account, which owns this file
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            if ids[0] is not None and os.geteuid() == 0:
                os.fchown(fd, ids[0], ids[1])
        except FileExistsError:
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | nofollow)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    except OSError as exc:
        log("ERROR", f"audit append failed ({exc.strerror}); unrecorded: {action}")
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
    return entry


def audit_entries_for(cfg, correlation_id, max_bytes=16 * 1024 * 1024):
    """Audit entries whose details carry this correlation id (tail of the file only)."""
    out = []
    try:
        with open(cfg.audit_log, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            chunk = fh.read()
    except OSError:
        return out
    for line in chunk.splitlines():
        if correlation_id.encode() not in line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and (e.get("details") or {}).get("correlation_id") == correlation_id:
            out.append(e)
    return out


# --- the maintenance page (served by nginx while switching) ------------------------------------

_LOGO = ('<svg width="20" height="20" viewBox="0 0 32 32" role="img" aria-label="OPA Compliance Wizard"><path d="M16 2.5 27 6.5V15c0 '
         '7.2-4.6 12-11 14.5C9.6 27 5 22.2 5 15V6.5Z" fill="none" stroke="#E2E8F0" stroke-width="2.4" stroke-linejoin="round"/>'
         '<path d="M11 11h10M11 15.5h10" stroke="#E2E8F0" stroke-width="2.4" stroke-linecap="round"/><path d="m11.5 20.5 3 3 6-6.5" '
         'fill="none" stroke="#F59E0B" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def maintenance_html(mode, started_at, step_no, step_total, expected_seconds):
    """mode: 'upgrading' | 'rolling_back' | 'needs_operator'. No version numbers (hosted mode keeps the version off the network)."""
    started = time.strftime("%d %b %Y, %H:%M %Z", time.localtime(started_at))
    if mode == "needs_operator":
        title, spin = "Temporarily unavailable", ""
        body = ("An upgrade failed and could not be rolled back automatically. An operator must run "
                "<code>ocw-updater status</code> on the server. Your data has not been changed.")
        facts = f'<span class="lbl">Started</span><span class="v">{started}</span>'
    else:
        spin = '<span class="spin" aria-hidden="true"></span>'
        title = "Upgrading — back in under a minute" if mode == "upgrading" else "Restoring the previous version — back shortly"
        body = ("An administrator approved an upgrade to a newer version. The service is restarting. You stay signed in; this "
                "page refreshes itself every 5 seconds and returns you to where you were." if mode == "upgrading" else
                "The upgrade did not pass its checks, so the previous version is being put back automatically. This page "
                "refreshes itself every 5 seconds.")
        facts = (f'<span class="lbl">Started</span><span class="v">{started}</span>'
                 f'<span class="lbl">Step</span><span class="v">{step_no} of {step_total}</span>'
                 f'<span class="lbl">Expected</span><span class="v">About {max(10, int(expected_seconds))} seconds</span>')
    refresh = '<meta http-equiv="refresh" content="5">' if mode != "needs_operator" else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">{refresh}<title>OPA Compliance Wizard</title>
<style>body{{margin:0;background:#09090b;color:#f4f4f5;font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:14px;line-height:1.5}}
.page{{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px 16px}}
.box{{max-width:560px;width:100%;background:#17171c;border:1px solid #2a2a30;border-radius:8px;padding:28px}}
h1{{margin:0 0 8px;font-size:18px;font-weight:600;display:flex;align-items:center;gap:10px}}p{{margin:0 0 10px;color:#d1d1d6;font-size:13px}}
.lbl{{font-size:11px;font-weight:600;color:#9a9aa4;text-transform:uppercase;letter-spacing:.08em}}
.kv{{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:12px;margin:14px 0;padding:12px;background:#111114;border:1px solid #2a2a30;border-radius:8px}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}.note{{font-size:12px;color:#9a9aa4;margin:0}}
.spin{{display:inline-block;width:14px;height:14px;border-radius:999px;border:2px solid #1662DD;border-top-color:transparent;flex:none}}
.brand{{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:#d1d1d6;margin-bottom:18px}}</style></head>
<body><div class="page"><main class="box" role="main"><div class="brand">{_LOGO}<span>OPA Compliance Wizard <span style="font-weight:400;color:#9a9aa4">· Evidence for OPA audits</span></span></div>
<h1>{spin}{title}</h1><p>{body}</p><div class="kv">{facts}</div>
<p>If this page is still here after a few minutes, the upgrade may have been rolled back to the previous version automatically, or an operator may be needed. Administrators: check the Updates page or run <code>ocw-updater status</code> on the server.</p>
<p class="note">An independent open-source tool. Not affiliated with or endorsed by Okta, Inc.</p></main></div></body></html>
"""


# --- the engine ---------------------------------------------------------------------------------


class Updater:
    def __init__(self, cfg, host):
        self.cfg, self.host = cfg, host
        self.uid, self.gid = cfg.ids()
        self.st = None
        self.t0 = host.now()
        self._secrets = None

    # faults / kills
    def fault(self, name):
        return name in self.cfg.faults

    def kill_point(self, step):
        if f"kill_at:{step}" in self.cfg.faults:
            raise Killed(step)

    # state
    def persist(self):
        self.st["updated_at"] = iso(self.host.now())
        write_json_atomic(self.cfg.state_path, self.st)

    def audit(self, action, details=None, actor_email=None):
        d = dict(details or {})
        d.setdefault("correlation_id", self.st.get("correlation_id") if self.st else None)
        d.setdefault("trigger", "ocw-updater")
        log("INFO", action, **{k: v for k, v in d.items() if k not in ("correlation_id",)})
        return audit_append(self.cfg, action, d, actor_email, (self.uid, self.gid))

    def begin(self, step):
        self.st["step"] = step
        self.st["step_started_at"] = iso(self.host.now())
        self._step_t = self.host.now()
        self.persist()
        log("INFO", f"step {step} started")
        self.kill_point(step)

    def finish(self, step, **detail):
        secs = round(self.host.now() - getattr(self, "_step_t", self.host.now()), 1)
        self.st["steps_done"].append({"step": step, "at": iso(self.host.now()), "seconds": secs, "detail": detail})
        self.persist()
        self.audit("upgrade.step", {"step": step, "label": STEP_LABEL.get(step, step), "seconds": secs, **detail,
                                    "version_from": self.st.get("version_from"), "version_to": self.st.get("version_to")})

    # maintenance page
    def page(self, mode, step):
        no = STEP_ORDER.index(step) + 1 if step in STEP_ORDER else 7
        try:
            os.makedirs(self.cfg.maintenance_dir, exist_ok=True)
            html = maintenance_html(mode, parse_iso(self.st["started_at"]) or self.host.now(), no, len(STEP_ORDER),
                                    self.st.get("downtime_estimate_seconds") or 60)
            tmp = self.cfg.maintenance_page + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(html)
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.cfg.maintenance_page)
        except OSError as exc:
            log("WARN", f"could not write the maintenance page: {exc.strerror}")

    def page_off(self):
        try:
            os.unlink(self.cfg.maintenance_page)
        except FileNotFoundError:
            pass
        except OSError as exc:
            log("WARN", f"could not remove the maintenance page: {exc.strerror}")

    # --- units ----------------------------------------------------------------------------------
    def units(self):
        c = self.cfg
        units = [c.backend_service]
        if self.host.unit_exists(c.gate_service):  # a server fronted by something else has no main gate unit
            units.append(c.gate_service)
        units += self.host.extra_gate_units()
        if self.host.unit_exists("opa-host-status") and self.host.unit_enabled("opa-host-status"):
            units.append("opa-host-status")
        return units

    def gates(self):
        return [u for u in self.units() if u.startswith("opa-auth-gate")]

    # --- failures bookkeeping -------------------------------------------------------------------
    def failures(self):
        f = read_json(self.cfg.failures_path, {}) or {}
        f.setdefault("versions", {})
        return f

    def record_failure(self, version, code):
        f = self.failures()
        v = f["versions"].setdefault(version, {"count": 0})
        v["count"] += 1
        v["last_code"], v["last_at"], v["correlation_id"] = code, iso(self.host.now()), self.st.get("correlation_id")
        write_json_atomic(self.cfg.failures_path, f)

    # --- request validation (the request is advisory) ---------------------------------------------
    def validate_request(self, req, origin_trusted):
        c = self.cfg
        if not isinstance(req, dict) or req.get("schema") != 1 or req.get("action") != "apply":
            raise StepFailed("request_invalid", "unsupported request")
        if not _CID.match(str(req.get("correlation_id", ""))):
            raise StepFailed("request_invalid", "bad correlation id")
        if not _VER.match(str(req.get("version", ""))) or not _SHA.match(str(req.get("sha256", ""))):
            raise StepFailed("request_invalid", "bad version or sha256")
        aid = req.get("action_id")
        if aid is not None and not _ACTION_ID.match(str(aid)):
            raise StepFailed("request_invalid", "bad action id")
        at = parse_iso(req.get("requested_at"))
        now = self.host.now()
        if at is None or at > now + 300 or now - at > REQUEST_MAX_AGE:
            raise StepFailed("request_stale", "the request is older than 24 hours or dated in the future")
        if aid:
            for line in self._history_lines():
                if line.get("action_id") == aid:
                    raise StepFailed("request_replayed", "this approval was already used")
        nb = req.get("not_before")
        if nb is not None and parse_iso(nb) is None:
            raise StepFailed("request_invalid", "bad not_before")
        if self.in_flight():
            raise StepFailed("in_flight", "another upgrade is in progress")
        f = self.failures()
        rec = f["versions"].get(req["version"])
        if rec and rec.get("count", 0) >= 1:
            raise StepFailed("version_failed_before", f"{req['version']} failed before ({rec.get('last_code')}); an operator must "
                                                      "run `ocw-updater clear-failure` first")
        if sum(v.get("count", 0) for v in f["versions"].values()) >= 2:
            raise StepFailed("too_many_failures", "two upgrades have failed; contact the maintainers with the support bundle, then clear-failure")

    def _history_lines(self):
        out = []
        try:
            with open(self.cfg.history_path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        return out

    def in_flight(self):
        st = read_json(self.cfg.state_path)
        return bool(st and st.get("result") is None and st.get("step"))

    # --- the tree check ---------------------------------------------------------------------------
    def check_tree(self, root, manifest):
        """Every file under `root` must be listed in the signed manifest with a matching sha256;
        nothing else may exist (except .venv and .staged); no links outside .venv."""
        expected = dict(manifest["files"])
        expected.pop("manifest.json", None)
        seen = set()
        for base, dirs, files in os.walk(root, followlinks=False):
            rel_base = os.path.relpath(base, root)
            if rel_base == ".":
                dirs[:] = [d for d in dirs if d != ".venv"]
                files = [f for f in files if f not in (".staged", ".staging")]
            for d in list(dirs):
                p = os.path.join(base, d)
                if os.path.islink(p):
                    raise StepFailed("tree_mismatch", f"{os.path.relpath(p, root)} is a link", "staged")
            for name in files:
                p = os.path.join(base, name)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise StepFailed("tree_mismatch", f"{rel} is not a plain single-link file", "staged")
                if "__pycache__" in rel.split("/"):
                    os.unlink(p)
                    continue
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                if rel == "manifest.json":
                    continue
                if expected.get(rel) != h.hexdigest():
                    raise StepFailed("tree_mismatch", f"{rel} does not match the signed manifest", "staged")
                seen.add(rel)
        missing = sorted(set(expected) - seen)
        if missing:
            raise StepFailed("tree_mismatch", f"{len(missing)} file(s) the manifest lists are missing (first: {missing[0]})", "staged")

    # --- prepare phase (everything before the switch) ----------------------------------------------
    def prepare(self, req):
        c = self.cfg
        ver = req["version"]
        trust = self._trust()
        self.begin("validated")
        installed = installed_version(c)
        if not installed:
            raise StepFailed("internal_error", "cannot read the installed version", "validated")
        self.st["version_from"] = installed
        artifact = os.path.join(c.artifacts, f"ocw-{ver}.tar.gz")
        staged_dir = os.path.join(c.staging, ver)
        staged_marker = os.path.join(staged_dir, ".staged")
        had_artifact = os.path.exists(artifact) and os.path.exists(staged_marker)
        self.finish("validated", request=os.path.basename(req.get("_file", "")), sha256_ok=True)
        self.begin("downloaded")
        if not had_artifact:
            ok, out = self.host.start(f"ocw-stage@{ver}.service")
            err = read_json(os.path.join(c.artifacts, f"{ver}.stage-error.json"))
            if not ok or not os.path.exists(staged_marker):
                code = (err or {}).get("code") or "stage_failed"
                raise StepFailed(code if code in REASONS else "stage_failed", (err or {}).get("message") or "staging failed: " + out[-300:],
                                 "downloaded", {"stage_output_tail": out[-300:]})
            self.finish("downloaded", source="fetched or copied by the stage unit")
        else:
            self.finish("downloaded", source="staged earlier")
        self.begin("staged")
        # The unprivileged account that staged the release could swap the file between two reads. Verify a private,
        # root-only copy that is read exactly once, and take the manifest from that same copy.
        try:
            artifact, sig = self.snapshot_artifact(artifact)
            info = ocw_trust.verify_release(artifact, sig, trust, installed, expect_sha256=req["sha256"], expect_version=ver)
        except ocw_trust.TrustError as exc:
            self._quarantine(os.path.join(c.artifacts, f"ocw-{ver}.tar.gz"))
            raise StepFailed(exc.code if exc.code in REASONS else "bad_release", str(exc), "staged")
        manifest = info["manifest"]
        self.st["manifest"] = {k: manifest.get(k) for k in ("version", "min_upgrade_from", "migrations",
                                                         "downtime_estimate_seconds", "nginx_template_changed", "expected_schema_version",
                                                         "migration_time_estimate_seconds", "nginx_change_required", "requires_install_sh") if k in manifest}
        self.st["downtime_estimate_seconds"] = manifest.get("downtime_estimate_seconds") or 60
        self.st["signed_by"] = info["key_id"]
        self.st["sha256"] = info["sha256"]
        self._adoption = (info["adoption"], info["candidate_keys"])
        root = self.take_staged(ver)
        # The tree is now under releases/ (a directory only root can write): take it away from the staging account
        # FIRST (the stage unit has exited), then hash it. Nobody but root can change, replace or move a file or a
        # directory entry between the check and the switch.
        self.host.chown_tree(root)
        self.check_tree(root, manifest)
        self.finish("staged", signed_by=info["key_id"], files_verified=len(manifest["files"]), adoption=info["adoption"])
        self.begin("preflight")
        self.preflight(req, artifact)
        self.finish("preflight", **self.st.get("preflight", {}))
        self.begin("backup")
        self.backup()
        b = self.st.get("backup") or {}
        self.finish("backup", **{k: b[k] for k in ("name", "size", "integrity") if k in b})
        self.audit("upgrade.started", {"version_from": installed, "version_to": ver, "trigger_kind": req.get("trigger_kind", "request"),
                                       "backup": (self.st.get("backup") or {}).get("name"),
                                       "schema_before": self.st.get("schema_before"),
                                       "chain_heads_recorded": len(self.st.get("chain_heads_before") or {}),
                                       "requested_by": req.get("actor")})

    def take_staged(self, ver):
        """Move staging/<ver> to releases/<ver> and return the new path. The rename comes FIRST: it pins whatever entry the
        staging account left, under a parent directory only root can write, so nothing it does afterwards can swap the
        tree that is about to be owned, hashed and switched to."""
        c = self.cfg
        src, dst = os.path.join(c.staging, ver), os.path.join(c.releases, ver)
        st = os.lstat(src) if os.path.lexists(src) else None
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise StepFailed("not_staged", "the staged release is missing or is not a directory", "staged")
        if os.path.lexists(dst):
            if ver in (link_version(c.current), link_version(c.previous)):
                raise StepFailed("internal_error", f"releases/{ver} is the current or previous release", "staged")
            shutil.rmtree(dst)  # root-owned leftover of an earlier attempt that failed after the rename
        os.rename(src, dst)
        after = os.lstat(dst)
        if not stat.S_ISDIR(after.st_mode):  # swapped for a link or file between the check and the rename: never follow it
            os.unlink(dst)
            raise StepFailed("not_staged", "the staged release is not a plain directory", "staged")
        if not os.path.isdir(os.path.join(dst, ".venv")):
            raise StepFailed("not_staged", "the staged release has no virtualenv", "staged")
        return dst

    def _trust(self):
        try:
            return ocw_trust.load_trust(self.cfg.trust_path)
        except ocw_trust.TrustError as exc:
            raise StepFailed(exc.code, str(exc), "staged")

    def snapshot_artifact(self, artifact):
        """Copy artifact + .minisig into a root-only directory (each opened once, links refused); returns the copies."""
        c = self.cfg
        os.makedirs(c.verified, exist_ok=True)
        os.chmod(c.verified, 0o700)
        out = []
        for src in (artifact, artifact + ".minisig"):
            dst = os.path.join(c.verified, os.path.basename(src))
            try:
                fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as exc:
                raise ocw_trust.TrustError("bad_artifact", f"cannot open {os.path.basename(src)}: {exc.strerror}")
            with os.fdopen(fd, "rb") as fin:
                if not stat.S_ISREG(os.fstat(fin.fileno()).st_mode):
                    raise ocw_trust.TrustError("bad_artifact", f"{os.path.basename(src)} is not a regular file")
                with open(dst, "wb") as fout:
                    shutil.copyfileobj(fin, fout, 1 << 20)
                    fout.flush()
                    os.fsync(fout.fileno())
            os.chmod(dst, 0o600)
            out.append(dst)
        return out[0], out[1]

    def _quarantine(self, artifact):
        for p in (artifact, artifact + ".minisig"):
            try:
                os.replace(p, p + ".rejected")
            except OSError:
                pass

    def preflight(self, req, artifact):
        c = self.cfg
        db = c.db_path()
        snap = self.host.db_tool(["snapshot", db])
        if not snap.get("ok"):
            raise StepFailed("backup_failed", "cannot read the archive: " + str(snap.get("error")), "preflight")
        tar_size = os.path.getsize(artifact)
        need_opt = 3 * tar_size + 100 * 1024 * 1024
        need_data = 3 * (snap.get("size") or 0) + 100 * 1024 * 1024
        free_opt, free_data = self.host.free_bytes(c.opt), self.host.free_bytes(c.data)
        if self.fault("disk_full"):
            free_opt = free_data = 0
        if free_opt < need_opt or free_data < need_data:
            raise StepFailed("disk_space", f"not enough free disk space (code volume {free_opt // 2**20} MB free, needs {need_opt // 2**20}; "
                                           f"data volume {free_data // 2**20} MB free, needs {need_data // 2**20})", "preflight",
                             {"free_opt": free_opt, "free_data": free_data, "need_opt": need_opt, "need_data": need_data})
        waited = 0
        limit = 0 if c.fast else 600
        while snap.get("sync_running"):
            if waited >= limit:
                raise StepFailed("sync_in_progress", "an archive sync is running; the upgrade waited 10 minutes and did not start", "preflight")
            self.host.sleep(5)
            waited += 5
            snap = self.host.db_tool(["snapshot", db])
        if self.st["manifest"].get("nginx_template_changed"):
            self.nginx_prepare()
        self.st["schema_before"] = snap.get("schema_version")
        self.st["chain_heads_before"] = snap.get("chain_heads") or {}
        self.st["preflight"] = {"free_opt_mb": free_opt // 2**20, "free_data_mb": free_data // 2**20, "sync_waited_s": waited,
                                "nginx_template_changed": bool(self.st["manifest"].get("nginx_template_changed"))}
        # baseline for "not worse than before"
        status, body = self.host.http_get(c.backend_port, "/healthz")
        self.st["baseline"] = {"healthz": _healthz_status(body) if status == 200 else None}

    def backup(self):
        c = self.cfg
        db = c.db_path()
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.host.now()))
        ver = self.st["version_to"]
        for d in (c.work, c.backups):
            os.makedirs(d, exist_ok=True)
        os.chmod(c.backups, 0o700)
        if self.uid is not None and os.geteuid() == 0:
            os.lchown(c.work, self.uid, self.gid)
        os.chmod(c.work, 0o700)
        name = f"audit_store-pre-{ver}-{ts}.db"
        n = 1
        while os.path.exists(os.path.join(c.backups, name)):  # two attempts in one second (never in practice) must not clash
            n += 1
            name = f"audit_store-pre-{ver}-{ts}-{n}.db"
        work_file = os.path.join(c.work, name)
        if self.fault("disk_full_backup"):
            raise StepFailed("disk_space", "the disk filled up while copying the archive", "backup")
        res = self.host.db_tool(["backup", db, work_file])
        if not res.get("ok"):
            try:
                os.unlink(work_file)
            except OSError:
                pass
            code = "disk_space" if res.get("enospc") else "backup_failed"
            raise StepFailed(code, "the archive backup failed: " + str(res.get("error") or res.get("integrity_check")), "backup")
        record = {"name": name, "exists": res.get("exists", False), "integrity": res.get("integrity_check", "n/a"), "size": 0}
        if res.get("exists"):
            dest = os.path.join(c.backups, name)
            # The work directory belongs to the application account: copy from a file descriptor opened without following
            # links (never rename a path the application could have swapped), into a fresh root-only file.
            try:
                fd = os.open(work_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as exc:
                raise StepFailed("backup_failed", f"cannot open the backup copy: {exc.strerror}", "backup")
            with os.fdopen(fd, "rb") as fin:
                st = os.fstat(fin.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise StepFailed("backup_failed", "the backup copy is not a plain file", "backup")
                try:
                    out_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(out_fd, "wb") as fout:
                        shutil.copyfileobj(fin, fout, 1 << 20)
                        fout.flush()
                        os.fsync(fout.fileno())
                except OSError as exc:
                    raise StepFailed("disk_space" if exc.errno == errno.ENOSPC else "backup_failed", f"cannot write the backup: {exc.strerror}", "backup")
            try:
                os.unlink(work_file)
            except OSError:
                pass
            try:  # immutable: no -shm/-wal is created next to the root-only copy
                chk = sqlite3.connect(f"file:{dest}?immutable=1", uri=True)
                try:
                    verdict = chk.execute("PRAGMA integrity_check").fetchone()[0]
                finally:
                    chk.close()
            except sqlite3.Error as exc:
                verdict = f"unreadable: {exc}"
            if verdict != "ok":
                os.unlink(dest)
                raise StepFailed("backup_failed", "the root-only backup copy failed its integrity check: " + str(verdict)[:120], "backup")
            record["size"] = os.path.getsize(dest)
            record["path"] = dest
        for src, label in ((c.audit_log, "audit_log"), (os.path.join(c.data, "access_control.json"), "access_control")):
            if os.path.exists(src):
                ext = ".jsonl" if label == "audit_log" else ".json"
                dst = os.path.join(c.backups, f"{label}-pre-{ver}-{ts}{ext}")
                try:
                    safe_copy(src, dst)
                except OSError as exc:
                    if exc.errno == errno.ENOSPC:
                        raise StepFailed("disk_space", "the disk filled up while copying files", "backup")
                    raise StepFailed("backup_failed", f"cannot copy {label}: {exc.strerror}", "backup")
        self.st["backup"] = record

    # --- nginx -------------------------------------------------------------------------------------
    def _nginx_skip(self, why, step="preflight"):
        """The server's nginx site cannot take this release's template. Unless the manifest says the new site is required,
        that is not a reason to refuse the upgrade: leave nginx alone, say so in the journal and the audit log."""
        self._nginx_baked = self._nginx_live = None
        if (self.st.get("manifest") or {}).get("nginx_change_required"):
            raise StepFailed("nginx_invalid", why, step)
        log("WARN", f"nginx left unchanged: {why}")
        self.audit("upgrade.step", {"step": "nginx_skipped", "detail": why[:300]})

    def nginx_prepare(self):
        """Bake the release's template with this server's values. A missing or differently laid out site is skipped with a
        warning (the maintenance page then simply does not show), unless the manifest says the change is required."""
        import nginx_bake
        c = self.cfg
        self._nginx_baked = self._nginx_live = None
        template = os.path.join(c.releases, self.st["version_to"], "server", "nginx-opa-secrets-wizard.conf")
        if os.path.islink(c.nginx_site) or (os.path.exists(c.nginx_site) and not os.path.isfile(c.nginx_site)):
            return self._nginx_skip(f"{c.nginx_site} is a link or not a regular file: not reading or replacing it")
        if not os.path.exists(c.nginx_site):
            return self._nginx_skip(f"there is no nginx site at {c.nginx_site}")
        try:
            with open(c.nginx_site, encoding="utf-8") as fh:
                live = fh.read()
            with open(template, encoding="utf-8") as fh:
                tpl = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            return self._nginx_skip(f"cannot read the nginx files: {getattr(exc, 'strerror', None) or exc}")
        baked, problems = nginx_bake.bake(live, tpl)
        if problems:
            return self._nginx_skip("the nginx site cannot take this release's template: " + "; ".join(problems))
        self._nginx_baked = baked
        self._nginx_live = live

    def nginx_apply(self):
        c = self.cfg
        baked, live = getattr(self, "_nginx_baked", None), getattr(self, "_nginx_live", None)
        if baked is None or baked == live:
            return False
        # root-only directory: the site file holds the proxy secret, and `work/` belongs to the application account
        os.makedirs(c.verified, exist_ok=True)
        os.chmod(c.verified, 0o700)
        backup = os.path.join(c.verified, "nginx-site.backup")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(live)
        self.st["nginx_backup"] = backup
        self._write_site(baked)
        rc, out = self.host.nginx_test()
        if rc != 0:
            if not self.nginx_restore():
                # `nginx -t` fails on the ORIGINAL site too: the test cannot run here (or nginx was already broken), so it
                # says nothing about this release. Not the release's fault: no version is marked failed.
                f = StepFailed("internal_error", "`nginx -t` fails on the original site as well, so it cannot judge this release: " + out[-300:],
                               "restarting")
                f.no_blame = True
                raise f
            raise StepFailed("nginx_invalid", "the new nginx configuration failed `nginx -t`: " + out[-300:], "restarting")
        if not self.host.nginx_reload():
            self.nginx_restore()
            raise StepFailed("nginx_invalid", "nginx could not reload the new configuration", "restarting")
        self.st["nginx_applied"] = True
        self.persist()
        return True

    def _write_site(self, text):
        site = self.cfg.nginx_site
        mode = stat.S_IMODE(os.stat(site).st_mode) if os.path.exists(site) else 0o640
        tmp = site + ".ocw-tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        try:
            st = os.stat(site)
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, PermissionError):
            pass
        os.replace(tmp, site)

    def nginx_restore(self):
        backup = self.st.get("nginx_backup")
        if not backup or not os.path.exists(backup):
            return False
        with open(backup, encoding="utf-8") as fh:
            self._write_site(fh.read())
        rc, _out = self.host.nginx_test()
        if rc == 0:
            self.host.nginx_reload()
        else:
            log("CRIT", "the restored nginx configuration failed `nginx -t`; fix it by hand (the copy is in " + backup + ")")
        self.st["nginx_applied"] = False
        return rc == 0

    # --- switching, restarting ---------------------------------------------------------------------
    def switch_to(self, version, set_previous=None):
        c = self.cfg
        if set_previous:
            self.host.switch_symlink(c.previous, os.path.join("releases", set_previous))
        self.host.switch_symlink(c.current, os.path.join("releases", version))

    def restart_all(self, label):
        self._pids_before = {u: self.host.unit_prop(u, "MainPID") for u in self.units()}
        failed = []
        for u in self.units():
            ok, out = self.host.restart(u)
            if not ok:
                failed.append(f"{u}: {out.strip()[-200:]}")
        if failed:
            raise StepFailed("restart_failed", "a service did not restart: " + "; ".join(failed), "restarting")

    # --- health -----------------------------------------------------------------------------------
    def wait_for(self, fn, seconds, every=1):
        """Poll fn() until it returns a truthy (ok, detail); returns the last result."""
        deadline = self.host.now() + (0 if self.cfg.fast else seconds)
        last = (False, "no answer")
        while True:
            last = fn()
            if last[0] or self.host.now() >= deadline:
                return last
            self.host.sleep(every)

    def run_health(self, expect_version, rollback=False):
        c = self.cfg
        results = []
        units = self.units()
        gates = [u for u in units if u.startswith("opa-auth-gate")]
        manifest = self.st.get("manifest") or {}
        old_pid = (getattr(self, "_pids_before", {}) or {}).get(c.backend_service, "0")

        def unit_active():
            def now_state():
                bad = [u for u in units if self.host.unit_prop(u, "ActiveState") != "active"]
                return (not bad, "not active: " + ", ".join(bad) if bad else "")
            ok, d = self.wait_for(now_state, 30)
            if not ok:
                return False, d
            self.host.sleep(0 if c.fast else 6)
            bad = [f"{u} (NRestarts {self.host.unit_prop(u, 'NRestarts')})" for u in units
                   if self.host.unit_prop(u, "NRestarts") not in ("0", "") or self.host.unit_prop(u, "ActiveState") != "active"]
            return (not bad, "restarted by systemd: " + ", ".join(bad) if bad else f"{len(units)} units active, 0 restarts")

        def version():
            budget = 60 + int(manifest.get("migration_time_estimate_seconds") or 0)

            def probe():
                s, body = self.host.http_get(c.backend_port, "/api/version")
                v = _json_field(body, "version") if s == 200 else None
                pid = self.host.unit_prop(c.backend_service, "MainPID")
                if v == expect_version and pid not in ("0", "") and pid != old_pid:
                    return True, f"/api/version = {v} from a new process (pid {pid})"
                return False, f"/api/version answered {v!r}, pid {pid} (old {old_pid})"
            return self.wait_for(probe, budget)

        def healthz():
            s, body = self.host.http_get(c.backend_port, "/healthz")
            cur = _healthz_status(body) if s == 200 else None
            base = (self.st.get("baseline") or {}).get("healthz")
            if self.fault("health_fail") and not rollback:
                return False, 'injected fault: /healthz reported "degraded: injected"'
            if cur is None:
                return False, "/healthz did not answer"
            if cur != "ok" and base == "ok":
                return False, f"/healthz reported {cur!r}; the baseline before the upgrade was 'ok'"
            return True, f"/healthz {cur} (baseline {base})"

        def gate_401():
            def probe():
                bad = []
                for g in gates:
                    s, _b = self.host.http_get(self.host.gate_port(g), "/verify")
                    if s != 401:
                        bad.append(f"{g} answered {s}")
                return (not bad, "; ".join(bad) if bad else f"{len(gates)} gate(s) answer 401")
            return self.wait_for(probe, 20)

        def snap():
            return self.host.db_tool(["snapshot", c.db_path()])

        def quick_check():
            s = snap()
            return (s.get("ok") and s.get("quick_check") == "ok", f"quick_check {s.get('quick_check') or s.get('error')}")

        def schema():
            s = snap()
            after, before = s.get("schema_version"), self.st.get("schema_before")
            self.st["schema_after"] = after
            want = manifest.get("expected_schema_version")
            if not s.get("ok") or after is None:
                return False, "cannot read the schema version"
            if not rollback and want is not None and after != want:
                return False, f"schema_version is {after}, the release expects {want}"
            if before is not None and after < before:
                return False, f"schema_version went down ({before} -> {after})"
            return True, f"schema_version {after} (before {before})"

        def chain():
            s = self.host.db_tool(["snapshot", c.db_path(), self.st.get("started_at") or ""])
            before = self.st.get("chain_heads_before") or {}
            after = s.get("chain_heads") or {}
            self.st["chain_heads_after"] = after if not rollback else self.st.get("chain_heads_after")
            lost = [e for e in before if e not in after]
            if lost:
                return False, f"{len(lost)} environment chain head(s) disappeared"
            changed = [e for e, h in before.items() if after.get(e) != h]
            if not changed:
                return True, f"chain heads unchanged for {len(before)} environment(s)"
            if s.get("sync_after"):
                return True, f"{len(changed)} head(s) advanced: a sync ran after the upgrade began (not lost)"
            return False, f"{len(changed)} chain head(s) changed although no sync ran"

        def smoke():
            secret = self.cfg.env_values().get("NGINX_PROXY_SECRET")
            if not secret:
                return True, "skipped: no proxy secret (local mode)"
            s, _b = self.host.http_get(c.backend_port, "/api/environments",
                                       {"X-Nginx-Proxy-Secret": secret, "X-Auth-Sub": "ocw-updater-health-probe"})
            return s == 200, f"GET /api/environments answered {s}"

        fns = {"unit_active": unit_active, "version": version, "healthz": healthz, "gate_401": gate_401, "quick_check": quick_check,
               "schema_version": schema, "chain_heads": chain, "smoke_read": smoke}
        for name in HEALTH_CHECKS:
            try:
                ok, detail = fns[name]()
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"check crashed: {type(exc).__name__}"
            results.append({"id": name, "ok": bool(ok), "detail": detail})
            if not ok:
                break
        return all(r["ok"] for r in results) and len(results) == len(HEALTH_CHECKS), results

    # --- the whole apply ------------------------------------------------------------------------------
    def apply(self, req):
        c = self.cfg
        _cid[0] = req.get("correlation_id")
        try:
            self.validate_request(req, True)
        except StepFailed as f:
            reject(self, str(req.get("correlation_id", "upg-00000000")), f.code, str(f))
            return "rejected"
        self.st = {"schema": 1, "correlation_id": req["correlation_id"], "action": "apply", "version_from": installed_version(c),
                   "version_to": req["version"], "step": None, "steps_done": [], "started_at": iso(self.host.now()), "result": None,
                   "reason_code": None, "bundle": None, "action_id": req.get("action_id"), "requested_by": req.get("actor"),
                   "activator_version": ACTIVATOR_VERSION}
        self.persist()
        try:
            self.prepare(req)
        except StepFailed as f:
            return self.fail_before_switch(f)
        except (OSError, ocw_host.HostError) as exc:
            code = "disk_space" if getattr(exc, "errno", None) == errno.ENOSPC else "internal_error"
            return self.fail_before_switch(StepFailed(code, f"{type(exc).__name__}: {getattr(exc, 'strerror', None) or exc}", self.st.get("step")))
        ver = req["version"]
        old = installed_version(c)
        old_link = link_version(c.current) or old
        try:
            self.begin("switching")
            self.page("upgrading", "switching")
            self.switch_to(ver, set_previous=old_link)
            self.st["switched"] = True
            self.persist()
            if self.fault("after_switch"):
                raise Killed("after_switch")
            self.finish("switching", current=ver, previous=old_link)
            self.step_restart_and_check(ver)
        except StepFailed as f:
            return self.rollback_after(f)
        except Killed:
            raise
        except Exception as exc:  # noqa: BLE001
            return self.rollback_after(StepFailed("internal_error", f"{type(exc).__name__}: {exc}", self.st.get("step")))
        return self.complete(req)

    def step_restart_and_check(self, ver):
        self.begin("restarting")
        self.page("upgrading", "restarting")
        before = self.st.get("schema_before")
        self.restart_all("upgrade")
        if self.fault("during_migration"):
            raise StepFailed("migration_failed", "injected fault: a migration failed during start-up", "restarting")
        if self.st["manifest"].get("nginx_template_changed") or self.st.get("nginx_pending"):
            self.nginx_apply()
        self.finish("restarting", units=self.units())
        self.begin("health_check")
        self.page("upgrading", "health_check")
        ok, results = self.run_health(ver)
        self.st["health"] = results
        after = self.st.get("schema_after")
        if after is not None and before is not None and after != before:
            self.audit("upgrade.migrated", {"schema_from": before, "schema_to": after,
                                            "migrations": [m for m in ((self.st.get("manifest") or {}).get("migrations") or [])
                                                           if before < m.get("version", 0) <= after]})
        passed = [r["id"] for r in results if r["ok"]]
        failed = next((r for r in results if not r["ok"]), None)
        self.audit("upgrade.health_check", {"result": "passed" if ok else f"failed at check {len(results)} of {len(HEALTH_CHECKS)} ({failed['id']})",
                                            "passed": passed, "failed": failed, "checks_total": len(HEALTH_CHECKS)})
        if not ok:
            raise StepFailed(HEALTH_REASON[failed["id"]], failed["detail"], "health_check", {"check": failed["id"]})
        self.finish("health_check", passed=len(passed), total=len(HEALTH_CHECKS))

    def complete(self, req):
        c = self.cfg
        self.begin("completed")
        ver = req["version"]
        self.page_off()
        notes = {}
        try:
            adoption, candidate = getattr(self, "_adoption", ("same", []))
            if adoption == "adopt":
                trust = ocw_trust.load_trust(c.trust_path)
                merged = ocw_trust.merge(trust, candidate)
                write_json_atomic(c.trust_path, merged, 0o644)
                self.audit("release_keys.updated", {"version": ver, "signed_by": self.st.get("signed_by"), "keys_after": len(merged["keys"])})
                notes["trust"] = "updated"
        except Exception as exc:  # noqa: BLE001
            log("WARN", f"trust list not updated: {type(exc).__name__}")
        try:
            notes["updater"] = self.self_update(ver)
        except Exception as exc:  # noqa: BLE001 - a finished upgrade is not undone by housekeeping
            log("WARN", f"self-update skipped: {type(exc).__name__}: {exc}")
            notes["updater"] = "kept (self-update failed)"
        try:
            notes["pruned"] = self.prune(ver)
        except OSError as exc:
            log("WARN", f"pruning old releases skipped: {exc.strerror}")
        f = self.failures()
        f["versions"].pop(ver, None)
        write_json_atomic(c.failures_path, f)
        secs = round(self.host.now() - self.t0, 1)
        self.st.update(result="completed", step="completed", seconds=secs)
        self.persist()
        self._history()
        self.audit("upgrade.completed", {"version_from": self.st["version_from"], "version_to": ver, "duration_seconds": secs,
                                         "schema_before": self.st.get("schema_before"), "schema_after": self.st.get("schema_after"),
                                         "backup": (self.st.get("backup") or {}).get("name"), "notes": notes})
        return "completed"

    def _history(self):
        line = {k: self.st.get(k) for k in ("correlation_id", "action", "version_from", "version_to", "result", "reason_code",
                                            "started_at", "updated_at", "action_id", "seconds")}
        line["backup"] = (self.st.get("backup") or {}).get("path")
        line["bundle"] = (self.st.get("bundle") or {}).get("name")
        fd = os.open(self.cfg.history_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # --- failure paths -----------------------------------------------------------------------------------
    def fail_before_switch(self, f):
        """Nothing was switched: leave the install exactly as it was."""
        self.st.update(result="failed", reason_code=f.code if f.code in REASONS else "internal_error", failed_step=f.step or self.st.get("step"),
                       error=str(f)[:500])
        self.st["failed_detail"] = f.detail
        self.page_off()
        self.persist()
        log("ERROR", f"upgrade refused or failed before switching: {f.code}: {f}")
        self.make_bundle()
        self._history()
        self.audit("upgrade.failed", {"version_from": self.st.get("version_from"), "version_to": self.st.get("version_to"),
                                      "step": self.st["failed_step"], "reason_code": self.st["reason_code"], "detail": str(f)[:300],
                                      "rollback": "not needed: nothing was switched", "bundle": self.st.get("bundle"),
                                      "schema_before": self.st.get("schema_before"), "schema_after": self.st.get("schema_after")})
        return "failed"

    def rollback_after(self, f):
        """A failure at or after the switch: ONE automatic code-only rollback."""
        self.st["failure"] = {"step": f.step or self.st.get("step"), "reason_code": f.code if f.code in REASONS else "internal_error",
                              "detail": str(f)[:500], "at": iso(self.host.now())}
        log("ERROR", f"upgrade failed at {self.st['failure']['step']}: {f.code}: {f}")
        try:
            return self.rollback(trigger="automatic", failure=f)
        except Killed:
            raise
        except Exception as exc:  # noqa: BLE001
            return self.needs_operator(f"rollback crashed: {type(exc).__name__}: {exc}")

    def rollback(self, trigger, failure=None):
        c = self.cfg
        target = link_version(c.previous)
        t_start = self.host.now()
        self.begin("rolling_back")
        self.page("rolling_back", "restarting")
        if not target or not os.path.isdir(os.path.join(c.releases, target)):
            return self.needs_operator("there is no previous release to switch back to")
        failed_ver = installed_version(c) if self.st.get("action") != "rollback" else self.st.get("version_from")
        if self.st.get("nginx_applied"):
            self.nginx_restore()
        self.switch_to(target)
        try:
            self.restart_all("rollback")
        except StepFailed as exc:
            return self.needs_operator(str(exc))
        ok, results = self.run_health(target, rollback=True)
        if self.fault("rollback_fail"):
            ok, results = False, results + [{"id": "injected", "ok": False, "detail": "injected fault: rollback health failed"}]
        self.st["rollback_health"] = results
        if not ok:
            bad = next((r for r in results if not r["ok"]), {"detail": "unknown"})
            return self.needs_operator("health checks failed after the rollback: " + bad["detail"])
        self.page_off()
        secs = round(self.host.now() - t_start, 1)
        self.st.update(result="rolled_back", step="rolled_back", rolled_back_to=target, rollback_seconds=secs,
                       reason_code=(self.st.get("failure") or {}).get("reason_code") if failure else "operator")
        self.persist()
        if failure is not None and self.st["version_to"] and not getattr(failure, "no_blame", False):
            self.record_failure(self.st["version_to"], self.st["reason_code"])
        self.make_bundle()
        self._history()
        self.audit("upgrade.rolled_back", {"version_from": failed_ver, "version_to": target, "trigger_kind": trigger,
                                           "health": f"{len(results)} of {len(HEALTH_CHECKS)} passed on {target}",
                                           "schema_kept": self.st.get("schema_after"), "duration_seconds": secs})
        if failure is not None:
            self.audit("upgrade.failed", {"version_from": self.st.get("version_from"), "version_to": self.st.get("version_to"),
                                          "step": self.st["failure"]["step"], "reason_code": self.st["reason_code"],
                                          "detail": self.st["failure"]["detail"][:300], "rollback": "automatic, completed",
                                          "bundle": self.st.get("bundle"), "schema_before": self.st.get("schema_before"),
                                          "schema_after": self.st.get("schema_after")})
        return "rolled_back"

    def needs_operator(self, why):
        self.st.update(result="failed_needs_operator", step="failed_needs_operator", operator_reason=why[:500],
                       reason_code="rollback_failed")
        self.page("needs_operator", "restarting")
        self.persist()
        log("CRIT", "UPGRADE FAILED AND COULD NOT BE ROLLED BACK AUTOMATICALLY. An operator must run `ocw-updater status`. " + why[:300])
        self.make_bundle()
        if self.st.get("version_to"):
            self.record_failure(self.st["version_to"], "rollback_failed")
        self._history()
        self.audit("upgrade.failed", {"version_from": self.st.get("version_from"), "version_to": self.st.get("version_to"),
                                      "step": (self.st.get("failure") or {}).get("step") or "rolling_back", "reason_code": "rollback_failed",
                                      "detail": why[:300], "rollback": "failed: operator needed", "bundle": self.st.get("bundle"),
                                      "original_failure": self.st.get("failure")})
        return "failed_needs_operator"

    # --- support bundle ---------------------------------------------------------------------------------------
    def make_bundle(self, include_hosts=False, correlation_id=None):
        c = self.cfg
        try:
            cid = correlation_id or self.st.get("correlation_id")
            secrets = [v for k, v in c.env_values().items() if ocw_bundle.SENSITIVE_NAME.search(k)]
            entries = audit_entries_for(c, cid) if cid else []
            red = ocw_bundle.Redactor(secret_values=secrets, include_hosts=include_hosts, env_names=ocw_bundle.collect_env_names(entries))
            since = self.st.get("started_at")
            texts = {}
            names = list(dict.fromkeys(self.units() + ["ocw-upgrade"]))
            for u in names:
                texts[f"journal-{u}.txt"] = self.host.journal(u, 500, since)
                texts[f"status-{u}.txt"] = self.host.status_text(u)
            texts["journal-ocw-stage.txt"] = self.host.journal("ocw-stage@*", 500, since)
            rc, out = self.host.nginx_test()
            texts["nginx-test.txt"] = f"exit {rc}\n{out}"
            summary = self._summary()
            frm, to = self.st.get("version_from") or "unknown", self.st.get("version_to") or "unknown"
            stem = f"ocw-support-{frm}-to-{to}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(self.host.now()))}"
            info = ocw_bundle.build(c.bundles, stem, summary, texts, entries, red, now=self.host.now(), gid=self.gid)
            self.st["bundle"] = {"name": info["name"], "size": info["size"], "sha256": info["sha256"], "include_hosts": include_hosts}
            self.persist()
            self.audit("upgrade.bundle_created", {"bundle": self.st["bundle"], "redaction": info["redaction"]})
            return info
        except Exception as exc:  # noqa: BLE001 - a bundle problem must never hide the real failure
            log("ERROR", f"could not build the support bundle: {type(exc).__name__}: {exc}")
            self.st["bundle_error"] = f"{type(exc).__name__}"
            return None

    def _summary(self):
        c = self.cfg
        rc, ver = self.host.run(["systemctl", "--version"], 10)
        ver_to = str(self.st.get("version_to"))
        staged = (read_json(os.path.join(c.releases, ver_to, ".staged")) or read_json(os.path.join(c.staging, ver_to, ".staged")) or {})
        s = {k: self.st.get(k) for k in ("correlation_id", "action", "version_from", "version_to", "result", "reason_code", "failure",
                                         "failed_step", "error", "started_at", "updated_at", "seconds", "rollback_seconds",
                                         "steps_done", "health", "rollback_health", "schema_before", "schema_after", "manifest",
                                         "baseline", "signed_by", "sha256", "operator_reason", "preflight")}
        heads_b, heads_a = self.st.get("chain_heads_before") or {}, self.st.get("chain_heads_after") or {}
        s["chain_heads"] = {"environments_before": len(heads_b), "environments_after": len(heads_a),
                            "unchanged": sorted(e for e in heads_b if heads_a.get(e) == heads_b[e]),
                            "changed": sorted(e for e in heads_b if e in heads_a and heads_a[e] != heads_b[e])}
        s["system"] = {"os": platform.platform(), "python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version,
                       "systemd": ver.splitlines()[0] if rc == 0 and ver else "unknown", "activator": ACTIVATOR_VERSION}
        try:
            s["free_mb"] = {"opt": self.host.free_bytes(c.opt) // 2**20, "data": self.host.free_bytes(c.data) // 2**20}
        except OSError:
            pass
        s["pip_freeze"] = staged.get("pip_freeze")
        s["stage"] = {k: staged.get(k) for k in ("staged_at", "key_id", "pip_freeze_sha256")}
        s["history"] = self._history_lines()[-10:]
        return s

    # --- finishing touches --------------------------------------------------------------------------------------
    def self_update(self, ver):
        """Copy the verified release's root-owned updater files into a NEW directory <updater>/lib/<id>, self-test it there, then
        flip <updater>/current to it atomically (the launcher at <updater>/ocw_activate.py follows that link). The previous
        directory is kept; older ones are removed."""
        c = self.cfg
        src_root = os.path.join(c.releases, ver, "server", "updater", "root")
        nb = os.path.join(c.releases, ver, "server", "nginx_bake.py")
        if not os.path.isdir(src_root):
            return "release has no updater files"
        files = {f: os.path.join(src_root, f) for f in os.listdir(src_root) if f.endswith(".py") and f != "ocw_launcher.py"}
        if "ocw_activate.py" not in files:
            return "release has no updater files"
        if os.path.exists(nb):
            files["nginx_bake.py"] = nb
        lib = os.path.join(c.updater_dir, "lib")
        os.makedirs(lib, exist_ok=True)
        new_id, n = f"v{ver}", 1
        while os.path.exists(os.path.join(lib, new_id)):
            n += 1
            new_id = f"v{ver}-{n}"
        tmp = os.path.join(lib, f".{new_id}.tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, mode=0o755)
        for name, path in files.items():
            safe_copy(path, os.path.join(tmp, name), 0o755 if name == "ocw_activate.py" else 0o644)
        rc, out = self.host.run([sys.executable, "-I", "-B", os.path.join(tmp, "ocw_activate.py"), "selftest"], 60)
        if rc != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            log("WARN", "the new updater failed its self-test; keeping the current one: " + out[-200:])
            return "kept (self-test of the new one failed)"
        os.replace(tmp, os.path.join(lib, new_id))
        self.host.switch_symlink(os.path.join(c.updater_dir, "current"), os.path.join("lib", new_id))
        keep = {new_id, os.path.basename(os.readlink(os.path.join(c.updater_dir, "current")))}
        olds = sorted((d for d in os.listdir(lib) if not d.startswith(".") and d not in keep), key=lambda d: os.lstat(os.path.join(lib, d)).st_mtime)
        for d in olds[:-1]:  # the previous generation stays
            shutil.rmtree(os.path.join(lib, d), ignore_errors=True)
        return "updated"

    def prune(self, keep_ver):
        """Keep current, previous and the one newest other release; remove older release directories (and any staging
        directory of a version that is no longer newer than the one just installed)."""
        c = self.cfg
        try:
            for d in os.listdir(c.staging):
                if _VER.match(d) and ocw_trust.version_tuple(d) <= ocw_trust.version_tuple(keep_ver):
                    shutil.rmtree(os.path.join(c.staging, d), ignore_errors=True)
        except OSError:
            pass
        keep = {keep_ver, link_version(c.previous), link_version(c.current)}
        others = sorted((d for d in os.listdir(c.releases) if _VER.match(d) and d not in keep), key=ocw_trust.version_tuple, reverse=True)
        removed = []
        for d in others[1:]:
            shutil.rmtree(os.path.join(c.releases, d), ignore_errors=True)
            removed.append(d)
        return removed

    # --- resume after a crash / power loss ------------------------------------------------------------------------------
    def resume(self):
        c = self.cfg
        st = read_json(c.state_path)
        if not st or st.get("result") is not None or not st.get("step"):
            return None
        self.st = st
        _cid[0] = st.get("correlation_id")
        self.t0 = parse_iso(st.get("started_at")) or self.host.now()
        step = st["step"]
        log("WARN", f"resuming an interrupted {st.get('action')} (was at step {step})")
        self.audit("upgrade.step", {"step": "resume", "was_at": step})
        ver_to, ver_from = st.get("version_to"), st.get("version_from")
        if st.get("action") == "restore":
            return self._resume_restore()
        if st.get("action") == "rollback":  # an operator's rollback: finish it, and do not blame any version
            return self.rollback("operator", failure=None)
        if step == "rolling_back" or st.get("failure"):
            code = (st.get("failure") or {}).get("reason_code", "interrupted")
            return self.rollback_after(StepFailed(code, "interrupted; finishing the rollback", step))
        switched = link_version(c.current) == ver_to and ver_from != ver_to
        if step in ("validated", "downloaded", "staged", "preflight", "backup") and not switched:
            return self.fail_before_switch(StepFailed("interrupted", f"the updater was interrupted at {step}; nothing was switched", step))
        if step == "switching" and not switched:
            return self.fail_before_switch(StepFailed("interrupted", "interrupted before the switch happened", step))
        # switched (or later): check the new release; roll back if it does not pass
        self.page("upgrading", "restarting")
        try:
            self.st.setdefault("manifest", {})
            self.step_restart_and_check(ver_to)
        except StepFailed as f:
            return self.rollback_after(f)
        req = {"version": ver_to, "correlation_id": st["correlation_id"]}
        self._adoption = ("same", [])
        return self.complete(req)

    def _resume_restore(self):
        """A restore was interrupted. The one dangerous moment is between moving the live database aside and putting the
        restored copy in place (the application would start on NO database): put the moved-aside one back first."""
        db = self.cfg.db_path()
        aside = self.st.get("restore_aside")
        if aside and not os.path.exists(db) and os.path.exists(aside):
            for ext in ("", "-wal", "-shm"):
                if os.path.exists(aside + ext):
                    os.replace(aside + ext, db + ext)
            log("WARN", "restore interrupted: the previous database was put back")
        self.page_off()
        self.st.update(result="failed", reason_code="interrupted")
        self.persist()
        self._history()
        self.audit("upgrade.failed", {"reason_code": "interrupted", "detail": "the restore was interrupted; check `ocw-updater status`"})
        for u in self.units():
            self.host.systemctl("start", u)
        return "failed"

    # --- operator actions --------------------------------------------------------------------------------------------------
    def rollback_action(self, actor):
        c = self.cfg
        cid = "upg-" + uuid.uuid4().hex[:8]
        _cid[0] = cid
        cur, prev = installed_version(c), link_version(c.previous)
        self.st = {"schema": 1, "correlation_id": cid, "action": "rollback", "version_from": cur, "version_to": prev, "step": "rolling_back",
                   "steps_done": [], "started_at": iso(self.host.now()), "result": None, "bundle": None, "requested_by": actor,
                   "manifest": {}, "schema_before": None, "activator_version": ACTIVATOR_VERSION}
        snap = self.host.db_tool(["snapshot", c.db_path()])
        self.st["schema_before"] = snap.get("schema_version")
        self.st["chain_heads_before"] = snap.get("chain_heads") or {}
        self.st["baseline"] = {"healthz": None}
        self.persist()
        self.audit("upgrade.step", {"step": "rollback_requested", "requested_by": actor}, actor_email=actor)
        return self.rollback("operator", failure=None)

    def restore_action(self, actor):
        c = self.cfg
        hist = [h for h in self._history_lines() if h.get("backup") and h.get("action") == "apply"]
        if not hist or not os.path.exists(hist[-1]["backup"]):
            raise StepFailed("backup_failed", "there is no pre-upgrade backup to restore")
        backup = hist[-1]["backup"]
        cid = "upg-" + uuid.uuid4().hex[:8]
        _cid[0] = cid
        db = c.db_path()
        self.st = {"schema": 1, "correlation_id": cid, "action": "restore", "version_from": installed_version(c), "version_to": installed_version(c),
                   "step": "restoring", "steps_done": [], "started_at": iso(self.host.now()), "result": None, "bundle": None,
                   "requested_by": actor, "manifest": {}, "activator_version": ACTIVATOR_VERSION, "restoring_from": os.path.basename(backup)}
        self.persist()
        self.audit("upgrade.restore_requested", {"backup": os.path.basename(backup), "requested_by": actor}, actor_email=actor)
        os.makedirs(c.work, exist_ok=True)
        if self.uid is not None and os.geteuid() == 0:
            os.lchown(c.work, self.uid, self.gid)
        os.chmod(c.work, 0o700)
        staged_copy = os.path.join(c.work, "restore-copy.db")
        # the backup is root-only; hand a copy to the application user's tool
        safe_copy(backup, staged_copy, 0o600, self.uid, self.gid)
        beside = db + ".restoring"
        res = self.host.db_tool(["restore", staged_copy, beside])
        try:
            os.unlink(staged_copy)
        except OSError:
            pass
        if not res.get("ok"):
            raise StepFailed("backup_failed", "the backup copy failed its integrity check: " + str(res.get("error") or res.get("integrity_check")))
        self.page("upgrading", "restarting")
        self.host.stop(c.backend_service)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.host.now()))
        aside = f"{db}.pre-restore-{stamp}"
        self.st["restore_aside"] = aside  # recorded BEFORE anything moves, so a power loss can undo the half-done move
        self.persist()
        if os.path.exists(db):
            os.replace(db, aside)
        for ext in ("-wal", "-shm"):
            if os.path.exists(db + ext):
                os.replace(db + ext, aside + ext)
        self.kill_point("restore_swap")  # test fault: the worst moment to lose power
        os.replace(beside, db)
        if self.uid is not None and os.geteuid() == 0:
            os.lchown(db, self.uid, self.gid)
        self.restart_all("restore")
        ok, results = self.run_health(installed_version(c), rollback=True)
        self.page_off()
        self.st.update(result="completed" if ok else "failed_needs_operator", step="restored", health=results, moved_aside=os.path.basename(aside))
        self.persist()
        self._history()
        self.audit("upgrade.restored" if ok else "upgrade.failed",
                   {"backup": os.path.basename(backup), "moved_aside": os.path.basename(aside), "health_ok": ok, "reason_code": None if ok else "health_unit"})
        return "restored" if ok else "failed_needs_operator"


# --- helpers used above -------------------------------------------------------------------------------------


def _json_field(body, key):
    try:
        v = json.loads(body)
        return v.get(key) if isinstance(v, dict) else None
    except ValueError:
        return None


def _healthz_status(body):
    return _json_field(body, "status")


# --- the dispatcher (what the systemd units run) -------------------------------------------------------------------------


def take_lock(cfg):
    os.makedirs(cfg.upgrade, exist_ok=True)
    fd = os.open(cfg.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def read_request_file(cfg, path, app_uid):
    """The request file is advisory: opened without following links, must be a small plain file
    owned by root or the application user and not writable by anyone else."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > REQUEST_MAX_BYTES:
            raise StepFailed("request_invalid", "not a small regular file")
        if st.st_uid not in (0, app_uid, os.geteuid()) or (st.st_mode & 0o022):
            raise StepFailed("request_invalid", "wrong owner or permissions")
        raw = os.read(fd, REQUEST_MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise StepFailed("request_invalid", "not valid JSON")
    return req


def process_directory(up, directory, due_only=False):
    """Handle every request file in `directory`, oldest first. Returns the results."""
    cfg = up.cfg
    results = []
    try:
        names = sorted(os.listdir(directory), key=lambda n: os.lstat(os.path.join(directory, n)).st_mtime)
    except OSError:
        return results
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            req = read_request_file(cfg, path, up.uid)
        except (StepFailed, OSError) as exc:
            reject(up, name[:-5], getattr(exc, "code", "request_invalid"), str(exc), name)
            _discard(path, cfg)
            continue
        if due_only and req.get("not_before"):
            nb = parse_iso(req["not_before"])
            if nb is None or nb > up.host.now():
                continue
        _discard(path, cfg)
        req["_file"] = name
        up.t0 = up.host.now()
        results.append(up.apply(req))
        up.st = None
    return results


def _discard(path, cfg):
    os.makedirs(cfg.done, exist_ok=True)
    try:
        os.replace(path, os.path.join(cfg.done, os.path.basename(path) + "." + uuid.uuid4().hex[:6]))
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass


def reject(up, cid, code, message, name=""):
    cfg = up.cfg
    if not _CID.match(cid):
        cid = "upg-00000000"
    os.makedirs(cfg.rejections, exist_ok=True)
    write_json_atomic(os.path.join(cfg.rejections, f"{cid}.json"), {"correlation_id": cid, "code": code if code in REASONS else "request_invalid",
                                                                    "message": message[:300], "at": iso(up.host.now())})
    up.st = {"correlation_id": cid}
    up.audit("upgrade.request_rejected", {"reason_code": code, "detail": message[:200], "file": name[:80]})
    up.st = None


def ingest_revocations(up):
    """Revocation files left by the application (upgrade/revocations/), by the staging step (<artifacts>/revocations/) or
    by an operator: each is re-verified here against root's own trust list (standby signature, serial order). The
    carrier is untrusted; a file that does not verify is ignored."""
    cfg = up.cfg
    found = []
    for d in (os.path.join(cfg.upgrade, "revocations"), os.path.join(cfg.artifacts, "revocations")):
        try:
            names = [n for n in os.listdir(d) if n.endswith(".json")]
        except OSError:
            continue
        for n in names:
            try:
                fd = os.open(os.path.join(d, n), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    raw = os.read(fd, ocw_trust.MAX_JSON + 1)
                finally:
                    os.close(fd)
            except OSError:
                continue
            serial = ocw_trust.revocation_serial(raw)
            if serial is not None:
                found.append((serial, n, raw))
    for _serial, n, raw in sorted(found, key=lambda t: (t[0], t[1])):
        try:
            trust = ocw_trust.load_trust(cfg.trust_path)
            new, det = ocw_trust.apply_revocation(trust, raw)
        except ocw_trust.TrustError as exc:
            if exc.code != "replayed":
                log("WARN", f"revocation file {n} ignored: {exc.code}: {exc}")
            continue
        write_json_atomic(cfg.trust_path, new, 0o644)
        up.st = {"correlation_id": None}
        up.audit("release_keys.revocation_applied", {**det, "source": "revocation file re-verified by the updater"})
        up.st = None


def run(cfg, host):
    """What `ocw-upgrade.service` runs: resume, then requests, then due schedules. Silent when idle."""
    fd = take_lock(cfg)
    if fd is None:
        return 0
    try:
        up = Updater(cfg, host)
        for d in (cfg.requests, cfg.schedule):
            os.makedirs(d, exist_ok=True)
        ingest_revocations(up)
        up.resume()
        up.st = None
        process_directory(up, cfg.requests)
        process_directory(up, cfg.schedule, due_only=True)
        return 0
    finally:
        os.close(fd)


def selftest():
    import ocw_crypto  # noqa: F401
    import ocw_cli  # noqa: F401
    assert ocw_trust.version_tuple("1.2.3") == (1, 2, 3)
    print("selftest ok")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "_dbtool":
        return ocw_host.dbtool_main(argv[1:])
    if argv and argv[0] == "selftest":
        return selftest()
    cfg = Cfg()
    uid, gid = cfg.ids()
    harmless = argv[:1] == ["cli"] and argv[1:2] in (["status"], ["trust"], ["help"])
    if os.geteuid() == 0 and uid is None and argv and not harmless:
        # Without the application account, the database tool would run as root and could leave root-owned -wal/-shm files.
        print(f"{os.path.join(cfg.updater_dir, 'config.json')} has no valid app_user: re-run server/install.sh", file=sys.stderr)
        return 2
    host = ocw_host.SystemHost(uid, gid)
    try:
        if not argv or argv[0] in ("run", "resume"):
            if os.geteuid() != 0 and not cfg.fast:
                print("ocw_activate.py must run as root (it is started by ocw-upgrade.service)", file=sys.stderr)
                return 2
            return run(cfg, host)
        import ocw_cli
        if argv[0] == "cli":
            return ocw_cli.main(argv[1:], cfg, host)
    except Killed as k:
        log("CRIT", f"simulated kill at {k}")
        os._exit(137)
    print("usage: ocw_activate.py run | cli <command> | selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
