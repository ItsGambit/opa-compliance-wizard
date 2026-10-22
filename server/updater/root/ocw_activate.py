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

ACTIVATOR_VERSION = "5.51.0"
STEP_ORDER = ["validated", "downloaded", "staged", "preflight", "backup", "switching", "restarting", "health_check", "completed"]
STEP_LABEL = {"validated": "Received and validated", "downloaded": "Downloaded", "staged": "Verified and staged",
              "preflight": "Preflight", "backup": "Backup", "switching": "Switching", "restarting": "Restarting",
              "health_check": "Health checks", "completed": "Completed"}
HEALTH_CHECKS = ["unit_active", "version", "healthz", "gate_401", "quick_check", "schema_version", "chain_heads", "smoke_read"]
REASONS = {"request_invalid", "request_replayed", "request_stale", "signature_invalid", "key_unknown", "version_not_newer",
           "hash_mismatch", "name_mismatch", "version_mismatch", "too_old", "disk_space", "sync_in_progress", "pip_failed",
           "stage_failed", "not_staged", "tree_mismatch", "release_files_mismatch", "environment_unexpected", "backup_failed", "migration_failed", "nginx_invalid", "restart_failed",
           "health_unit", "health_version", "health_healthz", "health_gate", "health_quick_check", "health_schema",
           "health_chain", "health_smoke", "rollback_failed", "interrupted", "failed_before", "too_many_failures",
           "version_failed_before", "in_flight", "bad_release", "bad_artifact", "revoked_key", "retired_key", "wrong_role",
           "no_key_pinned", "keys_changed", "unknown_alg", "no_trust", "bad_trust", "internal_error", "needs_install_sh",
           "confirm_required", "rollback_unavailable", "no_backup", "action_unsupported", "prune_refused", "target_changed",
           "needs_operator"}
# --- what every reason says (5.51.0) ------------------------------------------------------------------------------------
# One source for the CLI and the web page: the activator writes reason_text (what happened), changed (whether anything on the
# server changed) and next_step (what to do) into the run's state, so the two cannot drift. Every message says all three, in plain
# words, without alarm for conditions that are not a security finding. `tree_mismatch` stays so state and history written by an
# earlier release still validate; new runs use release_files_mismatch or environment_unexpected.
CHANGED_NONE = "Nothing was changed on the server."
CHANGED_BACK = "The previous release was put back and is running."
CHANGED_UNKNOWN = "Unknown: an operator must check the server."
ISSUE_STEP = "open an issue on the project's GitHub page"
BUNDLE_STEP = "Download the support bundle (Audit Log, the upgrade.failed entry) and attach it to an issue on the project's GitHub page."
INSTALL_STEP = "From the unpacked release folder, run `sudo server/install.sh --refresh-updater`, then try again."
STATUS_STEP = "`sudo ocw-updater status`"
# The commands next_step may name (the test checks each against the real command line parser).
NEXT_STEP_COMMANDS = ("sudo ocw-updater status", "sudo ocw-updater clear-failure", "sudo ocw-updater trust list",
                      "sudo server/install.sh --refresh-updater", "sudo server/install.sh")
_HEALTH_WHAT = {"health_unit": "the application service was not running", "health_version": "the service reported a different version than expected",
                "health_healthz": "the web page did not load", "health_gate": "the sign-in gate did not answer as expected",
                "health_quick_check": "the database did not open or failed its integrity check",
                "health_schema": "the database schema version was not the expected one",
                "health_chain": "the evidence chain heads were not as expected", "health_smoke": "a read of the archive failed"}
REASON_TEXT = {
    "request_invalid": ("The updater did not accept the request (a field was missing or malformed).",
                        "Reload the Updates page and request again. If it repeats, run " + STATUS_STEP + " on the server."),
    "request_replayed": ("This approval was already used.", "Request the upgrade again from the Updates page."),
    "request_stale": ("The request was older than 24 hours.", "Request the upgrade again from the Updates page."),
    "signature_invalid": ("The release file's signature did not verify.",
                          "The updater refused it. Download the release again; if it fails again, do not install that file and " + ISSUE_STEP + "."),
    "key_unknown": ("The release was signed by a key this server does not trust.",
                    "Check the release notes for a key change. `sudo ocw-updater trust list` shows the keys this server trusts."),
    "revoked_key": ("The release was signed by a key that is no longer accepted.", "Use a release signed by the current key."),
    "retired_key": ("The release was signed by a key that is no longer accepted.", "Use a release signed by the current key."),
    "wrong_role": ("The release was signed by a key that may not sign releases (a standby key).", "Use a release signed by the primary key."),
    "no_key_pinned": ("This server has no usable trust file for release keys.", INSTALL_STEP),
    "no_trust": ("This server has no usable trust file for release keys.", INSTALL_STEP),
    "bad_trust": ("This server has no usable trust file for release keys.", INSTALL_STEP),
    "keys_changed": ("The trusted keys changed while the request was being checked.", "Request the upgrade again."),
    "unknown_alg": ("The signature uses an algorithm this updater does not know.", "Refresh the updater, then try again. " + INSTALL_STEP),
    "version_not_newer": ("This server already runs the same or a newer version.", "Nothing to do."),
    "version_mismatch": ("The file's contents do not match the version it was requested as.", "Download the release again."),
    "name_mismatch": ("The file's contents do not match the name it was requested as.", "Download the release again."),
    "hash_mismatch": ("The downloaded file does not match its signed hash.",
                      "Try again. If it happens again, something between this server and GitHub is changing the file (often a proxy or a broken mirror). "
                      "Do not install it; " + ISSUE_STEP + "."),
    "too_old": ("This release cannot be installed over the installed version.",
                "Upgrade to an intermediate release first; the release notes say which."),
    "bad_release": ("The release archive is not in the expected shape.", "Download the release again."),
    "bad_artifact": ("The release archive is not in the expected shape.", "Download the release again."),
    "disk_space": ("There was not enough free disk space.", "Free some space (" + STATUS_STEP + " lists the backups directory), then request again."),
    "sync_in_progress": ("A refresh was still running after 10 minutes.", "Try again when it finishes (the Overview shows its progress)."),
    "pip_failed": ("The Python packages could not be installed.", "It is usually a network or Python version problem. " + BUNDLE_STEP),
    "stage_failed": ("The release could not be prepared for installation.", "Try again. If it repeats: " + BUNDLE_STEP),
    "not_staged": ("The release could not be prepared for installation.", "Try again. If it repeats: " + BUNDLE_STEP),
    "release_files_mismatch": ("The prepared files do not match the signed release (a file differs, is missing, or is extra).",
                               "Download the release again. If it happens again, " + ISSUE_STEP + "."),
    "environment_unexpected": ("The release's Python environment has something the updater does not expect (for example a link to a file "
                               "outside the release, or a file with group or world write permission).",
                               "This is usually a Python layout the updater has not seen. " + INSTALL_STEP + " If it repeats: " + BUNDLE_STEP),
    "tree_mismatch": ("The prepared files or environment did not pass the updater's checks (older release).",
                      "Download the release again. If it repeats: " + BUNDLE_STEP),
    "backup_failed": ("The pre-upgrade copy of the archive could not be made or is not usable.",
                      "Check that there is free disk space and that the archive can be read (the Overview's Verify the chain checks the evidence chain), then request again."),
    "no_backup": ("The pre-upgrade copy of the archive could not be made or is not usable.",
                  "Check that there is free disk space and that the archive can be read (the Overview's Verify the chain checks the evidence chain), then request again."),
    "migration_failed": ("A database schema migration failed.", "The archive is as it was before the upgrade. " + BUNDLE_STEP),
    "nginx_invalid": ("The release's nginx configuration did not validate.", BUNDLE_STEP),
    "restart_failed": ("The services did not restart.",
                       "Run " + STATUS_STEP + ". If the previous release is not running, an operator must act on the server."),
    "rollback_failed": ("The automatic rollback failed.",
                        "On the server, run " + STATUS_STEP + " and follow its instructions. The previous code is still on disk."),
    "needs_operator": ("The automatic rollback failed.",
                       "On the server, run " + STATUS_STEP + " and follow its instructions. The previous code is still on disk."),
    "interrupted": ("The updater was interrupted (power loss or a kill) before finishing.", "Run " + STATUS_STEP + " on the server."),
    "failed_before": ("This version failed before and is blocked.", "On the server, run `sudo ocw-updater clear-failure`, then request again."),
    "version_failed_before": ("This version failed before and is blocked.", "On the server, run `sudo ocw-updater clear-failure`, then request again."),
    "too_many_failures": ("Upgrades are paused after two failed attempts.", "Open an issue on the project's GitHub page with the support bundle."),
    "in_flight": ("Another upgrade was in progress.", "Wait for it to finish."),
    "target_changed": ("The release or the backup changed after the page was loaded.", "Reload the page and check the release again."),
    "confirm_required": ("The action needs a confirmation, or is only available on the server.", "Run it from the server's command line as the message says."),
    "action_unsupported": ("The action needs a confirmation, or is only available on the server.", "Run it from the server's command line as the message says."),
    "prune_refused": ("The action needs a confirmation, or is only available on the server.", "Run it from the server's command line as the message says."),
    "needs_install_sh": ("This change needs the installer.", "From the unpacked release folder, run `sudo server/install.sh` as the release notes say."),
    "rollback_unavailable": ("There is no previous release to go back to, or the 24-hour rollback window has passed.",
                             "Nothing to do. Request the release you want instead."),
    "internal_error": ("The updater hit an unexpected error.", BUNDLE_STEP + " It names the correlation id."),
}
for _code, _what in _HEALTH_WHAT.items():
    REASON_TEXT[_code] = (f"A health check failed after the restart: {_what}.",
                          "The previous release is running. " + BUNDLE_STEP + " It includes the failed check's detail.")


def describe_reason(code, result=None, detail=None, installed=None):
    """(reason_text, changed, next_step) for a reason code. `changed` follows what the run actually did (result), not the code:
    a refusal before the switch changed nothing, an automatic rollback put the previous release back, and only a rollback that
    failed (or a restore that was interrupted) leaves the server in a state an operator has to check."""
    if code == "operator":  # a rollback an operator asked for (not a failure)
        return "The previous release was put back at an operator's request.", CHANGED_BACK, "Nothing to do. The previous release is running."
    text, step = REASON_TEXT.get(code) or REASON_TEXT["internal_error"]
    if code == "disk_space" and isinstance(detail, str) and detail.startswith("not enough free disk space ("):
        text = "There was not enough free disk space " + detail[len("not enough free disk space "):] + "."
    elif code == "version_not_newer" and installed:
        text = f"This server already runs {installed} (the same or a newer version)."
    if code in ("rollback_failed", "needs_operator") or result == "failed_needs_operator":
        changed = CHANGED_UNKNOWN
    elif result == "rolled_back":
        changed = CHANGED_BACK
    else:
        changed = CHANGED_NONE
    return text, changed, step

# What the web application may ask for through the request inbox (5.48.0). Each is advisory: the application has checked the
# administrator's step-up approval, root re-validates everything here. Scheduling stays in the application (it never sends a time).
APP_ACTIONS = ("apply", "rollback", "restore", "clear_failure", "bundle")
_COMMON_FIELDS = {"schema", "action", "correlation_id", "requested_at", "action_id", "origin", "actor", "trigger_kind", "_file"}
_ACTION_FIELDS = {"apply": {"version", "sha256", "not_before", "entered"}, "rollback": {"confirm"}, "restore": {"confirm", "backup"},
                  "clear_failure": set(), "bundle": {"include_hosts", "for_correlation_id"}}
_STR_LIMITS = {"actor": 120, "trigger_kind": 80, "entered": 80, "origin": 8, "confirm": 16, "not_before": 24, "requested_at": 24}
ROLLBACK_WINDOW = 24 * 3600
QUIESCE_SECONDS = 600
ACTIONS_READ_BYTES = 4 * 1024 * 1024
ACTIONS_ROTATE_BYTES = 1024 * 1024
ACTIONS_KEEP_LINES = 20000
BUNDLES_KEEP = 10                # on-demand support bundles kept (newest)
BUNDLE_MIN_GAP = 300             # seconds before the same run's bundle may be built again
DONE_KEEP = 200                  # requests-done/ and rejections/ entries kept (newest)
_BACKUP_NAME = re.compile(r"^audit_store-pre-[0-9A-Za-z._-]{1,80}\.db$")
HEALTH_REASON = {"unit_active": "health_unit", "version": "health_version", "healthz": "health_healthz", "gate_401": "health_gate",
                 "quick_check": "health_quick_check", "schema_version": "health_schema", "chain_heads": "health_chain",
                 "smoke_read": "health_smoke"}
REQUEST_MAX_AGE = 24 * 3600
REQUEST_MAX_BYTES = 8192
_CID = re.compile(r"^(upg|sched)-[0-9a-f]{8}$")
_VER = re.compile(r"^\d+\.\d+\.\d+$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ACTION_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_ACTOR = re.compile(r"[^\x20-\x7e]")


class Killed(BaseException):
    """A simulated kill (fault injection): not catchable by `except Exception`."""


class StepFailed(Exception):
    def __init__(self, code, message, step=None, detail=None):
        super().__init__(message)
        self.code, self.step, self.detail = code, step, detail or {}


# --- configuration ---------------------------------------------------------------------


# A root-owned file whose presence allows the OCW_* test and path overrides for a process running as root. Nothing in a
# normal install creates it; the VM test does (and removes it).
TEST_MARKER = "/etc/ocw-updater-test-mode"


def env_overrides_allowed():
    """Root honours test-mode and path overrides from the environment only when the marker exists, is a plain file owned by
    root and not writable by others. A non-root process (the unit tests) is never privileged, so it may use them freely."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return True
    try:
        st = os.lstat(TEST_MARKER)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


class Cfg:
    def __init__(self, environ=None):
        if environ is None:
            environ = dict(os.environ)
            if not env_overrides_allowed():  # only where the wrapper and the units put them: the install location
                environ = {k: v for k, v in environ.items() if k in ("OCW_OPT_DIR", "OCW_DATA_DIR")}
        env = environ
        self.opt = env.get("OCW_OPT_DIR", "/opt/opa-compliance-wizard")
        self.data = env.get("OCW_DATA_DIR", "/var/lib/opa-compliance-wizard")
        self.updater_dir = env.get("OCW_UPDATER_DIR", os.path.join(self.opt, "updater"))
        self.env_file = env.get("OCW_ENV_FILE", "")
        c = {}
        try:
            with open(os.path.join(self.updater_dir, "config.json"), encoding="utf-8") as fh:
                c = json.load(fh)
        except (OSError, ValueError):
            pass
        self.env_file = self.env_file or c.get("env_file") or "/etc/opa-compliance-wizard.env"
        self.app_user = c.get("app_user", "")
        self.app_group = c.get("app_group", "")
        self.stage_user = c.get("stage_user", "ocw-updater")
        self.backend_service = c.get("backend_service", "opa-compliance-wizard")
        self.gate_service = c.get("gate_service", "opa-auth-gate")
        self.nginx_site = c.get("nginx_site", "/etc/nginx/sites-available/opa-secrets-wizard")
        self.backend_port = int(c.get("backend_port", 8766))
        v = c.get("install_sh_version")
        self.install_sh_version = v if isinstance(v, str) else ""   # written by server/install.sh: the release it was last run from
        sites = c.get("second_gate_sites_dir")
        self.second_gate_sites_dir = sites if isinstance(sites, str) and sites.startswith("/") else "/etc/nginx/sites-available"
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
        self.artifacts = env.get("OCW_ARTIFACTS_DIR") or c.get("artifacts_dir") or "/var/lib/ocw-updater/artifacts"
        self.verified = os.path.join(self.upgrade, "verified")
        self.state_path = os.path.join(self.upgrade, "state.json")
        self.history_path = os.path.join(self.upgrade, "history.jsonl")
        self.failures_path = os.path.join(self.upgrade, "failures.json")
        self.bundles = os.path.join(self.upgrade, "bundles")
        self.backups = os.path.join(self.upgrade, "backups")
        self.schedule = os.path.join(self.upgrade, "schedule")
        self.rejections = os.path.join(self.upgrade, "rejections")
        self.actions_path = os.path.join(self.upgrade, "actions.jsonl")          # approval ids already used by the non-apply kinds
        self.quiesce_path = os.path.join(self.upgrade, "quiesce.json")           # "start no new sync until ..." (read by the application)
        self.backups_status = os.path.join(self.upgrade, "backups-status.json")  # names, sizes, dates, integrity (no paths)
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


def read_tail(path, max_bytes):
    """The last `max_bytes` of a plain file (whole lines only: a cut first line is dropped), opened safely."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size <= max_bytes:
            return fh.read()
        fh.seek(size - max_bytes)
        data = fh.read()
    cut = data.find(b"\n")
    return data[cut + 1:] if cut >= 0 else b""


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
            lock_path = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".lock")
            nb = getattr(os, "O_NONBLOCK", 0)
            try:  # created by us: hand it to the application account (a root-owned lock would shut the application out of it)
                lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow | nb, 0o600)
                if ids[0] is not None and os.geteuid() == 0:
                    os.fchown(lock_fd, ids[0], ids[1])
            except FileExistsError:
                lock_fd = os.open(lock_path, os.O_RDWR | nofollow | nb)
                if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                    os.close(lock_fd)
                    raise OSError(errno.EINVAL, "not a regular file", lock_path)
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
            fd = open_regular(path, write=True)
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
        with os.fdopen(open_regular(cfg.audit_log), "rb") as fh:
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
        if step in STEP_ORDER[STEP_ORDER.index("preflight"):-1] or step == "rolling_back":
            self.quiesce()  # ten minutes from every step: the file covers the whole run
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
        self.unquiesce()
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
        if not isinstance(req, dict) or req.get("schema") != 1 or req.get("action") not in APP_ACTIONS:
            raise StepFailed("request_invalid", "unsupported request")
        action = req["action"]
        # closed set of fields, plain types, bounded lengths: anything else is refused, never ignored
        if set(req) - _COMMON_FIELDS - _ACTION_FIELDS[action]:
            raise StepFailed("request_invalid", "unexpected field in the request")
        for key, limit in _STR_LIMITS.items():
            v = req.get(key)
            if v is not None and (not isinstance(v, str) or len(v) > limit):
                raise StepFailed("request_invalid", f"{key} must be text of at most {limit} characters")
        if req.get("origin") not in (None, "cli", "app"):
            raise StepFailed("request_invalid", "bad origin")
        if not _CID.match(str(req.get("correlation_id", ""))):
            raise StepFailed("request_invalid", "bad correlation id")
        if action == "apply" and (not _VER.match(str(req.get("version", ""))) or not _SHA.match(str(req.get("sha256", "")))):
            raise StepFailed("request_invalid", "bad version or sha256")
        aid = req.get("action_id")
        if aid is not None and not _ACTION_ID.match(str(aid)):
            raise StepFailed("request_invalid", "bad action id")
        at = parse_iso(req.get("requested_at"))
        now = self.host.now()
        if at is None or at > now + 300 or now - at > REQUEST_MAX_AGE:
            raise StepFailed("request_stale", "the request is older than 24 hours or dated in the future")
        if aid and self.action_id_used(aid):
            raise StepFailed("request_replayed", "this approval was already used")
        if action != "apply":
            self.validate_other(req, action)
            return
        nb = req.get("not_before")
        if nb is not None and parse_iso(nb) is None:
            raise StepFailed("request_invalid", "bad not_before")
        if self.in_flight():
            raise StepFailed("in_flight", "another upgrade is in progress")
        last = read_json(self.cfg.state_path) or {}
        if last.get("result") == "failed_needs_operator":
            raise StepFailed("failed_before", "the last upgrade failed and could not be rolled back automatically; an operator must "
                                              "check `ocw-updater status`, fix it, then run `ocw-updater clear-failure`")
        f = self.failures()
        rec = f["versions"].get(req["version"])
        if rec and rec.get("count", 0) >= 1:
            raise StepFailed("version_failed_before", f"{req['version']} failed before ({rec.get('last_code')}); an operator must "
                                                      "run `ocw-updater clear-failure` first")
        if sum(v.get("count", 0) for v in f["versions"].values()) >= 2:
            raise StepFailed("too_many_failures", "two upgrades have failed; contact the maintainers with the support bundle, then clear-failure")

    def validate_other(self, req, action):
        """Field rules of the kinds other than apply (the common ones were checked already)."""
        if action == "rollback" and req.get("confirm") != "ROLLBACK":
            raise StepFailed("confirm_required", "a rollback request must carry the typed confirmation ROLLBACK")
        if action == "restore":
            if req.get("confirm") != "RESTORE":
                raise StepFailed("confirm_required", "a restore request must carry the typed confirmation RESTORE")
            if not isinstance(req.get("backup"), str) or not _BACKUP_NAME.match(req["backup"]):
                raise StepFailed("request_invalid", "a restore request must name the backup copy it was approved for")
            if self.in_flight():
                raise StepFailed("in_flight", "another upgrade is in progress")
        if action == "clear_failure" and (read_json(self.cfg.state_path) or {}).get("result") == "failed_needs_operator":
            raise StepFailed("needs_operator", "the last upgrade could not be rolled back automatically; an operator must run "
                                               "`sudo ocw-updater clear-failure` on the server")
        if action == "bundle":
            if not isinstance(req.get("include_hosts", False), bool):
                raise StepFailed("request_invalid", "include_hosts must be true or false")
            fc = req.get("for_correlation_id")
            if fc is not None and not _CID.match(str(fc)):
                raise StepFailed("request_invalid", "bad for_correlation_id")

    @staticmethod
    def validate_prune(req):
        """Field rules of `ocw-updater prune-backups` (a command-line operation only: the inbox does not take it)."""
        if req.get("confirm") != "PRUNE":
            raise StepFailed("confirm_required", "a backup clean-up request must carry the typed confirmation PRUNE")
        keep, names = req.get("keep_last"), req.get("names")
        if (keep is None) == (names is None):
            raise StepFailed("request_invalid", "send exactly one of keep_last and names")
        if keep is not None and (not isinstance(keep, int) or isinstance(keep, bool) or not 1 <= keep <= 50):
            raise StepFailed("request_invalid", "keep_last must be a whole number from 1 to 50")
        if names is not None and (not isinstance(names, list) or not 1 <= len(names) <= 50
                                  or not all(isinstance(n, str) and _BACKUP_NAME.match(n) for n in names)):
            raise StepFailed("request_invalid", "names must be 1 to 50 backup file names")

    def action_id_used(self, aid):
        for line in self._history_lines():
            if line.get("action_id") == aid:
                return True
        try:  # the newest part of the file: an id remembered last is never beyond the read
            return aid in read_tail(self.cfg.actions_path, ACTIONS_READ_BYTES).decode("utf-8", "replace").split()
        except OSError:
            return False

    def remember_action_id(self, aid):
        """Record a used approval id (root-owned directory; the file is opened without following links and must be a plain file).
        Lines are `<id> <epoch seconds>`; past a size the file is rewritten without the old ones."""
        if not aid:
            return
        fd = os.open(self.cfg.actions_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "not a regular file", self.cfg.actions_path)
            os.write(fd, f"{aid} {int(self.host.now())}\n".encode("ascii"))
            os.fsync(fd)
            size = os.fstat(fd).st_size
        finally:
            os.close(fd)
        if size > ACTIONS_ROTATE_BYTES:
            self._rotate_actions()

    def _rotate_actions(self):
        """Keep the ids remembered in the last two days (never more than ACTIONS_KEEP_LINES): a request older than a day is
        refused as stale anyway, so a forgotten id cannot be replayed."""
        try:
            lines = read_tail(self.cfg.actions_path, ACTIONS_READ_BYTES).decode("ascii", "replace").splitlines()
        except OSError:
            return
        cutoff = self.host.now() - 2 * 86400
        keep = []
        for ln in lines:
            parts = ln.split()
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= cutoff:
                keep.append(ln)
        keep = keep[-ACTIONS_KEEP_LINES:]
        tmp = self.cfg.actions_path + ".new"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write("".join(ln + "\n" for ln in keep))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.cfg.actions_path)
        except OSError as exc:
            log("WARN", f"could not rotate the approval ids file: {exc.strerror}")

    def _history_lines(self):
        out = []
        try:
            for line in read_tail(self.cfg.history_path, 8 * 1024 * 1024).decode("utf-8", "replace").splitlines():
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
            if os.lstat(base).st_mode & 0o6022:
                raise StepFailed("environment_unexpected", f"{os.path.relpath(base, root)} is writable by others or has a setuid/setgid bit", "staged")
            for d in list(dirs):
                p = os.path.join(base, d)
                if os.path.islink(p):
                    raise StepFailed("environment_unexpected", f"{os.path.relpath(p, root)} is a link", "staged")
            for name in files:
                p = os.path.join(base, name)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise StepFailed("environment_unexpected", f"{rel} is not a plain single-link file", "staged")
                if st.st_mode & 0o6022:
                    raise StepFailed("environment_unexpected", f"{rel} is writable by others or has a setuid/setgid bit", "staged")
                if "__pycache__" in rel.split("/"):
                    os.unlink(p)
                    continue
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                if rel == "manifest.json":
                    continue
                if rel not in expected:
                    raise StepFailed("release_files_mismatch", f"{rel} is not part of the signed release", "staged")
                if expected[rel] != h.hexdigest():
                    raise StepFailed("release_files_mismatch", f"{rel} does not match the signed manifest", "staged")
                seen.add(rel)
        missing = sorted(set(expected) - seen)
        if missing:
            raise StepFailed("release_files_mismatch", f"{len(missing)} file(s) the manifest lists are missing (first: {missing[0]})", "staged")
        self.check_venv(root)

    _INTERPRETER_NAME = re.compile(r"python[0-9]*(\.[0-9]+)?t?")   # t: free-threaded builds (python3.14t)

    def _is_base_interpreter_link(self, root, rel, target):
        """A link in .venv/bin may leave the release only if it is the venv's base interpreter: whatever its own name
        (python, python3, python3.14, Python 3.14's \U0001d70bthon, ...) it must resolve to a regular, executable file named
        like a Python interpreter, located under /usr or in the base-interpreter directory the venv records in its
        pyvenv.cfg ("home"), so a Python installed in /opt, /usr/local or a framework build works too. "home" is written
        by the staging account, so this is a consistency check; the venv stays outside the signed manifest (a known
        limitation: whoever controls staging can already change what the application account runs)."""
        if not rel.startswith(".venv/bin/") or rel.count("/") != 2:
            return False
        if not self._INTERPRETER_NAME.fullmatch(os.path.basename(target)):
            return False
        try:
            st = os.stat(target)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            return False
        if target.startswith("/usr/"):
            return True
        # Otherwise it must be what one of the interpreters in pyvenv.cfg's "home" resolves to (home may itself hold
        # links, e.g. into a framework or a version directory).
        home = self._venv_home(root)
        if not home:
            return False
        try:
            names = os.listdir(home)
        except OSError:
            return False
        return any(self._INTERPRETER_NAME.fullmatch(n) and os.path.realpath(os.path.join(home, n)) == target for n in names)

    @staticmethod
    def _venv_home(root):
        """The real path of the "home" directory pyvenv.cfg names (the base interpreter's bin), or None."""
        try:
            fd = open_regular(os.path.join(root, ".venv", "pyvenv.cfg"))
            with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(16384)
        except OSError:
            return None
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "home" and value.strip().startswith("/"):
                return os.path.realpath(value.strip())
        return None

    def check_venv(self, root):
        """The virtualenv is not in the manifest (pip built it), but it is walked too: no link may resolve outside the release
        directory (except a link in bin/ to the base interpreter: see _is_base_interpreter_link), no hard links, no setuid/setgid/group- or
        world-writable entry, nothing but plain files, directories and links."""
        venv = os.path.join(root, ".venv")
        if os.path.islink(venv):
            raise StepFailed("environment_unexpected", ".venv is a link", "staged")
        real_root = os.path.realpath(root)
        for base, dirs, files in os.walk(venv, followlinks=False):
            for name in dirs + files:
                p = os.path.join(base, name)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    target = os.path.realpath(p)
                    inside = target == real_root or target.startswith(real_root + os.sep)
                    interpreter = self._is_base_interpreter_link(root, rel, target)
                    if not (inside or interpreter):
                        raise StepFailed("environment_unexpected", f"{rel} is a link that leaves the release directory", "staged")
                    continue
                if st.st_mode & 0o6022:
                    raise StepFailed("environment_unexpected", f"{rel} is writable by others or has a setuid/setgid bit", "staged")
                if stat.S_ISREG(st.st_mode):
                    if st.st_nlink != 1:
                        raise StepFailed("environment_unexpected", f"{rel} has more than one hard link", "staged")
                elif not stat.S_ISDIR(st.st_mode):
                    raise StepFailed("environment_unexpected", f"{rel} is not a plain file, directory or link", "staged")

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
                                                         "migration_time_estimate_seconds", "nginx_change_required", "requires_install_sh", "install_sh_min_version") if k in manifest}
        self.st["downtime_estimate_seconds"] = manifest.get("downtime_estimate_seconds") or 60
        self.check_install_sh(manifest, ver)
        self.st["signed_by"] = info["key_id"]
        self.st["sha256"] = info["sha256"]
        self._adoption = (info["adoption"], info["candidate_keys"])
        root = self.take_staged(ver)
        # The tree is now under releases/ (a directory only root can write): take it away from the staging account
        # FIRST (the stage unit has exited), then hash it. Nobody but root can change, replace or move a file or a
        # directory entry between the check and the switch.
        try:
            self.host.chown_tree(root)
        except ocw_host.HostError as exc:
            raise StepFailed("environment_unexpected", str(exc), "staged")
        self.check_tree(root, manifest)
        self.finish("staged", signed_by=info["key_id"], files_verified=len(manifest["files"]), adoption=info["adoption"])
        self.begin("preflight")
        self.preflight(req, artifact)
        self.finish("preflight", **self.st.get("preflight", {}))
        self.begin("backup")
        self.backup()
        b = self.st.get("backup") or {}
        self.finish("backup", **{k: b[k] for k in ("name", "size", "integrity") if k in b})
        try:
            self.publish_backups()
        except OSError as exc:
            log("WARN", f"could not publish the backups status: {exc.strerror}")
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
                fd = open_regular(src)
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

    def check_install_sh(self, manifest, ver):
        """The units, the ocw-updater command and server/install.sh are replaced only by install.sh, never by the updater.
        install.sh records in config.json the version of the release it was run from; a release that says its newest change
        to those files is in `install_sh_min_version` is refused only while that record is missing or older. A manifest
        without the field falls back to the boolean `requires_install_sh` (true: the release's own version is the minimum),
        so a release that only a 5.47.0 updater would have refused unconditionally can now be satisfied."""
        need = manifest.get("install_sh_min_version")
        if need is None:
            if not manifest.get("requires_install_sh"):
                return
            need = ver
        try:
            need_t = ocw_trust.version_tuple(need)
        except ocw_trust.TrustError:
            raise StepFailed("bad_release", f"the manifest's install_sh_min_version {str(need)[:40]!r} is not a version", "staged")
        have = self.cfg.install_sh_version
        try:
            have_t = ocw_trust.version_tuple(have) if have else None
        except ocw_trust.TrustError:
            have_t = None
        if have_t is not None and have_t >= need_t:
            return
        recorded = f"was last run from {have}" if have_t is not None else "has not recorded a version"
        raise StepFailed("needs_install_sh", f"{ver} needs the systemd units, the ocw-updater command or server/install.sh from release {need} or newer, "
                                             f"and install.sh {recorded} on this server. Unpack the release file for {ver} that you downloaded "
                                             "(not the copy in the staging directory) and run `sudo server/install.sh --refresh-updater` from "
                                             "that unpacked directory; it refreshes the units, the command and the updater, records the version "
                                             "and touches no data. Then apply this release again.", "staged")

    def check_second_gate_sites(self):
        """Read-only. The nginx site of an additional login gate (setup-second-gate.sh) must answer 403 on /api/upgrade, or an
        administrator of that org could reach this server's upgrade routes through its hostname. Neither this updater nor
        install.sh rewrites those sites (`install.sh --regenerate-second-sites` does); this only looks, warns and writes an
        audit entry. Returns the names of the sites found without the deny. Never raises, never changes anything."""
        found = []
        try:
            directory = self.cfg.second_gate_sites_dir
            main = os.path.basename(self.cfg.nginx_site)
            for name in sorted(os.listdir(directory)):
                if not name.startswith("opa-") or name == main:
                    continue
                try:
                    fd = open_regular(os.path.join(directory, name))
                    with os.fdopen(fd, "rb") as fh:
                        raw = fh.read(1 << 20)
                except OSError:
                    continue
                text = raw.decode("utf-8", "replace")
                if "# OPA auth gate '" not in text[:600]:
                    continue    # not a site setup-second-gate.sh generated
                active = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
                if not re.search(r"location\s+/api/upgrade\s*\{\s*return\s+403\s*;\s*\}", active):
                    found.append(name[:60])
        except OSError:
            return []
        if found:
            msg = ("the nginx site of an additional login gate does not deny /api/upgrade: " + ", ".join(found) +
                   ". Run `sudo server/install.sh --regenerate-second-sites` from the installed release.")
            log("WARN", msg)
            try:
                self.audit("upgrade.step", {"step": "second_gate_site_unprotected", "sites": found, "detail": msg[:300]})
            except OSError as exc:
                log("WARN", f"could not write the audit entry: {exc.strerror}")
        return found

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
            raise StepFailed("disk_space", f"not enough free disk space (code volume {free_opt // 2**20} MB free, needs {need_opt // 2**20} MB; "
                                           f"data volume {free_data // 2**20} MB free, needs {need_data // 2**20} MB)", "preflight",
                             {"free_opt": free_opt, "free_data": free_data, "need_opt": need_opt, "need_data": need_data})
        waited = 0
        limit = 0 if c.fast else 600
        self.quiesce()
        while snap.get("sync_running"):
            if waited >= limit:
                raise StepFailed("sync_in_progress", "an archive sync is running; the upgrade waited 10 minutes and did not start", "preflight")
            self.host.sleep(5)
            self.quiesce()
            waited += 5
            snap = self.host.db_tool(["snapshot", db])
        if self.st["manifest"].get("nginx_template_changed"):
            self.nginx_prepare()
        unprotected = self.check_second_gate_sites()
        self.st["schema_before"] = snap.get("schema_version")
        self.st["chain_heads_before"] = snap.get("chain_heads") or {}
        self.st["preflight"] = {"free_opt_mb": free_opt // 2**20, "free_data_mb": free_data // 2**20, "sync_waited_s": waited,
                                "nginx_template_changed": bool(self.st["manifest"].get("nginx_template_changed"))}
        if unprotected:
            self.st["preflight"]["second_gate_sites_without_upgrade_deny"] = unprotected
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
                fd = open_regular(work_file)
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
            if os.path.exists(self.cfg.quiesce_path):
                self.quiesce()

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
            self.remember_action_id(req.get("action_id"))
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
                                            "started_at", "updated_at", "action_id", "seconds", "reason_text", "changed", "next_step")}
        line["backup"] = (self.st.get("backup") or {}).get("path")
        line["bundle"] = (self.st.get("bundle") or {}).get("name")
        b = self.st.get("backup") or {}
        line["backup_size"], line["backup_integrity"] = b.get("size"), b.get("integrity")
        fd = os.open(self.cfg.history_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # --- failure paths -----------------------------------------------------------------------------------
    def say(self, code, detail=None):
        """Records what the run's outcome means in plain words (reason_text, changed, next_step) once result is set."""
        text, changed, step = describe_reason(code, self.st.get("result"), detail, self.st.get("version_from"))
        self.st.update(reason_text=text, changed=changed, next_step=step)

    def fail_before_switch(self, f):
        """Nothing was switched: leave the install exactly as it was."""
        self.st.update(result="failed", reason_code=f.code if f.code in REASONS else "internal_error", failed_step=f.step or self.st.get("step"),
                       error=str(f)[:500])
        self.say(self.st["reason_code"], str(f))
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
        self.say(self.st["reason_code"], (self.st.get("failure") or {}).get("detail"))
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
        self.say("rollback_failed")
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
    def make_bundle(self, include_hosts=False, correlation_id=None, record=True, touch=True):
        """Build a support bundle. `record` writes it into self.st["bundle"] and state.json: only ever for a state that was loaded
        from (or is) the run on disk. `touch` False keeps the state's updated_at (the 24-hour rollback window starts there)."""
        c = self.cfg
        try:
            cid = correlation_id or self.st.get("correlation_id")
            secrets = [v for k, v in c.env_values().items() if ocw_bundle.SENSITIVE_NAME.search(k)]
            entries = audit_entries_for(c, cid) if cid else []
            env_names = set(ocw_bundle.collect_env_names(entries))
            try:  # the tenant / environment names the archive holds, so the application's own log lines can be scrubbed of them
                env_names.update(self.host.db_tool(["snapshot", c.db_path()]).get("env_names") or [])
            except (OSError, ocw_host.HostError):
                pass
            red = ocw_bundle.Redactor(secret_values=secrets, include_hosts=include_hosts, env_names=env_names)
            since = self.st.get("started_at")
            texts = {}
            names = list(dict.fromkeys(self.units() + ["ocw-upgrade"]))
            for u in names:
                raw = self.host.journal(u, 500, since)
                # the updater's own journal is ours and stays whole; the application's is filtered (WARN and above, or this run)
                texts[f"journal-{u}.txt"] = raw if u == "ocw-upgrade" else ocw_bundle.filter_app_journal(raw, cid)
                texts[f"status-{u}.txt"] = self.host.status_text(u)
            texts["journal-ocw-stage.txt"] = self.host.journal("ocw-stage@*", 500, since)
            rc, out = self.host.nginx_test()
            texts["nginx-test.txt"] = f"exit {rc}\n{out}"
            summary = self._summary()
            frm, to = self.st.get("version_from") or "unknown", self.st.get("version_to") or "unknown"
            stem = f"ocw-support-{frm}-to-{to}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(self.host.now()))}"
            info = ocw_bundle.build(c.bundles, stem, summary, texts, entries, red, now=self.host.now(), gid=self.gid)
            made = {"name": info["name"], "size": info["size"], "sha256": info["sha256"], "include_hosts": include_hosts,
                    "at": iso(self.host.now())}
            if record:
                self.st["bundle"] = made
                if touch:
                    self.persist()
                else:
                    write_json_atomic(c.state_path, self.st)
            self.audit("upgrade.bundle_created", {"bundle": made, "redaction": info["redaction"]})
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
        s = {k: self.st.get(k) for k in ("correlation_id", "action", "version_from", "version_to", "result", "reason_code", "reason_text", "changed", "next_step", "failure",
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

    def trim_housekeeping(self):
        """Bound what a flood of requests can leave behind: on-demand support bundles, handled request files, rejection notes."""
        c = self.cfg
        for d, keep, pat in ((c.bundles, BUNDLES_KEEP, re.compile(r"^ocw-support-[0-9A-Za-z._-]+\.tar\.gz$")),
                             (c.done, DONE_KEEP, None), (c.rejections, DONE_KEEP, re.compile(r"^[A-Za-z0-9_-]+\.json$"))):
            try:
                rows = []
                for n in os.listdir(d):
                    if pat is not None and not pat.match(n):
                        continue
                    try:
                        st = os.lstat(os.path.join(d, n))
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode):
                        rows.append((st.st_mtime, n))
                rows.sort(reverse=True)
                for _m, n in rows[keep:]:
                    try:
                        os.unlink(os.path.join(d, n))
                    except OSError:
                        pass
            except OSError:
                continue

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

    # --- requests from the web application (5.48.0) --------------------------------------------------------------
    @staticmethod
    def clean_actor(value):
        """The requester as the application named them: advisory text for the audit trail, printable ASCII, bounded."""
        return _ACTOR.sub("?", str(value or ""))[:120] or "web application"

    def quiesce(self):
        """Tell the application to start no new sync for ten minutes: a root-owned file it reads before every sync start
        (nothing to call, nothing to authenticate). The preflight still waits for a running sync."""
        try:
            write_json_atomic(self.cfg.quiesce_path, {"until": iso(self.host.now() + QUIESCE_SECONDS), "correlation_id": _cid[0]})
        except OSError as exc:
            log("WARN", f"could not write the quiesce file: {exc.strerror}")

    def unquiesce(self):
        try:
            os.unlink(self.cfg.quiesce_path)
        except OSError:
            pass

    def rollback_allowed(self):
        """A previous release exists, and the last upgrade (a completed apply) finished under 24 hours ago. The command line is
        looser on purpose (an operator may roll back after a failed run); a request through the inbox is not."""
        c = self.cfg
        cur, prev = installed_version(c), link_version(c.previous)
        if not prev or prev == cur:
            raise StepFailed("rollback_unavailable", "there is no previous release to roll back to")
        st = read_json(c.state_path) or {}
        done = parse_iso(st.get("updated_at"))
        # fails closed: only a completed upgrade, finished less than 24 hours ago, opens the window (a state that says anything
        # else, or nothing, is not evidence that it is open)
        if st.get("result") != "completed" or st.get("action") != "apply" or done is None:
            raise StepFailed("rollback_unavailable", "rolling back is only offered for 24 hours after an upgrade completes")
        if self.host.now() - done > ROLLBACK_WINDOW:
            raise StepFailed("rollback_unavailable", "the 24-hour rollback window after the last upgrade has passed")
        if self.in_flight():
            raise StepFailed("in_flight", "another upgrade is in progress")

    def backup_files(self):
        """[(name, size, mtime)] of the pre-upgrade copies, oldest first. Plain files only, matched by name."""
        out = []
        try:
            names = os.listdir(self.cfg.backups)
        except OSError:
            return out
        for n in names:
            if not _BACKUP_NAME.match(n):
                continue
            try:
                st = os.lstat(os.path.join(self.cfg.backups, n))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                out.append((n, st.st_size, st.st_mtime))
        return sorted(out, key=lambda t: (t[2], t[0]))

    def publish_backups(self):
        """upgrade/backups-status.json: what the Updates page shows as 'Pre-upgrade backups'. Names, sizes, dates, the integrity
        result recorded when it was taken and the version it was taken before; no paths. The backup directory itself is root-only."""
        info = {}
        for h in self._history_lines():
            if h.get("backup"):
                info[os.path.basename(str(h["backup"]))] = h
        rows = []
        for n, size, mtime in self.backup_files():
            h = info.get(n) or {}
            rows.append({"name": n, "size": size, "taken_at": iso(mtime), "taken_before": h.get("version_to"),
                         "integrity": h.get("backup_integrity")})
        total = sum(r["size"] for r in rows)
        write_json_atomic(self.cfg.backups_status, {"schema": 1, "updated_at": iso(self.host.now()), "backups": rows, "total_bytes": total})

    def prune_backups(self, req, actor):
        """Delete pre-upgrade copies the administrator chose (explicit names, or everything but the newest N). The newest copy
        and the one the last upgrade took are never deleted: they are what `restore` needs."""
        files = self.backup_files()
        protected = {files[-1][0]} if files else set()
        for h in reversed(self._history_lines()):
            if h.get("action") == "apply" and h.get("backup"):
                protected.add(os.path.basename(str(h["backup"])))
                break
        have = {n for n, _s, _m in files}
        if req.get("names") is not None:
            chosen = list(dict.fromkeys(req["names"]))
            unknown = [n for n in chosen if n not in have]
            if unknown:
                raise StepFailed("prune_refused", f"{len(unknown)} of the named backups do not exist")
        else:
            chosen = [n for n, _s, _m in files[:-req["keep_last"]]] if len(files) > req["keep_last"] else []
        refused = [n for n in chosen if n in protected]
        if req.get("names") is not None and refused:
            raise StepFailed("prune_refused", "the newest backup and the one the last upgrade took cannot be deleted (restore needs them)")
        chosen = [n for n in chosen if n not in protected]
        freed = 0
        for n in chosen:
            path = os.path.join(self.cfg.backups, n)
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            freed += os.lstat(path).st_size
            os.unlink(path)
        self.publish_backups()
        self.audit("upgrade.backups_pruned", {"deleted": chosen, "bytes_freed": freed, "kept": len(have) - len(chosen), "requested_by": actor})
        return "backups_pruned"

    def app_action(self, req):
        """rollback / restore / clear_failure / bundle / prune_backups, asked for through the inbox. The application has checked the
        administrator's step-up approval and the typed confirmation; the validation and the checks here are root's own."""
        c = self.cfg
        cid = str(req.get("correlation_id", "upg-00000000"))
        _cid[0] = cid
        action = req.get("action")
        actor = self.clean_actor(req.get("actor"))
        try:
            self.validate_request(req, True)
            self.remember_action_id(req.get("action_id"))
            if action == "clear_failure":  # (validate_request refused it while the run is failed_needs_operator)
                f = self.failures()
                cleared = sorted(f["versions"])
                write_json_atomic(c.failures_path, {"versions": {}, "cleared_at": iso(self.host.now())})
                self.st = {"correlation_id": cid}
                self.audit("upgrade.clear_failure", {"cleared": cleared, "via": "web application", "requested_by": actor,
                                                     "actor_is": "the application's claim, not verified by the updater"}, actor_email=actor)
                self.st = None
                return "failure_cleared"
            if action == "bundle":
                st = read_json(c.state_path) or {}
                last = st.get("correlation_id")
                want = req.get("for_correlation_id") or last
                if not last or want != last:  # the state on disk is never replaced by one built for another run
                    raise StepFailed("request_invalid", "a support bundle can only be built for the last upgrade run")
                built = parse_iso((st.get("bundle") or {}).get("at"))
                if built is not None and 0 <= self.host.now() - built < BUNDLE_MIN_GAP:
                    raise StepFailed("request_invalid", "a support bundle was built a moment ago")
                self.st = dict(st)
                info = self.make_bundle(include_hosts=bool(req.get("include_hosts")), correlation_id=want, touch=False)
                if not info:
                    raise StepFailed("internal_error", "could not build the support bundle")
                return "bundle_created"
            if action == "rollback":
                self.rollback_allowed()
                return self.rollback_action(actor)
            if action == "restore":
                return self.restore_action(actor, expect_backup=req.get("backup"))
        except StepFailed as f:
            reject(self, cid, f.code, str(f))
            return "rejected"
        except (OSError, ocw_host.HostError) as exc:  # the request file is already gone: refuse it, never leave run() on it
            reject(self, cid, "internal_error", f"{type(exc).__name__}")
            return "rejected"
        return "rejected"

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
        text, _changed, step = describe_reason("interrupted")
        self.st.update(reason_text=text, changed=CHANGED_UNKNOWN, next_step=step)  # a restore that stopped half way: an operator must look
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
        self.audit("upgrade.step", {"step": "rollback_requested", "requested_by": actor, **self._claim(actor)}, actor_email=actor)
        return self.rollback("operator", failure=None)

    @staticmethod
    def _claim(actor):
        """Audit details that say where the requester's name came from: the web application's claim, not checked here."""
        return {"actor_is": "the application's claim, not verified by the updater"} if actor and actor != "web application" else {}

    def restore_action(self, actor, expect_backup=None):
        """Put the pre-upgrade copy of the last upgrade back. A request through the inbox names the copy the administrator was
        shown (`expect_backup`) and is refused if the copy this would restore is another one, or if anything is in flight."""
        c = self.cfg
        if expect_backup is not None and self.in_flight():
            raise StepFailed("in_flight", "another upgrade is in progress")
        hist = [h for h in self._history_lines() if h.get("backup") and h.get("action") == "apply"]
        if not hist or not os.path.exists(hist[-1]["backup"]):
            raise StepFailed("backup_failed", "there is no pre-upgrade backup to restore")
        backup = hist[-1]["backup"]
        if expect_backup is not None and os.path.basename(backup) != expect_backup:
            raise StepFailed("target_changed", "the backup copy this would restore is not the one that was approved; reload the page")
        cid = "upg-" + uuid.uuid4().hex[:8]
        _cid[0] = cid
        db = c.db_path()
        self.st = {"schema": 1, "correlation_id": cid, "action": "restore", "version_from": installed_version(c), "version_to": installed_version(c),
                   "step": "restoring", "steps_done": [], "started_at": iso(self.host.now()), "result": None, "bundle": None,
                   "requested_by": actor, "manifest": {}, "activator_version": ACTIVATOR_VERSION, "restoring_from": os.path.basename(backup)}
        self.persist()
        self.audit("upgrade.restore_requested", {"backup": os.path.basename(backup), "requested_by": actor, **self._claim(actor)}, actor_email=actor)
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
        self.quiesce()
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
        self.quiesce()
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
        path = os.path.join(directory, name)
        if not name.endswith(".json"):
            # anything we will not process leaves the directory: a stray entry would otherwise keep the path unit
            # (DirectoryNotEmpty=) starting this service in a loop
            log("WARN", f"unexpected entry {name[:60]!r} in {os.path.basename(os.path.dirname(directory)) or directory}: moved aside")
            _discard(path, cfg)
            continue
        try:
            req = read_request_file(cfg, path, up.uid)
        except (StepFailed, OSError) as exc:
            reject(up, name[:-5], getattr(exc, "code", "request_invalid"), str(exc), name)
            _discard(path, cfg)
            continue
        if due_only and isinstance(req, dict) and req.get("not_before"):
            nb = parse_iso(req["not_before"])
            if nb is None or nb > up.host.now():
                continue
        _discard(path, cfg)
        if not isinstance(req, dict):  # valid JSON, wrong shape (a list, a number): refuse it, never crash the run
            reject(up, name[:-5], "request_invalid", "not a request object", name)
            continue
        req["_file"] = name
        up.t0 = up.host.now()
        if due_only and req.get("action") != "apply":  # the schedule directory only ever holds installs
            reject(up, str(req.get("correlation_id", name[:-5])), "request_invalid", "unsupported request", name)
            continue
        if due_only or req.get("action") == "apply":
            if not due_only and req.get("not_before") is not None:  # the inbox means "now"; scheduling is the application's or the CLI's
                reject(up, str(req.get("correlation_id", name[:-5])), "request_invalid", "an inbox request cannot carry a start time", name)
                continue
            results.append(up.apply(req))
        elif req.get("action") in APP_ACTIONS:
            results.append(up.app_action(req))
        else:
            reject(up, str(req.get("correlation_id", name[:-5])), "request_invalid", "unsupported request", name)
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
                                                                    "message": message[:300], "at": iso(up.host.now()),
                                                                    **dict(zip(("reason_text", "changed", "next_step"),
                                                                               describe_reason(code if code in REASONS else "request_invalid")))})
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
                raw = read_regular(os.path.join(d, n), ocw_trust.MAX_JSON + 1)
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
        up.trim_housekeeping()
        try:
            up.publish_backups()
        except OSError as exc:
            log("WARN", f"could not publish the backups status: {exc.strerror}")
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
