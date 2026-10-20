"""Everything the root-owned updater does to the machine, in one place.

Separating "what the upgrade does" (ocw_activate.py: a state machine) from
"how the machine is touched" (this file) lets the whole state machine run in
tests against a fake machine with injected faults, and keeps the dangerous
calls (systemctl, nginx, chown, the symlink switch, the database tool) easy to
review. Standard library only; root never imports anything from a release.

SystemHost does the real work. tests/updater_fakes.py subclasses it and
replaces `run`, `http_get`, `sleep`, `now`, `free_bytes` and `chown_tree`, so
the parsing of systemctl output etc. below is exercised by the tests too.
"""

import http.client
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

_UNIT_OK = re.compile(r"^[A-Za-z0-9@:._-]{1,120}$")
BACKUP_NAME_OK = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


class HostError(Exception):
    pass


class SystemHost:
    def __init__(self, app_uid=None, app_gid=None):
        self.app_uid, self.app_gid = app_uid, app_gid

    # --- time ---------------------------------------------------------------
    def now(self):
        return time.time()

    def sleep(self, seconds):
        time.sleep(seconds)

    # --- processes ------------------------------------------------------------
    def run(self, argv, timeout=120):
        """(returncode, combined output). Never raises for a missing program."""
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout,
                               errors="replace", stdin=subprocess.DEVNULL)
            return p.returncode, p.stdout
        except FileNotFoundError:
            return 127, f"{argv[0]}: not found"
        except subprocess.TimeoutExpired:
            return 124, f"{argv[0]}: timed out after {timeout}s"

    def systemctl(self, *args, timeout=120):
        return self.run(["systemctl", *args], timeout=timeout)

    def unit_prop(self, unit, prop):
        rc, out = self.systemctl("show", "-p", prop, "--value", unit)
        return out.strip() if rc == 0 else ""

    def unit_exists(self, unit):
        return self.systemctl("cat", unit)[0] == 0

    def unit_enabled(self, unit):
        return self.systemctl("is-enabled", "--quiet", unit)[0] == 0

    def restart(self, unit):
        rc, out = self.systemctl("restart", unit, timeout=180)
        return rc == 0, out

    def start(self, unit, timeout=3600):
        rc, out = self.systemctl("start", unit, timeout=timeout)
        return rc == 0, out

    def stop(self, unit):
        rc, out = self.systemctl("stop", unit, timeout=180)
        return rc == 0, out

    def extra_gate_units(self):
        rc, out = self.systemctl("list-unit-files", "opa-auth-gate-*.service", "--no-legend")
        units = []
        for line in out.splitlines() if rc == 0 else []:
            name = line.split()[0] if line.split() else ""
            if name.endswith(".service"):
                name = name[:-len(".service")]
                if _UNIT_OK.match(name) and self.unit_enabled(name):
                    units.append(name)
        return units

    def gate_port(self, unit):
        out = self.unit_prop(unit, "ExecStart")
        m = re.search(r"--port[ =](\d+)", out)
        return int(m.group(1)) if m else 8767

    def journal(self, unit_pattern, lines=500, since=None):
        argv = ["journalctl", "-u", unit_pattern, "-n", str(lines), "--no-pager", "-o", "cat"]
        if since:
            argv += ["--since", since]
        rc, out = self.run(argv, timeout=60)
        return out

    def status_text(self, unit):
        return self.systemctl("status", unit, "--no-pager", "-l")[1]

    def nginx_test(self):
        return self.run(["nginx", "-t"], timeout=60)

    def nginx_reload(self):
        return self.systemctl("reload", "nginx")[0] == 0

    # --- HTTP on loopback ---------------------------------------------------------
    def http_get(self, port, path, headers=None, timeout=3):
        """(status | None, body text). Only ever 127.0.0.1."""
        try:
            conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read(65536).decode("utf-8", "replace")
            conn.close()
            return resp.status, body
        except (OSError, http.client.HTTPException, ValueError):
            return None, ""

    # --- files ---------------------------------------------------------------------
    def free_bytes(self, path):
        return shutil.disk_usage(path).free

    def chown_tree(self, root, uid=0, gid=0):
        """Make a verified release tree immutable for everyone but root:
        ownership root:root, no group/other write bit. Symlinks are not followed."""
        os.lchown(root, uid, gid)
        for base, dirs, files in os.walk(root):
            for name in dirs + files:
                p = os.path.join(base, name)
                os.lchown(p, uid, gid)
                if not os.path.islink(p):
                    mode = os.lstat(p).st_mode & 0o7777
                    os.chmod(p, mode & ~0o022)
        os.chmod(root, os.lstat(root).st_mode & 0o7755)

    def switch_symlink(self, link, target):
        """Atomic: build a temporary symlink beside it and rename over it."""
        tmp = f"{link}.tmp-{os.getpid()}"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(target, tmp)
        os.replace(tmp, link)
        fd = os.open(os.path.dirname(link), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    # --- the database tool runs as the application user ------------------------------
    def db_tool(self, args):
        """Runs `ocw_activate.py _dbtool ...` as the application user (never as
        root: a root SQLite connection could leave root-owned -wal/-shm files
        the application cannot open). Returns the parsed JSON it prints."""
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ocw_activate.py")  # run with -B: no .pyc written
        kwargs = {}
        if hasattr(os, "geteuid") and os.geteuid() == 0 and self.app_uid is not None:
            kwargs = {"user": self.app_uid, "group": self.app_gid, "extra_groups": []}
        try:
            p = subprocess.run([sys.executable, "-I", "-B", script, "_dbtool", *args], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, timeout=3600, stdin=subprocess.DEVNULL, **kwargs)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HostError(f"database tool failed to run: {exc}")
        try:
            return json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {"ok": False, "error": p.stderr.strip()[:300]}
        except ValueError:
            return {"ok": False, "error": (p.stderr or p.stdout).strip()[:300]}


# --- the database tool itself (runs in the child process above) --------------------------


def dbtool_main(argv):
    """_dbtool snapshot <db> | backup <db> <dst> | quick <db> | restore <src> <db>.
    Prints one JSON line. Runs as the application user."""
    cmd = argv[0]
    try:
        if cmd == "snapshot":
            print(json.dumps(snapshot(argv[1], argv[2] if len(argv) > 2 else None)))
        elif cmd == "backup":
            print(json.dumps(backup(argv[1], argv[2])))
        elif cmd == "restore":
            print(json.dumps(restore_copy(argv[1], argv[2])))
        else:
            print(json.dumps({"ok": False, "error": "unknown command"}))
            return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}", "enospc": getattr(exc, "errno", None) == 28}))
        return 1
    return 0


def _ro(db):
    # Runs as the application user, so a normal connection is safe (it creates at most the -wal/-shm
    # files the application itself would); a mode=ro connection cannot open a WAL database
    # whose -shm does not exist yet. Only ever called for a database that exists.
    return sqlite3.connect(db, timeout=30)


def snapshot(db, since=None):
    """Read-only facts about the archive: schema version, quick_check, audit
    chain heads, whether a sync is running. A missing database is not an error
    (a fresh install): schema 0 and no heads."""
    if not os.path.exists(db):
        return {"ok": True, "exists": False, "schema_version": 0, "quick_check": "ok", "chain_heads": {}, "sync_running": False,
                "size": 0}
    conn = _ro(db)
    try:
        out = {"ok": True, "exists": True, "size": os.path.getsize(db)}
        try:
            out["schema_version"] = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
        except sqlite3.OperationalError:
            out["schema_version"] = 0
        out["quick_check"] = conn.execute("PRAGMA quick_check").fetchone()[0]
        try:
            out["chain_heads"] = {str(r[0]): str(r[1]) for r in conn.execute("SELECT environment_id, head_hash FROM chain_heads")}
        except sqlite3.OperationalError:
            out["chain_heads"] = {}
        running = False
        try:
            cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 1800))
            running = conn.execute("SELECT COUNT(*) FROM sync_state WHERE last_sync_status = 'running' "
                                   "AND COALESCE(last_sync_attempt_at, last_synced_at, '') > ?", (cutoff,)).fetchone()[0] > 0
        except sqlite3.OperationalError:
            try:
                running = conn.execute("SELECT COUNT(*) FROM sync_state WHERE last_sync_status = 'running'").fetchone()[0] > 0
            except sqlite3.OperationalError:
                running = False
        out["sync_running"] = running
        out["env_names"] = environment_names(conn, db)
        out["sync_after"] = False
        if since:
            try:
                out["sync_after"] = conn.execute("SELECT COUNT(*) FROM sync_state WHERE COALESCE(last_sync_attempt_at, last_synced_at, '') > ?",
                                                 (since.replace("Z", ""),)).fetchone()[0] > 0
            except sqlite3.OperationalError:
                pass
        return out
    finally:
        conn.close()


def environment_names(conn, db):
    """Distinct tenant / environment names and hosts the application knows (so a support bundle can hide them)."""
    names = set()
    try:
        for row in conn.execute("SELECT display_name, team_name, base_domain, okta_url FROM app_environments"):
            names.update(v for v in row if isinstance(v, str))
    except sqlite3.Error:
        pass
    try:  # the legacy environments file next to the archive: opened as the application account, plain files only
        import stat as _stat
        path = os.path.join(os.path.dirname(os.path.abspath(db)), "environments.json")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            if _stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                def walk(o, depth=0):
                    if depth > 5:
                        return
                    if isinstance(o, dict):
                        for k, v in o.items():
                            if k in ("display_name", "name", "team_name", "base_domain", "okta_url", "org_url") and isinstance(v, str):
                                names.add(v)
                            else:
                                walk(v, depth + 1)
                    elif isinstance(o, list):
                        for v in o[:500]:
                            walk(v, depth + 1)
                walk(json.loads(fh.read(4 << 20).decode("utf-8")))
    except (OSError, ValueError):
        pass
    return sorted(n for n in names if 3 <= len(n) <= 200)[:500]


def backup(db, dst):
    """SQLite online backup of `db` into the new file `dst` (SQLite's backup
    API copes with a database that is being written to), then integrity_check
    of the copy. The copy is written owner-only."""
    if not os.path.exists(db):
        return {"ok": True, "exists": False}
    old = os.umask(0o077)
    try:
        src = sqlite3.connect(db, timeout=60)
        out = sqlite3.connect(dst)
        try:
            src.backup(out)
            check = out.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            out.close()
            src.close()
    finally:
        os.umask(old)
    return {"ok": check == "ok", "exists": True, "integrity_check": check, "size": os.path.getsize(dst)}


def restore_copy(src, dst):
    """Copy a backup file to a NEW file beside the live database (the caller
    renames it into place). Verified with integrity_check."""
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o600)
    conn = sqlite3.connect(f"file:{dst}?immutable=1", uri=True)
    try:
        check = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()
    return {"ok": check == "ok", "integrity_check": check, "size": os.path.getsize(dst)}
