"""Folder handling for the local-mode guided upgrade (5.49.0). Standard library only: on
Windows the launcher's outer process, which has no third-party packages, finishes the swap.

The layout. A local install is a folder, e.g. <parent>/opa-compliance-wizard (the "current" folder, called
<base> below). An upgrade never changes it in place:

    <base>-<version>    the new release, unpacked and prepared next to it (the "staged" folder)
    <base>              the folder the user starts the dashboard from
    <base>-previous     the one before, kept so a single command can bring it back

The swap is three renames inside <parent> (current -> previous, staged -> current), each one atomic
on its own; a failed second rename undoes the first. A crash between them leaves <base> missing and
<base>-previous holding the old install; recover() puts it back. Nothing is deleted before the new
folder has passed a start-up check, and a folder that cannot be renamed because Windows has a file
in it open is retried and then reported with what to close. No symbolic links are used anywhere.

What belongs to the user (carried over, never moved): see DATA_FILES / DATA_GLOBS. The database is
copied with SQLite's online backup so a half-written page can never be copied; every other file is
copied byte for byte with its permissions. Credentials live in the operating system's keychain (not
in the folder) and are not touched; the files that do hold settings (environments.json, .env) are
copied to the same place in the new folder, so the old folder keeps its own copy until it is
discarded (`upgrade --discard-previous`).
"""

import fnmatch
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

DB_NAME = "audit_store.db"
# Exactly these names, plus these patterns, are the user's. Anything else untracked in the old folder is
# listed for the user and left where it is.
DATA_FILES = ("environments.json", "audit_log.jsonl", "banner_config.json", "access_control.json", "secrets_log_cache.json",
              "update_check.json", "release_keys.local.json", ".env")
DATA_GLOBS = ("environments.json.*", "audit_store.db.*", "folders_result_*.csv")
SKIP_NAMES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".DS_Store", "Thumbs.db", ".audit_log.jsonl.lock",
              DB_NAME + "-wal", DB_NAME + "-shm", ".deploy.lock", ".ocw-upgrade.json"}
JOURNAL = ".ocw-upgrade.json"
SMOKE_TIMEOUT = 900


class SwapError(Exception):
    """`rolled_back`: nothing the user had was changed (exit 3). False = the user must act (exit 4)."""

    def __init__(self, code, message, rolled_back=True):
        super().__init__(message)
        self.code = code
        self.rolled_back = rolled_back


def is_windows():
    return os.name == "nt"


# --- names ---------------------------------------------------------------------------------------------


class Layout:
    """The sibling folders of one install. `root` is any one of <base> / <base>-previous."""

    def __init__(self, root):
        root = Path(root).resolve()
        self.parent = root.parent
        name = root.name
        self.base = name[:-len("-previous")] if name.endswith("-previous") and len(name) > len("-previous") else name
        self.current = self.parent / self.base
        self.previous = self.parent / (self.base + "-previous")

    def staged(self, version):
        return self.parent / f"{self.base}-{version}"

    def replaced(self, version):
        candidate = self.parent / f"{self.base}-replaced-{version}"
        n = 1
        while candidate.exists():
            n += 1
            candidate = self.parent / f"{self.base}-replaced-{version}-{n}"
        return candidate

    def leftovers(self):
        prefix = self.base + "-previous.old-"
        return sorted(p for p in self.parent.glob(prefix + "*") if p.is_dir())


def version_of(folder):
    try:
        text = (Path(folder) / "create_secret_folders.py").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else None


def looks_like_install(folder):
    return (Path(folder) / "create_secret_folders.py").is_file() and (Path(folder) / "launch.py").is_file()


# --- renames -------------------------------------------------------------------------------------------


def _hint_for_lock():
    if is_windows():
        return ("Windows keeps a folder locked while a program has a file in it open. Close the dashboard (and its terminal "
                "window), any File Explorer window, editor or antivirus scan showing this folder, then run the command again. "
                "Run the upgrade with the system Python (`py -3 launch.py upgrade`), not from inside the project's .venv.")
    return "Close anything that has the folder open (a shell whose current directory is inside it, an editor) and run the command again."


def rename(src, dst, attempts=None, delay=0.6, sleep=time.sleep):
    """os.rename with the retries Windows needs (a virus scanner or indexer can hold a folder for a moment).
    Never overwrites: an existing `dst` is an error on every platform (os.rename would replace an empty
    directory on POSIX and fail on Windows; this makes both fail)."""
    src, dst = str(src), str(dst)
    if os.path.lexists(dst):
        raise SwapError("exists", f"{dst} already exists")
    tries = attempts or (6 if is_windows() else 1)
    last = None
    for i in range(tries):
        try:
            os.rename(src, dst)
            return
        except (PermissionError, OSError) as exc:
            last = exc
            if i + 1 < tries:
                sleep(delay)
    raise SwapError("locked", f"could not rename {src} to {dst} ({getattr(last, 'strerror', None) or last}). " + _hint_for_lock())


def remove_tree(path):
    """Best effort; returns True if gone. A read-only file (git objects) is made writable first on Windows."""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(str(path), onerror=onerror)
    return not os.path.exists(str(path))


def leave(folder, parent):
    """The process must not be standing inside a folder it is about to rename (Windows refuses; POSIX would
    leave a dangling cwd)."""
    try:
        here = Path.cwd().resolve()
    except OSError:
        here = None
    if here is None or here == Path(folder).resolve() or Path(folder).resolve() in here.parents:
        os.chdir(str(parent))


# --- data ----------------------------------------------------------------------------------------------


def data_candidates(old_root):
    """[(name, kind)] of the user's files in the old folder: kind 'db' | 'file'."""
    old_root = Path(old_root)
    found = []
    try:
        names = sorted(os.listdir(old_root))
    except OSError as exc:
        raise SwapError("unreadable", f"cannot read {old_root}: {exc.strerror or exc}")
    for name in names:
        if name in SKIP_NAMES:
            continue
        if name == DB_NAME:
            found.append((name, "db"))
        elif name in DATA_FILES or any(fnmatch.fnmatchcase(name, g) for g in DATA_GLOBS):
            found.append((name, "file"))
    return found


def other_untracked(old_root, new_root, carried):
    """Names in the old folder that are neither shipped by the new release, nor carried, nor build leftovers. Shown to
    the user so nothing disappears silently; they stay in the previous folder."""
    out = []
    for name in sorted(os.listdir(old_root)):
        if name in SKIP_NAMES or name in carried or (Path(new_root) / name).exists():
            continue
        out.append(name)
    return out


def user_csv_templates(old_root, new_root):
    """Folder templates the user saved next to the code (serve.py lists *.csv there). A file the release also ships under
    the same name stays the release's; it is reported, not overwritten."""
    keep, clash = [], []
    for p in sorted(Path(old_root).glob("*.csv")):
        if p.name.startswith("folders_result_") or not p.is_file() or p.is_symlink():
            continue
        (clash if (Path(new_root) / p.name).exists() else keep).append(p.name)
    return keep, clash


def _backup_db(src, dst):
    out = None
    old_umask = os.umask(0o077)
    try:
        con = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=60)
        try:
            out = sqlite3.connect(str(dst))
            con.backup(out)
            check = out.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            if out is not None:
                out.close()
            con.close()
    except sqlite3.Error as exc:
        raise SwapError("db_copy_failed", f"the archive database could not be copied safely ({exc}). Nothing was changed.")
    finally:
        os.umask(old_umask)
    if check != "ok":
        raise SwapError("db_copy_failed", f"the copy of the archive database failed its integrity check ({check}). Nothing was changed.")


def _same_mode(src, dst):
    try:
        os.chmod(dst, stat.S_IMODE(os.stat(src).st_mode))
    except OSError:
        pass


def _copy_file(src, dst):
    tmp = str(dst) + ".ocw-tmp"
    shutil.copyfile(src, tmp)
    shutil.copystat(src, tmp)
    _same_mode(src, tmp)
    os.replace(tmp, dst)


def copy_data(old_root, new_root, say=print):
    """Copy the user's data from the old folder into the (staged) new one. Returns {name: size}. Refuses a
    symbolic link where a data file should be (it would be copied as something else than it is)."""
    old_root, new_root = Path(old_root), Path(new_root)
    copied = {}
    for name, kind in data_candidates(old_root):
        src, dst = old_root / name, new_root / name
        if src.is_symlink() or not src.is_file():
            raise SwapError("data_is_link", f"{name} is a symbolic link or not a plain file. Copy it into place yourself "
                                            "(replace the link with the real file) and run the upgrade again. Nothing was changed.")
        if kind == "db":
            _backup_db(src, dst)
            _same_mode(src, dst)
        else:
            _copy_file(src, dst)
        copied[name] = dst.stat().st_size
    keep, _clash = user_csv_templates(old_root, new_root)
    for name in keep:
        _copy_file(old_root / name, new_root / name)
        copied[name] = (new_root / name).stat().st_size
    say_names = ", ".join(sorted(copied)) or "nothing (a fresh install)"
    say(f"Carried over: {say_names}")
    return copied


# --- schema compatibility (restore) --------------------------------------------------------------------


def db_schema_version(folder):
    db = Path(folder) / DB_NAME
    if not db.is_file():
        return 0
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    try:
        try:
            return con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
        except sqlite3.OperationalError:
            return 0
    finally:
        con.close()


def code_schema_version(folder):
    """The highest migration the code in `folder` knows, read from its audit_store.py without importing it."""
    try:
        text = (Path(folder) / "audit_store.py").read_text(encoding="utf-8")
    except OSError:
        return None
    block = re.search(r"^MIGRATIONS = \{(.*?)^\}", text, re.M | re.S)
    numbers = [int(n) for n in re.findall(r"^\s*(\d+):\s*_migration_", block.group(1), re.M)] if block else []
    return max(numbers) if numbers else None


def restore_compat(current, previous):
    """(ok, reason). Can the previous folder's CODE run on the current folder's DATA? Yes when the data's schema is not
    newer than the code knows, or every migration in between is declared rollback_safe by the current release."""
    have, known = db_schema_version(current), code_schema_version(previous)
    if known is None:
        return False, "the previous folder's database code could not be read"
    if have <= known:
        return True, f"schema {have} is within what the previous version knows ({known})"
    try:
        declared = json.loads((Path(current) / "server" / "schema_migrations.json").read_text(encoding="utf-8"))["migrations"]
    except (OSError, ValueError, KeyError):
        return False, f"the data is at schema {have}, newer than the previous version's {known}, and the current release declares nothing about it"
    unsafe = [n for n in range(known + 1, have + 1) if not (declared.get(str(n)) or {}).get("rollback_safe")]
    if unsafe:
        return False, (f"migration{'s' if len(unsafe) > 1 else ''} {', '.join(map(str, unsafe))} changed the archive in a way the "
                       f"previous version cannot read (schema {have}, previous knows {known})")
    return True, f"migrations {known + 1}-{have} are rollback-safe"


# --- start-up check ------------------------------------------------------------------------------------

_SMOKE = r"""
import json, sys
sys.path.insert(0, '.')
import create_secret_folders as e
assert e.SCRIPT_VERSION == sys.argv[1], 'version %s, expected %s' % (e.SCRIPT_VERSION, sys.argv[1])
if sys.argv[2] == 'migrate':
    import audit_store
    audit_store.init_db()
for ev in json.loads(sys.argv[3]):
    e.log_audit_event(ev['actor'], None, ev['action'], ev['details'], user_agent='launch.py')
print('ok')
"""


def smoke_test(folder, python, version, migrate=True, events=(), runner=subprocess.run):
    """Start the folder's own code with its own Python: it must import, report `version`, and (migrate=True) open and
    migrate its database. `events` are audit-log entries to write into THAT folder's log. Returns (ok, detail)."""
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "OPA_DATA_DIR")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = runner([str(python), "-c", _SMOKE, version, "migrate" if migrate else "check", json.dumps(list(events))],
                      cwd=str(folder), capture_output=True, text=True, timeout=SMOKE_TIMEOUT, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode != 0 or "ok" not in (proc.stdout or ""):
        tail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()[-4:]
        return False, " | ".join(tail)[:600] or f"exit {proc.returncode}"
    return True, "ok"


# --- the swap ------------------------------------------------------------------------------------------


def write_journal(folder, **fields):
    try:
        (Path(folder) / JOURNAL).write_text(json.dumps(fields), encoding="utf-8")
    except OSError:
        pass


def recover(layout, say=print):
    """Repair what an interrupted swap left. Returns a list of what was done."""
    done = []
    if not layout.current.exists() and layout.previous.exists() and looks_like_install(layout.previous):
        rename(layout.previous, layout.current)
        done.append(f"The last upgrade was interrupted: {layout.previous.name} was put back as {layout.current.name} "
                    f"(version {version_of(layout.current) or 'unknown'}).")
    if layout.current.exists() and not layout.previous.exists():
        old = layout.leftovers()
        if old:
            rename(old[0], layout.previous)
            done.append(f"The older previous version ({version_of(layout.previous) or 'unknown'}) was put back as {layout.previous.name}.")
    for line in done:
        say(line)
    return done


def swap_in(layout, staged, sleep=time.sleep):
    """current -> previous, staged -> current. Returns the path of an older previous folder that was set aside (to delete
    after the new folder passed its check), or None. Undoes itself on failure."""
    leave(layout.current, layout.parent)
    leave(staged, layout.parent)
    if not layout.current.is_dir() or not staged.is_dir():
        raise SwapError("missing", "the current or the new folder is missing; nothing was changed")
    aside = None
    if layout.previous.exists():
        aside = layout.parent / f"{layout.base}-previous.old-{os.getpid()}"
        rename(layout.previous, aside, sleep=sleep)
    try:
        rename(layout.current, layout.previous, sleep=sleep)
    except SwapError:
        if aside is not None:
            rename(aside, layout.previous, sleep=sleep)
        raise
    try:
        rename(staged, layout.current, sleep=sleep)
    except SwapError as exc:
        try:
            rename(layout.previous, layout.current, sleep=sleep)
        except SwapError:
            raise SwapError("swap_half_done", f"the swap stopped half way and could not be undone. {layout.current.name} is missing: "
                            f"your install is in {layout.previous.name}. Rename that folder back to {layout.current.name} "
                            "(File Explorer / mv), then run the upgrade again.", rolled_back=False)
        if aside is not None:
            rename(aside, layout.previous, sleep=sleep)
        raise SwapError(exc.code, str(exc))
    return aside


def swap_back(layout, failed_name, aside, sleep=time.sleep):
    """After a swap whose new folder failed its check: current -> <failed_name>, previous -> current, aside -> previous."""
    leave(layout.current, layout.parent)
    failed = layout.parent / failed_name
    n = 1
    while failed.exists():
        n += 1
        failed = layout.parent / f"{failed_name}-{n}"
    rename(layout.current, failed, sleep=sleep)
    try:
        rename(layout.previous, layout.current, sleep=sleep)
    except SwapError:
        rename(failed, layout.current, sleep=sleep)   # put the new one back rather than leave no install at all
        raise
    if aside is not None and aside.exists():
        rename(aside, layout.previous, sleep=sleep)
    return failed


def finish_swap(plan, say=print, runner=subprocess.run, sleep=time.sleep):
    """Do the swap described by `plan` (a dict written by localupgrade) and check the result; swap back if the new
    version does not start. Returns (exit_code, message). Exit codes: 0 done, 3 failed and nothing changed, 4 operator needed."""
    layout = Layout(plan["root"])
    version, staged = plan["version"], Path(plan["staged"])
    try:
        aside = swap_in(layout, staged, sleep=sleep)
    except SwapError as exc:
        return (3 if exc.rolled_back else 4), str(exc)
    write_journal(layout.current, state="swapped", to=version, previous=plan.get("from_version"))
    ok, detail = smoke_test(layout.current, plan["python"], version, migrate=True, events=plan.get("events", []), runner=runner)
    if not ok:
        say(f"The new version did not start ({detail}). Putting the previous version back...")
        try:
            swap_back(layout, f"{layout.base}-{version}-failed", aside, sleep=sleep)
        except SwapError as exc:
            return 4, f"The new version did not start and the previous one could not be put back: {exc}"
        return 3, (f"The new version {version} did not start ({detail}), so version {plan.get('from_version')} is back in place and "
                   f"unchanged. The failed copy is kept for inspection in {layout.base}-{version}-failed.")
    if aside is not None and not remove_tree(aside):
        say(f"Note: the older previous copy {aside.name} could not be deleted (something has it open); delete it by hand.")
    return 0, f"Upgraded to {version}. The previous version ({plan.get('from_version')}) is kept in {layout.previous.name}."


def restore_previous(layout, restore_data=False, python=None, say=print, runner=subprocess.run, sleep=time.sleep, events=()):
    """Bring <base>-previous back as <base>. The folder it replaces is kept as <base>-replaced-<version>. Code only by
    default: the current data is copied into the restored folder (its own older copy is set aside inside it) when
    the previous code can read it; `restore_data=True` instead keeps the previous folder's own, older data.
    Returns (exit_code, message)."""
    if not layout.previous.is_dir() or not looks_like_install(layout.previous):
        return 2, f"There is no previous version to restore ({layout.previous.name} does not exist)."
    if not layout.current.is_dir():
        return 4, f"{layout.current.name} is missing; run `upgrade --restore-previous` once more (it repairs an interrupted upgrade)."
    cur_v, prev_v = version_of(layout.current), version_of(layout.previous)
    if not restore_data:
        ok, reason = restore_compat(layout.current, layout.previous)
        if not ok:
            return 2, (f"Code-only restore is not possible: {reason}. Options: `--restore-data` brings back the previous version AND its "
                       f"older copy of the data (everything recorded since the upgrade stays in {layout.base}-replaced-{cur_v}), "
                       "or stay on the current version.")
        stamp = time.strftime("%Y%m%dT%H%M%S")
        safe = layout.previous / f".data-before-restore-{stamp}"
        try:
            safe.mkdir()
            for name, _kind in data_candidates(layout.previous):
                _copy_file(layout.previous / name, safe / name)
            copy_data(layout.current, layout.previous, say=lambda *_: None)
        except (SwapError, OSError) as exc:
            return 3, f"The data could not be copied into the previous folder ({exc}). Nothing was changed."
    replaced = layout.replaced(cur_v or "unknown")
    leave(layout.current, layout.parent)
    try:
        rename(layout.current, replaced, sleep=sleep)
        try:
            rename(layout.previous, layout.current, sleep=sleep)
        except SwapError:
            rename(replaced, layout.current, sleep=sleep)
            raise
    except SwapError as exc:
        return (3 if exc.code != "swap_half_done" else 4), str(exc)
    py = python or sys.executable
    venv_py = layout.current / (".venv/Scripts/python.exe" if is_windows() else ".venv/bin/python")
    if venv_py.exists():
        py = str(venv_py)
    ok, detail = smoke_test(layout.current, py, prev_v or "", migrate=True, events=events, runner=runner)
    if not ok:
        try:
            rename(layout.current, layout.previous, sleep=sleep)
            rename(replaced, layout.current, sleep=sleep)
        except SwapError as exc:
            return 4, f"The restored version did not start ({detail}) and could not be swapped back: {exc}"
        return 3, f"The previous version did not start ({detail}); the current version is back in place and unchanged."
    return 0, (f"Restored version {prev_v}. The version it replaced ({cur_v}) is kept in {replaced.name}; delete it when you no longer "
               "need it.")


def discard_previous(layout):
    """Delete <base>-previous (and leftovers). Returns (exit_code, message)."""
    if not layout.previous.exists():
        return 2, "There is no previous version to delete."
    leave(layout.previous, layout.parent)
    v = version_of(layout.previous)
    if not remove_tree(layout.previous):
        return 4, f"{layout.previous.name} could not be fully deleted (something has a file in it open). Close it and run this again."
    for extra in layout.leftovers():
        remove_tree(extra)
    return 0, f"Deleted the previous version ({v or 'unknown'}) and its copies of your settings."


# --- the Windows hand-over -------------------------------------------------------------------------------
# On Windows a folder cannot be renamed while a program has a file in it open, and the process doing the upgrade
# runs the project's own .venv\Scripts\python.exe. So that process only PREPARES, writes the plan below and exits with
# EXIT_SWAP_PENDING; the outer launcher (the system Python that started it, holding nothing in the folder) calls
# run_pending_plan() to do the renames and the start-up check.
EXIT_SWAP_PENDING = 86


def plan_path(layout):
    return layout.parent / f".{layout.base}-swap-plan.json"


def execute_plan(plan, say=print):
    layout = Layout(plan["root"])
    if plan.get("kind") == "restore":
        code, message = restore_previous(layout, restore_data=plan.get("restore_data", False), events=plan.get("events", []))
        say(message)
        return code
    code, message = finish_swap(plan, say=say)
    say(message)
    if code == 0:
        say("Start the dashboard again as usual (python launch.py). If your terminal window was inside the old folder, "
            f"close it and open a new one in {plan['root']}.")
    return code


def run_pending_plan(root, say=print):
    layout = Layout(root)
    path = plan_path(layout)
    try:
        path_mode = stat.S_IMODE(path.stat().st_mode)
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        say("ERROR: the upgrade plan could not be read; nothing was changed.")
        return 3
    try:
        path.unlink()
    except OSError:
        pass
    problem = _plan_problem(plan, layout, path_mode)
    if problem:
        say(f"ERROR: the upgrade plan was not used ({problem}); nothing was changed.")
        return 3
    return execute_plan(plan, say)


def _plan_problem(plan, layout, path_mode):
    """The plan file sits in a folder other programs may write to; it is only followed if it describes exactly the folders of THIS
    install and was not writable by anyone else."""
    if not isinstance(plan, dict) or plan.get("kind") not in ("upgrade", "restore"):
        return "unknown kind"
    if hasattr(os, "getuid") and path_mode is not None and (path_mode & 0o022):
        return "it was writable by other users"
    if plan.get("root") != str(layout.current):
        return "it is for another folder"
    if plan["kind"] == "restore":
        return None
    version = plan.get("version")
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version) or plan.get("staged") != str(layout.staged(version)):
        return "it names an unexpected folder"
    python = str(plan.get("python", ""))
    allowed = str(layout.current / (".venv/Scripts/python.exe" if is_windows() else ".venv/bin/python"))
    if python != allowed and python != sys.executable and python != str(getattr(sys, "_base_executable", "")):
        return "it names an unexpected program"
    return None
