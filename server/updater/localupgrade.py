"""The guided upgrade for local mode (launch.py on a laptop or desktop), 5.49.0.

    python launch.py upgrade --check [--channel stable|prerelease]
    python launch.py upgrade [--to X.Y.Z] [--channel ...] [--confirm X.Y.Z]
    python launch.py upgrade --from-file ocw-X.Y.Z-offline.tar.gz | ocw-X.Y.Z.tar.gz ocw-X.Y.Z.tar.gz.minisig
    python launch.py upgrade --restore-previous [--restore-data] [--confirm RESTORE]
    python launch.py upgrade --discard-previous [--confirm DELETE]
    python launch.py upgrade --status

What it does, in this order, and where it can stop without having touched anything the user has:
  1. check (or take the named version / file) and, for a download, apply any published key revocation;
  2. verify the signature, manifest and version with the SAME verifier the hosted updater uses
     (server/updater/verify.py, the pinned keys of THIS install) BEFORE a single file is unpacked;
  3. unpack into the sibling folder <base>-<version> (regular files only, each hashed against the signed
     manifest) and build its Python environment from the hash-pinned requirements.lock (from the offline
     bundle's wheels with --no-index when given one);
  4. show what will change and ask the user to type the version (there is no identity provider in local
     mode to step up with, so nothing is faked);
  5. make sure the dashboard is not running, copy the user's data into the new folder, swap folder names
     (localswap.py), start the new code once with its own Python (migrating the copied database) and swap
     back by itself if that fails. The old folder stays as <base>-previous.
Exit status: 0 done / up to date, 1 --check found a newer release, 2 refused (signature, version, key, not
confirmed, bad usage), 3 failed and nothing changed or everything was put back, 4 failed and the user
has to act (the message says how).
"""

import argparse
import getpass
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from . import check
from . import keys as keylib
from . import localswap
from . import offline
from . import service
from . import verify as verifylib

EXIT_OK, EXIT_NEWER, EXIT_REFUSED, EXIT_FAILED, EXIT_OPERATOR = 0, 1, 2, 3, 4
EXIT_SWAP_PENDING = localswap.EXIT_SWAP_PENDING   # Windows: the inner (venv) process is done; the outer one renames the folders
REEXEC_ENV = "OPA_LAUNCHER_IN_VENV"
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TAR_RE = re.compile(r"^ocw-(\d+\.\d+\.\d+)\.tar\.gz$")
MIN_FREE_EXTRA = 300 * 1024 * 1024


class Refused(Exception):
    def __init__(self, code, message, exit_code=EXIT_REFUSED):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


class Host:
    """What only launch.py knows how to do (processes, prompts); tests substitute it."""
    interactive = False

    def ask(self, prompt):
        return input(prompt)

    def port_in_use(self, port):
        return False

    def stop_server(self, port):
        return False

    def pip_python(self):
        return getattr(sys, "_base_executable", None) or sys.executable


def _actor():
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # noqa: BLE001
        return "cli:unknown"


def _audit_here(action, details):
    """Best effort record in THIS (old) folder's audit log; the new folder's log gets the completed/restored entries."""
    try:
        keylib._engine().log_audit_event(_actor(), None, action, {**details, "via": "launch.py"}, user_agent="launch.py")
    except Exception:  # noqa: BLE001 - never let logging stop or hide a refusal
        pass


# --- small helpers ---------------------------------------------------------------------------------------


def _human_size(n):
    return f"{n / 1024 / 1024:.1f} MB" if n and n >= 1024 * 1024 else (f"{max(n or 0, 1) / 1024:.0f} KB")


def venv_python(folder):
    return Path(folder) / (".venv/Scripts/python.exe" if localswap.is_windows() else ".venv/bin/python")


def _keyring_ok(python):
    try:
        return subprocess.run([str(python), "-c", "import keyring"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _release_base():
    base = (os.environ.get("OPA_RELEASE_BASE_URL") or check.DEFAULT_RELEASE_DOWNLOAD_BASE).rstrip("/")
    hosts = check.GITHUB_HOSTS if not os.environ.get("OPA_RELEASE_BASE_URL") else check.hosts_for(base)
    return base, hosts


def confirm_typed(host, expected, supplied, say, prompt):
    """The typed confirmation. `supplied` is --confirm. Without a terminal and without --confirm nothing proceeds."""
    if supplied is not None:
        if supplied.strip() != expected:
            raise Refused("not_confirmed", f"--confirm must be exactly {expected}; nothing was changed.")
        return
    if not host.interactive:
        raise Refused("needs_confirmation", f"This needs a typed confirmation and there is no terminal. Run it in a terminal, or add "
                                            f"--confirm {expected}. Nothing was changed.")
    try:
        answer = host.ask(prompt)
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip() != expected:
        raise Refused("not_confirmed", "Not confirmed. Nothing was changed.")


# --- check -----------------------------------------------------------------------------------------------


def do_check(args, root, say):
    installed = localswap.version_of(root)
    out = service.run_check(installed, force=True, trigger=_actor(), channel=args.channel)
    if out is None:
        say("Another update check is already running; try again in a moment.")
        return EXIT_FAILED
    s = service.status(service.load(), installed)
    if args.json:
        say(json.dumps({"result": out, "status": s}, indent=2))
    else:
        say(f"Installed        {installed}   ({root})")
        say(f"Channel          {s['check']['channel']}" + ("   (includes prereleases)" if s["check"]["channel"] == "prerelease" else ""))
        latest = s["latest"]
        if out["outcome"] == "failed":
            say(f"The check failed: {out['reason']}. {out.get('result', '')}".rstrip())
            say("Nothing was changed. If this computer has no internet access, use `upgrade --from-file` (README, 'Air-gapped').")
        elif latest:
            say(f"Latest           {latest['version']}   released {(latest['published_at'] or 'unknown')[:10]}"
                + (f"   {_human_size(latest['size'])}" if latest["size"] else "")
                + ("   PRERELEASE" if latest["prerelease"] else "")
                + ("" if latest["signed_artifact"] else "   [no signed download attached]"))
            if s["update_available"]:
                say(f"A newer release is available. Upgrade with:  python launch.py upgrade")
                if latest["release_url"]:
                    say(f"Release notes: {latest['release_url']}")
            else:
                say("You are up to date.")
        else:
            say("No release is published on this channel yet. You are up to date.")
        say("The check sent one HTTPS request to the release host and nothing about your tenant, users or data.")
    if out["outcome"] == "failed":
        return EXIT_FAILED
    return EXIT_NEWER if out["outcome"] == "update_available" else EXIT_OK


# --- preparation -----------------------------------------------------------------------------------------


def _capture(func, *a):
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = func(*a)
    return rc, out.getvalue(), err.getvalue()


def _refresh_revocations(say):
    """The same published-revocation step the update check runs, so a release signed by a stolen key cannot be
    installed on a computer that has not heard about the theft. Best effort: no network or none published is fine."""
    try:
        data = service.load()
        outcomes = service._revocation_step(data["state"], check.USER_AGENT)
        service.save(data)
    except Exception:  # noqa: BLE001
        return
    notable = [o for o in outcomes if o.split(":", 1)[1] not in ("none_published", "unchanged", "already_handled", "already_applied")
               and "fetch_failed" not in o]
    if notable:
        say("Signing-key revocation: " + "; ".join(notable))


def _download(version, dest_dir, say):
    base, hosts = _release_base()
    data = service.load()
    ua = check.USER_AGENT + (f"/{localswap.version_of(Path(keylib.REPO_ROOT))}" if data["settings"]["share_version"] else "")
    paths = []
    for name in (f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig"):
        say(f"Downloading {name} ...")
        got = check.download_file(f"{base}/v{version}/{name}", hosts, dest_dir / name,
                                  verifylib.MAX_TARBALL_BYTES if name.endswith(".gz") else 64 * 1024, timeout=120, user_agent=ua)
        if got.status != "ok":
            raise Refused("download_failed", f"Could not download {name}: {got.detail or got.code}. Check that version {version} exists "
                                             "and that this computer can reach the release host (proxy: https_proxy), or download the "
                                             "files on another computer and use `upgrade --from-file`. Nothing was changed.",
                          EXIT_FAILED)
        paths.append(dest_dir / name)
    return paths


def _locate_files(args, work, say):
    """-> (version, tarball, minisig, wheels_dir|None, offline_info|None)"""
    if args.from_file:
        files = [Path(f) for f in args.from_file]
        if len(files) == 1 and offline.is_bundle_name(files[0]):
            try:
                bundle = offline.open_bundle(files[0], work / "bundle")
            except offline.BundleError as exc:
                raise Refused(exc.code, f"The offline bundle was refused: {exc} Nothing was changed.")
            say(f"Offline bundle {files[0].name}: release {bundle.version} and {bundle.wheel_count} Python packages.")
            return bundle.version, Path(bundle.tarball), Path(bundle.minisig), Path(bundle.wheels_dir), bundle.info
        if len(files) == 2 and _TAR_RE.match(files[0].name):
            for f in files:
                if not f.is_file():
                    raise Refused("unreadable", f"{f} does not exist. Nothing was changed.")
            sibling = files[0].parent / "revocation.json"
            if sibling.is_file():
                try:
                    keylib.apply_revocation_file(str(sibling))
                    say(f"Applied the signing-key revocation next to the release files ({sibling.name}).")
                except keylib.KeyListError as exc:
                    if getattr(exc, "code", "") != "replayed":
                        raise Refused("revocation_rejected", f"The revocation file next to the release was refused: {exc}. Nothing was changed.")
            return _TAR_RE.match(files[0].name).group(1), files[0], files[1], None, None
        raise Refused("usage", "--from-file takes an offline bundle (ocw-X.Y.Z-offline.tar.gz) or the release file and its signature "
                               "(ocw-X.Y.Z.tar.gz ocw-X.Y.Z.tar.gz.minisig).")
    return None


def _check_space(parent, need, say):
    try:
        free = shutil.disk_usage(parent).free
    except OSError:
        return
    if free < need:
        raise Refused("disk_space", f"Not enough free disk space next to the install: about {_human_size(need)} needed, {_human_size(free)} free. "
                                    "Free some space and run it again. Nothing was changed.", EXIT_FAILED)


def _windows_path_check(staged, manifest):
    if not localswap.is_windows():
        return
    longest = max((len(p) for p in manifest["files"]), default=0)
    if len(str(staged)) + 1 + longest > 240:
        raise Refused("path_too_long", f"The install folder's path is too long for Windows (limit about 260 characters; the new folder "
                                       f"would reach {len(str(staged)) + 1 + longest}). Move the install to a shorter path such as "
                                       "C:\\opa-compliance-wizard and run it again. Nothing was changed.", EXIT_FAILED)


def _build_environment(staged, wheels, say, host):
    """-> the Python to use for the new folder (relative to nothing; absolute in the staged folder)."""
    lock = staged / "requirements.lock"
    if not lock.is_file():
        raise Refused("no_lock", "The release has no requirements.lock, so a hash-checked install is impossible. Nothing was changed.")
    base = host.pip_python()
    say("Creating the Python environment (hash-pinned packages) ...")
    venv = staged / ".venv"
    proc = subprocess.run([str(base), "-m", "venv", str(venv)], capture_output=True, text=True, timeout=600)
    py = venv_python(staged)
    if proc.returncode != 0 or not py.exists():
        raise Refused("venv_failed", "Could not create the virtual environment ("
                      + ((proc.stderr or proc.stdout or "").strip()[-200:] or "unknown error")
                      + "). On Debian/Ubuntu install python3-venv. Nothing was changed.", EXIT_FAILED)
    env = dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    argv = ([str(py), "-m", "pip"] + (offline.pip_install_args(lock, wheels) if wheels else
                                       ["install", "-q", "--require-hashes", "-r", str(lock)]))
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=3000, env=env, cwd=str(staged))
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-400:]
        hint = ("The offline bundle has no package for this computer's Python version or operating system, or a package is damaged."
                if wheels else "Check the internet connection (proxy: https_proxy), or use the offline bundle.")
        raise Refused("pip_failed", f"Installing the Python packages failed ({tail}). {hint} Nothing was changed.", EXIT_FAILED)
    return py


def _summary(manifest, installed, version, schema_now):
    migs = [m for m in (manifest.get("migrations") or []) if m.get("version", 0) > schema_now]
    lines = [f"This upgrades {installed} -> {version}."]
    if migs:
        unsafe = [str(m["version"]) for m in migs if m.get("rollback_safe") is False]
        lines.append("Database migrations: " + ", ".join(f"{m['version']} ({'rollback-safe' if m.get('rollback_safe') else 'NOT rollback-safe'})" for m in migs)
                     + f"  (schema {schema_now} -> {migs[-1]['version']})")
        if unsafe:
            lines.append("  After migration " + ", ".join(unsafe) + " the previous version cannot read the data. "
                         "`--restore-previous --restore-data` then returns to the older copy of the data.")
    else:
        lines.append("No database migrations.")
    lines.append(f"The app restarts (about {manifest.get('downtime_estimate_seconds') or 60} s); your browser tab reloads when it is back.")
    return lines


# --- the upgrade -----------------------------------------------------------------------------------------


def do_upgrade(args, root, host, say):
    layout = localswap.Layout(root)
    installed = localswap.version_of(layout.current)
    work = Path(tempfile.mkdtemp(prefix="ocw-upgrade-"))
    staged = None
    try:
        located = _locate_files(args, work, say)
        wheels, offline_info = (None, None)
        if located:
            version, tarball, minisig, wheels, offline_info = located
        else:
            if args.to:
                version = args.to
                if not _VERSION_RE.match(version):   # checked before the version is used in a URL or file name
                    raise Refused("usage", "The version must look like 5.49.0.")
            else:
                say("Checking for a new release ...")
                out = service.run_check(installed, force=True, trigger=_actor(), channel=args.channel)
                if out is None or out["outcome"] == "failed":
                    raise Refused("check_failed", f"The check failed ({(out or {}).get('reason', 'busy')}). Nothing was changed. "
                                                  "Without internet access use `upgrade --from-file`.", EXIT_FAILED)
                latest = service.load()["state"]["latest_version"]
                if out["outcome"] != "update_available" or not latest:
                    say(f"You are up to date ({installed}).")
                    return EXIT_OK
                version = latest
            _refresh_revocations(say)
            tarball, minisig = _download(version, work, say)
        if not _VERSION_RE.match(version):
            raise Refused("usage", "The version must look like 5.49.0.")
        staged = layout.staged(version)
        if staged.exists():
            journal = staged / localswap.JOURNAL
            if journal.is_file() and json.loads(journal.read_text(encoding="utf-8") or "{}").get("state") in ("staging", "staged"):
                localswap.remove_tree(staged)   # our own leftover from an interrupted earlier attempt
            else:
                raise Refused("exists", f"{staged} already exists and was not made by this tool. Move or delete it and run the upgrade "
                                        "again. Nothing was changed.")
        _check_space(layout.parent, 3 * tarball.stat().st_size + 2 * ((layout.current / localswap.DB_NAME).stat().st_size
                                                                      if (layout.current / localswap.DB_NAME).exists() else 0)
                     + MIN_FREE_EXTRA, say)
        # Verification first; the unpack inside this call happens only after the signature, manifest and version passed.
        say(f"Verifying {tarball.name} against the pinned signing keys ...")
        pre = _verify_only(tarball, minisig, installed)
        _windows_path_check(staged, pre.manifest)
        argv = [str(tarball), str(minisig), "--installed-version", installed, "--audit", "--extract", str(staged)]
        rc, out, err = _capture(verifylib.main, argv)
        if rc != 0:
            localswap.remove_tree(staged)
            raise Refused("verify_failed", (err.strip().replace("ERROR: ", "") or "The release was refused.") + " Nothing was changed.")
        for line in out.splitlines():
            say("  " + line)
        localswap.write_journal(staged, state="staging", to=version, previous=installed)
        manifest = json.loads((staged / "manifest.json").read_text(encoding="utf-8"))
        if offline_info is not None:
            try:
                offline.check_lock_matches(offline_info, staged / "requirements.lock")
            except offline.BundleError as exc:
                raise Refused(exc.code, f"{exc} Nothing was changed.")
        old_has_venv = (layout.current / ".venv").is_dir()
        if old_has_venv or not _keyring_ok(sys.executable):
            py_staged = _build_environment(staged, wheels, say, host)
            py_final = venv_python(layout.current)
        else:
            py_staged = py_final = Path(sys.executable)
            say("Using the Python packages already installed for this interpreter (no .venv in the current folder).")
        ok, detail = localswap.smoke_test(staged, py_staged, version, migrate=False)
        if not ok:
            raise Refused("smoke_failed", f"The new version does not start on this computer ({detail}). Nothing was changed.", EXIT_FAILED)
        localswap.write_journal(staged, state="staged", to=version, previous=installed)
        try:
            schema_now = localswap.db_schema_version(layout.current)
        except sqlite3.Error as exc:
            raise Refused("db_unreadable", f"The archive database in the current folder cannot be read ({exc}), so it cannot be copied safely. "
                                           "Nothing was changed. Repair or restore audit_store.db first.", EXIT_FAILED)
        say("")
        for line in _summary(manifest, installed, version, schema_now):
            say(line)
        say("Your settings and archive are copied (not moved) into the new folder; the current folder is kept as "
            f"{layout.previous.name}.")
        if layout.previous.exists():
            say(f"The older previous copy ({localswap.version_of(layout.previous) or 'unknown version'}) in {layout.previous.name} is deleted once the new version runs.")
        say("Local mode has no sign-in, so there is no MFA for this: confirm by typing the version. Everything is signed, verified and "
            "logged (actor: local operator).")
        confirm_typed(host, version, args.confirm, say, f"Type {version} to confirm: ")
        if host.port_in_use(args.port):
            say(f"The dashboard is running on port {args.port}.")
            if not host.stop_server(args.port):
                raise Refused("running", "Stop the dashboard (Ctrl+C in its window) and run the upgrade again. Nothing was changed.")
        say("Copying your data ...")
        keep, clash = localswap.user_csv_templates(layout.current, staged)
        try:
            localswap.copy_data(layout.current, staged, say=say)
        except localswap.SwapError as exc:
            raise Refused(exc.code, str(exc), EXIT_FAILED)
        for name in clash:
            say(f"Note: {name} is also shipped by the new release; the release's copy was used. Yours stays in {layout.previous.name}.")
        others = localswap.other_untracked(layout.current, staged, {n for n, _ in localswap.data_candidates(layout.current)} | set(keep))
        if others:
            say("Not carried over (kept in the previous folder): " + ", ".join(others[:12]) + (" ..." if len(others) > 12 else ""))
        if not localswap.is_windows():
            try:
                os.chmod(staged, os.stat(layout.current).st_mode & 0o7777)
            except OSError:
                pass
        user = _actor()
        details = {"from": installed, "to": version, "signed": True, "channel": args.channel or service.effective_channel(service.load())[0],
                   "source": "offline_file" if args.from_file else "download", "migrations_from_schema": schema_now}
        plan = {"kind": "upgrade", "root": str(layout.current), "staged": str(staged), "version": version, "from_version": installed,
                "python": str(py_final),
                "events": [{"actor": user, "action": "upgrade.local_completed", "details": {**details, "via": "launch.py"}}]}
        _audit_here("upgrade.local_started", details)
        if localswap.is_windows() and os.environ.get(REEXEC_ENV) == "1":
            localswap.plan_path(layout).write_text(json.dumps(plan), encoding="utf-8")
            return EXIT_SWAP_PENDING
        return _finish(plan, say)
    except Refused as exc:
        if staged is not None and (staged / localswap.JOURNAL).is_file():
            localswap.remove_tree(staged)
        _audit_here("upgrade.local_failed", {"reason": exc.code, "message": str(exc)[:300], "from": installed})
        say(f"ERROR: {exc}")
        return exc.exit_code
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _verify_only(tarball, minisig, installed):
    try:
        return verifylib.verify_release(str(tarball), str(minisig), keylib.effective_key_list(), installed)
    except (verifylib.VerifyError, keylib.KeyListError) as exc:
        _audit_here("upgrade.verify_failed", {"reason": getattr(exc, "code", "failed"), "file": tarball.name, "message": str(exc)[:300]})
        raise Refused(getattr(exc, "code", "verify_failed"), f"{exc} Nothing was changed.")


def _finish(plan, say):
    return localswap.execute_plan(plan, say)


# --- restore / discard / status --------------------------------------------------------------------------


def do_restore(args, root, host, say):
    layout = localswap.Layout(root)
    if not layout.current.is_dir():
        if localswap.recover(layout, say):
            say(f"Done. Start it from {layout.current}.")
            return EXIT_OK
    if not layout.previous.is_dir():
        say("There is no previous version to restore.")
        return EXIT_REFUSED
    prev_v, cur_v = localswap.version_of(layout.previous), localswap.version_of(layout.current)
    if layout.current.is_dir():
        say(f"Restore: current {cur_v} ({layout.current})  ->  previous {prev_v} ({layout.previous.name})")
        if args.restore_data:
            say("The previous version comes back with ITS OWN older copy of the data: everything recorded since the upgrade stays in "
                f"{layout.base}-replaced-{cur_v}.")
        else:
            ok, reason = localswap.restore_compat(layout.current, layout.previous)
            say("Code only: your current data is kept" + (f" ({reason})." if ok else "."))
            if not ok:
                say(f"ERROR: Code-only restore is not possible: {reason}. Use `--restore-data` to also bring back the older data, or stay on {cur_v}.")
                return EXIT_REFUSED
        confirm_typed(host, "RESTORE", args.confirm, say, "Type RESTORE to confirm: ")
        if host.port_in_use(args.port) and not host.stop_server(args.port):
            say("Stop the dashboard (Ctrl+C in its window) and run this again. Nothing was changed.")
            return EXIT_REFUSED
    events = [{"actor": _actor(), "action": "upgrade.local_restored",
               "details": {"from": cur_v, "to": prev_v, "data": "previous_copy" if args.restore_data else "kept", "via": "launch.py"}}]
    if localswap.is_windows() and os.environ.get(REEXEC_ENV) == "1" and layout.current.is_dir():
        localswap.plan_path(layout).write_text(json.dumps({"kind": "restore", "root": str(layout.current), "restore_data": args.restore_data,
                                                 "events": events}), encoding="utf-8")
        return EXIT_SWAP_PENDING
    code, message = localswap.restore_previous(layout, restore_data=args.restore_data, events=events)
    say(message)
    return code


def do_discard(args, root, host, say):
    layout = localswap.Layout(root)
    if not layout.previous.is_dir():
        say("There is no previous version to delete.")
        return EXIT_REFUSED
    say(f"This permanently deletes {layout.previous} (version {localswap.version_of(layout.previous) or 'unknown'}), including its own copies of "
        "your settings and archive (the current folder has its own). It cannot be undone.")
    confirm_typed(host, "DELETE", args.confirm, say, "Type DELETE to confirm: ")
    code, message = localswap.discard_previous(layout)
    say(message)
    return code


def do_status(args, root, say):
    layout = localswap.Layout(root)
    s = service.status(service.load(), localswap.version_of(layout.current))
    info = {"installed": localswap.version_of(layout.current), "folder": str(layout.current),
            "previous": localswap.version_of(layout.previous) if layout.previous.is_dir() else None,
            "previous_folder": str(layout.previous) if layout.previous.is_dir() else None,
            "channel": s["check"]["channel"], "update_check": s["check"]["frequency"], "share_version": s["check"]["share_version"],
            "latest_seen": (s["latest"] or {}).get("version"), "update_available": s["update_available"]}
    if args.json:
        say(json.dumps(info, indent=2))
        return EXIT_OK
    say(f"Installed      {info['installed']}   ({info['folder']})")
    say(f"Previous       {info['previous'] + '   (' + info['previous_folder'] + ')' if info['previous'] else 'none kept'}")
    say(f"Channel        {info['channel']}")
    say(f"Update check   {info['update_check'] or 'not set (nothing is sent unless you run `upgrade --check`)'}")
    say(f"Latest seen    {info['latest_seen'] or 'none yet'}" + ("   (newer than installed)" if info["update_available"] else ""))
    return EXIT_OK


# --- entry -----------------------------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(prog="python launch.py upgrade", description="Guided, verified upgrade of this local install.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="look for a newer signed release and say what is new (no changes)")
    g.add_argument("--to", metavar="X.Y.Z", help="install this version (default: the newest on the channel)")
    g.add_argument("--from-file", nargs="+", metavar="FILE",
                   help="install from files you brought: ocw-X.Y.Z-offline.tar.gz, or ocw-X.Y.Z.tar.gz and its .minisig")
    g.add_argument("--restore-previous", action="store_true", help="bring the previous version back (typed confirmation)")
    g.add_argument("--discard-previous", action="store_true", help="delete the kept previous version (typed confirmation)")
    g.add_argument("--status", action="store_true", help="show installed / previous versions and the channel")
    p.add_argument("--channel", choices=service.CHANNELS, help="for this run only: stable or prerelease (the saved setting is `python -m server.updater set-channel`)")
    p.add_argument("--restore-data", action="store_true", help="with --restore-previous: also bring back the previous folder's older data")
    p.add_argument("--confirm", metavar="TEXT", help="the typed confirmation (the version, RESTORE or DELETE), for scripts")
    p.add_argument("--port", type=int, default=8766, help="the dashboard port, to detect a running dashboard (default 8766)")
    p.add_argument("--json", action="store_true", help="with --check or --status: machine-readable output")
    return p


def main(argv, root, host=None, say=print):
    args = build_parser().parse_args(argv)   # usage errors exit 2
    host = host or Host()
    root = Path(root)
    try:
        if os.environ.get("DEPLOYMENT_MODE", "local") == "hosted" or root.parent.name == "releases":
            raise Refused("hosted", "This computer runs the hosted layout. Upgrade it with `ocw-updater` or server/deploy.sh --release "
                                    "(README, 'Upgrading'); the guided local upgrade is for launch.py installs.")
        if not localswap.version_of(root):
            raise Refused("not_install", f"{root} does not look like an OPA Compliance Wizard folder.")
        layout = localswap.Layout(root)
        if args.status:
            return do_status(args, root, say)
        if args.restore_previous:
            return do_restore(args, root, host, say)
        if args.discard_previous:
            return do_discard(args, root, host, say)
        if root.resolve() != layout.current.resolve():
            raise Refused("wrong_folder", f"You are running this from {root.name}. Run it from {layout.current.name} instead "
                                          f"(or use --restore-previous to bring {root.name} back).")
        if not os.access(layout.parent, os.W_OK):
            raise Refused("not_writable", f"{layout.parent} is not writable, so the new version cannot be unpacked next to the current one.",
                          EXIT_FAILED)
        localswap.recover(layout, say)
        if args.check:
            return do_check(args, root, say)
        return do_upgrade(args, root, host, say)
    except Refused as exc:
        say(f"ERROR: {exc}")
        return exc.exit_code
    except localswap.SwapError as exc:
        say(f"ERROR: {exc}")
        return EXIT_FAILED if exc.rolled_back else EXIT_OPERATOR
