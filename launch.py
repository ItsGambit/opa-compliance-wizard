#!/usr/bin/env python3
"""
Cross-platform launcher for the OPA Compliance Wizard dashboard.

Checks prerequisites (Python, Node.js/npm, the `keyring` Python package,
frontend deps), offering to install/upgrade anything missing or too old via
whatever package manager the OS already has -- then builds the React
frontend when its sources changed, and starts server/serve.py. This is the
ONLY place build/launch logic lives; the Windows .bat and Mac/Linux .sh
wrappers just call `python(3) launch.py` so there's nothing OS-specific to
keep in sync between them.

Python packages go into a project virtual environment (`.venv`, next to this
file) when the interpreter running the launcher doesn't already have them
(5.41.0, LNCH-02): current Debian/Ubuntu and Homebrew Pythons refuse a plain
`pip install` (PEP 668). Once `.venv` exists, the launcher re-runs itself
with it.

Before starting the server, also checks whether a server from a previous
run is still bound to the target port (serve.py's StrictBindHTTPServer
refuses to share a port). It is stopped -- after asking -- only if the
process LISTENING on that port is this checkout's own server/serve.py
(5.41.0, LNCH-01: it used to SIGKILL every process whose command line
merely contained "serve.py").

Usage:
    python launch.py [--port 8766] [--no-browser] [--skip-checks]
    (args other than --skip-checks are passed straight through to server/serve.py)
"""

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
FRONTEND_DIST_INDEX = FRONTEND_DIR / "dist" / "index.html"
SERVER_SCRIPT = PROJECT_ROOT / "server" / "serve.py"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"
VENV_DIR = PROJECT_ROOT / ".venv"
IS_WINDOWS = sys.platform == "win32"
_REEXEC_MARKER = "OPA_LAUNCHER_IN_VENV"

MIN_PYTHON = (3, 9)  # driven by the `keyring` dependency's own requires-python
MIN_SQLITE = (3, 35, 0)  # ALTER TABLE ... DROP COLUMN (audit_store.py migration 4); see audit_store.MIN_SQLITE_VERSION

# Everything the Vite build reads; the build is skipped while dist/index.html
# is newer than all of it (LNCH-03).
_FRONTEND_INPUTS = ("src", "public", "index.html", "package.json", "package-lock.json", "vite.config.ts",
                    "tsconfig.json", "tsconfig.app.json", "tsconfig.node.json")


# =============================================================================
# Prerequisite checking / guided install
# =============================================================================

def _confirm(prompt):
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def _detect_package_manager():
    """First OS-native package manager found on PATH, or None. Only ever
    used after the user has explicitly confirmed an install -- this
    function just narrows down which command to show them."""
    system = platform.system()
    if system == "Windows":
        return "winget" if shutil.which("winget") else None
    if system == "Darwin":
        return "brew" if shutil.which("brew") else None
    for mgr in ("apt-get", "dnf", "pacman", "zypper"):
        if shutil.which(mgr):
            return mgr
    return None


# component -> manager -> list of argv lists to run in order.
# pacman: `-S --needed`, never `-Sy` -- refreshing the package database
# without upgrading the system is the partial upgrade Arch documents as
# unsupported (LNCH-02); pacman asks for its own confirmation.
_INSTALL_COMMANDS = {
    "node": {
        "winget": [["winget", "install", "-e", "--id", "OpenJS.NodeJS.LTS"]],
        "brew": [["brew", "install", "node"]],
        "apt-get": [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "nodejs", "npm"]],
        "dnf": [["sudo", "dnf", "install", "-y", "nodejs", "npm"]],
        "pacman": [["sudo", "pacman", "-S", "--needed", "nodejs", "npm"]],
        "zypper": [["sudo", "zypper", "install", "-y", "nodejs", "npm"]],
    },
    "python": {
        "winget": [["winget", "install", "-e", "--id", "Python.Python.3.13"]],
        "brew": [["brew", "install", "python@3.13"]],
        "apt-get": [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "python3"]],
        "dnf": [["sudo", "dnf", "install", "-y", "python3"]],
        "pacman": [["sudo", "pacman", "-S", "--needed", "python"]],
        "zypper": [["sudo", "zypper", "install", "-y", "python3"]],
    },
}

_MANUAL_INSTALL_URL = {
    "node": "https://nodejs.org/ (LTS release)",
    "python": "https://www.python.org/downloads/",
}


def _offer_install_or_upgrade(display_name, component_key):
    """Shows the exact command(s) for the OS's own package manager and asks
    before running anything. Returns True only if something was actually
    run (not whether it worked -- callers re-check the real version/
    presence afterward, since that's the only reliable signal)."""
    manager = _detect_package_manager()
    if not manager:
        print(f"Could not find a supported package manager (winget/brew/apt-get/dnf/pacman/zypper) "
              f"to install {display_name} automatically.")
        print(f"Please install it manually from {_MANUAL_INSTALL_URL[component_key]}, then run this launcher again.")
        return False

    commands = _INSTALL_COMMANDS[component_key].get(manager)
    if not commands:
        print(f"No known install command for {display_name} via {manager}.")
        print(f"Please install it manually from {_MANUAL_INSTALL_URL[component_key]}, then run this launcher again.")
        return False

    print(f"\nDetected package manager: {manager}. This would run:")
    for cmd in commands:
        print("  " + " ".join(cmd))
    if not _confirm(f"Install/upgrade {display_name} now?"):
        print(f"Skipping {display_name} -- the dashboard likely won't start correctly without it.")
        return False

    for cmd in commands:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"'{' '.join(cmd)}' exited with code {result.returncode} -- installation may not have completed.")
            return True  # still "ran something" -- caller re-checks the real state
    return True


def _get_node_version():
    """Returns (path, (major, minor, patch)) or (path, None) if found but
    unparseable, or (None, None) if not found at all."""
    node = shutil.which("node")
    if not node:
        return None, None
    try:
        out = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10)
        parts = tuple(int(p) for p in out.stdout.strip().lstrip("v").split(".")[:3])
        return node, parts
    except Exception:
        return node, None


def _node_version_ok(version):
    # Mirrors Vite 8's own engines field: "^20.19.0 || >=22.12.0"
    if version is None:
        return False
    return (20, 19, 0) <= version < (21, 0, 0) or version >= (22, 12, 0)


def _version_text(version):
    return f"v{'.'.join(map(str, version))}" if version else "version unknown"


def check_python():
    """We can't upgrade the interpreter we're already running under, so a
    successful install here still requires the user to relaunch -- there's
    no safe, portable way to re-exec into a not-yet-verified interpreter
    path across Windows/Mac/Linux package managers."""
    if sys.version_info[:2] >= MIN_PYTHON:
        # DATA-08 (external review, 2026-10-05): the interpreter's bundled
        # SQLite matters as much as the interpreter -- the schema
        # migrations need DROP COLUMN (SQLite 3.35+), and an older build
        # (e.g. a distro Python 3.9 shipped with SQLite 3.34) used to fail
        # at first start with a raw syntax error instead of this message.
        import sqlite3
        if sqlite3.sqlite_version_info < MIN_SQLITE:
            print(f"Python {'.'.join(map(str, sys.version_info[:3]))} is fine, but its bundled SQLite "
                  f"{sqlite3.sqlite_version} is below the {'.'.join(map(str, MIN_SQLITE))} this dashboard's "
                  f"database schema needs. Install a newer Python build (python.org, Homebrew, or your distro's "
                  f"newer package) whose sqlite3 module links a current SQLite, then run the launcher again.")
            return False
        return True
    current = ".".join(map(str, sys.version_info[:3]))
    needed = ".".join(map(str, MIN_PYTHON))
    print(f"Python {current} is below the minimum this dashboard needs ({needed}+, for the "
          f"`keyring` encrypted-credential-storage dependency).")
    if _offer_install_or_upgrade("Python", "python"):
        print(f"Python {needed}+ may now be installed, but this session is still running under the "
              f"old interpreter (Python {current}). Close this window/terminal and run the launcher "
              f"again so it picks up the new version.")
    return False


def check_node():
    node_path, version = _get_node_version()
    if node_path and _node_version_ok(version):
        return True

    shown = _version_text(version) if version else ("found, but version could not be determined" if node_path else "not found")
    print(f"Node.js is {'outdated' if node_path else 'missing'} ({shown}; this frontend's build tool needs "
          f"^20.19.0 or >=22.12.0).")
    if not _offer_install_or_upgrade("Node.js", "node"):
        return False

    node_path, version = _get_node_version()
    if node_path and _node_version_ok(version):
        print("Node.js is now available.")
        return True
    if node_path and version:
        # LNCH-02: the OS package manager installed a Node that is simply too
        # old (current Debian/Ubuntu LTS ship one) -- re-running would loop.
        print(f"Node.js {_version_text(version)} is installed but still too old for this frontend's build "
              f"tool (needs ^20.19.0 or >=22.12.0). Your package manager's Node.js is behind; install a "
              f"current LTS from {_MANUAL_INSTALL_URL['node']} (or NodeSource's packages on Linux), "
              f"then run the launcher again.")
        return False
    print("Node.js was installed/updated, but isn't visible in this session yet (common right after a "
          "fresh install, especially on Windows, since PATH changes need a new terminal to take effect).")
    print("Close this window/terminal and run the launcher again.")
    return False


def _venv_python():
    return VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def _keyring_importable(python):
    try:
        return subprocess.run([str(python), "-c", "import keyring"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run_child_and_exit(argv, owns_shutdown=True):
    """Windows has no exec: run `argv` as a child and exit with its status.
    The console delivers Ctrl+C to the child too, so on Ctrl+C the child gets
    10 s to finish before it is terminated (subprocess.run would kill it
    after 0.25 s); further Ctrl+Cs while waiting don't abandon it. With
    owns_shutdown=False (the outer launcher after a venv relaunch) it only
    waits: the inner launcher stops the server itself."""
    proc = subprocess.Popen(argv)
    deadline = None
    while True:
        try:
            if deadline is None:
                sys.exit(proc.wait())
            sys.exit(proc.wait(timeout=max(0.0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            if owns_shutdown and deadline is None:
                deadline = time.monotonic() + 10
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                sys.exit(proc.wait(timeout=5))
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                proc.kill()
                sys.exit(proc.wait())


def _relaunch_with(python):
    """Re-runs this launcher under `python` (the project venv) with the same
    arguments. Never returns."""
    os.environ[_REEXEC_MARKER] = "1"
    argv = [str(python), str(Path(__file__).resolve()), *sys.argv[1:]]
    sys.stdout.flush()
    if IS_WINDOWS:
        _run_child_and_exit(argv, owns_shutdown=False)
    os.execv(str(python), argv)


def _running_in_project_venv():
    # Not a comparison of interpreter paths: .venv/bin/python is a symlink to
    # the interpreter that created it, so both resolve to the same file.
    try:
        return Path(sys.prefix).resolve() == VENV_DIR.resolve()
    except OSError:
        return False


def use_project_venv_if_present():
    """If this interpreter can't import `keyring` but the project's .venv
    can, continue under the venv (a previous run created it)."""
    if os.environ.get(_REEXEC_MARKER) == "1":
        return
    try:
        import keyring  # noqa: F401
        return
    except ImportError:
        pass
    venv_python = _venv_python()
    if venv_python.exists() and not _running_in_project_venv() and _keyring_importable(venv_python):
        _relaunch_with(venv_python)


def ensure_python_deps():
    """Non-fatal: missing `keyring` only breaks credential *saving*, not
    booting the dashboard (it's imported lazily, not at module load), so
    this warns and continues rather than blocking the whole launch.

    LNCH-02: installs into a project virtual environment (.venv), not into
    whatever interpreter is running -- an "externally managed" Python
    (PEP 668: current Debian/Ubuntu, Homebrew) refuses that, and the old
    code ignored the refusal and said nothing. Every step's exit code is
    checked and the result is confirmed by importing keyring."""
    try:
        import keyring  # noqa: F401
        return
    except ImportError:
        pass
    venv_python = _venv_python()
    print("\nThe Python package 'keyring' (encrypted credential storage) isn't installed yet.")
    print(f"It will be installed into a virtual environment for this project: {VENV_DIR}")
    if not _confirm(f"Create it and run 'pip install -r {REQUIREMENTS_FILE.name}' there now?"):
        print("Skipping -- saving new environments/credentials will fail until this is installed.")
        return
    if not venv_python.exists():
        result = subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)])
        if result.returncode != 0 or not venv_python.exists():
            print("Could not create the virtual environment. On Debian/Ubuntu install the 'python3-venv' "
                  "package (sudo apt-get install python3-venv), then run the launcher again.")
            return
    result = subprocess.run([str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])
    if result.returncode != 0:
        print(f"pip exited with code {result.returncode}; the packages were not installed (see its output "
              f"above). Saving credentials will fail until this is fixed.")
        return
    if not _keyring_importable(venv_python):
        print("pip finished, but 'keyring' still can't be imported from the virtual environment.")
        return
    print("Installed. Restarting the launcher with the project's virtual environment...")
    _relaunch_with(venv_python)


def check_prerequisites():
    """Returns (ok, node_ok). A missing or too-old Node is not fatal when a
    frontend build already exists (LNCH-02): the launcher then serves it."""
    print("Checking prerequisites...", flush=True)
    if not check_python():
        return False, False
    node_ok = check_node()
    if not node_ok:
        if not FRONTEND_DIST_INDEX.is_file():
            return False, False
        print(f"Continuing with the existing frontend build in {FRONTEND_DIST_INDEX.parent} "
              f"(it can't be rebuilt without Node.js, so it may be older than the code).")
    ensure_python_deps()
    return True, node_ok


# =============================================================================
# Build / launch
# =============================================================================

def _newest_input_mtime():
    newest = 0.0
    for name in _FRONTEND_INPUTS:
        path = FRONTEND_DIR / name
        if path.is_dir():
            for sub in path.rglob("*"):
                if sub.is_file():
                    newest = max(newest, sub.stat().st_mtime)
        elif path.is_file():
            newest = max(newest, path.stat().st_mtime)
    return newest


def frontend_build_is_current():
    """True while frontend/dist/index.html is newer than every file the
    build reads (sources, config, package.json and the lockfile)."""
    if not FRONTEND_DIST_INDEX.is_file():
        return False
    return FRONTEND_DIST_INDEX.stat().st_mtime >= _newest_input_mtime()


def build_frontend(node_ok=True):
    """LNCH-03: a build is skipped when nothing it reads changed; a failed
    build is retried once after `npm ci` (the lockfile's exact deps -- a
    `git pull` that adds one used to leave node_modules short); if it still
    fails the launcher stops when there is no UI to serve, and asks before
    serving a stale one."""
    if frontend_build_is_current():
        print("Frontend build is up to date.")
        return
    npm = shutil.which("npm") if node_ok else None
    if not npm:
        if FRONTEND_DIST_INDEX.is_file():
            print("npm not available -- skipping the frontend build, using the existing one in frontend/dist/.")
            return
        print("ERROR: npm is not available and there is no frontend build (frontend/dist/index.html) "
              "to serve. Install Node.js (see above) and run the launcher again.")
        sys.exit(1)
    print("Building React frontend...", flush=True)
    result = subprocess.run([npm, "run", "build"], cwd=str(FRONTEND_DIR))
    if result.returncode != 0:
        node_modules = FRONTEND_DIR / "node_modules"
        deps_missing = not node_modules.is_dir() or not any(node_modules.iterdir())
        question = ("Frontend dependencies aren't installed yet. Install them now with 'npm ci'?" if deps_missing
                    else "The build failed -- often because dependencies changed since they were installed. "
                         "Reinstall them with 'npm ci' and try again?")
        if _confirm(question):
            if subprocess.run([npm, "ci"], cwd=str(FRONTEND_DIR)).returncode == 0:
                result = subprocess.run([npm, "run", "build"], cwd=str(FRONTEND_DIR))
    if result.returncode == 0:
        return
    if not FRONTEND_DIST_INDEX.is_file():
        print("ERROR: the frontend build failed and there is no previous build to serve "
              "(frontend/dist/index.html). See the build output above.")
        sys.exit(1)
    print("WARNING: the frontend build failed (see above). A previous build exists, but it may not match "
          "this version of the server.")
    if not _confirm("Start with the previous build anyway?"):
        sys.exit(1)


def _port_is_bound(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def _run_text(argv, timeout=10):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _linux_listening_pid(port):
    """The PID listening on 127.0.0.1/any:<port>, from /proc (no lsof
    needed): the socket's inode from /proc/net/tcp{,6}, then the process
    whose fd links to it. Only this user's processes are visible."""
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, encoding="ascii") as fh:
                next(fh)
                for line in fh:
                    fields = line.split()
                    local, state, inode = fields[1], fields[3], fields[9]
                    if state == "0A" and int(local.rsplit(":", 1)[1], 16) == port:
                        inodes.add(f"socket:[{inode}]")
        except (OSError, ValueError, IndexError, StopIteration):
            continue
    if not inodes:
        return None
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            for fd in (proc_dir / "fd").iterdir():
                if os.readlink(fd) in inodes:
                    return int(proc_dir.name)
        except OSError:
            continue
    return None


def _listening_pid(port):
    """PID of the process LISTENING on `port`, or None if it can't be told."""
    if IS_WINDOWS:
        out = _run_text(["powershell", "-NoProfile", "-Command",
                         f"(Get-NetTCPConnection -LocalPort {int(port)} -State Listen -ErrorAction SilentlyContinue"
                         f" | Select-Object -First 1).OwningProcess"])
    elif shutil.which("lsof"):
        out = _run_text(["lsof", "-nP", f"-iTCP:{int(port)}", "-sTCP:LISTEN", "-t"])
    elif sys.platform.startswith("linux"):
        return _linux_listening_pid(port)
    else:
        return None
    for token in (out or "").split():
        if token.isdigit():
            return int(token)
    return None


def _process_command_line(pid):
    """(argv list or None, command line string or None, cwd or None)."""
    if IS_WINDOWS:
        out = _run_text(["powershell", "-NoProfile", "-Command",
                         f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"])
        return None, (out or "").strip() or None, None
    proc = Path(f"/proc/{int(pid)}")
    if proc.is_dir():
        try:
            argv = [a.decode(errors="replace") for a in (proc / "cmdline").read_bytes().split(b"\0") if a]
        except OSError:
            argv = None
        try:
            cwd = os.readlink(proc / "cwd")
        except OSError:
            cwd = None
        return argv, " ".join(argv) if argv else None, cwd
    out = _run_text(["ps", "-ww", "-o", "command=", "-p", str(int(pid))])
    return None, (out or "").strip() or None, None


def _is_this_checkouts_server(argv, command_line, cwd):
    """True only if the process runs THIS checkout's server/serve.py --
    another project's serve.py, an editor with serve.py open, or `tail -f
    serve.py.log` is never a match."""
    target = str(SERVER_SCRIPT)
    if argv:
        for arg in argv[1:]:
            if not arg.endswith("serve.py"):
                continue
            path = Path(arg)
            if not path.is_absolute():
                if not cwd:
                    continue
                path = Path(cwd) / path
            try:
                if path.resolve() == SERVER_SCRIPT:
                    return True
            except OSError:
                continue
        return False
    if command_line:
        if IS_WINDOWS:
            return target.lower() in command_line.lower()
        return target in command_line
    return False


def _pid_alive(pid):
    if IS_WINDOWS:
        out = _run_text(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"])
        return bool(out) and str(int(pid)) in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_pid(pid, grace=5.0):
    """Asks the process to exit (SIGTERM / taskkill), waits up to `grace`
    seconds, and only then forces it (LNCH-01: it used to be SIGKILL
    straight away, losing an in-flight sync chunk's job state)."""
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True, timeout=10)
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"  could not stop PID {pid}: {exc}")
        return False
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
        else:
            os.kill(pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"  could not stop PID {pid}: {exc}")
        return False
    return True


def stop_stale_server(port):
    """If something is listening on `port` and it is this checkout's own
    server from an earlier run, offer to stop it so the fresh launch can
    bind. Anything else on the port is left alone -- serve.py's own
    bind-failure message then explains the conflict."""
    if not _port_is_bound(port):
        return
    pid = _listening_pid(port)
    if pid is None:
        print(f"Port {port} is already in use by something we couldn't identify -- leaving it alone. "
              f"If the launch below fails to bind, close whatever's using port {port}, or run with "
              f"--port <other_port>.")
        return
    argv, command_line, cwd = _process_command_line(pid)
    if not _is_this_checkouts_server(argv, command_line, cwd):
        print(f"Port {port} is in use by PID {pid}, which is not this folder's dashboard server -- leaving it "
              f"alone. Close it, or run with --port <other_port>.")
        return
    print(f"A dashboard server from this folder is still running on port {port} (PID {pid}), probably left "
          f"over from an earlier session.")
    if not _confirm("Stop it and start a fresh one?"):
        print("Leaving it running.")
        return
    if _stop_pid(pid):
        print(f"  stopped PID {pid}")
    for _ in range(10):
        if not _port_is_bound(port):
            return
        time.sleep(0.3)
    print(f"WARNING: port {port} still appears bound after stopping the old process -- "
          f"the fresh launch below may fail; a manual retry usually clears it.")


def start_server(extra_args):
    """LNCH-04: on Mac/Linux the launcher becomes the server (exec), so
    Ctrl+C, SIGTERM and SIGHUP reach serve.py itself and there is no parent
    left to be killed out from under it. On Windows (no exec) the server is
    a child: on Ctrl+C it gets time to shut down before being terminated.
    Either way the launcher's exit status is the server's."""
    print("Starting OPA Compliance Wizard server...", flush=True)
    print("No credentials required to start -- if none are configured yet, the dashboard")
    print("itself will prompt you to set up an environment on first load.")
    print("Press Ctrl+C to stop.\n", flush=True)
    argv = [sys.executable, str(SERVER_SCRIPT), *extra_args]
    if not IS_WINDOWS:
        os.execv(sys.executable, argv)
    _run_child_and_exit(argv)


def main():
    # LNCH-06: run from the checkout, so nothing is ever resolved relative to
    # whatever directory the launcher happened to be started from.
    os.chdir(PROJECT_ROOT)
    # Line-buffer stdout even when redirected to a file/pipe (not a TTY) --
    # otherwise our own print()s can sit in Python's block buffer while
    # subprocess calls (npm, winget, etc.) write directly to the same fd,
    # making the interleaved output appear out of chronological order.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    # --skip-checks is consumed here; everything else is still forwarded to
    # serve.py unchanged (including --port, which we also peek at below to
    # know which port to pre-check).
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--skip-checks", action="store_true")
    known, _ = parser.parse_known_args(sys.argv[1:])
    forwarded_args = [a for a in sys.argv[1:] if a != "--skip-checks"]

    use_project_venv_if_present()
    node_ok = True
    if not known.skip_checks:
        ok, node_ok = check_prerequisites()
        if not ok:
            sys.exit(1)

    build_frontend(node_ok)
    stop_stale_server(known.port)
    start_server(forwarded_args)


if __name__ == "__main__":
    main()
