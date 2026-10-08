#!/usr/bin/env python3
"""
Cross-platform launcher for the OPA Compliance Wizard dashboard.

Checks prerequisites (Python, Node.js/npm, the `keyring` Python package,
frontend deps), offering to install/upgrade anything missing or too old via
whatever package manager the OS already has -- then builds the React
frontend (best-effort -- falls back to whatever is already in
frontend/dist/ if the build fails) and starts server/serve.py. This is the
ONLY place build/launch logic lives; the Windows .bat and Mac/Linux .sh
wrappers just call `python(3) launch.py` so there's nothing OS-specific to
keep in sync between them.

Before starting the server, also checks whether a server from a previous
run is still bound to the target port (serve.py's StrictBindHTTPServer
refuses to share a port, so a leftover process -- e.g. one left running by
a prior session, or a window that got closed without Ctrl+C -- makes every
fresh launch fail to bind before the dashboard ever opens). If one is
found, it's stopped automatically and a fresh server is started in its
place.

Usage:
    python launch.py [--port 8766] [--no-browser] [--skip-checks]
    (args other than --skip-checks are passed straight through to server/serve.py)
"""

import argparse
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
SERVER_SCRIPT = PROJECT_ROOT / "server" / "serve.py"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"

MIN_PYTHON = (3, 9)  # driven by the `keyring` dependency's own requires-python
MIN_SQLITE = (3, 35, 0)  # ALTER TABLE ... DROP COLUMN (audit_store.py migration 4); see audit_store.MIN_SQLITE_VERSION


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


# component -> manager -> list of argv lists to run in order
_INSTALL_COMMANDS = {
    "node": {
        "winget": [["winget", "install", "-e", "--id", "OpenJS.NodeJS.LTS"]],
        "brew": [["brew", "install", "node"]],
        "apt-get": [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "nodejs", "npm"]],
        "dnf": [["sudo", "dnf", "install", "-y", "nodejs", "npm"]],
        "pacman": [["sudo", "pacman", "-Sy", "--noconfirm", "nodejs", "npm"]],
        "zypper": [["sudo", "zypper", "install", "-y", "nodejs", "npm"]],
    },
    "python": {
        "winget": [["winget", "install", "-e", "--id", "Python.Python.3.13"]],
        "brew": [["brew", "install", "python@3.13"]],
        "apt-get": [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "python3"]],
        "dnf": [["sudo", "dnf", "install", "-y", "python3"]],
        "pacman": [["sudo", "pacman", "-Sy", "--noconfirm", "python"]],
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

    shown = f"v{'.'.join(map(str, version))}" if version else ("found, but version could not be determined" if node_path else "not found")
    print(f"Node.js is {'outdated' if node_path else 'missing'} ({shown}; this frontend's build tool needs "
          f"^20.19.0 or >=22.12.0).")
    if not _offer_install_or_upgrade("Node.js", "node"):
        return False

    node_path, version = _get_node_version()
    if node_path and _node_version_ok(version):
        print("Node.js is now available.")
        return True
    print("Node.js was installed/updated, but isn't visible in this session yet (common right after a "
          "fresh install, especially on Windows, since PATH changes need a new terminal to take effect).")
    print("Close this window/terminal and run the launcher again.")
    return False


def ensure_python_deps():
    """Non-fatal: missing `keyring` only breaks credential *saving*, not
    booting the dashboard (it's imported lazily, not at module load), so
    this warns and continues rather than blocking the whole launch."""
    try:
        import keyring  # noqa: F401
        return
    except ImportError:
        pass
    print("\nThe Python package 'keyring' (encrypted credential storage) isn't installed yet.")
    if _confirm(f"Install it now via 'pip install -r {REQUIREMENTS_FILE.name}'?"):
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])
    else:
        print("Skipping -- saving new environments/credentials will fail until this is installed.")


def check_prerequisites():
    print("Checking prerequisites...", flush=True)
    if not check_python():
        return False
    if not check_node():
        return False
    ensure_python_deps()
    return True


# =============================================================================
# Build / launch
# =============================================================================

def build_frontend():
    npm = shutil.which("npm")
    if not npm:
        print("npm not found on PATH -- skipping frontend build, using whatever is in frontend/dist/ already.")
        return
    print("Building React frontend...", flush=True)
    result = subprocess.run([npm, "run", "build"], cwd=str(FRONTEND_DIR))
    if result.returncode != 0:
        node_modules = FRONTEND_DIR / "node_modules"
        deps_missing = not node_modules.is_dir() or not any(node_modules.iterdir())
        if deps_missing and _confirm("Frontend dependencies aren't installed yet. Install them now with 'npm install'?"):
            subprocess.run([npm, "install"], cwd=str(FRONTEND_DIR))
            result = subprocess.run([npm, "run", "build"], cwd=str(FRONTEND_DIR))
        if result.returncode != 0:
            print("WARNING: Frontend build failed. Will use existing build if available.")


def _port_is_bound(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def _find_stale_server_pids():
    """PIDs of processes whose command line looks like this project's own
    serve.py (matched on the script's own filename, not just any process
    using the target port, so we don't touch some unrelated process that
    happens to be on the same port). Best-effort: returns [] on any
    failure rather than raising, since this is a convenience, not the
    launcher's critical path."""
    try:
        if sys.platform == "win32":
            ps_cmd = (
                "Get-CimInstance Win32_Process | "
                f"Where-Object {{ $_.CommandLine -like '*{SERVER_SCRIPT.name}*' }} | "
                "Select-Object -ExpandProperty ProcessId"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10,
            )
        else:
            result = subprocess.run(
                ["pgrep", "-f", SERVER_SCRIPT.name],
                capture_output=True, text=True, timeout=10,
            )
    except Exception:
        return []
    return [int(tok) for tok in result.stdout.split() if tok.strip().isdigit()]


def _kill_pid(pid):
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
        else:
            import os
            import signal
            os.kill(pid, signal.SIGKILL)
        return True
    except Exception as exc:
        print(f"  could not stop PID {pid}: {exc}")
        return False


def stop_stale_server(port):
    """If something is already listening on `port`, try to identify it as
    a leftover instance of this project's own server and stop it so the
    fresh launch below can bind cleanly. If the port is occupied by
    something we can't identify as ours, leave it alone and let serve.py's
    own bind-failure message explain the conflict -- safer than killing an
    unrelated process by port number alone."""
    if not _port_is_bound(port):
        return

    pids = _find_stale_server_pids()
    if not pids:
        print(f"Port {port} is already in use by something we couldn't identify as this dashboard's "
              f"own server -- leaving it alone. If the launch below fails to bind, close whatever's "
              f"using port {port} manually, or run with --port <other_port>.")
        return

    print(f"Found {len(pids)} leftover dashboard server process(es) still bound to port {port} "
          f"-- stopping before starting a fresh one...")
    for pid in pids:
        if _kill_pid(pid):
            print(f"  stopped PID {pid}")

    for _ in range(10):
        if not _port_is_bound(port):
            return
        time.sleep(0.3)
    print(f"WARNING: port {port} still appears bound after stopping the old process(es) -- "
          f"the fresh launch below may fail; a manual retry usually clears it.")


def start_server(extra_args):
    print("Starting OPA Compliance Wizard server...", flush=True)
    print("No credentials required to start -- if none are configured yet, the dashboard")
    print("itself will prompt you to set up an environment on first load.")
    print("Press Ctrl+C to stop.\n")
    try:
        subprocess.run([sys.executable, str(SERVER_SCRIPT)] + extra_args)
    except KeyboardInterrupt:
        pass


def main():
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

    if not known.skip_checks and not check_prerequisites():
        sys.exit(1)

    build_frontend()
    stop_stale_server(known.port)
    start_server(forwarded_args)


if __name__ == "__main__":
    main()
