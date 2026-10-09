"""Read-only host status for monitoring (optional, 5.39.0).

Serves GET /__status as JSON on a loopback port: OS, uptime, load, memory, root-disk use, the state
of a configured list of systemd services, pending apt updates (security ones counted separately),
whether a reboot is required, and this app's version. Python standard library only; no secrets in
the output and no input other than the path.

Meant to be published behind an access gate (e.g. a Cloudflare Tunnel path rule protected by
Cloudflare Access, readable with a service token), never directly. It binds 127.0.0.1 only.
Set it up with server/setup-host-status.sh.

    python3 server/host_status.py [--port 8790]
    HOST_STATUS_SERVICES="nginx opa-secrets-wizard opa-auth-gate cloudflared"   # services to report
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
UPDATES_TTL = 3600          # apt simulation is slow-ish: refresh at most hourly
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._-]{0,79}")   # never starts with "-" (an option)


# ---------------------------------------------------------------- pure parsers (tested)

def parse_os_release(text):
    """PRETTY_NAME from /etc/os-release, or ''."""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return ""


def parse_meminfo(text):
    """{'total_mb', 'available_mb', 'used_pct'} from /proc/meminfo (kB values)."""
    kb = {}
    for line in text.splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            kb[m.group(1)] = int(m.group(2))
    total, available = kb.get("MemTotal", 0), kb.get("MemAvailable", 0)
    used_pct = round(100 * (total - available) / total, 1) if total else None
    return {"total_mb": total // 1024, "available_mb": available // 1024, "used_pct": used_pct}


def parse_apt_simulation(text):
    """(pending, security) from `apt-get -s upgrade` output: one 'Inst ' line per package."""
    inst = [line for line in text.splitlines() if line.startswith("Inst ")]
    return len(inst), sum(1 for line in inst if "-security" in line)


def parse_app_version(text):
    """SCRIPT_VERSION = "x.y.z" from create_secret_folders.py, or ''."""
    m = re.search(r'^SCRIPT_VERSION\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else ""


def services_from_env(value):
    """Space-separated service names; anything that isn't a plain unit name is dropped."""
    return [s for s in (value or "").split() if _SERVICE_NAME.fullmatch(s)]


def build_unit(app_dir, user, port, services):
    """systemd unit for the status service (server/setup-host-status.sh). Runs as the app user (it
    reads the app's version file under its home) with a read-only, capability-free sandbox."""
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", app_dir):
        raise ValueError(f"bad app dir {app_dir!r}")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) or user == "root":
        raise ValueError(f"bad user {user!r}")
    if not re.fullmatch(r"[0-9]{4,5}", str(port)) or str(port) in ("8766", "8767", "8768"):
        raise ValueError(f"bad port {port!r}")
    names = services_from_env(services)
    if not names or names != services.split():
        raise ValueError(f"bad service list {services!r}")
    return f"""[Unit]
Description=OPA host status (read-only, loopback)
After=network.target

[Service]
User={user}
WorkingDirectory={app_dir}
Environment=HOST_STATUS_SERVICES="{' '.join(names)}"
ExecStart=/usr/bin/python3 {app_dir}/server/host_status.py --port {port}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
MemoryMax=64M

[Install]
WantedBy=multi-user.target
"""


def overall_state(status):
    """ok / warn / down for a status dict: down if any service isn't active, warn for a pending
    reboot, security updates, disk or memory over 90%, else ok."""
    services = status.get("services") or {}
    if any(state != "active" for state in services.values()):
        return "down"
    updates = status.get("updates") or {}
    disk, mem = status.get("disk") or {}, status.get("memory") or {}
    if (updates.get("reboot_required") or (updates.get("security") or 0) > 0
            or (disk.get("used_pct") or 0) > 90 or (mem.get("used_pct") or 0) > 90):
        return "warn"
    return "ok"


# ---------------------------------------------------------------- collection

def _read(path):
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def _service_state(name):
    try:
        out = subprocess.run(["systemctl", "show", "-p", "ActiveState", "--value", "--", name],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


_updates_cache = {"at": 0.0, "value": None}
_updates_lock = threading.Lock()


def _run_apt_simulation():
    pending = security = None
    try:
        out = subprocess.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"],
                             capture_output=True, text=True, timeout=60,
                             env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        pending, security = parse_apt_simulation(out.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    return {"pending": pending, "security": security,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _updates():
    """GATE-15 (external review, 2026-10-05): the apt simulation (up to 60 s)
    used to run with the lock held, so every concurrent request queued
    behind it. Now one request refreshes while the others answer at once
    with the previous result (or nulls on the very first run, the same
    shape as a failed check)."""
    stale = _updates_cache["value"] is None or time.time() - _updates_cache["at"] > UPDATES_TTL
    if stale and _updates_lock.acquire(blocking=False):
        try:
            if _updates_cache["value"] is None or time.time() - _updates_cache["at"] > UPDATES_TTL:
                _updates_cache["value"] = _run_apt_simulation()
                _updates_cache["at"] = time.time()
        finally:
            _updates_lock.release()
    cached = _updates_cache["value"]
    value = dict(cached) if cached is not None else {"pending": None, "security": None, "checked_at": None}
    value["reboot_required"] = Path("/var/run/reboot-required").exists()
    return value


def collect():
    uptime = _read("/proc/uptime").split()
    load = os.getloadavg()
    disk = shutil.disk_usage("/")
    status = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "os": parse_os_release(_read("/etc/os-release")),
        "kernel": os.uname().release,
        "uptime_seconds": int(float(uptime[0])) if uptime else None,
        "load": [round(x, 2) for x in load],
        "cpus": os.cpu_count(),
        "memory": parse_meminfo(_read("/proc/meminfo")),
        "disk": {"path": "/", "total_gb": round(disk.total / 1e9, 1), "free_gb": round(disk.free / 1e9, 1),
                 "used_pct": round(100 * disk.used / disk.total, 1) if disk.total else None},
        "services": {name: _service_state(name) for name in services_from_env(os.environ.get("HOST_STATUS_SERVICES"))},
        "updates": _updates(),
        "app_version": parse_app_version(_read(APP_DIR / "create_secret_folders.py")),
    }
    status["state"] = overall_state(status)
    return status


# ---------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    server_version = "host-status"
    sys_version = ""
    timeout = 30  # GATE-15: an idle connection no longer holds a thread forever

    def do_GET(self):
        if self.path.split("?", 1)[0] != "/__status":
            self.send_error(404)
            return
        body = json.dumps(collect(), separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # quiet: systemd journal only needs errors
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--print-unit", nargs=3, metavar=("APP_DIR", "USER", "SERVICES"),
                        help="print the systemd unit for setup-host-status.sh and exit")
    args = parser.parse_args()
    if args.print_unit:
        print(build_unit(args.print_unit[0], args.print_unit[1], args.port, args.print_unit[2]), end="")
        return
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
