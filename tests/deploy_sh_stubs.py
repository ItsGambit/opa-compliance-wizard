"""Stand-ins for the system commands server/deploy.sh calls, for
tests/test_deploy_sh.py (TEST-10, OPS-02/06/09/10/11).

Each stub is a tiny sh wrapper in a temp bin directory that runs
`python deploy_sh_stubs.py <name> <args...>`. The stubs share one JSON state
file (DEPLOY_STUB_STATE) that the test sets up and reads back, and append
every call to calls.jsonl next to it. Nothing here touches the real system:
git clones only file:// URLs (a local fixture tree), sudo runs only the
allow-listed commands and only through these stubs (or the real `cp` on
temp files), systemctl/nginx/curl/npm/npx answer from the state file.
"""

import fcntl
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys

STATE_PATH = os.environ["DEPLOY_STUB_STATE"]


def _load():
    with open(STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _save(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_PATH)


def _record(name, argv):
    with open(os.path.join(os.path.dirname(STATE_PATH), "calls.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"cmd": name, "argv": argv}) + "\n")


def _unit(state, name):
    name = name[:-len(".service")] if name.endswith(".service") else name
    return name, state["units"].get(name)


def systemctl(state, argv):
    words = [a for a in argv if not a.startswith("-")]
    props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    words = [w for w in words if w not in props]
    cmd, rest = words[0], words[1:]
    if cmd == "cat":
        return 0 if _unit(state, rest[0])[1] is not None else 1
    if cmd == "list-unit-files":
        pattern = rest[0][:-len(".service")] if rest[0].endswith(".service") else rest[0]
        for name in sorted(state["units"]):
            if fnmatch.fnmatch(name, pattern):
                print(f"{name}.service enabled enabled")
        return 0
    if cmd == "is-enabled":
        unit = _unit(state, rest[0])[1]
        return 0 if unit and unit.get("enabled", True) else 1
    if cmd == "is-active":
        unit = _unit(state, rest[0])[1]
        return 0 if unit and unit.get("ActiveState", "active") == "active" else 3
    if cmd == "show":
        name, unit = _unit(state, rest[0])
        if name == "systemd-journald":
            unit = {"NeedDaemonReload": state.get("journald_need_reload", "no")}
        unit = unit or {}
        if "NRestarts" in props and "crash_after_shows" in unit:
            # crashes a while after the restart: later NRestarts reads see it
            unit["nr_shows"] = unit.get("nr_shows", 0) + 1
            if unit["nr_shows"] > unit["crash_after_shows"]:
                unit["NRestarts"], unit["ActiveState"] = "1", "activating"
        defaults = {"NeedDaemonReload": "no", "FragmentPath": "", "MainPID": "0", "NRestarts": "0",
                    "ActiveState": "inactive", "ExecStart": "", "EnvironmentFiles": ""}
        for prop in props:
            print(unit.get(prop, defaults.get(prop, "")))
        return 0
    if cmd == "status":
        print(f"* {rest[0]} - stub status")
        return 0
    if cmd == "restart":
        name, unit = _unit(state, rest[0])
        if unit is None:
            return 5
        state.setdefault("restarted", []).append(name)
        if unit.get("restart_rc", 0):
            return unit["restart_rc"]
        if not unit.get("keep_pid"):
            unit["MainPID"] = str(int(unit.get("MainPID", "0")) + 1000)
        unit["NRestarts"] = str(unit.get("nrestarts_after_restart", 0))
        unit["ActiveState"] = unit.get("state_after_restart", "active")
        if name in ("opa-secrets-wizard", "opa-compliance-wizard"):
            state["backend_version"] = state.get("version_after_restart", state.get("backend_version"))
        return 0
    if cmd == "reload" and rest == ["nginx"]:
        state.setdefault("nginx_reloads", 0)
        state["nginx_reloads"] += 1
        return state.get("nginx_reload_rc", 0)
    print(f"systemctl stub: unhandled {argv}", file=sys.stderr)
    return 64


def nginx(state, argv):
    if argv == ["-t"]:
        results = state.setdefault("nginx_t_results", [])
        rc = results.pop(0) if results else 0
        print("nginx: configuration file test is successful" if rc == 0 else "nginx: [emerg] stub failure")
        return rc
    return 64


def sudo(state, argv):
    opts = []
    while argv and argv[0].startswith("-"):
        opts.append(argv.pop(0))
    key = " ".join(argv)
    password_required = key in state.get("sudo_password_required", [])
    if "-l" in opts:
        if not argv:
            if state.get("sudo_not_allowed"):
                print("Sorry, user x is not allowed to run sudo on host.", file=sys.stderr)
                return 1
            if not state.get("sudo_list_ok", True):
                print("sudo: a password is required", file=sys.stderr)
                return 1
            return 0
        if key in state.get("sudo_allow", []) or password_required:
            if opts.count("-l") >= 2 and not state.get("sudo_path_only_listing"):
                # verbose: the matching rule (classic sudo 1.9.15+, sudoers display.c format);
                # sudo-rs and older sudo print only the command (the line below)
                print("\nSudoers entry: /etc/sudoers.d/x\n    RunAsUsers: ALL")
                if not password_required:
                    print("    Options: !authenticate")
                print("    Commands:")
            print(f"\t{key}")
            return 0
        return 1
    if password_required or key not in state.get("sudo_allow", []):
        print("sudo: a password is required", file=sys.stderr)
        return 1
    if key in state.get("sudo_fail", []):
        return 1
    if argv[0] == "systemctl":
        return systemctl(state, argv[1:])
    if argv[0] == "nginx":
        return nginx(state, argv[1:])
    if argv[0] == "cp":
        return subprocess.run(["cp", *argv[1:]]).returncode
    return 64


def git(state, argv):
    if argv[:1] == ["-C"]:
        argv = argv[2:]
        if argv == ["rev-parse", "HEAD"]:
            print(state.get("head_sha", "a" * 40))
            return 0
        if argv[:1] == ["checkout"]:
            state["checked_out"] = argv[-1]
            return state.get("checkout_rc", 0)
        return 64
    if argv[:1] == ["clone"]:
        state["clone_argv"] = argv
        url, dest = argv[-2], argv[-1]
        if not url.startswith("file://"):
            print(f"fatal: stub refuses network URL {url}", file=sys.stderr)
            return 128
        shutil.copytree(url[len("file://"):], dest, symlinks=True)
        return 0
    return 64


def npm(state, argv):
    return state.get("npm_rc", 0)


def npx(state, argv):
    if argv[:2] == ["vite", "build"]:
        if state.get("vite_rc", 0):
            return state["vite_rc"]
        out = argv[argv.index("--outDir") + 1] if "--outDir" in argv else "dist"
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as fh:
            fh.write("new build")
        return 0
    return 64


def curl(state, argv):
    url = next(a for a in argv if a.startswith("http://"))
    if url.endswith("/api/version"):
        version = state.get("backend_version")
        if version is None:
            return 7
        print(json.dumps({"version": version}))
        return 0
    m = re.match(r"http://127\.0\.0\.1:(\d+)/verify$", url)
    if m:
        sys.stdout.write(str(state.get("verify_codes", {}).get(m.group(1), "401")))
        return 0
    return 7


def pip(state, argv):
    state["pip_argv"] = argv
    return state.get("pip_rc", 0)


def sleep(state, argv):
    return 0


def flock(state, argv):
    # Only installed where the host has no util-linux flock (macOS): same
    # semantics for `flock -n <fd>` on an inherited descriptor.
    fd = int(argv[-1])
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if "-n" in argv else 0))
    except BlockingIOError:
        return 1
    return 0


def realpath(state, argv):
    # Only installed where the host realpath has no -m (macOS).
    path = [a for a in argv if a not in ("-m", "--")][0]
    print(os.path.realpath(path))
    return 0


HANDLERS = {
    "systemctl": systemctl, "nginx": nginx, "sudo": sudo, "git": git, "npm": npm, "npx": npx,
    "curl": curl, "pip": pip, "sleep": sleep, "flock": flock, "realpath": realpath,
}

# Commands whose calls don't change the state file (and may run while
# another stub holds it, e.g. flock inside deploy.sh's own lock).
_READ_ONLY = {"flock", "realpath", "sleep"}


def main():
    name, argv = sys.argv[1], sys.argv[2:]
    if name in _READ_ONLY:
        sys.exit(HANDLERS[name]({}, list(argv)))
    _record(name, list(argv))
    state = _load()
    rc = HANDLERS[name](state, list(argv))
    _save(state)
    sys.exit(rc)


if __name__ == "__main__":
    main()
