"""`ocw-updater`: the operator's command line for upgrades (root-owned, stdlib only).

    ocw-updater status [--json]
    ocw-updater stage <ocw-X.Y.Z.tar.gz | X.Y.Z>        verify + stage (air-gapped: from a file)
    ocw-updater apply <X.Y.Z> [--at "YYYY-MM-DD HH:MM" [--tz ZONE]] [--yes] [--json]
    ocw-updater cancel                                    cancel a scheduled upgrade
    ocw-updater rollback                                  code-only, typed ROLLBACK
    ocw-updater restore --confirm RESTORE                 put the pre-upgrade archive copy back
    ocw-updater bundle [--correlation ID] [--include-hosts]
    ocw-updater trust list | seed | add <entry.json> | apply <revocation.json>
    ocw-updater clear-failure
    ocw-updater prune-backups --keep N | --name FILE ... --confirm PRUNE   delete old pre-upgrade copies (never the newest)

The read-only commands of the update check (check, verify, enable-check,
audit, keys list) are `python -m server.updater ...`, run as the application
user by the same `ocw-updater` wrapper. Everything here that changes anything
needs root and takes the same lock as the systemd path; `apply` writes the
same request file the in-app flow will write and follows state.json, so the
manual and in-app upgrades are one code path.

Exit status: 0 ok, 2 refused (signature, version, key, sync running, one in
flight, bad usage), 3 failed and rolled back, 4 failed and an operator is
needed. `--json` where it makes sense.
"""

import argparse
import getpass
import json
import os
import re
import sys
import time
import uuid

import ocw_activate as act
import ocw_trust

EXIT_OK, EXIT_REFUSED, EXIT_ROLLED_BACK, EXIT_OPERATOR = 0, 2, 3, 4


def _actor():
    try:
        return "cli:" + (os.environ.get("SUDO_USER") or getpass.getuser())
    except Exception:  # noqa: BLE001
        return "cli:unknown"


def _need_root(cfg):
    if os.geteuid() != 0 and not cfg.fast:
        print("This command changes the installation and must run as root: use sudo.", file=sys.stderr)
        return False
    return True


def _say(a, text=""):
    if not getattr(a, "json", False):
        print(text)


def _emit(a, rc, **data):
    """--json: one object with the exit code and what happened (every command accepts --json)."""
    if getattr(a, "json", False):
        print(json.dumps({"exit_code": rc, **data}, default=str))
    return rc


STEP_TOKENS = {
    "validated": lambda d: "received   ✓ validated",
    "downloaded": lambda d: None,
    "staged": lambda d: "staged (re-verified)",
    "preflight": lambda d: "preflight",
    "backup": lambda d: f"backup {d.get('detail', {}).get('size', 0) / 1e9:.1f} GB (integrity {d.get('detail', {}).get('integrity', '?')})"
    if d.get("detail", {}).get("size", 0) >= 1e8 else f"backup {d.get('detail', {}).get('size', 0) / 1e6:.1f} MB (integrity {d.get('detail', {}).get('integrity', '?')})",
    "switching": lambda d: "switching",
    "restarting": lambda d: f"restarting ({d.get('seconds', 0):.0f} s)",
    "health_check": lambda d: f"health {d.get('detail', {}).get('passed', '?')}/{d.get('detail', {}).get('total', '?')}",
}


def _updater(cfg, host):
    return act.Updater(cfg, host)


def _audit(cfg, host, action, details):
    up = _updater(cfg, host)
    up.st = {"correlation_id": details.get("correlation_id")}
    return up.audit(action, details, actor_email=_actor())


# --- status ------------------------------------------------------------------------------------


def collect_status(cfg):
    st = act.read_json(cfg.state_path)
    hist = []
    try:
        with open(cfg.history_path, encoding="utf-8") as fh:
            hist = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError):
        pass
    cur, prev = act.installed_version(cfg), act.link_version(cfg.previous)
    staged = []
    try:
        for d in sorted(os.listdir(cfg.staging)):
            m = act.read_json(os.path.join(cfg.staging, d, ".staged"))
            if isinstance(m, dict) and d not in (cur, prev):
                staged.append({"version": d, "sha256": m.get("sha256"), "key_id": m.get("key_id"), "staged_at": m.get("staged_at")})
    except OSError:
        pass
    cur_staged = act.read_json(os.path.join(cfg.releases, cur or "-", ".staged"), {}) or {}
    since = None
    try:
        since = act.iso(os.lstat(cfg.current).st_mtime)
    except OSError:
        pass
    sched = []
    try:
        for n in sorted(os.listdir(cfg.schedule)):
            r = act.read_json(os.path.join(cfg.schedule, n))
            if r:
                sched.append({"version": r.get("version"), "not_before": r.get("not_before"), "entered": r.get("entered"),
                              "by": r.get("actor"), "correlation_id": r.get("correlation_id")})
    except OSError:
        pass
    uc = (act.read_json(os.path.join(cfg.data, "update_check.json"), {}) or {}).get("state", {})
    try:
        trust = ocw_trust.load_trust(cfg.trust_path)
    except ocw_trust.TrustError as exc:
        trust = {"keys": [], "revoked": [], "error": str(exc)}
    backups = []
    try:
        backups = [f for f in os.listdir(cfg.backups) if f.endswith(".db")]
        bsize = sum(os.path.getsize(os.path.join(cfg.backups, f)) for f in backups)
    except OSError:
        bsize = None
    return {"installed": cur, "installed_since": since, "installed_signed_by": cur_staged.get("key_id"), "previous": prev,
            "latest": uc.get("latest_version"), "latest_checked": uc.get("last_check_at"), "staged": staged, "schedule": sched,
            "updater": {"activator": act.ACTIVATOR_VERSION, "inbox_exists": os.path.isdir(cfg.requests),
                        "stage_unit": os.path.exists("/etc/systemd/system/ocw-stage@.service")},
            "keys": [{"key_id": k["key_id"], "role": k["role"], "status": k["status"], "since": k["since"]} for k in trust["keys"]],
            "keys_error": trust.get("error"), "backups": {"count": len(backups), "bytes": bsize},
            "state": st, "last_run": hist[-1] if hist else None, "failures": act.read_json(cfg.failures_path, {})}


def cmd_status(a, cfg, host):
    s = collect_status(cfg)
    if a.json:
        print(json.dumps(s, indent=2, default=str))
        return EXIT_OK
    since = f", since {s['installed_since']}" if s["installed_since"] else ""
    signed = f", signed by {s['installed_signed_by']}" if s["installed_signed_by"] else ""
    print(f"installed      {s['installed'] or 'unknown'}   (releases/{s['installed']}{since}{signed})")
    if s["latest"]:
        print(f"latest stable  {s['latest']}   (checked {s['latest_checked'] or 'never'})")
    last_target = (s.get("state") or {}).get("version_to")
    for r in s["staged"]:
        # A tree staged by an earlier attempt stays on disk until it is applied or pruned: say so when the last run was about another version.
        earlier = f"   (staged earlier, not part of the last run: {last_target})" if last_target and last_target != r["version"] else ""
        print(f"staged         {r['version']}   verified ok, venv built, sha256 {str(r['sha256'])[:8]}…{str(r['sha256'])[-4:]}{earlier}")
    for r in s["schedule"]:
        print(f"schedule       {r['not_before']} (entered as {r['entered'] or 'UTC'}) by {r['by']}, upgrade {r['correlation_id']}")
    u = s["updater"]
    print(f"updater        {'ready' if u['inbox_exists'] and u['stage_unit'] else 'NOT READY'}    activator {u['activator']}, "
          f"ocw-stage@ template {'installed' if u['stage_unit'] else 'MISSING'}, inbox {'present' if u['inbox_exists'] else 'MISSING'}")
    if s["keys_error"]:
        print(f"keys           PROBLEM: {s['keys_error']}")
    else:
        rel = [f"{k['key_id']} {k['status']} (since {k['since']})" for k in s["keys"] if k["role"] == "release"]
        sb = [k["key_id"] for k in s["keys"] if k["role"] == "standby" and k["status"] == "active"]
        print(f"keys           primary {'; '.join(rel) or 'none'}; standby {', '.join(sb) or 'none'}")
    b = s["backups"]
    print("backups        " + (f"{b['count']} kept, {b['bytes'] / 2**30:.1f} GB  (never pruned automatically)" if b["bytes"] is not None
                              else "not readable (run as root)"))
    st = s["state"]
    if st:
        # A state with neither a result nor a step was written by a maintenance action (e.g. nginx-sync), not an upgrade run.
        res = st.get("result") or (f"IN PROGRESS at step {st.get('step')}" if st.get("step") else "no upgrade in progress")
        print(f"last run       {st.get('correlation_id')} {st.get('version_from')}→{st.get('version_to')} {res}"
              + (f" in {st['seconds']:.0f} s" if st.get("seconds") else "") + (f"  [{st['reason_code']}]" if st.get("reason_code") else ""))
        if st.get("reason_text"):
            print(f"               {st['reason_text']} {st.get('changed')} Next: {st.get('next_step')}")
        if st.get("result") == "failed_needs_operator":
            print(f"               AN OPERATOR IS NEEDED: {st.get('operator_reason')}")
        if st.get("bundle"):
            print(f"               support bundle: {st['bundle']['name']} ({st['bundle']['size'] / 1e6:.1f} MB) in {cfg.bundles}")
    fails = {v: r for v, r in (s["failures"] or {}).get("versions", {}).items() if r.get("count")}
    if fails:
        print("failures       " + ", ".join(f"{v} ({r['last_code']})" for v, r in fails.items()) + "  -> `ocw-updater clear-failure` to allow a retry")
    return EXIT_OK


# --- stage -----------------------------------------------------------------------------------------


def _drop_in_handoff(cfg, tar_path):
    """Give the operator's file to the staging step WITHOUT touching anything that account owns: root writes fresh copies
    into the root-owned handoff directory (exclusive create, no links followed, group-readable by the staging account)
    and the staging step copies them from there."""
    base = os.path.basename(tar_path)
    m = re.match(r"^ocw-(\d+\.\d+\.\d+)\.tar\.gz$", base)
    if not m:
        raise act.StepFailed("name_mismatch", f"{base} must keep its original name ocw-X.Y.Z.tar.gz")
    sig = tar_path + ".minisig"
    if not os.path.exists(sig):
        raise act.StepFailed("signature_invalid", f"{sig} is missing: bring the .minisig file next to the tarball")
    gid = _stage_gid(cfg)
    os.makedirs(cfg.handoff, mode=0o750, exist_ok=True)
    if os.geteuid() == 0:  # this directory is root's: it is created and fixed by install.sh; correct it if someone loosened it
        os.chown(cfg.handoff, 0, gid if gid is not None else 0)
        os.chmod(cfg.handoff, 0o750)
    for src in (tar_path, sig):
        dst = os.path.join(cfg.handoff, os.path.basename(src))
        act.safe_copy(src, dst, 0o640, 0 if gid is not None and os.geteuid() == 0 else None, gid)
    return m.group(1)


def _stage_gid(cfg):
    import pwd
    try:
        return pwd.getpwnam(cfg.stage_user).pw_gid
    except KeyError:
        return None


def _clear_handoff(cfg, version):
    for n in (f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig"):
        try:
            os.unlink(os.path.join(cfg.handoff, n))
        except OSError:
            pass


def cmd_stage(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    cid = "upg-" + uuid.uuid4().hex[:8]
    act._cid[0] = cid
    target = a.target
    trust = ocw_trust.load_trust(cfg.trust_path)
    installed = act.installed_version(cfg)
    try:
        if re.match(r"^\d+\.\d+\.\d+$", target):
            version = target
            ok, out = host.start(f"ocw-stage@{version}.service")
            err = act.read_json(os.path.join(cfg.artifacts, f"{version}.stage-error.json"))
            if not ok:
                raise act.StepFailed((err or {}).get("code", "stage_failed"), (err or {}).get("message") or out[-300:])
        else:
            if not os.path.isfile(target):
                raise act.StepFailed("not_staged", f"{target} does not exist")
            tar = os.path.abspath(target)
            checked = ocw_trust.verify_release(tar, tar + ".minisig", trust, installed)  # root's own check first
            version = checked["version"]
            _drop_in_handoff(cfg, tar)
            try:
                ok, out = host.start(f"ocw-stage@{version}.service")
            finally:
                _clear_handoff(cfg, version)
            err = act.read_json(os.path.join(cfg.artifacts, f"{version}.stage-error.json"))
            if not ok:
                raise act.StepFailed((err or {}).get("code", "stage_failed"), (err or {}).get("message") or out[-300:])
    except (act.StepFailed, ocw_trust.TrustError) as exc:
        code = getattr(exc, "code", "stage_failed")
        _audit(cfg, host, "upgrade.verify_failed", {"correlation_id": cid, "reason_code": code, "message": str(exc)[:300], "via": "cli"})
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    marker = act.read_json(os.path.join(cfg.staging, version, ".staged"), {}) or {}
    _audit(cfg, host, "upgrade.staged", {"correlation_id": cid, "version": version, "sha256": marker.get("sha256"),
                                        "signed_by": marker.get("key_id"), "via": "cli"})
    print(f"staged {version}: signature verified, venv built, sha256 {str(marker.get('sha256'))[:8]}…")
    print(f"next: ocw-updater apply {version}")
    return EXIT_OK


# --- apply / cancel -------------------------------------------------------------------------------------


def _summary_line(manifest, installed, version, schema_now=None):
    migs = [m for m in (manifest.get("migrations") or []) if schema_now is None or m.get("version", 0) > schema_now]
    parts = f"This upgrades {installed} → {version}"
    if migs:
        names = [str(m.get("version")) for m in migs]
        unsafe = [str(m.get("version")) for m in migs if m.get("rollback_safe") is False]
        parts += f", applies migration{'s' if len(names) > 1 else ''} {' and '.join(names)}"
        if unsafe:
            parts += f" ({', '.join(unsafe)} {'is' if len(unsafe) == 1 else 'are'} NOT rollback-safe)"
    return parts + f", ~{manifest.get('downtime_estimate_seconds') or 60} s downtime."


def _local_to_utc(text, tz):
    import calendar
    from datetime import datetime
    try:
        naive = datetime.strptime(text, "%Y-%m-%d %H:%M")
    except ValueError:
        naive = datetime.strptime(text, "%Y-%m-%dT%H:%M")
    if tz and tz.upper() != "UTC":
        try:
            from zoneinfo import ZoneInfo
            naive = naive.replace(tzinfo=ZoneInfo(tz))
            return act.iso(naive.timestamp()), f"{tz} {naive.strftime('%H:%M')}"
        except Exception:  # noqa: BLE001
            raise act.StepFailed("request_invalid", f"unknown time zone {tz!r}")
    return act.iso(calendar.timegm(naive.timetuple())), "UTC"


def _confirm(a, prompt, expected):
    if getattr(a, "confirm_text", None) == expected:
        return True
    try:
        typed = input(prompt)
    except EOFError:
        return False
    return typed.strip() == expected


def cmd_apply(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    version = a.version
    installed = act.installed_version(cfg)
    artifact = os.path.join(cfg.artifacts, f"ocw-{version}.tar.gz")
    staged_ok = os.path.isfile(os.path.join(cfg.staging, version, ".staged")) and os.path.exists(artifact)
    if not staged_ok:
        _say(a, f"{version} is not staged yet: staging it now (verify, unpack, build the environment)...")
        s = argparse.Namespace(target=version, json=a.json)
        rc = cmd_stage(s, cfg, host)
        if rc != EXIT_OK:
            return rc
    try:
        info = ocw_trust.verify_release(artifact, artifact + ".minisig", ocw_trust.load_trust(cfg.trust_path), installed, expect_version=version)
    except ocw_trust.TrustError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    snap = host.db_tool(["snapshot", cfg.db_path()])
    _say(a, _summary_line(info["manifest"], installed, version, snap.get("schema_version") if snap.get("ok") else None))
    if not _confirm(a, "Type the version to confirm: ", version):
        print("not confirmed; nothing was changed.", file=sys.stderr)
        return EXIT_REFUSED
    cid = "upg-" + uuid.uuid4().hex[:8]
    now = host.now()
    req = {"schema": 1, "action": "apply", "correlation_id": cid, "version": version, "sha256": info["sha256"], "action_id": None,
           "requested_at": act.iso(now), "not_before": None, "origin": "cli", "actor": _actor(), "trigger_kind": "cli"}
    if a.at:
        when, entered = _local_to_utc(a.at, a.tz)
        req.update(not_before=when, entered=entered, trigger_kind="schedule " + when)
        os.makedirs(cfg.schedule, exist_ok=True)
        os.chmod(cfg.schedule, 0o700)
        act.write_json_atomic(os.path.join(cfg.schedule, f"{cid}.json"), req, 0o600)
        _audit(cfg, host, "upgrade.scheduled", {"correlation_id": cid, "version": version, "sha256": info["sha256"], "when_utc": when,
                                               "entered": entered, "via": "cli"})
        host.systemctl("enable", "--now", "ocw-upgrade-due.timer")
        print(f"staged {version} (already verified)  →  scheduled for {when} ({entered})")
        return EXIT_OK
    _audit(cfg, host, "upgrade.requested", {"correlation_id": cid, "version": version, "sha256": info["sha256"], "via": "cli",
                                           "acknowledged": ["rollback is code-only"]})
    try:
        _write_request(cfg, cid, req)
    except (OSError, act.StepFailed) as exc:
        print(f"refused: cannot write the request into the inbox: {getattr(exc, 'strerror', None) or exc} (run server/install.sh)", file=sys.stderr)
        return EXIT_REFUSED
    host.systemctl("start", "--no-block", "ocw-upgrade.service")
    return follow(a, cfg, host, cid)


def _write_request(cfg, cid, req):
    """Put the request file into the application-owned inbox without trusting it: each directory on the way is opened without
    following a link (relative to the one before), its owner is checked, the file gets a random temporary name created
    exclusively, and is renamed into place within that directory."""
    import secrets
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    uid, _gid = cfg.ids()
    allowed = {0, os.geteuid()} | ({uid} if uid is not None else set())
    rel = os.path.relpath(cfg.requests, cfg.upgrade).split(os.sep)
    fd = os.open(cfg.upgrade, flags)
    try:
        for part in rel:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        if os.fstat(fd).st_uid not in allowed:
            raise act.StepFailed("request_invalid", "the request inbox belongs to an unexpected account; refusing to write into it")
        data = (json.dumps(req, indent=2, sort_keys=True, default=str)).encode("utf-8")
        tmp = f".{cid}.{secrets.token_hex(6)}.tmp"
        ffd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        with os.fdopen(ffd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, f"{cid}.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def follow(a, cfg, host, cid):
    """Print state.json steps until this correlation id reaches a result. If the updater stops without one (killed, power
    loss) say so instead of waiting for hours: it resumes by itself at boot, or by starting ocw-upgrade.service."""
    printed = set()
    waited = idle = 0
    limit = 3 * 3600
    last_seen = None
    while waited < limit:
        rej = act.read_json(os.path.join(cfg.rejections, f"{cid}.json"))
        if rej:
            print(f"refused: {rej['message']} ({rej['code']})", file=sys.stderr)
            return EXIT_REFUSED
        st = act.read_json(cfg.state_path)
        if st and st.get("correlation_id") == cid:
            for d in st.get("steps_done", []):
                if d["step"] not in printed:
                    printed.add(d["step"])
                    token = STEP_TOKENS.get(d["step"], lambda x: d["step"])(d)
                    if token and not getattr(a, "json", False):
                        print(f"✓ {token}", end="   ", flush=True)
            res = st.get("result")
            if res:
                return finish_report(a, cfg, st)
            if st.get("updated_at") == last_seen and host.unit_prop("ocw-upgrade.service", "ActiveState") not in ("active", "activating", "reloading"):
                idle += 1
            else:
                idle = 0
            last_seen = st.get("updated_at")
            if idle >= 20:
                print("The updater stopped before finishing (this upgrade is mid-way). It resumes by itself when the server boots, or now with:\n"
                      "  sudo systemctl start ocw-upgrade.service\nThen check `ocw-updater status`.", file=sys.stderr)
                return EXIT_OPERATOR
        host.sleep(1)
        waited += 1
        if cfg.fast:
            break
    print("still running; follow it with `ocw-updater status`", file=sys.stderr)
    return EXIT_OK


def finish_report(a, cfg, st):
    res = st["result"]
    if getattr(a, "json", False):
        print(json.dumps(st, indent=2, default=str))
    elif res == "completed":
        print(f"✓ completed in {st.get('seconds', 0):.0f} s")
        print(f"audit: upgrade.started … upgrade.completed  correlation={st['correlation_id']}")
    elif res == "rolled_back":
        print()
        if st.get("reason_text"):
            print(f"Rolled back to {st.get('rolled_back_to')}: {st['reason_text']} {st.get('changed')} Next: {st.get('next_step')} "
                  f"(reason code {st.get('reason_code')}; audit: upgrade.rolled_back)")
        else:  # a run recorded by an earlier release
            print(f"rolled back to {st.get('rolled_back_to')}  (reason {st.get('reason_code')}; audit: upgrade.rolled_back)")
        b = st.get("bundle")
        print(f"support bundle: {b['name'] if b else 'not created'}  (in {cfg.bundles}; download it from the Audit Log entry too)")
    elif res == "failed":
        if st.get("reason_text"):
            print(f"Refused before anything was switched: {st['reason_text']} Next: {st.get('next_step')} (reason code {st.get('reason_code')})")
            if st.get("error"):
                print(f"Detail: {st['error']}")
        else:  # a run recorded by an earlier release
            print(f"failed before anything was switched: {st.get('reason_code')} — {st.get('error')}")
    else:
        print(f"FAILED and could not be rolled back automatically: {st.get('operator_reason')}")
        print("An operator must act: see `ocw-updater status`. The previous code is still on disk.")
    return {"completed": EXIT_OK, "rolled_back": EXIT_ROLLED_BACK, "failed": EXIT_REFUSED}.get(res, EXIT_OPERATOR)


def cmd_cancel(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    n = 0
    try:
        for f in os.listdir(cfg.schedule):
            r = act.read_json(os.path.join(cfg.schedule, f), {}) or {}
            os.unlink(os.path.join(cfg.schedule, f))
            n += 1
            _audit(cfg, host, "upgrade.cancelled", {"correlation_id": r.get("correlation_id"), "version": r.get("version"), "via": "cli"})
            print(f"cancelled schedule {r.get('correlation_id')} (actor={_actor()}); staged files kept")
    except OSError:
        pass
    if not n:
        print("nothing is scheduled")
    host.systemctl("disable", "--now", "ocw-upgrade-due.timer")
    return EXIT_OK


# --- rollback / restore / bundle / clear-failure -----------------------------------------------------------------


def _locked(cfg, fn):
    fd = act.take_lock(cfg)
    if fd is None:
        print("refused: another upgrade action is running (in_flight)", file=sys.stderr)
        return EXIT_REFUSED
    try:
        return fn()
    finally:
        os.close(fd)


def cmd_rollback(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    cur, prev = act.installed_version(cfg), act.link_version(cfg.previous)
    st = act.read_json(cfg.state_path) or {}
    if not prev or prev == cur:
        print("refused: there is no previous release to roll back to.", file=sys.stderr)
        return EXIT_REFUSED
    done = act.parse_iso(st.get("updated_at"))
    if st.get("result") == "completed" and done and host.now() - done > 24 * 3600:
        print("refused: the 24-hour rollback window after the last upgrade has passed. Use `apply` with a fixed release.", file=sys.stderr)
        return EXIT_REFUSED
    schema = st.get("schema_after")
    print(f"current {cur} → previous {prev}. Schema stays at {schema if schema is not None else 'its current version'}"
          " (a code rollback never touches data). Data is not touched.")
    if not _confirm(a, "Type ROLLBACK to confirm: ", "ROLLBACK"):
        print("not confirmed; nothing was changed.", file=sys.stderr)
        return EXIT_REFUSED

    def go():
        up = _updater(cfg, host)
        res = up.rollback_action(_actor())
        print(f"✓ switched  ✓ restarted  → {res.replace('_', ' ')} to {prev}" if res == "rolled_back" else f"FAILED: {res}")
        return EXIT_OK if res == "rolled_back" else EXIT_OPERATOR
    return _locked(cfg, go)


def cmd_restore(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    if a.confirm != "RESTORE":
        print("refused: pass --confirm RESTORE. This replaces the archive with the copy taken before the last upgrade; every event "
              "archived since then disappears (the current database is moved aside, never deleted).", file=sys.stderr)
        return EXIT_REFUSED

    def go():
        up = _updater(cfg, host)
        try:
            res = up.restore_action(_actor())
        except act.StepFailed as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        print("restored: the pre-upgrade archive copy is in place (the previous database was moved aside)." if res == "restored"
              else "the restore finished but the health checks failed: see `ocw-updater status`")
        return EXIT_OK if res == "restored" else EXIT_OPERATOR
    return _locked(cfg, go)


def cmd_bundle(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED

    def go():
        up = _updater(cfg, host)
        st = act.read_json(cfg.state_path) or {}
        cid = a.correlation or st.get("correlation_id")
        same = bool(cid) and st.get("correlation_id") == cid
        # a bundle for an older run is built from a throw-away state and never written over the real one
        up.st = dict(st) if same else {"correlation_id": cid}
        info = up.make_bundle(include_hosts=a.include_hosts, correlation_id=cid, record=same, touch=False)
        if not info:
            print("could not build the bundle; see the journal", file=sys.stderr)
            return EXIT_OPERATOR
        names = {"secrets": "secrets", "headers": "cookies/headers", "tokens": "tokens", "emails": "e-mails", "sub_ids": "sub ids",
                 "hosts": "hosts/IPs", "env_names": "env names"}
        r = info["redaction"]
        print("redaction: " + ", ".join(f"{v} {names.get(k, k)}" for k, v in r.items()) + "  (see redaction-report.txt)")
        print(f"wrote {info['path']}  {info['size'] / 1e6:.1f} MB")
        print(f"sha256 {info['sha256'][:6]}…{info['sha256'][-4:]}   Email it to the address in SECURITY.md. Nothing is sent automatically.")
        return EXIT_OK
    return _locked(cfg, go)


def cmd_clear_failure(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    f = act.read_json(cfg.failures_path, {}) or {}
    cleared = sorted((f.get("versions") or {}))
    act.write_json_atomic(cfg.failures_path, {"versions": {}, "cleared_at": act.iso(host.now())})
    st = act.read_json(cfg.state_path)
    if isinstance(st, dict) and st.get("result") == "failed_needs_operator":
        st.update(result="failed", operator_cleared_at=act.iso(host.now()))  # the operator has dealt with it: new requests are allowed again
        act.write_json_atomic(cfg.state_path, st)
    _audit(cfg, host, "upgrade.clear_failure", {"cleared": cleared, "via": "cli", "correlation_id": None})
    print("failure record cleared" + (f" ({', '.join(cleared)} may be staged and applied again)" if cleared else ""))
    return EXIT_OK


def cmd_prune_backups(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    if a.confirm != "PRUNE":
        print("refused: pass --confirm PRUNE. This deletes pre-upgrade archive copies; the newest one and the one the last upgrade "
              "took are always kept.", file=sys.stderr)
        return EXIT_REFUSED
    if (a.keep is None) == (not a.name):
        print("refused: give exactly one of --keep N (keep the newest N) and --name FILE (repeatable).", file=sys.stderr)
        return EXIT_REFUSED
    req = {"confirm": a.confirm, "keep_last": a.keep, "names": list(a.name) if a.name else None}

    def go():
        up = _updater(cfg, host)
        up.st = {"correlation_id": None}
        try:
            up.validate_prune(req)
            up.prune_backups(req, _actor())
        except act.StepFailed as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        print("done: " + ", ".join(f"{n} {s / 1e6:.1f} MB" for n, s, _m in up.backup_files()) + " remain")
        return EXIT_OK
    return _locked(cfg, go)


# --- trust -------------------------------------------------------------------------------------------------------


def cmd_trust(a, cfg, host):
    if a.trust_cmd == "list":
        try:
            t = ocw_trust.load_trust(cfg.trust_path)
        except ocw_trust.TrustError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        rev = {r["key_id"]: r for r in t["revoked"]}
        for k in t["keys"]:
            r = rev.get(k["key_id"])
            role = "primary" if k["role"] == "release" else "standby"
            print(f"{role:8} {k['key_id']}  {k['status']:8} since {k['since']}" + (f"  revoked {r['revoked_at']}, signed by standby" if r else ""))
        print(f"last revocation serial applied: {t['serial']}")
        return EXIT_OK
    if not _need_root(cfg):
        return EXIT_REFUSED
    if a.trust_cmd == "seed":
        if os.path.exists(cfg.trust_path) and not a.force:
            print("trust list already exists; use --force to replace it (the revocation history is lost).", file=sys.stderr)
            return EXIT_REFUSED
        src = a.source or os.path.join(cfg.current, "server", "release_keys.json")
        try:
            with open(src, "rb") as fh:
                keys = ocw_trust.parse_key_list(fh.read())
        except (OSError, ocw_trust.TrustError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        trust = {"schema": 1, "serial": 0, "keys": keys, "revoked": []}
        if a.local_state:
            # The application's own key state (release_keys.local.json): the application account can write it, so only
            # what makes root's list STRICTER is taken from it (statuses toward revoked, revocation records). Keys that
            # exist only there (added by a past revocation) are imported only on the operator's explicit say-so.
            try:
                st = json.loads(open(a.local_state, encoding="utf-8").read(70000))
                extra = [ocw_trust._check_entry(e) for e in st.get("keys", []) if e["key_id"] not in {k["key_id"] for k in keys}]
                revoked = [{"key_id": r["key_id"], "revoked_at": r["revoked_at"], "last_good_version": r.get("last_good_version"),
                            **({"known_good": ocw_trust._check_known_good(r["known_good"])} if r.get("known_good") else {})}
                           for r in st.get("revoked", [])]
                if extra and not a.import_local_keys:
                    print("refused: this install's key state holds key(s) that are not in the release's key list ("
                          + ", ".join(e["key_id"] for e in extra) + ").\nThey came from a past revocation. Re-apply that revocation file after "
                          "installing (`ocw-updater trust apply FILE`), or, if you trust this install's key state, pass --import-local-keys.",
                          file=sys.stderr)
                    return EXIT_REFUSED
                if a.import_local_keys:
                    trust["keys"] = sorted(trust["keys"] + extra, key=lambda k: k["key_id"])
                trust["revoked"] = revoked
                trust["serial"] = int(st.get("serial", 0)) if (a.import_local_keys or not extra) else 0
                trust = ocw_trust.merge(trust, [e for e in (st.get("keys") or []) if e["key_id"] in {k["key_id"] for k in trust["keys"]}])
            except (OSError, ValueError, KeyError, TypeError, ocw_trust.TrustError) as exc:
                print(f"ERROR: cannot use the local key state {a.local_state}: {exc}", file=sys.stderr)
                return EXIT_REFUSED
        act.write_json_atomic(cfg.trust_path, trust, 0o644)
        print(f"trust list written with {len(trust['keys'])} key(s), {len(trust['revoked'])} revocation record(s), from {src}")
        return EXIT_OK
    if a.trust_cmd == "apply":
        try:
            with open(a.file, "rb") as fh:
                raw = fh.read(70000)
            t = ocw_trust.load_trust(cfg.trust_path)
            new, d = ocw_trust.apply_revocation(t, raw)
        except (OSError, ocw_trust.TrustError) as exc:
            if getattr(exc, "code", "") == "replayed":
                print(f"Nothing to do: {exc}")
                return EXIT_OK
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        act.write_json_atomic(cfg.trust_path, new, 0o644)
        _audit(cfg, host, "release_keys.revocation_applied", {**d, "source": "ocw-updater trust apply", "via": "cli", "correlation_id": None})
        print(f"Revocation applied: serial {d['from_serial']} → {d['to_serial']}. Reason: {d['reason']}")
        print("  revoked: " + (", ".join(d["revoked"]) or "none") + "   new keys: " + (", ".join(d["added"]) or "none"))
        app = _apply_to_application(cfg, host, a.file)
        print(app)
        return EXIT_OK
    if a.trust_cmd == "add":
        try:
            with open(a.file, "rb") as fh:
                entry = json.loads(fh.read(8192).decode("utf-8"))
            entry = ocw_trust._check_entry(entry)
            t = ocw_trust.load_trust(cfg.trust_path)
        except (OSError, ValueError, ocw_trust.TrustError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        if entry["role"] != "release" or entry["status"] != "active":
            print("refused: only an active RELEASE key can be added by hand (the standby changes only by a signed revocation).", file=sys.stderr)
            return EXIT_REFUSED
        if any(k["key_id"] == entry["key_id"] or k["public_key"] == entry["public_key"] for k in t["keys"]):
            print("refused: that key is already pinned.", file=sys.stderr)
            return EXIT_REFUSED
        print(f"This trusts key {entry['key_id']} to sign releases for this server. Only do this with a key from a source you trust "
              "(README: 'If the signing key is compromised').")
        if not _confirm(a, "Type TRUST to confirm: ", "TRUST"):
            print("not confirmed; nothing was changed.", file=sys.stderr)
            return EXIT_REFUSED
        t["keys"] = sorted(t["keys"] + [entry], key=lambda k: k["key_id"])
        act.write_json_atomic(cfg.trust_path, t, 0o644)
        _audit(cfg, host, "release_keys.updated", {"added": entry["key_id"], "source": "ocw-updater trust add", "via": "cli", "correlation_id": None})
        print(f"key {entry['key_id']} added.")
        return EXIT_OK
    return EXIT_REFUSED


def _apply_to_application(cfg, host, path):
    """Keep the application's own key list (used by the update check and the Updates screen) in step with root's:
    run its CLI as the application account (never as root)."""
    if not cfg.app_user:
        return "Note: run `ocw-updater keys apply-revocation FILE` too, so the application's own key list matches."
    py = os.path.join(cfg.current, ".venv", "bin", "python")
    rc, out = host.run(["runuser", "-u", cfg.app_user, "--", "env", f"OPA_DATA_DIR={cfg.data}", py, "-m", "server.updater", "keys",
                        "apply-revocation", path], timeout=120)
    return ("The application's own key list was updated too." if rc == 0 else
            "Root's list is updated, but the application's own key list was not (" + out.strip()[-120:] +
            "); run `ocw-updater keys apply-revocation FILE`.")


def cmd_nginx_sync(a, cfg, host):
    if not _need_root(cfg):
        return EXIT_REFUSED
    cid = "upg-" + uuid.uuid4().hex[:8]

    def go():
        up = _updater(cfg, host)
        cur = act.installed_version(cfg)
        up.st = {"correlation_id": cid, "version_to": cur, "version_from": cur, "manifest": {"nginx_template_changed": True, "nginx_change_required": True}}
        try:
            up.nginx_prepare()
            changed = up.nginx_apply()
        except act.StepFailed as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        up.audit("upgrade.nginx_synced", {"changed": changed, "version": cur, "via": "cli"}, actor_email=_actor())
        print("nginx site updated and reloaded (maintenance page support)." if changed else "the nginx site already matches this release's template.")
        return EXIT_OK
    return _locked(cfg, go)


# --- argument parsing ------------------------------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(prog="ocw-updater", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("stage")
    s.add_argument("target")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_stage)
    s = sub.add_parser("apply")
    s.add_argument("version")
    s.add_argument("--at")
    s.add_argument("--tz", default="UTC")
    s.add_argument("--yes", action="store_true", help="with --confirm-text: do not prompt (the text must still match)")
    s.add_argument("--confirm-text", dest="confirm_text")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_apply)
    s = sub.add_parser("cancel")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_cancel)
    s = sub.add_parser("rollback")
    s.add_argument("--json", action="store_true")
    s.add_argument("--confirm-text", dest="confirm_text")
    s.set_defaults(fn=cmd_rollback)
    s = sub.add_parser("restore")
    s.add_argument("--json", action="store_true")
    s.add_argument("--confirm")
    s.set_defaults(fn=cmd_restore)
    s = sub.add_parser("bundle")
    s.add_argument("--json", action="store_true")
    s.add_argument("--correlation")
    s.add_argument("--include-hosts", action="store_true")
    s.set_defaults(fn=cmd_bundle)
    s = sub.add_parser("clear-failure")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_clear_failure)
    s = sub.add_parser("prune-backups")
    s.add_argument("--json", action="store_true")
    s.add_argument("--keep", type=int)
    s.add_argument("--name", action="append")
    s.add_argument("--confirm")
    s.set_defaults(fn=cmd_prune_backups)
    s = sub.add_parser("nginx-sync")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_nginx_sync)
    t = sub.add_parser("trust")
    t.add_argument("--json", action="store_true")
    ts = t.add_subparsers(dest="trust_cmd", required=True)
    ts.add_parser("list")
    sd = ts.add_parser("seed")
    sd.add_argument("--source")
    sd.add_argument("--force", action="store_true")
    sd.add_argument("--local-state")
    sd.add_argument("--import-local-keys", action="store_true")
    ap = ts.add_parser("apply")
    ap.add_argument("file")
    ad = ts.add_parser("add")
    ad.add_argument("file")
    ad.add_argument("--confirm-text", dest="confirm_text")
    t.set_defaults(fn=cmd_trust)
    return p


JSON_SELF = ("status",)


def main(argv, cfg, host):
    try:
        a = build_parser().parse_args(argv)
    except SystemExit as e:
        return EXIT_REFUSED if e.code else EXIT_OK
    if getattr(a, "json", False) and a.cmd not in JSON_SELF:
        # --json: the human text goes to stderr; stdout carries one JSON object (the exit code and the final state, if any)
        import contextlib
        with contextlib.redirect_stdout(sys.stderr):
            rc = a.fn(a, cfg, host)
        print(json.dumps({"command": a.cmd, "exit_code": rc, "state": act.read_json(cfg.state_path)}, default=str))
        return rc
    return a.fn(a, cfg, host)
