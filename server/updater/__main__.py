"""Command line for the update check and signed releases (everything the
Updates page shows is also here, for admins who work from a shell).

    python -m server.updater status [--json]
    python -m server.updater check [--force] [--json]
    python -m server.updater enable-check | disable-check
    python -m server.updater set-channel stable|prerelease
    python -m server.updater share-version on|off
    python -m server.updater verify <tarball> <minisig> [verify options]
    python -m server.updater keys list
    python -m server.updater keys apply-revocation <revocation.json>
    python -m server.updater audit [--since 2026-01-31[T10:00:00Z]] [--correlation upg-xxxxxxxx] [--last N] [--json]

Installing, rolling back, restoring, staging and the support bundle need root
and are run through the `ocw-updater` command that server/install.sh puts on
the PATH (the same name also forwards the commands above to this module as the
application user): `ocw-updater stage | apply | cancel | rollback | restore |
bundle | clear-failure | trust ...`. Typing them here only explains that.

Exit status: 0 ok, 1 `check` found a newer release, 2 usage error,
3 failure (the message says what to do). Actions that change anything write
the same audit-log events as the app, with the actor recorded as
`cli:<operating-system user>`. Run it from the install directory with the
app's Python (`.venv/bin/python -m server.updater ...`).
"""

import argparse
import getpass
import json
import sys

from . import keys as keylib
from . import service
from . import verify as verifylib

EXIT_OK, EXIT_NEWER, EXIT_FAILURE = 0, 1, 3
AUDIT_PREFIXES = ("upgrade.", "release_keys.", "deploy.")


def _engine():
    return keylib._engine()


def _installed():
    return _engine().SCRIPT_VERSION


def _actor():
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # noqa: BLE001
        return "cli:unknown"


def _cli_audit(action, details):
    _engine().log_audit_event(_actor(), None, action, {**details, "via": "cli"}, user_agent="cli")


def _print_status(s):
    chk, last = s["check"], s["last_check"]
    print(f"Installed version : {s['installed_version']}")
    where = {"env_off": "OFF (OPA_UPDATE_CHECK=off in the environment; always wins)",
             "env_on": "ON (OPA_UPDATE_CHECK=on in the environment)",
             "setting": "ON (admin setting)" if chk["enabled"] else "OFF (admin setting)",
             "default_off": "OFF (never enabled; this is the default)"}[chk["source"]]
    print(f"Update check      : {where}")
    print(f"Release channel   : {chk['channel']}" + (" (fixed by OPA_UPDATE_CHANNEL)" if chk["channel_source"] == "env" else "")
          + ("  -- includes prereleases; set back with `set-channel stable`" if chk["channel"] == "prerelease" else ""))
    print("Share my version  : " + ("on (the installed version is added to the check's User-Agent)" if chk["share_version"] else "off (default)"))
    if chk["prompt_needed"]:
        print("                    Enable with: python -m server.updater enable-check")
    if last["at"]:
        print(f"Last check        : {last['at']} -> {last['status']} ({last['code']})")
        if last["consecutive_failures"]:
            print(f"                    {last['consecutive_failures']} failed check(s) in a row since {last['failing_since']}")
    latest = s["latest"]
    if latest:
        print(f"Latest release    : {latest['version']} (published {latest['published_at'] or 'unknown'})"
              + ("" if latest["signed_artifact"] else "  [no signed download attached]"))
        if s["update_available"]:
            print(f"                    A newer version is available. Read the release notes"
                  + (f": {latest['release_url']}" if latest["release_url"] else "") + ".")
            print(f"                    Install with: server/deploy.sh --release {latest['version']}")
    keys = s["signing_keys"]
    if keys["error"]:
        print(f"Signing keys      : PROBLEM: {keys['error']}")
    elif not keys["pinned"]:
        print("Signing keys      : none pinned yet. Signed installs (deploy.sh --release) are unavailable until the "
              "project publishes its key; nothing else is affected.")
    else:
        print(f"Signing keys      : pinned (last revocation serial {keys['serial']})")


def cmd_status(a):
    s = service.status(service.load(), _installed())
    if a.json:
        print(json.dumps(s, indent=2))
    else:
        _print_status(s)
        run = service.upgrade_run()
        if run:
            print(f"Last upgrade run  : {run['correlation_id']} {run['version_from']} -> {run['version_to']}: "
                  f"{run['result'] or 'IN PROGRESS at ' + str(run['step'])}" + (f" ({run['reason_code']})" if run["reason_code"] else ""))
            if run.get("reason_text"):
                print(f"                    {run['reason_text']} {run.get('changed') or ''} Next: {run.get('next_step') or ''}")
            print("                    Full picture and actions: sudo ocw-updater status")
    return EXIT_OK


def cmd_check(a):
    data = service.load()
    enabled, source = service.is_enabled(data)
    if source == "env_off":
        print("The update check is switched off by OPA_UPDATE_CHECK=off in the environment; nothing was sent.")
        return EXIT_OK
    if not enabled and not a.force:
        print("The update check is off, so nothing was sent. Turn it on with `enable-check`, or run a one-off "
              "check with `check --force` (recorded in the audit log).")
        return EXIT_OK
    out = service.run_check(_installed(), force=a.force, trigger=_actor())
    if out is None:
        print("Another check is already running; try again in a moment.", file=sys.stderr)
        return EXIT_FAILURE
    s = service.status(service.load(), _installed())
    if a.json:
        print(json.dumps({"result": out, "status": s}, indent=2))
    else:
        if out["outcome"] == "failed":
            print(f"The check failed: {out['reason']}. See `status`; the check retries later.", file=sys.stderr)
        else:
            _print_status(s)
    if out["outcome"] == "failed":
        return EXIT_FAILURE
    return EXIT_NEWER if out["outcome"] == "update_available" else EXIT_OK


def _set(enabled):
    status_code, body = service.change_settings(enabled, None, _installed(), _cli_audit)
    if status_code != 200:
        print(f"ERROR: {body['error']}", file=sys.stderr)
        return EXIT_FAILURE
    print(("Update check is now ON. " if enabled else "Update check is now OFF. ") +
          ("One request a day goes to GitHub; see README 'Upgrading'." if enabled else "Nothing will be sent."))
    return EXIT_OK


def _set_channel(a):
    status_code, body = service.change_settings(None, None, _installed(), _cli_audit, channel=a.channel)
    if status_code != 200:
        print(f"ERROR: {body['error']}", file=sys.stderr)
        return EXIT_FAILURE
    if a.channel == "prerelease":
        print("Release channel is now PRERELEASE: the check also offers releases the maintainers marked as prereleases. "
              "They are signed and verified like any other release, but have had less testing. Switch back with `set-channel stable`.")
    else:
        print("Release channel is now STABLE (the default). A prerelease that is already installed is never downgraded; "
              "you simply get the next stable release when it is newer.")
    return EXIT_OK


def _share_version(a):
    status_code, body = service.change_settings(None, a.state == "on", _installed(), _cli_audit)
    if status_code != 200:
        print(f"ERROR: {body['error']}", file=sys.stderr)
        return EXIT_FAILURE
    print("The update check will now include the installed version in its User-Agent." if a.state == "on" else
          "The update check no longer includes the installed version.")
    return EXIT_OK


def cmd_keys_list(_a):
    try:
        kl = keylib.effective_key_list()
    except keylib.KeyListError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    if not kl["keys"]:
        print("No release key is pinned on this install. Signed installs are unavailable until the "
              "project publishes its key.")
        return EXIT_OK
    return keylib.main(["show"])


def cmd_keys_apply(a):
    rc = keylib.main(["apply-revocation", a.revocation_json])
    return EXIT_OK if rc == 0 else EXIT_FAILURE


def cmd_verify(a):
    argv = [a.tarball, a.minisig, "--audit"] + (["--keys", a.keys] if a.keys else []) + \
        (["--installed-version", a.installed_version] if a.installed_version else []) + \
        (["--allow-same-version"] if a.allow_same_version else []) + (["--extract", a.extract] if a.extract else [])
    return EXIT_OK if verifylib.main(argv) == 0 else EXIT_FAILURE


def cmd_audit(a):
    engine = _engine()
    entries = [e for e in engine.read_audit_log(limit=5000)
               if str(e.get("action", "")).startswith(AUDIT_PREFIXES) and (not a.since or e.get("timestamp", "") >= a.since)
               and (not a.correlation or (e.get("details") or {}).get("correlation_id") == a.correlation)]
    if a.last:
        entries = entries[:a.last]  # newest first
    if a.json:
        print(json.dumps(entries, indent=2))
        return EXIT_OK
    if not entries:
        print("No upgrade-related audit events" + (f" since {a.since}" if a.since else "") + ".")
    for e in reversed(entries):
        d = e.get("details") or {}
        brief = ", ".join(f"{k}={v}" for k, v in d.items() if k != "correlation_id" and v not in (None, ""))
        print(f"{e.get('timestamp', '')[:19]}  {e['action']:34} {e.get('actor_email') or 'system':16} {brief[:140]}")
    return EXIT_OK


ROOT_COMMANDS = ("stage", "apply", "cancel", "rollback", "restore", "bundle", "clear-failure", "trust")


def cmd_root_only(a):
    print(f"`{a.cmd}` changes the installation and runs as root through the updater, not through this module.\n"
          f"Use:  sudo ocw-updater {a.cmd} ...   (installed by server/install.sh; see README 'Upgrading').\n"
          "If this server has not been migrated yet, run server/install.sh first (it prints a dry-run plan with --dry-run).",
          file=sys.stderr)
    return 2


def build_parser():
    p = argparse.ArgumentParser(prog="python -m server.updater", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("check")
    s.add_argument("--force", action="store_true", help="check even though the check is off (recorded)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_check)
    sub.add_parser("enable-check").set_defaults(fn=lambda a: _set(True))
    sub.add_parser("disable-check").set_defaults(fn=lambda a: _set(False))
    s = sub.add_parser("set-channel")
    s.add_argument("channel", choices=service.CHANNELS)
    s.set_defaults(fn=_set_channel)
    s = sub.add_parser("share-version")
    s.add_argument("state", choices=("on", "off"))
    s.set_defaults(fn=_share_version)
    s = sub.add_parser("verify")
    s.add_argument("tarball")
    s.add_argument("minisig")
    s.add_argument("--keys")
    s.add_argument("--installed-version")
    s.add_argument("--allow-same-version", action="store_true")
    s.add_argument("--extract")
    s.set_defaults(fn=cmd_verify)
    k = sub.add_parser("keys").add_subparsers(dest="keys_cmd", required=True)
    k.add_parser("list").set_defaults(fn=cmd_keys_list)
    s = k.add_parser("apply-revocation")
    s.add_argument("revocation_json")
    s.set_defaults(fn=cmd_keys_apply)
    for name in ROOT_COMMANDS:
        r = sub.add_parser(name, add_help=False)
        r.add_argument("rest", nargs="*")
        r.set_defaults(fn=cmd_root_only)
    s = sub.add_parser("audit")
    s.add_argument("--since", help="ISO date or time, e.g. 2026-01-31 or 2026-01-31T10:00:00Z")
    s.add_argument("--correlation", help="only the entries of one upgrade run, e.g. upg-7f3a9c2e")
    s.add_argument("--last", type=int, help="only the newest N entries")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)  # usage errors exit 2
    try:
        return args.fn(args)
    except (keylib.KeyListError, verifylib.VerifyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError as exc:
        print(f"ERROR: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
