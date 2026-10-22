"""Helpers server/install.sh calls for a fresh install (5.52.0). Standard library only; run as root, on a verified release.

    python3 -I install_helpers.py validate-server-name --name=NAME
    python3 -I install_helpers.py write-env --path P --owner USER --data-dir D --server-name N [--port N] [--revocation-url U]
    python3 -I install_helpers.py write-session-key --path P --group G
    python3 -I install_helpers.py render-site --template T --out P --server-name N --env-file E --group G [--port N]
    python3 -I install_helpers.py record-release --release-dir D --info FILE --stamp S
    python3 -I install_helpers.py check-cert --cert FILE --key FILE
    python3 -I install_helpers.py health --port N --version V [--nginx-host H --nginx-port N]

Why these are Python and not shell: the generated secrets (the proxy secret, the keyring unlock password, the internal API
secret) and the session key are made and written INSIDE this process, to a file created with its final mode, owner-only
from its first byte. They are never in a command line (`ps`, sudo's log), never in an environment variable, never printed
and never logged: no subcommand prints a secret, and none takes one as an argument.

Exit status: 0 ok; 2 refused (the message says why, and that nothing was changed); 3 failed.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TESTING = os.environ.get("OCW_INSTALL_TEST") == "1"

DNS_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
URL_RE = re.compile(r"^(https://|http://127\.0\.0\.1|http://localhost)[A-Za-z0-9._:/%~+-]+$")
REQUIRED_KEYS = ("OPA_DATA_DIR", "DEPLOYMENT_MODE", "NGINX_PROXY_SECRET", "KEYRING_UNLOCK_PASSWORD", "INTERNAL_API_SHARED_SECRET")


class Refuse(Exception):
    pass


def server_name_kind(name):
    """'dns', 'ip4' or 'ip6' for a usable server name; Refuse otherwise (no scheme, path, port, spaces or wildcards)."""
    if not name or len(name) > 253 or name != name.strip():
        raise Refuse(f"'{name}' is not a DNS name or an IP address")
    if ":" in name:
        try:
            addr = ipaddress.ip_address(name)
        except ValueError:
            raise Refuse(f"'{name}' is not a DNS name or an IP address (no scheme, port or path)")
        if addr.version != 6:
            raise Refuse(f"'{name}' is not a DNS name or an IP address")
        return "ip6"
    if re.match(r"^[0-9.]+$", name):
        try:
            ipaddress.IPv4Address(name)
        except ValueError:
            raise Refuse(f"'{name}' is not a valid IPv4 address")
        return "ip4"
    labels = name.split(".")
    if not all(DNS_LABEL.match(lbl) for lbl in labels):
        raise Refuse(f"'{name}' is not a DNS name (letters, digits and hyphens in dot-separated labels; no scheme, path, port or spaces)")
    return "dns"


def origin_for(name):
    return f"https://[{name}]" if server_name_kind(name) == "ip6" else f"https://{name}"


def _lookup(owner=None, group=None):
    """(uid, gid) for an account / group name; None parts when not asked. A missing account is an error, except in a test run."""
    import grp
    import pwd
    uid = gid = None
    try:
        if owner is not None:
            pw = pwd.getpwnam(owner)
            uid, gid = pw.pw_uid, pw.pw_gid
        if group is not None:
            gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        if TESTING:
            return None, None
        raise Refuse(f"the account or group {exc} does not exist")
    return uid, gid


def _chown(fd, uid, gid):
    if uid is None and gid is None:
        return
    try:
        os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
    except PermissionError:
        if not TESTING:
            raise


def create_private_file(path, data, mode, uid=None, gid=None, exclusive=True):
    """Create `path` (never following a link) with `data`; the file exists only with mode 0600 and root's ownership until it
    has its final owner and mode, and holds no data before then: nobody else can read it at any moment."""
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        _chown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_env_keys(text):
    """{KEY: value} of the active (uncommented) KEY=value lines; values are only compared, never printed."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


# --- subcommands --------------------------------------------------------------------------------------------------------


def cmd_validate_server_name(a):
    try:
        kind = server_name_kind(a.name)
    except Refuse as exc:
        print(f"refused: {exc}. Nothing was changed. Give the public DNS name or IP address of this server.", file=sys.stderr)
        return 2
    print(kind)
    return 0


def env_text(a, secrets_map):
    origin = origin_for(a.server_name) if a.server_name else None
    lines = [
        "# OPA Compliance Wizard settings. Written once by server/install.sh; this file is yours to edit.",
        "# It holds generated secrets: keep it readable by its owner only (mode 0600). Never paste it anywhere.",
        f"OPA_DATA_DIR={a.data_dir}",
        "DEPLOYMENT_MODE=hosted",
        f"NGINX_PROXY_SECRET={secrets_map['NGINX_PROXY_SECRET']}",
        f"KEYRING_UNLOCK_PASSWORD={secrets_map['KEYRING_UNLOCK_PASSWORD']}",
        f"INTERNAL_API_SHARED_SECRET={secrets_map['INTERNAL_API_SHARED_SECRET']}",
    ]
    if origin:
        lines += [f"EXTRA_ALLOWED_ORIGINS={origin}", f"DASHBOARD_ORIGIN={origin}"]
    if a.port and int(a.port) != 8766:
        lines.append(f"OPA_BACKEND_PORT={int(a.port)}")
    if a.revocation_url:
        if not URL_RE.match(a.revocation_url):
            raise Refuse("the revocation URL is not a plain https address")
        lines.append(f"OPA_REVOCATION_URL={a.revocation_url}")
    lines += [
        "",
        "# The login gate (opa-auth-gate) will not start until these are filled in (docs/hosting.md, steps 1-4):",
        "# OKTA_ORG_URL=https://your-org.okta.com",
        "# OKTA_OIDC_CLIENT_ID=<the Client ID of your Okta OIDC web app>",
        "# OKTA_ADMIN_GROUP_ID=<the id of the Okta group whose members administer this tool>",
        "# OKTA_ENV_NAME=default",
        "# The Okta client secret and the admin-check token do NOT go here: they go in the application's keyring",
        "# (the commands the installer printed; docs/hosting.md step 3).",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def cmd_write_env(a):
    path = a.path
    if a.server_name:
        server_name_kind(a.server_name)
    if os.path.lexists(path):
        if os.path.islink(path) or not os.path.isfile(path):
            raise Refuse(f"{path} exists and is not a regular file")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            have = parse_env_keys(fh.read())
        missing = [k for k in REQUIRED_KEYS if not have.get(k)]
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            os.chmod(path, 0o600)
            print(f"note: {path} was readable by others (mode {mode:04o}); it holds secrets, so it is now 0600")
        print(f"ok  kept the existing settings file {path} (not overwritten)")
        if missing:
            print(f"note: {path} lacks: {', '.join(missing)}. The installer never edits an existing settings file: add them by hand "
                  "(docs/hosting.md step 4; a hosted backend will not start without NGINX_PROXY_SECRET and KEYRING_UNLOCK_PASSWORD).")
        return 0
    uid, gid = _lookup(owner=a.owner)
    values = {k: secrets.token_hex(32) for k in ("NGINX_PROXY_SECRET", "KEYRING_UNLOCK_PASSWORD", "INTERNAL_API_SHARED_SECRET")}
    create_private_file(path, env_text(a, values), 0o600, uid, gid)
    print(f"ok  wrote {path} (mode 0600, owner {a.owner}); three secrets were generated in it and are not shown anywhere")
    return 0


def cmd_write_session_key(a):
    path = a.path
    if os.path.lexists(path):
        if os.path.islink(path) or not os.path.isfile(path):
            raise Refuse(f"{path} exists and is not a regular file")
        if os.path.getsize(path) < 32:
            raise Refuse(f"{path} exists but holds fewer than 32 bytes; the login gate would refuse to start. Remove it and run again")
        print(f"ok  kept the existing session key {path}")
        return 0
    _uid, gid = _lookup(group=a.group)
    create_private_file(path, os.urandom(32), 0o640, 0 if not TESTING else None, gid)
    print(f"ok  wrote the login gate's session key {path} (32 random bytes, mode 0640, group {a.group})")
    return 0


def read_env_value(path, key):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_env_keys(fh.read()).get(key)


def _with_port(text, port):
    if int(port) == 8766:
        return text
    return re.sub(r"(proxy_pass\s+http://127\.0\.0\.1:)8766\b", lambda m: m.group(1) + str(int(port)), text)


def render_site_text(template, server_name, secret, port, live=None):
    """The nginx site for this server. With `live` (an earlier site: a resumed install) the template is baked with the live
    site's values by nginx_bake, exactly as deploy.sh/updater do."""
    if live is not None:
        sys.path.insert(0, HERE)
        import nginx_bake
        baked, problems = nginx_bake.bake(live, template)
        if problems:
            raise Refuse("the nginx site that is already there cannot be updated from this release's template: " + "; ".join(problems) +
                         ". Fix it by hand (docs/hosting.md) or move it aside and run the same command again")
        return _with_port(baked, port)
    if "REPLACE_WITH_NGINX_PROXY_SECRET_VALUE" not in template or "REPLACE_WITH_SERVER_NAME" not in template:
        raise Refuse("the nginx template is not in the layout this installer knows (placeholders missing)")
    out = _with_port(template.replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", secret).replace("REPLACE_WITH_SERVER_NAME", server_name), port)
    if "REPLACE_WITH_" in out:
        raise Refuse("a placeholder is left in the nginx site")
    return out


def cmd_render_site(a):
    kind = server_name_kind(a.server_name)
    del kind
    with open(a.template, "r", encoding="utf-8") as fh:
        template = fh.read()
    secret = read_env_value(a.env_file, "NGINX_PROXY_SECRET") if os.path.exists(a.env_file) else None
    if not secret:
        raise Refuse(f"{a.env_file} has no NGINX_PROXY_SECRET, which the nginx site must carry. Add it (docs/hosting.md step 4) and run again")
    live = None
    if os.path.lexists(a.out):
        if os.path.islink(a.out) or not os.path.isfile(a.out):
            raise Refuse(f"{a.out} exists and is not a regular file")
        with open(a.out, "r", encoding="utf-8", errors="replace") as fh:
            live = fh.read()
    text = render_site_text(template, a.server_name, secret, a.port, live)
    if live is not None and text == live:
        print(f"ok  the nginx site {a.out} is already current")
        return 0
    _uid, gid = _lookup(group=a.group)
    tmp = a.out + ".new"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    create_private_file(tmp, text.encode("utf-8"), 0o640, 0 if not TESTING else None, gid)
    os.replace(tmp, a.out)
    print(f"ok  wrote the nginx site {a.out} (mode 0640, group {a.group}); it carries the proxy secret, which is not shown")
    return 0


def cmd_record_release(a):
    with open(a.info, "r", encoding="utf-8") as fh:
        info = json.load(fh)
    for key in ("version", "sha256", "key_id"):
        if not isinstance(info.get(key), str):
            raise Refuse(f"the release information file lacks '{key}'")
    if not VERSION_RE.match(info["version"]) or not re.match(r"^[0-9a-f]{64}$", info["sha256"]) or not re.match(r"^[0-9A-F]{16}$", info["key_id"]):
        raise Refuse("the release information file has malformed values")
    serial = info.get("revocation_serial_applied", 0)
    record = {"version": info["version"], "source": "get-ocw.sh", "signed": True, "sha256": info["sha256"], "key_id": info["key_id"],
              "revocation_serial": serial if isinstance(serial, int) and not isinstance(serial, bool) else 0,
              "signed_at": info.get("signed_at"), "installed_at": a.stamp}
    marker = {"version": info["version"], "sha256": info["sha256"], "key_id": info["key_id"], "staged_at": a.stamp, "verifier": "ok",
              "source": "get-ocw.sh"}
    for name, body in ((".installed-from-release", record), (".staged", marker)):
        path = os.path.join(a.release_dir, name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(body, fh, indent=2)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    print(f"ok  recorded that {info['version']} was installed from a verified release (key {info['key_id']})")
    return 0


def _openssl(args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=60)


def cmd_check_cert(a):
    if shutil.which("openssl") is None:
        print("note: openssl is not installed yet, so the certificate and key were not compared")
        return 0
    cert = _openssl(["x509", "-in", a.cert, "-noout", "-pubkey"])
    if cert.returncode != 0:
        raise Refuse(f"{a.cert} is not a readable PEM certificate")
    key = _openssl(["pkey", "-in", a.key, "-pubout", "-passin", "pass:"])
    if key.returncode != 0:
        raise Refuse(f"{a.key} is not a readable PEM private key without a passphrase (nginx cannot ask for one)")
    if hashlib.sha256(cert.stdout).digest() != hashlib.sha256(key.stdout).digest():
        raise Refuse(f"{a.cert} and {a.key} do not belong together (the certificate is for a different key)")
    print("ok  the certificate and the key belong together")
    return 0


def _get(url, host=None, context=None, timeout=3):
    request = urllib.request.Request(url, headers={"Host": host} if host else {})
    with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
        return resp.status, resp.read(65536)


def cmd_health(a):
    """0 when the backend answers /api/version as `--version` (and, with --nginx-port, /healthz through nginx answers 200 with a
    JSON status). One attempt: install.sh loops."""
    try:
        status, body = _get(f"http://127.0.0.1:{int(a.port)}/api/version")
        if status != 200 or json.loads(body.decode()).get("version") != a.version:
            return 1
        if a.nginx_port:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # loopback to our own nginx, whose certificate may be the temporary self-signed one
            status, body = _get(f"https://127.0.0.1:{int(a.nginx_port)}/healthz", host=a.nginx_host, context=ctx)
            if status != 200 or "status" not in json.loads(body.decode()):
                return 1
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        return 1
    return 0


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("validate-server-name")
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_validate_server_name)
    s = sub.add_parser("write-env")
    s.add_argument("--path", required=True)
    s.add_argument("--owner", required=True)
    s.add_argument("--data-dir", required=True)
    s.add_argument("--server-name")
    s.add_argument("--port")
    s.add_argument("--revocation-url")
    s.set_defaults(fn=cmd_write_env)
    s = sub.add_parser("write-session-key")
    s.add_argument("--path", required=True)
    s.add_argument("--group", required=True)
    s.set_defaults(fn=cmd_write_session_key)
    s = sub.add_parser("render-site")
    s.add_argument("--template", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--server-name", required=True)
    s.add_argument("--env-file", required=True)
    s.add_argument("--group", required=True)
    s.add_argument("--port", default="8766")
    s.set_defaults(fn=cmd_render_site)
    s = sub.add_parser("record-release")
    s.add_argument("--release-dir", required=True)
    s.add_argument("--info", required=True)
    s.add_argument("--stamp", required=True)
    s.set_defaults(fn=cmd_record_release)
    s = sub.add_parser("check-cert")
    s.add_argument("--cert", required=True)
    s.add_argument("--key", required=True)
    s.set_defaults(fn=cmd_check_cert)
    s = sub.add_parser("health")
    s.add_argument("--port", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--nginx-host")
    s.add_argument("--nginx-port")
    s.set_defaults(fn=cmd_health)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except Refuse as exc:
        print(f"refused: {exc}. Nothing was changed by this step.", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"failed: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
