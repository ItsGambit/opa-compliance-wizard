"""server/install.sh, fresh mode (5.52.0): the application account, lingering, the settings file with generated secrets, the two
application units with the account's real id, the nginx site and certificate, the session key, provenance, revocations, the
health check, resuming after a failure, and `--uninstall --keep-data`. Run for real against a temp directory tree with
stubbed system commands (systemctl, useradd, loginctl, getent, id, nginx, openssl, chown...). OCW_INSTALL_TEST=1 skips only
the root-only steps. Every secret value the installer generates is looked for in its output and its log: it must be in the
settings file and nowhere else."""

import http.server
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("bash"), reason="install.sh is a Linux server script")

STUB_SYSTEMCTL = r'''#!/bin/bash
echo "systemctl $*" >> "$STUB/calls"
cmd=""; props=""; rest=(); args=("$@"); i=0
while [ $i -lt ${#args[@]} ]; do
  a="${args[$i]}"
  case "$a" in
    -p) i=$((i+1)); props="${args[$i]}" ;;
    --value | --no-legend | --no-pager | -l | --quiet | --no-block) ;;
    -*) ;;
    *) if [ -z "$cmd" ]; then cmd="$a"; else rest+=("$a"); fi ;;
  esac
  i=$((i+1))
done
unit="${rest[0]:-}"; unit="${unit%.service}"
f="$OCW_UNIT_DIR/$unit.service"
mkdir -p "$STUB/state"
case "$cmd" in
  cat) [ -f "$f" ] ;;
  show)
    [ -f "$f" ] || exit 0
    case "$props" in
      FragmentPath) echo "$f" ;;
      User) sed -n 's/^User=//p' "$f" | head -n 1 ;;
      WorkingDirectory) sed -n 's/^[[:space:]]*WorkingDirectory=//p' "$f" | head -n 1 ;;
      ActiveState) cat "$STUB/state/$unit" 2>/dev/null || echo inactive ;;
      NRestarts) cat "$STUB/restarts" 2>/dev/null || echo 0 ;;
    esac ;;
  list-unit-files) for g in "$OCW_UNIT_DIR"/opa-auth-gate-*.service; do [ -f "$g" ] && echo "$(basename "$g") enabled"; done; exit 0 ;;
  stop) echo inactive > "$STUB/state/$unit"; exit 0 ;;
  start | restart)
    if [ -e "$STUB/fail_start" ] && [ "$unit" = "opa-compliance-wizard" ]; then echo failed > "$STUB/state/$unit"; else echo active > "$STUB/state/$unit"; fi
    exit 0 ;;
  *) exit 0 ;;
esac
'''
STUB_USERADD = r'''#!/bin/bash
echo "$*" >> "$STUB/useradd.args"
home=""; prev=""
for a in "$@"; do
  [ "$prev" = "--home-dir" ] && home="$a"
  prev="$a"
  last="$a"
done
mkdir -p "$STUB/users"
echo "$home" > "$STUB/users/$last"
[ -z "$home" ] || mkdir -p "$home"
exit 0
'''
STUB_ID = r'''#!/bin/bash
for last; do :; done
if [ -f "$STUB/users/$last" ]; then
  case "$1" in -u) echo 4242 ;; -gn) echo "$last" ;; *) echo "uid=4242($last) gid=4242($last)" ;; esac
  exit 0
fi
exec /usr/bin/id "$@"
'''
STUB_GETENT = r'''#!/bin/bash
db="$1"; name="$2"
if [ "$db" = "passwd" ] && [ -f "$STUB/users/$name" ]; then echo "$name:x:4242:4242::$(cat "$STUB/users/$name"):/usr/sbin/nologin"; exit 0; fi
if [ "$db" = "group" ] && [ -f "$STUB/users/$name" ]; then echo "$name:x:4242:"; exit 0; fi
if [ "$db" = "passwd" ]; then exec python3 -c 'import pwd,sys
try:
    p = pwd.getpwnam(sys.argv[1])
except KeyError:
    sys.exit(2)
print(":".join(map(str, [p.pw_name, "x", p.pw_uid, p.pw_gid, "", p.pw_dir, p.pw_shell])))' "$name"; fi
exit 2
'''
STUB_OPENSSL = r'''#!/bin/bash
echo "openssl $*" >> "$STUB/openssl.calls"
if [ "$1" = "req" ]; then
  key=""; out=""; prev=""
  for a in "$@"; do
    [ "$prev" = "-keyout" ] && key="$a"
    [ "$prev" = "-out" ] && out="$a"
    prev="$a"
  done
  [ ! -e "$STUB/openssl_fail" ] || { echo "openssl: simulated failure" >&2; exit 1; }
  printf -- '-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n' > "$key"
  printf -- '-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n' > "$out"
  exit 0
fi
exec /usr/bin/openssl "$@"
'''
STUB_NGINX = r'''#!/bin/bash
echo "nginx $*" >> "$STUB/calls"
[ "$1" = "-t" ] || exit 0
[ ! -e "$STUB/nginx_bad" ] || { echo "nginx: configuration file test failed (simulated)" >&2; exit 1; }
exit 0
'''
# runuser: -u USER -- cmd...; with FAKE_APP_DIR set, the application's own CLI (`env OPA_DATA_DIR=.. <venv python> -m server.updater ...`) runs
# from that directory with the test interpreter, as the application account would run it
STUB_RUNUSER = r'''#!/bin/bash
shift 3
if [ -n "$FAKE_APP_DIR" ] && [ "$1" = env ]; then
  envarg="$2"; shift 3; cd "$FAKE_APP_DIR" && exec env "$envarg" PYTHONPATH="$FAKE_APP_PYPATH" OPA_WIZARD_SKIP_DOTENV=1 "$FAKE_APP_PY" "$@"
fi
exec "$@"
'''
# sh: the real one, unless the test says the application account cannot run the release
STUB_SH = r'''#!/bin/bash
if [ -e "$STUB/app_cannot_run" ] && [ "$1" = "-c" ] && [[ "$2" == *"test -x"* ]]; then exit 1; fi
exec /bin/sh "$@"
'''
STUBS = {"systemctl": STUB_SYSTEMCTL, "sleep": "#!/bin/bash\nexit 0\n", "runuser": STUB_RUNUSER, "sh": STUB_SH, "useradd": STUB_USERADD,
         "userdel": '#!/bin/bash\necho "$*" >> "$STUB/userdel.args"\nexit 0\n', "loginctl": '#!/bin/bash\necho "loginctl $*" >> "$STUB/calls"\nexit 0\n',
         "id": STUB_ID, "getent": STUB_GETENT, "openssl": STUB_OPENSSL, "nginx": STUB_NGINX,
         "chown": '#!/bin/bash\necho "$@" >> "$STUB/chowns"\nexit 0\n'}

# values the test knows: if the installer ever printed or logged one of the generated secrets it would be one of these 64-hex strings
HEX64 = re.compile(r"[0-9a-f]{64}")


class Backend(http.server.BaseHTTPRequestHandler):
    version = "5.52.0"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"version": Backend.version, "status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def world(tmp_path):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    Backend.version = "5.52.0"
    w = tmp_path
    stub = w / "stub"
    (stub / "bin").mkdir(parents=True)
    for name, body in STUBS.items():
        p = stub / "bin" / name
        p.write_text(body)
        p.chmod(0o755)
    src = w / "src"
    (src / "server" / "updater").mkdir(parents=True)
    shutil.copytree(REPO / "server" / "updater" / "root", src / "server" / "updater" / "root")
    for f in ("nginx_bake.py", "release_keys.json", "ocw-stage@.service", "ocw-upgrade.path", "ocw-upgrade.service", "ocw-upgrade-due.service",
              "ocw-upgrade-due.timer", "ocw-updater.sh", "install.sh", "nginx_second_site.py", "opa-compliance-wizard.service",
              "opa-auth-gate.service", "start-headless.sh", "nginx-opa-secrets-wizard.conf", "install_helpers.py"):
        shutil.copy(REPO / "server" / f, src / "server" / f)
    (src / "server" / "serve.py").write_text("# the application\n")
    (src / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.52.0"\n')
    (src / "requirements.lock").write_text("# empty on purpose\n")
    (src / "frontend" / "dist").mkdir(parents=True)
    (src / "frontend" / "dist" / "index.html").write_text("<html>built</html>")
    unit_dir, sites, enabled, ssl_dir = w / "units", w / "nginx-sites", w / "nginx-enabled", w / "nginx-ssl"
    for d in (unit_dir, sites, enabled, w / "bin", w / "sudoers", w / "wheels", w / "etc"):
        d.mkdir()
    user = os.environ.get("USER") or os.popen("id -un").read().strip()
    answers = w / "tty-answers"
    answers.write_text("")
    env = dict(os.environ, PATH=f"{stub / 'bin'}:{os.environ['PATH']}", STUB=str(stub), OCW_INSTALL_TEST="1", OCW_TEST_MODE="1", OCW_FAST="1",
               OCW_OPT_DIR=str(w / "opt"), OCW_DATA_DIR=str(w / "var-lib"), OCW_UNIT_DIR=str(unit_dir), OCW_BIN_DIR=str(w / "bin"),
               OCW_ENV_FILE=str(w / "etc" / "opa-compliance-wizard.env"), OCW_SUDOERS_DIR=str(w / "sudoers"),
               OCW_ARTIFACTS_DIR=str(w / "var" / "ocw-updater" / "artifacts"), OCW_UPDATER_ENV=str(w / "etc" / "ocw-updater.env"),
               OCW_NGINX_SITES_DIR=str(sites), OCW_NGINX_ENABLED_DIR=str(enabled), OCW_NGINX_SSL_DIR=str(ssl_dir),
               OCW_SESSION_KEY_FILE=str(w / "etc" / "session.key"), OCW_TTY=str(answers))
    env.pop("OCW_INSTALL_LOGGING", None)

    class W:
        pass
    o = W()
    o.__dict__.update(w=w, src=src, env=env, stub=stub, user=user, port=port, answers=answers, unit_dir=unit_dir, sites=sites, enabled=enabled,
                      ssl=ssl_dir, env_file=w / "etc" / "opa-compliance-wizard.env", opt=w / "opt", data=w / "var-lib",
                      key=w / "etc" / "session.key", home=w / "var-lib" / "home")

    def run(*args, extra_env=None, answers=None, script=None, umask=None):
        if answers is not None:
            o.answers.write_text(answers)
        e = dict(env, **(extra_env or {}))
        pre = (lambda: os.umask(umask)) if umask is not None else None
        return subprocess.run(["bash", str(script or (src / "server" / "install.sh")), "--wheelhouse", str(w / "wheels"), *args],
                              capture_output=True, text=True, env=e, timeout=300, stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=pre)

    def fresh(*args, **kw):
        base = ["--yes", "--create-app-user", "--server-name", "opa.example.com", "--self-signed", "--backend-port", str(port)]
        return run(*base, *args, **kw)
    o.run, o.fresh = run, fresh
    yield o
    srv.shutdown()


def calls(world):
    f = world.stub / "calls"
    return f.read_text() if f.exists() else ""


def env_values(world):
    return dict(line.split("=", 1) for line in world.env_file.read_text().splitlines() if re.match(r"^[A-Z_]+=", line))


def mode(path):
    return stat.S_IMODE(Path(path).stat().st_mode)


def test_a_fresh_install_makes_a_working_server_and_says_what_is_left(world):
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    out = p.stdout
    for needle in ("(fresh)", "Done. OPA Compliance Wizard 5.52.0 is installed and the backend is running.", "opa-auth-gate.service (installed, not started)",
                   "self-signed certificate: your browser will warn", "1. Register the Okta OIDC web app", "DASHBOARD_ORIGIN is already set to https://opa.example.com",
                   "keyring.set_password('opa-compliance-wizard:default', 'okta_client_secret'", "XDG_RUNTIME_DIR=/run/user/4242"):
        assert needle in out, needle
    # the account: created with the right flags, lingering on
    args = (world.stub / "useradd.args").read_text()
    assert f"--user-group --create-home --home-dir {world.data}/home --shell /usr/sbin/nologin ocw" in args
    assert "loginctl enable-linger ocw" in calls(world)
    # both units are rendered with the account's real id, home and the release link; nothing hardcoded is left
    for name in ("opa-compliance-wizard.service", "opa-auth-gate.service"):
        u = (world.unit_dir / name).read_text()
        assert "XDG_RUNTIME_DIR=/run/user/4242" in u and "unix:path=/run/user/4242/bus" in u and "ReadWritePaths=/run/user/4242\n" in u
        assert f"ReadWritePaths={world.home}/.local/share/keyrings" in u and f"WorkingDirectory={world.opt}/current" in u
        assert "__APP_" not in u and "/run/user/1000" not in u.replace("# ", "").split("[Install]")[0].split("NoNewPrivileges")[1] and "User=ocw" in u
        assert f"EnvironmentFile={world.env_file}" in u
        assert mode(world.unit_dir / name) == 0o644
    assert (world.home / ".local" / "share" / "keyrings").is_dir() and mode(world.home / ".local" / "share" / "keyrings") == 0o700
    c = calls(world)
    assert "systemctl enable opa-compliance-wizard opa-auth-gate" in c and "systemctl start opa-compliance-wizard" in c
    assert "start opa-auth-gate" not in c.replace("start opa-compliance-wizard", "")      # the gate is enabled, not started
    # the release is in place and linked; the completion marker is gone
    assert (world.opt / "current").is_symlink() and (world.opt / "releases" / "5.52.0" / ".installed-from-source").exists()
    assert not (world.opt / ".fresh-install-incomplete").exists()
    cfg = json.loads((world.opt / "updater" / "config.json").read_text())
    assert cfg["app_user"] == "ocw" and cfg["backend_port"] == world.port and cfg["nginx_site"] == str(world.sites / "opa-secrets-wizard")
    assert cfg["install_sh_version"] == "5.52.0"


def test_the_settings_file_has_the_secrets_and_nothing_else_ever_shows_them(world):
    log = world.w / "install.log"
    p = world.fresh("--log", str(log))
    assert p.returncode == 0, p.stderr + p.stdout
    assert mode(world.env_file) == 0o600
    values = env_values(world)
    secrets_ = [values[k] for k in ("NGINX_PROXY_SECRET", "KEYRING_UNLOCK_PASSWORD", "INTERNAL_API_SHARED_SECRET")]
    assert all(HEX64.fullmatch(v) for v in secrets_) and len(set(secrets_)) == 3
    assert values["DEPLOYMENT_MODE"] == "hosted" and values["OPA_DATA_DIR"] == str(world.data)
    assert values["EXTRA_ALLOWED_ORIGINS"] == "https://opa.example.com" and values["DASHBOARD_ORIGIN"] == "https://opa.example.com"
    assert values["OPA_BACKEND_PORT"] == str(world.port)
    text = world.env_file.read_text()
    for line in ("# OKTA_ORG_URL=https://your-org.okta.com", "# OKTA_OIDC_CLIENT_ID=", "# OKTA_ADMIN_GROUP_ID=", "# OKTA_ENV_NAME=default"):
        assert line in text
    # no secret on stdout, stderr, the log, a command line (the stubs record the arguments of every call) or any other file
    everything = p.stdout + p.stderr + log.read_text() + calls(world) + (world.stub / "useradd.args").read_text() + (world.stub / "openssl.calls").read_text()
    for s in secrets_:
        assert s not in everything
    for path in world.w.rglob("*"):
        if path.is_file() and not path.is_symlink() and path != world.env_file and path.stat().st_size < 5_000_000 and ".venv" not in path.parts:
            try:
                data = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if path.parent == world.sites:
                continue  # the nginx site carries the proxy secret by design; checked below
            for s in secrets_:
                assert s not in data, f"a generated secret is in {path}"
    # the nginx site carries the proxy secret and nothing else generated
    site = (world.sites / "opa-secrets-wizard").read_text()
    assert values["NGINX_PROXY_SECRET"] in site and values["KEYRING_UNLOCK_PASSWORD"] not in site and values["INTERNAL_API_SHARED_SECRET"] not in site
    assert log.exists() and mode(log) == 0o600 and "Done. OPA Compliance Wizard" in log.read_text()


def test_the_nginx_site_the_certificate_and_the_session_key(world):
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    site_path = world.sites / "opa-secrets-wizard"
    site = site_path.read_text()
    assert site.count("server_name opa.example.com;") == 2 and "REPLACE_WITH" not in site
    assert f"proxy_pass http://127.0.0.1:{world.port};" in site and "127.0.0.1:8766" not in site.replace("# ", "").split("set $nginx_proxy_secret")[1]
    assert "ssl_certificate /etc/nginx/ssl/opa-secrets-wizard.crt;" in site
    assert mode(site_path) == 0o640
    link = world.enabled / "opa-secrets-wizard"
    assert link.is_symlink() and os.readlink(link) == str(site_path)
    c = calls(world)
    assert c.index("nginx -t") < c.index("systemctl reload nginx")
    # self-signed: openssl was asked for exactly the documented certificate, with the name in the SAN
    req = (world.stub / "openssl.calls").read_text()
    assert "req -x509 -newkey rsa:2048 -nodes -days 825 -subj /CN=opa.example.com -addext subjectAltName=DNS:opa.example.com" in req
    assert f"-keyout {world.ssl}/opa-secrets-wizard.key -out {world.ssl}/opa-secrets-wizard.crt" in req
    assert mode(world.ssl) == 0o700 and mode(world.ssl / "opa-secrets-wizard.key") == 0o600
    # the session key: 32 random bytes, 0640
    assert world.key.stat().st_size == 32 and mode(world.key) == 0o640
    # the distribution's default site is left alone
    assert not (world.enabled / "default").exists()


def test_an_ip_address_gets_an_ip_san_and_ipv6_gets_brackets_in_the_origin(world):
    p = world.fresh("--server-name", "192.0.2.10")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "subjectAltName=IP:192.0.2.10" in (world.stub / "openssl.calls").read_text()
    assert env_values(world)["DASHBOARD_ORIGIN"] == "https://192.0.2.10"
    w2 = world
    for d in (w2.opt, w2.data, w2.sites, w2.enabled, w2.ssl):
        shutil.rmtree(d, ignore_errors=True)
    for d in (w2.sites, w2.enabled):
        d.mkdir()
    for f in list(w2.unit_dir.iterdir()) + [w2.env_file, w2.key]:
        f.unlink()
    p = world.fresh("--server-name", "2001:db8::10")
    assert p.returncode == 0, p.stderr + p.stdout
    assert env_values(world)["DASHBOARD_ORIGIN"] == "https://[2001:db8::10]" and "subjectAltName=IP:2001:db8::10" in (world.stub / "openssl.calls").read_text()


def test_your_own_certificate_is_copied_privately_and_checked(world):
    cert, key = world.w / "mine.crt", world.w / "mine.key"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=opa.example.com", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    base = ["--yes", "--create-app-user", "--server-name", "opa.example.com", "--cert", str(cert), "--key", str(key), "--backend-port", str(world.port)]
    p = world.run(*base)
    assert p.returncode == 0, p.stderr + p.stdout
    assert (world.ssl / "opa-secrets-wizard.crt").read_bytes() == cert.read_bytes() and (world.ssl / "opa-secrets-wizard.key").read_bytes() == key.read_bytes()
    assert mode(world.ssl / "opa-secrets-wizard.key") == 0o600 and not (world.stub / "openssl.calls").exists() or "req " not in (world.stub / "openssl.calls").read_text()
    assert "(your certificate)" in p.stdout and "self-signed" not in p.stdout.split("What changed")[1].split("Not done yet")[0]


def test_a_certificate_and_key_that_do_not_match_are_refused_before_anything_changes(world):
    certs = []
    for n in range(2):
        cert, key = world.w / f"c{n}.crt", world.w / f"c{n}.key"
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=x", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True)
        certs.append((cert, key))
    p = world.run("--yes", "--create-app-user", "--server-name", "opa.example.com", "--cert", str(certs[0][0]), "--key", str(certs[1][1]))
    assert p.returncode == 2 and "do not belong together" in p.stderr and not world.opt.exists() and not world.data.exists()


def test_no_nginx_skips_the_site_and_says_where_the_template_is(world):
    p = world.run("--yes", "--create-app-user", "--no-nginx", "--server-name", "opa.example.com", "--backend-port", str(world.port))
    assert p.returncode == 0, p.stderr + p.stdout
    assert not (world.sites / "opa-secrets-wizard").exists() and not world.ssl.exists() and "nginx" not in calls(world).replace("systemctl", "")
    assert f"skipped: nginx not set up here (--no-nginx). The site template is at {world.opt}/current/server/nginx-opa-secrets-wizard.conf" in p.stdout
    assert "NGINX_PROXY_SECRET is in" not in p.stdout and "NGINX_PROXY_SECRET in" in p.stdout
    # without a server name the origins are left for the operator and the Done block says so
    for d in (world.opt, world.data):
        shutil.rmtree(d)
    for f in list(world.unit_dir.iterdir()) + [world.env_file, world.key]:
        f.unlink()
    p = world.run("--yes", "--create-app-user", "--no-nginx", "--backend-port", str(world.port))
    assert p.returncode == 0 and "DASHBOARD_ORIGIN" in p.stdout and "DASHBOARD_ORIGIN" not in world.env_file.read_text().replace("#", "").split("OKTA")[0]


def test_yes_must_name_the_choices_and_a_bad_choice_changes_nothing(world):
    cases = [
        (["--yes", "--create-app-user", "--self-signed"], "needs --server-name"),
        (["--yes", "--create-app-user", "--server-name", "opa.example.com"], "must choose its certificate"),
        (["--yes", "--create-app-user", "--server-name", "https://opa.example.com", "--self-signed"], "not a DNS name"),
        (["--yes", "--create-app-user", "--server-name", "opa example.com", "--self-signed"], "not a DNS name"),
        (["--yes", "--create-app-user", "--server-name", "999.1.1.1", "--self-signed"], "not a valid IPv4"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--self-signed", "--no-nginx"], "alternatives"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--cert", "x"], "go together"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--self-signed", "--backend-port", "80"], "between 1024 and 65535"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--self-signed", "--backend-port", "8767"], "login gate"),
        (["--yes", "--app-user", "nosuchaccount", "--server-name", "a.com", "--self-signed"], "--create-app-user to create it"),
        (["--yes", "--create-app-user", "--app-user", "root", "--server-name", "a.com", "--self-signed"], "must not run as root"),
        (["--yes", "--create-app-user", "--app-user", "Bad Name", "--server-name", "a.com", "--self-signed"], "usable account name"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--self-signed", "--release-base-url", "http://mirror.example.com/x"], "plain https address"),
        (["--yes", "--create-app-user", "--server-name", "a.com", "--self-signed", "--revocation-url", "https://u:p@example.com/r.json"], "plain https address"),
    ]
    for args, fragment in cases:
        p = world.run(*args)
        assert p.returncode == 2 and fragment in p.stderr, (args, p.returncode, p.stderr)
        assert not world.opt.exists() and not world.data.exists() and not world.env_file.exists() and not (world.stub / "useradd.args").exists(), args


def test_interactive_fresh_install_asks_for_the_name_and_the_certificate_through_the_terminal(world):
    p = world.run("--create-app-user", "--backend-port", str(world.port), answers="opa.example.com\n\ny\n")  # no --yes: name, the default certificate choice (2), then the confirmation
    assert p.returncode == 0, p.stderr + p.stdout
    assert "Public name or IP address" in p.stderr and "TLS certificate for the web site" in p.stdout
    assert env_values(world)["DASHBOARD_ORIGIN"] == "https://opa.example.com" and "-subj /CN=opa.example.com" in (world.stub / "openssl.calls").read_text()


def test_interactive_without_a_terminal_refuses(world):
    p = world.run("--create-app-user", "--backend-port", str(world.port), extra_env={"OCW_TTY": "/nonexistent/tty"})
    assert p.returncode == 2 and "no terminal to ask you on" in p.stderr and not world.opt.exists()


def test_the_dry_run_prints_the_whole_fresh_plan_and_changes_nothing(world):
    p = world.fresh("--dry-run")
    assert p.returncode == 0, p.stderr + p.stdout
    for needle in ("(fresh)", "create the application account ocw", "write " + str(world.env_file), "three generated secrets that are never shown",
                   "login gate is NOT started", "temporary self-signed certificate for opa.example.com", "write the nginx site", "Dry run: nothing was changed."):
        assert needle in p.stdout, needle
    for path in (world.opt, world.data, world.env_file, world.key, world.ssl, world.stub / "useradd.args", world.stub / "openssl.calls"):
        assert not path.exists(), path
    assert not list(world.unit_dir.iterdir()) and not list(world.sites.iterdir())


def test_a_secret_never_appears_in_the_dry_run_either(world):
    p = world.fresh("--dry-run")
    assert not HEX64.search(p.stdout + p.stderr)


def test_provenance_of_a_verified_release_is_recorded(world):
    info = world.w / "release-info.json"
    info.write_text(json.dumps({"version": "5.52.0", "sha256": "a" * 64, "key_id": "88DFB54FC6C0E819", "signed_at": "2026-10-30T10:12:00Z",
                                "revocation_serial_applied": 0, "bootstrap_version": "5.52.0"}))
    p = world.fresh("--release-info", str(info))
    assert p.returncode == 0, p.stderr + p.stdout
    rel = world.opt / "releases" / "5.52.0"
    rec = json.loads((rel / ".installed-from-release").read_text())
    assert rec["source"] == "get-ocw.sh" and rec["signed"] is True and rec["sha256"] == "a" * 64 and rec["key_id"] == "88DFB54FC6C0E819"
    assert not (rel / ".installed-from-source").exists()
    staged = json.loads((rel / ".staged").read_text())      # what `ocw-updater status` reads for "signed by"
    assert staged["key_id"] == "88DFB54FC6C0E819" and staged["version"] == "5.52.0"
    again = world.fresh("--release-info", str(info))          # the same command again: a finished install is a reinstall, the release is kept
    assert again.returncode == 0 and "(reinstall)" in again.stdout and "--backend-port is ignored" in again.stdout


def test_a_malformed_release_info_stops_the_install_with_a_reason(world):
    info = world.w / "bad.json"
    info.write_text(json.dumps({"version": "5.52.0", "sha256": "nothex", "key_id": "x"}))
    p = world.fresh("--release-info", str(info))
    assert p.returncode == 4 and "could not record the provenance" in p.stderr


def _revocation_setup(world, tmp_path):
    sys.path.insert(0, str(REPO / "tests"))
    from release_helpers import TestKey, TestStandby, key_list, make_revocation, revocation_payload
    key, standby, new = TestKey(), TestStandby(), TestKey()
    (world.src / "server" / "release_keys.json").write_text(json.dumps(key_list([key, standby])))
    rev = tmp_path / "revocation-0000000001.json"
    make_revocation(rev, [standby], revocation_payload(1, revoke=[key.key_id], add_keys=[new]))
    return key, rev


def test_a_verified_revocation_is_applied_to_roots_trust_list_and_the_applications_key_state(world, tmp_path):
    key, rev = _revocation_setup(world, tmp_path)
    # the application's own CLI, run as its account by `trust apply`, from a tree with the test key list
    appdir = world.w / "appdir"
    (appdir / "server").mkdir(parents=True)
    shutil.copytree(REPO / "server" / "updater", appdir / "server" / "updater", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(world.src / "server" / "release_keys.json", appdir / "server" / "release_keys.json")
    p = world.fresh("--revocation", str(rev), extra_env={"FAKE_APP_DIR": str(appdir), "FAKE_APP_PY": sys.executable, "FAKE_APP_PYPATH": str(REPO),
                                                                      "OPA_RELEASE_KEYS_LOCAL": str(world.data / "release_keys.local.json")})
    assert p.returncode == 0, p.stderr + p.stdout
    trust = json.loads((world.opt / "updater" / "trust.json").read_text())
    assert trust["serial"] == 1 and [r["key_id"] for r in trust["revoked"]] == [key.key_id]
    assert "The application's own key list was updated too." in p.stdout, p.stdout[p.stdout.index("Key revocations"):][:900]
    local = json.loads((world.data / "release_keys.local.json").read_text())
    assert [r["key_id"] for r in local["revoked"]] == [key.key_id]
    # the copy lives in a root-owned, world-readable place, never in the application's upgrade/ directories
    kept = world.opt / "updater" / "revocations" / rev.name
    assert kept.read_bytes() == rev.read_bytes() and mode(kept) == 0o644 and mode(kept.parent) == 0o755
    assert not (world.data / "upgrade" / "revocations" / rev.name).exists()
    assert "Key revocations" in p.stdout and "keep them for the application" not in p.stdout


def test_a_link_planted_where_the_revocation_copy_goes_is_refused_and_nothing_is_written(world, tmp_path):
    _key, rev = _revocation_setup(world, tmp_path)
    victim = world.w / "victim"
    victim.write_text("keep me")
    dest = world.opt / "updater" / "revocations"
    dest.mkdir(parents=True)
    (dest / rev.name).symlink_to(victim)
    p = world.fresh("--revocation", str(rev))
    assert p.returncode == 4 and "could not keep a copy" in p.stderr
    assert victim.read_text() == "keep me"
    # and a link in place of the directory itself
    for f in dest.iterdir():
        f.unlink()
    dest.rmdir()
    elsewhere = world.w / "elsewhere"
    elsewhere.mkdir()
    dest.symlink_to(elsewhere)
    p = world.fresh("--revocation", str(rev))
    assert p.returncode == 4 and not list(elsewhere.iterdir())


def test_a_planted_link_below_the_application_home_is_refused_and_nothing_is_created_through_it(world):
    home = world.w / "apphome"
    (home / ".local").mkdir(parents=True)
    target = world.w / "target"
    target.mkdir()
    (home / ".local" / "share").symlink_to(target)
    (world.stub / "users").mkdir()
    (world.stub / "users" / "ocw").write_text(str(home))        # the account exists, with this home
    p = world.run("--yes", "--app-user", "ocw", "--server-name", "opa.example.com", "--self-signed", "--backend-port", str(world.port))
    assert p.returncode == 4 and "is a link" in p.stderr
    assert not list(target.iterdir())


def test_the_release_tree_is_readable_by_the_application_whatever_umask_the_caller_has(world):
    p = world.fresh(umask=0o077)       # get-ocw.sh runs with 077
    assert p.returncode == 0, p.stderr + p.stdout
    rel = world.opt / "releases" / "5.52.0"
    bad = []
    for path in [rel, *rel.rglob("*")]:
        if path.is_symlink():
            continue
        m = path.stat().st_mode
        if path.is_dir() and not (m & 0o005 == 0o005):
            bad.append(("dir", str(path.relative_to(world.opt)), oct(m & 0o777)))
        if path.is_file() and not (m & 0o004):
            bad.append(("file", str(path.relative_to(world.opt)), oct(m & 0o777)))
        if m & 0o022:
            bad.append(("writable", str(path.relative_to(world.opt)), oct(m & 0o777)))
    assert not bad, bad[:10]
    assert os.access(rel / ".venv" / "bin" / "python", os.X_OK) and mode(world.opt) == 0o755 and mode(world.opt / "updater") == 0o755
    # the secret-bearing files keep their own modes under the same umask
    assert mode(world.env_file) == 0o600 and mode(world.key) == 0o640 and mode(world.sites / "opa-secrets-wizard") == 0o640
    assert mode(world.ssl) == 0o700 and mode(world.ssl / "opa-secrets-wizard.key") == 0o600
    assert mode(world.data) == 0o1770 and mode(world.data / "upgrade" / "backups") == 0o700


def test_the_backend_is_not_started_when_the_application_account_cannot_run_the_release(world):
    (world.stub / "app_cannot_run").write_text("")
    p = world.fresh()
    assert p.returncode == 4 and "cannot run the installed release" in p.stderr and "Something was changed" in p.stderr and "run the same command again" in p.stderr
    assert "systemctl start opa-compliance-wizard" not in calls(world) and (world.opt / ".fresh-install-incomplete").exists()
    (world.stub / "app_cannot_run").unlink()
    assert world.fresh().returncode == 0


def test_a_revocation_that_does_not_apply_stops_the_install(world, tmp_path):
    rev = tmp_path / "revocation-0000000001.json"
    rev.write_text("garbage")
    p = world.fresh("--revocation", str(rev))
    assert p.returncode == 4 and "could not apply the verified key revocation" in p.stderr


def test_the_mirror_and_the_owners_revocation_url_reach_the_updater_settings(world):
    p = world.fresh("--release-base-url", "https://mirror.example.com/ocw", "--revocation-url", "https://example.com/revocation.json")
    assert p.returncode == 0, p.stderr + p.stdout
    upd = (world.w / "etc" / "ocw-updater.env").read_text()
    assert "OPA_RELEASE_BASE_URL=https://mirror.example.com/ocw" in upd and "OPA_REVOCATION_URL=https://example.com/revocation.json" in upd
    assert "OPA_REVOCATION_URL=https://example.com/revocation.json" in world.env_file.read_text()


# --- health, failure and resume ----------------------------------------------------------------------------------------


def test_a_backend_that_does_not_come_up_stops_the_run_with_exit_4_and_keeps_everything(world):
    (world.stub / "fail_start").write_text("")
    p = world.fresh()
    assert p.returncode == 4, p.stderr + p.stdout
    assert "did not come up healthy" in p.stdout and "journalctl -u opa-compliance-wizard -n 100" in p.stdout and "--uninstall --keep-data" in p.stdout
    c = calls(world)
    assert "systemctl stop opa-compliance-wizard" in c and "systemctl disable opa-compliance-wizard" in c
    assert world.env_file.exists() and (world.unit_dir / "opa-compliance-wizard.service").exists() and (world.opt / "current").is_symlink()
    assert (world.opt / ".fresh-install-incomplete").exists()   # the next run resumes
    # fix the cause, run the same command again: it resumes, keeps the settings file, and finishes
    before = world.env_file.read_bytes()
    (world.stub / "fail_start").unlink()
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    assert world.env_file.read_bytes() == before and "kept the existing settings file" in p.stdout
    assert not (world.opt / ".fresh-install-incomplete").exists()
    assert "is already current" in p.stdout            # the units were not rewritten
    assert "kept the certificate and key already in" in p.stdout


def test_a_failure_after_the_account_step_is_resumed_and_never_overwrites_data(world):
    # the first run dies while rendering the nginx site (a template without its placeholders)
    tpl = world.src / "server" / "nginx-opa-secrets-wizard.conf"
    good = tpl.read_text()
    tpl.write_text("server { }\n")
    p = world.fresh()
    assert p.returncode == 4 and "could not write the nginx site" in p.stderr
    assert (world.opt / ".fresh-install-incomplete").exists() and (world.stub / "useradd.args").exists()
    # an archive and an audit entry exist now; the second run must not touch them
    (world.data / "audit_store.db").write_text("ARCHIVE")
    (world.data / "audit_log.jsonl").write_text('{"a":1}\n')
    tpl.write_text(good)
    useradd_calls = (world.stub / "useradd.args").read_text()
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    assert (world.data / "audit_store.db").read_text() == "ARCHIVE" and (world.data / "audit_log.jsonl").read_text() == '{"a":1}\n'
    assert (world.stub / "useradd.args").read_text() == useradd_calls      # the account was reused, not created twice
    assert (world.sites / "opa-secrets-wizard").exists()


def test_an_existing_settings_file_is_never_overwritten_and_missing_keys_are_reported(world):
    world.env_file.write_text("SOMETHING=else\nNGINX_PROXY_SECRET=operator-owned-value\n")
    world.env_file.chmod(0o644)
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    assert world.env_file.read_text() == "SOMETHING=else\nNGINX_PROXY_SECRET=operator-owned-value\n"
    assert "lacks: DEPLOYMENT_MODE, KEYRING_UNLOCK_PASSWORD, INTERNAL_API_SHARED_SECRET" in p.stdout or "lacks: OPA_DATA_DIR" in p.stdout
    assert "operator-owned-value" not in p.stdout and mode(world.env_file) == 0o600 and "now 0600" in p.stdout
    assert "operator-owned-value" in (world.sites / "opa-secrets-wizard").read_text()   # the site carries the operator's proxy secret


def test_nginx_that_rejects_the_site_gets_the_old_state_back(world):
    (world.stub / "nginx_bad").write_text("")
    p = world.fresh()
    assert p.returncode == 4 and "nginx -t rejected the new site" in p.stderr
    assert not (world.sites / "opa-secrets-wizard").exists() and not (world.enabled / "opa-secrets-wizard").exists()
    assert not (world.unit_dir / "opa-compliance-wizard.service").exists()   # it stopped before the units: nothing half-started


def test_an_existing_nginx_site_is_kept_with_its_own_values_and_restored_when_rejected(world):
    assert world.fresh().returncode == 0
    site = world.sites / "opa-secrets-wizard"
    first = site.read_text()
    # an operator's own server name and certificate paths survive a resumed run (nginx_bake carries them)
    custom = first.replace("opa.example.com", "ours.example.org").replace("/etc/nginx/ssl/opa-secrets-wizard", "/etc/ssl/ours")
    site.write_text(custom)
    (world.opt / ".fresh-install-incomplete").write_text("")
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    assert site.read_text() == custom


def test_an_openssl_failure_leaves_no_half_written_key(world):
    (world.stub / "openssl_fail").write_text("")
    p = world.fresh()
    assert p.returncode == 4 and "could not make the self-signed certificate" in p.stderr
    assert not (world.ssl / "opa-secrets-wizard.key").exists() and not (world.ssl / "opa-secrets-wizard.crt").exists()


def test_missing_prerequisites_are_named_before_anything_changes(world):
    (world.stub / "bin" / "nginx").unlink()
    path = f"{world.stub / 'bin'}:/usr/bin:/bin"
    p = world.fresh(extra_env={"PATH": path})
    assert p.returncode == 2 and "lacks: nginx" in p.stderr and "Nothing was changed" in p.stderr and not world.opt.exists()


# --- other modes keep working ----------------------------------------------------------------------------------------------


def test_a_second_run_on_a_finished_install_is_a_reinstall_that_keeps_everything(world):
    assert world.fresh().returncode == 0
    env_before = world.env_file.read_bytes()
    site_before = (world.sites / "opa-secrets-wizard").read_bytes()
    p = world.run("--yes", "--wheelhouse", str(world.w / "wheels"))
    assert p.returncode == 0, p.stderr + p.stdout
    assert "(reinstall)" in p.stdout and world.env_file.read_bytes() == env_before and (world.sites / "opa-secrets-wizard").read_bytes() == site_before


# --- uninstall ---------------------------------------------------------------------------------------------------------------


def test_uninstall_keep_data_removes_the_software_and_keeps_the_data(world):
    assert world.fresh().returncode == 0
    (world.data / "audit_store.db").write_text("ARCHIVE")
    (world.data / "audit_log.jsonl").write_text('{"a":1}\n')
    keep = {world.env_file: world.env_file.read_bytes(), world.key: world.key.read_bytes(), world.ssl / "opa-secrets-wizard.key": (world.ssl / "opa-secrets-wizard.key").read_bytes()}
    (world.stub / "users" / "ocw-updater").write_text("")        # pretend the staging account exists, so its removal is exercised
    p = world.run("--uninstall", "--keep-data", answers="UNINSTALL\n")
    assert p.returncode == 0, p.stderr + p.stdout
    assert not world.opt.exists() and not (world.w / "var" / "ocw-updater").exists() and not (world.w / "bin" / "ocw-updater").exists()
    assert not (world.w / "etc" / "ocw-updater.env").exists() and not list(world.unit_dir.iterdir())
    assert not (world.sites / "opa-secrets-wizard").exists() and not (world.enabled / "opa-secrets-wizard").is_symlink()
    assert (world.data / "audit_store.db").read_text() == "ARCHIVE" and (world.data / "audit_log.jsonl").read_text() == '{"a":1}\n'
    assert (world.data / "home" / ".local" / "share" / "keyrings").is_dir()
    for path, content in keep.items():
        assert path.read_bytes() == content
    assert "userdel ocw-updater" in (world.stub / "userdel.args").read_text().replace("\n", "") or (world.stub / "userdel.args").read_text().strip() == "ocw-updater"
    assert "Kept:" in p.stdout and "Removing the data too is a manual step" in p.stdout
    c = calls(world)
    assert "systemctl stop opa-compliance-wizard" in c and "systemctl disable opa-auth-gate" in c and c.count("systemctl reload nginx") >= 2
    # install again: the archive and the settings are found and used
    again = world.fresh()
    assert again.returncode == 0, again.stderr + again.stdout
    assert (world.data / "audit_store.db").read_text() == "ARCHIVE" and world.env_file.read_bytes() == keep[world.env_file]


def test_uninstall_needs_the_typed_word_and_keep_data(world):
    assert world.fresh().returncode == 0
    p = world.run("--uninstall", answers="UNINSTALL\n")
    assert p.returncode == 2 and "needs --keep-data" in p.stderr and world.opt.exists()
    p = world.run("--uninstall", "--keep-data", answers="uninstall\n")
    assert p.returncode == 2 and "not confirmed" in p.stderr and world.opt.exists() and (world.unit_dir / "opa-compliance-wizard.service").exists()
    p = world.run("--uninstall", "--keep-data", extra_env={"OCW_TTY": "/nonexistent"})
    assert p.returncode == 2 and "no terminal" in p.stderr and world.opt.exists()
    p = world.run("--keep-data")
    assert p.returncode == 2 and "only goes with --uninstall" in p.stderr


def test_uninstall_dry_run_lists_and_changes_nothing(world):
    assert world.fresh().returncode == 0
    p = world.run("--uninstall", "--keep-data", "--dry-run")
    assert p.returncode == 0 and "Will remove:" in p.stdout and "Will keep:" in p.stdout and "Dry run: nothing was changed." in p.stdout
    assert world.opt.exists() and (world.unit_dir / "opa-compliance-wizard.service").exists()


def test_uninstall_keeps_the_nginx_site_while_a_second_gate_uses_its_zone(world):
    assert world.fresh().returncode == 0
    (world.unit_dir / "opa-auth-gate-other.service").write_text("[Service]\nUser=x\n")
    p = world.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "NOT the nginx site" in p.stdout and (world.sites / "opa-secrets-wizard").exists() and not world.opt.exists()
    assert (world.unit_dir / "opa-auth-gate-other.service").exists()


def test_uninstall_refuses_a_data_directory_inside_the_tree_it_would_remove(world):
    assert world.fresh().returncode == 0
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_DATA_DIR": str(world.opt / "data-inside")})
    assert p.returncode == 2 and "holds the data directory" in p.stderr and (world.data / "home").exists()
    assert (world.unit_dir / "opa-compliance-wizard.service").exists() and "stop opa-compliance-wizard" not in calls(world).split("systemctl start")[-1]   # nothing was stopped


@pytest.mark.parametrize("bad", ["/opt", "/usr/..", "/var/lib", "/etc/", "/"])
def test_uninstall_refuses_system_directories_before_it_stops_or_removes_anything(world, bad):
    assert world.fresh().returncode == 0
    before = calls(world)
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_OPT_DIR": bad})
    assert p.returncode == 2 and "refusing to remove" in p.stderr
    new = calls(world)[len(before):]
    assert not any(w in new for w in ("stop", "disable", "daemon-reload", "reload nginx"))      # only read-only queries ran
    assert (world.unit_dir / "opa-compliance-wizard.service").exists() and world.opt.exists()


def test_uninstall_leaves_an_nginx_site_that_is_not_this_applications(world):
    assert world.fresh().returncode == 0
    site = world.sites / "opa-secrets-wizard"
    site.write_text("server { listen 443; }\n")        # an operator's own site under the same name: no proxy secret in it
    p = world.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "it is not this application's site" in p.stdout and site.exists() and not world.opt.exists()


def test_uninstall_leaves_a_unit_that_runs_from_somewhere_else(world):
    (world.unit_dir / "opa-compliance-wizard.service").write_text(f"[Service]\nUser={world.user}\nWorkingDirectory=/home/someone/opa\n")
    (world.opt / "releases" / "5.0.0").mkdir(parents=True)
    (world.opt / "updater").mkdir()
    (world.opt / "current").symlink_to("releases/5.0.0")
    p = world.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0 and "is not removed" in p.stdout and (world.unit_dir / "opa-compliance-wizard.service").exists()


# --- the logging wrapper -----------------------------------------------------------------------------------------------------


def test_log_receives_everything_and_the_exit_status_passes_through(world):
    log = world.w / "logs" / "run.log"
    p = world.run("--yes", "--create-app-user", "--self-signed", "--log", str(log))      # refused: no --server-name
    assert p.returncode == 2 and "needs --server-name" in p.stdout     # the wrapper merges stderr into the stream it logs
    assert log.exists() and mode(log) == 0o600 and mode(log.parent) == 0o700 and "needs --server-name" in log.read_text()


# --- helpers, on their own -------------------------------------------------------------------------------------------------------


def helpers(*args):
    return subprocess.run([sys.executable, "-I", str(REPO / "server" / "install_helpers.py"), *args], capture_output=True, text=True, env=dict(os.environ, OCW_INSTALL_TEST="1"))


@pytest.mark.parametrize("name,kind", [("opa.example.com", "dns"), ("a", "dns"), ("a-b.example.org", "dns"), ("192.0.2.1", "ip4"), ("2001:db8::1", "ip6"), ("::1", "ip6")])
def test_server_names_that_are_accepted(name, kind):
    p = helpers("validate-server-name", f"--name={name}")
    assert p.returncode == 0 and p.stdout.strip() == kind


@pytest.mark.parametrize("name", ["", " a.com", "a.com/x", "http://a.com", "a.com:443", "-a.com", "a..com", "a_b.com", "*.a.com", "a b", "1.2.3", "300.1.1.1",
                                  "a" * 64 + ".com", "x" * 260, "a.com;rm", "a.com\n", "$(id).com", "`id`.com"])
def test_server_names_that_are_refused(name):
    p = helpers("validate-server-name", f"--name={name}")
    assert p.returncode == 2 and "refused:" in p.stderr and "Nothing was changed" in p.stderr


def test_write_env_creates_the_file_private_from_the_first_byte(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "server"))
    import install_helpers as h
    seen = []
    real_write = os.write

    def spy(fd, data):
        seen.append((oct(os.fstat(fd).st_mode & 0o777), len(data)))
        return real_write(fd, data)
    monkeypatch.setattr(h.os, "write", spy)
    monkeypatch.setenv("OCW_INSTALL_TEST", "1")
    monkeypatch.setattr(h, "TESTING", True)
    path = tmp_path / "e.env"
    a = h.build_parser().parse_args(["write-env", "--path", str(path), "--owner", os.environ.get("USER", "root"), "--data-dir", "/d", "--server-name", "a.com"])
    assert h.cmd_write_env(a) == 0
    assert seen and all(m == "0o600" for m, _ in seen)           # the mode was already 0600 when the first byte was written
    a2 = h.build_parser().parse_args(["write-session-key", "--path", str(tmp_path / "k"), "--group", "staff" if sys.platform == "darwin" else "root"])
    h.cmd_write_session_key(a2)
    assert oct(os.stat(tmp_path / "k").st_mode & 0o777) == "0o640" and os.stat(tmp_path / "k").st_size == 32


def test_write_env_refuses_to_follow_a_link(tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "e.env"
    link.symlink_to(target)
    p = helpers("write-env", "--path", str(link), "--owner", os.environ.get("USER", "root"), "--data-dir", "/d")
    assert p.returncode == 2 and target.read_text() == "keep"


def test_check_cert_accepts_a_pair_and_refuses_a_stranger(tmp_path):
    for n in ("a", "b"):
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=x", "-keyout", str(tmp_path / f"{n}.key"),
                        "-out", str(tmp_path / f"{n}.crt")], check=True, capture_output=True)
    assert helpers("check-cert", "--cert", str(tmp_path / "a.crt"), "--key", str(tmp_path / "a.key")).returncode == 0
    assert helpers("check-cert", "--cert", str(tmp_path / "a.crt"), "--key", str(tmp_path / "b.key")).returncode == 2
    (tmp_path / "junk").write_text("not pem")
    assert helpers("check-cert", "--cert", str(tmp_path / "junk"), "--key", str(tmp_path / "a.key")).returncode == 2


def test_uninstall_leaves_an_enabled_link_that_points_to_another_site(world):
    assert world.fresh().returncode == 0
    link = world.enabled / "opa-secrets-wizard"
    link.unlink()
    other = world.w / "someone-elses-site"
    other.write_text("server { }\n")
    link.symlink_to(other)
    p = world.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert link.is_symlink() and os.readlink(link) == str(other) and "it was left in place" in p.stdout
    assert not (world.sites / "opa-secrets-wizard").exists() and "Lingering stays on" in p.stdout


# --- the last review round --------------------------------------------------------------------------------------------------------


def _default_site(world):
    default = world.sites / "default"
    default.write_text("server { listen 80 default_server; }\n")
    (world.enabled / "default").symlink_to(default)
    return world.enabled / "default"


def test_the_default_nginx_site_is_removed_only_when_this_run_installed_nginx(world):
    link = _default_site(world)
    p = world.fresh("--disable-default-site")
    assert p.returncode == 0, p.stderr + p.stdout
    assert not link.exists() and not link.is_symlink() and (world.sites / "default").exists()     # the link goes, the file stays
    assert "removed the distribution's default site link" in p.stdout and calls(world).count("systemctl reload nginx") >= 2
    assert "nginx's own 'default' site" not in p.stdout


def test_an_existing_nginx_keeps_its_other_sites_and_the_done_text_mentions_the_default_one(world):
    link = _default_site(world)
    p = world.fresh()
    assert p.returncode == 0, p.stderr + p.stdout
    assert link.is_symlink()
    assert "nginx's own 'default' site" in p.stdout and "sudo rm" in p.stdout


def test_the_dry_run_says_the_default_site_link_would_go(world):
    _default_site(world)
    p = world.fresh("--dry-run", "--disable-default-site")
    assert p.returncode == 0 and "remove the link" in p.stdout and (world.enabled / "default").is_symlink()


@pytest.mark.parametrize("bad", ["/usr/local", "/usr/share", "/var/cache", "/etc/nginx", "/home/someone", "/var/lib", "/usr/lib"])
def test_uninstall_refuses_system_directories_it_did_not_make(world, bad):
    assert world.fresh().returncode == 0
    before = calls(world)
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_OPT_DIR": bad})
    assert p.returncode == 2 and "refusing to remove" in p.stderr
    assert not any(w in calls(world)[len(before):] for w in ("stop", "disable", "daemon-reload")) and world.opt.exists()


def test_uninstall_refuses_a_directory_that_does_not_look_like_an_install_of_ours(world):
    assert world.fresh().returncode == 0
    other = world.w / "somebody-elses-app"
    (other / "releases").mkdir(parents=True)
    (other / "important.txt").write_text("keep")
    before = calls(world)
    p = world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_OPT_DIR": str(other)})
    assert p.returncode == 2 and "does not look like an install made by this installer" in p.stderr
    assert (other / "important.txt").read_text() == "keep" and not any(w in calls(world)[len(before):] for w in ("stop", "disable"))
    # a `current` link that points outside releases/ is not ours either
    (other / "updater").mkdir()
    (other / "current").symlink_to("/etc")
    assert world.run("--uninstall", "--keep-data", "--yes", extra_env={"OCW_OPT_DIR": str(other)}).returncode == 2
    assert (other / "important.txt").exists()


def test_uninstall_words_what_it_did_to_the_link_and_names_the_account(world):
    assert world.fresh().returncode == 0
    link = world.enabled / "opa-secrets-wizard"
    link.unlink()
    other = world.w / "other-site"
    other.write_text("server { }\n")
    link.symlink_to(other)
    p = world.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "was kept: it points elsewhere" in p.stdout and f"removed {world.sites}/opa-secrets-wizard and {link}" not in p.stdout
    assert "Lingering stays on for ocw " in p.stdout and "for  (" not in p.stdout
