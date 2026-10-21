"""server/install.sh (5.47.0), run for real against a temp directory tree with stubbed system commands (systemctl, useradd,
runuser, sleep). OCW_INSTALL_TEST=1 skips only the root-only steps (creating the account, chown to other users)."""

import http.server
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MAIN_SITE = (REPO / "server" / "nginx-opa-secrets-wizard.conf").read_text().replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", "s3cr3t-live-value")
pytestmark = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("bash"), reason="install.sh is a Linux server script")

STUB_SYSTEMCTL = r'''#!/bin/bash
# state: $STUB/units/<name>.props (KEY=VALUE lines); calls are logged to $STUB/calls
echo "systemctl $*" >> "$STUB/calls"
args=()
for a in "$@"; do args+=("$a"); done
cmd=""
props=""
rest=()
i=0
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
unit="${rest[0]:-}"
unit="${unit%.service}"
f="$STUB/units/$unit.props"
case "$cmd" in
  cat) [ -f "$f" ] ;;
  show) [ -f "$f" ] || exit 0; grep -m1 "^$props=" "$f" | sed "s/^$props=//" ;;
  list-unit-files) for g in "$STUB"/units/opa-auth-gate-*.props; do [ -f "$g" ] && echo "$(basename "$g" .props).service enabled"; done; exit 0 ;;
  stop) [ -f "$f" ] && sed -i.b 's/^ActiveState=.*/ActiveState=inactive/' "$f" && rm -f "$f.b"; exit 0 ;;
  start | restart)
    [ -f "$f" ] || exit 5
    if [ -e "$STUB/fail_start" ]; then sed -i.b 's/^ActiveState=.*/ActiveState=failed/' "$f"; else sed -i.b 's/^ActiveState=.*/ActiveState=active/' "$f"; fi
    rm -f "$f.b"; exit 0 ;;
  *) exit 0 ;;
esac
'''


# `nginx -t` fails while $STUB/nginx_bad exists or when any file in $OCW_NGINX_SITES_DIR contains the word BROKEN
NGINX_STUB = r'''#!/bin/bash
echo "nginx $*" >> "$STUB/calls"
[ "$1" = "-t" ] || exit 0
[ ! -e "$STUB/nginx_bad" ] || exit 1
! grep -rq BROKEN "$OCW_NGINX_SITES_DIR" 2>/dev/null
'''


class Backend(http.server.BaseHTTPRequestHandler):
    version = "0.0.0"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"version": Backend.version}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def world(tmp_path):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    w = tmp_path
    stub = w / "stub"
    (stub / "bin").mkdir(parents=True)
    (stub / "units").mkdir()
    for name, body in (("systemctl", STUB_SYSTEMCTL), ("sleep", "#!/bin/bash\nexit 0\n"), ("runuser", '#!/bin/bash\nshift 3\nexec "$@"\n'),
                       ("useradd", "#!/bin/bash\nexit 0\n"), ("nginx", NGINX_STUB), ("chown", '#!/bin/bash\necho "$@" >> "$STUB/chowns"\nexit 0\n')):
        p = stub / "bin" / name
        p.write_text(body)
        p.chmod(0o755)
    # the checkout to install: the real server files, a tiny fake application, an empty requirements lock
    src = w / "src"
    (src / "server" / "updater").mkdir(parents=True)
    shutil.copytree(REPO / "server" / "updater" / "root", src / "server" / "updater" / "root")
    for f in ("nginx_bake.py", "release_keys.json", "ocw-stage@.service", "ocw-upgrade.path", "ocw-upgrade.service", "ocw-upgrade-due.service",
              "ocw-upgrade-due.timer", "ocw-updater.sh", "install.sh", "nginx_second_site.py", "opa-compliance-wizard.service", "start-headless.sh"):
        shutil.copy(REPO / "server" / f, src / "server" / f)
    (src / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.47.0"\n')
    (src / "requirements.lock").write_text("# empty on purpose\n")
    (src / "frontend" / "dist").mkdir(parents=True)
    (src / "frontend" / "dist" / "index.html").write_text("<html>built</html>")
    (src / "folders_template.csv").write_text("path,description\nA,\n")
    # the existing in-home install
    legacy = w / "home" / "app" / "opa"
    legacy.mkdir(parents=True)
    (legacy / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.45.1"\n')
    (legacy / ".venv" / "bin").mkdir(parents=True)
    (legacy / ".venv" / "bin" / "python").write_text("")
    import sqlite3
    conn = sqlite3.connect(legacy / "audit_store.db")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    (legacy / "audit_log.jsonl").write_text('{"action":"x"}\n')
    (legacy / "access_control.json").write_text('{"admin_group_id": null}')
    (legacy / "my-template.csv").write_text("path,description\nB,\n")
    main_site = w / "nginx" / "opa-secrets-wizard"
    main_site.parent.mkdir()
    main_site.write_text(MAIN_SITE)
    (legacy / ".deploy.conf").write_text(f"OPA_BACKEND_PORT={port}\nOPA_NGINX_SITE={main_site}\n")
    unit_dir = w / "units"
    unit_dir.mkdir()
    user = os.environ.get("USER") or os.popen("id -un").read().strip()
    unit = unit_dir / "opa-compliance-wizard.service"
    # indented, as the units on a real server often are (systemd accepts leading whitespace)
    unit.write_text(f"""[Unit]
Description=OPA Compliance Wizard
[Service]
  User={user}
  WorkingDirectory={legacy}
  EnvironmentFile=/etc/opa-compliance-wizard.env
  ExecStart={legacy}/server/start-headless.sh
  ProtectHome=read-only
  ReadWritePaths={legacy}
  ReadWritePaths=/home/app/.local/share/keyrings
  ReadWritePaths=/run/user/1000
""")
    gate = unit_dir / "opa-auth-gate.service"
    gate.write_text(f"[Service]\nUser={user}\nWorkingDirectory={legacy}\nExecStart={legacy}/.venv/bin/python server/auth_gate.py --port 8767\n"
                    f"ReadWritePaths={legacy}\nReadWritePaths=/run/user/1000\n")
    for name, u, extra in (("opa-compliance-wizard", unit, ""), ("opa-auth-gate", gate, "")):
        (stub / "units" / f"{name}.props").write_text(
            f"FragmentPath={u}\nUser={user}\nWorkingDirectory={legacy}\nActiveState=active\nNRestarts=0\n")
    env_file = w / "etc" / "opa-compliance-wizard.env"
    env_file.parent.mkdir()
    env_file.write_text(f"NGINX_PROXY_SECRET=abc\nOPA_AUDIT_DB_PATH={legacy}/audit_store.db\n")
    env = dict(os.environ, PATH=f"{stub / 'bin'}:{os.environ['PATH']}", STUB=str(stub), OCW_INSTALL_TEST="1", OCW_TEST_MODE="1", OCW_FAST="1",
               OCW_OPT_DIR=str(w / "opt"), OCW_DATA_DIR=str(w / "var-lib"), OCW_UNIT_DIR=str(unit_dir), OCW_BIN_DIR=str(w / "bin"),
               OCW_ENV_FILE=str(env_file), OCW_SUDOERS_DIR=str(w / "sudoers"), OCW_ARTIFACTS_DIR=str(w / "var-ocw" / "artifacts"),
               OCW_UPDATER_ENV=str(w / "etc" / "ocw-updater.env"), OCW_NGINX_SITES_DIR=str(w / "nginx-sites"))
    (w / "nginx-sites").mkdir()
    (w / "bin").mkdir()
    (w / "sudoers").mkdir()

    class W:
        pass
    o = W()
    o.__dict__.update(w=w, src=src, legacy=legacy, unit=unit, gate=gate, env=env, env_file=env_file, stub=stub, user=user, port=port, backend=Backend)

    def run(*args, extra_env=None):
        e = dict(env, **(extra_env or {}))
        return subprocess.run(["bash", str(src / "server" / "install.sh"), "--yes", "--app-user", user, "--wheelhouse", str(w / "wheels"), *args],
                              capture_output=True, text=True, env=e, timeout=300)
    o.run = run
    (w / "wheels").mkdir()
    yield o
    srv.shutdown()


def calls(world):
    return (world.stub / "calls").read_text() if (world.stub / "calls").exists() else ""


def test_dry_run_prints_the_plan_and_changes_nothing(world):
    p = world.run("--dry-run")
    assert p.returncode == 0, p.stderr + p.stdout
    out = p.stdout
    for needle in ("(migrate)", "Plan:", "move audit_store.db", "move audit_log.jsonl", "rewrite", "Dry run: nothing was changed.",
                   "leave any old deploy sudoers lines alone", "kept; nothing in it is deleted"):
        assert needle in out, needle
    assert not (world.w / "opt").exists() and not (world.w / "var-lib").exists()
    assert (world.legacy / "audit_store.db").exists()
    assert "stop" not in calls(world).replace("show", "")  # nothing stopped
    assert "ReadWritePaths=" in world.unit.read_text() and str(world.legacy) in world.unit.read_text()


def test_migration_moves_data_rewrites_units_and_keeps_the_carve_outs(world):
    Backend.version = "5.47.0"
    p = world.run()
    assert p.returncode == 0, p.stderr + p.stdout
    opt, data = world.w / "opt", world.w / "var-lib"
    assert os.readlink(opt / "current") == "releases/5.47.0"
    assert (opt / "releases" / "5.47.0" / "create_secret_folders.py").exists() and (opt / "releases" / "5.47.0" / ".venv" / "bin" / "python").exists()
    assert (opt / "releases" / "5.47.0" / "frontend" / "dist" / "index.html").exists()
    # data copied, originals renamed (never deleted)
    for f in ("audit_store.db", "audit_log.jsonl", "access_control.json"):
        assert (data / f).exists()
        assert not (world.legacy / f).exists() and list(world.legacy.glob(f + ".migrated-*"))
    assert (data / "my-template.csv").exists() and (world.legacy / "my-template.csv").exists()
    # the migrated archive is intact
    import sqlite3
    assert sqlite3.connect(data / "audit_store.db").execute("SELECT x FROM t").fetchone()[0] == 1
    # data directory: root-style layout, sticky + group write
    assert stat.S_IMODE((data).stat().st_mode) == 0o1770
    assert stat.S_IMODE((data / "upgrade" / "backups").stat().st_mode) == 0o700
    # units rewritten, carve-outs untouched
    u = world.unit.read_text()
    assert f"WorkingDirectory={opt}/current" in u and f"ExecStart={opt}/current/server/start-headless.sh" in u
    assert f"ReadWritePaths={data}" in u and "ReadWritePaths=/home/app/.local/share/keyrings" in u and "ReadWritePaths=/run/user/1000" in u
    assert str(world.legacy) not in u and "ProtectSystem=strict" in u and f"Environment=OPA_DATA_DIR={data}" in u
    g = world.gate.read_text()
    assert f"{opt}/current/.venv/bin/python server/auth_gate.py --port 8767" in g and "ProtectSystem" not in g
    # the env file gained OPA_DATA_DIR and its archive path followed the move; a copy of the old one is kept
    env = world.env_file.read_text()
    assert f"OPA_DATA_DIR={data}" in env and f"OPA_AUDIT_DB_PATH={data}/audit_store.db" in env
    assert list((opt).glob("install-backup-*/opa-compliance-wizard.env"))
    # updater files, config, trust list, units, command
    for f in ("ocw_activate.py", "config.json", "trust.json"):
        assert (opt / "updater" / f).exists(), f
    for f in ("ocw_activate.py", "ocw_trust.py", "ocw_cli.py", "nginx_bake.py"):
        assert (opt / "updater" / "current" / f).exists(), f
    assert (opt / "updater" / "ocw_activate.py").read_text().startswith("#!/usr/bin/env python3") and "os.execv" in (opt / "updater" / "ocw_activate.py").read_text()
    cfg = json.loads((opt / "updater" / "config.json").read_text())
    assert cfg["nginx_site"] == str(world.w / "nginx" / "opa-secrets-wizard") and cfg["backend_port"] == world.port
    assert json.loads((opt / "updater" / "trust.json").read_text())["keys"]
    for f in ("ocw-stage@.service", "ocw-upgrade.path", "ocw-upgrade.service"):
        text = (world.w / "units" / f).read_text()
        assert "__OPT_DIR__" not in text and "__DATA_DIR__" not in text
    assert f"{data}/upgrade/inbox/requests" in (world.w / "units" / "ocw-upgrade.path").read_text()
    cmd = (world.w / "bin" / "ocw-updater").read_text()
    assert "__" not in cmd.replace("__NAME__", "") or "__OPT_DIR__" not in cmd
    assert f'OPT="{opt}"' in cmd
    assert "enable ocw-upgrade.path ocw-upgrade.service" in calls(world)
    # the old tree is left in place
    assert (world.legacy / "create_secret_folders.py").exists()


def test_rerun_is_idempotent_and_does_not_replace_root_owned_updater_code(world):
    Backend.version = "5.47.0"
    assert world.run().returncode == 0
    opt, data = world.w / "opt", world.w / "var-lib"
    marker = opt / "updater" / "ocw_activate.py"
    marker.write_text("# modified by the (pretend) operator\n")
    libs_before = sorted(p.name for p in (opt / "updater" / "lib").iterdir())
    (data / "audit_log.jsonl").write_text('{"action":"newer"}\n')
    p = world.run()
    assert p.returncode == 0, p.stdout + p.stderr
    assert "(reinstall)" in p.stdout
    assert marker.read_text().startswith("# modified")  # not replaced without --refresh-updater
    assert (data / "audit_log.jsonl").read_text() == '{"action":"newer"}\n'  # data untouched
    assert world.run("--refresh-updater").returncode == 0
    assert "os.execv" in marker.read_text() and marker.read_text().startswith("#!/usr/bin/env python3")
    assert set(libs_before) <= {p.name for p in (opt / "updater" / "lib").iterdir()}  # earlier generations are not removed by a refresh


def test_failed_health_check_puts_everything_back(world):
    Backend.version = "9.9.9"  # the migrated application "answers" the wrong version
    before = {p.name: p.read_text() for p in (world.unit, world.gate, world.env_file)}
    p = world.run()
    assert p.returncode != 0 and "migration rolled back" in p.stderr + p.stdout
    assert world.unit.read_text() == before[world.unit.name] and world.gate.read_text() == before[world.gate.name]
    assert world.env_file.read_text() == before[world.env_file.name]
    for f in ("audit_store.db", "audit_log.jsonl", "access_control.json"):
        assert (world.legacy / f).exists(), f
        assert not list(world.legacy.glob(f + ".migrated-*"))


def test_units_that_do_not_start_roll_back_too(world):
    Backend.version = "5.47.0"
    (world.stub / "fail_start").write_text("")
    p = world.run()
    assert p.returncode != 0
    assert str(world.legacy) in world.unit.read_text()
    assert (world.legacy / "audit_store.db").exists()


def test_legacy_sudoers_are_removed_only_when_asked_and_only_if_recognised(world):
    Backend.version = "5.47.0"
    sf = world.w / "sudoers" / "opa-compliance-wizard-deploy"
    body = ("deployer ALL=(root) NOPASSWD: /usr/bin/systemctl restart opa-compliance-wizard, /usr/bin/systemctl restart opa-auth-gate, "
            "/usr/bin/systemctl reload nginx, /usr/sbin/nginx -t\n")
    sf.write_text(body)
    assert world.run().returncode == 0 and sf.exists()  # not without the flag
    p = world.run("--remove-legacy-sudoers")
    assert p.returncode == 0 and not sf.exists()
    assert list((world.w / "opt").glob("install-backup-*/opa-compliance-wizard-deploy.sudoers"))
    sf.write_text(body + "deployer ALL=(root) NOPASSWD: /bin/rm -rf /\n")
    p = world.run("--remove-legacy-sudoers")
    assert sf.exists() and "NOT removed" in p.stdout


def test_missing_frontend_or_source_stops_before_changing_anything(world):
    shutil.rmtree(world.src / "frontend" / "dist")
    p = world.run()
    assert p.returncode != 0 and "frontend/dist/index.html is missing" in p.stderr
    assert not (world.w / "opt").exists()


def test_the_script_is_not_runnable_by_non_root_without_dry_run(world):
    e = dict(world.env)
    e.pop("OCW_INSTALL_TEST")
    p = subprocess.run(["bash", str(world.src / "server" / "install.sh"), "--yes"], capture_output=True, text=True, env=e)
    if os.geteuid() != 0:
        assert p.returncode != 0 and "run as root" in p.stderr


def test_install_hands_out_owners_releases_root_staging_to_the_staging_account_audit_files_to_the_app(world):
    # pretend the staging account exists, so install.sh picks it as owner (the real chown is a recording stub here)
    idstub = world.stub / "bin" / "id"
    idstub.write_text('#!/bin/bash\n[ "$1" = "ocw-updater" ] && exit 0\nexec /usr/bin/id "$@"\n')
    idstub.chmod(0o755)
    Backend.version = "5.47.0"
    p = world.run()
    assert p.returncode == 0, p.stderr + p.stdout
    chowns = [line.split() for line in (world.stub / "chowns").read_text().splitlines()]
    owner = {Path(line[-1]).name: line[0] for line in chowns if len(line) == 2}
    assert owner["releases"] == "root:root"
    assert owner["staging"] == "ocw-updater:ocw-updater"
    assert owner["handoff"] == "root:ocw-updater"
    for f in ("audit_log.jsonl", ".audit_log.jsonl.lock"):
        assert owner[f].split(":")[0] == world.user
        assert stat.S_IMODE((world.w / "var-lib" / f).stat().st_mode) == 0o600
    assert stat.S_IMODE((world.w / "opt" / "releases").stat().st_mode) == 0o755
    assert stat.S_IMODE((world.w / "opt" / "handoff").stat().st_mode) == 0o750


# --- version-gated updater refusals: install.sh records the release it was run from ---------------------------------

def _cfg(world):
    return json.loads((world.w / "opt" / "updater" / "config.json").read_text())


def test_install_records_the_version_it_was_run_from_and_a_rerun_from_a_newer_tree_advances_it(world):
    Backend.version = "5.47.0"
    d = world.run("--dry-run")
    assert d.returncode == 0 and "install_sh_version=5.47.0" in d.stdout and not (world.w / "opt").exists()
    assert world.run().returncode == 0
    assert _cfg(world)["install_sh_version"] == "5.47.0"
    # a plain re-run from the same tree keeps it; one from a newer unpacked release (--refresh-updater) advances it
    (world.src / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.48.0"\n')
    assert _cfg(world)["install_sh_version"] == "5.47.0"
    p = world.run("--refresh-updater")
    assert p.returncode == 0, p.stdout + p.stderr
    cfg = _cfg(world)
    assert cfg["install_sh_version"] == "5.48.0" and cfg["app_user"] == world.user and "recorded install_sh_version=5.48.0" in p.stdout
    # the units and the command were refreshed by the same run, and no data was touched
    assert (world.w / "bin" / "ocw-updater").read_text() == (REPO / "server" / "ocw-updater.sh").read_text().replace("__OPT_DIR__", str(world.w / "opt")).replace(
        "__DATA_DIR__", str(world.w / "var-lib")).replace("__APP_USER__", world.user).replace("__PYTHON3__", shutil.which("python3")).replace(
        "__ARTIFACTS_DIR__", str(world.w / "var-ocw" / "artifacts")).replace("__ENV_FILE__", str(world.env_file))


def test_a_failed_run_keeps_the_previously_recorded_version(world):
    Backend.version = "5.47.0"
    assert world.run().returncode == 0
    (world.src / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.48.0"\n')
    (world.src / "server" / "ocw-upgrade.service").unlink()  # the run dies while installing the units, after config.json is rewritten
    assert world.run("--refresh-updater").returncode != 0
    assert _cfg(world)["install_sh_version"] == "5.47.0"


# --- indented units (systemd accepts leading whitespace; the units on a real server often have it) ---------------------

def test_indented_unit_lines_are_edited_and_their_indentation_is_kept(world):
    Backend.version = "5.47.0"
    p = world.run()
    assert p.returncode == 0, p.stdout + p.stderr
    data = world.w / "var-lib"
    lines = world.unit.read_text().splitlines()
    assert f"  WorkingDirectory={world.w / 'opt'}/current" in lines
    assert f"  Environment=OPA_DATA_DIR={data}" in lines and "  Environment=PYTHONDONTWRITEBYTECODE=1" in lines
    assert lines.index("  ProtectSystem=strict") == lines.index("  ProtectHome=read-only") - 1
    assert f"  ReadWritePaths={data}" in lines and "  ReadWritePaths=/run/user/1000" in lines
    # the unindented gate unit stays unindented
    assert f"Environment=OPA_DATA_DIR={data}" in world.gate.read_text().splitlines()


def test_a_unit_without_the_expected_lines_stops_the_run_before_anything_changes_even_in_a_dry_run(world):
    before = world.unit.read_text()
    world.unit.write_text(before.replace(f"  WorkingDirectory={world.legacy}\n", ""))
    for args in (("--dry-run",), ()):
        p = world.run(*args)
        assert p.returncode != 0 and "WorkingDirectory" in p.stderr and "nothing was changed" in p.stderr, (args, p.stdout, p.stderr)
        assert not (world.w / "opt").exists() and not (world.w / "var-lib").exists()
        assert (world.legacy / "audit_store.db").exists()
    world.unit.write_text(before.replace("  ProtectHome=read-only\n", ""))
    p = world.run("--dry-run")
    assert p.returncode != 0 and "ProtectSystem" in p.stderr and not (world.w / "opt").exists()
    # an already hardened unit does not need ProtectHome
    world.unit.write_text(before.replace("  ProtectHome=read-only\n", "  ProtectSystem=strict\n"))
    assert world.run("--dry-run").returncode == 0


def test_an_indented_env_file_is_recognised(world):
    Backend.version = "5.47.0"
    world.env_file.write_text(f"  OPA_DATA_DIR=/somewhere/else\n\tOPA_AUDIT_DB_PATH={world.legacy}/audit_store.db\n")
    assert world.run().returncode == 0
    env = world.env_file.read_text()
    assert env.count("OPA_DATA_DIR=") == 1  # not added a second time
    assert f"\tOPA_AUDIT_DB_PATH={world.w / 'var-lib'}/audit_store.db" in env


# --- additional login gates ---------------------------------------------------------------------------------------------

def _add_second_gate(world, name="second", with_deny=False, listen="127.0.0.1:8080", host="opa2.example.com"):
    from server.nginx_second_site import build
    user = world.user
    unit = world.w / "units" / f"opa-auth-gate-{name}.service"
    unit.write_text(f"[Service]\nUser={user}\nWorkingDirectory={world.legacy}\nExecStart={world.legacy}/.venv/bin/python server/auth_gate.py --port 8768\n"
                    f"ReadWritePaths={world.legacy}\n")
    (world.stub / "units" / f"opa-auth-gate-{name}.props").write_text(
        f"FragmentPath={unit}\nUser={user}\nWorkingDirectory={world.legacy}\nActiveState=active\nNRestarts=0\n")
    text = build(MAIN_SITE, 8768, listen, host, name, allow_public_listen=not listen.startswith("127."))
    if not with_deny:
        text = text.replace("    location /api/upgrade {\n        return 403;\n    }\n", "")
        assert "/api/upgrade" not in text
    site = world.w / "nginx-sites" / f"opa-{name}"
    site.write_text(text)
    return site, unit


def test_second_gates_are_announced_loudly_in_the_dry_run_and_the_real_run(world):
    Backend.version = "5.47.0"
    site, _unit = _add_second_gate(world)
    d = world.run("--dry-run")
    assert d.returncode == 0, d.stdout + d.stderr
    assert "ADDITIONAL LOGIN GATES FOUND: second" in d.stdout and "does NOT deny /api/upgrade" in d.stdout
    assert f"server/install.sh --regenerate-second-sites" in d.stdout
    p = world.run()
    assert p.returncode == 0, p.stdout + p.stderr
    assert "ACTION NEEDED" in p.stdout and "--regenerate-second-sites" in p.stdout and "second" in p.stdout.split("ACTION NEEDED")[1]
    assert "/api/upgrade" not in site.read_text()  # not touched without the flag


def test_regenerate_second_sites_adds_the_deny_keeps_the_rest_and_validates_nginx(world):
    Backend.version = "5.47.0"
    site, _unit = _add_second_gate(world)
    before = site.read_text()
    p = world.run("--regenerate-second-sites")
    assert p.returncode == 0, p.stdout + p.stderr
    after = site.read_text()
    assert "location /api/upgrade {\n        return 403;\n    }" in after
    assert "listen 127.0.0.1:8080;" in after and "server_name opa2.example.com;" in after and "127.0.0.1:8768" in after
    assert "ACTION NEEDED" not in p.stdout
    # only the deny block was added
    import difflib
    changed = [l for l in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    assert all(l.startswith("+") for l in changed) and any("/api/upgrade" in l for l in changed)
    c = calls(world)
    assert "nginx -t" in c and "systemctl reload nginx" in c
    assert list((world.w / "opt").glob("install-backup-*/opa-second.site.before"))
    # idempotent
    assert world.run("--regenerate-second-sites").returncode == 0
    assert site.read_text() == after


def test_regenerate_second_sites_keeps_an_operator_chosen_public_listen_address(world):
    Backend.version = "5.47.0"
    site, _unit = _add_second_gate(world, listen="10.0.0.5:8080")
    assert world.run("--regenerate-second-sites").returncode == 0
    assert "listen 10.0.0.5:8080;" in site.read_text() and "location /api/upgrade" in site.read_text()


def test_regenerate_second_sites_puts_the_old_site_back_when_nginx_rejects_the_new_one(world):
    Backend.version = "5.47.0"
    site, _unit = _add_second_gate(world)
    before = site.read_text()
    (world.stub / "nginx_bad").write_text("")
    p = world.run("--regenerate-second-sites")
    assert p.returncode != 0 and "nginx -t rejected the regenerated site" in p.stdout
    assert site.read_text() == before
    assert "systemctl reload nginx" not in calls(world)


def test_regenerate_second_sites_reports_a_missing_site_and_fails(world):
    Backend.version = "5.47.0"
    site, _unit = _add_second_gate(world)
    site.unlink()
    p = world.run("--regenerate-second-sites")
    assert p.returncode != 0 and "no regular file" in p.stdout


def test_a_second_site_that_already_denies_upgrade_is_reported_ok(world):
    Backend.version = "5.47.0"
    _add_second_gate(world, with_deny=True)
    p = world.run("--dry-run")
    assert "already denies /api/upgrade" in p.stdout and "does NOT" not in p.stdout
