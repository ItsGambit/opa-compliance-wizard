"""A fake machine for the root-owned updater's tests.

`Machine` builds, in a temp directory, the /opt + /var/lib layout of an
install at version 5.46.0 (real SQLite archive, a trust list, an nginx site,
an environment file with SEEDED FAKE SECRETS) and a `FakeHost` that stands in
for systemd, journald, nginx and the network on loopback. The updater code
under test is the real code: only `SystemHost.run`, `http_get`, `sleep`,
`now`, `free_bytes` and `chown_tree` are replaced, so the parsing of systemctl
output, the database tool and every file operation are exercised for real.

The fake backend "starts" a release by reading the SCRIPT_VERSION of whatever
`current` points at (like a real restart); `crash_versions` makes that
release crash-loop, `schema_on_start` makes it migrate the archive on start,
`unhealthy_versions` makes /healthz degraded, and so on.
"""

import contextlib
import io
import json
import os
import re
import sqlite3
import sys
import tarfile
from pathlib import Path

ROOT_DIR = str(Path(__file__).resolve().parent.parent / "server" / "updater" / "root")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))  # nginx_bake

import ocw_activate as act  # noqa: E402
import ocw_host  # noqa: E402
import ocw_trust  # noqa: E402
from release_helpers import TestKey, TestStandby, key_list, make_release_tar, sign_release  # noqa: E402

PROXY_SECRET = "test-proxy-secret-0123456789abcdef"
FAKE_SECRETS = {
    "KEYRING_UNLOCK_PASSWORD": "hunter2-keyring-unlock-FAKE",
    "NGINX_PROXY_SECRET": PROXY_SECRET,
    "INTERNAL_API_SHARED_SECRET": "internal-shared-FAKE-value-77",
    "OKTA_API_TOKEN": "00" + "A1b2C3d4" * 5,
}
SEED_EMAIL = "someone@example.com"
SEED_HOST = "tenant-one.example.com"
SEED_ENV_NAME = "prod-example"
SITE_TEMPLATE = """server {{
    listen 443 ssl;
    server_name {name};
    ssl_certificate {cert};
    ssl_certificate_key {key};
    set $nginx_proxy_secret "{secret}";
    location / {{ proxy_pass http://127.0.0.1:8766; }}
}}
"""
SITE_NEW_TEMPLATE = SITE_TEMPLATE.replace("location /", "if (-f /opt/x/maintenance/active.html) {{ return 503; }}\n    location /")


class FakeHost(ocw_host.SystemHost):
    def __init__(self, machine):
        super().__init__(None, None)
        self.m = machine
        self.clock = 1_800_000_000.0
        self.calls = []
        self.units = {}
        self.pid = 1000
        self.serving = {}          # unit -> version
        self.crash_versions = set()
        self.unhealthy_versions = set()
        self.schema_on_start = {}  # version -> migration number to apply on start
        self.fail_migration = set()
        self.restart_fail_units = set()
        self.nginx_t_results = []
        self.reloads = 0
        self.free = 50 * 2**30
        self.stage_calls = []
        self.fake_journal = {}
        for u, port in (("opa-compliance-wizard", 8766), ("opa-auth-gate", 8767)):
            self.units[u] = {"ActiveState": "active", "MainPID": str(self._next_pid()), "NRestarts": "0", "port": port, "enabled": True}
        self.serving["opa-compliance-wizard"] = "5.46.0"
        self.kill_on = None  # a callable(argv) that may raise act.Killed

    def _next_pid(self):
        self.pid += 1
        return self.pid

    # --- time
    def now(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def free_bytes(self, path):
        return self.free

    def chown_tree(self, root, uid=0, gid=0):
        self.calls.append(("chown_tree", root))
        for base, dirs, files in os.walk(root):
            for n in dirs + files:
                p = os.path.join(base, n)
                if not os.path.islink(p):
                    os.chmod(p, os.lstat(p).st_mode & ~0o022)

    # --- the machine
    def _start_unit(self, unit):
        u = self.units[unit]
        if unit in self.restart_fail_units:
            return False
        if unit == "opa-compliance-wizard":
            ver = _installed(self.m.opt_current())
            u["MainPID"] = str(self._next_pid())
            if ver in self.crash_versions:
                u.update(ActiveState="activating", NRestarts="1")
                self.serving.pop(unit, None)
                return True
            if ver in self.fail_migration and ver in self.schema_on_start:
                u.update(ActiveState="activating", NRestarts="1")
                return True
            n = self.schema_on_start.get(ver)
            if n is not None:
                conn = sqlite3.connect(self.m.db)
                conn.execute("INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, 'now')", (n,))
                conn.commit()
                conn.close()
            self.serving[unit] = ver
        else:
            u["MainPID"] = str(self._next_pid())
        u.update(ActiveState="active", NRestarts="0")
        return True

    def run(self, argv, timeout=120):
        self.calls.append(tuple(argv))
        if self.kill_on:
            self.kill_on(argv)
        prog, args = argv[0], list(argv[1:])
        if prog == sys.executable:
            return super().run(argv, timeout)
        if prog == "systemctl":
            return self._systemctl(args)
        if prog == "journalctl":
            unit = args[args.index("-u") + 1] if "-u" in args else "?"
            return 0, self.fake_journal.get(unit, f"log line for {unit}\n")
        if prog == "nginx" and args == ["-t"]:
            rc = self.nginx_t_results.pop(0) if self.nginx_t_results else 0
            return rc, "nginx: configuration file test is successful\n" if rc == 0 else "nginx: [emerg] stub failure\n"
        return 127, "not found"

    def _systemctl(self, args):
        words = [a for a in args if not a.startswith("-")]
        props = [args[i + 1] for i, a in enumerate(args) if a == "-p"]
        words = [w for w in words if w not in props]
        if args == ["--version"]:
            return 0, "systemd 252 (252.22-1)\n+PAM\n"
        cmd, rest = words[0], words[1:]
        name = (rest[0] if rest else "")
        name = name[:-len(".service")] if name.endswith(".service") else name
        if cmd == "cat":
            return (0, "") if name in self.units else (1, "")
        if cmd == "is-enabled":
            return (0, "") if self.units.get(name, {}).get("enabled") else (1, "")
        if cmd == "list-unit-files":
            lines = "".join(f"{u}.service enabled enabled\n" for u in sorted(self.units) if u.startswith("opa-auth-gate-"))
            return 0, lines
        if cmd == "show":
            u = self.units.get(name, {})
            prop = props[0]
            if prop == "ExecStart":
                return 0, f"{{ path=/x ; argv[]=/x/python server/auth_gate.py --port {u.get('port', 8767)} ; }}\n"
            return 0, str(u.get(prop, "")) + "\n"
        if cmd == "status":
            return 0, f"* {name} - stub status\n  Active: {self.units.get(name, {}).get('ActiveState')}\n"
        if cmd == "restart":
            if name not in self.units:
                return 5, "Unit not found"
            return (0, "") if self._start_unit(name) else (1, "Job failed")
        if cmd == "start":
            if name.startswith("ocw-stage@"):
                ver = name.split("@", 1)[1]
                self.stage_calls.append(ver)
                return self.m.stage_impl(ver)
            if name == "ocw-upgrade":  # what the path unit / due timer would start
                act.run(self.m.cfg(), self)
                return 0, ""
            return (0, "") if name in self.units and self._start_unit(name) else (1, "")
        if cmd == "stop":
            if name in self.units:
                self.units[name]["ActiveState"] = "inactive"
            return 0, ""
        if cmd == "reload" and rest == ["nginx"]:
            self.reloads += 1
            return 0, ""
        if cmd in ("enable", "disable"):
            return 0, ""
        return 64, f"unhandled {args}"

    def http_get(self, port, path, headers=None, timeout=3):
        self.calls.append(("http", port, path))
        be = self.units["opa-compliance-wizard"]
        if port == 8766:
            if be["ActiveState"] != "active" or "opa-compliance-wizard" not in self.serving:
                return None, ""
            ver = self.serving["opa-compliance-wizard"]
            if path == "/api/version":
                return 200, json.dumps({"version": ver})
            if path == "/healthz":
                return 200, json.dumps({"status": "degraded" if ver in self.unhealthy_versions else "ok"})
            if path == "/api/environments":
                return (200, "[]") if (headers or {}).get("X-Nginx-Proxy-Secret") == PROXY_SECRET else (403, "")
        for u, v in self.units.items():
            if v.get("port") == port and path == "/verify":
                return (401, "") if v["ActiveState"] == "active" else (None, "")
        return None, ""

    def db_tool(self, args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ocw_host.dbtool_main(list(args))
        return json.loads(buf.getvalue().strip().splitlines()[-1])


def _installed(release_dir):
    real = os.path.realpath(release_dir)
    m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', Path(real, "create_secret_folders.py").read_text(), re.M)
    return m.group(1)


class Machine:
    """The temp layout + the fake host + a release builder."""

    def __init__(self, tmp_path, version="5.46.0"):
        self.root = Path(tmp_path)
        self.opt = self.root / "opt"
        self.data = self.root / "var-lib"
        self.etc = self.root / "etc"
        self.db = str(self.data / "audit_store.db")
        self.primary, self.standby = TestKey(), TestStandby()
        self.key_list = key_list([self.primary, self.standby])
        for d in (self.opt / "releases", self.opt / "updater", self.data / "upgrade" / "inbox" / "requests", self.etc, self.root / "nginx"):
            d.mkdir(parents=True, exist_ok=True)
        self.install_release(version)
        os.symlink(f"releases/{version}", self.opt / "current")
        (self.opt / "updater" / "config.json").write_text(json.dumps({
            "app_user": "nobody", "app_group": "nogroup", "backend_service": "opa-compliance-wizard", "gate_service": "opa-auth-gate",
            "nginx_site": str(self.root / "nginx" / "site"), "backend_port": 8766}))
        trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list(json.dumps(self.key_list).encode()), "revoked": []}
        (self.opt / "updater" / "trust.json").write_text(json.dumps(trust))
        (self.etc / "app.env").write_text("".join(f"{k}={v}\n" for k, v in FAKE_SECRETS.items()) + f"OPA_AUDIT_DB_PATH={self.db}\n")
        self.site = self.root / "nginx" / "site"
        self.site.write_text(SITE_TEMPLATE.format(name="opa.example.com", cert="/c/full.pem", key="/c/key.pem", secret=PROXY_SECRET))
        self._make_db()
        self.env = {"OCW_OPT_DIR": str(self.opt), "OCW_DATA_DIR": str(self.data), "OCW_ENV_FILE": str(self.etc / "app.env"),
                    "OCW_TEST_MODE": "1", "OCW_FAST": "1",
                    "OCW_ARTIFACTS_DIR": str(self.data / "upgrade" / "artifacts")}
        self.host = FakeHost(self)
        self.releases_dir = self.root / "dist"
        self.releases_dir.mkdir()
        self.stage_overrides = {}

    # --- construction
    def install_release(self, version):
        d = self.opt / "releases" / version
        (d / "server" / "updater").mkdir(parents=True, exist_ok=True)
        (d / "create_secret_folders.py").write_text(f'SCRIPT_VERSION = "{version}"\n')
        (d / ".venv" / "bin").mkdir(parents=True, exist_ok=True)

    def _make_db(self):
        conn = sqlite3.connect(self.db)
        conn.executescript(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT);"
            "CREATE TABLE chain_heads (environment_id TEXT PRIMARY KEY, manifest_id TEXT, head_hash TEXT, updated_at TEXT);"
            "CREATE TABLE sync_state (environment_id TEXT PRIMARY KEY, last_synced_at TEXT, last_sync_status TEXT, last_sync_attempt_at TEXT);"
            "CREATE TABLE events (id INTEGER PRIMARY KEY, who TEXT, what TEXT);")
        for v in range(1, 10):
            conn.execute("INSERT INTO schema_migrations VALUES (?, 'then')", (v,))
        conn.execute("INSERT INTO chain_heads VALUES ('env-a', 'm1', 'hash-a', 'then')")
        conn.execute("INSERT INTO chain_heads VALUES ('env-b', 'm2', 'hash-b', 'then')")
        conn.execute("INSERT INTO sync_state VALUES ('env-a', '2020-01-01T00:00:00', 'success', '2020-01-01T00:00:00')")
        for i in range(50):
            conn.execute("INSERT INTO events (who, what) VALUES (?, ?)", (f"user{i}@example.com", f"event {i}"))
        conn.commit()
        conn.close()

    def opt_current(self):
        return str(self.opt / "current")

    def cfg(self):
        return act.Cfg(self.env)

    def updater(self):
        return act.Updater(self.cfg(), self.host)

    # --- releases
    def build_release(self, version, **kw):
        """A signed release tarball in self.releases_dir (the artifact an operator brings)."""
        root_files = {}
        for p in Path(ROOT_DIR).glob("*.py"):
            root_files[f"server/updater/root/{p.name}"] = p.read_bytes()
        root_files["server/nginx_bake.py"] = (Path(ROOT_DIR).parent.parent / "nginx_bake.py").read_bytes()
        files = {
            "requirements.lock": b"# lock\n",
            "server/nginx-opa-secrets-wizard.conf": kw.pop("nginx", SITE_NEW_TEMPLATE.format(
                name="REPLACE_WITH_SERVER_NAME", cert="REPLACE_WITH_CERT", key="REPLACE_WITH_KEY", secret="REPLACE_WITH_SECRET")),
            **root_files, **kw.pop("extra_files", {}),
        }
        over = {"expected_schema_version": kw.pop("expected_schema_version", None), "nginx_template_changed": kw.pop("nginx_changed", False),
                "migrations": kw.pop("migrations", []), "downtime_estimate_seconds": 45}
        over = {k: v for k, v in over.items() if v is not None}
        signer = kw.pop("signer", self.primary)
        tar = make_release_tar(self.releases_dir / f"ocw-{version}.tar.gz", version, kw.pop("key_list", self.key_list),
                               extra_files=files, manifest_over={**over, **kw.pop("manifest_over", {})}, **kw)
        sign_release(tar, signer, version)
        return tar

    def stage_impl(self, version):
        """What ocw-stage@<version> does, without pip: unpack the artifact into releases/<version>."""
        over = self.stage_overrides.get(version)
        if over:
            return over()
        art = self.data / "upgrade" / "artifacts"
        tar, sig = art / f"ocw-{version}.tar.gz", art / f"ocw-{version}.tar.gz.minisig"
        if not tar.exists():
            return 1, "no artifact"
        try:
            info = ocw_trust.verify_release(str(tar), str(sig), ocw_trust.load_trust(str(self.opt / "updater" / "trust.json")), "5.46.0")
        except ocw_trust.TrustError as exc:
            for p in (tar, sig):
                os.replace(p, str(p) + ".rejected")
            (art / f"{version}.stage-error.json").write_text(json.dumps({"code": exc.code, "message": str(exc)}))
            return 1, str(exc)
        dest = self.opt / "releases" / version
        with tarfile.open(tar, "r:gz") as t:
            for m in t:
                if m.isreg():
                    p = dest / m.name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(t.extractfile(m).read())
        (dest / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
        (dest / ".staged").write_text(json.dumps({"version": version, "sha256": info["sha256"], "key_id": info["key_id"],
                                                  "staged_at": "now", "pip_freeze": ["cryptography==1.0"], "pip_freeze_sha256": "0" * 64}))
        return 0, ""

    def put_artifacts(self, version):
        art = self.data / "upgrade" / "artifacts"
        art.mkdir(parents=True, exist_ok=True)
        for n in (f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig"):
            (art / n).write_bytes((self.releases_dir / n).read_bytes())

    def request(self, version, tar=None, **over):
        tar = tar or (self.releases_dir / f"ocw-{version}.tar.gz")
        import hashlib
        sha = hashlib.sha256(Path(tar).read_bytes()).hexdigest()
        req = {"schema": 1, "action": "apply", "correlation_id": "upg-00000000",
               "version": version, "sha256": sha, "action_id": None, "requested_at": act.iso(self.host.now()), "not_before": None,
               "origin": "cli", "actor": "cli:tester", "trigger_kind": "cli"}
        req.update(over)
        return req

    def read_state(self):
        return json.loads((self.data / "upgrade" / "state.json").read_text())

    def audit_actions(self):
        p = self.data / "audit_log.jsonl"
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []
