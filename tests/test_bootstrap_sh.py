"""get-ocw.sh, the one-line installer, rendered from the template with TEST keys and run for real against a fake release server
on loopback: system detection, existing-install detection, version resolution, mirror rules, download limits, verification
(good, wrong key, standby key, revoked key, known_good, tampered tarball, truncated download, downgrade), the hand-over flags
to server/install.sh (a recording stub for most tests; the real install.sh against a real release tree for the end-to-end ones),
prompts through the terminal only, the dry run, the log, and the rule that no secret is ever printed or logged.

The script is generated for each test by tools/render_bootstrap.py from the REAL template and the REAL embedded verifier; only
the key list inside it is the test list. OCW_INSTALL_TEST=1 skips the root-only checks and enables the OCW_* path overrides."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from release_helpers import TestKey, TestStandby, key_list, make_release_tar, make_revocation, revocation_payload, sign_release
from fake_release_server import FakeReleaseServer
from test_install_fresh import STUBS, Backend

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import render_bootstrap as rb  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("bash"), reason="get-ocw.sh is a Linux server script")

STUB_INSTALL = r'''#!/bin/bash
echo "$@" >> "$STUB/install.args"
echo "PWD-SCRIPT $0" >> "$STUB/install.where"
for a in "$@"; do
  if [ "$a" = "--dry-run" ]; then echo "STUB PLAN (dry run)"; exit 0; fi
done
echo "STUB INSTALL RAN"
exit "$(cat "$STUB/install_rc" 2>/dev/null || echo 0)"
'''
STUB_PYTHON = r'''#!/bin/bash
# python3 that reports the facts a test asks for to the system check, and is the real python3 for everything else
if [ "$1" = "-I" ] && [ "$2" = "-c" ] && [[ "$3" == *sqlite3* ]] && [ -n "$FAKE_PY_FACTS" ]; then
  printf '%s\n' $FAKE_PY_FACTS
  exit 0
fi
exec /usr/bin/python3 "$@"
'''
OS_RELEASES = {
    "debian13": 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n',
    "debian12": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
    "debian11": 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nID=debian\nVERSION_ID="11"\n',
    "ubuntu2404": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n',
    "ubuntu2004": 'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="20.04"\n',
    "rocky9": 'NAME="Rocky Linux"\nPRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n',
    "alpine": 'PRETTY_NAME="Alpine Linux v3.20"\nID=alpine\nVERSION_ID=3.20.0\n',
    "mint": 'PRETTY_NAME="Linux Mint 22"\nID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\n',
}
HEX64 = re.compile(r"[0-9a-f]{64}")


def full_tree_files():
    """Everything a real install.sh run needs from an unpacked release, as {path: bytes}."""
    files = {}
    for f in (REPO / "server" / "updater" / "root").glob("*.py"):
        files[f"server/updater/root/{f.name}"] = f.read_bytes()
    for name in ("nginx_bake.py", "ocw-stage@.service", "ocw-upgrade.path", "ocw-upgrade.service", "ocw-upgrade-due.service", "ocw-upgrade-due.timer",
                 "ocw-updater.sh", "install.sh", "nginx_second_site.py", "opa-compliance-wizard.service", "opa-auth-gate.service", "start-headless.sh",
                 "nginx-opa-secrets-wizard.conf", "install_helpers.py"):
        files[f"server/{name}"] = (REPO / "server" / name).read_bytes()
    files["requirements.lock"] = b"# empty on purpose\n"
    return files


class BW:
    def __init__(self, tmp_path):
        self.w = tmp_path
        self.key, self.standby = TestKey(), TestStandby()
        self.kl = key_list([self.key, self.standby])
        self.keys_bytes = (json.dumps(self.kl) + "\n").encode()
        self.server = FakeReleaseServer()
        self.stub = tmp_path / "stub"
        (self.stub / "bin").mkdir(parents=True)
        for name, body in STUBS.items():
            self.put_stub(name, body)
        self.put_stub("apt-get", '#!/bin/bash\necho "$*" >> "$STUB/apt.calls"\n[ ! -e "$STUB/apt_fail" ] || { echo "E: simulated apt failure" >&2; exit 100; }\nexit 0\n')
        self.put_stub("dpkg-query", "#!/bin/bash\nexit 1\n")
        self.put_stub("python3", STUB_PYTHON)
        for d in ("units", "nginx-sites", "nginx-enabled", "etc", "bin", "sudoers", "wheels", "systemd", "logs", "work"):
            (tmp_path / d).mkdir()
        self.os_release = tmp_path / "os-release"
        self.os_release.write_text(OS_RELEASES["debian13"])
        self.answers = tmp_path / "answers"
        self.answers.write_text("")
        self.opt, self.data = tmp_path / "opt", tmp_path / "var-lib"
        self.releases = {}
        Backend.version = "5.52.0"
        self.env = dict(os.environ, PATH=f"{self.stub / 'bin'}:{os.environ['PATH']}", STUB=str(self.stub), OCW_INSTALL_TEST="1", OCW_TEST_MODE="1", OCW_FAST="1",
                        OCW_OS_RELEASE=str(self.os_release), OCW_UNAME_M="x86_64", OCW_SYSTEMD_DIR=str(tmp_path / "systemd"), OCW_MIN_FREE_KB_TEST="1024",
                        OCW_OPT_DIR=str(self.opt), OCW_DATA_DIR=str(self.data), OCW_UNIT_DIR=str(tmp_path / "units"), OCW_BIN_DIR=str(tmp_path / "bin"),
                        OCW_ENV_FILE=str(tmp_path / "etc" / "opa-compliance-wizard.env"), OCW_SUDOERS_DIR=str(tmp_path / "sudoers"),
                        OCW_ARTIFACTS_DIR=str(tmp_path / "var-ocw" / "artifacts"), OCW_UPDATER_ENV=str(tmp_path / "etc" / "ocw-updater.env"),
                        OCW_NGINX_SITES_DIR=str(tmp_path / "nginx-sites"), OCW_NGINX_ENABLED_DIR=str(tmp_path / "nginx-enabled"),
                        OCW_NGINX_SSL_DIR=str(tmp_path / "nginx-ssl"), OCW_SESSION_KEY_FILE=str(tmp_path / "etc" / "session.key"),
                        OCW_LOG_DIR=str(tmp_path / "logs"), OCW_WORK_BASE=str(tmp_path / "work"), OCW_TTY=str(self.answers),
                        OCW_GITHUB_BASE=f"{self.server.base}/gh")
        for k in ("OCW_RELEASE_BASE_URL", "OCW_REVOCATION_URL", "FAKE_PY_FACTS", "OCW_INSTALL_LOGGING", "https_proxy", "HTTPS_PROXY", "http_proxy"):
            self.env.pop(k, None)
        self.render("5.52.0")

    def put_stub(self, name, body):
        p = self.stub / "bin" / name
        p.write_text(body)
        p.chmod(0o755)

    def render(self, version):
        files = {rb.TEMPLATE_PATH: (REPO / rb.TEMPLATE_PATH).read_bytes()}
        for _n, path in rb.EMBEDDED:
            files[path] = (REPO / path).read_bytes()
        files["server/release_keys.json"] = self.keys_bytes
        self.script = self.w / "get-ocw.sh"
        self.script.write_bytes(rb.render(version, files))

    def publish(self, version="5.52.0", key=None, stub_install=True, latest=True, alg=b"ED", kl=None, mutate=None, **kw):
        """Builds, signs and serves release `version`. Returns (tarball path, signature path)."""
        d = self.w / f"rel-{version}-{len(self.releases)}"
        d.mkdir()
        extra = full_tree_files()
        extra["frontend/dist/index.html"] = b"<html>built</html>\n"
        if stub_install:
            extra = {"server/install.sh": STUB_INSTALL.encode()}
        extra.update(kw.pop("extra_files", {}))
        tar = make_release_tar(d / f"ocw-{version}.tar.gz", version, kl or self.kl, extra_files=extra, **kw)
        sig = sign_release(tar, key or self.key, version, alg=alg)
        body = Path(tar).read_bytes()
        if mutate:
            body = mutate(body)
        self.releases[version] = (tar, sig)
        self.server.respond(f"/gh/download/v{version}/ocw-{version}.tar.gz", body=body)
        self.server.respond(f"/gh/download/v{version}/ocw-{version}.tar.gz.minisig", body=Path(sig).read_bytes())
        if latest:
            self.server.respond("/gh/latest/download/manifest.json", body=json.dumps({"version": version}).encode())
        return tar, sig

    def revocation(self, serial=1, revoke=None, add=None, known_good=None, path="/gh/download/revocation/revocation.json", signer=None):
        d = self.w / f"rev-{serial}"
        d.mkdir(exist_ok=True)
        f = d / "revocation.json"
        item = revoke if revoke is not None else self.key.key_id
        if known_good:
            item = {"key_id": item, "known_good": known_good}
        make_revocation(f, [signer or self.standby], revocation_payload(serial, revoke=[item], add_keys=[add] if add else []))
        self.server.respond(path, body=f.read_bytes())
        return f

    def run(self, *args, extra_env=None, answers=None, stdin=subprocess.DEVNULL, script=None):
        if answers is not None:
            self.answers.write_text(answers)
        e = dict(self.env, **(extra_env or {}))
        return subprocess.run(["bash", str(script or self.script), *args], capture_output=True, text=True, env=e, timeout=300, stdin=stdin, start_new_session=True)

    def install_args(self):
        f = self.stub / "install.args"
        return f.read_text().splitlines() if f.exists() else []

    def work_dirs(self):
        return [p for p in (self.w / "work").iterdir()]

    def logs(self):
        return sorted((self.w / "logs").glob("*.log"))


@pytest.fixture
def bw(tmp_path):
    w = BW(tmp_path)
    yield w
    w.server.close()


# --- the happy path -------------------------------------------------------------------------------------------------------------


def test_a_fresh_install_downloads_verifies_plans_confirms_installs_packages_and_hands_over(bw):
    bw.publish()
    (bw.stub / "bin" / "nginx").unlink()          # this server has no nginx yet
    p = bw.run("--server-name", "opa.example.com", "--self-signed", answers="y\n")
    assert p.returncode == 0, p.stderr + p.stdout
    out = p.stdout
    for needle in ("ok  system: Debian GNU/Linux 13 (trixie) (x86_64), systemd, Python 3.", "SQLite 3.", "ok  existing install: none found (a fresh install)",
                   f"ok  release 5.52.0: signature valid (key {bw.key.key_id}, signed 2026-01-15T10:00:00Z); sha256 ", "no key revocation published",
                   "Plan: fresh, release 5.52.0", "packages from your distribution", "STUB PLAN (dry run)", "STUB INSTALL RAN"):
        assert needle in out, (needle, out)
    # packages: only after the plan was confirmed, never anything unasked
    apt = (bw.stub / "apt.calls").read_text()
    assert "update" in apt and "install -y -q --no-install-recommends" in apt and "nginx" in apt and "gnome-keyring" in apt and "dbus-user-session" in apt
    # the flags handed to install.sh: first the dry run for the plan, then the real run with --yes after the one confirmation
    first, second = bw.install_args()
    for a in (first, second):
        assert "--source" in a and "/release " in a + " " and "--release-info" in a and "--create-app-user" in a and "--server-name opa.example.com" in a and "--self-signed" in a
        assert "--app-user ocw" in a and "--log" in a
    assert first.endswith("--dry-run") and second.endswith("--yes") and "--dry-run" not in second
    # the work directory is gone, the log is there and 0600 and names every step
    assert not bw.work_dirs()
    log = bw.logs()[0]
    assert stat.S_IMODE(log.stat().st_mode) == 0o600 and "ok  release 5.52.0" in log.read_text() and f"Log: {log}" in out


def test_the_verified_release_tree_is_what_install_sh_runs_from_and_is_not_writable_by_others(bw):
    bw.publish(extra_files={"extra/file.txt": b"data\n"})
    p = bw.run("--server-name", "a.example.com", "--self-signed", "--keep-work", answers="y\n")
    assert p.returncode == 0, p.stderr
    (work,) = bw.work_dirs()
    rel = work / "release-parent" / "release"
    assert (rel / "extra" / "file.txt").read_text() == "data\n" and not (rel.stat().st_mode & 0o022) and not ((rel / "server" / "install.sh").stat().st_mode & 0o022)
    info = json.loads((work / "release-info.json").read_text())
    assert info["version"] == "5.52.0" and info["key_id"] == bw.key.key_id and stat.S_IMODE((work / "release-info.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(work.stat().st_mode) == 0o700
    assert (bw.stub / "install.where").read_text().strip().split()[-1] == str(rel / "server" / "install.sh")


def test_latest_is_resolved_from_the_manifest_and_a_specific_version_can_be_named(bw):
    bw.publish("5.52.0")
    bw.publish("5.53.0", latest=False)
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0 and "release 5.52.0: signature valid" in p.stdout
    p = bw.run("--dry-run", "--version", "5.53.0", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0 and "release 5.53.0: signature valid" in p.stdout
    reqs = [r["path"] for r in bw.server.requests]
    assert "/gh/latest/download/manifest.json" in reqs and reqs.count("/gh/latest/download/manifest.json") == 1   # the second run never asked


def test_a_manifest_that_names_a_different_release_than_the_one_signed_is_refused(bw):
    bw.publish("5.52.0")
    bw.server.respond("/gh/latest/download/manifest.json", body=json.dumps({"version": "5.53.0"}).encode())
    bw.publish("5.53.0", latest=False, script_version="5.52.0")   # a validly signed file whose content says another version
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 2 and "refused:" in p.stderr and "Nothing was changed" in p.stderr


def test_version_command_names_the_release_and_the_keys(bw):
    p = bw.run("--version")
    assert p.returncode == 0 and p.stdout.strip() == f"get-ocw.sh from release 5.52.0; knows release keys: {bw.key.key_id} (release), {bw.standby.key_id} (standby)"


# --- verification refusals ------------------------------------------------------------------------------------------------------


def refused(bw, *args, fragment, **kw):
    p = bw.run(*args, **kw)
    assert p.returncode == 2, p.stderr + p.stdout
    assert fragment in p.stderr and "Nothing was changed" in p.stderr, p.stderr
    assert not bw.work_dirs() and not (bw.stub / "apt.calls").exists() and not (bw.stub / "install.args").exists()
    assert not bw.opt.exists() and not bw.data.exists()
    return p


def test_a_tampered_tarball_is_refused_and_nothing_is_installed(bw):
    bw.publish(mutate=lambda b: b[:-20] + bytes(x ^ 1 for x in b[-20:]))
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="signature does not match the file")


def test_a_truncated_download_is_a_failure_not_an_install(bw):
    bw.publish()
    bw.server.respond("/gh/download/v5.52.0/ocw-5.52.0.tar.gz", body=Path(bw.releases["5.52.0"][0]).read_bytes(), mode="truncate")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 3 and "failed: could not download the release" in p.stderr and "cut short" in p.stderr and "Nothing was changed" in p.stderr
    assert not bw.work_dirs() and not (bw.stub / "install.args").exists()


def test_a_release_signed_by_an_unknown_key_says_to_fetch_the_current_installer(bw):
    bw.publish(key=TestKey())
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="not trusted on this server")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert "Download the current get-ocw.sh" in p.stderr


def test_a_release_signed_by_a_key_claiming_the_standby_id_is_refused(bw):
    forged = TestKey()
    forged.stored_id = bytes.fromhex(bw.standby.key_id)[::-1]
    forged.key_id = bw.standby.key_id
    bw.publish(key=forged)
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="may not sign releases")


def test_a_legacy_signature_is_refused(bw):
    bw.publish(alg=b"Ed")
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="legacy")


def test_a_missing_signature_file_stops_the_run(bw):
    bw.publish()
    bw.server.script.pop("/gh/download/v5.52.0/ocw-5.52.0.tar.gz.minisig")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 3 and "without the signature nothing can be installed" in p.stderr and not bw.work_dirs()


def test_a_standby_signed_revocation_revokes_the_key_before_the_release_is_checked(bw):
    bw.publish()
    bw.revocation(1, add=TestKey())
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="is revoked")


def test_known_good_pin_lets_the_revoked_keys_old_release_through(bw):
    tar, _sig = bw.publish()
    sha = hashlib.sha256(Path(tar).read_bytes()).hexdigest()
    bw.revocation(1, add=TestKey(), known_good={"5.52.0": sha})
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "key revocation serial 1 applied" in p.stdout
    # and the applied file is handed to install.sh, for root's trust list and the application
    args = bw.install_args()[0]
    assert "--revocation" in args and "revocation-0000000001.json" in args


def test_garbage_and_forged_revocation_files_never_block_an_install(bw):
    bw.publish()
    bw.server.respond("/gh/download/revocation/revocation.json", body=b"<html>an error page</html>")
    bw.revocation(2, signer=TestStandby(), path="/gh/download/revocation-1/revocation.json")
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr + p.stdout
    assert p.stdout.count("ignored") == 2 and "no valid key revocation applied" in p.stdout and "--revocation" not in bw.install_args()[0]


def test_the_owners_static_revocation_url_is_a_third_source(bw):
    bw.publish()
    bw.revocation(1, add=TestKey(), path="/static/revocation.json")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed", extra_env={"OCW_REVOCATION_URL": f"{bw.server.base}/static/revocation.json"})
    assert p.returncode == 2 and "is revoked" in p.stderr
    assert "/static/revocation.json" in [r["path"] for r in bw.server.requests]
    assert "--revocation-url" in " ".join(bw.install_args()) or not bw.install_args()


def test_when_no_revocation_source_can_be_read_the_run_asks_and_yes_needs_the_named_flag(bw):
    bw.publish()
    bw.server.respond("/gh/download/revocation/revocation.json", status=500, body=b"x")
    p = bw.run("--server-name", "a.example.com", "--self-signed", answers="n\n")
    assert p.returncode == 2 and "could not check for a published key revocation" in p.stdout and "not confirmed" in p.stderr and not bw.work_dirs()
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 2 and "--yes-no-revocation-check" in p.stderr
    p = bw.run("--yes", "--yes-no-revocation-check", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0 and "continuing without a revocation check" in p.stdout


def test_downgrade_below_the_installers_own_release_needs_allow_older(bw):
    bw.publish("5.49.0")
    refused(bw, "--yes", "--version", "5.49.0", "--server-name", "a.example.com", "--self-signed", fragment="5.49.0 is older than this installer (5.52.0)")
    p = bw.run("--yes", "--version", "5.49.0", "--allow-older", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "release 5.49.0: signature valid" in p.stdout


def test_a_mirror_needs_a_version_and_chooses_nothing(bw):
    bw.publish()
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed", extra_env={"OCW_RELEASE_BASE_URL": f"{bw.server.base}/gh/download"})
    assert p.returncode == 2 and "needs --version X.Y.Z" in p.stderr and not bw.work_dirs()
    p = bw.run("--yes", "--version", "5.52.0", "--server-name", "a.example.com", "--self-signed", extra_env={"OCW_RELEASE_BASE_URL": f"{bw.server.base}/gh/download"})
    assert p.returncode == 0, p.stderr + p.stdout
    assert "--release-base-url " + f"{bw.server.base}/gh/download" in " ".join(bw.install_args())
    assert "/gh/latest/download/manifest.json" not in [r["path"] for r in bw.server.requests]
    for url in ("http://mirror.example.com/x", "https://user:pw@mirror.example.com/x", "https://m.example.com/x y", "https://m.example.com/x;y"):
        p = bw.run("--yes", "--version", "5.52.0", "--server-name", "a.example.com", "--self-signed", extra_env={"OCW_RELEASE_BASE_URL": url})
        assert p.returncode == 2 and "not a plain https address" in p.stderr, url


def test_a_redirect_to_another_host_is_refused(bw):
    bw.publish()
    bw.server.respond("/gh/download/v5.52.0/ocw-5.52.0.tar.gz", status=302, headers={"Location": "https://evil.example.com/ocw.tar.gz"})
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 3 and "not one of the allowed hosts" in p.stderr and not bw.work_dirs() and not (bw.stub / "install.args").exists()


def test_a_tarball_with_a_path_that_escapes_is_refused_after_the_signature_and_never_written(bw):
    import io
    import tarfile
    tar, _sig = bw.publish()
    evil = bw.w / "evil" / "ocw-5.52.0.tar.gz"
    evil.parent.mkdir()
    out = io.BytesIO()
    with tarfile.open(tar, "r:gz") as old, tarfile.open(fileobj=out, mode="w:gz") as new:
        for m in old:
            new.addfile(m, old.extractfile(m) if m.isreg() else None)
        info = tarfile.TarInfo("../../escaped.txt")
        info.size = 2
        new.addfile(info, io.BytesIO(b"x\n"))
    evil.write_bytes(out.getvalue())
    sig = sign_release(evil, bw.key, "5.52.0")
    bw.server.respond("/gh/download/v5.52.0/ocw-5.52.0.tar.gz", body=evil.read_bytes())
    bw.server.respond("/gh/download/v5.52.0/ocw-5.52.0.tar.gz.minisig", body=Path(sig).read_bytes())
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="unsafe path")
    assert not (bw.w / "escaped.txt").exists() and not (bw.w.parent / "escaped.txt").exists()


# --- the system checks ------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name,fragment", [
    ("rocky9", "Red Hat family is not supported by this installer yet"),
    ("ubuntu2004", "needs Ubuntu 22.04 LTS or newer"),
    ("debian11", "needs Debian 12 or newer"),
    ("alpine", "does not support"),
    ("mint", "does not support"),
])
def test_unsupported_systems_are_refused_with_the_reason_and_nothing_is_created(bw, name, fragment):
    bw.publish()
    bw.os_release.write_text(OS_RELEASES[name])
    p = refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment=fragment)
    assert not [r for r in bw.server.requests if "download" in r["path"]]      # not even a download


def test_supported_systems_are_accepted(bw):
    bw.publish()
    for name in ("debian12", "debian13", "ubuntu2404"):
        bw.os_release.write_text(OS_RELEASES[name])
        p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
        assert p.returncode == 0 and "ok  system:" in p.stdout, (name, p.stderr)


def test_a_missing_os_release_python_too_old_sqlite_too_old_and_no_systemd_are_refused(bw):
    bw.publish()
    bw.os_release.unlink()
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="cannot be identified")
    bw.os_release.write_text(OS_RELEASES["debian13"])
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="needs Python 3.9 or newer",
            extra_env={"FAKE_PY_FACTS": "py=3.8.10 sqlite=3.37.2 venv=yes sqlok=yes pyok=no"})
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="needs SQLite 3.35 or newer",
            extra_env={"FAKE_PY_FACTS": "py=3.9.2 sqlite=3.34.1 venv=yes sqlok=no pyok=yes"})
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="systemd is not running as PID 1",
            extra_env={"OCW_SYSTEMD_DIR": str(bw.w / "no-such-dir")})
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="packages exist for x86_64 and aarch64 only",
            extra_env={"OCW_UNAME_M": "armv7l"})
    refused(bw, "--yes", "--server-name", "a.example.com", "--self-signed", fragment="not enough free disk space",
            extra_env={"OCW_MIN_FREE_KB_TEST": "999999999999"})


def test_python_venv_missing_adds_the_package_instead_of_refusing(bw):
    bw.publish()
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed", extra_env={"FAKE_PY_FACTS": "py=3.11.2 sqlite=3.40.1 venv=no sqlok=yes pyok=yes"})
    assert p.returncode == 0, p.stderr + p.stdout
    assert "python3-venv" in (bw.stub / "apt.calls").read_text()


def test_a_package_failure_stops_before_the_application_is_touched(bw):
    bw.publish()
    (bw.stub / "apt_fail").write_text("")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 3 and "Nothing of the application was installed yet" in p.stderr and "run the same command again" in p.stderr
    assert not (bw.stub / "install.args").exists() or all("--dry-run" in a for a in bw.install_args())
    assert not bw.opt.exists()


# --- prompts, --yes, the dry run -------------------------------------------------------------------------------------------------------


def test_without_a_terminal_and_without_yes_it_refuses_before_downloading(bw):
    bw.publish()
    refused(bw, "--server-name", "a.example.com", "--self-signed", fragment="no terminal to ask you on", extra_env={"OCW_TTY": "/nonexistent/tty"})
    assert not [r for r in bw.server.requests if "download" in r["path"]]


def test_the_answers_come_from_the_terminal_never_from_stdin(bw):
    bw.publish()
    # stdin is a pipe carrying "y": it must not be read; the terminal answers "n"
    p = subprocess.run(["bash", str(bw.script), "--server-name", "a.example.com", "--self-signed"], input="y\ny\ny\n", capture_output=True, text=True,
                       env=dict(bw.env, OCW_TTY=str(bw.answers)), start_new_session=True, timeout=120)
    bw.answers.write_text("n\n")
    p = subprocess.run(["bash", str(bw.script), "--server-name", "a.example.com", "--self-signed"], input="y\ny\ny\n", capture_output=True, text=True,
                       env=bw.env, start_new_session=True, timeout=120)
    assert p.returncode == 2 and "not confirmed" in p.stderr and not (bw.stub / "apt.calls").exists()


def test_yes_on_a_fresh_install_must_name_the_server_and_the_certificate_choice(bw):
    bw.publish()
    refused(bw, "--yes", "--self-signed", fragment="needs --server-name")
    refused(bw, "--yes", "--server-name", "a.example.com", fragment="must choose the certificate")
    for bad in ("https://a.example.com", "a b", "a.com/x", ""):
        p = bw.run("--yes", "--server-name", bad, "--self-signed")
        assert p.returncode == 2 and ("not a DNS name" in p.stderr or "needs --server-name" in p.stderr), bad


def test_interactive_name_and_certificate_choices(bw):
    bw.publish()
    (bw.stub / "bin" / "nginx").unlink()
    # server name, then choice 3 (no nginx), then the confirmation
    p = bw.run(answers="opa.example.com\n3\ny\n")
    assert p.returncode == 0, p.stderr + p.stdout
    second = bw.install_args()[-1]
    assert "--no-nginx" in second and "--self-signed" not in second
    assert "nginx" not in (bw.stub / "apt.calls").read_text()       # no nginx package when nginx is not wanted
    # default choice (2): self-signed
    (bw.stub / "install.args").unlink()
    p = bw.run(answers="opa.example.com\n\ny\n")
    assert p.returncode == 0 and "--self-signed" in bw.install_args()[-1]
    # a certificate of your own
    (bw.stub / "install.args").unlink()
    cert, key = bw.w / "my.crt", bw.w / "my.key"
    cert.write_text("c")
    key.write_text("k")
    p = bw.run(answers=f"opa.example.com\n1\n{cert}\n{key}\ny\n")
    assert p.returncode == 0 and f"--cert {cert} --key {key}" in bw.install_args()[-1]


def test_the_dry_run_downloads_and_verifies_for_real_changes_nothing_and_keeps_the_work_directory(bw):
    bw.publish()
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "Dry run: nothing was changed. The downloaded and verified release is in" in p.stdout
    (work,) = bw.work_dirs()
    assert (work / "release-parent" / "release" / "server" / "install.sh").exists()
    assert not (bw.stub / "apt.calls").exists() and not bw.opt.exists() and not bw.data.exists()
    assert len(bw.install_args()) == 1 and bw.install_args()[0].endswith("--dry-run")


def test_the_dry_run_works_when_the_script_is_piped_into_bash_with_no_terminal(bw):
    bw.publish()
    p = subprocess.run(["bash", "-s", "--", "--dry-run"], input=bw.script.read_text(), capture_output=True, text=True, env=dict(bw.env, OCW_TTY="/nonexistent/tty"),
                       start_new_session=True, timeout=120)
    assert p.returncode == 0, p.stderr + p.stdout
    assert "Dry run: nothing was changed." in p.stdout and "placeholder" in p.stdout


def test_a_failing_install_script_exits_with_its_code_and_keeps_the_verified_release_and_the_log(bw):
    bw.publish()
    (bw.stub / "install_rc").write_text("4")
    p = bw.run("--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 4 and "The installer stopped (exit 4)" in p.stderr and "Log:" in p.stderr
    assert len(bw.work_dirs()) == 1
    (bw.stub / "install_rc").write_text("1")
    assert bw.run("--yes", "--server-name", "a.example.com", "--self-signed").returncode == 4     # an unknown code means an operator must act


def test_unknown_arguments_are_refused(bw):
    refused(bw, "--frobnicate", fragment="unknown argument")


# --- existing installs ------------------------------------------------------------------------------------------------------------------


def test_a_server_with_the_upgrade_layout_is_left_alone(bw):
    bw.publish()
    (bw.opt / "releases" / "5.51.0").mkdir(parents=True)
    (bw.opt / "current").symlink_to("releases/5.51.0")
    cmd = bw.w / "bin" / "ocw-updater"
    cmd.write_text("#!/bin/bash\necho 'installed 5.51.0'\n")
    cmd.chmod(0o755)
    p = bw.run("--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr
    assert "This server already runs the upgrade layout" in p.stdout and "--refresh-updater" in p.stdout and "installed 5.51.0" in p.stdout
    assert "Nothing was changed." in p.stdout and not [r for r in bw.server.requests if "download" in r["path"]]


def test_refresh_updater_downloads_and_hands_over_with_the_flag_and_no_account_options(bw):
    bw.publish()
    (bw.opt / "releases" / "5.51.0").mkdir(parents=True)
    (bw.opt / "current").symlink_to("releases/5.51.0")
    cmd = bw.w / "bin" / "ocw-updater"
    cmd.write_text("#!/bin/bash\necho status\n")
    cmd.chmod(0o755)
    p = bw.run("--refresh-updater", answers="y\n")
    assert p.returncode == 0, p.stderr + p.stdout
    second = bw.install_args()[-1]
    assert "--refresh-updater" in second and "--create-app-user" not in second and "--server-name" not in second and "--app-user" not in second


def test_a_legacy_in_home_install_is_migrated_after_two_confirmations(bw):
    bw.publish()
    legacy = bw.w / "home" / "opa"
    legacy.mkdir(parents=True)
    (legacy / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.45.1"\n')
    (bw.w / "units" / "opa-compliance-wizard.service").write_text(f"[Service]\nUser=x\nWorkingDirectory={legacy}\n")
    p = bw.run(answers="y\n")          # only one confirmation: the migration's own second one is missing
    assert p.returncode == 2 and "This is a migration" in p.stdout and "not confirmed" in p.stderr
    assert "ok  existing install: an in-home install at" in p.stdout and not (bw.stub / "apt.calls").exists()
    assert all("--dry-run" in a for a in bw.install_args())
    p = bw.run(answers="y\ny\n")
    assert p.returncode == 0, p.stderr + p.stdout
    second = bw.install_args()[-1]
    assert "--create-app-user" not in second and second.endswith("--yes")


def test_an_unfinished_fresh_install_is_resumed(bw):
    bw.publish()
    bw.opt.mkdir()
    (bw.opt / ".fresh-install-incomplete").write_text("")
    (bw.opt / "current").symlink_to("releases/5.52.0")
    cmd = bw.w / "bin" / "ocw-updater"
    cmd.write_text("#!/bin/bash\n")
    cmd.chmod(0o755)
    p = bw.run("--server-name", "a.example.com", "--self-signed", answers="y\n")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "an unfinished earlier install" in p.stdout and "--create-app-user" in bw.install_args()[-1]


def test_an_existing_archive_is_reported_and_kept(bw):
    bw.publish()
    bw.data.mkdir()
    (bw.data / "audit_store.db").write_text("ARCHIVE")
    p = bw.run("--dry-run", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0 and "existing archive found" in p.stdout and (bw.data / "audit_store.db").read_text() == "ARCHIVE"


# --- --from-dir ---------------------------------------------------------------------------------------------------------------------------


def test_from_dir_installs_the_brought_files_without_any_download(bw):
    tar, sig = bw.publish()
    d = bw.w / "usb"
    d.mkdir()
    shutil.copy(tar, d)
    shutil.copy(sig, d)
    rev = bw.revocation(1, revoke=TestKey().key_id) if False else None  # none: only the signature and the tarball
    bw.server.requests.clear()
    p = bw.run("--from-dir", str(d), "--yes", "--yes-no-revocation-check", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0, p.stderr + p.stdout
    assert rev is None and not [r for r in bw.server.requests]                           # not a single request
    assert "no revocation.json was brought" in p.stdout and "release 5.52.0: signature valid" in p.stdout


def test_from_dir_with_a_revocation_applies_it(bw):
    tar, sig = bw.publish()
    d = bw.w / "usb"
    d.mkdir()
    shutil.copy(tar, d)
    shutil.copy(sig, d)
    f = bw.revocation(1, add=TestKey())
    shutil.copy(f, d / "revocation.json")
    p = bw.run("--from-dir", str(d), "--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 2 and "is revoked" in p.stderr
    # a revocation that does not touch this release's key leaves it installable
    other = TestKey()
    bw.revocation(1, revoke=other.key_id, add=TestKey())
    f2 = bw.w / "rev-1" / "revocation.json"
    shutil.copy(f2, d / "revocation.json")
    # revoking an unpinned key is refused by the rules, so the file is ignored with a note, and the install goes on
    p = bw.run("--from-dir", str(d), "--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 0 and "ignored" in p.stdout


def test_from_dir_needs_exactly_one_release_file_and_its_signature(bw):
    tar, sig = bw.publish()
    d = bw.w / "usb"
    d.mkdir()
    refused(bw, "--from-dir", str(d), "--yes", "--server-name", "a.example.com", "--self-signed", fragment="exactly one ocw-X.Y.Z.tar.gz")
    shutil.copy(tar, d)
    p = bw.run("--from-dir", str(d), "--yes", "--server-name", "a.example.com", "--self-signed")
    assert p.returncode == 3 and "signature file must sit next to the tarball" in p.stderr
    shutil.copy(sig, d)
    shutil.copy(tar, d / "ocw-5.51.0.tar.gz")
    refused(bw, "--from-dir", str(d), "--yes", "--server-name", "a.example.com", "--self-signed", fragment="found 2")
    refused(bw, "--from-dir", str(d / "missing"), "--yes", "--server-name", "a.example.com", "--self-signed", fragment="is not a directory")


# --- uninstall --------------------------------------------------------------------------------------------------------------------------------


def test_uninstall_uses_the_installed_releases_own_installer_and_needs_keep_data(bw):
    refused(bw, "--uninstall", fragment="only uninstall with --keep-data")
    rel = bw.opt / "releases" / "5.52.0" / "server"
    rel.mkdir(parents=True)
    (rel / "install.sh").write_text(STUB_INSTALL)
    (bw.opt / "current").symlink_to("releases/5.52.0")
    p = bw.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert bw.install_args() == [f"--uninstall --keep-data --log {bw.logs()[0]} --yes"] and not [r for r in bw.server.requests]


def test_uninstall_with_a_damaged_layout_falls_back_to_a_verified_download(bw):
    bw.publish()
    p = bw.run("--uninstall", "--keep-data", "--yes")
    assert p.returncode == 0, p.stderr + p.stdout
    assert "downloading one to run its uninstaller" in p.stdout and "release 5.52.0: signature valid" in p.stdout
    assert bw.install_args()[0].startswith("--uninstall --keep-data --log ") and "--source" in bw.install_args()[0]


# --- end to end with the real install.sh -------------------------------------------------------------------------------------------------------------


def test_end_to_end_with_the_real_installer_and_no_secret_in_the_output_or_the_log(bw):
    import socket
    srv = __import__("http.server").server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        bw.publish(stub_install=False, extra_files={"create_secret_folders.py": b'SCRIPT_VERSION = "5.52.0"\n'})
        p = bw.run("--yes", "--server-name", "opa.example.com", "--self-signed", "--backend-port", str(port))
        assert p.returncode == 0, p.stderr + p.stdout
        assert "Done. OPA Compliance Wizard 5.52.0 is installed and the backend is running." in p.stdout
        env_file = bw.w / "etc" / "opa-compliance-wizard.env"
        values = dict(line.split("=", 1) for line in env_file.read_text().splitlines() if re.match(r"^[A-Z_]+=", line))
        secrets_ = [values[k] for k in ("NGINX_PROXY_SECRET", "KEYRING_UNLOCK_PASSWORD", "INTERNAL_API_SHARED_SECRET")]
        assert len(secrets_) == 3 and all(HEX64.fullmatch(s) for s in secrets_)
        log = bw.logs()[0]
        text = p.stdout + p.stderr + log.read_text()
        for s in secrets_:
            assert s not in text, "a generated secret appeared in the output or the log"
        assert not HEX64.search(text.replace(hashlib.sha256(Path(bw.releases["5.52.0"][0]).read_bytes()).hexdigest(), ""))   # only the release hash is hex64 here
        # the provenance of the release says it came through the verified path
        rec = json.loads((bw.opt / "releases" / "5.52.0" / ".installed-from-release").read_text())
        assert rec["source"] == "get-ocw.sh" and rec["key_id"] == bw.key.key_id and rec["signed"] is True
        assert (bw.opt / "current").is_symlink() and stat.S_IMODE(env_file.stat().st_mode) == 0o600
        # running the same command again is the already-installed mode: nothing changed
        before = {str(f): f.stat().st_mtime_ns for f in bw.opt.rglob("*") if f.is_file() and ".venv" not in f.parts}
        p2 = bw.run("--yes", "--server-name", "opa.example.com", "--self-signed")
        assert p2.returncode == 0 and "already runs the upgrade layout" in p2.stdout
        assert before == {str(f): f.stat().st_mtime_ns for f in bw.opt.rglob("*") if f.is_file() and ".venv" not in f.parts}
        # uninstall keeps the settings and the data
        (bw.data / "audit_store.db").write_text("ARCHIVE")
        p3 = bw.run("--uninstall", "--keep-data", "--yes")
        assert p3.returncode == 0, p3.stderr + p3.stdout
        assert not bw.opt.exists() and (bw.data / "audit_store.db").read_text() == "ARCHIVE" and env_file.exists()
    finally:
        srv.shutdown()
        del socket
