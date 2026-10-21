"""The guided upgrade for local mode (5.49.0): server/updater/localupgrade.py, localswap.py and the launch.py glue.

Everything runs against throwaway install folders built from tiny stand-in sources (a real engine is not needed to test
folder handling): signed releases are made with tests/release_helpers.py, the download comes from the local fake release
server, and the "new version starts" check runs the stand-in code with the real Python. Windows behaviour (renames that
fail while a file is open, the hand-over between the two launcher processes) is simulated by switching
localswap.is_windows and by making renames fail; it has not been run on real Windows."""

import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tarfile
from pathlib import Path

import pytest

from fake_release_server import FakeReleaseServer
from release_helpers import TestKey, key_list, make_release_tar, sign_release
from server.updater import keys as keylib
from server.updater import localswap, localupgrade, offline, service
from server.updater import verify as verifylib

OLD, NEW = "5.47.0", "5.49.0"
POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


# --- fixtures ------------------------------------------------------------------------------------------


def engine_source(version):
    return (f'SCRIPT_VERSION = "{version}"\nimport json, os\n'
            'def log_audit_event(actor, sub, action, details, user_agent=None):\n'
            '    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl"), "a") as fh:\n'
            '        fh.write(json.dumps({"action": action, "actor": actor, "details": details}) + "\\n")\n')


def audit_store_source(top, fail=False):
    migs = "".join(f"    {n}: _migration_{n},\n" for n in range(1, top + 1))
    funcs = "".join(f"def _migration_{n}(conn):\n    pass\n\n" for n in range(1, top + 1))
    body = ("    raise RuntimeError('boom')\n" if fail else
            "    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit_store.db')\n"
            "    c = sqlite3.connect(p)\n"
            "    c.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)')\n"
            f"    for v in range(1, {top} + 1):\n"
            "        c.execute('INSERT OR IGNORE INTO schema_migrations VALUES (?, ?)', (v, 'x'))\n"
            "    c.commit()\n    c.close()\n")
    return f"import os, sqlite3\n{funcs}MIGRATIONS = {{\n{migs}}}\n\ndef init_db():\n{body}"


def migrations_json(top, unsafe=()):
    return json.dumps({"schema": 1, "migrations": {str(n): {"since": "5.29.0", "rollback_safe": n not in unsafe} for n in range(1, top + 1)}})


def write_tree(folder, version, top, secret_mode=0o600, data=True):
    folder.mkdir(parents=True)
    (folder / "create_secret_folders.py").write_text(engine_source(version))
    (folder / "audit_store.py").write_text(audit_store_source(top))
    (folder / "launch.py").write_text("# stand-in launcher\n")
    (folder / "server").mkdir()
    (folder / "server" / "schema_migrations.json").write_text(migrations_json(top))
    (folder / "requirements.lock").write_text("# lock\n")
    (folder / "folders_template.csv").write_text("a,b\n")
    if data:
        (folder / "environments.json").write_text('{"envs": ["one"]}')
        os.chmod(folder / "environments.json", secret_mode)
        (folder / ".env").write_text("SOME=thing\n")
        os.chmod(folder / ".env", 0o600)
        (folder / "banner_config.json").write_text('{"banner": "hello"}')
        (folder / "my_template.csv").write_text("x,y\n1,2\n")
        (folder / "notes.txt").write_text("my own notes")
        con = sqlite3.connect(folder / "audit_store.db")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)")
        for n in range(1, top + 1):
            con.execute("INSERT INTO schema_migrations VALUES (?, 'x')", (n,))
        con.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, note TEXT)")
        con.execute("INSERT INTO evidence (note) VALUES ('kept')")
        con.commit()
        con.close()


class Release:
    def __init__(self, tmp, version=NEW, top=3, fail_init=False, unsafe=(), key=None):
        self.key = key or TestKey()
        self.kl = key_list([self.key])
        self.keys_file = tmp / "release_keys.json"
        self.keys_file.write_text(json.dumps(self.kl))
        self.dir = tmp / "downloads"
        self.dir.mkdir(exist_ok=True)
        self.version = version
        files = {"create_secret_folders.py": engine_source(version), "audit_store.py": audit_store_source(top, fail_init),
                 "launch.py": "# stand-in launcher, new\n", "server/schema_migrations.json": migrations_json(top, unsafe),
                 "requirements.lock": "# lock\n", "folders_template.csv": "a,b,new\n"}
        self.tar = make_release_tar(self.dir / f"ocw-{version}.tar.gz", version, self.kl, extra_files=files,
                                    manifest_over={"migrations": [{"version": n, "since": "5.49.0", "rollback_safe": n not in unsafe}
                                                                  for n in range(1, top + 1)]})
        self.sig = Path(sign_release(self.tar, self.key, version))


@pytest.fixture
def world(tmp_path, monkeypatch):
    parent = tmp_path / "my apps"            # a path with a space, on purpose
    parent.mkdir()
    root = parent / "opa-compliance-wizard"
    write_tree(root, OLD, top=2)
    rel = Release(tmp_path)
    monkeypatch.setattr(keylib, "SHIPPED_PATH", rel.keys_file)
    monkeypatch.delenv("DEPLOYMENT_MODE", raising=False)
    monkeypatch.delenv(localupgrade.REEXEC_ENV, raising=False)
    monkeypatch.setattr(localupgrade, "_keyring_ok", lambda python: True)   # no venv is built in these tests
    return type("W", (), {"parent": parent, "root": root, "rel": rel, "tmp": tmp_path})


class FakeHost(localupgrade.Host):
    def __init__(self, answers=None, running=False, stoppable=True):
        self.answers = list(answers or [])
        self.interactive = answers is not None
        self.running, self.stoppable, self.stopped = running, stoppable, False

    def ask(self, prompt):
        return self.answers.pop(0)

    def port_in_use(self, port):
        return self.running and not self.stopped

    def stop_server(self, port):
        self.stopped = self.stoppable
        return self.stoppable


def go(world, *argv, host=None, root=None):
    lines = []
    code = localupgrade.main(list(argv), root or world.root, host=host or FakeHost(), say=lines.append)
    return code, "\n".join(lines)


def upgrade_args(world, confirm=NEW):
    return ["--from-file", str(world.rel.tar), str(world.rel.sig), "--confirm", confirm]


def snapshot_tree(folder):
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(folder).rglob("*"))
            if p.is_file() and p.name not in (localswap.JOURNAL,) and not p.name.startswith("audit_store.db-")}


def rows(db):
    con = sqlite3.connect(db)
    try:
        return [r[0] for r in con.execute("SELECT note FROM evidence")], con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    finally:
        con.close()


def siblings(world):
    return sorted(p.name for p in world.parent.iterdir())


# --- the happy path ------------------------------------------------------------------------------------


def test_guided_upgrade_from_files(world):
    before = snapshot_tree(world.root)
    code, out = go(world, *upgrade_args(world))
    assert code == 0, out
    cur, prev = world.parent / "opa-compliance-wizard", world.parent / "opa-compliance-wizard-previous"
    assert siblings(world) == ["opa-compliance-wizard", "opa-compliance-wizard-previous"]
    assert localswap.version_of(cur) == NEW and localswap.version_of(prev) == OLD
    assert snapshot_tree(prev) == before                                     # the old folder is untouched, byte for byte
    assert rows(cur / "audit_store.db") == (["kept"], 3)                      # data carried over, migrated on the COPY ...
    assert rows(prev / "audit_store.db") == (["kept"], 2)                     # ... never on the original
    assert (cur / "environments.json").read_text() == '{"envs": ["one"]}' and (cur / ".env").read_text() == "SOME=thing\n"
    assert (cur / "banner_config.json").exists() and (cur / "my_template.csv").read_text() == "x,y\n1,2\n"
    assert (cur / "folders_template.csv").read_text() == "a,b,new\n"          # the release's own file wins
    assert not (cur / "notes.txt").exists() and "notes.txt" in out and "Not carried over" in out
    assert "folders_template.csv" not in {n for n in out.split("Not carried over")[-1].split()}
    events = [json.loads(line) for line in (cur / "audit_log.jsonl").read_text().splitlines()]
    assert [e["action"] for e in events] == ["upgrade.local_completed"] and events[0]["details"]["to"] == NEW
    assert "Upgraded to 5.49.0" in out and "No MFA" not in out and "no MFA" in out
    assert not list(world.parent.glob(".*swap-plan*"))


@POSIX
def test_permissions_are_preserved_and_nothing_new_is_world_readable(world):
    os.chmod(world.root / "environments.json", 0o600)
    os.chmod(world.root, 0o750)
    os.chmod(world.root / "audit_store.db", 0o600)
    assert go(world, *upgrade_args(world))[0] == 0
    cur = world.parent / "opa-compliance-wizard"
    assert stat.S_IMODE((cur / "environments.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((cur / ".env").stat().st_mode) == 0o600
    assert stat.S_IMODE((cur / "audit_store.db").stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(cur.stat().st_mode) == 0o750


def test_download_flow_through_the_check(world, monkeypatch):
    server = FakeReleaseServer()
    try:
        monkeypatch.setenv("OPA_RELEASE_API_URL", server.base + "/repos/x/y/releases/latest")
        monkeypatch.setenv("OPA_REVOCATION_URL_BASE", server.base + "/rev/")
        monkeypatch.setenv("OPA_RELEASE_BASE_URL", server.base + "/dl")
        names = [f"ocw-{NEW}.tar.gz", f"ocw-{NEW}.tar.gz.minisig", "manifest.json"]
        server.respond("/repos/x/y/releases/latest", body=json.dumps({"tag_name": f"v{NEW}", "draft": False, "prerelease": False,
                                                                       "published_at": "2026-10-01T12:00:00Z",
                                                                       "assets": [{"name": n} for n in names]}).encode())
        server.respond(f"/dl/v{NEW}/ocw-{NEW}.tar.gz", body=world.rel.tar.read_bytes())
        server.respond(f"/dl/v{NEW}/ocw-{NEW}.tar.gz.minisig", body=world.rel.sig.read_bytes())
        code, out = go(world, "--confirm", NEW)
        assert code == 0, out
        assert localswap.version_of(world.root) == NEW
        assert server.requests[0]["headers"]["user-agent"] == "opa-compliance-wizard-update-check"   # no version unless opted in
    finally:
        server.close()


def test_up_to_date_does_nothing(world, monkeypatch):
    server = FakeReleaseServer()
    try:
        monkeypatch.setenv("OPA_RELEASE_API_URL", server.base + "/repos/x/y/releases/latest")
        monkeypatch.setenv("OPA_REVOCATION_URL_BASE", server.base + "/rev/")
        server.respond("/repos/x/y/releases/latest", body=json.dumps({"tag_name": f"v{OLD}", "draft": False, "prerelease": False,
                                                                       "assets": []}).encode())
        code, out = go(world)
        assert code == 0 and "up to date" in out and siblings(world) == ["opa-compliance-wizard"]
    finally:
        server.close()


def test_check_exit_codes_and_prerelease_override(world, monkeypatch):
    server = FakeReleaseServer()
    try:
        monkeypatch.setenv("OPA_RELEASE_API_URL", server.base + "/repos/x/y/releases/latest")
        monkeypatch.setenv("OPA_REVOCATION_URL_BASE", server.base + "/rev/")
        rel = lambda v, pre: {"tag_name": f"v{v}", "draft": False, "prerelease": pre, "published_at": "2026-10-01T12:00:00Z", "assets": []}  # noqa: E731
        server.respond("/repos/x/y/releases/latest", body=json.dumps(rel("5.48.0", False)).encode())
        server.respond("/repos/x/y/releases", body=json.dumps([rel("5.50.0", True), rel("5.48.0", False)]).encode())
        code, out = go(world, "--check")
        assert code == 1 and "5.48.0" in out and "Channel          stable" in out and "nothing about your tenant" in out
        code, out = go(world, "--check", "--channel", "prerelease")
        assert code == 1 and "5.50.0" in out and "PRERELEASE" in out
        assert service.load()["settings"]["channel"] == "stable"             # the switch is for this run only
        gone = FakeReleaseServer()
        monkeypatch.setenv("OPA_RELEASE_API_URL", gone.base + "/repos/x/y/releases/latest")
        gone.close()
        code, out = go(world, "--check")
        assert code == 3 and "Nothing was changed" in out
        assert siblings(world) == ["opa-compliance-wizard"]
    finally:
        server.close()


def test_status_and_json(world):
    code, out = go(world, "--status", "--json")
    info = json.loads(out)
    assert code == 0 and info["installed"] == OLD and info["previous"] is None and info["channel"] == "stable"
    go(world, *upgrade_args(world))
    info = json.loads(go(world, "--status", "--json")[1])
    assert info["installed"] == NEW and info["previous"] == OLD


# --- verification comes first; hostile and wrong inputs -------------------------------------------------


def refused(world, code_expected=2, *argv):
    before = snapshot_tree(world.root)
    code, out = go(world, *(argv or upgrade_args(world)))
    assert code == code_expected, out
    assert siblings(world) == ["opa-compliance-wizard"], siblings(world)    # nothing staged, nothing left behind
    assert snapshot_tree(world.root) == before
    return out


def test_a_tampered_tarball_is_refused_before_unpacking(world):
    data = bytearray(world.rel.tar.read_bytes())
    data[len(data) // 2] ^= 1
    world.rel.tar.write_bytes(bytes(data))
    assert "Nothing was changed" in refused(world)


def test_a_signature_from_an_unpinned_key_is_refused(world):
    sign_release(world.rel.tar, TestKey(), NEW)
    assert "Nothing was changed" in refused(world)


def test_a_missing_signature_file_is_refused(world):
    world.rel.sig.unlink()
    assert "does not exist" in refused(world)


def test_no_downgrade_and_no_reinstall(world):
    old = Release(world.tmp, version="5.40.0", key=world.rel.key)
    assert "not newer" in refused(world, 2, "--from-file", str(old.tar), str(old.sig), "--confirm", "5.40.0")
    same = Release(world.tmp, version=OLD, key=world.rel.key)
    assert "not newer" in refused(world, 2, "--from-file", str(same.tar), str(same.sig), "--confirm", OLD)


def test_a_version_the_manifest_does_not_confirm_is_refused(world):
    tar = make_release_tar(world.rel.dir / "ocw-5.50.0.tar.gz", "5.50.0", world.rel.kl, manifest_over={"version": "5.48.0"})
    sig = sign_release(tar, world.rel.key, "5.50.0")
    out = refused(world, 2, "--from-file", str(tar), sig, "--confirm", "5.50.0")
    assert "manifest says" in out


def test_code_that_reports_another_version_is_refused(world):
    tar = make_release_tar(world.rel.dir / "ocw-5.50.0.tar.gz", "5.50.0", world.rel.kl, script_version="5.46.0")
    assert "code inside says" in refused(world, 2, "--from-file", str(tar), sign_release(tar, world.rel.key, "5.50.0"), "--confirm", "5.50.0")


def test_a_file_renamed_after_signing_is_refused(world):
    renamed = world.rel.dir / "ocw-5.51.0.tar.gz"
    renamed.write_bytes(world.rel.tar.read_bytes())
    Path(str(renamed) + ".minisig").write_text(world.rel.sig.read_text())
    assert "do not rename" in refused(world, 2, "--from-file", str(renamed), str(renamed) + ".minisig", "--confirm", "5.51.0")


def test_unusable_from_file_arguments(world):
    assert "--from-file takes" in refused(world, 2, "--from-file", str(world.rel.tar))
    assert "--from-file takes" in refused(world, 2, "--from-file", "a.txt", "b.txt")


def hostile_tar(world, version, extra, name=None):
    """A correctly SIGNED release that also carries `extra` ({member name: TarInfo-or-bytes}) -- the signature proves who
    made the file, not that it is safe, so the unpacker must refuse these on its own."""
    files = {"create_secret_folders.py": engine_source(version).encode(), "server/release_keys.json": json.dumps(world.rel.kl).encode()}
    manifest = {"schema": 1, "version": version, "built_at": "2026-01-15T10:00:00Z", "min_upgrade_from": "5.41.0",
                "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
    path = world.rel.dir / (name or f"ocw-{version}.tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        for n, d in {**files, "manifest.json": json.dumps(manifest).encode()}.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tar.addfile(ti, io.BytesIO(d))
        for n, d in extra.items():
            if isinstance(d, tarfile.TarInfo):
                tar.addfile(d)
            else:
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                tar.addfile(ti, io.BytesIO(d))
    return path, sign_release(path, world.rel.key, version)


def link(name, kind, target):
    ti = tarfile.TarInfo(name)
    ti.type, ti.linkname = kind, target
    return ti


@pytest.mark.parametrize("member", [
    link("evil", tarfile.SYMTYPE, "/etc"),
    link("evil", tarfile.LNKTYPE, "create_secret_folders.py"),
    link("dev", tarfile.CHRTYPE, ""),
    "../escape.txt", "/abs/escape.txt", "a/../../escape.txt", "C:/escape.txt", "back\\slash.txt",
    "CON", "docs/NUL.txt", "name.", "ads:stream", "bad|char", "Create_Secret_Folders.py",
])
def test_hostile_tarballs_are_refused_and_leave_nothing(world, member):
    extra = {member.name: member} if isinstance(member, tarfile.TarInfo) else {member: b"payload"}
    tar, sig = hostile_tar(world, "5.51.0", extra)
    refused(world, 2, "--from-file", str(tar), sig, "--confirm", "5.51.0")
    assert not (world.tmp / "escape.txt").exists() and not (world.parent / "escape.txt").exists()
    assert not (world.parent.parent / "escape.txt").exists()


def test_a_file_the_signed_manifest_does_not_list_is_refused(world):
    tar = make_release_tar(world.rel.dir / "ocw-5.51.0.tar.gz", "5.51.0", world.rel.kl, extra_files={"extra.py": "x"}, unlisted=("extra.py",))
    assert "signed manifest" in refused(world, 2, "--from-file", str(tar), sign_release(tar, world.rel.key, "5.51.0"), "--confirm", "5.51.0")


def test_a_missing_listed_file_is_refused(world):
    tar = make_release_tar(world.rel.dir / "ocw-5.51.0.tar.gz", "5.51.0", world.rel.kl, drop=("CHANGELOG.md",))
    assert "missing" in refused(world, 2, "--from-file", str(tar), sign_release(tar, world.rel.key, "5.51.0"), "--confirm", "5.51.0")


# --- confirmation --------------------------------------------------------------------------------------


def test_wrong_or_missing_confirmation_changes_nothing(world):
    assert "must be exactly 5.49.0" in refused(world, 2, "--from-file", str(world.rel.tar), str(world.rel.sig), "--confirm", "yes")
    out = refused(world, 2, "--from-file", str(world.rel.tar), str(world.rel.sig))   # no terminal, no --confirm
    assert "no terminal" in out and "--confirm 5.49.0" in out


def test_typed_confirmation_at_a_terminal(world):
    argv = ["--from-file", str(world.rel.tar), str(world.rel.sig)]
    before = snapshot_tree(world.root)
    code, out = go(world, *argv, host=FakeHost(["5.49"]))
    assert code == 2 and "Not confirmed" in out and siblings(world) == ["opa-compliance-wizard"] and snapshot_tree(world.root) == before
    code, out = go(world, *argv, host=FakeHost([""]))
    assert code == 2
    code, out = go(world, *argv, host=FakeHost([" 5.49.0 "]))
    assert code == 0 and localswap.version_of(world.root) == NEW


def test_the_summary_names_the_migrations_and_their_rollback_safety(world):
    rel = Release(world.tmp, version="5.50.0", top=4, unsafe=(4,), key=world.rel.key)
    out = refused(world, 2, "--from-file", str(rel.tar), str(rel.sig))
    assert "5.47.0 -> 5.50.0" in out and "3 (rollback-safe), 4 (NOT rollback-safe)" in out and "schema 2 -> 4" in out
    assert "--restore-data" in out


def test_a_running_dashboard_must_be_stopped_first(world):
    host = FakeHost(running=True, stoppable=False)
    code, out = go(world, *upgrade_args(world), host=host)
    assert code == 2 and "Stop the dashboard" in out and siblings(world) == ["opa-compliance-wizard"]
    host = FakeHost(running=True, stoppable=True)
    code, out = go(world, *upgrade_args(world), host=host)
    assert code == 0 and host.stopped


# --- the swap: interruption, failure, locks ------------------------------------------------------------


def test_a_failed_second_rename_puts_the_install_back(world, monkeypatch):
    real = localswap.os.rename
    calls = []

    def flaky(src, dst):
        calls.append(os.path.basename(dst))
        if os.path.basename(dst) == "opa-compliance-wizard" and os.path.basename(src) == "opa-compliance-wizard-5.49.0":
            raise PermissionError(13, "Access is denied")
        return real(src, dst)
    monkeypatch.setattr(localswap.os, "rename", flaky)
    before = snapshot_tree(world.root)
    code, out = go(world, *upgrade_args(world))
    assert code == 3 and "Close" in out
    assert localswap.version_of(world.root) == OLD and snapshot_tree(world.root) == before
    assert not (world.parent / "opa-compliance-wizard-previous").exists()
    assert "opa-compliance-wizard-5.49.0" in siblings(world)    # prepared, not discarded: the user can retry the swap by re-running


def test_an_older_previous_copy_survives_a_failed_swap(world, monkeypatch):
    old_prev = world.parent / "opa-compliance-wizard-previous"
    write_tree(old_prev, "5.40.0", top=1)
    real = localswap.os.rename

    def flaky(src, dst):
        if os.path.basename(src) == "opa-compliance-wizard-5.49.0":
            raise PermissionError(13, "locked")
        return real(src, dst)
    monkeypatch.setattr(localswap.os, "rename", flaky)
    assert go(world, *upgrade_args(world))[0] == 3
    assert localswap.version_of(old_prev) == "5.40.0" and localswap.version_of(world.root) == OLD


def test_an_older_previous_copy_is_replaced_after_success(world):
    write_tree(world.parent / "opa-compliance-wizard-previous", "5.40.0", top=1)
    code, out = go(world, *upgrade_args(world))
    assert code == 0 and "5.40.0" in out
    assert localswap.version_of(world.parent / "opa-compliance-wizard-previous") == OLD
    assert siblings(world) == ["opa-compliance-wizard", "opa-compliance-wizard-previous"]


def test_if_the_new_version_does_not_start_the_old_one_is_put_back(world):
    bad = Release(world.tmp, version="5.50.0", fail_init=True, key=world.rel.key)
    before = snapshot_tree(world.root)
    code, out = go(world, "--from-file", str(bad.tar), str(bad.sig), "--confirm", "5.50.0")
    assert code == 3 and "did not start" in out and "boom" in out
    assert localswap.version_of(world.root) == OLD and snapshot_tree(world.root) == before
    assert siblings(world) == ["opa-compliance-wizard", "opa-compliance-wizard-5.50.0-failed"]


def test_a_crash_between_the_two_renames_is_repaired_by_the_next_run(world, monkeypatch):
    real = localswap.os.rename
    state = {"n": 0}

    def crash(src, dst):
        state["n"] += 1
        if os.path.basename(src) == "opa-compliance-wizard-5.49.0":
            raise KeyboardInterrupt()     # power cut / Ctrl+C right after current -> previous
        return real(src, dst)
    monkeypatch.setattr(localswap.os, "rename", crash)
    with pytest.raises(KeyboardInterrupt):
        go(world, *upgrade_args(world))
    monkeypatch.setattr(localswap.os, "rename", real)
    assert not world.root.exists() and (world.parent / "opa-compliance-wizard-previous").is_dir()
    # the user starts the old code from the previous folder
    code, out = go(world, "--restore-previous", root=world.parent / "opa-compliance-wizard-previous")
    assert "interrupted" in out and world.root.is_dir() and localswap.version_of(world.root) == OLD
    # and can simply run the upgrade again; the half-prepared folder is ours and is replaced
    code, out = go(world, *upgrade_args(world))
    assert code == 0 and localswap.version_of(world.root) == NEW


def test_recover_puts_back_an_aside_previous_after_a_crash(world):
    layout = localswap.Layout(world.root)
    aside = world.parent / "opa-compliance-wizard-previous.old-123"
    write_tree(aside, "5.40.0", top=1)
    assert localswap.recover(layout, lambda *_: None)
    assert localswap.version_of(layout.previous) == "5.40.0"


def test_a_foreign_folder_with_the_staging_name_is_never_deleted(world):
    foreign = world.parent / "opa-compliance-wizard-5.49.0"
    foreign.mkdir()
    (foreign / "precious.txt").write_text("mine")
    out = refused(world, 2, *upgrade_args(world)) if False else go(world, *upgrade_args(world))[1]
    assert (foreign / "precious.txt").read_text() == "mine" and "was not made by this tool" in out


def test_an_interrupted_earlier_staging_folder_is_replaced(world):
    stale = world.parent / "opa-compliance-wizard-5.49.0"
    stale.mkdir()
    localswap.write_journal(stale, state="staging", to=NEW)
    (stale / "half.txt").write_text("x")
    assert go(world, *upgrade_args(world))[0] == 0 and not (world.parent / "opa-compliance-wizard-previous" / "half.txt").exists()


def test_not_enough_disk_space(world, monkeypatch):
    monkeypatch.setattr(localupgrade.shutil, "disk_usage", lambda p: type("U", (), {"free": 1024})())
    out = refused(world, 3, *upgrade_args(world))
    assert "Not enough free disk space" in out


def test_a_symbolic_link_where_data_should_be_stops_before_any_swap(world):
    if sys.platform == "win32":
        pytest.skip("symlinks need privileges on Windows")
    (world.root / "banner_config.json").unlink()
    (world.tmp / "elsewhere.json").write_text("{}")
    os.symlink(world.tmp / "elsewhere.json", world.root / "banner_config.json")
    out = go(world, *upgrade_args(world))[1]
    assert "symbolic link" in out and world.root.is_dir() and localswap.version_of(world.root) == OLD
    assert "opa-compliance-wizard-previous" not in siblings(world)


def test_a_corrupt_database_is_not_copied(world):
    (world.root / "audit_store.db").write_bytes(b"this is not a database" * 100)
    for extra in ("-wal", "-shm"):
        (world.root / f"audit_store.db{extra}").unlink(missing_ok=True)
    code, out = go(world, *upgrade_args(world))
    assert code == 3 and "cannot be read" in out and localswap.version_of(world.root) == OLD
    assert siblings(world) == ["opa-compliance-wizard"]
    new = world.tmp / "new"
    new.mkdir()
    with pytest.raises(localswap.SwapError) as exc:
        localswap.copy_data(world.root, new, say=lambda *_: None)
    assert exc.value.code == "db_copy_failed" and not (new / "environments.json").exists()


def test_wal_sidecars_are_not_copied_but_their_content_is(world):
    con = sqlite3.connect(world.root / "audit_store.db")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO evidence (note) VALUES ('only in the wal')")
    con.commit()   # stays in the -wal file while this connection is open
    try:
        assert go(world, *upgrade_args(world))[0] == 0
    finally:
        con.close()
    assert rows(world.parent / "opa-compliance-wizard" / "audit_store.db")[0] == ["kept", "only in the wal"]


# --- restore / discard ---------------------------------------------------------------------------------


def upgraded(world):
    assert go(world, *upgrade_args(world))[0] == 0


def test_restore_previous_keeps_the_current_data(world):
    upgraded(world)
    con = sqlite3.connect(world.root / "audit_store.db")
    con.execute("INSERT INTO evidence (note) VALUES ('added after upgrade')")
    con.commit()
    con.close()
    code, out = go(world, "--restore-previous", "--confirm", "RESTORE")
    assert code == 0, out
    assert localswap.version_of(world.root) == OLD
    assert rows(world.root / "audit_store.db")[0] == ["kept", "added after upgrade"]
    replaced = world.parent / "opa-compliance-wizard-replaced-5.49.0"
    assert localswap.version_of(replaced) == NEW and not (world.parent / "opa-compliance-wizard-previous").exists()
    assert list(world.root.glob(".data-before-restore-*/audit_store.db"))      # the older copy is set aside, not destroyed
    assert "upgrade.local_restored" in (world.root / "audit_log.jsonl").read_text()


def test_restore_needs_the_typed_word(world):
    upgraded(world)
    assert go(world, "--restore-previous", "--confirm", "restore")[0] == 2
    assert go(world, "--restore-previous")[0] == 2                              # no terminal
    assert go(world, "--restore-previous", host=FakeHost(["no"]))[0] == 2
    assert localswap.version_of(world.root) == NEW
    assert go(world, "--restore-previous", host=FakeHost(["RESTORE"]))[0] == 0


def test_restore_refuses_code_only_when_the_data_moved_past_the_old_code(world):
    rel = Release(world.tmp, version="5.50.0", top=4, unsafe=(3, 4), key=world.rel.key)
    assert go(world, "--from-file", str(rel.tar), str(rel.sig), "--confirm", "5.50.0")[0] == 0
    code, out = go(world, "--restore-previous", "--confirm", "RESTORE")
    assert code == 2 and "migrations 3, 4" in out and "--restore-data" in out and localswap.version_of(world.root) == "5.50.0"
    code, out = go(world, "--restore-previous", "--restore-data", "--confirm", "RESTORE")
    assert code == 0 and localswap.version_of(world.root) == OLD
    assert rows(world.root / "audit_store.db") == (["kept"], 2)                  # its own, older data
    assert rows(world.parent / "opa-compliance-wizard-replaced-5.50.0" / "audit_store.db")[1] == 4   # the newer data is kept


def test_restore_when_the_restored_code_does_not_start_swaps_back(world):
    upgraded(world)
    (world.parent / "opa-compliance-wizard-previous" / "audit_store.py").write_text(audit_store_source(2, fail=True))
    code, out = go(world, "--restore-previous", "--confirm", "RESTORE")
    assert code == 3 and "did not start" in out and localswap.version_of(world.root) == NEW
    assert (world.parent / "opa-compliance-wizard-previous").is_dir()


def test_nothing_to_restore(world):
    code, out = go(world, "--restore-previous", "--confirm", "RESTORE")
    assert code == 2 and "no previous version" in out


def test_discard_previous(world):
    upgraded(world)
    prev = world.parent / "opa-compliance-wizard-previous"
    assert go(world, "--discard-previous", "--confirm", "delete")[0] == 2 and prev.exists()
    code, out = go(world, "--discard-previous", "--confirm", "DELETE")
    assert code == 0 and not prev.exists() and localswap.version_of(world.root) == NEW
    assert go(world, "--discard-previous", "--confirm", "DELETE")[0] == 2


def test_the_previous_folder_cannot_start_an_upgrade(world):
    upgraded(world)
    code, out = go(world, *upgrade_args(world), root=world.parent / "opa-compliance-wizard-previous")
    assert code == 2 and "Run it from opa-compliance-wizard" in out


# --- modes and places ----------------------------------------------------------------------------------


def test_hosted_installs_are_pointed_at_the_updater(world, monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_MODE", "hosted")
    out = refused(world, 2, "--check")
    assert "ocw-updater" in out
    monkeypatch.delenv("DEPLOYMENT_MODE")
    releases = world.tmp / "opt" / "releases" / "5.47.0"
    write_tree(releases, OLD, top=1)
    code, out = go(world, "--check", root=releases)
    assert code == 2 and "hosted layout" in out


def test_not_an_install_folder(world):
    code, out = go(world, "--check", root=world.tmp)
    assert code == 2 and "does not look like" in out


def test_usage_errors_exit_2(world):
    with pytest.raises(SystemExit) as exc:
        go(world, "--check", "--to", "5.49.0")
    assert exc.value.code == 2


# --- Windows behaviour (simulated) ---------------------------------------------------------------------


def test_rename_retries_while_a_file_is_open_then_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(localswap, "is_windows", lambda: True)
    src, dst = tmp_path / "a", tmp_path / "b"
    src.mkdir()
    real = os.rename
    attempts = []

    def locked_twice(s, d):
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError(32, "The process cannot access the file because it is being used by another process")
        return real(s, d)
    monkeypatch.setattr(localswap.os, "rename", locked_twice)
    slept = []
    localswap.rename(src, dst, sleep=slept.append)
    assert dst.is_dir() and len(attempts) == 3 and len(slept) == 2


def test_rename_that_stays_locked_explains_what_to_close(tmp_path, monkeypatch):
    monkeypatch.setattr(localswap, "is_windows", lambda: True)
    (tmp_path / "a").mkdir()
    monkeypatch.setattr(localswap.os, "rename", lambda s, d: (_ for _ in ()).throw(PermissionError(32, "in use")))
    with pytest.raises(localswap.SwapError) as exc:
        localswap.rename(tmp_path / "a", tmp_path / "b", sleep=lambda s: None)
    assert exc.value.code == "locked" and "Close the dashboard" in str(exc.value) and "system Python" in str(exc.value)


def test_rename_never_replaces_an_existing_folder(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(localswap.SwapError) as exc:
        localswap.rename(tmp_path / "a", tmp_path / "b")
    assert exc.value.code == "exists"


def test_windows_path_length_is_checked_before_unpacking(world, monkeypatch):
    monkeypatch.setattr(localswap, "is_windows", lambda: True)
    monkeypatch.setattr(localupgrade.Path, "__str__", localupgrade.Path.__str__)   # real paths; only the limit is lowered:
    long_manifest = {"files": {"a/" * 130 + "file.py": "0" * 64}}
    with pytest.raises(localupgrade.Refused) as exc:
        localupgrade._windows_path_check(Path("C:/apps/opa-compliance-wizard-5.49.0"), long_manifest)
    assert exc.value.code == "path_too_long" and "shorter path" in str(exc.value)
    localupgrade._windows_path_check(Path("C:/apps/x"), {"files": {"a.py": "0" * 64}})


def test_windows_hand_over_between_the_two_launcher_processes(world, monkeypatch):
    monkeypatch.setattr(localswap, "is_windows", lambda: True)
    monkeypatch.setenv(localupgrade.REEXEC_ENV, "1")        # we are the inner (venv) process
    code, out = go(world, *upgrade_args(world))
    assert code == localswap.EXIT_SWAP_PENDING == 86
    assert localswap.version_of(world.root) == OLD and "opa-compliance-wizard-5.49.0" in siblings(world)   # prepared, not swapped
    plan = localswap.plan_path(localswap.Layout(world.root))
    assert plan.is_file()
    monkeypatch.delenv(localupgrade.REEXEC_ENV)             # now we are the outer process
    lines = []
    assert localswap.run_pending_plan(world.root, lines.append) == 0
    assert localswap.version_of(world.root) == NEW and not plan.exists()
    assert any("Upgraded to 5.49.0" in line for line in lines)


def test_windows_hand_over_for_restore(world, monkeypatch):
    upgraded(world)
    monkeypatch.setattr(localswap, "is_windows", lambda: True)
    monkeypatch.setenv(localupgrade.REEXEC_ENV, "1")
    assert go(world, "--restore-previous", "--confirm", "RESTORE")[0] == 86
    assert localswap.version_of(world.root) == NEW
    monkeypatch.delenv(localupgrade.REEXEC_ENV)
    assert localswap.run_pending_plan(world.root, lambda *_: None) == 0
    assert localswap.version_of(world.root) == OLD


def test_an_unreadable_plan_changes_nothing(world):
    layout = localswap.Layout(world.root)
    localswap.plan_path(layout).write_text("{broken")
    assert localswap.run_pending_plan(world.root, lambda *_: None) == 3 and localswap.version_of(world.root) == OLD


def test_windows_device_and_stream_names_are_refused_by_the_release_unpacker():
    for bad in ("CON", "nul.txt", "dir/COM1.py", "file.", "dir /x", "a:b", "x<y", "q?"):
        assert verifylib._safe_relpath(bad) is None, bad
    for good in ("server/serve.py", "frontend/dist/assets/index-abc.js", "docs/api-notes.md", "console.py", "a.b/c.d"):
        assert verifylib._safe_relpath(good) == good, good


# --- the environment build -----------------------------------------------------------------------------


def test_pip_arguments_online_and_offline(world, monkeypatch, tmp_path):
    staged = tmp_path / "stage"
    staged.mkdir()
    (staged / "requirements.lock").write_text("x")
    calls = []

    def fake_run(argv, **kw):
        calls.append([str(a) for a in argv])
        if argv[1:3] == ["-m", "venv"]:
            py = localupgrade.venv_python(staged)
            py.parent.mkdir(parents=True, exist_ok=True)
            py.write_text("")
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(localupgrade.subprocess, "run", fake_run)
    host = localupgrade.Host()
    localupgrade._build_environment(staged, None, lambda *_: None, host)
    pip = calls[-1]
    assert "--require-hashes" in pip and "--no-index" not in pip and pip[-2:] == ["-r", str(staged / "requirements.lock")]
    calls.clear()
    (localupgrade.venv_python(staged)).unlink()
    localupgrade._build_environment(staged, tmp_path / "wheels", lambda *_: None, host)
    pip = calls[-1]
    assert "--no-index" in pip and "--require-hashes" in pip and pip[pip.index("--find-links") + 1] == str(tmp_path / "wheels")


def test_a_pip_failure_names_the_likely_cause_and_changes_nothing(world, monkeypatch, tmp_path):
    staged = tmp_path / "stage"
    staged.mkdir()
    (staged / "requirements.lock").write_text("x")

    def fake_run(argv, **kw):
        if argv[1:3] == ["-m", "venv"]:
            py = localupgrade.venv_python(staged)
            py.parent.mkdir(parents=True, exist_ok=True)
            py.write_text("")
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("P", (), {"returncode": 1, "stdout": "", "stderr": "No matching distribution found"})()
    monkeypatch.setattr(localupgrade.subprocess, "run", fake_run)
    with pytest.raises(localupgrade.Refused) as exc:
        localupgrade._build_environment(staged, tmp_path / "w", lambda *_: None, localupgrade.Host())
    assert "offline bundle has no package for this computer" in str(exc.value)


@POSIX
def test_an_environment_is_built_when_the_old_folder_had_one(world, monkeypatch):
    (world.root / ".venv").mkdir()
    built = []

    def fake_build(staged, wheels, say, host):
        built.append(wheels)
        py = localupgrade.venv_python(staged)
        py.parent.mkdir(parents=True)
        os.symlink(sys.executable, py)
        return py
    monkeypatch.setattr(localupgrade, "_build_environment", fake_build)
    assert go(world, *upgrade_args(world))[0] == 0 and built == [None]


# --- the offline bundle through the guided upgrade -----------------------------------------------------


def make_bundle(world, lock_text="# lock\n"):
    wheel = b"wheel"
    info = {"schema": 1, "version": NEW, "requirements_lock_sha256": hashlib.sha256(lock_text.encode()).hexdigest(),
            "wheels": {"a-1-py3-none-any.whl": hashlib.sha256(wheel).hexdigest()}}
    path = world.tmp / f"ocw-{NEW}-offline.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in {f"ocw-{NEW}.tar.gz": world.rel.tar.read_bytes(), f"ocw-{NEW}.tar.gz.minisig": world.rel.sig.read_bytes(),
                           "offline.json": json.dumps(info).encode(), "wheels/a-1-py3-none-any.whl": wheel}.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return path


@POSIX
def test_upgrade_from_an_offline_bundle_uses_its_wheels(world, monkeypatch):
    (world.root / ".venv").mkdir()
    seen = []

    def fake_build(staged, wheels, say, host):
        seen.append(wheels)
        py = localupgrade.venv_python(staged)
        py.parent.mkdir(parents=True)
        os.symlink(sys.executable, py)
        return py
    monkeypatch.setattr(localupgrade, "_build_environment", fake_build)
    code, out = go(world, "--from-file", str(make_bundle(world)), "--confirm", NEW)
    assert code == 0, out
    assert "Offline bundle" in out and seen and seen[0].name == "wheels" and localswap.version_of(world.root) == NEW


def test_a_bundle_paired_with_another_lock_is_refused(world):
    refused(world, 2, "--from-file", str(make_bundle(world, lock_text="# other lock\n")), "--confirm", NEW)


def test_a_hostile_bundle_is_refused(world):
    path = world.tmp / f"ocw-{NEW}-offline.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        ti = tarfile.TarInfo("../../evil")
        ti.size = 1
        tar.addfile(ti, io.BytesIO(b"x"))
    out = refused(world, 2, "--from-file", str(path), "--confirm", NEW)
    assert "offline bundle was refused" in out and not (world.tmp.parent / "evil").exists()


# --- the launcher glue ---------------------------------------------------------------------------------


def test_launch_py_dispatches_the_upgrade_command(monkeypatch):
    import launch
    seen = []
    monkeypatch.setattr(launch, "run_upgrade", lambda args: seen.append(args) or 0)
    monkeypatch.setattr(sys, "argv", ["launch.py", "upgrade", "--check"])
    with pytest.raises(SystemExit) as exc:
        launch.main()
    assert exc.value.code == 0 and seen == [["--check"]]


def test_the_outer_launcher_finishes_a_pending_swap_only_for_upgrade(monkeypatch, world):
    import launch
    monkeypatch.setattr(launch, "PROJECT_ROOT", world.root)
    done = []
    monkeypatch.setattr(localswap, "run_pending_plan", lambda root, say=print: done.append(root) or 0)
    # The outer launcher passes sys.argv: [script, command, ...]
    assert launch._finish_pending_swap_if_asked(86, ["launch.py", "upgrade", "--to", "5.49.0"]) == 0 and done == [world.root]
    assert launch._finish_pending_swap_if_asked(86, ["launch.py"]) == 86      # an ordinary run is untouched
    assert launch._finish_pending_swap_if_asked(1, ["launch.py", "upgrade"]) == 1


def test_the_outer_launcher_runs_the_pending_swap_when_the_inner_upgrade_asks(monkeypatch, world):
    """End to end through _run_child_and_exit with the real sys.argv shape: the inner (venv) process exits 86."""
    import launch
    monkeypatch.setattr(launch, "PROJECT_ROOT", world.root)
    done = []
    monkeypatch.setattr(localswap, "run_pending_plan", lambda root, say=print: done.append(root) or 0)

    class FakeChild:
        def __init__(self, argv):
            self.argv = argv

        def wait(self, timeout=None):
            return localswap.EXIT_SWAP_PENDING

    monkeypatch.setattr(launch.subprocess, "Popen", FakeChild)
    monkeypatch.setattr(sys, "argv", ["launch.py", "upgrade", "--to", "5.49.0"])
    with pytest.raises(SystemExit) as exc:
        launch._run_child_and_exit([".venv/Scripts/python.exe", "launch.py", "upgrade", "--to", "5.49.0"], owns_shutdown=False)
    assert exc.value.code == 0 and done == [world.root]


def test_a_malformed_version_is_refused_before_any_download(monkeypatch, world):
    called = []
    monkeypatch.setattr(localupgrade, "_download", lambda *a, **k: called.append(a))
    monkeypatch.setattr(localupgrade, "_refresh_revocations", lambda say: None)
    code, out = go(world, "--to", "../../x", "--confirm", "x")
    assert code == localupgrade.EXIT_REFUSED and called == [] and "must look like" in out

def test_launch_upgrade_without_cryptography_explains(monkeypatch, capsys):
    import launch
    real_import = __import__

    def fake_import(name, *a, **k):
        if name == "cryptography":
            raise ImportError("no cryptography")
        return real_import(name, *a, **k)
    monkeypatch.setattr("builtins.__import__", fake_import)
    monkeypatch.setenv(launch._REEXEC_MARKER, "1")
    assert launch.run_upgrade(["--check"]) == 4
    assert "Start the dashboard once" in capsys.readouterr().out


def test_launch_host_stop_server_only_stops_this_folders_dashboard(monkeypatch, capsys):
    import launch
    host = launch._UpgradeHost()
    monkeypatch.setattr(launch, "_listening_pid", lambda port: 4242)
    monkeypatch.setattr(launch, "_process_command_line", lambda pid: (["python", "other.py"], "python other.py", None))
    monkeypatch.setattr(launch, "_stop_pid", lambda pid: pytest.fail("must not stop a foreign process"))
    assert host.stop_server(8766) is False and "not this folder's dashboard" in capsys.readouterr().out
    monkeypatch.setattr(launch, "_is_this_checkouts_server", lambda *a: True)
    monkeypatch.setattr(launch, "_confirm", lambda prompt: True)
    monkeypatch.setattr(launch, "_stop_pid", lambda pid: True)
    assert host.stop_server(8766) is True
    monkeypatch.setattr(launch, "_listening_pid", lambda port: None)
    assert host.stop_server(8766) is False


@pytest.mark.parametrize("edit,why", [({"root": "/somewhere/else"}, "another folder"), ({"staged": "/etc"}, "unexpected folder"),
                                      ({"python": "/tmp/evil"}, "unexpected program"), ({"kind": "format-disk"}, "unknown kind"),
                                      ({"version": "../x"}, "unexpected folder")])
def test_a_tampered_swap_plan_is_not_followed(world, edit, why):
    layout = localswap.Layout(world.root)
    plan = {"kind": "upgrade", "root": str(layout.current), "staged": str(layout.staged(NEW)), "version": NEW, "from_version": OLD,
            "python": sys.executable, "events": []}
    path = localswap.plan_path(layout)
    path.write_text(json.dumps({**plan, **edit}))
    lines = []
    assert localswap.run_pending_plan(world.root, lines.append) == 3
    assert why in "\n".join(lines) and localswap.version_of(world.root) == OLD and not path.exists()


@POSIX
def test_a_swap_plan_writable_by_others_is_not_followed(world):
    layout = localswap.Layout(world.root)
    path = localswap.plan_path(layout)
    path.write_text(json.dumps({"kind": "restore", "root": str(layout.current)}))
    os.chmod(path, 0o666)
    lines = []
    assert localswap.run_pending_plan(world.root, lines.append) == 3 and "writable by other users" in "\n".join(lines)
