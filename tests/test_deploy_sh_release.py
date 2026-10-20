"""server/deploy.sh --release (5.46.0), run for real against a temp install
with the same stubbed system commands as test_deploy_sh.py. The installed
copy's pinned key list is the root of trust; every refusal must leave the
install untouched and say why."""

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

from release_helpers import TestKey, TestStandby, key_list, make_release_tar, sign_release
from server.updater import keys as keylib
from test_deploy_sh import Deploy, d, source_tree  # noqa: F401  (fixtures)
from test_release_verify import forged_as

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="deploy.sh runs on Linux servers")
REAL = Path(__file__).resolve().parent / "fixtures" / "minisign_real"
NEW = "9.9.9"


@pytest.fixture
def pinned(d):
    primary, standby = TestKey(), TestStandby()
    kl = keylib.validate_key_list(key_list([primary, standby]))
    (d.app / "server" / "release_keys.json").write_text(json.dumps(kl))
    return primary, standby, kl


def make_release(d, kl, signer, version=NEW, dest=None, tamper=False, **kw):
    """A complete signed release of the checkout under test, version bumped."""
    files = {}
    for p in d.remote.rglob("*"):
        if p.is_file() and ".git/" not in str(p):
            files[str(p.relative_to(d.remote))] = p.read_bytes()
    files["create_secret_folders.py"] = re.sub(rb'SCRIPT_VERSION = "[^"]+"', f'SCRIPT_VERSION = "{version}"'.encode(),
                                               files["create_secret_folders.py"])
    files["server/release_keys.json"] = json.dumps(kl).encode()
    out = Path(dest or d.tmp / "release")
    out.mkdir(parents=True, exist_ok=True)
    tar = make_release_tar(out / f"ocw-{version}.tar.gz", version, kl, extra_files=files)
    sig = sign_release(tar, signer, version, **kw)
    if tamper:
        data = bytearray(tar.read_bytes())
        data[len(data) // 2] ^= 1
        tar.write_bytes(bytes(data))
    d.state["version_after_restart"] = version
    return out


def snapshot(d):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (d.app / "create_secret_folders.py",
                                                                          d.app / "server" / "deploy.sh")}


def test_release_from_a_local_directory_installs_without_node(d, pinned):
    primary, _s, kl = pinned
    rel = make_release(d, kl, primary)
    proc = d.run("--release", NEW, "--from-dir", str(rel))
    assert proc.returncode == 0, d.out
    assert f'SCRIPT_VERSION = "{NEW}"' in (d.app / "create_secret_folders.py").read_text()
    assert (d.app / "frontend" / "dist" / "index.html").read_text().startswith("<html>built")  # from the tarball
    assert d.calls("npm") == [] and d.calls("npx") == []  # no Node needed
    assert "--require-hashes" in d.state["pip_argv"] and any(a.endswith("requirements.lock") for a in d.state["pip_argv"])
    d.assert_one_terminal("deploy.completed")
    started = [e for e in d.events() if e["action"] == "deploy.started"][0]
    assert started["details"]["source"] == "signed_release"
    assert "UNSIGNED" not in d.out
    assert (d.app / "manifest.json").exists()  # the installed manifest, for support


def test_release_download_uses_the_release_host(d, pinned):
    primary, _s, kl = pinned
    rel = make_release(d, kl, primary)
    d.state["release_files"] = {f"/v{NEW}/ocw-{NEW}.tar.gz": str(rel / f"ocw-{NEW}.tar.gz"),
                                f"/v{NEW}/ocw-{NEW}.tar.gz.minisig": str(rel / f"ocw-{NEW}.tar.gz.minisig")}
    proc = d.run("--release", NEW, env=d.env(OPA_RELEASE_BASE_URL="http://127.0.0.1:9/dl"))
    assert proc.returncode == 0, d.out
    urls = [a for argv in d.calls("curl") for a in argv if a.startswith("http://127.0.0.1:9/")]
    assert f"http://127.0.0.1:9/dl/v{NEW}/ocw-{NEW}.tar.gz" in urls
    all_urls = [a for argv in d.calls("curl") for a in argv if a.startswith("http")]
    assert any(u.endswith("/revocation/revocation.json") for u in all_urls)  # best-effort revocation check


def test_download_failure_changes_nothing_and_says_what_to_do(d, pinned):
    before = snapshot(d)
    proc = d.run("--release", NEW, env=d.env(OPA_RELEASE_BASE_URL="http://127.0.0.1:9/dl"))
    assert proc.returncode != 0 and "could not download release" in d.out and "--from-dir" in d.out
    assert snapshot(d) == before and d.deploy_events() == []


def test_unsigned_tampered_or_wrongly_signed_input_is_refused(d, pinned):
    primary, standby, kl = pinned
    before = snapshot(d)
    for label, signer, tamper, fragment in (
        ("flipped byte", primary, True, "signature does not match"),
        ("unknown key", TestKey(), False, "not pinned"),
        ("standby key", forged_as(standby), False, "may not sign releases"),
    ):
        rel = make_release(d, kl, signer, dest=d.tmp / label.replace(" ", "_"), tamper=tamper)
        proc = d.run("--release", NEW, "--from-dir", str(rel))
        assert proc.returncode != 0, label
        assert fragment in d.out and "REFUSED" in d.out and "Nothing has been changed" in d.out, (label, d.out)
        assert "Traceback" not in d.out
        assert snapshot(d) == before and d.calls("pip") == [] and d.calls("systemctl", ) is not None
        assert not [a for a, _ in d.deploy_events() if a == "deploy.started"]
    refusals = [e for e in d.events() if e["action"] == "upgrade.verify_failed"]
    assert len(refusals) == 3 and {e["details"]["reason"] for e in refusals} == {"bad_signature", "unknown_key", "wrong_role"}


def test_no_pinned_key_refuses_with_an_explanation(d):
    primary = TestKey()
    kl = keylib.validate_key_list(key_list([primary, TestStandby()]))
    rel = make_release(d, kl, primary)
    # a fork or self-built install with no pinned key
    (d.app / "server" / "release_keys.json").write_text('{"schema": 1, "keys": []}\n')
    proc = d.run("--release", NEW, "--from-dir", str(rel))
    assert proc.returncode != 0 and "no release key pinned" in d.out


def test_release_signed_by_an_unknown_key_is_refused(d):
    """The shipped install pins the project's keys; a release signed by any other key is refused."""
    stranger = TestKey()
    kl = keylib.validate_key_list(key_list([stranger, TestStandby()]))
    rel = make_release(d, kl, stranger)
    proc = d.run("--release", NEW, "--from-dir", str(rel))
    assert proc.returncode != 0
    assert "no release key pinned" not in d.out


def test_downgrade_and_same_version_need_intent(d, pinned):
    primary, _s, kl = pinned
    rel = make_release(d, kl, primary, version="5.1.0")
    proc = d.run("--release", "5.1.0", "--from-dir", str(rel))
    assert proc.returncode != 0 and "not newer" in d.out
    rel = make_release(d, kl, primary, version=d.version, dest=d.tmp / "same")
    proc = d.run("--release", d.version, "--from-dir", str(rel))
    assert proc.returncode != 0 and "--reinstall" in d.out
    proc = d.run("--release", d.version, "--from-dir", str(rel), "--reinstall")
    assert proc.returncode == 0, d.out


def test_a_published_revocation_blocks_a_release_signed_by_the_revoked_key(d):
    shutil.copy(REAL / "release_keys.json", d.app / "server" / "release_keys.json")
    rel = d.tmp / "real"
    shutil.copytree(REAL, rel)
    proc = d.run("--release", "9.9.11", "--from-dir", str(rel))
    assert proc.returncode != 0
    assert "revocation" in d.out.lower() and "was revoked" in d.out and "Do not install it" in d.out
    assert keylib.effective_key_list(d.app / "server" / "release_keys.json", d.app / "release_keys.local.json")["serial"] == 1
    assert not [a for a, _ in d.deploy_events() if a == "deploy.started"]
    actions = [e["action"] for e in d.events()]
    assert "upgrade.key_revoked" in actions and "upgrade.verify_failed" in actions


def test_a_bad_revocation_stops_the_deploy(d):
    shutil.copy(REAL / "release_keys.json", d.app / "server" / "release_keys.json")
    rel = d.tmp / "real"
    shutil.copytree(REAL, rel)
    envelope = json.loads((REAL / "revocation.json").read_text())
    envelope["payload"] = envelope["payload"][:-4] + "AAAA"          # a damaged / forged payload
    (rel / "revocation.json").write_text(json.dumps(envelope))
    proc = d.run("--release", "9.9.9", "--from-dir", str(rel))
    assert proc.returncode != 0 and "revocation is published but could not be applied" in d.out
    assert not (d.app / "release_keys.local.json").exists()


def test_the_local_key_state_survives_a_deploy(d, pinned):
    primary, _s, kl = pinned
    (d.app / "update_check.json").write_text('{"settings": {"enabled": true}}')
    (d.app / "release_keys.local.json").write_text(json.dumps({**keylib.empty_state(), "serial": 5}))
    rel = make_release(d, kl, primary)
    assert d.run("--release", NEW, "--from-dir", str(rel)).returncode == 0, d.out
    assert (d.app / "update_check.json").read_text() == '{"settings": {"enabled": true}}'
    state = json.loads((d.app / "release_keys.local.json").read_text())
    assert state["serial"] == 5 and len(state["keys"]) == 2      # kept, and now also remembers every key it verified with


def test_argument_rules(d, pinned):
    for args in (["--release", "5.1.0", "--ref", "main"], ["--from-dir", "/x"], ["--reinstall"],
                 ["--release", "latest"], ["--release", "5.1"], ["--release", "5.1.0", "--from-dir", "relative"]):
        proc = d.run(*args)
        assert proc.returncode == 2 or (proc.returncode == 1 and args[1] in ("latest", "5.1")), (args, d.out)
        assert d.deploy_events() == []


def test_git_ref_deploys_still_work_and_say_they_are_unsigned(d):
    proc = d.run()
    assert proc.returncode == 0, d.out
    assert "UNSIGNED source" in d.out and "--release" in d.out
    started = [e for e in d.events() if e["action"] == "deploy.started"][0]
    assert started["details"]["source"] == "unsigned_git"
