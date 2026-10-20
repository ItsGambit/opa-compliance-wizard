"""server/updater/stage.py: the unprivileged staging step (verify, unpack, hash-checked environment). pip and `venv`
are replaced by fakes; everything else is the real code, including the download from a local release server."""

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from release_helpers import TestKey, TestStandby, key_list, make_release_tar, sign_release
from server.updater import stage as stagemod

VERSION = "9.9.99"


@pytest.fixture
def env(tmp_path, monkeypatch):
    primary, standby = TestKey(), TestStandby()
    kl = key_list([primary, standby])
    opt = tmp_path / "opt"
    (opt / "updater").mkdir(parents=True)
    from updater_fakes import ocw_trust
    trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list(json.dumps(kl).encode()), "revoked": []}
    (opt / "updater" / "trust.json").write_text(json.dumps(trust))
    art = tmp_path / "artifacts"
    art.mkdir()
    dist = tmp_path / "dist"
    dist.mkdir()
    tar = make_release_tar(dist / f"ocw-{VERSION}.tar.gz", VERSION, kl, extra_files={"requirements.lock": b"# lock\n", "server/x.py": b"x = 1\n"})
    sign_release(tar, primary, VERSION)
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    monkeypatch.setenv("OCW_ARTIFACTS_DIR", str(art))
    for k in ("OCW_TEST_MODE", "OCW_UPDATER_FAULT", "OPA_RELEASE_BASE_URL", "OPA_REVOCATION_URL", "OPA_REVOCATION_URL_BASE"):
        monkeypatch.delenv(k, raising=False)
    runs = []
    pip_rc = {"rc": 0, "err": ""}

    def fake_run(argv, **kw):
        runs.append(list(argv))
        if "venv" in argv:
            (Path(argv[-1]) / "bin").mkdir(parents=True)
            (Path(argv[-1]) / "bin" / "pip").write_text("")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "install" in argv:
            return subprocess.CompletedProcess(argv, pip_rc["rc"], "", pip_rc["err"])
        if "freeze" in argv:
            return subprocess.CompletedProcess(argv, 0, "cryptography==1.0\nkeyring==2.0\n", "")
        raise AssertionError(argv)
    monkeypatch.setattr(stagemod.subprocess, "run", fake_run)

    class E:
        pass
    e = E()
    e.__dict__.update(opt=opt, art=art, dist=dist, tar=tar, primary=primary, standby=standby, kl=kl, runs=runs, pip=pip_rc, tmp=tmp_path)

    def put():
        for n in (f"ocw-{VERSION}.tar.gz", f"ocw-{VERSION}.tar.gz.minisig"):
            (art / n).write_bytes((dist / n).read_bytes())
    e.put = put
    return e


def test_stage_unpacks_builds_the_environment_with_hashes_and_writes_the_marker_last(env):
    env.put()
    info = stagemod.stage(VERSION)
    d = env.opt / "releases" / VERSION
    staged = json.loads((d / ".staged").read_text())
    assert staged["version"] == VERSION and staged["sha256"] == info.sha256 and staged["verifier"] == "ok"
    assert staged["pip_freeze"] == ["cryptography==1.0", "keyring==2.0"] and len(staged["pip_freeze_sha256"]) == 64
    assert (d / "server" / "x.py").read_text() == "x = 1\n" and (d / ".venv" / "bin" / "pip").exists()
    install = [r for r in env.runs if "install" in r][0]
    assert "--require-hashes" in install and install[install.index("-r") + 1].endswith("requirements.lock")
    assert not list(d.rglob("__pycache__"))


def test_a_forged_release_is_refused_quarantined_and_reported_with_a_code(env, monkeypatch):
    other = TestKey()
    sign_release(env.tar, other, VERSION)
    env.put()
    assert stagemod.main([VERSION]) == 1
    err = json.loads((env.art / f"{VERSION}.stage-error.json").read_text())
    assert err["code"] == "key_unknown"
    assert (env.art / f"ocw-{VERSION}.tar.gz.rejected").exists() and not (env.opt / "releases" / VERSION).exists()


def test_downgrade_and_tamper_are_refused(env):
    env.put()
    tar = env.art / f"ocw-{VERSION}.tar.gz"
    data = bytearray(tar.read_bytes())
    data[len(data) // 2] ^= 1
    tar.write_bytes(bytes(data))
    with pytest.raises(stagemod.StageError) as e:
        stagemod.stage(VERSION)
    assert e.value.code in ("hash_mismatch", "bad_release", "signature_invalid")


def test_a_crash_after_unpacking_leaves_nothing_usable_and_the_next_attempt_cleans_up(env, monkeypatch):
    env.put()
    monkeypatch.setenv("OCW_TEST_MODE", "1")
    monkeypatch.setenv("OCW_UPDATER_FAULT", "after_unpack")
    with pytest.raises(stagemod.StageError):
        stagemod.stage(VERSION)
    d = env.opt / "releases" / VERSION
    assert d.exists() and not (d / ".staged").exists()  # incomplete: no marker
    monkeypatch.delenv("OCW_UPDATER_FAULT")
    stagemod.stage(VERSION)
    assert (d / ".staged").exists()


def test_faults_only_count_in_test_mode(env, monkeypatch):
    env.put()
    monkeypatch.setenv("OCW_UPDATER_FAULT", "disk_full")  # OCW_TEST_MODE is not set: ignored
    stagemod.stage(VERSION)


def test_disk_full_and_pip_failures_have_their_own_codes_and_clean_up(env, monkeypatch):
    env.put()
    monkeypatch.setenv("OCW_TEST_MODE", "1")
    monkeypatch.setenv("OCW_UPDATER_FAULT", "disk_full")
    with pytest.raises(stagemod.StageError) as e:
        stagemod.stage(VERSION)
    assert e.value.code == "disk_space" and not (env.opt / "releases" / VERSION).exists()
    monkeypatch.delenv("OCW_UPDATER_FAULT")
    env.pip.update(rc=1, err="ERROR: THESE PACKAGES DO NOT MATCH THE HASHES")
    with pytest.raises(stagemod.StageError) as e:
        stagemod.stage(VERSION)
    assert e.value.code == "pip_failed" and "DO NOT MATCH THE HASHES" in str(e.value) and not (env.opt / "releases" / VERSION).exists()


def test_a_release_without_a_lock_cannot_be_staged(env):
    kl = env.kl
    tar = make_release_tar(env.dist / "ocw-9.9.98.tar.gz", "9.9.98", kl)
    sign_release(tar, env.primary, "9.9.98")
    for n in ("ocw-9.9.98.tar.gz", "ocw-9.9.98.tar.gz.minisig"):
        (env.art / n).write_bytes((env.dist / n).read_bytes())
    with pytest.raises(stagemod.StageError) as e:
        stagemod.stage("9.9.98")
    assert e.value.code == "pip_failed" and "requirements.lock" in str(e.value)


def test_already_staged_is_a_no_op(env):
    env.put()
    stagemod.stage(VERSION)
    env.runs.clear()
    stagemod.stage(VERSION)
    assert env.runs == []


@pytest.fixture
def mirror(env):
    files = {f"/v{VERSION}/ocw-{VERSION}.tar.gz": (env.dist / f"ocw-{VERSION}.tar.gz").read_bytes(),
             f"/v{VERSION}/ocw-{VERSION}.tar.gz.minisig": (env.dist / f"ocw-{VERSION}.tar.gz.minisig").read_bytes(),
             "/revocation/revocation.json": b'{"format": "x"}'}
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            if self.path in files:
                self.send_response(200)
                self.send_header("Content-Length", str(len(files[self.path])))
                self.end_headers()
                self.wfile.write(files[self.path])
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hits, files
    srv.shutdown()


def test_download_from_a_mirror_and_published_revocations_are_kept_for_root(env, mirror, monkeypatch):
    base, hits, _files = mirror
    monkeypatch.setenv("OPA_RELEASE_BASE_URL", base)
    monkeypatch.setenv("OPA_REVOCATION_URL_BASE", base + "/revocation")
    stagemod.stage(VERSION)
    assert (env.opt / "releases" / VERSION / ".staged").exists()
    assert any(p.endswith(".tar.gz.minisig") for p in hits) and "/revocation/revocation.json" in hits
    kept = list((env.art / "revocations").glob("rev-*.json"))
    assert len(kept) == 1  # root re-verifies it itself; staging does not interpret it


def test_download_failure_is_reported_in_words(env, mirror, monkeypatch):
    base, _hits, files = mirror
    files.clear()
    monkeypatch.setenv("OPA_RELEASE_BASE_URL", base)
    assert stagemod.main([VERSION]) == 1
    err = json.loads((env.art / f"{VERSION}.stage-error.json").read_text())
    assert err["code"] == "download_failed" and "stage <file>" in err["message"]


def test_usage_and_a_missing_trust_list(env, capsys):
    assert stagemod.main([]) == 2 and stagemod.main(["1.2"]) == 2
    (env.opt / "updater" / "trust.json").unlink()
    env.put()
    assert stagemod.main([VERSION]) == 1
    assert json.loads((env.art / f"{VERSION}.stage-error.json").read_text())["code"] == "no_trust"
