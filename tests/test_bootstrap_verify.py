"""The verifier that get-ocw.sh embeds (server/updater/root/ocw_bootstrap_verify.py), run on its own: the same vectors the
application's verifier is held to (good signature, wrong key, standby key, revoked key, known_good pin, tampered tarball,
tampered manifest, truncated file, downgrade, unsafe paths in the tarball), plus the downloader's rules. Test keys only,
generated here; no network except loopback."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from release_helpers import TestKey, TestStandby, key_list, make_release_tar, make_revocation, revocation_payload, sign_release

REPO = Path(__file__).resolve().parent.parent
ROOT_DIR = str(REPO / "server" / "updater" / "root")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import ocw_bootstrap_verify as bv  # noqa: E402
from fake_release_server import FakeReleaseServer  # noqa: E402


class World:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.key = TestKey()
        self.standby = TestStandby()
        self.keys_raw = (json.dumps(key_list([self.key, self.standby])) + "\n").encode()
        self.n = 0

    def release(self, version="5.52.0", key=None, alg=b"ED", kl=None, **kw):
        self.n += 1
        d = self.tmp / f"rel{self.n}"
        d.mkdir()
        tar = make_release_tar(d / f"ocw-{version}.tar.gz", version, kl or key_list([self.key, self.standby]), **kw)
        sig = sign_release(tar, key or self.key, version, alg=alg)
        return str(tar), sig

    def run(self, tar, sig, bootstrap="5.52.0", expect=None, allow_older=False, revocations=(), keys_raw=None):
        self.n += 1
        out = self.tmp / f"out{self.n}"
        return bv.verify_and_extract(tar, sig, keys_raw or self.keys_raw, bootstrap, str(out), expect, allow_older, list(revocations)), out

    def refused(self, code, *a, **kw):
        with pytest.raises(bv.Refused) as info:
            self.run(*a, **kw)
        assert info.value.code == code, str(info.value)
        return str(info.value)


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def test_good_release_verifies_and_unpacks(w):
    tar, sig = w.release()
    (info, ok, notes, applied), out = w.run(tar, sig, expect="5.52.0")
    assert info["version"] == "5.52.0" and info["key_id"] == w.key.key_id and info["revocation_serial_applied"] == 0
    assert info["sha256"] == hashlib.sha256(Path(tar).read_bytes()).hexdigest()
    assert "signature valid" in ok[0] and w.key.key_id in ok[0] and "no key revocation published" in ok[0]
    assert (out / "create_secret_folders.py").read_text().startswith('SCRIPT_VERSION = "5.52.0"')
    assert (out / "server" / "deploy.sh").stat().st_mode & 0o777 == 0o755
    assert (out / "manifest.json").is_file() and not notes and not applied


def test_wrong_key_is_refused(w):
    stranger = TestKey()
    tar, sig = w.release(key=stranger)
    msg = w.refused("key_unknown", tar, sig)
    assert "not trusted" in msg
    assert "download the current get-ocw.sh" in bv.hint_for("key_unknown").lower()


def test_a_key_claiming_the_standby_id_cannot_sign_a_release(w):
    forged = TestKey()
    forged.stored_id = bytes.fromhex(w.standby.key_id)[::-1]
    forged.key_id = w.standby.key_id
    tar, sig = w.release(key=forged)
    w.refused("wrong_role", tar, sig)


def test_legacy_non_prehashed_signature_is_refused(w):
    tar, sig = w.release(alg=b"Ed")
    w.refused("signature_invalid", tar, sig)


def test_tampered_tarball_is_refused_before_it_is_opened(w):
    tar, sig = w.release()
    data = bytearray(Path(tar).read_bytes())
    data[len(data) // 2] ^= 1
    Path(tar).write_bytes(bytes(data))
    w.refused("signature_invalid", tar, sig)  # the prehash no longer matches the signed digest
    assert not (w.tmp / f"out{w.n}").exists()  # nothing was unpacked


def test_truncated_tarball_is_refused(w):
    tar, sig = w.release()
    data = Path(tar).read_bytes()
    Path(tar).write_bytes(data[: len(data) // 2])
    w.refused("signature_invalid", tar, sig)


def test_tampered_signature_comment_is_refused(w):
    tar, sig = w.release()
    text = Path(sig).read_text().replace("version=5.52.0", "version=5.99.0")
    Path(sig).write_text(text)
    w.refused("signature_invalid", tar, sig)


def test_file_renamed_after_signing_is_refused(w):
    tar, sig = w.release()
    other = Path(tar).with_name("ocw-5.52.0-renamed.tar.gz")
    Path(tar).rename(other)
    Path(sig).rename(str(other) + ".minisig")
    w.refused("name_mismatch", str(other), str(other) + ".minisig")


def test_signed_but_wrong_manifest_is_refused(w):
    tar, sig = w.release(manifest_over={"version": "9.9.9"})
    w.refused("version_mismatch", tar, sig)
    tar, sig = w.release(script_version="5.51.0")
    w.refused("version_mismatch", tar, sig)


def test_a_file_that_differs_from_the_signed_manifest_is_refused(w):
    # the manifest names a different hash for a file the tarball carries: a validly signed but internally inconsistent release
    tar, sig = w.release(manifest_over={"files": {"CHANGELOG.md": "0" * 64}})
    with pytest.raises(bv.Refused) as info:
        w.run(tar, sig)
    assert info.value.code == "file_mismatch"


def test_manifest_missing_from_the_tarball_is_refused(w):
    tar, sig = w.release(drop=("create_secret_folders.py",))
    w.refused("bad_release", tar, sig)


def test_release_that_adds_a_standby_key_is_refused(w):
    extra = TestStandby()
    tar, sig = w.release(kl=key_list([w.key, w.standby, extra]))
    w.refused("keys_changed", tar, sig)


def test_downgrade_is_refused_unless_allowed(w):
    tar, sig = w.release(version="5.49.0")
    msg = w.refused("downgrade", tar, sig, bootstrap="5.52.0")
    assert "older than this installer (5.52.0)" in msg and "--allow-older" in bv.hint_for("downgrade")
    (info, *_), _out = w.run(tar, sig, bootstrap="5.52.0", allow_older=True)
    assert info["version"] == "5.49.0"
    # equal and newer are fine
    tar2, sig2 = w.release(version="5.52.0")
    w.run(tar2, sig2, bootstrap="5.52.0")
    tar3, sig3 = w.release(version="5.53.1")
    w.run(tar3, sig3, bootstrap="5.52.0")


def test_requested_version_must_be_the_signed_version(w):
    tar, sig = w.release()
    w.refused("version_mismatch", tar, sig, expect="5.51.0")


# --- revocation ------------------------------------------------------------------------------------------------------


def _revoke(w, serial=1, revoke=None, add=None, tamper=None, signer=None):
    path = w.tmp / f"revocation-{serial}-{w.n}.json"
    w.n += 1
    make_revocation(path, [signer or w.standby], revocation_payload(serial, revoke=revoke if revoke is not None else [w.key.key_id],
                                                                    add_keys=[add] if add else []), tamper=tamper)
    return str(path)


def test_a_revoked_key_verifies_nothing_after_a_standby_signed_revocation(w):
    tar, sig = w.release()
    new = TestKey()
    rev = _revoke(w, add=new)
    msg = w.refused("revoked_key", tar, sig, revocations=[rev])
    assert "revoked" in msg
    # a release signed by the key the revocation added verifies, and the serial is reported
    kl = key_list([w.key, w.standby, new])
    tar2, sig2 = w.release(key=new, kl=kl)
    (info, ok, _n, applied), _out = w.run(tar2, sig2, revocations=[rev])
    assert info["revocation_serial_applied"] == 1 and "serial 1 applied" in ok[0] and applied[0]["serial"] == 1


def test_known_good_pin_still_accepts_the_revoked_keys_old_release(w):
    tar, sig = w.release()
    sha = hashlib.sha256(Path(tar).read_bytes()).hexdigest()
    new = TestKey()
    rev = _revoke(w, revoke=[{"key_id": w.key.key_id, "known_good": {"5.52.0": sha}}], add=new)
    (info, *_), _out = w.run(tar, sig, revocations=[rev])
    assert info["version"] == "5.52.0" and info["revocation_serial_applied"] == 1
    other, other_sig = w.release(version="5.53.0")  # same revoked key, a release the revocation does not pin
    w.refused("revoked_key", other, other_sig, revocations=[rev])


def test_garbage_replayed_and_forged_revocations_are_ignored_not_fatal(w):
    tar, sig = w.release()
    garbage = w.tmp / "garbage.json"
    garbage.write_text("not json at all")
    forged = _revoke(w, signer=TestStandby())          # signed by a standby key this installer does not know
    tampered = _revoke(w, serial=2, tamper="payload")
    (info, ok, notes, applied), _ = w.run(tar, sig, revocations=[str(garbage), forged, tampered])
    assert info["revocation_serial_applied"] == 0 and not applied
    assert len(notes) == 3 and all("ignored" in n for n in notes)
    assert "no valid key revocation applied" in ok[0]


def test_revocation_with_an_old_serial_is_ignored_after_a_newer_one_applied(w):
    tar, sig = w.release(version="5.52.0")
    new = TestKey()
    first = _revoke(w, serial=1, revoke=[], add=new)
    again = _revoke(w, serial=1, revoke=[w.key.key_id])  # same serial: a replay, ignored once the first is applied
    (info, _ok, notes, applied), _ = w.run(tar, sig, revocations=[first, again])
    assert info["revocation_serial_applied"] == 1 and len(applied) == 1 and any("replayed" in n for n in notes)


# --- unpacking -------------------------------------------------------------------------------------------------------


def _with_member(src, dst, name, data=b"x", member_type=None, linkname=""):
    out = io.BytesIO()
    with tarfile.open(src, "r:gz") as old, tarfile.open(fileobj=out, mode="w:gz") as new:
        for m in old:
            new.addfile(m, old.extractfile(m) if m.isreg() else None)
        info = tarfile.TarInfo(name)
        info.size = len(data) if member_type is None else 0
        info.mode = 0o644
        if member_type is not None:
            info.type = member_type
            info.linkname = linkname
        new.addfile(info, io.BytesIO(data) if member_type is None else None)
    Path(dst).write_bytes(out.getvalue())


@pytest.mark.parametrize("name", ["../evil", "/etc/evil", "a/../../evil", "C:/evil", "a\\b", "server/./x", "con.txt", "x:y"])
def test_path_traversal_and_unsafe_names_in_a_signed_tarball_are_refused(w, name):
    tar, _sig = w.release()
    evil = str(w.tmp / "ocw-5.52.0.tar.gz")
    _with_member(tar, evil, name)
    sig = sign_release(evil, w.key, "5.52.0")
    with pytest.raises(bv.Refused) as info:
        w.run(evil, sig)
    assert info.value.code in ("unsafe_path", "file_mismatch"), str(info.value)
    assert not (w.tmp.parent / "evil").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_links_and_special_files_in_a_signed_tarball_are_refused(w, kind):
    tar, _sig = w.release()
    evil = str(w.tmp / "ocw-5.52.0.tar.gz")
    _with_member(tar, evil, "server/link", member_type=kind, linkname="/etc/passwd")
    sig = sign_release(evil, w.key, "5.52.0")
    with pytest.raises(bv.Refused) as info:
        w.run(evil, sig)
    assert info.value.code == "unsafe_member"


def test_an_unlisted_extra_file_in_a_signed_tarball_is_refused(w):
    tar, sig = w.release(unlisted=("CHANGELOG.md",))
    with pytest.raises(bv.Refused) as info:
        w.run(tar, sig)
    assert info.value.code == "file_mismatch" and "not listed" in str(info.value)


def test_a_missing_listed_file_is_refused(w):
    tar, sig = w.release(drop=("CHANGELOG.md",))
    with pytest.raises(bv.Refused) as info:
        w.run(tar, sig)
    assert info.value.code == "file_mismatch" and "missing" in str(info.value)


# --- the command line --------------------------------------------------------------------------------------------------


def _cli(*args):
    return subprocess.run([sys.executable, "-I", "-S", str(REPO / "server" / "updater" / "root" / "ocw_bootstrap_verify.py"), *args],
                          capture_output=True, text=True, timeout=60)


def test_cli_verify_writes_the_release_info_and_the_applied_revocations(w):
    tar, sig = w.release()
    keys = w.tmp / "keys.json"
    keys.write_bytes(w.keys_raw)
    new = TestKey()
    rev = _revoke(w, revoke=[], add=new)
    p = _cli("verify", "--tar", tar, "--sig", sig, "--keys", str(keys), "--bootstrap-version", "5.52.0", "--extract", str(w.tmp / "x"),
             "--info-out", str(w.tmp / "info.json"), "--revocation", rev, "--revocation-out", str(w.tmp / "revs"))
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("ok  release 5.52.0: signature valid") and "serial 1 applied" in p.stdout
    info = json.loads((w.tmp / "info.json").read_text())
    assert info["version"] == "5.52.0" and info["revocation_serial_applied"] == 1 and info["bootstrap_version"] == "5.52.0"
    assert oct((w.tmp / "info.json").stat().st_mode & 0o777) == "0o600"
    assert (w.tmp / "revs" / "revocation-1.json").read_bytes() == Path(rev).read_bytes()


def test_cli_refusal_exits_2_with_the_house_message(w):
    tar, sig = w.release(key=TestKey())
    keys = w.tmp / "keys.json"
    keys.write_bytes(w.keys_raw)
    p = _cli("verify", "--tar", tar, "--sig", sig, "--keys", str(keys), "--bootstrap-version", "5.52.0", "--extract", str(w.tmp / "x"),
             "--info-out", str(w.tmp / "info.json"))
    assert p.returncode == 2 and p.stderr.startswith("ERROR: key_unknown:") and "Nothing was changed." in p.stderr
    assert not (w.tmp / "x").exists() and not (w.tmp / "info.json").exists()


def test_manifest_version_command(w):
    good = w.tmp / "m.json"
    good.write_text(json.dumps({"version": "5.52.0"}))
    p = _cli("manifest-version", str(good))
    assert p.returncode == 0 and p.stdout.strip() == "5.52.0"
    for bad in ('{"version": "5.52"}', '{"version": "5.52.0; rm -rf /"}', "not json", '{"version": 5}', '{"version": "05.1.0"}'):
        good.write_text(bad)
        assert _cli("manifest-version", str(good)).returncode == 2, bad


# --- the downloader --------------------------------------------------------------------------------------------------------


@pytest.fixture
def server():
    s = FakeReleaseServer()
    yield s
    s.close()


def _fetch(server, path, out, allow=("127.0.0.1",), max_bytes=1000):
    return _cli("fetch", server.base + path, str(out), "--max-bytes", str(max_bytes), *sum((["--allow-host", h] for h in allow), []))


def test_fetch_downloads_and_renames_when_complete(server, tmp_path):
    server.respond("/a", body=b"hello")
    out = tmp_path / "a"
    p = _fetch(server, "/a", out)
    assert p.returncode == 0 and out.read_bytes() == b"hello" and not (tmp_path / "a.part").exists()
    assert out.stat().st_mode & 0o777 == 0o600


def test_fetch_not_found_is_20_and_other_failures_21(server, tmp_path):
    assert _fetch(server, "/missing", tmp_path / "m").returncode == 20
    server.respond("/err", status=500, body=b"x")
    assert _fetch(server, "/err", tmp_path / "e").returncode == 21
    assert not (tmp_path / "m").exists() and not (tmp_path / "e").exists()


def test_fetch_refuses_a_truncated_body(server, tmp_path):
    server.respond("/t", body=b"x" * 100, mode="truncate")
    p = _fetch(server, "/t", tmp_path / "t")
    assert p.returncode == 21 and not (tmp_path / "t").exists() and not (tmp_path / "t.part").exists()


def test_fetch_refuses_a_file_over_the_cap(server, tmp_path):
    server.respond("/big", body=b"x" * 5000)
    p = _fetch(server, "/big", tmp_path / "big", max_bytes=1000)
    assert p.returncode == 21 and "larger than" in p.stderr and not (tmp_path / "big").exists()


def test_fetch_refuses_a_redirect_to_a_foreign_host_and_follows_one_to_an_allowed_host(server, tmp_path):
    server.respond("/evil", status=302, headers={"Location": "https://evil.example.com/x"})
    p = _fetch(server, "/evil", tmp_path / "x")
    assert p.returncode == 21 and "not one of the allowed hosts" in p.stderr
    server.respond("/ok", status=302, headers={"Location": server.base + "/final"})
    server.respond("/final", body=b"done")
    assert _fetch(server, "/ok", tmp_path / "ok").returncode == 0 and (tmp_path / "ok").read_bytes() == b"done"
    server.respond("/plain", status=302, headers={"Location": "http://example.com/x"})  # http to a non-loopback host
    assert _fetch(server, "/plain", tmp_path / "p").returncode == 21


def test_fetch_refuses_a_host_that_is_not_allowed_and_plain_http_to_other_hosts(server, tmp_path):
    p = _fetch(server, "/a", tmp_path / "a", allow=("github.com",))
    assert p.returncode == 21 and "not an allowed address" in p.stderr
    p = _cli("fetch", "http://example.com/x", str(tmp_path / "b"), "--max-bytes", "10", "--allow-host", "example.com")
    assert p.returncode == 21


def test_fetch_stops_a_redirect_loop(server, tmp_path):
    server.respond("/loop", status=302, headers={"Location": server.base + "/loop"})
    assert _fetch(server, "/loop", tmp_path / "l").returncode == 21


def test_copy_takes_regular_files_only(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"abc")
    out = tmp_path / "out"
    assert _cli("copy", str(src), str(out), "--max-bytes", "10").returncode == 0 and out.read_bytes() == b"abc"
    link = tmp_path / "link"
    link.symlink_to(src)
    assert _cli("copy", str(link), str(tmp_path / "o2"), "--max-bytes", "10").returncode == 21
    assert _cli("copy", str(src), str(tmp_path / "o3"), "--max-bytes", "2").returncode == 21
    assert _cli("copy", str(tmp_path / "none"), str(tmp_path / "o4"), "--max-bytes", "10").returncode == 20
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert _cli("copy", str(fifo), str(tmp_path / "o5"), "--max-bytes", "10").returncode == 21
