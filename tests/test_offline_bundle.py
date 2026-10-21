"""The offline bundle (5.49.0): tools/release.py build-offline and server/updater/offline.py.

pip never runs and nothing touches the network: the `pip download` runner is replaced by a stub that writes
small fake wheels whose sha256 the test lock file records."""

import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from release_helpers import TestKey, key_list, make_release_tar, sign_release
from server.updater import offline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import release as tool  # noqa: E402

PACKAGES = [("keyring", "25.7.0", None), ("pyjwt", "2.15.1", None), ("cffi", "2.0.0", "python_full_version < '3.10' and platform_python_implementation != 'PyPy'"),
            ("pywin32-ctypes", "0.2.3", "sys_platform == 'win32'"), ("backports-tarfile", "1.2.0", "python_full_version < '3.12'")]


def wheel_bytes(name, version):
    return f"wheel:{name}=={version}".encode()


def make_lock():
    lines = ["# test lock\n"]
    for name, version, marker in PACKAGES:
        sha = hashlib.sha256(wheel_bytes(name, version)).hexdigest()
        other = hashlib.sha256(b"sdist" + name.encode()).hexdigest()
        lines.append(f"{name}=={version}" + (f" ; {marker}" if marker else "") + f" \\\n    --hash=sha256:{other} \\\n    --hash=sha256:{sha}\n")
    return "".join(lines)


@pytest.fixture
def signed(tmp_path):
    key = TestKey()
    kl = key_list([key])
    keys_file = tmp_path / "release_keys.json"
    keys_file.write_text(json.dumps(kl))
    lock = make_lock()
    tar = make_release_tar(tmp_path / "ocw-5.49.0.tar.gz", "5.49.0", kl, extra_files={"requirements.lock": lock})
    sign_release(tar, key, "5.49.0")
    return {"tar": tar, "keys": keys_file, "key": key, "kl": kl, "tmp": tmp_path, "lock": lock}


class StubPip:
    def __init__(self, fail_on=None, extra=None):
        self.calls = []
        self.fail_on = fail_on
        self.extra = extra or {}

    def __call__(self, argv):
        self.calls.append(argv)
        assert argv[0] == "download" and "--no-deps" in argv and "--only-binary=:all:" in argv and "--require-hashes" in argv
        req = Path(argv[argv.index("-r") + 1]).read_text().splitlines()
        dest = Path(argv[argv.index("-d") + 1])
        for line in req:
            name, version = line.split(" ")[0].split("==")
            if self.fail_on == name:
                raise tool.ReleaseError("pip download failed: no matching distribution")
            (dest / f"{name.replace('-', '_')}-{version}-py3-none-any.whl").write_bytes(wheel_bytes(name, version))
        for fname, data in self.extra.items():
            (dest / fname).write_bytes(data)


def build(signed, **kw):
    pip = kw.pop("runner", None) or StubPip()
    out = signed["tmp"] / "out"
    result = tool.build_offline(signed["tar"], out, keys_path=signed["keys"], runner=pip, **kw)
    return result, pip, out


# --- the builder -------------------------------------------------------------------------------------------


def test_build_collects_every_target_and_the_bundle_opens(signed, tmp_path):
    (bundle, info, digest), pip, out = build(signed)
    assert bundle.name == "ocw-5.49.0-offline.tar.gz" and (out / (bundle.name + ".sha256")).read_text() == f"{digest}  {bundle.name}\n"
    assert len(pip.calls) == len(tool.OFFLINE_PYTHONS) * len(tool.OFFLINE_DEFAULT_PLATFORMS)
    assert set(info["wheels"]) == {"keyring-25.7.0-py3-none-any.whl", "pyjwt-2.15.1-py3-none-any.whl", "cffi-2.0.0-py3-none-any.whl",
                                   "pywin32_ctypes-0.2.3-py3-none-any.whl", "backports_tarfile-1.2.0-py3-none-any.whl"}
    opened = offline.open_bundle(bundle, tmp_path / "opened")
    assert opened.version == "5.49.0" and opened.wheel_count == 5
    assert Path(opened.tarball).read_bytes() == signed["tar"].read_bytes()
    assert Path(opened.minisig).read_bytes() == Path(str(signed["tar"]) + ".minisig").read_bytes()
    assert opened.info["requirements_lock_sha256"] == hashlib.sha256(signed["lock"].encode()).hexdigest()
    assert opened.info["python_versions"] == list(tool.OFFLINE_PYTHONS)


def test_intel_mac_is_opt_in_only():
    assert "macos-x86_64" in tool.OFFLINE_PLATFORMS and "macos-x86_64" not in tool.OFFLINE_DEFAULT_PLATFORMS
    assert set(tool.OFFLINE_DEFAULT_PLATFORMS) == set(tool.OFFLINE_PLATFORMS) - {"macos-x86_64"}


def test_markers_decide_which_packages_each_target_needs(signed):
    _result, pip, _out = build(signed)

    # re-evaluate with the same function the builder used
    entries = tool.parse_lock(signed["lock"])
    names = lambda py, plat: {e["name"] for e in tool.entries_for(entries, py, plat)}  # noqa: E731
    assert "pywin32-ctypes" in names("3.12", "windows-amd64") and "pywin32-ctypes" not in names("3.12", "linux-x86_64")
    assert "backports-tarfile" in names("3.11", "linux-x86_64") and "backports-tarfile" not in names("3.12", "linux-x86_64")
    assert "cffi" in names("3.9", "macos-arm64") and "cffi" not in names("3.12", "macos-arm64")
    first = pip.calls[0]
    assert first[first.index("--python-version") + 1] == "3.9.99"  # not "3.9": pip would read that as 3.9.0 and refuse cryptography
    assert "--implementation" in first and first[first.index("--implementation") + 1] == "cp"
    assert [first[i + 1] for i, a in enumerate(first) if a == "--platform"] == tool.OFFLINE_PLATFORMS["linux-x86_64"]["tags"]


def test_python_and_platform_can_be_narrowed(signed):
    (_b, info, _d), pip, _out = build(signed, pythons=("3.12",), platforms=("linux-x86_64",))
    assert len(pip.calls) == 1 and info["python_versions"] == ["3.12"] and info["platforms"] == ["linux-x86_64"]
    assert "backports_tarfile-1.2.0-py3-none-any.whl" not in info["wheels"]   # 3.12 does not need it


def test_the_release_must_be_signed_and_the_signature_must_verify(signed):
    Path(str(signed["tar"]) + ".minisig").unlink()
    with pytest.raises(tool.ReleaseError, match="sign the release first"):
        build(signed)


def test_a_signature_by_an_unpinned_key_is_refused(signed):
    sign_release(signed["tar"], TestKey(), "5.49.0")
    with pytest.raises(Exception, match="(?i)key|signer|pinned"):
        build(signed)


def test_a_lock_that_the_signed_manifest_does_not_list_is_refused(signed, tmp_path):
    tar = make_release_tar(tmp_path / "x" / "ocw-5.49.0.tar.gz", "5.49.0", signed["kl"], extra_files={"requirements.lock": signed["lock"]},
                           unlisted=("requirements.lock",)) if (tmp_path / "x").mkdir() is None else None
    sign_release(tar, signed["key"], "5.49.0")
    with pytest.raises(tool.ReleaseError, match="signed manifest"):
        tool.build_offline(tar, tmp_path / "o", keys_path=signed["keys"], runner=StubPip())


def test_a_wheel_the_signed_lock_does_not_record_is_never_bundled(signed):
    with pytest.raises(tool.ReleaseError, match="not recorded in requirements.lock"):
        build(signed, runner=StubPip(extra={"evil-1.0-py3-none-any.whl": b"payload"}))


def test_a_wheel_swapped_under_a_known_name_is_refused(signed):
    class Swapper(StubPip):
        def __call__(self, argv):
            super().__call__(argv)
            Path(argv[argv.index("-d") + 1], "keyring-25.7.0-py3-none-any.whl").write_bytes(b"tampered")
    with pytest.raises(tool.ReleaseError, match="not recorded"):
        build(signed, runner=Swapper())


def test_a_target_with_no_wheel_fails_the_build(signed):
    with pytest.raises(tool.ReleaseError, match="no matching distribution"):
        build(signed, runner=StubPip(fail_on="cffi"))


def test_a_package_that_was_never_downloaded_fails_the_build(signed):
    class Skipper(StubPip):
        def __call__(self, argv):
            super().__call__(argv)
            for f in Path(argv[argv.index("-d") + 1]).glob("pyjwt*"):
                f.unlink()
    with pytest.raises(tool.ReleaseError, match="no wheel for pyjwt"):
        build(signed, runner=Skipper())


def test_unreadable_or_unpinned_locks_are_refused():
    with pytest.raises(tool.ReleaseError, match="no sha256"):
        tool.parse_lock("keyring==1.0\n")
    with pytest.raises(tool.ReleaseError, match="cannot read"):
        tool.parse_lock("git+https://example.com/x.git --hash=sha256:" + "a" * 64 + "\n")
    with pytest.raises(tool.ReleaseError, match="lists no packages"):
        tool.parse_lock("# nothing\n")


def test_bad_python_or_platform_arguments(signed):
    with pytest.raises(tool.ReleaseError, match="3.12"):
        build(signed, pythons=("three",))
    with pytest.raises(tool.ReleaseError, match="unknown platform"):
        build(signed, platforms=("beos",))


def test_the_real_repo_lock_parses_and_every_target_resolves():
    lock = (Path(__file__).resolve().parent.parent / "requirements.lock").read_text()
    entries = tool.parse_lock(lock)
    assert {"keyring", "pyjwt"} <= {e["name"] for e in entries} and all(e["hashes"] for e in entries)
    for py in tool.OFFLINE_PYTHONS:
        for plat in tool.OFFLINE_PLATFORMS:
            chosen = {e["name"] for e in tool.entries_for(entries, py, plat)}
            assert "keyring" in chosen and "cryptography" in chosen
            assert ("pywin32-ctypes" in chosen) == (plat.startswith("windows"))
            # one version of each package per target: a stale branch of the lock (3.9.0 only) must not add a second one
            listed = [e["name"] for e in tool.entries_for(entries, py, plat)]
            assert len(listed) == len(set(listed)), (py, plat)


# --- the opener (hostile bundles) ---------------------------------------------------------------------------


def bundle_with(path, members, version="5.49.0"):
    """members: {name: bytes | TarInfo-factory}. Default valid parts are added unless overridden with None."""
    release = b"release-bytes"
    wheel = b"w"
    base = {f"ocw-{version}.tar.gz": release, f"ocw-{version}.tar.gz.minisig": b"sig",
            "offline.json": json.dumps({"schema": 1, "version": version, "requirements_lock_sha256": "0" * 64,
                                        "wheels": {"a-1-py3-none-any.whl": hashlib.sha256(wheel).hexdigest()}}).encode(),
            "wheels/a-1-py3-none-any.whl": wheel}
    for k, v in members.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    with tarfile.open(path, "w:gz") as tar:
        for name, data in base.items():
            if isinstance(data, tarfile.TarInfo):
                tar.addfile(data)
                continue
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return path


def test_a_plain_bundle_opens(tmp_path):
    b = offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {}), tmp_path / "d")
    assert b.version == "5.49.0" and b.wheel_count == 1 and (Path(b.wheels_dir) / "a-1-py3-none-any.whl").read_bytes() == b"w"


def link(name, kind, target):
    ti = tarfile.TarInfo(name)
    ti.type, ti.linkname = kind, target
    return ti


@pytest.mark.parametrize("members,code", [
    ({"wheels/b-1-py3-none-any.whl": link("wheels/b-1-py3-none-any.whl", tarfile.SYMTYPE, "/etc/passwd")}, "unsafe_member"),
    ({"wheels/b-1-py3-none-any.whl": link("wheels/b-1-py3-none-any.whl", tarfile.LNKTYPE, "offline.json")}, "unsafe_member"),
    ({"../evil": b"x"}, "unsafe_path"),
    ({"/abs/evil": b"x"}, "unsafe_path"),
    ({"wheels/../../evil.whl": b"x"}, "unsafe_path"),
    ({"wheels/sub/b-1-py3-none-any.whl": b"x"}, "unsafe_path"),
    ({"wheels/b-1.tar.gz": b"x"}, "unsafe_path"),
    ({"README.txt": b"x"}, "unsafe_path"),
    ({"wheels\\b-1-py3-none-any.whl": b"x"}, "unsafe_path"),
    ({"extra/dir/": link("extra/dir/", tarfile.DIRTYPE, "")}, "unsafe_member"),
    ({"offline.json": None}, "bad_bundle"),
    ({"ocw-5.49.0.tar.gz.minisig": None}, "bad_bundle"),
    ({"ocw-5.49.0.tar.gz": None}, "bad_bundle"),
])
def test_hostile_members_are_refused(tmp_path, members, code):
    with pytest.raises(offline.BundleError) as exc:
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", members), tmp_path / "d")
    assert exc.value.code == code
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()


def test_wheels_not_matching_offline_json_are_refused(tmp_path):
    with pytest.raises(offline.BundleError) as exc:
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"wheels/a-1-py3-none-any.whl": b"changed"}), tmp_path / "d")
    assert exc.value.code == "hash_mismatch"
    with pytest.raises(offline.BundleError, match="not the ones offline.json lists"):
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"wheels/extra-1-py3-none-any.whl": b"w"}), tmp_path / "d2")


def test_offline_json_for_another_version_or_layout_is_refused(tmp_path):
    other = json.dumps({"schema": 1, "version": "5.48.0", "requirements_lock_sha256": "0" * 64, "wheels": {}}).encode()
    with pytest.raises(offline.BundleError, match="another version"):
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"offline.json": other, "wheels/a-1-py3-none-any.whl": None}), tmp_path / "d")
    with pytest.raises(offline.BundleError, match="not valid JSON"):
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"offline.json": b"{"}), tmp_path / "d2")


def test_names_and_formats(tmp_path):
    assert offline.is_bundle_name("/x/ocw-5.49.0-offline.tar.gz") and not offline.is_bundle_name("ocw-5.49.0.tar.gz")
    renamed = bundle_with(tmp_path / "release.tar.gz", {})
    with pytest.raises(offline.BundleError, match="do not rename"):
        offline.open_bundle(renamed, tmp_path / "d")
    junk = tmp_path / "ocw-5.49.0-offline.tar.gz"
    junk.write_bytes(b"not a tar")
    with pytest.raises(offline.BundleError, match="cannot be read"):
        offline.open_bundle(junk, tmp_path / "d2")
    with pytest.raises(offline.BundleError, match="cannot read"):
        offline.open_bundle(tmp_path / "ocw-5.50.0-offline.tar.gz", tmp_path / "d3")


def test_a_wheel_over_the_cap_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(offline, "MAX_WHEEL_BYTES", 4)
    with pytest.raises(offline.BundleError, match="larger than allowed"):
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"wheels/a-1-py3-none-any.whl": b"12345"}), tmp_path / "d")


def test_a_size_lying_member_cannot_exceed_the_cap_while_streaming(tmp_path, monkeypatch):
    monkeypatch.setattr(offline, "MAX_RELEASE_BYTES", 8)
    with pytest.raises(offline.BundleError, match="larger than allowed"):
        offline.open_bundle(bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {"ocw-5.49.0.tar.gz": b"x" * 20}), tmp_path / "d")


def test_the_lock_check_and_the_pip_arguments(tmp_path):
    lock = tmp_path / "requirements.lock"
    lock.write_text("x")
    info = {"requirements_lock_sha256": hashlib.sha256(b"x").hexdigest()}
    offline.check_lock_matches(info, lock)
    with pytest.raises(offline.BundleError, match="different requirements.lock"):
        offline.check_lock_matches({"requirements_lock_sha256": "0" * 64}, lock)
    args = offline.pip_install_args(lock, tmp_path / "wheels")
    assert args[:2] == ["install", "-q"] and "--no-index" in args and "--require-hashes" in args and "--only-binary=:all:" in args
    assert args[args.index("--find-links") + 1] == str(tmp_path / "wheels")


def test_cli_unpack(tmp_path, capsys):
    b = bundle_with(tmp_path / "ocw-5.49.0-offline.tar.gz", {})
    assert offline.main(["unpack", str(b), str(tmp_path / "d")]) == 0
    lines = capsys.readouterr().out.split()
    assert lines[0].endswith("ocw-5.49.0.tar.gz") and lines[1].endswith(".minisig") and lines[2].endswith("wheels")
    assert offline.main(["unpack", str(tmp_path / "nope-offline.tar.gz"), str(tmp_path / "d2")]) == 1
    assert offline.main([]) == 2
