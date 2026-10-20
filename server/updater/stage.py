"""Stage a signed release (runs as the unprivileged `ocw-updater` account).

    python -m server.updater.stage <X.Y.Z>

Started by systemd as `ocw-stage@<X.Y.Z>.service` (never by the web process,
never by root's own code path directly). It:

  1. takes ocw-<version>.tar.gz and .minisig from upgrade/artifacts/, or, if
     they are not there, downloads them from the project's GitHub release (or
     the mirror in OPA_RELEASE_BASE_URL; same host rules as the update check);
  2. verifies the signature against root's trust list (updater/trust.json,
     the same list root will use) with this install's own verifier, and that
     the version is newer than the installed one;
  3. unpacks into staging/<version>/ with the safe extractor (only regular
     files, every file matched to the signed manifest);
  4. builds the virtual environment there with
     `pip install --require-hashes -r requirements.lock`;
  5. writes staging/<version>/.staged LAST: a release directory without it is
     incomplete and is deleted and redone on the next attempt.

This account is NOT trusted and cannot write releases/ (root-owned): root moves
staging/<version> to releases/<version> first, then makes the tree root-owned
and re-verifies the signature and every file before switching (ocw_activate.py).
On failure it writes upgrade/artifacts/<version>.stage-error.json with a
stable reason code for root to audit, and removes what it built.

Fault injection (only with OCW_TEST_MODE=1): OCW_UPDATER_FAULT=after_unpack,
disk_full.
"""

import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import check
from . import keys as keylib
from . import verify as verifylib

CODES = {"signature_invalid", "key_unknown", "version_not_newer", "hash_mismatch", "name_mismatch", "version_mismatch", "too_old",
         "disk_space", "pip_failed", "stage_failed", "bad_release", "bad_artifact", "revoked_key", "retired_key", "wrong_role",
         "no_key_pinned", "keys_changed", "unknown_alg", "no_trust", "download_failed"}
_VERIFY_CODE = {"bad_signature": "signature_invalid", "bad_trusted_comment": "signature_invalid", "malformed": "signature_invalid",
                "legacy_signature": "signature_invalid", "key_mismatch": "signature_invalid", "unknown_key": "key_unknown",
                "not_newer": "version_not_newer", "file_mismatch": "hash_mismatch", "unsafe_path": "bad_release",
                "unsafe_member": "bad_release", "bad_archive": "bad_release", "bad_manifest": "bad_release",
                "missing_member": "bad_release", "bad_member": "bad_release", "unreadable": "bad_artifact",
                "no_key_pinned": "no_key_pinned", "retired_key": "retired_key", "revoked_key": "revoked_key",
                "wrong_role": "wrong_role", "keys_changed": "keys_changed", "unknown_alg": "unknown_alg"}


class StageError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code if code in CODES else "stage_failed"


def _dirs():
    opt = os.environ.get("OCW_OPT_DIR", "/opt/opa-compliance-wizard")
    return Path(opt), Path(os.environ.get("OCW_ARTIFACTS_DIR", "/var/lib/ocw-updater/artifacts")), Path(opt) / "updater" / "trust.json"


def _adopt_handoff(opt, art_dir, version):
    """An operator's file (`ocw-updater stage <file>`) arrives in the root-owned handoff directory; copy it into this
    account's own artifacts directory. The handoff copy wins over anything already there."""
    hand = Path(os.environ.get("OCW_HANDOFF_DIR", str(opt / "handoff")))
    names = (f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig")
    if not all((hand / n).is_file() and not (hand / n).is_symlink() for n in names):
        return False
    art_dir.mkdir(parents=True, exist_ok=True)
    for n in names:
        tmp = art_dir / (n + ".part")
        shutil.copyfile(hand / n, tmp)
        os.replace(tmp, art_dir / n)
    return True


def _relocate_venv(venv, old_root, new_root):
    """The environment is built under staging/<v> but will live under releases/<v>: rewrite the absolute path in the
    text files that carry it (console-script shebangs, activate scripts, pyvenv.cfg). Links and binaries are left alone."""
    old, new = str(old_root).encode(), str(new_root).encode()
    candidates = [venv / "pyvenv.cfg"] + sorted((venv / "bin").glob("*"))
    for p in candidates:
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > 1 << 20:
                continue
            data = p.read_bytes()
            if b"\0" in data[:512] or old not in data:
                continue
            mode = p.stat().st_mode
            p.write_bytes(data.replace(old, new))
            os.chmod(p, mode & 0o7777)
        except OSError:
            continue


def _faults():
    if os.environ.get("OCW_TEST_MODE") != "1":
        return set()
    return {f for f in os.environ.get("OCW_UPDATER_FAULT", "").split(",") if f}


def key_list_from_trust(path):
    """Root's trust list in the shape keys.effective_from produces."""
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = keylib._validate_entries(obj["keys"])
        revoked = {r["key_id"]: {"key_id": r["key_id"], "revoked_at": r["revoked_at"], "last_good_version": r.get("last_good_version"),
                                 **({"known_good": keylib.parse_known_good(r["known_good"])} if r.get("known_good") else {})}
                   for r in obj.get("revoked", [])}
        return {"schema": 1, "serial": int(obj.get("serial", 0)), "keys": entries, "revoked": revoked}
    except (OSError, ValueError, KeyError, keylib.KeyListError) as exc:
        raise StageError("no_trust", f"cannot read root's trust list ({path}): {exc}")


def _download(version, art_dir):
    base = os.environ.get("OPA_RELEASE_BASE_URL") or check.DEFAULT_RELEASE_DOWNLOAD_BASE
    base = base.rstrip("/")
    hosts = check.GITHUB_HOSTS if not os.environ.get("OPA_RELEASE_BASE_URL") else check.hosts_for(base)
    for name in (f"ocw-{version}.tar.gz", f"ocw-{version}.tar.gz.minisig"):
        got = check.fetch(f"{base}/v{version}/{name}", hosts, None, check.USER_AGENT, max_bytes=verifylib.MAX_TARBALL_BYTES,
                          timeout=120, accept="application/octet-stream")
        if got.status != "ok":
            raise StageError("download_failed", f"could not download {name}: {got.detail or got.code}. Check the version exists and this "
                                                "server can reach the release host (proxy: https_proxy), or bring the files and use "
                                                "`ocw-updater stage <file>`.")
        tmp = art_dir / (name + ".part")
        tmp.write_bytes(got.body)
        os.replace(tmp, art_dir / name)


def _fetch_revocations(art_dir, kl_serial=None):
    """Best effort, like the update check: a published revocation (the `revocation` release, and the owner's static URL if
    one is configured) goes into <artifacts>/revocations/. Root re-verifies it itself before the install and applies it
    if it is genuine, so a release signed by a stolen key cannot be installed on a server that has not heard of the
    theft. A mirror, none published, or no network is fine."""
    from . import service  # noqa: PLC0415 - the same source list the update check uses
    try:
        hosts = service._allowed_hosts()
        for name, url in service.revocation_sources(kl_serial):
            got = check.fetch(url, hosts, None, check.USER_AGENT, max_bytes=keylib.MAX_JSON_BYTES, accept="application/octet-stream")
            if got.status == "ok" and got.body:
                d = art_dir / "revocations"
                d.mkdir(exist_ok=True)
                (d / f"rev-{hashlib.sha256(got.body).hexdigest()[:16]}.json").write_bytes(got.body)
    except Exception:  # noqa: BLE001 - never block staging on this
        pass


def stage(version):
    opt, art_dir, trust_path = _dirs()
    faults = _faults()
    staging = opt / "staging"
    target = staging / version
    tar_path = art_dir / f"ocw-{version}.tar.gz"
    sig_path = art_dir / f"ocw-{version}.tar.gz.minisig"
    err_path = art_dir / f"{version}.stage-error.json"
    try:
        err_path.unlink()
    except FileNotFoundError:
        pass
    _adopt_handoff(opt, art_dir, version)
    if not (tar_path.exists() and sig_path.exists()):
        try:
            serial = key_list_from_trust(trust_path)["serial"]
        except StageError:
            serial = None
        _fetch_revocations(art_dir, serial)
        _download(version, art_dir)
    installed = verifylib.installed_version_from_tree(keylib.REPO_ROOT)
    kl = key_list_from_trust(trust_path)
    try:
        info = verifylib.verify_release(str(tar_path), str(sig_path), kl, installed)
    except (verifylib.VerifyError, keylib.KeyListError) as exc:
        for p in (tar_path, sig_path):
            try:
                os.replace(p, str(p) + ".rejected")
            except OSError:
                pass
        raise StageError(_VERIFY_CODE.get(getattr(exc, "code", ""), "signature_invalid"), str(exc))
    if info.version != version:
        raise StageError("version_mismatch", f"asked for {version} but the file is {info.version}")
    marker = target / ".staged"
    if marker.exists():
        return info
    if target.exists():
        shutil.rmtree(target)  # an earlier attempt that never finished
    try:
        if "disk_full" in faults:
            raise OSError(errno.ENOSPC, "No space left on device")
        n = verifylib.safe_extract(str(tar_path), str(target), info.manifest)
        if "after_unpack" in faults:
            raise StageError("stage_failed", "injected fault: stopped after unpacking")
        lock = target / "requirements.lock"
        if not lock.exists():
            raise StageError("pip_failed", "the release has no requirements.lock, so a hash-checked install is impossible")
        base_python = getattr(sys, "_base_executable", None) or sys.executable
        venv = target / ".venv"
        subprocess.run([base_python, "-m", "venv", str(venv)], check=True, capture_output=True, text=True, timeout=600)
        env = dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
        proc = subprocess.run([str(venv / "bin" / "pip"), "install", "-q", "--require-hashes", "--only-binary=:all:", "-r", str(lock)], cwd=str(target),
                              capture_output=True, text=True, timeout=3000, env=env)
        if proc.returncode != 0:
            raise StageError("pip_failed", "pip install --require-hashes failed: " + (proc.stderr or proc.stdout)[-400:])
        freeze = subprocess.run([str(venv / "bin" / "pip"), "freeze", "--all"], capture_output=True, text=True, timeout=120).stdout.splitlines()
        for base, dirs, _files in os.walk(target):
            if os.path.relpath(base, target) == ".":
                dirs[:] = [d for d in dirs if d != ".venv"]
            for d in list(dirs):
                if d == "__pycache__":
                    shutil.rmtree(os.path.join(base, d), ignore_errors=True)
                    dirs.remove(d)
        _relocate_venv(venv, target, opt / "releases" / version)
        record = {"version": version, "sha256": info.sha256, "key_id": info.key_id,
                  "staged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": n, "pip_freeze": freeze,
                  "pip_freeze_sha256": hashlib.sha256("\n".join(freeze).encode()).hexdigest(), "verifier": "ok"}
        tmp = target / ".staged.tmp"
        tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
        os.replace(tmp, marker)
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise StageError("stage_failed", "could not create the virtual environment: " + (exc.stderr or "")[-300:])
    except OSError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise StageError("disk_space" if exc.errno == errno.ENOSPC else "stage_failed", f"{exc.strerror or exc}")
    except verifylib.VerifyError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise StageError(_VERIFY_CODE.get(exc.code, "bad_release"), str(exc))
    except StageError:
        if "after_unpack" not in faults:
            shutil.rmtree(target, ignore_errors=True)
        raise
    return info


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or not __import__("re").match(r"^\d+\.\d+\.\d+$", argv[0]):
        print("usage: python -m server.updater.stage X.Y.Z", file=sys.stderr)
        return 2
    version = argv[0]
    _opt, art_dir, _t = _dirs()
    try:
        stage(version)
    except StageError as exc:
        print(json.dumps({"level": "ERROR", "msg": f"staging {version} failed", "code": exc.code, "detail": str(exc)[:500]}), file=sys.stderr)
        try:
            art_dir.mkdir(parents=True, exist_ok=True)
            (art_dir / f"{version}.stage-error.json").write_text(json.dumps({"code": exc.code, "message": str(exc)[:600]}), encoding="utf-8")
        except OSError:
            pass
        return 1
    print(json.dumps({"level": "INFO", "msg": f"staged {version}"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
