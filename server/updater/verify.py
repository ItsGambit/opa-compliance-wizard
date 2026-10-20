"""Verify (and safely unpack) a signed release: ocw-<version>.tar.gz + .minisig.

    python -m server.updater.verify <tarball> <minisig> [--keys FILE]
            [--installed-version X.Y.Z|none] [--allow-same-version]
            [--extract DIR]

Anyone can run this by hand on a download; server/deploy.sh --release runs it
with the pinned keys of the INSTALLED copy (the root of trust is what is
already on the server, never the file being checked).

What must all hold (any failure refuses the file, with the reason):
  1. the signature is a prehashed ("ED") minisign signature -- legacy "Ed"
     is refused -- made by a pinned PRIMARY key that is not revoked (a
     revoked key is accepted only for a release that predates its
     revocation; a standby key never signs releases; see keys.py);
  2. the trusted comment's signature verifies, and it reads
     `file=ocw-<ver>.tar.gz version=<ver> sha256=<hex> [timestamp=<UTC>]`;
  3. file name, version and sha256 match the tarball, the manifest.json
     inside it and the SCRIPT_VERSION of the code inside it;
  4. the version is strictly newer than the installed one (no downgrade; a
     same-version reinstall only with --allow-same-version) and the
     installed one is at least the manifest's min_upgrade_from;
  5. the signing-key list the release carries is the one this install
     trusts, or a permitted rotation of it (keys.check_adoption);
  6. when unpacking, every file matches the manifest's sha256, nothing is
     missing or extra, and no path escapes the target directory.
Output is one line per fact and, on failure, `ERROR: <what to do>` -- never a
stack trace. Exit status 0 only when everything held.
"""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
from collections import namedtuple
from pathlib import Path

from . import keys as keylib
from . import minisign

MAX_TARBALL_BYTES = 300 * 1024 * 1024
MAX_MEMBER_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 20000
MANIFEST_NAME = "manifest.json"
KEYS_MEMBER = "server/release_keys.json"
ENGINE_MEMBER = "create_secret_folders.py"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_FILE_RE = re.compile(r"^ocw-(\d+\.\d+\.\d+)\.tar\.gz$")
_SCRIPT_VERSION_RE = re.compile(r'^SCRIPT_VERSION = "([^"]+)"', re.MULTILINE)

Release = namedtuple("Release", "version sha256 key_id timestamp manifest key_list_action candidate_keys")


class VerifyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _wrap(exc):
    code = getattr(exc, "code", "failed")
    return VerifyError(code, str(exc))


def installed_version_from_tree(root=None):
    """SCRIPT_VERSION of the install this module lives in, or None."""
    path = Path(root or keylib.REPO_ROOT) / ENGINE_MEMBER
    try:
        match = _SCRIPT_VERSION_RE.search(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    return match.group(1) if match else None


def _read_member(tar, name, cap):
    try:
        member = tar.getmember(name)
    except KeyError:
        raise VerifyError("missing_member", f"the release does not contain {name}; it is not a valid release file")
    if not member.isreg() or member.size > cap:
        raise VerifyError("bad_member", f"{name} in the release is not a regular file of a sane size")
    fh = tar.extractfile(member)
    return fh.read(cap + 1)


def verify_release(tar_path, sig_path, key_list, installed_version=None, allow_same_version=False):
    """Returns a Release or raises VerifyError. Does not unpack."""
    try:
        sig_text = Path(sig_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerifyError("unreadable", f"cannot read the signature file {sig_path}: {getattr(exc, 'strerror', None) or exc}")
    try:
        prehash, sha256, _size = minisign.hash_file(tar_path, MAX_TARBALL_BYTES)
    except OSError as exc:
        raise VerifyError("unreadable", f"cannot read {tar_path}: {exc.strerror or exc}")
    except minisign.SignatureError as exc:
        raise _wrap(exc)
    try:
        sig = minisign.parse_signature(sig_text)
        fields = minisign.parse_trusted_comment(sig.trusted_comment, optional=("timestamp",))
        version = fields["version"]
        keylib.parse_version(version)
        pub = keylib.pick_signer(key_list, sig.key_id, "release", fields.get("timestamp"), version)
        minisign.verify(prehash, sig, pub)
    except (minisign.SignatureError, keylib.KeyListError) as exc:
        raise _wrap(exc)
    base = os.path.basename(str(tar_path))
    name_match = _FILE_RE.match(fields["file"])
    if fields["file"] != base or not name_match or name_match.group(1) != version:
        raise VerifyError("name_mismatch", f"the signature is for '{fields['file']}' (version {version}), not for "
                          f"'{base}'. Download the matching file; do not rename release files.")
    if fields["sha256"] != sha256:
        raise VerifyError("hash_mismatch", "the file's sha256 differs from the signed one: the download is damaged "
                          "or has been altered. Download it again.")
    if "timestamp" in fields:
        try:
            keylib.parse_timestamp(fields["timestamp"])
        except keylib.KeyListError as exc:
            raise _wrap(exc)
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            manifest_raw = _read_member(tar, MANIFEST_NAME, 4 * 1024 * 1024)
            keys_raw = _read_member(tar, KEYS_MEMBER, keylib.MAX_JSON_BYTES)
            engine_raw = _read_member(tar, ENGINE_MEMBER, 8 * 1024 * 1024)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise VerifyError("bad_archive", f"the release file cannot be read as a .tar.gz ({exc}). Download it again.")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise VerifyError("bad_manifest", "manifest.json in the release is not valid JSON")
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise VerifyError("bad_manifest", "manifest.json in the release has an unsupported layout")
    if manifest.get("version") != version:
        raise VerifyError("version_mismatch", f"signed version {version} but the manifest says {manifest.get('version')!r}")
    match = _SCRIPT_VERSION_RE.search(engine_raw.decode("utf-8", "replace"))
    if not match or match.group(1) != version:
        raise VerifyError("version_mismatch", f"signed version {version} but the code inside says "
                          f"{match.group(1) if match else 'no version'}")
    if "timestamp" in fields and manifest.get("built_at") not in (None, fields["timestamp"]):
        raise VerifyError("version_mismatch", "manifest build time differs from the signed timestamp")
    for path, digest in manifest["files"].items():
        if not isinstance(path, str) or not isinstance(digest, str) or not _SHA_RE.match(digest):
            raise VerifyError("bad_manifest", "manifest.json lists a file with an invalid hash")
    if installed_version:
        try:
            new_t, old_t = keylib.parse_version(version), keylib.parse_version(installed_version)
        except keylib.KeyListError as exc:
            raise _wrap(exc)
        if new_t < old_t or (new_t == old_t and not allow_same_version):
            raise VerifyError("not_newer", f"version {version} is not newer than the installed {installed_version}. "
                              "Downgrades are refused" + ("" if new_t < old_t else "; to reinstall the same version "
                                                          "deliberately, pass --allow-same-version (deploy.sh: --reinstall)") + ".")
        min_from = manifest.get("min_upgrade_from")
        if min_from:
            try:
                too_old = old_t < keylib.parse_version(min_from)
            except keylib.KeyListError as exc:
                raise _wrap(exc)
            if too_old:
                raise VerifyError("too_old", f"this release can only be installed over {min_from} or newer (installed: "
                                  f"{installed_version}). Upgrade to {min_from} first (see CHANGELOG).")
    try:
        candidate = keylib.parse_key_list_bytes(keys_raw, "the release's signing-key list")
        action = keylib.check_adoption(key_list, candidate)
    except keylib.KeyListError as exc:
        raise _wrap(exc)
    return Release(version, sha256, sig.key_id, fields.get("timestamp"), manifest, action, candidate)


def _safe_relpath(name):
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    clean = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in clean):
        return None
    return "/".join(clean)


def safe_extract(tar_path, dest, manifest):
    """Unpack `tar_path` into the (empty or new) directory `dest`. Only
    regular files and directories; each file is hashed while it is written and
    must equal the manifest; files the manifest lacks, or that are missing,
    refuse the release. Nothing is made executable except what the tar marks
    executable by its owner."""
    import hashlib
    expected = dict(manifest["files"])
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = count = 0
    seen = set()
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar:
                count += 1
                if count > MAX_MEMBERS:
                    raise VerifyError("bad_archive", "the release has too many files")
                rel = _safe_relpath(member.name)
                if rel is None:
                    raise VerifyError("unsafe_path", f"the release contains an unsafe path ({member.name!r}); do not install it")
                if member.isdir():
                    (root / rel).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isreg():
                    raise VerifyError("unsafe_member", f"the release contains a link or special file ({rel}); do not install it")
                if rel in seen:
                    raise VerifyError("bad_archive", f"{rel} appears twice in the release")
                seen.add(rel)
                total += member.size
                if member.size > MAX_MEMBER_BYTES or total > MAX_UNPACKED_BYTES:
                    raise VerifyError("bad_archive", "the release unpacks to an unreasonable size")
                target = (root / rel)
                if root not in target.resolve().parents:
                    raise VerifyError("unsafe_path", f"{rel} would be written outside the target directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with tar.extractfile(member) as src, open(target, "wb") as out:
                    shutil.copyfileobj(_HashingReader(src, digest), out, 1 << 20)
                os.chmod(target, 0o755 if member.mode & 0o100 else 0o644)
                if rel == MANIFEST_NAME:
                    continue
                if expected.get(rel) != digest.hexdigest():
                    raise VerifyError("file_mismatch", f"{rel} does not match the signed manifest "
                                      f"({'not listed' if rel not in expected else 'different content'}); do not install it")
    except (tarfile.TarError, OSError, EOFError) as exc:
        if isinstance(exc, VerifyError):
            raise
        raise VerifyError("bad_archive", f"the release file cannot be unpacked ({exc})")
    missing = sorted(set(expected) - seen)
    if missing:
        raise VerifyError("file_mismatch", f"the release is missing {len(missing)} file(s) the manifest lists "
                          f"(first: {missing[0]})")
    return count


class _HashingReader:
    def __init__(self, src, digest):
        self._src, self._digest = src, digest

    def read(self, n=-1):
        data = self._src.read(n)
        self._digest.update(data)
        return data


def _default_key_list(keys_path):
    if keys_path:
        return keylib.effective_from(keylib.load_key_list(keys_path))
    return keylib.effective_key_list()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m server.updater.verify", description=__doc__.split("\n\n")[0])
    parser.add_argument("tarball", nargs="?")
    parser.add_argument("minisig", nargs="?")
    parser.add_argument("--keys", help="a release_keys.json to trust instead of this install's own")
    parser.add_argument("--installed-version", default=None,
                        help="X.Y.Z, or 'none' to skip the downgrade check (default: this install's version)")
    parser.add_argument("--allow-same-version", action="store_true")
    parser.add_argument("--audit", action="store_true",
                        help="record a refusal (and any key-list change) in the app's audit log (deploy.sh sets this)")
    parser.add_argument("--extract", metavar="DIR", help="after verifying, unpack into DIR (new or empty)")
    parser.add_argument("--apply-revocation", metavar="FILE",
                        help="apply a standby-signed revocation.json instead (works offline), then exit")
    args = parser.parse_args(argv)
    if args.apply_revocation:
        return keylib.main(["apply-revocation", args.apply_revocation])
    if not args.tarball or not args.minisig:
        parser.error("give <tarball> <minisig>, or --apply-revocation FILE")
    try:
        key_list = _default_key_list(args.keys)
        installed = args.installed_version
        if installed is None:
            installed = installed_version_from_tree()
            if installed is None:
                print("note: no installed version found; the downgrade check was skipped")
        elif installed.lower() == "none":
            installed = None
        info = verify_release(args.tarball, args.minisig, key_list, installed, args.allow_same_version)
        print(f"OK  signature valid: key {info.key_id}" + (f", signed {info.timestamp}" if info.timestamp else ""))
        print(f"OK  version {info.version}, sha256 {info.sha256}")
        if installed:
            print(f"OK  newer than installed {installed}")
        if info.key_list_action == "adopt":
            print("NOTE  this release updates the pinned signing keys (adds or retires release keys); permitted by the rules")
        if args.extract:
            n = safe_extract(args.tarball, args.extract, info.manifest)
            print(f"OK  {n} entries unpacked into {args.extract}; every file matches the signed manifest")
            if not args.keys:
                # Remember everything this install knows (keys, statuses, revocations) in its own state file, so the
                # key list this release is about to put on disk can never make it forget one.
                merged = keylib.merged_with(key_list, info.candidate_keys)
                keylib.persist_effective(merged)
                if info.key_list_action == "adopt" and args.audit:
                    keylib.record_change("release_keys.updated", {
                        "version": info.version, "signed_by": info.key_id,
                        "keys_before": len(key_list["keys"]), "keys_after": len(merged["keys"])})
        return 0
    except (VerifyError, keylib.KeyListError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if args.audit:
            keylib.record_change("upgrade.verify_failed", {
                "reason": getattr(exc, "code", "failed"), "file": os.path.basename(args.tarball),
                "message": str(exc)[:300]})
        return 1


if __name__ == "__main__":
    sys.exit(main())
