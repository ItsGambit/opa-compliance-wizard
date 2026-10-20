"""The offline bundle (5.49.0): a signed release plus the Python packages it needs,
for a computer with no route to the internet.

    ocw-<version>-offline.tar.gz
        ocw-<version>.tar.gz            the normal signed release, unchanged
        ocw-<version>.tar.gz.minisig    its signature, unchanged
        manifest.json                   the release manifest (a copy, for reading)
        offline.json                    what the wheels are: python versions, platforms, sha256 of each
        wheels/<name>.whl               the hash-pinned Python packages (wheels only, no source)

What is trusted, and why. The bundle itself carries no signature and needs none:
the release inside it is verified exactly like a downloaded one (pinned keys,
signed manifest, no downgrade), and its requirements.lock is one of the files
the signed manifest lists. The wheels are installed with
`pip install --no-index --require-hashes --only-binary=:all: -r requirements.lock`, so pip
refuses any wheel whose sha256 is not recorded in that signed lock file. A wheel
that was swapped, damaged or added is therefore refused or never used; the worst
a tampered bundle can do is fail to install. offline.json is cross-checked as a
second line (every listed wheel present with the listed hash, nothing else),
but is not what the safety rests on.

open_bundle() unpacks the OUTER archive only, into a directory the caller
supplies, with the same discipline as the release extractor: a fixed set of
member names, regular files only (no links, no devices, no directories that
escape), name patterns that cannot hold a path separator, size and count caps.
"""

import hashlib
import json
import os
import re
import tarfile
from collections import namedtuple

BUNDLE_RE = re.compile(r"^ocw-(\d+\.\d+\.\d+)-offline\.tar\.gz$")
WHEEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]{0,200}\.whl$")
MAX_BUNDLE_BYTES = 3 * 1024 ** 3
MAX_RELEASE_BYTES = 300 * 1024 * 1024
MAX_WHEEL_BYTES = 120 * 1024 * 1024
MAX_WHEELS = 800
MAX_TOTAL_BYTES = 2 * 1024 ** 3
MAX_INFO_BYTES = 2 * 1024 * 1024
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")

Bundle = namedtuple("Bundle", "version tarball minisig wheels_dir info wheel_count")


class BundleError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def is_bundle_name(path):
    return bool(BUNDLE_RE.match(os.path.basename(str(path))))


def _copy_member(tar, member, dest_path, cap):
    digest = hashlib.sha256()
    written = 0
    src = tar.extractfile(member)
    # "xb": never overwrites, never follows a planted link at the destination
    with src, open(dest_path, "xb") as out:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > cap:
                raise BundleError("bad_bundle", f"{os.path.basename(dest_path)} in the bundle is larger than allowed")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest(), written


def open_bundle(path, dest):
    """Unpack the offline bundle at `path` into the new, empty directory `dest`.
    Returns Bundle(version, tarball, minisig, wheels_dir, info, wheel_count) or
    raises BundleError. Nothing in the bundle is executed or trusted here; the
    caller verifies the release inside it."""
    base = os.path.basename(str(path))
    name_match = BUNDLE_RE.match(base)
    if not name_match:
        raise BundleError("bad_name", f"{base} is not named ocw-<version>-offline.tar.gz; do not rename release files.")
    version = name_match.group(1)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise BundleError("unreadable", f"cannot read {path}: {exc.strerror or exc}")
    if size > MAX_BUNDLE_BYTES:
        raise BundleError("bad_bundle", "the offline bundle is larger than allowed")
    dest = str(dest)
    wheels_dir = os.path.join(dest, "wheels")
    os.makedirs(wheels_dir, exist_ok=True)
    release_name = f"ocw-{version}.tar.gz"
    fixed = {release_name: MAX_RELEASE_BYTES, release_name + ".minisig": 64 * 1024, "manifest.json": 4 * 1024 * 1024,
             "offline.json": MAX_INFO_BYTES}
    seen_fixed, wheels, total, count = {}, {}, 0, 0
    try:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar:
                count += 1
                if count > MAX_WHEELS + 10:
                    raise BundleError("bad_bundle", "the offline bundle holds too many files")
                name = member.name
                if member.isdir():
                    if name.rstrip("/") not in ("wheels", "."):
                        raise BundleError("unsafe_member", f"the bundle contains an unexpected folder ({name!r}); do not use it")
                    continue
                if not member.isreg():
                    raise BundleError("unsafe_member", f"the bundle contains a link or special file ({name!r}); do not use it")
                if name.startswith("./"):
                    name = name[2:]
                if name in fixed:
                    if name in seen_fixed:
                        raise BundleError("bad_bundle", f"{name} appears twice in the bundle")
                    if member.size > fixed[name]:
                        raise BundleError("bad_bundle", f"{name} in the bundle is larger than allowed")
                    target = os.path.join(dest, name)
                    sha, written = _copy_member(tar, member, target, fixed[name])
                    seen_fixed[name] = sha
                    total += written
                elif name.startswith("wheels/") and name.count("/") == 1 and WHEEL_RE.match(name[7:]):
                    wheel = name[7:]
                    if wheel in wheels:
                        raise BundleError("bad_bundle", f"{wheel} appears twice in the bundle")
                    if member.size > MAX_WHEEL_BYTES:
                        raise BundleError("bad_bundle", f"{wheel} in the bundle is larger than allowed")
                    sha, written = _copy_member(tar, member, os.path.join(wheels_dir, wheel), MAX_WHEEL_BYTES)
                    wheels[wheel] = sha
                    total += written
                else:
                    raise BundleError("unsafe_path", f"the bundle contains an unexpected file ({member.name!r}); do not use it")
                if total > MAX_TOTAL_BYTES:
                    raise BundleError("bad_bundle", "the offline bundle unpacks to an unreasonable size")
    except BundleError:
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BundleError("bad_bundle", f"the offline bundle cannot be read as a .tar.gz ({exc}). Download it again.")
    for needed in (release_name, release_name + ".minisig", "offline.json"):
        if needed not in seen_fixed:
            raise BundleError("bad_bundle", f"the offline bundle does not contain {needed}; it is not a valid bundle")
    try:
        with open(os.path.join(dest, "offline.json"), encoding="utf-8") as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        raise BundleError("bad_bundle", "offline.json in the bundle is not valid JSON")
    if not isinstance(info, dict) or info.get("schema") != 1 or info.get("version") != version \
            or not isinstance(info.get("wheels"), dict) or not isinstance(info.get("requirements_lock_sha256"), str):
        raise BundleError("bad_bundle", "offline.json in the bundle has an unsupported layout or is for another version")
    listed = info["wheels"]
    if set(listed) != set(wheels):
        raise BundleError("bad_bundle", "the wheels in the bundle are not the ones offline.json lists")
    for wheel, sha in listed.items():
        if not isinstance(sha, str) or not _SHA_RE.match(sha) or wheels[wheel] != sha:
            raise BundleError("hash_mismatch", f"{wheel} does not match the hash offline.json records: the bundle is damaged "
                                               "or has been altered. Download it again.")
    return Bundle(version, os.path.join(dest, release_name), os.path.join(dest, release_name + ".minisig"), wheels_dir, info, len(wheels))


def check_lock_matches(info, lock_path):
    """The requirements.lock inside the VERIFIED release is the one the wheels were
    collected for. (pip enforces the hashes anyway; this gives a clear message
    for a bundle paired with the wrong release.)"""
    try:
        with open(lock_path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        raise BundleError("bad_bundle", "the release has no requirements.lock")
    if actual != info.get("requirements_lock_sha256"):
        raise BundleError("lock_mismatch", "the packages in this offline bundle were collected for a different requirements.lock than "
                                           "the release inside it; do not use it. Download the bundle again.")


PIP_OFFLINE_ARGS = ("--no-index", "--require-hashes", "--only-binary=:all:")


def pip_install_args(lock_path, wheels_dir):
    """argv tail for `pip install` from the bundle's wheels only, hash-checked."""
    return ["install", "-q", *PIP_OFFLINE_ARGS, "--find-links", str(wheels_dir), "-r", str(lock_path)]


def main(argv=None):
    """python -m server.updater.offline unpack <bundle> <new-empty-dir>
    Used by deploy.sh --from-dir: prints the tarball, signature and wheels paths, one per line."""
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 3 or argv[0] != "unpack":
        print("usage: python -m server.updater.offline unpack <ocw-X.Y.Z-offline.tar.gz> <new-empty-dir>", file=sys.stderr)
        return 2
    try:
        bundle = open_bundle(argv[1], argv[2])
    except BundleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(bundle.tarball)
    print(bundle.minisig)
    print(bundle.wheels_dir)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
