"""The verifier inside get-ocw.sh (the one-line installer), standard library only.

This file is embedded, byte for byte, in every release's get-ocw.sh together with ocw_crypto.py, ocw_trust.py and the
release's server/release_keys.json (tools/release.py renders the script; a test compares the copies). It runs as root on a
server that has nothing installed yet, so it needs no `cryptography`, no `minisign` and no virtualenv: the signature rules
are ocw_trust's (the same code root's updater uses), the algorithms are ocw_crypto's.

    python3 -I -S ocw_bootstrap_verify.py fetch URL OUT --max-bytes N --allow-host HOST [--allow-host HOST ...]
    python3 -I -S ocw_bootstrap_verify.py copy SRC OUT --max-bytes N
    python3 -I -S ocw_bootstrap_verify.py manifest-version FILE
    python3 -I -S ocw_bootstrap_verify.py verify --tar F --sig F --keys F --bootstrap-version X.Y.Z --extract DIR
            --info-out FILE [--expect-version X.Y.Z] [--allow-older] [--revocation FILE ...] [--revocation-out DIR]

`verify` checks, in this order and before the tarball is opened: every revocation file offered (standby signature, serial
order; one that does not verify is reported and ignored, never fatal), then the release signature, trusted comment, file
name, version and sha256 against the keys the script was built with (ocw_trust.verify_release), then the manifest, the
SCRIPT_VERSION inside, the key list the release carries, and the downgrade rule (a release older than this installer is
refused without --allow-older). Only then is the tarball unpacked, by safe_extract below: regular files and directories
only, every file hashed while it is written and compared with the signed manifest, and the tarball is hashed once more
afterwards so a file swapped during the run cannot be what was unpacked.

Exit status: 0 ok; 2 refused (nothing was changed); 3 failed (network, disk); `fetch` also exits 20 for "not found" and 21
for any other fetch failure, so the caller can tell a missing optional file from an unreachable server.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl  # noqa: F401  (urllib needs it for https; imported here so a Python without it fails with a clear message)
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))

MAX_TARBALL_BYTES = 300 * 1024 * 1024
MAX_SIG_BYTES = 16 * 1024
MAX_JSON_BYTES = 64 * 1024
MAX_MEMBER_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 20000
MANIFEST_NAME = "manifest.json"
MAX_REDIRECTS = 3
FETCH_TIMEOUT_SECONDS = 30
FETCH_DEADLINE_SECONDS = 1800
USER_AGENT = "ocw-bootstrap"
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class ExtractError(Exception):
    """`code` is a stable reason: unsafe_path, unsafe_member, bad_archive, file_mismatch."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Refused(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# --- safe extraction (the one copy; server/updater/verify.py imports it) ----------------------------------------------

# Names Windows treats specially (devices, alternate data streams, trailing dots/spaces are silently dropped): a
# release that carries one would unpack differently there. Refused everywhere so the check is the same on every OS.
_WINDOWS_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_WINDOWS_DEVICE = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.IGNORECASE)


def _safe_relpath(name):
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    clean = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in clean):
        return None
    if any(_WINDOWS_UNSAFE_CHARS.search(p) or p.endswith((".", " ")) or _WINDOWS_DEVICE.match(p) for p in clean):
        return None
    return "/".join(clean)


class _HashingReader:
    def __init__(self, src, digest):
        self._src, self._digest = src, digest

    def read(self, n=-1):
        data = self._src.read(n)
        self._digest.update(data)
        return data


def safe_extract(tar_path, dest, manifest):
    """Unpack `tar_path` into the (empty or new) directory `dest`. Only
    regular files and directories; each file is hashed while it is written and
    must equal the manifest; files the manifest lacks, or that are missing,
    refuse the release. Nothing is made executable except what the tar marks
    executable by its owner."""
    expected = dict(manifest["files"])
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = count = 0
    seen = set()
    seen_folded = set()
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar:
                count += 1
                if count > MAX_MEMBERS:
                    raise ExtractError("bad_archive", "the release has too many files")
                rel = _safe_relpath(member.name)
                if rel is None:
                    raise ExtractError("unsafe_path", f"the release contains an unsafe path ({member.name!r}); do not install it")
                if member.isdir():
                    (root / rel).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isreg():
                    raise ExtractError("unsafe_member", f"the release contains a link or special file ({rel}); do not install it")
                if rel in seen or rel.lower() in seen_folded:
                    raise ExtractError("bad_archive", f"{rel} appears twice in the release (or differs from another file only by "
                                       "upper/lower case, which Windows and macOS cannot hold apart)")
                seen.add(rel)
                seen_folded.add(rel.lower())
                total += member.size
                if member.size > MAX_MEMBER_BYTES or total > MAX_UNPACKED_BYTES:
                    raise ExtractError("bad_archive", "the release unpacks to an unreasonable size")
                target = (root / rel)
                if root not in target.resolve().parents:
                    raise ExtractError("unsafe_path", f"{rel} would be written outside the target directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with tar.extractfile(member) as src, open(target, "wb") as out:
                    shutil.copyfileobj(_HashingReader(src, digest), out, 1 << 20)
                os.chmod(target, 0o755 if member.mode & 0o100 else 0o644)
                if rel == MANIFEST_NAME:
                    continue
                if expected.get(rel) != digest.hexdigest():
                    raise ExtractError("file_mismatch", f"{rel} does not match the signed manifest "
                                       f"({'not listed' if rel not in expected else 'different content'}); do not install it")
    except (tarfile.TarError, OSError, EOFError) as exc:
        if isinstance(exc, ExtractError):
            raise
        raise ExtractError("bad_archive", f"the release file cannot be unpacked ({exc})")
    missing = sorted(set(expected) - seen)
    if missing:
        raise ExtractError("file_mismatch", f"the release is missing {len(missing)} file(s) the manifest lists "
                           f"(first: {missing[0]})")
    return count


# --- ocw_trust / ocw_crypto sit next to this file (flat modules, like the rest of the root-owned updater) --------------


def _trust():
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    import ocw_trust
    return ocw_trust


# --- download ---------------------------------------------------------------------------------------------------------


class FetchError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status  # "not_found" | "failed"


def url_allowed(url, allowed_hosts):
    parts = urllib.parse.urlparse(url)
    host = (parts.hostname or "").lower()
    if host not in allowed_hosts:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and host in _LOOPBACK)


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, allowed_hosts):
        self._allowed = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl, self._allowed):
            raise FetchError("failed", f"the server redirected to {urllib.parse.urlparse(newurl).hostname or 'an unusable address'}, "
                             "which is not one of the allowed hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, out_path, allowed_hosts, max_bytes):
    """Download `url` to `out_path` (written as out_path.part, renamed when complete, mode 0600). https only (http only to a
    loopback host, for tests); redirects only to allowed hosts; at most `max_bytes`; a body shorter than the announced
    Content-Length is a failure. Raises FetchError."""
    allowed = frozenset(h.lower() for h in allowed_hosts)
    if not url_allowed(url, allowed):
        raise FetchError("failed", f"{url} is not an allowed address (https, on {', '.join(sorted(allowed)) or 'no host'})")
    opener = urllib.request.build_opener(_CheckedRedirects(allowed))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    part = out_path + ".part"
    try:
        os.unlink(part)
    except FileNotFoundError:
        pass
    started = time.monotonic()
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as resp:
            announced = resp.headers.get("Content-Length")
            if announced is not None and (not announced.isdigit() or int(announced) > max_bytes):
                raise FetchError("failed", f"{url} is larger than the {max_bytes} bytes this step accepts")
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            got = 0
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = resp.read(1 << 16)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > max_bytes:
                        raise FetchError("failed", f"{url} is larger than the {max_bytes} bytes this step accepts")
                    if time.monotonic() - started > FETCH_DEADLINE_SECONDS:
                        raise FetchError("failed", f"{url} took too long to download")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            if announced is not None and got != int(announced):
                raise FetchError("failed", f"the download from {url} was cut short ({got} of {announced} bytes)")
        os.replace(part, out_path)
    except FetchError:
        _drop(part)
        raise
    except urllib.error.HTTPError as exc:
        _drop(part)
        if exc.code == 404:
            raise FetchError("not_found", f"{url} does not exist (404)")
        raise FetchError("failed", f"{url} answered HTTP {exc.code}")
    except (urllib.error.URLError, OSError, ValueError, ssl.SSLError, EOFError) as exc:
        _drop(part)
        reason = getattr(exc, "reason", None) or getattr(exc, "strerror", None) or exc
        raise FetchError("failed", f"could not download {url}: {reason}")
    except Exception as exc:  # http.client errors (IncompleteRead, RemoteDisconnected, ...)
        _drop(part)
        raise FetchError("failed", f"could not download {url}: {exc.__class__.__name__}")


def _drop(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def copy_in(src, out_path, max_bytes):
    """Copy an operator-supplied file (--from-dir) into the root-only work directory: a regular file (never a link, device
    or FIFO), not larger than max_bytes, written 0600 exactly once."""
    try:
        fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise FetchError("not_found" if exc.errno == 2 else "failed", f"cannot read {src}: {exc.strerror or exc}")
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise FetchError("failed", f"{src} is not a regular file")
        if os.fstat(fh.fileno()).st_size > max_bytes:
            raise FetchError("failed", f"{src} is larger than the {max_bytes} bytes this step accepts")
        part = out_path + ".part"
        _drop(part)
        wfd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        got = 0
        with os.fdopen(wfd, "wb") as out:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > max_bytes:
                    _drop(part)
                    raise FetchError("failed", f"{src} is larger than the {max_bytes} bytes this step accepts")
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
    os.replace(part, out_path)


# --- verification -----------------------------------------------------------------------------------------------------

_HINT_REDOWNLOAD = ("Download again; if it repeats, the download is being altered in transit: stop and contact the project.")
_HINTS = {
    "key_unknown": "This installer does not know the key that signed the release. Download the current get-ocw.sh and run it "
                   "again (a release signed after a key rotation needs the installer that came with it).",
    "revoked_key": "The key that signed this release has been revoked. Stop and read the project's security advisory.",
    "retired_key": "The key that signed this release is retired. Download the current get-ocw.sh and install the current release.",
    "wrong_role": "The release was signed with a key that may not sign releases. Stop and contact the project.",
    "no_key_pinned": "Download the current get-ocw.sh.",
    "keys_changed": "The release carries a signing-key list this installer does not accept. Download the current get-ocw.sh; if "
                    "it repeats, stop and contact the project.",
    "downgrade": "Add --allow-older to install it anyway.",
    "version_mismatch": _HINT_REDOWNLOAD,
}


def hint_for(code):
    return _HINTS.get(code, _HINT_REDOWNLOAD)


def _read_small(path, cap):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError(f"{path} is not a regular file")
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise OSError(f"{path} is larger than {cap} bytes")
    return data


def apply_revocations(trust, paths):
    """(trust, applied, notes): the standby-signed revocation files, applied in serial order to the embedded list. A file
    that is unreadable, replayed, badly signed or malformed is reported and ignored: a garbage file at a public URL must
    never block an install, and it changes nothing."""
    ot = _trust()
    found, notes, applied = [], [], []
    for path in paths:
        name = os.path.basename(path)
        try:
            raw = _read_small(path, MAX_JSON_BYTES)
        except OSError as exc:
            notes.append(f"revocation file {name} ignored: {getattr(exc, 'strerror', None) or exc}")
            continue
        serial = ot.revocation_serial(raw)
        found.append((serial if isinstance(serial, int) and not isinstance(serial, bool) else -1, name, path, raw))
    for serial, name, path, raw in sorted(found, key=lambda t: (t[0], t[1])):
        try:
            trust, detail = ot.apply_revocation(trust, raw)
        except ot.TrustError as exc:
            notes.append(f"revocation file {name} ignored ({exc.code}: {exc})")
            continue
        applied.append({"serial": detail["to_serial"], "path": path, "raw": raw, "revoked": detail["revoked"],
                        "added": detail["added"], "reason": detail["reason"]})
    return trust, applied, notes


def verify_and_extract(tar, sig, keys_raw, bootstrap_version, extract_dir, expect_version=None, allow_older=False,
                       revocation_paths=()):
    """Everything this installer checks, then the unpack. Returns (info dict, ok lines, notes). Raises Refused."""
    ot = _trust()
    try:
        bootstrap_t = ot.version_tuple(bootstrap_version)
        trust = {"schema": 1, "serial": 0, "keys": ot.parse_key_list(keys_raw), "revoked": []}
    except ot.TrustError as exc:
        raise Refused(exc.code, f"this installer's own key list is unusable ({exc})")
    trust, applied, notes = apply_revocations(trust, revocation_paths)
    try:
        checked = ot.verify_release(tar, sig, trust, None, None, expect_version)
    except ot.TrustError as exc:
        raise Refused(exc.code, str(exc))
    except OSError as exc:
        raise Refused("bad_artifact", f"cannot read the downloaded files: {exc.strerror or exc}")
    version = checked["version"]
    if ot.version_tuple(version) < bootstrap_t and not allow_older:
        raise Refused("downgrade", f"{version} is older than this installer ({bootstrap_version}). Older releases may have known "
                      "problems; see the CHANGELOG")
    old_umask = os.umask(0o022)  # directories 0755 so the application account can read the installed tree
    try:
        count = safe_extract(tar, extract_dir, checked["manifest"])
    except ExtractError as exc:
        raise Refused(exc.code, str(exc))
    finally:
        os.umask(old_umask)
    # the tarball must still be the bytes that were signed, and the manifest on disk the one that was verified
    try:
        _b2, sha_after, _size = ot.hash_file(tar)
        with open(os.path.join(extract_dir, MANIFEST_NAME), "rb") as fh:
            on_disk = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError, ot.TrustError) as exc:
        raise Refused("bad_archive", f"the unpacked release cannot be re-checked ({exc})")
    if sha_after != checked["sha256"] or on_disk != checked["manifest"]:
        raise Refused("hash_mismatch", "the downloaded file changed while it was being checked")
    serial_applied = max([a["serial"] for a in applied], default=0)
    info = {"version": version, "sha256": checked["sha256"], "key_id": checked["key_id"], "signed_at": checked["timestamp"],
            "revocation_serial_applied": serial_applied, "bootstrap_version": bootstrap_version,
            "files": count}
    if applied:
        rev_text = "key revocation serial " + ", ".join(str(a["serial"]) for a in applied) + " applied"
    else:
        rev_text = "no key revocation published" if not revocation_paths else "no valid key revocation applied"
    signed = f", signed {checked['timestamp']}" if checked["timestamp"] else ""
    ok = [f"release {version}: signature valid (key {checked['key_id']}{signed}); sha256 {checked['sha256']}; "
          f"{len(checked['manifest']['files'])} files match the signed manifest; {rev_text}"]
    return info, ok, notes, applied


# --- command line -----------------------------------------------------------------------------------------------------


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def cmd_fetch(a):
    try:
        fetch(a.url, a.out, a.allow_host or [], a.max_bytes)
    except FetchError as exc:
        print(str(exc), file=sys.stderr)
        return 20 if exc.status == "not_found" else 21
    return 0


def cmd_copy(a):
    try:
        copy_in(a.src, a.out, a.max_bytes)
    except FetchError as exc:
        print(str(exc), file=sys.stderr)
        return 20 if exc.status == "not_found" else 21
    return 0


def cmd_manifest_version(a):
    try:
        manifest = json.loads(_read_small(a.file, 4 * 1024 * 1024).decode("utf-8"))
        version = manifest["version"]
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError):
        print("manifest.json could not be read", file=sys.stderr)
        return 2
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        print("manifest.json does not name a version like 5.52.0", file=sys.stderr)
        return 2
    print(version)
    return 0


def cmd_verify(a):
    try:
        keys_raw = _read_small(a.keys, MAX_JSON_BYTES)
    except OSError as exc:
        print(f"ERROR: bad_key_list: cannot read the key list: {exc}. Nothing was changed.", file=sys.stderr)
        return 3
    try:
        info, ok_lines, notes, applied = verify_and_extract(a.tar, a.sig, keys_raw, a.bootstrap_version, a.extract,
                                                            a.expect_version, a.allow_older, a.revocation or [])
    except Refused as exc:
        print(f"ERROR: {exc.code}: {exc}. Nothing was changed. {hint_for(exc.code)}", file=sys.stderr)
        return 2
    for note in notes:
        print(f"note: {note}")
    for line in ok_lines:
        print(f"ok  {line}")
    try:
        _write_private(a.info_out, (json.dumps(info, sort_keys=True) + "\n").encode())
        if a.revocation_out:
            os.makedirs(a.revocation_out, mode=0o700, exist_ok=True)
            for item in applied:
                _write_private(os.path.join(a.revocation_out, f"revocation-{item['serial']:010d}.json"), item["raw"])
    except OSError as exc:
        print(f"ERROR: could not write the verification result: {exc.strerror or exc}. Nothing was installed.", file=sys.stderr)
        return 3
    return 0


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("fetch")
    s.add_argument("url")
    s.add_argument("out")
    s.add_argument("--max-bytes", type=int, required=True)
    s.add_argument("--allow-host", action="append")
    s.set_defaults(fn=cmd_fetch)
    s = sub.add_parser("copy")
    s.add_argument("src")
    s.add_argument("out")
    s.add_argument("--max-bytes", type=int, required=True)
    s.set_defaults(fn=cmd_copy)
    s = sub.add_parser("manifest-version")
    s.add_argument("file")
    s.set_defaults(fn=cmd_manifest_version)
    s = sub.add_parser("verify")
    s.add_argument("--tar", required=True)
    s.add_argument("--sig", required=True)
    s.add_argument("--keys", required=True)
    s.add_argument("--bootstrap-version", required=True)
    s.add_argument("--extract", required=True)
    s.add_argument("--info-out", required=True)
    s.add_argument("--expect-version")
    s.add_argument("--allow-older", action="store_true")
    s.add_argument("--revocation", action="append")
    s.add_argument("--revocation-out")
    s.set_defaults(fn=cmd_verify)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except OSError as exc:
        print(f"ERROR: {exc.strerror or exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
