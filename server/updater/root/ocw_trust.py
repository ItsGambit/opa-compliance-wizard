"""What root trusts, and how it checks a release against it (stdlib only).

Part of the root-owned updater. This is a deliberately small re-statement, in
standard-library Python, of the rules the application's own verifier applies
(server/updater/keys.py and verify.py): root cannot import those, because they
live in a tree and a virtualenv that the `ocw-updater` account can write.
tests/test_updater_root.py runs both implementations over the same vectors.

The trust list is `trust.json`, owned by root, in the updater directory:

    {"schema": 1, "serial": <last revocation serial applied>,
     "keys": [{key_id, alg, public_key, role, status, since}, ...],
     "revoked": [{key_id, revoked_at, last_good_version}, ...]}

It is created by `install.sh` from the key list of the installed release, and
afterwards changed only by root: when a release it verified carries a
permitted key-list change (add/retire release keys; never a standby), and when
an operator applies a standby-signed revocation (`ocw-updater trust apply`).
Nothing the web process or the `ocw-updater` account can write is ever read as
a key. (The application keeps its own copy of the list for the update check
and the Updates screen; root does not use it.)
"""

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import tarfile
from datetime import datetime, timezone

import ocw_crypto

SCHEMA = 1
ROLE_ALG = {"release": "ed25519-minisign", "standby": "es256"}
STATUS_RANK = {"active": 0, "retired": 1, "revoked": 2}
REVOCATION_FORMAT = "ocw-revocation/1"
MAX_JSON = 64 * 1024
MAX_TARBALL = 300 * 1024 * 1024
_ID = re.compile(r"^[0-9A-F]{16}$")
_VER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_FILE = re.compile(r"^ocw-(\d+\.\d+\.\d+)\.tar\.gz$")
_SCRIPT_VERSION = re.compile(r'^SCRIPT_VERSION = "([^"]+)"', re.M)


class TrustError(Exception):
    """`code` is a stable reason (also used as the audit reason code)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def version_tuple(text):
    if not isinstance(text, str) or not _VER.match(text):
        raise TrustError("bad_version", f"{text!r} is not a MAJOR.MINOR.PATCH version")
    return tuple(int(p) for p in text.split("."))


def _ts(text):
    if not isinstance(text, str) or not _TS.match(text):
        raise TrustError("bad_timestamp", f"{text!r} is not a UTC time like 2026-01-31T12:00:00Z")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# --- trust list ------------------------------------------------------------------------


def _check_entry(e):
    fields = {"key_id", "alg", "public_key", "role", "status", "since"}
    if not isinstance(e, dict) or set(e) != fields:
        raise TrustError("bad_key_list", "each key needs exactly: key_id, alg, public_key, role, status, since")
    if not isinstance(e["key_id"], str) or not _ID.match(e["key_id"]):
        raise TrustError("bad_key_list", "key_id must be 16 upper-case hex digits")
    if e["role"] not in ROLE_ALG or e["status"] not in STATUS_RANK:
        raise TrustError("bad_key_list", f"key {e['key_id']}: bad role or status")
    version_tuple(e["since"])
    if not isinstance(e["alg"], str) or not isinstance(e["public_key"], str) or len(e["public_key"]) > 2048:
        raise TrustError("bad_key_list", f"key {e['key_id']}: alg and public_key must be text")
    if e["alg"] in ROLE_ALG.values():
        if e["alg"] != ROLE_ALG[e["role"]]:
            raise TrustError("bad_key_list", f"key {e['key_id']}: a {e['role']} key must use {ROLE_ALG[e['role']]}")
        try:
            raw = base64.b64decode(e["public_key"], validate=True)
        except (binascii.Error, ValueError):
            raise TrustError("bad_key_list", f"key {e['key_id']}: public_key is not base64")
        if e["alg"] == "ed25519-minisign" and len(raw) != 32:
            raise TrustError("bad_key_list", f"key {e['key_id']}: an Ed25519 key is 32 bytes")
        if e["alg"] == "es256":
            if ocw_crypto.p256_public_from_spki(raw) is None or hashlib.sha256(raw).digest()[:8].hex().upper() != e["key_id"]:
                raise TrustError("bad_key_list", f"key {e['key_id']}: not a P-256 key matching its key_id")
    return dict(e)


def parse_key_list(raw):
    if len(raw) > MAX_JSON:
        raise TrustError("bad_key_list", "key list is too large")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TrustError("bad_key_list", "key list is not valid JSON")
    if not isinstance(obj, dict) or set(obj) != {"schema", "keys"} or obj["schema"] != SCHEMA or not isinstance(obj["keys"], list):
        raise TrustError("bad_key_list", "release key list must be exactly {schema: 1, keys: [...]}")
    keys = sorted((_check_entry(e) for e in obj["keys"]), key=lambda e: e["key_id"])
    if len({k["key_id"] for k in keys}) != len(keys) or len({k["public_key"] for k in keys}) != len(keys):
        raise TrustError("bad_key_list", "a key appears twice")
    return keys


def empty_trust():
    return {"schema": SCHEMA, "serial": 0, "keys": [], "revoked": []}


def load_trust(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_JSON + 1)
    except FileNotFoundError:
        raise TrustError("no_trust", f"{path} does not exist: run install.sh (or `ocw-updater trust seed`) to create root's trust list")
    except OSError as exc:
        raise TrustError("no_trust", f"cannot read {path}: {exc.strerror or exc}")
    try:
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict) or set(obj) != {"schema", "serial", "keys", "revoked"} or obj["schema"] != SCHEMA:
            raise ValueError("layout")
        if isinstance(obj["serial"], bool) or not isinstance(obj["serial"], int) or obj["serial"] < 0:
            raise ValueError("serial")
        keys = sorted((_check_entry(e) for e in obj["keys"]), key=lambda e: e["key_id"])
        revoked = []
        for r in obj["revoked"]:
            if not isinstance(r, dict) or not _ID.match(str(r.get("key_id"))):
                raise ValueError("revoked")
            _ts(r.get("revoked_at"))
            if r.get("last_good_version") is not None:
                version_tuple(r["last_good_version"])
            rec = {"key_id": r["key_id"], "revoked_at": r["revoked_at"], "last_good_version": r.get("last_good_version")}
            if r.get("known_good") is not None:
                rec["known_good"] = _check_known_good(r["known_good"])
            revoked.append(rec)
    except (ValueError, UnicodeDecodeError, TrustError) as exc:
        raise TrustError("bad_trust", f"{path} is damaged ({exc}); restore it from a release's server/release_keys.json "
                                      "with `ocw-updater trust seed --force` and re-apply any published revocation")
    return {"schema": SCHEMA, "serial": obj["serial"], "keys": keys, "revoked": revoked}


def _check_known_good(kg):
    """{version: sha256 of the release tarball} pinned by a revocation, or None."""
    if kg is None:
        return None
    if not isinstance(kg, dict) or len(kg) > 200:
        raise TrustError("bad_revocation", "known_good must be a short map of version to sha256")
    for v, d in kg.items():
        version_tuple(v)
        if not isinstance(d, str) or not _SHA.match(d):
            raise TrustError("bad_revocation", "known_good digests must be lower-case sha256 hex")
    return dict(kg)


def _revoked_map(trust):
    return {r["key_id"]: r for r in trust["revoked"]}


def merge(trust, candidate_keys):
    """trust + a release's key list: union by key_id, strictest status wins."""
    keys = {k["key_id"]: dict(k) for k in trust["keys"]}
    for c in candidate_keys:
        cur = keys.get(c["key_id"])
        if cur is None:
            keys[c["key_id"]] = dict(c)
        elif STATUS_RANK[c["status"]] > STATUS_RANK[cur["status"]]:
            cur["status"] = c["status"]
    for key_id in _revoked_map(trust):
        if key_id in keys:
            keys[key_id]["status"] = "revoked"
    return {**trust, "keys": sorted(keys.values(), key=lambda k: k["key_id"])}


def _has_active(trust, role):
    return any(k["role"] == role and k["status"] == "active" and k["alg"] == ROLE_ALG[role] for k in trust["keys"])


def check_adoption(trust, candidate):
    """Rules for the key list a release carries; returns 'same' | 'adopt' | 'older'."""
    known = {k["key_id"]: k for k in trust["keys"]}
    new_keys, stricter = [], False
    for c in candidate:
        e = known.get(c["key_id"])
        if e is None:
            if c["role"] == "standby":
                raise TrustError("keys_changed", "this release adds a standby key; only a signed revocation can change the standby keys")
            new_keys.append(c)
            continue
        if (e["alg"], e["public_key"], e["role"]) != (c["alg"], c["public_key"], c["role"]):
            raise TrustError("keys_changed", f"this release redefines pinned key {c['key_id']}")
        stricter = stricter or STATUS_RANK[c["status"]] > STATUS_RANK[e["status"]]
    if not _has_active(merge(trust, candidate), "release"):
        raise TrustError("keys_changed", "this release would leave no usable release key")
    if new_keys or stricter:
        return "adopt"
    if {c["key_id"] for c in candidate} == set(known) and all(c["status"] == known[c["key_id"]]["status"] for c in candidate):
        return "same"
    return "older"


def pick_release_key(trust, key_id, signed_at, version, sha256=None):
    """The raw 32-byte Ed25519 key allowed to sign this release, or TrustError.

    A REVOKED key never verifies a release on the strength of anything the signature itself says (its trusted comment,
    including the timestamp, is chosen by whoever holds the key). The only exception is a release the revocation itself
    pins by version and tarball sha256 (`known_good`); the digest of the file in hand is compared, never a time."""
    if not trust["keys"]:
        raise TrustError("no_key_pinned", "no release key is pinned in root's trust list")
    entry = next((k for k in trust["keys"] if k["key_id"] == key_id), None)
    if entry is None:
        raise TrustError("key_unknown", f"signed by key {key_id}, which is not trusted on this server")
    if entry["role"] != "release":
        raise TrustError("wrong_role", f"key {key_id} is a {entry['role']} key and may not sign releases")
    if entry["alg"] != "ed25519-minisign":
        raise TrustError("unknown_alg", f"key {key_id} uses an algorithm this updater cannot verify")
    if entry["status"] == "retired":
        raise TrustError("retired_key", f"key {key_id} is retired and no longer signs releases")
    if entry["status"] == "revoked":
        rec = _revoked_map(trust).get(key_id) or {}
        pinned = (rec.get("known_good") or {}).get(version)
        if not pinned or sha256 is None or pinned != sha256:
            raise TrustError("revoked_key", f"key {key_id} is revoked: releases it signed are refused unless the revocation pins this exact file")
    return base64.b64decode(entry["public_key"])


# --- minisign signature ------------------------------------------------------------------


def _b64(text, n, what):
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise TrustError("signature_invalid", f"{what} is not valid base64")
    if len(raw) != n:
        raise TrustError("signature_invalid", f"{what} has the wrong length")
    return raw


def parse_signature(text):
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 4 or not lines[0].startswith("untrusted comment:") or not lines[2].startswith("trusted comment: "):
        raise TrustError("signature_invalid", "the signature file must have four lines (untrusted comment, signature, trusted comment, global signature)")
    raw = _b64(lines[1], 74, "signature")
    if raw[:2] == b"Ed":
        raise TrustError("signature_invalid", "legacy (non-prehashed) signatures are refused")
    if raw[:2] != b"ED":
        raise TrustError("signature_invalid", "unknown signature algorithm tag")
    return {"key_id": raw[2:10][::-1].hex().upper(), "sig": raw[10:], "comment": lines[2][len("trusted comment: "):],
            "global_sig": _b64(lines[3], 64, "trusted-comment signature")}


def parse_trusted_comment(comment):
    fields = {}
    for token in comment.split(" "):
        if "=" not in token:
            raise TrustError("signature_invalid", "trusted comment is not key=value pairs")
        k, v = token.split("=", 1)
        if not k or not v or k in fields:
            raise TrustError("signature_invalid", "trusted comment has an empty or repeated field")
        fields[k] = v
    if set(fields) - {"file", "version", "sha256", "timestamp"} or not {"file", "version", "sha256"} <= set(fields):
        raise TrustError("signature_invalid", "trusted comment must be file, version, sha256 [timestamp]")
    return fields


def hash_file(path, limit=MAX_TARBALL):
    """(blake2b-512 digest, sha256 hex, size) of a regular file, one pass."""
    b2, s2, size = hashlib.blake2b(digest_size=64), hashlib.sha256(), 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise TrustError("bad_artifact", f"{path} is not a regular file")
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise TrustError("bad_artifact", f"{path} is larger than {limit} bytes")
            b2.update(chunk)
            s2.update(chunk)
    return b2.digest(), s2.hexdigest(), size


def _member(tar, name, cap):
    try:
        m = tar.getmember(name)
    except KeyError:
        raise TrustError("bad_release", f"the release does not contain {name}")
    if not m.isreg() or m.size > cap:
        raise TrustError("bad_release", f"{name} in the release is not a regular file of a sane size")
    return tar.extractfile(m).read(cap + 1)


def verify_release(tar_path, sig_path, trust, installed_version=None, expect_sha256=None, expect_version=None):
    """Everything root checks about a signed release file. Returns
    {version, sha256, key_id, timestamp, manifest, candidate_keys, adoption}
    or raises TrustError (code = the audit reason code)."""
    try:
        with open(sig_path, "r", encoding="utf-8") as fh:
            sig = parse_signature(fh.read(20000))
    except (OSError, UnicodeDecodeError) as exc:
        raise TrustError("signature_invalid", f"cannot read the signature file: {getattr(exc, 'strerror', None) or exc}")
    try:
        prehash, sha256, _size = hash_file(tar_path)
    except OSError as exc:
        raise TrustError("bad_artifact", f"cannot read the release file: {exc.strerror or exc}")
    fields = parse_trusted_comment(sig["comment"])
    version = fields["version"]
    version_tuple(version)
    raw_key = pick_release_key(trust, sig["key_id"], fields.get("timestamp"), version, sha256)
    if not ocw_crypto.ed25519_verify(raw_key, prehash, sig["sig"]):
        raise TrustError("signature_invalid", "the signature does not match the file")
    if not ocw_crypto.ed25519_verify(raw_key, sig["sig"] + sig["comment"].encode("utf-8"), sig["global_sig"]):
        raise TrustError("signature_invalid", "the trusted comment was altered")
    base = os.path.basename(tar_path)
    m = _FILE.match(fields["file"])
    if fields["file"] != base or not m or m.group(1) != version:
        raise TrustError("name_mismatch", f"the signature is for {fields['file']}, not {base}")
    if fields["sha256"] != sha256:
        raise TrustError("hash_mismatch", "the file's sha256 differs from the signed one")
    if "timestamp" in fields:
        _ts(fields["timestamp"])
    if expect_sha256 is not None and expect_sha256 != sha256:
        raise TrustError("hash_mismatch", "the file's sha256 differs from the one that was approved")
    if expect_version is not None and expect_version != version:
        raise TrustError("version_mismatch", f"the signed version is {version}, not the requested {expect_version}")
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            manifest_raw = _member(tar, "manifest.json", 4 * 1024 * 1024)
            keys_raw = _member(tar, "server/release_keys.json", MAX_JSON)
            engine_raw = _member(tar, "create_secret_folders.py", 8 * 1024 * 1024)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise TrustError("bad_release", f"the release file cannot be read as a .tar.gz ({exc})")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TrustError("bad_release", "manifest.json is not valid JSON")
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise TrustError("bad_release", "manifest.json has an unsupported layout")
    if manifest.get("version") != version:
        raise TrustError("version_mismatch", f"signed version {version} but the manifest says {manifest.get('version')!r}")
    sv = _SCRIPT_VERSION.search(engine_raw.decode("utf-8", "replace"))
    if not sv or sv.group(1) != version:
        raise TrustError("version_mismatch", f"signed version {version} but the code inside says {sv.group(1) if sv else 'nothing'}")
    for path, digest in manifest["files"].items():
        if not isinstance(path, str) or not isinstance(digest, str) or not _SHA.match(digest):
            raise TrustError("bad_release", "manifest.json lists a file with an invalid hash")
    if installed_version:
        new_t, old_t = version_tuple(version), version_tuple(installed_version)
        if new_t <= old_t:
            raise TrustError("version_not_newer", f"version {version} is not newer than the installed {installed_version}")
        floor = manifest.get("min_upgrade_from")
        if floor and old_t < version_tuple(floor):
            raise TrustError("too_old", f"this release can only be installed over {floor} or newer (installed: {installed_version})")
    candidate = parse_key_list(keys_raw)
    adoption = check_adoption(trust, candidate)
    return {"version": version, "sha256": sha256, "key_id": sig["key_id"], "timestamp": fields.get("timestamp"),
            "manifest": manifest, "candidate_keys": candidate, "adoption": adoption}


# --- revocation (applied by root, offline, from a file) ------------------------------------


def _b64url(text):
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError, TypeError):
        raise TrustError("bad_revocation", "not valid base64url")


def revocation_serial(raw):
    """The serial inside a revocation envelope (unverified: only used to order files), or None."""
    try:
        env = json.loads(raw.decode("utf-8"))
        return json.loads(_b64url(env["payload"]).decode("utf-8"))["serial"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, TrustError):
        return None


def apply_revocation(trust, raw):
    """(new trust, details) for a standby-signed revocation.json, or TrustError."""
    if len(raw) > MAX_JSON:
        raise TrustError("bad_revocation", "revocation file is too large")
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TrustError("bad_revocation", "revocation file is not valid JSON")
    if not isinstance(env, dict) or set(env) != {"format", "payload", "signatures"} or env["format"] != REVOCATION_FORMAT:
        raise TrustError("bad_revocation", f"revocation must be exactly {{format: {REVOCATION_FORMAT}, payload, signatures}}")
    if not isinstance(env["payload"], str) or not isinstance(env["signatures"], list) or not env["signatures"]:
        raise TrustError("bad_revocation", "revocation has no payload or no signatures")
    payload_bytes = _b64url(env["payload"])
    try:
        p = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TrustError("bad_revocation", "revocation payload is not valid JSON")
    fields = {"serial", "issued_at", "revoke", "add_keys", "reason", "advisory_url"}
    if not isinstance(p, dict) or set(p) != fields:
        raise TrustError("bad_revocation", "revocation payload must be exactly: " + ", ".join(sorted(fields)))
    if isinstance(p["serial"], bool) or not isinstance(p["serial"], int) or p["serial"] < 1:
        raise TrustError("bad_revocation", "serial must be a whole number of at least 1")
    _ts(p["issued_at"])
    if not isinstance(p["revoke"], list) or not isinstance(p["add_keys"], list):
        raise TrustError("bad_revocation", "revoke and add_keys must be lists")
    if p["serial"] <= trust["serial"]:
        raise TrustError("replayed", f"revocation serial {p['serial']} is not newer than the last one applied ({trust['serial']})")
    digest = hashlib.sha256((REVOCATION_FORMAT + "\n").encode("ascii") + payload_bytes).digest()
    signer = None
    for sig in env["signatures"]:
        if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "sig"} or sig["alg"] != "es256":
            continue
        entry = next((k for k in trust["keys"] if k["key_id"] == sig["key_id"]), None)
        if entry is None or entry["role"] != "standby" or entry["status"] != "active" or entry["alg"] != "es256":
            continue
        point = ocw_crypto.p256_public_from_spki(base64.b64decode(entry["public_key"]))
        try:
            rs = _b64url(sig["sig"])
        except TrustError:
            continue
        if ocw_crypto.p256_verify_digest(point, digest, rs):
            signer = sig["key_id"]
            break
    if signer is None:
        raise TrustError("bad_signature", "no valid signature from an active standby key")
    keys = {k["key_id"]: dict(k) for k in trust["keys"]}
    revoked = {r["key_id"]: dict(r) for r in trust["revoked"]}
    newly = []
    for item in p["revoke"]:
        kg = None
        if isinstance(item, str):
            key_id, lgv = item, None
        elif isinstance(item, dict) and set(item) <= {"key_id", "last_good_version", "known_good"}:
            key_id, lgv = item.get("key_id"), item.get("last_good_version")
            kg = _check_known_good(item.get("known_good"))
        else:
            key_id, lgv = None, None
        if lgv is not None:
            version_tuple(lgv)
        if not isinstance(key_id, str) or key_id not in keys or key_id in revoked:
            raise TrustError("bad_revocation", f"cannot revoke {key_id!r}: not a pinned, unrevoked key")
        revoked[key_id] = {"key_id": key_id, "revoked_at": p["issued_at"], "last_good_version": lgv}
        if kg:
            revoked[key_id]["known_good"] = kg
        keys[key_id]["status"] = "revoked"
        newly.append(key_id)
    added = []
    for item in p["add_keys"]:
        e = _check_entry(item)
        if e["status"] != "active" or e["alg"] not in ROLE_ALG.values():
            raise TrustError("bad_revocation", f"added key {e['key_id']} must be active and use a known algorithm")
        if e["key_id"] in keys or any(e["public_key"] == k["public_key"] for k in keys.values()):
            raise TrustError("bad_revocation", f"key {e['key_id']} is already pinned")
        keys[e["key_id"]] = e
        added.append(e["key_id"])
    new = {"schema": SCHEMA, "serial": p["serial"], "keys": sorted(keys.values(), key=lambda k: k["key_id"]),
           "revoked": sorted(revoked.values(), key=lambda r: r["key_id"])}
    if not _has_active(new, "release") or not _has_active(new, "standby"):
        raise TrustError("bad_revocation", "this revocation would leave no usable release or standby key")
    return new, {"from_serial": trust["serial"], "to_serial": p["serial"], "revoked": sorted(newly), "added": sorted(added),
                 "signed_by": signer, "reason": str(p["reason"])[:200]}
