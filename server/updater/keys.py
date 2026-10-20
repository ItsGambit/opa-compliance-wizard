"""Pinned signing keys: who may sign what, and how the list may change.

server/release_keys.json (shipped with every release, pinned per install):

    {"schema": 1,
     "keys": [{"key_id": "<16 hex>",
               "alg": "ed25519-minisign" | "es256",
               "public_key": "<base64: 32-byte Ed25519 key | DER SubjectPublicKeyInfo of a P-256 key>",
               "role": "release" | "standby",
               "status": "active" | "retired" | "revoked",
               "since": "5.46.0"}]}

Rules this module enforces
  * The verifier dispatches strictly on `alg`. A `release` key must be
    ed25519-minisign (it verifies .minisig files only); a `standby` key must be
    es256 (it verifies revocation.json only). Any other pairing is refused when
    the list is read. An entry with an unknown `alg` is kept but never used.
  * A release may add `release` keys and retire keys. It may not add or change a
    `standby` key, change any existing entry, or re-activate a retired/revoked
    key; such a release is refused as malformed. At least one active, usable
    release key must remain.
  * A key's status only moves toward `revoked` (active < retired < revoked):
    the lists from every source are merged and the strictest status wins, and
    the revoked ids are remembered in this install's own state file
    (release_keys.local.json), so no later list can bring a key back.
  * A revoked release key never verifies a release (a timestamp or version
    number inside its signature is chosen by whoever holds the key, so neither
    is trusted). The one exception: the revocation may pin known-good
    releases in `known_good` ({"x.y.z": "<sha256 of the tarball>"}); a file
    whose version AND sha256 match a pin still verifies. A retired or revoked
    standby never verifies a revocation.

Compromise recovery: a revocation envelope (revocation.json, see below) signed
by an active standby key. The install keeps the highest `serial` it applied; a
revocation must exceed it. `revoke` entries mark release (or standby) keys
revoked from `issued_at`; `add_keys` adds new keys (a new standby hands the
role over; the old one is revoked in the same revocation).

    {"format": "ocw-revocation/1", "payload": "<base64url of the UTF-8 JSON>",
     "signatures": [{"key_id": "<standby id>", "alg": "es256", "sig": "<base64url R||S>"}]}
    payload: {"serial": int, "issued_at": "<RFC 3339 UTC>",
              "revoke": ["<key_id>" | {"key_id": ..., "known_good": {"x.y.z": "<sha256>"}, "last_good_version": "x.y.z" (informational)}],
              "add_keys": [<key entries>], "reason": "...", "advisory_url": "https://..."}
    signed value: SHA-256("ocw-revocation/1\\n" || payload bytes)

Everything refused raises KeyListError with a stable `code` and a message that
says what the operator should do.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import minisign
from . import p256

SCHEMA = 1
ROLES = ("release", "standby")
STATUSES = ("active", "retired", "revoked")
KNOWN_ALGS = ("ed25519-minisign", "es256")
ROLE_ALG = {"release": "ed25519-minisign", "standby": "es256"}
STATUS_RANK = {"active": 0, "retired": 1, "revoked": 2}
MAX_JSON_BYTES = 64 * 1024
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SHIPPED_PATH = Path(__file__).resolve().parent.parent / "release_keys.json"
LOCAL_PATH_ENV = "OPA_RELEASE_KEYS_LOCAL"
REVOCATION_FILE_NAME = "revocation.json"
REVOCATION_FORMAT = "ocw-revocation/1"

_ID_RE = re.compile(r"^[0-9A-F]{16}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_ENTRY_FIELDS = {"key_id", "alg", "public_key", "role", "status", "since"}


class KeyListError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def parse_version(text):
    if not isinstance(text, str) or not _VERSION_RE.match(text):
        raise KeyListError("bad_version", f"'{text}' is not a MAJOR.MINOR.PATCH version")
    return tuple(int(p) for p in text.split("."))


def parse_timestamp(text):
    if not isinstance(text, str) or not _TS_RE.match(text):
        raise KeyListError("bad_timestamp", f"'{text}' is not a UTC time like 2026-01-31T12:00:00Z")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _bad(message):
    return KeyListError("bad_key_list", message)


def empty_key_list():
    return {"schema": SCHEMA, "keys": []}


def empty_state():
    return {"schema": SCHEMA, "serial": 0, "keys": [], "revoked": [], "history": []}


# --- reading and validating ---------------------------------------------------


def validate_entry(entry):
    if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
        raise _bad("each key needs exactly: key_id, alg, public_key, role, status, since")
    if not isinstance(entry["key_id"], str) or not _ID_RE.match(entry["key_id"]):
        raise _bad("key_id must be 16 upper-case hex digits")
    if entry["role"] not in ROLES:
        raise _bad(f"key {entry['key_id']}: role must be 'release' or 'standby'")
    if entry["status"] not in STATUSES:
        raise _bad(f"key {entry['key_id']}: status must be active, retired or revoked")
    parse_version(entry["since"])
    if not isinstance(entry["alg"], str) or not isinstance(entry["public_key"], str) or len(entry["public_key"]) > 2048:
        raise _bad(f"key {entry['key_id']}: alg and public_key must be text")
    if entry["alg"] in KNOWN_ALGS:
        if entry["alg"] != ROLE_ALG[entry["role"]]:
            raise _bad(f"key {entry['key_id']}: a {entry['role']} key must use alg '{ROLE_ALG[entry['role']]}' "
                       f"(got '{entry['alg']}')")
        if entry["alg"] == "ed25519-minisign":
            try:
                ok = len(base64.b64decode(entry["public_key"], validate=True)) == 32
            except (binascii.Error, ValueError):
                ok = False
            if not ok:
                raise _bad(f"key {entry['key_id']}: public_key must be the base64 of a 32-byte Ed25519 key")
        else:
            try:
                derived = p256.parse_public_key(entry["public_key"])[0]
            except p256.P256Error as exc:
                raise _bad(f"key {entry['key_id']}: {exc}")
            if derived != entry["key_id"]:
                raise _bad(f"key {entry['key_id']}: key_id does not match the key (expected {derived})")
    return {k: entry[k] for k in ("key_id", "alg", "public_key", "role", "status", "since")}


def _validate_entries(entries):
    if not isinstance(entries, list):
        raise _bad("keys must be a list")
    out = sorted((validate_entry(e) for e in entries), key=lambda e: e["key_id"])
    if len({e["key_id"] for e in out}) != len(out):
        raise _bad("a key_id appears twice")
    if len({e["public_key"] for e in out}) != len(out):
        raise _bad("a public key appears twice")
    return out


def validate_key_list(obj):
    if not isinstance(obj, dict) or set(obj) != {"schema", "keys"}:
        raise _bad("release key list must have exactly: schema, keys")
    if obj["schema"] != SCHEMA:
        raise _bad(f"unsupported release key list schema {obj['schema']!r} (this version reads schema {SCHEMA})")
    return {"schema": SCHEMA, "keys": _validate_entries(obj["keys"])}


def parse_known_good(kg):
    """{version: sha256 hex of the tarball} pinned by a revocation."""
    if not isinstance(kg, dict) or len(kg) > 200:
        raise _bad("known_good must be a short map of version to sha256")
    for v, d in kg.items():
        parse_version(v)
        if not isinstance(d, str) or not re.match(r"^[0-9a-f]{64}$", d):
            raise _bad("known_good digests must be lower-case sha256 hex")
    return dict(kg)


def validate_state(obj):
    if not isinstance(obj, dict) or not {"schema", "serial", "keys", "revoked"} <= set(obj) <= {"schema", "serial", "keys", "revoked", "history"} \
            or obj["schema"] != SCHEMA:
        raise _bad("key state must have: schema, serial, keys, revoked (and optionally history)")
    if isinstance(obj["serial"], bool) or not isinstance(obj["serial"], int) or obj["serial"] < 0:
        raise _bad("serial must be a non-negative whole number")
    revoked = []
    for r in obj["revoked"] if isinstance(obj["revoked"], list) else [None]:
        if not isinstance(r, dict) or not {"key_id", "revoked_at"} <= set(r) <= {"key_id", "revoked_at", "last_good_version", "known_good"}:
            raise _bad("each revoked record needs key_id and revoked_at (and optionally last_good_version, known_good)")
        if not isinstance(r["key_id"], str) or not _ID_RE.match(r["key_id"]):
            raise _bad("revoked key_id must be 16 upper-case hex digits")
        parse_timestamp(r["revoked_at"])
        if r.get("last_good_version") is not None:
            parse_version(r["last_good_version"])
        rec = {"key_id": r["key_id"], "revoked_at": r["revoked_at"], "last_good_version": r.get("last_good_version")}
        if r.get("known_good") is not None:
            rec["known_good"] = parse_known_good(r["known_good"])
        revoked.append(rec)
    return {"schema": SCHEMA, "serial": obj["serial"], "keys": _validate_entries(obj["keys"]), "revoked": revoked,
            "history": _validate_history(obj.get("history", []))}


_HISTORY_FIELDS = ("serial", "issued_at", "applied_at", "reason", "advisory_url", "revoked", "added", "signed_by", "source")


def _validate_history(items):
    """The revocations this install applied (newest last), for the Keys screen. Bounded."""
    if not isinstance(items, list):
        raise _bad("history must be a list")
    out = []
    for h in items[-20:]:
        if not isinstance(h, dict):
            raise _bad("history entries must be objects")
        entry = {k: h.get(k) for k in _HISTORY_FIELDS}
        for k in ("revoked", "added"):
            entry[k] = [x for x in (entry[k] or []) if isinstance(x, str) and _ID_RE.match(x)]
        for k in ("reason", "advisory_url", "issued_at", "applied_at", "signed_by", "source"):
            entry[k] = entry[k][:300] if isinstance(entry[k], str) else None
        entry["serial"] = entry["serial"] if isinstance(entry["serial"], int) and not isinstance(entry["serial"], bool) else None
        out.append(entry)
    return out


def _read_capped(path, what):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise KeyListError("unreadable", f"cannot read {what} ({path}): {exc.strerror or exc}")
    if len(raw) > MAX_JSON_BYTES:
        raise _bad(f"{what} is too large")
    return raw


def parse_key_list_bytes(raw, what="release key list"):
    if len(raw) > MAX_JSON_BYTES:
        raise _bad(f"{what} is too large")
    try:
        return validate_key_list(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeDecodeError):
        raise _bad(f"{what} is not valid JSON")


def _damaged(path, exc):
    return KeyListError("bad_key_list", f"{path} is damaged ({exc}). If you did not edit it yourself, restore it from a "
                        "release (server/release_keys.json) or delete release_keys.local.json and, if a key revocation was "
                        "published, apply it again.")


def load_key_list(path):
    """A missing file is the empty list; an unreadable or malformed one is an error."""
    if not os.path.exists(path):
        return empty_key_list()
    try:
        return parse_key_list_bytes(_read_capped(path, "release key list"), f"release key list {path}")
    except KeyListError as exc:
        if exc.code == "bad_key_list":
            raise _damaged(path, exc)
        raise


def load_state(path):
    if not os.path.exists(path):
        return empty_state()
    raw = _read_capped(path, "key state")
    try:
        return validate_state(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _damaged(path, exc)
    except KeyListError as exc:
        if exc.code == "bad_key_list":
            raise _damaged(path, exc)
        raise


def local_path():
    return Path(os.environ.get(LOCAL_PATH_ENV) or (Path(os.environ.get("OPA_DATA_DIR") or REPO_ROOT) / "release_keys.local.json"))


# --- the effective list --------------------------------------------------------


def effective_from(shipped, state=None):
    """Merge a shipped list (validate_key_list output) with this install's state
    (validate_state output). Union by key_id; the strictest status wins; revoked
    records from the state mark their keys revoked. Returns
    {"schema", "serial", "keys": [...], "revoked": {key_id: record}}."""
    state = state or empty_state()
    keys = {}
    for source in (shipped["keys"], state["keys"]):
        for entry in source:
            cur = keys.get(entry["key_id"])
            if cur is None:
                keys[entry["key_id"]] = dict(entry)
                continue
            if (cur["alg"], cur["public_key"], cur["role"]) != (entry["alg"], entry["public_key"], entry["role"]):
                raise KeyListError("conflict", f"key {entry['key_id']} appears with two different definitions (release_keys.json "
                                   "and release_keys.local.json). Delete release_keys.local.json if you did not create it, or reinstall.")
            if STATUS_RANK[entry["status"]] > STATUS_RANK[cur["status"]]:
                cur["status"] = entry["status"]
    revoked = {r["key_id"]: r for r in state["revoked"]}
    for key_id in revoked:
        if key_id in keys:
            keys[key_id]["status"] = "revoked"
    return {"schema": SCHEMA, "serial": state["serial"], "keys": sorted(keys.values(), key=lambda e: e["key_id"]),
            "revoked": revoked, "history": state.get("history", [])}


def effective_key_list(shipped_path=None, local_state_path=None):
    return effective_from(load_key_list(shipped_path if shipped_path is not None else SHIPPED_PATH),
                          load_state(local_state_path if local_state_path is not None else local_path()))


def _entry(eff, key_id):
    return next((k for k in eff["keys"] if k["key_id"] == key_id), None)


def usable(entry, role):
    return entry["role"] == role and entry["status"] == "active" and entry["alg"] in KNOWN_ALGS


def has_active(eff, role):
    return any(usable(k, role) for k in eff["keys"])


def pick_signer(eff, key_id, role, signed_at=None, version=None, sha256=None):
    """The public key allowed to make this signature, or KeyListError. role
    'release': a release signature (`signed_at` is ignored on purpose;
    `version` and `sha256` (of the tarball) are used only to match a revoked key's `known_good` pins). role
    'standby': a revocation."""
    if not eff["keys"]:
        raise KeyListError("no_key_pinned", "no release key pinned: this install has no signing key to check against, so it "
                           "cannot verify a release. The project owner must publish the key; see 'Upgrading' in the README. "
                           "(Existing installs keep working; only verified installs are unavailable.)")
    entry = _entry(eff, key_id)
    if entry is None:
        raise KeyListError("unknown_key", f"signed by key {key_id}, which is not pinned on this install. If the project rotated "
                           "its signing key after a compromise, apply the published revocation (README: 'If the signing key "
                           "is compromised'); otherwise do not install this file.")
    if entry["role"] != role:
        what = "releases" if role == "release" else "revocations"
        raise KeyListError("wrong_role", f"key {key_id} is a {entry['role']} key and may not sign {what}. Do not install this file.")
    if entry["alg"] not in KNOWN_ALGS:
        raise KeyListError("unknown_alg", f"key {key_id} uses an algorithm ({entry['alg']}) this version cannot verify; update the "
                           "app with an unsigned --ref install of a newer version, or ask the project.")
    if entry["status"] == "retired":
        raise KeyListError("retired_key", f"key {key_id} is retired and no longer signs releases. Use a release signed by a current key.")
    if entry["status"] == "revoked":
        if role != "release":
            raise KeyListError("revoked_key", f"key {key_id} has been revoked and may not sign a revocation.")
        record = eff["revoked"].get(key_id) or {}
        pinned = (record.get("known_good") or {}).get(version)
        if not pinned or sha256 is None or pinned != sha256:
            raise KeyListError("revoked_key", f"key {key_id} has been revoked: releases it signed are refused unless the revocation "
                               "pins this exact file. Do not install it.")
    if entry["alg"] == "es256":
        return p256.parse_public_key(entry["public_key"])[1]
    return minisign.PubKey(key_id, base64.b64decode(entry["public_key"]))


def merged_with(eff, candidate):
    """The effective list after also taking a release's list into account."""
    return effective_from(candidate, {**empty_state(), "keys": eff["keys"], "serial": eff["serial"],
                                      "revoked": list(eff["revoked"].values())})


def check_adoption(eff, candidate):
    """Rules for the key list a release carries. Returns 'same', 'adopt' (it
    adds keys or retires some) or 'older' (it is a subset of what this install
    already knows: verifies, but changes nothing). Raises KeyListError for a
    list that adds or changes a standby, or redefines a key."""
    known = {k["key_id"]: k for k in eff["keys"]}
    new_keys, stricter = [], False
    for c in candidate["keys"]:
        e = known.get(c["key_id"])
        if e is None:
            if c["role"] == "standby":
                raise KeyListError("keys_changed", "this release adds a standby key; only a signed revocation can change the "
                                   "standby keys. Do not install it.")
            new_keys.append(c)
            continue
        if (e["alg"], e["public_key"], e["role"]) != (c["alg"], c["public_key"], c["role"]):
            raise KeyListError("keys_changed", f"this release redefines pinned key {c['key_id']}. Do not install it.")
        # A looser status in a release's list (an older release that predates a retirement or revocation) is
        # simply ignored: statuses only ever move toward revoked (effective_from keeps the strictest).
        stricter = stricter or STATUS_RANK[c["status"]] > STATUS_RANK[e["status"]]
    merged = merged_with(eff, candidate)
    if not has_active(merged, "release"):
        raise KeyListError("keys_changed", "this release would leave no usable release key. Do not install it.")
    if new_keys or stricter:
        return "adopt"
    if {k["key_id"] for k in candidate["keys"]} == set(known) and all(
            c["status"] == known[c["key_id"]]["status"] for c in candidate["keys"]):
        return "same"
    return "older"


# --- revocation ------------------------------------------------------------------


def revocation_digest(payload_bytes):
    return hashlib.sha256((REVOCATION_FORMAT + "\n").encode("ascii") + payload_bytes).digest()


def _bad_rev(message):
    return KeyListError("bad_revocation", message)


def parse_revocation(raw):
    """(payload_bytes, payload dict, signatures) from revocation.json bytes."""
    if len(raw) > MAX_JSON_BYTES:
        raise _bad_rev("revocation file is too large")
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise _bad_rev("revocation file is not valid JSON")
    if not isinstance(env, dict) or set(env) != {"format", "payload", "signatures"} or env["format"] != REVOCATION_FORMAT:
        raise _bad_rev(f"revocation must be exactly {{format: {REVOCATION_FORMAT}, payload, signatures}}")
    if not isinstance(env["payload"], str) or not isinstance(env["signatures"], list) or not env["signatures"]:
        raise _bad_rev("revocation has no payload or no signatures")
    try:
        payload_bytes = p256.b64url_decode(env["payload"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (p256.P256Error, ValueError, UnicodeDecodeError):
        raise _bad_rev("revocation payload is not valid base64url JSON")
    fields = {"serial", "issued_at", "revoke", "add_keys", "reason", "advisory_url"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise _bad_rev("revocation payload must be exactly: " + ", ".join(sorted(fields)))
    if isinstance(payload["serial"], bool) or not isinstance(payload["serial"], int) or payload["serial"] < 1:
        raise _bad_rev("serial must be a whole number of at least 1")
    parse_timestamp(payload["issued_at"])
    if not isinstance(payload["reason"], str) or not 0 < len(payload["reason"]) <= 500:
        raise _bad_rev("reason must be a short text")
    url = payload["advisory_url"]
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 300 or " " in url:
        raise _bad_rev("advisory_url must be an https:// link")
    if not isinstance(payload["revoke"], list) or not isinstance(payload["add_keys"], list):
        raise _bad_rev("revoke and add_keys must be lists")
    return payload_bytes, payload, env["signatures"]


def verify_revocation_signature(eff, payload_bytes, signatures):
    digest = revocation_digest(payload_bytes)
    first_error = None
    for sig in signatures:
        try:
            if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "sig"} or sig["alg"] != "es256":
                raise KeyListError("bad_signature", "a revocation signature must be exactly {key_id, alg: es256, sig}")
            public_key = pick_signer(eff, sig["key_id"], "standby")
            p256.verify_digest(digest, p256.b64url_decode(sig["sig"]), public_key)
            return sig["key_id"]
        except p256.P256Error as exc:
            first_error = first_error or KeyListError("bad_signature", f"revocation signature refused: {exc}")
        except KeyListError as exc:
            first_error = first_error or exc
    raise first_error


def apply_revocation(eff, raw):
    """Verify a revocation against `eff` and return (new_state, details); the
    caller persists new_state (write_local) and audits. Raises KeyListError."""
    payload_bytes, payload, signatures = parse_revocation(raw)
    serial = payload["serial"]
    if serial <= eff["serial"]:
        raise KeyListError("replayed", f"revocation serial {serial} is not newer than the last one applied on this install "
                           f"({eff['serial']}); it was already applied or is a replay. Nothing changed.")
    signer = verify_revocation_signature(eff, payload_bytes, signatures)
    issued = payload["issued_at"]
    keys = {k["key_id"]: dict(k) for k in eff["keys"]}
    revoked = {k: dict(v) for k, v in eff["revoked"].items()}
    newly = []
    for item in payload["revoke"]:
        kg = None
        if isinstance(item, dict) and set(item) <= {"key_id", "last_good_version", "known_good"}:
            key_id, lgv = item.get("key_id"), item.get("last_good_version")
            kg = parse_known_good(item["known_good"]) if item.get("known_good") is not None else None
        elif isinstance(item, str):
            key_id, lgv = item, None
        else:
            key_id, lgv = None, None
        if lgv is not None:
            parse_version(lgv)
        if not isinstance(key_id, str) or key_id not in keys:
            raise _bad_rev(f"cannot revoke {key_id!r}: not a pinned key")
        if key_id in revoked:
            raise _bad_rev(f"{key_id} is already revoked")
        revoked[key_id] = {"key_id": key_id, "revoked_at": issued, "last_good_version": lgv}
        if kg:
            revoked[key_id]["known_good"] = kg
        keys[key_id]["status"] = "revoked"
        newly.append(key_id)
    added = []
    for item in payload["add_keys"]:
        try:
            entry = validate_entry(item)
        except KeyListError as exc:
            raise _bad_rev(str(exc))
        if entry["status"] != "active" or entry["alg"] not in KNOWN_ALGS:
            raise _bad_rev(f"added key {entry['key_id']} must be active and use a known algorithm")
        if entry["key_id"] in keys or any(entry["public_key"] == k["public_key"] for k in keys.values()):
            raise _bad_rev(f"key {entry['key_id']} is already pinned")
        keys[entry["key_id"]] = entry
        added.append(entry["key_id"])
    result = {"schema": SCHEMA, "serial": serial, "keys": sorted(keys.values(), key=lambda k: k["key_id"]), "revoked": revoked}
    if not has_active(result, "release"):
        raise _bad_rev("this revocation would leave no usable release key; it must add a new one")
    if not has_active(result, "standby"):
        raise _bad_rev("this revocation would leave no usable standby key; it must add a new one")
    details = {"from_serial": eff["serial"], "to_serial": serial, "revoked": sorted(newly), "added": sorted(added),
               "signed_by": signer, "reason": payload["reason"][:200], "advisory_url": payload["advisory_url"],
               "issued_at": issued}
    history = list(eff.get("history", [])) + [{"serial": serial, "issued_at": issued, "applied_at": None,
                                               "reason": details["reason"], "advisory_url": details["advisory_url"],
                                               "revoked": details["revoked"], "added": details["added"],
                                               "signed_by": signer, "source": None}]
    state = {"schema": SCHEMA, "serial": serial, "keys": result["keys"], "revoked": list(revoked.values()), "history": history}
    return state, details


# --- persistence, audit, CLI ------------------------------------------------------


def _engine():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import create_secret_folders as engine
    return engine


def write_local(state, path=None):
    """This install's own key state: owner-only, written atomically."""
    _engine()._atomic_write_json(str(path or local_path()), state)


def persist_effective(eff, path=None):
    """Remember everything this install knows, so a later (older or stricter)
    shipped list can never make it forget a key, a status or a revocation."""
    write_local({"schema": SCHEMA, "serial": eff["serial"], "keys": eff["keys"], "revoked": list(eff["revoked"].values()),
                 "history": eff.get("history", [])}, path)


def record_change(action, details):
    """Every key-list change goes to the audit trail and the JSON log.
    Best effort: a logging failure never blocks the (already verified) change."""
    try:
        engine = _engine()
        details = dict(details)
        details.setdefault("correlation_id", engine.CORRELATION_ID.get())
        engine.log("INFO", f"{action}: {json.dumps(details, sort_keys=True)}")
        engine.log_audit_event(None, None, action, details)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not write the audit entry for {action}: {exc}", file=sys.stderr)


def _keep_raw_copy(raw, serial):
    """5.47.0: in the /var/lib layout the root-owned updater keeps its own trust list and does not read this install's
    key state; it re-verifies any revocation.json left in upgrade/revocations/ itself (an untrusted carrier, a verified
    file). Best effort and only when that directory exists (install.sh creates it)."""
    data = os.environ.get("OPA_DATA_DIR")
    if not data:
        return
    d = Path(data) / "upgrade" / "revocations"
    try:
        if d.is_dir():
            (d / f"{int(serial)}.json").write_bytes(raw)
    except OSError:
        pass


def apply_revocation_bytes(raw, source="file", shipped=None, local_state_path=None):
    """Verify, persist, audit. Returns (effective list after, details)."""
    shipped_list = load_key_list(shipped if shipped is not None else SHIPPED_PATH)
    path = local_state_path if local_state_path is not None else local_path()
    eff = effective_from(shipped_list, load_state(path))
    state, details = apply_revocation(eff, raw)
    state["history"][-1]["applied_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state["history"][-1]["source"] = source
    write_local(validate_state(state), path)
    _keep_raw_copy(raw, details["to_serial"])
    details = {**details, "source": source}
    # One audit entry per effect, like the Keys screen's history: what was revoked, and what was added.
    if details["revoked"]:
        record_change("upgrade.key_revoked", details)
    if details["added"]:
        record_change("upgrade.key_added", {k: details[k] for k in ("added", "signed_by", "source", "to_serial", "advisory_url")})
    return effective_from(shipped_list, state), details


def apply_revocation_file(path, **kw):
    return apply_revocation_bytes(_read_capped(path, "revocation file"), source="file", **kw)


def describe_keys(eff):
    """Read-only key table for the Updates > Release signing keys screen."""
    return [{"key_id": k["key_id"], "role": k["role"], "alg": k["alg"], "status": k["status"], "since": k["since"],
             "revoked_at": (eff["revoked"].get(k["key_id"]) or {}).get("revoked_at")} for k in eff["keys"]]


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="python -m server.updater.keys",
                                     description="Inspect or update the pinned signing keys.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ap = sub.add_parser("apply-revocation", help="apply a standby-signed revocation.json (works offline)")
    ap.add_argument("revocation_json")
    sub.add_parser("show", help="print the key list this install trusts")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "show":
            eff = effective_key_list()
            print(f"Pinned keys (last revocation serial {eff['serial']}): {len(eff['keys'])}")
            for k in eff["keys"]:
                r = eff["revoked"].get(k["key_id"])
                print(f"  {k['key_id']}  {k['role']:8} {k['alg']:17} {k['status']:8} since {k['since']}"
                      + (f"  revoked {r['revoked_at']}" if r else ""))
            return 0
        new, details = apply_revocation_file(args.revocation_json)
        print(f"Revocation applied: serial {details['from_serial']} -> {details['to_serial']}. Reason: {details['reason']}")
        print(f"  advisory: {details['advisory_url']}")
        if details["revoked"]:
            print("  revoked: " + ", ".join(details["revoked"]))
        if details["added"]:
            print("  new keys: " + ", ".join(details["added"]))
        print("Releases signed by a revoked key after the revocation time are now refused.")
        return 0
    except KeyListError as exc:
        if exc.code == "replayed":  # idempotent: applying it twice is not an error
            print(f"Nothing to do: {exc}")
            return 0
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
