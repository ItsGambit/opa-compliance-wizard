"""Minisign-format Ed25519 signature primitives (stdlib + `cryptography`).

Format reference: https://jedisct1.github.io/minisign/ . Public key text is
two lines (comment, base64 of "Ed" + key id(8) + Ed25519 key(32)); a
signature file is four lines (untrusted comment, base64 of algorithm(2) +
key id(8) + signature(64), "trusted comment: ...", base64 of the global
signature(64)). Algorithm "ED" signs the BLAKE2b-512 digest of the file
(prehashed); legacy "Ed" signs the file itself. This project REFUSES "Ed":
a prehashed signature is the only kind a release is ever given.

The global signature covers signature(64) + trusted comment bytes, so the
trusted comment (file, version, sha256, ...) cannot be altered without the
key. Key ids are shown the way minisign prints them (the 8 stored bytes in
reverse order, upper-case hex).

Nothing here reads a key list or decides who may sign what; see keys.py and
verify.py. Shared by the verifier, the key-list code, tools/release.py and
the tests -- there is exactly one implementation of the format.
"""

import base64
import binascii
import hashlib
import re
from collections import namedtuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SignatureError(Exception):
    """A signature or public key is malformed, or does not verify.
    `code` is a stable reason for tests and logs."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


PubKey = namedtuple("PubKey", "key_id raw")
Signature = namedtuple("Signature", "alg key_id sig trusted_comment global_sig")

_PREFIX_TRUSTED = "trusted comment: "
_MAX_TEXT = 4096
_MAX_SIG_TEXT = 16384  # a trusted comment may be up to 4000 bytes (tools cap it; KMS Sign takes 4096)


def _b64(text, expected_len, what):
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError("malformed", f"{what} is not valid base64")
    if len(raw) != expected_len:
        raise SignatureError("malformed", f"{what} has the wrong length")
    return raw


def key_id_hex(stored8):
    """minisign's printed key id: the stored bytes reversed, upper-case hex."""
    return stored8[::-1].hex().upper()


def parse_public_key(text):
    """Accepts the bare base64 line or a whole .pub file."""
    if not isinstance(text, str) or len(text) > _MAX_TEXT:
        raise SignatureError("malformed", "public key is not text")
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        raise SignatureError("malformed", "empty public key")
    if len(lines) == 2 and lines[0].startswith("untrusted comment:"):
        body = lines[1]
    elif len(lines) == 1:
        body = lines[0]
    else:
        raise SignatureError("malformed", "public key must be one base64 line or a two-line .pub file")
    raw = _b64(body, 42, "public key")
    if raw[:2] != b"Ed":
        raise SignatureError("malformed", "public key has an unknown algorithm tag")
    return PubKey(key_id_hex(raw[2:10]), raw[10:])


def parse_signature(text):
    if not isinstance(text, str) or len(text) > _MAX_SIG_TEXT:
        raise SignatureError("malformed", "signature is not text")
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 4 or not lines[0].startswith("untrusted comment:"):
        raise SignatureError("malformed", "signature file must have exactly four lines")
    if not lines[2].startswith(_PREFIX_TRUSTED):
        raise SignatureError("malformed", "signature file has no trusted comment")
    raw = _b64(lines[1], 74, "signature")
    alg = raw[:2]
    if alg == b"Ed":
        raise SignatureError("legacy_signature", "legacy (non-prehashed) signatures are refused; sign without -l")
    if alg != b"ED":
        raise SignatureError("malformed", "signature has an unknown algorithm tag")
    global_sig = _b64(lines[3], 64, "trusted-comment signature")
    return Signature("ED", key_id_hex(raw[2:10]), raw[10:], lines[2][len(_PREFIX_TRUSTED):], global_sig)


def format_signature(key_id, sig, trusted_comment, global_sig, untrusted_comment="signature from OPA Compliance Wizard release tool"):
    """The four-line signature file for a prehashed ("ED") signature. `sig` is
    the raw 64-byte Ed25519 signature of the file's BLAKE2b-512 digest and
    `global_sig` that of sig + trusted comment, however they were produced (a
    local key, minisign, a hardware or cloud signer): the verifier never
    depends on it. Used by tools/release.py's raw-signature backends."""
    if len(sig) != 64 or len(global_sig) != 64 or not _KEY_ID_RE.match(key_id):
        raise SignatureError("malformed", "signature parts have the wrong size")
    stored_id = bytes.fromhex(key_id)[::-1]
    if "\n" in trusted_comment or "\r" in trusted_comment:
        raise SignatureError("malformed", "trusted comment must be one line")
    return ("untrusted comment: " + untrusted_comment + "\n" + base64.b64encode(b"ED" + stored_id + sig).decode() +
            "\ntrusted comment: " + trusted_comment + "\n" + base64.b64encode(global_sig).decode() + "\n")


_KEY_ID_RE = re.compile(r"^[0-9A-F]{16}$")


def hash_file(path, max_bytes=None):
    """One pass over the file: (blake2b-512 digest bytes, sha256 hex, size)."""
    b2 = hashlib.blake2b(digest_size=64)
    s256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise SignatureError("too_large", "file is larger than the allowed size")
            b2.update(chunk)
            s256.update(chunk)
    return b2.digest(), s256.hexdigest(), size


def verify(prehash, signature, pubkey):
    """Verifies both signatures of `signature` (a parsed Signature) against
    `pubkey` (a PubKey) for a file whose BLAKE2b-512 digest is `prehash`.
    Raises SignatureError; returns None on success."""
    if signature.key_id != pubkey.key_id:
        raise SignatureError("key_mismatch", "signature was made by a different key")
    key = Ed25519PublicKey.from_public_bytes(pubkey.raw)
    try:
        key.verify(signature.sig, prehash)
    except InvalidSignature:
        raise SignatureError("bad_signature", "signature does not match the file")
    try:
        key.verify(signature.global_sig, signature.sig + signature.trusted_comment.encode("utf-8"))
    except InvalidSignature:
        raise SignatureError("bad_trusted_comment", "the trusted comment was altered")


def parse_trusted_comment(comment, required=("file", "version", "sha256"), optional=()):
    """`k=v k=v ...` (single spaces; values contain no spaces). Unknown or
    repeated keys, or missing required keys, are refused."""
    fields = {}
    for token in comment.split(" "):
        if "=" not in token:
            raise SignatureError("bad_trusted_comment", "trusted comment is not key=value pairs")
        k, v = token.split("=", 1)
        if not k or not v or k in fields:
            raise SignatureError("bad_trusted_comment", "trusted comment has an empty or repeated field")
        fields[k] = v
    extra = set(fields) - set(required) - set(optional)
    if extra:
        raise SignatureError("bad_trusted_comment", "trusted comment has unexpected fields")
    missing = [k for k in required if k not in fields]
    if missing:
        raise SignatureError("bad_trusted_comment", "trusted comment lacks " + ", ".join(missing))
    return fields
