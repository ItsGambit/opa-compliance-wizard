"""ES256 (ECDSA P-256 with SHA-256) helpers for the standby key, which signs
ONLY revocations. Azure Key Vault has no Ed25519, so the standby is a P-256 key
held there; verification is done in-process with `cryptography`.

Public key (release_keys.json `public_key` of an `es256` entry): base64 of the
SubjectPublicKeyInfo DER. Key id: first 8 bytes of SHA-256 of that DER, upper-
case hex (16 digits).

Signatures are the JWS/RFC 7518 form `R || S` (32 + 32 bytes), which is what
Azure Key Vault returns; this module converts to DER for `cryptography`.
The signed value is a SHA-256 digest computed locally (see keys.py,
revocation_digest): Key Vault signs hashes, it does not hash.
"""

import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

ALG = "es256"


class P256Error(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def key_id_for_spki(der):
    return hashlib.sha256(der).digest()[:8].hex().upper()


def parse_public_key(b64):
    """(key_id, EllipticCurvePublicKey) from base64 SPKI DER, or P256Error."""
    try:
        der = base64.b64decode(b64.strip(), validate=True)
        key = serialization.load_der_public_key(der)
    except (binascii.Error, ValueError, AttributeError, TypeError):
        raise P256Error("malformed", "standby public key is not a valid base64 SubjectPublicKeyInfo")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise P256Error("malformed", "standby public key must be an EC P-256 key")
    return key_id_for_spki(der), key


def spki_b64(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError, TypeError):
        raise P256Error("malformed", "not valid base64url")


def rs_to_der(rs):
    if len(rs) != 64:
        raise P256Error("malformed", "an ES256 signature must be 64 bytes (R || S)")
    return encode_dss_signature(int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big"))


def der_to_rs(der):
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_digest(digest, rs, public_key):
    """Verify R||S over a precomputed SHA-256 digest."""
    if len(digest) != 32:
        raise P256Error("malformed", "digest must be 32 bytes")
    try:
        public_key.verify(rs_to_der(rs), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        raise P256Error("bad_signature", "revocation signature does not match")
