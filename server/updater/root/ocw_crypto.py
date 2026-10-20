"""Signature verification with the Python standard library only.

This file is part of the small ROOT-OWNED updater (see ocw_activate.py): root
must never import code from a release tree or from the application's
virtualenv, so the checks root depends on are implemented here, from the
public algorithm descriptions, with `hashlib` and Python integers:

  * Ed25519 verification, RFC 8032 section 5.1.7 (the release signature);
  * ECDSA P-256 / SHA-256 verification, FIPS 186-4 / SEC 1 (the standby
    key's revocation signature).

Only VERIFICATION is implemented (no signing, no key generation), so there is
no secret here to protect and no side channel to worry about: every input is
public. It is slow (tens of milliseconds per signature) and that does not
matter for the two or three checks an upgrade makes.

tests/test_updater_root.py checks this module against the `cryptography`
based verifier the application uses (server/updater/minisign.py, p256.py) on
the same vectors, including signatures made by the real `minisign` program,
so the two cannot drift apart unnoticed.
"""

import hashlib

# --- Ed25519 (RFC 8032) ---------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, -1, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _decompress(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public_key, message, signature):
    """True only for a valid RFC 8032 Ed25519 signature (pure, not Ed25519ph)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


# --- ECDSA P-256 ----------------------------------------------------------------------

_PP = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_A = _PP - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GXP = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GYP = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _PP == 0:
            return None
        lam = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _PP) % _PP
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _PP) % _PP
    x = (lam * lam - p[0] - q[0]) % _PP
    return (x, (lam * (p[0] - x) - p[1]) % _PP)


def _p_mul(k, p):
    r = None
    while k > 0:
        if k & 1:
            r = _p_add(r, p)
        p = _p_add(p, p)
        k >>= 1
    return r


def p256_public_from_spki(der):
    """The (x, y) point of a P-256 SubjectPublicKeyInfo DER (the form stored
    in release_keys.json), or None if it is anything else. The fixed 26-byte
    prefix is the DER header for id-ecPublicKey + prime256v1 + an
    uncompressed 65-byte point."""
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    if len(der) != 91 or der[:26] != prefix or der[26] != 4:
        return None
    x, y = int.from_bytes(der[27:59], "big"), int.from_bytes(der[59:91], "big")
    if x >= _PP or y >= _PP or (y * y - (x * x * x + _A * x + _B)) % _PP != 0:
        return None
    return (x, y)


def p256_verify_digest(point, digest, rs):
    """ECDSA verify of R||S (64 bytes) over a precomputed 32-byte SHA-256 digest."""
    if point is None or len(digest) != 32 or len(rs) != 64:
        return False
    r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(digest, "big")
    w = pow(s, -1, _N)
    pt = _p_add(_p_mul(e * w % _N, (_GXP, _GYP)), _p_mul(r * w % _N, point))
    return pt is not None and pt[0] % _N == r
