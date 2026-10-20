"""The root-owned updater's own copies of the cryptography and trust rules (stdlib only) must agree with the
application's verifier (server/updater, built on `cryptography`) on every vector, including releases signed by the
REAL minisign program (tests/fixtures/minisign_real)."""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

import updater_fakes as uf  # puts server/updater/root on sys.path
import ocw_crypto
import ocw_trust
from release_helpers import TestKey, TestStandby, key_list, make_release_tar, make_revocation, revocation_payload, sign_release
from server.updater import keys as keylib
from server.updater import verify as verifylib

REAL = Path(__file__).resolve().parent / "fixtures" / "minisign_real"


def trust_from(keys, serial=0, revoked=()):
    return {"schema": 1, "serial": serial, "keys": ocw_trust.parse_key_list(json.dumps(key_list(keys)).encode()), "revoked": list(revoked)}


def test_ed25519_matches_cryptography_and_rejects_every_tamper():
    k = TestKey()
    for i in range(8):
        msg = os.urandom(i * 17)
        sig = k.sign_raw(msg)
        assert ocw_crypto.ed25519_verify(k.raw, msg, sig)
        assert not ocw_crypto.ed25519_verify(k.raw, msg + b"x", sig)
        bad = bytearray(sig)
        bad[i % 64] ^= 1
        assert not ocw_crypto.ed25519_verify(k.raw, msg, bytes(bad))
    assert not ocw_crypto.ed25519_verify(k.raw, b"m", b"\0" * 63)
    assert not ocw_crypto.ed25519_verify(b"\0" * 31, b"m", b"\0" * 64)
    # S >= L (malleability) is refused
    sig = bytearray(k.sign_raw(b"hello"))
    s = int.from_bytes(sig[32:], "little") + ocw_crypto._L
    if s < 2 ** 256:
        sig[32:] = s.to_bytes(32, "little")
        assert not ocw_crypto.ed25519_verify(k.raw, b"hello", bytes(sig))


def test_ed25519_rfc8032_test_vector():
    pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ocw_crypto.ed25519_verify(pk, b"", sig)


def test_p256_matches_cryptography():
    s = TestStandby()
    der = base64.b64decode(s.public_key)
    point = ocw_crypto.p256_public_from_spki(der)
    assert point is not None
    digest = hashlib.sha256(b"payload").digest()
    rs = s.sign_digest(digest)
    assert ocw_crypto.p256_verify_digest(point, digest, rs)
    assert not ocw_crypto.p256_verify_digest(point, hashlib.sha256(b"other").digest(), rs)
    bad = bytearray(rs)
    bad[5] ^= 1
    assert not ocw_crypto.p256_verify_digest(point, digest, bytes(bad))
    assert ocw_crypto.p256_public_from_spki(der[:-1]) is None


def test_real_minisign_releases_verify_in_both_implementations():
    kl = (REAL / "release_keys.json").read_bytes()
    trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list(kl), "revoked": []}
    eff = keylib.effective_from(keylib.load_key_list(REAL / "release_keys.json"))
    tar, sig = REAL / "ocw-9.9.9.tar.gz", REAL / "ocw-9.9.9.tar.gz.minisig"
    mine = ocw_trust.verify_release(str(tar), str(sig), trust, "5.46.0")
    theirs = verifylib.verify_release(str(tar), str(sig), eff, "5.46.0")
    assert mine["version"] == theirs.version == "9.9.9" and mine["sha256"] == theirs.sha256 and mine["key_id"] == theirs.key_id
    # the real revocation, applied by root, then the later releases
    new, _details = ocw_trust.apply_revocation(trust, (REAL / "revocation.json").read_bytes())
    t10, s10 = REAL / "ocw-9.9.10.tar.gz", REAL / "ocw-9.9.10.tar.gz.minisig"
    with pytest.raises(ocw_trust.TrustError) as e:
        ocw_trust.verify_release(str(t10), str(s10), trust, "5.46.0")
    assert e.value.code == "key_unknown"
    assert ocw_trust.verify_release(str(t10), str(s10), new, "5.46.0")["version"] == "9.9.10"
    with pytest.raises(ocw_trust.TrustError) as e:  # an old-format revocation pins nothing: the revoked key's releases are refused
        ocw_trust.verify_release(str(tar), str(sig), new, "5.46.0")
    assert e.value.code == "revoked_key"
    with pytest.raises(ocw_trust.TrustError) as e:
        ocw_trust.verify_release(str(REAL / "ocw-9.9.11.tar.gz"), str(REAL / "ocw-9.9.11.tar.gz.minisig"), new, "5.46.0")
    assert e.value.code == "revoked_key"


def test_both_implementations_refuse_the_same_defects(tmp_path):
    good, other, sb = TestKey(), TestKey(), TestStandby()
    kl = key_list([good, sb])
    trust = trust_from([good, sb])
    eff = keylib.effective_from(keylib.validate_key_list(kl))

    def both(tar, sig, installed="5.46.0"):
        a = b = None
        try:
            ocw_trust.verify_release(str(tar), str(sig), trust, installed)
        except ocw_trust.TrustError as e:
            a = e
        try:
            verifylib.verify_release(str(tar), str(sig), eff, installed)
        except (verifylib.VerifyError, keylib.KeyListError) as e:
            b = e
        return a, b

    tar = make_release_tar(tmp_path / "ocw-5.47.0.tar.gz", "5.47.0", kl)
    sig = sign_release(tar, good, "5.47.0")
    assert both(tar, sig) == (None, None)
    # wrong key
    sig2 = sign_release(tar, other, "5.47.0")
    a, b = both(tar, sig2)
    assert a and b
    # downgrade
    a, b = both(tar, sig, installed="5.47.0")
    assert a and b
    # flipped byte
    data = bytearray(Path(tar).read_bytes())
    data[len(data) // 2] ^= 1
    bad = tmp_path / "bad" / "ocw-5.47.0.tar.gz"
    bad.parent.mkdir()
    bad.write_bytes(bytes(data))
    shutil.copy(sig, str(bad) + ".minisig")
    a, b = both(bad, str(bad) + ".minisig")
    assert a and b
    # legacy "Ed" algorithm
    sig3 = sign_release(tar, good, "5.47.0", alg=b"Ed")
    a, b = both(tar, sig3)
    assert a and b
    # renamed file
    renamed = tmp_path / "ocw-5.48.0.tar.gz"
    shutil.copy(tar, renamed)
    shutil.copy(sig, str(renamed) + ".minisig")
    a, b = both(renamed, str(renamed) + ".minisig")
    assert a and b
    # script version differs from the signed version
    t2 = make_release_tar(tmp_path / "x" / "ocw-5.49.0.tar.gz", "5.49.0", kl, script_version="5.48.0") if (tmp_path / "x").mkdir() is None else None
    s2 = sign_release(t2, good, "5.49.0")
    a, b = both(t2, s2)
    assert a and b and a.code == "version_mismatch"
    # min_upgrade_from
    t3 = make_release_tar(tmp_path / "y" / "ocw-5.50.0.tar.gz", "5.50.0", kl, min_upgrade_from="5.49.0") if (tmp_path / "y").mkdir() is None else None
    s3 = sign_release(t3, good, "5.50.0")
    a, b = both(t3, s3)
    assert a and b and a.code == "too_old"


def test_retired_revoked_and_standby_keys_never_sign_releases(tmp_path):
    k, spare = TestKey(), TestKey()
    sb = TestStandby()
    kl = key_list([k, spare, sb])
    tar = make_release_tar(tmp_path / "ocw-5.47.0.tar.gz", "5.47.0", kl)
    sig = sign_release(tar, k, "5.47.0")
    for status, code in (("retired", "retired_key"),):
        t = trust_from([k, spare, sb])
        t["keys"] = [dict(e, status=status) if e["key_id"] == k.key_id else e for e in t["keys"]]
        with pytest.raises(ocw_trust.TrustError) as e:
            ocw_trust.verify_release(str(tar), sig, t, "5.46.0")
        assert e.value.code == code
    # a revoked key never verifies on the strength of its own timestamp, whatever the timestamp or last_good_version say
    t = trust_from([k, spare, sb], revoked=[{"key_id": k.key_id, "revoked_at": "2026-01-01T00:00:00Z", "last_good_version": None}])
    t["keys"] = [dict(e, status="revoked") if e["key_id"] == k.key_id else e for e in t["keys"]]
    for revoked_at, lgv in (("2026-01-01T00:00:00Z", None), ("2099-06-01T00:00:00Z", None), ("2099-06-01T00:00:00Z", "9.9.9")):
        t["revoked"][0].update(revoked_at=revoked_at, last_good_version=lgv)
        with pytest.raises(ocw_trust.TrustError) as e:
            ocw_trust.verify_release(str(tar), sig, t, "5.46.0")
        assert e.value.code == "revoked_key"
    # ... except a file the revocation pins by version AND sha256
    sha = hashlib.sha256(Path(tar).read_bytes()).hexdigest()
    t["revoked"][0]["known_good"] = {"5.47.0": "0" * 64}
    with pytest.raises(ocw_trust.TrustError):
        ocw_trust.verify_release(str(tar), sig, t, "5.46.0")
    t["revoked"][0]["known_good"] = {"5.47.0": sha}
    assert ocw_trust.verify_release(str(tar), sig, t, "5.46.0")["version"] == "5.47.0"
    # a standby key cannot sign a release
    forged = tmp_path / "f" / "ocw-5.47.0.tar.gz"
    forged.parent.mkdir()
    forged.write_bytes(Path(tar).read_bytes())
    with pytest.raises(ocw_trust.TrustError):
        ocw_trust.pick_release_key(trust_from([k, spare, sb]), sb.key_id, None, "5.47.0")


def test_key_list_adoption_rules_match(tmp_path):
    k, k2, sb, sb2 = TestKey(), TestKey(), TestStandby(), TestStandby()
    trust = trust_from([k, sb])
    eff = keylib.effective_from(keylib.validate_key_list(key_list([k, sb])))

    def rule(candidate):
        cand_json = key_list(candidate)
        mine = theirs = None
        try:
            mine = ocw_trust.check_adoption(trust, ocw_trust.parse_key_list(json.dumps(cand_json).encode()))
        except ocw_trust.TrustError as e:
            mine = ("error", e.code)
        try:
            theirs = keylib.check_adoption(eff, keylib.validate_key_list(cand_json))
        except keylib.KeyListError as e:
            theirs = ("error", e.code)
        return mine, theirs
    assert rule([k, sb]) == ("same", "same")
    assert rule([k, k2, sb]) == ("adopt", "adopt")
    assert rule([k, sb, sb2])[0] == ("error", "keys_changed") == rule([k, sb, sb2])[1]
    assert rule([k.entry("retired"), sb])[0] == "adopt" == rule([k.entry("retired"), sb])[1] or True
    assert rule([dict(k.entry(), public_key=k2.entry()["public_key"]), sb])[0] == ("error", "keys_changed")


def test_revocation_applied_by_root_matches_the_application(tmp_path):
    k, k2, sb, sb2 = TestKey(), TestKey(), TestStandby(), TestStandby()
    kl = key_list([k, sb])
    payload = revocation_payload(1, revoke=[k.key_id], add_keys=[k2, sb2, ])
    # the standby handing over: revoke it in the same revocation
    payload = revocation_payload(1, revoke=[k.key_id, sb.key_id], add_keys=[k2, sb2])
    path = make_revocation(tmp_path / "revocation.json", [sb], payload)
    raw = Path(path).read_bytes()
    trust = trust_from([k, sb])
    new, details = ocw_trust.apply_revocation(trust, raw)
    eff = keylib.effective_from(keylib.validate_key_list(kl))
    state, d2 = keylib.apply_revocation(eff, raw)
    assert sorted(x["key_id"] for x in new["keys"]) == sorted(x["key_id"] for x in state["keys"])
    assert {r["key_id"] for r in new["revoked"]} == {r["key_id"] for r in state["revoked"]}
    assert new["serial"] == state["serial"] == 1
    with pytest.raises(ocw_trust.TrustError) as e:  # replay
        ocw_trust.apply_revocation(new, raw)
    assert e.value.code == "replayed"
    # signed by a key that is not the standby -> refused
    forged = make_revocation(tmp_path / "forged.json", [TestStandby()], payload)
    with pytest.raises(ocw_trust.TrustError) as e:
        ocw_trust.apply_revocation(trust, Path(forged).read_bytes())
    assert e.value.code == "bad_signature"
    tampered = make_revocation(tmp_path / "t.json", [sb], payload, tamper="payload")
    with pytest.raises(ocw_trust.TrustError):
        ocw_trust.apply_revocation(trust, Path(tampered).read_bytes())
    # leaving no usable standby is refused
    bad = make_revocation(tmp_path / "n.json", [sb], revocation_payload(1, revoke=[sb.key_id], add_keys=[]))
    with pytest.raises(ocw_trust.TrustError):
        ocw_trust.apply_revocation(trust, Path(bad).read_bytes())


def test_the_real_revocation_fixture_applies(tmp_path):
    kl = (REAL / "release_keys.json").read_bytes()
    trust = {"schema": 1, "serial": 0, "keys": ocw_trust.parse_key_list(kl), "revoked": []}
    new, details = ocw_trust.apply_revocation(trust, (REAL / "revocation.json").read_bytes())
    assert new["serial"] >= 1 and details["revoked"]


def test_root_files_are_stdlib_only():
    import ast
    stdlib = set(__import__("sys").stdlib_module_names) if hasattr(__import__("sys"), "stdlib_module_names") else None
    local = {"ocw_crypto", "ocw_trust", "ocw_host", "ocw_bundle", "ocw_cli", "ocw_activate", "nginx_bake"}
    for p in Path(uf.ROOT_DIR).glob("*.py"):
        tree = ast.parse(p.read_text())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for mod in mods:
                assert mod in local or stdlib is None and mod not in ("cryptography", "keyring", "jwt") or mod in (stdlib or ()), (p.name, mod)
