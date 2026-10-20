"""Signed releases (5.46.0): the minisign-format verifier, the pinned key list
(roles, algorithms, statuses, rotation), revocation envelopes, safe unpacking,
and the maintainer tools (build, sign through a fake KMS, revoke through a fake
Key Vault).

Vectors come from two places. tests/fixtures/minisign_real/ holds releases signed
by the REAL `minisign` program 0.12 (throwaway keys whose secret halves were
never saved), so the verifier is checked against the reference implementation
without needing minisign in CI; its revocation was built by tools/revoke.py.
Everything with a deliberate defect is made by tests/release_helpers.py, a second,
independent implementation. All keys are generated in the test; no cloud is called.
"""

import base64
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from release_helpers import (TestKey, TestStandby, effective, key_list, make_release_tar, make_revocation, revocation_payload,
                             sign_release)
from server.updater import keys as keylib
from server.updater import minisign
from server.updater import verify as verifylib

REAL = Path(__file__).resolve().parent / "fixtures" / "minisign_real"
INSTALLED = "5.46.0"
REPO = Path(__file__).resolve().parent.parent


def real_eff(name="release_keys.json", state=None):
    return keylib.effective_from(keylib.load_key_list(REAL / name), state)


@pytest.fixture
def real(tmp_path):
    dest = tmp_path / "real"
    shutil.copytree(REAL, dest)
    return dest


def check(tar, sig, eff, installed=INSTALLED, **kw):
    return verifylib.verify_release(str(tar), str(sig), eff, installed, **kw)


def refused(code, *args, **kw):
    with pytest.raises((verifylib.VerifyError, keylib.KeyListError)) as info:
        check(*args, **kw)
    assert info.value.code == code, str(info.value)
    return str(info.value)


def forged_as(standby):
    """An Ed25519 key that claims the standby's key id: the standby itself is
    ES256 and cannot even make a release signature."""
    forged = TestKey()
    forged.stored_id = bytes.fromhex(standby.key_id)[::-1]
    forged.key_id = standby.key_id
    return forged


# --- real minisign vectors ---------------------------------------------------


def test_real_minisign_release_verifies(real):
    info = check(real / "ocw-9.9.9.tar.gz", real / "ocw-9.9.9.tar.gz.minisig", real_eff())
    assert info.version == "9.9.9" and info.key_list_action == "same" and info.timestamp == "2026-01-15T10:00:00Z"


def test_real_minisign_project_signature_and_key_id_format():
    pub = minisign.parse_public_key("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3")
    assert pub.key_id == "E7620F1842B4E81F"  # as minisign prints it


def test_real_legacy_signature_is_refused(real):
    with pytest.raises(minisign.SignatureError) as info:
        minisign.parse_signature((real / "legacy.txt.minisig").read_text())
    assert info.value.code == "legacy_signature"


def test_flipped_byte_in_the_tarball(real):
    data = bytearray((real / "ocw-9.9.9.tar.gz").read_bytes())
    data[len(data) // 2] ^= 0x01
    (real / "ocw-9.9.9.tar.gz").write_bytes(bytes(data))
    refused("bad_signature", real / "ocw-9.9.9.tar.gz", real / "ocw-9.9.9.tar.gz.minisig", real_eff())


def test_wrong_key_unknown_key_and_no_key():
    other = effective([TestKey(), TestStandby()])
    msg = refused("unknown_key", REAL / "ocw-9.9.9.tar.gz", REAL / "ocw-9.9.9.tar.gz.minisig", other)
    assert "not pinned" in msg
    msg = refused("no_key_pinned", REAL / "ocw-9.9.9.tar.gz", REAL / "ocw-9.9.9.tar.gz.minisig", effective())
    assert "no release key pinned" in msg


def test_same_key_id_different_key_does_not_verify(real):
    eff = real_eff()
    forged = TestKey()
    target = next(k for k in eff["keys"] if k["role"] == "release")
    forged.stored_id = bytes.fromhex(target["key_id"])[::-1]
    forged.key_id = target["key_id"]
    entries = [forged.entry() if k["role"] == "release" else k for k in eff["keys"]]
    refused("bad_signature", real / "ocw-9.9.9.tar.gz", real / "ocw-9.9.9.tar.gz.minisig",
            keylib.effective_from(keylib.validate_key_list({"schema": 1, "keys": entries})))


def test_trusted_comment_tamper(real):
    sig = real / "ocw-9.9.9.tar.gz.minisig"
    sig.write_text(sig.read_text().replace("version=9.9.9", "version=9.9.8"))
    refused("bad_trusted_comment", real / "ocw-9.9.9.tar.gz", sig, real_eff())


# --- helper-signed vectors with chosen defects -------------------------------


@pytest.fixture
def keys_and_list():
    primary, standby = TestKey(), TestStandby()
    return primary, standby, effective([primary, standby])


def release(tmp_path, kl_or_eff, signer, version="5.47.0", **kw):
    kl = {"schema": 1, "keys": kl_or_eff["keys"]}
    tar = make_release_tar(tmp_path / f"ocw-{version}.tar.gz", version, kl, **{
        k: v for k, v in kw.items() if k in ("extra_files", "manifest_over", "script_version", "built_at", "drop",
                                              "min_upgrade_from", "unlisted")})
    sig = sign_release(tar, signer, version, **{k: v for k, v in kw.items() if k in ("timestamp", "name", "sha", "alg")})
    return tar, sig


def test_good_release_and_downgrade_rules(tmp_path, keys_and_list):
    primary, _standby, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary)
    assert check(tar, sig, eff).version == "5.47.0"
    refused("not_newer", tar, sig, eff, installed="5.47.0")
    refused("not_newer", tar, sig, eff, installed="6.0.0")
    assert check(tar, sig, eff, installed="5.47.0", allow_same_version=True).version == "5.47.0"
    assert check(tar, sig, eff, installed=None).version == "5.47.0"  # a by-hand check on a workstation
    refused("too_old", tar, sig, eff, installed="5.40.0")


def test_legacy_ed_signature_from_a_release_key_is_refused(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary, alg=b"Ed")
    refused("legacy_signature", tar, sig, eff)


def test_standby_key_cannot_sign_a_release(tmp_path, keys_and_list):
    _p, standby, eff = keys_and_list
    tar, sig = release(tmp_path, eff, forged_as(standby))
    assert "standby" in refused("wrong_role", tar, sig, eff)


@pytest.mark.parametrize("over,code", [
    ({"version": "5.47.1"}, "version_mismatch"),
    ({"schema": 2}, "bad_manifest"),
    ({"files": "nope"}, "bad_manifest"),
])
def test_manifest_defects(tmp_path, keys_and_list, over, code):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary, manifest_over=over)
    refused(code, tar, sig, eff)


def test_code_version_must_match_signed_version(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary, script_version="5.46.9")
    refused("version_mismatch", tar, sig, eff)


def test_file_name_and_hash_in_trusted_comment(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary, name="ocw-5.47.1.tar.gz")
    refused("name_mismatch", tar, sig, eff)
    tar, sig = release(tmp_path, eff, primary, sha="0" * 64)
    refused("hash_mismatch", tar, sig, eff)


def test_renamed_download_is_refused(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary)
    renamed = tmp_path / "ocw-latest.tar.gz"
    shutil.copy(tar, renamed)
    shutil.copy(sig, str(renamed) + ".minisig")
    refused("name_mismatch", renamed, str(renamed) + ".minisig", eff)


def test_garbage_inputs_never_traceback(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary)
    bad_sig = tmp_path / "bad.minisig"
    for content in ("", "not a signature", "a\nb\nc\nd\n", "untrusted comment: x\n!!!\ntrusted comment: y\n!!!\n"):
        bad_sig.write_text(content)
        with pytest.raises(verifylib.VerifyError):
            check(tar, bad_sig, eff)
    with pytest.raises(verifylib.VerifyError):
        check(tmp_path / "missing.tar.gz", sig, eff)
    junk = tmp_path / "ocw-5.47.0.tar.gz"
    junk.write_bytes(b"not gzip at all")
    refused("bad_archive", junk, sign_release(junk, primary, "5.47.0"), eff)


# --- the key list: roles, algorithms, statuses -----------------------------------


def test_key_list_validation():
    primary, standby = TestKey(), TestStandby()
    good = key_list([primary, standby])
    assert len(keylib.validate_key_list(good)["keys"]) == 2
    p, s = primary.entry(), standby.entry()
    for bad in (
        {**good, "schema": 2}, {**good, "extra": 1}, {"schema": 1},
        key_list([{**p, "key_id": "short"}]), key_list([{**p, "role": "admin"}]), key_list([{**p, "status": "maybe"}]),
        key_list([{**p, "since": "soon"}]), key_list([{**p, "alg": "es256"}]),          # algorithm does not fit the role
        key_list([{**s, "alg": "ed25519-minisign"}]),                                   # ... either way round
        key_list([{**p, "public_key": "AAAA"}]), key_list([{**s, "public_key": p["public_key"]}]),
        key_list([{**s, "key_id": "0" * 16}]),                                           # id must match the P-256 key
        key_list([p, p]), key_list([{**p, "extra": 1}]), key_list([{k: v for k, v in p.items() if k != "alg"}]),
    ):
        with pytest.raises(keylib.KeyListError):
            keylib.validate_key_list(bad)


def test_unknown_alg_is_kept_but_never_used():
    odd = {**TestKey().entry(), "alg": "dilithium5", "public_key": "x" * 20}
    eff = keylib.effective_from(keylib.validate_key_list(key_list([odd, TestKey(), TestStandby()])))
    assert len(eff["keys"]) == 3 and keylib.has_active(eff, "release")
    with pytest.raises(keylib.KeyListError) as info:
        keylib.pick_signer(eff, odd["key_id"], "release")
    assert info.value.code == "unknown_alg"
    assert not keylib.has_active(keylib.effective_from(keylib.validate_key_list(key_list([odd, TestStandby()]))), "release")


def test_shipped_key_list_pins_exactly_one_release_and_one_standby_key():
    """5.46.0 ships the maintainer's keys: one active Ed25519 release key (AWS KMS) and one active
    ES256 standby key (Azure Key Vault). Any change to this list is a deliberate key ceremony."""
    data = keylib.load_key_list(keylib.SHIPPED_PATH)
    assert data["schema"] == 1
    by_role = {}
    for entry in data["keys"]:
        by_role.setdefault(entry["role"], []).append(entry)
    assert sorted(by_role) == ["release", "standby"]
    (release_key,), (standby_key,) = by_role["release"], by_role["standby"]
    assert release_key["alg"] == "ed25519-minisign" and release_key["status"] == "active"
    assert standby_key["alg"] == "es256" and standby_key["status"] == "active"
    assert release_key["key_id"] == "88DFB54FC6C0E819"
    assert standby_key["key_id"] == "76A2D96A6B0FAAAD"
    assert release_key["since"] == standby_key["since"] == "5.46.0"


def test_retired_key_does_not_sign_new_releases(tmp_path):
    old, new, standby = TestKey(status="retired"), TestKey(), TestStandby()
    eff = effective([old, new, standby])
    tar, sig = release(tmp_path, eff, old)
    refused("retired_key", tar, sig, eff)
    tar, sig = release(tmp_path, eff, new, version="5.48.0")
    assert check(tar, sig, eff).version == "5.48.0"


def test_adoption_rules(keys_and_list):
    primary, standby, eff = keys_and_list
    newer, evil_standby = TestKey(), TestStandby()

    def adopt(*keys, current=eff):
        return keylib.check_adoption(current, keylib.validate_key_list(key_list(keys)))

    assert adopt(primary, standby) == "same"
    assert adopt(primary, standby, newer) == "adopt"                       # add a release key
    two = effective([primary, newer, standby])
    assert adopt(primary.entry("retired"), newer, standby, current=two) == "adopt"   # retire one of two
    assert adopt(primary) == "older"                                       # a subset: verifies, changes nothing
    for bad in ((primary, standby, evil_standby),                          # a release adds a standby
                (primary, evil_standby),                                   # ... or swaps it
                (primary, {**standby.entry(), "public_key": evil_standby.public_key}),   # redefines a standby
                ({**primary.entry(), "public_key": newer.entry()["public_key"]}, standby)):  # redefines a release key
        with pytest.raises(keylib.KeyListError) as info:
            adopt(*bad)
        assert info.value.code in ("keys_changed", "bad_key_list"), bad
    # a list that says "active" for what this install knows as retired changes nothing (the strictest status wins) ...
    retired_eff = effective([primary.entry("retired"), TestKey(), standby])
    assert adopt(primary, standby, current=retired_eff) == "older"
    merged = keylib.merged_with(retired_eff, keylib.validate_key_list(key_list([primary, standby])))
    assert {k["key_id"]: k["status"] for k in merged["keys"]}[primary.key_id] == "retired"
    # ... and a list that would leave nothing to sign with is refused
    with pytest.raises(keylib.KeyListError) as info:
        adopt(primary.entry("retired"), standby)
    assert info.value.code == "keys_changed"


def test_release_carrying_a_bad_key_list_is_refused(tmp_path, keys_and_list):
    primary, standby, eff = keys_and_list
    evil = TestStandby()
    for name, kl in {"adds standby": key_list([primary, standby, evil]), "swaps standby": key_list([primary, evil])}.items():
        tar, sig = release(tmp_path, kl, primary)
        with pytest.raises((verifylib.VerifyError, keylib.KeyListError)) as info:
            check(tar, sig, eff)
        assert info.value.code == "keys_changed", name


def test_a_new_release_key_can_be_introduced_and_then_used(tmp_path, keys_and_list):
    primary, standby, eff = keys_and_list
    newer = TestKey()
    carrying = key_list([primary, standby, newer])
    tar, sig = release(tmp_path, carrying, primary)
    info = check(tar, sig, eff)
    assert info.key_list_action == "adopt"
    merged = keylib.merged_with(eff, info.candidate_keys)
    tar2, sig2 = release(tmp_path, carrying, newer, version="5.48.0")
    assert check(tar2, sig2, merged).version == "5.48.0"


def test_statuses_only_move_toward_revoked_and_are_remembered():
    primary, newer, standby = TestKey(), TestKey(), TestStandby()
    shipped = keylib.validate_key_list(key_list([primary, newer, standby]))
    state = keylib.validate_state({"schema": 1, "serial": 3, "keys": [primary.entry("retired")], "revoked": [
        {"key_id": newer.key_id, "revoked_at": "2026-02-01T00:00:00Z", "last_good_version": "5.47.0"}]})
    eff = keylib.effective_from(shipped, state)
    status = {k["key_id"]: k["status"] for k in eff["keys"]}
    assert status[primary.key_id] == "retired" and status[newer.key_id] == "revoked" and status[standby.key_id] == "active"
    again = keylib.effective_from(keylib.validate_key_list(key_list([primary, newer, standby])), state)  # a list saying "active"
    assert {k["key_id"]: k["status"] for k in again["keys"]} == status
    clash = keylib.validate_state({"schema": 1, "serial": 0, "keys": [{**primary.entry(), "public_key": newer.entry()["public_key"]}], "revoked": []})
    with pytest.raises(keylib.KeyListError) as info:
        keylib.effective_from(shipped, clash)
    assert info.value.code == "conflict"


# --- revocation envelopes -------------------------------------------------------------


def apply_rev(tmp_path, eff, signers, payload, **kw):
    path = make_revocation(tmp_path / "revocation.json", signers, payload, **kw)
    return keylib.apply_revocation(eff, Path(path).read_bytes())


def test_real_revocation_flow(real):
    eff1 = real_eff()
    raw = (real / "revocation.json").read_bytes()
    state, details = keylib.apply_revocation(eff1, raw)
    eff2 = keylib.effective_from(keylib.load_key_list(REAL / "release_keys.json"), keylib.validate_state(state))
    expected = real_eff("release_keys.next.json")
    assert [(k["key_id"], k["status"]) for k in eff2["keys"]] == [(k["key_id"], k["status"]) for k in expected["keys"]]
    assert details["to_serial"] == 1 and len(details["revoked"]) == 2 and len(details["added"]) == 2
    assert check(real / "ocw-9.9.9.tar.gz", real / "ocw-9.9.9.tar.gz.minisig", eff2).version == "9.9.9"   # signed BEFORE: valid
    assert check(real / "ocw-9.9.10.tar.gz", real / "ocw-9.9.10.tar.gz.minisig", eff2).version == "9.9.10"
    assert "revocation" in refused("unknown_key", real / "ocw-9.9.10.tar.gz", real / "ocw-9.9.10.tar.gz.minisig", eff1)
    assert "Do not install" in refused("revoked_key", real / "ocw-9.9.11.tar.gz", real / "ocw-9.9.11.tar.gz.minisig", eff2)
    with pytest.raises(keylib.KeyListError) as info:
        keylib.apply_revocation(eff2, raw)
    assert info.value.code == "replayed"


def test_revocation_matches_the_independent_implementation(tmp_path, keys_and_list):
    """tests/release_helpers.py and tools/revoke.py build envelopes independently."""
    primary, standby, eff = keys_and_list
    revoke_tool = load_tool("revoke")
    payload = revocation_payload(1, revoke=[{"key_id": primary.key_id, "last_good_version": "5.47.0"}], add_keys=[TestKey(), TestStandby()])
    theirs = revoke_tool.build_envelope(payload, standby)
    mine = Path(make_revocation(tmp_path / "r.json", [standby], payload)).read_bytes()
    assert json.loads(theirs)["payload"] == json.loads(mine)["payload"]
    keylib.apply_revocation(eff, theirs)
    keylib.apply_revocation(eff, mine)


def test_revocation_rules(tmp_path, keys_and_list):
    primary, standby, eff = keys_and_list
    new_p, new_s = TestKey(), TestStandby()
    revoke = [{"key_id": primary.key_id, "last_good_version": "5.47.0"}]
    ok = revocation_payload(1, revoke, [new_p, new_s])
    state, _ = apply_rev(tmp_path, eff, [standby], ok)
    after = keylib.effective_from(keylib.validate_key_list(key_list([primary, standby])), keylib.validate_state(state))
    assert keylib.has_active(after, "release") and keylib.has_active(after, "standby") and after["serial"] == 1

    def refuse(code, signers=(standby,), payload=ok, current=eff, **kw):
        with pytest.raises(keylib.KeyListError) as info:
            apply_rev(tmp_path, current, list(signers), payload, **kw)
        assert info.value.code == code, str(info.value)

    claims_release = TestStandby()
    claims_release.key_id = primary.key_id
    refuse("wrong_role", [claims_release])
    refuse("unknown_key", [TestStandby()])
    handover_state, _ = apply_rev(tmp_path, eff, [standby], revocation_payload(1, revoke + [standby.key_id], [new_p, new_s]))
    handed = keylib.effective_from(keylib.validate_key_list(key_list([primary, standby])), keylib.validate_state(handover_state))
    with pytest.raises(keylib.KeyListError) as info:      # the old standby handed over: it cannot sign again, the new one can
        apply_rev(tmp_path, handed, [standby], revocation_payload(2, [], [TestKey()]))
    assert info.value.code == "revoked_key"
    apply_rev(tmp_path, handed, [new_s], revocation_payload(2, [], [TestKey()]))
    refuse("replayed", payload=ok, current=after)                                          # serial not newer than the last applied
    refuse("bad_revocation", payload=revocation_payload(0, revoke, [new_p, new_s]))
    refuse("bad_signature", tamper="payload")
    refuse("bad_revocation", tamper="format")
    refuse("bad_signature", alg="ed25519")
    refuse("bad_revocation", signers=[])           # an envelope with no signatures at all
    refuse("bad_revocation", payload=revocation_payload(1, ["0" * 16], [new_p, new_s]))     # unknown key
    refuse("bad_revocation", payload=revocation_payload(1, [standby.key_id], [new_p]))       # leaves no standby
    refuse("bad_revocation", payload=revocation_payload(1, [primary.key_id], [new_s]))       # leaves no release key
    refuse("bad_revocation", payload=revocation_payload(1, revoke, [primary]))               # key already pinned
    refuse("bad_revocation", payload={**ok, "advisory_url": "http://insecure.example"})
    refuse("bad_revocation", payload={**ok, "reason": ""})
    refuse("bad_revocation", payload={**ok, "extra": 1})
    refuse("bad_revocation", payload=revocation_payload(3, [primary.key_id], [TestKey()]), current=after)   # already revoked


def test_two_signatures_one_valid_is_enough(tmp_path, keys_and_list):
    primary, standby, eff = keys_and_list
    payload = revocation_payload(1, [{"key_id": primary.key_id, "last_good_version": "5.47.0"}], [TestKey(), TestStandby()])
    apply_rev(tmp_path, eff, [TestStandby(), standby], payload)


def test_backdated_release_from_a_revoked_key_is_refused(tmp_path, keys_and_list):
    primary, standby, eff = keys_and_list
    payload = revocation_payload(1, [{"key_id": primary.key_id, "last_good_version": "5.47.0"}], [TestKey(), TestStandby()],
                                 issued="2026-02-01T00:00:00Z")
    state, _ = apply_rev(tmp_path, eff, [standby], payload)
    eff2 = keylib.effective_from(keylib.validate_key_list(key_list([primary, standby])), keylib.validate_state(state))
    ok = release(tmp_path, eff, primary, version="5.47.0", timestamp="2026-01-20T00:00:00Z", built_at="2026-01-20T00:00:00Z")
    assert check(*ok, eff2, installed="5.46.0").version == "5.47.0"
    forged = release(tmp_path, eff, primary, version="5.48.0", timestamp="2026-01-20T00:00:00Z", built_at="2026-01-20T00:00:00Z")
    refused("revoked_key", *forged, eff2)     # back-dated, but newer than last_good_version
    notime = release(tmp_path, eff, primary, version="5.47.0", timestamp=None)
    refused("revoked_key", *notime, eff2)     # no time: cannot be shown to predate the revocation


# --- offline CLI, state file, audit ------------------------------------------------


@pytest.fixture
def pinned_real(real, tmp_path, monkeypatch):
    shipped = tmp_path / "release_keys.json"
    shutil.copy(real / "release_keys.json", shipped)
    monkeypatch.setattr(keylib, "SHIPPED_PATH", shipped)
    local = tmp_path / "release_keys.local.json"
    monkeypatch.setenv(keylib.LOCAL_PATH_ENV, str(local))
    return real, shipped, local


def test_offline_cli_applies_a_revocation_and_audits(pinned_real, capsys):
    real, shipped, local = pinned_real
    assert keylib.main(["apply-revocation", str(real / "revocation.json")]) == 0
    out = capsys.readouterr().out
    assert "serial 0 -> 1" in out and "test: release key exposed" in out
    assert local.exists() and (local.stat().st_mode & 0o077) == 0
    assert keylib.effective_key_list()["serial"] == 1
    assert shipped.read_text() == (real / "release_keys.json").read_text()
    assert keylib.main(["apply-revocation", str(real / "revocation.json")]) == 0   # idempotent
    import create_secret_folders as engine
    entries = [e for e in engine.read_audit_log(limit=50) if e["action"] == "release_keys.revocation_applied"]
    assert len(entries) == 1 and entries[0]["details"]["to_serial"] == 1 and entries[0]["details"]["source"] == "file"
    assert "correlation_id" in entries[0]["details"] and entries[0]["details"]["advisory_url"].startswith("https://")
    assert keylib.main(["show"]) == 0
    assert "revoked" in capsys.readouterr().out
    assert verifylib.main(["--apply-revocation", str(real / "revocation.json")]) == 0   # same file through the verify CLI


def test_cli_refuses_a_bad_revocation_without_a_traceback(pinned_real, tmp_path, capsys):
    real, _shipped, local = pinned_real
    bad = tmp_path / "rev.json"
    envelope = json.loads((real / "revocation.json").read_text())
    envelope["payload"] = envelope["payload"][:-4] + "AAAA"
    bad.write_text(json.dumps(envelope))
    assert keylib.main(["apply-revocation", str(bad)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("ERROR:") and "Traceback" not in err
    assert not local.exists()
    assert keylib.main(["apply-revocation", str(tmp_path / "missing")]) == 1
    bad.write_text("not json")
    assert keylib.main(["apply-revocation", str(bad)]) == 1


def test_damaged_or_conflicting_state_is_an_actionable_error(tmp_path):
    shipped, local = tmp_path / "a.json", tmp_path / "b.json"
    shipped.write_text(json.dumps(key_list([TestKey(), TestStandby()])))
    local.write_text("{not json")
    with pytest.raises(keylib.KeyListError, match="release_keys.local.json"):
        keylib.effective_key_list(shipped, local)
    local.write_text(json.dumps({"schema": 1}))
    with pytest.raises(keylib.KeyListError, match="damaged"):
        keylib.effective_key_list(shipped, local)
    assert keylib.effective_key_list(shipped, tmp_path / "absent.json")["serial"] == 0


def test_verify_cli_output_exit_codes_and_audit(real, capsys):
    argv = [str(real / "ocw-9.9.9.tar.gz"), str(real / "ocw-9.9.9.tar.gz.minisig"), "--keys", str(real / "release_keys.json"),
            "--installed-version", INSTALLED, "--audit"]
    assert verifylib.main(argv) == 0
    assert "OK  signature valid" in capsys.readouterr().out
    assert verifylib.main(argv[:-3] + ["--installed-version", "99.0.0", "--audit"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("ERROR:") and "not newer" in err and "Traceback" not in err
    import create_secret_folders as engine
    failures = [e for e in engine.read_audit_log(limit=50) if e["action"] == "upgrade.verify_failed"]
    assert failures[0]["details"]["reason"] == "not_newer" and failures[0]["details"]["file"] == "ocw-9.9.9.tar.gz"


def test_extract_remembers_the_current_key_state(real, tmp_path, monkeypatch):
    local = tmp_path / "state.json"
    shipped = tmp_path / "shipped.json"
    shutil.copy(real / "release_keys.json", shipped)
    monkeypatch.setattr(keylib, "SHIPPED_PATH", shipped)
    monkeypatch.setenv(keylib.LOCAL_PATH_ENV, str(local))
    argv = [str(real / "ocw-9.9.9.tar.gz"), str(real / "ocw-9.9.9.tar.gz.minisig"), "--installed-version", INSTALLED,
            "--extract", str(tmp_path / "out")]
    assert verifylib.main(argv) == 0
    state = json.loads(local.read_text())
    assert len(state["keys"]) == 2 and state["serial"] == 0       # everything known is now in the install's own file


# --- safe unpacking -------------------------------------------------------------


def test_safe_extract_good_and_defects(tmp_path, keys_and_list):
    primary, _s, eff = keys_and_list
    tar, sig = release(tmp_path, eff, primary)
    info = check(tar, sig, eff)
    dest = tmp_path / "out"
    verifylib.safe_extract(tar, dest, info.manifest)
    assert (dest / "frontend/dist/index.html").read_text().startswith("<html>")
    assert os.access(dest / "server/deploy.sh", os.X_OK) and not os.access(dest / "create_secret_folders.py", os.X_OK)
    t2, s2 = release(tmp_path, eff, primary, version="5.47.1",
                     manifest_over={"files": {**info.manifest["files"], "create_secret_folders.py": "0" * 64}})
    with pytest.raises(verifylib.VerifyError) as e:
        verifylib.safe_extract(t2, tmp_path / "o2", check(t2, s2, eff).manifest)
    assert e.value.code == "file_mismatch"
    t3, s3 = release(tmp_path, eff, primary, version="5.47.2", extra_files={"evil.py": "x"}, unlisted=("evil.py",))
    with pytest.raises(verifylib.VerifyError) as e:
        verifylib.safe_extract(t3, tmp_path / "o3", check(t3, s3, eff).manifest)
    assert "not listed" in str(e.value)
    t4, s4 = release(tmp_path, eff, primary, version="5.47.3", drop=("frontend/dist/index.html",))
    with pytest.raises(verifylib.VerifyError) as e:
        verifylib.safe_extract(t4, tmp_path / "o4", check(t4, s4, eff).manifest)
    assert "missing" in str(e.value)


@pytest.mark.parametrize("name", ["../escape.txt", "/abs/path", "a/../../b", "a\\b", "C:/win"])
def test_safe_extract_refuses_unsafe_paths(tmp_path, name):
    tar = tmp_path / "x.tar.gz"
    with tarfile.open(tar, "w:gz") as t:
        info = tarfile.TarInfo(name)
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(verifylib.VerifyError) as e:
        verifylib.safe_extract(tar, tmp_path / "dest", {"files": {}})
    assert e.value.code == "unsafe_path"
    assert not (tmp_path / "escape.txt").exists()


def test_safe_extract_refuses_links_and_devices(tmp_path):
    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
        tar = tmp_path / f"x{kind.decode()}.tar.gz"
        with tarfile.open(tar, "w:gz") as t:
            info = tarfile.TarInfo("link")
            info.type = kind
            info.linkname = "/etc/passwd"
            t.addfile(info)
        with pytest.raises(verifylib.VerifyError) as e:
            verifylib.safe_extract(tar, tmp_path / "dest", {"files": {}})
        assert e.value.code == "unsafe_member"


# --- the maintainer tools ----------------------------------------------------------------


def load_tool(name):
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location(f"tool_{name}", REPO / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def tagged_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "server").mkdir(parents=True)
    (repo / "frontend").mkdir()
    (repo / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.50.0"\n')
    (repo / "server" / "release_keys.json").write_text(json.dumps(key_list()))
    (repo / "frontend" / "package-lock.json").write_text("{}")
    (repo / "CHANGELOG.md").write_text("5.50.0 \u2014 **Thing**\nSummary line.\n- **Added.** detail\n\n5.49.0 \u2014 **Old**\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"], ["tag", "v5.50.0"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("built")
    return repo, dist


def test_build_makes_a_deterministic_release(tagged_repo, tmp_path):
    tool = load_tool("release")
    repo, dist = tagged_repo
    tar1, manifest = tool.build_release("5.50.0", repo, tmp_path / "o1", dist, built_at="2026-05-01T00:00:00Z")
    tar2, _ = tool.build_release("5.50.0", repo, tmp_path / "o2", dist, built_at="2026-05-01T00:00:00Z")
    assert tar1.read_bytes() == tar2.read_bytes()
    assert manifest["version"] == "5.50.0" and manifest["min_upgrade_from"] == "5.41.0" and manifest["migrations"] == []
    assert "frontend/dist/index.html" in manifest["files"] and "Summary line." in manifest["changelog_excerpt"]
    assert "detail" not in manifest["changelog_excerpt"]
    with pytest.raises(verifylib.VerifyError) as e:
        verifylib.verify_release(str(tar1), str(tar1) + ".minisig", effective(), None)   # no signature yet
    assert e.value.code == "unreadable"
    out = tmp_path / "unpacked"
    verifylib.safe_extract(tar1, out, manifest)
    assert (out / "frontend/dist/index.html").read_text() == "built"


def test_build_refuses_bad_inputs(tagged_repo, tmp_path):
    tool = load_tool("release")
    repo, dist = tagged_repo
    for version, fragment in (("5.50.1", "does not exist"), ("5.5", "version must look like")):
        with pytest.raises(tool.ReleaseError) as e:
            tool.build_release(version, repo, tmp_path / "o", dist)
        assert fragment in str(e.value)
    with pytest.raises(tool.ReleaseError) as e:
        tool.changelog_excerpt("nothing here", "5.50.0")
    assert "CHANGELOG" in str(e.value)
    with pytest.raises(tool.ReleaseError):
        tool.build_release("5.50.0", repo, tmp_path / "o", tmp_path / "no-dist")


def spki_der(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class FakeKms:
    """Stands in for boto3's KMS client: an Ed25519 key that signs RAW messages."""

    def __init__(self, key, spec_ok=True, sig_len=64):
        self.key, self.spec_ok, self.sig_len = key, spec_ok, sig_len
        self.spki = spki_der(key.priv.public_key())
        self.sign_calls = []

    def get_public_key(self, KeyId):
        return {"PublicKey": self.spki, "SigningAlgorithms": ["ED25519_SHA_512"] if self.spec_ok else ["RSASSA_PSS_SHA_256"]}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.sign_calls.append((MessageType, SigningAlgorithm, len(Message)))
        return {"Signature": self.key.priv.sign(Message)[:self.sig_len],
                "ResponseMetadata": {"RequestId": f"req-{len(self.sign_calls)}"}}


def test_kms_signing_end_to_end_with_a_fake_client(tmp_path):
    tool = load_tool("release")
    fake_key, standby = TestKey(), TestStandby()
    client = FakeKms(fake_key)
    backend = tool.AwsKmsBackend("alias/example", client=client, since="5.46.0")
    entry = backend.entry
    assert entry["role"] == "release" and entry["alg"] == "ed25519-minisign" and entry["public_key"] == fake_key.entry()["public_key"]
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([entry, standby])))
    tar = make_release_tar(tmp_path / "ocw-5.80.0.tar.gz", "5.80.0", json.loads(keys_path.read_text()), built_at="2026-01-15T10:00:00Z")
    sig_path, info = tool.sign_release_file(tar, backend, keys_path)
    assert [c[:2] for c in client.sign_calls] == [("RAW", "ED25519_SHA_512")] * 2     # exactly two Sign calls, pure Ed25519
    assert client.sign_calls[0][2] == 64                                                  # the BLAKE2b-512 digest of the file
    assert backend.request_ids == ["req-1", "req-2"]
    eff = keylib.effective_from(keylib.load_key_list(keys_path))
    assert info.version == "5.80.0" and check(tar, sig_path, eff).version == "5.80.0"


def test_kms_failures_are_actionable(tmp_path):
    tool = load_tool("release")
    key = TestKey()
    with pytest.raises(tool.ReleaseError, match="ED25519_SHA_512"):
        tool.AwsKmsBackend("k", client=FakeKms(key, spec_ok=False))
    with pytest.raises(tool.ReleaseError, match="64-byte raw Ed25519"):
        tool.AwsKmsBackend("k", client=FakeKms(key, sig_len=32)).sign_raw(b"x")
    with pytest.raises(tool.ReleaseError, match="Ed25519"):
        tool.sb.ed25519_entry_from_spki(spki_der(TestStandby().priv.public_key()))
    backend = tool.AwsKmsBackend("k", client=FakeKms(key))
    (tmp_path / "f").write_bytes(b"x")
    with pytest.raises(tool.ReleaseError, match="4000"):
        backend.sign_file(tmp_path / "f", "a" * 4001, tmp_path / "f.minisig")
    backend.sign_file(tmp_path / "f", "a" * 4000, tmp_path / "f.minisig")   # exactly at the cap is fine
    assert tool.main(["sign", "x.tar.gz", "--signer", "kms"]) == 1           # needs --kms-key


def test_a_signature_that_does_not_verify_is_removed_and_nothing_is_listed(tmp_path):
    tool = load_tool("release")
    key = TestKey()
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([TestKey(), TestStandby()])))      # the KMS key is NOT pinned
    tar = make_release_tar(tmp_path / "ocw-5.80.0.tar.gz", "5.80.0", json.loads(keys_path.read_text()))
    with pytest.raises(tool.ReleaseError, match="does NOT verify"):
        tool.sign_release_file(tar, tool.AwsKmsBackend("k", client=FakeKms(key)), keys_path)
    assert not Path(str(tar) + ".minisig").exists()


@pytest.mark.skipif(shutil.which("minisign") is None, reason="the official minisign program is not installed")
def test_kms_signature_verifies_with_the_official_minisign_binary(tmp_path):
    """Interop with the reference program. REQUIRED before the first release (the real KMS
    must pass the same check: docs/releasing.md); skipped where minisign is not installed."""
    tool = load_tool("release")
    key, standby = TestKey(), TestStandby()
    backend = tool.AwsKmsBackend("k", client=FakeKms(key))
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([backend.entry, standby])))
    tar = make_release_tar(tmp_path / "ocw-5.81.0.tar.gz", "5.81.0", json.loads(keys_path.read_text()))
    sig_path, _info = tool.sign_release_file(tar, backend, keys_path, require_minisign=True)   # runs minisign -V -H inside
    line = base64.b64encode(b"Ed" + bytes.fromhex(backend.entry["key_id"])[::-1] + key.raw).decode()
    proc = subprocess.run([shutil.which("minisign"), "-V", "-H", "-m", str(tar), "-x", str(sig_path), "-P", line], capture_output=True)
    assert proc.returncode == 0, proc.stderr


def test_interop_check_is_skipped_loudly_or_required(tmp_path, monkeypatch, capsys):
    tool = load_tool("release")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.delenv("OPA_MINISIGN", raising=False)
    entry = TestKey().entry()
    tool.interop_check(tmp_path / "x", tmp_path / "x.minisig", entry, None, False)
    assert "REQUIRED before the first release" in capsys.readouterr().out
    with pytest.raises(tool.ReleaseError, match="require-minisign"):
        tool.interop_check(tmp_path / "x", tmp_path / "x.minisig", entry, None, True)


def test_aws_profile_starts_an_sso_login_when_there_is_no_session(monkeypatch):
    sb = load_tool("release").sb
    calls = []

    class Result:
        def __init__(self, rc):
            self.returncode = rc

    def fake_run(cmd, check=True):
        calls.append(cmd)
        return Result(1 if cmd[1:3] == ["sts", "get-caller-identity"] else 0)

    class FakeSession:
        def __init__(self, profile_name=None, region_name=None):
            self.profile = profile_name

        def client(self, name):
            return ("client", name, self.profile)

    class FakeBoto:
        Session = FakeSession

    monkeypatch.setattr(sb, "run_command", fake_run)
    monkeypatch.setattr(sb, "_require", lambda module, extra: FakeBoto)
    assert sb.aws_client("ocw-signer") == ("client", "kms", "ocw-signer")
    assert [c[1:3] for c in calls] == [["sts", "get-caller-identity"], ["sso", "login"]]
    assert "--profile" in calls[1] and "ocw-signer" in calls[1]


def test_cloud_sdks_are_optional_tool_dependencies(monkeypatch):
    sb = load_tool("release").sb
    assert not any(m == "boto3" or m.startswith("azure") for m in sys.modules)
    import builtins
    real_import = builtins.__import__

    def no_sdk(name, *args, **kwargs):
        if name.split(".")[0] in ("boto3", "azure"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_sdk)
    with pytest.raises(sb.ReleaseError, match="never of the app"):
        sb.aws_client()
    with pytest.raises(sb.ReleaseError, match="never of the app"):
        sb.AzureAdapter("https://vault.example/keys/k")


class FakeVault:
    """Stands in for the Azure adapter: a P-256 key returning raw R||S over a digest."""

    def __init__(self, standby, bad_len=False):
        self.standby, self.bad_len, self.digests = standby, bad_len, []

    def spki_der(self):
        return base64.b64decode(self.standby.public_key)

    def sign_digest(self, digest):
        self.digests.append(digest)
        raw = self.standby.sign_digest(digest)
        return raw[:60] if self.bad_len else raw


def test_pubkey_command_prints_pinnable_entries(tmp_path, capsys, monkeypatch):
    tool = load_tool("release")
    primary, standby = TestKey(), TestStandby()
    monkeypatch.setattr(tool.sb, "aws_client", lambda profile=None, region=None: FakeKms(primary))
    monkeypatch.setattr(tool.sb, "AzureAdapter", lambda url: FakeVault(standby))
    out_file = tmp_path / "entry.json"
    assert tool.main(["pubkey", "--aws-kms", "alias/example", "--out", str(out_file)]) == 0
    entry = json.loads(out_file.read_text())
    assert entry["role"] == "release" and entry["alg"] == "ed25519-minisign" and entry["status"] == "active"
    assert entry["public_key"] == primary.entry()["public_key"]
    capsys.readouterr()
    assert tool.main(["pubkey", "--azure", "https://vault.example/keys/standby"]) == 0
    out = capsys.readouterr().out
    shown = json.loads(out[out.index("{"):out.rindex("}") + 1])
    assert shown == {**standby.entry(), "since": shown["since"]}
    keylib.validate_key_list(key_list([entry, shown]))
    assert tool.main(["pubkey"]) == 1


def test_rotate_adds_and_retires_but_never_touches_a_standby(tmp_path):
    tool = load_tool("release")
    primary, standby, newer = TestKey(), TestStandby(), TestKey()
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([primary, standby])))
    entry = tmp_path / "entry.json"
    entry.write_text(json.dumps(newer.entry()))
    assert tool.main(["rotate", "--add-key", str(entry), "--keys", str(keys_path)]) == 0
    assert {k["key_id"] for k in json.loads(keys_path.read_text())["keys"]} == {primary.key_id, standby.key_id, newer.key_id}
    assert tool.main(["rotate", "--retire", primary.key_id, "--keys", str(keys_path)]) == 0
    statuses = {k["key_id"]: k["status"] for k in json.loads(keys_path.read_text())["keys"]}
    assert statuses[primary.key_id] == "retired" and statuses[newer.key_id] == "active"
    entry.write_text(json.dumps(TestStandby().entry()))   # adding a standby is not a release's job
    assert tool.main(["rotate", "--add-key", str(entry), "--keys", str(keys_path)]) == 1
    assert tool.main(["rotate", "--retire", "0" * 16, "--keys", str(keys_path)]) == 1
    assert tool.main(["rotate", "--keys", str(keys_path)]) == 1


class Args:
    pass


def revoke_args(tmp_path, keys_path, revoke, add_key=()):
    a = Args()
    a.keys, a.state, a.revoke, a.add_key = str(keys_path), str(tmp_path / "none.json"), list(revoke), list(add_key)
    a.reason, a.advisory_url, a.serial, a.issued, a.out = "test", "https://example.com/a", None, "2026-03-01T00:00:00Z", str(tmp_path / "out")
    return a


def test_revoke_tool_signs_through_a_fake_key_vault_and_self_checks(tmp_path, capsys):
    tool = load_tool("revoke")
    primary, standby, newer, new_standby = TestKey(), TestStandby(), TestKey(), TestStandby()
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([primary, standby])))
    adds = []
    for k, name in ((newer, "p.json"), (new_standby, "s.json")):
        (tmp_path / name).write_text(json.dumps(k.entry()))
        adds.append(tmp_path / name)
    vault = FakeVault(standby)
    signer = tool.AzureKeyVaultSigner(client=vault)
    assert signer.entry["key_id"] == standby.key_id
    tool.run(revoke_args(tmp_path, keys_path, [f"{primary.key_id}:5.47.0", standby.key_id], adds), signer, lambda: True)
    assert len(vault.digests) == 1 and len(vault.digests[0]) == 32          # Key Vault signs a SHA-256 digest
    out = tmp_path / "out"
    raw = (out / "revocation.json").read_bytes()
    _state, details = keylib.apply_revocation(effective([primary, standby]), raw)   # an install accepts it
    assert details["revoked"] == sorted([primary.key_id, standby.key_id])
    nxt = json.loads((out / "release_keys.next.json").read_text())
    assert {k["key_id"]: k["status"] for k in nxt["keys"]}[primary.key_id] == "revoked"
    assert "az logout" in capsys.readouterr().out


def test_revoke_tool_refusals(tmp_path):
    tool = load_tool("revoke")
    primary, standby, other = TestKey(), TestStandby(), TestStandby()
    keys_path = tmp_path / "release_keys.json"
    keys_path.write_text(json.dumps(key_list([primary, standby])))
    signer = tool.AzureKeyVaultSigner(client=FakeVault(standby))

    def run(args, signer=signer, confirm=lambda: True):
        return tool.run(args, signer, confirm)

    with pytest.raises(tool.ReleaseError, match="last good version"):
        run(revoke_args(tmp_path, keys_path, [primary.key_id]))
    with pytest.raises(tool.ReleaseError, match="not a pinned key"):
        run(revoke_args(tmp_path, keys_path, ["0" * 16]))
    with pytest.raises(tool.ReleaseError, match="not an active standby"):
        run(revoke_args(tmp_path, keys_path, [f"{primary.key_id}:5.47.0"]), tool.AzureKeyVaultSigner(client=FakeVault(other)))
    with pytest.raises(tool.ReleaseError, match="nothing was signed"):
        run(revoke_args(tmp_path, keys_path, [f"{primary.key_id}:5.47.0"]), confirm=lambda: False)
    with pytest.raises(tool.ReleaseError, match="REFUSED"):     # leaves no standby: installs would refuse it
        run(revoke_args(tmp_path, keys_path, [standby.key_id]))
    assert not (tmp_path / "out" / "revocation.json").exists()
    with pytest.raises(tool.ReleaseError, match="64 bytes"):
        tool.AzureKeyVaultSigner(client=FakeVault(standby, bad_len=True)).sign_digest(b"x" * 32)
    # never automated: without a terminal it refuses before touching any cloud
    assert tool.main(["--azure-key", "https://v/keys/k", "--revoke", "x", "--reason", "r", "--advisory-url", "https://a"]) == 1
