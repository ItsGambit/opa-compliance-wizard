"""The support bundle: seeded secrets must never appear in the archive (server/updater/root/ocw_bundle.py
and its use by the updater)."""

import io
import json
import sqlite3
import tarfile
from pathlib import Path

import pytest

import updater_fakes as uf
from updater_fakes import act

SUB = "00u1abcdefghij2klmno"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwMHUxYWJjIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
COOKIE = "session=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA"
BEARER = "Bearer abc.def.ghi-0123456789"
SECRET_ODDITY = "p@ss:with/odd+chars==9"


def seeded_machine(tmp_path):
    m = uf.Machine(tmp_path)
    env = m.etc / "app.env"
    env.write_text(env.read_text() + f"SOMETHING_PASSWORD={SECRET_ODDITY}\n")
    leaky = (f"starting for {uf.SEED_EMAIL} sub {SUB} on {uf.SEED_HOST} (192.0.2.44, 2001:db8:85a3:0:0:8a2e:370:7334)\n"
             f"env {uf.SEED_ENV_NAME} KEYRING_UNLOCK_PASSWORD={uf.FAKE_SECRETS['KEYRING_UNLOCK_PASSWORD']}\n"
             f"Authorization: {BEARER}\nCookie: {COOKIE}\nSet-Cookie: sid=zzz; Path=/\n"
             f"X-Nginx-Proxy-Secret: {uf.PROXY_SECRET}\n"
             f"token {uf.FAKE_SECRETS['OKTA_API_TOKEN']} jwt {JWT}\n"
             f'payload {{"password": "{SECRET_ODDITY}", "api_token": "tok-12345678"}}\n'
             f"hash {'ab12' * 12}\n")
    for u in ("opa-compliance-wizard", "opa-auth-gate", "ocw-upgrade"):
        m.host.fake_journal[u] = leaky
    return m


def failing_upgrade(m, cid="upg-ffff0001"):
    # audit entries with the environment/tenant/email names that must be hashed
    act.audit_append(m.cfg(), "sync.start", {"correlation_id": cid, "environment": uf.SEED_ENV_NAME, "org_url": f"https://{uf.SEED_HOST}",
                                             "who": uf.SEED_EMAIL, "sub": SUB}, actor_email=uf.SEED_EMAIL)
    m.host.unhealthy_versions.add("5.47.0")
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id=cid)) == "rolled_back"
    st = m.read_state()
    return m.data / "upgrade" / "bundles" / st["bundle"]["name"]


def members(path):
    out = {}
    with tarfile.open(path, "r:gz") as t:
        for mem in t:
            out[mem.name] = t.extractfile(mem).read().decode("utf-8")
    return out


FORBIDDEN = [uf.SEED_EMAIL, SUB, uf.SEED_HOST, "192.0.2.44", "2001:db8", uf.SEED_ENV_NAME, JWT, COOKIE, BEARER, uf.PROXY_SECRET,
             uf.FAKE_SECRETS["KEYRING_UNLOCK_PASSWORD"], uf.FAKE_SECRETS["INTERNAL_API_SHARED_SECRET"], uf.FAKE_SECRETS["OKTA_API_TOKEN"],
             SECRET_ODDITY, "tok-12345678", "ab12" * 12, "sid=zzz"]


def test_seeded_secrets_never_appear_anywhere_in_the_bundle(tmp_path):
    m = seeded_machine(tmp_path)
    path = failing_upgrade(m)
    parts = members(path)
    blob = "\n".join(parts.values())
    for needle in FORBIDDEN:
        assert needle not in blob, needle
    # what is there is still useful
    assert {"summary.json", "redaction-report.txt", "nginx-test.txt", "journal-opa-compliance-wizard.txt"} <= set(parts)
    assert any(n.startswith("audit-upg-ffff0001") for n in parts)
    summary = json.loads(parts["summary.json"])
    assert summary["reason_code"] == "health_healthz" and summary["version_from"] == "5.46.0"
    assert "user-" in blob and "@redacted" in blob and "host-" in blob and "env-" in blob and "[REDACTED:" in blob
    report = parts["redaction-report.txt"]
    assert "emails" in report and uf.SEED_EMAIL not in report


def test_nothing_that_must_never_be_included_is_a_member(tmp_path):
    m = seeded_machine(tmp_path)
    parts = members(failing_upgrade(m))
    names = " ".join(parts)
    for bad in (".env", "app.env", ".db", "keyring", "site", "audit_store", "environments"):
        assert bad not in names.replace("audit-upg-ffff0001.jsonl", ""), bad
    # the archive itself is not in the bundle either
    assert "SELECT" not in "\n".join(parts.values()) and "user0@example.com" not in "\n".join(parts.values())


def test_include_hosts_keeps_names_but_still_redacts_secrets_and_people(tmp_path):
    m = seeded_machine(tmp_path)
    failing_upgrade(m)
    up = m.updater()
    up.st = m.read_state()
    info = up.make_bundle(include_hosts=True, correlation_id="upg-ffff0001")
    blob = "\n".join(members(info["path"]).values())
    assert uf.SEED_HOST in blob and uf.SEED_ENV_NAME in blob
    for needle in [uf.SEED_EMAIL, SUB, JWT, COOKIE, uf.PROXY_SECRET, SECRET_ODDITY, uf.FAKE_SECRETS["OKTA_API_TOKEN"]]:
        assert needle not in blob, needle


def test_placeholders_are_consistent_within_a_bundle_and_not_across_bundles(tmp_path):
    from updater_fakes import ROOT_DIR  # noqa: F401
    import ocw_bundle
    a, b = ocw_bundle.Redactor(), ocw_bundle.Redactor()
    text = "mail a@example.com and again a@example.com"
    ra = a.redact(text)
    assert ra.split()[1] == ra.split()[4] and "a@example.com" not in ra
    assert a.redact("a@example.com") != b.redact("a@example.com")


def test_bundle_is_capped_at_5_mb_even_with_enormous_journals(tmp_path):
    import os
    import ocw_bundle
    huge = "".join(f"line {i} {os.urandom(24).hex()}\n" for i in range(400000))  # ~ 20 MB of incompressible text
    red = ocw_bundle.Redactor()
    info = ocw_bundle.build(str(tmp_path), "ocw-support-test", {"correlation_id": "upg-00000000"}, {"journal-x.txt": huge}, [], red)
    assert info["size"] <= ocw_bundle.MAX_BUNDLE_BYTES
    assert Path(info["path"]).stat().st_mode & 0o777 in (0o640, 0o600)
    assert "omitted" in members(info["path"])["journal-x.txt"]


def test_redactor_leaves_file_and_unit_names_alone():
    import ocw_bundle
    r = ocw_bundle.Redactor()
    s = "opa-compliance-wizard.service audit_store.db create_secret_folders.py 5.46.0 /opt/opa-compliance-wizard/releases/5.46.0 ocw-stage@5.47.0.service"
    assert r.redact(s) == s


def test_bundle_build_failure_never_hides_the_real_failure(tmp_path, monkeypatch):
    m = seeded_machine(tmp_path)
    import ocw_bundle
    monkeypatch.setattr(ocw_bundle, "build", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    m.host.unhealthy_versions.add("5.47.0")
    m.build_release("5.47.0")
    m.put_artifacts("5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-ffff0002")) == "rolled_back"
    assert m.read_state()["bundle"] is None
